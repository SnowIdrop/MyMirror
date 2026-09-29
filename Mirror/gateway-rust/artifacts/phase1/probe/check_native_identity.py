#!/usr/bin/env python3
"""注入身份脚本在**真 Chromium** 里的复核（离线自检 check_injected_identity.mjs 的证据来源）。

离线自检跑在桩宿主上，桩的形状是我写的——它验不出「真 Chromium 的描述符到底长什么样」。
这个脚本把同一段注入块喂给镜像里那套真 chromium146，做两次采集：

    1. 注入**前**：采集原生的身份面形状（描述符标志位、函数 name/length/toString、
       getHighEntropyValues 的键集与键序、brands 的冻结与复用语义）。
    2. 注入**后**：同一套采集再跑一遍。

然后断言 **形状逐位相同、取值全部换成注入身份**。形状里任何一位对不上，就是一条
页面侧可检测的漂移——真 Chrome 的 `getHighEntropyValues.name` 是
`getHighEntropyValues`，改写后要是变成 `gatewayHighEntropy`，这里立刻红。

依赖镜像里的系统 chromium 与 playwright，因此走 docker 跑（无网络）：

    docker run --rm --network none \\
      -v "$PWD/probe/check_native_identity.py:/probe.py:ro" \\
      -v "$PWD/source/src/assets/gateway-client.html:/asset.html:ro" \\
      --entrypoint python3 mirror-cfbypass:phase1 /probe.py /asset.html

不带参数时默认读 ../source/src/assets/gateway-client.html。
"""

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

# 形状用的样本身份：取值本身无关紧要（真取值由 identity::js_identity() 生成），
# 这里只验证改写行为，因此**不**在本文件里复制一份真身份表。
IDENTITY = {
    "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "appVersion": "5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "platform": "Linux x86_64",
    "brands": [
        {"brand": "Chromium", "version": "146"},
        {"brand": "Not-A.Brand", "version": "24"},
        {"brand": "Google Chrome", "version": "146"},
    ],
    "fullVersionList": [
        {"brand": "Chromium", "version": "146.0.7680.177"},
        {"brand": "Not-A.Brand", "version": "24.0.0.0"},
        {"brand": "Google Chrome", "version": "146.0.7680.177"},
    ],
    "mobile": False,
    "platformName": "Linux",
    "architecture": "x86",
    "bitness": "64",
    "model": "",
    "platformVersion": "",
    "fullVersion": "146.0.7680.177",
    "wow64": False,
    "formFactors": ["Desktop"],
}

# 身份面采集：形状（shape）与取值（values）分开返回，断言时只要求形状相同。
SURVEY = """async () => {
  const nproto = Object.getPrototypeOf(navigator);
  const uad = navigator.userAgentData;
  const uproto = Object.getPrototypeOf(uad);
  const accessor = (proto, name) => {
    const d = Object.getOwnPropertyDescriptor(proto, name);
    return {
      kind: 'accessor', enumerable: d.enumerable, configurable: d.configurable,
      hasSetter: d.set !== undefined, name: d.get.name, length: d.get.length,
      toString: d.get.toString(),
    };
  };
  const method = (proto, name) => {
    const d = Object.getOwnPropertyDescriptor(proto, name);
    return {
      kind: 'method', enumerable: d.enumerable, configurable: d.configurable,
      writable: d.writable, name: d.value.name, length: d.value.length,
      toString: d.value.toString(),
    };
  };
  const high = await uad.getHighEntropyValues(
    ['wow64', 'architecture', 'fullVersion', 'uaFullVersion', 'bogusHint']);
  const forms = await uad.getHighEntropyValues(['formFactors']);
  const empty = await uad.getHighEntropyValues([]);
  let badArg = null;
  try { await uad.getHighEntropyValues('architecture'); } catch (e) { badArg = e.constructor.name; }
  return {
    shape: {
      'Navigator.prototype.userAgent': accessor(nproto, 'userAgent'),
      'Navigator.prototype.appVersion': accessor(nproto, 'appVersion'),
      'Navigator.prototype.platform': accessor(nproto, 'platform'),
      'NavigatorUAData.prototype.brands': accessor(uproto, 'brands'),
      'NavigatorUAData.prototype.mobile': accessor(uproto, 'mobile'),
      'NavigatorUAData.prototype.platform': accessor(uproto, 'platform'),
      'NavigatorUAData.prototype.getHighEntropyValues': method(uproto, 'getHighEntropyValues'),
      'NavigatorUAData.prototype.toJSON': method(uproto, 'toJSON'),
      navigatorOwnProps: Object.getOwnPropertyNames(navigator),
      uaDataOwnProps: Object.getOwnPropertyNames(uad),
      toStringTag: uproto[Symbol.toStringTag],
      protoKeyOrder: Object.keys(uproto),
      instanceOf: uad instanceof uproto.constructor,
      // brands 的身份语义：每次取值是新数组、数组冻结、条目不冻结。
      brandsFreshEachRead: uad.brands !== uad.brands,
      brandsFrozen: Object.isFrozen(uad.brands),
      brandsEntryFrozen: Object.isFrozen(uad.brands[0]),
      highBrandsFrozen: Object.isFrozen(high.brands),
      // 高熵的键集与键序（字典序，恒含 brands/mobile/platform，表外提示不合成）。
      highKeys: Object.keys(high), formKeys: Object.keys(forms), emptyKeys: Object.keys(empty),
      toJsonKeys: Object.keys(uad.toJSON()),
      badArgError: badArg,
      ordinaryToString: (function ordinary() { return 1; }).toString(),
      fnToStringName: Function.prototype.toString.name,
    },
    values: {
      userAgent: navigator.userAgent, appVersion: navigator.appVersion,
      platform: navigator.platform, brands: uad.brands, mobile: uad.mobile,
      uaPlatform: uad.platform, high: high, forms: forms,
    },
  };
}"""


def injection_block(asset: Path) -> str:
    source = asset.read_text(encoding="utf-8")
    start = source.index("  var gatewayIdentity =")
    end = source.index("  var enableUserControls")
    return source[start:end].replace("@@IDENTITY_JSON@@", json.dumps(IDENTITY))


def diff(before: dict, after: dict) -> list[str]:
    """形状逐键比对，返回人读的差异行。"""
    problems = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            problems.append(f"  {key}\n    原生: {before.get(key)!r}\n    改写后: {after.get(key)!r}")
    return problems


def main() -> int:
    asset = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "source/src/assets/gateway-client.html"
    )
    block = injection_block(asset)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            executable_path="/usr/bin/chromium", chromium_sandbox=False, args=["--no-sandbox"]
        )
        page = browser.new_context().new_page()
        # userAgentData 只在安全上下文里存在，因此用拦截伪造一个 https 页面。
        page.route(
            "**/*",
            lambda route: route.fulfill(
                status=200, content_type="text/html", body="<html><head></head><body>probe</body></html>"
            ),
        )
        page.goto("https://identity-probe.invalid/", wait_until="domcontentloaded")
        native = page.evaluate(SURVEY)
        page.evaluate(f"() => {{ {block} }}")
        faked = page.evaluate(SURVEY)
        browser.close()

    problems = diff(native["shape"], faked["shape"])
    if problems:
        print("真 Chromium 复核失败：改写后的身份面与原生形状不一致（每一条都是可检测点）")
        print("\n".join(problems))
        return 1

    values = faked["values"]
    checks = [
        ("userAgent", values["userAgent"], IDENTITY["userAgent"]),
        ("appVersion", values["appVersion"], IDENTITY["appVersion"]),
        ("platform", values["platform"], IDENTITY["platform"]),
        ("userAgentData.brands", values["brands"], IDENTITY["brands"]),
        ("userAgentData.mobile", values["mobile"], IDENTITY["mobile"]),
        ("userAgentData.platform", values["uaPlatform"], IDENTITY["platformName"]),
        ("high.architecture", values["high"]["architecture"], IDENTITY["architecture"]),
        ("high.wow64", values["high"]["wow64"], IDENTITY["wow64"]),
        ("high.uaFullVersion", values["high"]["uaFullVersion"], IDENTITY["fullVersion"]),
        ("forms.formFactors", values["forms"]["formFactors"], IDENTITY["formFactors"]),
    ]
    failed = [(name, got, want) for name, got, want in checks if got != want]
    if failed:
        print("真 Chromium 复核失败：形状对了但取值没被改写")
        for name, got, want in failed:
            print(f"  {name}: 实得 {got!r}，应为 {want!r}")
        return 1

    # 原生取值必须确实被换掉，否则「通过」只是因为两边本来就一样。
    if native["values"]["userAgent"] == faked["values"]["userAgent"]:
        print("真 Chromium 复核失败：注入前后 UA 相同，说明这次比对没有判别力")
        return 1

    print(f"真 Chromium 复核通过：{len(native['shape'])} 项形状与原生逐位一致，取值已全部换成注入身份")
    print(f"  原生 UA : {native['values']['userAgent']}")
    print(f"  改写后  : {faked['values']['userAgent']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
