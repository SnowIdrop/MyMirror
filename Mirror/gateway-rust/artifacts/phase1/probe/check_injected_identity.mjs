// -----------------------------------------------------------------------------
// File    : probe/check_injected_identity.mjs
// Created : 2026-09-29
// Summary : 注入身份脚本的离线自检。不联网、不起浏览器：造一个「像 Chromium 的
//           宿主」（Navigator 原型 + NavigatorUAData 原型，取值全是 Windows），
//           跑一遍 src/assets/gateway-client.html 里的身份注入块，断言改写既生效
//           又不可检测。
//
//           这段 JS 的风险不在「有没有改写」，而在「改写留没留下痕迹」：装在实例
//           上会让 Object.getOwnPropertyNames(navigator) 多出自有属性，合成一个
//           普通对象会让 userAgentData instanceof NavigatorUAData 失败，不补
//           toString 会让改写过的函数体直接可读，不补 name 会让页面直接读到
//           `gatewayHighEntropy` 这种名字——每一条都比「UA 说 Linux」更好认。
//
//           本文件的期望值全部来自对真 Chromium146 的实测，采集脚本是
//           probe/check_native_identity.py（需要 docker + cfbypass 镜像）。
//           这里是跑得起来的快速门；那边是证据来源与真浏览器复核。
//
// 运行    ：node probe/check_injected_identity.mjs   （在 artifacts/phase1 下）
// -----------------------------------------------------------------------------

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const asset = join(here, '..', 'source', 'src', 'assets', 'gateway-client.html');

// 身份注入块：从 `var gatewayIdentity` 到页面控制条变量之前。
const source = readFileSync(asset, 'utf8');
const start = source.indexOf('  var gatewayIdentity =');
const end = source.indexOf('  var enableUserControls');
assert.ok(start > 0 && end > start, '找不到身份注入块：模板结构变了，先更新本自检');

// 取值形状与 identity::js_identity() 一致（值本身无关紧要，只验证改写行为）。
const identity = {
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/146.0.0.0',
  appVersion: '5.0 (X11; Linux x86_64) Chrome/146.0.0.0',
  platform: 'Linux x86_64',
  brands: [{ brand: 'Chromium', version: '146' }, { brand: 'Google Chrome', version: '146' }],
  fullVersionList: [{ brand: 'Chromium', version: '146.0.7680.177' }],
  mobile: false,
  platformName: 'Linux',
  architecture: 'x86',
  bitness: '64',
  model: '',
  platformVersion: '',
  fullVersion: '146.0.7680.177',
  wow64: false,
  formFactors: ['Desktop'],
};
const block = source.slice(start, end).replace('@@IDENTITY_JSON@@', JSON.stringify(identity));

// 宿主：取值全是 Windows，属性一律在**原型**上，描述符按真 Chromium146 实测的形状
// 铺开（访问器 enumerable:true / configurable:true，方法 enumerable:true /
// writable:true / configurable:true）。桩的形状错了，自检就验不出真问题。
function NavigatorUAData() {}
const accessor = (proto, name, value) =>
  Object.defineProperty(proto, name, { configurable: true, enumerable: true, get: () => value });
const method = (proto, name, fn) =>
  Object.defineProperty(proto, name, { configurable: true, enumerable: true, writable: true, value: fn });
accessor(NavigatorUAData.prototype, 'brands', [{ brand: 'Chromium', version: '999' }]);
accessor(NavigatorUAData.prototype, 'mobile', false);
accessor(NavigatorUAData.prototype, 'platform', 'Windows');
method(NavigatorUAData.prototype, 'getHighEntropyValues', () => Promise.resolve({}));
method(NavigatorUAData.prototype, 'toJSON', () => ({}));
function Navigator() {}
accessor(Navigator.prototype, 'userAgent', 'host-windows-ua');
accessor(Navigator.prototype, 'appVersion', 'host-windows');
accessor(Navigator.prototype, 'platform', 'Win32');

const uaData = new NavigatorUAData();
const navigator = new Navigator();
Object.defineProperty(navigator, 'userAgentData', { value: uaData, configurable: true });

new Function('navigator', block)(navigator);

// --- 改写生效 -----------------------------------------------------------------
assert.equal(navigator.userAgent, identity.userAgent);
assert.equal(navigator.appVersion, identity.appVersion);
assert.equal(navigator.platform, identity.platform);
assert.deepEqual(navigator.userAgentData.brands, identity.brands);
assert.equal(navigator.userAgentData.platform, 'Linux');
assert.equal(navigator.userAgentData.mobile, false);

// --- 改写不可检测 -------------------------------------------------------------
assert.ok(
  !Object.getOwnPropertyNames(navigator).includes('userAgent'),
  'navigator 实例上不能出现自有属性：真 Chrome 的这些值在原型上',
);
assert.equal(navigator.userAgentData, uaData, 'userAgentData 必须还是宿主那个实例');
assert.ok(navigator.userAgentData instanceof NavigatorUAData, 'instanceof 必须仍然成立');

const uaProto = Object.getPrototypeOf(uaData);
const navProto = Object.getPrototypeOf(navigator);
const describe = (proto, name) => Object.getOwnPropertyDescriptor(proto, name);

// 访问器的描述符：与真 Chromium 逐位一致（含 enumerable:true 与 set:undefined）。
for (const [proto, name] of [
  [navProto, 'userAgent'], [navProto, 'appVersion'], [navProto, 'platform'],
  [uaProto, 'brands'], [uaProto, 'mobile'], [uaProto, 'platform'],
]) {
  const d = describe(proto, name);
  assert.ok(d.get, `${name} 必须是访问器`);
  assert.equal(d.set, undefined, `${name} 不能有 setter：真 Chrome 是只读访问器`);
  assert.equal(d.enumerable, true, `${name} 必须可枚举：WebIDL 接口成员就是可枚举的`);
  assert.equal(d.configurable, true, `${name} 必须可配置`);
  assert.equal(d.get.name, `get ${name}`, `getter 的 name 必须是 "get ${name}"`);
  assert.equal(d.get.length, 0, 'getter 不取参数');
  assert.equal(d.get.toString(), `function get ${name}() { [native code] }`);
}

// 原型方法的描述符：真 Chromium 是 enumerable:true / writable:true / configurable:true。
// 写成 enumerable:false 会让 Object.keys(NavigatorUAData.prototype) 比真浏览器少两项。
for (const [name, length] of [['getHighEntropyValues', 1], ['toJSON', 0]]) {
  const d = describe(uaProto, name);
  assert.equal(typeof d.value, 'function', `${name} 必须是数据属性`);
  assert.equal(d.enumerable, true, `${name} 必须可枚举`);
  assert.equal(d.writable, true, `${name} 必须可写`);
  assert.equal(d.configurable, true, `${name} 必须可配置`);
  assert.equal(d.value.name, name, `${name} 的 name 不能泄漏改写用的变量名`);
  assert.equal(d.value.length, length, `${name} 的形参个数必须与真 Chrome 一致`);
  assert.equal(d.value.toString(), `function ${name}() { [native code] }`);
}

assert.equal(Function.prototype.toString.name, 'toString', '连 toString 自己的 name 也要对');
assert.ok(
  (function ordinary() { return 1; }).toString().includes('return 1'),
  'toString 的改写只能对改写过的函数生效，不能污染普通函数',
);

// brands 的身份：实测真 Chrome 每次取值都是**新**数组，数组冻结、条目不冻结。
const first = navigator.userAgentData.brands;
const second = navigator.userAgentData.brands;
assert.notEqual(first, second, 'brands 每次取值必须是新数组：复用同一个数组是检测点');
assert.deepEqual(first, second);
assert.ok(Object.isFrozen(first), 'uad.brands 数组本身冻结');
assert.ok(!Object.isFrozen(first[0]), 'uad.brands 的条目**不**冻结');

// --- 高熵：键集、键序、取值都按实测对齐 ---------------------------------------
const high = await navigator.userAgentData.getHighEntropyValues([
  'wow64',
  'architecture',
  'fullVersion',
  'uaFullVersion',
  'bogusHint',
]);
assert.deepEqual(
  Object.keys(high),
  ['architecture', 'brands', 'mobile', 'platform', 'uaFullVersion', 'wow64'],
  '键序必须是字典序、恒含 brands/mobile/platform、表外提示不合成',
);
assert.equal(high.architecture, 'x86');
assert.equal(high.wow64, false, 'Linux 上 wow64 是 false，不是「缺席」');
assert.equal(high.uaFullVersion, identity.fullVersion);
assert.ok(!('fullVersion' in high), 'fullVersion 不是合法提示名，只有 uaFullVersion');
assert.ok(!('bogusHint' in high), '表外提示不合成');
assert.ok(!Object.isFrozen(high.brands), '高熵回的 brands 数组不冻结（与 uad.brands 不同）');

const forms = await navigator.userAgentData.getHighEntropyValues(['formFactors']);
assert.deepEqual(Object.keys(forms), ['brands', 'formFactors', 'mobile', 'platform']);
assert.deepEqual(forms.formFactors, ['Desktop']);

const empty = await navigator.userAgentData.getHighEntropyValues([]);
assert.deepEqual(Object.keys(empty), ['brands', 'mobile', 'platform']);

await assert.rejects(
  () => navigator.userAgentData.getHighEntropyValues('architecture'),
  TypeError,
  '非数组入参必须像真 Chrome 一样报 TypeError，不能静默放过',
);

assert.deepEqual(
  Object.keys(navigator.userAgentData.toJSON()).sort(),
  ['brands', 'mobile', 'platform'],
  'toJSON 与真 NavigatorUAData.prototype.toJSON 同形：只回低熵三项',
);

console.log('注入身份脚本自检：全部通过');
