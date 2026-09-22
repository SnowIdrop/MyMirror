"""Append Python and an isolated init to a COPY of the existing initramfs. Author: MingTea."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(r"D:\Project\MirrorNiXiang")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate")
    args = parser.parse_args()
    out = ROOT / ".build/sandbox.cpio.gz"
    out.parent.mkdir(exist_ok=True)
    shutil.copyfile(BASE / "reverse/tools/sandbox-initramfs.cpio.gz", out)
    count = 0
    with out.open("ab") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        def add(name, mode, body=b""):
            nonlocal count
            count += 1
            nb = name.encode() + b"\0"
            fields = (count, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(nb), 0)
            gz.write(b"070701" + b"".join(b"%08X" % item for item in fields) + nb)
            gz.write(b"\0" * (-gz.tell() % 4))
            gz.write(body)
            gz.write(b"\0" * (-gz.tell() % 4))
        with tarfile.open(BASE / "image.tar") as image:
            layers = json.load(image.extractfile("manifest.json"))[0]["Layers"]
            for layer_name in layers[2:4]:
                with tarfile.open(fileobj=image.extractfile(layer_name), mode="r|") as layer:
                    for entry in layer:
                        name = entry.name.strip("/")
                        if name.startswith("usr/local/"):
                            if entry.isdir():
                                add(name, 0o040755)
                            elif entry.issym():
                                add(name, 0o120777, entry.linkname.encode())
                            elif entry.isfile():
                                add(name, 0o100000 | entry.mode, layer.extractfile(entry).read())
        add("init", 0o100755, b'''#!/usr/bin/busybox sh
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export LD_LIBRARY_PATH=/usr/local/lib
/usr/bin/busybox mount -t proc proc /proc
/usr/bin/busybox mount -t sysfs sysfs /sys
/usr/bin/busybox mount -t devtmpfs devtmpfs /dev
/usr/bin/busybox ip link set lo up
echo '====== SANDBOX READY (interactive sh) ======'
exec /usr/bin/busybox sh
''')
        if args.candidate:
            add("app/candidate", 0o100755, Path(args.candidate).read_bytes())
        add("app/ROLLBACK.sh",0o100755,(ROOT / "artifacts/ROLLBACK.sh").read_bytes())
        add("app/baseline.gateway",0o100755,(BASE / "reverse/extracted/chatgpt-mirror-gateway").read_bytes())
        add("TRAILER!!!", 0)
    print(json.dumps({"initramfs": str(out), "entries": count, "candidate": args.candidate}))
    manifest={"candidate_sha256":hashlib.sha256(Path(args.candidate).read_bytes()).hexdigest() if args.candidate else None,
              "initramfs_sha256":hashlib.sha256(out.read_bytes()).hexdigest()}
    (ROOT/".build/sandbox.manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")


if __name__ == "__main__":
    main()
