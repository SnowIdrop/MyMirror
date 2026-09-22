"""Run original/candidate only in a disposable QEMU guest with NO network adapter.
Author: MingTea. Existing VM, input image and source directories are never changed.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(r"D:\Project\MirrorNiXiang\reverse\tools")
ORIGINAL = TOOLS.parent / "extracted/chatgpt-mirror-gateway"
EXPECTED = "4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guest-script", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--serial-port", type=int, default=45591)
    parser.add_argument("--subject", choices=["original", "candidate", "rollback"], default="original")
    args = parser.parse_args()
    actual = hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()
    if actual != EXPECTED:
        raise RuntimeError("Original digest mismatch; refusing to change baseline")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    command = [str(TOOLS / "qemu-installer/qemu-system-x86_64.exe"),
               "-m", "1536", "-no-reboot", "-kernel", str(TOOLS / "downloads/vmlinuz-virt"),
               "-initrd", str(ROOT / ".build/sandbox.cpio.gz"),
               "-append", "console=ttyS0 rdinit=/init panic=60", "-nic", "none",
               "-display", "none", "-serial", f"tcp:127.0.0.1:{args.serial_port},server=on,wait=on",
               "-monitor", "none"]
    metadata = {"command": command, "original_sha256": actual, "external_network": False,
                "guest_script_sha256": hashlib.sha256(Path(args.guest_script).read_bytes()).hexdigest(),
                "subject": args.subject}
    metadata["initramfs"]=json.loads((ROOT/".build/sandbox.manifest.json").read_text(encoding="utf-8"))
    (output / "command.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    with (output / "qemu.stderr").open("wb") as errors, (output / "serial.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        channel = None
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    channel = socket.create_connection(("127.0.0.1", args.serial_port), timeout=1)
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(f"QEMU exited: {process.returncode}")
                    time.sleep(.2)
            if channel is None:
                raise TimeoutError("QEMU serial did not become available")
            channel.settimeout(1)
            received = bytearray()

            def read_until(marker, seconds):
                start = len(received)
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    try:
                        data = channel.recv(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        raise RuntimeError("Serial closed before acceptance marker")
                    log.write(data)
                    log.flush()
                    received.extend(data)
                    if marker in received[start:]:
                        return
                raise TimeoutError(f"Guest marker not observed: {marker!r}")

            read_until(b"SANDBOX READY (interactive sh)", 150)
            channel.sendall(b"stty -echo\n")
            time.sleep(.2)
            subject_binary = "/app/candidate" if args.subject == "candidate" else "/app/chatgpt-mirror-gateway"
            prefix = f"import os; os.environ['GATEWAY_TEST_BINARY']={subject_binary!r}; os.environ['GATEWAY_TEST_SUBJECT']={args.subject!r}\n"
            payload = base64.b64encode(prefix.encode() + Path(args.guest_script).read_bytes()).decode()
            channel.sendall(b"cat > /tmp/contract.b64 <<'PAYLOAD_END'\n")
            for i in range(0, len(payload), 512):
                channel.sendall(payload[i:i + 512].encode() + b"\n")
                time.sleep(.01)
            channel.sendall(b"PAYLOAD_END\npython -u -c \"import base64;exec(base64.b64decode(open('/tmp/contract.b64','rb').read()))\"; echo GUEST_EXIT:$?\n")
            read_until(b"GUEST_EXIT:", 240)
            time.sleep(.5)
            try:
                tail = channel.recv(65536)
                received.extend(tail)
                log.write(tail)
            except socket.timeout:
                pass
            lines = received.decode("utf-8", errors="replace").splitlines()
            results = [json.loads(line[len("RESULT:"):]) for line in lines if line.startswith("RESULT:")]
            (output / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
            if not results or not any(line.strip() == "GUEST_EXIT:0" for line in lines):
                raise RuntimeError("Guest did not produce successful result evidence")
            print(json.dumps({"output": str(output), "observations": len(results), "guest_exit": 0}))
        finally:
            if channel is not None:
                channel.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            metadata["qemu_exit"] = process.returncode
            (output / "command.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
