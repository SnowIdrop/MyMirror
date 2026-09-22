"""Use the existing offline oracle, relocating only the moved workspace paths."""
import importlib.util
from pathlib import Path

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gateway_oracle", root / "tools/oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
oracle.TOOLS = root.parent.parent / "MirrorNiXiang/reverse/tools"
oracle.ORIGINAL = oracle.TOOLS.parent / "extracted/chatgpt-mirror-gateway"
oracle.main()
