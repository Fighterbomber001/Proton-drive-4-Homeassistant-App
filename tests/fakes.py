from __future__ import annotations

from pathlib import Path
import sys


def python_executable() -> str:
    executable = Path(sys.executable)
    if executable.is_file():
        return str(executable)
    windows_launcher = executable.parent / "python.exe"
    if windows_launcher.is_file():
        return str(windows_launcher)
    raise RuntimeError("No runnable Python interpreter found")


def write_python_script(root: Path, name: str, source: str) -> Path:
    path = root / name
    path.write_text(source, encoding="utf-8")
    return path
