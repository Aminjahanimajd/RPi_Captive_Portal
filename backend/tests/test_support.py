from pathlib import Path
import sys


def ensure_backend_path() -> Path:
    """Ensure backend directory is available on sys.path for test imports."""
    backend_root = Path(__file__).resolve().parents[1]
    backend_str = str(backend_root)
    if backend_str not in sys.path:
        sys.path.insert(0, backend_str)
    return backend_root
