import os


def _set_default_env(key: str, value: str) -> None:
    if not os.environ.get(key):
        os.environ[key] = value


def load_runtime_profile() -> str:
    """Apply singleton runtime defaults for venv-first deployments."""
    requested = os.environ.get("RUNTIME_PROFILE", "auto").strip().lower()
    if requested in ("", "auto"):
        profile = "windows-venv" if os.name == "nt" else "linux-rpi-venv"
    else:
        profile = requested

    if profile == "windows-venv":
        defaults = {
            "DATA_DIR": os.path.abspath(os.environ.get("DATA_DIR", "data")),
            "DATABASE": os.path.abspath(os.environ.get("DATABASE", os.path.join("data", "db", "portal.db"))),
            "FEDERATION_MOUNT_MODE": os.environ.get("FEDERATION_MOUNT_MODE", "simulation"),
            "ALLOW_SIMULATION_FALLBACK": os.environ.get("ALLOW_SIMULATION_FALLBACK", "1"),
            "FLASK_ENV": os.environ.get("FLASK_ENV", "development"),
        }
    elif profile == "linux-rpi-venv":
        defaults = {
            "DATA_DIR": os.environ.get("DATA_DIR", "/var/lib/captive-portal"),
            "DATABASE": os.environ.get("DATABASE", "/var/lib/captive-portal/db/portal.db"),
            "FEDERATION_MOUNT_MODE": os.environ.get("FEDERATION_MOUNT_MODE", "auto"),
            "ALLOW_SIMULATION_FALLBACK": os.environ.get("ALLOW_SIMULATION_FALLBACK", "0"),
            "FLASK_ENV": os.environ.get("FLASK_ENV", "production"),
        }
    else:
        # Unknown profile: keep current environment untouched except profile tag.
        defaults = {}

    for key, value in defaults.items():
        _set_default_env(key, value)

    os.environ["RUNTIME_PROFILE"] = profile
    return profile
