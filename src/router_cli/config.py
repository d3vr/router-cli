"""Configuration loading for router CLI."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def get_config_paths() -> list[Path]:
    """Return list of config file paths in order of priority."""
    return [
        Path.cwd() / "config.toml",
        Path.home() / ".config" / "router" / "config.toml",
        Path("/etc/router/config.toml"),
    ]


def _load_config_file() -> dict | None:
    """Load the raw config file if it exists."""
    for config_path in get_config_paths():
        if config_path.exists():
            with open(config_path, "rb") as f:
                return tomllib.load(f)
    return None


def load_config() -> dict:
    """Load configuration from TOML file.

    Searches for config in:
    1. ./config.toml (current directory)
    2. ~/.config/router/config.toml
    3. /etc/router/config.toml
    """
    config = _load_config_file()
    if config is not None:
        return config.get("router", {})

    raise FileNotFoundError(
        "No config.toml found. Create one at ~/.config/router/config.toml with:\n"
        "[router]\n"
        'ip = "192.168.1.1"\n'
        'username = "admin"\n'
        'password = "your_password"\n'
        "\n"
        "[known_devices]\n"
        '"AA:BB:CC:DD:EE:FF" = "My Phone"\n'
        '"11:22:33:44:55:66" = "Smart TV"'
    )


def load_known_devices() -> dict[str, str]:
    """Load known devices from config file.

    Returns a dict mapping MAC addresses (uppercase) to aliases.
    """
    config = _load_config_file()
    if config is None:
        return {}

    known = config.get("known_devices", {})
    # Normalize MAC addresses to uppercase for case-insensitive matching
    return {mac.upper(): alias for mac, alias in known.items()}
