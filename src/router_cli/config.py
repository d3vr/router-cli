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


def load_config() -> dict:
    """Load configuration from TOML file.

    Searches for config in:
    1. ./config.toml (current directory)
    2. ~/.config/router/config.toml
    3. /etc/router/config.toml
    """
    for config_path in get_config_paths():
        if config_path.exists():
            with open(config_path, "rb") as f:
                config = tomllib.load(f)
                return config.get("router", {})

    raise FileNotFoundError(
        "No config.toml found. Create one at ~/.config/router/config.toml with:\n"
        "[router]\n"
        'ip = "192.168.1.1"\n'
        'username = "admin"\n'
        'password = "your_password"'
    )
