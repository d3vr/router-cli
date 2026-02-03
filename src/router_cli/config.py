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
        '"AA:BB:CC:DD:EE:FF" = "My Phone"      # by MAC address\n'
        '"android-abc123" = "Pixel Phone"     # by hostname (for random MACs)'
    )


def _is_mac_address(identifier: str) -> bool:
    """Check if a string looks like a MAC address.

    MAC addresses contain colons and are in format XX:XX:XX:XX:XX:XX
    """
    import re

    # Match typical MAC address formats (with colons)
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", identifier))


class KnownDevices:
    """Container for known devices, supporting lookup by MAC or hostname.

    This class supports devices that use random MAC addresses by allowing
    hostname-based identification in addition to MAC-based.
    """

    def __init__(
        self,
        by_mac: dict[str, str] | None = None,
        by_hostname: dict[str, str] | None = None,
    ):
        self.by_mac: dict[str, str] = by_mac or {}
        self.by_hostname: dict[str, str] = by_hostname or {}

    def get_alias(self, mac: str, hostname: str = "") -> str | None:
        """Get alias for a device by MAC or hostname.

        MAC lookup takes priority. Returns None if device is not known.
        """
        # First try MAC lookup (normalized to uppercase)
        alias = self.by_mac.get(mac.upper())
        if alias:
            return alias

        # Then try hostname lookup (case-insensitive)
        if hostname:
            alias = self.by_hostname.get(hostname.lower())
            if alias:
                return alias

        return None

    def is_known(self, mac: str, hostname: str = "") -> bool:
        """Check if a device is known by MAC or hostname."""
        return self.get_alias(mac, hostname) is not None

    def get(self, key: str, default: str | None = None) -> str | None:
        """Dict-like get for backward compatibility (MAC lookup only)."""
        return self.by_mac.get(key, default)

    def __contains__(self, key: str) -> bool:
        """Dict-like contains for backward compatibility (MAC lookup only)."""
        return key in self.by_mac


def load_known_devices() -> KnownDevices:
    """Load known devices from config file.

    Returns a KnownDevices object supporting lookup by MAC address or hostname.

    Config format:
        [known_devices]
        "AA:BB:CC:DD:EE:FF" = "My Phone"      # MAC-based (for stable MACs)
        "android-abc123" = "John's Pixel"     # Hostname-based (for random MACs)

    MAC addresses are identified by format (XX:XX:XX:XX:XX:XX with colons).
    Any other identifier is treated as a hostname.
    """
    config = _load_config_file()
    if config is None:
        return KnownDevices()

    known = config.get("known_devices", {})

    by_mac: dict[str, str] = {}
    by_hostname: dict[str, str] = {}

    for identifier, alias in known.items():
        if _is_mac_address(identifier):
            # MAC address - normalize to uppercase
            by_mac[identifier.upper()] = alias
        else:
            # Hostname - normalize to lowercase for case-insensitive matching
            by_hostname[identifier.lower()] = alias

    return KnownDevices(by_mac=by_mac, by_hostname=by_hostname)
