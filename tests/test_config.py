"""Tests for configuration loading."""

import pytest
from pathlib import Path

from router_cli.config import (
    load_config,
    get_config_paths,
    load_known_devices,
    KnownDevices,
)


class TestConfigPaths:
    """Tests for config path resolution."""

    def test_get_config_paths_returns_list(self):
        """Test that get_config_paths returns a list of paths."""
        paths = get_config_paths()
        assert isinstance(paths, list)
        assert len(paths) >= 3

    def test_config_paths_are_path_objects(self):
        """Test that all config paths are Path objects."""
        paths = get_config_paths()
        for path in paths:
            assert isinstance(path, Path)

    def test_config_paths_priority_order(self):
        """Test config paths are in correct priority order."""
        paths = get_config_paths()
        # First should be current directory
        assert paths[0] == Path.cwd() / "config.toml"
        # Second should be user config
        assert paths[1] == Path.home() / ".config" / "router" / "config.toml"


class TestLoadConfig:
    """Tests for config loading."""

    def test_load_config_from_cwd(self, tmp_path: Path, monkeypatch):
        """Test loading config from current working directory."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[router]
ip = "10.0.0.1"
username = "testuser"
password = "testpass"
""")
        monkeypatch.chdir(tmp_path)

        config = load_config()

        assert config["ip"] == "10.0.0.1"
        assert config["username"] == "testuser"
        assert config["password"] == "testpass"

    def test_load_config_missing_raises(self, tmp_path: Path, monkeypatch):
        """Test that missing config without password raises FileNotFoundError."""
        monkeypatch.chdir(tmp_path)
        # Ensure no config exists in any search path
        monkeypatch.setattr(
            "router_cli.config.get_config_paths",
            lambda: [tmp_path / "nonexistent.toml"],
        )
        # Also ensure no environment variables are set
        monkeypatch.delenv("ROUTER_PASS", raising=False)

        with pytest.raises(FileNotFoundError, match="No password configured"):
            load_config()

    def test_load_config_empty_router_section(self, tmp_path: Path, monkeypatch):
        """Test loading config with empty router section uses defaults."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[router]\npassword = 'test'\n")
        monkeypatch.chdir(tmp_path)

        config = load_config()

        # Should have defaults plus the password from file
        assert config["ip"] == "192.168.1.1"
        assert config["username"] == "admin"
        assert config["password"] == "test"

    def test_load_config_env_vars_override(self, tmp_path: Path, monkeypatch):
        """Test environment variables override config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[router]
ip = "10.0.0.1"
username = "fileuser"
password = "filepass"
""")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ROUTER_IP", "172.16.0.1")
        monkeypatch.setenv("ROUTER_USER", "envuser")
        monkeypatch.setenv("ROUTER_PASS", "envpass")

        config = load_config()

        assert config["ip"] == "172.16.0.1"
        assert config["username"] == "envuser"
        assert config["password"] == "envpass"

    def test_load_config_cli_overrides_all(self, tmp_path: Path, monkeypatch):
        """Test CLI arguments override both env vars and config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[router]
ip = "10.0.0.1"
username = "fileuser"
password = "filepass"
""")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ROUTER_IP", "172.16.0.1")

        config = load_config(
            cli_ip="192.168.100.1", cli_user="cliuser", cli_pass="clipass"
        )

        assert config["ip"] == "192.168.100.1"
        assert config["username"] == "cliuser"
        assert config["password"] == "clipass"


class TestKnownDevices:
    """Tests for KnownDevices class."""

    def test_empty_known_devices(self):
        """Test empty KnownDevices returns None for lookups."""
        known = KnownDevices()
        assert known.get_alias("AA:BB:CC:DD:EE:FF") is None
        assert known.get_alias("AA:BB:CC:DD:EE:FF", "some-host") is None
        assert not known.is_known("AA:BB:CC:DD:EE:FF")

    def test_mac_lookup(self):
        """Test MAC address lookup."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        assert known.get_alias("AA:BB:CC:DD:EE:FF") == "My Phone"
        assert known.is_known("AA:BB:CC:DD:EE:FF")

    def test_mac_lookup_case_insensitive(self):
        """Test MAC address lookup is case-insensitive."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        assert known.get_alias("aa:bb:cc:dd:ee:ff") == "My Phone"
        assert known.get_alias("Aa:Bb:Cc:Dd:Ee:Ff") == "My Phone"

    def test_hostname_lookup(self):
        """Test hostname lookup."""
        known = KnownDevices(by_hostname={"android-abc123": "John's Pixel"})
        assert known.get_alias("XX:XX:XX:XX:XX:XX", "android-abc123") == "John's Pixel"
        assert known.is_known("XX:XX:XX:XX:XX:XX", "android-abc123")

    def test_hostname_lookup_case_insensitive(self):
        """Test hostname lookup is case-insensitive."""
        known = KnownDevices(by_hostname={"android-abc123": "John's Pixel"})
        assert known.get_alias("XX:XX:XX:XX:XX:XX", "Android-ABC123") == "John's Pixel"
        assert known.get_alias("XX:XX:XX:XX:XX:XX", "ANDROID-ABC123") == "John's Pixel"

    def test_mac_takes_priority_over_hostname(self):
        """Test MAC lookup takes priority over hostname."""
        known = KnownDevices(
            by_mac={"AA:BB:CC:DD:EE:FF": "MAC Device"},
            by_hostname={"some-host": "Hostname Device"},
        )
        # Even when hostname matches, MAC should win
        assert known.get_alias("AA:BB:CC:DD:EE:FF", "some-host") == "MAC Device"

    def test_hostname_fallback_when_mac_not_found(self):
        """Test hostname is used when MAC is not in known devices."""
        known = KnownDevices(
            by_mac={"11:22:33:44:55:66": "Other Device"},
            by_hostname={"android-phone": "Android"},
        )
        # MAC not in list, but hostname is
        assert known.get_alias("AA:BB:CC:DD:EE:FF", "android-phone") == "Android"

    def test_backward_compatible_get(self):
        """Test dict-like get() for backward compatibility."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        assert known.get("AA:BB:CC:DD:EE:FF") == "My Phone"
        assert known.get("XX:XX:XX:XX:XX:XX") is None
        assert known.get("XX:XX:XX:XX:XX:XX", "default") == "default"

    def test_backward_compatible_contains(self):
        """Test dict-like __contains__ for backward compatibility."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        assert "AA:BB:CC:DD:EE:FF" in known
        assert "XX:XX:XX:XX:XX:XX" not in known


class TestLoadKnownDevices:
    """Tests for load_known_devices function."""

    def test_load_mac_addresses(self, tmp_path: Path, monkeypatch):
        """Test loading MAC addresses from config."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[known_devices]
"AA:BB:CC:DD:EE:FF" = "My Phone"
"11:22:33:44:55:66" = "Smart TV"
""")
        monkeypatch.chdir(tmp_path)

        known = load_known_devices()

        assert known.get_alias("AA:BB:CC:DD:EE:FF") == "My Phone"
        assert known.get_alias("11:22:33:44:55:66") == "Smart TV"

    def test_load_hostnames(self, tmp_path: Path, monkeypatch):
        """Test loading hostnames from config."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[known_devices]
"android-abc123" = "John's Pixel"
"Galaxy-S24" = "Sarah's Phone"
""")
        monkeypatch.chdir(tmp_path)

        known = load_known_devices()

        assert known.get_alias("XX:XX:XX:XX:XX:XX", "android-abc123") == "John's Pixel"
        assert known.get_alias("YY:YY:YY:YY:YY:YY", "Galaxy-S24") == "Sarah's Phone"

    def test_load_mixed_mac_and_hostname(self, tmp_path: Path, monkeypatch):
        """Test loading both MAC addresses and hostnames."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[known_devices]
"AA:BB:CC:DD:EE:FF" = "My Phone"
"android-abc123" = "John's Pixel"
""")
        monkeypatch.chdir(tmp_path)

        known = load_known_devices()

        # MAC lookup
        assert known.get_alias("AA:BB:CC:DD:EE:FF") == "My Phone"
        # Hostname lookup
        assert known.get_alias("XX:XX:XX:XX:XX:XX", "android-abc123") == "John's Pixel"
        # Unknown device
        assert known.get_alias("XX:XX:XX:XX:XX:XX", "unknown-host") is None

    def test_load_empty_returns_empty_known_devices(self, tmp_path: Path, monkeypatch):
        """Test loading empty config returns empty KnownDevices."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[router]\nip = '192.168.1.1'\n")
        monkeypatch.chdir(tmp_path)

        known = load_known_devices()

        assert not known.is_known("AA:BB:CC:DD:EE:FF")
        assert not known.is_known("XX:XX:XX:XX:XX:XX", "any-host")
