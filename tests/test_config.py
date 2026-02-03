"""Tests for configuration loading."""

import pytest
from pathlib import Path

from router_cli.config import load_config, get_config_paths


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
        """Test that missing config raises FileNotFoundError."""
        monkeypatch.chdir(tmp_path)
        # Ensure no config exists in any search path
        monkeypatch.setattr(
            "router_cli.config.get_config_paths",
            lambda: [tmp_path / "nonexistent.toml"],
        )

        with pytest.raises(FileNotFoundError, match="No config.toml found"):
            load_config()

    def test_load_config_empty_router_section(self, tmp_path: Path, monkeypatch):
        """Test loading config with empty router section."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[other]\nkey = 'value'\n")
        monkeypatch.chdir(tmp_path)

        config = load_config()

        assert config == {}
