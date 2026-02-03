"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def device_info_html() -> str:
    """Load the device info page HTML fixture."""
    return (FIXTURES_DIR / "device_info.html").read_text()


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to fixtures directory."""
    return FIXTURES_DIR
