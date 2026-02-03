"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def device_info_html() -> str:
    """Load the device info page HTML fixture."""
    return (FIXTURES_DIR / "device_info.html").read_text()


@pytest.fixture
def info_html() -> str:
    """Load the info page HTML fixture."""
    return (FIXTURES_DIR / "info.html").read_text()


@pytest.fixture
def wlstationlist_html() -> str:
    """Load the wireless station list HTML fixture."""
    return (FIXTURES_DIR / "wlstationlist.html").read_text()


@pytest.fixture
def dhcpinfo_html() -> str:
    """Load the DHCP info HTML fixture."""
    return (FIXTURES_DIR / "dhcpinfo.html").read_text()


@pytest.fixture
def logview_html() -> str:
    """Load the log view HTML fixture."""
    return (FIXTURES_DIR / "logview.html").read_text()


@pytest.fixture
def statistics_html() -> str:
    """Load the statistics HTML fixture."""
    return (FIXTURES_DIR / "statistics.html").read_text()


@pytest.fixture
def routeinfo_html() -> str:
    """Load the route info HTML fixture."""
    return (FIXTURES_DIR / "routeinfo.html").read_text()


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to fixtures directory."""
    return FIXTURES_DIR
