"""Tests for CLI main module."""

import pytest

from router_cli.models import RouterStatus, WANConnection
from router_cli.formatters import format_status


class TestFormatStatus:
    """Tests for status output formatting."""

    @pytest.fixture
    def sample_status(self) -> RouterStatus:
        """Create a sample status for testing."""
        return RouterStatus(
            model_name="DSL-2750U",
            time_date="Mon Jan 1 12:00:00 2024",
            firmware="ME_1.00",
            default_gateway="192.168.1.1",
            preferred_dns="8.8.8.8",
            alternate_dns="8.8.4.4",
            wan_connections=[
                WANConnection(
                    interface="ADSL",
                    description="pppoe_0_0_38",
                    status="Connected",
                    ipv4="1.2.3.4",
                )
            ],
            ssid="MyNetwork",
            wireless_mac="AA:BB:CC:DD:EE:FF",
            wireless_status="Enabled",
            security_mode="WPA2",
            local_mac="11:22:33:44:55:66",
            local_ip="192.168.1.1",
            subnet_mask="255.255.255.0",
            dhcp_server="Enabled",
        )

    def test_format_includes_header(self, sample_status: RouterStatus):
        """Test output includes header."""
        output = format_status(sample_status)
        assert "ROUTER STATUS" in output
        assert "=" * 50 in output

    def test_format_includes_system_info(self, sample_status: RouterStatus):
        """Test output includes system info section."""
        output = format_status(sample_status)
        assert "SYSTEM INFO" in output
        assert "DSL-2750U" in output
        assert "ME_1.00" in output

    def test_format_includes_internet_info(self, sample_status: RouterStatus):
        """Test output includes internet info section."""
        output = format_status(sample_status)
        assert "INTERNET INFO" in output
        assert "192.168.1.1" in output
        assert "8.8.8.8" in output

    def test_format_includes_wan_connections(self, sample_status: RouterStatus):
        """Test output includes WAN connections table."""
        output = format_status(sample_status)
        assert "WAN Connections:" in output
        assert "ADSL" in output
        assert "Connected" in output

    def test_format_includes_wireless_info(self, sample_status: RouterStatus):
        """Test output includes wireless info section."""
        output = format_status(sample_status)
        assert "WIRELESS INFO" in output
        assert "MyNetwork" in output
        assert "WPA2" in output

    def test_format_includes_local_network(self, sample_status: RouterStatus):
        """Test output includes local network section."""
        output = format_status(sample_status)
        assert "LOCAL NETWORK" in output
        assert "255.255.255.0" in output
        assert "Enabled" in output

    def test_format_empty_wan_connections(self):
        """Test formatting with no WAN connections."""
        status = RouterStatus()
        output = format_status(status)
        assert "WAN Connections:" not in output
