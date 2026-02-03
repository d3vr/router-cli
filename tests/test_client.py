"""Tests for router client and HTML parsing."""

import pytest

from router_cli.client import RouterClient, RouterStatus


class TestRouterClient:
    """Tests for RouterClient class."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient(ip="192.168.1.1", username="admin", password="testpass")

    def test_client_initialization(self, client: RouterClient):
        """Test client initializes with correct attributes."""
        assert client.ip == "192.168.1.1"
        assert client.username == "admin"
        assert client.password == "testpass"
        assert client.base_url == "http://192.168.1.1"
        assert client._authenticated is False

    def test_get_session_key(self, client: RouterClient, device_info_html: str):
        """Test session key extraction from HTML."""
        session_key = client.get_session_key(device_info_html)
        assert session_key == "123456789"

    def test_get_session_key_missing(self, client: RouterClient):
        """Test session key extraction fails gracefully."""
        with pytest.raises(ValueError, match="Could not find session key"):
            client.get_session_key("<html>no session key here</html>")


class TestStatusParsing:
    """Tests for HTML status parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    @pytest.fixture
    def status(self, client: RouterClient, device_info_html: str) -> RouterStatus:
        """Parse status from fixture HTML."""
        return client._parse_status(device_info_html)

    def test_parse_model_name(self, status: RouterStatus):
        """Test model name parsing."""
        assert status.model_name == "DSL-2750U"

    def test_parse_firmware(self, status: RouterStatus):
        """Test firmware version parsing."""
        assert status.firmware == "ME_1.00"

    def test_parse_time_date(self, status: RouterStatus):
        """Test time and date parsing."""
        assert "Feb" in status.time_date
        assert "2026" in status.time_date

    def test_parse_default_gateway(self, status: RouterStatus):
        """Test default gateway parsing."""
        assert status.default_gateway == "203.0.113.1"

    def test_parse_dns_servers(self, status: RouterStatus):
        """Test DNS server parsing."""
        assert status.preferred_dns == "1.1.1.1"
        assert status.alternate_dns == "1.0.0.1"

    def test_parse_wan_connections(self, status: RouterStatus):
        """Test WAN connections table parsing."""
        assert len(status.wan_connections) == 1
        conn = status.wan_connections[0]
        assert conn["interface"] == "ADSL"
        assert conn["description"] == "pppoe_0_0_38"
        assert conn["status"] == "Connected"
        assert conn["ipv4"] == "203.0.113.100"

    def test_parse_wireless_info(self, status: RouterStatus):
        """Test wireless info parsing."""
        assert status.ssid == "MyNetwork"
        assert status.wireless_mac == "AA:BB:CC:DD:EE:01"
        assert status.wireless_status == "Enabled"
        assert status.security_mode == "WPA"

    def test_parse_local_network(self, status: RouterStatus):
        """Test local network info parsing."""
        assert status.local_mac == "aa:bb:cc:dd:ee:00"
        assert status.local_ip == "192.168.1.1"
        assert status.subnet_mask == "255.255.255.0"
        assert status.dhcp_server == "Enabled"


class TestStatusDataclass:
    """Tests for RouterStatus dataclass."""

    def test_default_values(self):
        """Test RouterStatus has sensible defaults."""
        status = RouterStatus()
        assert status.model_name == ""
        assert status.wan_connections == []
        assert status.firmware == ""

    def test_wan_connections_mutable_default(self):
        """Test wan_connections doesn't share state between instances."""
        status1 = RouterStatus()
        status2 = RouterStatus()
        status1.wan_connections.append({"test": "value"})
        assert len(status2.wan_connections) == 0
