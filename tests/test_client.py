"""Tests for router client and HTML parsing."""

import pytest

from router_cli.client import (
    RouterClient,
    RouterStatus,
    WirelessClient,
    DHCPLease,
    Route,
    InterfaceStats,
    ADSLStats,
    Statistics,
    LogEntry,
)


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


class TestWirelessClientsParsing:
    """Tests for wireless clients parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_wireless_clients(
        self, client: RouterClient, wlstationlist_html: str
    ):
        """Test wireless clients parsing."""
        clients = client._parse_wireless_clients(wlstationlist_html)
        assert len(clients) == 4

    def test_wireless_client_fields(
        self, client: RouterClient, wlstationlist_html: str
    ):
        """Test wireless client field values."""
        clients = client._parse_wireless_clients(wlstationlist_html)
        first = clients[0]
        assert first.mac == "AA:BB:CC:DD:01:01"
        assert first.associated is True
        assert first.authorized is True
        assert first.ssid == "MyNetwork"
        assert first.interface == "wl0"


class TestDHCPLeasesParsing:
    """Tests for DHCP leases parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_dhcp_leases(self, client: RouterClient, dhcpinfo_html: str):
        """Test DHCP leases parsing."""
        leases = client._parse_dhcp_leases(dhcpinfo_html)
        assert len(leases) == 7

    def test_dhcp_lease_fields(self, client: RouterClient, dhcpinfo_html: str):
        """Test DHCP lease field values."""
        leases = client._parse_dhcp_leases(dhcpinfo_html)
        first = leases[0]
        assert first.hostname == "wifi-extender"
        assert first.mac == "aa:bb:cc:dd:01:01"
        assert first.ip == "192.168.1.45"
        assert "22 hours" in first.expires_in


class TestRoutesParsing:
    """Tests for routing table parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_routes(self, client: RouterClient, routeinfo_html: str):
        """Test routing table parsing."""
        routes = client._parse_routes(routeinfo_html)
        assert len(routes) == 4

    def test_route_fields(self, client: RouterClient, routeinfo_html: str):
        """Test route field values."""
        routes = client._parse_routes(routeinfo_html)
        first = routes[0]
        assert first.destination == "203.0.113.50"
        assert first.gateway == "0.0.0.0"
        assert first.subnet_mask == "255.255.255.255"
        assert first.flag == "UH"
        assert first.metric == 0
        assert first.service == "pppoe_0_0_38"

    def test_default_route(self, client: RouterClient, routeinfo_html: str):
        """Test default route parsing."""
        routes = client._parse_routes(routeinfo_html)
        default = routes[-1]
        assert default.destination == "0.0.0.0"
        assert default.subnet_mask == "0.0.0.0"


class TestStatisticsParsing:
    """Tests for statistics parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_statistics(self, client: RouterClient, statistics_html: str):
        """Test statistics parsing."""
        stats = client._parse_statistics(statistics_html)
        assert stats is not None

    def test_lan_interfaces(self, client: RouterClient, statistics_html: str):
        """Test LAN interface stats parsing."""
        stats = client._parse_statistics(statistics_html)
        assert len(stats.lan_interfaces) == 5

    def test_lan_interface_values(self, client: RouterClient, statistics_html: str):
        """Test LAN interface stat values."""
        stats = client._parse_statistics(statistics_html)
        eth0 = stats.lan_interfaces[0]
        assert eth0.interface == "eth0"
        assert eth0.rx_bytes == 75423250
        assert eth0.tx_bytes == 770009076

    def test_wan_interfaces(self, client: RouterClient, statistics_html: str):
        """Test WAN interface stats parsing."""
        stats = client._parse_statistics(statistics_html)
        assert len(stats.wan_interfaces) == 3

    def test_adsl_stats(self, client: RouterClient, statistics_html: str):
        """Test ADSL stats parsing."""
        stats = client._parse_statistics(statistics_html)
        assert stats.adsl.mode == "ADSL_2plus"
        assert stats.adsl.status == "Up"
        assert stats.adsl.downstream_rate == 18525
        assert stats.adsl.upstream_rate == 738


class TestLogsParsing:
    """Tests for log parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_empty_logs(self, client: RouterClient, logview_html: str):
        """Test empty logs parsing."""
        logs = client._parse_logs(logview_html)
        # The fixture has an empty log table
        assert len(logs) == 0

    def test_parse_logs_with_entries(self, client: RouterClient):
        """Test parsing logs with actual entries."""
        html = """
        <table class=formlisting>
        <tr class=form_label_row>
            <td class='form_label_col'>Date/Time</td>
            <td class='form_label_col'>Facility</td>
            <td class='form_label_col'>Severity</td>
            <td class='form_label_col'>Message</td>
        </tr>
        <tr>
            <td>Feb 3 10:00:00</td>
            <td>kernel</td>
            <td>warning</td>
            <td>Link up on eth0</td>
        </tr>
        <tr>
            <td>Feb 3 09:55:00</td>
            <td>pppd</td>
            <td>info</td>
            <td>PPP connection established</td>
        </tr>
        </table>
        """
        logs = client._parse_logs(html)
        assert len(logs) == 2
        assert logs[0].datetime == "Feb 3 10:00:00"
        assert logs[0].facility == "kernel"
        assert logs[0].severity == "warning"
        assert logs[0].message == "Link up on eth0"
        assert logs[1].facility == "pppd"


class TestDataclassDefaults:
    """Tests for dataclass default values and mutability."""

    def test_wireless_client_fields(self):
        """Test WirelessClient dataclass."""
        client = WirelessClient(
            mac="AA:BB:CC:DD:EE:FF",
            associated=True,
            authorized=False,
            ssid="TestNetwork",
            interface="wl0",
        )
        assert client.mac == "AA:BB:CC:DD:EE:FF"
        assert client.associated is True
        assert client.authorized is False

    def test_dhcp_lease_fields(self):
        """Test DHCPLease dataclass."""
        lease = DHCPLease(
            hostname="mydevice",
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.168.1.100",
            expires_in="1 hour",
        )
        assert lease.hostname == "mydevice"
        assert lease.ip == "192.168.1.100"

    def test_route_fields(self):
        """Test Route dataclass."""
        route = Route(
            destination="0.0.0.0",
            gateway="192.168.1.1",
            subnet_mask="0.0.0.0",
            flag="UG",
            metric=100,
            service="ppp0",
        )
        assert route.destination == "0.0.0.0"
        assert route.metric == 100

    def test_interface_stats_fields(self):
        """Test InterfaceStats dataclass."""
        stats = InterfaceStats(
            interface="eth0",
            rx_bytes=1000,
            rx_packets=10,
            rx_errors=0,
            rx_drops=0,
            tx_bytes=2000,
            tx_packets=20,
            tx_errors=0,
            tx_drops=0,
        )
        assert stats.interface == "eth0"
        assert stats.rx_bytes == 1000
        assert stats.tx_bytes == 2000

    def test_adsl_stats_defaults(self):
        """Test ADSLStats default values."""
        adsl = ADSLStats()
        assert adsl.mode == ""
        assert adsl.status == ""
        assert adsl.downstream_rate == 0
        assert adsl.upstream_rate == 0
        assert adsl.downstream_snr_margin == 0.0

    def test_statistics_defaults(self):
        """Test Statistics default values."""
        stats = Statistics()
        assert stats.lan_interfaces == []
        assert stats.wan_interfaces == []
        assert isinstance(stats.adsl, ADSLStats)

    def test_statistics_mutable_defaults(self):
        """Test Statistics lists don't share state."""
        stats1 = Statistics()
        stats2 = Statistics()
        stats1.lan_interfaces.append(InterfaceStats("eth0", 0, 0, 0, 0, 0, 0, 0, 0))
        assert len(stats2.lan_interfaces) == 0

    def test_log_entry_fields(self):
        """Test LogEntry dataclass."""
        entry = LogEntry(
            datetime="Feb 3 10:00:00",
            facility="kernel",
            severity="error",
            message="Test message",
        )
        assert entry.datetime == "Feb 3 10:00:00"
        assert entry.severity == "error"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_parse_empty_wireless_clients(self, client: RouterClient):
        """Test parsing empty wireless clients table."""
        html = """
        <table class=formlisting>
        <tr class=form_label_row>
            <td>MAC</td><td>Associated</td><td>Authorized</td>
            <td>SSID</td><td>Interface</td>
        </tr>
        </table>
        """
        clients = client._parse_wireless_clients(html)
        assert len(clients) == 0

    def test_parse_empty_dhcp_leases(self, client: RouterClient):
        """Test parsing empty DHCP leases table."""
        html = """
        <table class=formlisting>
        <tr class=form_label_row>
            <td>Hostname</td><td>MAC</td><td>IP</td><td>Expires</td>
        </tr>
        </table>
        """
        leases = client._parse_dhcp_leases(html)
        assert len(leases) == 0

    def test_parse_empty_routes(self, client: RouterClient):
        """Test parsing empty routing table."""
        html = """
        <table class=formlisting>
        <tr class=form_label_row>
            <td>Destination</td><td>Gateway</td><td>Mask</td>
            <td>Flag</td><td>Metric</td><td>Service</td>
        </tr>
        </table>
        """
        routes = client._parse_routes(html)
        assert len(routes) == 0

    def test_parse_no_table_wireless(self, client: RouterClient):
        """Test parsing HTML without wireless table."""
        html = "<html><body>No table here</body></html>"
        clients = client._parse_wireless_clients(html)
        assert len(clients) == 0

    def test_parse_no_table_dhcp(self, client: RouterClient):
        """Test parsing HTML without DHCP table."""
        html = "<html><body>No table here</body></html>"
        leases = client._parse_dhcp_leases(html)
        assert len(leases) == 0

    def test_parse_no_table_routes(self, client: RouterClient):
        """Test parsing HTML without routing table."""
        html = "<html><body>No table here</body></html>"
        routes = client._parse_routes(html)
        assert len(routes) == 0

    def test_parse_no_table_logs(self, client: RouterClient):
        """Test parsing HTML without log table."""
        html = "<html><body>No table here</body></html>"
        logs = client._parse_logs(html)
        assert len(logs) == 0

    def test_parse_statistics_no_sections(self, client: RouterClient):
        """Test parsing statistics with no sections."""
        html = "<html><body>No stats here</body></html>"
        stats = client._parse_statistics(html)
        assert len(stats.lan_interfaces) == 0
        assert len(stats.wan_interfaces) == 0

    def test_extract_value_no_match(self, client: RouterClient):
        """Test _extract_value returns N/A when no match."""
        result = client._extract_value("<html>no match</html>", r"nonexistent: (\w+)")
        assert result == "N/A"

    def test_extract_value_multiple_patterns(self, client: RouterClient):
        """Test _extract_value tries multiple patterns."""
        html = "<td>Value: test123</td>"
        result = client._extract_value(
            html,
            r"NotFound: (\w+)",  # First pattern won't match
            r"Value: (\w+)",  # Second pattern will match
        )
        assert result == "test123"

    def test_route_non_numeric_metric(self, client: RouterClient):
        """Test route parsing handles non-numeric metric."""
        html = """
        <table class=formlisting>
        <tr>
            <td>192.168.1.0</td>
            <td>0.0.0.0</td>
            <td>255.255.255.0</td>
            <td>U</td>
            <td>notanumber</td>
            <td>eth0</td>
        </tr>
        </table>
        """
        routes = client._parse_routes(html)
        assert len(routes) == 1
        assert routes[0].metric == 0  # Should default to 0


class TestInfoHtmlParsing:
    """Tests for parsing info.html fixture."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    @pytest.fixture
    def status(self, client: RouterClient, info_html: str) -> RouterStatus:
        """Parse status from info.html fixture."""
        return client._parse_status(info_html)

    def test_parse_model_name_from_info(self, status: RouterStatus):
        """Test model name parsing from info.html."""
        assert status.model_name == "DSL-2750U"

    def test_parse_firmware_from_info(self, status: RouterStatus):
        """Test firmware version parsing from info.html."""
        assert status.firmware == "ME_1.00"

    def test_parse_gateway_from_info(self, status: RouterStatus):
        """Test default gateway parsing from info.html."""
        assert status.default_gateway == "203.0.113.1"


class TestWirelessClientsDetails:
    """Detailed tests for wireless clients parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_all_wireless_clients(self, client: RouterClient, wlstationlist_html: str):
        """Test all wireless clients are parsed correctly."""
        clients = client._parse_wireless_clients(wlstationlist_html)
        assert len(clients) == 4

        # Check each client has unique MAC
        macs = [c.mac for c in clients]
        assert len(set(macs)) == 4

        # All should be on same SSID and interface
        for c in clients:
            assert c.ssid == "MyNetwork"
            assert c.interface == "wl0"
            assert c.associated is True
            assert c.authorized is True

    def test_wireless_client_mac_formats(self, client: RouterClient):
        """Test various MAC address formats are parsed."""
        html = """
        <tr> <td><p align=center> aa:bb:cc:dd:ee:ff
        &nbsp </td> <td><p align=center> Yes </p></td> <td><p align=center> Yes </p></td>
        <td><p align=center> Test&nbsp </td>  <td><p align=center> wl0&nbsp </td>  </tr>
        """
        clients = client._parse_wireless_clients(html)
        assert len(clients) == 1
        assert clients[0].mac == "aa:bb:cc:dd:ee:ff"


class TestDHCPLeasesDetails:
    """Detailed tests for DHCP leases parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_all_dhcp_leases(self, client: RouterClient, dhcpinfo_html: str):
        """Test all DHCP leases are parsed correctly."""
        leases = client._parse_dhcp_leases(dhcpinfo_html)
        assert len(leases) == 7

        # Check each lease has unique IP
        ips = [l.ip for l in leases]
        assert len(set(ips)) == 7

        # Check IP range
        for lease in leases:
            assert lease.ip.startswith("192.168.1.")

    def test_dhcp_lease_expiry_formats(self, client: RouterClient, dhcpinfo_html: str):
        """Test DHCP lease expiry times are parsed."""
        leases = client._parse_dhcp_leases(dhcpinfo_html)
        for lease in leases:
            assert "hours" in lease.expires_in or "minutes" in lease.expires_in

    def test_specific_lease_values(self, client: RouterClient, dhcpinfo_html: str):
        """Test specific lease values."""
        leases = client._parse_dhcp_leases(dhcpinfo_html)

        # Check last lease
        last = leases[-1]
        assert last.hostname == "laptop-pc"
        assert last.ip == "192.168.1.52"


class TestRoutesDetails:
    """Detailed tests for routing table parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_all_routes(self, client: RouterClient, routeinfo_html: str):
        """Test all routes are parsed correctly."""
        routes = client._parse_routes(routeinfo_html)
        assert len(routes) == 4

    def test_route_flags(self, client: RouterClient, routeinfo_html: str):
        """Test route flags are parsed correctly."""
        routes = client._parse_routes(routeinfo_html)
        flags = [r.flag for r in routes]
        assert "UH" in flags
        assert "U" in flags

    def test_local_network_route(self, client: RouterClient, routeinfo_html: str):
        """Test local network route parsing."""
        routes = client._parse_routes(routeinfo_html)
        local = next(r for r in routes if r.destination == "192.168.1.0")
        assert local.subnet_mask == "255.255.255.0"
        assert local.flag == "U"
        assert local.service == ""

    def test_gateway_routes(self, client: RouterClient, routeinfo_html: str):
        """Test gateway routes parsing."""
        routes = client._parse_routes(routeinfo_html)
        gw_routes = [r for r in routes if r.service == "pppoe_0_0_38"]
        assert len(gw_routes) == 3


class TestStatisticsDetails:
    """Detailed tests for statistics parsing."""

    @pytest.fixture
    def client(self) -> RouterClient:
        """Create a test client instance."""
        return RouterClient("192.168.1.1", "admin", "test")

    def test_all_lan_interfaces(self, client: RouterClient, statistics_html: str):
        """Test all LAN interfaces are parsed."""
        stats = client._parse_statistics(statistics_html)
        assert len(stats.lan_interfaces) == 5

        # Check interface names
        names = [i.interface for i in stats.lan_interfaces]
        assert "eth0" in names
        assert "wl0" in names

    def test_inactive_interfaces(self, client: RouterClient, statistics_html: str):
        """Test inactive interfaces have zero stats."""
        stats = client._parse_statistics(statistics_html)
        eth1 = next(i for i in stats.lan_interfaces if i.interface == "eth1")
        assert eth1.rx_bytes == 0
        assert eth1.tx_bytes == 0

    def test_wireless_interface_stats(self, client: RouterClient, statistics_html: str):
        """Test wireless interface statistics."""
        stats = client._parse_statistics(statistics_html)
        wl0 = next(i for i in stats.lan_interfaces if i.interface == "wl0")
        assert wl0.rx_bytes == 20189548
        assert wl0.tx_bytes == 417006008
        assert wl0.rx_packets == 60115

    def test_wan_interface_stats(self, client: RouterClient, statistics_html: str):
        """Test WAN interface statistics."""
        stats = client._parse_statistics(statistics_html)
        assert len(stats.wan_interfaces) == 3

        ppp = next(i for i in stats.wan_interfaces if i.interface == "ppp0.1")
        assert ppp.rx_bytes == 1159357175
        assert ppp.tx_bytes == 84061012

    def test_adsl_snr_margin(self, client: RouterClient, statistics_html: str):
        """Test ADSL SNR margin parsing."""
        stats = client._parse_statistics(statistics_html)
        # Values in fixture: 44/10 = 4.4, 68/10 = 6.8
        assert stats.adsl.downstream_snr_margin == 4.4
        assert stats.adsl.upstream_snr_margin == 6.8

    def test_adsl_attenuation(self, client: RouterClient, statistics_html: str):
        """Test ADSL attenuation parsing."""
        stats = client._parse_statistics(statistics_html)
        # Values in fixture: 140/10 = 14.0, 224/10 = 22.4
        assert stats.adsl.downstream_attenuation == 14.0
        assert stats.adsl.upstream_attenuation == 22.4

    def test_adsl_output_power(self, client: RouterClient, statistics_html: str):
        """Test ADSL output power parsing."""
        stats = client._parse_statistics(statistics_html)
        # Values in fixture: 194/10 = 19.4, 125/10 = 12.5
        assert stats.adsl.downstream_output_power == 19.4
        assert stats.adsl.upstream_output_power == 12.5

    def test_adsl_attainable_rate(self, client: RouterClient, statistics_html: str):
        """Test ADSL attainable rate parsing."""
        stats = client._parse_statistics(statistics_html)
        assert stats.adsl.downstream_attainable_rate == 19412
        assert stats.adsl.upstream_attainable_rate == 925

    def test_adsl_traffic_type(self, client: RouterClient, statistics_html: str):
        """Test ADSL traffic type parsing."""
        stats = client._parse_statistics(statistics_html)
        assert stats.adsl.traffic_type == "ATM"

    def test_adsl_link_power_state(self, client: RouterClient, statistics_html: str):
        """Test ADSL link power state parsing."""
        stats = client._parse_statistics(statistics_html)
        assert stats.adsl.link_power_state == "L0"
