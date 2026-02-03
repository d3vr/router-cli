"""HTTP client for D-Link DSL-2750U router."""

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar


@dataclass
class RouterStatus:
    """Parsed router status information."""

    # System Info
    model_name: str = ""
    time_date: str = ""
    firmware: str = ""

    # Internet Info
    default_gateway: str = ""
    preferred_dns: str = ""
    alternate_dns: str = ""

    # WAN Connections
    wan_connections: list[dict] = field(default_factory=list)

    # Wireless Info
    ssid: str = ""
    wireless_mac: str = ""
    wireless_status: str = ""
    security_mode: str = ""

    # Local Network
    local_mac: str = ""
    local_ip: str = ""
    subnet_mask: str = ""
    dhcp_server: str = ""


@dataclass
class WirelessClient:
    """A connected wireless client."""

    mac: str
    associated: bool
    authorized: bool
    ssid: str
    interface: str


@dataclass
class DHCPLease:
    """A DHCP lease entry."""

    hostname: str
    mac: str
    ip: str
    expires_in: str


@dataclass
class Route:
    """A routing table entry."""

    destination: str
    gateway: str
    subnet_mask: str
    flag: str
    metric: int
    service: str


@dataclass
class InterfaceStats:
    """Statistics for a network interface."""

    interface: str
    rx_bytes: int
    rx_packets: int
    rx_errors: int
    rx_drops: int
    tx_bytes: int
    tx_packets: int
    tx_errors: int
    tx_drops: int


@dataclass
class ADSLStats:
    """ADSL line statistics."""

    mode: str = ""
    traffic_type: str = ""
    status: str = ""
    link_power_state: str = ""
    downstream_rate: int = 0
    upstream_rate: int = 0
    downstream_snr_margin: float = 0.0
    upstream_snr_margin: float = 0.0
    downstream_attenuation: float = 0.0
    upstream_attenuation: float = 0.0
    downstream_output_power: float = 0.0
    upstream_output_power: float = 0.0
    downstream_attainable_rate: int = 0
    upstream_attainable_rate: int = 0


@dataclass
class Statistics:
    """Network and ADSL statistics."""

    lan_interfaces: list[InterfaceStats] = field(default_factory=list)
    wan_interfaces: list[InterfaceStats] = field(default_factory=list)
    adsl: ADSLStats = field(default_factory=ADSLStats)


@dataclass
class LogEntry:
    """A system log entry."""

    datetime: str
    facility: str
    severity: str
    message: str


class RouterClient:
    """Client for communicating with D-Link DSL-2750U router."""

    def __init__(self, ip: str, username: str, password: str):
        self.ip = ip
        self.username = username
        self.password = password
        self.base_url = f"http://{ip}"
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self._authenticated = False

    def authenticate(self) -> bool:
        """Authenticate with the router.

        POST to /main with credentials in cookies and form data.
        """
        url = f"{self.base_url}/main"

        # URL-encode the password for form data (+ becomes %2B)
        encoded_password = urllib.parse.quote(self.password, safe="")
        form_data = f"username={self.username}&password={encoded_password}&loginfo=on"

        # Set auth cookies
        cookie_header = f"username={self.username}; password={self.password}"

        request = urllib.request.Request(
            url,
            data=form_data.encode("utf-8"),
            headers={
                "Cookie": cookie_header,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )

        try:
            with self.opener.open(request, timeout=10) as response:
                self._authenticated = response.status == 200
                return self._authenticated
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to connect to router at {self.ip}: {e}")

    def fetch_page(self, path: str) -> str:
        """Fetch a page from the router with authentication cookies."""
        if not self._authenticated:
            self.authenticate()

        url = f"{self.base_url}/{path.lstrip('/')}"
        cookie_header = f"username={self.username}; password={self.password}"

        request = urllib.request.Request(
            url, headers={"Cookie": cookie_header}, method="GET"
        )

        try:
            with self.opener.open(request, timeout=10) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {path}: {e}")

    def get_session_key(self, html: str) -> str:
        """Extract session key from HTML page."""
        match = re.search(r"var\s+sessionKey\s*=\s*[\"']([^\"']+)[\"']", html)
        if match:
            return match.group(1)
        raise ValueError("Could not find session key in page")

    def get_status(self) -> RouterStatus:
        """Fetch and parse router status."""
        html = self.fetch_page("/info.html")
        return self._parse_status(html)

    def _parse_status(self, html: str) -> RouterStatus:
        """Parse status information from HTML."""
        status = RouterStatus()

        # System Info - from JavaScript variables or table cells
        status.model_name = self._extract_value(
            html,
            r"var\s+modeName\s*=\s*[\"']([^\"']+)[\"']",
            r"Model Name:.*?<td[^>]*>([^<]+)</td>",
        )

        status.time_date = self._extract_value(
            html,
            # From document.writeln() in JS
            r"Time and Date:.*?<td>([^<]+)</td>",
            # Static HTML fallback
            r"Time and Date:.*?<td[^>]*>([^<]+)</td>",
        )

        status.firmware = self._extract_value(
            html,
            r"Firmware Version:\s*([A-Z0-9_.]+)",
            r"<td[^>]*>Firmware Version:</td>\s*<td[^>]*>([^<]+)</td>",
        )

        # Internet Info - parse from JS variables first, then static HTML
        status.default_gateway = self._extract_value(
            html,
            r"var\s+dfltGw\s*=\s*[\"']([^\"']+)[\"']",
            r"Default Gateway:.*?<td[^>]*>([^<]+)</td>",
        )

        status.preferred_dns = self._extract_value(
            html, r"Preferred DNS Server:.*?<td[^>]*>([^<]+)</td>"
        )

        status.alternate_dns = self._extract_value(
            html, r"Alternate DNS Server:.*?<td[^>]*>([^<]+)</td>"
        )

        # WAN Connections - parse table rows with class="hd"
        status.wan_connections = self._parse_wan_connections(html)

        # Wireless Info - find section and extract all values
        wireless_section = re.search(
            r"Wireless Info:.*?Local Network Info", html, re.DOTALL
        )
        if wireless_section:
            ws = wireless_section.group(0)
            status.ssid = self._extract_value(
                ws,
                r"<option[^>]*selected[^>]*>\s*([^<\n]+?)\s*</option>",
            )
            status.wireless_mac = self._extract_value(
                ws, r"MAC Address:.*?<td[^>]*>([^<]+)</td>"
            )
            status.wireless_status = self._extract_value(
                ws, r"Status:.*?<td[^>]*>([^<]+)</td>"
            )
            status.security_mode = self._extract_value(
                ws, r"Security Mode:.*?<td[^>]*>([^<]+)</td>"
            )

        # Local Network Info - find section after "Local Network Info"
        local_section = re.search(
            r"Local Network Info.*?(?:Storage Device|$)", html, re.DOTALL
        )
        if local_section:
            ls = local_section.group(0)
            # MAC address may have malformed HTML (</SPAN> without opening tag)
            status.local_mac = self._extract_value(
                ls,
                r"MAC Address:</TD>\s*<TD>([^<]+)",
                r"MAC Address:.*?<td[^>]*>([^<]+)</td>",
            )
            status.local_ip = self._extract_value(
                ls, r"IP Address:.*?<td[^>]*>([^<]+)</td>"
            )
            status.subnet_mask = self._extract_value(
                ls, r"Subnet Mask:.*?<td[^>]*>([^<]+)</td>"
            )
            # DHCP may be in document.writeln() or static HTML
            status.dhcp_server = self._extract_value(
                ls,
                r"DHCP Server:.*?<td>([^<]+)</td>",
                r"DHCP Server:.*?<td[^>]*>([^<]+)</td>",
            )

        return status

    def _extract_value(self, html: str, *patterns: str) -> str:
        """Try multiple regex patterns and return first match."""
        for pattern in patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                # Clean up HTML entities
                value = value.replace("&nbsp;", "").strip()
                if value:
                    return value
        return "N/A"

    def _parse_wan_connections(self, html: str) -> list[dict]:
        """Parse WAN connection table."""
        connections = []

        # Find the WAN connections table section
        wan_section = re.search(
            r"Enabled WAN Connections:.*?</table>", html, re.DOTALL | re.IGNORECASE
        )
        if not wan_section:
            return connections

        section = wan_section.group(0)

        # Find data rows - handle both single and double quotes
        # Pattern matches: <tr align='center'> or <tr align="center">
        rows = re.findall(
            r"<tr[^>]*align=[\"']center[\"'][^>]*>(.*?)</tr>",
            section,
            re.DOTALL | re.IGNORECASE,
        )

        for row in rows:
            # Match cells with class='hd' or class="hd"
            cells = re.findall(
                r"<td[^>]*class=[\"']hd[\"'][^>]*>([^<]*)</td>",
                row,
                re.IGNORECASE,
            )
            if len(cells) >= 4:
                connections.append(
                    {
                        "interface": cells[0].strip(),
                        "description": cells[1].strip(),
                        "status": cells[2].strip(),
                        "ipv4": cells[3].strip(),
                    }
                )

        return connections

    def reboot(self) -> bool:
        """Reboot the router."""
        # First get session key from internet.html
        html = self.fetch_page("/internet.html")
        session_key = self.get_session_key(html)

        # POST to rebootinfo.cgi
        url = f"{self.base_url}/rebootinfo.cgi?sessionKey={session_key}"
        cookie_header = f"username={self.username}; password={self.password}"

        request = urllib.request.Request(
            url, headers={"Cookie": cookie_header}, method="POST", data=b""
        )

        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status == 200
        except urllib.error.URLError:
            # Router may disconnect during reboot, this is expected
            return True

    def get_wireless_clients(self) -> list[WirelessClient]:
        """Fetch and parse wireless clients."""
        html = self.fetch_page("/wlstationlist.cmd")
        return self._parse_wireless_clients(html)

    def _parse_wireless_clients(self, html: str) -> list[WirelessClient]:
        """Parse wireless clients from HTML."""
        clients = []

        # Find all data rows in the table
        rows = re.findall(
            r"<tr>\s*<td><p align=center>\s*([A-Fa-f0-9:]+)\s*"
            r".*?<p align=center>\s*(Yes|No)\s*</p>.*?"
            r"<p align=center>\s*(Yes|No)\s*</p>.*?"
            r"<p align=center>\s*([^<&]+?)(?:&nbsp)?\s*</td>.*?"
            r"<p align=center>\s*([^<&]+?)(?:&nbsp)?\s*</td>",
            html,
            re.DOTALL | re.IGNORECASE,
        )

        for row in rows:
            mac, associated, authorized, ssid, interface = row
            clients.append(
                WirelessClient(
                    mac=mac.strip(),
                    associated=associated.lower() == "yes",
                    authorized=authorized.lower() == "yes",
                    ssid=ssid.strip(),
                    interface=interface.strip(),
                )
            )

        return clients

    def get_dhcp_leases(self) -> list[DHCPLease]:
        """Fetch and parse DHCP leases."""
        html = self.fetch_page("/dhcpinfo.html")
        return self._parse_dhcp_leases(html)

    def _parse_dhcp_leases(self, html: str) -> list[DHCPLease]:
        """Parse DHCP leases from HTML."""
        leases = []

        # Find the DHCP table section
        table_match = re.search(
            r"<table class=formlisting>.*?</table>", html, re.DOTALL | re.IGNORECASE
        )
        if not table_match:
            return leases

        table = table_match.group(0)

        # Find data rows (skip header row)
        rows = re.findall(
            r"<tr><td>([^<]*)</td><td>([^<]*)</td><td>([^<]*)</td><td>([^<]*)</td></tr>",
            table,
            re.IGNORECASE,
        )

        for row in rows:
            hostname, mac, ip, expires = row
            leases.append(
                DHCPLease(
                    hostname=hostname.strip(),
                    mac=mac.strip(),
                    ip=ip.strip(),
                    expires_in=expires.strip(),
                )
            )

        return leases

    def get_routes(self) -> list[Route]:
        """Fetch and parse routing table."""
        html = self.fetch_page("/rtroutecfg.cmd?action=dlinkau")
        return self._parse_routes(html)

    def _parse_routes(self, html: str) -> list[Route]:
        """Parse routing table from HTML."""
        routes = []

        # Find the routing table
        table_match = re.search(
            r"<table class=formlisting>.*?</table>", html, re.DOTALL | re.IGNORECASE
        )
        if not table_match:
            return routes

        table = table_match.group(0)

        # Find data rows - 6 cells per row
        rows = re.findall(
            r"<tr>\s*"
            r"<td>([^<]*)</td>\s*"
            r"<td>([^<]*)</td>\s*"
            r"<td>([^<]*)</td>\s*"
            r"<td>([^<]*)</td>\s*"
            r"<td>([^<]*)</td>\s*"
            r"<td>([^<]*)</td>\s*"
            r"</tr>",
            table,
            re.IGNORECASE,
        )

        for row in rows:
            dest, gw, mask, flag, metric, service = row
            # Skip header row
            if "Destination" in dest:
                continue
            routes.append(
                Route(
                    destination=dest.strip(),
                    gateway=gw.strip(),
                    subnet_mask=mask.strip(),
                    flag=flag.strip(),
                    metric=int(metric.strip()) if metric.strip().isdigit() else 0,
                    service=service.replace("&nbsp;", "").strip(),
                )
            )

        return routes

    def get_statistics(self) -> Statistics:
        """Fetch and parse network statistics."""
        html = self.fetch_page("/statsifcwanber.html")
        return self._parse_statistics(html)

    def _parse_statistics(self, html: str) -> Statistics:
        """Parse statistics from HTML."""
        stats = Statistics()

        # Parse LAN interface stats - look for rows with 9 cells
        lan_section = re.search(
            r"Local Network.*?</table>", html, re.DOTALL | re.IGNORECASE
        )
        if lan_section:
            stats.lan_interfaces = self._parse_interface_stats(lan_section.group(0))

        # Parse WAN interface stats
        wan_section = re.search(
            r"<td class=topheader>\s*Internet\s*</td>.*?</table>",
            html,
            re.DOTALL | re.IGNORECASE,
        )
        if wan_section:
            stats.wan_interfaces = self._parse_wan_interface_stats(wan_section.group(0))

        # Parse ADSL stats
        stats.adsl = self._parse_adsl_stats(html)

        return stats

    def _parse_interface_stats(self, html: str) -> list[InterfaceStats]:
        """Parse interface statistics table."""
        interfaces = []

        # Find rows with 9 numeric values
        rows = re.findall(
            r"<tr>\s*<td class='hd'>.*?</script>\s*</td>\s*"
            r"<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*"
            r"<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*</tr>",
            html,
            re.DOTALL | re.IGNORECASE,
        )

        # Extract interface names from script blocks
        intf_names = re.findall(
            r"brdIntf\s*=\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE
        )

        for i, row in enumerate(rows):
            intf_name = (
                intf_names[i].split("|")[-1] if i < len(intf_names) else f"eth{i}"
            )
            (
                rx_bytes,
                rx_pkts,
                rx_errs,
                rx_drops,
                tx_bytes,
                tx_pkts,
                tx_errs,
                tx_drops,
            ) = row
            interfaces.append(
                InterfaceStats(
                    interface=intf_name,
                    rx_bytes=int(rx_bytes),
                    rx_packets=int(rx_pkts),
                    rx_errors=int(rx_errs),
                    rx_drops=int(rx_drops),
                    tx_bytes=int(tx_bytes),
                    tx_packets=int(tx_pkts),
                    tx_errors=int(tx_errs),
                    tx_drops=int(tx_drops),
                )
            )

        return interfaces

    def _parse_wan_interface_stats(self, html: str) -> list[InterfaceStats]:
        """Parse WAN interface statistics table."""
        interfaces = []

        # Find rows with interface name, description, and 8 numeric values
        rows = re.findall(
            r"<tr>\s*<td class='hd'>([^<]+)</td>\s*"
            r"<td>([^<]+)</td>\s*"
            r"<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*"
            r"<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*<td>(\d+)</td>\s*</tr>",
            html,
            re.DOTALL | re.IGNORECASE,
        )

        for row in rows:
            (
                intf_name,
                _desc,
                rx_bytes,
                rx_pkts,
                rx_errs,
                rx_drops,
                tx_bytes,
                tx_pkts,
                tx_errs,
                tx_drops,
            ) = row
            interfaces.append(
                InterfaceStats(
                    interface=intf_name.strip(),
                    rx_bytes=int(rx_bytes),
                    rx_packets=int(rx_pkts),
                    rx_errors=int(rx_errs),
                    rx_drops=int(rx_drops),
                    tx_bytes=int(tx_bytes),
                    tx_packets=int(tx_pkts),
                    tx_errors=int(tx_errs),
                    tx_drops=int(tx_drops),
                )
            )

        return interfaces

    def _parse_adsl_stats(self, html: str) -> ADSLStats:
        """Parse ADSL statistics from HTML."""
        adsl = ADSLStats()

        adsl.mode = self._extract_value(html, r"Mode:</td><td>([^<]+)</td>")
        adsl.traffic_type = self._extract_value(
            html, r"Traffic Type:</td><td>([^<]+)</td>"
        )
        adsl.status = self._extract_value(html, r"Status:</td><td>([^<]+)</td>")
        adsl.link_power_state = self._extract_value(
            html, r"Link Power State:</td><td>([^<]+)</td>"
        )

        # Parse rate info - downstream and upstream
        rate_match = re.search(
            r"Rate \(Kbps\):</td><td>(\d+)</td><td>(\d+)</td>", html, re.IGNORECASE
        )
        if rate_match:
            adsl.downstream_rate = int(rate_match.group(1))
            adsl.upstream_rate = int(rate_match.group(2))

        # Parse SNR margin
        snr_match = re.search(
            r"SNR Margin.*?<td>(\d+)</td><td>(\d+)</td>", html, re.IGNORECASE
        )
        if snr_match:
            adsl.downstream_snr_margin = float(snr_match.group(1)) / 10
            adsl.upstream_snr_margin = float(snr_match.group(2)) / 10

        # Parse attenuation
        atten_match = re.search(
            r"Attenuation.*?<td>(\d+)</td><td>(\d+)</td>", html, re.IGNORECASE
        )
        if atten_match:
            adsl.downstream_attenuation = float(atten_match.group(1)) / 10
            adsl.upstream_attenuation = float(atten_match.group(2)) / 10

        # Parse output power
        power_match = re.search(
            r"Output Power.*?<td>(\d+)</td><td>(\d+)</td>", html, re.IGNORECASE
        )
        if power_match:
            adsl.downstream_output_power = float(power_match.group(1)) / 10
            adsl.upstream_output_power = float(power_match.group(2)) / 10

        # Parse attainable rate
        attain_match = re.search(
            r"Attainable Rate.*?<td>(\d+)</td><td>(\d+)</td>", html, re.IGNORECASE
        )
        if attain_match:
            adsl.downstream_attainable_rate = int(attain_match.group(1))
            adsl.upstream_attainable_rate = int(attain_match.group(2))

        return adsl

    def get_logs(self) -> list[LogEntry]:
        """Fetch and parse system logs."""
        html = self.fetch_page("/logview.cmd")
        return self._parse_logs(html)

    def _parse_logs(self, html: str) -> list[LogEntry]:
        """Parse system logs from HTML."""
        logs = []

        # Find the log table
        table_match = re.search(
            r"<table class=formlisting>.*?</table>", html, re.DOTALL | re.IGNORECASE
        )
        if not table_match:
            return logs

        table = table_match.group(0)

        # Find data rows - 4 cells per row
        rows = re.findall(
            r"<tr>\s*"
            r"<td[^>]*>([^<]*)</td>\s*"
            r"<td[^>]*>([^<]*)</td>\s*"
            r"<td[^>]*>([^<]*)</td>\s*"
            r"<td[^>]*>([^<]*)</td>\s*"
            r"</tr>",
            table,
            re.IGNORECASE,
        )

        for row in rows:
            datetime_str, facility, severity, message = row
            # Skip header row
            if "Date/Time" in datetime_str:
                continue
            logs.append(
                LogEntry(
                    datetime=datetime_str.strip(),
                    facility=facility.strip(),
                    severity=severity.strip(),
                    message=message.strip(),
                )
            )

        return logs
