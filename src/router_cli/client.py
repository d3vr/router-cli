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
