"""HTTP client for D-Link DSL-2750U router."""

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

from .models import (
    ADSLStats,
    AuthenticationError,
    ConnectionError,
    DHCPLease,
    HTTPError,
    InterfaceStats,
    LogEntry,
    Route,
    RouterError,
    RouterStatus,
    Statistics,
    WANConnection,
    WirelessClient,
)
from .parser import (
    parse_dhcp_leases,
    parse_logs,
    parse_routes,
    parse_statistics,
    parse_status,
    parse_wireless_clients,
)

# Re-export models for backward compatibility
__all__ = [
    "ADSLStats",
    "AuthenticationError",
    "ConnectionError",
    "DHCPLease",
    "HTTPError",
    "InterfaceStats",
    "LogEntry",
    "Route",
    "RouterClient",
    "RouterError",
    "RouterStatus",
    "Statistics",
    "WANConnection",
    "WirelessClient",
]


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

    # Patterns that indicate a login/session expired page
    _LOGIN_PAGE_PATTERNS = [
        re.compile(r"<title>\s*Login\s*</title>", re.IGNORECASE),
        re.compile(r'name=["\']?password["\']?.*type=["\']?password', re.IGNORECASE),
        re.compile(r"session\s*(has\s*)?expired", re.IGNORECASE),
        re.compile(r"please\s*log\s*in", re.IGNORECASE),
        re.compile(r"unauthorized", re.IGNORECASE),
    ]

    # Patterns that indicate an error page
    _ERROR_PAGE_PATTERNS = [
        re.compile(r"<title>\s*Error\s*</title>", re.IGNORECASE),
        re.compile(r"internal\s*server\s*error", re.IGNORECASE),
        re.compile(r"service\s*unavailable", re.IGNORECASE),
        re.compile(r"<h1>\s*\d{3}\s*</h1>", re.IGNORECASE),  # <h1>500</h1> etc.
    ]

    def _is_login_page(self, html: str) -> bool:
        """Check if the HTML response is a login/session expired page."""
        for pattern in self._LOGIN_PAGE_PATTERNS:
            if pattern.search(html):
                return True
        return False

    def _is_error_page(self, html: str) -> tuple[bool, str | None]:
        """Check if the HTML response is an error page.

        Returns (is_error, error_message).
        """
        for pattern in self._ERROR_PAGE_PATTERNS:
            if pattern.search(html):
                # Try to extract a meaningful error message
                title_match = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
                h1_match = re.search(r"<h1>([^<]+)</h1>", html, re.IGNORECASE)
                msg = (
                    title_match.group(1)
                    if title_match
                    else (h1_match.group(1) if h1_match else "Unknown error")
                )
                return True, msg.strip()
        return False, None

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
                html = response.read().decode("utf-8", errors="replace")
                # Check if we got redirected to login page (auth failed)
                if self._is_login_page(html):
                    self._authenticated = False
                    raise AuthenticationError(
                        "Authentication failed: invalid credentials"
                    )
                self._authenticated = response.status == 200
                return self._authenticated
        except urllib.error.HTTPError as e:
            raise AuthenticationError(f"Authentication failed: HTTP {e.code}")
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Failed to connect to router at {self.ip}: {e.reason}"
            )

    def fetch_page(self, path: str, max_retries: int = 3) -> str:
        """Fetch a page from the router with authentication cookies.

        Args:
            path: The page path to fetch (e.g., "/info.html")
            max_retries: Maximum number of retry attempts for transient failures

        Returns:
            The HTML content of the page

        Raises:
            AuthenticationError: If session expired and re-auth fails
            ConnectionError: If unable to connect to the router
            HTTPError: If the router returns an HTTP error
        """
        if not self._authenticated:
            self.authenticate()

        url = f"{self.base_url}/{path.lstrip('/')}"
        cookie_header = f"username={self.username}; password={self.password}"

        last_error: Exception | None = None

        for attempt in range(max_retries):
            request = urllib.request.Request(
                url, headers={"Cookie": cookie_header}, method="GET"
            )

            try:
                with self.opener.open(request, timeout=10) as response:
                    html = response.read().decode("utf-8", errors="replace")

                    # Check if we got a login page (session expired)
                    if self._is_login_page(html):
                        self._authenticated = False
                        # Try to re-authenticate once
                        if attempt == 0:
                            try:
                                self.authenticate()
                                continue  # Retry the request
                            except AuthenticationError:
                                raise AuthenticationError(
                                    "Session expired and re-authentication failed"
                                )
                        raise AuthenticationError("Session expired")

                    # Check if we got an error page
                    is_error, error_msg = self._is_error_page(html)
                    if is_error:
                        # Some error pages are transient, retry
                        if attempt < max_retries - 1:
                            time.sleep(1 * (attempt + 1))  # Backoff
                            continue
                        raise HTTPError(f"Router returned error page: {error_msg}")

                    return html

            except urllib.error.HTTPError as e:
                last_error = e
                # Read the error body for better diagnostics
                try:
                    error_body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    error_body = ""

                # Retry on 5xx errors (server-side issues)
                if 500 <= e.code < 600 and attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))  # Exponential backoff
                    continue

                # Provide helpful error message based on status code
                if e.code == 401:
                    self._authenticated = False
                    raise AuthenticationError("Authentication required (401)")
                elif e.code == 403:
                    raise AuthenticationError("Access forbidden (403)")
                elif e.code == 404:
                    raise HTTPError(f"Page not found: {path}", status_code=404)
                elif e.code == 503:
                    raise HTTPError(
                        "Router is busy or unavailable (503). Try again later.",
                        status_code=503,
                    )
                else:
                    # Include snippet of error body for debugging
                    snippet = error_body[:100].replace("\n", " ").strip()
                    raise HTTPError(
                        f"HTTP {e.code} fetching {path}: {snippet or e.reason}",
                        status_code=e.code,
                    )

            except urllib.error.URLError as e:
                last_error = e
                # Retry on network errors
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise ConnectionError(f"Failed to connect to {self.ip}: {e.reason}")

            except TimeoutError:
                last_error = TimeoutError(f"Request to {path} timed out")
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise ConnectionError(
                    f"Request to {path} timed out after {max_retries} attempts"
                )

        # Should not reach here, but just in case
        raise ConnectionError(
            f"Failed to fetch {path} after {max_retries} attempts: {last_error}"
        )

    def get_session_key(self, html: str) -> str:
        """Extract session key from HTML page."""
        match = re.search(r"var\s+sessionKey\s*=\s*[\"']([^\"']+)[\"']", html)
        if match:
            return match.group(1)
        raise ValueError("Could not find session key in page")

    def get_status(self) -> RouterStatus:
        """Fetch and parse router status."""
        html = self.fetch_page("/info.html")
        return parse_status(html)

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
        return parse_wireless_clients(html)

    def get_dhcp_leases(self) -> list[DHCPLease]:
        """Fetch and parse DHCP leases."""
        html = self.fetch_page("/dhcpinfo.html")
        return parse_dhcp_leases(html)

    def get_routes(self) -> list[Route]:
        """Fetch and parse routing table."""
        html = self.fetch_page("/rtroutecfg.cmd?action=dlinkau")
        return parse_routes(html)

    def get_statistics(self) -> Statistics:
        """Fetch and parse network statistics."""
        html = self.fetch_page("/statsifcwanber.html")
        return parse_statistics(html)

    def get_logs(self) -> list[LogEntry]:
        """Fetch and parse system logs."""
        html = self.fetch_page("/logview.cmd")
        return parse_logs(html)
