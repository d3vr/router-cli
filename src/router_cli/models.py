"""Data models for router CLI."""

from dataclasses import dataclass, field


class RouterError(Exception):
    """Base exception for router errors."""

    pass


class AuthenticationError(RouterError):
    """Raised when authentication fails or session expires."""

    pass


class ConnectionError(RouterError):
    """Raised when unable to connect to the router."""

    pass


class HTTPError(RouterError):
    """Raised for HTTP error responses."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class WANConnection:
    """A WAN connection entry."""

    interface: str = ""
    description: str = ""
    status: str = ""
    ipv4: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for backward compatibility."""
        return {
            "interface": self.interface,
            "description": self.description,
            "status": self.status,
            "ipv4": self.ipv4,
        }


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
    wan_connections: list[WANConnection] = field(default_factory=list)

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
