#!/usr/bin/env python3
"""Router CLI - Main entry point."""

import argparse
import re
import sys
import threading
from contextlib import contextmanager

from .client import (
    ADSLStats,
    AuthenticationError,
    ConnectionError,
    DHCPLease,
    HTTPError,
    InterfaceStats,
    LogEntry,
    Route,
    RouterClient,
    RouterError,
    RouterStatus,
    Statistics,
    WirelessClient,
)
from .config import load_config, load_known_devices


# ANSI color codes
_COLORS = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "reset": "\033[0m",
}


def _handle_error(e: Exception) -> int:
    """Handle exceptions and print user-friendly error messages.

    Returns the exit code to use.
    """
    if isinstance(e, AuthenticationError):
        print(f"Authentication error: {e}", file=sys.stderr)
        print(
            "  Hint: Check your username/password in the config file.", file=sys.stderr
        )
        return 2
    elif isinstance(e, ConnectionError):
        print(f"Connection error: {e}", file=sys.stderr)
        print(
            "  Hint: Ensure the router is reachable and the IP is correct.",
            file=sys.stderr,
        )
        return 3
    elif isinstance(e, HTTPError):
        print(f"Router error: {e}", file=sys.stderr)
        if e.status_code == 503:
            print(
                "  Hint: The router may be busy. Wait a moment and try again.",
                file=sys.stderr,
            )
        return 4
    elif isinstance(e, RouterError):
        print(f"Router error: {e}", file=sys.stderr)
        return 1
    else:
        # Catch-all for unexpected errors - include type for debugging
        print(f"Unexpected error ({type(e).__name__}): {e}", file=sys.stderr)
        return 1


def colorize(text: str, color: str) -> str:
    """Apply ANSI color to text if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


# Spinner frames - braille pattern for smooth animation
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_SPINNER_INTERVAL = 0.08  # seconds between frames


@contextmanager
def spinner(message: str = "Loading..."):
    """Display an animated spinner while waiting for an operation.

    Usage:
        with spinner("Fetching status..."):
            result = client.get_status()

    Only displays spinner if stdout is a TTY.
    """
    if not sys.stdout.isatty():
        # Not a TTY, just run without spinner
        yield
        return

    stop_event = threading.Event()
    spinner_thread = None

    def animate():
        frame_idx = 0
        # Hide cursor
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

        while not stop_event.is_set():
            frame = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
            # Write spinner frame and message, then return cursor to start
            sys.stdout.write(f"\r{frame} {message}")
            sys.stdout.flush()
            frame_idx += 1
            stop_event.wait(_SPINNER_INTERVAL)

        # Clear the spinner line
        sys.stdout.write("\r" + " " * (len(message) + 3) + "\r")
        # Show cursor
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    try:
        spinner_thread = threading.Thread(target=animate, daemon=True)
        spinner_thread.start()
        yield
    finally:
        stop_event.set()
        if spinner_thread:
            spinner_thread.join(timeout=0.5)


def get_device_display(
    mac: str, hostname: str, known_devices: dict[str, str]
) -> tuple[str, bool]:
    """Get display name for a device and whether it's known.

    Returns (display_name, is_known) tuple.
    If known, display_name is 'Alias (hostname)'.
    """
    alias = known_devices.get(mac.upper())
    if alias:
        if hostname and hostname != alias:
            return f"{alias} ({hostname})", True
        return alias, True
    return hostname or mac, False


def format_expires(expires_in: str) -> str:
    """Convert verbose expires string to compact HH:MM:SS format.

    Input: "22 hours, 27 minutes, 15 seconds"
    Output: "22:27:15"
    """
    hours = minutes = seconds = 0

    h_match = re.search(r"(\d+)\s*hour", expires_in)
    m_match = re.search(r"(\d+)\s*minute", expires_in)
    s_match = re.search(r"(\d+)\s*second", expires_in)

    if h_match:
        hours = int(h_match.group(1))
    if m_match:
        minutes = int(m_match.group(1))
    if s_match:
        seconds = int(s_match.group(1))

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def format_status(status: RouterStatus) -> str:
    """Format router status for display."""
    lines = [
        "=" * 50,
        f"{'ROUTER STATUS (DSL-2750U)':^50}",
        "=" * 50,
        "",
        "SYSTEM INFO",
        f"  Model Name:        {status.model_name}",
        f"  Time and Date:     {status.time_date}",
        f"  Firmware:          {status.firmware}",
        "",
        "INTERNET INFO",
        f"  Default Gateway:   {status.default_gateway}",
        f"  Preferred DNS:     {status.preferred_dns}",
        f"  Alternate DNS:     {status.alternate_dns}",
        "",
    ]

    if status.wan_connections:
        lines.append("  WAN Connections:")
        lines.append(
            f"  {'Interface':<12} {'Description':<16} {'Status':<12} {'IPv4 Address':<16}"
        )
        lines.append(f"  {'-' * 10:<12} {'-' * 14:<16} {'-' * 10:<12} {'-' * 14:<16}")
        for conn in status.wan_connections:
            lines.append(
                f"  {conn['interface']:<12} {conn['description']:<16} "
                f"{conn['status']:<12} {conn['ipv4']:<16}"
            )
        lines.append("")

    lines.extend(
        [
            "WIRELESS INFO",
            f"  SSID:              {status.ssid}",
            f"  MAC Address:       {status.wireless_mac}",
            f"  Status:            {status.wireless_status}",
            f"  Security Mode:     {status.security_mode}",
            "",
            "LOCAL NETWORK",
            f"  MAC Address:       {status.local_mac}",
            f"  IP Address:        {status.local_ip}",
            f"  Subnet Mask:       {status.subnet_mask}",
            f"  DHCP Server:       {status.dhcp_server}",
            "=" * 50,
        ]
    )

    return "\n".join(lines)


def format_clients(
    clients: list[WirelessClient], known_devices: dict[str, str] | None = None
) -> str:
    """Format wireless clients for display."""
    if not clients:
        return "No wireless clients connected."

    known_devices = known_devices or {}

    # Build display data and calculate column widths
    rows = []
    for c in clients:
        assoc = "Yes" if c.associated else "No"
        auth = "Yes" if c.authorized else "No"
        is_known = c.mac.upper() in known_devices
        alias = known_devices.get(c.mac.upper(), "")
        mac_display = f"{c.mac} ({alias})" if alias else c.mac
        rows.append((mac_display, assoc, auth, c.ssid, c.interface, is_known))

    # Calculate column widths
    headers = ["MAC Address", "Associated", "Authorized", "SSID", "Interface"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row[:5]):
            widths[i] = max(widths[i], len(str(val)))

    # Add padding
    widths = [w + 2 for w in widths]

    # Build output
    header_line = "".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep_line = "".join(("-" * (w - 2)).ljust(w) for w in widths)
    lines = [header_line, sep_line]

    for mac_display, assoc, auth, ssid, interface, is_known in rows:
        color = "green" if is_known else "red"
        line = (
            f"{mac_display.ljust(widths[0])}"
            f"{assoc.ljust(widths[1])}"
            f"{auth.ljust(widths[2])}"
            f"{ssid.ljust(widths[3])}"
            f"{interface.ljust(widths[4])}"
        )
        lines.append(colorize(line, color))

    return "\n".join(lines)


def format_dhcp(
    leases: list[DHCPLease], known_devices: dict[str, str] | None = None
) -> str:
    """Format DHCP leases for display."""
    if not leases:
        return "No DHCP leases."

    known_devices = known_devices or {}

    # Build display data and calculate column widths
    rows = []
    for lease in leases:
        display_name, is_known = get_device_display(
            lease.mac, lease.hostname, known_devices
        )
        expires = f"⏱ {format_expires(lease.expires_in)}"
        rows.append((display_name, lease.mac, lease.ip, expires, is_known))

    # Calculate column widths
    headers = ["Device", "MAC Address", "IP Address", "Expires"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row[:4]):
            widths[i] = max(widths[i], len(str(val)))

    # Add padding
    widths = [w + 2 for w in widths]

    # Build output
    header_line = "".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep_line = "".join(("-" * (w - 2)).ljust(w) for w in widths)
    lines = [header_line, sep_line]

    for display_name, mac, ip, expires, is_known in rows:
        color = "green" if is_known else "red"
        line = (
            f"{display_name.ljust(widths[0])}"
            f"{mac.ljust(widths[1])}"
            f"{ip.ljust(widths[2])}"
            f"{expires.ljust(widths[3])}"
        )
        lines.append(colorize(line, color))

    return "\n".join(lines)


def format_routes(routes: list[Route]) -> str:
    """Format routing table for display."""
    if not routes:
        return "No routes found."

    lines = [
        f"{'Destination':<16} {'Gateway':<16} {'Subnet Mask':<16} {'Flag':<6} {'Metric':<8} {'Service':<12}",
        f"{'-' * 14:<16} {'-' * 14:<16} {'-' * 14:<16} {'-' * 4:<6} {'-' * 6:<8} {'-' * 10:<12}",
    ]
    for r in routes:
        lines.append(
            f"{r.destination:<16} {r.gateway:<16} {r.subnet_mask:<16} "
            f"{r.flag:<6} {r.metric:<8} {r.service:<12}"
        )

    return "\n".join(lines)


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def format_interface_stats(interfaces: list[InterfaceStats], title: str) -> list[str]:
    """Format interface stats section."""
    if not interfaces:
        return []

    lines = [
        title,
        f"  {'Interface':<12} {'RX Bytes':<12} {'RX Pkts':<10} {'RX Err':<8} {'RX Drop':<8} "
        f"{'TX Bytes':<12} {'TX Pkts':<10} {'TX Err':<8} {'TX Drop':<8}",
        f"  {'-' * 10:<12} {'-' * 10:<12} {'-' * 8:<10} {'-' * 6:<8} {'-' * 6:<8} "
        f"{'-' * 10:<12} {'-' * 8:<10} {'-' * 6:<8} {'-' * 6:<8}",
    ]
    for intf in interfaces:
        lines.append(
            f"  {intf.interface:<12} {format_bytes(intf.rx_bytes):<12} {intf.rx_packets:<10} "
            f"{intf.rx_errors:<8} {intf.rx_drops:<8} {format_bytes(intf.tx_bytes):<12} "
            f"{intf.tx_packets:<10} {intf.tx_errors:<8} {intf.tx_drops:<8}"
        )
    return lines


def format_adsl(adsl: ADSLStats) -> list[str]:
    """Format ADSL statistics."""
    if adsl.status == "N/A":
        return []

    return [
        "ADSL STATUS",
        f"  Mode:               {adsl.mode}",
        f"  Status:             {adsl.status}",
        f"  Link Power State:   {adsl.link_power_state}",
        "",
        f"  {'Metric':<22} {'Downstream':<14} {'Upstream':<14}",
        f"  {'-' * 20:<22} {'-' * 12:<14} {'-' * 12:<14}",
        f"  {'Rate (Kbps)':<22} {adsl.downstream_rate:<14} {adsl.upstream_rate:<14}",
        f"  {'Attainable Rate':<22} {adsl.downstream_attainable_rate:<14} {adsl.upstream_attainable_rate:<14}",
        f"  {'SNR Margin (dB)':<22} {adsl.downstream_snr_margin:<14.1f} {adsl.upstream_snr_margin:<14.1f}",
        f"  {'Attenuation (dB)':<22} {adsl.downstream_attenuation:<14.1f} {adsl.upstream_attenuation:<14.1f}",
        f"  {'Output Power (dBm)':<22} {adsl.downstream_output_power:<14.1f} {adsl.upstream_output_power:<14.1f}",
    ]


def format_stats(stats: Statistics) -> str:
    """Format network statistics for display."""
    lines = []

    lines.extend(format_interface_stats(stats.lan_interfaces, "LAN INTERFACES"))
    if stats.lan_interfaces:
        lines.append("")

    lines.extend(format_interface_stats(stats.wan_interfaces, "WAN INTERFACES"))
    if stats.wan_interfaces:
        lines.append("")

    lines.extend(format_adsl(stats.adsl))

    return "\n".join(lines) if lines else "No statistics available."


def format_logs(logs: list[LogEntry]) -> str:
    """Format system logs for display."""
    if not logs:
        return "No log entries."

    lines = [
        f"{'Date/Time':<22} {'Facility':<10} {'Severity':<10} {'Message'}",
        f"{'-' * 20:<22} {'-' * 8:<10} {'-' * 8:<10} {'-' * 40}",
    ]
    for log in logs:
        lines.append(
            f"{log.datetime:<22} {log.facility:<10} {log.severity:<10} {log.message}"
        )

    return "\n".join(lines)


def format_overview(
    status: RouterStatus,
    clients: list[WirelessClient],
    leases: list[DHCPLease],
    stats: Statistics,
    known_devices: dict[str, str] | None = None,
) -> str:
    """Format overview dashboard with highlights from multiple sources."""
    known_devices = known_devices or {}
    lines = [
        "=" * 60,
        f"{'ROUTER OVERVIEW':^60}",
        "=" * 60,
        "",
    ]

    # Connection status
    lines.append("CONNECTION")
    if stats.adsl.status and stats.adsl.status != "N/A":
        lines.append(f"  ADSL Status:        {stats.adsl.status}")
        lines.append(
            f"  Sync Rate:          {stats.adsl.downstream_rate} / {stats.adsl.upstream_rate} Kbps (down/up)"
        )
        lines.append(
            f"  SNR Margin:         {stats.adsl.downstream_snr_margin:.1f} / {stats.adsl.upstream_snr_margin:.1f} dB"
        )
    lines.append(f"  Default Gateway:    {status.default_gateway}")
    if status.wan_connections:
        wan = status.wan_connections[0]
        lines.append(
            f"  WAN IP:             {wan.get('ipv4', 'N/A')} ({wan.get('status', 'N/A')})"
        )
    lines.append("")

    # Network
    lines.append("NETWORK")
    lines.append(f"  Router IP:          {status.local_ip}")
    lines.append(f"  SSID:               {status.ssid}")
    lines.append(f"  Wireless Clients:   {len(clients)}")
    lines.append(f"  DHCP Leases:        {len(leases)}")
    lines.append("")

    # DHCP Leases list
    if leases:
        lines.append("DEVICES")

        # Build display data and calculate column widths
        rows = []
        for lease in leases:
            display_name, is_known = get_device_display(
                lease.mac, lease.hostname, known_devices
            )
            expires = f"⏱ {format_expires(lease.expires_in)}"
            rows.append((display_name, lease.mac, lease.ip, expires, is_known))

        # Calculate column widths
        widths = [
            max(len(row[0]) for row in rows),
            max(len(row[1]) for row in rows),
            max(len(row[2]) for row in rows),
            max(len(row[3]) for row in rows),
        ]
        widths = [w + 2 for w in widths]

        for display_name, mac, ip, expires, is_known in rows:
            color = "green" if is_known else "red"
            device_line = (
                f"  {display_name.ljust(widths[0])}"
                f"{mac.ljust(widths[1])}"
                f"{ip.ljust(widths[2])}"
                f"{expires}"
            )
            lines.append(colorize(device_line, color))
        lines.append("")

    # Traffic summary (if available)
    total_rx = sum(i.rx_bytes for i in stats.wan_interfaces)
    total_tx = sum(i.tx_bytes for i in stats.wan_interfaces)
    if total_rx or total_tx:
        lines.append("TRAFFIC (WAN)")
        lines.append(f"  Downloaded:         {format_bytes(total_rx)}")
        lines.append(f"  Uploaded:           {format_bytes(total_tx)}")
        lines.append("")

    # Warnings
    warnings = []
    total_errors = sum(
        i.rx_errors + i.tx_errors for i in stats.wan_interfaces + stats.lan_interfaces
    )
    if total_errors > 0:
        warnings.append(f"  Interface errors detected: {total_errors}")
    if stats.adsl.downstream_snr_margin and stats.adsl.downstream_snr_margin < 6:
        warnings.append(
            f"  Low SNR margin: {stats.adsl.downstream_snr_margin:.1f} dB (may cause disconnects)"
        )
    # Warn about unknown devices
    unknown_count = sum(1 for lease in leases if lease.mac.upper() not in known_devices)
    if unknown_count > 0:
        warnings.append(
            colorize(f"  Unknown devices on network: {unknown_count}", "red")
        )

    if warnings:
        lines.append("WARNINGS")
        lines.extend(warnings)
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def cmd_status(client: RouterClient) -> int:
    """Execute status command."""
    try:
        with spinner("Fetching router status..."):
            status = client.get_status()
        print(format_status(status))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_reboot(client: RouterClient) -> int:
    """Execute reboot command."""
    try:
        with spinner("Sending reboot command..."):
            client.reboot()
        print("Reboot command sent successfully.")
        print("The router will restart in a few seconds.")
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_clients(client: RouterClient, known_devices: dict[str, str]) -> int:
    """Execute clients command."""
    try:
        with spinner("Fetching wireless clients..."):
            clients = client.get_wireless_clients()
        print(format_clients(clients, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_dhcp(client: RouterClient, known_devices: dict[str, str]) -> int:
    """Execute dhcp command."""
    try:
        with spinner("Fetching DHCP leases..."):
            leases = client.get_dhcp_leases()
        print(format_dhcp(leases, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_routes(client: RouterClient) -> int:
    """Execute routes command."""
    try:
        with spinner("Fetching routing table..."):
            routes = client.get_routes()
        print(format_routes(routes))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_stats(client: RouterClient) -> int:
    """Execute stats command."""
    try:
        with spinner("Fetching network statistics..."):
            stats = client.get_statistics()
        print(format_stats(stats))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_logs(
    client: RouterClient, tail: int | None = None, level: str | None = None
) -> int:
    """Execute logs command."""
    try:
        with spinner("Fetching system logs..."):
            logs = client.get_logs()

        # Filter by severity level if specified
        if level:
            level_upper = level.upper()
            logs = [log for log in logs if log.severity.upper() == level_upper]

        # Limit to last N entries if tail specified
        if tail and tail > 0:
            logs = logs[-tail:]

        print(format_logs(logs))
        return 0
    except Exception as e:
        return _handle_error(e)


def cmd_overview(client: RouterClient, known_devices: dict[str, str]) -> int:
    """Execute overview command."""
    try:
        with spinner("Fetching router overview..."):
            status = client.get_status()
            clients = client.get_wireless_clients()
            leases = client.get_dhcp_leases()
            stats = client.get_statistics()
        print(format_overview(status, clients, leases, stats, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="router", description="Manage D-Link DSL-2750U router"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Display router status")
    subparsers.add_parser("clients", help="List connected wireless clients")
    subparsers.add_parser("dhcp", help="Show DHCP leases")
    subparsers.add_parser("routes", help="Show routing table")
    subparsers.add_parser("stats", help="Show network and ADSL statistics")

    logs_parser = subparsers.add_parser("logs", help="Show system logs")
    logs_parser.add_argument(
        "--tail", "-n", type=int, metavar="N", help="Show only the last N log entries"
    )
    logs_parser.add_argument(
        "--level", "-l", type=str, metavar="LEVEL", help="Filter by severity level"
    )

    subparsers.add_parser("overview", help="Show quick dashboard with highlights")
    subparsers.add_parser("reboot", help="Reboot the router")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Load configuration
    try:
        config = load_config()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Create client
    client = RouterClient(
        ip=config.get("ip", "192.168.1.1"),
        username=config.get("username", "admin"),
        password=config.get("password", ""),
    )

    # Load known devices for colorization
    known_devices = load_known_devices()

    # Execute command
    if args.command == "status":
        return cmd_status(client)
    elif args.command == "clients":
        return cmd_clients(client, known_devices)
    elif args.command == "dhcp":
        return cmd_dhcp(client, known_devices)
    elif args.command == "routes":
        return cmd_routes(client)
    elif args.command == "stats":
        return cmd_stats(client)
    elif args.command == "logs":
        return cmd_logs(client, tail=args.tail, level=args.level)
    elif args.command == "overview":
        return cmd_overview(client, known_devices)
    elif args.command == "reboot":
        return cmd_reboot(client)

    return 0


if __name__ == "__main__":
    sys.exit(main())
