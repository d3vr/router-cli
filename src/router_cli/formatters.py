"""Formatting functions for router data."""

from .models import (
    ADSLStats,
    DHCPLease,
    InterfaceStats,
    LogEntry,
    Route,
    RouterStatus,
    Statistics,
    WirelessClient,
)
from .config import KnownDevices
from .display import colorize, format_bytes, format_expires, get_device_display


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
                f"  {conn.interface:<12} {conn.description:<16} "
                f"{conn.status:<12} {conn.ipv4:<16}"
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
    clients: list[WirelessClient], known_devices: KnownDevices | None = None
) -> str:
    """Format wireless clients for display."""
    if not clients:
        return "No wireless clients connected."

    known_devices = known_devices or KnownDevices()

    # Build display data and calculate column widths
    rows = []
    for c in clients:
        assoc = "Yes" if c.associated else "No"
        auth = "Yes" if c.authorized else "No"
        # WirelessClient doesn't have hostname, so we can only check by MAC
        alias = known_devices.get_alias(c.mac, "")
        is_known = alias is not None
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
    leases: list[DHCPLease], known_devices: KnownDevices | None = None
) -> str:
    """Format DHCP leases for display."""
    if not leases:
        return "No DHCP leases."

    known_devices = known_devices or KnownDevices()

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
    known_devices: KnownDevices | None = None,
) -> str:
    """Format overview dashboard with highlights from multiple sources."""
    known_devices = known_devices or KnownDevices()
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
            f"  WAN IP:             {wan.ipv4 or 'N/A'} ({wan.status or 'N/A'})"
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
    unknown_count = sum(
        1 for lease in leases if not known_devices.is_known(lease.mac, lease.hostname)
    )
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
