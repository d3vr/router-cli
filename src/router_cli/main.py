#!/usr/bin/env python3
"""Router CLI - Main entry point."""

import argparse
import sys

from .client import (
    ADSLStats,
    DHCPLease,
    InterfaceStats,
    LogEntry,
    Route,
    RouterClient,
    RouterStatus,
    Statistics,
    WirelessClient,
)
from .config import load_config


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


def format_clients(clients: list[WirelessClient]) -> str:
    """Format wireless clients for display."""
    if not clients:
        return "No wireless clients connected."

    lines = [
        f"{'MAC Address':<18} {'Associated':<12} {'Authorized':<12} {'SSID':<20} {'Interface':<10}",
        f"{'-' * 17:<18} {'-' * 10:<12} {'-' * 10:<12} {'-' * 18:<20} {'-' * 8:<10}",
    ]
    for c in clients:
        assoc = "Yes" if c.associated else "No"
        auth = "Yes" if c.authorized else "No"
        lines.append(
            f"{c.mac:<18} {assoc:<12} {auth:<12} {c.ssid:<20} {c.interface:<10}"
        )

    return "\n".join(lines)


def format_dhcp(leases: list[DHCPLease]) -> str:
    """Format DHCP leases for display."""
    if not leases:
        return "No DHCP leases."

    lines = [
        f"{'Hostname':<20} {'MAC Address':<18} {'IP Address':<16} {'Expires In':<12}",
        f"{'-' * 18:<20} {'-' * 16:<18} {'-' * 14:<16} {'-' * 10:<12}",
    ]
    for lease in leases:
        lines.append(
            f"{lease.hostname:<20} {lease.mac:<18} {lease.ip:<16} {lease.expires_in:<12}"
        )

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
) -> str:
    """Format overview dashboard with highlights from multiple sources."""
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

    if warnings:
        lines.append("WARNINGS")
        lines.extend(warnings)
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def cmd_status(client: RouterClient) -> int:
    """Execute status command."""
    try:
        status = client.get_status()
        print(format_status(status))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_reboot(client: RouterClient) -> int:
    """Execute reboot command."""
    try:
        print("Rebooting router...")
        client.reboot()
        print("Reboot command sent successfully.")
        print("The router will restart in a few seconds.")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_clients(client: RouterClient) -> int:
    """Execute clients command."""
    try:
        clients = client.get_wireless_clients()
        print(format_clients(clients))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_dhcp(client: RouterClient) -> int:
    """Execute dhcp command."""
    try:
        leases = client.get_dhcp_leases()
        print(format_dhcp(leases))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_routes(client: RouterClient) -> int:
    """Execute routes command."""
    try:
        routes = client.get_routes()
        print(format_routes(routes))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_stats(client: RouterClient) -> int:
    """Execute stats command."""
    try:
        stats = client.get_statistics()
        print(format_stats(stats))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_logs(
    client: RouterClient, tail: int | None = None, level: str | None = None
) -> int:
    """Execute logs command."""
    try:
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
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_overview(client: RouterClient) -> int:
    """Execute overview command."""
    try:
        status = client.get_status()
        clients = client.get_wireless_clients()
        leases = client.get_dhcp_leases()
        stats = client.get_statistics()
        print(format_overview(status, clients, leases, stats))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


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

    # Execute command
    if args.command == "status":
        return cmd_status(client)
    elif args.command == "clients":
        return cmd_clients(client)
    elif args.command == "dhcp":
        return cmd_dhcp(client)
    elif args.command == "routes":
        return cmd_routes(client)
    elif args.command == "stats":
        return cmd_stats(client)
    elif args.command == "logs":
        return cmd_logs(client, tail=args.tail, level=args.level)
    elif args.command == "overview":
        return cmd_overview(client)
    elif args.command == "reboot":
        return cmd_reboot(client)

    return 0


if __name__ == "__main__":
    sys.exit(main())
