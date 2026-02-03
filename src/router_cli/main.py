#!/usr/bin/env python3
"""Router CLI - Main entry point."""

import argparse
import sys

from .client import RouterClient, RouterStatus
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


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="router", description="Manage D-Link DSL-2750U router"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Display router status")
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
    elif args.command == "reboot":
        return cmd_reboot(client)

    return 0


if __name__ == "__main__":
    sys.exit(main())
