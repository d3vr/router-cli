#!/usr/bin/env python3
"""Router CLI - Main entry point."""

import argparse
import sys

from .client import RouterClient
from .commands import (
    cmd_clients,
    cmd_dhcp,
    cmd_logs,
    cmd_overview,
    cmd_reboot,
    cmd_routes,
    cmd_stats,
    cmd_status,
)
from .config import load_config, load_known_devices


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="router", description="Manage D-Link DSL-2750U router"
    )

    # Global options for connection
    parser.add_argument(
        "--ip",
        metavar="ADDRESS",
        help="Router IP address (overrides config and ROUTER_IP env var)",
    )
    parser.add_argument(
        "--user",
        metavar="USERNAME",
        help="Username for authentication (overrides config and ROUTER_USER env var)",
    )
    parser.add_argument(
        "--pass",
        dest="password",
        metavar="PASSWORD",
        help="Password for authentication (overrides config and ROUTER_PASS env var)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format (for scripting)",
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

    # Load configuration with CLI overrides
    try:
        config = load_config(
            cli_ip=args.ip,
            cli_user=args.user,
            cli_pass=args.password,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Create client
    client = RouterClient(
        ip=config["ip"],
        username=config["username"],
        password=config["password"],
    )

    # Load known devices for colorization
    known_devices = load_known_devices()

    # Execute command
    if args.command == "status":
        return cmd_status(client, json_output=args.json)
    elif args.command == "clients":
        return cmd_clients(client, known_devices, json_output=args.json)
    elif args.command == "dhcp":
        return cmd_dhcp(client, known_devices, json_output=args.json)
    elif args.command == "routes":
        return cmd_routes(client, json_output=args.json)
    elif args.command == "stats":
        return cmd_stats(client, json_output=args.json)
    elif args.command == "logs":
        return cmd_logs(client, tail=args.tail, level=args.level, json_output=args.json)
    elif args.command == "overview":
        return cmd_overview(client, known_devices, json_output=args.json)
    elif args.command == "reboot":
        return cmd_reboot(client)

    return 0


if __name__ == "__main__":
    sys.exit(main())
