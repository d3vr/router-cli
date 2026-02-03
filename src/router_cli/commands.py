"""Command handlers for the router CLI."""

import json
import sys
from dataclasses import asdict

from .client import (
    AuthenticationError,
    ConnectionError,
    HTTPError,
    RouterClient,
    RouterError,
)
from .config import KnownDevices
from .display import spinner
from .formatters import (
    format_clients,
    format_dhcp,
    format_logs,
    format_overview,
    format_routes,
    format_stats,
    format_status,
)


def _handle_error(e: Exception, json_output: bool = False) -> int:
    """Handle exceptions and print user-friendly error messages.

    Returns the exit code to use.
    """
    error_info = {"error": str(e), "type": type(e).__name__}

    if isinstance(e, AuthenticationError):
        error_info["hint"] = "Check your username/password in the config file."
        error_info["code"] = 2
    elif isinstance(e, ConnectionError):
        error_info["hint"] = "Ensure the router is reachable and the IP is correct."
        error_info["code"] = 3
    elif isinstance(e, HTTPError):
        error_info["code"] = 4
        if e.status_code == 503:
            error_info["hint"] = "The router may be busy. Wait a moment and try again."
        error_info["status_code"] = e.status_code
    elif isinstance(e, RouterError):
        error_info["code"] = 1
    else:
        error_info["code"] = 1

    if json_output:
        print(json.dumps(error_info, indent=2), file=sys.stderr)
    else:
        if isinstance(e, AuthenticationError):
            print(f"Authentication error: {e}", file=sys.stderr)
            print(
                "  Hint: Check your username/password in the config file.",
                file=sys.stderr,
            )
        elif isinstance(e, ConnectionError):
            print(f"Connection error: {e}", file=sys.stderr)
            print(
                "  Hint: Ensure the router is reachable and the IP is correct.",
                file=sys.stderr,
            )
        elif isinstance(e, HTTPError):
            print(f"Router error: {e}", file=sys.stderr)
            if e.status_code == 503:
                print(
                    "  Hint: The router may be busy. Wait a moment and try again.",
                    file=sys.stderr,
                )
        elif isinstance(e, RouterError):
            print(f"Router error: {e}", file=sys.stderr)
        else:
            print(f"Unexpected error ({type(e).__name__}): {e}", file=sys.stderr)

    return error_info["code"]


def _to_json(obj) -> str:
    """Convert dataclass or list of dataclasses to JSON."""
    if isinstance(obj, list):
        return json.dumps([asdict(item) for item in obj], indent=2)
    return json.dumps(asdict(obj), indent=2)


def cmd_status(client: RouterClient, json_output: bool = False) -> int:
    """Execute status command."""
    try:
        with spinner("Fetching router status..."):
            status = client.get_status()
        if json_output:
            # Convert WANConnection objects to dicts for JSON
            data = asdict(status)
            print(json.dumps(data, indent=2))
        else:
            print(format_status(status))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


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


def cmd_clients(
    client: RouterClient, known_devices: KnownDevices, json_output: bool = False
) -> int:
    """Execute clients command."""
    try:
        with spinner("Fetching wireless clients..."):
            clients = client.get_wireless_clients()
        if json_output:
            print(_to_json(clients))
        else:
            print(format_clients(clients, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


def cmd_dhcp(
    client: RouterClient, known_devices: KnownDevices, json_output: bool = False
) -> int:
    """Execute dhcp command."""
    try:
        with spinner("Fetching DHCP leases..."):
            leases = client.get_dhcp_leases()
        if json_output:
            print(_to_json(leases))
        else:
            print(format_dhcp(leases, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


def cmd_routes(client: RouterClient, json_output: bool = False) -> int:
    """Execute routes command."""
    try:
        with spinner("Fetching routing table..."):
            routes = client.get_routes()
        if json_output:
            print(_to_json(routes))
        else:
            print(format_routes(routes))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


def cmd_stats(client: RouterClient, json_output: bool = False) -> int:
    """Execute stats command."""
    try:
        with spinner("Fetching network statistics..."):
            stats = client.get_statistics()
        if json_output:
            print(_to_json(stats))
        else:
            print(format_stats(stats))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


def cmd_logs(
    client: RouterClient,
    tail: int | None = None,
    level: str | None = None,
    json_output: bool = False,
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

        if json_output:
            print(_to_json(logs))
        else:
            print(format_logs(logs))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)


def cmd_overview(
    client: RouterClient, known_devices: KnownDevices, json_output: bool = False
) -> int:
    """Execute overview command."""
    try:
        with spinner("Fetching router overview..."):
            status = client.get_status()
            clients = client.get_wireless_clients()
            leases = client.get_dhcp_leases()
            stats = client.get_statistics()

        if json_output:
            data = {
                "status": asdict(status),
                "wireless_clients": [asdict(c) for c in clients],
                "dhcp_leases": [asdict(lease) for lease in leases],
                "statistics": asdict(stats),
            }
            print(json.dumps(data, indent=2))
        else:
            print(format_overview(status, clients, leases, stats, known_devices))
        return 0
    except Exception as e:
        return _handle_error(e, json_output)
