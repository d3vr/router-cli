"""HTML parsing utilities for router responses.

The router's HTML is often malformed (unclosed tags, mixed case, etc.).
These parsers use flexible regex patterns with re.IGNORECASE and re.DOTALL
to handle the inconsistencies.
"""

import re

from .models import (
    ADSLStats,
    DHCPLease,
    InterfaceStats,
    LogEntry,
    Route,
    RouterStatus,
    Statistics,
    WANConnection,
    WirelessClient,
)


def extract_value(html: str, *patterns: str) -> str:
    """Try multiple regex patterns and return first match.

    Args:
        html: The HTML content to search
        *patterns: One or more regex patterns to try in order

    Returns:
        The first captured group from the first matching pattern,
        or "N/A" if no pattern matches.
    """
    for pattern in patterns:
        match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            # Clean up HTML entities
            value = value.replace("&nbsp;", "").strip()
            if value:
                return value
    return "N/A"


def parse_status(html: str) -> RouterStatus:
    """Parse status information from HTML.

    Parses the /info.html page to extract router status including
    system info, internet info, WAN connections, wireless info,
    and local network settings.
    """
    status = RouterStatus()

    # System Info - from JavaScript variables or table cells
    status.model_name = extract_value(
        html,
        r"var\s+modeName\s*=\s*[\"']([^\"']+)[\"']",
        r"Model Name:.*?<td[^>]*>([^<]+)</td>",
    )

    status.time_date = extract_value(
        html,
        # From document.writeln() in JS
        r"Time and Date:.*?<td>([^<]+)</td>",
        # Static HTML fallback
        r"Time and Date:.*?<td[^>]*>([^<]+)</td>",
    )

    status.firmware = extract_value(
        html,
        r"Firmware Version:\s*([A-Z0-9_.]+)",
        r"<td[^>]*>Firmware Version:</td>\s*<td[^>]*>([^<]+)</td>",
    )

    # Internet Info - parse from JS variables first, then static HTML
    status.default_gateway = extract_value(
        html,
        r"var\s+dfltGw\s*=\s*[\"']([^\"']+)[\"']",
        r"Default Gateway:.*?<td[^>]*>([^<]+)</td>",
    )

    status.preferred_dns = extract_value(
        html, r"Preferred DNS Server:.*?<td[^>]*>([^<]+)</td>"
    )

    status.alternate_dns = extract_value(
        html, r"Alternate DNS Server:.*?<td[^>]*>([^<]+)</td>"
    )

    # WAN Connections - parse table rows with class="hd"
    status.wan_connections = parse_wan_connections(html)

    # Wireless Info - find section and extract all values
    wireless_section = re.search(
        r"Wireless Info:.*?Local Network Info", html, re.DOTALL
    )
    if wireless_section:
        ws = wireless_section.group(0)
        status.ssid = extract_value(
            ws,
            r"<option[^>]*selected[^>]*>\s*([^<\n]+?)\s*</option>",
        )
        status.wireless_mac = extract_value(ws, r"MAC Address:.*?<td[^>]*>([^<]+)</td>")
        status.wireless_status = extract_value(ws, r"Status:.*?<td[^>]*>([^<]+)</td>")
        status.security_mode = extract_value(
            ws, r"Security Mode:.*?<td[^>]*>([^<]+)</td>"
        )

    # Local Network Info - find section after "Local Network Info"
    # Note: MAC address may have malformed HTML (</SPAN> without opening tag)
    local_section = re.search(
        r"Local Network Info.*?(?:Storage Device|$)", html, re.DOTALL
    )
    if local_section:
        ls = local_section.group(0)
        status.local_mac = extract_value(
            ls,
            r"MAC Address:</TD>\s*<TD>([^<]+)",
            r"MAC Address:.*?<td[^>]*>([^<]+)</td>",
        )
        status.local_ip = extract_value(ls, r"IP Address:.*?<td[^>]*>([^<]+)</td>")
        status.subnet_mask = extract_value(ls, r"Subnet Mask:.*?<td[^>]*>([^<]+)</td>")
        # DHCP may be in document.writeln() or static HTML
        status.dhcp_server = extract_value(
            ls,
            r"DHCP Server:.*?<td>([^<]+)</td>",
            r"DHCP Server:.*?<td[^>]*>([^<]+)</td>",
        )

    return status


def parse_wan_connections(html: str) -> list[WANConnection]:
    """Parse WAN connection table from HTML.

    Looks for the "Enabled WAN Connections:" table and extracts
    interface, description, status, and IPv4 address from each row.
    """
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
                WANConnection(
                    interface=cells[0].strip(),
                    description=cells[1].strip(),
                    status=cells[2].strip(),
                    ipv4=cells[3].strip(),
                )
            )

    return connections


def parse_wireless_clients(html: str) -> list[WirelessClient]:
    """Parse wireless clients from HTML.

    Parses the /wlstationlist.cmd page to extract connected
    wireless clients with their MAC, association/authorization status,
    SSID, and interface.
    """
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


def parse_dhcp_leases(html: str) -> list[DHCPLease]:
    """Parse DHCP leases from HTML.

    Parses the /dhcpinfo.html page to extract active DHCP leases
    with hostname, MAC address, IP address, and expiry time.
    """
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


def parse_routes(html: str) -> list[Route]:
    """Parse routing table from HTML.

    Parses the /rtroutecfg.cmd page to extract routing table entries
    with destination, gateway, subnet mask, flags, metric, and service.
    """
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


def parse_statistics(html: str) -> Statistics:
    """Parse network statistics from HTML.

    Parses the /statsifcwanber.html page to extract LAN interface stats,
    WAN interface stats, and ADSL line statistics.
    """
    stats = Statistics()

    # Parse LAN interface stats - look for rows with 9 cells
    lan_section = re.search(
        r"Local Network.*?</table>", html, re.DOTALL | re.IGNORECASE
    )
    if lan_section:
        stats.lan_interfaces = parse_interface_stats(lan_section.group(0))

    # Parse WAN interface stats
    wan_section = re.search(
        r"<td class=topheader>\s*Internet\s*</td>.*?</table>",
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if wan_section:
        stats.wan_interfaces = parse_wan_interface_stats(wan_section.group(0))

    # Parse ADSL stats
    stats.adsl = parse_adsl_stats(html)

    return stats


def parse_interface_stats(html: str) -> list[InterfaceStats]:
    """Parse LAN interface statistics table."""
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
    intf_names = re.findall(r"brdIntf\s*=\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE)

    for i, row in enumerate(rows):
        intf_name = intf_names[i].split("|")[-1] if i < len(intf_names) else f"eth{i}"
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


def parse_wan_interface_stats(html: str) -> list[InterfaceStats]:
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


def parse_adsl_stats(html: str) -> ADSLStats:
    """Parse ADSL statistics from HTML.

    Extracts mode, status, link power state, rates, SNR margins,
    attenuation, and output power levels.
    """
    adsl = ADSLStats()

    adsl.mode = extract_value(html, r"Mode:</td><td>([^<]+)</td>")
    adsl.traffic_type = extract_value(html, r"Traffic Type:</td><td>([^<]+)</td>")
    adsl.status = extract_value(html, r"Status:</td><td>([^<]+)</td>")
    adsl.link_power_state = extract_value(
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


def parse_logs(html: str) -> list[LogEntry]:
    """Parse system logs from HTML.

    Parses the /logview.cmd page to extract log entries with
    timestamp, facility, severity, and message.
    """
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
