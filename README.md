# router-cli

A command-line tool to manage and monitor D-Link DSL-2750U routers.

Since the router doesn't provide a formal API, this tool works by authenticating with the router's web interface and parsing the HTML status pages to extract information.

## Features

- **Zero external dependencies** - Uses only Python standard library
- **Colorized output** - Highlights known vs unknown devices on your network
- **Comprehensive monitoring** - View status, clients, DHCP leases, routes, statistics, and logs
- **Remote management** - Reboot the router from the command line
- **ADSL statistics** - Monitor line quality metrics (SNR, attenuation, sync rates)
- **Configurable** - Define known devices with friendly aliases

## Installation

Requires Python 3.11 or higher.

### Using uv (recommended)

```bash
uv tool install router-cli
```

### Using pip

```bash
pip install router-cli
```

### From source

```bash
git clone https://github.com/d3vr/router-cli
cd router-cli
uv sync
```

## Configuration

Create a configuration file at `~/.config/router/config.toml`:

```toml
[router]
ip = "192.168.1.1"
username = "admin"
password = "your_password_here"

# Optional: Define known devices for colorized output
[known_devices]
"AA:BB:CC:DD:EE:FF" = "My Phone"
"11:22:33:44:55:66" = "Smart TV"
"DE:AD:BE:EF:00:01" = "Work Laptop"
```

The tool searches for configuration in the following locations (in order):
1. `./config.toml` (current directory)
2. `~/.config/router/config.toml`
3. `/etc/router/config.toml`

## Usage

### Quick Overview

```bash
router overview
```

Shows a dashboard with connection status, sync rates, connected devices, and warnings:

```
============================================================
                      ROUTER OVERVIEW
============================================================

CONNECTION
  ADSL Status:        Showtime
  Sync Rate:          8180 / 1022 Kbps (down/up)
  SNR Margin:         6.5 / 12.0 dB
  Default Gateway:    10.0.0.1
  WAN IP:             203.0.113.45 (Connected)

NETWORK
  Router IP:          192.168.1.1
  SSID:               MyNetwork
  Wireless Clients:   3
  DHCP Leases:        5

DEVICES
  My Phone          AA:BB:CC:DD:EE:FF  192.168.1.100  ⏱ 22:45:30
  Smart TV          11:22:33:44:55:66  192.168.1.101  ⏱ 20:15:45
  unknown-device    CC:DD:EE:FF:00:11  192.168.1.102  ⏱ 18:30:00

WARNINGS
  Unknown devices on network: 1

============================================================
```

### Available Commands

| Command | Description |
|---------|-------------|
| `router status` | Display full router status (system, internet, wireless, local network) |
| `router overview` | Show quick dashboard with highlights |
| `router clients` | List connected wireless clients |
| `router dhcp` | Show DHCP leases with expiration times |
| `router stats` | Show network interface and ADSL statistics |
| `router routes` | Display the kernel routing table |
| `router logs` | Show system logs |
| `router reboot` | Reboot the router |

### Command Details

#### Status

```bash
router status
```

Displays comprehensive router information:
- System info (model, firmware, date/time)
- Internet info (gateway, DNS servers, WAN connections)
- Wireless info (SSID, MAC, security mode)
- Local network (IP, subnet, DHCP status)

#### Wireless Clients

```bash
router clients
```

Lists all connected wireless devices with association and authorization status.

#### DHCP Leases

```bash
router dhcp
```

Shows all active DHCP leases with device names, MAC addresses, IP addresses, and lease expiration times.

#### Network Statistics

```bash
router stats
```

Displays detailed statistics including:
- LAN interface traffic (bytes, packets, errors, drops)
- WAN interface traffic
- ADSL line metrics (sync rate, SNR margin, attenuation, output power)

#### System Logs

```bash
router logs                    # Show all logs
router logs --tail 20          # Show last 20 entries
router logs --level error      # Filter by severity level
router logs -n 10 -l warning   # Combine options
```

#### Routing Table

```bash
router routes
```

Displays the kernel routing table with destination, gateway, subnet mask, flags, metric, and service.

#### Reboot

```bash
router reboot
```

Sends a reboot command to the router.

## Known Devices

The `[known_devices]` section in your config file maps MAC addresses to friendly names. This enables:

- **Color-coded output**: Known devices appear in green, unknown in red
- **Friendly names**: See "My Phone" instead of a hostname or MAC address
- **Security awareness**: Quickly spot unauthorized devices on your network

```toml
[known_devices]
"AA:BB:CC:DD:EE:FF" = "My Phone"
"11:22:33:44:55:66" = "Smart TV"
```

MAC addresses are matched case-insensitively.

## Development

### Setup

```bash
git clone https://github.com/d3vr/router-cli
cd router-cli
uv sync --all-groups
```

### Running Tests

```bash
uv run pytest
```

Tests use HTML fixtures captured from a real router, ensuring the parsing logic correctly handles the router's specific (and sometimes malformed) HTML output.

### Project Structure

```
router-cli/
├── src/router_cli/
│   ├── __init__.py
│   ├── main.py          # CLI entry point and formatters
│   ├── client.py        # RouterClient class and data models
│   └── config.py        # Configuration loading
├── tests/
│   ├── fixtures/        # HTML fixtures from real router
│   ├── test_client.py   # Client parsing tests
│   ├── test_main.py     # CLI formatting tests
│   └── test_config.py   # Config loading tests
├── config.example.toml  # Example configuration
└── pyproject.toml
```

## Compatibility

- **Python**: 3.11+
- **Router**: D-Link DSL-2750U (firmware ME_1.00)

This tool may work with other D-Link routers that share a similar web interface, but has only been tested with the DSL-2750U.

## License

MIT
