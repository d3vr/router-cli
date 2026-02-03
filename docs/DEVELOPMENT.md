# Development Guide

This guide covers development setup, testing, and contribution guidelines.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) - Fast Python package manager

## Quick Start

```bash
# Clone and enter the repo
git clone <repo-url>
cd router-cli

# Install dependencies (creates .venv automatically)
uv sync --all-groups

# Run all checks
uvx ruff check && uvx ruff format --check && uv run pytest
```

## Configuration

Copy the example config and update with your router credentials:

```bash
cp config.example.toml ~/.config/router/config.toml
# Edit with your router IP, username, and password
```

For development, you can also use `./config.toml` in the project root.

## Testing

Tests use HTML fixtures captured from a real router, allowing parser testing without network access.

### Running Tests

```bash
uv run pytest           # Run all tests
uv run pytest -v        # Verbose output
uv run pytest -k dhcp   # Run tests matching "dhcp"
```

### Adding New Tests

1. **Capture HTML** from the router (browser dev tools → Network tab → Copy Response)
2. **Save fixture** to `tests/fixtures/<page_name>.html`
3. **Add pytest fixture** in `tests/conftest.py`:
   ```python
   @pytest.fixture
   def my_page_html() -> str:
       return (FIXTURES_DIR / "my_page.html").read_text()
   ```
4. **Write test** using the fixture:
   ```python
   def test_parse_my_page(client, my_page_html):
       result = client._parse_my_page(my_page_html)
       assert result.some_field == "expected"
   ```

## Code Style

This project uses **ruff** for both linting and formatting.

```bash
# Check for issues
uvx ruff check
uvx ruff format --check

# Auto-fix
uvx ruff check --fix
uvx ruff format
```

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
```

Types: `feat`, `fix`, `refactor`, `ci`, `docs`, `test`, `chore`

## CI/CD

The CI pipeline (`.github/workflows/ci.yml`) runs:
1. `uvx ruff check` - Linting
2. `uvx ruff format --check` - Format verification
3. `uv run pytest` - Tests
4. `uv build` - Package build

Releases are published to PyPI via `.github/workflows/release.yml` when tags are pushed.

## Architecture Overview

The codebase is organized into focused modules:

- **`main.py`** - CLI entry point using `argparse`. Handles argument parsing and dispatches to commands.
- **`client.py`** - `RouterClient` handles HTTP requests to the router using `urllib.request`.
- **`parser.py`** - HTML parsing logic with regex-based extraction (the router returns malformed HTML).
- **`models.py`** - Data classes for structured router data (status, clients, DHCP leases, etc.).
- **`commands.py`** - Command implementations (`cmd_status`, `cmd_clients`, etc.).
- **`display.py`** - Output display logic for terminal rendering.
- **`formatters.py`** - Formatting functions for human-readable and JSON output.
- **`config.py`** - TOML configuration loading with environment variable and CLI override support.

See `AGENTS.md` for pitfalls and edge cases when working with the router's quirky web interface.
