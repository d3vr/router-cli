# Agent Guidelines for router-cli

This document helps AI agents work effectively in this codebase.

For detailed development setup and testing guides, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Tech Stack

- **Python 3.10+** (see `.python-version` for exact version)
- **uv** - Package manager and virtual environment
- **ruff** - Linting and formatting
- **pytest** - Testing framework

## Development Commands

Always use these commands to match CI behavior:

```bash
# Install dependencies (creates .venv automatically)
uv sync --all-groups

# Run linter
uvx ruff check

# Run formatter check (CI will fail if not formatted)
uvx ruff format --check

# Auto-fix lint issues
uvx ruff check --fix

# Auto-format code
uvx ruff format

# Run tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Build package
uv build
```

**Important:** Do NOT use `python -m pytest` or `pip install`. Always use `uv run` and `uv sync`.

## Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>: <description>

[optional body]
```

**Types used in this project:**
- `feat:` - New feature
- `fix:` - Bug fix
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `ci:` - CI/CD changes
- `docs:` - Documentation only
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

**Examples from this repo:**
```
ci: add ruff checks, PyPI publishing, and simplify CI matrix
feat: add animated spinner for router API requests
fix: improve error handling with retries and meaningful messages
```

## Common Pitfalls

### 1. Router returns HTML error pages with 200 status
The router often returns error/login pages with HTTP 200. Always check response content, not just status code. The `_is_login_page()` and `_is_error_page()` methods in `client.py` handle this.

### 2. Malformed HTML from router
The router's HTML is often malformed (unclosed tags, mixed case, etc.). Use flexible regex patterns with `re.IGNORECASE` and `re.DOTALL`. The `_extract_value()` method tries multiple patterns.

### 3. Session expiration
Router sessions expire. The `fetch_page()` method auto-detects this and re-authenticates. Look for login page patterns in responses.

### 4. CI uses Python 3.10, not latest
The CI explicitly uses Python 3.10 for compatibility. Don't use syntax/features from Python 3.11+ (like `except*`, `tomllib` stdlib).

## Before Submitting Changes

Run the full CI check locally:

```bash
uvx ruff check && uvx ruff format --check && uv run pytest
```

Or fix issues automatically:

```bash
uvx ruff check --fix && uvx ruff format && uv run pytest
```
