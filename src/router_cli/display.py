"""Display utilities for terminal output."""

import re
import sys
import threading
from contextlib import contextmanager

from .config import KnownDevices


# ANSI color codes
_COLORS = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "reset": "\033[0m",
}


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


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


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


def get_device_display(
    mac: str, hostname: str, known_devices: KnownDevices | None
) -> tuple[str, bool]:
    """Get display name for a device and whether it's known.

    Returns (display_name, is_known) tuple.
    If known, display_name is 'Alias (hostname)'.

    Supports lookup by both MAC address and hostname (for devices with
    random MAC addresses like some Android phones).
    """
    if known_devices is None:
        return hostname or mac, False

    alias = known_devices.get_alias(mac, hostname)
    if alias:
        if hostname and hostname != alias:
            return f"{alias} ({hostname})", True
        return alias, True
    return hostname or mac, False


def format_table(
    headers: list[str],
    rows: list[list[str]],
    row_colors: list[str | None] | None = None,
    padding: int = 2,
) -> str:
    """Format data as an aligned table with optional row coloring.

    Args:
        headers: Column header labels
        rows: List of rows, each row is a list of cell values
        row_colors: Optional list of color names (one per row), None for no color
        padding: Extra padding to add to column widths

    Returns:
        Formatted table as a string

    Example:
        >>> format_table(
        ...     ["Name", "Value"],
        ...     [["foo", "123"], ["bar", "456"]],
        ...     row_colors=["green", "red"]
        ... )
    """
    if not rows:
        return ""

    # Calculate column widths based on headers and data
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(val)))

    # Add padding
    widths = [w + padding for w in widths]

    # Build header line
    header_line = "".join(h.ljust(widths[i]) for i, h in enumerate(headers))

    # Build separator line
    sep_line = "".join(("-" * (w - padding)).ljust(w) for w in widths)

    # Build data lines
    lines = [header_line, sep_line]

    for row_idx, row in enumerate(rows):
        line = "".join(
            str(val).ljust(widths[i]) if i < len(widths) else str(val)
            for i, val in enumerate(row)
        )

        # Apply color if specified
        if row_colors and row_idx < len(row_colors) and row_colors[row_idx]:
            line = colorize(line, row_colors[row_idx])

        lines.append(line)

    return "\n".join(lines)
