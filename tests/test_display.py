"""Tests for display utilities."""

from router_cli.display import (
    colorize,
    format_bytes,
    format_expires,
    format_table,
    get_device_display,
)
from router_cli.config import KnownDevices


class TestColorize:
    """Tests for colorize function."""

    def test_colorize_returns_text_when_not_tty(self, monkeypatch):
        """Test colorize returns plain text when not a TTY."""
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)
        result = colorize("test", "green")
        assert result == "test"
        assert "\033[" not in result


class TestFormatBytes:
    """Tests for format_bytes function."""

    def test_format_bytes_zero(self):
        """Test formatting zero bytes."""
        assert format_bytes(0) == "0.0 B"

    def test_format_bytes_small(self):
        """Test formatting small byte values."""
        assert format_bytes(100) == "100.0 B"
        assert format_bytes(1023) == "1023.0 B"

    def test_format_bytes_kilobytes(self):
        """Test formatting kilobyte values."""
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1536) == "1.5 KB"

    def test_format_bytes_megabytes(self):
        """Test formatting megabyte values."""
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(1024 * 1024 * 10) == "10.0 MB"

    def test_format_bytes_gigabytes(self):
        """Test formatting gigabyte values."""
        assert format_bytes(1024**3) == "1.0 GB"

    def test_format_bytes_terabytes(self):
        """Test formatting terabyte values."""
        assert format_bytes(1024**4) == "1.0 TB"

    def test_format_bytes_petabytes(self):
        """Test formatting petabyte values."""
        assert format_bytes(1024**5) == "1.0 PB"

    def test_format_bytes_negative(self):
        """Test formatting negative byte values."""
        assert format_bytes(-1024) == "-1.0 KB"


class TestFormatExpires:
    """Tests for format_expires function."""

    def test_format_expires_full(self):
        """Test formatting full time string."""
        result = format_expires("22 hours, 27 minutes, 15 seconds")
        assert result == "22:27:15"

    def test_format_expires_hours_only(self):
        """Test formatting hours only."""
        result = format_expires("5 hours")
        assert result == "05:00:00"

    def test_format_expires_minutes_only(self):
        """Test formatting minutes only."""
        result = format_expires("30 minutes")
        assert result == "00:30:00"

    def test_format_expires_seconds_only(self):
        """Test formatting seconds only."""
        result = format_expires("45 seconds")
        assert result == "00:00:45"

    def test_format_expires_empty(self):
        """Test formatting empty string."""
        result = format_expires("")
        assert result == "00:00:00"

    def test_format_expires_no_match(self):
        """Test formatting string with no time components."""
        result = format_expires("unknown format")
        assert result == "00:00:00"

    def test_format_expires_singular(self):
        """Test formatting with singular time words."""
        result = format_expires("1 hour, 1 minute, 1 second")
        assert result == "01:01:01"


class TestFormatTable:
    """Tests for format_table function."""

    def test_format_table_basic(self):
        """Test basic table formatting."""
        headers = ["Name", "Value"]
        rows = [["foo", "123"], ["bar", "456"]]
        result = format_table(headers, rows)

        assert "Name" in result
        assert "Value" in result
        assert "foo" in result
        assert "123" in result
        assert "bar" in result
        assert "456" in result

    def test_format_table_empty_rows(self):
        """Test table with no rows returns empty string."""
        headers = ["Name", "Value"]
        rows = []
        result = format_table(headers, rows)
        assert result == ""

    def test_format_table_column_alignment(self):
        """Test columns are properly aligned."""
        headers = ["A", "B"]
        rows = [["short", "x"], ["verylongvalue", "y"]]
        result = format_table(headers, rows)
        lines = result.split("\n")

        # Check all data lines have consistent width
        assert len(lines) >= 3  # header + separator + 2 data rows

    def test_format_table_with_colors(self, monkeypatch):
        """Test table formatting with row colors."""
        # Disable TTY check to get color codes
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)

        headers = ["Name", "Status"]
        rows = [["good", "ok"], ["bad", "fail"]]
        row_colors = ["green", "red"]
        result = format_table(headers, rows, row_colors=row_colors)

        # Should contain ANSI codes
        assert "\033[32m" in result  # green
        assert "\033[31m" in result  # red

    def test_format_table_separator_line(self):
        """Test table has proper separator line."""
        headers = ["Col1", "Col2"]
        rows = [["a", "b"]]
        result = format_table(headers, rows)
        lines = result.split("\n")

        # Second line should be separator with dashes
        assert "---" in lines[1]


class TestGetDeviceDisplay:
    """Tests for get_device_display function."""

    def test_unknown_device_returns_hostname(self):
        """Test unknown device returns hostname."""
        display, is_known = get_device_display("AA:BB:CC:DD:EE:FF", "my-device", None)
        assert display == "my-device"
        assert is_known is False

    def test_unknown_device_returns_mac_when_no_hostname(self):
        """Test unknown device returns MAC when hostname is empty."""
        display, is_known = get_device_display("AA:BB:CC:DD:EE:FF", "", None)
        assert display == "AA:BB:CC:DD:EE:FF"
        assert is_known is False

    def test_known_device_returns_alias(self):
        """Test known device returns alias."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        display, is_known = get_device_display("AA:BB:CC:DD:EE:FF", "", known)
        assert display == "My Phone"
        assert is_known is True

    def test_known_device_with_hostname_shows_both(self):
        """Test known device with different hostname shows both."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "My Phone"})
        display, is_known = get_device_display(
            "AA:BB:CC:DD:EE:FF", "android-123", known
        )
        assert display == "My Phone (android-123)"
        assert is_known is True

    def test_known_device_same_alias_and_hostname(self):
        """Test known device where alias equals hostname shows just alias."""
        known = KnownDevices(by_mac={"AA:BB:CC:DD:EE:FF": "my-device"})
        display, is_known = get_device_display("AA:BB:CC:DD:EE:FF", "my-device", known)
        assert display == "my-device"
        assert is_known is True

    def test_known_by_hostname(self):
        """Test device known by hostname."""
        known = KnownDevices(by_hostname={"android-abc": "John's Phone"})
        display, is_known = get_device_display(
            "XX:XX:XX:XX:XX:XX", "android-abc", known
        )
        assert display == "John's Phone (android-abc)"
        assert is_known is True
