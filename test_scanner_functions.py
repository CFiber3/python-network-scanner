import pytest
import socket
from scanner_functions import validate_target, validate_port, parse_port_range, scan_port

class TestValidatePort:
    def test_valid_port_returns_int(self):
        assert validate_port("80") == 80


    def test_port_with_spaces_is_accepted(self):
        assert validate_port(" 443 ") == 443


    def test_lowest_valid_port(self):
        assert validate_port("1") == 1


    def test_highest_valid_port(self):
        assert validate_port("65535") == 65535


    def test_zero_is_rejected(self):
        with pytest.raises(ValueError):
            validate_port("0")


    def test_port_above_range_is_rejected(self):
        with pytest.raises(ValueError):
            validate_port("65536")


    def test_negative_port_is_rejected(self):
        with pytest.raises(ValueError):
            validate_port("-5")


    def test_non_number_is_rejected(self):
        with pytest.raises(ValueError):
            validate_port("abc")


    def test_empty_string_is_rejected(self):
        with pytest.raises(ValueError):
            validate_port("")

class TestParsePortRange:
    def test_single_port(self):
        assert parse_port_range("80") == (80, 80)

    def test_port_range(self):
        assert parse_port_range("20-80") == (20, 80)

    def test_spaces_in_port_range(self):
        assert parse_port_range(" 20 - 80 ") == (20, 80)

    def test_full_port_range(self):
        assert parse_port_range("1-65535") == (1, 65535)

    def test_same_port_range(self):
        assert parse_port_range("80-80") == (80, 80)

    def test_start_port_greater_than_end_port(self):
        with pytest.raises(ValueError):
            parse_port_range("80-20")

    def test_below_range_port(self):
        with pytest.raises(ValueError):
            parse_port_range("0-80")

    def test_above_range_port(self):
        with pytest.raises(ValueError):
            parse_port_range("20-70000")

    def test_non_number_in_port(self):
        with pytest.raises(ValueError):
            parse_port_range("abc")

    def test_non_number_in_port_range(self):
        with pytest.raises(ValueError):
            parse_port_range("abc-80")

    def test_missing_end_port(self):
        with pytest.raises(ValueError):
            parse_port_range("20-")

    def test_missing_start_port(self):
        with pytest.raises(ValueError):
            parse_port_range("-80")

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            parse_port_range("20-80-100")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            parse_port_range("")

class TestValidateTarget:
    def test_valid_target(self):
        assert validate_target("127.0.0.1") == "127.0.0.1"

    def test_spaces_in_target(self):
        assert validate_target(" 127.0.0.1 ") == "127.0.0.1"

    def test_highest_ip(self):
        assert validate_target("255.255.255.255") == "255.255.255.255"

    def test_zero_ip(self):
        assert validate_target("0.0.0.0") == "0.0.0.0"

    def test_non_ip_target(self):
        with pytest.raises(ValueError):
            validate_target("abc")

    def test_above_highest_ip(self):
        with pytest.raises(ValueError):
            validate_target("300.1.1.1")

    def test_too_few_octets(self):
        with pytest.raises(ValueError):
            validate_target("127.0.0")

    def test_too_many_octets(self):
        with pytest.raises(ValueError):
            validate_target("127.0.0.1.1")

    def test_ipv6_target(self):
        with pytest.raises(ValueError):
            validate_target("::1")

    def test_hostname_target(self):
        with pytest.raises(ValueError):
            validate_target("localhost")

    def test_empty_target(self):
        with pytest.raises(ValueError):
            validate_target("")

class TestScanPort:
    def test_port_open(self):
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            assert scan_port("127.0.0.1", port) == "open"

    def test_port_closed(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            server.close()  # Close the server to make the port closed
            assert scan_port("127.0.0.1", port) == "closed"