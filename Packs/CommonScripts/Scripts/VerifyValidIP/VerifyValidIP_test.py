import VerifyValidIP
import demistomock as demisto
from VerifyValidIP import is_valid_ip_address


class TestVerifyValidIP:
    """Test cases for VerifyValidIP script."""

    def test_valid_ipv4_addresses(self):
        """Test validation of valid IPv4 addresses."""
        valid_ipv4_addresses = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "127.0.0.1", "0.0.0.0", "255.255.255.255"]

        for ip in valid_ipv4_addresses:
            assert is_valid_ip_address(ip) is True, f"IPv4 {ip} should be valid"

    def test_valid_ipv6_addresses(self):
        """Test validation of valid IPv6 addresses."""
        valid_ipv6_addresses = [
            "2001:db8::1",
            "::1",
            "fe80::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::",
            "::ffff:192.0.2.1",
        ]

        for ip in valid_ipv6_addresses:
            assert is_valid_ip_address(ip) is True, f"IPv6 {ip} should be valid"

    def test_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses."""
        invalid_addresses = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "invalid_ip",
            "www.example.com",
            "",
            "192.168.1.-1",
            "2001:db8::gggg",
            "2001:db8:::1",
        ]

        for ip in invalid_addresses:
            assert is_valid_ip_address(ip) is False, f"Invalid IP {ip} should be rejected"

    def test_edge_cases(self):
        """Test edge cases."""
        edge_cases = [
            ("192.168.1.1", True),
            ("   192.168.1.1   ", False),  # Whitespace should make it invalid
            ("192.168.1.1/24", False),  # CIDR notation should be invalid
            ("localhost", False),  # Hostname should be invalid
        ]

        for ip, expected in edge_cases:
            assert is_valid_ip_address(ip) is expected, f"Edge case {ip} should return {expected}"


def test_main_function(mocker):
    """Test the main function with mocked demisto."""
    # Mock demisto functions
    mocker.patch.object(demisto, "args", return_value={"input": "192.168.1.1,invalid_ip,2001:db8::1"})
    mock_return_results = mocker.patch.object(VerifyValidIP, "return_results")

    # Import and run main
    from VerifyValidIP import main

    main()

    # Verify the results - now expecting a list of dicts
    expected_outputs = {
        "VerifyValidIP": [
            {"IP": "192.168.1.1", "Valid": True},
            {"IP": "invalid_ip", "Valid": False},
            {"IP": "2001:db8::1", "Valid": True},
        ]
    }

    # Get the actual call arguments
    call_args = mock_return_results.call_args[0][0]
    assert call_args.outputs == expected_outputs
