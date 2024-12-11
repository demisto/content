import pytest
from your_script import (
    is_base64,
    clean_non_base64_chars,
    decode_base64,
    identify_and_decode_base64,
    analyze_command_line,
    check_malicious_commands,
    check_reconnaissance_temp,
    check_windows_temp_paths,
    check_suspicious_content,
    check_amsi,
    check_powershell_suspicious_patterns,
    check_credential_dumping,
    check_lateral_movement,
    check_data_exfiltration,
)


@pytest.mark.parametrize("input_str, expected", [
    ("VGVzdCBzdHJpbmc=", True),  # Valid Base64
    ("VGVzdCBzdHJpbmc==", True),  # Valid Base64 with padding
    ("InvalidBase64", False),  # Invalid characters
    ("TooShort==", False),  # Too short to be valid
])
def test_is_base64(input_str, expected):
    assert is_base64(input_str) == expected


@pytest.mark.parametrize("input_str, expected", [
    ("aGVsbG8@#", "aGVsbG8"),
    ("dGVzdA**==", "dGVzdA=="),
    ("123+=456/=", "123=456="),
])
def test_clean_non_base64_chars(input_str, expected):
    assert clean_non_base64_chars(input_str) == expected


@pytest.mark.parametrize("input_str, expected", [
    ("VGVzdA==", "Test"),
    ("VGVzdCBzdHJpbmc=", "Test string"),
    ("InvalidBase64", None),
])
def test_decode_base64(input_str, expected):
    result, _ = decode_base64(input_str)
    assert result == expected


def test_decode_base64_recursive():
    encoded = "VkRWRlRtVjNjWE5oVkRWMVYwVk9hMVZTVkRCV1YxSmFWVzFzY1ZGdFRuQlpiRkpGVW01T1dGbDZWbkphUnpGTFZURmFjRlpxUm1GVmJGSnJXa2RHTTFwRmRGZGtNMEpIVmpKR2FsSnNXbWxTTTA1SFdWVldUMU5WYUZaaU1rcHpWa2Q0UzFkc1JtRlhSRVpyWkZaS2VWWnRlR0ZXUms1VldXMUdTV0pHV21oVWExcENaVVprYTJGclNtdE9WVVpyVWpBMU1HSklWbXRTTWtwc1pHeGtWMVZYYkU5aVYyaFlaVWRHU0Zkc1dsZFRWRUpZVm0xT2ExWXhVbkppVjJ4VVlteHdiMVp0WkZabFJtUlFWbXRHTTFwRmRGZGtNMUo2VGtWd1QxZEdVbk5WYmxacFVteFNlbFl3WkdwVmJHaHBUV3RzYTFJeFVuUlZNRnBTVWxkR1dWWkhaR3hWYkdSVVZqTkZlRlJxUms1U1ZGWmhWbTEwWVdOVmFHcE5XRXByV2tWYWVGcElUVEJaYTNSclUzcHNSRkpIYUVWUmExUkhZekZhWVdRd2JISmtNWEI1Vld4a2FWSlVWbTlXVmxWcFZtdHdXazFXU2pGWFdHeFlWbXMxVjJReFdrZGpTRXBUVVdzMVZrOVdVbGhTTTAxSFkyeGFkVkpHUWxWaE1sSlJWbTFTU0ZkRlNsbE9NMUl5VGxaWk1GcElUbEJhVldSb1pWaE9NMU5JVGtkU2FsSnNaMGRLU0ZaR2RGaFNNWEIzVFZaWk1HSklRbGRqTTFwclpXeHdTMXBHVG1oaE1YQkpWa1Z3WVZac2JGTlhSVXBTVmxrS1NWWnFTazlqTTFJMlZGUXdXRXBSTTA1R1RHdE9ibVZYVGxObFVrNUdWakZpUjFaR1ZqRmtibEpxUWtoVWExcFZaVVprYTJGclNtdE9WVVp6VGxBMU1HSklRbGhrUjA1cVprZEdVVlpITVZkalJrNVdVbTEwWVdOVmFHaFZhMVozVkZoa1ZWWlhkR2xVVjNodlVWUlplRlpyVms5bFIwWm9UVlpLUkZrd1RuZGFWV1IwWkVkU2RWSlVUbGRWYm14VVVqSTBOVlZzU2tkV01rNXNWRzE0WVdONWNHcE5XRUpHVWxjNWNsWnJjRXBoYldoclVteGFTMVZxVG1sVVZWcHpWVmROYWxKWWFIZFNiWFJVWWpGU2NGVjZhRlpXTW5CTFpFVXdkRlpyWkd4V1YzaHZVbXhrUm1OSGVHZFNiWFJVWVZkT1dGWnFSbUZXYkVwU1RVaHdWMVl5ZHpGV1ZscFZUVlJzVlZac1drZGpSbHByWVRBMVdWZEdVbXhVYkdSWVpWWktNMVpXVGtWTmJGWm9aVVprYW1OSGFIZFNiWFJVWWpGU2NGVjZhRkpUTWxKUVZqQkNNSGxXWkd0V01teFhUVlpXTmxsWGFHcE5WRUozWVVaT1NHRkdUbGRaTUZwSFkyZG9VVkpXUm1sU01XUnpWa1UxUzFwRlNsVk5WbkJXWVZjMVZtRlZXbUZpVlhCRldWWk5TMlJxUWs5VVdFSkhXbGRzYVZZd2NHeFpNWEJ5VGtWYWVGcElUbEpVTVZsVVlsUlZlVlZyVkc5aU1rcHpWbTEwWVdONWEzZGFNMUpUVGxaYWVGcEpUakJhUlhoVVRWVmtWMVZWWkhGU1NsVk5WbkJXWVZjMVZtRlZXbUZpVlhCRldWWk5TMlJxUWs5VVdFSkhXbGRzYVZZd2NHeFpNWEJ5VGtWYWVGcElUbEpVTVZsVVlsUlZlVlZyVkc5aU1rcHpWbTEwWVdONWEzZGFNMUpUVGxaYWVGcEpUakJhUlhoVVRWVmtWMVZWWkhGU1NsVk5WbkJXWVZjMVZtRlZXbUZpVlhCRldWWk5TMlJxUWs5VVdFSkhXbGRzYVZZd2NHeFpNWEJ5VGtWYWVGcElUbEpVTVZsVVlsUlZlVlZyVkc5aU1rcHpWbTEwWVdONWEzZGFNMUpUVGxaYWVGcEpUakJhUlhoVVRWVmtWMVZWWkhGU1NsVk5WbkJXWVZjMVZtRlZXbUZpVlhCRldWWk5TMlJxUWs5VVdFSkhXbGRz"
    
    decoded, _ = decode_base64(encoded)
    assert "Test string" in decoded  # Confirm the content


@pytest.mark.parametrize("command_line, expected", [
    ("mimikatz && procdump.exe", ["mimikatz", "procdump.exe"]),
    ("ipconfig && netstat", ["ipconfig", "netstat"]),
    ("InvalidCommand", []),
])
def test_check_malicious_commands(command_line, expected):
    assert check_malicious_commands(command_line) == expected


def test_analyze_command_line():
    command_line = "VGVzdA== && mimikatz"
    results = analyze_command_line(command_line)
    assert "mimikatz" in results["analysis"]["original"]["malicious_commands"]
    assert results["analysis"]["original"]["base64_encoding"] == "Test"
