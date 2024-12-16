import pytest
from CommandLineAnalysis import (
    analyze_command_line,
    check_malicious_commands,
    clean_non_base64_chars,
    decode_base64,
    is_base64,
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
    encoded = "UmVjdXJzaXZlIGRlY29kZSBvZiBkMlVnZDJGdWRDQjBieUJrWldOdlpHVWdhWFFnVmtkb2NHTjVRbkJqZVVKb1NVaFNiR016VVdkak0xSjVZVmMxYmc9PQ=="

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
