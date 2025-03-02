import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import re
import ipaddress
import json
from typing import Any, Callable


def check_for_obfuscation(command_line: str) -> tuple[dict[str, bool], str]:

    flags = {
        "base_64_encoded": False,
        "obfuscated": False,
        "double_encoding": False,
        "reversed": False,
    }

    parsed_command_line = command_line

    reversed_command_line, flags["reversed"] = reverse_command(parsed_command_line)

    if flags["reversed"]:
        parsed_command_line = (
            reversed_command_line  # Use the reversed command line for further analysis
        )

    decoded_command_line, flags["base_64_encoded"], flags["double_encoding"] = (
        identify_and_decode_base64(parsed_command_line)
    )

    if flags["double_encoding"] or flags["base_64_encoded"]:
        parsed_command_line = decoded_command_line

    decoded_command_line, flags["obfuscated"] = encode_hex_and_oct_chars(
        parsed_command_line
    )

    if flags["obfuscated"]:
        parsed_command_line = decoded_command_line

    return flags, parsed_command_line


def encode_hex_and_oct_chars(command_line: str):
    """
    Decodes hexadecimal and octal escape sequences in a command line string.

    This function searches for hexadecimal (\\xXX) and octal (\\OOO) escape sequences
    in the input string and replaces them with their corresponding ASCII characters.

    Args:
        command_line (str): The input command line string to process.

    Returns:
        tuple: A tuple containing two elements:
            - The processed string with decoded escape sequences (if any were found).
            - A boolean indicating whether any changes were made to the input string.
    """

    def decode_match(match):
        hex_part, octal_part = match.groups()
        if hex_part:
            return chr(int(hex_part, 16))
        elif octal_part:
            return chr(int(octal_part, 8))
        return ""

    pattern = re.compile(r"\\x([0-9A-Fa-f]{2})|\\([0-7]{2,3})")

    parsed = pattern.sub(lambda m: decode_match(m), command_line)

    if parsed != command_line:
        return parsed, True

    else:
        return command_line, False


# -----------------------------------------------------------------------------
# 1) BASE64 & RELATED UTILITY FUNCTIONS
# -----------------------------------------------------------------------------


def detect_final_powershell_script(data: str) -> bool:
    known_powershell_commands = [
        "[Convert]::FromBase64String",
        "::ASCII",
        "Replace",
        "ForEach-Object",
        "powershell",
        "New-Object",
    ]

    for command in known_powershell_commands:
        if command.lower() in data.lower():
            return True

        else:
            continue

    return False


def try_decode(data: bytes) -> str:
    """Try decoding the data with UTF-8 first, then UTF-16-LE."""

    try:
        if b"\x00" in data:
            # If they remain the same, try UTF-16-LE
            decoded_str = data.decode("utf-16-le")

        else:
            decoded_str = data.decode("utf-8")

        return decoded_str

    except (UnicodeDecodeError, AttributeError):
        # If decoding fails, return None
        return ""


def decode_base64_until_final_script(encoded_str: str) -> tuple[str, int]:
    """Decode a base64 string until it looks like plain text."""
    decoded_str = encoded_str
    counter = 0

    while not detect_final_powershell_script(decoded_str):
        try:
            counter += 1
            decoded_bytes = base64.b64decode(decoded_str)
            decoded_str = try_decode(decoded_bytes)

        except Exception:
            break

    return decoded_str, counter


def is_base64(possible_base64: str | bytes) -> bool:
    """
    Validates if the provided string is a Base64-encoded string.
    For strings of length 20 or less, require that the string must contain '+', '/' or '='.
    For longer strings, rely solely on strict base64 decoding.
    """
    try:
        if isinstance(possible_base64, str):
            possible_base64 = possible_base64.encode("ascii")

        # Check for valid Base64 characters and correct padding
        if not re.fullmatch(b"[A-Za-z0-9+/]*={0,2}", possible_base64):
            return False

        # Ensure length is a multiple of 4
        if len(possible_base64) % 4 != 0:
            return False

        # Apply heuristic for short strings: must contain '=' if <= 20
        if len(possible_base64) <= 20 and b"=" not in possible_base64:
            return False

        # Attempt strict decoding
        base64.b64decode(possible_base64, validate=True)
        return True
    except Exception:
        return False


def clean_non_base64_chars(encoded_str: str) -> str:
    """
    Cleans and ensures the Base64 string contains only valid Base64 characters (+, /, =, alphanumeric).
    Adds proper padding if necessary.
    """
    # Remove all invalid Base64 characters
    cleaned_str = re.sub(r"[^A-Za-z0-9+/=]", "", encoded_str)

    # Fix padding only if the string length is reasonable for Base64
    if len(cleaned_str) % 4 != 0:
        cleaned_str += "=" * (4 - len(cleaned_str) % 4)

    return cleaned_str


def remove_null_bytes(decoded_str: str) -> str:
    """
    Removes null bytes from the decoded string.
    """
    return decoded_str.replace("\x00", "")


def handle_powershell_base64(command_line: str) -> tuple[str, bool, bool]:

    double_encoded_detected = False
    encoded = False
    num_of_encodings = 0
    result = command_line
    powershell_encoded_base64 = re.compile(
        r'-(?:encodedCommand|e)\s+["\']?([A-Za-z0-9+/]{4,}(?:={0,2}))["\']?',
        re.IGNORECASE,
    )

    while matches := powershell_encoded_base64.findall(result):

        demisto.debug(f"Detected -encodedCommand matches: {matches}")

        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches:
            demisto.debug("No valid Base64 matches found.")
            return "", False, False

        for match in valid_matches:
            decoded_segment, num_of_encodings = decode_base64_until_final_script(match)
            demisto.debug(f"Decoded segment: {decoded_segment}")

            if decoded_segment:
                escaped_match = match.replace("+", "\\+")
                encoded_param = re.compile(
                    f"(?i)-(?:encodedCommand|e)\\s+[\"']?{escaped_match}"
                )
                result = encoded_param.sub(r"%%TEMP%%", result)
                result = result.replace(r"%%TEMP%%", f'"{decoded_segment}"')

        if num_of_encodings > 1:
            double_encoded_detected = True

    if num_of_encodings != 0:
        encoded = True
        
    return result, encoded, double_encoded_detected


def handle_general_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Handles the general case of decoding Base64 in a command line.
    """

    result = command_line
    base64_pattern = r"[A-Za-z0-9+/]{4,}(?:={0,2})"
    num_of_encodings = 0
    double_encoded_detected = False

    while matches := re.findall(base64_pattern, result):
        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches:
            if num_of_encodings > 1:
                double_encoded_detected = True
                return result, True, double_encoded_detected

            elif num_of_encodings == 1:
                return result, True, double_encoded_detected

            else:
                return result, False, double_encoded_detected

        num_of_encodings += 1

        for match in valid_matches:
            decoded_bytes = base64.b64decode(match)
            decoded_segment = try_decode(decoded_bytes)

            if decoded_segment:
                result = result.replace(match, f'"{decoded_segment}"')
    
    return result, False, double_encoded_detected


def identify_and_decode_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Identifies and decodes all Base64 occurrences in a command line.
    Specifically targets encodedCommand flags commonly used in PowerShell.
    """

    if "powershell" in command_line.lower():
        return handle_powershell_base64(command_line)

    else:
        return handle_general_base64(command_line)


def reverse_command(command_line: str) -> tuple[str, bool]:
    """
    Detects if the command line contains a reversed PowerShell string and reverses it.
    """
    if "llehsrewop" in command_line.lower():
        return command_line[::-1], True
    return command_line, False


# -----------------------------------------------------------------------------
# 2) PATTERN-CHECKING FUNCTIONS
# -----------------------------------------------------------------------------


def check_suspicious_macos_applescript_commands(
    command_line: str,
) -> dict[str, list[list[str]]]:
    """
    Checks for suspicious macOS/AppleScript commands by grouping multiple sets
    of required substrings under a category. If all required substrings appear,
    that combination is recorded under its category.
    """
    text = command_line.lower()

    # Define categories and the sets of required substrings belonging to each
    patterns_by_category = {
        "infostealer_characteristics": [
            ["telegram", "deskwallet"],
            ["to set visible", "false"],
            ["chflags hidden"],
            ["osascript -e", "system_profiler", "hidden answer"],
            ["tell application finder", "duplicate"],
        ],
        "possible_exfiltration": [
            ["display dialog", "curl -"],
            ["osascript -e", "curl -x", "system_profiler"],
            ["osascript -e", "curl -"],
        ],
    }

    results: dict[str, list[list[str]]] = {}
    for category, pattern_groups in patterns_by_category.items():
        matched_combinations = []
        for required_phrases in pattern_groups:
            # If all required substrings appear in text
            if all(phrase in text for phrase in required_phrases):
                matched_combinations.append(required_phrases)
        # Store only if we found matches
        if matched_combinations:
            results[category] = matched_combinations

    return results


def check_malicious_commands(command_line: str) -> list[str]:
    patterns = [
        r"\bb374k\.php\b",
        r"\bbeacon\.exe\b",
        r"\bbloodhound\.exe\b",
        r"\bc99\.php\b",
        r"\bchopper\.php\b",
        r"\bcme\.exe\b",
        r"\bcobaltstrike_beacon\.exe\b",
        r"\bcovenant\.exe\b",
        r"\bdarkcomet\.exe\b",
        r"\beternalblue\.exe\b",
        r"\beternalromance\.exe\b",
        r"\bGetUserSPNs\.py\b",
        r"\bimpacket\-scripts\b",
        r"\bInvoke\-(?:ReflectivePEInjection|Shellcode|Expression|WmiMethod|KickoffAtomicRunner|SMBExec|Obfuscation|CradleCrafter|PSRemoting|TheHash)\b",
        r"\bkoadic\b",
        r"\bLaZagne\.exe\b",
        r"\blsassdump\.py\b",
        r"\bmeterpreter\.exe\b",
        r"\bmimikatz\b",
        r"\bmsfconsole\b",
        r"\bmsfvenom\b",
        r"\bnanocore\.exe\b",
        r"\bnjRAT\.exe\b",
        r"\bPowerUp\.ps1\b",
        r"\bpowercat\.ps1\b",
        r"\bPowGoop\.ps1\b",
        r"\bprocdump\.exe\b",
        r"\bquasar\.exe\b",
        r"\bresponder\.py\b",
        r"\brubeus\.exe\b",
        r"\bseatbelt\.exe\b",
        r"\bsharphound\.exe\b",
        r"\bsharpview\.exe\b",
        r"\bsmbexec\.py\b",
        r"\bwinrm\.vbs\b",
        r"\bwso\.php\b",
    ]

    matches: list[str] = []
    
    demisto.debug("Checking for malicious commands.")
    
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_reconnaissance_temp(command_line: str) -> list[str]:
    patterns = [
        r"\barp\b",
        r"\battrib\b",
        r"\bdir\b",
        r"\bfsutil\b",
        r"\bhostname\b",
        r"\bipconfig\b",
        r"\bnet\s+(?:group|localgroup|user)\b",
        r"\bnetstat\b",
        r"\bnslookup\b",
        r"\bping\b",
        r"\bquery\s+user\b",
        r"\breg\s+query\b",
        r"\broute\s+print\b",
        r"\bsc\s+query\b",
        r"\bsysteminfo\b",
        r"\btasklist\b",
        r"\btracert\b",
        r"\btree\b",
        r"\bwhoami\b",
        r"\bwmic\s+process\s+list\b",
    ]

    demisto.debug("Checking for reconnaissance patterns.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_windows_temp_paths(command_line: str) -> list[str]:
    """
    Identifies all occurrences of temporary paths in the given command line.
    """
    patterns = [
        r"%TEMP%",
        r"%TMP%",
        r"\bC:\\Temp\b",
        r"\bC:\\Windows\\System32\\Temp\b",
        r"\\AppData\\Local\\Temp\b",
        r"\\ProgramData\\Microsoft\\Windows\\Caches\b",
        r"\\Users\\Public\\Public\s+Downloads\b",
        r"\\Windows\\(?:Tasks|debug|Temp)\b",
        r"\\Windows\\System32\\spool\b",
    ]

    demisto.debug("Checking for windows temp paths in command line.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_suspicious_content(command_line: str) -> list[str]:
    patterns = [
        r"\-(?:EncodedCommand|enc|e)\b",
        r"\-(?:ExecutionPolicy|exec)\s+Bypass\b",
        r"\-(?:NonInteractive|noi)\b",
        r"\-(?:noprofile|nop)\b",
        r"\-(?:WindowStyle|window|w)\s+(?:hidden|h)\b",
        r"\bbcedit\b",
        r"\bBypass\b",
        r"\bcertutil.*\-encodehex\b",
        r"\bClipboardContents\b",
        r"\bGet\-GPPPassword\b",
        r"\bGet\-LSASecret\b",
        r"\blsass\b",
        r"\bnet\s+user\s+\/\s+add\b",
        r"\bnetsh\s+firewall\s+set\b",
        r"\breg\s+add\b",
        r"\brundll32\b",
        r"\bschtasks\b",
        r"\btaskkill\b",
        r"\s*\<NUL\b",
        r"wevtutil\s+cl\b",
    ]

    demisto.debug("Checking for suspicious content.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(
            match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE)
        )

    return matches


def check_amsi(command_line: str) -> list[str]:
    patterns = [
        r"\bSystem\.Management\.Automation\.AmsiUtils\b",
        r"\bamsiInitFailed\b",
        r"\bLoadLibrary\(\"amsi\.dll\"\)\b",
        r"\bAmsiScanBuffer\(\)\b",
    ]

    demisto.debug("Checking for amsi patterns.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_mixed_case_powershell(command_line: str) -> list[str]:
    mixed_case_powershell_regex = re.compile(
        r"\b(?=.*[a-z])(?=.*[A-Z])[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}(\.exe)?\b"
    )
    
    demisto.debug("Checking for mixed case powershell usage.")
    
    exclusions = {
        "Powershell",
        "PowerShell",
        "powershell",
        "Powershell.exe",
        "PowerShell.exe",
        "powershell.exe",
    }

    return [
        match.group()
        for match in mixed_case_powershell_regex.finditer(command_line)
        if match.group() not in exclusions
    ]


def check_powershell_suspicious_patterns(command_line: str) -> list[str]:
    """
    Detects potential obfuscation, backdoor mechanisms and Command-and-Control (C2) communication
    implemented using PowerShell.
    """
    patterns = [
        r"\bNew\-Object\s+Net\.Sockets\.(?:TcpClient|UdpClient)\b",
        r"\bSystem\.Net\.Sockets\.Tcp(?:Client|listener)\b",
        r"\.Connect\(",
        r"\.AcceptTcpClient\(",
        r"\.Receive\(",
        r"\.Send\(",
        r"\bpowershell.*IEX.*\(New\-Object\s+Net\.WebClient\)\b",
        r"\bInvoke\-WebRequest.*-Uri\b",
        r"\bInvoke\-RestMethod.*-Uri\b",
        r"\bNew\-Object\s+System\.Net\.WebClient\b",
        r"\bNew\-Object\s+Net\.WebClient\b",
        r"\bDownloadString\b",
        r"\bUploadString\b",
        r"\bSystem\.Net\.WebSockets\.ClientWebSocket\b",
        r"\.ConnectAsync\(",
        r"\[char\[\]\]\s*\([\d,\s]+\)|-join\s*\(\s*\[char\[\]\][^\)]+\)",
        r"\$(env:[a-zA-Z]+)\[\d+\]\s*\+\s*\$env:[a-zA-Z]+\[\d+\]",
        r"%\w+:~\d+,\d+%",
        r"(cmd\.exe.*\/V:ON|setlocal.*EnableDelayedExpansion)",
        r"if\s+%?\w+%?\s+geq\s+\d+\s+call\s+%?\w+%?:~\d+%?",
        r"(\[char\[[^\]]+\]\]){3,}",
        r"for\s+%?\w+%?\s+in\s*\([^)]{50,}\)",
        r"powershell.*?\b(iex.*?2>&1)\b",
    ]

    demisto.debug("Checking for powershell suspicious patterns.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_credential_dumping(command_line: str) -> list[str]:
    """
    Detects credential dumping techniques.
    """
    patterns = [
        r"\brundll32.*comsvcs\.dll\b",
        r"\bprocdump.*lsass\b",
        r"\bwmic\s+process\s+call\s+create.*lsass\b",
        r"\bInvoke\-Mimikatz\b",
        r"\btasklist.*lsass\b",
        r"\bProcessHacker\b",
        r"\bMiniDumpWriteDump\b",
        r"\bGet\-Credential\b",
        r"\blsass\.dmp\b",
        r"\bntds\.dit\b",
        r"\bntdsutil\.exe.*ntds.*create\b",
        r"\bsekurlsa\:\:",
        r"\bprocdump(\.exe)?\s+-ma\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp",
        r"\brundll32(\.exe)?\s+comsvcs\.dll,\s+MiniDump\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp.*",
        r'\bwmic\s+process\s+call\s+create\s+".*mimikatz.*"',
        r"\btaskmgr(\.exe)?\s+/create\s+/PID:\d+\s+/DumpFile:[a-zA-Z0-9_.-]+\.dmp",
        r'\bntdsutil(\.exe)?\s+".*ac i ntds.*" "ifm" "create full\s+[a-zA-Z]:\\.*"',
        r"\bsecretsdump(\.py)?\s+.*domain/.*:.*@.*",
        r"\breg\s+save\s+hklm\\(sam|system)\s+[a-zA-Z0-9_.-]+\.hive",
        r"\bwce(\.exe)?\s+-o",
        r"\bpowershell.*Invoke\-BloodHound.*-CollectionMethod.*",
    ]

    demisto.debug("Checking for credential dumping.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(
            match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE)
        )

    return matches


def check_lateral_movement(command_line: str) -> list[str]:
    """
    Detects potential lateral movement techniques from a given command line.
    """
    patterns = [
        r"\b(?:cmd(?:\.exe)?)\s+(?=.*\/q)(?=.*\/c).*?((?:1>\s?.*?)?\s*2>&1)\b",
        r"\bpsexec(\.exe)?",
        r"\bpsexesvc\.exe\b",
        r"\bpsexesvc\.log\b",
        r"\bwmic\s+/node:\s*[a-zA-Z0-9_.-]+",
        r"\bmstsc(\.exe)?",
        r"\\\\[a-zA-Z0-9_.-]+\\C\$\b",
        r"\bnet use \\\\.*\\IPC\$\b",
        r"\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\b",
        r"\bEnter-PSSession\b",
        r"\bpowershell.*Enter-PSSession\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-Credential\b",
        r'\bschtasks\s+/create\s+/tn\s+[a-zA-Z0-9_.-]+\s+/tr\s+".*"\s+/sc\s+[a-zA-Z]+\b',
        r"\bpowershell.*Invoke\-Command\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-ScriptBlock\b",
        r"\bmstsc(\.exe)?\s+/v\s+[a-zA-Z0-9_.-]+\b",
        r'\bwmiexec\.py\s+[a-zA-Z0-9_.-]+\s+".*"\b',
        r"\bssh.*?-o.*?StrictHostKeyChecking=no\b",
        r"\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\\.*\s+[a-zA-Z]:\\.*\b",
        r'\bcrackmapexec\s+smb\s+[a-zA-Z0-9_.-]+\s+-u\s+[a-zA-Z0-9_.-]+\s+-p\s+[a-zA-Z0-9_.-]+\s+-x\s+".*"\b',
    ]

    demisto.debug("Checking for lateral movement patterns.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_data_exfiltration(command_line: str) -> list[str]:
    """
    Detects potential data exfiltration techniques from a given command line.
    """
    patterns = [
        r"\bcurl\s+-X\s+(POST|PUT)\s+-d\s+@[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b",
        r"\bwget\s+--post-file=[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b",
        r"\bscp\s+-i\s+[a-zA-Z0-9_.-]+\.pem\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+:/.*\b",
        r"\bftp\s+-n\s+[a-zA-Z0-9_.-]+\s+<<END_SCRIPT.*put\s+.*END_SCRIPT\b",
        r"\bnc\s+[a-zA-Z0-9_.-]+\s+\d+\s+<\s+[a-zA-Z0-9_.-]+\b",
        r"\baws\s+s3\s+cp\s+[a-zA-Z0-9_.-]+\s+s3://[a-zA-Z0-9_.-]+/.*\b",
        r"\bgsutil\s+cp\s+[a-zA-Z0-9_.-]+\s+gs://[a-zA-Z0-9_.-]+/.*\b",
        r"\baz\s+storage\s+blob\s+upload\s+-f\s+[a-zA-Z0-9_.-]+\s+-c\s+[a-zA-Z0-9_.-]+.*\b",
        r"\bpowershell.*System\.Net\.WebClient.*UploadFile.*https?://[a-zA-Z0-9_.-]+/.*\b",
        r"\brsync\s+-avz\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+:/.*\b",
    ]

    demisto.debug("Checking for data exfiltration patterns.")
    
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_suspicious_mshta(command_line: str) -> list[str]:
    patterns = [
        r"mshta(?:\.exe)?\s*[\"\']?.*?(?:vbscript|javascript)\s*:",
        r"mshta(?:\.exe)?\s*[\"\']?\s*(?:https?|ftp|file)://",
        r"mshta(?:\.exe)?.*(?:CreateObject|Wscript\.Shell|Shell\.Application|powershell|document\.write)",
        r"mshta(?:\.exe)?.*(?:-enc|base64)",
    ]

    demisto.debug("Checking for suspicious mshta usage.")
    
    matches: list[str] = []

    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_social_engineering(command_line: str) -> list[str]:
    checkmark_emojis = [
        "\u2705",  # ✅ Check Mark Button
        "\u2714",  # ✔️ Heavy Check Mark
        "\u2611",  # ☑️ Ballot Box with Check
        "\u1F5F8",  # 🗸 Light Check Mark
        "\u1F5F9",  # 🗹 Ballot Box with Bold Check
    ]

    demisto.debug("Checking for social engineering patterns in command.")
    
    for emoji in checkmark_emojis:
        if emoji in command_line:
            return ["Emoji Found in command line"]

    return []


def check_custom_patterns(
    command_line: str, custom_patterns: list[str] | None = None
) -> list[str]:
    matches: list[str] = []
    if custom_patterns:
        # Ensure custom_patterns is a list
        if isinstance(custom_patterns, str):
            custom_patterns = [custom_patterns]  # Convert single string to a list
        for pattern in custom_patterns:
            matches.extend(re.findall(pattern, command_line, re.IGNORECASE))
    return matches


# -----------------------------------------------------------------------------
# 3) IP & INDICATOR EXTRACTION
# -----------------------------------------------------------------------------


def is_reserved_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
        )
    except ValueError:
        return False


def extract_indicators(command_line: str) -> dict[str, list[str]]:
    """
    Extracts indicators by type (e.g., 'IP', 'Domain') and returns them as a dictionary.
    """
    extracted_by_type: dict[str, list[str]] = {}

    demisto.debug("Attempting to extract indicators from command line.")
    
    try:
        indicators = demisto.executeCommand("extractIndicators", {"text": command_line})

        if indicators and isinstance(indicators, list):
            contents = indicators[0].get("Contents", {})

            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except json.JSONDecodeError:
                    return {}

            if isinstance(contents, dict):
                for indicator_type, values in contents.items():
                    if isinstance(values, list):
                        for value in values:
                            if value == "::":
                                continue
                            if indicator_type == "IP" and is_reserved_ip(value):
                                continue  # Skip reserved IPs

                            if indicator_type not in extracted_by_type:
                                extracted_by_type[indicator_type] = []
                            extracted_by_type[indicator_type].append(value)

    except Exception as e:
        demisto.debug(f"Failed to extract indicators: {str(e)}")

    return extracted_by_type


# -----------------------------------------------------------------------------
# 4) SCORING FUNCTION
# -----------------------------------------------------------------------------


def calculate_score(results: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregates findings from the analysis and assigns a score (0-100).
    Incorporates bonuses for certain risky combinations.
    """

    # Define weights for base scoring
    weights: dict[str, int] = {
        "mixed_case_powershell": 25,
        "reversed_command": 25,
        "powershell_suspicious_patterns": 25,
        "credential_dumping": 25,
        "double_encoding": 25,
        "amsi_techniques": 25,
        "malicious_commands": 25,
        "custom_patterns": 25,
        "suspicious_macos_applescript_commands": 25,
        "suspicious_mshta": 25,
        "social_engineering": 25,
        "data_exfiltration": 15,
        "lateral_movement": 15,
        "obfuscated": 15,
        "windows_temp_path": 10,
        "indicators": 10,
        "reconnaissance": 10,
        "base64_encoding": 5,
        "suspicious_parameters": 5,
    }

    # Initialize findings and scores for original and decoded
    findings: dict[str, list[Any]] = {"original": [], "decoded": []}
    scores: dict[str, int] = {"original": 0, "decoded": 0}

    # Define risk groups and bonus scores
    high_risk_keys = {
        "mixed_case_powershell",
        "double_encoding",
        "amsi_techniques",
        "malicious_commands",
        "powershell_suspicious_patterns",
        "credential_dumping",
        "reversed_command",
        "suspicious_macos_applescript_commands",
        "suspicious_mshta",
        "custom_patterns",
        "social_engineering",
    }

    medium_risk_keys = {
        "data_exfiltration",
        "lateral_movement",
        "indicators",
        "obfuscated",
    }

    low_risk_keys = {
        "suspicious_parameters",
        "windows_temp_path",
        "reconnaissance",
        "base64_encoding",
    }

    risk_bonuses: dict[str, int] = {
        "high": 30,
        "medium": 20,
        "low": 10,
    }

    # Define the fixed theoretical maximum score
    theoretical_max = 120

    # Helper function to calculate score and detect combinations
    def process_context(context_results: dict[str, Any]) -> tuple[int, list[str]]:
        context_score = 0
        context_findings: list[str] = []
        context_keys_detected = set()

        # Calculate base score for each key (count each category once)
        for key, value in context_results.items():
            if value and value != "{}":
                context_keys_detected.add(key)
                if isinstance(value, list) and len(value) > 0:
                    # Add weight once, report how many instances were found
                    context_score += weights.get(key, 0)
                    context_findings.append(
                        f"{key.replace('_', ' ')} detected ({len(value)} instances)"
                    )
                else:
                    # Not a list or empty list, just count once
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected")

        # Apply combination bonuses based on detected keys
        if (high_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["high"]
            context_findings.append("High-risk combination detected")
        elif (medium_risk_keys & context_keys_detected) and len(
            context_keys_detected
        ) > 1:
            context_score += risk_bonuses["medium"]
            context_findings.append("Medium-risk combination detected")
        elif (low_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["low"]
            context_findings.append("Low-risk combination detected")

        return context_score, context_findings

    # Process original
    original_results = results.get("analysis", {}).get("original", {})
    scores["original"], findings["original"] = process_context(original_results)

    # Process decoded
    #decoded_results = results.get("analysis", {}).get("decoded", {})
    #scores["decoded"], findings["decoded"] = process_context(decoded_results)

    # Check global combinations (like double encoding globally)
    if original_results.get("double_encoding", False):
        scores["decoded"] += weights["double_encoding"]
        findings["decoded"].append("double_encoding")

    # Calculate total raw score
    total_raw_score = scores["original"]# + scores["decoded"]

    # Normalize the score to fit within 0-100 based on the fixed theoretical max
    normalized_score = (total_raw_score / theoretical_max) * 100
    normalized_score = min(normalized_score, 100)  # Cap at 100

    # Determine overall risk level
    risk = "Low Risk"
    if normalized_score > 90:
        risk = "Critical Risk"
    elif normalized_score > 50:
        risk = "High Risk"
    elif normalized_score > 25:
        risk = "Medium Risk"

    return {
        "score": int(round(normalized_score, 0)),
        "findings": findings,
        "risk": risk,
    }


# -----------------------------------------------------------------------------
# 5) ANALYZER FUNCTION
# -----------------------------------------------------------------------------


def analyze_command_line(
    command_line: str, custom_patterns: list[str] | None = None
) -> dict[str, Any]:
    """
    Analyzes the given command line for suspicious patterns, indicators, and encodings.
    Returns a dictionary containing:
      - "original_command"
      - "analysis" -> {"original": {...}, "decoded": {...}}
      - "decoded_command" (if any)
      - "Double Encoding Detected" (bool)
      - "score", "findings", "risk"
    """

    checks: dict[str, Callable[[str]]] = {
        "malicious_commands": check_malicious_commands,
        "windows_temp_path": check_windows_temp_paths,
        "suspicious_parameters": check_suspicious_content,
        "mixed_case_powershell": check_mixed_case_powershell,
        "powershell_suspicious_patterns": check_powershell_suspicious_patterns,
        "credential_dumping": check_credential_dumping,
        "suspicious_mshta": check_suspicious_mshta,
        "reconnaissance": check_reconnaissance_temp,
        "lateral_movement": check_lateral_movement,
        "data_exfiltration": check_data_exfiltration,
        "amsi_techniques": check_amsi,
        "indicators": extract_indicators,
        "social_engineering": check_social_engineering,
    }

    results: dict[str, Any] = {
        "original_command": command_line,
        "analysis": {"original": {}},
    }

    flags, parsed_command_line = check_for_obfuscation(command_line)

    if parsed_command_line:
        results["parsed_command"] = parsed_command_line

    # Perform checks on the original command line
    for check_name, check in checks.items():
        results["analysis"]["original"][check_name] = check(parsed_command_line)


    results["analysis"]["custom_patterns"] = check_custom_patterns(parsed_command_line, 
                                                                   custom_patterns) if custom_patterns else []
    
    # Only set "base64_encoding" if we actually decoded something

    for flag, value in flags.items():
        if value:
            results["analysis"]["original"][flag] = value

    # Handle macOS
    if "osascript" in parsed_command_line.lower():
        results["analysis"]["original"]["macOS_suspicious_commands"] = (
            check_suspicious_macos_applescript_commands(parsed_command_line)
        )

    #results["analysis"]["original"] = original_analysis
    score_details = calculate_score(results)
    results.update(score_details)

    return results


def main():
    """
    Entry point for analyzing command lines for suspicious activities and patterns.
    """
    args = demisto.args()
    command_lines = args.get("command_line", [])
    custom_patterns = args.get("custom_patterns", [])
    readable_output = ""

    if isinstance(command_lines, str):
        command_lines = [command_lines]

    if isinstance(custom_patterns, str):
        custom_patterns = [custom_patterns]

    # Analyze each command line
    results = [analyze_command_line(cmd, custom_patterns) for cmd in command_lines]

    # Prepare readable output for the results

    for result in results:
        if result.get("parsed_command", None) != result["original_command"]: 
            parsed_command = f"**Decoded Command**: {result['parsed_command']}\n"
        else:
            parsed_command = None

        readable_output += (
            f"**Command Line**: {result['original_command']}\n"
            f"{parsed_command if parsed_command else ''}"
            f"**Risk**: {result['risk']}\n"
            f"**Score**: {result['score']}\n"
            f"**Findings (Original)**: {', '.join(result['findings']['original'])}\n\n\n"
        )

    # Return results
    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="CommandLineAnalysis",
            outputs_key_field="original_command",
            outputs=results,
        )
    )


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
