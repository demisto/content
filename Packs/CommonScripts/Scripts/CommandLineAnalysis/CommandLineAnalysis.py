import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import ipaddress
import json
import re
from typing import Any
from collections.abc import Callable


KNOWN_POWERSHELL_COMMANDS_BREAKPOINTS = [
    "[Convert]::FromBase64String",
    "::ASCII",
    "Replace",
    "ForEach-Object",
    "powershell",
    "New-Object",
    " ",
    "Windows.Forms",
]


POWERSHELL_SUSPICIOUS_PATTERNS = [
    r"%\w+:~\d+,\d+%",
    r"(\[char\[[^\]]+\]\]){3,}",
    r"(cmd\.exe.*\/V:ON|setlocal.*EnableDelayedExpansion)",
    r"\$(env:[a-zA-Z]+)\[\d+\]\s*\+\s*\$env:[a-zA-Z]+\[\d+\]",
    r"\.AcceptTcpClient\(",
    r"\.Connect\(",
    r"\.ConnectAsync\(",
    r"\.Receive\(",
    r"\.Send\(",
    r"\[char\[\]\]\s*\([\d,\s]+\)|-join\s*\(\s*\[char\[\]\][^\)]+\)",
    r"\b(?:Invoke\-Expression|IEX)\b",
    r"\b(?:Invoke\-WebRequest|\biwr\b)",
    r"\b(?:Upload|Download)String\b",
    r"\bInvoke\-RestMethod.*-Uri\b",
    r"\bNew\-Object\s+(?:System\.)?Net\.WebClient\b",
    r"\bNew\-Object\s+Net\.Sockets\.(?:TcpClient|UdpClient)\b",
    r"\bOutFile\b",
    r"\bSystem\.Net\.Sockets\.Tcp(?:Client|listener)\b",
    r"\bSystem\.Net\.WebSockets\.ClientWebSocket\b",
    r"for\s+%?\w+%?\s+in\s*\([^)]{50,}\)",
    r"if\s+%?\w+%?\s+geq\s+\d+\s+call\s+%?\w+%?:~\d+%?",
]

RECON_COMMANDS = [
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


WINDOWS_TEMP_PATHS = [
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


AMSI = [
    r"\bamsiInitFailed\b",
    r"\bAmsiScanBuffer\(\)\b",
    r"\bLoadLibrary\(\"amsi\.dll\"\)\b",
    r"\bSystem\.Management\.Automation\.AmsiUtils\b",
]


LATERAL_MOVEMENT = [
    r"\\\\[a-zA-Z0-9_.-]+\\C\$\b",
    r"\b(?:cmd(?:\.exe)?)\s+(?=.*\/q)(?=.*\/c).*?((?:1>\s?.*?)?\s*2>&1)\b",
    r"\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\b",
    r"\bmstsc(\.exe)?",
    r"\bnet use \\\\.*\\IPC\$\b",
    r"\bpowershell.*(?:Enter-PSSession|Invoke\-Command)\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-(?:Credential|ScriptBlock)\b",
    r"\bpsexec([.]exe)?",
    r"\bpsexesvc[.](?:exe|log)\b",
    r"\bssh.*?-o.*?StrictHostKeyChecking=no\b",
    r"\bwmic\s+/node:\s*[a-zA-Z0-9_.-]+",
    r'\bcrackmapexec\s+smb\s+[a-zA-Z0-9_.-]+\s+-u\s+[a-zA-Z0-9_.-]+\s+-p\s+[a-zA-Z0-9_.-]+\s+-x\s+".*"\b',
    r'\bschtasks\s+/create\s+/tn\s+[a-zA-Z0-9_.-]+\s+/tr\s+".*"\s+/sc\s+[a-zA-Z]+\b',
    r'\bwmiexec\.py\s+[a-zA-Z0-9_.-]+\s+".*"\b',
]


MALICIOUS_COMMANDS = [
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


CREDENTIALS_DUMPING = [
    r"\bGet\-Credential\b",
    r"\bInvoke\-Mimikatz\b",
    r"\blsass\.dmp\b",
    r"\bMiniDumpWriteDump\b",
    r"\bntds\.dit\b",
    r"\bntdsutil\.exe.*ntds.*create\b",
    r"\bpowershell.*Invoke\-BloodHound.*-CollectionMethod.*",
    r"\bprocdump(\.exe)?\s+-ma\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp",
    r"\bprocdump.*lsass\b",
    r"\bProcessHacker\b",
    r"\breg\s+save\s+hklm\\(sam|system)\s+[a-zA-Z0-9_.-]+\.hive",
    r"\brundll32(\.exe)?\s+comsvcs\.dll,\s+MiniDump\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp.*",
    r"\brundll32.*comsvcs\.dll\b",
    r"\bsecretsdump(\.py)?\s+.*domain/.*:.*@.*",
    r"\bsekurlsa\:\:",
    r"\btasklist.*lsass\b",
    r"\btaskmgr(\.exe)?\s+/create\s+/PID:\d+\s+/DumpFile:[a-zA-Z0-9_.-]+\.dmp",
    r"\bwce(\.exe)?\s+-o",
    r"\bwmic\s+process\s+call\s+create.*(?:lsass|mimikatz)\b",
    r'\bntdsutil(\.exe)?\s+".*ac i ntds.*" "ifm" "create full\s+[a-zA-Z]:\\.*"',
]


DATA_EXFILTRATION = [
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


MSHTA = [
    r"mshta(?:\.exe)?\s*[\"\']?.*?(?:vbscript|javascript)\s*:",
    r"mshta(?:\.exe)?\s*[\"\']?\s*(?:https?|ftp|file)://",
    r"mshta(?:\.exe)?.*(?:CreateObject|Wscript\.Shell|Shell\.Application|powershell|document\.write)",
    r"mshta(?:\.exe)?.*(?:-enc|base64)",
]


SUSPICIOUS_COMMAND_PATTERNS = [
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
    r"(?i)opacity=0\.0[0-9]?\d*",
]


def check_for_obfuscation(command_line: str) -> tuple[dict[str, bool], str]:
    """
    Checks for various obfuscation techniques in a command line string.

    This function analyzes the given command line string for common obfuscation techniques
    such as base64 encoding, double encoding, reversed text, and other obfuscation methods.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        tuple: A tuple containing two elements:
            - A dictionary of flags indicating which obfuscation techniques were detected.
            - The deobfuscated/decoded command line string.
    """

    flags = {
        "base64_encoding": False,
        "obfuscated": False,
        "double_encoding": False,
        "reversed_command": False,
    }

    parsed_command_line = command_line

    reversed_command_line, flags["reversed_command"] = reverse_command(parsed_command_line)

    if flags["reversed_command"]:
        parsed_command_line = reversed_command_line  # Use the reversed command line for further analysis

    decoded_command_line, flags["base64_encoding"], flags["double_encoding"] = identify_and_decode_base64(parsed_command_line)

    if flags["double_encoding"] or flags["base64_encoding"]:
        parsed_command_line = decoded_command_line

    decoded_command_line, flags["obfuscated"] = encode_hex_and_oct_chars(parsed_command_line)
    decoded_command_line, flags["obfuscated"] = concat_multiple_strings(parsed_command_line)

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


def concat_multiple_strings(command_line: str):
    """
    Detects and joins multiple string concatenations in a command line string.

    This function identifies patterns where strings are concatenated using the '+'
    operator (e.g., "h" + "e" + "l" + "l" + "o") and joins them together by removing the
    quotes and '+' symbols.

    Args:
        command_line (str): The input command line string to process.

    Returns:
        tuple: A tuple containing two elements:
            - The processed string with concatenated strings joined together (if any were found).
            - A boolean indicating whether any changes were made to the input string.
    """

    if re.search(r"\"\s*\+\s*\"", command_line):
        return re.sub(r"\"(.*?)\"\s*\+", r"\1", command_line), True

    else:
        return command_line, False


def detect_final_powershell_script(data: str) -> bool:
    """
    Determines if the data contains known PowerShell command patterns.

    This function checks if the given string contains any known PowerShell commands
    that would indicate the data is a PowerShell script and not an encoded payload.

    Args:
        data (str): The string to analyze for PowerShell commands.

    Returns:
        bool: True if PowerShell commands are detected, False otherwise.
    """

    for command in KNOWN_POWERSHELL_COMMANDS_BREAKPOINTS:
        if command.lower() in data.lower():
            return True

        else:
            continue

    return False


def try_decode(data: bytes) -> str:
    """
    Try decoding the data with various encoding methods.

    This function attempts to decode binary data using different encodings:
    1. If data starts with 'MZ' (PE file signature), it decodes as UTF-8 after removing null bytes
    2. If data contains null bytes, it tries UTF-16-LE decoding
    3. Otherwise, it uses UTF-8 decoding

    Args:
        data (bytes): The binary data to decode

    Returns:
        str: The decoded string, or an empty string if decoding fails
    """

    try:
        if data.startswith(b"MZ"):
            decoded_str = data.replace(b"\x00", b"").decode("utf-8", errors="ignore")

        elif b"\x00" in data:
            # If they remain the same, try UTF-16-LE
            decoded_str = data.decode("utf-16-le")

        else:
            decoded_str = data.decode("utf-8")

        return decoded_str

    except (UnicodeDecodeError, AttributeError):
        # If decoding fails, return None
        return ""


def decode_base64_until_final_script(encoded_str: str) -> tuple[str, int]:
    """
    Decode a base64 string until it reaches the final PowerShell script.

    This function iteratively decodes a base64 encoded string until it can no longer be
    decoded or until it identifies a final PowerShell script. It keeps track of how many
    decoding iterations were performed.

    Args:
        encoded_str (str): The base64 encoded string to decode

    Returns:
        tuple[str, int]: A tuple containing the decoded string and the number of decoding iterations
    """
    decoded_str = encoded_str
    counter = 0

    while not detect_final_powershell_script(decoded_str):
        initial_string = decoded_str

        try:
            counter += 1
            decoded_bytes = base64.b64decode(decoded_str)
            decoded_str = try_decode(decoded_bytes)
            if not decoded_str:
                return initial_string, counter - 1

        except Exception:
            break

    return decoded_str, counter


def is_base64(possible_base64: str | bytes) -> bool:
    """
    Validates if the provided string is a Base64-encoded string.

    This function performs multiple checks to determine if a string is valid Base64:
    1. Verifies the string contains only valid Base64 characters (A-Z, a-z, 0-9, +, /, =)
    2. Ensures the length is a multiple of 4 (correct padding)
    3. For strings of length 20 or less, requires that the string contains '+', '/' or '='
       as an additional heuristic to reduce false positives
    4. Attempts strict base64 decoding which validates the content

    Args:
        possible_base64 (str | bytes): The string or bytes to validate as Base64

    Returns:
        bool: True if the input is valid Base64, False otherwise
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


def handle_powershell_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Detects and decodes Base64-encoded PowerShell commands.

    This function searches for PowerShell's -EncodedCommand parameter and decodes
    any Base64-encoded commands found. It can detect multiple levels of encoding.

    Args:
        command_line (str): The PowerShell command line to analyze

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The decoded command line
            - A boolean indicating if encoding was detected
            - A boolean indicating if double encoding was detected
    """

    double_encoded_detected = False
    encoded = False
    num_of_encodings = 0
    result = command_line
    powershell_encoded_base64 = re.compile(
        r"""
        -(?:e(?:n(?:c(?:o(?:d(?:e(?:d(?:C(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+
        ["']?([A-Za-z0-9+/]{4,}(?:={0,2}))["']?
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    while matches := powershell_encoded_base64.findall(result):
        demisto.debug(f"Detected -encodedCommand matches: {matches}")

        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches:
            demisto.debug("No valid Base64 matches found.")
            return "", False, False

        for match in valid_matches:
            decoded_segment, counter = decode_base64_until_final_script(match)
            num_of_encodings += counter
            demisto.debug(f"Decoded segment: {decoded_segment}")

            if decoded_segment:
                escaped_match = match.replace("+", "\\+")
                encoded_param = re.compile(
                    f"(?i)-(?:e(?:n(?:c(?:o(?:d(?:e(?:d(?:C(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\\s+[\"']?{escaped_match}"
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

    This function searches for any Base64-encoded strings in the given command line
    and attempts to decode them. It handles multiple encoding layers and keeps track
    of whether double encoding was detected.

    Args:
        command_line (str): The command line string to analyze

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The decoded command line
            - A boolean indicating if encoding was detected
            - A boolean indicating if double encoding was detected
    """

    result = command_line
    base64_pattern = r"[A-Za-z0-9+/]{4,}(?:={0,2})"
    num_of_encodings = 0
    double_encoded_detected = False
    previous_matches: list[str] = []

    while matches := re.findall(base64_pattern, result):
        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches or set(valid_matches).issubset(set(previous_matches)):
            if valid_matches and set(valid_matches).issubset(set(previous_matches)):
                num_of_encodings -= 1

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

        previous_matches = valid_matches

    return result, False, double_encoded_detected


def identify_and_decode_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Identifies and decodes all Base64 occurrences in a command line.

    This function checks if "powershell" is in the command line and calls the
    appropriate handler function: handle_powershell_base64 for PowerShell commands
    or handle_general_base64 for other command types.

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The command line with decoded content
            - A boolean indicating if any encoding was detected
            - A boolean indicating if double encoding was detected
    """

    if "powershell" in command_line.lower():
        return handle_powershell_base64(command_line)

    else:
        return handle_general_base64(command_line)


def reverse_command(command_line: str) -> tuple[str, bool]:
    """
    Detects if the command line contains a reversed PowerShell string and reverses it.

    Args:
        command_line (str): The command line to check for reversed PowerShell strings.

    Returns:
        tuple[str, bool]: A tuple containing:
            - The command line, reversed if it contained a reversed PowerShell string
            - A boolean indicating if a reversal was performed
    """

    if "llehsrewop" in command_line.lower():
        return command_line[::-1], True
    return command_line, False


def check_macOS_suspicious_commands(command_line: str) -> dict[str, list[list[str]]]:
    """
    Checks for suspicious macOS/AppleScript commands by grouping multiple sets
    of required substrings under a category. If all required substrings appear,
    that combination is recorded under its category.

    Args:
        command_line (str): The command line to check for suspicious macOS/AppleScript commands.

    Returns:
        dict[str, list[list[str]]]: A dictionary where keys are categories of suspicious behavior
                                    and values are lists of matched substring combinations.
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
    """
    Checks for known malicious commands or patterns in the given command line.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        list[str]: A list of matched malicious commands or patterns found in the command line.
    """

    matches: list[str] = []

    demisto.debug("Checking for malicious commands.")

    for pattern in MALICIOUS_COMMANDS:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_reconnaissance_temp(command_line: str) -> list[str]:
    """
    Checks for reconnaissance patterns in the given command line.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        list[str]: A list of matched reconnaissance patterns found in the command line.
    """

    demisto.debug("Checking for reconnaissance patterns.")

    matches: list[str] = []
    for pattern in RECON_COMMANDS:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_windows_temp_paths(command_line: str) -> list[str]:
    """
    Identifies given occurrences of Windows temporary paths in the given command line.

    This function scans the command line for common Windows temporary directory paths
    such as %TEMP%, %TMP%, AppData\\Local\\Temp, or Windows\\Temp. Threat actors often
    use these locations to store and execute malicious payloads.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        list[str]: A list of matched temporary paths found in the command line.
    """

    demisto.debug("Checking for windows temp paths in command line.")

    matches: list[str] = []
    for pattern in WINDOWS_TEMP_PATHS:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_suspicious_content(command_line: str) -> list[str]:
    """
    Scans the command line for suspicious content patterns.

    This function examines the command line for potentially malicious patterns defined
    in SUSPICIOUS_COMMAND_PATTERNS. These patterns could indicate suspicious activities
    such as obfuscation, encoded commands, or other evasion techniques commonly used
    in malicious scripts.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        list[str]: A list of suspicious patterns found in the command line.
    """

    demisto.debug("Checking for suspicious content.")

    matches: list[str] = []
    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        matches.extend(match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE))

    return matches


def check_amsi(command_line: str) -> list[str]:
    """
    Detects potential AMSI (Antimalware Scan Interface) bypass techniques in a command line.

    This function searches for patterns associated with AMSI bypass attempts, which are
    commonly used by attackers to evade antimalware detection when executing PowerShell code.

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched AMSI bypass patterns found in the command line
    """

    demisto.debug("Checking for amsi patterns.")

    matches: list[str] = []
    for pattern in AMSI:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_mixed_case_powershell(command_line: str) -> list[str]:
    """
    Detects mixed case obfuscation of the word 'powershell' in a command line.

    This function searches for variations of the word 'powershell' that use mixed case
    characters (e.g. PoWeRsHeLL), which is a common obfuscation technique used to evade
    detection. Normal legitimate versions of the word are excluded from the results.

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched obfuscated 'powershell' strings
    """

    mixed_case_powershell_regex = re.compile(r"\b(?=.*[a-z])(?=.*[A-Z])[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}(\.exe)?\b")

    demisto.debug("Checking for mixed case powershell usage.")

    exclusions = {
        "Powershell",
        "PowerShell",
        "powershell",
        "Powershell.exe",
        "PowerShell.exe",
        "powershell.exe",
    }

    return [match.group() for match in mixed_case_powershell_regex.finditer(command_line) if match.group() not in exclusions]


def check_powershell_suspicious_patterns(command_line: str) -> list[str]:
    """
    Detects suspicious PowerShell patterns in a given command line.

    This function searches for potentially malicious PowerShell patterns such as:
    - Obfuscation techniques
    - Encoded commands
    - Execution policy bypass
    - Hidden window usage
    - Known malicious cmdlets and parameters
    - Script execution with suspicious flags

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched suspicious PowerShell patterns
    """

    demisto.debug("Checking for powershell suspicious patterns.")

    matches: list[str] = []
    for pattern in POWERSHELL_SUSPICIOUS_PATTERNS:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_credential_dumping(command_line: str) -> list[str]:
    """
    Detects credential dumping attempts from a given command line.

    This function searches for patterns that indicate credential dumping activities such as:
    - LSASS dumping techniques
    - Mimikatz commands and parameters
    - Registry operations targeting credential storage
    - SAM/SYSTEM/SECURITY file access
    - Windows Credential Editor (WCE) usage
    - Other known credential extraction tools and commands

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched suspicious credential dumping patterns
    """

    demisto.debug("Checking for credential dumping.")

    matches: list[str] = []
    for pattern in CREDENTIALS_DUMPING:
        matches.extend(match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE))

    return matches


def check_lateral_movement(command_line: str) -> list[str]:
    """
    Detects techniques and commands commonly used for lateral movement in a network.

    This function searches for patterns that indicate lateral movement attempts such as:
    - Remote access tools (PsExec, WMI, WinRM)
    - Remote file copy techniques
    - Remote service creation
    - Remote scheduled task creation
    - Use of administrative shares
    - Pass-the-hash or pass-the-ticket techniques

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched suspicious lateral movement patterns
    """

    demisto.debug("Checking for lateral movement patterns.")

    matches: list[str] = []
    for pattern in LATERAL_MOVEMENT:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_data_exfiltration(command_line: str) -> list[str]:
    """
    Detects potential data exfiltration techniques from a given command line.

    This function searches for patterns that indicate data exfiltration attempts such as:
    - Data compression (zip, rar, tar)
    - Network data transfer commands (curl, wget, scp)
    - Unusual upload/download behaviors
    - Data staging before exfiltration
    - DNS/ICMP tunneling techniques
    - Usage of non-standard ports or protocols for data transfer

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched suspicious data exfiltration patterns
    """

    demisto.debug("Checking for data exfiltration patterns.")

    matches: list[str] = []
    for pattern in DATA_EXFILTRATION:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_suspicious_mshta(command_line: str) -> list[str]:
    """
    Detects suspicious mshta usage in a given command line.

    This function searches for patterns that indicate potential abuse of
    Microsoft HTML Application Host (mshta.exe) for malicious purposes.

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched suspicious mshta patterns
    """

    demisto.debug("Checking for suspicious mshta usage.")

    matches: list[str] = []

    for pattern in MSHTA:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_social_engineering(command_line: str) -> list[str]:
    """
    Detects social engineering tactics in a given command line.

    This function searches for patterns that indicate social engineering attempts, such as:
    - Use of checkmark emojis that might be used to suggest legitimacy
    - Comment characters in mshta commands that may be used to trick users

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched social engineering patterns
    """

    checkmark_emojis = [
        "\u2705",  # ✅ Check Mark Button
        "\u2714",  # ✔️ Heavy Check Mark
        "\u2611",  # ☑️ Ballot Box with Check
        "\u1f5f8",  # 🗸 Light Check Mark
        "\u1f5f9",  # 🗹 Ballot Box with Bold Check
    ]

    demisto.debug("Checking for social engineering patterns in command.")

    for emoji in checkmark_emojis:
        if emoji in command_line:
            return ["Emoji Found in command line"]

    if re.search("mshta.*?#", command_line, re.IGNORECASE):
        # This is used by attackers to fool a victim to run the mshta command via the explorer
        return ["Comment character detected in mshta command line"]

    return []


def check_custom_patterns(command_line: str, custom_patterns: list[str] | None = None) -> list[str]:
    """
    Checks for user-defined patterns in a given command line.

    This function matches custom regular expression patterns against the command line
    text to identify specific patterns of interest defined by the user.

    Args:
        command_line (str): The command line text to analyze
        custom_patterns (list[str] | None, optional): List of regex patterns to match. Defaults to None.

    Returns:
        list[str]: A list of matched patterns from the command line
    """

    matches: list[str] = []
    if custom_patterns:
        # Ensure custom_patterns is a list
        if isinstance(custom_patterns, str):
            custom_patterns = [custom_patterns]  # Convert single string to a list
        for pattern in custom_patterns:
            matches.extend(re.findall(pattern, command_line, re.IGNORECASE))
    return matches


def extract_indicators(command_line: str) -> dict[str, list[str]]:
    """
    Extract various indicators (IP addresses, domains, URLs, etc.) from the command line.

    This function uses the Demisto extractIndicators command to identify and extract
    various indicators from the command line text. It filters out reserved IPs and
    special cases like '::'.

    Args:
        command_line (str): The command line text to extract indicators from

    Returns:
        dict[str, list[str]]: A dictionary mapping indicator types to lists of extracted values
    """

    def is_reserved_ip(ip_str: str) -> bool:
        """
        Check if an IP address is reserved (non-global).

        Args:
            ip_str (str): The IP address as a string

        Returns:
            bool: True if the IP is reserved (not globally routable), False otherwise
        """

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not ip_obj.is_global

        except ValueError:
            return False

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
        demisto.debug(f"Failed to extract indicators: {e!s}")

    return extracted_by_type


def calculate_score(results: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregates findings from the analysis and assigns a score (0-100).
    Incorporates bonuses for certain risky combinations.

    The scoring algorithm works as follows:
    1. Each detection adds points based on predefined weights (e.g., obfuscation techniques, malicious commands)
    2. Findings are categorized into high-risk and medium-risk groups
    3. Multiple high-risk findings trigger additional bonus points
    4. Multiple medium-risk findings trigger smaller bonus points
    5. A final score is calculated for both original and decoded command lines
    6. The score is normalized to a 0-100 scale, with higher scores indicating more suspicious activity

    Returns:
        dict: Contains the calculated scores and detailed findings for both original and decoded command lines
    """

    # Define weights for base scoring
    weights: dict[str, int] = {
        "mixed_case_powershell": 25,
        "reversed_command": 25,
        "powershell_suspicious_patterns": 35,
        "credential_dumping": 25,
        "double_encoding": 25,
        "amsi_techniques": 25,
        "malicious_commands": 25,
        "custom_patterns": 25,
        "macOS_suspicious_commands": 25,
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
        "macOS_suspicious_commands",
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
        "suspicious_parameters",
        "windows_temp_path",
        "reconnaissance",
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
                    context_findings.append(f"{key.replace('_', ' ')} detected ({len(value)} instances)")
                else:
                    # Not a list or empty list, just count once
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected")

        # Apply combination bonuses based on detected keys
        if (high_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["high"]
            context_findings.append("High-risk combination detected")
        elif (medium_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["medium"]
            context_findings.append("Medium-risk combination detected")
        elif (low_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["low"]
            context_findings.append("Low-risk combination detected")

        return context_score, context_findings

    # Process original
    original_results = results.get("analysis", {}).get("original", {})
    scores["original"], findings["original"] = process_context(original_results)

    # Check global combinations (like double encoding globally)
    if original_results.get("double_encoding", False):
        scores["decoded"] += weights["double_encoding"]
        findings["decoded"].append("double_encoding")

    # Calculate total raw score
    total_raw_score = scores["original"]  # + scores["decoded"]

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


def analyze_command_line(command_line: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
    """
    Analyzes a command line string for potential security threats and suspicious patterns.

    This function performs a comprehensive analysis of the provided command line, checking for
    various indicators of malicious activity including obfuscation techniques, suspicious commands,
    credential dumping attempts, lateral movement, and more.

    Args:
        command_line (str): The command line string to analyze.
        custom_patterns (list[str] | None, optional): Additional custom patterns to check for in the command line.
                                                     Defaults to None.

    Returns:
        dict[str, Any]: Analysis results containing:
            - original_command: The input command line string
            - parsed_command: The command line after deobfuscation (if applicable)
            - analysis: Detailed analysis results for various security checks
            - score: Numerical risk score (0-100)
            - findings: Detailed findings that contributed to the score
            - risk: Overall risk assessment (Low/Medium/High/Critical Risk)
    """

    checks: dict[str, Callable] = {
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

    results["analysis"]["original"]["custom_patterns"] = (
        check_custom_patterns(parsed_command_line, custom_patterns) if custom_patterns else []
    )

    # Only set "base64_encoding" if we actually decoded something

    for flag, value in flags.items():
        if value:
            results["analysis"]["original"][flag] = value

    # Handle macOS
    if "osascript" in parsed_command_line.lower():
        results["analysis"]["original"]["macOS_suspicious_commands"] = check_macOS_suspicious_commands(parsed_command_line)

    # results["analysis"]["original"] = original_analysis
    score_details = calculate_score(results)
    results.update(score_details)

    return results


def main():
    """
    Entry point for analyzing command lines for suspicious activities and patterns.
    """
    args = demisto.args()
    command_lines = argToList(args.get("command_line", []), separator=" , ")
    custom_patterns = argToList(args.get("custom_patterns", []))
    readable_output = ""

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
