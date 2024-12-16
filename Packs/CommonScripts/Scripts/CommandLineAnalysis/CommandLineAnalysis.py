import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import re
import ipaddress
import json

def is_base64(base64_string: str) -> bool:
    """
    Validates if the provided string is a Base64-encoded string.
    """
    try:
        if isinstance(base64_string, str):
            base64_string = base64_string.encode('ascii')
        # Validate Base64
        padding = len(base64_string) % 4
        if padding:
            base64_string += b'=' * (4 - padding)  # Add missing padding
        base64.b64decode(base64_string, validate=True)  # Use strict validation
        return True
    except Exception as e:
        demisto.debug(f"Error validating Base64: {e}")
        return False

def clean_non_base64_chars(encoded_str: str) -> str:
    """
    Cleans and ensures the Base64 string contains only valid Base64 characters.
    Adds proper padding if necessary.
    """
    # Remove unwanted characters
    cleaned_str = re.sub(r'[^A-Za-z0-9=]', '', encoded_str)
    # Fix padding (Base64 strings should be a multiple of 4 in length)
    padding = len(cleaned_str) % 4
    if padding:
        cleaned_str += "=" * (4 - padding)
    return cleaned_str


def remove_null_bytes(decoded_str: str) -> str:
    """
    Removes null bytes from the decoded string.
    """
    return decoded_str.replace("\x00", "")

def decode_base64(encoded_str: str, max_recursions: int = 5) -> Tuple[Optional[str], bool]:
    """
    Decodes a Base64-encoded string recursively up to a defined limit.
    """
    try:
        recursion_depth = 0
        while is_base64(encoded_str) and recursion_depth < max_recursions:
            # Clean and ensure the string is valid
            encoded_str = clean_non_base64_chars(encoded_str)
            decoded_bytes = base64.b64decode(encoded_str)
            try:
                encoded_str = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                encoded_str = decoded_bytes.decode('latin-1')  # Fallback for non-UTF-8 content
            recursion_depth += 1
        return encoded_str, recursion_depth > 1  # Return decoded string and if double encoding was detected
    except Exception as e:
        demisto.debug(f"Error decoding base64: {e}")
        return None, False


def identify_and_decode_base64(command_line: str) -> Tuple[str, bool]:
    """
    Identifies and decodes all Base64 occurrences in a command line,
    returning the original command line, the fully decoded content, and a flag for double encoding.
    """
    # Base64 regex pattern
    base64_pattern = re.compile(
        r'((?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})?)'
    )

    matches = base64_pattern.findall(command_line)
    fully_decoded_content = []  # Collect decoded Base64 strings
    double_encoded_detected = False

    for match in matches:
        if is_base64(match):  # Validate Base64
            # Decode Base64 recursively
            decoded_str, is_double_encoded = decode_base64(match)
            if decoded_str:
                # Preprocess decoded content: remove non-printable characters, line breaks, and excess whitespace
                cleaned_decoded = ''.join(c for c in decoded_str if c.isprintable())
                cleaned_decoded = cleaned_decoded.replace("\n", "").replace("\r", "").strip()
                fully_decoded_content.append(cleaned_decoded)

                # Track double encoding
                if is_double_encoded:
                    double_encoded_detected = True

    # Join all decoded Base64 strings to form the fully decoded command
    decoded_command_line = ''.join(fully_decoded_content)

    return decoded_command_line, double_encoded_detected


def reverse_command(command_line: str) -> Tuple[str, bool]:
    """
    Detects if the command line contains a reversed PowerShell string and reverses it.
    """
    if "llehsrewop" in command_line.lower():
        return command_line[::-1], True
    return command_line, False

def check_malicious_commands(command_line: str) -> List[str]:
    patterns = [
        r'\bmimikatz\b',
        r'\bLaZagne\.exe\b',
        r'\bprocdump\.exe\b',
        r'\bcobaltstrike_beacon\.exe\b',
        r'\bbloodhound\.exe\b',
        r'\bsharphound\.exe\b',
        r'\bcme\.exe\b',
        r'\bresponder\.py\b',
        r'\bsmbexec\.py\b',
        r'\bInvoke\-PSRemoting\b',
        r'\bInvoke\-TheHash\b',
        r'\bGetUserSPNs\.py\b',
        r'\beternalblue\.exe\b',
        r'\beternalromance\.exe\b',
        r'\bmeterpreter\.exe\b',
        r'\bmsfconsole\b',
        r'\bsharpview\.exe\b',
        r'\bInvoke\-SMBExec\b',
        r'\bInvoke\-Obfuscation\b',
        r'\bInvoke\-CradleCrafter\b',
        r'\bcovenant\.exe\b',
        r'\bkoadic\b',
        r'\bquasar\.exe\b',
        r'\bnjRAT\.exe\b',
        r'\bdarkcomet\.exe\b',
        r'\bnanocore\.exe\b',
        r'\bpowercat\.ps1\b',
        r'\brubeus\.exe\b',
        r'\bc99\.php\b',
        r'\bchopper\.php\b',
        r'\bwso\.php\b',
        r'\bb374k\.php\b',
        r'\bbeacon\.exe\b',
        r'\bwinrm\.vbs\b',
        r'\bmsfvenom\b',
        r'\bPowGoop\.ps1\b',
        r'\bimpacket\-scripts\b',
        r'\bPowerUp\.ps1\b',
        r'\bseatbelt\.exe\b',
        r'\blsassdump\.py\b',
        r'\bInvoke\-ReflectivePEInjection\b',
        r'\bInvoke\-Shellcode\b',
        r'\bInvoke\-Expression\b',
        r'\bInvoke\-WmiMethod\b',
        r'\bInvoke\-KickoffAtomicRunner\b'
    ]


    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_reconnaissance(command_line: str) -> List[str]:
    patterns = [
        r'\bipconfig\b',
        r'\bnetstat\b',
        r'\bnslookup\b',
        r'\barp\b',
        r'\broute\s+print\b',
        r'\bhostname\b',
        r'\bping\b',
        r'\btracert\b',
        r'\bwhoami\b',
        r'\bnet\s+user\b',
        r'\bnet\s+group\b',
        r'\bnet\s+localgroup\b',
        r'\bquery\s+user\b',
        r'\bsysteminfo\b',
        r'\btasklist\b',
        r'\bsc\s+query\b',
        r'\bwmic\s+process\s+list\b',
        r'\bfsutil\b',
        r'\bdir\b',
        r'\battrib\b',
        r'\btree\b',
        r'\bnetstat\s+\-ano\b',
        r'\breg\s+query\b'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_windows_temp_paths(command_line: str) -> List[str]:
    """
    Identifies all occurrences of temporary paths in the given command line.
    """
    patterns = [
        r'\bC:\\Windows\\Temp\b',
        r'\bC:\\Temp\b',
        r'\bC:\\Windows\\System32\\Temp\b',
        r'\b%TEMP%\b',
        r'\b%TMP%\b',
        r'\\Users\\Public\\Public\s+Downloads\b',
        r'\\AppData\\Local\\Temp\b',
        r'\\ProgramData\\Microsoft\\Windows\\Caches\b',
        r'\\Windows\\System32\\spool\b',
        r'\\Windows\\Tasks\b',
        r'\\Windows\\debug\b',
        r'\\Windows\\Temp\b'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches


def check_suspicious_content(command_line: str) -> List[str]:
    patterns = [
        r'\-w\s+hidden\b',
        r'\-WindowStyle\s+Hidden\b',
        r'\-window\s+hidden\b',
        r'\-noni\b',
        r'\-enc\b',
        r'\-NonInteractive\b',
        r'\-nop\b',
        r'\-noprofile\b',
        r'\-ExecutionPolicy\s+Bypass\b',
        r'\bBypass\b',
        r'\bClipboardContents\b',
        r'\bGet\-GPPPassword\b',
        r'\bGet\-LSASecret\b',
        r'\bnet\s+user\s+\/\s+add\b',
        r'\btaskkill\b',
        r'\brundll32\b',
        r'\blsass\b',
        r'\breg\s+add\b',
        r'\bbcedit\b',
        r'\bschtasks\b',
        r'\bnetsh\s+firewall\s+set\b',
        r'\s*\<NUL\b',
        r'\bcertutil.*\-encodehex\b',
    ]

    matches = []
    for pattern in patterns:
        matches.extend(match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE))

    return matches

def check_amsi(command_line: str) -> List[str]:
    patterns = [
        r'\bSystem\.Management\.Automation\.AmsiUtils\b',
        r'\bamsiInitFailed\b',
        r'\bLoadLibrary\(\"amsi\.dll\"\)\b',
        r'\bAmsiScanBuffer\(\)\b'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_mixed_case_powershell(command_line: str) -> List[str]:
    mixed_case_powershell_regex = re.compile(
        r'\b(?=.*[a-z])(?=.*[A-Z])[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}(\.exe)?\b'
    )

    exclusions = {"Powershell", "PowerShell", "powershell", "Powershell.exe", "PowerShell.exe", "powershell.exe"}

    return [
        match.group() for match in mixed_case_powershell_regex.finditer(command_line)
        if match.group() not in exclusions
    ]



def check_powershell_suspicious_patterns(command_line: str) -> List[str]:
    """
    Detects potential obfuscation, backdoor mechanisms and Command-and-Control (C2) communication
    implemented using PowerShell.
    """
    patterns = [
        r'\bNew\-Object\s+Net\.Sockets\.TcpClient\b',
        r'\bNew\-Object\s+Net\.Sockets\.UdpClient\b',
        r'\bSystem\.Net\.Sockets\.TcpListener\b',
        r'\.Connect\(',
        r'\.AcceptTcpClient\(',
        r'\.Receive\(',
        r'\.Send\(',
        r'\bpowershell.*IEX.*\(New\-Object\s+Net\.WebClient\)\b',
        r'\bInvoke\-WebRequest.*-Uri\b',
        r'\bInvoke\-RestMethod.*-Uri\b',
        r'\bNew\-Object\s+System\.Net\.WebClient\b',
        r'\bNew\-Object\s+Net\.WebClient\b',
        r'\bDownloadString\b',
        r'\bUploadString\b',
        r'\bSystem\.Net\.WebSockets\.ClientWebSocket\b',
        r'\.ConnectAsync\(',
        r'\[char\[\]\]\s*\([\d,\s]+\)|-join\s*\(\s*\[char\[\]\][^\)]+\)',
        r'\$(env:[a-zA-Z]+)\[\d+\]\s*\+\s*\$env:[a-zA-Z]+\[\d+\]',
        r'%\w+:~\d+,\d+%',
        r'(cmd\.exe.*\/V:ON|setlocal.*EnableDelayedExpansion)',
        r'if\s+%?\w+%?\s+geq\s+\d+\s+call\s+%?\w+%?:~\d+%?',
        r'(\[char\[[^\]]+\]\]){3,}',
        r'for\s+%?\w+%?\s+in\s*\([^)]{50,}\)'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_credential_dumping(command_line: str) -> List[str]:
    """
    Detects credential dumping techniques.
    """
    patterns = [
        r'\brundll32.*comsvcs\.dll\b',
        r'\bprocdump.*lsass\b',
        r'\bwmic\s+process\s+call\s+create.*lsass\b',
        r'\bInvoke\-Mimikatz\b',
        r'\btasklist.*lsass\b',
        r'\bProcessHacker\b',
        r'\bMiniDumpWriteDump\b',
        r'\bGet\-Credential\b',
        r'\blsass\.dmp\b',
        r'\bntds\.dit\b',
        r'\bntdsutil\.exe.*ntds.*create\b',
        r'\bsekurlsa\:\:',
        r'\bprocdump(\.exe)?\s+-ma\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp',
        r'\brundll32(\.exe)?\s+comsvcs\.dll,\s+MiniDump\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp.*',
        r'\bwmic\s+process\s+call\s+create\s+".*mimikatz.*"',
        r'\btaskmgr(\.exe)?\s+/create\s+/PID:\d+\s+/DumpFile:[a-zA-Z0-9_.-]+\.dmp',
        r'\bntdsutil(\.exe)?\s+".*ac i ntds.*" "ifm" "create full\s+[a-zA-Z]:\\.*"',
        r'\bsecretsdump(\.py)?\s+.*domain/.*:.*@.*',
        r'\breg\s+save\s+hklm\\(sam|system)\s+[a-zA-Z0-9_.-]+\.hive',
        r'\bwce(\.exe)?\s+-o',
        r'\bpowershell.*Invoke\-BloodHound.*-CollectionMethod.*'
    ]


    matches = []
    for pattern in patterns:
        matches.extend(match.group() for match in re.finditer(pattern, command_line, re.IGNORECASE))

    return matches

def check_lateral_movement(command_line: str) -> List[str]:
    """
    Detects potential lateral movement techniques from a given command line.
    """
    patterns = [
        r'\b(?:cmd(?:\.exe)?)\s+(?=.*\/q)(?=.*\/c).*?((?:1>\s?.*?)?\s*2>&1)\b',
        r'\bpsexec(\.exe)?',
        r'\bpsexesvc\.exe\b',
        r'\bpsexesvc\.log\b',
        r'\bwmic\s+/node:\s*[a-zA-Z0-9_.-]+',
        r'\bmstsc(\.exe)?',
        r'\\\\[a-zA-Z0-9_.-]+\\C\$\b',
        r'\bnet use \\\\.*\\IPC\$\b',
        r'\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\b',
        r'\bEnter-PSSession\b',
        r'\bpowershell.*Enter-PSSession\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-Credential\b',
        r'\bschtasks\s+/create\s+/tn\s+[a-zA-Z0-9_.-]+\s+/tr\s+".*"\s+/sc\s+[a-zA-Z]+\b',
        r'\bpowershell.*Invoke\-Command\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-ScriptBlock\b',
        r'\bmstsc(\.exe)?\s+/v\s+[a-zA-Z0-9_.-]+\b',
        r'\bwmiexec\.py\s+[a-zA-Z0-9_.-]+\s+".*"\b',
        r'\bssh.*?-o.*?StrictHostKeyChecking=no\b',
        r'\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\\.*\s+[a-zA-Z]:\\.*\b',
        r'\bcrackmapexec\s+smb\s+[a-zA-Z0-9_.-]+\s+-u\s+[a-zA-Z0-9_.-]+\s+-p\s+[a-zA-Z0-9_.-]+\s+-x\s+".*"\b'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_data_exfiltration(command_line: str) -> List[str]:
    """
    Detects potential data exfiltration techniques from a given command line.
    """
    patterns = [
        r'\bcurl\s+-X\s+(POST|PUT)\s+-d\s+@[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b',
        r'\bwget\s+--post-file=[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b',
        r'\bscp\s+-i\s+[a-zA-Z0-9_.-]+\.pem\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+:/.*\b',
        r'\bftp\s+-n\s+[a-zA-Z0-9_.-]+\s+<<END_SCRIPT.*put\s+.*END_SCRIPT\b',
        r'\bnc\s+[a-zA-Z0-9_.-]+\s+\d+\s+<\s+[a-zA-Z0-9_.-]+\b',
        r'\baws\s+s3\s+cp\s+[a-zA-Z0-9_.-]+\s+s3://[a-zA-Z0-9_.-]+/.*\b',
        r'\bgsutil\s+cp\s+[a-zA-Z0-9_.-]+\s+gs://[a-zA-Z0-9_.-]+/.*\b',
        r'\baz\s+storage\s+blob\s+upload\s+-f\s+[a-zA-Z0-9_.-]+\s+-c\s+[a-zA-Z0-9_.-]+.*\b',
        r'\bpowershell.*System\.Net\.WebClient.*UploadFile.*https?://[a-zA-Z0-9_.-]+/.*\b',
        r'\brsync\s+-avz\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+:/.*\b'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def check_custom_patterns(command_line: str, custom_patterns: Optional[List[str]] = None) -> List[str]:

    matches = []
    for pattern in custom_patterns:
        matches.extend(re.findall(pattern, command_line, re.IGNORECASE))

    return matches

def is_reserved_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local
        )
    except ValueError:
        return False

def extract_indicators(command_line: str) -> List[str]:
    """
    Extracts indicators like IPs and other data from the command line.

    Args:
        command_line (str): The command line input to analyze.

    Returns:
        List[str]: A list of extracted indicators (e.g., IPs) that are not reserved.
    """
    try:
        indicators = demisto.executeCommand("extractIndicators", {"text": command_line})
        if indicators and isinstance(indicators, list):
            contents = indicators[0].get("Contents", {})
            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except json.JSONDecodeError as json_err:
                    demisto.debug(f"JSON parsing failed: {str(json_err)}")
                    return []
            if isinstance(contents, dict):
                if "IP" in contents:
                    return [ip for ip in contents["IP"] if not is_reserved_ip(ip)]
                else:
                    return [value for key in contents for value in contents[key]]
    except ValueError as ve:
        demisto.debug(f"Value error encountered: {str(ve)}")
    except Exception as e:
        demisto.debug(f"Failed to extract indicators: {str(e)}")

    return []
def calculate_score(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates a risk score based on analysis results.

    Args:
        results (Dict[str, Any]): The analysis results containing original and decoded findings.

    Returns:
        Dict[str, Any]: A dictionary containing the score, findings, and risk level.
    """
    # Define weights for base scoring
    weights: Dict[str, int] = {
        "mixed_case_powershell": 25,
        "reversed_command": 25,
        "powershell_suspicious_patterns": 25,
        "credential_dumping": 25,
        "double_encoding": 25,
        "amsi_techniques": 25,
        "malicious_commands": 25,
        "custom_patterns": 25,
        "data_exfiltration": 15,
        "lateral_movement": 15,
        "windows_temp_path": 10,
        "indicators": 10,
        "reconnaissance": 10,
        "base64_encoding": 5,
        "suspicious_parameters": 5,
    }

    # Risk bonuses for detected combinations
    risk_bonuses: Dict[str, int] = {
        "high": 30,
        "medium": 20,
        "low": 10,
    }

    # Group risk categories
    high_risk_keys: set = {
        "mixed_case_powershell", "double_encoding", "amsi_techniques",
        "malicious_commands", "powershell_suspicious_patterns",
        "credential_dumping", "reversed_command", "custom_patterns"
    }
    medium_risk_keys: set = {
        "data_exfiltration", "lateral_movement", "indicators",
    }
    low_risk_keys: set = {
        "suspicious_parameters", "windows_temp_path", "reconnaissance", "base64_encoding",
    }

    # Define findings and scores containers
    findings: Dict[str, List[str]] = {"original": [], "decoded": []}
    scores: Dict[str, int] = {"original": 0, "decoded": 0}

    # Fixed theoretical maximum score for normalization
    theoretical_max: int = 120

    def process_context(context_name: str, context_results: Dict[str, Any]) -> Tuple[int, List[str]]:
        """
        Calculates the score and findings for a specific context (original/decoded).

        Args:
            context_name (str): Name of the context (e.g., "original", "decoded").
            context_results (Dict[str, Any]): Analysis results for the context.

        Returns:
            Tuple[int, List[str]]: The score and findings for the context.
        """
        context_score: int = 0
        context_findings: List[str] = []
        context_keys_detected: set = set()

        for key, value in context_results.items():
            if value:  # Ensure key has non-empty results
                context_keys_detected.add(key)
                if isinstance(value, list) and len(value) > 0:
                    # Add weight and track instances found
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected ({len(value)} instances)")
                else:
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected")

        # Apply risk bonuses based on detected combinations
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

    # Process scores for "original" and "decoded" contexts
    scores["original"], findings["original"] = process_context("original", results.get("analysis", {}).get("original", {}))
    scores["decoded"], findings["decoded"] = process_context("decoded", results.get("analysis", {}).get("decoded", {}))

    # Check global combinations (e.g., double encoding detected)
    if results.get("Double Encoding Detected"):
        scores["decoded"] += weights["double_encoding"]
        findings["decoded"].append("Double encoding detected")

    # Calculate total score and normalize it
    total_raw_score: int = scores["original"] + scores["decoded"]
    normalized_score: float = (total_raw_score / theoretical_max) * 100
    normalized_score = min(normalized_score, 100)  # Cap the score at 100

    # Determine risk level
    risk: str = "Low Risk"
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
def analyze_command_line(command_line, custom_patterns=None):
    """
    Analyzes the given command line for suspicious patterns, indicators, and encodings.
    """
    reversed_command_line, is_reversed = reverse_command(command_line)
    if is_reversed:
        command_line = reversed_command_line  # Use the reversed command line for further analysis

    decoded_command_line, double_encoded = identify_and_decode_base64(command_line)

    results = {
        "original_command": command_line,
        "analysis": {"original": {}}
    }

    # Perform checks on the original command line
    results["analysis"]["original"] = {
        "malicious_commands": check_malicious_commands(command_line),
        "windows_temp_path": check_windows_temp_paths(command_line),
        "suspicious_parameters": check_suspicious_content(command_line),
        "mixed_case_powershell": check_mixed_case_powershell(command_line),
        "powershell_suspicious_patterns": check_powershell_suspicious_patterns(command_line),
        "credential_dumping": check_credential_dumping(command_line),
        "custom_patterns": check_custom_patterns(command_line, custom_patterns) if custom_patterns else [],
        "reconnaissance": check_reconnaissance(command_line),
        "lateral_movement": check_lateral_movement(command_line),
        "data_exfiltration": check_data_exfiltration(command_line),
        "amsi_techniques": check_amsi(command_line),
        "indicators": extract_indicators(command_line),
        "base64_encoding": decoded_command_line if decoded_command_line else []
    }

    if is_reversed:
        results["analysis"]["original"]["reversed_command"] = ["reversed_command"]

    # Identify and analyze decoded Base64 command line if available
    if decoded_command_line:
        results["decoded_command"] = decoded_command_line
        results["analysis"]["decoded"] = {
            "malicious_commands": check_malicious_commands(decoded_command_line),
            "windows_temp_path": check_windows_temp_paths(decoded_command_line),
            "suspicious_parameters": check_suspicious_content(decoded_command_line),
            "mixed_case_powershell": check_mixed_case_powershell(decoded_command_line),
            "powershell_suspicious_patterns": check_powershell_suspicious_patterns(decoded_command_line),
            "credential_dumping": check_credential_dumping(decoded_command_line),
            "custom_patterns": check_custom_patterns(decoded_command_line, custom_patterns) if custom_patterns else [],
            "reconnaissance": check_reconnaissance(decoded_command_line),
            "lateral_movement": check_lateral_movement(decoded_command_line),
            "data_exfiltration": check_data_exfiltration(decoded_command_line),
            "amsi_techniques": check_amsi(decoded_command_line),
            "indicators": extract_indicators(decoded_command_line)
        }
        results["Double Encoding Detected"] = double_encoded

    # Calculate the score
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

    if isinstance(command_lines, str):
        command_lines = [command_lines]

    # Analyze each command line
    results = [analyze_command_line(cmd, custom_patterns) for cmd in command_lines]

    # Prepare readable output for the results
    readable_output = "\n\n".join([
        f"Command Line: {result['original_command']}\n"
        f"Risk: {result['risk']}\n"
        f"Score: {result['score']}\n"
        f"Findings (Original): {', '.join(result['findings']['original'])}\n"
        f"Findings (Decoded): {', '.join(result['findings'].get('decoded', []))}\n"
        for result in results
    ])

    # Return results
    return_results(CommandResults(
        readable_output=readable_output,
        outputs_prefix="CommandLineAnalysis",
        outputs_key_field="original_command",
        outputs=results
    ))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
