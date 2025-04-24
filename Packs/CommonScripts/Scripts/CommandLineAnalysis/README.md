This script evaluates command-line threats by analyzing both original and decoded inputs. It assigns weighted scores to detected patterns, such as AMSI bypass or credential dumping, and applies risk combination bonuses for multiple detections. The total score is normalized to a 0-100 scale, with risk levels categorized as follows:

* 0-25: Low Risk
* 26-50: Medium Risk
* 51-90: High Risk
* 91-100: Critical Risk

The scoring mechanism provides a comprehensive risk assessment, considering both the severity and frequency of malicious behaviors.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| command_line | The command line input to analyze. |
| custom_patterns | A list of custom regex patterns to search for within the command line. Each pattern should be a valid regular expression string. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CommandLineAnalysis.original_command | The original command line string analyzed for potential risks. | Unknown |
| CommandLineAnalysis.decoded_command | The decoded Base64 command line string, if decoding was performed. | Unknown |
| CommandLineAnalysis.risk | The overall risk level derived from the command line analysis, classified as Low, Medium, High, or Critical. | Unknown |
| CommandLineAnalysis.score | The normalized score \(0-100\) representing the risk associated with the analyzed command line. | Unknown |
| CommandLineAnalysis | A detailed summary of the analysis results, including findings and scores. | Unknown |
| CommandLineAnalysis.findings.original | Findings from the analysis of the original command line, highlighting the detected patterns. | Unknown |
| CommandLineAnalysis.findings.decoded | Findings from the analysis of the decoded Base64 command line, if decoding was applicable. | Unknown |
| CommandLineAnalysis.analysis.original.malicious_commands | Checks for malicious commands in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.windows_temp_path | Checks if the original command line accesses Windows temporary paths. | Unknown |
| CommandLineAnalysis.analysis.original.suspicious_parameters | Identifies suspicious parameters or content in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.mixed_case_powershell | Detects mixed case PowerShell commands in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.powershell_suspicious_patterns | Searches for suspicious PowerShell patterns in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.credential_dumping | Checks for credential dumping techniques in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.custom_patterns | Matches custom patterns \(if provided\) in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.reconnaissance | Checks for reconnaissance activities in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.lateral_movement | Identifies lateral movement techniques in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.data_exfiltration | Detects data exfiltration activities in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.amsi_techniques | Checks for AMSI bypass techniques in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.indicators | Extracts indicators of compromise \(IOCs\) from the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.base64_encoding | Decoded content from Base64 encoding in the original command line. | Unknown |
| CommandLineAnalysis.analysis.original.reversed_command | Indicates if the original command line was reversed. | Unknown |
| CommandLineAnalysis.analysis.decoded.malicious_commands | Checks for malicious commands in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.windows_temp_path | Checks if the decoded Base64 command line accesses Windows temporary paths. | Unknown |
| CommandLineAnalysis.analysis.decoded.suspicious_parameters | Identifies suspicious parameters or content in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.mixed_case_powershell | Detects mixed case PowerShell commands in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.powershell_suspicious_patterns | Searches for suspicious PowerShell patterns in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.credential_dumping | Checks for credential dumping techniques in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.custom_patterns | Matches custom patterns \(if provided\) in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.reconnaissance | Checks for reconnaissance activities in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.lateral_movement | Identifies lateral movement techniques in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.data_exfiltration | Detects data exfiltration activities in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.amsi_techniques | Checks for AMSI bypass techniques in the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.analysis.decoded.indicators | Extracts indicators of compromise \(IOCs\) from the decoded Base64 command line. | Unknown |
| CommandLineAnalysis.Double Encoding Detected | Identifies nested Base64 strings. | Unknown |
