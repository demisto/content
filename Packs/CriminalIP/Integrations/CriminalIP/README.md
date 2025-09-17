Criminal IP is a comprehensive cyber threat intelligence solution that provides actionable insights into IP addresses, domains, and connected assets across the internet.
It enables organizations to detect malicious indicators, assess asset reputation, and enhance threat detection by integrating enriched threat data directly into security operations via the XSOAR interface.

This integration was integrated and tested with version 1.0 of CriminalIP.

## Configure CriminalIP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | The API Key to use for connection | False |
| Server URL | The base URL of the Criminal IP API. | True |
| Trust any certificate (not secure) | When set to true, SSL certificates will not be validated. | False |
| Use system proxy settings | Use the system proxy settings to communicate with the API. | False |
| Request timeout (seconds) | Timeout for HTTP requests in seconds. Default is 30. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### criminal-ip-ip-report

***
Provides detailed information about an IP address using Criminal IP's API.

#### Base Command

`criminal-ip-ip-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to search. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.IP.IP | String | Queried IP address. |
| CriminalIP.IP.InboundScore | String | Inbound reputation score. |
| CriminalIP.IP.OutboundScore | String | Outbound reputation score. |
| CriminalIP.IP.Issues | String | Detected issues \(VPN, Proxy, Tor, Hosting, Cloud, etc.\) |
| CriminalIP.IP.ProtectedIPs | Number | Number of protected IPs related to this IP. |
| CriminalIP.IP.RelatedDomains | Number | Number of domains related to this IP. |
| CriminalIP.IP.ASN | Number | Autonomous System Number \(ASN\). |
| CriminalIP.IP.ASName | String | Autonomous System Name. |
| CriminalIP.IP.Org | String | Organization name from Whois. |
| CriminalIP.IP.Country | String | Country code from Whois. |
| CriminalIP.IP.Hostname | String | Resolved hostname. |
| CriminalIP.IP.OpenPorts | Number | Number of open ports detected. |
| CriminalIP.IP.TopPort | Number | Example open port number. |
| CriminalIP.IP.TopService | String | Example service detected on an open port. |
| CriminalIP.IP.Vulnerabilities | Number | Number of vulnerabilities detected on the IP. |
| CriminalIP.IP.TopCVE | String | Example CVE ID detected on the IP. |
| CriminalIP.IP.TopCVSS | Number | Example CVSS v3 score of detected vulnerability. |
| CriminalIP.IP.raw | Unknown | Full raw response from CriminalIP API. |

### criminal-ip-check-malicious-ip

***
Determines whether an IP is malicious or safe through CriminalIP Asset Search.

#### Base Command

`criminal-ip-check-malicious-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Mal_IP.ip | String | Queried IP address. |
| CriminalIP.Mal_IP.malicious | Boolean | Whether the IP was detected as malicious. |
| CriminalIP.Mal_IP.real_ip_list | Unknown | List of real IPs if protected IP was detected. |
| CriminalIP.Mal_IP.raw | Unknown | Full raw response. |

### criminal-ip-check-last-scan-date

***
Checks if the domain has been scanned within the last 7 days.

#### Base Command

`criminal-ip-check-last-scan-date`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check last scan date for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Scan_Date.domain | String | Queried Domain. |
| CriminalIP.Scan_Date.scan_id | String | The last scan ID of the domain. |
| CriminalIP.Scan_Date.scanned | Boolean | Whether the domain was scanned within the last 7 days. |
| CriminalIP.Scan_Date.raw | Unknown | Full raw response from CriminalIP API. |

### criminal-ip-domain-quick-scan

***
Performs a Domain Quick Scan using CriminalIP's API.

#### Base Command

`criminal-ip-domain-quick-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to perform Quick Scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Domain_Quick.domain | String | Queried Domain. |
| CriminalIP.Domain_Quick.risk_score | Number | Risk Score. |
| CriminalIP.Domain_Quick.raw | Unknown | Full raw response. |

### criminal-ip-domain-lite-scan

***
Initiates a Domain Lite Scan and returns a scan_id.

#### Base Command

`criminal-ip-domain-lite-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to perform Lite Scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Domain_Lite.scan_id | String | Scan ID returned for Lite Scan. |
| CriminalIP.Domain_Lite.raw | Unknown | Full raw response. |

### criminal-ip-domain-lite-scan-status

***
Checks the progress of the Lite Scan.

#### Base Command

`criminal-ip-domain-lite-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id whose Lite Scan progress to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Domain_Lite_Status.status | String | Lite Scan status. |
| CriminalIP.Domain_Lite_Status.raw | Unknown | Full raw response. |

### criminal-ip-domain-lite-scan-result

***
Returns the Lite Scan results for the given scan_id.

#### Base Command

`criminal-ip-domain-lite-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id whose Lite Scan result to fetch. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Domain_Lite_Result.domain | String | Queried Domain. |
| CriminalIP.Domain_Lite_Result.vulns | Unknown | CVEs detected. |
| CriminalIP.Domain_Lite_Result.raw | Unknown | Full raw response. |

### criminal-ip-domain-full-scan

***
Initiates a Domain Full Scan and returns a scan_id.

#### Base Command

`criminal-ip-domain-full-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to perform Full Scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Full_Scan.scan_id | String | Scan ID returned for Full Scan. |
| CriminalIP.Full_Scan.raw | Unknown | Full raw response. |

### criminal-ip-domain-full-scan-status

***
Checks the progress of the Full Scan.

#### Base Command

`criminal-ip-domain-full-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id whose Full Scan status to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Full_Scan_Status.status | String | Full Scan status. |
| CriminalIP.Full_Scan_Status.raw | Unknown | Full raw response. |

### criminal-ip-domain-full-scan-result

***
Returns the Full Scan results for the given scan_id.

#### Base Command

`criminal-ip-domain-full-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id whose Full Scan result to fetch. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Full_Scan_Result.domain | String | Queried Domain. |
| CriminalIP.Full_Scan_Result.certificates | Unknown | Certificate Information. |
| CriminalIP.Full_Scan_Result.vulns | Unknown | CVEs detected in Full Scan. |
| CriminalIP.Full_Scan_Result.raw | Unknown | Full raw response. |

### criminal-ip-domain-full-scan-make-email-body

***
Builds an email body summarizing notable findings from a completed Full Scan.

#### Base Command

`criminal-ip-domain-full-scan-make-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id of the completed Full Scan. | Required |
| domain | The domain of the completed Full Scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Email_Body.domain | String | Domain analyzed. |
| CriminalIP.Email_Body.scan_id | String | Scan ID used for generating the email body. |
| CriminalIP.Email_Body.summary | String | Generated email summary string. |
| CriminalIP.Email_Body.body | String | Generated email body text \(for email notifications\). |
| CriminalIP.Email_Body.raw | Unknown | Full raw response from Criminal IP API. |

### criminal-ip-micro-asm

***
Performs a micro ASM-style summary for a domain with a completed Full Scan.

#### Base Command

`criminal-ip-micro-asm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan_id of the completed Full Scan. | Required |
| domain | The domain of the completed Full Scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CriminalIP.Micro_ASM.domain | String | Domain analyzed. |
| CriminalIP.Micro_ASM.scan_id | String | Scan ID used for Micro ASM. |
| CriminalIP.Micro_ASM.summary | String | Concise summary string of notable findings \(certificate expiry, domain score, phishing probability, suspicious elements, main IP, SSL vulnerabilities\). |
| CriminalIP.Micro_ASM.raw | Unknown | Full raw response from CriminalIP API. |
