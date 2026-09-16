Criminal IP is a comprehensive cyber threat intelligence solution that provides actionable insights into IP addresses, domains, and connected assets across the internet.
It enables organizations to detect malicious indicators, assess asset reputation, and enhance threat detection by integrating enriched threat data directly into security operations via the XSOAR interface.

This integration was integrated and tested with version 1.0.0 of CriminalIP.

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
| CriminalIP.IP.ObservedPort | Number | Example open port number. |
| CriminalIP.IP.ObservedService | String | Example service detected on an open port. |
| CriminalIP.IP.Vulnerabilities | Number | Number of vulnerabilities detected on the IP. |
| CriminalIP.IP.ObservedCVE | String | Example CVE ID detected on the IP. |
| CriminalIP.IP.ObservedCVSS | Number | Example CVSS v3 score of detected vulnerability. |
| CriminalIP.IP.raw | Unknown | Full raw response from CriminalIP API. |

#### Example

```text
!criminal-ip-ip-report ip=8.8.8.8
```

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

#### Example

```text
!criminal-ip-check-malicious-ip ip=192.168.1.1
```

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
| CriminalIP.Scan_Date.scan_date | String | The last scan date in ISO format. |
| CriminalIP.Scan_Date.raw | Unknown | Full raw response from CriminalIP API. |

#### Example

```text
!criminal-ip-check-last-scan-date domain=example.com
```

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
| CriminalIP.Domain_Quick.reg_dtime | String | Domain registration time. |
| CriminalIP.Domain_Quick.result | String | Quick scan result string. |
| CriminalIP.Domain_Quick.type | String | Domain type classification. |
| CriminalIP.Domain_Quick.raw | Unknown | Full raw response. |

#### Example

```text
!criminal-ip-domain-quick-scan domain=example.com
```

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

#### Example

```text
!criminal-ip-domain-lite-scan domain=example.com
```

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
| CriminalIP.Domain_Lite_Status.scan_percentage | Number | Scan percentage progress. |
| CriminalIP.Domain_Lite_Status.raw | Unknown | Full raw response. |

#### Example

```text
!criminal-ip-domain-lite-scan-status scan_id=abc123def456
```

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
| CriminalIP.Domain_Lite_Result.created | String | Domain creation date. |
| CriminalIP.Domain_Lite_Result.registrar | String | Domain registrar. |
| CriminalIP.Domain_Lite_Result.score | String | Domain risk score. |
| CriminalIP.Domain_Lite_Result.report_time | String | Report generation time. |
| CriminalIP.Domain_Lite_Result.phishing_prob | Number | Phishing probability. |
| CriminalIP.Domain_Lite_Result.dga_score | Number | DGA score. |
| CriminalIP.Domain_Lite_Result.abuse_critical | Number | Critical abuse record count. |
| CriminalIP.Domain_Lite_Result.abuse_dangerous | Number | Dangerous abuse record count. |
| CriminalIP.Domain_Lite_Result.a_records | String | A records resolved. |
| CriminalIP.Domain_Lite_Result.ns_records | String | NS records resolved. |
| CriminalIP.Domain_Lite_Result.mapped_ips | String | Mapped IP list. |
| CriminalIP.Domain_Lite_Result.raw | Unknown | Full raw response. |

#### Example

```text
!criminal-ip-domain-lite-scan-result scan_id=abc123def456
```

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

#### Example

```text
!criminal-ip-domain-full-scan domain=example.com
```

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
| CriminalIP.Full_Scan_Status.scan_percentage | Number | Scan percentage progress. |
| CriminalIP.Full_Scan_Status.raw | Unknown | Full raw response. |

#### Example

```text
!criminal-ip-domain-full-scan-status scan_id=xyz789abc123
```

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
| CriminalIP.Full_Scan_Result.created | String | Domain creation date. |
| CriminalIP.Full_Scan_Result.registrar | String | Domain registrar. |
| CriminalIP.Full_Scan_Result.score | String | Domain risk score. |
| CriminalIP.Full_Scan_Result.report_time | String | Report generation time. |
| CriminalIP.Full_Scan_Result.phishing_prob | Number | Phishing probability. |
| CriminalIP.Full_Scan_Result.dga_score | Number | DGA score. |
| CriminalIP.Full_Scan_Result.punycode | Boolean | Whether punycode detected. |
| CriminalIP.Full_Scan_Result.fake_https | Boolean | Whether fake HTTPS detected. |
| CriminalIP.Full_Scan_Result.abuse_critical | Number | Critical abuse record count. |
| CriminalIP.Full_Scan_Result.abuse_dangerous | Number | Dangerous abuse record count. |
| CriminalIP.Full_Scan_Result.cert_valid_to | String | Certificate valid until date. |
| CriminalIP.Full_Scan_Result.connected_ips | String | Connected IP list. |
| CriminalIP.Full_Scan_Result.ssl_vulns | String | SSL vulnerabilities detected. |
| CriminalIP.Full_Scan_Result.raw | Unknown | Full raw response. |

#### Example

```text
!criminal-ip-domain-full-scan-result scan_id=xyz789abc123
```

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
| CriminalIP.Email_Body.domain_score | String | Domain score. |
| CriminalIP.Email_Body.phishing_prob | Number | Phishing probability. |
| CriminalIP.Email_Body.dga_score | Number | DGA score. |
| CriminalIP.Email_Body.registrar | String | Domain registrar. |
| CriminalIP.Email_Body.created | String | Domain creation date. |
| CriminalIP.Email_Body.report_time | String | Report generation time. |
| CriminalIP.Email_Body.abuse_critical | Number | Critical abuse record count. |
| CriminalIP.Email_Body.abuse_dangerous | Number | Dangerous abuse record count. |
| CriminalIP.Email_Body.fake_https | Boolean | Whether fake HTTPS detected. |
| CriminalIP.Email_Body.punycode | Boolean | Whether punycode detected. |
| CriminalIP.Email_Body.cert_valid_to | String | Certificate expiration date. |
| CriminalIP.Email_Body.connected_ips | String | Connected IP addresses (comma-separated). |
| CriminalIP.Email_Body.ssl_vulns | String | SSL vulnerabilities detected. |
| CriminalIP.Email_Body.readable_output | String | Pre-formatted Full Scan report (email-ready). |
| CriminalIP.Email_Body.raw | Unknown | Full raw response from Criminal IP API. |

#### Example

```text
!criminal-ip-domain-full-scan-make-email-body scan_id=xyz789abc123 domain=example.com
```

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
| CriminalIP.Micro_ASM.domain_score | String | Domain score. |
| CriminalIP.Micro_ASM.phishing_prob | Number | Phishing probability. |
| CriminalIP.Micro_ASM.dga_score | Number | DGA score. |
| CriminalIP.Micro_ASM.registrar | String | Domain registrar. |
| CriminalIP.Micro_ASM.created | String | Domain creation date. |
| CriminalIP.Micro_ASM.report_time | String | Report generation time. |
| CriminalIP.Micro_ASM.abuse_critical | Number | Critical abuse record count. |
| CriminalIP.Micro_ASM.abuse_dangerous | Number | Dangerous abuse record count. |
| CriminalIP.Micro_ASM.fake_https | Boolean | Whether fake HTTPS detected. |
| CriminalIP.Micro_ASM.punycode | Boolean | Whether punycode detected. |
| CriminalIP.Micro_ASM.cert_valid_to | String | Certificate expiration date. |
| CriminalIP.Micro_ASM.connected_ips | String | Connected IP addresses (comma-separated). |
| CriminalIP.Micro_ASM.ssl_vulns | String | SSL vulnerabilities detected. |
| CriminalIP.Micro_ASM.readable_output | String | Pre-formatted Micro ASM report (email-ready). |
| CriminalIP.Micro_ASM.raw | Unknown | Full raw response from CriminalIP API. |

#### Example

```text
!criminal-ip-micro-asm scan_id=xyz789abc123 domain=example.com
```

## Resources

- [Criminal IP](https://www.criminalip.io/)  
- [Criminal IP Blog](https://blog.criminalip.io/)
