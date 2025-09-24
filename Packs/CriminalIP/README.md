# Criminal IP Integration for Palo Alto XSOAR

This integration was integrated and tested with Criminal IP API version 1.0.0

## About

Criminal IP delivers cyber threat intelligence powered by AI and OSINT, enabling precise threat analysis and deep investigations into IPs, domains, and URLs with reputation data, threat scoring, along with real-time detection of malicious indicators such as C2, IOCs, and other critical threats. Built on this intelligence, Criminal IP Attack Surface Management discovers and monitors exposed assets, identifying risks across the attack surface with real-time enrichment and risk prioritisation.

The integration between Criminal IP and Palo Alto XSOAR enables users to assess the malicious nature of IPs and domains through dedicated Commands and Playbooks. For domains, the system delivers comprehensive reports directly to users via email.

Additionally, Criminal IP's Micro-ASM playbook provides rapid and robust Attack Surface Management capabilities, allowing users to receive detailed reports about their digital assets via email.

---

## Requirements

To use this integration, a Criminal IP API key is required.  
Users can obtain an API key by registering at [Criminal IP](https://www.criminalip.io/).

---

## What does this pack do?

### IP Analysis

- Evaluates IPs to determine whether they are malicious or safe.
- Supports automated maliciousness checks using Criminal IP's scoring and Real IP detection.

### Domain Analysis

- Runs multiple scan types (Quick, Lite, Full) on domains to assess security posture.
- Full Scan results can be summarized for email delivery.

### Attack Surface Management

- Monitors domain assets for anomalies (e.g., CVEs, expiring certificates, malicious connections).
- Can be scheduled for continuous monitoring and email reporting.

### Playbooks Included

- Criminal IP Micro ASM – Takes a list of domains, executes a Full Scan, runs Micro ASM checks, and emails results.  
- Criminal IP Run Micro ASM – Sub-playbook that scans a single domain and polls for completion.

---

## Commands

### criminal-ip-ip-report

Provides detailed information about IP addresses through Criminal IP's API.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| ip | The IP address to search | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.IP.ip | String | Queried IP Address |
| CriminalIP.IP.score.inbound | String | Inbound Score |
| CriminalIP.IP.score.outbound | String | Outbound Score |
| CriminalIP.IP.issues | Unknown | Detected Issues (VPN, Proxy, Tor, etc.) |
| CriminalIP.IP.vulnerability | Unknown | Vulnerabilities detected on the IP |
| CriminalIP.IP.raw | Unknown | Full raw response from Criminal IP API (contains all additional fields not listed above) |

#### Example

```text
!criminal-ip-ip-report ip=8.8.8.8
```

### criminal-ip-check-malicious-ip

Determines whether an IP is malicious or safe through Criminal IP Asset Search.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| ip | IP Address to check | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Mal_IP.result | String | Malicious / Safe decision |
| CriminalIP.Mal_IP.real_ip | String | Real IP if detected |
| CriminalIP.Mal_IP.raw | Unknown | Full raw response (contains complete API response data) |

#### Example

```text
!criminal-ip-check-malicious-ip ip=192.168.1.1
```

### criminal-ip-domain-quick-scan

Performs a Domain Quick Scan using Criminal IP's API.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| domain | The domain to perform Quick Scan | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Domain_Quick.domain | String | Queried Domain |
| CriminalIP.Domain_Quick.risk_score | Number | Risk Score |
| CriminalIP.Domain_Quick.raw | Unknown | Full raw response (contains complete API response data) |

#### Example

```text
!criminal-ip-domain-quick-scan domain=example.com
```

### criminal-ip-domain-lite-scan

Initiates a Domain Lite Scan and returns a scan_id.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| domain | The domain to perform Lite Scan | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Domain_Lite.scan_id | String | Scan ID returned for Lite Scan |
| CriminalIP.Domain_Lite.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-lite-scan domain=example.com
```

### criminal-ip-domain-lite-scan-status

Checks the progress of the Lite Scan.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id whose Lite Scan progress to check | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Domain_Lite_Status.status | String | Lite Scan status |
| CriminalIP.Domain_Lite_Status.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-lite-scan-status scan_id=abc123def456
```

### criminal-ip-domain-lite-scan-result

Returns the Lite Scan results for the given scan_id.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id whose Lite Scan result to fetch | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Domain_Lite_Result.domain | String | Queried Domain |
| CriminalIP.Domain_Lite_Result.vulns | Unknown | CVEs detected |
| CriminalIP.Domain_Lite_Result.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-lite-scan-result scan_id=abc123def456
```

### criminal-ip-check-last-scan-date

Checks whether a Full Scan exists within the last 7 days and returns the latest scan status.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| domain | The domain to check scan history | True | - | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Scan_Date | String | Last scan date check result |

#### Example

```text
!criminal-ip-check-last-scan-date domain=example.com
```

### criminal-ip-domain-full-scan

Initiates a Domain Full Scan and returns a scan_id.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| domain | The domain to perform Full Scan | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Full_Scan.scan_id | String | Scan ID returned for Full Scan |
| CriminalIP.Full_Scan.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-full-scan domain=example.com
```

### criminal-ip-domain-full-scan-status

Checks the progress of the Full Scan.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id whose Full Scan status to check | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Full_Scan_Status.status | String | Full Scan status |
| CriminalIP.Full_Scan_Status.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-full-scan-status scan_id=xyz789abc123
```

### criminal-ip-domain-full-scan-result

Returns the Full Scan results for the given scan_id.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id whose Full Scan result to fetch | True | True | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Full_Scan_Result.domain | String | Queried Domain |
| CriminalIP.Full_Scan_Result.certificates | Unknown | Certificate Information |
| CriminalIP.Full_Scan_Result.vulns | Unknown | CVEs detected in Full Scan |
| CriminalIP.Full_Scan_Result.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-domain-full-scan-result scan_id=xyz789abc123
```

### criminal-ip-domain-full-scan-make-email-body

Builds an email body summarizing notable findings from a completed Full Scan.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id of the completed Full Scan | True | True | String |
| domain | The domain of the completed Full Scan | True | - | String |

#### Context Output

| Path | Type | Description |
| --- | --- | --- |
| CriminalIP.Email_Body.domain | String | Domain analyzed |
| CriminalIP.Email_Body.scan_id | String | Scan ID used for generating the email body |
| CriminalIP.Email_Body.summary | String | Generated email summary string |
| CriminalIP.Email_Body.body | String | Generated email body text (for email notifications) |
| CriminalIP.Email_Body.raw | Unknown | Full raw response from Criminal IP API |

#### Example

```text
!criminal-ip-domain-full-scan-make-email-body scan_id=xyz789abc123 domain=example.com
```

### criminal-ip-micro-asm

Performs a micro ASM-style summary for a domain with a completed Full Scan. See also: Criminal IP Micro ASM playbook.

#### Input

| Argument | Description | Required | Default | Type |
|---|---|---|---|---|
| scan_id | The scan_id of the completed Full Scan | True | True | String |
| domain | The domain of the completed Full Scan | True | - | String |

#### Context Output

| Path | Type | Description |
|---|---|---|
| CriminalIP.Micro_ASM.summary | String | Concise summary string of notable findings |
| CriminalIP.Micro_ASM.raw | Unknown | Full raw response |

#### Example

```text
!criminal-ip-micro-asm scan_id=xyz789abc123 domain=example.com
```

---

## Resources

- [Criminal IP](https://www.criminalip.io/)  
- [Criminal IP Blog](https://blog.criminalip.io/)
