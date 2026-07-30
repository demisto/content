RelayShield real-time identity-compromise and agent-security threat intelligence.

This integration implements the generic `domain`, `ip`, and `email` reputation commands,
which are automatically invoked by any existing enrichment playbook that calls generic
reputation commands, with no playbook changes needed. It adds three RelayShield-specific
commands for MCP server registry risk, certificate expiry, and supply-chain vendor risk.

This integration was integrated and tested with version 1.0 of the RelayShield API.

## Configure RelayShield in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The RelayShield API base URL. | True |
| API Key | The RelayShield API key, sent as the `X-RS-API-KEY` header. | True |
| Trust any certificate (not secure) | Whether to trust any TLS certificate. | False |
| Use system proxy settings | Whether to route requests through the system proxy. | False |

## DBotScore mapping

A clean result ("no known finding") maps to DBotScore **Unknown (0)**, never **Good (1)**.
"No known finding" means nothing was flagged in the sources RelayShield actually queried,
which is not a verified-safe guarantee.

| **RelayShield verdict** | **DBotScore** |
| --- | --- |
| CRITICAL | 3 (Bad) |
| HIGH | 3 (Bad) |
| MEDIUM | 2 (Suspicious) |
| LOW | 2 (Suspicious) |
| No known finding | 0 (Unknown) |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the
command details.

### domain

***
Check a domain for phishing-lookalike/typosquat risk, presence in RelayShield's criminal IOC corpus, and set a DBotScore.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.Domain.queried | String | The domain queried. |
| RelayShield.Domain.verdict | String | The RelayShield verdict \(CRITICAL/HIGH/MEDIUM/LOW\), absent if no known finding. |
| RelayShield.Domain.findings | Unknown | The list of findings, if any. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score \(0=Unknown, 2=Suspicious, 3=Bad, never 1/Good for a clean result\). |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

### ip

***
Check an IP address for reputation, malicious/suspicious votes, and set a DBotScore.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.IP.queried | String | The IP address queried. |
| RelayShield.IP.reputation | Number | The community reputation score. |
| RelayShield.IP.malicious_votes | Number | The malicious vote count. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score \(0=Unknown, 2=Suspicious, 3=Bad, never 1/Good for a clean result\). |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

### email

***
Check an email address for breach exposure and active stolen-session risk, and set a DBotScore.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | A comma-separated list of email addresses to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.Email.queried | String | The email address queried. |
| RelayShield.Email.breach_found | Boolean | Whether the email address appears in a known breach. |
| RelayShield.Email.breach_sources | Unknown | The list of breach sources the email address was found in. |
| RelayShield.Email.session_risk_found | Boolean | Whether an active stolen session was found. |
| RelayShield.Email.sessions | Unknown | The list of stolen sessions found, if any. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score \(0=Unknown, 2=Suspicious, 3=Bad, never 1/Good for a clean result\). |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

### relayshield-mcp-registry-risk

***
Assess an MCP server URL or package name for typosquat/supply-chain/registry risk before an agent connects to it.

#### Base Command

`relayshield-mcp-registry-risk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_url | The full URL of the MCP server to check. Provide this or package_name. | Optional |
| package_name | The package name of the MCP server if no server_url is available. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.MCPRegistryRisk.queried | String | The server URL or package name queried. |
| RelayShield.MCPRegistryRisk.verdict | String | The RelayShield verdict, absent if no known finding. |
| RelayShield.MCPRegistryRisk.findings | Unknown | The list of findings, if any. |

### relayshield-cert-expiry

***
Check a domain's TLS certificate expiry risk.

#### Base Command

`relayshield-cert-expiry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.CertExpiry.domain | String | The domain checked. |
| RelayShield.CertExpiry.days_remaining | Number | The days until certificate expiry. |
| RelayShield.CertExpiry.risk_level | String | The risk level \(CRITICAL/HIGH/MEDIUM/LOW\). |

### relayshield-supply-chain

***
Check up to 10 vendor domains (or emails) for combined breach/infostealer risk.

#### Base Command

`relayshield-supply-chain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_domains | A comma-separated list of up to 10 vendor domains to check. Provide this or vendor_emails. | Optional |
| vendor_emails | A comma-separated list of vendor email addresses. The domain portion is extracted automatically. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RelayShield.SupplyChain.domains_checked | Number | The number of vendor domains checked. |
| RelayShield.SupplyChain.highest_risk | String | The highest risk level found across all vendors checked. |
| RelayShield.SupplyChain.critical_vendors | Unknown | The list of vendors flagged as critical risk. |
