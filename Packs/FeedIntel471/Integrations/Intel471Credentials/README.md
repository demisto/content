# Intel471 Credentials

Fetches leaked credentials from the Intel471 Credentials API (`/credentials/stream`) and creates an incident per credential. Indicators are then extracted from each credential and associated with the incident that produced them.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---intel471-credentials).

## How it works

The primary command is `fetch-incidents`:

1. Leaked credentials are pulled from `/credentials/stream`.
2. Each credential becomes one incident of type **Intel471 Leaked Credential** (configurable), named `Intel471 Leaked Credential: <login> @ <domain>`, with the info stealer attributes attached as incident labels and the raw API record kept in `rawJSON`.
3. The incidents are created and their server-assigned IDs are read back.
4. Every observable the credential carries is then extracted as its own indicator:

   | Source field | Indicator type |
   | --- | --- |
   | `data.credential_login` | `Email` if the login contains `@`, otherwise `Account` |
   | `data.detection_domain`, `data.credential_domain` | `Domain` |
   | `data.info_stealer.ip` | `IP` or `IPv6` |
   | `data.info_stealer.pc_name` | `Host` |

5. Each extracted indicator is associated with the incident it came from via its `relatedIncidents` field, then created.

Only the login indicator carries the `intel471infostealer*` custom fields — those describe the host the credential was stolen from, so repeating them on the host's own IP and Host indicators would be redundant. Malformed observables (unparseable domains, invalid IPs) are skipped rather than created.

## Notes

* On the first run, the integration fetches credentials with `last_updated_ts` newer than the configured "First fetch timestamp" (default: 7 days).
* Subsequent runs continue from the stream cursor returned by the API.

## Prerequisites

The integration authenticates to the Intel471 Credentials API with HTTP Basic auth (**Username** = API username, **Password** = API key). To obtain these credentials:

1. Sign in to the [Intel471 Developer Portal](https://developer.intel471.com/) using your organization SSO account (or sign up if this is your first visit).
2. Confirm that your organization has an active subscription that grants access to the Credentials Intelligence product. If it does not, contact your Intel471 account manager to enable it.
3. In the portal, open **API Keys** (under your account menu) and click **Create new API key**.
4. Copy the generated **username** and **API key** — the API key is shown only once.
5. Use these values in the **Username** and **Password** fields of the configuration below.

## Configure Intel471 Credentials in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | HTTP Basic auth credentials for the Intel471 Credentials API — enter your API username and API key. | True |
| Password |  | True |
| Use system proxy settings | When enabled, requests are routed through the system proxy configured on the Cortex engine. | False |
| Trust any certificate (not secure) | When enabled, SSL certificate verification is skipped. Not recommended for production use. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The time to go back when performing the first fetch. | False |
| Maximum number of incidents per fetch | The maximum number of credentials to pull per fetch. Each credential becomes one incident, plus one indicator per observable it carries. | False |
| Incidents Fetch Interval | How often \(in minutes\) the integration polls the Intel471 API for new credentials. | False |
| Indicator Reputation | Indicators extracted from the fetched credentials will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to the extracted indicators. | False |
| Tags | Tags to apply to every extracted indicator. Supports CSV values. | False |
| Credential set name | The credential set name to filter results by. | False |
| Credential set id | The credential set ID to filter results by. | False |
| Credential login | Search results by credential login. | False |
| Domain | The credential detection domain to filter results by. | False |
| Affiliation group | The affiliation group to filter results by. Possible values: my_employees, my_customers, third_parties, vip_emails. | False |
| Password strength | The password strength to filter results by. | False |
| Detected malware | The detected info stealer malware family to filter results by \(e.g., agent_tesla, Lumma, VIDAR\). | False |
| GIRs | A comma-separated list of custom GIRs \(General Intelligence Requirements\), my_girs or company_pirs, to filter results by. | False |
| Password length (&gt;=) | Minimum total password length to filter results by. Must be greater than or equal to 0. | False |
| Password lowercase count (&gt;=) | Minimum number of lowercase characters in the password to filter results by. Must be greater than or equal to 0. | False |
| Password uppercase count (&gt;=) | Minimum number of uppercase characters in the password to filter results by. Must be greater than or equal to 0. | False |
| Password numbers count (&gt;=) | Minimum number of numeric characters in the password to filter results by. Must be greater than or equal to 0. | False |
| Password punctuation count (&gt;=) | Minimum number of punctuation characters in the password to filter results by. Must be greater than or equal to 0. | False |
| Password symbols count (&gt;=) | Minimum number of symbol characters in the password to filter results by. Must be greater than or equal to 0. | False |
| Password separators count (&gt;=) | Minimum number of separator characters in the password to filter results by. Must be greater than or equal to 0. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### intel471-credentials-get-indicators

***
Gets a preview of the indicators that the next fetch would extract, along with the incident each one would be associated with. No state is persisted and nothing is created.

#### Base Command

`intel471-credentials-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of credentials to read when building the preview. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Intel471Credentials.Indicators.value | String | The indicator value. |
| Intel471Credentials.Indicators.type | String | The indicator type — Email, Account, Domain, IP, IPv6, or Host. |
| Intel471Credentials.Indicators.score | Number | The reputation score applied to the indicator, derived from the Indicator Reputation parameter. |
| Intel471Credentials.Indicators.relatedIncidents | Unknown | The incident the indicator is associated with. Populated during fetch only. |
| Intel471Credentials.Indicators.fields.firstseenbysource | Date | Timestamp when the credential was first observed by Intel471. |
| Intel471Credentials.Indicators.fields.lastseenbysource | Date | Timestamp when the credential was last observed by Intel471. |
| Intel471Credentials.Indicators.fields.tags | Unknown | Aggregated tags — malware families, affiliations, and the configured instance tags. |
| Intel471Credentials.Indicators.fields.trafficlightprotocol | String | The Traffic Light Protocol designation applied to the indicator. |
| Intel471Credentials.Indicators.fields.intel471infostealerantivirussoftware | String | Antivirus software detected on the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealercomputerusername | String | Operating-system username logged in on the infected machine. |
| Intel471Credentials.Indicators.fields.intel471infostealerinfectiontimestamp | Date | Timestamp when the info stealer infection was recorded. |
| Intel471Credentials.Indicators.fields.intel471infostealerip | String | IP address of the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerisp | String | Internet service provider associated with the infected machine. |
| Intel471Credentials.Indicators.fields.intel471infostealermachineid | String | Unique identifier fingerprinted by the info stealer for the infected host. |
| Intel471Credentials.Indicators.fields.intel471infostealermalwarefamily | String | Family of info stealer malware that captured the credential. |
| Intel471Credentials.Indicators.fields.intel471infostealermalwareinstallpath | String | Filesystem path where the info stealer malware was installed. |
| Intel471Credentials.Indicators.fields.intel471infostealeros | String | Operating system reported for the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerpcname | String | Hostname \(PC name\) of the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerscreenshotpath | String | Path to the desktop screenshot captured by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerversion | String | Version identifier reported by the info stealer malware. |

## Breaking changes from the previous version of this integration - Intel471 Credentials

The integration changed from a feed to a fetch-incidents integration. Existing instances must be reconfigured after the upgrade — the differences below describe what changed.

### Fetch mode

The previous version was a feed and ran `fetch-indicators`; this version runs `fetch-incidents`. The **Fetch indicators** toggle is replaced by **Fetch incidents**, and **Feed Fetch Interval** by **Incidents Fetch Interval**. The feed-only parameters **Bypass exclusion list**, **Indicator Expiration Method** and **Indicator Expiration Interval** no longer apply; **Source Reliability** is now a plain integration parameter instead of a feed parameter.

### Indicators

The previous version created exactly one indicator per credential (the login). This version additionally extracts the detection and credential domains, the infected host's IP addresses, and its PC name — so one credential can now yield several indicators. Each one is associated with the incident created for that credential.

The previous version set the indicator's `relatedIncidents` to the incident *name*, because the feed handed the incidents to the server without learning their IDs. This version creates the incidents first and uses the real incident ID, falling back to the name only if the server does not report one.

### Commands

#### The following commands were changed in this version

* *intel471-credentials-get-indicators* - now also reports the incident each previewed indicator would be associated with, and previews the domain, IP and host indicators in addition to the login.

## Additional Considerations for this version

* Incidents are created directly from the fetch rather than returned to the server, so that the extracted indicators can reference the incident IDs the server assigns. Incident counts in the fetch history view may therefore read as 0 even though incidents were created — the actual counts are written to the integration log.
* Indicator deduplication is the server's, not the integration's: the same login seen in a later credential updates the existing indicator and gains an additional entry in `relatedIncidents`.
