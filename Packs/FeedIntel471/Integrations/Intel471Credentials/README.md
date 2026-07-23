# Intel 471 Credentials

Fetches leaked credentials from the Intel 471 Credentials API (`/credentials/stream`).

The primary command is `fetch-indicators`: each credential is converted into one Cortex indicator (`Email` if the login contains `@`, otherwise `Account`). While iterating the indicator-creation loop, the integration also creates an associated Cortex incident for the same credential and links it back via the indicator's `relatedIncidents` field.

## Notes

* On the first run, the integration fetches credentials with `last_updated_ts` newer than the configured "First fetch timestamp" (default: 7 days).
* Subsequent runs continue from the stream cursor returned by the API.

## Prerequisites

The integration authenticates to the Intel 471 Credentials API with HTTP Basic auth (**Username** = API username, **Password** = API key). To obtain these credentials:

1. Sign in to the [Intel 471 Developer Portal](https://developer.intel471.com/) using your organization SSO account (or sign up if this is your first visit).
2. Confirm that your organization has an active subscription that grants access to the Credentials Intelligence product. If it does not, contact your Intel 471 account manager to enable it.
3. In the portal, open **API Keys** (under your account menu) and click **Create new API key**.
4. Copy the generated **username** and **API key** — the API key is shown only once.
5. Use these values in the **Username** and **Password** fields of the configuration below.

## Configure Intel 471 Credentials in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | HTTP Basic auth credentials for the Intel 471 Credentials API — enter your API username and API key. | True |
| Password | HTTP Basic auth credentials for the Intel 471 Credentials API — enter your API username and API key. | True |
| Use system proxy settings | When enabled, requests are routed through the system proxy configured on the Cortex engine. | False |
| Trust any certificate (not secure) | When enabled, SSL certificate verification is skipped. Not recommended for production use. | False |
| Fetch indicators |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The time to go back when performing the first fetch. | False |
| Maximum items per fetch | The maximum number of credentials to pull per fetch \(each one becomes one indicator and one incident\). | False |
| Feed Fetch Interval | How often \(in minutes\) the integration polls the Intel 471 API for new credentials. | False |
| Indicator Reputation | The reputation to apply to indicators from this integration instance. | False |
| Source Reliability | The reliability of the source providing the intelligence data. | True |
| Tags | A comma-separated list of tags. | False |
| Bypass exclusion list | Whether to ignore the exclusion list for indicators from this feed. | False |
| Credential set name | The credential set name to filter results by. | False |
| Credential set id | The credential set ID to filter results by. | False |
| Domain | The credential detection domain to filter results by. | False |
| Affiliation group | The affiliation group to filter results by. Possible values: my_employees, my_customers, third_parties, vip_emails. | False |
| Password strength | The password strength to filter results by. | False |
| Detected malware | The detected info stealer malware family to filter results by \(e.g., agent_tesla, Lumma, VIDAR\). | False |
| GIRs | A comma-separated list of custom GIRs \(General Intelligence Requirements\), my_girs or company_pirs, to filter results by. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### intel471-credentials-get-indicators

***
Gets a preview of indicators that the feed would pull on the next run (no state is persisted).

#### Base Command

`intel471-credentials-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Intel471Credentials.Indicators.value | String | The credential login value (email address or account username). |
| Intel471Credentials.Indicators.type | String | The indicator type — Email or Account. |
| Intel471Credentials.Indicators.fields.firstseenbysource | Date | Timestamp when the credential was first observed by Intel 471. |
| Intel471Credentials.Indicators.fields.lastseenbysource | Date | Timestamp when the credential was last observed by Intel 471. |
| Intel471Credentials.Indicators.fields.tags | Unknown | Aggregated tags — malware families, affiliations, and configured feed tags. |
| Intel471Credentials.Indicators.fields.intel471infostealerantivirussoftware | String | Antivirus software detected on the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealercomputerusername | String | Operating-system username logged in on the infected machine. |
| Intel471Credentials.Indicators.fields.intel471infostealerinfectiontimestamp | Date | Timestamp when the info stealer infection was recorded. |
| Intel471Credentials.Indicators.fields.intel471infostealerip | String | IP address of the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerisp | String | Internet service provider associated with the infected machine. |
| Intel471Credentials.Indicators.fields.intel471infostealermachineid | String | Unique identifier fingerprinted by the info stealer for the infected host. |
| Intel471Credentials.Indicators.fields.intel471infostealermalwarefamily | String | Family of info stealer malware that captured the credential. |
| Intel471Credentials.Indicators.fields.intel471infostealermalwareinstallpath | String | Filesystem path where the info stealer malware was installed. |
| Intel471Credentials.Indicators.fields.intel471infostealeros | String | Operating system reported for the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerpcname | String | Hostname (PC name) of the machine infected by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerscreenshotpath | String | Path to the desktop screenshot captured by the info stealer. |
| Intel471Credentials.Indicators.fields.intel471infostealerversion | String | Version identifier reported by the info stealer malware. |

#### Command example

```!intel471-credentials-get-indicators limit=5```

#### Context Example

```json
{
    "Intel471Credentials": {
        "Indicators": [
            {
                "value": "victim@example.com",
                "type": "Email",
                "fields": {
                    "firstseenbysource": "2026-06-01T00:00:00Z",
                    "lastseenbysource": "2026-06-20T00:00:00Z",
                    "tags": ["lumma", "my_employees"],
                    "intel471infostealerantivirussoftware": "Defender",
                    "intel471infostealercomputerusername": "jdoe",
                    "intel471infostealerinfectiontimestamp": "2026-06-19T12:00:00Z",
                    "intel471infostealerip": "1.2.3.4, 5.6.7.8",
                    "intel471infostealerisp": "ExampleISP",
                    "intel471infostealermachineid": "m-1",
                    "intel471infostealermalwarefamily": "lumma",
                    "intel471infostealermalwareinstallpath": "C:/Users/jdoe/AppData/Roaming",
                    "intel471infostealeros": "Windows 11",
                    "intel471infostealerpcname": "DESKTOP-XYZ",
                    "intel471infostealerscreenshotpath": "screens/abc.png",
                    "intel471infostealerversion": "1.2.3"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators from Intel 471 Credentials
>
>|Value|Type|fields|
>|---|---|---|
>| victim@example.com | Email | firstseenbysource: 2026-06-01T00:00:00Z<br>lastseenbysource: 2026-06-20T00:00:00Z<br>tags: lumma, my_employees<br>intel471infostealermalwarefamily: lumma<br>intel471infostealerip: 1.2.3.4, 5.6.7.8<br>intel471infostealeros: Windows 11<br>intel471infostealerpcname: DESKTOP-XYZ<br>intel471infostealerversion: 1.2.3 |
