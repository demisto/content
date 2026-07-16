# Intel 471 Credentials

Fetches leaked credentials from the Intel 471 Credentials API (`/credentials/stream`).

The primary command is `fetch-indicators`: each credential is converted into one Cortex XSOAR indicator (`Email` if the login contains `@`, otherwise `Account`). While iterating the indicator-creation loop the integration also creates an associated Cortex XSOAR incident for the same credential and links it back via the indicator's `relatedIncidents` field.

## Notes

* On the first run, the integration fetches credentials with `last_updated_ts` newer than the configured "First fetch timestamp" (default: 7 days).
* Subsequent runs continue from the stream cursor returned by the API.

## Configure Intel 471 Credentials in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | True |
| Password |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch indicators |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The time to go back when performing the first fetch. | False |
| Maximum items per fetch | The maximum number of credentials to pull per fetch \(each one becomes one indicator and one incident\). | False |
| Feed Fetch Interval |  | False |
| Indicator Reputation | The reputation to apply to indicators from this integration instance. | False |
| Source Reliability | The reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
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

There is no context output for this command.
