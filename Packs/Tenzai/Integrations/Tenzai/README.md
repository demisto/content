Validate Cortex ASM-discovered exposures with Tenzai's agentic penetration testing. Create a scan for an exposure, poll it to completion, and fetch the verdict and evidence back into the Cortex issue.

## Prerequisites

- A Tenzai license.
- A Tenzai partner API key. To obtain one:
  1. Sign in to the Tenzai application.
  2. Generate a partner API key for your tenant.
  3. Copy the key — you paste it into the integration instance below (it is stored encrypted).

## Configure Tenzai in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Tenzai Server URL (e.g., https://api.tenzai.io) | The base URL of the Tenzai API. | True |
| API Key | The Tenzai partner API key, generated in the Tenzai application. Stored encrypted. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Tenzai App URL (e.g., https://app.tenzai.io) | The base URL of the Tenzai web app, used to build a deep link \(referenceUrl\) to the scan results. Leave empty to derive it from the Tenzai Server URL \(the API and web-app hosts mirror each other\); set it only to override that. | False |
| HTTP request timeout (seconds) | The per-request timeout for calls to the Tenzai API. Kept low so a stalled or unreachable host fails fast and the validation poll automation can reschedule instead of exceeding its execution timeout. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tenzai-create-scan

***
Create a Tenzai agentic scan for a Cortex ASM-discovered exposure. Finds or creates a Tenzai application for the target domain, then triggers an EXTERNAL_LEAD scan — a short, targeted confirm/refute of the single externally-reported exposure — scoped to the exposed socket. Returns a scan id used to poll status and fetch results.

#### Base Command

`tenzai-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The exposure target — an IP address, FQDN, host:port, or URL. | Required |
| exposure_name | The human-readable name for the exposure (e.g. the ASM issue/alert name). Used as the scan name. | Required |
| supporting_data | The free-text context for the scan objective (e.g. inferred CVE(s), attack-surface rule, service classification, detected technology, certificate details). | Optional |
| application_type | The Tenzai application type to scan as. Derived from the target/service classification when omitted. Possible values are: WEB_APP, NETWORK_SERVICE, NETWORK_HOST. | Optional |
| port | The exposed service port. | Optional |
| protocol | The exposed service protocol (e.g. tcp, udp). | Optional |
| service_classification | The Cortex ASM service classification (e.g. WebServer, SshServer). | Optional |
| asm_service_id | The Cortex ASM ExternalService id (folded into the app guidelines as a correlation note). | Optional |
| alert_internal_id | The Cortex issue/alert id (folded into the app guidelines as a correlation note). | Optional |
| issue_description | The Cortex issue Description, folded into the application guidelines at create time. Also sent as the EXTERNAL_LEAD exposure description. | Optional |
| category | Whether the exposure is a CVE or a misconfiguration. Inferred from cve_id when omitted (cve when a CVE id is present, otherwise misconfiguration). Possible values are: cve, misconfiguration. | Optional |
| cve_id | The CVE identifier for the exposure (e.g. CVE-2018-15473), taken from the Cortex/ASM structured CVE field. Sets the EXTERNAL_LEAD category to cve. | Optional |
| rule_id | The external source's rule identifier for the exposure (e.g. a Cortex attack-surface rule id). | Optional |
| severity | The severity as reported by Cortex (free text), attached to the EXTERNAL_LEAD exposure reference. | Optional |
| cwe | The CWE identifier for the exposure when Cortex supplies one. | Optional |
| guidelines | The optional analyst guidelines for this scan (free text). Appended to the synthesized scan guidelines; the exposure focus and the single-target scope lock are always kept. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tenzai.Scan.id | String | The Tenzai scan \(test\) id. |
| Tenzai.Scan.applicationId | String | The Tenzai application id the scan runs under. |
| Tenzai.Scan.status | String | The initial status of the scan \(e.g. Pending, Running\). |
| Tenzai.Scan.alertId | String | The originating Cortex alert id the exposure lead was seeded with \(re-supply to tenzai-get-scan-result to scope the verdict to this alert's lead\). |
| Tenzai.Scan.cve | String | The CVE id the exposure lead was seeded with, when the exposure is a CVE. |
| Tenzai.Scan.ruleId | String | The Cortex rule id the exposure lead was seeded with, when supplied. |

### tenzai-get-scan

***
Poll the status of a Tenzai scan until it reaches a terminal state (Complete or Error).

#### Base Command

`tenzai-get-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Tenzai scan id (returned by tenzai-create-scan). | Required |
| interval_in_seconds | The interval, in seconds, between status polls. Default is 60. | Optional |
| timeout_in_seconds | The timeout, in seconds, for polling. Default is 3600. | Optional |
| hide_polling_output | Whether to hide the polling result while waiting (automatically filled by the platform). | Optional |
| polling | Whether to poll until the scan reaches a terminal state. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tenzai.Scan.id | String | The Tenzai scan id. |
| Tenzai.Scan.status | String | The scan status \(Pending, Running, Complete, Error\). |

### tenzai-get-scan-result

***
Fetch the verdict and evidence of a completed Tenzai scan.

#### Base Command

`tenzai-get-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Tenzai scan id. | Required |
| alert_id | The originating Cortex alert id, used to correlate the verdict to this alert's exposure lead on a multi-lead host scan. Strongest correlation key. | Optional |
| cve | The exposure's CVE id, used (with rule_id) to correlate the verdict to the matching exposure lead when alert_id does not resolve. | Optional |
| rule_id | The Cortex rule id, used together with cve to disambiguate same-CVE sibling leads. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tenzai.Scan.id | String | The Tenzai scan id. |
| Tenzai.Scan.applicationId | String | The Tenzai application id the scan ran under. |
| Tenzai.Scan.status | String | The scan status. |
| Tenzai.Scan.validated | Boolean | The tri-state verdict for the matched exposure lead — true when its status is MATERIALIZED, false when INVALIDATED, and null \(no verdict\) when BLOCKED, unresolved, or no lead correlated to the alert. |
| Tenzai.Scan.correlationState | String | The tri-state lead correlation for this alert: resolved \(a lead matched\), unmatched \(leads fetched but none correlate — final\), or pending \(the leads fetch failed or returned none yet — transient\). Drives the verdict write-back readiness gate. |
| Tenzai.Scan.evidence | String | The markdown assessment summary — impact-first per confirmed finding. |
| Tenzai.Scan.reproduction | String | The markdown reproduction steps \(prerequisites, steps, scripts\) across the scan's findings. |
| Tenzai.Scan.guidance | String | The markdown remediation guidance \(fix items and coding-agent prompt\) across the scan's findings. |
| Tenzai.Scan.creditUsage | Number | The approximate Tenzai ACU cost of the scan. |
| Tenzai.Scan.duration | Number | The wall-clock duration of the scan, in whole seconds. |
| Tenzai.Scan.referenceUrl | String | The deep link to view the scan results in the Tenzai web app. |
| Tenzai.Scan.exposureStatus | String | The exposure lead's terminal status \(e.g. MATERIALIZED, INVALIDATED, BLOCKED\) — the literal lead status shown in the panel's Status cell. |
| Tenzai.Scan.startedAt | Date | The date when the assessment started, as a full ISO-8601 timestamp \(e.g., 2024-01-15T12:34:56Z\) \(the exposure lead's earliest OPEN status-history entry\). |
| Tenzai.Scan.cwe | String | The exposure lead's CWE classification \(e.g. CWE-79\). |
| Tenzai.Scan.owaspCategory | String | The exposure lead's OWASP category \(e.g. A03\). |
| Tenzai.Scan.leadRationale | String | The markdown Description/Conclusion narrative for a CVE exposure lead. |
| Tenzai.Scan.timeline | Unknown | The exposure lead's status history — one entry per status change \(status \+ time\). |
| Tenzai.Finding.title | String | The finding title. |
| Tenzai.Finding.severity | String | The finding severity \(uppercase\). |
| Tenzai.Finding.details | String | The markdown assessment details for the finding — impact then description. |
| Tenzai.Finding.reproduction | String | The markdown reproduction steps for the finding. |
| Tenzai.Finding.guidance | String | The remediation guidance for the finding. |
| Tenzai.Finding.detail | String | The combined markdown \(details \+ reproduction \+ fix guidance\) shown in the Tenzai Findings grid's Details cell. |
| Tenzai.Finding.cve | String | The finding's CVE id, parsed from its structured field or name \(display only\). |
| Tenzai.Finding.attribution | String | The finding's attribution relative to the matched exposure: own \(this alert's exposure\), discovered \(a different CVE found while testing the host\), or unattributed \(no lead correlated to the alert\). |
