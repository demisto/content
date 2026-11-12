Create Cortex XSOAR incidents from finished tLab Anti-APT sandbox analyses.
This integration was developed against the tLab Anti-APT API of sandbox-core 1.13.0.

## Configure tLab Anti-APT Verdicts in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the tLab Anti-APT sandbox API \(tlab-server\). Through the tLab web server use https://&lt;tlab-host&gt;/api; for a direct connection use http://&lt;tlab-host&gt;:8080. | True |
| Auth server URL (tlab-auth) | Used by the tLab account mode. Where the integration logs in to tlab-auth. Leave empty to use https://&lt;Server URL host&gt;:8002/api, the omni-center portal, which forwards /api to tlab-auth over TLS; if its certificate is self-signed, enable Trust any certificate. Not https://&lt;host&gt;/api, which is the sandbox API itself. | False |
| Authentication mode | tLab account \(tlab-auth\) is recommended: the integration logs in to tlab-auth like the omni-center portal and sends the token as Bearer. Source key needs the source-key gateway \(balancer\) and covers submissions only. Username and password is the legacy tlab-server sign-in. Internal token works only when Cortex XSOAR runs on the tlab-server host itself. | True |
| Credentials | Login and password of a tLab account \(tLab account mode\). This integration only reads. See the detailed instructions for the role the account needs. Turn off password expiry for this account: tlab-auth rejects an expired password and every command starts failing. | True |
| Password / source key / internal token | The password of the tLab account, or the source key or internal token, depending on the authentication mode. | True |
| Use system proxy settings | Whether to use the Cortex XSOAR server's system proxy settings. | False |
| Trust any certificate (not secure) | Whether to skip TLS certificate verification. Needed when the tLab certificate is self-signed. | False |
| Fetch incidents | Do not enable this if the tLab Cortex XSOAR connector is running in PUSH mode against the same tenant: both halves create the same incidents, and you will get two of everything. | False |
| Incident type | Incident type for fetched incidents when the classifier does not set one. The pack's classifier sets tLab Anti-APT Verdict. | False |
| Incidents Fetch Interval | How often, in minutes, new verdicts are fetched. | False |
| Installation ID | Identifies this tLab installation inside every deduplication key. Required, and it must match INSTALLATION_UUID in the tLab Cortex XSOAR connector if that connector also runs against this tenant, otherwise the two halves will not recognize each other's incidents as duplicates. | True |
| Client name | Sent as the X-Client header. | False |
| Verdicts to fetch | Only analyses ending in one of these verdicts become incidents. | False |
| Maximum incidents per fetch | Upper bound on sample reports processed per run. With enrichment on, each report costs one extra API call. | False |
| First sample report id | Lowest sample report id to fetch. Takes effect on the next fetch, also when fetching has already started - raise it to skip a backfill. Leave empty to start from the beginning of history, which on a long-running installation means a very large backfill. | False |
| Late completion lookback (hours) | The sandbox finishes analyses out of id order, so a report can complete after a higher-numbered one already did. Each run also re-scans reports updated within this window. Set to 0 to disable, at the cost of losing late completions permanently. | False |
| Enrich incidents | Adds threat indicators, MITRE ATT&amp;CK techniques and the antivirus flag. Costs one extra API call per report. With this off, those three fields are always empty. | False |
| Root reports only | On by default. Dropped and embedded files get their own sample reports, so turning this off turns one archive into a dozen incidents for a single delivery. | False |
| Include partially complete analyses | Off by default. A partial verdict can still change, and an incident whose severity drops after the analyst triaged it is worse than a late one. | False |
| Incident name template | Placeholders: \{verdict\}, \{filename\}, \{sha256\}, \{score\}, \{report_id\}, \{source_type\}. Must match INCIDENT_NAME_TEMPLATE in the tLab Cortex XSOAR connector if both halves run against this tenant. | False |
| Severity map | Comma-separated VERDICT:severity pairs. Valid severities are 0, 0.5, 1, 2, 3 and 4 \(Unknown, Informational, Low, Medium, High, Critical\). Must match SEVERITY_MAP in the tLab Cortex XSOAR connector if both halves run against this tenant. | False |
| Critical score threshold | A MALWARE verdict at or above this score is raised to Critical. Set to 0 to disable. | False |
| Suspicious score threshold | Scores from this value up to the malicious threshold are Suspicious. Fractional values are allowed. Default is 50, the product default. | False |
| Malicious score threshold | Scores at or above this value are Malicious. Fractional values are allowed. Default is 85, the product default. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tlab-get-verdicts

***
Preview the incidents the next fetch would create, without creating them and without moving the fetch cursor. Use it to check the verdict filter and the name template before enabling fetch.

#### Base Command

`tlab-get-verdicts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of verdicts to return. Default is 10. | Optional | 
| from_report_id | Preview from this sample report id instead of the current cursor. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Verdict.tlab_dedupe_key | String | Deduplication key, stable across restarts and re-sends. | 
| TLabAntiAPT.Verdict.tlab_sample_report_id | Number | Sample report identifier in tLab Anti-APT. | 
| TLabAntiAPT.Verdict.tlab_verdict | String | Canonical verdict. | 
| TLabAntiAPT.Verdict.tlab_score | Number | Sandbox score from 0 to 100. | 
| TLabAntiAPT.Verdict.tlab_file_sha256 | String | SHA256 of the analyzed sample. | 
| TLabAntiAPT.Verdict.tlab_report_url | String | Link to the full report. | 

#### Command example
```!tlab-get-verdicts limit=10```
#### Context Example
```json
{
    "TLabAntiAPT.Verdict(val.tlab_dedupe_key && val.tlab_dedupe_key == obj.tlab_dedupe_key)": [
        {
            "tlab_dedupe_key": "tlab-apt:inst-uuid:412839",
            "tlab_sample_report_id": 412839,
            "tlab_verdict": "MALWARE",
            "tlab_delivery_mode": "PULL",
            "tlab_whitelisted": false,
            "tlab_av_detected": true,
            "tlab_multistage": true,
            "tlab_attack_techniques": [
                "T1027.002",
                "T1071"
            ],
            "tlab_threat_indicators": [
                {
                    "source": "BEHAVIOR",
                    "level": "MALICIOUS",
                    "title": "Connects to a known bad host",
                    "count": 3
                },
                {
                    "source": "AV",
                    "level": "MALICIOUS",
                    "title": "Antivirus detection",
                    "count": 1
                },
                {
                    "source": "STATIC",
                    "level": "SUSPICIOUS",
                    "title": "Packed executable",
                    "count": 1
                }
            ],
            "tlab_tags": [],
            "tlab_analysis_request_id": 900123,
            "tlab_access_code": "ac-412839",
            "tlab_report_type": "MAIN",
            "tlab_completeness": "COMPLETE",
            "tlab_score_level": "MALICIOUS",
            "tlab_file_verdict": "MALWARE",
            "tlab_file_sha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "tlab_file_sha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "tlab_file_md5": "aaaabbbbccccddddeeeeffff00001111",
            "tlab_file_name": "invoice.exe",
            "tlab_file_size": 2048,
            "tlab_file_type": "PE",
            "tlab_mime_type": "application/x-dosexec",
            "tlab_source_type": "Cortex XSOAR",
            "tlab_source_uid": "inc-77",
            "tlab_malware_family": "Emotet",
            "tlab_malware_confidence": 0.92,
            "tlab_report_url": "https://tlab.example.com/reports/412839",
            "tlab_create_time": "2026-03-26T08:00:00Z",
            "tlab_update_time": "2026-03-26T08:10:00Z",
            "tlab_score": 91.5,
            "tlab_max_score": 91.5
        },
        {
            "tlab_dedupe_key": "tlab-apt:inst-uuid:412840",
            "tlab_sample_report_id": 412840,
            "tlab_verdict": "SUSPICIOUS",
            "tlab_delivery_mode": "PULL",
            "tlab_whitelisted": false,
            "tlab_av_detected": false,
            "tlab_multistage": false,
            "tlab_attack_techniques": [],
            "tlab_threat_indicators": [
                {
                    "source": "AV",
                    "level": "SUSPICIOUS",
                    "title": "Heuristic hit",
                    "count": 1
                }
            ],
            "tlab_tags": [],
            "tlab_report_type": "MAIN",
            "tlab_completeness": "COMPLETE",
            "tlab_score_level": "SUSPICIOUS",
            "tlab_file_verdict": "SUSPICIOUS",
            "tlab_file_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "tlab_file_name": "macro.docm",
            "tlab_file_size": 512,
            "tlab_file_type": "OFFICE",
            "tlab_source_type": "tLab Mail",
            "tlab_source_uid": "mail-9",
            "tlab_report_url": "https://tlab.example.com/reports/412840",
            "tlab_create_time": "2026-03-26T08:16:40Z",
            "tlab_update_time": "2026-03-26T08:18:20Z",
            "tlab_score": 61.0
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT verdicts (2)
>|Name|Report ID|Verdict|Score|Severity|File|Occurred|
>|---|---|---|---|---|---|---|
>| tLab Anti-APT MALWARE: invoice.exe | 412839 | MALWARE | 91.5 | 3.0 | invoice.exe | 2026-03-26T08:00:00Z |
>| tLab Anti-APT SUSPICIOUS: macro.docm | 412840 | SUSPICIOUS | 61.0 | 2.0 | macro.docm | 2026-03-26T08:16:40Z |

### tlab-verdicts-reset-cursor

***
Reset the fetch cursor. Without an argument the next fetch starts from the configured first sample report id. Incidents already created are not removed.

#### Base Command

`tlab-verdicts-reset-cursor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_report_id | Set the cursor to this sample report id instead of resetting it entirely. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!tlab-verdicts-reset-cursor from_report_id=412839```
#### Human Readable Output

>Fetch cursor set to sample report 412839; the next fetch starts there. A First sample report id above it still takes precedence.
