Turn observables seen during tLab Anti-APT sandbox analysis into Threat Intel Management indicators.
This integration was developed against the tLab Anti-APT API of sandbox-core 1.13.0.

## Configure tLab Anti-APT Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the tLab Anti-APT sandbox API \(tlab-server\). Through the tLab web server use https://&lt;tlab-host&gt;/api; for a direct connection use http://&lt;tlab-host&gt;:8080. | True |
| Auth server URL (tlab-auth) | Used by the tLab account mode. Where the integration logs in to tlab-auth. Leave empty to use https://&lt;Server URL host&gt;:8002/api, the omni-center portal, which forwards /api to tlab-auth over TLS; if its certificate is self-signed, enable Trust any certificate. Not https://&lt;host&gt;/api, which is the sandbox API itself. | False |
| Authentication mode | tLab account \(tlab-auth\) is recommended: the integration logs in to tlab-auth like the omni-center portal and sends the token as Bearer. Source key needs the source-key gateway \(balancer\) and covers submissions only. Username and password is the legacy tlab-server sign-in. Internal token works only when Cortex XSOAR runs on the tlab-server host itself. | True |
| Credentials | Login and password of a tLab account \(tLab account mode\). This integration only reads, so a restricted account is sufficient. Turn off password expiry for this account: tlab-auth rejects an expired password and every command starts failing. | True |
| Password / source key / internal token | The password of the tLab account, or the source key or internal token, depending on the authentication mode. | True |
| Use system proxy settings | Whether to use the Cortex XSOAR server's system proxy settings. | False |
| Trust any certificate (not secure) | Whether to skip TLS certificate verification. Needed when the tLab certificate is self-signed. | False |
| Fetch indicators | Whether to fetch indicators from tLab Anti-APT on the feed fetch interval. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Indicator Expiration Method | How fetched indicators expire. Indicator type uses the expiration set for each indicator type in Cortex XSOAR. | False |
| Indicator Expiration Interval (minutes) | Minutes until an indicator expires when the expiration method is Interval. | False |
| Feed Fetch Interval | How often, in minutes, the feed fetches new indicators. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Client name | Sent as the X-Client header. | False |
| Minimum threat indicator level | Observables are only harvested from threat indicators at or above this level. INFO produces a large amount of benign noise and is rarely what you want. | False |
| Reports per fetch | Upper bound on sample reports processed per run. Each report costs one or two extra API calls, so raising this raises load on tlab-server proportionally. | False |
| First sample report id | Lowest sample report id to fetch. Takes effect on the next fetch, also when fetching has already started - raise it to skip a backfill. Leave empty to start from the beginning of history, which on a long-running installation can be a very large backfill. | False |
| Late completion lookback (hours) | The sandbox finishes analyses out of id order, so a report can complete after a higher-numbered one already did. Each run also re-scans reports updated within this window to catch them. Set to 0 to disable. | False |
| Include partially complete reports | Off by default. A partial report's observables are a snapshot that will still change, so the indicators it yields can contradict the finished report minutes later. | False |
| Fetch MITRE ATT&amp;CK techniques | Creates Attack Pattern indicators from the attack matrix. Costs one extra API call per report. | False |
| Create relationships | Links each sample to the indicators observed with it. Requires Cortex XSOAR 6.2.0 or later; on older servers this is silently skipped. | False |
| Record observed file names | File names are not emitted as indicators, because nothing can match on them. When enabled they are attached to the sample indicator's Associated File Names field instead. | False |
| Include private and reserved addresses | Off by default. A sandbox VM's traffic is mostly RFC1918, link-local and multicast noise, and publishing that as threat intel is actively harmful. | False |
| Excluded networks | CIDR blocks never emitted as indicators. Add the sandbox's own simulated network ranges here. Leave empty to use the built-in private and reserved list. | False |
| Suspicious score threshold | Scores from this value up to the malicious threshold are Suspicious. Fractional values are allowed. Default is 50, the product default. | False |
| Malicious score threshold | Scores at or above this value are Malicious. Fractional values are allowed. Default is 85, the product default. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tlab-get-indicators

***
Preview indicators without creating them in Threat Intel Management and without moving the fetch cursor. Use it to check filtering before enabling the feed.

#### Base Command

`tlab-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of indicators to return. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Indicator.value | String | The indicator value. | 
| TLabAntiAPT.Indicator.type | String | The Cortex XSOAR indicator type. | 
| TLabAntiAPT.Indicator.score | Number | The DBot score assigned to the indicator. | 

#### Command example
```!tlab-get-indicators limit=10```
#### Context Example
```json
{
    "TLabAntiAPT.Indicator(val.Value && val.Value == obj.Value)": [
        {
            "value": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "type": "File",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "sample_report_id": 412839,
                "verdict": "MALWARE"
            },
            "score": 3,
            "fields": {
                "md5": "aaaabbbbccccddddeeeeffff00001111",
                "sha1": "aaaabbbbccccddddeeeeffff0000111122223333",
                "sha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
                "size": 2048,
                "filetype": "PE",
                "firstseenbysource": "2026-03-26T08:00:00Z",
                "lastseenbysource": "2026-03-26T08:10:00Z",
                "tlabsamplereportid": 412839,
                "tlabverdict": "MALWARE",
                "tlabreporturl": "https://tlab.example.com/reports/412839",
                "tlabscore": 91.5,
                "malwarefamily": "Emotet",
                "associatedfilenames": [
                    "invoice.exe"
                ],
                "tlabsignatures": [
                    "Trojan.Win32.Emotet.abc"
                ]
            }
        },
        {
            "value": "evil.example.com",
            "type": "Domain",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "source": "BEHAVIOR",
                "level": "MALICIOUS",
                "title": "Connects to a known bad host",
                "analysis_type": "DYN_ANALYSIS"
            },
            "score": 3,
            "fields": {
                "tlabverdict": "MALWARE",
                "description": "Connects to a known bad host"
            }
        },
        {
            "value": "203.0.113.5",
            "type": "IP",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "source": "BEHAVIOR",
                "level": "MALICIOUS",
                "title": "Connects to a known bad host",
                "analysis_type": "DYN_ANALYSIS"
            },
            "score": 3,
            "fields": {
                "tlabverdict": "MALWARE",
                "description": "Connects to a known bad host"
            }
        },
        {
            "value": "https://evil.example.com/gate.php",
            "type": "URL",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "source": "BEHAVIOR",
                "level": "MALICIOUS",
                "title": "Connects to a known bad host",
                "analysis_type": "DYN_ANALYSIS"
            },
            "score": 3,
            "fields": {
                "tlabverdict": "MALWARE",
                "description": "Connects to a known bad host"
            }
        },
        {
            "value": "T1071",
            "type": "Attack Pattern",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "technique": "T1071"
            },
            "fields": {}
        },
        {
            "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "type": "Registry Key",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "source": "STATIC",
                "level": "SUSPICIOUS",
                "title": "Packed executable",
                "analysis_type": "STAT_ANALYSIS"
            },
            "score": 2,
            "fields": {
                "tlabverdict": "SUSPICIOUS",
                "description": "Packed executable"
            }
        },
        {
            "value": "1111111111111111111111111111111111111111111111111111111111111111",
            "type": "File",
            "rawJSON": {
                "service": "tLab Anti-APT",
                "sample_report_id": 412840,
                "verdict": "OK"
            },
            "score": 1,
            "fields": {
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "size": 64,
                "filetype": "TEXT",
                "firstseenbysource": "2026-03-26T08:16:40Z",
                "lastseenbysource": "2026-03-26T08:18:20Z",
                "tlabsamplereportid": 412840,
                "tlabverdict": "OK",
                "tlabreporturl": "https://tlab.example.com/reports/412840",
                "tlabscore": 12.0,
                "associatedfilenames": [
                    "readme.txt"
                ]
            }
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT indicators (7)
>|Value|Type|Verdict|Source|Description|
>|---|---|---|---|---|
>| aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | File | MALWARE |  |  |
>| evil.example.com | Domain | MALWARE | BEHAVIOR | Connects to a known bad host |
>| 203.0.113.5 | IP | MALWARE | BEHAVIOR | Connects to a known bad host |
>| https://evil.example.com/gate.php | URL | MALWARE | BEHAVIOR | Connects to a known bad host |
>| T1071 | Attack Pattern |  |  |  |
>| HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Registry Key | SUSPICIOUS | STATIC | Packed executable |
>| 1111111111111111111111111111111111111111111111111111111111111111 | File | OK |  |  |

### tlab-feed-reset-cursor

***
Reset the fetch cursor so the next fetch starts over from the configured first sample report id. Indicators already in Threat Intel Management are not removed.

#### Base Command

`tlab-feed-reset-cursor`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example
```!tlab-feed-reset-cursor```
#### Human Readable Output

>Fetch cursor reset. The next fetch starts from the configured first report id.
