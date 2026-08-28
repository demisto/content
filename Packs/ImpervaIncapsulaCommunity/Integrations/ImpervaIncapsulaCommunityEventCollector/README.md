Community-maintained, agentless event collector for Imperva Cloud WAF (Incapsula) accounts using the Imperva API log connection type. Not developed, reviewed, or supported by Imperva or Palo Alto Networks.

> **This is a community pack.** It is not developed, reviewed, tested, or supported by Imperva or Palo Alto Networks. Validate it thoroughly against your own tenant before relying on it in production.

This integration is for Imperva Cloud WAF (Incapsula) accounts whose **SIEM Logs → Log Configuration** connection type is **Imperva API** (the short-term log buffer served from `https://logs<N>.incapsula.com/<account>_<id>/`). If your account's connection type is **Amazon S3**, use the native ingestion path documented in the `Imperva Incapsula` pack instead.

This integration was integrated and tested with the Imperva Incapsula log integration API.

## Configure Imperva Incapsula Community Event Collector on Cortex XSIAM

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Logs URL | The Imperva Logs URL from SIEM Logs > Log Configuration, for example: `https://logs1.incapsula.com/123456_456789/`. Must end with a trailing slash. | True |
| API ID and API Key | The Imperva API ID (username) and API Key (password) from your account's API settings page. | True |
| Log encryption private key (PEM) | Only required if log encryption is enabled on the account. Paste the RSA private key in PEM format. | False |
| Log encryption public key ID | Only required if log encryption is enabled on the account. Must match the `publicKeyId` value found in encrypted log file headers. | False |
| Number of files to backfill on first run | On the first fetch cycle, how many of the most recent entries in `logs.index` to fetch. Has no effect on subsequent cycles. Default: 10. | False |
| Maximum files per fetch cycle | Upper bound on the number of log files downloaded in a single fetch cycle. Default: 50. | False |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |
| Fetch events | | False |
| Events Fetch Interval | | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### imperva-incapsula-community-get-events

***
Manual command to fetch and display Imperva Incapsula events. Use for development and debugging only, as it may produce duplicate events or disrupt the fetch mechanism.

#### Base Command

`imperva-incapsula-community-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to send the fetched events to XSIAM, otherwise the command only displays them in the War Room. Possible values are: True, False. Default is False. | Required |
| limit | The maximum number of log files to fetch and display. Defaults to the "Maximum files per fetch cycle" instance parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaIncapsulaCommunity.Event.file_name | String | The name of the log file the event was read from. |
| ImpervaIncapsulaCommunity.Event.raw | String | The raw, decrypted, decompressed log line. |

#### Command example

```!imperva-incapsula-community-get-events should_push_events=False limit=5```

#### Human Readable Output

>### Imperva Incapsula Events (5)
>
>|Raw|
>|---|
>| CEF:0\|Incapsula\|SIEMintegration\|1\|1\|Normal\|0\|fileId=123 sourceServiceName=site.example.com cn1=200 src=1.2.3.4 ... |

## Troubleshooting

- **`_raw_log` is populated in `imperva_incapsula_raw` but structured CEF fields (`cefName`, `cn1`, `src`, ...) are null.** The parsing rule's key-boundary regex did not recognize one of the extension keys present in your account's log format. Compare `_raw_log` against the key list in the pack's parsing rule and extend it.
- **`Authorization error` on Test.** Double-check the API ID and API Key against the account's API settings page - these are separate from the account's login credentials.
- **`File '<name>' is encrypted, but no log encryption private key is configured`.** Log encryption is enabled on this Imperva account; configure the private key and public key ID parameters.
- **Gaps in `fileId` continuity in the dataset.** Imperva's log buffer retains files for a short window. If fetching is paused for longer than that window, the aged-out files are unrecoverable - this shows up as a gap rather than an error.
