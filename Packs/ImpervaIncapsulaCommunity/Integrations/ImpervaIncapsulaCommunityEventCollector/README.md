Community-maintained, agentless event collector for Imperva Cloud WAF (Incapsula) accounts using Retrieve (Pull mode) / Imperva API log integration. Not developed, reviewed, or supported by Imperva or Palo Alto Networks.

> **This is a community pack.** It is not developed, reviewed, tested, or supported by Imperva or Palo Alto Networks. Validate it thoroughly against your own tenant before relying on it in production.

This integration is for Imperva Cloud WAF (Incapsula) accounts using [**Retrieve (Pull mode)**](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/settings/log-integration.htm) log integration — what the Log Configuration screen itself labels the **Imperva API** connection type. Imperva writes logs to a short-lived cloud repository (kept up to 48 hours or 500 MB) that this integration polls and downloads from. If your account uses one of Imperva's push modes instead (Amazon S3, SFTP, or Splunk HEC), use the native ingestion path documented in the `Imperva Incapsula` pack.

This integration was tested against Imperva's own [documented log format](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/more/log-file-structure.htm) and a live Cortex XSIAM tenant.

## Configure Imperva Incapsula Community Event Collector on Cortex XSIAM

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Logs URL | The Log Server URI from SIEM Logs > Log Configuration, for example: `https://logs1.incapsula.com/1234_12345/`. Must end with a trailing slash. | True |
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
>| CEF:0\|Incapsula\|SIEMintegration\|1\|1\|Illegal Resource Access\|3\| fileid=3412341160002518171 sourceServiceName=site123.abcd.info siteid=1509732 suid=50005477 requestClientApplication=Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0 deviceFacility=mia cs2=true cs2Label=Javascript Support cn1=200 in=54 start=1453290121336 request=site123.abcd.info/ requestmethod=GET app=HTTP act=REQ_CHALLENGE_CAPTCHA src=12.12.12.12 ver=TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 end=1566300670892 ... |

(Real event from Imperva's own [documented example](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/more/example-logs.htm) — note the lowercase `fileid`/`requestmethod`, which is how Imperva's own reference examples write them despite their field table using `fileId`/`requestMethod`; this pack's parsing rule matches key names case-insensitively for exactly this reason.)

## Troubleshooting

- **`_raw_log` is populated in `imperva_incapsula_raw` but structured CEF fields (`cefName`, `cn1`, `src`, ...) are null.** Check the CEF header's vendor/product segments in `_raw_log` first — this pack's parsing rule targets `Incapsula|SIEMintegration` specifically; a different `Device Product` (for example, an Attack Analytics export through the same connection) will not match this rule's field vocabulary at all. If the header does say `Incapsula|SIEMintegration` and fields are still null, the parsing rule's key-boundary matching did not recognize one of the extension keys present in your account's log format — compare `_raw_log` against the key list in the pack's parsing rule and extend it.
- **A `csN` field's value looks truncated, cut off right before what should be more text.** Check whether it bled into a companion field this rule doesn't recognize — every `cs1`–`cs11` field is followed on the wire by a `csNLabel` field this rule explicitly accounts for, but if Imperva adds a similarly-placed field in the future, the same class of truncation can recur for it until the rule's key list is updated.
- **`Authorization error` on Test.** Double-check the API ID and API Key against the account's API settings page - these are separate from the account's login credentials.
- **`File '<name>' is encrypted, but no log encryption private key is configured`.** Log encryption is enabled on this Imperva account; configure the private key and public key ID parameters.
- **Missing time ranges in the dataset.** Imperva's log buffer retains files for up to 48 hours or 500 MB, whichever comes first. If fetching is paused longer than that, the aged-out files are unrecoverable - this shows up as a gap in `_time` coverage rather than an error.
