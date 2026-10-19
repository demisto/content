# Imperva Incapsula Event Collector v2 Pack

## Overview

The **Imperva Incapsula Event Collector v2** pack enables continuous collection of web security, access, and DDoS events from the **Imperva Incapsula Cloud WAF / SIEM Integration** into Cortex XSIAM.

Logs are retrieved incrementally via the Imperva Log Server API, decompressed, parsed into CEF (Common Event Format) records, and routed into the XSIAM data lake dataset: `imperva_siemintegration_raw`.

---

## Pack Content & Capabilities

- **Imperva Incapsula Event Collector v2 Integration**:
  - **Automated Event Ingestion (`fetch-events`)**: Continuous background polling and real-time push into the XSIAM data lake.
  - **CLI Log Inspection (`imperva-v2-get-logs-index`)**: On-demand inspection of remote log server file index directly in the War Room.
  - **On-Demand Event Preview (`imperva-incapsula-get-events`)**: Inspect and sample parsed CEF records or trigger manual ingestion.
  - **Connection Verification (`test-module`)**: Automated credential and connectivity validation.
- **Robust Multi-Strategy Decompression**: Automatic support for GZIP (`wbits=31`), standard ZLIB (`wbits=15`), raw DEFLATE (`wbits=-15`), and uncompressed plain text fallback.
- **Stateful Resume**: Automatically tracks `last_file_id` across runs to prevent log duplicate ingestion.
- **XSIAM Health Module Integration**: Full operational status and event volume reporting in the **Fetch History** tab.

---

## Dependencies

This content pack depends on the following Cortex XSOAR / XSIAM content packs:

| Pack Name | Type | Description |
| :--- | :---: | :--- |
| **Base** | Mandatory | Cortex Core base content pack providing standard scripts, commands, and schemas. |

---

## Commands

This integration provides the following commands for automated event collection, troubleshooting, and manual investigation:

### 1. `imperva-v2-get-logs-index`

Manually retrieves and inspects available log files from `logs.index` on the Imperva Log Server directly from the Cortex XSIAM CLI or playbooks.

#### Input Arguments

| Argument | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `limit` | The maximum number of recent log file entries to display from the index. | False | `50` |

#### Context Outputs

| Context Path | Type | Description |
| :--- | :--- | :--- |
| `Imperva.LogIndex.total_files` | Number | Total count of files currently hosted on the log server. |
| `Imperva.LogIndex.files` | List | Full list of log file names retrieved from the index. |

#### Command Example

```text
!imperva-v2-get-logs-index limit=10
```

#### Human Readable Output

> ### Imperva Logs Index (Showing latest 10 of 1,240 files)
> | File Name | File ID |
> | :--- | :--- |
> | 798724459616_304510.log | 304510 |
> | 798724459616_304511.log | 304511 |
> | 798724459616_304512.log | 304512 |

---

### 2. `imperva-incapsula-get-events`

Fetches and previews CEF events on-demand directly into the War Room for verification, troubleshooting, or manual ingestion.

#### Input Arguments

| Argument | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `limit` | The maximum number of log files to process. | False | `1` |
| `should_push_events` | If `true`, pushes the extracted events into dataset `imperva_siemintegration_raw`. If `false`, only displays them. | False | `false` |
| `file_id` | Specific log file ID (e.g. `304512`) or filename to download and inspect. | False | |

#### Context Outputs

| Context Path | Type | Description |
| :--- | :--- | :--- |
| `Imperva.Events.total_events` | Number | Total count of CEF events parsed from the downloaded logs. |
| `Imperva.Events.files_processed` | List | Full list of log file names downloaded and processed. |
| `Imperva.Events.sample_events` | List | Sample list of CEF event strings. |

#### Command Example

```text
!imperva-incapsula-get-events limit=1 should_push_events=false
```

---

### 3. `test-module`

Tests API connectivity, validates the Log Server URL, and verifies your Basic Authentication credentials.

#### Input Arguments

*No arguments required.*

#### Returns

- Returns `ok` upon successful connection and index retrieval.
- Returns clear diagnostic error messages for HTTP 401/403 (Authentication), 404 (Invalid URL), or SSL certificate issues.

---

### 4. `fetch-events` (Automated Background Engine)

The built-in event collection mechanism scheduled by Cortex XSIAM:
1. Downloads `logs.index` from the Imperva Log Server.
2. Identifies new log files where `file_id > last_file_id`.
3. Processes up to `max_logs` files per batch.
4. Decompresses and extracts individual CEF records.
5. Ingests all events via `send_events_to_xsiam()` into dataset `imperva_siemintegration_raw`.
6. Updates the integration state with the highest processed `last_file_id`.

---

## Dataset & Schema Mapping

| Property | Value |
| :--- | :--- |
| **Target Dataset** | `imperva_siemintegration_raw` |
| **Vendor** | `Imperva` |
| **Product** | `SIEMIntegration` |
| **Payload Format** | `CEF` (Common Event Format) |

Each ingested record includes enriched metadata tags:
- `logfilename`: The source log archive name (e.g. `798724459616_304512.log`).
- `eventhash`: Unique SHA-based hash of the raw CEF message for deduplication.

---

## Configuration Parameters

| Parameter | Required | Type | Default | Description |
| :--- | :---: | :---: | :--- | :--- |
| **Log Server Base URL** (`url`) | True | String | `https://logs.incapsula.com/` | The base URL of the Imperva Log Server endpoint. |
| **API ID** (`api_id`) | True | String | | The API ID used to authenticate with the Imperva Log Server. |
| **API Key** (`api_key`) | True | Password | | The API Key used to authenticate with the Imperva Log Server. |
| **Fetch events** (`isFetchEvents`) | False | Boolean | `true` | Enable automatic background collection of Imperva CEF logs into XSIAM. |
| **Events Fetch Interval** (`eventFetchInterval`) | False | Interval | `1` | Polling interval (in minutes) between consecutive fetch cycles. |
| **Max Logs Per Fetch** (`max_logs`) | False | Number | `10` | Maximum number of log files to process per fetch execution cycle. |
| **Starting File ID** (`starting_file_id`) | False | String | `0` | File ID from which to start ingesting logs (e.g. `0` or `304510`). |
| **Trust any certificate (insecure)** (`insecure`) | False | Boolean | `true` | When selected, HTTPS certificate validation is skipped. |
| **Use system proxy settings** (`proxy`) | False | Boolean | `false` | When selected, system HTTP(S) proxy settings are used. |

---

## Important Best Practice: Starting File ID

> [!TIP]
> When configuring a new instance:
> * **Do NOT leave `Starting File ID` at `0`** if your Imperva Log Server has months of old logs, or it will attempt to download thousands of historical files.
> * Run `!imperva-v2-get-logs-index limit=5` in the War Room, grab the newest `File ID` (e.g. `304500`), and set `Starting File ID` to that number (or ~100 files earlier if you want the last 1–2 hours of history).

---

## Support

* **Author**: [Prima Secondary Ramadhan](https://github.com/primasr)
* **GitHub**: [https://github.com/primasr](https://github.com/primasr)
* **Email**: [prima.s.r.2001@gmail.com](mailto:prima.s.r.2001@gmail.com)
* **Support**: Community Supported