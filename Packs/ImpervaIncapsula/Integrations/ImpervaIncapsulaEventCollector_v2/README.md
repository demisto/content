# Imperva Incapsula Event Collector v2

Collects CEF (Common Event Format) web security, DDoS mitigation, and traffic access logs from the Imperva Incapsula Log Server into Cortex XSIAM.

---

## Configuration Parameters

| Parameter | Required | Type | Default | Description |
| :--- | :---: | :---: | :--- | :--- |
| **Log Server Base URL** (`url`) | True | String | `https://logs.incapsula.com/` | The base URL of the Imperva Log Server endpoint. |
| **API ID** (`api_id`) | True | String | | The API ID used to authenticate with the Imperva Log Server. |
| **API Key** (`api_key`) | True | Password | | The API Key used to authenticate with the Imperva Log Server. |
| **Fetch events** (`isFetchEvents`) | False | Boolean | `true` | Enable automatic background collection of Imperva CEF logs. |
| **Events Fetch Interval** (`eventFetchInterval`) | False | Interval | `1` | Interval (in minutes) between consecutive fetch execution cycles. |
| **Max Logs Per Fetch** (`max_logs`) | False | Number | `10` | Maximum number of log files to process per fetch execution cycle. |
| **Starting File ID** (`starting_file_id`) | False | String | `0` | File ID from which to start ingesting logs (e.g., `0` or `304510`). Logs with IDs greater than this value will be processed. |
| **Trust any certificate (insecure)** (`insecure`) | False | Boolean | `true` | When selected, HTTPS certificate validation is skipped. |
| **Use system proxy settings** (`proxy`) | False | Boolean | `false` | When selected, system HTTP(S) proxy settings are used. |

---

### Important Best Practice: Starting File ID

> [!TIP]
> When configuring a new instance:
> * **Do NOT leave `Starting File ID` at `0`** if your Imperva Log Server has months of old logs, or it will attempt to download thousands of historical files.
> * Run `!imperva-v2-get-logs-index limit=5` in the War Room, grab the newest `File ID` (e.g. `304500`), and set `Starting File ID` to that number (or ~100 files earlier if you want the last 1–2 hours of history).

---

## Commands

You can execute these commands from the Cortex XSIAM CLI or playbooks.

### 1. `imperva-v2-get-logs-index`

Retrieves the list of available log files from `logs.index` on the Imperva Log Server.

#### Input Arguments

| Argument | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `limit` | Maximum number of recent log file entries to display. | False | `50` |

#### Context Outputs

| Context Path | Type | Description |
| :--- | :--- | :--- |
| `Imperva.LogIndex.total_files` | Number | Total number of log files currently hosted on the server. |
| `Imperva.LogIndex.files` | List | Full list of log file names retrieved from the index. |

#### Command Example

```text
!imperva-v2-get-logs-index limit=10
```

#### Human Readable Output

> ### Imperva Logs Index (Showing latest 10 of 1,240 files)
> | File Name | File ID |
> | :--- | :--- |
> | 798724459616_304511.log | 304511 |
> | 798724459616_304512.log | 304512 |
> | 798724459616_304513.log | 304513 |

---

### 2. `imperva-incapsula-get-events`

Fetches and displays CEF events directly into the War Room for inspection and manual testing.

#### Input Arguments

| Argument | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `limit` | Maximum number of log files to process. | False | `1` |
| `should_push_events` | If `true`, pushes the parsed events into the XSIAM dataset (`imperva_siemintegration_raw`). If `false`, only displays them. | False | `false` |
| `file_id` | Specific log file ID (e.g. `304512`) to download and inspect. | False | |

#### Context Outputs

| Context Path | Type | Description |
| :--- | :--- | :--- |
| `Imperva.Events.total_events` | Number | Total count of CEF events parsed from the downloaded logs. |
| `Imperva.Events.files_processed` | List | List of log file names downloaded and processed. |
| `Imperva.Events.sample_events` | List | Preview list of CEF event strings. |

#### Command Example

```text
!imperva-incapsula-get-events limit=1 should_push_events=false
```

---

### 3. `test-module`

Tests connectivity, base URL validity, and API authentication credentials. Returns `ok` if successful.

#### Input Arguments

*No arguments required.*

---

### 4. `fetch-events`

Scheduled background ingestion engine triggered periodically by Cortex XSIAM to ingest CEF events into `imperva_siemintegration_raw`.

---

## Troubleshooting

- **Authentication Error (401/403)**: Ensure your `API ID` and `API Key` match the credentials generated in the Imperva Management Console.
- **SSL Certificate Errors**: Enable the `Trust any certificate (insecure)` option in instance settings.
- **No events appearing in Dataset**: Check the **Fetch History** tab on the integration page to inspect the status of recent fetch cycles. Verify that the `Starting File ID` is lower than the newest file ID available on the server.
