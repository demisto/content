### Setup Instructions

1. **Imperva Credentials**:
   - Log in to your **Imperva Cloud Application Security Console**.
   - Navigate to **Account** > **API Keys** and generate an **API ID** and **API Key**.
2. **Log Server URL**:
   - Provide the URL of your Imperva Log Server endpoint (e.g. `https://logs.incapsula.com/`).
3. **Event Collection**:
   - Enable the **Fetch events** toggle to activate automated collection.
   - Adjust **Events Fetch Interval** (default: `1` minute) and **Max Logs Per Fetch** (recommended: `10`) according to your traffic volume.
   - Specify a **Starting File ID** if you want to skip historical archives and only process newer logs.

---

### Important Best Practice: Starting File ID

> [!TIP]
> When configuring a new instance:
> * **Do NOT leave `Starting File ID` at `0`** if your Imperva Log Server has months of old logs, or it will attempt to download thousands of historical files.
> * Run `!imperva-v2-get-logs-index limit=5` in the War Room, grab the newest `File ID` (e.g. `304500`), and set `Starting File ID` to that number (or ~100 files earlier if you want the last 1–2 hours of history).

---

4. **Dataset Ingestion**:
   - Ingested CEF events are stored under the dataset: `imperva_siemintegration_raw`.
