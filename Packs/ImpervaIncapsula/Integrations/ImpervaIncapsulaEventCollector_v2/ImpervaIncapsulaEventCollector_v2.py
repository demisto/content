"""Imperva Incapsula Event Collector v2 Integration for Cortex XSIAM

This integration continuously pulls CEF (Common Event Format) web security and traffic
logs from the Imperva Incapsula Log Server into Cortex XSIAM.
"""

from base64 import b64encode
import concurrent.futures
import json
import re
import time
import traceback
from typing import List, Optional, Tuple
import zlib

import requests
import requests.adapters
import urllib3

# Suppress insecure HTTPS request warnings if verify is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" CONSTANTS """
INTEGRATION_NAME = "Imperva Incapsula Event Collector v2"
LOG_PREFIX = "[Imperva Incapsula Collector v2]"
DEFAULT_MAX_LOGS = 500
DEFAULT_MAX_WORKERS = 8
VENDOR = "Imperva"
PRODUCT = "SIEMIntegration"

# Safety timeout budget in seconds for background polling (Docker containers typically timeout at 120-180s)
FETCH_TIMEOUT_SAFETY_SECONDS = 110

# Set of CEF keys that contain structured JSON arrays or objects
JSON_KEYS = {"cs10", "cs11", "cs12", "cs13", "cs14", "cs15"}

# Set of standard metadata, network, and numeric keys that never contain unclosed user quotes or complex payloads
SAFE_KEYS = {
    "src", "dst", "spt", "dpt", "sip", "dip",
    "siteid", "suid", "fileId", "start", "end", "cpt", "deviceExternalId",
    "act", "app", "deviceFacility", "ccode", "proto", "in", "out",
    "logfilename", "eventhash", "customer", "ver", "cefVersion", "severity"
}

# Regex to match CEF extension key boundaries across all standard and custom fields
EXT_PATTERN = re.compile(r"(?:^|\s+)([a-zA-Z0-9_]+)=")


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Imperva Incapsula Log Server API."""

    def __init__(self, base_url="", api_id="", api_key="", verify=False, proxy=False, max_workers=DEFAULT_MAX_WORKERS):
        if base_url and not base_url.endswith("/"):
            base_url += "/"

        credentials = "{}:{}".format(api_id, api_key)
        encoded_credentials = b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": "Basic {}".format(encoded_credentials),
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate, identity"
        }

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

        # Configure session connection pooling for high-throughput concurrent downloads
        try:
            pool_size = max(32, max_workers * 2)
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=pool_size,
                pool_maxsize=pool_size,
                max_retries=3
            )
            if hasattr(self, "_session") and self._session:
                self._session.mount("https://", adapter)
                self._session.mount("http://", adapter)
        except Exception as e:
            demisto.debug("{} Non-critical error configuring session adapter pool: {}".format(LOG_PREFIX, e))

    def get_logs_index(self):
        """Fetch the list of log files available on the server (logs.index) with retry backoff."""
        demisto.debug("{} Fetching logs.index from {}".format(LOG_PREFIX, self._base_url))
        response = self._http_request(
            method="GET",
            url_suffix="logs.index",
            resp_type="text",
            timeout=(10, 45),
            retries=3,
            backoff_factor=2,
            status_list_to_retry=[429, 500, 502, 503, 504]
        )
        lines = [line.strip() for line in response.splitlines() if line.strip()]
        demisto.debug("{} Successfully retrieved {} files from index.".format(LOG_PREFIX, len(lines)))
        return lines

    def get_log_file(self, file_name):
        """Download a raw compressed log file with retry backoff."""
        demisto.debug("{} Downloading log file: {}".format(LOG_PREFIX, file_name))
        response = self._http_request(
            method="GET",
            url_suffix=file_name,
            resp_type="content",
            timeout=(10, 30),
            retries=3,
            backoff_factor=2,
            status_list_to_retry=[429, 500, 502, 503, 504]
        )
        return response


""" HELPER FUNCTIONS """


def extract_file_id(file_name):
    """Safely extract numeric file ID from log filename (e.g. 798724459616_304511.log -> 304511)."""
    try:
        parts = file_name.strip().split("_")
        if len(parts) >= 2:
            return int(parts[1].replace(".log", ""))
    except (ValueError, IndexError) as e:
        demisto.debug("{} Skipping non-standard index line '{}': {}".format(LOG_PREFIX, file_name, e))
    return None


# C-level character translation table to instantly strip single quotes, control characters, and normalize whitespace
CLEAN_TRANS = {i: " " for i in range(32)}
CLEAN_TRANS[127] = None
CLEAN_TRANS[ord("'")] = None  # Instantly strip single quotes / apostrophes across all fields
CLEAN_TRANS[ord("\r")] = " "
CLEAN_TRANS[ord("\n")] = " "
CLEAN_TRANS[ord("\t")] = " "
CLEAN_TRANS_TABLE = str.maketrans(CLEAN_TRANS)


def sanitize_cef_value(key: str, val: str) -> str:
    """Fast-path targeted sanitization of an individual CEF extension field value.

    - 100% safe fields (IDs, IPs, ports, labels) bypass complex parsing after fast C-level translation.
    - High-risk fields (request, user-agent, payloads, JSON) undergo deep quote & JSON normalization.
    """
    if not val:
        return ""

    # 1. Fast C-level translation for control chars, CR/LF/tab, and single quotes (sub-microsecond)
    val = val.translate(CLEAN_TRANS_TABLE)

    # 2. Fast-path bypass for safe metadata, network, numeric, and label fields
    if key in SAFE_KEYS or key.endswith("Label"):
        return val.strip()

    # 3. Handle double quotes and JSON structures on complex payload fields
    stripped = val.strip()
    if key in JSON_KEYS and (stripped.startswith(("[", "{")) and stripped.endswith(("]", "}"))):
        normalized_json = stripped.replace('""', '"')
        try:
            json.loads(normalized_json)
            val = normalized_json
        except Exception:
            val = val.replace('"', "")
    else:
        # Strip all double quotes from non-JSON fields
        val = val.replace('"', "")

    # 4. Strip trailing unescaped backslashes
    val = val.rstrip("\\")

    # 5. Normalize multiple consecutive spaces
    if key not in JSON_KEYS and "  " in val:
        val = re.sub(r" +", " ", val)

    return val.strip()


def sanitize_cef_event(raw_event: str, file_name: str = "") -> Optional[str]:
    """Parses, cleans, and standardizes a single CEF event across all columns and header fields.

    Uses high-speed vectorized string routines and avoids dictionary recreation overhead.
    """
    if not raw_event or not raw_event.strip():
        return None

    raw_event = raw_event.strip()
    if not raw_event.startswith("CEF:"):
        if raw_event.startswith("0|"):
            raw_event = "CEF:" + raw_event
        else:
            raw_event = "CEF:0|" + raw_event

    parts = re.split(r"(?<!\\)\|", raw_event, maxsplit=7)
    if len(parts) < 8:
        return raw_event

    # Sanitize header fields (indexes 0 to 6) in C-speed
    header_parts = [h.translate(CLEAN_TRANS_TABLE).strip() for h in parts[:7]]
    extension_str = parts[7]

    # Fast tokenization of extension key=value pairs
    matches = list(EXT_PATTERN.finditer(extension_str))
    ext_pairs = []
    has_logfilename = False
    has_eventhash = False

    for i in range(len(matches)):
        k = matches[i].group(1)
        v_start = matches[i].end()
        v_end = matches[i + 1].start() if i + 1 < len(matches) else len(extension_str)
        raw_val = extension_str[v_start:v_end]
        sanitized_val = sanitize_cef_value(k, raw_val)
        if sanitized_val:
            ext_pairs.append("{}={}".format(k, sanitized_val))
            if k == "logfilename":
                has_logfilename = True
            elif k == "eventhash":
                has_eventhash = True

    if file_name and not has_logfilename:
        ext_pairs.append("logfilename={}".format(file_name))
    if not has_eventhash:
        event_hash = str(hash(raw_event))
        ext_pairs.append("eventhash={}".format(event_hash))

    return "{}|{}".format("|".join(header_parts), " ".join(ext_pairs))


def decompress_and_parse_cef(raw_data, file_name):
    """Decompress Imperva log payload (supporting GZIP/ZLIB/Deflate) and format sanitized CEF events."""
    marker = b"|==|"
    if marker in raw_data:
        payload = raw_data.split(marker, 1)[1].lstrip(b"\r\n")
    else:
        payload = raw_data

    decompressed_bytes = None
    decompression_strategies = [
        (32 + zlib.MAX_WBITS, "GZIP/ZLIB Auto-Detect"),
        (16 + zlib.MAX_WBITS, "GZIP Header (wbits=31)"),
        (-zlib.MAX_WBITS, "Raw DEFLATE (wbits=-15)"),
        (zlib.MAX_WBITS, "Standard ZLIB (wbits=15)")
    ]

    for wbits, method_name in decompression_strategies:
        try:
            decompressed_bytes = zlib.decompress(payload, wbits)
            demisto.debug("{} Successfully decompressed {} using {}".format(LOG_PREFIX, file_name, method_name))
            break
        except Exception:
            continue

    if decompressed_bytes is None:
        try:
            payload.decode("utf-8")
            decompressed_bytes = payload
            demisto.debug("{} {} is uncompressed plain text.".format(LOG_PREFIX, file_name))
        except Exception:
            pass

    if decompressed_bytes is None:
        error_msg = "Failed to decompress log payload for file {}. First 100 bytes: {}".format(file_name, repr(payload[:100]))
        demisto.error("{} {}".format(LOG_PREFIX, error_msg))
        raise ValueError(error_msg)

    text_data = decompressed_bytes.decode("utf-8", errors="ignore")
    fixed_events = []

    for event in text_data.split("CEF:0|"):
        if event.strip():
            sanitized = sanitize_cef_event(event, file_name)
            if sanitized:
                fixed_events.append(sanitized)

    demisto.debug("{} Extracted and sanitized {} CEF events from {}".format(LOG_PREFIX, len(fixed_events), file_name))
    return fixed_events


def process_single_log_file(client: Client, file_info: Tuple[int, str]) -> Tuple[int, str, List[str], Optional[str]]:
    """Worker task: downloads, decompresses, and sanitizes CEF events for a single log file."""
    file_id, file_name = file_info
    try:
        raw_content = client.get_log_file(file_name)
        log_events = decompress_and_parse_cef(raw_content, file_name)
        return file_id, file_name, log_events, None
    except Exception as e:
        err_msg = "{} ({})".format(file_name, str(e))
        demisto.error("{} Error processing file {}: {}\n{}".format(LOG_PREFIX, file_name, e, traceback.format_exc()))
        return file_id, file_name, [], err_msg


""" COMMAND FUNCTIONS """


def test_module(client):
    """Tests API connectivity, URL, and authentication credentials. Must return exactly 'ok'."""
    demisto.debug("{} Running test-module...".format(LOG_PREFIX))
    try:
        index_lines = client.get_logs_index()
        demisto.debug("{} test-module verified: logs.index has {} files.".format(LOG_PREFIX, len(index_lines)))
        return "ok"
    except DemistoException as e:
        err_str = str(e)
        if "Unauthorized" in err_str or "401" in err_str or "403" in err_str:
            return "Authentication Error: Please check your API ID and API Key."
        elif "404" in err_str:
            return "Resource Not Found: Could not find logs.index. Verify Log Server URL."
        elif "Certificate" in err_str or "SSL" in err_str:
            return "SSL Error: Certificate validation failed. Enable 'Trust any certificate (insecure)'."
        raise e
    except Exception as e:
        return "Connection Failed: {}".format(str(e))


def safe_send_events_to_xsiam(events: List[str], vendor: str, product: str) -> None:
    """Sends events to XSIAM with retry backoff for rate limits and server hiccups."""
    if not events:
        try:
            send_events_to_xsiam(events=[], vendor=vendor, product=product)
        except Exception as e:
            demisto.debug("{} Non-critical error updating health module for empty batch: {}".format(LOG_PREFIX, e))
        return

    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            demisto.debug("{} Sending {} events to XSIAM (attempt {}/{})".format(LOG_PREFIX, len(events), attempt, max_retries))
            send_events_to_xsiam(
                events=events,
                vendor=vendor,
                product=product,
                data_format="cef"
            )
            demisto.debug("{} Successfully sent {} events to XSIAM.".format(LOG_PREFIX, len(events)))
            return
        except Exception as e:
            demisto.error("{} Error sending events to XSIAM (attempt {}/{}): {}".format(LOG_PREFIX, attempt, max_retries, e))
            if attempt == max_retries:
                raise e
            time.sleep(2 * attempt)


def fetch_events(client, last_run, max_logs=DEFAULT_MAX_LOGS, starting_file_id=0, max_workers=DEFAULT_MAX_WORKERS):
    """Fetches new log files concurrently using ThreadPoolExecutor and extracts CEF events for XSIAM."""
    start_time = time.time()
    last_file_id = int(last_run.get("last_file_id", 0))
    last_file_id = max(last_file_id, starting_file_id)
    demisto.info(
        "{} Starting fetch cycle: last_file_id={}, max_logs={}, max_workers={}".format(
            LOG_PREFIX, last_file_id, max_logs, max_workers
        )
    )

    try:
        idx = client.get_logs_index()
    except Exception as e:
        demisto.error("{} Transient error retrieving logs.index: {}. Will retry automatically on next interval.".format(LOG_PREFIX, e))
        return last_run, []

    # Filter and sort files chronologically
    candidate_files = []
    for file in idx:
        file_id = extract_file_id(file)
        if file_id is not None and file_id > last_file_id:
            candidate_files.append((file_id, file))

    candidate_files.sort(key=lambda x: x[0])
    total_eligible = len(candidate_files)

    if total_eligible > max_logs:
        candidate_files = candidate_files[:max_logs]
        demisto.info("{} Backlog detected: processing capped batch of {} / {} eligible files.".format(LOG_PREFIX, max_logs, total_eligible))
    else:
        demisto.info("{} Processing all {} eligible files.".format(LOG_PREFIX, total_eligible))

    if not candidate_files:
        demisto.debug("{} No new files to process. Up to date at file ID {}.".format(LOG_PREFIX, last_file_id))
        return {"last_file_id": last_file_id, "event_count": 0}, []

    max_file_id = last_file_id
    all_events = []
    failed_files = []

    # Process files in parallel batches using ThreadPoolExecutor (inspired by Imperva LogsDownloader.py)
    chunk_size = max(4, max_workers * 2)

    for i in range(0, len(candidate_files), chunk_size):
        elapsed = time.time() - start_time
        if elapsed > FETCH_TIMEOUT_SAFETY_SECONDS:
            demisto.info(
                "{} Approaching execution timeout limit ({}s elapsed). "
                "Yielding current batch with {} parsed events up to file ID {}. "
                "Remaining {} files will be processed in the next polling cycle.".format(
                    LOG_PREFIX, round(elapsed, 1), len(all_events), max_file_id, len(candidate_files) - i
                )
            )
            break

        chunk = candidate_files[i:i + chunk_size]
        demisto.debug("{} Spawning {} parallel download workers for chunk [{}..{}]".format(
            LOG_PREFIX, min(len(chunk), max_workers), chunk[0][0], chunk[-1][0]
        ))

        chunk_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(process_single_log_file, client, item): item for item in chunk}
            for future in concurrent.futures.as_completed(future_to_file):
                try:
                    res = future.result()
                    chunk_results.append(res)
                except Exception as e:
                    item = future_to_file[future]
                    failed_files.append("{} ({})".format(item[1], str(e)))

        # Sort chunk results chronologically by file_id to preserve stream order
        chunk_results.sort(key=lambda x: x[0])

        for f_id, f_name, f_events, f_err in chunk_results:
            if f_err:
                failed_files.append(f_err)
            else:
                all_events.extend(f_events)
                max_file_id = max(max_file_id, f_id)

    if failed_files:
        demisto.error("{} Errors encountered on {} file(s): {}".format(LOG_PREFIX, len(failed_files), ", ".join(failed_files)))

    next_run = {
        "last_file_id": max_file_id,
        "event_count": len(all_events)
    }
    demisto.info(
        "{} Fetch complete in {:.2f}s. Extracted {} events from {} files. Advanced checkpoint to {}.".format(
            LOG_PREFIX, time.time() - start_time, len(all_events), len(candidate_files), max_file_id
        )
    )
    return next_run, all_events


def get_logs_index_command(client, args):
    """Manual command to list files in logs.index from the CLI."""
    limit = arg_to_number(args.get("limit")) or 50
    idx = client.get_logs_index()
    total_files = len(idx)
    preview = idx[-limit:] if total_files > limit else idx

    table_data = [{"File Name": f, "File ID": extract_file_id(f)} for f in preview]
    readable_output = tableToMarkdown(
        "Imperva Logs Index (Showing latest {} of {} files)".format(len(table_data), total_files),
        table_data,
        headers=["File Name", "File ID"]
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Imperva.LogIndex",
        outputs_key_field="FileName",
        outputs={"total_files": total_files, "files": idx}
    )


def get_events_command(client, args):
    """Manual command to fetch, preview, and optionally push CEF events from the CLI."""
    limit = arg_to_number(args.get("limit")) or 1
    should_push = argToBoolean(args.get("should_push_events", "false"))
    specified_file = args.get("file_id")

    files_to_download = []
    if specified_file:
        if not specified_file.endswith(".log"):
            idx = client.get_logs_index()
            matched = [f for f in idx if str(specified_file) in f]
            files_to_download = matched[:1] if matched else [specified_file]
        else:
            files_to_download = [specified_file]
    else:
        idx = client.get_logs_index()
        files_to_download = idx[-limit:] if len(idx) > limit else idx

    all_events = []
    processed_files = []
    for f in files_to_download:
        try:
            raw_content = client.get_log_file(f)
            events = decompress_and_parse_cef(raw_content, f)
            all_events.extend(events)
            processed_files.append(f)
        except Exception as e:
            demisto.error("{} Failed to process file {}: {}".format(LOG_PREFIX, f, e))

    if should_push and all_events:
        safe_send_events_to_xsiam(events=all_events, vendor=VENDOR, product=PRODUCT)
        push_msg = " (pushed to dataset imperva_siemintegration_raw)"
    else:
        push_msg = " (preview only, not pushed)"

    preview_events = all_events[:5]
    table_data = [{"Index": i + 1, "CEF Event": ev[:150] + "..." if len(ev) > 150 else ev} for i, ev in enumerate(preview_events)]
    readable_output = tableToMarkdown(
        "Imperva Incapsula Events - {} events parsed from {} file(s){}".format(len(all_events), len(processed_files), push_msg),
        table_data,
        headers=["Index", "CEF Event"]
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Imperva.Events",
        outputs_key_field="total_events",
        outputs={
            "total_events": len(all_events),
            "files_processed": processed_files,
            "sample_events": preview_events
        }
    )


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_id = params.get("api_id", "")
    api_key = params.get("api_key", "")
    base_url = params.get("url", "")
    verify_certificate = not params.get("insecure", True)
    proxy = params.get("proxy", False)

    max_logs = arg_to_number(params.get("max_logs")) or DEFAULT_MAX_LOGS
    max_workers = arg_to_number(params.get("max_workers")) or DEFAULT_MAX_WORKERS
    starting_file_id = arg_to_number(params.get("starting_file_id")) or 0

    demisto.debug("{} Executing command: {}".format(LOG_PREFIX, command))

    try:
        client = Client(
            base_url=base_url,
            api_id=api_id,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
            max_workers=max_workers
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-events":
            try:
                next_run, events = fetch_events(
                    client=client,
                    last_run=demisto.getLastRun(),
                    max_logs=max_logs,
                    starting_file_id=starting_file_id,
                    max_workers=max_workers
                )
                safe_send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(next_run)
            except Exception as e:
                demisto.error(
                    "{} Transient error in fetch-events cycle: {}\n{}".format(
                        LOG_PREFIX, str(e), traceback.format_exc()
                    )
                )
                # Keep Health Module updated even during transient connection hiccups
                try:
                    send_events_to_xsiam(events=[], vendor=VENDOR, product=PRODUCT)
                except Exception:
                    pass

        elif command in ("imperva-get-logs-index", "imperva-v2-get-logs-index"):
            return_results(get_logs_index_command(client, args))

        elif command in ("imperva-get-events", "imperva-incapsula-get-events"):
            return_results(get_events_command(client, args))

        else:
            raise NotImplementedError("Command {} is not implemented".format(command))

    except Exception as e:
        demisto.error("{} Execution failed: {}\n{}".format(LOG_PREFIX, e, traceback.format_exc()))
        return_error("Failed to execute '{}' command in {}.\n\nError: {}".format(command, INTEGRATION_NAME, str(e)))


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
