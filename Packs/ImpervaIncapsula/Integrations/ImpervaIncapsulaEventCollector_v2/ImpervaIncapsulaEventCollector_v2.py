"""Imperva Incapsula Event Collector v2 Integration for Cortex XSIAM

This integration continuously pulls CEF (Common Event Format) web security and traffic
logs from the Imperva Incapsula Log Server into Cortex XSIAM.
"""

import re
import traceback
import urllib3
import zlib
from base64 import b64encode
from typing import Any, Dict, List, Optional, Tuple

# Suppress insecure HTTPS request warnings if verify is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" CONSTANTS """
INTEGRATION_NAME = "Imperva Incapsula Event Collector v2"
LOG_PREFIX = "[Imperva Incapsula Collector v2]"
DEFAULT_MAX_LOGS = 10
VENDOR = "Imperva"
PRODUCT = "SIEMIntegration"

# Regex to match CEF extension key boundaries across all standard and custom fields
EXT_PATTERN = re.compile(r"(?:^|\s+)([a-zA-Z0-9_]+)=")


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Imperva Incapsula Log Server API."""

    def __init__(self, base_url="", api_id="", api_key="", verify=False, proxy=False):
        if base_url and not base_url.endswith("/"):
            base_url += "/"

        credentials = "{}:{}".format(api_id, api_key)
        encoded_credentials = b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": "Basic {}".format(encoded_credentials),
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, identity"
        }

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

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
            timeout=(10, 90),
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


def sanitize_cef_value(key: str, val: str) -> str:
    """Sanitizes an individual CEF extension field value across all columns.

    - Strips carriage returns and newlines inside values to protect single-line integrity.
    - Removes unescaped single quotes/apostrophes (e.g., Al 'Ayyat -> Al Ayyat, 'Amran -> Amran,
      unbalanced quotes in user-agents or payloads) to prevent CEF tokenizers from entering
      an unclosed string literal state.
    - Normalizes doubled quotes in embedded JSON arrays/objects (e.g. cs10, cs11).
    - Removes non-printable control characters that crash SIEM parsers.
    """
    if not val:
        return ""

    # 1. Strip raw carriage returns and newlines inside field values
    val = val.replace("\r", " ").replace("\n", " ")

    # 2. Strip unescaped single quotes/apostrophes across all columns
    val = val.replace("'", "")

    # 3. Normalize doubled quotes in embedded JSON structures
    val = val.replace('""', '"')

    # 4. Remove non-printable control characters (keep printable chars and unicode)
    val = "".join(c for c in val if c.isprintable() or c == " ")

    return val.strip()


def sanitize_cef_event(raw_event: str, file_name: str = "") -> Optional[str]:
    """Parses, cleans, and standardizes a single CEF event across all columns and header fields.

    Accurately tokenizes the 7 CEF header parts and all extension key=value pairs,
    sanitizes every value, and outputs a clean, standards-compliant CEF string.
    """
    if not raw_event or not raw_event.strip():
        return None

    raw_event = raw_event.strip()
    if not raw_event.startswith("CEF:"):
        if raw_event.startswith("0|"):
            raw_event = "CEF:" + raw_event
        else:
            raw_event = "CEF:0|" + raw_event

    # CEF Header structure: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    parts = raw_event.split("|", 7)
    if len(parts) < 8:
        return raw_event

    # Sanitize header fields (indexes 0 to 6)
    header_parts = [h.replace("\r", " ").replace("\n", " ").strip() for h in parts[:7]]
    extension_str = parts[7]

    # Robust tokenization of all key=value pairs in the extension
    matches = list(EXT_PATTERN.finditer(extension_str))
    extension_kvs = {}

    for i in range(len(matches)):
        k = matches[i].group(1)
        v_start = matches[i].end()
        v_end = matches[i + 1].start() if i + 1 < len(matches) else len(extension_str)
        raw_val = extension_str[v_start:v_end]
        extension_kvs[k] = sanitize_cef_value(k, raw_val)

    # Reconstruct clean extension string
    ext_pairs = []
    for k, v in extension_kvs.items():
        if v:
            ext_pairs.append("{}={}".format(k, v))

    # Ensure logfilename and eventhash are present
    if file_name and "logfilename" not in extension_kvs:
        ext_pairs.append("logfilename={}".format(file_name))
    if "eventhash" not in extension_kvs:
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


def fetch_events(client, last_run, max_logs, starting_file_id):
    """Fetches new log files incrementally and extracts CEF events for XSIAM."""
    last_file_id = int(last_run.get("last_file_id", 0))
    last_file_id = max(last_file_id, starting_file_id)
    demisto.debug("{} Starting fetch from last_file_id={}, max_logs={}".format(LOG_PREFIX, last_file_id, max_logs))

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

    if len(candidate_files) > max_logs:
        candidate_files = candidate_files[:max_logs]
        demisto.debug("{} Capping batch to {} of {} eligible files.".format(LOG_PREFIX, max_logs, total_eligible))
    else:
        demisto.debug("{} Processing {} eligible files.".format(LOG_PREFIX, total_eligible))

    max_file_id = last_file_id
    events = []
    failed_files = []

    for file_id, file in candidate_files:
        try:
            raw_content = client.get_log_file(file)
            log_events = decompress_and_parse_cef(raw_content, file)
            events.extend(log_events)
            max_file_id = max(max_file_id, file_id)
        except Exception as e:
            failed_files.append("{} ({})".format(file, e))
            demisto.error("{} Error processing file {}: {}\n{}".format(LOG_PREFIX, file, e, traceback.format_exc()))

    if failed_files:
        demisto.error("{} Errors encountered on {} file(s): {}".format(LOG_PREFIX, len(failed_files), ", ".join(failed_files)))

    next_run = {
        "last_file_id": max_file_id,
        "event_count": len(events)
    }
    demisto.debug("{} Fetch complete. Parsed {} events. Next state: {}".format(LOG_PREFIX, len(events), next_run))
    return next_run, events


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
        send_events_to_xsiam(events=all_events, vendor=VENDOR, product=PRODUCT, data_format="cef")
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
    starting_file_id = arg_to_number(params.get("starting_file_id")) or 0

    demisto.debug("{} Executing command: {}".format(LOG_PREFIX, command))

    try:
        client = Client(
            base_url=base_url,
            api_id=api_id,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-events":
            next_run, events = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                max_logs=max_logs,
                starting_file_id=starting_file_id
            )
            if events:
                demisto.debug("{} Sending {} events to XSIAM.".format(LOG_PREFIX, len(events)))
                send_events_to_xsiam(
                    events=events,
                    vendor=VENDOR,
                    product=PRODUCT,
                    data_format="cef"
                )
                demisto.debug("{} Successfully sent {} events to XSIAM.".format(LOG_PREFIX, len(events)))
            else:
                demisto.debug("{} No new events to push.".format(LOG_PREFIX))
                send_events_to_xsiam(
                    events=[],
                    vendor=VENDOR,
                    product=PRODUCT
                )

            demisto.setLastRun(next_run)

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
