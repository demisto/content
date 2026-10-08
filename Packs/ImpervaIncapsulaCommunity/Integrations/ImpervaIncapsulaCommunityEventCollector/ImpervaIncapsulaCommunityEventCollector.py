"""
Imperva Incapsula Community Event Collector

Community-maintained. Not developed, reviewed, or supported by Imperva or Palo Alto Networks.

Fetches log files from the Imperva Cloud WAF (Incapsula) "Imperva API" log connection - the short-term
buffer served at https://logs<N>.incapsula.com/<account>_<id>/ - decrypts and decompresses them in
memory, and sends the decoded lines to Cortex XSIAM as raw text.

The download/decrypt/decompress algorithm is a Python-3/`cryptography`-library port of the logic in
Imperva's open-source https://github.com/imperva/incapsula-logs-downloader (LogsDownloader.py,
LogsFileIndex.py, FileDownloader.py - BSD-style license), adapted to run inside an XSIAM fetch cycle
instead of as a standalone on-prem daemon.
"""

import base64
import hashlib
import re
import zlib
from typing import Any
from urllib.parse import urljoin

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

urllib3.disable_warnings()

VENDOR = "imperva"
PRODUCT = "incapsula"

INDEX_FILE_NAME = "logs.index"
LOG_FILE_NAME_RE = re.compile(r"\d+_\d+\.log")
# Files that carry a header (CEF/LEEF/W3C) separate it from the log content with this exact marker.
# Other formats have no header and are neither compressed nor encrypted.
HEADER_SEPARATOR = b"|==|\n"
# Imperva encrypts with a fixed all-zero AES-CBC IV (see upstream LogsDownloader.decrypt_file).
AES_IV = b"\x00" * 16

DEFAULT_FIRST_FETCH_FILES = 10
DEFAULT_MAX_FILES_PER_FETCH = 50


class RateLimitError(Exception):
    """Raised when Imperva returns 429. Callers should stop the current fetch cycle cleanly on this,
    leaving already-collected events intact and unprocessed files for the next cycle to retry."""


class Client(BaseClient):
    def __init__(self, base_url: str, api_id: str, api_key: str, verify: bool = True, proxy: bool = False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._auth = (api_id, api_key)

    def _get(self, path: str) -> bytes | None:
        """
        GETs a path relative to the configured Logs URL.

        :return: the response body, or None if the file does not exist (404) - which for an
            individual log file means it has aged out of the short-term buffer, and for logs.index on
            a brand-new account means no logs have been generated yet.
        :raises DemistoException: on a 401 (bad credentials).
        :raises RateLimitError: on a 429, so the caller can stop the fetch cycle without failing it.
        """
        resp = self._http_request(
            method="GET",
            full_url=urljoin(self._base_url, path),
            auth=self._auth,
            resp_type="response",
            ok_codes=(200, 401, 404, 429),
        )
        if resp.status_code == 401:
            raise DemistoException("Authorization error - verify the configured API ID and API Key are correct.")
        if resp.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded while requesting '{path}'.")
        if resp.status_code == 404:
            return None
        return resp.content

    def get_index(self) -> list[str]:
        """Downloads and parses logs.index into an ordered list of file name entries."""
        content = self._get(INDEX_FILE_NAME)
        if content is None:
            demisto.info(f"{INDEX_FILE_NAME} does not exist yet - no logs have been generated for this account.")
            return []
        return [line for line in content.decode("utf-8").splitlines() if line]

    def get_log_file(self, file_name: str) -> bytes | None:
        """Downloads a single log file. Returns None if it has aged out of the buffer."""
        return self._get(file_name)


def is_valid_log_file_name(name: str) -> bool:
    """Anchored validation of the '<account>_<counter>.log' file name format.

    Upstream's LogsFileIndex.validate_log_file_format uses an unanchored re.match, which accepts
    trailing junk after a valid prefix. Use fullmatch instead.
    """
    return bool(LOG_FILE_NAME_RE.fullmatch(name))


def file_counter(file_name: str) -> int:
    """Extracts the numeric counter from a '<account>_<counter>.log' file name, for sort ordering."""
    try:
        return int(file_name.split("_")[1].rsplit(".log", 1)[0])
    except (IndexError, ValueError):
        return -1


def _extract_header_field(header: str, field_name: str) -> str | None:
    """Extracts a single 'field_name:value' line from a decoded log file header section."""
    marker = f"{field_name}:"
    idx = header.find(marker)
    if idx == -1:
        return None
    return header[idx + len(marker) :].splitlines()[0].strip()


def _zlib_decompress(data: bytes) -> bytes:
    """
    Decompresses zlib-deflated data, tolerating trailing bytes after the deflate stream ends.

    Uses decompressobj().decompress() rather than zlib.decompress(): AES-CBC decryption leaves PKCS
    padding after the deflate stream, which decompressobj ignores but zlib.decompress rejects with
    zlib.error. If the data is not actually compressed, return it unchanged.
    """
    try:
        return zlib.decompressobj().decompress(data)
    except zlib.error:
        return data


def decode_file(
    file_content: bytes,
    file_name: str,
    private_key_pem: str | None,
    configured_public_key_id: str | None,
) -> bytes:
    """
    Decrypts (if applicable) and decompresses (if applicable) a downloaded log file's content.

    Port of LogsDownloader.decrypt_file. Formats other than CEF/LEEF/W3C carry no '|==|' header and
    are returned unchanged - they are neither compressed nor encrypted.
    """
    parts = file_content.split(HEADER_SEPARATOR)
    if len(parts) != 2:
        return file_content

    header, payload = parts[0].decode("utf-8"), parts[1]

    if "key:" not in header:
        # Not encrypted - only (possibly) compressed.
        return _zlib_decompress(payload)

    if not private_key_pem:
        raise DemistoException(
            f"File '{file_name}' is encrypted, but no log encryption private key is configured " "on this instance."
        )

    file_public_key_id = _extract_header_field(header, "publicKeyId")
    if configured_public_key_id and file_public_key_id != configured_public_key_id:
        raise DemistoException(
            f"File '{file_name}' was encrypted with publicKeyId={file_public_key_id}, which does not "
            f"match the configured public key ID ({configured_public_key_id})."
        )

    encrypted_sym_key_b64 = _extract_header_field(header, "key")
    checksum = _extract_header_field(header, "checksum")
    if not encrypted_sym_key_b64:
        raise DemistoException(f"File '{file_name}' header is missing the expected 'key:' value.")

    private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    sym_key_b64 = private_key.decrypt(base64.b64decode(encrypted_sym_key_b64), padding.PKCS1v15())
    aes_key = base64.b64decode(sym_key_b64)
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(AES_IV)).decryptor()
    decrypted_payload = decryptor.update(payload) + decryptor.finalize()
    content = _zlib_decompress(decrypted_payload)

    if checksum:
        actual_checksum = hashlib.md5(content).hexdigest()  # nosec - Imperva-defined integrity check, not a security boundary
        if actual_checksum != checksum:
            demisto.info(
                f"Checksum mismatch for '{file_name}': expected {checksum}, computed {actual_checksum}. "
                "Content will still be ingested."
            )

    return content


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    private_key_pem: str | None,
    public_key_id: str | None,
    first_fetch_files: int,
    max_files_per_fetch: int,
) -> tuple[list[str], dict[str, Any]]:
    """
    Runs one fetch cycle: lists logs.index, downloads/decodes any files not yet processed (bounded by
    max_files_per_fetch), and returns the decoded log lines plus the lastRun to persist.

    State is a flat list of already-processed file names in last_run["processed"], intersected each
    cycle with the current index so it stays bounded to roughly the index size - mirroring upstream's
    own complete.log reconciliation against logs.index.
    """
    is_first_run = not last_run
    processed = set(last_run.get("processed", []))

    index_entries = client.get_index()
    valid_entries = sorted((e for e in index_entries if is_valid_log_file_name(e)), key=file_counter)
    invalid_count = len(index_entries) - len(valid_entries)
    if invalid_count:
        demisto.info(f"Ignoring {invalid_count} {INDEX_FILE_NAME} entries with an unexpected file name format.")

    if is_first_run and first_fetch_files > 0:
        backfill = set(valid_entries[-first_fetch_files:])
        # Everything older than the backfill window is marked processed without being downloaded -
        # there is no meaningful "first fetch time" for a counter-based index.
        processed |= {e for e in valid_entries if e not in backfill}

    pending = [e for e in valid_entries if e not in processed][:max_files_per_fetch]

    events: list[str] = []
    newly_processed: list[str] = []
    for file_name in pending:
        try:
            raw_content = client.get_log_file(file_name)
        except RateLimitError as e:
            demisto.info(f"{e} Stopping this fetch cycle early; remaining files will be retried next cycle.")
            break

        if raw_content is None:
            demisto.info(f"'{file_name}' is no longer available (aged out of the log buffer). Marking as processed.")
            newly_processed.append(file_name)
            continue

        try:
            decoded_content = decode_file(raw_content, file_name, private_key_pem, public_key_id)
        except Exception as e:
            demisto.error(f"Failed to decode '{file_name}': {e}. Will retry next cycle.")
            break

        lines = [line for line in decoded_content.decode("utf-8", errors="replace").splitlines() if line.strip()]
        events.extend(lines)
        newly_processed.append(file_name)

    next_processed = sorted((processed | set(newly_processed)) & set(valid_entries), key=file_counter)
    return events, {"processed": next_processed}


def test_module(client: Client) -> str:
    # get_index() returns an empty list (rather than raising) for a brand-new account with no logs.index
    # yet, so the only failure mode surfaced here is a genuine authorization error.
    client.get_index()
    return "ok"


def get_events_command(
    client: Client,
    args: dict[str, Any],
    last_run: dict[str, Any],
    private_key_pem: str | None,
    public_key_id: str | None,
    first_fetch_files: int,
    default_limit: int,
) -> tuple[list[str], dict[str, Any], CommandResults]:
    """Manual/debug command backing 'imperva-incapsula-community-get-events'."""
    limit = arg_to_number(args.get("limit")) or default_limit

    events, next_run = fetch_events(client, last_run, private_key_pem, public_key_id, first_fetch_files, limit)

    readable = tableToMarkdown(
        f"Imperva Incapsula Events ({len(events)})",
        [{"Raw": e} for e in events],
        headers=["Raw"],
    )
    results = CommandResults(
        readable_output=readable,
        outputs_prefix="ImpervaIncapsulaCommunity.Event",
        outputs=[{"raw": e} for e in events],
        raw_response=events,
    )
    return events, next_run, results


def main() -> None:  # pragma: no cover - exercised via unit tests calling the functions above directly
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is '{command}'")

    url = (params.get("url") or "").rstrip("/") + "/"
    credentials = params.get("credentials") or {}
    api_id = credentials.get("identifier")
    api_key = credentials.get("password")

    private_key_credentials = params.get("private_key") or {}
    private_key_pem = private_key_credentials.get("password") or None
    public_key_id = params.get("public_key_id") or None

    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    first_fetch_files = arg_to_number(params.get("first_fetch_files")) or DEFAULT_FIRST_FETCH_FILES
    max_files_per_fetch = arg_to_number(params.get("max_files_per_fetch")) or DEFAULT_MAX_FILES_PER_FETCH

    try:
        client = Client(base_url=url, api_id=api_id, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(
                client, last_run, private_key_pem, public_key_id, first_fetch_files, max_files_per_fetch
            )
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        elif command == "imperva-incapsula-community-get-events":
            last_run = demisto.getLastRun()
            events, next_run, results = get_events_command(
                client, args, last_run, private_key_pem, public_key_id, first_fetch_files, max_files_per_fetch
            )
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(next_run)
            return_results(results)

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute '{command}' command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
