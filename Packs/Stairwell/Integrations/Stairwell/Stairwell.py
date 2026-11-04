"""IMPORTS"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import ipaddress
import json
import re
import socket
import urllib3
import urllib.parse
import uuid
import requests  # type: ignore[import]
from requests.adapters import HTTPAdapter  # type: ignore[import]
from urllib3.util.retry import Retry
import os
import tempfile
import traceback
import hashlib
from typing import Any

""" CONSTANTS """
REPUTATION_BASE_URL = "https://reputation.app.stairwell.com/api/v3/files/"
VARIANTS_BASE_URL = "https://app.stairwell.com/v202112/variants/"
INTAKE_PREFLIGHT_URL = "https://http.intake.app.stairwell.com/v2021.05/upload"
OBJECTS_BASE_URL = "https://app.stairwell.com/v1/objects/"
V1_BASE_URL = "https://app.stairwell.com/v1/"
V2_BASE_URL = "https://app.stairwell.com/v2/"

HTTP_TIMEOUT = 120  # seconds for API calls
UPLOAD_TIMEOUT = 600  # seconds for GCS upload
RETRY_COUNT = 3
RETRY_BACKOFF_FACTOR = 1.5  # exponential backoff factor
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]
# Largest file stairwell-intake-upload downloads from a URL. The download runs on the
# engine host, so the cap bounds disk use by a single command.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
# Fields the Stairwell asset API returns that are credentials, kept out of context and
# the War Room.
ASSET_SECRET_FIELDS = ("uploadToken", "upload_token")
VENDOR_NAME = "Stairwell"
# MalEval probability bucket -> DBotScore. VERY_HIGH and HIGH are the buckets Stairwell
# treats as malicious; LOW is a positive signal that the file is benign.
MAL_EVAL_SCORES = {
    "PROBABILITY_VERY_HIGH": 3,
    "PROBABILITY_HIGH": 3,
    "PROBABILITY_MEDIUM": 2,
    "PROBABILITY_LOW": 1,
}


# --------------------------------
# Helpers
# --------------------------------
def _require_args(required: dict[str, Any]) -> None:
    """Raise a DemistoException naming any required arguments that are empty."""
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise DemistoException(f"Missing required arguments: {', '.join(missing)}")


def _status_code(err: Exception) -> int | None:
    """
    Return the HTTP status code behind a DemistoException raised by BaseClient.

    Prefers the attached response object; falls back to the "[NNN]" marker that
    BaseClient puts in its error message. Returns None when no code can be determined,
    so callers never match on digits that happen to appear elsewhere in the message.
    """
    res = getattr(err, "res", None)
    code = getattr(res, "status_code", None)
    if isinstance(code, int):
        return code
    match = re.search(r"\[(\d{3})\]", str(err)) or re.match(r"\s*(\d{3})\b", str(err))
    return int(match.group(1)) if match else None


def _parse_int_arg(value: str | None, param_name: str, allow_negative: bool = False) -> int | None:
    """
    Safely parse integer argument with validation.

    Args:
        value: String value to parse
        param_name: Parameter name for error messages
        allow_negative: Whether to allow negative integers

    Returns:
        Parsed integer or None if value is None

    Raises:
        DemistoException: If value cannot be parsed as integer
    """
    if value is None:
        return None

    try:
        parsed = int(value)
        if not allow_negative and parsed < 0:
            raise DemistoException(f"Invalid {param_name} parameter: '{value}'. Must be a positive integer.")
        return parsed
    except ValueError:
        raise DemistoException(f"Invalid {param_name} parameter: '{value}'. Must be an integer.")


def _hash_sha256(file_path: str) -> str:
    """Return the hex SHA-256 of the file at file_path."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        raise DemistoException(f"Failed computing sha256 for {os.path.basename(file_path)}: {e}") from e


def _strip_asset_secrets(asset: Any) -> Any:
    """Return a copy of an asset API response without its upload token."""
    if not isinstance(asset, dict):
        return asset
    return {k: v for k, v in asset.items() if k not in ASSET_SECRET_FIELDS}


def _check_download_host(hostname: str) -> None:
    """
    Refuse a download host that is not a public, globally routable address.

    Every address the name resolves to must be global: a loopback, private, link-local
    (including the cloud metadata service at 169.254.169.254) or otherwise reserved
    address would let a playbook argument read from the engine's own network.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise DemistoException(f"Cannot resolve download host {hostname}: {e}") from e
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise DemistoException(f"Cannot resolve download host {hostname}")
    for raw in addresses:
        addr = ipaddress.ip_address(raw.split("%")[0])
        if not addr.is_global or addr.is_multicast:
            raise DemistoException(
                f"Refusing to download from {hostname}: it resolves to {raw}, which is not a public address."
            )


def _create_session_with_retries(
    max_retries: int = RETRY_COUNT, backoff_factor: float = RETRY_BACKOFF_FACTOR
) -> requests.Session:
    """
    Create a requests Session with retry logic for 5xx and 429 status codes.
    Uses urllib3's Retry mechanism instead of sleep to comply with XSOAR best practices.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504, 429],
        allowed_methods=["POST", "GET", "PUT", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _resolve_file_source(
    entry_id: str | None = None,
    url: str | None = None,
    verify: bool = True,
    use_proxy: bool = False,
) -> tuple[str, str, bool]:
    """
    Resolve the file to upload from exactly one of entry_id or url.

    Returns (path, filename, is_temp). is_temp is True when the file was downloaded
    to a temporary path the caller must remove. Raises DemistoException when the
    source cannot be resolved.
    """
    if entry_id and url:
        raise DemistoException("Multiple file sources provided: provide only one of entry_id or url")
    if not entry_id and not url:
        raise DemistoException("Missing file source: provide one of entry_id or url")

    if entry_id:
        file_info = demisto.getFilePath(entry_id)
        if not isinstance(file_info, dict) or not file_info.get("path"):
            raise DemistoException(f"Failed to resolve entry ID {entry_id}: no file path in response")
        resolved_path = file_info["path"]
        if not os.path.exists(resolved_path):
            raise DemistoException(f"Failed to resolve entry ID {entry_id}: file not found")
        return resolved_path, file_info.get("name") or "unknown", False

    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise DemistoException(f"Invalid URL scheme: only http and https are supported (got: {parsed_url.scheme})")
    if not parsed_url.hostname:
        raise DemistoException(f"Invalid URL: no host in {url}")
    _check_download_host(parsed_url.hostname)

    filename = os.path.basename(parsed_url.path) if parsed_url.path else ""
    if not filename or filename == "/":
        filename = "downloaded_file"

    session = _create_session_with_retries()
    proxies = handle_proxy() if use_proxy else None
    try:
        # Redirects are not followed: a redirect target would skip the host check above.
        response = session.get(
            url, verify=verify, proxies=proxies, stream=True, timeout=HTTP_TIMEOUT, allow_redirects=False
        )
    except requests.exceptions.Timeout as e:
        raise DemistoException(f"Timeout downloading from {url} after {HTTP_TIMEOUT}s. Check connectivity.") from e
    except requests.exceptions.ConnectionError as e:
        raise DemistoException(f"Connection error downloading from URL {url}: {e}. Check URL and network connectivity.") from e
    except requests.exceptions.RequestException as e:
        raise DemistoException(f"Failed to download from URL {url}: {e}") from e

    if 300 <= response.status_code < 400:
        raise DemistoException(
            f"Download from {url} returned a redirect ({response.status_code}), which is not followed. "
            "Provide the final URL."
        )
    if response.status_code != 200:
        raise DemistoException(f"Download from {url} failed with status {response.status_code}.")

    content_length = response.headers.get("Content-Length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_DOWNLOAD_BYTES:
        raise DemistoException(f"Download from {url} is {content_length} bytes; the limit is {MAX_DOWNLOAD_BYTES}.")

    # delete=False so the file survives close() and can be reopened for hashing and upload.
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}")
    temp_path = temp_file.name
    try:
        written = 0
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if not chunk:
                continue
            written += len(chunk)
            if written > MAX_DOWNLOAD_BYTES:
                raise DemistoException(f"Download from {url} exceeded the {MAX_DOWNLOAD_BYTES} byte limit.")
            temp_file.write(chunk)
        temp_file.close()
    except Exception:
        temp_file.close()
        _remove_temp_file(temp_path)
        raise
    return temp_path, filename, True


def _remove_temp_file(path: str) -> None:
    """Remove a downloaded temp file, logging rather than failing the command if it cannot."""
    if not os.path.exists(path):
        return
    try:
        os.remove(path)
        demisto.debug(f"Removed temp file {path}")
    except OSError as e:
        demisto.error(f"Could not remove temp file {path}: {e}. File may remain.")


class Client(BaseClient):
    """
    Single client for every Stairwell API surface.

    The Stairwell APIs live on several hosts/versions, so each method passes a full URL
    rather than relying on BaseClient's base_url (which is set to V1_BASE_URL only as a default).
    """

    def __init__(self, api_key: str, verify: bool = True, proxy: bool = False):
        super().__init__(base_url=V1_BASE_URL, verify=verify, proxy=proxy, headers={"Authorization": api_key})

    def _request(self, method: str, full_url: str, retries: int = RETRY_COUNT, **kwargs: Any) -> dict[str, Any]:
        """
        Issue a request with the integration-wide timeout and retry policy applied.

        A request that creates something and cannot be made idempotent passes retries=0:
        a retry after a lost response would create it twice.
        """
        return self._http_request(
            method=method,
            full_url=full_url,
            timeout=HTTP_TIMEOUT,
            retries=retries,
            status_list_to_retry=RETRY_STATUS_CODES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            **kwargs,
        )

    # File reputation / variants
    def get_file_reputation(self, file_hash: str) -> dict[str, Any]:
        return self._request("GET", f"{REPUTATION_BASE_URL}{file_hash}")

    def get_file_variants(self, file_hash: str) -> dict[str, Any]:
        return self._request("GET", f"{VARIANTS_BASE_URL}{file_hash}")

    # Objects
    def get_object_metadata(self, object_id: str) -> dict[str, Any]:
        """Get an object's metadata, including its MalEval verdict and YARA matches."""
        return self._request("GET", f"{OBJECTS_BASE_URL}{object_id}/metadata")

    def summarize_file(self, object_id: str) -> dict[str, Any]:
        """Get AI-generated summary for a file object."""
        return self._request("GET", f"{OBJECTS_BASE_URL}{object_id}:summarize")

    def list_object_sightings(self, object_id: str) -> dict[str, Any]:
        """List sightings for a given object."""
        return self._request("GET", f"{OBJECTS_BASE_URL}{object_id}/sightings")

    def list_object_opinions(self, object_id: str) -> dict[str, Any]:
        """List opinions for an object."""
        return self._request("GET", f"{OBJECTS_BASE_URL}{object_id}/opinions")

    def generate_run_to_ground(self, object_ids: list[str]) -> dict[str, Any]:
        """Generate Run-To-Ground analysis for objects."""
        # API expects objectIds parameter (can be repeated for multiple objects)
        return self._request("GET", f"{V1_BASE_URL}generateRunToGround:generate", params={"objectIds": object_ids})

    # Network Intel API Methods - ASN
    def get_asn_whois(self, asn: str) -> dict[str, Any]:
        """Get ASN WHOIS information."""
        return self._request("GET", f"{V2_BASE_URL}asns/{asn}/whois")

    # Network Intel API Methods - Hostname
    def get_hostname(self, hostname: str, record_type: str | None = None) -> dict[str, Any]:
        """Get hostname entity with DNS resolution data."""
        params: dict[str, Any] = {}
        if record_type:
            params["recordTypes"] = record_type
        return self._request("GET", f"{V2_BASE_URL}hostnames/{hostname}", params=params)

    def get_hostname_resolutions(
        self, hostname: str, start_time: str | None = None, end_time: str | None = None
    ) -> dict[str, Any]:
        """Get all addresses resolved to by a hostname over a time range."""
        params: dict[str, Any] = {}
        if start_time:
            params["interval.startTime"] = start_time
        if end_time:
            params["interval.endTime"] = end_time
        return self._request("GET", f"{V2_BASE_URL}hostnames/{hostname}/resolutions", params=params)

    def get_hostname_whitelist_status(self, hostname: str) -> dict[str, Any]:
        """Whether Stairwell lists the hostname as known-good."""
        return self._request("GET", f"{V2_BASE_URL}hostnames/{hostname}/whitelist-status")

    def batch_get_hostname_resolutions(
        self,
        hostnames: list[str],
        start_time: str | None = None,
        end_time: str | None = None,
        record_types: list[str] | None = None,
        include_errors: bool | None = None,
    ) -> dict[str, Any]:
        """Get resolution summaries for multiple hostnames."""
        json_data: dict[str, Any] = {"hostnames": hostnames}
        if start_time or end_time:
            interval: dict[str, str] = {}
            if start_time:
                interval["startTime"] = start_time
            if end_time:
                interval["endTime"] = end_time
            json_data["interval"] = interval
        if record_types:
            json_data["recordTypes"] = record_types
        if include_errors is not None:
            json_data["includeErrors"] = include_errors
        return self._request("POST", f"{V2_BASE_URL}hostnames:batch-resolutions", json_data=json_data)

    # Network Intel API Methods - IP Address
    def get_ip_address(self, ip_address: str) -> dict[str, Any]:
        """Get IP address entity with enrichment data."""
        return self._request("GET", f"{V2_BASE_URL}ips/{ip_address}")

    def lookup_cloud_provider(self, ip_address: str) -> dict[str, Any]:
        """Check if an IP address belongs to a known cloud provider."""
        return self._request("GET", f"{V2_BASE_URL}ips/{ip_address}/provider")

    def get_hostnames_resolving_to_ip(
        self, ip_address: str, start_time: str | None = None, end_time: str | None = None
    ) -> dict[str, Any]:
        """Get all hostnames resolved to by an IP over a time interval."""
        params: dict[str, Any] = {}
        if start_time:
            params["interval.startTime"] = start_time
        if end_time:
            params["interval.endTime"] = end_time
        return self._request("GET", f"{V2_BASE_URL}ips/{ip_address}/hostnames", params=params)

    def get_ip_address_whois(self, ip_address: str) -> dict[str, Any]:
        """Get WHOIS information for an IP address."""
        return self._request("GET", f"{V2_BASE_URL}ips/{ip_address}/whois")

    # Network Intel API Methods - Utilities
    def get_cloud_ip_ranges(self, provider: str | None = None) -> dict[str, Any]:
        """Get IP ranges for known cloud providers."""
        suffix = f"providers/{provider}/ip-ranges" if provider else "providers/ip-ranges"
        return self._request("GET", f"{V2_BASE_URL}{suffix}")

    def batch_canonicalize_hostnames(self, hostnames: list[str]) -> dict[str, Any]:
        """Canonicalize multiple hostnames in bulk."""
        return self._request("POST", f"{V2_BASE_URL}utilities/hostnames:batch-canonicalize", json_data={"hostnames": hostnames})

    def batch_compute_etld_plus_one(self, domains: list[str]) -> dict[str, Any]:
        """Compute effective top-level domain plus one for multiple domains."""
        return self._request("POST", f"{V2_BASE_URL}utilities/hostnames:batch-etld-plus-one", json_data={"domains": domains})

    def canonicalize_hostname(self, hostname: str) -> dict[str, Any]:
        """Canonicalize a single hostname."""
        return self._request("GET", f"{V2_BASE_URL}utilities/hostnames:canonicalize/{hostname}")

    def compute_etld_plus_one(self, domain: str) -> dict[str, Any]:
        """Compute effective top-level domain plus one for a single domain."""
        return self._request("GET", f"{V2_BASE_URL}utilities/hostnames:etld-plus-one/{domain}")

    def batch_canonicalize_urls(self, urls: list[str]) -> dict[str, Any]:
        """Canonicalize multiple URLs in bulk."""
        return self._request("POST", f"{V2_BASE_URL}utilities/urls:batch-canonicalize", json_data={"urls": urls})

    def canonicalize_url(self, url: str) -> dict[str, Any]:
        """Canonicalize a single URL."""
        return self._request("GET", f"{V2_BASE_URL}utilities/urls:canonicalize", params={"url": url})

    # Intake
    def intake_preflight(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send intake preflight request to Stairwell Intake API."""
        return self._request("POST", INTAKE_PREFLIGHT_URL, json_data=payload)

    # YARA Rules API Methods
    def create_yara_rule(self, environment: str, rule_definition: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a new YARA rule."""
        json_data: dict[str, Any] = {"definition": rule_definition}
        if metadata:
            json_data.update(metadata)
        return self._request("POST", f"{V1_BASE_URL}environments/{environment}/yaraRules", json_data=json_data, retries=0)

    def get_yara_rule(self, environment: str, yara_rule: str, match_count_envs: str | None = None) -> dict[str, Any]:
        """Get a specific YARA rule."""
        params: dict[str, Any] = {}
        if match_count_envs:
            params["matchCountEnvs"] = match_count_envs
        return self._request("GET", f"{V1_BASE_URL}environments/{environment}/yaraRules/{yara_rule}", params=params)

    def query_yara_matches(
        self,
        environment: str,
        yara_rule: str,
        included_environments: list[str] | None = None,
        page_size: int | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Query objects matching a YARA rule."""
        params: dict[str, Any] = {}
        if included_environments:
            params["includedEnvironments"] = included_environments
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        return self._request(
            "GET", f"{V1_BASE_URL}environments/{environment}/yaraRules/{yara_rule}/matchingObjects", params=params
        )

    # Asset Management API Methods
    def list_assets(self, environment: str, page_size: int | None = None, page_token: str | None = None) -> dict[str, Any]:
        """List all assets in an environment."""
        params: dict[str, Any] = {}
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", f"{V1_BASE_URL}environments/{environment}/assets", params=params)

    def create_asset(
        self,
        environment: str,
        label: str,
        idempotency_key: str | None = None,
        os_name: str | None = None,
        os_version: str | None = None,
        forwarder_version: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new asset in an environment.

        An idempotency key is always sent (generated when the caller gives none) so the
        request can be retried without creating a second asset.
        """
        json_data: dict[str, Any] = {"label": label}
        params: dict[str, Any] = {"idempotencyKey": idempotency_key or str(uuid.uuid4())}
        if os_name:
            params["os"] = os_name
        if os_version:
            params["osVersion"] = os_version
        if forwarder_version:
            params["forwarderVersion"] = forwarder_version
        return self._request("POST", f"{V1_BASE_URL}environments/{environment}/assets", json_data=json_data, params=params)

    def get_asset(self, asset: str) -> dict[str, Any]:
        """Get a specific asset by ID."""
        return self._request("GET", f"{V1_BASE_URL}assets/{asset}")


TEST_MODULE_HASH = "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"  # in the shared corpus


def test_module(client: Client) -> str:
    """
    Check the API key against both Stairwell API hosts.

    The reputation host and app.stairwell.com authenticate separately, and a key
    that works for one can be refused by the other, so both are called.
    """
    checks = (
        ("reputation API", lambda: client.get_file_reputation(TEST_MODULE_HASH)),
        ("Stairwell API", lambda: client.get_object_metadata(TEST_MODULE_HASH)),
    )
    for name, call in checks:
        try:
            response = call()
        except DemistoException as err:
            if _status_code(err) in (401, 403):
                return f"Authorization Error: the API key was refused by the {name}. Check the key in Stairwell."
            if _status_code(err) == 404:
                continue  # the key is accepted; the sample file is just not visible to this account
            return f"Connection Error ({name}): {err}"
        if not isinstance(response, dict):
            return f"Unexpected response from the {name}: {str(response)[:200]}"
    return "ok"


def file_enrichment_command(client: Client, file_hash: str) -> CommandResults:
    _require_args({"file_hash": file_hash})
    try:
        response = client.get_file_reputation(file_hash)
        # Build safe accessors
        data = response.get("data", {}) if isinstance(response, dict) else {}
        attributes = data.get("attributes", {})
        md = "# Stairwell\n"

        file_md5 = attributes.get("md5", "")
        file_sha256 = attributes.get("sha256", "")
        if file_md5:
            md += f"MD5: {file_md5}\n"
        if file_sha256:
            md += f"SHA256: {file_sha256}\n"

        # Filenames
        names = attributes.get("names") or []
        if isinstance(names, list) and names:
            filenames = []
            for ind in names:
                if not isinstance(ind, str):
                    continue
                if "\\" in ind:
                    filename = ind.split("\\")[-1].lower()
                elif "/" in ind:
                    filename = ind.split("/")[-1].lower()
                else:
                    filename = ind.lower()
                if filename and filename not in filenames:
                    filenames.append(filename)
            if filenames:
                md += f"Filename(s): {', '.join(filenames)}\n"

        # Seen assets: the reputation API reports them per environment under
        # attributes.occurrences[] = {environment: {id, name}, assets: [{id, name}]}.
        seen_environments: list[dict[str, Any]] = []
        for occurrence in attributes.get("occurrences") or []:
            if not isinstance(occurrence, dict):
                continue
            environment = occurrence.get("environment") if isinstance(occurrence.get("environment"), dict) else {}
            assets = [a for a in occurrence.get("assets") or [] if isinstance(a, dict)]
            seen_environments.append(
                {
                    "environment_id": environment.get("id"),
                    "environment_name": environment.get("name"),
                    "asset_count": len(assets),
                    "assets": [{"id": a.get("id"), "name": a.get("name")} for a in assets],
                }
            )
        seen_assets_count = sum(env["asset_count"] for env in seen_environments)
        if len(seen_environments) > 1:
            per_env = ", ".join(
                f"{env['environment_name'] or env['environment_id']}({env['asset_count']})" for env in seen_environments
            )
            md += f"Seen Assets: {seen_assets_count} across {len(seen_environments)} environments: {per_env}\n"
        elif seen_environments:
            env = seen_environments[0]
            md += f"Seen Assets: {env['asset_count']} in {env['environment_name'] or env['environment_id']}\n"
        else:
            md += "Seen Assets: 0\n"

        # YARA intel
        yara_results = attributes.get("crowdsourced_yara_results") or []
        if isinstance(yara_results, list) and yara_results:
            yara_rules = [str(y.get("rule_name")) for y in yara_results if isinstance(y, dict) and y.get("rule_name")]
            if yara_rules:
                md += f"Matching YARA Intel: {', '.join(yara_rules)}\n"

        # AV results
        last_analysis_results = attributes.get("last_analysis_results") or {}
        if isinstance(last_analysis_results, dict) and last_analysis_results:
            md += "### AV Scanning Results\n"
            md += "Engine Name|Result\n"
            md += "---|---\n"
            for res in last_analysis_results.values():
                engine_name = res.get("engine_name")
                result = res.get("result")
                if engine_name and result:  # skip empty
                    md += f"{engine_name}|{result}\n"

        # Structured outputs (normalized subset + raw)
        summary = {
            "md5": file_md5,
            "sha256": file_sha256,
            "filenames": names,
            "seen_assets_count": seen_assets_count,
            "seen_environments": seen_environments,
        }
        outputs = {"sha256": file_sha256 or file_hash, "summary": summary, "raw": response}

        return CommandResults(
            readable_output=md,
            outputs_prefix="Stairwell.File_Details",
            outputs_key_field="sha256",
            outputs=outputs,
        )

    except DemistoException as err:
        # API will return 404 if the file is not found
        if _status_code(err) == 404:
            return CommandResults(readable_output="File not found: " + file_hash)
        else:
            raise err


def variant_discovery_command(client: Client, file_hash: str) -> CommandResults:
    _require_args({"sha256": file_hash})
    try:
        response = client.get_file_variants(file_hash)
        if isinstance(response, dict):
            variants = response.get("variants", [])
            if variants:
                md_string = tableToMarkdown("File Variants Discovered", variants)
                return CommandResults(
                    outputs_prefix="Stairwell.Variants",
                    outputs_key_field="sha256",
                    readable_output=md_string,
                    outputs={"sha256": file_hash, **response},
                )
            else:
                return CommandResults(readable_output="No variants discovered for: " + file_hash)
        return CommandResults(readable_output="Unexpected response format from variants API.")
    except DemistoException as err:
        # The variants API answers 404 (and, historically, 500) when the file is unknown
        if _status_code(err) in (404, 500):
            return CommandResults(readable_output=f"File not found or no variants available: {file_hash}")
        else:
            raise err


_TRIAGE_TITLES = {
    "iocs": "Indicators of compromise",
    "api_analysis": "API analysis",
    "mitre_attack_mapping": "MITRE ATT&CK mapping",
    "guidance_for_clarity_and_impact": "Guidance",
    "file_paths_filenames": "File paths and filenames",
    "ip_addresses": "IP addresses",
    "urls": "URLs",
}
# summaryJson keys that are rendered in the header, not as sections.
_TRIAGE_HEADER_KEYS = ("tldr", "malicious_likelihood", "confidence", "threat_type")
# Section order for the keys Stairwell AI Triage is known to return; any other key follows.
_TRIAGE_SECTION_ORDER = ("summary", "iocs", "key_considerations", "guidance_for_clarity_and_impact", "mitre_attack_mapping")
_TRIAGE_LIST_LIMIT = 25
_TRIAGE_HEADER_LINE = re.compile(
    r"^\s*(\*\*)?\s*(TL;DR|MALICIOUS LIKELIHOOD|CONFIDENCE|THREAT TYPE)\s*:?\s*(\*\*)?", re.IGNORECASE
)


def _triage_title(key: str) -> str:
    return _TRIAGE_TITLES.get(key) or key.replace("_", " ").capitalize()


def _triage_section(key: str, value: Any, level: int) -> str:
    """Render one summaryJson entry as markdown: dicts become subsections, lists bullets, scalars text."""
    heading = "#" * min(level, 4)
    if isinstance(value, dict):
        body = "".join(_triage_section(k, v, level + 1) for k, v in value.items() if v not in (None, "", [], {}))
        return f"{heading} {_triage_title(key)}\n{body}\n" if body else ""
    if isinstance(value, list):
        items = [item for item in value if item not in (None, "")]
        if not items:
            return ""
        lines = []
        for item in items[:_TRIAGE_LIST_LIMIT]:
            if isinstance(item, dict):
                fields = [f"**{_triage_title(str(k))}:** {v}" for k, v in item.items() if v not in (None, "")]
                lines.append("- " + "; ".join(fields))
            else:
                lines.append(f"- {item}")
        if len(items) > _TRIAGE_LIST_LIMIT:
            lines.append(f"- … and {len(items) - _TRIAGE_LIST_LIMIT} more")
        return f"{heading} {_triage_title(key)}\n" + "\n".join(lines) + "\n\n"
    return f"**{_triage_title(key)}:** {value}\n\n"


def ai_triage_summarize_command(client: Client, object_id: str) -> CommandResults:
    """
    Get the AI Triage summary for a file.

    The API returns {tldr, summary, summaryJson}: summary is the full report as
    markdown and summaryJson its structured form. The War Room shows the metrics
    and the report; the structured form goes to context.
    """
    _require_args({"object_id": object_id})

    try:
        response = client.summarize_file(object_id)
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Object not found: {object_id}")
        if _status_code(err) == 400:
            return CommandResults(readable_output=f"Invalid request for object: {object_id}")
        raise

    if not isinstance(response, dict):
        raise DemistoException(f"Unexpected AI Triage response for {object_id}: {response}")

    summary_json = response.get("summaryJson") if isinstance(response.get("summaryJson"), dict) else {}
    tldr = response.get("tldr") or summary_json.get("tldr") or ""
    report = response.get("summary") if isinstance(response.get("summary"), str) else ""
    file_hash = response.get("hash") or object_id
    metrics = {
        "Malicious likelihood": summary_json.get("malicious_likelihood"),
        "Confidence": summary_json.get("confidence"),
        "Threat type": summary_json.get("threat_type"),
    }

    md = f"### Stairwell AI Triage: {file_hash}\n\n"
    if tldr:
        md += f"**TL;DR:** {tldr}\n\n"
    if any(v is not None for v in metrics.values()):
        row = {k: (f"{v}%" if isinstance(v, (int, float)) else v) for k, v in metrics.items()}
        md += tableToMarkdown("", row, headers=list(metrics), removeNull=True) + "\n"
    if report:
        # The report is the same content as summaryJson, already formatted as markdown.
        # Its leading TL;DR and metric lines are dropped because the header above shows them.
        lines = report.strip().splitlines()
        while lines and _TRIAGE_HEADER_LINE.match(lines[0]):
            lines.pop(0)
        md += "\n".join(lines).strip() + "\n"
    elif summary_json:
        sections = [k for k in _TRIAGE_SECTION_ORDER if k in summary_json]
        sections += [k for k in summary_json if k not in sections and k not in _TRIAGE_HEADER_KEYS]
        md += "".join(_triage_section(key, summary_json[key], 2) for key in sections)
    elif not tldr:
        md += "No AI Triage summary is available for this object.\n"

    outputs = {
        "hash": file_hash,
        "tldr": tldr,
        "malicious_likelihood": summary_json.get("malicious_likelihood"),
        "confidence": summary_json.get("confidence"),
        "threat_type": summary_json.get("threat_type"),
        "summary_points": summary_json.get("summary"),
        "iocs": summary_json.get("iocs"),
        "raw": response,
    }
    return CommandResults(
        readable_output=md,
        outputs_prefix="Stairwell.AI_Triage",
        outputs_key_field="hash",
        outputs=outputs,
        raw_response=response,
    )


def object_sightings_command(client: Client, object_id: str) -> CommandResults:
    _require_args({"object_id": object_id})

    try:
        response = client.list_object_sightings(object_id)
        sightings = response.get("objectSightings") if isinstance(response, dict) else None
        readable = tableToMarkdown("Object Sightings", sightings) if sightings else "No sightings found."

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Sightings", outputs_key_field="objectId", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Object not found: {object_id}")
        else:
            raise err


def object_opinions_command(client: Client, object_id: str) -> CommandResults:
    _require_args({"object_id": object_id})

    try:
        response = client.list_object_opinions(object_id)
        opinions = response.get("opinions") if isinstance(response, dict) else None
        readable = tableToMarkdown("Object Opinions", opinions) if opinions else "No opinions found."

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Opinions", outputs_key_field="objectId", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Object not found: {object_id}")
        else:
            raise err


def run_to_ground_generate_command(client: Client, object_ids: str) -> CommandResults:
    _require_args({"object_ids": object_ids})

    try:
        object_list = [oid.strip() for oid in object_ids.split(",") if oid.strip()]
        response = client.generate_run_to_ground(object_list)
        readable = tableToMarkdown("Run To Ground Results", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.RunToGround", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(readable_output="Invalid object IDs provided. Check that object IDs are valid SHA256 hashes.")
        elif _status_code(err) == 404:
            return CommandResults(readable_output="One or more objects not found. Check that the object IDs exist in Stairwell.")
        else:
            raise DemistoException(f"Failed to generate Run-To-Ground analysis: {err}") from err


# Network Intel Command Functions - ASN
def asn_get_whois_command(client: Client, asn: str) -> CommandResults:
    """Get ASN WHOIS information."""
    _require_args({"asn": asn})

    try:
        response = client.get_asn_whois(asn)

        # Add asn to response for key field tracking if not already present
        if isinstance(response, dict) and "asn" not in response:
            response["asn"] = asn

        readable = tableToMarkdown(f"ASN {asn} WHOIS Information", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.ASN.WHOIS", outputs_key_field="asn", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"ASN not found: {asn}")
        else:
            raise err


# Network Intel Command Functions - Hostname
def hostname_get_command(client: Client, hostname: str, record_type: str | None = None) -> CommandResults:
    """Get hostname entity with DNS resolution data."""
    _require_args({"hostname": hostname})

    try:
        response = client.get_hostname(hostname, record_type)

        # Add hostname to response for key field tracking
        if isinstance(response, dict):
            response["hostname"] = hostname

        readable = tableToMarkdown(f"Hostname: {hostname}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Hostname", outputs_key_field="hostname", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Hostname not found: {hostname}")
        else:
            raise err


def hostname_get_resolutions_command(
    client: Client, hostname: str, start_time: str | None = None, end_time: str | None = None
) -> CommandResults:
    """Get all addresses resolved to by a hostname."""
    _require_args({"hostname": hostname})

    try:
        response = client.get_hostname_resolutions(hostname, start_time, end_time)
        resolutions = response.get("resolutions", []) if isinstance(response, dict) else []

        # Add hostname to response for key field tracking
        if isinstance(response, dict):
            response["hostname"] = hostname

        readable = (
            tableToMarkdown(f"Resolutions for {hostname}", resolutions) if resolutions else f"No resolutions found for {hostname}"
        )
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Hostname.Resolutions",
            outputs_key_field="hostname",
            outputs=response,
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Hostname not found: {hostname}")
        else:
            raise err


def hostname_batch_get_resolutions_command(
    client: Client,
    hostnames: str,
    start_time: str | None = None,
    end_time: str | None = None,
    record_types: str | None = None,
    include_errors: str | None = None,
) -> CommandResults:
    """Get resolution summaries for multiple hostnames."""
    _require_args({"hostnames": hostnames})

    hostname_list = [h.strip() for h in hostnames.split(",") if h.strip()]

    # Parse recordTypes if provided (comma-separated string to list)
    record_types_list = None
    if record_types:
        record_types_list = [rt.strip() for rt in record_types.split(",") if rt.strip()]

    # Parse includeErrors boolean
    include_errors_bool = None
    if include_errors:
        include_errors_bool = argToBoolean(include_errors)

    response = client.batch_get_hostname_resolutions(hostname_list, start_time, end_time, record_types_list, include_errors_bool)

    # Extract resolutions for display
    resolutions_data = []
    if isinstance(response, dict) and "resolutions" in response:
        for hostname_res in response.get("resolutions", []):
            if isinstance(hostname_res, dict):
                hostname = hostname_res.get("reversedHostname", "")
                for resolution in hostname_res.get("resolutions", []):
                    if isinstance(resolution, dict):
                        # Add hostname to each resolution for clarity
                        resolution_with_hostname = {"hostname": hostname}
                        resolution_with_hostname.update(resolution)
                        resolutions_data.append(resolution_with_hostname)

    readable = tableToMarkdown("Batch Hostname Resolutions", resolutions_data) if resolutions_data else "No resolutions found."
    return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Hostname.BatchResolutions", outputs=response)


# Network Intel Command Functions - IP Address
def ipaddress_get_command(client: Client, ip_address: str) -> CommandResults:
    """Get IP address entity with enrichment data."""
    _require_args({"ip_address": ip_address})

    try:
        response = client.get_ip_address(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = tableToMarkdown(f"IP Address: {ip_address}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.IPAddress", outputs_key_field="ip", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_lookup_cloud_provider_command(client: Client, ip_address: str) -> CommandResults:
    """Check if an IP address belongs to a known cloud provider."""
    _require_args({"ip_address": ip_address})

    try:
        response = client.lookup_cloud_provider(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = (
            tableToMarkdown(f"Cloud Provider Lookup for {ip_address}", response) if isinstance(response, dict) else str(response)
        )
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.IPAddress.CloudProvider", outputs_key_field="ip", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_get_hostnames_resolving_to_ip_command(
    client: Client, ip_address: str, start_time: str | None = None, end_time: str | None = None
) -> CommandResults:
    """Get all hostnames resolved to by an IP address."""
    _require_args({"ip_address": ip_address})

    try:
        response = client.get_hostnames_resolving_to_ip(ip_address, start_time, end_time)
        hostnames = response.get("hostnames", []) if isinstance(response, dict) else []

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = (
            tableToMarkdown(f"Hostnames Resolving to {ip_address}", [{"Hostname": h} for h in hostnames], headers=["Hostname"])
            if hostnames
            else f"No hostnames found resolving to {ip_address}"
        )
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.IPAddress.Hostnames", outputs_key_field="ip", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_get_whois_command(client: Client, ip_address: str) -> CommandResults:
    """Get WHOIS information for an IP address."""
    _require_args({"ip_address": ip_address})

    try:
        response = client.get_ip_address_whois(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = (
            tableToMarkdown(f"IP Address {ip_address} WHOIS Information", response)
            if isinstance(response, dict)
            else str(response)
        )
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.IPAddress.WHOIS", outputs_key_field="ip", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


# Network Intel Command Functions - Utilities
def utilities_get_cloud_ip_ranges_command(client: Client, provider: str | None = None) -> CommandResults:
    """Get IP ranges for known cloud providers."""
    try:
        response = client.get_cloud_ip_ranges(provider)
        ranges = response.get("ranges", []) if isinstance(response, dict) else []
        readable = tableToMarkdown("Cloud IP Ranges", ranges) if ranges else "No cloud IP ranges found"
        if provider:
            readable = f"Cloud IP Ranges for Provider: {provider}\n\n{readable}"
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Utilities.CloudIPRanges", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(
                readable_output=(
                    f"Invalid provider parameter: '{provider}'. Check valid cloud provider names."
                    if provider
                    else "Bad request to cloud IP ranges API. Check parameters."
                )
            )
        elif _status_code(err) == 404:
            return CommandResults(
                readable_output=f"Cloud provider not found: '{provider}'" if provider else "Cloud IP ranges endpoint not found."
            )
        else:
            provider_info = f" for provider {provider}" if provider else ""
            raise DemistoException(f"Failed to retrieve cloud IP ranges{provider_info}: {err}") from err


def utilities_batch_canonicalize_hostnames_command(client: Client, hostnames: str) -> CommandResults:
    """Canonicalize multiple hostnames in bulk."""
    _require_args({"hostnames": hostnames})

    try:
        hostname_list = [h.strip() for h in hostnames.split(",") if h.strip()]
        response = client.batch_canonicalize_hostnames(hostname_list)
        readable = tableToMarkdown("Canonicalized Hostnames", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Utilities.CanonicalizedHostnames", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(
                readable_output="Invalid hostname format in request. Check that hostnames are properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize hostnames: {err}") from err


def utilities_batch_compute_etld_plus_one_command(client: Client, domains: str) -> CommandResults:
    """Compute effective top-level domain plus one for multiple domains."""
    _require_args({"domains": domains})

    try:
        domain_list = [d.strip() for d in domains.split(",") if d.strip()]
        response = client.batch_compute_etld_plus_one(domain_list)

        # Extract results for display
        results = []
        if isinstance(response, dict) and "results" in response:
            for result in response.get("results", []):
                if isinstance(result, dict) and "response" in result:
                    results.append(result["response"])

        readable = tableToMarkdown("ETLD+1 Results", results) if results else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Utilities.ETLDPlusOne", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(readable_output="Invalid domain format in request. Check that domains are properly formatted.")
        else:
            raise DemistoException(f"Failed to compute ETLD+1 for domains: {err}") from err


def utilities_canonicalize_hostname_command(client: Client, hostname: str) -> CommandResults:
    """Canonicalize a single hostname."""
    _require_args({"hostname": hostname})

    try:
        response = client.canonicalize_hostname(hostname)
        readable = (
            tableToMarkdown(f"Canonicalized Hostname: {hostname}", response) if isinstance(response, dict) else str(response)
        )
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Utilities.CanonicalizedHostname", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(
                readable_output=f"Invalid hostname format: '{hostname}'. Check that the hostname is properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize hostname '{hostname}': {err}") from err


def utilities_compute_etld_plus_one_command(client: Client, domain: str) -> CommandResults:
    """Compute effective top-level domain plus one for a single domain."""
    _require_args({"domain": domain})

    try:
        response = client.compute_etld_plus_one(domain)
        readable = tableToMarkdown(f"ETLD+1 for Domain: {domain}", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Utilities.ETLDPlusOne", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(
                readable_output=f"Invalid domain format: '{domain}'. Check that the domain is properly formatted."
            )
        else:
            raise DemistoException(f"Failed to compute ETLD+1 for domain '{domain}': {err}") from err


def utilities_batch_canonicalize_urls_command(client: Client, urls: str) -> CommandResults:
    """Canonicalize multiple URLs in bulk."""
    _require_args({"urls": urls})

    try:
        url_list = [u.strip() for u in urls.split(",") if u.strip()]
        response = client.batch_canonicalize_urls(url_list)
        readable = tableToMarkdown("Canonicalized URLs", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Utilities.CanonicalizedURLs", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(readable_output="Invalid URL format in request. Check that URLs are properly formatted.")
        else:
            raise DemistoException(f"Failed to canonicalize URLs: {err}") from err


def utilities_canonicalize_url_command(client: Client, url: str) -> CommandResults:
    """Canonicalize a single URL."""
    _require_args({"url": url})

    try:
        response = client.canonicalize_url(url)
        readable = tableToMarkdown(f"Canonicalized URL: {url}", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Utilities.CanonicalizedURL", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(readable_output=f"Invalid URL format: '{url}'. Check that the URL is properly formatted.")
        else:
            raise DemistoException(f"Failed to canonicalize URL '{url}': {err}") from err


def intake_preflight_and_upload(
    client: Client,
    asset_id: str | None = None,
    entry_id: str | None = None,
    url: str | None = None,
    sha256: str | None = None,
    origin_type: str | None = None,
    origin_referrer_url: str | None = None,
    origin_host_url: str | None = None,
    origin_zone_id: int | None = None,
    verify: bool = True,
    use_proxy: bool = False,
) -> CommandResults:
    """
    Implements Stairwell Intake API 'preflight' + conditional upload.

    Any failure raises DemistoException so a playbook sees an error entry; the only
    non-upload outcome reported as success is a file Stairwell already holds.
    """
    _require_args({"asset_id": asset_id})

    file_path, filename, is_temp = _resolve_file_source(entry_id=entry_id, url=url, verify=verify, use_proxy=use_proxy)
    try:
        if not sha256:
            sha256 = _hash_sha256(file_path)

        origin_obj: dict[str, Any] = {}
        if origin_type == "web":
            origin_web: dict[str, Any] = {}
            if origin_referrer_url:
                origin_web["referrer-url"] = origin_referrer_url
            if origin_host_url:
                origin_web["host-url"] = origin_host_url
            if origin_zone_id is not None:
                origin_web["zone-id"] = origin_zone_id
            origin_obj["web"] = origin_web
        else:
            origin_obj["unspecified"] = {}

        # Only the file name goes to the API; the engine's local path is not the file's
        # path on any asset.
        file_obj: dict[str, Any] = {
            "filePath": filename,
            "expected_attributes": {"identifiers": [{"sha256": sha256}]},
            "origin": origin_obj,
        }
        payload: dict[str, Any] = {"asset": {"id": asset_id}, "files": [file_obj]}

        try:
            preflight = client.intake_preflight(payload)
        except requests.exceptions.Timeout as e:
            raise DemistoException(f"Intake preflight timed out after {HTTP_TIMEOUT}s. Try again later.") from e
        except requests.exceptions.ConnectionError as e:
            raise DemistoException(
                f"Connection error during intake preflight: {e}. Check network connectivity to Stairwell API."
            ) from e
        except (requests.exceptions.HTTPError, DemistoException) as e:
            raise DemistoException(f"HTTP error during intake preflight: {e}") from e

        file_actions = preflight.get("fileActions") or preflight.get("file_actions") if isinstance(preflight, dict) else None
        if not file_actions:
            raise DemistoException(f"Unexpected preflight response: {preflight}")

        action_obj = file_actions[0] or {}
        action = action_obj.get("action")

        md = "### Stairwell Intake — Preflight\n"
        md += f"Asset ID: {asset_id}\nFile: {filename}\n"
        md += f"Source: Entry ID {entry_id}\n" if entry_id else f"Source: URL {url}\n"
        md += f"Action: {action}\n"

        if action == "NO_ACTION_ALREADY_EXISTS":
            md += "\nFile already exists in Stairwell. No upload needed."
            return CommandResults(
                readable_output=md,
                outputs_prefix="Stairwell.Intake",
                outputs={"sha256": sha256, "preflight": preflight, "result": "already_exists"},
                raw_response=preflight,
            )

        if action != "UPLOAD":
            raise DemistoException(f"Unrecognized preflight action {action!r}: {preflight}")

        upload_url = action_obj.get("uploadUrl") or action_obj.get("upload_url")
        fields = action_obj.get("fields", {})
        file_field_name = action_obj.get("fileField", "file")
        if not upload_url or not fields:
            raise DemistoException("Preflight requested UPLOAD but returned no uploadUrl/fields.")

        proxies = handle_proxy() if use_proxy else None
        upload_session = _create_session_with_retries()
        try:
            with open(file_path, "rb") as fh:
                upload_resp = upload_session.post(
                    upload_url,
                    data=list(fields.items()),
                    files={file_field_name: (filename, fh)},
                    verify=verify,
                    proxies=proxies,
                    timeout=UPLOAD_TIMEOUT,
                )
        except requests.exceptions.Timeout as e:
            raise DemistoException(
                f"File upload timed out after {UPLOAD_TIMEOUT}s. Contact Stairwell admin if this persists."
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise DemistoException(f"Connection error during file upload: {e}. Check network connectivity.") from e

        if upload_resp.status_code not in (200, 201, 202, 204):
            raise DemistoException(f"Upload failed with status {upload_resp.status_code}: {upload_resp.text}")

        md += "\nUpload completed successfully."
        return CommandResults(
            readable_output=md,
            outputs_prefix="Stairwell.Intake",
            outputs={"sha256": sha256, "preflight": preflight, "result": "uploaded", "upload_status": upload_resp.status_code},
            raw_response=preflight,
        )
    finally:
        if is_temp:
            _remove_temp_file(file_path)


# YARA Rules Command Functions
def yara_create_rule_command(client: Client, environment: str, rule_definition: str) -> CommandResults:
    """Create a new YARA rule."""
    _require_args({"environment": environment, "rule_definition": rule_definition})

    try:
        response = client.create_yara_rule(environment, rule_definition)
        readable = tableToMarkdown("Created YARA Rule", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.YaraRule", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(readable_output="Invalid YARA rule definition. Check syntax and formatting of the rule.")
        elif _status_code(err) == 403:
            return CommandResults(
                readable_output=f"Permission denied to create YARA rule in environment: {environment}. Check API key permissions."
            )
        else:
            raise DemistoException(f"Failed to create YARA rule in environment '{environment}': {err}") from err


def yara_get_rule_command(
    client: Client, environment: str, yara_rule: str, match_count_envs: str | None = None
) -> CommandResults:
    """Get a specific YARA rule."""
    _require_args({"environment": environment, "yara_rule": yara_rule})

    try:
        response = client.get_yara_rule(environment, yara_rule, match_count_envs)
        readable = tableToMarkdown(f"YARA Rule: {yara_rule}", response) if isinstance(response, dict) else str(response)
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.YaraRule", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"YARA rule not found: {yara_rule}")
        else:
            raise err


def yara_query_matches_command(
    client: Client,
    environment: str,
    yara_rule: str,
    included_environments: str | None = None,
    page_size: str | None = None,
    page_token: str | None = None,
) -> CommandResults:
    """Query objects matching a YARA rule."""
    _require_args({"environment": environment, "yara_rule": yara_rule})

    try:
        included_envs_list = [e.strip() for e in included_environments.split(",")] if included_environments else None
        page_size_int = _parse_int_arg(page_size, "pageSize")
        response = client.query_yara_matches(environment, yara_rule, included_envs_list, page_size_int, page_token)
        matches = response.get("objects", []) if isinstance(response, dict) else []
        readable = (
            tableToMarkdown(f"YARA Rule Matches: {yara_rule}", matches)
            if matches
            else f"No matches found for YARA rule: {yara_rule}"
        )
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.YaraRuleMatches", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"YARA rule not found: {yara_rule}")
        else:
            raise err


# Asset Management Command Functions
def asset_list_command(
    client: Client, environment: str, page_size: str | None = None, page_token: str | None = None
) -> CommandResults:
    """List all assets in an environment."""
    _require_args({"environment": environment})

    try:
        page_size_int = _parse_int_arg(page_size, "pageSize")
        response = client.list_assets(environment, page_size_int, page_token)
        assets = response.get("assets", []) if isinstance(response, dict) else []
        readable = tableToMarkdown("Assets", assets) if assets else "No assets found."
        return CommandResults(readable_output=readable, outputs_prefix="Stairwell.Assets", outputs=response)
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Environment not found: {environment}")
        else:
            raise err


def asset_create_command(
    client: Client,
    environment: str,
    label: str,
    idempotency_key: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    forwarder_version: str | None = None,
) -> CommandResults:
    """Create a new asset in an environment. The asset's upload token is not returned."""
    _require_args({"environment": environment, "label": label})

    try:
        response = client.create_asset(environment, label, idempotency_key, os_name, os_version, forwarder_version)
        asset = _strip_asset_secrets(response)
        readable = tableToMarkdown("Created Asset", asset) if isinstance(asset, dict) else str(asset)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Asset", outputs_key_field="name", outputs=asset
        )
    except DemistoException as err:
        if _status_code(err) == 400:
            return CommandResults(
                readable_output="Invalid asset parameters. Check that label and other fields are properly formatted."
            )
        elif _status_code(err) == 403:
            return CommandResults(
                readable_output=f"Permission denied to create asset in environment: {environment}. Check API key permissions."
            )
        elif _status_code(err) == 409:
            return CommandResults(
                readable_output=f"Asset with label '{label}' may already exist. Try a different label or check existing assets."
            )
        else:
            raise DemistoException(f"Failed to create asset in environment '{environment}': {err}") from err


def asset_get_command(client: Client, asset: str) -> CommandResults:
    """Get a specific asset by ID."""
    _require_args({"asset": asset})

    try:
        response = _strip_asset_secrets(client.get_asset(asset))
        readable = tableToMarkdown(f"Asset: {asset}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable, outputs_prefix="Stairwell.Asset", outputs_key_field="name", outputs=response
        )
    except DemistoException as err:
        if _status_code(err) == 404:
            return CommandResults(readable_output=f"Asset not found: {asset}")
        else:
            raise err


# --------------------------------
# Reputation commands: file, ip, domain
# --------------------------------
def _optional_lookup(what: str, fn: Any, *args: Any) -> dict[str, Any] | None:
    """
    Run a lookup that adds detail to a reputation result but is not the result itself.

    A failure is logged and the detail is left out; the indicator is still returned
    from the lookup that defines it.
    """
    try:
        response = fn(*args)
    except DemistoException as err:
        demisto.debug(f"Stairwell {what} lookup failed: {err}")
        return None
    return response if isinstance(response, dict) else None


def _not_found(err: DemistoException) -> bool:
    return _status_code(err) == 404


def _mal_eval_score(mal_eval: dict[str, Any]) -> tuple[int, str | None]:
    """
    Map a MalEval verdict to a DBotScore.

    PROBABILITY_VERY_HIGH and PROBABILITY_HIGH are malicious; PROBABILITY_MEDIUM is
    suspicious; PROBABILITY_LOW is good; no bucket is unknown. Returns the score and,
    for a malicious score, the description shown as File.Malicious.Description.
    """
    bucket = mal_eval.get("probabilityBucket") or mal_eval.get("probability_bucket")
    score = MAL_EVAL_SCORES.get(bucket or "", Common.DBotScore.NONE)
    if score != Common.DBotScore.BAD:
        return score, None
    parts = [f"Stairwell MalEval verdict {bucket}"]
    if mal_eval.get("severity"):
        parts.append(f"severity {mal_eval['severity']}")
    labels = mal_eval.get("labels")
    if isinstance(labels, list) and labels:
        parts.append("labels " + ", ".join(str(label) for label in labels))
    return score, "; ".join(parts)


def _unknown_indicator(indicator: str, indicator_type: str, reliability: str) -> Common.DBotScore:
    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        integration_name=VENDOR_NAME,
        score=Common.DBotScore.NONE,
        reliability=reliability,
    )


def file_command(client: Client, file: str, reliability: str) -> list[CommandResults]:
    """Reputation for one or more file hashes from Stairwell object metadata and its MalEval verdict."""
    hashes = argToList(file)
    _require_args({"file": hashes})
    results: list[CommandResults] = []
    for file_hash in hashes:
        try:
            metadata = client.get_object_metadata(file_hash)
        except DemistoException as err:
            if not _not_found(err):
                raise
            results.append(
                CommandResults(
                    readable_output=f"### Stairwell\nFile not found: {file_hash}",
                    indicator=Common.File(dbot_score=_unknown_indicator(file_hash, DBotScoreType.FILE, reliability)),
                )
            )
            continue
        if not isinstance(metadata, dict):
            raise DemistoException(f"Unexpected object metadata response for {file_hash}: {metadata}")

        mal_eval = metadata.get("malEval") if isinstance(metadata.get("malEval"), dict) else {}
        score, malicious_description = _mal_eval_score(mal_eval)
        yara_rules = [r for r in metadata.get("yaraRuleMatches") or [] if isinstance(r, str) and r]
        sha256 = metadata.get("sha256") or (file_hash if len(file_hash) == 64 else None)
        size = arg_to_number(metadata.get("size"))

        dbot_score = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=score,
            reliability=reliability,
            malicious_description=malicious_description,
        )
        indicator = Common.File(
            dbot_score=dbot_score,
            md5=metadata.get("md5"),
            sha1=metadata.get("sha1"),
            sha256=sha256,
            size=size,
            name=metadata.get("name"),
            file_type=metadata.get("mimeType") or metadata.get("magic"),
            imphash=metadata.get("imphash"),
            ssdeep=metadata.get("ssdeep"),
            tags=yara_rules or None,
            first_seen_by_source=metadata.get("stairwellFirstSeenTime"),
        )
        outputs = {
            "sha256": sha256,
            "md5": metadata.get("md5"),
            "sha1": metadata.get("sha1"),
            "name": metadata.get("name"),
            "size": size,
            "mimeType": metadata.get("mimeType"),
            "magic": metadata.get("magic"),
            "malEval": {
                "probabilityBucket": mal_eval.get("probabilityBucket"),
                "severity": mal_eval.get("severity"),
                "labels": mal_eval.get("labels"),
            },
            "yaraRuleMatches": yara_rules,
            "stairwellFirstSeenTime": metadata.get("stairwellFirstSeenTime"),
            "networkIndicators": metadata.get("networkIndicators"),
        }
        table = {
            "SHA256": sha256,
            "MD5": metadata.get("md5"),
            "Name": metadata.get("name"),
            "Size": size,
            "Type": metadata.get("mimeType") or metadata.get("magic"),
            "MalEval": mal_eval.get("probabilityBucket"),
            "Severity": mal_eval.get("severity"),
            "YARA": ", ".join(yara_rules),
            "Score": score,
        }
        results.append(
            CommandResults(
                readable_output=tableToMarkdown(f"Stairwell file reputation: {file_hash}", table, removeNull=True),
                outputs_prefix="Stairwell.File",
                outputs_key_field="sha256",
                outputs=outputs,
                indicator=indicator,
                raw_response=metadata,
            )
        )
    return results


def _whois_org_name(whois: dict[str, Any] | None) -> str | None:
    """The holder of an IP's address prefix from a /v2/ips/{ip}/whois response."""
    record = whois.get("record") if isinstance(whois, dict) else None
    if not isinstance(record, dict):
        return None
    for path in (("arinOrg", "name"), ("rpslOrganization", "orgName"), ("rpslInetnum", "netname"), ("rpslInet6num", "netname")):
        value: Any = record
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if value:
            return str(value)
    return None


def ip_command(client: Client, ip: str, reliability: str) -> list[CommandResults]:
    """
    Enrichment for one or more IP addresses from Stairwell network intelligence.

    Stairwell holds no verdict for an IP, so the DBotScore is always Unknown; the
    value is the ASN, geolocation, cloud-provider and reverse-DNS context.
    """
    ips = argToList(ip)
    _require_args({"ip": ips})
    results: list[CommandResults] = []
    for ip_address in ips:
        try:
            ip_data = client.get_ip_address(ip_address)
        except DemistoException as err:
            if not _not_found(err):
                raise
            results.append(
                CommandResults(
                    readable_output=f"### Stairwell\nIP address not found: {ip_address}",
                    indicator=Common.IP(ip=ip_address, dbot_score=_unknown_indicator(ip_address, DBotScoreType.IP, reliability)),
                )
            )
            continue
        if not isinstance(ip_data, dict):
            raise DemistoException(f"Unexpected IP response for {ip_address}: {ip_data}")

        whois = _optional_lookup("IP whois", client.get_ip_address_whois, ip_address)
        hosts = _optional_lookup("IP hostnames", client.get_hostnames_resolving_to_ip, ip_address)

        asns = [a for a in ip_data.get("asns") or [] if isinstance(a, int)]
        geo = ip_data.get("geoLocation") if isinstance(ip_data.get("geoLocation"), dict) else {}
        hostnames: list[str] = []
        for entry in (hosts or {}).get("hostnames") or []:
            name = entry.get("canonicalHostname") or entry.get("hostname") if isinstance(entry, dict) else entry
            if isinstance(name, str) and name:
                hostnames.append(name)
        cloud_provider = ip_data.get("cloudProvider")
        if cloud_provider == "CLOUD_PROVIDER_UNSPECIFIED":
            cloud_provider = None
        tags = [f"stairwell:cloud-{str(cloud_provider).lower()}"] if cloud_provider else []
        if ip_data.get("isDatacenter"):
            tags.append("stairwell:datacenter")
        if ip_data.get("isVpn"):
            tags.append("stairwell:vpn")
        location = ", ".join(str(v) for v in (geo.get("city"), geo.get("region")) if v)

        indicator = Common.IP(
            ip=ip_address,
            dbot_score=_unknown_indicator(ip_address, DBotScoreType.IP, reliability),
            asn=str(asns[0]) if asns else None,
            as_owner=_whois_org_name(whois),
            geo_country=geo.get("country"),
            geo_description=location or None,
            hostname=hostnames[0] if hostnames else None,
            tags=tags or None,
        )
        outputs = {
            "ip": ip_address,
            "asns": asns,
            "cloudProvider": cloud_provider,
            "isDatacenter": ip_data.get("isDatacenter"),
            "isVpn": ip_data.get("isVpn"),
            "geoLocation": geo,
            "subnetInfo": ip_data.get("subnetInfo"),
            "whoisOrganization": _whois_org_name(whois),
            "hostnames": hostnames,
        }
        table = {
            "IP": ip_address,
            "ASN": asns[0] if asns else None,
            "Organization": _whois_org_name(whois),
            "Country": geo.get("country"),
            "Location": location,
            "Cloud provider": cloud_provider,
            "Reverse DNS": ", ".join(hostnames[:5]),
        }
        results.append(
            CommandResults(
                readable_output=tableToMarkdown(f"Stairwell IP intelligence: {ip_address}", table, removeNull=True),
                outputs_prefix="Stairwell.IP",
                outputs_key_field="ip",
                outputs=outputs,
                indicator=indicator,
                raw_response={"ip": ip_data, "whois": whois, "hostnames": hosts},
            )
        )
    return results


def _normalized_resolutions(blob: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in (blob or {}).get("resolutions") or []:
        if not isinstance(entry, dict):
            continue
        record_type = str(entry.get("recordType") or "A").upper()
        answer = entry.get("answer")
        if not answer or (record_type, str(answer)) in seen:
            continue
        seen.add((record_type, str(answer)))
        out.append(
            {
                "recordType": record_type,
                "answer": str(answer),
                "firstSeen": entry.get("firstSeen"),
                "lastSeen": entry.get("lastSeen"),
                "observationCount": entry.get("observationCount"),
            }
        )
    return out


def domain_command(client: Client, domain: str, reliability: str) -> list[CommandResults]:
    """
    Enrichment for one or more domains from Stairwell hostname intelligence.

    A hostname on Stairwell's whitelist scores Good; any other scores Unknown, as
    Stairwell holds no malicious verdict for a hostname.
    """
    domains = argToList(domain)
    _require_args({"domain": domains})
    results: list[CommandResults] = []
    for hostname in domains:
        try:
            host_data = client.get_hostname(hostname)
        except DemistoException as err:
            if not _not_found(err):
                raise
            results.append(
                CommandResults(
                    readable_output=f"### Stairwell\nHostname not found: {hostname}",
                    indicator=Common.Domain(
                        domain=hostname, dbot_score=_unknown_indicator(hostname, DBotScoreType.DOMAIN, reliability)
                    ),
                )
            )
            continue
        if not isinstance(host_data, dict):
            raise DemistoException(f"Unexpected hostname response for {hostname}: {host_data}")

        whitelist = _optional_lookup("hostname whitelist", client.get_hostname_whitelist_status, hostname)
        resolutions_blob = _optional_lookup("hostname resolutions", client.get_hostname_resolutions, hostname)

        whitelisted = False
        for blob in (whitelist, host_data):
            if isinstance(blob, dict) and isinstance(blob.get("whitelisted"), bool):
                whitelisted = blob["whitelisted"]
                break
        resolutions = _normalized_resolutions(resolutions_blob) or _normalized_resolutions(host_data)
        a_records = [r["answer"] for r in resolutions if r["recordType"] in ("A", "AAAA")]
        etld = host_data.get("etldPlusOne") or (resolutions_blob or {}).get("etldPlusOne")

        indicator = Common.Domain(
            domain=hostname,
            dbot_score=Common.DBotScore(
                indicator=hostname,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=VENDOR_NAME,
                score=Common.DBotScore.GOOD if whitelisted else Common.DBotScore.NONE,
                reliability=reliability,
            ),
            dns=", ".join(a_records) or None,
            tags=["stairwell:whitelisted"] if whitelisted else None,
        )
        outputs = {
            "hostname": hostname,
            "etldPlusOne": etld,
            "whitelisted": whitelisted,
            "resolutions": resolutions,
        }
        table = {
            "Hostname": hostname,
            "eTLD+1": etld,
            "Whitelisted": whitelisted,
            "Resolutions": len(resolutions),
            "A/AAAA": ", ".join(a_records[:10]),
        }
        results.append(
            CommandResults(
                readable_output=tableToMarkdown(f"Stairwell hostname intelligence: {hostname}", table, removeNull=True),
                outputs_prefix="Stairwell.Domain",
                outputs_key_field="hostname",
                outputs=outputs,
                indicator=indicator,
                raw_response={"hostname": host_data, "whitelist": whitelist, "resolutions": resolutions_blob},
            )
        )
    return results


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("apikey", {}).get("password")
    reliability = params.get("integrationReliability") or DBotScoreReliability.A
    if not DBotScoreReliability.is_valid_type(reliability):
        raise DemistoException(f"Invalid Source Reliability setting: {reliability}")

    # Params enabled by XSOAR functionality
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    if not verify_certificate:
        urllib3.disable_warnings()  # pylint: disable=no-member

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(api_key=api_key, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client))
            return

        reputation_commands: dict[str, tuple[Any, str]] = {
            "file": (file_command, "file"),
            "ip": (ip_command, "ip"),
            "domain": (domain_command, "domain"),
        }
        if command in reputation_commands:
            handler, arg_name = reputation_commands[command]
            return_results(handler(client, args.get(arg_name), reliability))
            return

        if command == "stairwell-intake-upload":
            # Uses preflight and conditionally uploads
            result = intake_preflight_and_upload(
                client=client,
                asset_id=args.get("asset_id"),
                entry_id=args.get("entry_id"),
                url=args.get("url"),
                sha256=args.get("sha256"),
                origin_type=args.get("origin_type"),
                origin_referrer_url=args.get("origin_referrer_url"),
                origin_host_url=args.get("origin_host_url"),
                origin_zone_id=_parse_int_arg(args.get("origin_zone_id"), "origin_zone_id"),
                verify=verify_certificate,
                use_proxy=proxy,
            )
            return_results(result)
            return

        # command name -> (handler, argument names in handler order)
        commands: dict[str, tuple[Any, list[str]]] = {
            "stairwell-file-enrichment": (file_enrichment_command, ["file_hash"]),
            "stairwell-variant-discovery": (variant_discovery_command, ["sha256"]),
            "stairwell-ai-triage-summarize": (ai_triage_summarize_command, ["object_id"]),
            "stairwell-object-sightings": (object_sightings_command, ["object_id"]),
            "stairwell-object-opinions": (object_opinions_command, ["object_id"]),
            "stairwell-run-to-ground-generate": (run_to_ground_generate_command, ["object_ids"]),
            # Network Intel
            "stairwell-asn-get-whois": (asn_get_whois_command, ["asn"]),
            "stairwell-hostname-get": (hostname_get_command, ["hostname", "record_type"]),
            "stairwell-hostname-get-resolutions": (hostname_get_resolutions_command, ["hostname", "start_time", "end_time"]),
            "stairwell-hostname-batch-get-resolutions": (
                hostname_batch_get_resolutions_command,
                ["hostnames", "start_time", "end_time", "record_types", "include_errors"],
            ),
            "stairwell-ipaddress-get": (ipaddress_get_command, ["ip_address"]),
            "stairwell-ipaddress-lookup-cloud-provider": (ipaddress_lookup_cloud_provider_command, ["ip_address"]),
            "stairwell-ipaddress-get-hostnames-resolving-to-ip": (
                ipaddress_get_hostnames_resolving_to_ip_command,
                ["ip_address", "start_time", "end_time"],
            ),
            "stairwell-ipaddress-get-whois": (ipaddress_get_whois_command, ["ip_address"]),
            "stairwell-utilities-get-cloud-ip-ranges": (utilities_get_cloud_ip_ranges_command, ["provider"]),
            "stairwell-utilities-batch-canonicalize-hostnames": (utilities_batch_canonicalize_hostnames_command, ["hostnames"]),
            "stairwell-utilities-batch-compute-etld-plus-one": (utilities_batch_compute_etld_plus_one_command, ["domains"]),
            "stairwell-utilities-canonicalize-hostname": (utilities_canonicalize_hostname_command, ["hostname"]),
            "stairwell-utilities-compute-etld-plus-one": (utilities_compute_etld_plus_one_command, ["domain"]),
            "stairwell-utilities-batch-canonicalize-urls": (utilities_batch_canonicalize_urls_command, ["urls"]),
            "stairwell-utilities-canonicalize-url": (utilities_canonicalize_url_command, ["url"]),
            # YARA
            "stairwell-yara-create-rule": (yara_create_rule_command, ["environment", "rule_definition"]),
            "stairwell-yara-get-rule": (yara_get_rule_command, ["environment", "yara_rule", "match_count_envs"]),
            "stairwell-yara-query-matches": (
                yara_query_matches_command,
                ["environment", "yara_rule", "included_environments", "page_size", "page_token"],
            ),
            # Assets
            "stairwell-asset-list": (asset_list_command, ["environment", "page_size", "page_token"]),
            "stairwell-asset-create": (
                asset_create_command,
                ["environment", "label", "idempotency_key", "os", "os_version", "forwarder_version"],
            ),
            "stairwell-asset-get": (asset_get_command, ["asset"]),
        }

        if command not in commands:
            raise NotImplementedError(f"command {command} is not implemented.")

        handler, arg_names = commands[command]
        return_results(handler(client, *[args.get(name) for name in arg_names]))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join((f"Failed to execute {command} command.", "Error:", str(e))))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
