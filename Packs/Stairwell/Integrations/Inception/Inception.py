''' IMPORTS '''
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import urllib3
import urllib.parse
import requests  # type: ignore[import]
from requests.adapters import HTTPAdapter  # type: ignore[import]
from urllib3.util.retry import Retry
import os
import tempfile
import traceback
import hashlib
from typing import Optional, Dict, Any, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
REPUTATION_BASE_URL = "https://reputation.app.stairwell.com/api/v3/files/"
VARIANTS_BASE_URL = "https://app.stairwell.com/v202112/variants/"
INTAKE_PREFLIGHT_URL = "https://http.intake.app.stairwell.com/v2021.05/upload"
AI_TRIAGE_BASE_URL = "https://app.stairwell.com/v1/objects/"
V1_BASE_URL = "https://app.stairwell.com/v1/"
V2_BASE_URL = "https://app.stairwell.com/v2/"
NETWORK_INTEL_BASE_URL = "https://app.stairwell.com/v1/network/"

HTTP_TIMEOUT = 120        # seconds for API calls
UPLOAD_TIMEOUT = 600      # seconds for GCS upload
RETRY_COUNT = 3
RETRY_BACKOFF_FACTOR = 1.5  # exponential backoff factor

# HTTP Error Code Mappings for User-Friendly Messages
HTTP_ERROR_MESSAGES = {
    400: "Bad request. Check command parameters - one or more values may be invalid or incorrectly formatted.",
    401: "Authentication failed. Check your API Key in the integration configuration.",
    403: "Permission denied. Your API Key does not have permission for this operation.",
    404: "Resource not found. The requested {resource_type} does not exist or may have been deleted.",
    429: "Rate limit exceeded. Too many requests to Stairwell API. Please wait and try again.",
    500: "Internal server error. Stairwell API is experiencing issues. Try again later.",
    502: "Bad gateway. Unable to reach Stairwell API servers.",
    503: "Service unavailable. Stairwell API is temporarily down for maintenance.",
    504: "Gateway timeout. Stairwell API took too long to respond."
}


def get_http_error_message(status_code: int, resource_type: str = "resource", custom_context: str = "") -> str:
    """Get user-friendly error message for HTTP status code."""
    base_message = HTTP_ERROR_MESSAGES.get(status_code, f"Request failed with status {status_code}")
    message = base_message.replace("{resource_type}", resource_type)
    if custom_context:
        message = f"{message} {custom_context}"
    return message


# --------------------------------
# Helpers
# --------------------------------
def _require_args(required: Dict[str, Optional[str]]) -> Optional[CommandResults]:
    missing = [k for k, v in required.items() if not v]
    if missing:
        return CommandResults(
            readable_output=f"Missing required arguments: {', '.join(missing)}"
        )
    return None


def _parse_int_arg(value: Optional[str], param_name: str, allow_negative: bool = False) -> Optional[int]:
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
            raise DemistoException(
                f"Invalid {param_name} parameter: '{value}'. Must be a positive integer."
            )
        return parsed
    except ValueError:
        raise DemistoException(
            f"Invalid {param_name} parameter: '{value}'. Must be an integer."
        )


def _hash_sha256(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (sha256_hex, error_str)"""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return None, f"Failed computing sha256 for {file_path}: {e}"


def _create_session_with_retries(max_retries: int = RETRY_COUNT, backoff_factor: float = RETRY_BACKOFF_FACTOR) -> requests.Session:
    """
    Create a requests Session with retry logic for 5xx and 429 status codes.
    Uses urllib3's Retry mechanism instead of sleep to comply with XSOAR best practices.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504, 429],
        allowed_methods=["POST", "GET", "PUT", "DELETE"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _resolve_file_source(entry_id: Optional[str] = None,
                         url: Optional[str] = None,
                         file_path: Optional[str] = None,
                         verify: bool = True,
                         use_proxy: bool = False) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Resolve file source from one of three methods: entryID, url, or filePath.

    Args:
        entry_id: XSOAR War Room entry ID
        url: HTTP/HTTPS URL to download file from
        file_path: Direct file path
        verify: SSL verification for URL downloads
        use_proxy: Use proxy for URL downloads

    Returns:
        Tuple of (resolved_path, filename, error_message)
        - On success: (path_string, filename_string, None)
        - On error: (None, None, error_string)
    """
    # Count how many sources were provided
    sources_provided = sum([
        entry_id is not None,
        url is not None,
        file_path is not None
    ])

    # Validate exactly one source is provided
    if sources_provided == 0:
        return None, None, "Missing file source: provide one of entryID, url, or filePath"

    if sources_provided > 1:
        return None, None, "Multiple file sources provided: provide only one of entryID, url, or filePath"

    # Handle entryID resolution
    if entry_id:
        try:
            file_info = demisto.getFilePath(entry_id)
            if not isinstance(file_info, dict):
                return None, None, f"Failed to resolve entry ID {entry_id}: invalid response from getFilePath"

            resolved_path = file_info.get('path')
            filename = file_info.get('name', 'unknown')

            if not resolved_path:
                return None, None, f"Failed to resolve entry ID {entry_id}: no path in response"

            if not os.path.exists(resolved_path):
                return None, None, f"Failed to resolve entry ID {entry_id}: file not found at {resolved_path}"

            return resolved_path, filename, None

        except Exception as e:
            return None, None, f"Failed to resolve entry ID {entry_id}: {e}"

    # Handle URL download
    if url:
        try:
            # Validate URL scheme
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.scheme not in ['http', 'https']:
                return None, None, f"Invalid URL scheme: only http and https are supported (got: {parsed_url.scheme})"

            # Extract filename from URL
            url_path = parsed_url.path
            filename = os.path.basename(url_path) if url_path else 'downloaded_file'
            if not filename or filename == '/':
                filename = 'downloaded_file'

            # Download file to temp location
            session = _create_session_with_retries()
            proxies = handle_proxy() if use_proxy else None

            try:
                response = session.get(url, verify=verify, proxies=proxies, stream=True, timeout=HTTP_TIMEOUT)
                response.raise_for_status()
            except requests.exceptions.Timeout:
                return None, None, f"Timeout downloading file from URL {url} after {HTTP_TIMEOUT} seconds. Check network connectivity or try again later."
            except requests.exceptions.ConnectionError as e:
                return None, None, f"Connection error downloading from URL {url}: {e}. Check URL and network connectivity."
            except requests.exceptions.RequestException as e:
                return None, None, f"Failed to download from URL {url}: {e}"

            # Create temp file (delete=False so we can use it after closing)
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}")
            temp_path = temp_file.name

            try:
                # Download in chunks
                for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
                    if chunk:
                        temp_file.write(chunk)
                temp_file.close()

                return temp_path, filename, None

            except Exception as write_error:
                temp_file.close()
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                raise write_error

        except Exception as e:
            return None, None, f"Failed to download from URL {url}: {e}"

    # Handle direct file path
    if file_path:
        try:
            if not os.path.exists(file_path):
                return None, None, f"File not found at path: {file_path}"

            filename = os.path.basename(file_path) or 'unknown'
            return file_path, filename, None

        except Exception as e:
            return None, None, f"Failed to access file at {file_path}: {e}"

    # Should never reach here due to validation above
    return None, None, "Unexpected error in file source resolution"


class Client(BaseClient):
    def get_file_reputation(self, file_hash: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=file_hash,
            timeout=HTTP_TIMEOUT
        )

    def get_file_variants(self, file_hash: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=file_hash,
            timeout=HTTP_TIMEOUT
        )

    def summarize_file(self, object_id: str) -> Dict[str, Any]:
        """Get AI-generated summary for a file object."""
        return self._http_request(
            method='GET',
            url_suffix=f"{object_id}:summarize",
            timeout=HTTP_TIMEOUT
        )

    def list_object_sightings(self, object_id: str) -> Dict[str, Any]:
        """List sightings for a given object."""
        return self._http_request(
            method='GET',
            url_suffix=f"{object_id}/sightings",
            timeout=HTTP_TIMEOUT
        )

    def trigger_object_detonation(self, object_id: str) -> Dict[str, Any]:
        """Trigger detonation for an object."""
        return self._http_request(
            method='POST',
            url_suffix=f"{object_id}/detonation:trigger",
            timeout=HTTP_TIMEOUT
        )

    def get_object_detonation(self, object_id: str) -> Dict[str, Any]:
        """Get detonation details for an object."""
        return self._http_request(
            method='GET',
            url_suffix=f"{object_id}/detonation",
            timeout=HTTP_TIMEOUT
        )

    def list_object_opinions(self, object_id: str) -> Dict[str, Any]:
        """List opinions for an object."""
        return self._http_request(
            method='GET',
            url_suffix=f"{object_id}/opinions",
            timeout=HTTP_TIMEOUT
        )

    def generate_run_to_ground(self, object_ids: List[str]) -> Dict[str, Any]:
        """Generate Run-To-Ground analysis for objects."""
        # API expects objectIds parameter (can be repeated for multiple objects)
        params = {"objectIds": object_ids}
        return self._http_request(
            method='GET',
            url_suffix="generateRunToGround:generate",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    # Network Intel API Methods - ASN
    def get_asn_whois(self, asn: str) -> Dict[str, Any]:
        """Get ASN WHOIS information."""
        return self._http_request(
            method='GET',
            url_suffix=f"asns/{asn}/whois",
            timeout=HTTP_TIMEOUT
        )

    # Network Intel API Methods - Hostname
    def get_hostname(self, hostname: str, record_type: Optional[str] = None) -> Dict[str, Any]:
        """Get hostname entity with DNS resolution data."""
        params: Dict[str, Any] = {}
        if record_type:
            params["recordTypes"] = record_type
        return self._http_request(
            method='GET',
            url_suffix=f"hostnames/{hostname}",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def get_hostname_resolutions(self, hostname: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, Any]:
        """Get all addresses resolved to by a hostname over a time range."""
        params: Dict[str, Any] = {}
        if start_time:
            params["interval.startTime"] = start_time
        if end_time:
            params["interval.endTime"] = end_time
        return self._http_request(
            method='GET',
            url_suffix=f"hostnames/{hostname}/resolutions",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def batch_get_hostname_resolutions(self, hostnames: List[str], start_time: Optional[str] = None, end_time: Optional[str] = None,
                                      record_types: Optional[List[str]] = None, include_errors: Optional[bool] = None) -> Dict[str, Any]:
        """Get resolution summaries for multiple hostnames."""
        json_data: Dict[str, Any] = {"hostnames": hostnames}

        # Add interval if provided
        if start_time or end_time:
            interval: Dict[str, str] = {}
            if start_time:
                interval["startTime"] = start_time
            if end_time:
                interval["endTime"] = end_time
            json_data["interval"] = interval

        # Add recordTypes if provided
        if record_types:
            json_data["recordTypes"] = record_types

        # Add includeErrors if provided
        if include_errors is not None:
            json_data["includeErrors"] = include_errors

        return self._http_request(
            method='POST',
            url_suffix="hostnames:batch-resolutions",
            json_data=json_data,
            timeout=HTTP_TIMEOUT
        )

    # Network Intel API Methods - IP Address
    def get_ip_address(self, ip_address: str) -> Dict[str, Any]:
        """Get IP address entity with enrichment data."""
        return self._http_request(
            method='GET',
            url_suffix=f"ips/{ip_address}",
            timeout=HTTP_TIMEOUT
        )

    def lookup_cloud_provider(self, ip_address: str) -> Dict[str, Any]:
        """Check if an IP address belongs to a known cloud provider."""
        return self._http_request(
            method='GET',
            url_suffix=f"ips/{ip_address}/provider",
            timeout=HTTP_TIMEOUT
        )

    def get_hostnames_resolving_to_ip(self, ip_address: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, Any]:
        """Get all hostnames resolved to by an IP over a time interval."""
        params: Dict[str, Any] = {}
        if start_time:
            params["interval.startTime"] = start_time
        if end_time:
            params["interval.endTime"] = end_time
        return self._http_request(
            method='GET',
            url_suffix=f"ips/{ip_address}/hostnames",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def get_ip_address_whois(self, ip_address: str) -> Dict[str, Any]:
        """Get WHOIS information for an IP address."""
        return self._http_request(
            method='GET',
            url_suffix=f"ips/{ip_address}/whois",
            timeout=HTTP_TIMEOUT
        )

    # Network Intel API Methods - Utilities
    def get_cloud_ip_ranges(self, provider: Optional[str] = None) -> Dict[str, Any]:
        """Get IP ranges for known cloud providers."""
        # v2 API uses a different path structure: providers/{providers}/ip-ranges
        # If no provider specified, use empty string to get all
        provider_path = provider if provider else ""
        return self._http_request(
            method='GET',
            url_suffix=f"providers/{provider_path}/ip-ranges" if provider_path else "providers/ip-ranges",
            timeout=HTTP_TIMEOUT
        )

    def batch_canonicalize_hostnames(self, hostnames: List[str]) -> Dict[str, Any]:
        """Canonicalize multiple hostnames in bulk."""
        return self._http_request(
            method='POST',
            url_suffix="utilities/hostnames:batch-canonicalize",
            json_data={"hostnames": hostnames},
            timeout=HTTP_TIMEOUT
        )

    def batch_compute_etld_plus_one(self, domains: List[str]) -> Dict[str, Any]:
        """Compute effective top-level domain plus one for multiple domains."""
        return self._http_request(
            method='POST',
            url_suffix="utilities/hostnames:batch-etld-plus-one",
            json_data={"domains": domains},
            timeout=HTTP_TIMEOUT
        )

    def canonicalize_hostname(self, hostname: str) -> Dict[str, Any]:
        """Canonicalize a single hostname."""
        return self._http_request(
            method='GET',
            url_suffix=f"utilities/hostnames:canonicalize/{hostname}",
            timeout=HTTP_TIMEOUT
        )

    def compute_etld_plus_one(self, domain: str) -> Dict[str, Any]:
        """Compute effective top-level domain plus one for a single domain."""
        return self._http_request(
            method='GET',
            url_suffix=f"utilities/hostnames:etld-plus-one/{domain}",
            timeout=HTTP_TIMEOUT
        )

    def batch_canonicalize_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Canonicalize multiple URLs in bulk."""
        return self._http_request(
            method='POST',
            url_suffix="utilities/urls:batch-canonicalize",
            json_data={"urls": urls},
            timeout=HTTP_TIMEOUT
        )

    def canonicalize_url(self, url: str) -> Dict[str, Any]:
        """Canonicalize a single URL."""
        return self._http_request(
            method='GET',
            url_suffix="utilities/urls:canonicalize",
            params={"url": url},
            timeout=HTTP_TIMEOUT
        )

    # YARA Rules API Methods
    def list_yara_rules(self, environment: str, page_size: Optional[int] = None, page_token: Optional[str] = None) -> Dict[str, Any]:
        """List all YARA rules in an environment."""
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        return self._http_request(
            method='GET',
            url_suffix=f"environments/{environment}/yaraRules",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def create_yara_rule(self, environment: str, rule_definition: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a new YARA rule."""
        json_data: Dict[str, Any] = {"definition": rule_definition}
        if metadata:
            json_data.update(metadata)
        return self._http_request(
            method='POST',
            url_suffix=f"environments/{environment}/yaraRules",
            json_data=json_data,
            timeout=HTTP_TIMEOUT
        )

    def get_yara_rule(self, environment: str, yara_rule: str, match_count_envs: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific YARA rule."""
        params: Dict[str, Any] = {}
        if match_count_envs:
            params["matchCountEnvs"] = match_count_envs
        return self._http_request(
            method='GET',
            url_suffix=f"environments/{environment}/yaraRules/{yara_rule}",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def delete_yara_rule(self, environment: str, yara_rule: str, force: bool = False) -> Dict[str, Any]:
        """Delete a YARA rule."""
        params: Dict[str, Any] = {}
        if force:
            params["force"] = "true"
        return self._http_request(
            method='DELETE',
            url_suffix=f"environments/{environment}/yaraRules/{yara_rule}",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def update_yara_rule(self, environment: str, yara_rule: str, rule_definition: Optional[str] = None,
                        update_mask: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Update a YARA rule."""
        json_data: Dict[str, Any] = {}
        if rule_definition:
            json_data["definition"] = rule_definition
        if metadata:
            json_data.update(metadata)

        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask

        return self._http_request(
            method='PATCH',
            url_suffix=f"environments/{environment}/yaraRules/{yara_rule}",
            json_data=json_data,
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def query_yara_matches(self, environment: str, yara_rule: str, included_environments: Optional[List[str]] = None,
                          page_size: Optional[int] = None, page_token: Optional[str] = None) -> Dict[str, Any]:
        """Query objects matching a YARA rule."""
        params: Dict[str, Any] = {}
        if included_environments:
            params["includedEnvironments"] = included_environments
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        return self._http_request(
            method='GET',
            url_suffix=f"environments/{environment}/yaraRules/{yara_rule}/matchingObjects",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    # Asset Management API Methods
    def list_assets(self, environment: str, page_size: Optional[int] = None, page_token: Optional[str] = None) -> Dict[str, Any]:
        """List all assets in an environment."""
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        return self._http_request(
            method='GET',
            url_suffix=f"environments/{environment}/assets",
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def create_asset(self, environment: str, label: str, idempotency_key: Optional[str] = None,
                    os: Optional[str] = None, os_version: Optional[str] = None,
                    forwarder_version: Optional[str] = None) -> Dict[str, Any]:
        """Create a new asset in an environment."""
        json_data: Dict[str, Any] = {"label": label}

        params: Dict[str, Any] = {}
        if idempotency_key:
            params["idempotencyKey"] = idempotency_key
        if label:
            params["label"] = label
        if os:
            params["os"] = os
        if os_version:
            params["osVersion"] = os_version
        if forwarder_version:
            params["forwarderVersion"] = forwarder_version

        return self._http_request(
            method='POST',
            url_suffix=f"environments/{environment}/assets",
            json_data=json_data,
            params=params,
            timeout=HTTP_TIMEOUT
        )

    def get_asset(self, asset: str) -> Dict[str, Any]:
        """Get a specific asset by ID."""
        return self._http_request(
            method='GET',
            url_suffix=f"assets/{asset}",
            timeout=HTTP_TIMEOUT
        )


def test_module(client):  # pragma: no cover
    try:
        # We'll use a default file hash, accessible by all, to test the connection
        response = client.get_file_reputation("e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d")
        if isinstance(response, dict) and "data" in response:
            data = response.get("data", {})
            if isinstance(data, dict) and "attributes" in data:
                return 'ok'
        return 'Authorization Error: unexpected response format'
    except Exception:
        return 'Authorization Error: make sure API Key is correctly set'


def file_enrichment_command(client: Client, file_hash: str) -> CommandResults:
    missing = _require_args({"fileHash": file_hash})
    if missing:
        return missing
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

        # Seen assets
        stairwell_block = attributes.get("stairwell", {}) or {}
        seen_assets_list = stairwell_block.get("assets") or []
        if isinstance(seen_assets_list, list):
            md += f"Seen Assets: {len(seen_assets_list)}\n"

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
            for key, res in last_analysis_results.items():
                engine_name = res.get("engine_name")
                result = res.get("result")
                if engine_name and result:  # skip empty
                    md += f"{engine_name}|{result}\n"

        # Structured outputs (normalized subset + raw)
        summary = {
            "md5": file_md5,
            "sha256": file_sha256,
            "filenames": names,
            "seen_assets_count": len(seen_assets_list) if isinstance(seen_assets_list, list) else 0,
        }
        outputs = {
            "summary": summary,
            "raw": response
        }

        return CommandResults(
            readable_output=md,
            outputs_prefix='Stairwell.File_Details',
            outputs_key_field='sha256',
            outputs=outputs,
        )

    except DemistoException as err:
        # API will return 404 if the file is not found
        if "404" in str(err):
            return CommandResults(readable_output="File not found: " + file_hash)
        else:
            raise err


def variant_discovery_command(client: Client, file_hash: str) -> CommandResults:
    missing = _require_args({"sha256": file_hash})
    if missing:
        return missing
    try:
        response = client.get_file_variants(file_hash)
        if isinstance(response, dict):
            variants = response.get("variants", [])
            if variants:
                md_string = tableToMarkdown("File Variants Discovered", variants)
                return CommandResults(
                    outputs_prefix='Stairwell.Variants',
                    outputs_key_field='sha256',
                    readable_output=md_string,
                    outputs=response,
                )
            else:
                return CommandResults(readable_output="No variants discovered for: " + file_hash)
        return CommandResults(readable_output="Unexpected response format from variants API.")
    except DemistoException as err:
        # API will return 500 if the file is not found
        if "500" in str(err):
            return CommandResults(readable_output="File not found: " + file_hash)
        else:
            raise err


def ai_triage_summarize_command(client: Client, object_id: str) -> CommandResults:
    """
    Get AI-generated summary for a file using Stairwell AI Triage.
    """
    missing = _require_args({"objectId": object_id})
    if missing:
        return missing
    
    try:
        response = client.summarize_file(object_id)
        
        # Build readable markdown output
        md = "# Stairwell AI Triage Summary\n\n"
        
        if isinstance(response, dict):
            file_hash = response.get("hash", object_id)
            raw_data = response.get("raw", {})
            
            if not raw_data:
                # Fallback if structure is different
                md += "### AI Summary Response\n"
                md += json.dumps(response, indent=2)
                return CommandResults(
                    readable_output=md,
                    outputs_prefix='Stairwell.AI_Triage',
                    outputs={
                        "hash": file_hash,
                        "raw": response
                    }
                )
            
            summary_json = raw_data.get("summaryJson", {})
            tldr = raw_data.get("tldr", summary_json.get("tldr", ""))
            detailed_summary = raw_data.get("summary", "")
            
            # Header with key metrics
            md += f"**File Hash:** {file_hash}\n\n"
            
            if tldr:
                md += f"## TL;DR\n{tldr}\n\n"
            
            # Key metrics from summaryJson
            malicious_likelihood = summary_json.get("malicious_likelihood")
            confidence = summary_json.get("confidence")
            threat_type = summary_json.get("threat_type")
            
            if malicious_likelihood is not None:
                md += f"**Malicious Likelihood:** {malicious_likelihood}%\n"
            if confidence is not None:
                md += f"**Confidence:** {confidence}%\n"
            if threat_type:
                md += f"**Threat Type:** {threat_type}\n"
            md += "\n"
            
            # Summary points
            summary_points = summary_json.get("summary", [])
            if isinstance(summary_points, list) and summary_points:
                md += "## Summary Points\n"
                for point in summary_points:
                    if isinstance(point, str):
                        md += f"- {point}\n"
                md += "\n"
            
            # IOCs
            iocs = summary_json.get("iocs", {})
            if isinstance(iocs, dict):
                md += "## Indicators of Compromise (IOCs)\n"
                
                urls = iocs.get("urls", [])
                if urls:
                    md += "### URLs\n"
                    for url in urls:
                        md += f"- {url}\n"
                    md += "\n"
                
                file_paths = iocs.get("file_paths_filenames", [])
                if file_paths:
                    md += "### File Paths/Filenames\n"
                    for path in file_paths[:20]:  # Limit to first 20
                        md += f"- {path}\n"
                    if len(file_paths) > 20:
                        md += f"- ... and {len(file_paths) - 20} more\n"
                    md += "\n"
                
                registry_keys = iocs.get("registry_keys", [])
                if registry_keys:
                    md += "### Registry Keys\n"
                    for key in registry_keys:
                        md += f"- {key}\n"
                    md += "\n"
                
                ip_addresses = iocs.get("ip_addresses", [])
                if ip_addresses:
                    md += "### IP Addresses\n"
                    for ip in ip_addresses:
                        md += f"- {ip}\n"
                    md += "\n"
            
            # Key Considerations
            key_considerations = summary_json.get("key_considerations", {})
            if isinstance(key_considerations, dict):
                md += "## Key Considerations\n"
                
                prevalence = key_considerations.get("prevalence")
                if prevalence:
                    md += f"### Prevalence\n{prevalence}\n\n"
                
                api_analysis = key_considerations.get("api_analysis")
                if api_analysis:
                    md += f"### API Analysis\n{api_analysis}\n\n"
                
                entropy_analysis = key_considerations.get("entropy_analysis")
                if entropy_analysis:
                    md += f"### Entropy Analysis\n{entropy_analysis}\n\n"
            
            # Guidance for Clarity and Impact
            guidance = summary_json.get("guidance_for_clarity_and_impact", {})
            if isinstance(guidance, dict):
                md += "## Guidance for Clarity and Impact\n"
                
                persistence = guidance.get("persistence_mechanisms", [])
                if persistence:
                    md += "### Persistence Mechanisms\n"
                    for item in persistence:
                        md += f"- {item}\n"
                    md += "\n"
                
                obfuscation = guidance.get("obfuscation_or_evasion_techniques", [])
                if obfuscation:
                    md += "### Obfuscation/Evasion Techniques\n"
                    for item in obfuscation:
                        md += f"- {item}\n"
                    md += "\n"
                
                data_exfiltration = guidance.get("data_exfiltration_capabilities", [])
                if data_exfiltration:
                    md += "### Data Exfiltration Capabilities\n"
                    for item in data_exfiltration:
                        md += f"- {item}\n"
                    md += "\n"
            
            # Full detailed summary if available
            if detailed_summary and len(detailed_summary) > len(tldr):
                md += "## Detailed Analysis\n"
                md += detailed_summary
        else:
            md += f"### AI Summary Response\n{json.dumps(response, indent=2)}"
        
        # Prepare structured outputs
        outputs = {
            "hash": response.get("hash", object_id) if isinstance(response, dict) else object_id,
            "raw": response
        }
        
        # Extract key fields for easier access
        if isinstance(response, dict):
            raw_data = response.get("raw", {})
            summary_json = raw_data.get("summaryJson", {}) if isinstance(raw_data, dict) else {}
            if summary_json:
                outputs["malicious_likelihood"] = summary_json.get("malicious_likelihood")
                outputs["confidence"] = summary_json.get("confidence")
                outputs["threat_type"] = summary_json.get("threat_type")
                outputs["tldr"] = summary_json.get("tldr", raw_data.get("tldr", ""))
        
        return CommandResults(
            readable_output=md,
            outputs_prefix='Stairwell.AI_Triage',
            outputs_key_field='hash',
            outputs=outputs
        )
    
    except DemistoException as err:
        # Handle different error codes
        if "404" in str(err):
            return CommandResults(readable_output=f"Object not found: {object_id}")
        elif "400" in str(err):
            return CommandResults(readable_output=f"Invalid request for object: {object_id}")
        else:
            raise err


def object_sightings_command(client: Client, object_id: str) -> CommandResults:
    missing = _require_args({"objectId": object_id})
    if missing:
        return missing

    try:
        response = client.list_object_sightings(object_id)
        sightings = response.get("objectSightings") if isinstance(response, dict) else None
        readable = tableToMarkdown("Object Sightings", sightings) if sightings else "No sightings found."

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Sightings",
            outputs_key_field="objectId",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Object not found: {object_id}")
        else:
            raise err


def object_detonation_trigger_command(client: Client, object_id: str) -> CommandResults:
    missing = _require_args({"objectId": object_id})
    if missing:
        return missing

    try:
        response = client.trigger_object_detonation(object_id)
        readable = "Detonation triggered successfully." if response else "Detonation trigger request sent."

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Detonation.Trigger",
            outputs_key_field="objectId",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Object not found: {object_id}")
        elif "403" in str(err):
            return CommandResults(readable_output=f"Permission denied to trigger detonation for object: {object_id}. Check API key permissions.")
        else:
            raise err


def object_detonation_get_command(client: Client, object_id: str) -> CommandResults:
    missing = _require_args({"objectId": object_id})
    if missing:
        return missing

    try:
        response = client.get_object_detonation(object_id)
        readable = tableToMarkdown("Detonation Details", response) if isinstance(response, dict) else str(response)

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Detonation",
            outputs_key_field="objectId",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"No detonation results found for object: {object_id}")
        else:
            raise err


def object_opinions_command(client: Client, object_id: str) -> CommandResults:
    missing = _require_args({"objectId": object_id})
    if missing:
        return missing

    try:
        response = client.list_object_opinions(object_id)
        opinions = response.get("opinions") if isinstance(response, dict) else None
        readable = tableToMarkdown("Object Opinions", opinions) if opinions else "No opinions found."

        # Add objectId to response for key field tracking
        if isinstance(response, dict):
            response["objectId"] = object_id

        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Opinions",
            outputs_key_field="objectId",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Object not found: {object_id}")
        else:
            raise err


def run_to_ground_generate_command(client: Client, object_ids: str) -> CommandResults:
    missing = _require_args({"objectIds": object_ids})
    if missing:
        return missing

    try:
        object_list = [oid.strip() for oid in object_ids.split(",") if oid.strip()]
        response = client.generate_run_to_ground(object_list)
        readable = tableToMarkdown("Run To Ground Results", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.RunToGround",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output="Invalid object IDs provided. Check that object IDs are valid SHA256 hashes."
            )
        elif "404" in str(err):
            return CommandResults(
                readable_output="One or more objects not found. Check that the object IDs exist in Stairwell."
            )
        else:
            raise DemistoException(f"Failed to generate Run-To-Ground analysis: {err}") from err


# Network Intel Command Functions - ASN
def asn_get_whois_command(client: Client, asn: str) -> CommandResults:
    """Get ASN WHOIS information."""
    missing = _require_args({"asn": asn})
    if missing:
        return missing

    try:
        response = client.get_asn_whois(asn)

        # Add asn to response for key field tracking
        if isinstance(response, dict):
            response["asn"] = asn

        readable = tableToMarkdown(f"ASN {asn} WHOIS Information", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.ASN.WHOIS",
            outputs_key_field="asn",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"ASN not found: {asn}")
        else:
            raise err


# Network Intel Command Functions - Hostname
def hostname_get_command(client: Client, hostname: str, record_type: Optional[str] = None) -> CommandResults:
    """Get hostname entity with DNS resolution data."""
    missing = _require_args({"hostname": hostname})
    if missing:
        return missing

    try:
        response = client.get_hostname(hostname, record_type)

        # Add hostname to response for key field tracking
        if isinstance(response, dict):
            response["hostname"] = hostname

        readable = tableToMarkdown(f"Hostname: {hostname}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Hostname",
            outputs_key_field="hostname",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Hostname not found: {hostname}")
        else:
            raise err


def hostname_get_resolutions_command(client: Client, hostname: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> CommandResults:
    """Get all addresses resolved to by a hostname."""
    missing = _require_args({"hostname": hostname})
    if missing:
        return missing

    try:
        response = client.get_hostname_resolutions(hostname, start_time, end_time)
        resolutions = response.get("resolutions", []) if isinstance(response, dict) else []

        # Add hostname to response for key field tracking
        if isinstance(response, dict):
            response["hostname"] = hostname

        readable = tableToMarkdown(f"Resolutions for {hostname}", resolutions) if resolutions else f"No resolutions found for {hostname}"
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Hostname.Resolutions",
            outputs_key_field="hostname",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Hostname not found: {hostname}")
        else:
            raise err


def hostname_batch_get_resolutions_command(client: Client, hostnames: str, start_time: Optional[str] = None, end_time: Optional[str] = None,
                                          record_types: Optional[str] = None, include_errors: Optional[str] = None) -> CommandResults:
    """Get resolution summaries for multiple hostnames."""
    missing = _require_args({"hostnames": hostnames})
    if missing:
        return missing

    try:
        hostname_list = [h.strip() for h in hostnames.split(",") if h.strip()]

        # Parse recordTypes if provided (comma-separated string to list)
        record_types_list = None
        if record_types:
            record_types_list = [rt.strip() for rt in record_types.split(",") if rt.strip()]

        # Parse includeErrors boolean
        include_errors_bool = None
        if include_errors:
            include_errors_bool = include_errors.lower() in ["true", "yes", "1"]

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
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Hostname.BatchResolutions",
            outputs=response
        )
    except DemistoException as err:
        raise err


# Network Intel Command Functions - IP Address
def ipaddress_get_command(client: Client, ip_address: str) -> CommandResults:
    """Get IP address entity with enrichment data."""
    missing = _require_args({"ipAddress": ip_address})
    if missing:
        return missing

    try:
        response = client.get_ip_address(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = tableToMarkdown(f"IP Address: {ip_address}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.IPAddress",
            outputs_key_field="ip",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_lookup_cloud_provider_command(client: Client, ip_address: str) -> CommandResults:
    """Check if an IP address belongs to a known cloud provider."""
    missing = _require_args({"ipAddress": ip_address})
    if missing:
        return missing

    try:
        response = client.lookup_cloud_provider(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = tableToMarkdown(f"Cloud Provider Lookup for {ip_address}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.IPAddress.CloudProvider",
            outputs_key_field="ip",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_get_hostnames_resolving_to_ip_command(client: Client, ip_address: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> CommandResults:
    """Get all hostnames resolved to by an IP address."""
    missing = _require_args({"ipAddress": ip_address})
    if missing:
        return missing

    try:
        response = client.get_hostnames_resolving_to_ip(ip_address, start_time, end_time)
        hostnames = response.get("hostnames", []) if isinstance(response, dict) else []

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = tableToMarkdown(f"Hostnames Resolving to {ip_address}", hostnames) if hostnames else f"No hostnames found resolving to {ip_address}"
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.IPAddress.Hostnames",
            outputs_key_field="ip",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


def ipaddress_get_whois_command(client: Client, ip_address: str) -> CommandResults:
    """Get WHOIS information for an IP address."""
    missing = _require_args({"ipAddress": ip_address})
    if missing:
        return missing

    try:
        response = client.get_ip_address_whois(ip_address)

        # Add ip to response for key field tracking
        if isinstance(response, dict):
            response["ip"] = ip_address

        readable = tableToMarkdown(f"IP Address {ip_address} WHOIS Information", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.IPAddress.WHOIS",
            outputs_key_field="ip",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"IP address not found: {ip_address}")
        else:
            raise err


# Network Intel Command Functions - Utilities
def utilities_get_cloud_ip_ranges_command(client: Client, provider: Optional[str] = None) -> CommandResults:
    """Get IP ranges for known cloud providers."""
    try:
        response = client.get_cloud_ip_ranges(provider)
        ranges = response.get("ranges", []) if isinstance(response, dict) else []
        readable = tableToMarkdown("Cloud IP Ranges", ranges) if ranges else "No cloud IP ranges found"
        if provider:
            readable = f"Cloud IP Ranges for Provider: {provider}\n\n{readable}"
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.CloudIPRanges",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid provider parameter: '{provider}'. Check valid cloud provider names." if provider else "Bad request to cloud IP ranges API. Check parameters."
            )
        elif "404" in str(err):
            return CommandResults(
                readable_output=f"Cloud provider not found: '{provider}'" if provider else "Cloud IP ranges endpoint not found."
            )
        else:
            raise DemistoException(f"Failed to retrieve cloud IP ranges{f' for provider {provider}' if provider else ''}: {err}") from err


def utilities_batch_canonicalize_hostnames_command(client: Client, hostnames: str) -> CommandResults:
    """Canonicalize multiple hostnames in bulk."""
    missing = _require_args({"hostnames": hostnames})
    if missing:
        return missing

    try:
        hostname_list = [h.strip() for h in hostnames.split(",") if h.strip()]
        response = client.batch_canonicalize_hostnames(hostname_list)
        readable = tableToMarkdown("Canonicalized Hostnames", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.CanonicalizedHostnames",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output="Invalid hostname format in request. Check that hostnames are properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize hostnames: {err}") from err


def utilities_batch_compute_etld_plus_one_command(client: Client, domains: str) -> CommandResults:
    """Compute effective top-level domain plus one for multiple domains."""
    missing = _require_args({"domains": domains})
    if missing:
        return missing

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
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.ETLDPlusOne",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output="Invalid domain format in request. Check that domains are properly formatted."
            )
        else:
            raise DemistoException(f"Failed to compute ETLD+1 for domains: {err}") from err


def utilities_canonicalize_hostname_command(client: Client, hostname: str) -> CommandResults:
    """Canonicalize a single hostname."""
    missing = _require_args({"hostname": hostname})
    if missing:
        return missing

    try:
        response = client.canonicalize_hostname(hostname)
        readable = tableToMarkdown(f"Canonicalized Hostname: {hostname}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.CanonicalizedHostname",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid hostname format: '{hostname}'. Check that the hostname is properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize hostname '{hostname}': {err}") from err


def utilities_compute_etld_plus_one_command(client: Client, domain: str) -> CommandResults:
    """Compute effective top-level domain plus one for a single domain."""
    missing = _require_args({"domain": domain})
    if missing:
        return missing

    try:
        response = client.compute_etld_plus_one(domain)
        readable = tableToMarkdown(f"ETLD+1 for Domain: {domain}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.ETLDPlusOne",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid domain format: '{domain}'. Check that the domain is properly formatted."
            )
        else:
            raise DemistoException(f"Failed to compute ETLD+1 for domain '{domain}': {err}") from err


def utilities_batch_canonicalize_urls_command(client: Client, urls: str) -> CommandResults:
    """Canonicalize multiple URLs in bulk."""
    missing = _require_args({"urls": urls})
    if missing:
        return missing

    try:
        url_list = [u.strip() for u in urls.split(",") if u.strip()]
        response = client.batch_canonicalize_urls(url_list)
        readable = tableToMarkdown("Canonicalized URLs", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.CanonicalizedURLs",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output="Invalid URL format in request. Check that URLs are properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize URLs: {err}") from err


def utilities_canonicalize_url_command(client: Client, url: str) -> CommandResults:
    """Canonicalize a single URL."""
    missing = _require_args({"url": url})
    if missing:
        return missing

    try:
        response = client.canonicalize_url(url)
        readable = tableToMarkdown(f"Canonicalized URL: {url}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Utilities.CanonicalizedURL",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid URL format: '{url}'. Check that the URL is properly formatted."
            )
        else:
            raise DemistoException(f"Failed to canonicalize URL '{url}': {err}") from err


def intake_preflight_and_upload(asset_id: Optional[str] = None,
                                entry_id: Optional[str] = None,
                                url: Optional[str] = None,
                                file_path: Optional[str] = None,
                                sha256: Optional[str] = None,
                                detonation_plan: Optional[str] = None,
                                origin_type: Optional[str] = None,
                                origin_referrer_url: Optional[str] = None,
                                origin_host_url: Optional[str] = None,
                                origin_zone_id: Optional[int] = None,
                                verify: bool = True,
                                use_proxy: bool = False) -> CommandResults:
    """
    Implements Stairwell Intake API 'preflight' + conditional upload with retries.
    """
    # Validate required args
    missing = _require_args({"assetId": asset_id})
    if missing:
        return missing

    temp_file_path = None  # Track temp file for cleanup

    try:
        # Resolve file source
        resolved_path, filename, resolve_error = _resolve_file_source(
            entry_id=entry_id,
            url=url,
            file_path=file_path,
            verify=verify,
            use_proxy=use_proxy
        )

        if resolve_error:
            return CommandResults(readable_output=resolve_error)

        # Track temp file for cleanup (only if downloaded from URL)
        if url:
            temp_file_path = resolved_path

        # Use resolved path for all operations
        file_path = resolved_path

        # Auto-calc sha256 if not provided
        if not sha256:
            sha256, err = _hash_sha256(file_path)
            if err:
                return CommandResults(readable_output=err)

        # Build origin object
        origin_obj: Dict[str, Any] = {}
        if origin_type == "web":
            origin_web: Dict[str, Any] = {}
            if origin_referrer_url:
                origin_web["referrer-url"] = origin_referrer_url
            if origin_host_url:
                origin_web["host-url"] = origin_host_url
            if origin_zone_id is not None:
                origin_web["zone-id"] = origin_zone_id
            origin_obj["web"] = origin_web
        else:
            origin_obj["unspecified"] = {}

        expected_identifiers = [{"sha256": sha256}] if sha256 else []

        file_obj: Dict[str, Any] = {
            "filePath": file_path,
            "expected_attributes": {"identifiers": expected_identifiers} if expected_identifiers else {},
            "origin": origin_obj,
        }
        if detonation_plan:
            file_obj["detonation_plan"] = detonation_plan

        payload: Dict[str, Any] = {
            "asset": {"id": asset_id},
            "files": [file_obj]
        }

        proxies = handle_proxy() if use_proxy else None
        # Preflight with retries using session-based retry mechanism
        session = _create_session_with_retries()

        try:
            resp = session.post(
                INTAKE_PREFLIGHT_URL,
                json=payload,
                verify=verify,
                proxies=proxies,
                timeout=HTTP_TIMEOUT
            )
            resp.raise_for_status()

            try:
                preflight = resp.json() if resp.content else {}
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return CommandResults(
                    readable_output=f"Failed to parse preflight response. Raw response: {resp.text[:200]}",
                    outputs_prefix="Stairwell.Intake",
                    outputs={"error": "json_parse_error", "details": str(e)}
                )

        except requests.exceptions.Timeout:
            return CommandResults(
                readable_output=f"Intake preflight request timed out after {HTTP_TIMEOUT} seconds. The Stairwell API may be experiencing high load. Please try again later.",
                outputs_prefix="Stairwell.Intake",
                outputs={"error": "timeout", "timeout_seconds": HTTP_TIMEOUT}
            )
        except requests.exceptions.ConnectionError as e:
            return CommandResults(
                readable_output=f"Connection error during intake preflight: {e}. Check network connectivity to Stairwell API.",
                outputs_prefix="Stairwell.Intake",
                outputs={"error": str(e)}
            )
        except requests.HTTPError as http_err:
            return CommandResults(
                readable_output=f"HTTP error during Intake preflight: {http_err}",
                outputs_prefix="Stairwell.Intake",
                outputs={"error": str(http_err)}
            )

        file_actions = preflight.get("fileActions") or preflight.get("file_actions")
        if not file_actions:
            return CommandResults(
                readable_output=f"Unexpected preflight response: {preflight}",
                outputs_prefix="Stairwell.Intake.Preflight",
                outputs=preflight
            )

        action_obj = file_actions[0] or {}
        action = action_obj.get("action")

        md = "### Stairwell Intake — Preflight\n"
        md += f"Asset ID: {asset_id}\nFile: {filename}\n"
        if entry_id:
            md += f"Source: Entry ID {entry_id}\n"
        elif url:
            md += f"Source: URL {url}\n"
        else:
            md += f"Source: File Path {file_path}\n"
        md += f"Action: {action}\n"

        if action == "NO_ACTION_ALREADY_EXISTS":
            md += "\nFile already exists in Stairwell. No upload needed."
            return CommandResults(
                readable_output=md,
                outputs_prefix="Stairwell.Intake",
                outputs={"preflight": preflight, "result": "already_exists"}
            )

        if action == "UPLOAD":
            upload_url = action_obj.get("uploadUrl") or action_obj.get("upload_url")
            fields = action_obj.get("fields", {})
            file_field_name = action_obj.get("fileField", "file")

            if not upload_url or not fields:
                return CommandResults(
                    readable_output="Preflight requested UPLOAD but missing uploadUrl/fields.",
                    outputs_prefix="Stairwell.Intake",
                    outputs={"preflight": preflight, "error": "missing_upload_instructions"}
                )

            form_data = list(fields.items())
            filename = os.path.basename(file_path) or "file"
            # Use session with retries for upload
            upload_session = _create_session_with_retries()

            try:
                with open(file_path, "rb") as fh:
                    files_tup = {file_field_name: (filename, fh)}
                    upload_resp = upload_session.post(
                        upload_url,
                        data=form_data,
                        files=files_tup,
                        verify=verify,
                        proxies=proxies,
                        timeout=UPLOAD_TIMEOUT
                    )
            except requests.exceptions.Timeout:
                return CommandResults(
                    readable_output=f"File upload timed out after {UPLOAD_TIMEOUT} seconds. Large files may require more time. Contact your Stairwell administrator if this persists.",
                    outputs_prefix="Stairwell.Intake",
                    outputs={"preflight": preflight, "error": "upload_timeout", "timeout_seconds": UPLOAD_TIMEOUT}
                )
            except requests.exceptions.ConnectionError as e:
                return CommandResults(
                    readable_output=f"Connection error during file upload: {e}. Check network connectivity.",
                    outputs_prefix="Stairwell.Intake",
                    outputs={"preflight": preflight, "error": str(e)}
                )

            if upload_resp.status_code not in (200, 201, 202, 204):
                return CommandResults(
                    readable_output=f"Upload failed with status {upload_resp.status_code}: {upload_resp.text}",
                    outputs_prefix="Stairwell.Intake",
                    outputs={"preflight": preflight, "upload_status": upload_resp.status_code, "upload_text": upload_resp.text}
                )

            md += "\nUpload completed successfully."
            return CommandResults(
                readable_output=md,
                outputs_prefix="Stairwell.Intake",
                outputs={"preflight": preflight, "upload_status": upload_resp.status_code}
            )

        md += "\nUnrecognized action; returning raw response."
        return CommandResults(
            readable_output=md,
            outputs_prefix="Stairwell.Intake",
            outputs={"preflight": preflight}
        )

    except requests.HTTPError as http_err:
        return CommandResults(
            readable_output=f"HTTP error during Intake preflight/upload: {http_err}",
            outputs_prefix="Stairwell.Intake",
            outputs={"error": str(http_err)}
        )
    except Exception as ex:
        return CommandResults(
            readable_output=f"Unexpected error during Intake preflight/upload: {ex}",
            outputs_prefix="Stairwell.Intake",
            outputs={"error": str(ex)}
        )
    finally:
        # Clean up temp file if downloaded from URL
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                demisto.debug(f"Successfully cleaned up temp file: {temp_file_path}")
            except PermissionError as cleanup_ex:
                demisto.error(f"Permission denied cleaning up temp file {temp_file_path}: {cleanup_ex}. File may remain.")
            except OSError as cleanup_ex:
                demisto.error(f"OS error cleaning up temp file {temp_file_path}: {cleanup_ex}. File may remain.")
            except Exception as cleanup_ex:
                demisto.error(f"Unexpected error cleaning up temp file {temp_file_path}: {cleanup_ex}")


# YARA Rules Command Functions
def yara_create_rule_command(client: Client, environment: str, rule_definition: str) -> CommandResults:
    """Create a new YARA rule."""
    missing = _require_args({"environment": environment, "ruleDefinition": rule_definition})
    if missing:
        return missing

    try:
        response = client.create_yara_rule(environment, rule_definition)
        readable = tableToMarkdown("Created YARA Rule", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.YaraRule",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid YARA rule definition. Check syntax and formatting of the rule."
            )
        elif "403" in str(err):
            return CommandResults(
                readable_output=f"Permission denied to create YARA rule in environment: {environment}. Check API key permissions."
            )
        else:
            raise DemistoException(f"Failed to create YARA rule in environment '{environment}': {err}") from err


def yara_get_rule_command(client: Client, environment: str, yara_rule: str,
                         match_count_envs: Optional[str] = None) -> CommandResults:
    """Get a specific YARA rule."""
    missing = _require_args({"environment": environment, "yaraRule": yara_rule})
    if missing:
        return missing

    try:
        response = client.get_yara_rule(environment, yara_rule, match_count_envs)
        readable = tableToMarkdown(f"YARA Rule: {yara_rule}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.YaraRule",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"YARA rule not found: {yara_rule}")
        else:
            raise err


def yara_query_matches_command(client: Client, environment: str, yara_rule: str,
                               included_environments: Optional[str] = None, page_size: Optional[str] = None,
                               page_token: Optional[str] = None) -> CommandResults:
    """Query objects matching a YARA rule."""
    missing = _require_args({"environment": environment, "yaraRule": yara_rule})
    if missing:
        return missing

    try:
        included_envs_list = [e.strip() for e in included_environments.split(",")] if included_environments else None
        page_size_int = _parse_int_arg(page_size, "pageSize")
        response = client.query_yara_matches(environment, yara_rule, included_envs_list, page_size_int, page_token)
        matches = response.get("objects", []) if isinstance(response, dict) else []
        readable = tableToMarkdown(f"YARA Rule Matches: {yara_rule}", matches) if matches else f"No matches found for YARA rule: {yara_rule}"
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.YaraRuleMatches",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"YARA rule not found: {yara_rule}")
        else:
            raise err


# Asset Management Command Functions
def asset_list_command(client: Client, environment: str, page_size: Optional[str] = None,
                      page_token: Optional[str] = None) -> CommandResults:
    """List all assets in an environment."""
    missing = _require_args({"environment": environment})
    if missing:
        return missing

    try:
        page_size_int = _parse_int_arg(page_size, "pageSize")
        response = client.list_assets(environment, page_size_int, page_token)
        assets = response.get("assets", []) if isinstance(response, dict) else []
        readable = tableToMarkdown("Assets", assets) if assets else "No assets found."
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Assets",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Environment not found: {environment}")
        else:
            raise err


def asset_create_command(client: Client, environment: str, label: str, idempotency_key: Optional[str] = None,
                        os: Optional[str] = None, os_version: Optional[str] = None,
                        forwarder_version: Optional[str] = None) -> CommandResults:
    """Create a new asset in an environment."""
    missing = _require_args({"environment": environment, "label": label})
    if missing:
        return missing

    try:
        response = client.create_asset(environment, label, idempotency_key, os, os_version, forwarder_version)
        readable = tableToMarkdown("Created Asset", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Asset",
            outputs=response
        )
    except DemistoException as err:
        if "400" in str(err):
            return CommandResults(
                readable_output=f"Invalid asset parameters. Check that label and other fields are properly formatted."
            )
        elif "403" in str(err):
            return CommandResults(
                readable_output=f"Permission denied to create asset in environment: {environment}. Check API key permissions."
            )
        elif "409" in str(err):
            return CommandResults(
                readable_output=f"Asset with label '{label}' may already exist. Try a different label or check existing assets."
            )
        else:
            raise DemistoException(f"Failed to create asset in environment '{environment}': {err}") from err


def asset_get_command(client: Client, asset: str) -> CommandResults:
    """Get a specific asset by ID."""
    missing = _require_args({"asset": asset})
    if missing:
        return missing

    try:
        response = client.get_asset(asset)
        readable = tableToMarkdown(f"Asset: {asset}", response) if isinstance(response, dict) else str(response)
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Stairwell.Asset",
            outputs=response
        )
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(readable_output=f"Asset not found: {asset}")
        else:
            raise err


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')

    # Params enabled by XSOAR functionality
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        # Built-in command
        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            client = Client(
                base_url=REPUTATION_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = test_module(client)
            return_results(result)

        elif command == 'stairwell-file-enrichment':
            client = Client(
                base_url=REPUTATION_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = file_enrichment_command(client, args.get('fileHash'))
            return_results(result)

        elif command == 'stairwell-variant-discovery':
            client = Client(
                base_url=VARIANTS_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy,
                timeout=HTTP_TIMEOUT)
            result = variant_discovery_command(client, args.get('sha256'))
            return_results(result)

        elif command == 'stairwell-intake-upload':
            # Uses preflight and conditionally uploads
            result = intake_preflight_and_upload(
                asset_id=args.get('assetId'),
                entry_id=args.get('entryID'),
                url=args.get('url'),
                file_path=args.get('filePath'),
                sha256=args.get('sha256'),
                detonation_plan=args.get('detonationPlan'),
                origin_type=args.get('originType'),
                origin_referrer_url=args.get('originReferrerUrl'),
                origin_host_url=args.get('originHostUrl'),
                origin_zone_id=_parse_int_arg(args.get('originZoneId'), "originZoneId"),
                verify=verify_certificate,
                use_proxy=proxy
            )
            return_results(result)

        elif command == 'stairwell-object-sightings':
            client = Client(
                base_url=AI_TRIAGE_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = object_sightings_command(client, args.get('objectId'))
            return_results(result)

        elif command == 'stairwell-object-detonation-trigger':
            client = Client(
                base_url=AI_TRIAGE_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = object_detonation_trigger_command(client, args.get('objectId'))
            return_results(result)

        elif command == 'stairwell-object-detonation-get':
            client = Client(
                base_url=AI_TRIAGE_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = object_detonation_get_command(client, args.get('objectId'))
            return_results(result)

        elif command == 'stairwell-object-opinions':
            client = Client(
                base_url=AI_TRIAGE_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = object_opinions_command(client, args.get('objectId'))
            return_results(result)

        elif command == 'stairwell-run-to-ground-generate':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = run_to_ground_generate_command(client, args.get('objectIds'))
            return_results(result)

        elif command == 'stairwell-ai-triage-summarize':
            client = Client(
                base_url=AI_TRIAGE_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = ai_triage_summarize_command(client, args.get('objectId'))
            return_results(result)

        # Network Intel Commands - ASN
        elif command == 'stairwell-asn-get-whois':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = asn_get_whois_command(client, args.get('asn'))
            return_results(result)

        # Network Intel Commands - Hostname
        elif command == 'stairwell-hostname-get':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = hostname_get_command(client, args.get('hostname'), args.get('recordType'))
            return_results(result)

        elif command == 'stairwell-hostname-get-resolutions':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = hostname_get_resolutions_command(
                client,
                args.get('hostname'),
                args.get('startTime'),
                args.get('endTime')
            )
            return_results(result)

        elif command == 'stairwell-hostname-batch-get-resolutions':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = hostname_batch_get_resolutions_command(
                client,
                args.get('hostnames'),
                args.get('startTime'),
                args.get('endTime'),
                args.get('recordTypes'),
                args.get('includeErrors')
            )
            return_results(result)

        # Network Intel Commands - IP Address
        elif command == 'stairwell-ipaddress-get':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = ipaddress_get_command(client, args.get('ipAddress'))
            return_results(result)

        elif command == 'stairwell-ipaddress-lookup-cloud-provider':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = ipaddress_lookup_cloud_provider_command(client, args.get('ipAddress'))
            return_results(result)

        elif command == 'stairwell-ipaddress-get-hostnames-resolving-to-ip':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = ipaddress_get_hostnames_resolving_to_ip_command(
                client,
                args.get('ipAddress'),
                args.get('startTime'),
                args.get('endTime')
            )
            return_results(result)

        elif command == 'stairwell-ipaddress-get-whois':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = ipaddress_get_whois_command(client, args.get('ipAddress'))
            return_results(result)

        # Network Intel Commands - Utilities
        elif command == 'stairwell-utilities-get-cloud-ip-ranges':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_get_cloud_ip_ranges_command(client, args.get('provider'))
            return_results(result)

        elif command == 'stairwell-utilities-batch-canonicalize-hostnames':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_batch_canonicalize_hostnames_command(client, args.get('hostnames'))
            return_results(result)

        elif command == 'stairwell-utilities-batch-compute-etld-plus-one':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_batch_compute_etld_plus_one_command(client, args.get('domains'))
            return_results(result)

        elif command == 'stairwell-utilities-canonicalize-hostname':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_canonicalize_hostname_command(client, args.get('hostname'))
            return_results(result)

        elif command == 'stairwell-utilities-compute-etld-plus-one':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_compute_etld_plus_one_command(client, args.get('domain'))
            return_results(result)

        elif command == 'stairwell-utilities-batch-canonicalize-urls':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_batch_canonicalize_urls_command(client, args.get('urls'))
            return_results(result)

        elif command == 'stairwell-utilities-canonicalize-url':
            client = Client(
                base_url=V2_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = utilities_canonicalize_url_command(client, args.get('url'))
            return_results(result)

        # YARA Rules Commands
        elif command == 'stairwell-yara-create-rule':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = yara_create_rule_command(
                client,
                args.get('environment'),
                args.get('ruleDefinition')
            )
            return_results(result)

        elif command == 'stairwell-yara-get-rule':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = yara_get_rule_command(
                client,
                args.get('environment'),
                args.get('yaraRule'),
                args.get('matchCountEnvs')
            )
            return_results(result)

        elif command == 'stairwell-yara-query-matches':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = yara_query_matches_command(
                client,
                args.get('environment'),
                args.get('yaraRule'),
                args.get('includedEnvironments'),
                args.get('pageSize'),
                args.get('pageToken')
            )
            return_results(result)

        # Asset Management Commands
        elif command == 'stairwell-asset-list':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = asset_list_command(
                client,
                args.get('environment'),
                args.get('pageSize'),
                args.get('pageToken')
            )
            return_results(result)

        elif command == 'stairwell-asset-create':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = asset_create_command(
                client,
                args.get('environment'),
                args.get('label'),
                args.get('idempotencyKey'),
                args.get('os'),
                args.get('osVersion'),
                args.get('forwarderVersion')
            )
            return_results(result)

        elif command == 'stairwell-asset-get':
            client = Client(
                base_url=V1_BASE_URL,
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy)
            result = asset_get_command(
                client,
                args.get('asset')
            )
            return_results(result)

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join((f"Failed to execute {command} command.",
                                "Error:",
                                str(e))))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
