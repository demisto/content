import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 50
PA_OUTPUT_PREFIX = "PrismaAIRs."
# API path suffixes (appended to Server URL from config)
MGMT_API_PATH = "/aisec"
MGMT_API_V1_PREFIX = "/v1/mgmt"
MODEL_SEC_DATA_PATH = "/aims/data"
MODEL_SEC_MGMT_PATH = "/aims/mgmt"
# Red Team API path suffixes
# Reference: ./knowledge/prisma-airs-sdk-main/src/constants.ts
RED_TEAM_DATA_PATH = "/ai-red-teaming/data-plane"
RED_TEAM_MGMT_PATH = "/ai-red-teaming/mgmt-plane"
RED_TEAM_TARGETS_ENDPOINT = "/v1/target"
RED_TEAM_SCANS_ENDPOINT = "/v1/scan"
RED_TEAM_CATEGORIES_ENDPOINT = "/v1/categories"
RED_TEAM_REPORTS_ENDPOINT = "/v1/report"
RED_TEAM_REPORT_STATIC_ENDPOINT = "/v1/report/static"
RED_TEAM_REPORT_DYNAMIC_ENDPOINT = "/v1/report/dynamic"
RED_TEAM_CUSTOM_ATTACKS_ENDPOINT = "/v1/custom-attacks"
RED_TEAM_CUSTOM_ATTACK_ENDPOINT = "/v1/custom-attack"  # For prompts within prompt sets
RED_TEAM_EULA_ENDPOINT = "/v1/eula"
RED_TEAM_REGISTRY_CREDENTIALS_ENDPOINT = "/v1/registry-credentials"
# DLP API path suffixes (v2 API) - uses separate base URL
# Reference: ./knowledge/prisma-airs-sdk-main/src/constants.ts
# CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (NOT the SCM base URL)
# Default DLP base URL (can be overridden in configuration)
DEFAULT_DLP_BASE_URL = "https://api.dlp.paloaltonetworks.com"
DLP_DICTIONARIES_PATH = "/v2/api/dictionaries"
DLP_PATTERNS_PATH = "/v2/api/data-patterns"
DLP_FILTERING_PROFILES_PATH = "/v2/api/data-filtering-profiles"
DLP_DATA_PROFILES_PATH = "/v2/api/data-profiles"
# Scanner API path (SDK: SYNC_SCAN_PATH = '/v1/scan/sync/request')
SCANNER_SYNC_SCAN_PATH = "/v1/scan/sync/request"
# Default Scanner base URL (can be overridden in configuration)
DEFAULT_SCANNER_BASE_URL = "https://service.api.aisecurity.paloaltonetworks.com"


class Client(BaseClient):
    """Client class to interact with Prisma AIRs API

    This Client implements API calls to the Prisma AIRs platform via Strata Cloud Manager,
    and does not contain any XSOAR logic. Handles OAuth2 token retrieval.

    Args:
       base_url: Strata Cloud Manager server URL.
       client_id: OAuth2 client ID.
       client_secret: OAuth2 client secret.
       tsg_id: The default Prisma SASE Tenant Services Group ID
       verify: Specifies whether to verify the SSL certificate or not.
       proxy: Specifies if to use XSOAR proxy settings.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        tsg_id: str | None,
        runtime_api_key: str | None,
        scanner_base_url: str | None,
        dlp_base_url: str | None,
        verify: bool,
        proxy: bool,
        headers: dict[str, str],
        **kwargs: Any,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.runtime_api_key = runtime_api_key
        # Use configured URLs or fall back to defaults
        self.scanner_base_url = scanner_base_url or DEFAULT_SCANNER_BASE_URL
        self.dlp_base_url = dlp_base_url or DEFAULT_DLP_BASE_URL
        self._access_token: str | None = None

    def get_access_token(self) -> str:
        """Retrieve OAuth2 access token from SCM token endpoint.

        Returns:
            str: Access token for API authentication.
        """
        if self._access_token:
            return self._access_token

        token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "profile tsg_id:{}".format(self.tsg_id) if self.tsg_id else "profile"
        }

        response = self._http_request(
            method="POST",
            full_url=token_url,
            headers=headers,
            data=data,
            resp_type="json"
        )

        self._access_token = response.get("access_token")
        if not self._access_token:
            raise DemistoException("Failed to retrieve access token from SCM")

        return self._access_token

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        tsg_id: str | None = None,
        use_mgmt_base: bool = False,
        use_model_sec_data: bool = False,
        use_model_sec_mgmt: bool = False,
        use_redteam_data: bool = False,
        use_redteam_mgmt: bool = False,
        use_dlp_base: bool = False,
    ) -> dict[str, Any]:
        """Execute HTTP request with OAuth2 authentication for Management API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            url_suffix: URL suffix to append to base URL.
            params: URL parameters.
            json_data: JSON data for request body.
            tsg_id: Override TSG ID for this request.
            use_mgmt_base: If True, use MGMT_API_PATH prefix (e.g., /aisec/v1/mgmt/...).
            use_model_sec_data: If True, use MODEL_SEC_DATA_PATH prefix (e.g., /aims/data/...).
            use_model_sec_mgmt: If True, use MODEL_SEC_MGMT_PATH prefix (e.g., /aims/mgmt/...).
            use_redteam_data: If True, use RED_TEAM_DATA_PATH prefix (e.g., /ai-red-teaming/data-plane/...).
            use_redteam_mgmt: If True, use RED_TEAM_MGMT_PATH prefix (e.g., /ai-red-teaming/mgmt-plane/...).
            use_dlp_base: If True, use DLP_BASE_URL (https://api.dlp.paloaltonetworks.com) + url_suffix directly.

        Returns:
            dict: API response.
        """
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        # Determine which API path prefix to use
        # CRITICAL: DLP v2 API uses a completely different base URL
        if use_dlp_base:
            full_url = f"{self.dlp_base_url}{url_suffix}"
        elif use_model_sec_data:
            full_url = f"{self._base_url}{MODEL_SEC_DATA_PATH}{url_suffix}"
        elif use_model_sec_mgmt:
            full_url = f"{self._base_url}{MODEL_SEC_MGMT_PATH}{url_suffix}"
        elif use_redteam_data:
            full_url = f"{self._base_url}{RED_TEAM_DATA_PATH}{url_suffix}"
        elif use_redteam_mgmt:
            full_url = f"{self._base_url}{RED_TEAM_MGMT_PATH}{url_suffix}"
        elif use_mgmt_base:
            full_url = f"{self._base_url}{MGMT_API_PATH}{url_suffix}"
        else:
            # Use default base URL without additional prefix
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                json_data=json_data,
                headers=headers,
                resp_type="json"
            )

        return self._http_request(
            method=method,
            full_url=full_url,
            params=params,
            json_data=json_data,
            headers=headers,
            resp_type="json"
        )

    def scanner_request(
        self,
        json_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute scanner API request with API key authentication.

        Args:
            json_data: JSON data for scanner request body.

        Returns:
            dict: Scanner API response.
        """
        if not self.runtime_api_key:
            raise DemistoException(
                "Runtime API Key is required for scanner operations. Please configure the Runtime API Key in the integration settings.")

        headers = {
            "x-pan-token": self.runtime_api_key,
            "Content-Type": "application/json"
        }

        # Use regional scanner endpoint + sync scan path
        # Full URL: https://service{-region}.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request
        return self._http_request(
            method="POST",
            full_url=f"{self.scanner_base_url}{SCANNER_SYNC_SCAN_PATH}",
            json_data=json_data,
            headers=headers,
            resp_type="json"
        )


def test_module(client: Client) -> str:
    """Test connectivity to Prisma AIRs API.

    Args:
        client: Prisma AIRs API client.

    Returns:
        str: 'ok' if test passed, error message otherwise.
    """
    try:
        # Test authentication by attempting to get access token
        client.get_access_token()
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


def runtime_scan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Scan a prompt against a security profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_name = args.get("profile_name")
    prompt = args.get("prompt")
    response_text = args.get("response")

    # Optional metadata fields (per scan-sync-request.md docs)
    tr_id = args.get("tr_id")
    session_id = args.get("session_id")
    app_name = args.get("app_name")
    app_user = args.get("app_user")
    ai_model = args.get("ai_model")
    user_ip = args.get("user_ip")
    agent_id = args.get("agent_id")
    agent_version = args.get("agent_version")
    agent_arn = args.get("agent_arn")

    if not profile_name or not prompt:
        raise ValueError("profile_name and prompt are required arguments")

    # Build scanner API request
    # Reference: ./knowledge/docs/Prisma_AIRs_airuntime/scans/scan-sync-request.md
    content: dict[str, str] = {"prompt": prompt}
    if response_text:
        content["response"] = response_text

    scan_request: dict[str, Any] = {
        "ai_profile": {
            "profile_name": profile_name
        },
        "contents": [content]
    }

    # Add optional top-level metadata fields
    if tr_id:
        scan_request["tr_id"] = tr_id
    if session_id:
        scan_request["session_id"] = session_id

    # Build metadata object if any metadata fields are provided
    metadata: dict[str, Any] = {}
    if app_name:
        metadata["app_name"] = app_name
    if app_user:
        metadata["app_user"] = app_user
    if ai_model:
        metadata["ai_model"] = ai_model
    if user_ip:
        metadata["user_ip"] = user_ip

    # Build agent_meta nested object
    agent_meta: dict[str, str] = {}
    if agent_id:
        agent_meta["agent_id"] = agent_id
    if agent_version:
        agent_meta["agent_version"] = agent_version
    if agent_arn:
        agent_meta["agent_arn"] = agent_arn

    if agent_meta:
        metadata["agent_meta"] = agent_meta

    if metadata:
        scan_request["metadata"] = metadata

    # Call Prisma AIRs scanner API
    scan_response = client.scanner_request(scan_request)

    # Parse detections for both prompt and response
    # Forward-compatible: capture all fields from API response
    prompt_detected = scan_response.get("prompt_detected", {})
    response_detected = scan_response.get("response_detected", {})

    # Check if ANY detection occurred across prompt or response
    prompt_has_detections = any(prompt_detected.values()) if prompt_detected else False
    response_has_detections = any(response_detected.values()) if response_detected else False
    overall_detected = prompt_has_detections or response_has_detections

    # Build scan result with all top-level fields from API response
    # Forward-compatible: include all fields from scan_response
    scan_result = {
        "prompt": prompt,
        "response": response_text,
        "scan_id": scan_response.get("scan_id", ""),
        "report_id": scan_response.get("report_id", ""),
        "action": scan_response.get("action", "unknown"),
        "category": scan_response.get("category", "unknown"),
        "detected": overall_detected,
        "prompt_detected": prompt_detected,  # Include full prompt_detected object
        "response_detected": response_detected  # Include full response_detected object
    }

    # Add optional metadata fields from response if present (forward-compatible)
    if scan_response.get("tr_id"):
        scan_result["tr_id"] = scan_response["tr_id"]
    if scan_response.get("session_id"):
        scan_result["session_id"] = scan_response["session_id"]
    if scan_response.get("profile_id"):
        scan_result["profile_id"] = scan_response["profile_id"]
    if scan_response.get("profile_name"):
        scan_result["profile_name"] = scan_response["profile_name"]
    if scan_response.get("source"):
        scan_result["source"] = scan_response["source"]
    if scan_response.get("timeout"):
        scan_result["timeout"] = scan_response["timeout"]
    if scan_response.get("error"):
        scan_result["error"] = scan_response["error"]
    if scan_response.get("errors"):
        scan_result["errors"] = scan_response["errors"]

    # Create human-readable output using table format
    scan_summary = [{
        "Scan ID": scan_result['scan_id'],
        "Report ID": scan_result['report_id'],
        "Profile": profile_name,
        "Action": scan_result['action'].upper(),
        "Category": scan_result['category'],
        "Detected": "Yes" if overall_detected else "No"
    }]

    # Add metadata table if any metadata fields are present
    metadata_table = []
    if scan_result.get("tr_id"):
        metadata_table.append({"Field": "Transaction ID", "Value": scan_result["tr_id"]})
    if scan_result.get("session_id"):
        metadata_table.append({"Field": "Session ID", "Value": scan_result["session_id"]})

    # Build prompt detections table (forward-compatible: dynamically handle all detection fields)
    prompt_detections_table = []
    if prompt_detected:
        for detection_type, detected_value in prompt_detected.items():
            prompt_detections_table.append({
                "Detection Type": detection_type.replace("_", " ").title(),
                "Detected": "Yes" if detected_value else "No"
            })

    # Build response detections table (forward-compatible: dynamically handle all detection fields)
    response_detections_table = []
    if response_detected:
        for detection_type, detected_value in response_detected.items():
            response_detections_table.append({
                "Detection Type": detection_type.replace("_", " ").title(),
                "Detected": "Yes" if detected_value else "No"
            })

    # Build scanned content table
    content_table = [{
        "Type": "Prompt",
        "Content": prompt[:100] + "..." if len(prompt) > 100 else prompt,
        "Threats Detected": "Yes" if prompt_has_detections else "No"
    }]
    if response_text:
        content_table.append({
            "Type": "Response",
            "Content": response_text[:100] + "..." if len(response_text) > 100 else response_text,
            "Threats Detected": "Yes" if response_has_detections else "No"
        })

    # Build readable output
    readable_output = "## Prisma AIRs Runtime Scan Results\n\n"
    readable_output += tableToMarkdown(
        "Scan Summary",
        scan_summary,
        headers=["Scan ID", "Report ID", "Profile", "Action", "Category", "Detected"]
    )
    readable_output += "\n"

    # Add metadata table if present
    if metadata_table:
        readable_output += tableToMarkdown(
            "Metadata",
            metadata_table,
            headers=["Field", "Value"]
        )
        readable_output += "\n"

    # Scanned content first to show what was scanned
    readable_output += tableToMarkdown(
        "Scanned Content",
        content_table,
        headers=["Type", "Content", "Threats Detected"]
    )
    readable_output += "\n"

    # Prompt detections (if any)
    if prompt_detections_table:
        readable_output += tableToMarkdown(
            "Prompt Detections",
            prompt_detections_table,
            headers=["Detection Type", "Detected"]
        )
        readable_output += "\n"

    # Response detections (if any)
    if response_detections_table:
        readable_output += tableToMarkdown(
            "Response Detections",
            response_detections_table,
            headers=["Detection Type", "Detected"]
        )
        readable_output += "\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RuntimeScan",
        outputs_key_field="scan_id",
        outputs=scan_result,
        readable_output=readable_output,
        raw_response=scan_response
    )


def runtime_api_keys_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Runtime API Keys.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Management API to list API keys
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/api-keys.ts
    # SDK path: /v1/mgmt/apikeys/tsg/{tsgId}
    # SDK uses offset for pagination, but we'll use limit for simplicity
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikeys/tsg/{client.tsg_id}"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK returns snake_case field names
    api_keys_raw = response.get("api_keys", [])
    api_keys = []

    for key in api_keys_raw:
        api_key_info = {
            "id": key.get("api_key_id"),
            "name": key.get("api_key_name"),
            "last8": key.get("api_key_last8"),
            "created_at": key.get("created_at"),
            "expires_at": key.get("expiration"),
            "revoked": key.get("revoked")
        }
        api_keys.append(api_key_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Runtime API Keys",
        api_keys,
        headers=["id", "name", "last8", "created_at", "expires_at", "revoked"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKey",
        outputs_key_field="id",
        outputs=api_keys,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_profiles_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List runtime security profiles.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Management API to list security profiles
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/profiles.ts
    # SDK path: /v1/mgmt/profiles/tsg/{tsgId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/profiles/tsg/{client.tsg_id}"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK returns ai_profiles array
    # Schema: profile_id, profile_name, revision, active, created_by, updated_by, last_modified_ts
    profiles_raw = response.get("ai_profiles", [])
    profiles = []

    for profile in profiles_raw:
        profile_info = {
            "id": profile.get("profile_id"),
            "name": profile.get("profile_name"),
            "revision": profile.get("revision"),
            "active": profile.get("active"),
            "created_by": profile.get("created_by"),
            "updated_by": profile.get("updated_by"),
            "last_modified_ts": profile.get("last_modified_ts"),
            "tsg_id": profile.get("tsg_id")
        }
        profiles.append(profile_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Security Profiles",
        profiles,
        headers=["id", "name", "revision", "active", "created_by", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfile",
        outputs_key_field="id",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_customer_apps_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List customer applications.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Management API to list customer apps
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/customer-apps.ts
    # SDK path: /v1/mgmt/customerapp/tsg/{tsgId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/customerapp/tsg/{client.tsg_id}"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK schema: customer_appId, app_name, model_name, cloud_provider, environment
    apps_raw = response.get("customer_apps", [])
    apps = []

    for app in apps_raw:
        app_info = {
            "id": app.get("customer_appId"),
            "name": app.get("app_name"),
            "model_name": app.get("model_name"),
            "cloud_provider": app.get("cloud_provider"),
            "environment": app.get("environment"),
            "ai_agent_framework": app.get("ai_agent_framework"),
            "tsg_id": app.get("tsg_id")
        }
        apps.append(app_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Customer Applications",
        apps,
        headers=["id", "name", "model_name", "cloud_provider", "environment", "ai_agent_framework"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerApp",
        outputs_key_field="id",
        outputs=apps,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_deployment_profiles_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List deployment profiles.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    unactivated = args.get("unactivated", "false").lower() == "true"

    # Call Management API to list deployment profiles
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/deployment-profiles.ts
    # SDK path: /v1/mgmt/deploymentprofiles
    url_suffix = f"{MGMT_API_V1_PREFIX}/deploymentprofiles"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }
    if unactivated:
        params["unactivated"] = "true"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK schema: dp_name, auth_code, tsg_id, status, expiration_date
    profiles_raw = response.get("deployment_profiles", [])
    profiles = []

    for profile in profiles_raw:
        profile_info = {
            "name": profile.get("dp_name"),
            "auth_code": profile.get("auth_code"),
            "tsg_id": profile.get("tsg_id"),
            "status": profile.get("status"),
            "expiration_date": profile.get("expiration_date"),
            "ave_text_records": profile.get("ave_text_records")
        }
        profiles.append(profile_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Deployment Profiles",
        profiles,
        headers=["name", "auth_code", "status", "expiration_date", "ave_text_records"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DeploymentProfile",
        outputs_key_field="name",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_profiles_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List DLP data profiles (v2 API).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    page = arg_to_number(args.get("page")) or 0
    size = arg_to_number(args.get("size")) or 50

    # Build query parameters
    params: dict[str, Any] = {
        "page": page,
        "size": size
    }

    # Call DLP v2 API to list data profiles
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # CRITICAL: Uses DLP v2 API base URL (https://api.dlp.paloaltonetworks.com)
    response = client.http_request(
        method="GET",
        url_suffix=DLP_DATA_PROFILES_PATH,
        params=params,
        use_dlp_base=True
    )

    # Parse response
    # SDK schema (dlp-data-profile.ts): id, name, description, tenant_id, type, profile_status, profile_type, etc.
    # Returns paginated: { content: [...], page: {...} }
    profiles_raw = response.get("content", [])
    profiles = []

    for profile in profiles_raw:
        profile_info = {
            "id": profile.get("id"),
            "name": profile.get("name"),
            "description": profile.get("description"),
            "tenant_id": profile.get("tenant_id"),
            "type": profile.get("type"),
            "profile_status": profile.get("profile_status"),
            "profile_type": profile.get("profile_type"),
            "is_granular_data_profile": profile.get("is_granular_data_profile"),
            "is_parent_managed": profile.get("is_parent_managed"),
            "version": profile.get("version"),
            "created_at": profile.get("audit_metadata", {}).get("created_at"),
            "updated_at": profile.get("audit_metadata", {}).get("updated_at"),
            "created_by": profile.get("audit_metadata", {}).get("created_by"),
            "updated_by": profile.get("audit_metadata", {}).get("updated_by")
        }
        profiles.append(profile_info)

    total_elements = response.get("page", {}).get("total_elements", len(profiles))
    total_pages = response.get("page", {}).get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profiles (Page {page + 1}/{total_pages}, {len(profiles)} of {total_elements})",
        profiles,
        headers=["id", "name", "type", "profile_status", "profile_type", "version"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List model security scans.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Model Security Data API to list scans
    # Reference: ./knowledge/prisma-airs-sdk-main/src/model-security/scans-client.ts
    # SDK path: /v1/scans (data plane)
    url_suffix = "/v1/scans"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema from model-security.ts: ScanBaseResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, model_uri, owner, scan_origin,
    # security_group_uuid, security_group_name, model_version_uuid, eval_outcome, source_type
    scans_raw = response.get("scans", [])
    scans = []

    for scan in scans_raw:
        scan_info = {
            "uuid": scan.get("uuid"),
            "model_uri": scan.get("model_uri"),
            "eval_outcome": scan.get("eval_outcome"),
            "source_type": scan.get("source_type"),
            "security_group_uuid": scan.get("security_group_uuid"),
            "security_group_name": scan.get("security_group_name"),
            "scan_origin": scan.get("scan_origin"),
            "created_at": scan.get("created_at"),
            "updated_at": scan.get("updated_at"),
            "created_by": scan.get("created_by")
        }
        scans.append(scan_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Scans",
        scans,
        headers=["uuid", "model_uri", "eval_outcome", "source_type", "security_group_name", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScan",
        outputs_key_field="uuid",
        outputs=scans,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_groups_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List model security groups.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Model Security Management API to list security groups
    # Reference: ./knowledge/prisma-airs-sdk-main/src/model-security/security-groups-client.ts
    # SDK path: /v1/security-groups (management plane)
    url_suffix = "/v1/security-groups"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityGroupResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, name, description, source_type, state, is_tombstone
    groups_raw = response.get("security_groups", [])
    groups = []

    for group in groups_raw:
        group_info = {
            "uuid": group.get("uuid"),
            "name": group.get("name"),
            "description": group.get("description"),
            "source_type": group.get("source_type"),
            "state": group.get("state"),
            "is_tombstone": group.get("is_tombstone"),
            "created_at": group.get("created_at"),
            "updated_at": group.get("updated_at"),
            "tsg_id": group.get("tsg_id")
        }
        groups.append(group_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Groups",
        groups,
        headers=["uuid", "name", "source_type", "state", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroup",
        outputs_key_field="uuid",
        outputs=groups,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_rules_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List model security rules.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    # Call Model Security Management API to list security rules
    # Reference: ./knowledge/prisma-airs-sdk-main/src/model-security/security-rules-client.ts
    # SDK path: /v1/security-rules (management plane)
    url_suffix = "/v1/security-rules"
    params = {
        "offset": "0",
        "limit": str(limit) if limit else "100"
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityRuleResponseSchema
    # Fields: uuid, name, description, rule_type, compatible_sources, default_state, remediation, editable_fields
    rules_raw = response.get("rules", [])
    rules = []

    for rule in rules_raw:
        rule_info = {
            "uuid": rule.get("uuid"),
            "name": rule.get("name"),
            "description": rule.get("description"),
            "rule_type": rule.get("rule_type"),
            "compatible_sources": rule.get("compatible_sources"),
            "default_state": rule.get("default_state")
        }
        rules.append(rule_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Rules",
        rules,
        headers=["uuid", "name", "rule_type", "default_state"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRule",
        outputs_key_field="uuid",
        outputs=rules,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List all Red Team targets.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    target_type = args.get("target_type")
    status = args.get("status")

    # Build query parameters
    params: dict[str, Any] = {"limit": limit}
    if target_type:
        params["target_type"] = target_type
    if status:
        params["status"] = status

    # Call Red Team targets list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts
    response = client.http_request(
        method="GET",
        url_suffix=RED_TEAM_TARGETS_ENDPOINT,
        params=params,
        use_redteam_mgmt=True
    )

    # Extract targets from response (forward-compatible: capture all fields)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    targets_data = response.get("data", [])
    targets = []
    for target in targets_data:
        target_info = {
            "uuid": target.get("uuid"),
            "name": target.get("name"),
            "tsg_id": target.get("tsg_id"),
            "status": target.get("status"),
            "active": target.get("active"),
            "validated": target.get("validated"),
            "created_at": target.get("created_at"),
            "updated_at": target.get("updated_at"),
            "description": target.get("description"),
            "target_type": target.get("target_type"),
            "connection_type": target.get("connection_type"),
            "api_endpoint_type": target.get("api_endpoint_type"),
            "response_mode": target.get("response_mode"),
            "session_supported": target.get("session_supported"),
            "auth_type": target.get("auth_type"),
            "created_by_user_id": target.get("created_by_user_id"),
            "updated_by_user_id": target.get("updated_by_user_id")
        }
        targets.append(target_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Targets",
        targets,
        headers=["uuid", "name", "target_type", "status", "active", "validated", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=targets,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team target.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Required fields
    name = args.get("name")
    if not name:
        raise ValueError("name is required")

    # Build request body according to TargetCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetRequestBaseFields)
    request_body: dict[str, Any] = {
        "name": name
    }

    # Optional fields
    if args.get("description"):
        request_body["description"] = args.get("description")
    if args.get("target_type"):
        request_body["target_type"] = args.get("target_type")
    if args.get("connection_type"):
        request_body["connection_type"] = args.get("connection_type")
    if args.get("api_endpoint_type"):
        request_body["api_endpoint_type"] = args.get("api_endpoint_type")
    if args.get("response_mode"):
        request_body["response_mode"] = args.get("response_mode")
    if args.get("session_supported") is not None:
        request_body["session_supported"] = argToBoolean(args.get("session_supported"))

    # Connection params (JSON)
    if args.get("connection_params"):
        import json
        request_body["connection_params"] = json.loads(args.get("connection_params"))

    # Optional validation parameter
    validate = argToBoolean(args.get("validate", False))
    params = {"validate": str(validate).lower()} if validate is not None else None

    # Call Red Team target create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (create method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="POST",
        url_suffix=RED_TEAM_TARGETS_ENDPOINT,
        json_data=request_body,
        params=params,
        use_redteam_mgmt=True
    )

    # Parse response according to TargetResponseSchema
    target_info = {
        "uuid": response.get("uuid"),
        "tsg_id": response.get("tsg_id"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "description": response.get("description"),
        "target_type": response.get("target_type"),
        "connection_type": response.get("connection_type"),
        "api_endpoint_type": response.get("api_endpoint_type"),
        "response_mode": response.get("response_mode"),
        "session_supported": response.get("session_supported"),
        "auth_type": response.get("auth_type"),
        "version": response.get("version"),
        "created_by_user_id": response.get("created_by_user_id")
    }

    readable_output = tableToMarkdown(
        f"Red Team Target Created: {name}",
        [target_info],
        headers=["uuid", "name", "target_type", "status", "active", "validated"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team target details by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Red Team target get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (get method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}",
        use_redteam_mgmt=True
    )

    # Parse response according to TargetResponseSchema
    target_info = {
        "uuid": response.get("uuid"),
        "tsg_id": response.get("tsg_id"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "description": response.get("description"),
        "target_type": response.get("target_type"),
        "connection_type": response.get("connection_type"),
        "api_endpoint_type": response.get("api_endpoint_type"),
        "response_mode": response.get("response_mode"),
        "session_supported": response.get("session_supported"),
        "auth_type": response.get("auth_type"),
        "version": response.get("version"),
        "secret_version": response.get("secret_version"),
        "created_by_user_id": response.get("created_by_user_id"),
        "updated_by_user_id": response.get("updated_by_user_id"),
        "profiling_status": response.get("profiling_status")
    }

    # Include metadata if present
    target_metadata = response.get("target_metadata")
    if target_metadata:
        target_info["target_metadata"] = target_metadata

    target_background = response.get("target_background")
    if target_background:
        target_info["target_background"] = target_background

    additional_context = response.get("additional_context")
    if additional_context:
        target_info["additional_context"] = additional_context

    readable_output = tableToMarkdown(
        f"Red Team Target: {target_info.get('name', uuid)}",
        [target_info],
        headers=["uuid", "name", "target_type", "status", "active", "validated", "connection_type"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing Red Team target.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Build request body according to TargetUpdateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetRequestBaseFields)
    # Note: At least one field must be provided for update
    request_body: dict[str, Any] = {}

    # Name is required in the schema, but for update we might want to keep the existing name
    # Check if name is provided, otherwise we need to get the current target first
    if args.get("name"):
        request_body["name"] = args.get("name")

    # Optional fields
    if args.get("description") is not None:
        request_body["description"] = args.get("description")
    if args.get("target_type"):
        request_body["target_type"] = args.get("target_type")
    if args.get("connection_type"):
        request_body["connection_type"] = args.get("connection_type")
    if args.get("api_endpoint_type"):
        request_body["api_endpoint_type"] = args.get("api_endpoint_type")
    if args.get("response_mode"):
        request_body["response_mode"] = args.get("response_mode")
    if args.get("session_supported") is not None:
        request_body["session_supported"] = argToBoolean(args.get("session_supported"))

    # Connection params (JSON)
    if args.get("connection_params"):
        import json
        request_body["connection_params"] = json.loads(args.get("connection_params"))

    # If no fields provided, error
    if not request_body:
        raise ValueError("At least one field must be provided for update (name, description, target_type, etc.)")

    # If name not provided but other fields are, we need to preserve the existing name
    # by fetching the current target first
    if "name" not in request_body:
        current_target = client.http_request(
            method="GET",
            url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}",
            use_redteam_mgmt=True
        )
        request_body["name"] = current_target.get("name")

    # Optional validation parameter
    validate = args.get("validate")
    params = {"validate": str(argToBoolean(validate)).lower()} if validate is not None else None

    # Call Red Team target update endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (update method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}",
        json_data=request_body,
        params=params,
        use_redteam_mgmt=True
    )

    # Parse response according to TargetResponseSchema
    target_info = {
        "uuid": response.get("uuid"),
        "tsg_id": response.get("tsg_id"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "description": response.get("description"),
        "target_type": response.get("target_type"),
        "connection_type": response.get("connection_type"),
        "updated_by_user_id": response.get("updated_by_user_id")
    }

    readable_output = tableToMarkdown(
        f"Red Team Target Updated: {target_info.get('name', uuid)}",
        [target_info],
        headers=["uuid", "name", "target_type", "status", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a Red Team target.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Red Team target delete endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (delete method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (BaseResponseSchema)
    response = client.http_request(
        method="DELETE",
        url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}",
        use_redteam_mgmt=True
    )

    # Parse response according to BaseResponseSchema (optional - may be empty)
    # Fields: message, status
    delete_info = {
        "uuid": uuid,
        "message": response.get("message", "Target deleted successfully"),
        "status": response.get("status", 200)
    }

    readable_output = f"## Red Team Target Deleted\n\n**UUID:** {uuid}\n\n**Status:** {delete_info.get('status')}\n\n**Message:** {delete_info.get('message')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetDelete",
        outputs_key_field="uuid",
        outputs=delete_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_probe_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Probe a Red Team target to validate connectivity and profiling.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Required fields for probe
    name = args.get("name")
    if not name:
        raise ValueError("name is required for target probe")

    # Build request body according to TargetProbeRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetProbeRequestSchema)
    request_body: dict[str, Any] = {
        "name": name
    }

    # Optional UUID (for probing existing target)
    if args.get("uuid"):
        request_body["uuid"] = args.get("uuid")

    # Optional fields (same as create)
    if args.get("description"):
        request_body["description"] = args.get("description")
    if args.get("target_type"):
        request_body["target_type"] = args.get("target_type")
    if args.get("connection_type"):
        request_body["connection_type"] = args.get("connection_type")
    if args.get("api_endpoint_type"):
        request_body["api_endpoint_type"] = args.get("api_endpoint_type")
    if args.get("response_mode"):
        request_body["response_mode"] = args.get("response_mode")

    # Connection params (JSON)
    if args.get("connection_params"):
        import json
        request_body["connection_params"] = json.loads(args.get("connection_params"))

    # Probe fields - array of fields to probe (e.g., ["multi_turn", "rate_limit"])
    if args.get("probe_fields"):
        probe_fields_str = args.get("probe_fields")
        request_body["probe_fields"] = [field.strip() for field in probe_fields_str.split(",")]

    # Call Red Team target probe endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (probe method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/probe",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to TargetResponseSchema
    target_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "profiling_status": response.get("profiling_status"),
        "target_type": response.get("target_type"),
        "connection_type": response.get("connection_type")
    }

    # Include target_metadata if present (contains probe results)
    target_metadata = response.get("target_metadata")
    if target_metadata:
        target_info["target_metadata"] = target_metadata
        # Extract specific probe results for display
        target_info["multi_turn_supported"] = target_metadata.get("multi_turn")
        target_info["rate_limit_enabled"] = target_metadata.get("rate_limit_enabled")
        target_info["content_filter_enabled"] = target_metadata.get("content_filter_enabled")

    readable_output = tableToMarkdown(
        f"Red Team Target Probe Results: {name}",
        [target_info],
        headers=["uuid", "name", "status", "validated", "profiling_status", "multi_turn_supported"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_scans_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List all Red Team scans.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    job_type = args.get("job_type")
    status = args.get("status")

    # Build query parameters
    params: dict[str, Any] = {"limit": limit}
    if job_type:
        params["job_type"] = job_type
    if status:
        params["status"] = status

    # Call Red Team scans list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts
    response = client.http_request(
        method="GET",
        url_suffix=RED_TEAM_SCANS_ENDPOINT,
        params=params,
        use_redteam_data=True
    )

    # Extract scans from response (forward-compatible: capture all fields)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (ScanResponseSchema)
    scans_data = response.get("data", [])
    scans = []
    for scan in scans_data:
        scan_info = {
            "uuid": scan.get("uuid"),
            "tsg_id": scan.get("tsg_id"),
            "job_type": scan.get("job_type"),
            "status": scan.get("status"),
            "created_at": scan.get("created_at"),
            "updated_at": scan.get("updated_at"),
            "target_uuid": scan.get("target_uuid"),
            "target_name": scan.get("target_name"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "progress": scan.get("progress"),
            "total_prompts": scan.get("total_prompts"),
            "completed_prompts": scan.get("completed_prompts"),
            "failed_prompts": scan.get("failed_prompts"),
            "error_message": scan.get("error_message")
        }
        scans.append(scan_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Scans",
        scans,
        headers=["uuid", "job_type", "status", "target_name", "progress", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScan",
        outputs_key_field="uuid",
        outputs=scans,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_scan_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team scan status and details.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team scan get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts (get method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (JobResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_SCANS_ENDPOINT}/{job_id}",
        use_redteam_data=True
    )

    # Parse response according to JobResponseSchema
    # Critical fields: uuid, name, target, job_type, status, total, completed, score, asr
    scan_info = {
        "uuid": response.get("uuid"),
        "tsg_id": response.get("tsg_id"),
        "name": response.get("name"),
        "job_type": response.get("job_type"),
        "status": response.get("status"),
        "target_id": response.get("target_id"),
        "target_type": response.get("target_type"),
        "total": response.get("total"),
        "completed": response.get("completed"),
        "score": response.get("score"),
        "asr": response.get("asr"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "created_by_user_id": response.get("created_by_user_id"),
        "version": response.get("version"),
        "metering_quota_uuid": response.get("metering_quota_uuid"),
        "counted_towards_quota": response.get("counted_towards_quota"),
        "invocation_id": response.get("invocation_id")
    }

    # Add target reference if present
    target = response.get("target", {})
    if target:
        scan_info["target_name"] = target.get("name")
        scan_info["target_uuid"] = target.get("uuid")

    # Add time record if present
    time_record = response.get("time_record", {})
    if time_record:
        scan_info["started_at"] = time_record.get("started_at")
        scan_info["completed_at"] = time_record.get("completed_at")
        scan_info["aborted_at"] = time_record.get("aborted_at")

    # Calculate progress percentage if total > 0
    total = scan_info.get("total")
    completed = scan_info.get("completed")
    if total and completed is not None:
        scan_info["progress_percentage"] = round((completed / total) * 100, 2) if total > 0 else 0
        scan_info["progress"] = f"{completed}/{total}"

    readable_output = tableToMarkdown(
        f"Red Team Scan: {scan_info.get('name', job_id)}",
        [scan_info],
        headers=["uuid", "name", "job_type", "status", "progress", "score", "asr", "target_name"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScan",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_scan_abort_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Abort a running Red Team scan.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team scan abort endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts (abort method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (JobAbortResponseSchema)
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_SCANS_ENDPOINT}/{job_id}/abort",
        use_redteam_data=True
    )

    # Parse response according to JobAbortResponseSchema
    # Fields: job_id, message
    abort_info = {
        "job_id": response.get("job_id"),
        "message": response.get("message")
    }

    readable_output = f"## Red Team Scan Aborted\n\n**Job ID:** {abort_info.get('job_id')}\n\n**Message:** {abort_info.get('message')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanAbort",
        outputs_key_field="job_id",
        outputs=abort_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_categories_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Red Team attack categories.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team categories endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts (getCategories method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CategoryModelSchema)
    response = client.http_request(
        method="GET",
        url_suffix=RED_TEAM_CATEGORIES_ENDPOINT,
        use_redteam_data=True
    )

    # Parse response - returns array of CategoryModel
    # Fields: id, display_name, description, preselect, sub_categories
    categories = []
    for category in response:
        category_info = {
            "id": category.get("id"),
            "display_name": category.get("display_name"),
            "description": category.get("description"),
            "preselect": category.get("preselect"),
            "sub_category_count": len(category.get("sub_categories", []))
        }

        # Extract subcategory details
        sub_cats = []
        for sub_cat in category.get("sub_categories", []):
            sub_cat_info = {
                "id": sub_cat.get("id"),
                "display_name": sub_cat.get("display_name"),
                "description": sub_cat.get("description"),
                "preselect": sub_cat.get("preselect"),
                "active": sub_cat.get("active")
            }
            sub_cats.append(sub_cat_info)

        category_info["sub_categories"] = sub_cats
        categories.append(category_info)

    readable_output = tableToMarkdown(
        "Red Team Attack Categories",
        categories,
        headers=["id", "display_name", "description", "sub_category_count"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCategory",
        outputs_key_field="id",
        outputs=categories,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_report_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    job_type = args.get("job_type", "STATIC")  # Default to STATIC if not provided

    if not job_id:
        raise ValueError("job_id is required")

    # Determine endpoint based on job type
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts
    # SDK schemas: StaticJobReportSchema, DynamicJobReportSchema
    if job_type.upper() == "DYNAMIC":
        url_suffix = f"{RED_TEAM_REPORT_DYNAMIC_ENDPOINT}/{job_id}/report"
    else:
        # STATIC or CUSTOM scans use static report endpoint
        url_suffix = f"{RED_TEAM_REPORT_STATIC_ENDPOINT}/{job_id}/report"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_redteam_data=True
    )

    # Parse response based on job type
    if job_type.upper() == "DYNAMIC":
        # DynamicJobReportSchema fields: total_goals, total_streams, total_threats, goals_achieved, score, asr, report_summary
        report_info = {
            "job_id": job_id,
            "job_type": job_type,
            "total_goals": response.get("total_goals"),
            "total_streams": response.get("total_streams"),
            "total_threats": response.get("total_threats"),
            "goals_achieved": response.get("goals_achieved"),
            "score": response.get("score"),
            "asr": response.get("asr"),
            "report_summary": response.get("report_summary")
        }

        readable_output = tableToMarkdown(
            f"Red Team Report (Dynamic) - Job {job_id}",
            [report_info],
            headers=["job_type", "total_goals", "goals_achieved", "total_threats", "score", "asr"],
            headerTransform=lambda h: h.replace("_", " ").title()
        )

    else:
        # StaticJobReportSchema fields: severity_report, asr, score, security_report, safety_report, brand_report, compliance_report, report_summary, recommendations
        severity_report = response.get("severity_report", {})
        severity_stats = severity_report.get("stats", [])

        report_info = {
            "job_id": job_id,
            "job_type": job_type,
            "score": response.get("score"),
            "asr": response.get("asr"),
            "total_attacks": severity_report.get("total_attacks"),
            "successful_attacks": severity_report.get("successful"),
            "failed_attacks": severity_report.get("failed"),
            "report_summary": response.get("report_summary")
        }

        # Build severity breakdown
        severity_breakdown = []
        for severity_stat in severity_stats:
            severity_breakdown.append({
                "severity": severity_stat.get("severity"),
                "successful": severity_stat.get("successful"),
                "failed": severity_stat.get("failed")
            })

        report_info["severity_breakdown"] = severity_breakdown

        # Build category reports
        category_reports = []
        for cat_type in ["security_report", "safety_report", "brand_report"]:
            cat_report = response.get(cat_type)
            if cat_report:
                category_reports.append({
                    "category": cat_type.replace("_report", "").title(),
                    "id": cat_report.get("id"),
                    "display_name": cat_report.get("display_name"),
                    "asr": cat_report.get("asr"),
                    "total_prompts": cat_report.get("total_prompts"),
                    "total_attacks": cat_report.get("total_attacks"),
                    "successful": cat_report.get("successful"),
                    "failed": cat_report.get("failed")
                })

        report_info["category_reports"] = category_reports

        # Extract recommendations if present
        recommendations_data = response.get("recommendations", {})
        if recommendations_data:
            other_measures = recommendations_data.get("other_measures", [])
            report_info["recommendations_count"] = len(other_measures)

        readable_output = tableToMarkdown(
            f"Red Team Report (Static) - Job {job_id}",
            [report_info],
            headers=["job_type", "score", "asr", "total_attacks", "successful_attacks", "failed_attacks"],
            headerTransform=lambda h: h.replace("_", " ").title()
        )

        # Add severity breakdown table
        if severity_breakdown:
            readable_output += "\n\n" + tableToMarkdown(
                "Severity Breakdown",
                severity_breakdown,
                headers=["severity", "successful", "failed"],
                headerTransform=lambda h: h.replace("_", " ").title()
            )

        # Add category reports table
        if category_reports:
            readable_output += "\n\n" + tableToMarkdown(
                "Category Reports",
                category_reports,
                headers=["category", "display_name", "asr", "total_attacks", "successful", "failed"],
                headerTransform=lambda h: h.replace("_", " ").title()
            )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamReport",
        outputs_key_field="job_id",
        outputs=report_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_eula_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team EULA acceptance status.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team EULA status endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/eula-client.ts (getStatus method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/status",
        use_redteam_mgmt=True
    )

    # Parse response according to EulaResponseSchema
    # Fields: uuid, is_accepted, accepted_at, accepted_by_user_id
    eula_info = {
        "uuid": response.get("uuid"),
        "is_accepted": response.get("is_accepted"),
        "accepted_at": response.get("accepted_at"),
        "accepted_by_user_id": response.get("accepted_by_user_id")
    }

    # Create human-readable output
    status_text = "Accepted" if eula_info.get("is_accepted") else "Not Accepted"
    readable_output = f"## Red Team EULA Status\n\n**Status:** {status_text}\n\n"

    if eula_info.get("is_accepted"):
        readable_output += f"**Accepted At:** {eula_info.get('accepted_at', 'N/A')}\n\n"
        readable_output += f"**Accepted By:** {eula_info.get('accepted_by_user_id', 'N/A')}"
    else:
        readable_output += "**Note:** The EULA must be accepted before running Red Team scans."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamEula",
        outputs_key_field="uuid",
        outputs=eula_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_eula_content_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team EULA content (full text).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team EULA content endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/eula-client.ts (getContent method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaContentResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/content",
        use_redteam_mgmt=True
    )

    # Parse response according to EulaContentResponseSchema
    # Fields: content (string - full EULA text)
    eula_content = response.get("content", "")

    eula_info = {
        "content": eula_content,
        "content_length": len(eula_content)
    }

    # Truncate content for display (show first 1000 chars)
    display_content = eula_content[:1000]
    if len(eula_content) > 1000:
        display_content += f"\n\n... (truncated, {len(eula_content) - 1000} more characters)\n\nFull content available in context output."

    readable_output = f"## Red Team EULA Content\n\n**Length:** {len(eula_content)} characters\n\n**Content Preview:**\n\n```\n{display_content}\n```"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamEula",
        outputs_key_field="content_length",
        outputs=eula_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_eula_accept_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Accept the Red Team EULA.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Get EULA content first (required for accept request)
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/eula-client.ts (accept method example)
    content_response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/content",
        use_redteam_mgmt=True
    )

    eula_content = content_response.get("content", "")
    if not eula_content:
        raise ValueError("Failed to retrieve EULA content")

    # Build request body according to EulaAcceptRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaAcceptRequestSchema)
    # Fields: eula_content (required), accepted_at (optional)
    request_body = {
        "eula_content": eula_content
    }

    # Optional accepted_at timestamp (will use server time if not provided)
    if args.get("accepted_at"):
        request_body["accepted_at"] = args.get("accepted_at")

    # Call Red Team EULA accept endpoint
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaResponseSchema)
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/accept",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to EulaResponseSchema
    # Fields: uuid, is_accepted, accepted_at, accepted_by_user_id
    eula_info = {
        "uuid": response.get("uuid"),
        "is_accepted": response.get("is_accepted"),
        "accepted_at": response.get("accepted_at"),
        "accepted_by_user_id": response.get("accepted_by_user_id")
    }

    # Create success message
    readable_output = f"## Red Team EULA Accepted\n\n**Status:** {'Accepted' if eula_info.get('is_accepted') else 'Failed'}\n\n"
    readable_output += f"**Accepted At:** {eula_info.get('accepted_at', 'N/A')}\n\n"
    readable_output += f"**Accepted By:** {eula_info.get('accepted_by_user_id', 'N/A')}\n\n"
    readable_output += "You can now create and run Red Team scans."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamEula",
        outputs_key_field="uuid",
        outputs=eula_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompts_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new prompt in a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - prompt_set_uuid (required): UUID of the prompt set
              - prompt (required): The prompt text
              - goal (optional): Custom goal for the prompt
              - properties (optional): JSON object with additional properties

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameters
    prompt_set_uuid = args.get("prompt_set_uuid")
    prompt_text = args.get("prompt")

    if not prompt_set_uuid:
        raise ValueError("prompt_set_uuid is required")
    if not prompt_text:
        raise ValueError("prompt is required")

    # Build request body according to CustomPromptCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptCreateRequestSchema)
    # Fields: prompt (required), prompt_set_id (required), goal (optional), properties (optional)
    request_body = {
        "prompt": prompt_text,
        "prompt_set_id": prompt_set_uuid
    }

    # Optional fields
    if args.get("goal"):
        request_body["goal"] = args.get("goal")

    if args.get("properties"):
        # Parse JSON properties if provided as string
        properties_str = args.get("properties", "")
        try:
            request_body["properties"] = json.loads(properties_str) if isinstance(properties_str, str) else properties_str
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON format for properties: {properties_str}")

    # Call Red Team Custom Attack endpoint to create prompt
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (createPrompt method)
    # Endpoint: POST /v1/custom-attack/custom-prompt-set/custom-prompt
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/custom-prompt",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptResponseSchema
    # Fields: uuid, prompt, user_defined_goal, status, active, prompt_set_id, created_at, updated_at
    #         goal (optional), properties (optional), property_assignments (optional),
    #         detector_category (optional), severity (optional), extra_info (optional)
    prompt_info = {
        "uuid": response.get("uuid"),
        "prompt": response.get("prompt"),
        "user_defined_goal": response.get("user_defined_goal"),
        "status": response.get("status"),
        "active": response.get("active"),
        "prompt_set_id": response.get("prompt_set_id"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    if response.get("goal"):
        prompt_info["goal"] = response.get("goal")
    if response.get("properties"):
        prompt_info["properties"] = response.get("properties")

    # Create readable output
    readable_output = f"## Red Team Prompt Created\n\n"
    readable_output += f"**UUID:** {prompt_info.get('uuid')}\n\n"
    readable_output += f"**Prompt Set ID:** {prompt_info.get('prompt_set_id')}\n\n"
    readable_output += f"**Status:** {prompt_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_info.get('active')}\n\n"
    readable_output += f"**User Defined Goal:** {prompt_info.get('user_defined_goal')}\n\n"
    readable_output += f"**Prompt:** {prompt_info.get('prompt', 'N/A')[:200]}...\n\n"
    readable_output += f"**Created At:** {prompt_info.get('created_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPrompt",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompts_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List prompts in a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - prompt_set_uuid (required): UUID of the prompt set
              - limit (optional): Max records to return
              - skip (optional): Number of records to skip
              - search (optional): Free-text search filter
              - status (optional): Filter by status
              - active (optional): Filter by active status (true/false)

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameter
    prompt_set_uuid = args.get("prompt_set_uuid")
    if not prompt_set_uuid:
        raise ValueError("prompt_set_uuid is required")

    # Build query parameters according to PromptListOptions
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (listPrompts method)
    # Base: skip, limit, search (from ListingOptions)
    # Extended: status, active (from PromptListOptions)
    params: dict[str, Any] = {}

    if args.get("limit"):
        params["limit"] = int(args.get("limit", 50))
    if args.get("skip"):
        params["skip"] = int(args.get("skip", 0))
    if args.get("search"):
        params["search"] = args.get("search")
    if args.get("status"):
        params["status"] = args.get("status")
    if args.get("active"):
        # Convert to string as SDK does: params.active = String(opts.active)
        active_val = args.get("active", "").lower()
        if active_val in ["true", "false"]:
            params["active"] = active_val

    # Call Red Team Custom Attack endpoint to list prompts
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (listPrompts method)
    # Endpoint: GET /v1/custom-attack/custom-prompt-set/{promptSetUuid}/list-custom-prompts
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{prompt_set_uuid}/list-custom-prompts",
        params=params,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptListSchema
    # Response structure: { pagination: RedTeamPaginationSchema, data: [CustomPromptListItemSchema] }
    # CustomPromptListItemSchema fields: uuid, prompt, user_defined_goal, status, active,
    #                                     created_at, updated_at, goal (optional), properties (optional)
    prompts = response.get("data", [])
    pagination = response.get("pagination", {})

    prompts_list = []
    for prompt in prompts:
        prompt_info = {
            "uuid": prompt.get("uuid"),
            "prompt": prompt.get("prompt"),
            "user_defined_goal": prompt.get("user_defined_goal"),
            "status": prompt.get("status"),
            "active": prompt.get("active"),
            "created_at": prompt.get("created_at"),
            "updated_at": prompt.get("updated_at")
        }
        # Add optional fields if present
        if prompt.get("goal"):
            prompt_info["goal"] = prompt.get("goal")
        if prompt.get("properties"):
            prompt_info["properties"] = prompt.get("properties")

        prompts_list.append(prompt_info)

    # Create readable output table
    if prompts_list:
        readable_output = f"## Red Team Prompts (Total: {pagination.get('total_items', len(prompts_list))})\n\n"
        readable_output += "| UUID | Status | Active | User Defined Goal | Prompt |\n"
        readable_output += "|------|--------|--------|-------------------|--------|\n"
        for prompt in prompts_list:
            prompt_text = prompt.get("prompt", "N/A")
            # Truncate long prompts for table display
            prompt_preview = prompt_text[:50] + "..." if len(prompt_text) > 50 else prompt_text
            readable_output += f"| {prompt.get('uuid', 'N/A')} | {prompt.get('status', 'N/A')} | {prompt.get('active', 'N/A')} | {prompt.get('user_defined_goal', 'N/A')} | {prompt_preview} |\n"
    else:
        readable_output = "## No prompts found in this prompt set"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPrompts",
        outputs_key_field="uuid",
        outputs=prompts_list,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompts_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a specific prompt by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - prompt_set_uuid (required): UUID of the prompt set
              - prompt_uuid (required): UUID of the prompt

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameters
    prompt_set_uuid = args.get("prompt_set_uuid")
    prompt_uuid = args.get("prompt_uuid")

    if not prompt_set_uuid:
        raise ValueError("prompt_set_uuid is required")
    if not prompt_uuid:
        raise ValueError("prompt_uuid is required")

    # Call Red Team Custom Attack endpoint to get prompt details
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (getPrompt method)
    # Endpoint: GET /v1/custom-attack/custom-prompt-set/{promptSetUuid}/custom-prompt/{promptUuid}
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}",
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptResponseSchema
    # Fields: uuid, prompt, user_defined_goal, status, active, prompt_set_id, created_at, updated_at
    #         goal (optional), properties (optional), property_assignments (optional),
    #         detector_category (optional), severity (optional), extra_info (optional)
    prompt_info = {
        "uuid": response.get("uuid"),
        "prompt": response.get("prompt"),
        "user_defined_goal": response.get("user_defined_goal"),
        "status": response.get("status"),
        "active": response.get("active"),
        "prompt_set_id": response.get("prompt_set_id"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["goal", "properties", "property_assignments", "detector_category", "severity", "extra_info"]
    for field in optional_fields:
        if response.get(field):
            prompt_info[field] = response.get(field)

    # Create detailed readable output
    readable_output = f"## Red Team Prompt Details\n\n"
    readable_output += f"**UUID:** {prompt_info.get('uuid')}\n\n"
    readable_output += f"**Prompt Set ID:** {prompt_info.get('prompt_set_id')}\n\n"
    readable_output += f"**Status:** {prompt_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_info.get('active')}\n\n"
    readable_output += f"**User Defined Goal:** {prompt_info.get('user_defined_goal')}\n\n"

    # Display full prompt text
    readable_output += f"**Prompt:**\n```\n{prompt_info.get('prompt', 'N/A')}\n```\n\n"

    # Add optional fields if present
    if prompt_info.get("goal"):
        readable_output += f"**Goal:** {prompt_info.get('goal')}\n\n"
    if prompt_info.get("detector_category"):
        readable_output += f"**Detector Category:** {prompt_info.get('detector_category')}\n\n"
    if prompt_info.get("severity"):
        readable_output += f"**Severity:** {prompt_info.get('severity')}\n\n"

    readable_output += f"**Created At:** {prompt_info.get('created_at', 'N/A')}\n\n"
    readable_output += f"**Updated At:** {prompt_info.get('updated_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPrompt",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompts_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing prompt.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - prompt_set_uuid (required): UUID of the prompt set
              - prompt_uuid (required): UUID of the prompt to update
              - prompt (optional): Updated prompt text
              - goal (optional): Updated custom goal
              - properties (optional): Updated properties JSON object

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameters
    prompt_set_uuid = args.get("prompt_set_uuid")
    prompt_uuid = args.get("prompt_uuid")

    if not prompt_set_uuid:
        raise ValueError("prompt_set_uuid is required")
    if not prompt_uuid:
        raise ValueError("prompt_uuid is required")

    # Build request body according to CustomPromptUpdateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptUpdateRequestSchema)
    # Fields: prompt (optional), goal (optional), properties (optional)
    # All fields are optional in update request
    request_body: dict[str, Any] = {}

    if args.get("prompt"):
        request_body["prompt"] = args.get("prompt")

    if args.get("goal"):
        request_body["goal"] = args.get("goal")

    if args.get("properties"):
        # Parse JSON properties if provided as string
        properties_str = args.get("properties", "")
        try:
            request_body["properties"] = json.loads(properties_str) if isinstance(properties_str, str) else properties_str
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON format for properties: {properties_str}")

    # Ensure at least one field is provided
    if not request_body:
        raise ValueError("At least one field to update must be provided (prompt, goal, or properties)")

    # Call Red Team Custom Attack endpoint to update prompt
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (updatePrompt method)
    # Endpoint: PUT /v1/custom-attack/custom-prompt-set/{promptSetUuid}/custom-prompt/{promptUuid}
    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptResponseSchema
    # Fields: uuid, prompt, user_defined_goal, status, active, prompt_set_id, created_at, updated_at
    #         goal (optional), properties (optional), property_assignments (optional),
    #         detector_category (optional), severity (optional), extra_info (optional)
    prompt_info = {
        "uuid": response.get("uuid"),
        "prompt": response.get("prompt"),
        "user_defined_goal": response.get("user_defined_goal"),
        "status": response.get("status"),
        "active": response.get("active"),
        "prompt_set_id": response.get("prompt_set_id"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["goal", "properties", "property_assignments", "detector_category", "severity", "extra_info"]
    for field in optional_fields:
        if response.get(field):
            prompt_info[field] = response.get(field)

    # Create readable output
    readable_output = f"## Red Team Prompt Updated\n\n"
    readable_output += f"**UUID:** {prompt_info.get('uuid')}\n\n"
    readable_output += f"**Prompt Set ID:** {prompt_info.get('prompt_set_id')}\n\n"
    readable_output += f"**Status:** {prompt_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_info.get('active')}\n\n"
    readable_output += f"**User Defined Goal:** {prompt_info.get('user_defined_goal')}\n\n"

    # Show updated fields
    if "prompt" in request_body:
        readable_output += f"**Updated Prompt:** {prompt_info.get('prompt', 'N/A')[:200]}...\n\n"
    if "goal" in request_body:
        readable_output += f"**Updated Goal:** {prompt_info.get('goal', 'N/A')}\n\n"

    readable_output += f"**Updated At:** {prompt_info.get('updated_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPrompt",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompts_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a prompt from a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - prompt_set_uuid (required): UUID of the prompt set
              - prompt_uuid (required): UUID of the prompt to delete

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameters
    prompt_set_uuid = args.get("prompt_set_uuid")
    prompt_uuid = args.get("prompt_uuid")

    if not prompt_set_uuid:
        raise ValueError("prompt_set_uuid is required")
    if not prompt_uuid:
        raise ValueError("prompt_uuid is required")

    # Call Red Team Custom Attack endpoint to delete prompt
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (deletePrompt method)
    # Endpoint: DELETE /v1/custom-attack/custom-prompt-set/{promptSetUuid}/custom-prompt/{promptUuid}
    # Response: BaseResponse (message, status) or undefined
    response = client.http_request(
        method="DELETE",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}",
        use_redteam_mgmt=True,
        resp_type="response"  # Allow empty response
    )

    # Parse response according to BaseResponseSchema (optional)
    # Fields: message (optional), status (optional)
    # SDK allows undefined response for successful deletion
    result_info = {
        "prompt_uuid": prompt_uuid,
        "prompt_set_uuid": prompt_set_uuid,
        "status": "deleted"
    }

    # Try to extract response data if present
    if response and hasattr(response, 'json'):
        try:
            response_data = response.json()
            if response_data.get("message"):
                result_info["message"] = response_data.get("message")
            if response_data.get("status"):
                result_info["api_status"] = response_data.get("status")
        except Exception:
            # Empty or non-JSON response is valid for DELETE
            pass

    # Create readable output
    readable_output = f"## Red Team Prompt Deleted\n\n"
    readable_output += f"**Prompt UUID:** {prompt_uuid}\n\n"
    readable_output += f"**Prompt Set UUID:** {prompt_set_uuid}\n\n"
    readable_output += f"**Status:** Successfully deleted"

    if result_info.get("message"):
        readable_output += f"\n\n**Message:** {result_info.get('message')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptDeleted",
        outputs_key_field="prompt_uuid",
        outputs=result_info,
        readable_output=readable_output,
        raw_response=result_info
    )


def redteam_prompt_sets_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team prompt set for custom attack scenarios.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - name (required): Name of the prompt set
              - description (optional): Description of the prompt set
              - property_names (optional): Comma-separated list of property names

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameter
    name = args.get("name")
    if not name:
        raise ValueError("name is required")

    # Build request body according to CustomPromptSetCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetCreateRequestSchema)
    # Fields: name (required), description (optional), property_names (optional array)
    request_body: dict[str, Any] = {
        "name": name
    }

    # Optional fields
    if args.get("description"):
        request_body["description"] = args.get("description")

    if args.get("property_names"):
        # Parse comma-separated property names into array
        property_names_str = args.get("property_names", "")
        request_body["property_names"] = [name.strip() for name in property_names_str.split(",")]

    # Call Red Team Custom Attack endpoint to create prompt set
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (createPromptSet method)
    # Endpoint: POST /v1/custom-attack/custom-prompt-set
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptSetResponseSchema
    # Fields: uuid, name, active, archive, status, created_at, updated_at
    #         description (optional), property_names (optional), properties (optional),
    #         stats (optional), extra_info (optional), version (optional),
    #         created_by_user_id (optional), updated_by_user_id (optional)
    prompt_set_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "active": response.get("active"),
        "archive": response.get("archive"),
        "status": response.get("status"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["description", "property_names", "properties", "stats", "extra_info",
                       "version", "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    readable_output = f"## Red Team Prompt Set Created\n\n"
    readable_output += f"**UUID:** {prompt_set_info.get('uuid')}\n\n"
    readable_output += f"**Name:** {prompt_set_info.get('name')}\n\n"
    readable_output += f"**Status:** {prompt_set_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_set_info.get('active')}\n\n"
    readable_output += f"**Archive:** {prompt_set_info.get('archive')}\n\n"

    if prompt_set_info.get("description"):
        readable_output += f"**Description:** {prompt_set_info.get('description')}\n\n"
    if prompt_set_info.get("property_names"):
        readable_output += f"**Property Names:** {', '.join(prompt_set_info.get('property_names', []))}\n\n"

    readable_output += f"**Created At:** {prompt_set_info.get('created_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSet",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompt_sets_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Red Team prompt sets for custom attack scenarios.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - limit (optional): Max records to return
              - skip (optional): Number of records to skip
              - search (optional): Free-text search filter
              - status (optional): Filter by status
              - active (optional): Filter by active status (true/false)
              - archive (optional): Filter by archive status (true/false)

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Build query parameters according to PromptSetListOptions
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (listPromptSets method)
    # Base: skip, limit, search (from ListingOptions)
    # Extended: status, active, archive (from PromptSetListOptions)
    params: dict[str, Any] = {}

    if args.get("limit"):
        params["limit"] = int(args.get("limit", 50))
    if args.get("skip"):
        params["skip"] = int(args.get("skip", 0))
    if args.get("search"):
        params["search"] = args.get("search")
    if args.get("status"):
        params["status"] = args.get("status")
    if args.get("active"):
        # Convert to string as SDK does: params.active = String(opts.active)
        active_val = args.get("active", "").lower()
        if active_val in ["true", "false"]:
            params["active"] = active_val
    if args.get("archive"):
        # Convert to string as SDK does: params.archive = String(opts.archive)
        archive_val = args.get("archive", "").lower()
        if archive_val in ["true", "false"]:
            params["archive"] = archive_val

    # Call Red Team Custom Attack endpoint to list prompt sets
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (listPromptSets method)
    # Endpoint: GET /v1/custom-attack/list-custom-prompt-sets
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/list-custom-prompt-sets",
        params=params,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptSetListSchema
    # Response structure: { pagination: RedTeamPaginationSchema, data: [CustomPromptSetListItemSchema] }
    # CustomPromptSetListItemSchema fields: uuid, name, active, archive, status, created_at, updated_at
    #                                        description (optional), property_names (optional),
    #                                        stats (optional), created_by_user_id (optional)
    prompt_sets = response.get("data", [])
    pagination = response.get("pagination", {})

    prompt_sets_list = []
    for prompt_set in prompt_sets:
        set_info = {
            "uuid": prompt_set.get("uuid"),
            "name": prompt_set.get("name"),
            "active": prompt_set.get("active"),
            "archive": prompt_set.get("archive"),
            "status": prompt_set.get("status"),
            "created_at": prompt_set.get("created_at"),
            "updated_at": prompt_set.get("updated_at")
        }
        # Add optional fields if present
        optional_fields = ["description", "property_names", "stats", "created_by_user_id"]
        for field in optional_fields:
            if prompt_set.get(field):
                set_info[field] = prompt_set.get(field)

        prompt_sets_list.append(set_info)

    # Create readable output table
    if prompt_sets_list:
        readable_output = f"## Red Team Prompt Sets (Total: {pagination.get('total_items', len(prompt_sets_list))})\n\n"
        readable_output += "| UUID | Name | Status | Active | Archive | Description |\n"
        readable_output += "|------|------|--------|--------|---------|-------------|\n"
        for ps in prompt_sets_list:
            description = ps.get("description", "N/A")
            # Truncate long descriptions for table display
            desc_preview = str(description)[:30] + "..." if len(str(description)) > 30 else str(description)
            readable_output += f"| {ps.get('uuid', 'N/A')} | {ps.get('name', 'N/A')} | {ps.get('status', 'N/A')} | {ps.get('active', 'N/A')} | {ps.get('archive', 'N/A')} | {desc_preview} |\n"
    else:
        readable_output = "## No prompt sets found"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSets",
        outputs_key_field="uuid",
        outputs=prompt_sets_list,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompt_sets_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get details of a specific Red Team prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - uuid (required): UUID of the prompt set

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameter
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Red Team Custom Attack endpoint to get prompt set details
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (getPromptSet method)
    # Endpoint: GET /v1/custom-attack/custom-prompt-set/{uuid}
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}",
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptSetResponseSchema
    # Fields: uuid, name, active, archive, status, created_at, updated_at
    #         description (optional), property_names (optional), properties (optional),
    #         stats (optional), extra_info (optional), version (optional),
    #         created_by_user_id (optional), updated_by_user_id (optional)
    prompt_set_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "active": response.get("active"),
        "archive": response.get("archive"),
        "status": response.get("status"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["description", "property_names", "properties", "stats", "extra_info",
                       "version", "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create detailed readable output
    readable_output = f"## Red Team Prompt Set Details\n\n"
    readable_output += f"**UUID:** {prompt_set_info.get('uuid')}\n\n"
    readable_output += f"**Name:** {prompt_set_info.get('name')}\n\n"
    readable_output += f"**Status:** {prompt_set_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_set_info.get('active')}\n\n"
    readable_output += f"**Archive:** {prompt_set_info.get('archive')}\n\n"

    # Add optional fields if present
    if prompt_set_info.get("description"):
        readable_output += f"**Description:** {prompt_set_info.get('description')}\n\n"
    if prompt_set_info.get("property_names"):
        readable_output += f"**Property Names:** {', '.join(prompt_set_info.get('property_names', []))}\n\n"
    if prompt_set_info.get("stats"):
        readable_output += f"**Stats:** {prompt_set_info.get('stats')}\n\n"
    if prompt_set_info.get("version"):
        readable_output += f"**Version:** {prompt_set_info.get('version')}\n\n"
    if prompt_set_info.get("created_by_user_id"):
        readable_output += f"**Created By:** {prompt_set_info.get('created_by_user_id')}\n\n"
    if prompt_set_info.get("updated_by_user_id"):
        readable_output += f"**Updated By:** {prompt_set_info.get('updated_by_user_id')}\n\n"

    readable_output += f"**Created At:** {prompt_set_info.get('created_at', 'N/A')}\n\n"
    readable_output += f"**Updated At:** {prompt_set_info.get('updated_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSet",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompt_sets_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing Red Team prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - uuid (required): UUID of the prompt set to update
              - name (optional): Updated name
              - description (optional): Updated description
              - property_names (optional): Updated comma-separated property names
              - archive (optional): Updated archive status (true/false)

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameter
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Build request body according to CustomPromptSetUpdateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetUpdateRequestSchema)
    # Fields: name (optional), description (optional), archive (optional), property_names (optional)
    # All fields are optional in update request
    request_body: dict[str, Any] = {}

    if args.get("name"):
        request_body["name"] = args.get("name")

    if args.get("description"):
        request_body["description"] = args.get("description")

    if args.get("archive"):
        # Convert string to boolean
        archive_val = args.get("archive", "").lower()
        if archive_val in ["true", "false"]:
            request_body["archive"] = archive_val == "true"

    if args.get("property_names"):
        # Parse comma-separated property names into array
        property_names_str = args.get("property_names", "")
        request_body["property_names"] = [name.strip() for name in property_names_str.split(",")]

    # Ensure at least one field is provided
    if not request_body:
        raise ValueError("At least one field to update must be provided (name, description, archive, or property_names)")

    # Call Red Team Custom Attack endpoint to update prompt set
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (updatePromptSet method)
    # Endpoint: PUT /v1/custom-attack/custom-prompt-set/{uuid}
    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptSetResponseSchema
    # Fields: uuid, name, active, archive, status, created_at, updated_at
    #         description (optional), property_names (optional), properties (optional),
    #         stats (optional), extra_info (optional), version (optional),
    #         created_by_user_id (optional), updated_by_user_id (optional)
    prompt_set_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "active": response.get("active"),
        "archive": response.get("archive"),
        "status": response.get("status"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["description", "property_names", "properties", "stats", "extra_info",
                       "version", "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    readable_output = f"## Red Team Prompt Set Updated\n\n"
    readable_output += f"**UUID:** {prompt_set_info.get('uuid')}\n\n"
    readable_output += f"**Name:** {prompt_set_info.get('name')}\n\n"
    readable_output += f"**Status:** {prompt_set_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_set_info.get('active')}\n\n"
    readable_output += f"**Archive:** {prompt_set_info.get('archive')}\n\n"

    # Show updated fields
    if "name" in request_body:
        readable_output += f"**Updated Name:** {prompt_set_info.get('name')}\n\n"
    if "description" in request_body:
        readable_output += f"**Updated Description:** {prompt_set_info.get('description', 'N/A')}\n\n"
    if "property_names" in request_body:
        readable_output += f"**Updated Property Names:** {', '.join(prompt_set_info.get('property_names', []))}\n\n"

    readable_output += f"**Updated At:** {prompt_set_info.get('updated_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSet",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompt_sets_archive_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Archive or unarchive a Red Team prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - uuid (required): UUID of the prompt set
              - archive (required): Archive status (true or false)

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Validate required parameters
    uuid = args.get("uuid")
    archive_str = args.get("archive")

    if not uuid:
        raise ValueError("uuid is required")
    if not archive_str:
        raise ValueError("archive is required")

    # Convert archive string to boolean
    archive_val = archive_str.lower()
    if archive_val not in ["true", "false"]:
        raise ValueError("archive must be 'true' or 'false'")

    archive_bool = archive_val == "true"

    # Build request body according to CustomPromptSetArchiveRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetArchiveRequestSchema)
    # Fields: archive (required boolean)
    request_body = {
        "archive": archive_bool
    }

    # Call Red Team Custom Attack endpoint to archive/unarchive prompt set
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (archivePromptSet method)
    # Endpoint: PUT /v1/custom-attack/custom-prompt-set/{uuid}/archive
    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}/archive",
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to CustomPromptSetResponseSchema
    # Fields: uuid, name, active, archive, status, created_at, updated_at
    #         description (optional), property_names (optional), properties (optional),
    #         stats (optional), extra_info (optional), version (optional),
    #         created_by_user_id (optional), updated_by_user_id (optional)
    prompt_set_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "active": response.get("active"),
        "archive": response.get("archive"),
        "status": response.get("status"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["description", "property_names", "properties", "stats", "extra_info",
                       "version", "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    action = "Archived" if archive_bool else "Unarchived"
    readable_output = f"## Red Team Prompt Set {action}\n\n"
    readable_output += f"**UUID:** {prompt_set_info.get('uuid')}\n\n"
    readable_output += f"**Name:** {prompt_set_info.get('name')}\n\n"
    readable_output += f"**Status:** {prompt_set_info.get('status')}\n\n"
    readable_output += f"**Active:** {prompt_set_info.get('active')}\n\n"
    readable_output += f"**Archive:** {prompt_set_info.get('archive')}\n\n"
    readable_output += f"**Updated At:** {prompt_set_info.get('updated_at', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSet",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_registry_credentials_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get or create Red Team registry credentials for pulling scanner images.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR (no arguments required).

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team registry credentials endpoint
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/instances-client.ts (getRegistryCredentials method)
    # Endpoint: POST /v1/registry-credentials
    # This is a POST request that either creates new credentials or returns existing ones
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (RegistryCredentialsSchema)
    response = client.http_request(
        method="POST",
        url_suffix=RED_TEAM_REGISTRY_CREDENTIALS_ENDPOINT,
        use_redteam_mgmt=True
    )

    # Parse response according to RegistryCredentialsSchema
    # Fields: token (required), expiry (required)
    credentials_info = {
        "token": response.get("token"),
        "expiry": response.get("expiry")
    }

    # Create readable output
    # Truncate token for security (show only first and last 8 characters)
    token_display = credentials_info.get("token", "")
    if len(token_display) > 20:
        token_truncated = f"{token_display[:8]}...{token_display[-8:]}"
    else:
        token_truncated = token_display

    readable_output = f"## Red Team Registry Credentials\n\n"
    readable_output += f"**Token:** {token_truncated}\n\n"
    readable_output += f"**Expiry:** {credentials_info.get('expiry', 'N/A')}\n\n"
    readable_output += "**Note:** These credentials are used to pull Red Team scanner container images from the Prisma AIRs registry."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamRegistryCredentials",
        outputs_key_field="expiry",
        outputs=credentials_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_prompt_sets_download_command(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    """Download CSV template for a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        File result dict for war room display.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Red Team download template endpoint
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (downloadTemplate method)
    # Endpoint: GET /v1/custom-attack/download-template/{uuid}
    # Returns: CSV string with header + sample row
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts:207-230
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/download-template/{uuid}",
        use_redteam_mgmt=True,
        resp_type="text"  # CSV response is plain text, not JSON
    )

    # Response is CSV string like:
    # prompt,goal
    # This is a sample prompt,Optional goal text (leave empty for AI-generated goal)

    # Generate filename based on UUID
    filename = f"prompt_set_template_{uuid}.csv"

    # Return file using XSOAR fileResult() pattern
    # Reference: CLAUDE.md section "File Handling in XSOAR"
    from CommonServerPython import fileResult
    return fileResult(
        filename=filename,
        data=response,
        file_type=None  # Auto-detect from extension
    )


def redteam_prompt_sets_upload_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Upload CSV file with prompts to a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    import demisto

    uuid = args.get("uuid")
    entry_id = args.get("entryID")

    if not uuid:
        raise ValueError("uuid is required")
    if not entry_id:
        raise ValueError("entryID is required")

    # Get file from war room using demisto.getFilePath()
    # Reference: CLAUDE.md section "File Handling in XSOAR"
    try:
        file_info = demisto.getFilePath(entry_id)
        file_path = file_info.get("path")
        file_name = file_info.get("name")

        if not file_path:
            raise ValueError(f"Could not get file path for entry ID: {entry_id}")

        # Validate file extension
        if not file_name.lower().endswith('.csv'):
            raise ValueError(f"File must be a CSV file. Got: {file_name}")

        # Read CSV file content
        with open(file_path, 'rb') as f:
            file_content = f.read()

    except FileNotFoundError:
        raise ValueError(f"File not found for entry ID: {entry_id}")
    except PermissionError:
        raise ValueError(f"Permission denied accessing file for entry ID: {entry_id}")

    # Call Red Team upload prompts CSV endpoint
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (uploadPromptsCsv method)
    # Endpoint: POST /v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid={uuid}
    # Body: multipart/form-data with 'file' field
    # Returns: BaseResponse { message: string, status: number }
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts:232-264

    # Python requests library handles multipart/form-data with files parameter
    # We need to override the http_request method to use files parameter
    url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/upload-custom-prompts-csv"
    params = {"prompt_set_uuid": uuid}

    # Build full URL
    full_url = f"{client.base_url_no_aisec}{url_suffix}"

    # Prepare files for multipart upload
    files = {
        'file': (file_name, file_content, 'text/csv')
    }

    # Get OAuth token
    token = client._get_oauth_token()
    headers = {
        'Authorization': f'Bearer {token}'
    }

    # Make request with files (multipart/form-data)
    response = client._http_request(
        method='POST',
        full_url=full_url,
        params=params,
        headers=headers,
        files=files,
        resp_type='json'
    )

    # Parse response according to BaseResponseSchema
    # Fields: message (string), status (number)
    message = response.get("message", "Upload completed")
    status_code = response.get("status", 200)

    upload_info = {
        "message": message,
        "status": status_code,
        "prompt_set_uuid": uuid,
        "file_name": file_name
    }

    # Create readable output
    readable_output = f"## Red Team Prompt Set Upload\n\n"
    readable_output += f"**Status:** {status_code}\n\n"
    readable_output += f"**Message:** {message}\n\n"
    readable_output += f"**Prompt Set UUID:** {uuid}\n\n"
    readable_output += f"**File:** {file_name}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetUpload",
        outputs_key_field="prompt_set_uuid",
        outputs=upload_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_scan_logs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Query runtime scan logs.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    interval = arg_to_number(args.get("interval"), required=True)
    unit = args.get("unit", "hours")
    filter_type = args.get("filter", "all")
    page = arg_to_number(args.get("page")) or 1
    page_size = arg_to_number(args.get("page_size")) or 50

    # Build query parameters
    # Reference: ./knowledge/prisma-airs-sdk-main/src/constants.ts (MGMT_SCAN_LOGS_PATH)
    params: dict[str, Any] = {
        "interval": interval,
        "unit": unit,
        "filter": filter_type,
        "page": page,
        "page_size": page_size
    }

    # Add TSG ID to URL suffix
    url_suffix = f"{MGMT_API_V1_PREFIX}/scanlogs/tsg/{client.tsg_id}"

    # Call scan logs endpoint
    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Extract scan logs from response (forward-compatible: capture all fields)
    logs_data = response.get("data", []) or response.get("logs", [])
    scan_logs = []

    for log in logs_data:
        log_info = {
            "scan_id": log.get("scan_id"),
            "report_id": log.get("report_id"),
            "timestamp": log.get("timestamp"),
            "profile_name": log.get("profile_name"),
            "action": log.get("action"),
            "category": log.get("category"),
            "detected": log.get("detected"),
            "prompt": log.get("prompt"),
            "response": log.get("response")
        }
        scan_logs.append(log_info)

    if not scan_logs:
        readable_output = "No scan logs found."
    else:
        readable_output = tableToMarkdown(
            f"Prisma AIRs Runtime Scan Logs ({len(scan_logs)} results)",
            scan_logs,
            headers=["scan_id", "timestamp", "profile_name", "action", "category", "detected"],
            headerTransform=lambda h: h.replace("_", " ").title()
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RuntimeScanLog",
        outputs_key_field="scan_id",
        outputs=scan_logs,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_topics_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List custom topics.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or 100
    offset = arg_to_number(args.get("offset")) or 0

    # Build query parameters
    params: dict[str, Any] = {
        "limit": limit,
        "offset": offset
    }

    # Add TSG ID to URL suffix
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/topics-client.ts
    url_suffix = f"{MGMT_API_V1_PREFIX}/topics/tsg/{client.tsg_id}"

    # Call topics list endpoint
    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Extract topics from response (forward-compatible: capture all fields)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/mgmt-topics.ts (TopicSchema)
    topics_data = response.get("data", [])
    topics = []

    for topic in topics_data:
        topic_info = {
            "topic_id": topic.get("topic_id"),
            "topic_name": topic.get("topic_name"),
            "revision": topic.get("revision"),
            "description": topic.get("description"),
            "examples": topic.get("examples", []),
            "last_modified_ts": topic.get("last_modified_ts"),
            "created_by": topic.get("created_by"),
            "updated_by": topic.get("updated_by"),
            "csp_id": topic.get("csp_id"),
            "tsg_id": topic.get("tsg_id")
        }
        topics.append(topic_info)

    readable_output = tableToMarkdown(
        f"Prisma AIRs Custom Topics ({len(topics)} of {response.get('total', len(topics))})",
        topics,
        headers=["topic_id", "topic_name", "revision", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}Topic",
        outputs_key_field="topic_id",
        outputs=topics,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_bulk_scan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Perform bulk scanning of prompts via async API.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_name = args.get("profile_name")
    prompts_csv = args.get("prompts_csv")  # CSV content as string
    session_id = args.get("session_id")

    if not profile_name or not prompts_csv:
        raise ValueError("profile_name and prompts_csv are required arguments")

    # Parse CSV content to extract prompts
    import csv
    import io

    prompts = []
    reader = csv.DictReader(io.StringIO(prompts_csv))

    # Try to find prompt column (case-insensitive)
    if reader.fieldnames:
        prompt_col = next((col for col in reader.fieldnames if col.lower() == "prompt"), None)
        if prompt_col:
            for row in reader:
                prompt = row.get(prompt_col, "").strip()
                if prompt:
                    prompts.append(prompt)
        else:
            # If no "prompt" column, treat entire CSV as newline-separated prompts
            prompts = [line.strip() for line in prompts_csv.split("\n") if line.strip()]
    else:
        # No headers, treat as newline-separated prompts
        prompts.append(line.strip() for line in prompts_csv.split("\n") if line.strip())

    if not prompts:
        raise ValueError("No prompts found in CSV input")

    # Build bulk scan request (batch into groups of 5 as per CLI)
    # Note: XSOAR doesn't have async scanning capability built-in like the CLI
    # We'll do synchronous scanning but in batches
    scan_results = []
    batch_size = 5
    total_prompts = len(prompts)

    demisto.debug(f"Starting bulk scan of {total_prompts} prompts in batches of {batch_size}")

    for i in range(0, total_prompts, batch_size):
        batch = prompts[i:i + batch_size]

        for prompt in batch:
            # Use scanner_request for each prompt
            content = {"prompt": prompt}
            scan_request = {
                "ai_profile": {"profile_name": profile_name},
                "contents": [content]
            }
            if session_id:
                scan_request["session_id"] = session_id

            try:
                scan_response = client.scanner_request(scan_request)

                # Extract key fields
                scan_result = {
                    "prompt": prompt,
                    "scan_id": scan_response.get("scan_id"),
                    "action": scan_response.get("action"),
                    "category": scan_response.get("category"),
                    "detected": any(scan_response.get("prompt_detected", {}).values()) if scan_response.get("prompt_detected") else False
                }
                scan_results.append(scan_result)
            except Exception as e:
                demisto.error(f"Failed to scan prompt: {str(e)}")
                scan_results.append({
                    "prompt": prompt,
                    "scan_id": None,
                    "action": "error",
                    "category": "error",
                    "detected": False,
                    "error": str(e)
                })

    # Calculate summary stats
    total = len(scan_results)
    blocked = sum(1 for r in scan_results if r.get("action") == "block")
    allowed = sum(1 for r in scan_results if r.get("action") == "allow")
    errors = sum(1 for r in scan_results if r.get("action") == "error")

    # Create summary table
    summary = [{
        "Total Prompts": total,
        "Blocked": blocked,
        "Allowed": allowed,
        "Errors": errors
    }]

    readable_output = f"## Prisma AIRs Bulk Scan Results\n\n"
    readable_output += f"**Profile:** {profile_name}\n"
    if session_id:
        readable_output += f"**Session ID:** {session_id}\n"
    readable_output += "\n"
    readable_output += tableToMarkdown(
        "Summary",
        summary,
        headers=["Total Prompts", "Blocked", "Allowed", "Errors"]
    )
    readable_output += "\n"
    readable_output += tableToMarkdown(
        "Scan Results (first 50)",
        scan_results[:50],
        headers=["prompt", "action", "category", "detected"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}BulkScan",
        outputs_key_field="scan_id",
        outputs={
            "profile_name": profile_name,
            "session_id": session_id,
            "total": total,
            "blocked": blocked,
            "allowed": allowed,
            "errors": errors,
            "results": scan_results
        },
        readable_output=readable_output
    )


def runtime_dlp_dictionaries_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List DLP dictionaries.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    page = arg_to_number(args.get("page")) or 0
    size = arg_to_number(args.get("size")) or 50
    include_keywords = argToBoolean(args.get("include_keywords", False))

    # Build query parameters
    params: dict[str, Any] = {
        "page": page,
        "size": size
    }
    if include_keywords:
        params["keywords"] = "true"

    # Call DLP dictionaries list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(
        method="GET",
        url_suffix=DLP_DICTIONARIES_PATH,
        params=params,
        use_dlp_base=True
    )

    # Extract dictionaries from paginated response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-dictionary.ts
    dictionaries_data = response.get("content", [])
    dictionaries = []

    for dictionary in dictionaries_data:
        dict_info = {
            "id": dictionary.get("id"),
            "name": dictionary.get("name"),
            "description": dictionary.get("description"),
            "category": dictionary.get("category"),
            "region_name": dictionary.get("region_name"),
            "type": dictionary.get("type"),
            "is_case_sensitive": dictionary.get("is_case_sensitive"),
            "is_parent_managed": dictionary.get("is_parent_managed"),
            "detection_technique": dictionary.get("detection_technique"),
            "number_of_keywords": dictionary.get("dictionary_metadata", {}).get("number_of_keywords"),
            "created_at": dictionary.get("audit_metadata", {}).get("created_at"),
            "updated_at": dictionary.get("audit_metadata", {}).get("updated_at"),
            "created_by": dictionary.get("audit_metadata", {}).get("created_by"),
            "updated_by": dictionary.get("audit_metadata", {}).get("updated_by")
        }
        dictionaries.append(dict_info)

    total_elements = response.get("total_elements", len(dictionaries))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionaries (Page {page + 1}/{total_pages}, {len(dictionaries)} of {total_elements})",
        dictionaries,
        headers=["id", "name", "category", "type", "number_of_keywords", "region_name"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
        outputs_key_field="id",
        outputs=dictionaries,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_patterns_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List DLP data patterns.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    page = arg_to_number(args.get("page")) or 0
    size = arg_to_number(args.get("size")) or 50

    # Build query parameters
    params: dict[str, Any] = {
        "page": page,
        "size": size
    }

    # Call DLP patterns list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(
        method="GET",
        url_suffix=DLP_PATTERNS_PATH,
        params=params,
        use_dlp_base=True
    )

    # Extract patterns from paginated response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-pattern.ts
    patterns_data = response.get("content", [])
    patterns = []

    for pattern in patterns_data:
        pattern_info = {
            "id": pattern.get("id"),
            "name": pattern.get("name"),
            "description": pattern.get("description"),
            "category": pattern.get("category"),
            "region_name": pattern.get("region_name"),
            "type": pattern.get("type"),
            "is_parent_managed": pattern.get("is_parent_managed"),
            "detection_technique": pattern.get("detection_technique"),
            "detection_sub_technique": pattern.get("detection_sub_technique"),
            "pattern_status": pattern.get("pattern_status"),
            "created_at": pattern.get("audit_metadata", {}).get("created_at"),
            "updated_at": pattern.get("audit_metadata", {}).get("updated_at"),
            "created_by": pattern.get("audit_metadata", {}).get("created_by"),
            "updated_by": pattern.get("audit_metadata", {}).get("updated_by")
        }
        patterns.append(pattern_info)

    total_elements = response.get("total_elements", len(patterns))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Patterns (Page {page + 1}/{total_pages}, {len(patterns)} of {total_elements})",
        patterns,
        headers=["id", "name", "category", "type", "detection_technique", "pattern_status"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=patterns,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_filtering_profiles_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List DLP filtering profiles.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    page = arg_to_number(args.get("page")) or 0
    size = arg_to_number(args.get("size")) or 50

    # Build query parameters
    params: dict[str, Any] = {
        "page": page,
        "size": size
    }

    # Call DLP filtering profiles list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-filtering-profiles.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(
        method="GET",
        url_suffix=DLP_FILTERING_PROFILES_PATH,
        params=params,
        use_dlp_base=True
    )

    # Extract filtering profiles from paginated response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-filtering-profile.ts
    profiles_data = response.get("content", [])
    filtering_profiles = []

    for profile in profiles_data:
        profile_info = {
            "id": profile.get("id"),
            "name": profile.get("name"),
            "description": profile.get("description"),
            "type": profile.get("type"),
            "default_action": profile.get("default_action"),
            "is_parent_managed": profile.get("is_parent_managed"),
            "created_at": profile.get("audit_metadata", {}).get("created_at"),
            "updated_at": profile.get("audit_metadata", {}).get("updated_at"),
            "created_by": profile.get("audit_metadata", {}).get("created_by"),
            "updated_by": profile.get("audit_metadata", {}).get("updated_by")
        }
        filtering_profiles.append(profile_info)

    total_elements = response.get("total_elements", len(filtering_profiles))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profiles (Page {page + 1}/{total_pages}, {len(filtering_profiles)} of {total_elements})",
        filtering_profiles,
        headers=["id", "name", "type", "default_action", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfile",
        outputs_key_field="id",
        outputs=filtering_profiles,
        readable_output=readable_output,
        raw_response=response
    )


def main() -> None:
    """Main function for Prisma AIRs integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
        # Client configuration
        base_url = params.get("url", "https://api.sase.paloaltonetworks.com")
        credentials = params.get("credentials", {})
        client_id = credentials.get("identifier", "")
        client_secret = credentials.get("password", "")
        tsg_id = params.get("tsg_id")
        runtime_api_key = params.get("runtime_api_key", {}).get("password", "") or params.get("runtime_api_key", "")
        scanner_base_url = params.get("scanner_base_url")
        dlp_base_url = params.get("dlp_base_url")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)

        headers: dict[str, str] = {}

        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            runtime_api_key=runtime_api_key,
            scanner_base_url=scanner_base_url,
            dlp_base_url=dlp_base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "prisma-airs-runtime-scan":
            return_results(runtime_scan_command(client, args))

        elif command == "prisma-airs-runtime-api-keys-list":
            return_results(runtime_api_keys_list_command(client, args))

        elif command == "prisma-airs-runtime-profiles-list":
            return_results(runtime_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-list":
            return_results(runtime_customer_apps_list_command(client, args))

        elif command == "prisma-airs-runtime-deployment-profiles-list":
            return_results(runtime_deployment_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-list":
            return_results(runtime_dlp_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-list":
            return_results(runtime_dlp_dictionaries_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-list":
            return_results(runtime_dlp_patterns_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-filtering-profiles-list":
            return_results(runtime_dlp_filtering_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-scan-logs":
            return_results(runtime_scan_logs_command(client, args))

        elif command == "prisma-airs-runtime-topics-list":
            return_results(runtime_topics_list_command(client, args))

        elif command == "prisma-airs-runtime-bulk-scan":
            return_results(runtime_bulk_scan_command(client, args))

        elif command == "prisma-airs-model-security-scans-list":
            return_results(model_security_scans_list_command(client, args))

        elif command == "prisma-airs-model-security-groups-list":
            return_results(model_security_groups_list_command(client, args))

        elif command == "prisma-airs-model-security-rules-list":
            return_results(model_security_rules_list_command(client, args))

        elif command == "prisma-airs-redteam-targets-list":
            return_results(redteam_targets_list_command(client, args))

        elif command == "prisma-airs-redteam-targets-create":
            return_results(redteam_targets_create_command(client, args))

        elif command == "prisma-airs-redteam-targets-get":
            return_results(redteam_targets_get_command(client, args))

        elif command == "prisma-airs-redteam-targets-update":
            return_results(redteam_targets_update_command(client, args))

        elif command == "prisma-airs-redteam-targets-delete":
            return_results(redteam_targets_delete_command(client, args))

        elif command == "prisma-airs-redteam-targets-probe":
            return_results(redteam_targets_probe_command(client, args))

        elif command == "prisma-airs-redteam-scans-list":
            return_results(redteam_scans_list_command(client, args))

        elif command == "prisma-airs-redteam-scan-get":
            return_results(redteam_scan_get_command(client, args))

        elif command == "prisma-airs-redteam-scan-abort":
            return_results(redteam_scan_abort_command(client, args))

        elif command == "prisma-airs-redteam-categories-list":
            return_results(redteam_categories_list_command(client, args))

        elif command == "prisma-airs-redteam-report-get":
            return_results(redteam_report_get_command(client, args))

        elif command == "prisma-airs-redteam-eula-status":
            return_results(redteam_eula_status_command(client, args))

        elif command == "prisma-airs-redteam-eula-content":
            return_results(redteam_eula_content_command(client, args))

        elif command == "prisma-airs-redteam-eula-accept":
            return_results(redteam_eula_accept_command(client, args))

        # Red Team Prompts Commands (5 commands)
        elif command == "prisma-airs-redteam-prompts-create":
            return_results(redteam_prompts_create_command(client, args))

        elif command == "prisma-airs-redteam-prompts-list":
            return_results(redteam_prompts_list_command(client, args))

        elif command == "prisma-airs-redteam-prompts-get":
            return_results(redteam_prompts_get_command(client, args))

        elif command == "prisma-airs-redteam-prompts-update":
            return_results(redteam_prompts_update_command(client, args))

        elif command == "prisma-airs-redteam-prompts-delete":
            return_results(redteam_prompts_delete_command(client, args))

        # Red Team Prompt Sets Commands (5 commands)
        elif command == "prisma-airs-redteam-prompt-sets-create":
            return_results(redteam_prompt_sets_create_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-list":
            return_results(redteam_prompt_sets_list_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-get":
            return_results(redteam_prompt_sets_get_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-update":
            return_results(redteam_prompt_sets_update_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-archive":
            return_results(redteam_prompt_sets_archive_command(client, args))

        # Red Team Registry Credentials Command (1 command)
        elif command == "prisma-airs-redteam-registry-credentials-get":
            return_results(redteam_registry_credentials_get_command(client, args))

        # Red Team Prompt Sets Download Command (1 command)
        elif command == "prisma-airs-redteam-prompt-sets-download":
            return_results(redteam_prompt_sets_download_command(client, args))

        # Red Team Prompt Sets Upload Command (1 command)
        elif command == "prisma-airs-redteam-prompt-sets-upload":
            return_results(redteam_prompt_sets_upload_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
