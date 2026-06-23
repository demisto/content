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


def runtime_api_keys_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Runtime API Key.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR with the full API key secret.
    """
    # Required arguments
    api_key_name = args.get("api_key_name")
    auth_code = args.get("auth_code")
    cust_app = args.get("cust_app")
    rotation_time_interval = arg_to_number(args.get("rotation_time_interval"))
    rotation_time_unit = args.get("rotation_time_unit")
    created_by = args.get("created_by")

    if not api_key_name:
        raise ValueError("api_key_name is required")
    if not auth_code:
        raise ValueError("auth_code is required")
    if not cust_app:
        raise ValueError("cust_app is required")
    if not rotation_time_interval:
        raise ValueError("rotation_time_interval is required")
    if not rotation_time_unit:
        raise ValueError("rotation_time_unit is required (hours, days, or months)")
    if not created_by:
        raise ValueError("created_by is required")

    # Validate rotation_time_unit
    valid_units = ["hours", "days", "months"]
    if rotation_time_unit not in valid_units:
        raise ValueError(f"rotation_time_unit must be one of: {', '.join(valid_units)}")

    # Build request body according to ApiKeyCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/mgmt-api-key.ts
    # Required: auth_code, cust_app, revoked, created_by, api_key_name,
    #           rotation_time_interval, rotation_time_unit
    # Optional: dp_name, cust_env, cust_cloud_provider, cust_ai_agent_framework
    request_body = {
        "api_key_name": api_key_name,
        "auth_code": auth_code,
        "cust_app": cust_app,
        "created_by": created_by,
        "revoked": False,  # Always create as not revoked
        "rotation_time_interval": rotation_time_interval,
        "rotation_time_unit": rotation_time_unit
    }

    # Add optional fields if provided
    optional_fields = {
        "dp_name": args.get("dp_name"),
        "cust_env": args.get("cust_env"),
        "cust_cloud_provider": args.get("cust_cloud_provider"),
        "cust_ai_agent_framework": args.get("cust_ai_agent_framework")
    }
    for field, value in optional_fields.items():
        if value:
            request_body[field] = value

    # Call Management API to create API key
    # SDK: ./knowledge/prisma-airs-sdk-main/src/management/api-keys.ts (create method)
    # Endpoint: POST /v1/mgmt/apikeys
    # Response: ApiKeySchema with full secret (only time it's shown)
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikeys"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response according to ApiKeySchema
    # Fields: api_key_id, api_key_name, api_key (full secret - only shown once!),
    #         api_key_last8, auth_code, expiration, revoked
    # Optional: created_at, updated_at, created_by, cust_app, etc.
    api_key_info = {
        "id": response.get("api_key_id"),
        "name": response.get("api_key_name"),
        "api_key": response.get("api_key"),  # FULL SECRET - only shown on create/regenerate
        "last8": response.get("api_key_last8"),
        "auth_code": response.get("auth_code"),
        "expires_at": response.get("expiration"),
        "revoked": response.get("revoked"),
        "created_at": response.get("created_at"),
        "created_by": response.get("created_by"),
        "cust_app": response.get("cust_app")
    }

    # Add optional fields if present
    optional_response_fields = ["updated_at", "updated_by", "cust_env", "cust_cloud_provider",
                                "cust_ai_agent_framework", "dp_name"]
    for field in optional_response_fields:
        if response.get(field):
            api_key_info[field] = response.get(field)

    # Create readable output with WARNING about secret
    readable_output = f"## ⚠️ API Key Created - Save the Secret Now!\n\n"
    readable_output += f"**ID:** {api_key_info.get('id')}\n\n"
    readable_output += f"**Name:** {api_key_info.get('name')}\n\n"
    readable_output += f"**API Key (Secret):** `{api_key_info.get('api_key')}`\n\n"
    readable_output += f"**Last 8 Characters:** {api_key_info.get('last8')}\n\n"
    readable_output += f"**Expires:** {api_key_info.get('expires_at', 'N/A')}\n\n"
    readable_output += f"**Created By:** {api_key_info.get('created_by')}\n\n"
    readable_output += "**⚠️ IMPORTANT:** This is the ONLY time the full API key secret will be shown. "
    readable_output += "Save it securely now. Future API calls will only show the last 8 characters."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKey",
        outputs_key_field="id",
        outputs=api_key_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_api_keys_regenerate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Regenerate an existing Runtime API Key.

    This creates a NEW key with a NEW UUID and invalidates the old key.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR with the new API key secret.
    """
    # Required arguments
    api_key_id = args.get("api_key_id")
    rotation_time_interval = arg_to_number(args.get("rotation_time_interval"))
    rotation_time_unit = args.get("rotation_time_unit")

    if not api_key_id:
        raise ValueError("api_key_id is required")
    if not rotation_time_interval:
        raise ValueError("rotation_time_interval is required")
    if not rotation_time_unit:
        raise ValueError("rotation_time_unit is required (hours, days, or months)")

    # Validate rotation_time_unit
    valid_units = ["hours", "days", "months"]
    if rotation_time_unit not in valid_units:
        raise ValueError(f"rotation_time_unit must be one of: {', '.join(valid_units)}")

    # Build request body according to ApiKeyRegenerateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/mgmt-api-key.ts
    # Required: rotation_time_interval, rotation_time_unit
    # Optional: updated_by
    request_body = {
        "rotation_time_interval": rotation_time_interval,
        "rotation_time_unit": rotation_time_unit
    }

    # Add optional updated_by if provided
    updated_by = args.get("updated_by")
    if updated_by:
        request_body["updated_by"] = updated_by

    # Call Management API to regenerate API key
    # SDK: ./knowledge/prisma-airs-sdk-main/src/management/api-keys.ts (regenerate method)
    # Endpoint: PUT /v1/mgmt/apikeys/regenerate/{apiKeyId}
    # Response: ApiKeySchema with NEW UUID and NEW full secret
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikeys/regenerate/{api_key_id}"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response according to ApiKeySchema
    # IMPORTANT: Returns NEW api_key_id and NEW api_key (full secret)
    # The old key is invalidated
    api_key_info = {
        "id": response.get("api_key_id"),  # NEW UUID
        "name": response.get("api_key_name"),
        "api_key": response.get("api_key"),  # NEW FULL SECRET
        "last8": response.get("api_key_last8"),
        "auth_code": response.get("auth_code"),
        "expires_at": response.get("expiration"),
        "revoked": response.get("revoked"),
        "updated_at": response.get("updated_at"),
        "updated_by": response.get("updated_by"),
        "cust_app": response.get("cust_app")
    }

    # Add optional fields if present
    optional_response_fields = ["created_at", "created_by", "cust_env", "cust_cloud_provider",
                                "cust_ai_agent_framework", "dp_name"]
    for field in optional_response_fields:
        if response.get(field):
            api_key_info[field] = response.get(field)

    # Create readable output with WARNING about new secret and old key invalidation
    readable_output = f"## ⚠️ API Key Regenerated - Old Key Invalidated!\n\n"
    readable_output += f"**New ID:** {api_key_info.get('id')}\n\n"
    readable_output += f"**Name:** {api_key_info.get('name')}\n\n"
    readable_output += f"**New API Key (Secret):** `{api_key_info.get('api_key')}`\n\n"
    readable_output += f"**Last 8 Characters:** {api_key_info.get('last8')}\n\n"
    readable_output += f"**New Expiration:** {api_key_info.get('expires_at', 'N/A')}\n\n"
    readable_output += f"**Updated By:** {api_key_info.get('updated_by', 'N/A')}\n\n"
    readable_output += "**⚠️ IMPORTANT:**\n\n"
    readable_output += "1. The OLD API key has been INVALIDATED and will no longer work\n"
    readable_output += "2. This is the ONLY time the NEW full API key secret will be shown\n"
    readable_output += "3. Update all applications using the old key with this new key\n"
    readable_output += "4. The API key ID has changed - use the new ID for future operations"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKey",
        outputs_key_field="id",
        outputs=api_key_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_api_keys_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a Runtime API Key by name.

    This permanently deletes the API key and revokes access immediately.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR with deletion confirmation.
    """
    # Required arguments
    api_key_name = args.get("api_key_name")
    updated_by = args.get("updated_by")

    if not api_key_name:
        raise ValueError("api_key_name is required")
    if not updated_by:
        raise ValueError("updated_by is required (email of user performing deletion)")

    # Call Management API to delete API key
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/api-keys.ts
    # SDK: ApiKeysClient.delete(apiKeyName, updatedBy)
    # Endpoint: DELETE /v1/mgmt/apikey/delete/{apiKeyName}?updated_by={email}
    # Response: { message: "deleted" } (or plain string that gets transformed)
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikey/delete/{api_key_name}"
    params = {
        "updated_by": updated_by
    }

    response = client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK handles both string and object responses
    # ApiKeyDeleteResponseSchema transforms plain string to { message: "..." }
    # Response: { message: "deleted" } or { message: "successfully deleted apiKeyName: <name>" }
    message = response.get("message", "API key deleted successfully") if isinstance(response, dict) else str(response)

    # Create readable output with deletion confirmation
    readable_output = f"## ✅ API Key Deleted\n\n"
    readable_output += f"**Key Name:** {api_key_name}\n\n"
    readable_output += f"**Deleted By:** {updated_by}\n\n"
    readable_output += f"**Status:** {message}\n\n"
    readable_output += "**⚠️ WARNING:** This action cannot be undone. The API key has been permanently revoked."

    # Context output
    context_output = {
        "api_key_name": api_key_name,
        "deleted_by": updated_by,
        "message": message,
        "deleted": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKeyDeleted",
        outputs_key_field="api_key_name",
        outputs=context_output,
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


def runtime_profiles_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a specific security profile by ID or name.

    Note: There is no dedicated GET endpoint - this fetches all profiles and filters.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    profile_name = args.get("profile_name")

    if not profile_id and not profile_name:
        raise ValueError("Either profile_id or profile_name is required")

    # Call Management API to list all profiles, then filter
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # SDK: ProfilesClient.get(profileId) or getByName(profileName)
    # Note: No dedicated GET endpoint exists - SDK fetches all and filters
    url_suffix = f"{MGMT_API_V1_PREFIX}/profiles/tsg/{client.tsg_id}"
    params = {
        "offset": "0",
        "limit": "1000"  # Get all profiles for filtering
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response and filter
    profiles_raw = response.get("ai_profiles", [])

    # Filter by ID or name
    if profile_id:
        matches = [p for p in profiles_raw if p.get("profile_id") == profile_id]
        search_key = f"ID: {profile_id}"
    else:
        # Filter by name and get highest revision (SDK behavior)
        matches = [p for p in profiles_raw if p.get("profile_name") == profile_name]
        if len(matches) > 1:
            # Return highest revision
            matches = [max(matches, key=lambda p: p.get("revision", 0))]
        search_key = f"Name: {profile_name}"

    if not matches:
        raise ValueError(f"Profile not found: {search_key}")

    profile = matches[0]

    # Extract full profile details including policy
    profile_info = {
        "id": profile.get("profile_id"),
        "name": profile.get("profile_name"),
        "revision": profile.get("revision"),
        "active": profile.get("active"),
        "policy": profile.get("policy"),  # Full policy object
        "created_by": profile.get("created_by"),
        "updated_by": profile.get("updated_by"),
        "last_modified_ts": profile.get("last_modified_ts"),
        "tsg_id": profile.get("tsg_id"),
        "csp_id": profile.get("csp_id")
    }

    # Create readable output
    readable_output = f"## Security Profile: {profile_info.get('name')}\n\n"
    readable_output += f"**ID:** {profile_info.get('id')}\n\n"
    readable_output += f"**Revision:** {profile_info.get('revision')}\n\n"
    readable_output += f"**Active:** {profile_info.get('active')}\n\n"
    readable_output += f"**Created By:** {profile_info.get('created_by', 'N/A')}\n\n"
    readable_output += f"**Updated By:** {profile_info.get('updated_by', 'N/A')}\n\n"
    readable_output += f"**Last Modified:** {profile_info.get('last_modified_ts', 'N/A')}\n\n"

    # Add policy summary if present
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += f"**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=profile
    )


def runtime_profiles_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new security profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_name = args.get("profile_name")
    active = argToBoolean(args.get("active", True))
    policy_json = args.get("policy")

    if not profile_name:
        raise ValueError("profile_name is required")

    # Build request body according to CreateSecurityProfileRequest
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/mgmt-security-profile.ts
    # Required: profile_name, active, policy
    request_body: dict[str, Any] = {
        "profile_name": profile_name,
        "active": active
    }

    # Parse policy JSON if provided
    if policy_json:
        try:
            import json
            policy = json.loads(policy_json)
            request_body["policy"] = policy
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid policy JSON: {str(e)}")
    else:
        # Default empty policy
        request_body["policy"] = {
            "ai-security-profiles": [],
            "dlp-data-profiles": []
        }

    # Call Management API to create profile
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # SDK: ProfilesClient.create(body)
    # Endpoint: POST /v1/mgmt/profile
    url_suffix = f"{MGMT_API_V1_PREFIX}/profile"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response - returns full SecurityProfile
    profile_info = {
        "id": response.get("profile_id"),
        "name": response.get("profile_name"),
        "revision": response.get("revision"),
        "active": response.get("active"),
        "policy": response.get("policy"),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by"),
        "last_modified_ts": response.get("last_modified_ts"),
        "tsg_id": response.get("tsg_id"),
        "csp_id": response.get("csp_id")
    }

    # Create readable output
    readable_output = f"## ✅ Security Profile Created\n\n"
    readable_output += f"**ID:** {profile_info.get('id')}\n\n"
    readable_output += f"**Name:** {profile_info.get('name')}\n\n"
    readable_output += f"**Revision:** {profile_info.get('revision')}\n\n"
    readable_output += f"**Active:** {profile_info.get('active')}\n\n"
    readable_output += f"**Created By:** {profile_info.get('created_by', 'N/A')}\n\n"

    # Add policy summary
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += f"**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_profiles_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing security profile.

    WARNING: This modifies the profile configuration and can break scanning if misconfigured.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    profile_name = args.get("profile_name")
    active = args.get("active")
    policy_json = args.get("policy")

    if not profile_id:
        raise ValueError("profile_id is required")
    if not profile_name:
        raise ValueError("profile_name is required")

    # Build request body according to CreateSecurityProfileRequest
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/mgmt-security-profile.ts
    # Required: profile_name, active, policy
    request_body: dict[str, Any] = {
        "profile_name": profile_name
    }

    # Add active if provided
    if active is not None:
        request_body["active"] = argToBoolean(active)

    # Parse policy JSON if provided
    if policy_json:
        try:
            import json
            policy = json.loads(policy_json)
            request_body["policy"] = policy
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid policy JSON: {str(e)}")

    # Call Management API to update profile
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # SDK: ProfilesClient.update(profileId, body)
    # Endpoint: PUT /v1/mgmt/profile/uuid/{profileId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/profile/uuid/{profile_id}"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response - returns updated SecurityProfile with incremented revision
    profile_info = {
        "id": response.get("profile_id"),
        "name": response.get("profile_name"),
        "revision": response.get("revision"),  # Incremented
        "active": response.get("active"),
        "policy": response.get("policy"),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by"),
        "last_modified_ts": response.get("last_modified_ts"),
        "tsg_id": response.get("tsg_id"),
        "csp_id": response.get("csp_id")
    }

    # Create readable output
    readable_output = f"## ✅ Security Profile Updated\n\n"
    readable_output += f"**ID:** {profile_info.get('id')}\n\n"
    readable_output += f"**Name:** {profile_info.get('name')}\n\n"
    readable_output += f"**Revision:** {profile_info.get('revision')} (incremented)\n\n"
    readable_output += f"**Active:** {profile_info.get('active')}\n\n"
    readable_output += f"**Updated By:** {profile_info.get('updated_by', 'N/A')}\n\n"
    readable_output += f"**Last Modified:** {profile_info.get('last_modified_ts', 'N/A')}\n\n"

    # Add policy summary
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += f"**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_profiles_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a security profile.

    WARNING: This permanently deletes the security profile. This action cannot be undone.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")

    if not profile_id:
        raise ValueError("profile_id is required")

    # Call Management API to delete profile
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # SDK: ProfilesClient.delete(profileId)
    # Endpoint: DELETE /v1/mgmt/profile/{profileId}
    # Response: { message: "deleted" } (or plain string transformed to object)
    url_suffix = f"{MGMT_API_V1_PREFIX}/profile/{profile_id}"

    response = client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        use_mgmt_base=True
    )

    # Parse response - SDK handles both string and object responses
    # DeleteProfileResponseSchema transforms plain string to { message: "..." }
    message = response.get("message", "Security profile deleted successfully") if isinstance(response, dict) else str(response)

    # Create readable output
    readable_output = f"## ✅ Security Profile Deleted\n\n"
    readable_output += f"**Profile ID:** {profile_id}\n\n"
    readable_output += f"**Status:** {message}\n\n"
    readable_output += "**⚠️ WARNING:** This action cannot be undone. The security profile has been permanently deleted."

    # Context output
    context_output = {
        "profile_id": profile_id,
        "message": message,
        "deleted": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfileDeleted",
        outputs_key_field="profile_id",
        outputs=context_output,
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


def runtime_customer_apps_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get customer application details by name.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    app_name = args.get("app_name")
    if not app_name:
        raise ValueError("app_name is required")

    # Call Management API to get customer app details
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/customer-apps.ts
    # SDK: CustomerAppsClient.get(appName)
    # Endpoint: GET /v1/mgmt/customerapp?app_name={appName}
    url_suffix = f"{MGMT_API_V1_PREFIX}/customerapp"
    params = {
        "app_name": app_name
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK schema (mgmt-customer-app.ts): CustomerAppSchema
    # Fields: customer_appId, tsg_id, app_name, model_name, cloud_provider, environment, status, created_by, updated_by, ai_agent_framework
    app_info = {
        "id": response.get("customer_appId"),
        "name": response.get("app_name"),
        "model_name": response.get("model_name"),
        "cloud_provider": response.get("cloud_provider"),
        "environment": response.get("environment"),
        "ai_agent_framework": response.get("ai_agent_framework"),
        "tsg_id": response.get("tsg_id"),
        "status": response.get("status"),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Customer Application: {app_name}",
        [app_info],
        headers=["id", "name", "model_name", "cloud_provider", "environment",
                 "ai_agent_framework", "status", "created_by", "updated_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerApp",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_customer_apps_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a customer application.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    customer_app_id = args.get("customer_app_id")
    if not customer_app_id:
        raise ValueError("customer_app_id is required")

    # Build request body from arguments
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/mgmt-customer-app.ts
    # SDK: CustomerAppSchema - tsg_id, app_name, model_name (optional), cloud_provider, environment, ai_agent_framework (optional)
    request_body: dict[str, Any] = {
        "tsg_id": args.get("tsg_id", client.tsg_id),  # Default to client's TSG ID if not provided
        "app_name": args.get("app_name"),
        "cloud_provider": args.get("cloud_provider"),
        "environment": args.get("environment")
    }

    # Add optional fields if provided
    if args.get("model_name"):
        request_body["model_name"] = args.get("model_name")
    if args.get("ai_agent_framework"):
        request_body["ai_agent_framework"] = args.get("ai_agent_framework")
    if args.get("updated_by"):
        request_body["updated_by"] = args.get("updated_by")

    # Validate required fields
    if not request_body.get("app_name"):
        raise ValueError("app_name is required")
    if not request_body.get("cloud_provider"):
        raise ValueError("cloud_provider is required")
    if not request_body.get("environment"):
        raise ValueError("environment is required")

    # Call Management API to update customer app
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/customer-apps.ts
    # SDK: CustomerAppsClient.update(customerAppId, body)
    # Endpoint: PUT /v1/mgmt/customerapp?customer_app_id={customerAppId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/customerapp"
    params = {
        "customer_app_id": customer_app_id
    }

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        params=params,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response - Returns updated CustomerApp
    app_info = {
        "id": response.get("customer_appId"),
        "name": response.get("app_name"),
        "model_name": response.get("model_name"),
        "cloud_provider": response.get("cloud_provider"),
        "environment": response.get("environment"),
        "ai_agent_framework": response.get("ai_agent_framework"),
        "tsg_id": response.get("tsg_id"),
        "status": response.get("status"),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Updated Customer Application: {app_info.get('name')}",
        [app_info],
        headers=["id", "name", "model_name", "cloud_provider", "environment", "ai_agent_framework", "status", "updated_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerApp",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_customer_apps_consumption_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get per-application token consumption and session statistics.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    app_id = args.get("app_id")
    app_name = args.get("app_name")
    time_interval = arg_to_number(args.get("time_interval")) or 30
    time_unit = args.get("time_unit", "days")

    if not app_id:
        raise ValueError("app_id is required")
    if not app_name:
        raise ValueError("app_name is required")

    # Validate time_interval - API only accepts 7, 30, or 60 days
    if time_interval not in [7, 30, 60]:
        raise ValueError("time_interval must be 7, 30, or 60 days")

    # Call Dashboard API to get application consumption
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/dashboard.ts
    # SDK: DashboardClient.application(query)
    # Endpoint: GET /v1/mgmt/dashboard/v2/apps/application?appid={appId}&appname={appName}&time_interval={interval}&time_unit={unit}
    url_suffix = "/v1/mgmt/dashboard/v2/apps/application"
    params = {
        "appid": app_id,
        "appname": app_name,
        "time_interval": str(time_interval),
        "time_unit": time_unit
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK schema (mgmt-dashboard.ts): DashboardApplicationSchema
    # Fields: id, name, cloud, source, created_at, updated_at, profiles[], token_stats{}, session_stats{}
    token_stats = response.get("token_stats") or {}
    session_stats = response.get("session_stats") or {}
    violation_breakdown = session_stats.get("violation_breakdown") or {}

    app_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "cloud": response.get("cloud"),
        "source": response.get("source"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "profiles": response.get("profiles"),
        # Token consumption stats
        "average_daily_tokens": token_stats.get("average_daily_tokens"),
        "average_daily_tokens_scale": token_stats.get("average_daily_tokens_scale"),
        "monthly_total_tokens": token_stats.get("monthly_total_tokens"),
        "monthly_total_tokens_scale": token_stats.get("monthly_total_tokens_scale"),
        # Session stats
        "sessions_total": session_stats.get("total"),
        "sessions_violating": session_stats.get("violating"),
        "last_session_id": session_stats.get("last_session_id"),
        "most_recent_session_time": session_stats.get("most_recent_session_time"),
        # Violation severity counts
        "violations_critical": violation_breakdown.get("critical"),
        "violations_high": violation_breakdown.get("high"),
        "violations_medium": violation_breakdown.get("medium"),
        "violations_low": violation_breakdown.get("low"),
        "violations_total": violation_breakdown.get("total")
    }

    # Format readable output using XSOAR best practice table format
    # Create multiple tables for different data sections
    readable_parts = []

    # Application Overview Table
    app_overview = [{
        "App ID": app_info.get("id"),
        "Name": app_info.get("name"),
        "Cloud": app_info.get("cloud"),
        "Source": app_info.get("source"),
        "Profiles": ", ".join(app_info.get("profiles")) if app_info.get("profiles") else "None",
        "Time Window": f"{time_interval} {time_unit}"
    }]
    readable_parts.append(tableToMarkdown(
        "Application Overview",
        app_overview,
        headers=["App ID", "Name", "Cloud", "Source", "Profiles", "Time Window"],
        removeNull=True
    ))

    # Token Consumption Table
    avg_tokens = app_info.get("average_daily_tokens")
    avg_scale = app_info.get("average_daily_tokens_scale") or ""
    monthly_tokens = app_info.get("monthly_total_tokens")
    monthly_scale = app_info.get("monthly_total_tokens_scale") or ""

    token_consumption = [{
        "Metric": "Daily Average",
        "Value": f"{avg_tokens}{avg_scale}" if avg_tokens else "N/A"
    }, {
        "Metric": "Monthly Total",
        "Value": f"{monthly_tokens}{monthly_scale}" if monthly_tokens else "N/A"
    }]
    readable_parts.append(tableToMarkdown(
        "Token Consumption",
        token_consumption,
        headers=["Metric", "Value"]
    ))

    # Session Statistics Table
    session_stats_table = [{
        "Total Sessions": app_info.get("sessions_total") or 0,
        "Violating Sessions": app_info.get("sessions_violating") or 0,
        "Last Session ID": app_info.get("last_session_id") or "N/A",
        "Most Recent Session": app_info.get("most_recent_session_time") or "N/A"
    }]
    readable_parts.append(tableToMarkdown(
        "Session Statistics",
        session_stats_table,
        headers=["Total Sessions", "Violating Sessions", "Last Session ID", "Most Recent Session"],
        removeNull=True
    ))

    # Violation Severity Breakdown Table
    violations_table = [{
        "Critical": app_info.get("violations_critical") or 0,
        "High": app_info.get("violations_high") or 0,
        "Medium": app_info.get("violations_medium") or 0,
        "Low": app_info.get("violations_low") or 0,
        "Total": app_info.get("violations_total") or 0
    }]
    readable_parts.append(tableToMarkdown(
        "Violation Severity Breakdown",
        violations_table,
        headers=["Critical", "High", "Medium", "Low", "Total"]
    ))

    readable_output = "\n".join(readable_parts)

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppConsumption",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_customer_apps_violations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get per-detector violation severity breakdown for an application.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    app_id = args.get("app_id")
    app_name = args.get("app_name")
    time_interval = arg_to_number(args.get("time_interval")) or 30
    time_unit = args.get("time_unit", "days")

    if not app_id:
        raise ValueError("app_id is required")
    if not app_name:
        raise ValueError("app_name is required")

    # Validate time_interval - API only accepts 7, 30, or 60 days
    if time_interval not in [7, 30, 60]:
        raise ValueError("time_interval must be 7, 30, or 60 days")

    # Call Dashboard API to get application violation breakdown
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/dashboard.ts
    # SDK: DashboardClient.applicationViolationBreakdown(query)
    # Endpoint: GET /v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown?appid={appId}&appname={appName}&time_interval={interval}&time_unit={unit}
    url_suffix = "/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
    params = {
        "appid": app_id,
        "appname": app_name,
        "time_interval": str(time_interval),
        "time_unit": time_unit
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK schema (mgmt-dashboard.ts): DashboardApplicationViolationBreakdownSchema
    # Fields: detection_type_violation_breakdown[], total_violating
    # Known detection types: agent_security, contextual_grounding, dbs, dlp, malicious_code, pi, source_code, tc, topic_guardrails, uf
    breakdowns_raw = response.get("detection_type_violation_breakdown", [])
    total_violating = response.get("total_violating", 0)

    # Parse detector breakdowns
    detectors = []
    for breakdown in breakdowns_raw:
        detection_type = breakdown.get("detection_type")
        violation_breakdown = breakdown.get("violation_breakdown") or {}

        detector_info = {
            "detection_type": detection_type,
            "critical": violation_breakdown.get("critical", 0),
            "high": violation_breakdown.get("high", 0),
            "medium": violation_breakdown.get("medium", 0),
            "low": violation_breakdown.get("low", 0),
            "total": violation_breakdown.get("total", 0)
        }
        detectors.append(detector_info)

    # Sort by total violations (descending) for better readability
    detectors.sort(key=lambda x: x.get("total", 0), reverse=True)

    readable_output = tableToMarkdown(
        f"Violation Breakdown by Detector (Total Violating: {total_violating})",
        detectors,
        headers=["detection_type", "critical", "high", "medium", "low", "total"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Create structured output
    output = {
        "app_id": app_id,
        "app_name": app_name,
        "total_violating": total_violating,
        "detectors": detectors,
        "time_interval": time_interval,
        "time_unit": time_unit
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppViolations",
        outputs_key_field="app_id",
        outputs=output,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_customer_apps_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a customer application and all associated API keys.

    WARNING: This permanently deletes the application and revokes all associated API keys immediately.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR with deletion confirmation.
    """
    # Required arguments
    app_name = args.get("app_name")
    updated_by = args.get("updated_by")

    if not app_name:
        raise ValueError("app_name is required")
    if not updated_by:
        raise ValueError("updated_by is required (email of user performing deletion)")

    # Call Management API to delete customer app
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/customer-apps.ts
    # SDK: CustomerAppsClient.delete(appName, updatedBy)
    # Endpoint: DELETE /v1/mgmt/customerapp?app_name={appName}&updated_by={email}
    # Response: { message: "customer app and associated keys successfully deleted" }
    url_suffix = f"{MGMT_API_V1_PREFIX}/customerapp"
    params = {
        "app_name": app_name,
        "updated_by": updated_by
    }

    response = client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response - SDK handles both string and object responses
    # CustomerAppDeleteResponseSchema transforms plain string to { message: "..." }
    message = response.get("message", "Customer app and associated keys deleted successfully") if isinstance(
        response, dict) else str(response)

    # Create readable output with deletion confirmation
    readable_output = f"## ✅ Customer Application Deleted\n\n"
    readable_output += f"**App Name:** {app_name}\n\n"
    readable_output += f"**Deleted By:** {updated_by}\n\n"
    readable_output += f"**Status:** {message}\n\n"
    readable_output += "**⚠️ WARNING:** This action cannot be undone. The customer application and all associated API keys have been permanently deleted and revoked."

    # Context output
    context_output = {
        "app_name": app_name,
        "deleted_by": updated_by,
        "message": message,
        "deleted": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppDeleted",
        outputs_key_field="app_name",
        outputs=context_output,
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


def runtime_dlp_profiles_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single DLP data profile by ID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Call DLP data profiles get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # SDK: GET /v2/api/data-profiles/{resourceId}
    response = client.http_request(
        method="GET",
        url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}",
        use_dlp_base=True
    )

    # Extract profile details from response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-profile.ts
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "profile_status": response.get("profile_status"),
        "profile_type": response.get("profile_type"),
        "is_granular_data_profile": response.get("is_granular_data_profile"),
        "is_parent_managed": response.get("is_parent_managed"),
        "version": response.get("version"),
        "detection_rules": response.get("detection_rules"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_profiles_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new DLP data profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-profile.ts
    # Required fields: name, detection_rules (array of rule objects)
    name = args.get("name")
    detection_rules_str = args.get("detection_rules")

    if not name:
        raise ValueError("name is required")
    if not detection_rules_str:
        raise ValueError("detection_rules is required (JSON array)")

    # Parse detection_rules from JSON
    try:
        detection_rules = json.loads(detection_rules_str)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"detection_rules must be valid JSON: {e}")

    request_body: dict[str, Any] = {
        "name": name,
        "detection_rules": detection_rules
    }

    # Optional: description
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Optional: is_granular_data_profile
    if args.get("is_granular_data_profile") is not None:
        request_body["is_granular_data_profile"] = argToBoolean(args.get("is_granular_data_profile"))

    # Call DLP data profiles create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # SDK: POST /v2/api/data-profiles
    response = client.http_request(
        method="POST",
        url_suffix=DLP_DATA_PROFILES_PATH,
        json_data=request_body,
        use_dlp_base=True
    )

    # Extract created profile details
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "profile_status": response.get("profile_status"),
        "profile_type": response.get("profile_type"),
        "is_granular_data_profile": response.get("is_granular_data_profile"),
        "version": response.get("version"),
        "detection_rules": response.get("detection_rules"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Created: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_profiles_patch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Partially update a DLP data profile (JSON Merge Patch).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-profile.ts
    # PATCH requires: name, profile_type (cannot be cleared)
    name = args.get("name")
    profile_type = args.get("profile_type")

    if not name:
        raise ValueError("name is required for PATCH")
    if not profile_type:
        raise ValueError("profile_type is required for PATCH")

    request_body: dict[str, Any] = {
        "name": name,
        "profile_type": profile_type
    }

    # Optional: description (can be null to clear)
    if args.get("description") is not None:
        desc_value = args.get("description")
        request_body["description"] = None if desc_value == "null" else desc_value

    # Optional: detection_rules (can be null to clear)
    if args.get("detection_rules") is not None:
        rules_value = args.get("detection_rules")
        if rules_value == "null":
            request_body["detection_rules"] = None
        else:
            try:
                request_body["detection_rules"] = json.loads(rules_value)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"detection_rules must be valid JSON or 'null': {e}")

    # Call DLP data profiles patch endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # SDK: PATCH /v2/api/data-profiles/{resourceId}
    # Uses Content-Type: application/merge-patch+json
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}",
        json_data=request_body,
        use_dlp_base=True,
        headers={"Content-Type": "application/merge-patch+json"}
    )

    # Extract updated profile details
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "profile_status": response.get("profile_status"),
        "profile_type": response.get("profile_type"),
        "version": response.get("version"),
        "detection_rules": response.get("detection_rules"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Patched: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_profiles_replace_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Replace (full update) a DLP data profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-profile.ts
    # Required fields: name, detection_rules
    name = args.get("name")
    detection_rules_str = args.get("detection_rules")

    if not name:
        raise ValueError("name is required")
    if not detection_rules_str:
        raise ValueError("detection_rules is required (JSON array)")

    # Parse detection_rules from JSON
    try:
        detection_rules = json.loads(detection_rules_str)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"detection_rules must be valid JSON: {e}")

    request_body: dict[str, Any] = {
        "name": name,
        "detection_rules": detection_rules
    }

    # Optional: description
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Optional: is_granular_data_profile
    if args.get("is_granular_data_profile") is not None:
        request_body["is_granular_data_profile"] = argToBoolean(args.get("is_granular_data_profile"))

    # Call DLP data profiles replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # SDK: PUT /v2/api/data-profiles/{resourceId}
    response = client.http_request(
        method="PUT",
        url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}",
        json_data=request_body,
        use_dlp_base=True
    )

    # Extract updated profile details
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "profile_status": response.get("profile_status"),
        "profile_type": response.get("profile_type"),
        "version": response.get("version"),
        "detection_rules": response.get("detection_rules"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Replaced: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profile_info,
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


def model_security_scans_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new model security scan.

    This command creates a scan and returns immediately with PENDING status.
    Use prisma-airs-model-security-scans-get to poll for completion.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    model_uri = args.get("model_uri")
    security_group_uuid = args.get("security_group_uuid")
    scan_origin = args.get("scan_origin", "XSOAR_INTEGRATION")

    if not model_uri:
        raise ValueError("model_uri is required")
    if not security_group_uuid:
        raise ValueError("security_group_uuid is required")

    # Build request body according to ScanCreateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Required: model_uri, security_group_uuid, scan_origin
    # Optional: allow_patterns, ignore_patterns, labels, model_author, model_name, model_version, scan_details
    request_body: dict[str, Any] = {
        "model_uri": model_uri,
        "security_group_uuid": security_group_uuid,
        "scan_origin": scan_origin
    }

    # Add optional fields if provided
    if args.get("model_name"):
        request_body["model_name"] = args.get("model_name")
    if args.get("model_author"):
        request_body["model_author"] = args.get("model_author")
    if args.get("model_version"):
        request_body["model_version"] = args.get("model_version")

    # Call Model Security Data API to create scan
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.create(body)
    # Endpoint: POST /v1/scans (data plane, not management)
    url_suffix = "/v1/scans"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: ScanBaseResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, model_uri, owner, scan_origin,
    #         security_group_uuid, security_group_name, model_version_uuid, eval_outcome,
    #         source_type, eval_summary, etc.
    scan_info = {
        "uuid": response.get("uuid"),
        "model_uri": response.get("model_uri"),
        "security_group_uuid": response.get("security_group_uuid"),
        "security_group_name": response.get("security_group_name"),
        "scan_origin": response.get("scan_origin"),
        "eval_outcome": response.get("eval_outcome"),
        "source_type": response.get("source_type"),
        "owner": response.get("owner"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Add eval_summary if present
    eval_summary = response.get("eval_summary")
    if eval_summary:
        scan_info["rules_passed"] = eval_summary.get("rules_passed", 0)
        scan_info["rules_failed"] = eval_summary.get("rules_failed", 0)
        scan_info["total_rules"] = eval_summary.get("total_rules", 0)

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Scan Created",
        [scan_info],
        headers=["uuid", "model_uri", "eval_outcome", "security_group_name", "source_type", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add helpful notes
    readable_output += f"\n**Scan UUID:** `{scan_info.get('uuid')}`"
    readable_output += f"\n**Status:** {scan_info.get('eval_outcome')} (scan is processing)"
    readable_output += f"\n\n**Next Steps:** Use `!prisma-airs-model-security-scans-get uuid=\"{scan_info.get('uuid')}\"` to check scan status and results."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScan",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get model security scan status and results.

    This command retrieves the current state of a scan, including eval_outcome (PENDING/ALLOWED/BLOCKED),
    rule evaluation summary, and any error details.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Data API to get scan details
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.get(uuid)
    # Endpoint: GET /v1/scans/{uuid} (data plane)
    url_suffix = f"/v1/scans/{uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: ScanBaseResponseSchema (same as scans-create)
    # Key fields: uuid, eval_outcome (PENDING/ALLOWED/BLOCKED), eval_summary, error_code, error_message
    scan_info = {
        "uuid": response.get("uuid"),
        "model_uri": response.get("model_uri"),
        "security_group_uuid": response.get("security_group_uuid"),
        "security_group_name": response.get("security_group_name"),
        "scan_origin": response.get("scan_origin"),
        "eval_outcome": response.get("eval_outcome"),
        "source_type": response.get("source_type"),
        "owner": response.get("owner"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "created_by": response.get("created_by"),
        "tsg_id": response.get("tsg_id"),
        "model_version_uuid": response.get("model_version_uuid"),
        "enabled_rule_count_snapshot": response.get("enabled_rule_count_snapshot"),
        "scanner_version": response.get("scanner_version"),
        "time_started": response.get("time_started"),
        "total_files_scanned": response.get("total_files_scanned"),
        "total_files_skipped": response.get("total_files_skipped")
    }

    # Add eval_summary if present
    eval_summary = response.get("eval_summary")
    if eval_summary:
        scan_info["rules_passed"] = eval_summary.get("rules_passed", 0)
        scan_info["rules_failed"] = eval_summary.get("rules_failed", 0)
        scan_info["total_rules"] = eval_summary.get("total_rules", 0)

    # Add error details if present
    if response.get("error_code"):
        scan_info["error_code"] = response.get("error_code")
    if response.get("error_message"):
        scan_info["error_message"] = response.get("error_message")

    # Add model formats if present
    if response.get("model_formats"):
        scan_info["model_formats"] = response.get("model_formats")

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Scan Status",
        [scan_info],
        headers=["uuid", "eval_outcome", "model_uri", "security_group_name",
                 "source_type", "rules_passed", "rules_failed", "total_rules", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add status-specific notes
    eval_outcome = scan_info.get("eval_outcome")
    if eval_outcome == "PENDING":
        readable_output += "\n\n**Status:** Scan is still processing. Poll this command to check for completion."
    elif eval_outcome == "ALLOWED":
        readable_output += f"\n\n**Status:** ✅ Scan complete - model ALLOWED ({scan_info.get('rules_passed', 0)} rules passed, {scan_info.get('rules_failed', 0)} failed)"
    elif eval_outcome == "BLOCKED":
        readable_output += f"\n\n**Status:** ❌ Scan complete - model BLOCKED ({scan_info.get('rules_failed', 0)} rules failed)"
        readable_output += f"\n\n**Next Steps:** Use `!prisma-airs-model-security-scans-violations uuid=\"{uuid}\"` to see detailed violations."

    # Add error details if present
    if scan_info.get("error_code") or scan_info.get("error_message"):
        readable_output += f"\n\n**Error Code:** {scan_info.get('error_code', 'N/A')}"
        readable_output += f"\n**Error Message:** {scan_info.get('error_message', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScan",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_violations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get rule violations for a model security scan.

    This command retrieves detailed violation information for a completed scan,
    showing which security rules failed and why.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Data API to get scan violations
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getViolations(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/rule-violations (data plane)
    url_suffix = f"/v1/scans/{uuid}/rule-violations"
    params = {
        "limit": limit,
        "offset": offset
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: ViolationListSchema
    # Response: { pagination: {...}, violations: [...] }
    violations_list = response.get("violations", [])
    pagination = response.get("pagination", {})

    # Transform violations for XSOAR output
    # Fields per ViolationResponseSchema: uuid, tsg_id, created_at, updated_at, description,
    # rule_instance_uuid, rule_name, rule_description, rule_instance_state,
    # file, hash, module, operator, threat, threat_description
    violations = []
    for violation in violations_list:
        violations.append({
            "uuid": violation.get("uuid"),
            "rule_name": violation.get("rule_name"),
            "rule_description": violation.get("rule_description"),
            "description": violation.get("description"),
            "rule_instance_state": violation.get("rule_instance_state"),
            "file": violation.get("file"),
            "threat": violation.get("threat"),
            "threat_description": violation.get("threat_description"),
            "module": violation.get("module"),
            "operator": violation.get("operator"),
            "hash": violation.get("hash"),
            "rule_instance_uuid": violation.get("rule_instance_uuid"),
            "created_at": violation.get("created_at"),
            "updated_at": violation.get("updated_at"),
            "tsg_id": violation.get("tsg_id")
        })

    # Create readable output using XSOAR table format
    if violations:
        readable_output = tableToMarkdown(
            f"Model Security Scan Violations (Scan: {uuid})",
            violations,
            headers=["rule_name", "description", "threat", "file", "module", "operator", "rule_instance_state"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True
        )
        readable_output += f"\n\n**Total Violations:** {len(violations)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(violations)} of {pagination.get('total_items')})"
    else:
        readable_output = f"No violations found for scan {uuid}"

    # Add context output with pagination metadata
    context_output = {
        "scan_uuid": uuid,
        "violations": violations,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityViolation",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_labels_keys_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get distinct label keys across all scans.

    Lists all unique label keys that have been used across scans for organization/filtering.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    # Call Model Security Data API to get label keys
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getLabelKeys(opts)
    # Endpoint: GET /v1/scans/label-keys (data plane)
    url_suffix = "/v1/scans/label-keys"
    params = {
        "limit": limit,
        "offset": offset
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: LabelKeyListSchema
    # Response: { pagination: {...}, keys: [...] }
    keys = response.get("keys", [])
    pagination = response.get("pagination", {})

    # Create readable output
    if keys:
        # Convert array of strings to list of dicts for table display
        keys_table = [{"Key": key} for key in keys]
        readable_output = tableToMarkdown(
            "Model Security Label Keys",
            keys_table,
            headers=["Key"],
            removeNull=True
        )
        readable_output += f"\n\n**Total Keys:** {len(keys)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(keys)} of {pagination.get('total_items')})"
    else:
        readable_output = "No label keys found"

    # Add context output
    context_output = {
        "keys": keys,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelKeys",
        outputs_key_field=None,  # No unique key field for this list
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_labels_values_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get distinct values for a label key.

    Lists all unique values that have been used for a specific label key across scans.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    key = args.get("key")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    if not key:
        raise ValueError("key is required")

    # Call Model Security Data API to get label values
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getLabelValues(key, opts)
    # Endpoint: GET /v1/scans/label-keys/{key}/values (data plane)
    # Note: SDK uses encodeURIComponent for key in path
    from urllib.parse import quote
    url_suffix = f"/v1/scans/label-keys/{quote(key, safe='')}/values"
    params = {
        "limit": limit,
        "offset": offset
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: LabelValueListSchema
    # Response: { pagination: {...}, values: [...] }
    values = response.get("values", [])
    pagination = response.get("pagination", {})

    # Create readable output
    if values:
        # Convert array of strings to list of dicts for table display
        values_table = [{"Value": value} for value in values]
        readable_output = tableToMarkdown(
            f"Model Security Label Values for Key: {key}",
            values_table,
            headers=["Value"],
            removeNull=True
        )
        readable_output += f"\n\n**Total Values:** {len(values)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(values)} of {pagination.get('total_items')})"
    else:
        readable_output = f"No label values found for key: {key}"

    # Add context output
    context_output = {
        "key": key,
        "values": values,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelValues",
        outputs_key_field=None,  # No unique key field for this list
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_labels_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add labels to a model security scan.

    Adds one or more labels to an existing scan for organization/filtering.
    Labels are key-value pairs that can be used to tag scans.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    scan_uuid = args.get("scan_uuid")
    labels_json = args.get("labels")

    if not scan_uuid:
        raise ValueError("scan_uuid is required")
    if not labels_json:
        raise ValueError("labels is required")

    # Parse labels JSON
    # Expected format: [{"key": "env", "value": "prod"}, {"key": "team", "value": "security"}]
    import json
    try:
        labels = json.loads(labels_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"labels must be valid JSON array: {e}")

    # Validate labels structure
    if not isinstance(labels, list):
        raise ValueError("labels must be a JSON array of objects with 'key' and 'value' fields")

    for label in labels:
        if not isinstance(label, dict) or "key" not in label or "value" not in label:
            raise ValueError("Each label must have 'key' and 'value' fields")

    # Build request body according to LabelsCreateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Schema: { labels: [{ key: string, value: string }] }
    request_body = {
        "labels": labels
    }

    # Call Model Security Data API to add labels
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.addLabels(scanUuid, body)
    # Endpoint: POST /v1/scans/{uuid}/labels (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/labels"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_data=True
    )

    # Response is empty object on success per LabelsResponseSchema
    # Create readable output
    labels_summary = ", ".join([f"{label['key']}={label['value']}" for label in labels])
    readable_output = f"✅ Successfully added {len(labels)} label(s) to scan {scan_uuid}\n\n"
    readable_output += f"**Labels Added:** {labels_summary}"

    # Context output
    context_output = {
        "scan_uuid": scan_uuid,
        "labels_added": labels,
        "success": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsAdd",
        outputs_key_field=None,
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_labels_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Set labels on a model security scan (replace all existing).

    Replaces all existing labels on a scan with the provided labels.
    This is different from add which appends to existing labels.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    scan_uuid = args.get("scan_uuid")
    labels_json = args.get("labels")

    if not scan_uuid:
        raise ValueError("scan_uuid is required")
    if not labels_json:
        raise ValueError("labels is required")

    # Parse labels JSON
    # Expected format: [{"key": "env", "value": "prod"}, {"key": "team", "value": "security"}]
    import json
    try:
        labels = json.loads(labels_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"labels must be valid JSON array: {e}")

    # Validate labels structure
    if not isinstance(labels, list):
        raise ValueError("labels must be a JSON array of objects with 'key' and 'value' fields")

    for label in labels:
        if not isinstance(label, dict) or "key" not in label or "value" not in label:
            raise ValueError("Each label must have 'key' and 'value' fields")

    # Build request body according to LabelsCreateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Schema: { labels: [{ key: string, value: string }] }
    request_body = {
        "labels": labels
    }

    # Call Model Security Data API to set labels (replace all)
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.setLabels(scanUuid, body)
    # Endpoint: PUT /v1/scans/{uuid}/labels (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/labels"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_data=True
    )

    # Response is empty object on success per LabelsResponseSchema
    # Create readable output
    labels_summary = ", ".join([f"{label['key']}={label['value']}" for label in labels])
    readable_output = f"✅ Successfully set {len(labels)} label(s) on scan {scan_uuid}\n\n"
    readable_output += f"**Labels (all previous labels replaced):** {labels_summary}"

    # Context output
    context_output = {
        "scan_uuid": scan_uuid,
        "labels_set": labels,
        "success": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsSet",
        outputs_key_field=None,
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_labels_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete labels from a model security scan by key.

    Deletes specific labels from a scan by providing their keys.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    scan_uuid = args.get("scan_uuid")
    keys_str = args.get("keys")

    if not scan_uuid:
        raise ValueError("scan_uuid is required")
    if not keys_str:
        raise ValueError("keys is required")

    # Parse keys - can be comma-separated string or JSON array
    # Expected format: "env,team" or '["env","team"]'
    keys = []
    if keys_str.startswith("["):
        # JSON array format
        import json
        try:
            keys = json.loads(keys_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"keys must be valid JSON array or comma-separated string: {e}")

        if not isinstance(keys, list):
            raise ValueError("keys JSON must be an array of strings")
    else:
        # Comma-separated format
        keys = [key.strip() for key in keys_str.split(",")]

    # Validate keys
    if not keys:
        raise ValueError("At least one key must be provided")

    # Call Model Security Data API to delete labels
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.deleteLabels(scanUuid, keys)
    # Endpoint: DELETE /v1/scans/{uuid}/labels?keys=key1&keys=key2 (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/labels"
    params = {"keys": keys}  # SDK passes array as repeated query params

    response = client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True,
        resp_type="response"  # DELETE may return empty response
    )

    # Response is void/undefined on success per SDK
    # Create readable output
    keys_summary = ", ".join(keys)
    readable_output = f"✅ Successfully deleted {len(keys)} label key(s) from scan {scan_uuid}\n\n"
    readable_output += f"**Deleted Keys:** {keys_summary}"

    # Context output
    context_output = {
        "scan_uuid": scan_uuid,
        "keys_deleted": keys,
        "success": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsDelete",
        outputs_key_field=None,
        outputs=context_output,
        readable_output=readable_output,
        raw_response={}  # Empty response
    )


def model_security_scans_evaluation_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single rule evaluation by UUID.

    Retrieves detailed information about a specific rule evaluation result.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Data API to get evaluation
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getEvaluation(uuid)
    # Endpoint: GET /v1/evaluations/{uuid} (data plane)
    url_suffix = f"/v1/evaluations/{uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: RuleEvaluationResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, result, violation_count,
    #         rule_instance_uuid, scan_uuid, rule_name, rule_description, rule_instance_state
    evaluation_info = {
        "uuid": response.get("uuid"),
        "scan_uuid": response.get("scan_uuid"),
        "rule_instance_uuid": response.get("rule_instance_uuid"),
        "rule_name": response.get("rule_name"),
        "rule_description": response.get("rule_description"),
        "result": response.get("result"),
        "violation_count": response.get("violation_count"),
        "rule_instance_state": response.get("rule_instance_state"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Rule Evaluation",
        [evaluation_info],
        headers=["rule_name", "result", "violation_count", "rule_instance_state", "scan_uuid"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add result-specific context
    result = evaluation_info.get("result")
    if result == "PASSED":
        readable_output += "\n\n✅ **Rule Passed** - No violations found"
    elif result == "FAILED":
        readable_output += f"\n\n❌ **Rule Failed** - {evaluation_info.get('violation_count', 0)} violation(s) detected"
    elif result == "ERROR":
        readable_output += "\n\n⚠️ **Evaluation Error** - Rule evaluation encountered an error"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityEvaluation",
        outputs_key_field="uuid",
        outputs=evaluation_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_violation_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single violation by UUID.

    Retrieves detailed information about a specific security rule violation.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Data API to get violation
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getViolation(uuid)
    # Endpoint: GET /v1/violations/{uuid} (data plane)
    url_suffix = f"/v1/violations/{uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: ViolationResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, description, rule_instance_uuid,
    #         rule_name, rule_description, rule_instance_state, file, hash, module,
    #         operator, threat, threat_description
    violation_info = {
        "uuid": response.get("uuid"),
        "rule_name": response.get("rule_name"),
        "rule_description": response.get("rule_description"),
        "description": response.get("description"),
        "rule_instance_state": response.get("rule_instance_state"),
        "file": response.get("file"),
        "threat": response.get("threat"),
        "threat_description": response.get("threat_description"),
        "module": response.get("module"),
        "operator": response.get("operator"),
        "hash": response.get("hash"),
        "rule_instance_uuid": response.get("rule_instance_uuid"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Violation Details",
        [violation_info],
        headers=["rule_name", "description", "threat", "file", "module", "operator"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add threat context if present
    if violation_info.get("threat"):
        readable_output += f"\n\n**Threat:** {violation_info.get('threat')}"
        if violation_info.get("threat_description"):
            readable_output += f"\n**Threat Description:** {violation_info.get('threat_description')}"

    # Add file context
    if violation_info.get("file"):
        readable_output += f"\n**File:** {violation_info.get('file')}"
        if violation_info.get("hash"):
            readable_output += f"\n**File Hash:** {violation_info.get('hash')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityViolationDetail",
        outputs_key_field="uuid",
        outputs=violation_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_files_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get files for a scan.

    Lists all files that were scanned within a model, showing file structure and scan results.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    scan_uuid = args.get("scan_uuid")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    if not scan_uuid:
        raise ValueError("scan_uuid is required")

    # Call Model Security Data API to get scan files
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getFiles(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/files (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/files"
    params = {
        "limit": limit,
        "offset": offset
    }

    # Add optional filters
    if args.get("sort_field"):
        params["sort_field"] = args.get("sort_field")
    if args.get("sort_dir"):
        params["sort_dir"] = args.get("sort_dir")
    if args.get("type"):
        params["type"] = args.get("type")
    if args.get("result"):
        params["result"] = args.get("result")
    if args.get("query_path"):
        params["query_path"] = args.get("query_path")

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: FileListSchema
    # Response: { pagination: {...}, files: [...] }
    files_list = response.get("files", [])
    pagination = response.get("pagination", {})

    # Transform files for XSOAR output
    # Fields per FileResponseSchema: uuid, tsg_id, created_at, updated_at, path,
    # parent_path, type, result, model_version_uuid, blob_id, formats, scan_uuid
    files = []
    for file in files_list:
        file_info = {
            "uuid": file.get("uuid"),
            "path": file.get("path"),
            "parent_path": file.get("parent_path"),
            "type": file.get("type"),
            "result": file.get("result"),
            "model_version_uuid": file.get("model_version_uuid"),
            "blob_id": file.get("blob_id"),
            "scan_uuid": file.get("scan_uuid"),
            "created_at": file.get("created_at"),
            "updated_at": file.get("updated_at"),
            "tsg_id": file.get("tsg_id")
        }

        # Add formats if present
        if file.get("formats"):
            file_info["formats"] = file.get("formats")

        files.append(file_info)

    # Create readable output using XSOAR table format
    if files:
        readable_output = tableToMarkdown(
            f"Model Security Scan Files (Scan: {scan_uuid})",
            files,
            headers=["path", "type", "result", "formats", "parent_path"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True
        )
        readable_output += f"\n\n**Total Files:** {len(files)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(files)} of {pagination.get('total_items')})"
    else:
        readable_output = f"No files found for scan {scan_uuid}"

    # Add context output with pagination metadata
    context_output = {
        "scan_uuid": scan_uuid,
        "files": files,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityFiles",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_scans_evaluations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get rule evaluations for a scan.

    Lists all rule evaluations for a scan, showing which security rules passed, failed, or had errors.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    scan_uuid = args.get("scan_uuid")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    if not scan_uuid:
        raise ValueError("scan_uuid is required")

    # Call Model Security Data API to get scan rule evaluations
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getEvaluations(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/evaluations (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/evaluations"
    params = {
        "limit": limit,
        "offset": offset
    }

    # Add optional filters
    if args.get("sort_field"):
        params["sort_field"] = args.get("sort_field")
    if args.get("sort_order"):
        params["sort_order"] = args.get("sort_order")
    if args.get("result"):
        params["result"] = args.get("result")
    if args.get("rule_instance_uuid"):
        params["rule_instance_uuid"] = args.get("rule_instance_uuid")

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True
    )

    # Parse response - SDK schema: RuleEvaluationListSchema
    # Response: { pagination: {...}, evaluations: [...] }
    evaluations_list = response.get("evaluations", [])
    pagination = response.get("pagination", {})

    # Transform evaluations for XSOAR output
    # Fields per RuleEvaluationResponseSchema: uuid, tsg_id, created_at, updated_at,
    # scan_uuid, rule_name, result, violation_count, rule_instance_state,
    # rule_instance_uuid, rule_description
    evaluations = []
    for evaluation in evaluations_list:
        eval_info = {
            "uuid": evaluation.get("uuid"),
            "scan_uuid": evaluation.get("scan_uuid"),
            "rule_name": evaluation.get("rule_name"),
            "result": evaluation.get("result"),
            "violation_count": evaluation.get("violation_count"),
            "rule_instance_state": evaluation.get("rule_instance_state"),
            "rule_instance_uuid": evaluation.get("rule_instance_uuid"),
            "rule_description": evaluation.get("rule_description"),
            "created_at": evaluation.get("created_at"),
            "updated_at": evaluation.get("updated_at"),
            "tsg_id": evaluation.get("tsg_id")
        }
        evaluations.append(eval_info)

    # Create readable output using XSOAR table format
    if evaluations:
        readable_output = tableToMarkdown(
            f"Model Security Scan Rule Evaluations (Scan: {scan_uuid})",
            evaluations,
            headers=["rule_name", "result", "violation_count", "rule_instance_state", "rule_description"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True
        )
        readable_output += f"\n\n**Total Evaluations:** {len(evaluations)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(evaluations)} of {pagination.get('total_items')})"
    else:
        readable_output = f"No rule evaluations found for scan {scan_uuid}"

    # Add context output with pagination metadata
    context_output = {
        "scan_uuid": scan_uuid,
        "evaluations": evaluations,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityEvaluations",
        outputs_key_field="uuid",
        outputs=context_output,
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


def model_security_groups_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get model security group details by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Management API to get security group details
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.get(uuid)
    # Endpoint: GET /v1/security-groups/{uuid}
    url_suffix = f"/v1/security-groups/{uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityGroupResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, name, description, source_type, state, is_tombstone
    group_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "description": response.get("description"),
        "source_type": response.get("source_type"),
        "state": response.get("state"),
        "is_tombstone": response.get("is_tombstone"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        f"Model Security Group: {group_info.get('name')}",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroup",
        outputs_key_field="uuid",
        outputs=group_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_groups_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new model security group.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    name = args.get("name")
    source_type = args.get("source_type")
    description = args.get("description", "")

    if not name:
        raise ValueError("name is required")
    if not source_type:
        raise ValueError("source_type is required")

    # Validate source_type
    valid_source_types = ["HUGGING_FACE", "LOCAL", "S3", "GCS", "AZURE"]
    if source_type not in valid_source_types:
        raise ValueError(f"source_type must be one of: {', '.join(valid_source_types)}")

    # Build request body according to ModelSecurityGroupCreateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Required: name, source_type
    # Optional: description, rule_configurations
    request_body = {
        "name": name,
        "source_type": source_type,
        "description": description
    }

    # Call Model Security Management API to create security group
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.create(body)
    # Endpoint: POST /v1/security-groups
    url_suffix = "/v1/security-groups"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityGroupResponseSchema
    # Fields: uuid, tsg_id, created_at, updated_at, name, description, source_type, state, is_tombstone
    group_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "description": response.get("description"),
        "source_type": response.get("source_type"),
        "state": response.get("state"),
        "is_tombstone": response.get("is_tombstone"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        f"Model Security Group Created: {group_info.get('name')}",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add helpful note
    readable_output += f"\n**UUID:** `{group_info.get('uuid')}`"
    readable_output += f"\n**State:** {group_info.get('state')} (Group will become ACTIVE after rule instances are configured)"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroup",
        outputs_key_field="uuid",
        outputs=group_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_groups_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a security group.

    Removes a security group that is no longer needed.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Management API to delete security group
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.delete(uuid)
    # Endpoint: DELETE /v1/security-groups/{uuid} (management plane)
    url_suffix = f"/v1/security-groups/{uuid}"

    client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        use_model_sec_mgmt=True,
        resp_type="response"  # DELETE returns empty response
    )

    # Response is void on success per SDK
    # Create readable output
    readable_output = f"✅ Successfully deleted security group: {uuid}"

    # Context output
    context_output = {
        "uuid": uuid,
        "deleted": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroupDelete",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response={}  # Empty response
    )


def model_security_groups_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing security group.

    Updates the name and/or description of a security group.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    name = args.get("name")
    description = args.get("description")

    if not uuid:
        raise ValueError("uuid is required")

    # At least one field must be provided to update
    if not name and not description:
        raise ValueError("At least one of 'name' or 'description' must be provided")

    # Build request body according to ModelSecurityGroupUpdateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Schema: { name?: string, description?: string }
    request_body: dict[str, Any] = {}

    if name:
        request_body["name"] = name
    if description:
        request_body["description"] = description

    # Call Model Security Management API to update security group
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.update(uuid, body)
    # Endpoint: PUT /v1/security-groups/{uuid} (management plane)
    url_suffix = f"/v1/security-groups/{uuid}"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityGroupResponseSchema (same as groups-get)
    group_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "description": response.get("description"),
        "source_type": response.get("source_type"),
        "state": response.get("state"),
        "is_tombstone": response.get("is_tombstone"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Updated Model Security Group",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add update summary
    updates = []
    if name:
        updates.append(f"name → '{name}'")
    if description:
        updates.append(f"description → '{description}'")
    readable_output += f"\n\n**Updated:** {', '.join(updates)}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroup",
        outputs_key_field="uuid",
        outputs=group_info,
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


def model_security_rules_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get model security rule details by UUID.

    Retrieves full rule definition including description, compatible sources, default state,
    remediation steps, and editable fields.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Management API to get rule details
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-rules-client.ts
    # SDK: SecurityRulesClient.get(uuid)
    # Endpoint: GET /v1/security-rules/{uuid} (management plane)
    url_suffix = f"/v1/security-rules/{uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityRuleResponseSchema
    # Fields: uuid, name, description, rule_type, compatible_sources, default_state,
    #         remediation (description, steps, url), editable_fields, constant_values, default_values
    rule_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "description": response.get("description"),
        "rule_type": response.get("rule_type"),
        "compatible_sources": response.get("compatible_sources", []),
        "default_state": response.get("default_state")
    }

    # Add remediation info
    remediation = response.get("remediation")
    if remediation:
        rule_info["remediation_description"] = remediation.get("description")
        rule_info["remediation_steps"] = remediation.get("steps", [])
        rule_info["remediation_url"] = remediation.get("url")

    # Add editable_fields, constant_values, default_values for advanced use
    if response.get("editable_fields"):
        rule_info["editable_fields"] = response.get("editable_fields")
    if response.get("constant_values"):
        rule_info["constant_values"] = response.get("constant_values")
    if response.get("default_values"):
        rule_info["default_values"] = response.get("default_values")

    # Create readable output using XSOAR table format
    # Basic info table
    basic_info = [{
        "UUID": rule_info.get("uuid"),
        "Name": rule_info.get("name"),
        "Type": rule_info.get("rule_type"),
        "Default State": rule_info.get("default_state"),
        "Compatible Sources": ", ".join(rule_info.get("compatible_sources", []))
    }]

    readable_output = tableToMarkdown(
        "Model Security Rule Details",
        basic_info,
        headers=["UUID", "Name", "Type", "Default State", "Compatible Sources"],
        removeNull=True
    )

    # Add description
    readable_output += f"\n**Description:** {rule_info.get('description')}"

    # Add remediation section if present
    if remediation:
        readable_output += "\n\n### Remediation"
        readable_output += f"\n{remediation.get('description', '')}"
        if remediation.get("steps"):
            readable_output += "\n\n**Steps:**"
            for i, step in enumerate(remediation.get("steps", []), 1):
                readable_output += f"\n{i}. {step}"
        if remediation.get("url"):
            readable_output += f"\n\n**Reference:** {remediation.get('url')}"

    # Add editable fields info if present
    editable_fields = response.get("editable_fields", [])
    if editable_fields:
        readable_output += f"\n\n**Editable Fields:** {len(editable_fields)} field(s) can be customized when applying this rule to a security group"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRule",
        outputs_key_field="uuid",
        outputs=rule_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_rule_instances_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List rule instances for a security group.

    Rule instances are rules that have been applied to a specific security group.
    Each instance has a state (DISABLED/ALLOWING/BLOCKING) and optional field customizations.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    security_group_uuid = args.get("security_group_uuid")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    offset = arg_to_number(args.get("offset", 0))

    if not security_group_uuid:
        raise ValueError("security_group_uuid is required")

    # Call Model Security Management API to list rule instances
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.listRuleInstances(securityGroupUuid, opts)
    # Endpoint: GET /v1/security-groups/{uuid}/rule-instances (management plane)
    url_suffix = f"/v1/security-groups/{security_group_uuid}/rule-instances"
    params = {
        "limit": limit,
        "offset": offset
    }

    # Add optional filters
    if args.get("security_rule_uuid"):
        params["security_rule_uuid"] = args.get("security_rule_uuid")
    if args.get("state"):
        params["state"] = args.get("state")

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ListModelSecurityRuleInstancesResponseSchema
    # Response: { pagination: {...}, rule_instances: [...] }
    rule_instances_list = response.get("rule_instances", [])
    pagination = response.get("pagination", {})

    # Transform rule instances for XSOAR output
    # Fields per ModelSecurityRuleInstanceResponseSchema: uuid, tsg_id, created_at, updated_at,
    # security_group_uuid, security_rule_uuid, state, rule (nested ModelSecurityRuleResponseSchema), field_values
    rule_instances = []
    for instance in rule_instances_list:
        rule_data = instance.get("rule", {})
        rule_instance_info = {
            "uuid": instance.get("uuid"),
            "security_group_uuid": instance.get("security_group_uuid"),
            "security_rule_uuid": instance.get("security_rule_uuid"),
            "state": instance.get("state"),
            "rule_name": rule_data.get("name"),
            "rule_type": rule_data.get("rule_type"),
            "rule_description": rule_data.get("description"),
            "created_at": instance.get("created_at"),
            "updated_at": instance.get("updated_at"),
            "tsg_id": instance.get("tsg_id")
        }

        # Add field_values if present (custom configuration for this rule instance)
        if instance.get("field_values"):
            rule_instance_info["field_values"] = instance.get("field_values")

        rule_instances.append(rule_instance_info)

    # Create readable output using XSOAR table format
    if rule_instances:
        readable_output = tableToMarkdown(
            f"Model Security Rule Instances (Security Group: {security_group_uuid})",
            rule_instances,
            headers=["rule_name", "state", "rule_type", "uuid", "updated_at"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True
        )
        readable_output += f"\n\n**Total Rule Instances:** {len(rule_instances)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(rule_instances)} of {pagination.get('total_items')})"
    else:
        readable_output = f"No rule instances found for security group {security_group_uuid}"

    # Add context output with pagination metadata
    context_output = {
        "security_group_uuid": security_group_uuid,
        "rule_instances": rule_instances,
        "total_items": pagination.get("total_items"),
        "limit": limit,
        "offset": offset
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstance",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_rule_instances_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a rule instance within a security group.

    This command allows updating the state (DISABLED/ALLOWING/BLOCKING) and field values
    of a rule instance. Use this to enable/disable rules or customize rule parameters.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    security_group_uuid = args.get("security_group_uuid")
    rule_instance_uuid = args.get("rule_instance_uuid")
    state = args.get("state")

    if not security_group_uuid:
        raise ValueError("security_group_uuid is required")
    if not rule_instance_uuid:
        raise ValueError("rule_instance_uuid is required")

    # Build request body according to ModelSecurityRuleInstanceUpdateRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/model-security.ts
    # Required: security_group_uuid
    # Optional: state (DISABLED/ALLOWING/BLOCKING), field_values (custom rule config)
    request_body: dict[str, Any] = {
        "security_group_uuid": security_group_uuid
    }

    # Add optional state update
    if state:
        request_body["state"] = state

    # Add optional field_values update (JSON object with custom rule configuration)
    # Note: field_values is a JSON object, so we expect it as a JSON string in args
    if args.get("field_values"):
        import json
        try:
            request_body["field_values"] = json.loads(args.get("field_values"))
        except json.JSONDecodeError as e:
            raise ValueError(f"field_values must be valid JSON: {e}")

    # Call Model Security Management API to update rule instance
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.updateRuleInstance(securityGroupUuid, ruleInstanceUuid, body)
    # Endpoint: PUT /v1/security-groups/{uuid}/rule-instances/{ruleInstanceUuid} (management plane)
    url_suffix = f"/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityRuleInstanceResponseSchema (same as list)
    rule_data = response.get("rule", {})
    rule_instance_info = {
        "uuid": response.get("uuid"),
        "security_group_uuid": response.get("security_group_uuid"),
        "security_rule_uuid": response.get("security_rule_uuid"),
        "state": response.get("state"),
        "rule_name": rule_data.get("name"),
        "rule_type": rule_data.get("rule_type"),
        "rule_description": rule_data.get("description"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Add field_values if present
    if response.get("field_values"):
        rule_instance_info["field_values"] = response.get("field_values")

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Updated Model Security Rule Instance",
        [rule_instance_info],
        headers=["rule_name", "state", "rule_type", "uuid", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add helpful context about the update
    if state:
        readable_output += f"\n\n**State Updated:** {state}"
    if response.get("field_values"):
        readable_output += f"\n**Custom Field Values:** {len(response.get('field_values', {}))} field(s) configured"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstance",
        outputs_key_field="uuid",
        outputs=rule_instance_info,
        readable_output=readable_output,
        raw_response=response
    )


def model_security_rule_instances_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single rule instance within a security group.

    Retrieves detailed configuration of a specific rule instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    security_group_uuid = args.get("security_group_uuid")
    rule_instance_uuid = args.get("rule_instance_uuid")

    if not security_group_uuid:
        raise ValueError("security_group_uuid is required")
    if not rule_instance_uuid:
        raise ValueError("rule_instance_uuid is required")

    # Call Model Security Management API to get rule instance
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.getRuleInstance(securityGroupUuid, ruleInstanceUuid)
    # Endpoint: GET /v1/security-groups/{groupUuid}/rule-instances/{instanceUuid} (management plane)
    url_suffix = f"/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}"

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_model_sec_mgmt=True
    )

    # Parse response - SDK schema: ModelSecurityRuleInstanceResponseSchema
    # Same structure as rule-instances-list items
    rule_data = response.get("rule", {})
    rule_instance_info = {
        "uuid": response.get("uuid"),
        "security_group_uuid": response.get("security_group_uuid"),
        "security_rule_uuid": response.get("security_rule_uuid"),
        "state": response.get("state"),
        "rule_name": rule_data.get("name"),
        "rule_type": rule_data.get("rule_type"),
        "rule_description": rule_data.get("description"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "tsg_id": response.get("tsg_id")
    }

    # Add field_values if present
    if response.get("field_values"):
        rule_instance_info["field_values"] = response.get("field_values")

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        f"Model Security Rule Instance Details",
        [rule_instance_info],
        headers=["rule_name", "state", "rule_type", "uuid", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add configuration details
    if rule_instance_info.get("field_values"):
        readable_output += f"\n\n**Custom Field Values:** {len(rule_instance_info.get('field_values', {}))} field(s) configured"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstance",
        outputs_key_field="uuid",
        outputs=rule_instance_info,
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


def redteam_targets_profile_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team target profile (background, context, profiling status).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    target_uuid = args.get("target_uuid")
    if not target_uuid:
        raise ValueError("target_uuid is required")

    # Call Red Team target profile endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/targets-client.ts (lines 272-282)
    # SDK: TargetsClient.getProfile(uuid)
    # Endpoint: GET /v1/target/{uuid}/profile
    # Response: TargetProfileResponseSchema - { target_id, target_version, status, profiling_status, target_background, additional_context, ai_generated_fields, other_details }
    url_suffix = f"{RED_TEAM_TARGETS_ENDPOINT}/{target_uuid}/profile"
    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_redteam_mgmt=True
    )

    # Parse response according to TargetProfileResponseSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (lines 1160-1172)
    profile_info = {
        "target_id": response.get("target_id"),
        "target_version": response.get("target_version"),
        "status": response.get("status"),
        "profiling_status": response.get("profiling_status")
    }

    # Add optional fields if present
    if response.get("target_background"):
        profile_info["target_background"] = response.get("target_background")
    if response.get("additional_context"):
        profile_info["additional_context"] = response.get("additional_context")
    if response.get("ai_generated_fields"):
        profile_info["ai_generated_fields"] = response.get("ai_generated_fields")
    if response.get("other_details"):
        profile_info["other_details"] = response.get("other_details")

    # Create readable output
    readable_output = f"## Red Team Target Profile\n\n"
    readable_output += f"**Target ID:** {profile_info.get('target_id')}\n\n"
    readable_output += f"**Version:** {profile_info.get('target_version')}\n\n"
    readable_output += f"**Status:** {profile_info.get('status')}\n\n"
    readable_output += f"**Profiling Status:** {profile_info.get('profiling_status')}\n\n"

    if profile_info.get("target_background"):
        import json
        readable_output += f"**Background:**\n```json\n{json.dumps(profile_info.get('target_background'), indent=2)}\n```\n\n"

    if profile_info.get("additional_context"):
        import json
        readable_output += f"**Additional Context:**\n```json\n{json.dumps(profile_info.get('additional_context'), indent=2)}\n```\n\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetProfile",
        outputs_key_field="target_id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_update_profile_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update Red Team target profile (background and additional context).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    import json

    target_uuid = args.get("target_uuid")
    if not target_uuid:
        raise ValueError("target_uuid is required")

    # Build request body according to TargetContextUpdateSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (lines 1063-1069)
    # SDK: TargetsClient.updateProfile(uuid, body)
    # Endpoint: PUT /v1/target/{uuid}/profile
    # Body: { target_background?: {...}, additional_context?: {...} }
    request_body: dict[str, Any] = {}

    # Parse target_background from JSON string if provided
    target_background_json = args.get("target_background")
    if target_background_json:
        try:
            request_body["target_background"] = json.loads(target_background_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in target_background: {e}")

    # Parse additional_context from JSON string if provided
    additional_context_json = args.get("additional_context")
    if additional_context_json:
        try:
            request_body["additional_context"] = json.loads(additional_context_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in additional_context: {e}")

    if not request_body:
        raise ValueError("At least one of target_background or additional_context must be provided")

    # Call Red Team target update profile endpoint
    url_suffix = f"{RED_TEAM_TARGETS_ENDPOINT}/{target_uuid}/profile"
    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_redteam_mgmt=True
    )

    # Parse response according to TargetResponseSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (lines 1071-1099)
    target_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "updated_at": response.get("updated_at")
    }

    # Add target_background and additional_context if present in response
    if response.get("target_background"):
        target_info["target_background"] = response.get("target_background")
    if response.get("additional_context"):
        target_info["additional_context"] = response.get("additional_context")

    # Create readable output
    readable_output = f"## ✅ Target Profile Updated\n\n"
    readable_output += f"**Target:** {target_info.get('name')} (UUID: {target_info.get('uuid')})\n\n"
    readable_output += f"**Status:** {target_info.get('status')}\n\n"
    readable_output += f"**Updated:** {target_info.get('updated_at')}\n\n"

    if target_info.get("target_background"):
        readable_output += f"**Background:**\n```json\n{json.dumps(target_info.get('target_background'), indent=2)}\n```\n\n"

    if target_info.get("additional_context"):
        readable_output += f"**Additional Context:**\n```json\n{json.dumps(target_info.get('additional_context'), indent=2)}\n```\n\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_targets_metadata_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team target field metadata (field definitions for target configuration).

    This command returns metadata describing all available fields for target configuration,
    including their types, requirements, and constraints. Useful for understanding what
    fields are available when creating or updating targets.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team target metadata endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/targets-client.ts (lines 357-366)
    # SDK: TargetsClient.getTargetMetadata()
    # Endpoint: GET /v1/template/target-metadata
    # Response: Record<string, unknown> - field definitions
    url_suffix = f"{RED_TEAM_TEMPLATE_ENDPOINT}/target-metadata"
    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_redteam_mgmt=True
    )

    # Response is a dictionary of field definitions
    # Example: { "rate_limit": { "type": "number", "required": false }, "multi_turn": { "type": "boolean" } }
    metadata = response if isinstance(response, dict) else {}

    # Create readable output showing field definitions
    import json
    readable_output = f"## Red Team Target Field Metadata\n\n"
    readable_output += f"**Total Fields:** {len(metadata)}\n\n"

    if metadata:
        readable_output += "**Field Definitions:**\n```json\n"
        readable_output += json.dumps(metadata, indent=2)
        readable_output += "\n```\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetMetadata",
        outputs=metadata,
        readable_output=readable_output,
        raw_response=response
    )


def redteam_scan_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team scan job.

    This command creates a scan and returns immediately. It does NOT poll for completion.
    Use prisma-airs-redteam-scan-get to check status, or implement polling in a playbook.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    import json

    # Required arguments
    name = args.get("name")
    target_uuid = args.get("target_uuid")
    job_type = args.get("job_type", "STATIC")  # Default to STATIC

    if not name:
        raise ValueError("name is required")
    if not target_uuid:
        raise ValueError("target_uuid is required")

    # Validate job_type
    valid_types = ["STATIC", "DYNAMIC", "CUSTOM"]
    if job_type not in valid_types:
        raise ValueError(f"job_type must be one of: {', '.join(valid_types)}")

    # Build job_metadata based on job_type
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts
    # - StaticJobMetadataSchema: { categories: Record<string, unknown> }
    # - DynamicJobMetadataSchema: { stream_breadth, stream_depth, attack_goals }
    # - CustomJobMetadataSchema: { custom_prompt_sets: Array<unknown> }
    job_metadata: dict[str, Any] = {}

    if job_type == "STATIC":
        # STATIC scans: optional categories filter
        categories_json = args.get("categories")
        if categories_json:
            try:
                job_metadata["categories"] = json.loads(categories_json)
            except json.JSONDecodeError as e:
                raise ValueError(f"categories must be valid JSON: {e}")
        else:
            # Empty categories object means "all categories"
            job_metadata["categories"] = {}

    elif job_type == "DYNAMIC":
        # DYNAMIC scans: stream_breadth, stream_depth, attack_goals
        # Defaults from CLI: breadth=6, depth=10
        stream_breadth = arg_to_number(args.get("stream_breadth")) or 6
        stream_depth = arg_to_number(args.get("stream_depth")) or 10

        job_metadata["stream_breadth"] = stream_breadth
        job_metadata["stream_depth"] = stream_depth

        # Optional attack_goals array
        attack_goals_json = args.get("attack_goals")
        if attack_goals_json:
            try:
                attack_goals = json.loads(attack_goals_json)
                if not isinstance(attack_goals, list):
                    raise ValueError("attack_goals must be a JSON array")
                job_metadata["attack_goals"] = attack_goals
            except json.JSONDecodeError as e:
                raise ValueError(f"attack_goals must be valid JSON: {e}")

    elif job_type == "CUSTOM":
        # CUSTOM scans: custom_prompt_sets as array of UUIDs
        # CRITICAL: Must be array of UUID strings, NOT objects
        # Reference: CLI redteam.ts line 352-355
        prompt_sets_str = args.get("custom_prompt_sets")
        if not prompt_sets_str:
            raise ValueError("custom_prompt_sets is required for CUSTOM scans")

        # Parse comma-separated UUIDs
        custom_prompt_sets = [uuid.strip() for uuid in prompt_sets_str.split(",")]
        job_metadata["custom_prompt_sets"] = custom_prompt_sets

    # Build request body according to JobCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (JobCreateRequestSchema)
    # Required fields: name, target (TargetJobRequestSchema), job_type, job_metadata
    request_body = {
        "name": name,
        "target": {
            "uuid": target_uuid
        },
        "job_type": job_type,
        "job_metadata": job_metadata
    }

    # Call Red Team scan create endpoint
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts (create method)
    # Endpoint: POST /ai-red-teaming/data-plane/v1/scan
    # Response: JobResponseSchema
    response = client.http_request(
        method="POST",
        url_suffix=RED_TEAM_SCANS_ENDPOINT,
        json_data=request_body,
        use_redteam_data=True
    )

    # Parse response according to JobResponseSchema
    # Key fields: uuid (job ID), name, status, job_type, target_id, total, completed, score, asr
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
        "updated_at": response.get("updated_at")
    }

    # Add optional fields if present
    optional_fields = ["version", "extra_info", "job_metadata", "time_record",
                       "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            scan_info[field] = response.get(field)

    # Create readable output using XSOAR best practice table format
    readable_output = tableToMarkdown(
        "Red Team Scan Created Successfully",
        [scan_info],
        headers=["uuid", "name", "job_type", "status", "target_id",
                 "target_type", "total", "completed", "score", "asr", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True
    )

    # Add helpful note below table
    readable_output += "\n**Next Steps:** Use `!prisma-airs-redteam-scan-get uuid=\"" + \
        str(scan_info.get('uuid')) + "\"` to check scan status and progress."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScan",
        outputs_key_field="uuid",
        outputs=scan_info,
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


def runtime_topics_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a specific custom topic by ID or name.

    Note: There is no dedicated GET endpoint - this fetches all topics and filters.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    topic_id = args.get("topic_id")
    topic_name = args.get("topic_name")

    if not topic_id and not topic_name:
        raise ValueError("Either topic_id or topic_name is required")

    # Call Management API to list all topics, then filter
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # SDK: TopicsClient has no get() method - uses list() and client-side filtering
    # Note: No dedicated GET endpoint exists - SDK pattern is same as profiles
    url_suffix = f"{MGMT_API_V1_PREFIX}/topics/tsg/{client.tsg_id}"
    params = {
        "offset": "0",
        "limit": "1000"  # Get all topics for filtering
    }

    response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        params=params,
        use_mgmt_base=True
    )

    # Parse response and filter
    # SDK schema: CustomTopicListResponseSchema has "custom_topics" field
    topics_raw = response.get("custom_topics", response.get("data", []))

    # Filter by ID or name
    if topic_id:
        matches = [t for t in topics_raw if t.get("topic_id") == topic_id]
        search_key = f"ID: {topic_id}"
    else:
        # Filter by name
        matches = [t for t in topics_raw if t.get("topic_name") == topic_name]
        search_key = f"Name: {topic_name}"

    if not matches:
        raise ValueError(f"Topic not found: {search_key}")

    topic = matches[0]

    # Extract full topic details
    topic_info = {
        "topic_id": topic.get("topic_id"),
        "topic_name": topic.get("topic_name"),
        "revision": topic.get("revision"),
        "active": topic.get("active"),
        "description": topic.get("description"),
        "examples": topic.get("examples", []),
        "created_by": topic.get("created_by"),
        "updated_by": topic.get("updated_by"),
        "last_modified_ts": topic.get("last_modified_ts"),
        "created_ts": topic.get("created_ts")
    }

    # Create readable output
    readable_output = f"## Custom Topic: {topic_info.get('topic_name')}\n\n"
    readable_output += f"**ID:** {topic_info.get('topic_id')}\n\n"
    readable_output += f"**Revision:** {topic_info.get('revision')}\n\n"
    readable_output += f"**Active:** {topic_info.get('active')}\n\n"
    readable_output += f"**Description:** {topic_info.get('description', 'N/A')}\n\n"
    readable_output += f"**Created By:** {topic_info.get('created_by', 'N/A')}\n\n"
    readable_output += f"**Updated By:** {topic_info.get('updated_by', 'N/A')}\n\n"
    readable_output += f"**Last Modified:** {topic_info.get('last_modified_ts', 'N/A')}\n\n"

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):  # Show first 5
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}Topic",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=topic
    )


def runtime_topics_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new custom topic guardrail.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    topic_name = args.get("topic_name")
    description = args.get("description")
    examples = argToList(args.get("examples"))
    active = argToBoolean(args.get("active", True))

    if not topic_name:
        raise ValueError("topic_name is required")
    if not description:
        raise ValueError("description is required")
    if not examples:
        raise ValueError("examples is required (comma-separated list)")

    # Build request body according to CreateCustomTopicRequest
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/mgmt-custom-topic.ts
    # Required: topic_name, description, examples
    # Optional: active
    request_body: dict[str, Any] = {
        "topic_name": topic_name,
        "description": description,
        "examples": examples,
        "active": active
    }

    # Call Management API to create topic
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # SDK: TopicsClient.create(body)
    # Endpoint: POST /v1/mgmt/topic
    url_suffix = f"{MGMT_API_V1_PREFIX}/topic"

    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response - returns full CustomTopic
    topic_info = {
        "topic_id": response.get("topic_id"),
        "topic_name": response.get("topic_name"),
        "revision": response.get("revision"),
        "active": response.get("active"),
        "description": response.get("description"),
        "examples": response.get("examples", []),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by"),
        "last_modified_ts": response.get("last_modified_ts"),
        "created_ts": response.get("created_ts")
    }

    # Create readable output
    readable_output = f"## ✅ Custom Topic Created\n\n"
    readable_output += f"**ID:** {topic_info.get('topic_id')}\n\n"
    readable_output += f"**Name:** {topic_info.get('topic_name')}\n\n"
    readable_output += f"**Revision:** {topic_info.get('revision')}\n\n"
    readable_output += f"**Active:** {topic_info.get('active')}\n\n"
    readable_output += f"**Description:** {topic_info.get('description')}\n\n"
    readable_output += f"**Created By:** {topic_info.get('created_by', 'N/A')}\n\n"

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}Topic",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_topics_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing custom topic.

    WARNING: This modifies the topic definition and can break detection if misconfigured.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    topic_id = args.get("topic_id")
    topic_name = args.get("topic_name")
    description = args.get("description")
    examples = args.get("examples")
    active = args.get("active")

    if not topic_id:
        raise ValueError("topic_id is required")
    if not topic_name:
        raise ValueError("topic_name is required")

    # Build request body according to CreateCustomTopicRequest
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/mgmt-custom-topic.ts
    request_body: dict[str, Any] = {
        "topic_name": topic_name
    }

    # Add optional fields if provided
    if description:
        request_body["description"] = description
    if examples:
        request_body["examples"] = argToList(examples)
    if active is not None:
        request_body["active"] = argToBoolean(active)

    # Call Management API to update topic
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # SDK: TopicsClient.update(topicId, body)
    # Endpoint: PUT /v1/mgmt/topic/uuid/{topicId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/topic/uuid/{topic_id}"

    response = client.http_request(
        method="PUT",
        url_suffix=url_suffix,
        json_data=request_body,
        use_mgmt_base=True
    )

    # Parse response - returns updated CustomTopic with incremented revision
    topic_info = {
        "topic_id": response.get("topic_id"),
        "topic_name": response.get("topic_name"),
        "revision": response.get("revision"),  # Incremented
        "active": response.get("active"),
        "description": response.get("description"),
        "examples": response.get("examples", []),
        "created_by": response.get("created_by"),
        "updated_by": response.get("updated_by"),
        "last_modified_ts": response.get("last_modified_ts"),
        "created_ts": response.get("created_ts")
    }

    # Create readable output
    readable_output = f"## ✅ Custom Topic Updated\n\n"
    readable_output += f"**ID:** {topic_info.get('topic_id')}\n\n"
    readable_output += f"**Name:** {topic_info.get('topic_name')}\n\n"
    readable_output += f"**Revision:** {topic_info.get('revision')} (incremented)\n\n"
    readable_output += f"**Active:** {topic_info.get('active')}\n\n"
    readable_output += f"**Description:** {topic_info.get('description')}\n\n"
    readable_output += f"**Updated By:** {topic_info.get('updated_by', 'N/A')}\n\n"
    readable_output += f"**Last Modified:** {topic_info.get('last_modified_ts', 'N/A')}\n\n"

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}Topic",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_topics_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a custom topic.

    WARNING: This permanently deletes the topic. Fails if topic is referenced by a profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    topic_id = args.get("topic_id")

    if not topic_id:
        raise ValueError("topic_id is required")

    # Call Management API to delete topic
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # SDK: TopicsClient.delete(topicId)
    # Endpoint: DELETE /v1/mgmt/topic/{topicId}
    # Response: { message: "deleted" } (or plain string transformed to object)
    # NOTE: Fails with 409 Conflict if topic is referenced by any profile
    url_suffix = f"{MGMT_API_V1_PREFIX}/topic/{topic_id}"

    response = client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        use_mgmt_base=True
    )

    # Parse response - SDK handles both string and object responses
    # DeleteTopicResponseSchema transforms plain string to { message: "..." }
    message = response.get("message", "Custom topic deleted successfully") if isinstance(response, dict) else str(response)

    # Create readable output
    readable_output = f"## ✅ Custom Topic Deleted\n\n"
    readable_output += f"**Topic ID:** {topic_id}\n\n"
    readable_output += f"**Status:** {message}\n\n"
    readable_output += "**⚠️ WARNING:** This action cannot be undone. The custom topic has been permanently deleted."

    # Context output
    context_output = {
        "topic_id": topic_id,
        "message": message,
        "deleted": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicDeleted",
        outputs_key_field="topic_id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_topics_apply_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Apply a topic to a security profile (additive - preserves existing topics).

    This command orchestrates multiple API calls to apply a custom topic to a security profile:
    1. Find topic by name → get topic_id and current revision
    2. Get profile by name → extract current topic-guardrails configuration
    3. Merge topics: remove old instance (if exists), add new with action/revision
    4. Update profile with modified policy

    CRITICAL: AIRS requires the topic revision number to pin topic content correctly.
    Omitting revision defaults to revision 0 (original), not latest.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_name = args.get("profile_name")
    topic_name = args.get("topic_name")
    action = args.get("action", "block")  # Topic action: "allow" or "block"
    guardrail_action = args.get("guardrail_action", "block")  # Overall default action

    if not profile_name or not topic_name:
        raise ValueError("profile_name and topic_name are required")

    if action not in ["allow", "block"]:
        raise ValueError("action must be 'allow' or 'block'")

    if guardrail_action not in ["allow", "block"]:
        raise ValueError("guardrail_action must be 'allow' or 'block'")

    # Step 1: Find topic by name and get current revision
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/cli/commands/topics-apply.ts (lines 24-28)
    # SDK: ManagementClient.topics.list()
    # Endpoint: GET /v1/mgmt/topics/tsg/{tsgId}
    url_suffix = f"{MGMT_API_V1_PREFIX}/topics/tsg/{client.tsg_id}"
    topics_response = client.http_request(
        method="GET",
        url_suffix=url_suffix,
        use_mgmt_base=True
    )

    all_topics = topics_response.get("custom_topics", [])
    topic = next((t for t in all_topics if t.get("topic_name") == topic_name), None)

    if not topic:
        raise DemistoException(f"Topic '{topic_name}' not found. Create it first with prisma-airs-runtime-topics-create.")

    topic_id = topic.get("topic_id")
    topic_revision = topic.get("revision", 0)

    if not topic_id:
        raise DemistoException(f"Topic '{topic_name}' found but missing topic_id")

    # Step 2: Get profile by name
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/airs/management.ts (lines 102-106)
    # SDK: ManagementClient.profiles.list()
    # Endpoint: GET /v1/mgmt/securityprofiles/tsg/{tsgId}
    profiles_url_suffix = f"{MGMT_API_V1_PREFIX}/securityprofiles/tsg/{client.tsg_id}"
    profiles_response = client.http_request(
        method="GET",
        url_suffix=profiles_url_suffix,
        use_mgmt_base=True
    )

    ai_profiles = profiles_response.get("ai_profiles", [])
    profile = next((p for p in ai_profiles if p.get("profile_name") == profile_name), None)

    if not profile:
        raise DemistoException(f"Profile '{profile_name}' not found. Create it first with prisma-airs-runtime-profiles-create.")

    profile_id = profile.get("profile_id")
    if not profile_id:
        raise DemistoException(f"Profile '{profile_name}' found but missing profile_id")

    # Step 3: Extract and modify profile policy
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/airs/management.ts (lines 114-162)
    # Profile structure: policy → ai-security-profiles → model-configuration → model-protection → topic-guardrails
    import copy
    policy = copy.deepcopy(profile.get("policy", {}))

    # Navigate to ai-security-profiles
    ai_sec_profiles = policy.get("ai-security-profiles", [])
    if not ai_sec_profiles:
        ai_sec_profiles = [{"model-type": "default", "model-configuration": {}}]
        policy["ai-security-profiles"] = ai_sec_profiles

    model_config = ai_sec_profiles[0].get("model-configuration", {})
    if "model-configuration" not in ai_sec_profiles[0]:
        ai_sec_profiles[0]["model-configuration"] = model_config

    # Navigate to model-protection
    model_protection = model_config.get("model-protection", [])
    if "model-protection" not in model_config:
        model_config["model-protection"] = model_protection

    # Find or create topic-guardrails
    topic_guardrails = next((mp for mp in model_protection if mp.get("name") == "topic-guardrails"), None)

    if not topic_guardrails:
        topic_guardrails = {
            "action": guardrail_action,
            "name": "topic-guardrails",
            "options": [],
            "topic-list": []
        }
        model_protection.append(topic_guardrails)
    else:
        # Update guardrail-level action
        topic_guardrails["action"] = guardrail_action

    # Get current topic-list
    topic_list = topic_guardrails.get("topic-list", [])
    if "topic-list" not in topic_guardrails:
        topic_guardrails["topic-list"] = topic_list

    # Remove old instance of this topic (if exists) to avoid duplicates
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/cli/commands/topics-apply.ts (lines 32-34)
    for entry in topic_list:
        topics_in_entry = entry.get("topic", [])
        entry["topic"] = [t for t in topics_in_entry if t.get("topic_name") != topic_name]

    # Remove empty action groups (AIRS rejects them)
    topic_list = [entry for entry in topic_list if entry.get("topic")]

    # Add new topic to appropriate action group
    # Find or create action group
    action_group = next((entry for entry in topic_list if entry.get("action") == action), None)

    if not action_group:
        action_group = {"action": action, "topic": []}
        topic_list.append(action_group)

    # Add topic with revision (CRITICAL: must include revision)
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/airs/management.ts (lines 144-152)
    action_group["topic"].append({
        "topic_id": topic_id,
        "topic_name": topic_name,
        "revision": topic_revision
    })

    topic_guardrails["topic-list"] = topic_list

    # Step 4: Update profile with modified policy
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/airs/management.ts (lines 169-173)
    # SDK: ManagementClient.profiles.update(profileId, body)
    # Endpoint: PUT /v1/mgmt/securityprofiles/uuid/{profileId}
    update_url_suffix = f"{MGMT_API_V1_PREFIX}/securityprofiles/uuid/{profile_id}"
    update_body = {
        "profile_name": profile_name,
        "active": profile.get("active", True),
        "policy": policy
    }

    update_response = client.http_request(
        method="PUT",
        url_suffix=update_url_suffix,
        json_data=update_body,
        use_mgmt_base=True
    )

    # Create readable output
    readable_output = f"## ✅ Topic Applied to Profile\n\n"
    readable_output += f"**Topic:** {topic_name} (ID: {topic_id}, Revision: {topic_revision})\n\n"
    readable_output += f"**Profile:** {profile_name}\n\n"
    readable_output += f"**Topic Action:** {action}\n\n"
    readable_output += f"**Guardrail Default Action:** {guardrail_action}\n\n"
    readable_output += "**Note:** Topic has been added to the profile. Existing topics were preserved. "
    readable_output += "The topic's current revision was pinned to ensure consistent detection behavior."

    # Context output
    context_output = {
        "profile_name": profile_name,
        "profile_id": profile_id,
        "topic_name": topic_name,
        "topic_id": topic_id,
        "topic_revision": topic_revision,
        "action": action,
        "guardrail_action": guardrail_action,
        "applied": True
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicApplied",
        outputs_key_field="profile_name",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=update_response
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


def runtime_dlp_dictionaries_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single DLP dictionary by ID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    dictionary_id = args.get("dictionary_id")
    if not dictionary_id:
        raise ValueError("dictionary_id is required")

    include_keywords = argToBoolean(args.get("include_keywords", False))

    # Build query parameters
    params: dict[str, Any] = {}
    if include_keywords:
        params["keywords"] = "true"

    # Call DLP dictionaries get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: GET /v2/api/dictionaries/{resourceId}?keywords=true
    response = client.http_request(
        method="GET",
        url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}",
        params=params,
        use_dlp_base=True
    )

    # Extract dictionary details from response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-dictionary.ts
    dict_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "category": response.get("category"),
        "region_name": response.get("region_name"),
        "type": response.get("type"),
        "is_case_sensitive": response.get("is_case_sensitive"),
        "is_parent_managed": response.get("is_parent_managed"),
        "detection_technique": response.get("detection_technique"),
        "detection_sub_technique": response.get("detection_sub_technique"),
        "dictionary_metadata": response.get("dictionary_metadata"),
        "keywords": response.get("keywords"),  # Only populated if include_keywords=true
        "tags": response.get("tags"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "is_case_sensitive", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_dictionaries_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new DLP dictionary by uploading a keyword file.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Build metadata (required fields)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-dictionary.ts
    name = args.get("name")
    category = args.get("category")
    region_name = args.get("region_name")
    entry_id = args.get("entry_id")

    if not name:
        raise ValueError("name is required")
    if not category:
        raise ValueError("category is required")
    if not region_name:
        raise ValueError("region_name is required")
    if not entry_id:
        raise ValueError("entry_id is required (file entry ID from war room)")

    # Get uploaded file from war room
    file_info = demisto.getFilePath(entry_id)
    file_path = file_info["path"]
    file_name = file_info["name"]

    # Read file content
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Build metadata JSON
    metadata: dict[str, Any] = {
        "category": category,
        "name": name,
        "original_file_name": file_name,
        "region_name": region_name
    }

    # Optional fields
    if args.get("description"):
        metadata["description"] = args.get("description")

    if args.get("is_case_sensitive") is not None:
        metadata["is_case_sensitive"] = argToBoolean(args.get("is_case_sensitive"))

    if args.get("type"):
        metadata["type"] = args.get("type")

    include_keywords = argToBoolean(args.get("include_keywords", False))

    # Build query parameters
    params: dict[str, Any] = {}
    if include_keywords:
        params["keywords"] = "true"

    # Build multipart form data
    # SDK sends: FormData with 'json' part (metadata as JSON blob) and 'file' part (keyword file)
    files = {
        'json': ('metadata.json', json.dumps(metadata).encode('utf-8'), 'application/json'),
        'file': (file_name, file_content, 'text/plain')
    }

    # Call DLP dictionaries create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: POST /v2/api/dictionaries (multipart/form-data)
    response = client.http_request(
        method="POST",
        url_suffix=DLP_DICTIONARIES_PATH,
        params=params,
        files=files,
        use_dlp_base=True
    )

    # Extract created dictionary details
    dict_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "category": response.get("category"),
        "region_name": response.get("region_name"),
        "type": response.get("type"),
        "is_case_sensitive": response.get("is_case_sensitive"),
        "detection_technique": response.get("detection_technique"),
        "dictionary_metadata": response.get("dictionary_metadata"),
        "keywords": response.get("keywords"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary Created: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_dictionaries_patch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Partially update a DLP dictionary (JSON Merge Patch).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    dictionary_id = args.get("dictionary_id")
    if not dictionary_id:
        raise ValueError("dictionary_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-dictionary.ts
    # PATCH requires: category, name, original_file_name (cannot be cleared)
    name = args.get("name")
    category = args.get("category")
    original_file_name = args.get("original_file_name")

    if not name:
        raise ValueError("name is required for PATCH")
    if not category:
        raise ValueError("category is required for PATCH")
    if not original_file_name:
        raise ValueError("original_file_name is required for PATCH")

    request_body: dict[str, Any] = {
        "category": category,
        "name": name,
        "original_file_name": original_file_name
    }

    # Optional: description (can be null to clear)
    if args.get("description") is not None:
        desc_value = args.get("description")
        request_body["description"] = None if desc_value == "null" else desc_value

    # Optional: is_case_sensitive (can be null to clear)
    if args.get("is_case_sensitive") is not None:
        case_value = args.get("is_case_sensitive")
        if case_value == "null":
            request_body["is_case_sensitive"] = None
        else:
            request_body["is_case_sensitive"] = argToBoolean(case_value)

    # Optional: region_name (can be null to clear)
    if args.get("region_name") is not None:
        region_value = args.get("region_name")
        request_body["region_name"] = None if region_value == "null" else region_value

    # Call DLP dictionaries patch endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: PATCH /v2/api/dictionaries/{resourceId}
    # Uses Content-Type: application/merge-patch+json
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}",
        json_data=request_body,
        use_dlp_base=True,
        headers={"Content-Type": "application/merge-patch+json"}
    )

    # Extract updated dictionary details
    dict_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "category": response.get("category"),
        "region_name": response.get("region_name"),
        "type": response.get("type"),
        "is_case_sensitive": response.get("is_case_sensitive"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary Patched: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_dictionaries_replace_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Replace (full update) a DLP dictionary by uploading a new keyword file.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    dictionary_id = args.get("dictionary_id")
    if not dictionary_id:
        raise ValueError("dictionary_id is required")

    # Build metadata (required fields)
    name = args.get("name")
    category = args.get("category")
    region_name = args.get("region_name")
    entry_id = args.get("entry_id")

    if not name:
        raise ValueError("name is required")
    if not category:
        raise ValueError("category is required")
    if not region_name:
        raise ValueError("region_name is required")
    if not entry_id:
        raise ValueError("entry_id is required (file entry ID from war room)")

    # Get uploaded file from war room
    file_info = demisto.getFilePath(entry_id)
    file_path = file_info["path"]
    file_name = file_info["name"]

    # Read file content
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Build metadata JSON
    metadata: dict[str, Any] = {
        "category": category,
        "name": name,
        "original_file_name": file_name,
        "region_name": region_name
    }

    # Optional fields
    if args.get("description"):
        metadata["description"] = args.get("description")

    if args.get("is_case_sensitive") is not None:
        metadata["is_case_sensitive"] = argToBoolean(args.get("is_case_sensitive"))

    if args.get("type"):
        metadata["type"] = args.get("type")

    include_keywords = argToBoolean(args.get("include_keywords", False))

    # Build query parameters
    params: dict[str, Any] = {}
    if include_keywords:
        params["keywords"] = "true"

    # Build multipart form data
    files = {
        'json': ('metadata.json', json.dumps(metadata).encode('utf-8'), 'application/json'),
        'file': (file_name, file_content, 'text/plain')
    }

    # Call DLP dictionaries replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: PUT /v2/api/dictionaries/{resourceId} (multipart/form-data)
    # API may return 200 with body or 204 with no body
    response = client.http_request(
        method="PUT",
        url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}",
        params=params,
        files=files,
        use_dlp_base=True
    )

    # Handle both 200 (with body) and 204 (no body) responses
    if response:
        dict_info = {
            "id": response.get("id"),
            "name": response.get("name"),
            "description": response.get("description"),
            "category": response.get("category"),
            "region_name": response.get("region_name"),
            "type": response.get("type"),
            "is_case_sensitive": response.get("is_case_sensitive"),
            "keywords": response.get("keywords"),
            "updated_at": response.get("audit_metadata", {}).get("updated_at"),
            "updated_by": response.get("audit_metadata", {}).get("updated_by")
        }

        readable_output = tableToMarkdown(
            f"Prisma AIRs DLP Dictionary Replaced: {dict_info.get('name')}",
            dict_info,
            headers=["id", "name", "category", "type", "region_name", "description"],
            headerTransform=lambda h: h.replace("_", " ").title()
        )

        return CommandResults(
            outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
            outputs_key_field="id",
            outputs=dict_info,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        # 204 No Content response
        readable_output = f"## Prisma AIRs DLP Dictionary Replaced\n\nDictionary ID `{dictionary_id}` has been successfully replaced (204 No Content)."
        return CommandResults(readable_output=readable_output)


def runtime_dlp_dictionaries_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a DLP dictionary.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    dictionary_id = args.get("dictionary_id")
    if not dictionary_id:
        raise ValueError("dictionary_id is required")

    # Call DLP dictionaries delete endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: DELETE /v2/api/dictionaries/{resourceId}
    # Returns 204 No Content on success
    client.http_request(
        method="DELETE",
        url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}",
        use_dlp_base=True,
        resp_type="response"
    )

    readable_output = f"## Prisma AIRs DLP Dictionary Deleted\n\nDictionary ID `{dictionary_id}` has been successfully deleted."

    return CommandResults(
        readable_output=readable_output
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


def runtime_dlp_patterns_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single DLP data pattern by ID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    pattern_id = args.get("pattern_id")
    if not pattern_id:
        raise ValueError("pattern_id is required")

    # Call DLP patterns get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: GET /v2/api/data-patterns/{resourceId}
    response = client.http_request(
        method="GET",
        url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}",
        use_dlp_base=True
    )

    # Extract pattern details from response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-pattern.ts
    pattern_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "status": response.get("status"),
        "license_type": response.get("license_type"),
        "is_parent_managed": response.get("is_parent_managed"),
        "version": response.get("version"),
        "detection_config": response.get("detection_config"),
        "matching_rules": response.get("matching_rules"),
        "tags": response.get("tags"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "license_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_patterns_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new DLP data pattern.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-pattern.ts
    # Required fields: name, type, detection_config
    name = args.get("name")
    pattern_type = args.get("type")
    detection_technique = args.get("detection_technique")

    if not name:
        raise ValueError("name is required")
    if not pattern_type:
        raise ValueError("type is required")
    if not detection_technique:
        raise ValueError("detection_technique is required")

    request_body: dict[str, Any] = {
        "name": name,
        "type": pattern_type,
        "detection_config": {
            "technique": detection_technique
        }
    }

    # Optional: supported_confidence_levels (array of low/medium/high)
    if args.get("supported_confidence_levels"):
        confidence_levels = args.get("supported_confidence_levels")
        if isinstance(confidence_levels, str):
            try:
                confidence_list = json.loads(confidence_levels)
            except (json.JSONDecodeError, ValueError):
                confidence_list = [c.strip() for c in confidence_levels.split(",")]
        else:
            confidence_list = confidence_levels
        request_body["detection_config"]["supported_confidence_levels"] = confidence_list

    # Optional: description
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Optional: matching_rules (complex nested object)
    if args.get("matching_rules"):
        matching_rules_str = args.get("matching_rules")
        try:
            matching_rules = json.loads(matching_rules_str)
            request_body["matching_rules"] = matching_rules
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"matching_rules must be valid JSON: {e}")

    # Optional: tags (classification, compliance, geography arrays)
    if args.get("tags"):
        tags_str = args.get("tags")
        try:
            tags = json.loads(tags_str)
            request_body["tags"] = tags
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"tags must be valid JSON: {e}")

    # Call DLP patterns create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: POST /v2/api/data-patterns
    response = client.http_request(
        method="POST",
        url_suffix=DLP_PATTERNS_PATH,
        json_data=request_body,
        use_dlp_base=True
    )

    # Extract created pattern details
    pattern_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "status": response.get("status"),
        "license_type": response.get("license_type"),
        "version": response.get("version"),
        "detection_config": response.get("detection_config"),
        "matching_rules": response.get("matching_rules"),
        "tags": response.get("tags"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Created: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_patterns_patch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Partially update a DLP data pattern (JSON Merge Patch).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    pattern_id = args.get("pattern_id")
    if not pattern_id:
        raise ValueError("pattern_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-pattern.ts
    # PATCH requires: name, type, detection_config (cannot be cleared)
    name = args.get("name")
    pattern_type = args.get("type")
    detection_technique = args.get("detection_technique")

    if not name:
        raise ValueError("name is required for PATCH")
    if not pattern_type:
        raise ValueError("type is required for PATCH")
    if not detection_technique:
        raise ValueError("detection_technique is required for PATCH")

    request_body: dict[str, Any] = {
        "name": name,
        "type": pattern_type,
        "detection_config": {
            "technique": detection_technique
        }
    }

    # Optional: supported_confidence_levels
    if args.get("supported_confidence_levels"):
        confidence_levels = args.get("supported_confidence_levels")
        if isinstance(confidence_levels, str):
            try:
                confidence_list = json.loads(confidence_levels)
            except (json.JSONDecodeError, ValueError):
                confidence_list = [c.strip() for c in confidence_levels.split(",")]
        else:
            confidence_list = confidence_levels
        request_body["detection_config"]["supported_confidence_levels"] = confidence_list

    # Optional: description (can be null to clear)
    if args.get("description") is not None:
        desc_value = args.get("description")
        request_body["description"] = None if desc_value == "null" else desc_value

    # Optional: matching_rules (can be null to clear)
    if args.get("matching_rules") is not None:
        matching_rules_str = args.get("matching_rules")
        if matching_rules_str == "null":
            request_body["matching_rules"] = None
        else:
            try:
                request_body["matching_rules"] = json.loads(matching_rules_str)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"matching_rules must be valid JSON or 'null': {e}")

    # Optional: tags (can be null to clear)
    if args.get("tags") is not None:
        tags_str = args.get("tags")
        if tags_str == "null":
            request_body["tags"] = None
        else:
            try:
                request_body["tags"] = json.loads(tags_str)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"tags must be valid JSON or 'null': {e}")

    # Call DLP patterns patch endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: PATCH /v2/api/data-patterns/{resourceId}
    # Uses Content-Type: application/merge-patch+json
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}",
        json_data=request_body,
        use_dlp_base=True,
        headers={"Content-Type": "application/merge-patch+json"}
    )

    # Extract updated pattern details
    pattern_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "status": response.get("status"),
        "version": response.get("version"),
        "detection_config": response.get("detection_config"),
        "matching_rules": response.get("matching_rules"),
        "tags": response.get("tags"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Patched: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_patterns_replace_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Replace (full update) a DLP data pattern.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    pattern_id = args.get("pattern_id")
    if not pattern_id:
        raise ValueError("pattern_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-pattern.ts
    # Required fields: name, type, detection_config
    name = args.get("name")
    pattern_type = args.get("type")
    detection_technique = args.get("detection_technique")

    if not name:
        raise ValueError("name is required")
    if not pattern_type:
        raise ValueError("type is required")
    if not detection_technique:
        raise ValueError("detection_technique is required")

    request_body: dict[str, Any] = {
        "name": name,
        "type": pattern_type,
        "detection_config": {
            "technique": detection_technique
        }
    }

    # Optional: supported_confidence_levels
    if args.get("supported_confidence_levels"):
        confidence_levels = args.get("supported_confidence_levels")
        if isinstance(confidence_levels, str):
            try:
                confidence_list = json.loads(confidence_levels)
            except (json.JSONDecodeError, ValueError):
                confidence_list = [c.strip() for c in confidence_levels.split(",")]
        else:
            confidence_list = confidence_levels
        request_body["detection_config"]["supported_confidence_levels"] = confidence_list

    # Optional: description
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Optional: matching_rules
    if args.get("matching_rules"):
        matching_rules_str = args.get("matching_rules")
        try:
            request_body["matching_rules"] = json.loads(matching_rules_str)
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"matching_rules must be valid JSON: {e}")

    # Optional: tags
    if args.get("tags"):
        tags_str = args.get("tags")
        try:
            request_body["tags"] = json.loads(tags_str)
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"tags must be valid JSON: {e}")

    # Call DLP patterns replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: PUT /v2/api/data-patterns/{resourceId}
    response = client.http_request(
        method="PUT",
        url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}",
        json_data=request_body,
        use_dlp_base=True
    )

    # Extract updated pattern details
    pattern_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "status": response.get("status"),
        "version": response.get("version"),
        "detection_config": response.get("detection_config"),
        "matching_rules": response.get("matching_rules"),
        "tags": response.get("tags"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Replaced: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_patterns_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete (soft-delete/archive) a DLP data pattern.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    pattern_id = args.get("pattern_id")
    if not pattern_id:
        raise ValueError("pattern_id is required")

    # Call DLP patterns delete endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: DELETE /v2/api/data-patterns/{resourceId}
    # Returns 204 No Content on success
    client.http_request(
        method="DELETE",
        url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}",
        use_dlp_base=True,
        resp_type="response"
    )

    readable_output = f"## Prisma AIRs DLP Pattern Deleted\n\nPattern ID `{pattern_id}` has been successfully archived."

    return CommandResults(
        readable_output=readable_output
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


def runtime_dlp_filtering_profiles_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single DLP filtering profile by ID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Call DLP filtering profiles get endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-filtering-profiles.ts
    # SDK: GET /v2/api/data-filtering-profiles/{resourceId}
    response = client.http_request(
        method="GET",
        url_suffix=f"{DLP_FILTERING_PROFILES_PATH}/{profile_id}",
        use_dlp_base=True
    )

    # Extract profile details from response
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-filtering-profile.ts
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "data_profile_id": response.get("data_profile_id"),
        "direction": response.get("direction"),
        "file_based": response.get("file_based"),
        "non_file_based": response.get("non_file_based"),
        "log_severity": response.get("log_severity"),
        "scan_type": response.get("scan_type"),
        "is_end_user_coaching_enabled": response.get("is_end_user_coaching_enabled"),
        "is_granular_profile": response.get("is_granular_profile"),
        "is_parent_managed": response.get("is_parent_managed"),
        "euc_template_id": response.get("euc_template_id"),
        "version": response.get("version"),
        "file_type": response.get("file_type"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profile: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "direction", "file_based", "non_file_based", "log_severity", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfile",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response
    )


def runtime_dlp_filtering_profiles_replace_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Replace (full update) a DLP filtering profile.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Build request body
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/dlp-data-filtering-profile.ts
    # Required fields: file_based, non_file_based
    request_body: dict[str, Any] = {
        "file_based": argToBoolean(args.get("file_based", False)),
        "non_file_based": argToBoolean(args.get("non_file_based", False))
    }

    # Optional fields
    if args.get("description"):
        request_body["description"] = args.get("description")

    if args.get("direction"):
        request_body["direction"] = args.get("direction")

    if args.get("log_severity"):
        request_body["log_severity"] = args.get("log_severity")

    if args.get("scan_type"):
        request_body["scan_type"] = args.get("scan_type")

    if args.get("data_profile_id"):
        request_body["data_profile_id"] = arg_to_number(args.get("data_profile_id"))

    if args.get("euc_template_id"):
        request_body["euc_template_id"] = args.get("euc_template_id")

    if args.get("is_end_user_coaching_enabled") is not None:
        request_body["is_end_user_coaching_enabled"] = argToBoolean(args.get("is_end_user_coaching_enabled"))

    if args.get("is_granular_profile") is not None:
        request_body["is_granular_profile"] = argToBoolean(args.get("is_granular_profile"))

    # Handle file_type as comma-separated string or JSON array
    if args.get("file_type"):
        file_type_value = args.get("file_type")
        if isinstance(file_type_value, str):
            try:
                # Try parsing as JSON array first
                file_type_list = json.loads(file_type_value)
            except (json.JSONDecodeError, ValueError):
                # Fall back to comma-separated string
                file_type_list = [ft.strip() for ft in file_type_value.split(",")]
        else:
            file_type_list = file_type_value
        request_body["file_type"] = file_type_list

    # Call DLP filtering profiles replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-filtering-profiles.ts
    # SDK: PUT /v2/api/data-filtering-profiles/{resourceId}
    response = client.http_request(
        method="PUT",
        url_suffix=f"{DLP_FILTERING_PROFILES_PATH}/{profile_id}",
        json_data=request_body,
        use_dlp_base=True
    )

    # Extract updated profile details from response
    profile_info = {
        "id": response.get("id"),
        "name": response.get("name"),
        "description": response.get("description"),
        "tenant_id": response.get("tenant_id"),
        "type": response.get("type"),
        "data_profile_id": response.get("data_profile_id"),
        "direction": response.get("direction"),
        "file_based": response.get("file_based"),
        "non_file_based": response.get("non_file_based"),
        "log_severity": response.get("log_severity"),
        "scan_type": response.get("scan_type"),
        "is_end_user_coaching_enabled": response.get("is_end_user_coaching_enabled"),
        "is_granular_profile": response.get("is_granular_profile"),
        "is_parent_managed": response.get("is_parent_managed"),
        "version": response.get("version"),
        "created_at": response.get("audit_metadata", {}).get("created_at"),
        "updated_at": response.get("audit_metadata", {}).get("updated_at"),
        "created_by": response.get("audit_metadata", {}).get("created_by"),
        "updated_by": response.get("audit_metadata", {}).get("updated_by")
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profile Updated: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "direction", "file_based", "non_file_based", "log_severity", "description"],
        headerTransform=lambda h: h.replace("_", " ").title()
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfile",
        outputs_key_field="id",
        outputs=profile_info,
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

        elif command == "prisma-airs-runtime-api-keys-create":
            return_results(runtime_api_keys_create_command(client, args))

        elif command == "prisma-airs-runtime-api-keys-regenerate":
            return_results(runtime_api_keys_regenerate_command(client, args))

        elif command == "prisma-airs-runtime-api-keys-delete":
            return_results(runtime_api_keys_delete_command(client, args))

        elif command == "prisma-airs-runtime-profiles-list":
            return_results(runtime_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-profiles-get":
            return_results(runtime_profiles_get_command(client, args))

        elif command == "prisma-airs-runtime-profiles-create":
            return_results(runtime_profiles_create_command(client, args))

        elif command == "prisma-airs-runtime-profiles-update":
            return_results(runtime_profiles_update_command(client, args))

        elif command == "prisma-airs-runtime-profiles-delete":
            return_results(runtime_profiles_delete_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-list":
            return_results(runtime_customer_apps_list_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-get":
            return_results(runtime_customer_apps_get_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-update":
            return_results(runtime_customer_apps_update_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-consumption":
            return_results(runtime_customer_apps_consumption_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-violations":
            return_results(runtime_customer_apps_violations_command(client, args))

        elif command == "prisma-airs-runtime-customer-apps-delete":
            return_results(runtime_customer_apps_delete_command(client, args))

        elif command == "prisma-airs-runtime-deployment-profiles-list":
            return_results(runtime_deployment_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-list":
            return_results(runtime_dlp_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-get":
            return_results(runtime_dlp_profiles_get_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-create":
            return_results(runtime_dlp_profiles_create_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-patch":
            return_results(runtime_dlp_profiles_patch_command(client, args))

        elif command == "prisma-airs-runtime-dlp-profiles-replace":
            return_results(runtime_dlp_profiles_replace_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-list":
            return_results(runtime_dlp_dictionaries_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-get":
            return_results(runtime_dlp_dictionaries_get_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-create":
            return_results(runtime_dlp_dictionaries_create_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-patch":
            return_results(runtime_dlp_dictionaries_patch_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-replace":
            return_results(runtime_dlp_dictionaries_replace_command(client, args))

        elif command == "prisma-airs-runtime-dlp-dictionaries-delete":
            return_results(runtime_dlp_dictionaries_delete_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-list":
            return_results(runtime_dlp_patterns_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-get":
            return_results(runtime_dlp_patterns_get_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-create":
            return_results(runtime_dlp_patterns_create_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-patch":
            return_results(runtime_dlp_patterns_patch_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-replace":
            return_results(runtime_dlp_patterns_replace_command(client, args))

        elif command == "prisma-airs-runtime-dlp-patterns-delete":
            return_results(runtime_dlp_patterns_delete_command(client, args))

        elif command == "prisma-airs-runtime-dlp-filtering-profiles-list":
            return_results(runtime_dlp_filtering_profiles_list_command(client, args))

        elif command == "prisma-airs-runtime-dlp-filtering-profiles-get":
            return_results(runtime_dlp_filtering_profiles_get_command(client, args))

        elif command == "prisma-airs-runtime-dlp-filtering-profiles-replace":
            return_results(runtime_dlp_filtering_profiles_replace_command(client, args))

        elif command == "prisma-airs-runtime-scan-logs":
            return_results(runtime_scan_logs_command(client, args))

        elif command == "prisma-airs-runtime-topics-list":
            return_results(runtime_topics_list_command(client, args))

        elif command == "prisma-airs-runtime-topics-get":
            return_results(runtime_topics_get_command(client, args))

        elif command == "prisma-airs-runtime-topics-create":
            return_results(runtime_topics_create_command(client, args))

        elif command == "prisma-airs-runtime-topics-update":
            return_results(runtime_topics_update_command(client, args))

        elif command == "prisma-airs-runtime-topics-delete":
            return_results(runtime_topics_delete_command(client, args))

        elif command == "prisma-airs-runtime-topics-apply":
            return_results(runtime_topics_apply_command(client, args))

        elif command == "prisma-airs-runtime-bulk-scan":
            return_results(runtime_bulk_scan_command(client, args))

        elif command == "prisma-airs-model-security-scans-list":
            return_results(model_security_scans_list_command(client, args))

        elif command == "prisma-airs-model-security-scans-create":
            return_results(model_security_scans_create_command(client, args))

        elif command == "prisma-airs-model-security-scans-get":
            return_results(model_security_scans_get_command(client, args))

        elif command == "prisma-airs-model-security-scans-violations":
            return_results(model_security_scans_violations_command(client, args))

        elif command == "prisma-airs-model-security-labels-keys":
            return_results(model_security_labels_keys_command(client, args))

        elif command == "prisma-airs-model-security-labels-values":
            return_results(model_security_labels_values_command(client, args))

        elif command == "prisma-airs-model-security-labels-add":
            return_results(model_security_labels_add_command(client, args))

        elif command == "prisma-airs-model-security-labels-set":
            return_results(model_security_labels_set_command(client, args))

        elif command == "prisma-airs-model-security-labels-delete":
            return_results(model_security_labels_delete_command(client, args))

        elif command == "prisma-airs-model-security-scans-evaluation":
            return_results(model_security_scans_evaluation_command(client, args))

        elif command == "prisma-airs-model-security-scans-violation":
            return_results(model_security_scans_violation_command(client, args))

        elif command == "prisma-airs-model-security-scans-files":
            return_results(model_security_scans_files_command(client, args))

        elif command == "prisma-airs-model-security-scans-evaluations":
            return_results(model_security_scans_evaluations_command(client, args))

        elif command == "prisma-airs-model-security-groups-list":
            return_results(model_security_groups_list_command(client, args))

        elif command == "prisma-airs-model-security-groups-get":
            return_results(model_security_groups_get_command(client, args))

        elif command == "prisma-airs-model-security-groups-create":
            return_results(model_security_groups_create_command(client, args))

        elif command == "prisma-airs-model-security-groups-delete":
            return_results(model_security_groups_delete_command(client, args))

        elif command == "prisma-airs-model-security-groups-update":
            return_results(model_security_groups_update_command(client, args))

        elif command == "prisma-airs-model-security-rules-list":
            return_results(model_security_rules_list_command(client, args))

        elif command == "prisma-airs-model-security-rules-get":
            return_results(model_security_rules_get_command(client, args))

        elif command == "prisma-airs-model-security-rule-instances-list":
            return_results(model_security_rule_instances_list_command(client, args))

        elif command == "prisma-airs-model-security-rule-instances-update":
            return_results(model_security_rule_instances_update_command(client, args))

        elif command == "prisma-airs-model-security-rule-instances-get":
            return_results(model_security_rule_instances_get_command(client, args))

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

        elif command == "prisma-airs-redteam-scan-create":
            return_results(redteam_scan_create_command(client, args))

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
