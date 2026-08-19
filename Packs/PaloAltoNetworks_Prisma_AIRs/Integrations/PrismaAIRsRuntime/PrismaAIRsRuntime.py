import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from PrismaAirsApiModule import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS (Runtime + DLP specific; shared constants come from PrismaAirsApiModule)
# Management API v1 path prefix (appended after MGMT_API_PATH).
MGMT_API_V1_PREFIX = "/v1/mgmt"
# DLP API path suffixes (v2 API) - uses the separate DLP base URL (see PrismaAirsApiModule).
# Reference: ./knowledge/prisma-airs-sdk-main/src/constants.ts
DLP_DICTIONARIES_PATH = "/v2/api/dictionaries"
DLP_PATTERNS_PATH = "/v2/api/data-patterns"
DLP_FILTERING_PROFILES_PATH = "/v2/api/data-filtering-profiles"
DLP_DATA_PROFILES_PATH = "/v2/api/data-profiles"


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

    scan_request: dict[str, Any] = {"ai_profile": {"profile_name": profile_name}, "contents": [content]}

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
        "response_detected": response_detected,  # Include full response_detected object
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
    scan_summary = [
        {
            "Scan ID": scan_result["scan_id"],
            "Report ID": scan_result["report_id"],
            "Profile": profile_name,
            "Action": scan_result["action"].upper(),
            "Category": scan_result["category"],
            "Detected": "Yes" if overall_detected else "No",
        }
    ]

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
            prompt_detections_table.append(
                {"Detection Type": detection_type.replace("_", " ").title(), "Detected": "Yes" if detected_value else "No"}
            )

    # Build response detections table (forward-compatible: dynamically handle all detection fields)
    response_detections_table = []
    if response_detected:
        for detection_type, detected_value in response_detected.items():
            response_detections_table.append(
                {"Detection Type": detection_type.replace("_", " ").title(), "Detected": "Yes" if detected_value else "No"}
            )

    # Build scanned content table
    content_table = [
        {
            "Type": "Prompt",
            "Content": prompt[:100] + "..." if len(prompt) > 100 else prompt,
            "Threats Detected": "Yes" if prompt_has_detections else "No",
        }
    ]
    if response_text:
        content_table.append(
            {
                "Type": "Response",
                "Content": response_text[:100] + "..." if len(response_text) > 100 else response_text,
                "Threats Detected": "Yes" if response_has_detections else "No",
            }
        )

    # Build readable output
    readable_output = "## Prisma AIRs Runtime Scan Results\n\n"
    readable_output += tableToMarkdown(
        "Scan Summary", scan_summary, headers=["Scan ID", "Report ID", "Profile", "Action", "Category", "Detected"]
    )
    readable_output += "\n"

    # Add metadata table if present
    if metadata_table:
        readable_output += tableToMarkdown("Metadata", metadata_table, headers=["Field", "Value"])
        readable_output += "\n"

    # Scanned content first to show what was scanned
    readable_output += tableToMarkdown("Scanned Content", content_table, headers=["Type", "Content", "Threats Detected"])
    readable_output += "\n"

    # Prompt detections (if any)
    if prompt_detections_table:
        readable_output += tableToMarkdown("Prompt Detections", prompt_detections_table, headers=["Detection Type", "Detected"])
        readable_output += "\n"

    # Response detections (if any)
    if response_detections_table:
        readable_output += tableToMarkdown(
            "Response Detections", response_detections_table, headers=["Detection Type", "Detected"]
        )
        readable_output += "\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RuntimeScan",
        outputs_key_field="scan_id",
        outputs=scan_result,
        readable_output=readable_output,
        raw_response=scan_response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
            "revoked": key.get("revoked"),
        }
        api_keys.append(api_key_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Runtime API Keys",
        api_keys,
        headers=["id", "name", "last8", "created_at", "expires_at", "revoked"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKey",
        outputs_key_field="id",
        outputs=api_keys,
        readable_output=readable_output,
        raw_response=response,
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
    # cust_env and cust_cloud_provider are optional in the APIKeyCreationObject schema, but the
    # customer app record created as a side effect REQUIRES environment and cloud_provider. Omitting
    # them yields an opaque HTTP 400 "Error inserting/updating customer app record", so require them here.
    cust_env = args.get("cust_env")
    cust_cloud_provider = args.get("cust_cloud_provider")

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
    if not cust_env:
        raise ValueError("cust_env is required (the customer app record mandates an environment value)")
    if not cust_cloud_provider:
        raise ValueError("cust_cloud_provider is required (the customer app record mandates a cloud provider value)")

    # Validate rotation_time_unit
    valid_units = ["hours", "days", "months"]
    if rotation_time_unit not in valid_units:
        raise ValueError(f"rotation_time_unit must be one of: {', '.join(valid_units)}")

    # Build request body according to ApiKeyCreateRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/mgmt-api-key.ts
    # Required by API schema: auth_code, cust_app, revoked, created_by, api_key_name,
    #           rotation_time_interval, rotation_time_unit
    # Required in practice (customer app record mandates them): cust_env, cust_cloud_provider
    # Optional: dp_name, cust_ai_agent_framework
    request_body = {
        "api_key_name": api_key_name,
        "auth_code": auth_code,
        "cust_app": cust_app,
        "created_by": created_by,
        "revoked": False,  # Always create as not revoked
        "rotation_time_interval": rotation_time_interval,
        "rotation_time_unit": rotation_time_unit,
        "cust_env": cust_env,
        "cust_cloud_provider": cust_cloud_provider,
    }

    # Add optional fields if provided
    optional_fields = {
        "dp_name": args.get("dp_name"),
        "cust_ai_agent_framework": args.get("cust_ai_agent_framework"),
    }
    for field, value in optional_fields.items():
        if value:
            request_body[field] = value

    # Call Management API to create API key
    # SDK: ./knowledge/prisma-airs-sdk-main/src/management/api-keys.ts (create method)
    # Endpoint: POST /v1/mgmt/apikey (singular; matches OpenAPI operationId CreateNewAPIKey and SDK MGMT_API_KEY_PATH)
    # Response: ApiKeySchema with full secret (only time it's shown)
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikey"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "cust_app": response.get("cust_app"),
    }

    # Add optional fields if present
    optional_response_fields = [
        "updated_at",
        "updated_by",
        "cust_env",
        "cust_cloud_provider",
        "cust_ai_agent_framework",
        "dp_name",
    ]
    for field in optional_response_fields:
        if response.get(field):
            api_key_info[field] = response.get(field)

    # Create readable output with WARNING about secret
    readable_output = tableToMarkdown(
        "API Key Created",
        api_key_info,
        headers=["id", "name", "api_key", "last8", "expires_at", "created_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += (
        "\n\n**⚠️ IMPORTANT:** This is the ONLY time the full API key secret will be shown. "
        "Save it securely now. Future API calls will only show the last 8 characters."
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKeyCreate",
        outputs_key_field="id",
        outputs=api_key_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"rotation_time_interval": rotation_time_interval, "rotation_time_unit": rotation_time_unit}

    # Add optional updated_by if provided
    updated_by = args.get("updated_by")
    if updated_by:
        request_body["updated_by"] = updated_by

    # Call Management API to regenerate API key
    # SDK: ./knowledge/prisma-airs-sdk-main/src/management/api-keys.ts (regenerate method)
    # Endpoint: POST /v1/mgmt/apikey/regenerate/{apiKeyId} (singular path + POST; matches OpenAPI RegenerateAPIKeyById and SDK)
    # Response: ApiKeySchema with NEW UUID and NEW full secret
    url_suffix = f"{MGMT_API_V1_PREFIX}/apikey/regenerate/{api_key_id}"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "cust_app": response.get("cust_app"),
    }

    # Add optional fields if present
    optional_response_fields = [
        "created_at",
        "created_by",
        "cust_env",
        "cust_cloud_provider",
        "cust_ai_agent_framework",
        "dp_name",
    ]
    for field in optional_response_fields:
        if response.get(field):
            api_key_info[field] = response.get(field)

    # Create readable output with WARNING about new secret and old key invalidation
    readable_output = tableToMarkdown(
        "API Key Regenerated",
        api_key_info,
        headers=["id", "name", "api_key", "last8", "expires_at", "updated_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += (
        "\n\n**⚠️ IMPORTANT:**\n\n"
        "1. The OLD API key has been INVALIDATED and will no longer work\n"
        "2. This is the ONLY time the NEW full API key secret will be shown\n"
        "3. Update all applications using the old key with this new key\n"
        "4. The API key ID has changed - use the new ID for future operations"
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKeyRegenerate",
        outputs_key_field="id",
        outputs=api_key_info,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"updated_by": updated_by}

    response = client.http_request(method="DELETE", url_suffix=url_suffix, params=params, use_mgmt_base=True)

    # Parse response - SDK handles both string and object responses
    # ApiKeyDeleteResponseSchema transforms plain string to { message: "..." }
    # Response: { message: "deleted" } or { message: "successfully deleted apiKeyName: <name>" }
    message = response.get("message", "API key deleted successfully") if isinstance(response, dict) else str(response)

    # Context output
    context_output = {"api_key_name": api_key_name, "deleted_by": updated_by, "message": message, "deleted": True}

    # Create readable output with deletion confirmation
    readable_output = tableToMarkdown(
        "API Key Deleted",
        context_output,
        headers=["api_key_name", "deleted_by", "message", "deleted"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += "\n\n**⚠️ WARNING:** This action cannot be undone. The API key has been permanently revoked."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ApiKeyDeleted",
        outputs_key_field="api_key_name",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
            "tsg_id": profile.get("tsg_id"),
        }
        profiles.append(profile_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Security Profiles",
        profiles,
        headers=["id", "name", "revision", "active", "created_by", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfile",
        outputs_key_field="id",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response,
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
        "limit": "1000",  # Get all profiles for filtering
    }

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
        "csp_id": profile.get("csp_id"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        f"Security Profile: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "revision", "active", "created_by", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add policy summary if present
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += "\n\n**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfileGet",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=profile,
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
    request_body: dict[str, Any] = {"profile_name": profile_name, "active": active}

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
        request_body["policy"] = {"ai-security-profiles": [], "dlp-data-profiles": []}

    # Call Management API to create profile
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # SDK: ProfilesClient.create(body)
    # Endpoint: POST /v1/mgmt/profile
    url_suffix = f"{MGMT_API_V1_PREFIX}/profile"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "csp_id": response.get("csp_id"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        "Security Profile Created",
        profile_info,
        headers=["id", "name", "revision", "active", "created_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add policy summary
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += "\n\n**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfileCreate",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body: dict[str, Any] = {"profile_name": profile_name}

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

    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "csp_id": response.get("csp_id"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        "Security Profile Updated",
        profile_info,
        headers=["id", "name", "revision", "active", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add policy summary
    if profile_info.get("policy"):
        policy = profile_info["policy"]
        ai_profiles_count = len(policy.get("ai-security-profiles", []))
        dlp_profiles_count = len(policy.get("dlp-data-profiles", []))
        readable_output += "\n\n**Policy:**\n\n"
        readable_output += f"- AI Security Profiles: {ai_profiles_count}\n"
        readable_output += f"- DLP Data Profiles: {dlp_profiles_count}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfileUpdate",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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

    force = argToBoolean(args.get("force", False))
    updated_by = args.get("updated_by")

    # Call Management API to delete profile
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/profiles.ts
    # Response: { message: "deleted" } (or plain string transformed to object)
    if force:
        # SDK: ProfilesClient.forceDelete(profileId, updatedBy)
        # Endpoint: DELETE /v1/mgmt/profile/{profileId}/force?updated_by=...
        # Force-delete bypasses safety checks; the force endpoint requires updated_by.
        if not updated_by:
            raise ValueError("updated_by is required when force is true")
        url_suffix = f"{MGMT_API_V1_PREFIX}/profile/{profile_id}/force"
        response = client.http_request(
            method="DELETE", url_suffix=url_suffix, params={"updated_by": updated_by}, use_mgmt_base=True
        )
    else:
        # SDK: ProfilesClient.delete(profileId)
        # Endpoint: DELETE /v1/mgmt/profile/{profileId}
        url_suffix = f"{MGMT_API_V1_PREFIX}/profile/{profile_id}"
        response = client.http_request(method="DELETE", url_suffix=url_suffix, use_mgmt_base=True)

    # Parse response - SDK handles both string and object responses
    # DeleteProfileResponseSchema transforms plain string to { message: "..." }
    default_message = "Security profile force-deleted successfully" if force else "Security profile deleted successfully"
    message = response.get("message", default_message) if isinstance(response, dict) else str(response)

    # Create readable output
    # Context output
    context_output = {"profile_id": profile_id, "message": message, "deleted": True, "force": force}

    readable_output = tableToMarkdown(
        "Security Profile Force-Deleted" if force else "Security Profile Deleted",
        context_output,
        headers=["profile_id", "message", "deleted", "force"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += "\n\n**⚠️ WARNING:** This action cannot be undone. The security profile has been permanently deleted."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}SecurityProfileDeleted",
        outputs_key_field="profile_id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
            "tsg_id": app.get("tsg_id"),
        }
        apps.append(app_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Customer Applications",
        apps,
        headers=["id", "name", "model_name", "cloud_provider", "environment", "ai_agent_framework"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerApp",
        outputs_key_field="id",
        outputs=apps,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"app_name": app_name}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

    # Parse response - SDK schema (mgmt-customer-app.ts): CustomerAppSchema
    # Fields: customer_appId, tsg_id, app_name, model_name, cloud_provider, environment,
    # status, created_by, updated_by, ai_agent_framework
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
        "updated_by": response.get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Customer Application: {app_name}",
        [app_info],
        headers=[
            "id",
            "name",
            "model_name",
            "cloud_provider",
            "environment",
            "ai_agent_framework",
            "status",
            "created_by",
            "updated_by",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppGet",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response,
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
    # SDK: CustomerAppSchema - tsg_id, app_name, model_name (optional), cloud_provider,
    # environment, ai_agent_framework (optional)
    request_body: dict[str, Any] = {
        "tsg_id": args.get("tsg_id", client.tsg_id),  # Default to client's TSG ID if not provided
        "app_name": args.get("app_name"),
        "cloud_provider": args.get("cloud_provider"),
        "environment": args.get("environment"),
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
    params = {"customer_app_id": customer_app_id}

    response = client.http_request(method="PUT", url_suffix=url_suffix, params=params, json_data=request_body, use_mgmt_base=True)

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
        "updated_by": response.get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Updated Customer Application: {app_info.get('name')}",
        [app_info],
        headers=["id", "name", "model_name", "cloud_provider", "environment", "ai_agent_framework", "status", "updated_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppUpdate",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response,
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
    # Endpoint: GET /v1/mgmt/dashboard/v2/apps/application?appid={appId}&appname={appName}
    # &time_interval={interval}&time_unit={unit}
    url_suffix = "/v1/mgmt/dashboard/v2/apps/application"
    params = {"appid": app_id, "appname": app_name, "time_interval": str(time_interval), "time_unit": time_unit}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
        "violations_total": violation_breakdown.get("total"),
    }

    # Format readable output using XSOAR best practice table format
    # Create multiple tables for different data sections
    readable_parts = []

    # Application Overview Table
    app_overview = [
        {
            "App ID": app_info.get("id"),
            "Name": app_info.get("name"),
            "Cloud": app_info.get("cloud"),
            "Source": app_info.get("source"),
            "Profiles": ", ".join(app_info.get("profiles") or []) if app_info.get("profiles") else "None",
            "Time Window": f"{time_interval} {time_unit}",
        }
    ]
    readable_parts.append(
        tableToMarkdown(
            "Application Overview",
            app_overview,
            headers=["App ID", "Name", "Cloud", "Source", "Profiles", "Time Window"],
            removeNull=True,
        )
    )

    # Token Consumption Table
    avg_tokens = app_info.get("average_daily_tokens")
    avg_scale = app_info.get("average_daily_tokens_scale") or ""
    monthly_tokens = app_info.get("monthly_total_tokens")
    monthly_scale = app_info.get("monthly_total_tokens_scale") or ""

    token_consumption = [
        {"Metric": "Daily Average", "Value": f"{avg_tokens}{avg_scale}" if avg_tokens else "N/A"},
        {"Metric": "Monthly Total", "Value": f"{monthly_tokens}{monthly_scale}" if monthly_tokens else "N/A"},
    ]
    readable_parts.append(tableToMarkdown("Token Consumption", token_consumption, headers=["Metric", "Value"]))

    # Session Statistics Table
    session_stats_table = [
        {
            "Total Sessions": app_info.get("sessions_total") or 0,
            "Violating Sessions": app_info.get("sessions_violating") or 0,
            "Last Session ID": app_info.get("last_session_id") or "N/A",
            "Most Recent Session": app_info.get("most_recent_session_time") or "N/A",
        }
    ]
    readable_parts.append(
        tableToMarkdown(
            "Session Statistics",
            session_stats_table,
            headers=["Total Sessions", "Violating Sessions", "Last Session ID", "Most Recent Session"],
            removeNull=True,
        )
    )

    # Violation Severity Breakdown Table
    violations_table = [
        {
            "Critical": app_info.get("violations_critical") or 0,
            "High": app_info.get("violations_high") or 0,
            "Medium": app_info.get("violations_medium") or 0,
            "Low": app_info.get("violations_low") or 0,
            "Total": app_info.get("violations_total") or 0,
        }
    ]
    readable_parts.append(
        tableToMarkdown("Violation Severity Breakdown", violations_table, headers=["Critical", "High", "Medium", "Low", "Total"])
    )

    readable_output = "\n".join(readable_parts)

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppConsumption",
        outputs_key_field="id",
        outputs=app_info,
        readable_output=readable_output,
        raw_response=response,
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
    # Endpoint: GET /v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown
    # ?appid={appId}&appname={appName}&time_interval={interval}&time_unit={unit}
    url_suffix = "/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
    params = {"appid": app_id, "appname": app_name, "time_interval": str(time_interval), "time_unit": time_unit}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

    # Parse response - SDK schema (mgmt-dashboard.ts): DashboardApplicationViolationBreakdownSchema
    # Fields: detection_type_violation_breakdown[], total_violating
    # Known detection types: agent_security, contextual_grounding, dbs, dlp, malicious_code,
    # pi, source_code, tc, topic_guardrails, uf
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
            "total": violation_breakdown.get("total", 0),
        }
        detectors.append(detector_info)

    # Sort by total violations (descending) for better readability
    detectors.sort(key=lambda x: x.get("total", 0), reverse=True)

    readable_output = tableToMarkdown(
        f"Violation Breakdown by Detector (Total Violating: {total_violating})",
        detectors,
        headers=["detection_type", "critical", "high", "medium", "low", "total"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Create structured output
    output = {
        "app_id": app_id,
        "app_name": app_name,
        "total_violating": total_violating,
        "detectors": detectors,
        "time_interval": time_interval,
        "time_unit": time_unit,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppViolations",
        outputs_key_field="app_id",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"app_name": app_name, "updated_by": updated_by}

    response = client.http_request(method="DELETE", url_suffix=url_suffix, params=params, use_mgmt_base=True)

    # Parse response - SDK handles both string and object responses
    # CustomerAppDeleteResponseSchema transforms plain string to { message: "..." }
    message = (
        response.get("message", "Customer app and associated keys deleted successfully")
        if isinstance(response, dict)
        else str(response)
    )

    # Context output
    context_output = {"app_name": app_name, "deleted_by": updated_by, "message": message, "deleted": True}

    # Create readable output with deletion confirmation
    readable_output = tableToMarkdown(
        "Customer Application Deleted",
        context_output,
        headers=["app_name", "deleted_by", "message", "deleted"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += (
        "\n\n**⚠️ WARNING:** This action cannot be undone. The customer application and all "
        "associated API keys have been permanently deleted and revoked."
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}CustomerAppDeleted",
        outputs_key_field="app_name",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}
    if unactivated:
        params["unactivated"] = "true"

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
            "ave_text_records": profile.get("ave_text_records"),
        }
        profiles.append(profile_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Deployment Profiles",
        profiles,
        headers=["name", "auth_code", "status", "expiration_date", "ave_text_records"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DeploymentProfile",
        outputs_key_field="name",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response,
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
    params: dict[str, Any] = {"page": page, "size": size}

    # Call DLP v2 API to list data profiles
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # CRITICAL: Uses DLP v2 API base URL (https://api.dlp.paloaltonetworks.com)
    response = client.http_request(method="GET", url_suffix=DLP_DATA_PROFILES_PATH, params=params, use_dlp_base=True)

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
            "updated_by": profile.get("audit_metadata", {}).get("updated_by"),
        }
        profiles.append(profile_info)

    total_elements = response.get("page", {}).get("total_elements", len(profiles))
    total_pages = response.get("page", {}).get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profiles (Page {page + 1}/{total_pages}, {len(profiles)} of {total_elements})",
        profiles,
        headers=["id", "name", "type", "profile_status", "profile_type", "version"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfile",
        outputs_key_field="id",
        outputs=profiles,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}", use_dlp_base=True)

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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfileGet",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "detection_rules": detection_rules}

    # Optional: description
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Optional: is_granular_data_profile
    if args.get("is_granular_data_profile") is not None:
        request_body["is_granular_data_profile"] = argToBoolean(args.get("is_granular_data_profile"))

    # Call DLP data profiles create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
    # SDK: POST /v2/api/data-profiles
    response = client.http_request(method="POST", url_suffix=DLP_DATA_PROFILES_PATH, json_data=request_body, use_dlp_base=True)

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
        "created_by": response.get("audit_metadata", {}).get("created_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Created: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfileCreate",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "profile_type": profile_type}

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
                request_body["detection_rules"] = json.loads(rules_value or "")
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
        headers={"Content-Type": "application/merge-patch+json"},
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Patched: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfilePatch",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "detection_rules": detection_rules}

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
        method="PUT", url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}", json_data=request_body, use_dlp_base=True
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Data Profile Replaced: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "profile_status", "profile_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfileReplace",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
    )


def runtime_dlp_profiles_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Soft-delete a DLP data profile.

    The DLP Data Profiles API does not expose a DELETE endpoint. To remove a profile,
    it must be patched to a deleted lifecycle state (profile_status="deleted"). The
    JSON Merge Patch requires name + profile_type, so this command first fetches the
    profile to obtain those fields, then patches profile_status to "deleted".

    Reference: ./knowledge/versions/current/prisma-airs-sdk-main/src/management/dlp/data-profiles.ts
      "The DLP spec does not expose a DELETE for data profiles - to remove a profile,
       patch it to a deleted lifecycle state (typically profile_status: 'deleted')."

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    profile_id = args.get("profile_id")
    if not profile_id:
        raise ValueError("profile_id is required")

    # Step 1: Fetch the profile to obtain name + profile_type (required by the merge-patch).
    # SDK: GET /v2/api/data-profiles/{resourceId}
    profile = client.http_request(method="GET", url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}", use_dlp_base=True)

    name = profile.get("name")
    profile_type = profile.get("profile_type")
    if not name or not profile_type:
        raise ValueError(
            f"Cannot delete DLP data profile '{profile_id}': unable to resolve required fields "
            "(name, profile_type) from the existing profile."
        )

    # Step 2: Patch profile_status to "deleted" (soft-delete).
    # SDK: PATCH /v2/api/data-profiles/{resourceId} with Content-Type application/merge-patch+json
    request_body: dict[str, Any] = {"name": name, "profile_type": profile_type, "profile_status": "deleted"}
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{DLP_DATA_PROFILES_PATH}/{profile_id}",
        json_data=request_body,
        use_dlp_base=True,
        headers={"Content-Type": "application/merge-patch+json"},
    )

    # Action-tracking context (own key, consistent with other delete commands in this pack)
    context_output = {
        "id": profile_id,
        "name": name,
        "profile_status": (response or {}).get("profile_status", "deleted"),
        "deleted": True,
        "status": "Successfully soft-deleted",
    }

    readable_output = tableToMarkdown(
        "Prisma AIRs DLP Data Profile Deleted",
        [context_output],
        headers=["id", "name", "profile_status", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpProfileDelete",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    # Add TSG ID to URL suffix
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/topics-client.ts
    url_suffix = f"{MGMT_API_V1_PREFIX}/topics/tsg/{client.tsg_id}"

    # Call topics list endpoint
    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

    # Extract topics from response (forward-compatible: capture all fields)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/mgmt-topics.ts (TopicSchema)
    # API returns custom topics under "custom_topics"; fall back to "data" for compatibility.
    topics_data = response.get("custom_topics", response.get("data", []))
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
            "tsg_id": topic.get("tsg_id"),
        }
        topics.append(topic_info)

    readable_output = tableToMarkdown(
        f"Prisma AIRs Custom Topics ({len(topics)} of {response.get('total', len(topics))})",
        topics,
        headers=["topic_id", "topic_name", "revision", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}Topic",
        outputs_key_field="topic_id",
        outputs=topics,
        readable_output=readable_output,
        raw_response=response,
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
        "limit": "1000",  # Get all topics for filtering
    }

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_mgmt_base=True)

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
        "created_ts": topic.get("created_ts"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        f"Custom Topic: {topic_info.get('topic_name')}",
        topic_info,
        headers=["topic_id", "topic_name", "revision", "active", "description", "created_by", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"\n\n**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):  # Show first 5
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicGet",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=topic,
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
    request_body: dict[str, Any] = {"topic_name": topic_name, "description": description, "examples": examples, "active": active}

    # Call Management API to create topic
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # SDK: TopicsClient.create(body)
    # Endpoint: POST /v1/mgmt/topic
    url_suffix = f"{MGMT_API_V1_PREFIX}/topic"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "created_ts": response.get("created_ts"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        "Custom Topic Created",
        topic_info,
        headers=["topic_id", "topic_name", "revision", "active", "description", "created_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"\n\n**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicCreate",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body: dict[str, Any] = {"topic_name": topic_name}

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

    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_mgmt_base=True)

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
        "created_ts": response.get("created_ts"),
    }

    # Create readable output
    readable_output = tableToMarkdown(
        "Custom Topic Updated",
        topic_info,
        headers=["topic_id", "topic_name", "revision", "active", "description", "updated_by", "last_modified_ts"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add examples
    if topic_info.get("examples"):
        readable_output += f"\n\n**Examples ({len(topic_info['examples'])}):**\n\n"
        for i, example in enumerate(topic_info["examples"][:5], 1):
            readable_output += f"{i}. {example}\n"
        if len(topic_info["examples"]) > 5:
            readable_output += f"\n... and {len(topic_info['examples']) - 5} more\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicUpdate",
        outputs_key_field="topic_id",
        outputs=topic_info,
        readable_output=readable_output,
        raw_response=response,
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

    force = argToBoolean(args.get("force", False))
    updated_by = args.get("updated_by")

    # Call Management API to delete topic
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/management/topics.ts
    # Response: { message: "deleted" } (or plain string transformed to object)
    if force:
        # SDK: TopicsClient.forceDelete(topicId, updatedBy?)
        # Endpoint: DELETE /v1/mgmt/topic/force/{topicId}[?updated_by=...]
        # Force-delete removes the topic from any referencing profiles; updated_by is optional.
        url_suffix = f"{MGMT_API_V1_PREFIX}/topic/force/{topic_id}"
        params = {"updated_by": updated_by} if updated_by else None
        response = client.http_request(method="DELETE", url_suffix=url_suffix, params=params, use_mgmt_base=True)
    else:
        # SDK: TopicsClient.delete(topicId)
        # Endpoint: DELETE /v1/mgmt/topic/{topicId}
        # NOTE: Fails with 409 Conflict if topic is referenced by any profile
        url_suffix = f"{MGMT_API_V1_PREFIX}/topic/{topic_id}"
        response = client.http_request(method="DELETE", url_suffix=url_suffix, use_mgmt_base=True)

    # Parse response - SDK handles both string and object responses
    # DeleteTopicResponseSchema transforms plain string to { message: "..." }
    default_message = "Custom topic force-deleted successfully" if force else "Custom topic deleted successfully"
    message = response.get("message", default_message) if isinstance(response, dict) else str(response)

    # Create readable output
    # Context output
    context_output = {"topic_id": topic_id, "message": message, "deleted": True, "force": force}

    readable_output = tableToMarkdown(
        "Custom Topic Force-Deleted" if force else "Custom Topic Deleted",
        context_output,
        headers=["topic_id", "message", "deleted", "force"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += "\n\n**⚠️ WARNING:** This action cannot be undone. The custom topic has been permanently deleted."

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicDeleted",
        outputs_key_field="topic_id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
        method="GET", url_suffix=url_suffix, params={"offset": 0, "limit": 100}, use_mgmt_base=True
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
    profiles_url_suffix = f"{MGMT_API_V1_PREFIX}/profiles/tsg/{client.tsg_id}"
    profiles_response = client.http_request(
        method="GET", url_suffix=profiles_url_suffix, params={"offset": 0, "limit": 100}, use_mgmt_base=True
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
        topic_guardrails = {"action": guardrail_action, "name": "topic-guardrails", "options": [], "topic-list": []}
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
    action_group["topic"].append({"topic_id": topic_id, "topic_name": topic_name, "revision": topic_revision})

    topic_guardrails["topic-list"] = topic_list

    # Step 4: Update profile with modified policy
    # Reference: ./knowledge/versions/current/prisma-airs-cli/src/airs/management.ts (lines 169-173)
    # SDK: ManagementClient.profiles.update(profileId, body)
    # Endpoint: PUT /v1/mgmt/profile/uuid/{profileId}
    update_url_suffix = f"{MGMT_API_V1_PREFIX}/profile/uuid/{profile_id}"
    update_body = {"profile_name": profile_name, "active": profile.get("active", True), "policy": policy}

    update_response = client.http_request(method="PUT", url_suffix=update_url_suffix, json_data=update_body, use_mgmt_base=True)

    # Create readable output
    # Context output. Applying a topic versions the profile, so the resulting profile_id from the
    # PUT response is the revision the topic is actually bound to (fall back to the source id).
    context_output = {
        "profile_name": profile_name,
        "profile_id": update_response.get("profile_id", profile_id),
        "topic_name": topic_name,
        "topic_id": topic_id,
        "topic_revision": topic_revision,
        "action": action,
        "guardrail_action": guardrail_action,
        "applied": True,
    }

    readable_output = tableToMarkdown(
        "Topic Applied to Profile",
        context_output,
        headers=[
            "profile_name",
            "profile_id",
            "topic_name",
            "topic_id",
            "topic_revision",
            "action",
            "guardrail_action",
            "applied",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += (
        "\n\n**Note:** Topic has been added to the profile (existing topics preserved). "
        "The topic's current revision was pinned to ensure consistent detection behavior."
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}TopicApplied",
        outputs_key_field="profile_name",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=update_response,
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
        batch = prompts[i : i + batch_size]

        for prompt in batch:
            # Use scanner_request for each prompt
            content = {"prompt": prompt}
            scan_request = {"ai_profile": {"profile_name": profile_name}, "contents": [content]}
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
                    "detected": any(scan_response.get("prompt_detected", {}).values())
                    if scan_response.get("prompt_detected")
                    else False,
                }
                scan_results.append(scan_result)
            except Exception as e:
                demisto.error(f"Failed to scan prompt: {str(e)}")
                scan_results.append(
                    {
                        "prompt": prompt,
                        "scan_id": None,
                        "action": "error",
                        "category": "error",
                        "detected": False,
                        "error": str(e),
                    }
                )

    # Calculate summary stats
    total = len(scan_results)
    blocked = sum(1 for r in scan_results if r.get("action") == "block")
    allowed = sum(1 for r in scan_results if r.get("action") == "allow")
    errors = sum(1 for r in scan_results if r.get("action") == "error")

    # Create summary table
    summary = [{"Total Prompts": total, "Blocked": blocked, "Allowed": allowed, "Errors": errors}]

    readable_output = "## Prisma AIRs Bulk Scan Results\n\n"
    readable_output += f"**Profile:** {profile_name}\n"
    if session_id:
        readable_output += f"**Session ID:** {session_id}\n"
    readable_output += "\n"
    readable_output += tableToMarkdown("Summary", summary, headers=["Total Prompts", "Blocked", "Allowed", "Errors"])
    readable_output += "\n"
    readable_output += tableToMarkdown(
        "Scan Results (first 50)",
        scan_results[:50],
        headers=["prompt", "action", "category", "detected"],
        headerTransform=lambda h: h.replace("_", " ").title(),
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
            "results": scan_results,
        },
        readable_output=readable_output,
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
    params: dict[str, Any] = {"page": page, "size": size}
    if include_keywords:
        params["keywords"] = "true"

    # Call DLP dictionaries list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(method="GET", url_suffix=DLP_DICTIONARIES_PATH, params=params, use_dlp_base=True)

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
            "updated_by": dictionary.get("audit_metadata", {}).get("updated_by"),
        }
        dictionaries.append(dict_info)

    total_elements = response.get("total_elements", len(dictionaries))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionaries (Page {page + 1}/{total_pages}, {len(dictionaries)} of {total_elements})",
        dictionaries,
        headers=["id", "name", "category", "type", "number_of_keywords", "region_name"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionary",
        outputs_key_field="id",
        outputs=dictionaries,
        readable_output=readable_output,
        raw_response=response,
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
        method="GET", url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}", params=params, use_dlp_base=True
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "is_case_sensitive", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionaryGet",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response,
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
    metadata: dict[str, Any] = {"category": category, "name": name, "original_file_name": file_name, "region_name": region_name}

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
        "json": ("metadata.json", json.dumps(metadata).encode("utf-8"), "application/json"),
        "file": (file_name, file_content, "text/plain"),
    }

    # Call DLP dictionaries create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: POST /v2/api/dictionaries (multipart/form-data)
    response = client.http_request(method="POST", url_suffix=DLP_DICTIONARIES_PATH, params=params, files=files, use_dlp_base=True)

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
        "created_by": response.get("audit_metadata", {}).get("created_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary Created: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionaryCreate",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"category": category, "name": name, "original_file_name": original_file_name}

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
        headers={"Content-Type": "application/merge-patch+json"},
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Dictionary Patched: {dict_info.get('name')}",
        dict_info,
        headers=["id", "name", "category", "type", "region_name", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionaryPatch",
        outputs_key_field="id",
        outputs=dict_info,
        readable_output=readable_output,
        raw_response=response,
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
    metadata: dict[str, Any] = {"category": category, "name": name, "original_file_name": file_name, "region_name": region_name}

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
        "json": ("metadata.json", json.dumps(metadata).encode("utf-8"), "application/json"),
        "file": (file_name, file_content, "text/plain"),
    }

    # Call DLP dictionaries replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/dictionaries.ts
    # SDK: PUT /v2/api/dictionaries/{resourceId} (multipart/form-data)
    # API may return 200 with body or 204 with no body
    response = client.http_request(
        method="PUT", url_suffix=f"{DLP_DICTIONARIES_PATH}/{dictionary_id}", params=params, files=files, use_dlp_base=True
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
            "updated_by": response.get("audit_metadata", {}).get("updated_by"),
        }

        readable_output = tableToMarkdown(
            f"Prisma AIRs DLP Dictionary Replaced: {dict_info.get('name')}",
            dict_info,
            headers=["id", "name", "category", "type", "region_name", "description"],
            headerTransform=lambda h: h.replace("_", " ").title(),
        )

        return CommandResults(
            outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionaryReplace",
            outputs_key_field="id",
            outputs=dict_info,
            readable_output=readable_output,
            raw_response=response,
        )
    else:
        # 204 No Content response
        readable_output = (
            f"## Prisma AIRs DLP Dictionary Replaced\n\n"
            f"Dictionary ID `{dictionary_id}` has been successfully replaced (204 No Content)."
        )
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
        return_empty_response=True,  # Proper XSOAR pattern for DELETE operations (204 No Content)
    )

    # Action-tracking context so playbooks can confirm the deletion
    context_output = {"id": dictionary_id, "deleted": True, "status": "Successfully deleted"}

    readable_output = tableToMarkdown(
        "Prisma AIRs DLP Dictionary Deleted",
        context_output,
        headers=["id", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpDictionaryDelete",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
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
    params: dict[str, Any] = {"page": page, "size": size}

    # Call DLP patterns list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(method="GET", url_suffix=DLP_PATTERNS_PATH, params=params, use_dlp_base=True)

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
            "updated_by": pattern.get("audit_metadata", {}).get("updated_by"),
        }
        patterns.append(pattern_info)

    total_elements = response.get("total_elements", len(patterns))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Patterns (Page {page + 1}/{total_pages}, {len(patterns)} of {total_elements})",
        patterns,
        headers=["id", "name", "category", "type", "detection_technique", "pattern_status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPattern",
        outputs_key_field="id",
        outputs=patterns,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}", use_dlp_base=True)

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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "license_type", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPatternGet",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "type": pattern_type, "detection_config": {"technique": detection_technique}}

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
            matching_rules = json.loads(matching_rules_str or "")
            request_body["matching_rules"] = matching_rules
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"matching_rules must be valid JSON: {e}")

    # Optional: tags (classification, compliance, geography arrays)
    if args.get("tags"):
        tags_str = args.get("tags")
        try:
            tags = json.loads(tags_str or "")
            request_body["tags"] = tags
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"tags must be valid JSON: {e}")

    # Call DLP patterns create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: POST /v2/api/data-patterns
    response = client.http_request(method="POST", url_suffix=DLP_PATTERNS_PATH, json_data=request_body, use_dlp_base=True)

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
        "created_by": response.get("audit_metadata", {}).get("created_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Created: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPatternCreate",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "type": pattern_type, "detection_config": {"technique": detection_technique}}

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
                request_body["matching_rules"] = json.loads(matching_rules_str or "")
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"matching_rules must be valid JSON or 'null': {e}")

    # Optional: tags (can be null to clear)
    if args.get("tags") is not None:
        tags_str = args.get("tags")
        if tags_str == "null":
            request_body["tags"] = None
        else:
            try:
                request_body["tags"] = json.loads(tags_str or "")
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
        headers={"Content-Type": "application/merge-patch+json"},
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Patched: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPatternPatch",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response,
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

    request_body: dict[str, Any] = {"name": name, "type": pattern_type, "detection_config": {"technique": detection_technique}}

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
            request_body["matching_rules"] = json.loads(matching_rules_str or "")
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"matching_rules must be valid JSON: {e}")

    # Optional: tags
    if args.get("tags"):
        tags_str = args.get("tags")
        try:
            request_body["tags"] = json.loads(tags_str or "")
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"tags must be valid JSON: {e}")

    # Call DLP patterns replace endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-patterns.ts
    # SDK: PUT /v2/api/data-patterns/{resourceId}
    response = client.http_request(
        method="PUT", url_suffix=f"{DLP_PATTERNS_PATH}/{pattern_id}", json_data=request_body, use_dlp_base=True
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Pattern Replaced: {pattern_info.get('name')}",
        pattern_info,
        headers=["id", "name", "type", "status", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPatternReplace",
        outputs_key_field="id",
        outputs=pattern_info,
        readable_output=readable_output,
        raw_response=response,
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
        return_empty_response=True,  # Proper XSOAR pattern for DELETE operations (204 No Content)
    )

    # Action-tracking context so playbooks can confirm the deletion (soft-delete / archive)
    context_output = {"id": pattern_id, "deleted": True, "status": "Successfully archived"}

    readable_output = tableToMarkdown(
        "Prisma AIRs DLP Pattern Deleted",
        context_output,
        headers=["id", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpPatternDelete",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
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
    params: dict[str, Any] = {"page": page, "size": size}

    # Call DLP filtering profiles list endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/management/dlp/data-filtering-profiles.ts
    # CRITICAL: DLP v2 API uses https://api.dlp.paloaltonetworks.com (separate from SCM)
    response = client.http_request(method="GET", url_suffix=DLP_FILTERING_PROFILES_PATH, params=params, use_dlp_base=True)

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
            "updated_by": profile.get("audit_metadata", {}).get("updated_by"),
        }
        filtering_profiles.append(profile_info)

    total_elements = response.get("total_elements", len(filtering_profiles))
    total_pages = response.get("total_pages", 1)

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profiles (Page {page + 1}/{total_pages}, {len(filtering_profiles)} of {total_elements})",
        filtering_profiles,
        headers=["id", "name", "type", "default_action", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfile",
        outputs_key_field="id",
        outputs=filtering_profiles,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{DLP_FILTERING_PROFILES_PATH}/{profile_id}", use_dlp_base=True)

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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profile: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "direction", "file_based", "non_file_based", "log_severity", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfileGet",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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
        "non_file_based": argToBoolean(args.get("non_file_based", False)),
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
        method="PUT", url_suffix=f"{DLP_FILTERING_PROFILES_PATH}/{profile_id}", json_data=request_body, use_dlp_base=True
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
        "updated_by": response.get("audit_metadata", {}).get("updated_by"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs DLP Filtering Profile Updated: {profile_info.get('name')}",
        profile_info,
        headers=["id", "name", "type", "direction", "file_based", "non_file_based", "log_severity", "description"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}DlpFilteringProfileReplace",
        outputs_key_field="id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
    )


def main() -> None:
    """Main function for Prisma AIRs AI Runtime Security integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
        # Client configuration (scoped credentials for the Runtime Security + DLP planes)
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
            headers=headers,
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

        elif command == "prisma-airs-runtime-dlp-profiles-delete":
            return_results(runtime_dlp_profiles_delete_command(client, args))

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

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
