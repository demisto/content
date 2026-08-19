import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from PrismaAirsApiModule import *  # noqa # pylint: disable=unused-wildcard-import

import base64
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS (Red Team specific; shared constants and plane path prefixes come from PrismaAirsApiModule)
# Red Team API endpoint suffixes (appended after RED_TEAM_DATA_PATH / RED_TEAM_MGMT_PATH from PrismaAirsApiModule)
# Reference: ./knowledge/prisma-airs-sdk-main/src/constants.ts
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
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_INSTANCES_PATH)
RED_TEAM_INSTANCES_ENDPOINT = "/v1/instances"
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_ADAPTER_PATH)
RED_TEAM_ADAPTERS_ENDPOINT = "/v1/adapters"
RED_TEAM_ADAPTERS_VALIDATE_ENDPOINT = "/v1/adapters/validate"
RED_TEAM_TEMPLATE_ENDPOINT = "/v1/template"
# Supported languages endpoint - identical path served on both the data plane and the mgmt plane.
# Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_LANGUAGES_PATH)
RED_TEAM_LANGUAGES_ENDPOINT = "/v1/languages"
# Network broker channels live on a distinct data-plane sub-path (/network-broker), used with use_redteam_data=True.
# Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_CHANNELS_PATH + network-broker base URL)
RED_TEAM_NETWORK_CHANNELS_ENDPOINT = "/network-broker/v1/channels"
# Sentiment (up/down-vote a scan report) - data-plane.
# Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_SENTIMENT_PATH)
RED_TEAM_SENTIMENT_ENDPOINT = "/v1/sentiment"
# Target-profile error logs (profiling failures for a target) - data-plane.
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_ERROR_LOG_TARGET_PROFILE_PATH)
RED_TEAM_ERROR_LOG_TARGET_PROFILE_ENDPOINT = "/v1/error-log/target-profile"
# Job-level error logs (per-scan-job probe failures) - data-plane.
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_ERROR_LOG_PATH)
RED_TEAM_ERROR_LOG_JOB_ENDPOINT = "/v1/error-log/job"
# Dashboard telemetry - scan-statistics + score-trend are data-plane; overview is mgmt-plane.
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_DASHBOARD_PATH / RED_TEAM_MGMT_DASHBOARD_PATH)
RED_TEAM_DASHBOARD_ENDPOINT = "/v1/dashboard"
# Metering quota summary (static/dynamic/custom allocations) - data-plane, POST with no body.
# Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/constants.ts (RED_TEAM_QUOTA_PATH)
RED_TEAM_QUOTA_ENDPOINT = "/v1/metering/quota"


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
    response = client.http_request(method="GET", url_suffix=RED_TEAM_TARGETS_ENDPOINT, params=params, use_redteam_mgmt=True)

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
            "updated_by_user_id": target.get("updated_by_user_id"),
        }
        targets.append(target_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Targets",
        targets,
        headers=["uuid", "name", "target_type", "status", "active", "validated", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTarget",
        outputs_key_field="uuid",
        outputs=targets,
        readable_output=readable_output,
        raw_response=response,
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
    request_body: dict[str, Any] = {"name": name}

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

        request_body["connection_params"] = json.loads(args.get("connection_params", ""))

    # Optional validation parameter
    validate = argToBoolean(args.get("validate", False))
    params = {"validate": str(validate).lower()} if validate is not None else None

    # Call Red Team target create endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (create method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_TARGETS_ENDPOINT, json_data=request_body, params=params, use_redteam_mgmt=True
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
        "created_by_user_id": response.get("created_by_user_id"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Target Created: {name}",
        [target_info],
        headers=["uuid", "name", "target_type", "status", "active", "validated"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetCreate",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}", use_redteam_mgmt=True)

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
        "profiling_status": response.get("profiling_status"),
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
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetGet",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response,
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

        request_body["connection_params"] = json.loads(args.get("connection_params", ""))

    # If no fields provided, error
    if not request_body:
        raise ValueError("At least one field must be provided for update (name, description, target_type, etc.)")

    # If name not provided but other fields are, we need to preserve the existing name
    # by fetching the current target first
    if "name" not in request_body:
        current_target = client.http_request(
            method="GET", url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}", use_redteam_mgmt=True
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
        use_redteam_mgmt=True,
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
        "updated_by_user_id": response.get("updated_by_user_id"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Target Updated: {target_info.get('name', uuid)}",
        [target_info],
        headers=["uuid", "name", "target_type", "status", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetUpdate",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="DELETE", url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/{uuid}", use_redteam_mgmt=True)

    # Parse response according to BaseResponseSchema (optional - may be empty)
    # Fields: message, status
    delete_info = {
        "uuid": uuid,
        "message": response.get("message", "Target deleted successfully"),
        "status": response.get("status", 200),
    }

    readable_output = tableToMarkdown(
        "Red Team Target Deleted",
        delete_info,
        headers=["uuid", "status", "message"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetDelete",
        outputs_key_field="uuid",
        outputs=delete_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_instances_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Required fields per InstanceRequestSchema
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (InstanceRequestSchema)
    tsg_id = args.get("tsg_id")
    tenant_id = args.get("tenant_id")
    app_id = args.get("app_id")
    region = args.get("region")
    if not tsg_id:
        raise ValueError("tsg_id is required")
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not app_id:
        raise ValueError("app_id is required")
    if not region:
        raise ValueError("region is required")

    request_body: dict[str, Any] = {
        "tsg_id": tsg_id,
        "tenant_id": tenant_id,
        "app_id": app_id,
        "region": region,
    }

    # Optional fields
    if args.get("support_account_id"):
        request_body["support_account_id"] = args.get("support_account_id")
    if args.get("support_account_name"):
        request_body["support_account_name"] = args.get("support_account_name")
    if args.get("created_by"):
        request_body["created_by"] = args.get("created_by")
    if args.get("internal") is not None:
        request_body["internal"] = argToBoolean(args.get("internal"))
    if args.get("tenant_instance_name"):
        request_body["tenant_instance_name"] = args.get("tenant_instance_name")
    if args.get("iam_controlled") is not None:
        request_body["iam_controlled"] = argToBoolean(args.get("iam_controlled"))
    if args.get("platform_region"):
        request_body["platform_region"] = args.get("platform_region")
    if args.get("csp_tenant_id"):
        request_body["csp_tenant_id"] = args.get("csp_tenant_id")
    if args.get("extra"):
        request_body["extra"] = json.loads(args.get("extra", ""))

    # Call Red Team instance create endpoint (management plane)
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (createInstance)
    # SDK schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (InstanceResponseSchema)
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_INSTANCES_ENDPOINT, json_data=request_body, use_redteam_mgmt=True
    )

    instance_info = {
        "tsg_id": response.get("tsg_id"),
        "tenant_id": response.get("tenant_id", tenant_id),
        "app_id": response.get("app_id"),
        "is_success": response.get("is_success"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Instance Created: {tenant_id}",
        [instance_info],
        headers=["tenant_id", "tsg_id", "app_id", "is_success"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamInstanceCreate",
        outputs_key_field="tenant_id",
        outputs=instance_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_instances_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a Red Team tenant instance by tenant ID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    # Call Red Team instance get endpoint (management plane)
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (getInstance)
    # SDK schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (InstanceGetResponseSchema)
    response = client.http_request(
        method="GET", url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}", use_redteam_mgmt=True
    )

    instance_info = {
        "tsg_id": response.get("tsg_id"),
        "tenant_id": response.get("tenant_id"),
        "app_id": response.get("app_id"),
        "region": response.get("region"),
        "support_account_id": response.get("support_account_id"),
        "support_account_name": response.get("support_account_name"),
        "created_by": response.get("created_by"),
        "internal": response.get("internal"),
        "tenant_instance_name": response.get("tenant_instance_name"),
    }

    # Include nested deployment profiles if present
    deployment_profiles = response.get("deployment_profiles")
    if deployment_profiles:
        instance_info["deployment_profiles"] = deployment_profiles

    readable_output = tableToMarkdown(
        f"Red Team Instance: {instance_info.get('tenant_instance_name') or tenant_id}",
        [instance_info],
        headers=["tenant_id", "tsg_id", "app_id", "region", "tenant_instance_name", "created_by"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamInstanceGet",
        outputs_key_field="tenant_id",
        outputs=instance_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_instances_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an existing Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    # InstanceRequestSchema requires tsg_id/tenant_id/app_id/region, so fetch the current
    # instance to preserve any required fields the caller does not override.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (updateInstance)
    current = client.http_request(
        method="GET", url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}", use_redteam_mgmt=True
    )

    request_body: dict[str, Any] = {
        "tsg_id": args.get("tsg_id") or current.get("tsg_id"),
        "tenant_id": tenant_id,
        "app_id": args.get("app_id") or current.get("app_id"),
        "region": args.get("region") or current.get("region"),
    }

    # Preserve existing optional fields returned by GET unless overridden below
    for field in ("support_account_id", "support_account_name", "created_by", "internal", "tenant_instance_name"):
        if current.get(field) is not None:
            request_body[field] = current.get(field)

    # Optional overrides
    if args.get("support_account_id"):
        request_body["support_account_id"] = args.get("support_account_id")
    if args.get("support_account_name"):
        request_body["support_account_name"] = args.get("support_account_name")
    if args.get("created_by"):
        request_body["created_by"] = args.get("created_by")
    if args.get("internal") is not None:
        request_body["internal"] = argToBoolean(args.get("internal"))
    if args.get("tenant_instance_name"):
        request_body["tenant_instance_name"] = args.get("tenant_instance_name")
    if args.get("iam_controlled") is not None:
        request_body["iam_controlled"] = argToBoolean(args.get("iam_controlled"))
    if args.get("platform_region"):
        request_body["platform_region"] = args.get("platform_region")
    if args.get("csp_tenant_id"):
        request_body["csp_tenant_id"] = args.get("csp_tenant_id")
    if args.get("extra"):
        request_body["extra"] = json.loads(args.get("extra", ""))

    # Call Red Team instance update endpoint (management plane)
    # SDK schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (InstanceResponseSchema)
    response = client.http_request(
        method="PUT", url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}", json_data=request_body, use_redteam_mgmt=True
    )

    instance_info = {
        "tsg_id": response.get("tsg_id"),
        "tenant_id": response.get("tenant_id", tenant_id),
        "app_id": response.get("app_id"),
        "is_success": response.get("is_success"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Instance Updated: {tenant_id}",
        [instance_info],
        headers=["tenant_id", "tsg_id", "app_id", "is_success"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamInstanceUpdate",
        outputs_key_field="tenant_id",
        outputs=instance_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_instances_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    # Call Red Team instance delete endpoint (management plane)
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (deleteInstance)
    # SDK schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (InstanceResponseSchema)
    response = client.http_request(
        method="DELETE", url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}", use_redteam_mgmt=True
    )

    delete_info = {
        "tenant_id": response.get("tenant_id", tenant_id),
        "tsg_id": response.get("tsg_id"),
        "app_id": response.get("app_id"),
        "is_success": response.get("is_success", True),
    }

    readable_output = tableToMarkdown(
        f"Red Team Instance Deleted: {tenant_id}",
        [delete_info],
        headers=["tenant_id", "tsg_id", "app_id", "is_success"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamInstanceDelete",
        outputs_key_field="tenant_id",
        outputs=delete_info,
        readable_output=readable_output,
        raw_response=response,
    )


def _resolve_device_instance(client: Client, tenant_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Build the required ``instance`` object for a device request.

    The device create/update body requires an ``instance`` block with all four of
    tsg_id/app_id/region/tenant_id. Callers may pass these explicitly; any that are
    omitted are resolved from the parent instance via a GET so the analyst only needs
    the tenant_id in the common case.

    Args:
        client: Prisma AIRs API client.
        tenant_id: The tenant ID of the parent instance.
        args: Command arguments from XSOAR.

    Returns:
        dict[str, Any]: The instance block (app_id, region, tenant_id, tsg_id).
    """
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (DeviceInstanceSchema)
    app_id = args.get("app_id")
    region = args.get("region")
    tsg_id = args.get("tsg_id")

    # Only fetch the parent instance when a required field is missing.
    if not (app_id and region and tsg_id):
        current = client.http_request(
            method="GET", url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}", use_redteam_mgmt=True
        )
        app_id = app_id or current.get("app_id")
        region = region or current.get("region")
        tsg_id = tsg_id or current.get("tsg_id")

    return {"app_id": app_id, "region": region, "tenant_id": tenant_id, "tsg_id": tsg_id}


def _build_device_list(args: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the ``devices`` array for a device create/update request.

    Supports either a single device (via ``serial_number`` plus optional attributes)
    or a batch of devices supplied as a JSON array string via ``devices``.

    Args:
        args: Command arguments from XSOAR.

    Returns:
        list[dict[str, Any]]: The devices list to send in the request body.
    """
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (DeviceSchema)
    devices_json = args.get("devices")
    if devices_json:
        devices = json.loads(devices_json)
        if not isinstance(devices, list):
            raise ValueError("devices must be a JSON array of device objects")
    else:
        serial_number = args.get("serial_number")
        if not serial_number:
            raise ValueError("Either serial_number or devices (JSON array) is required")
        device: dict[str, Any] = {"serial_number": serial_number}
        for field in ("device_name", "model", "sku", "device_type", "asset_type", "support_account_id"):
            if args.get(field):
                device[field] = args.get(field)
        devices = [device]

    # SDK caps batch operations at 5 items.
    if len(devices) > 5:
        raise ValueError("A maximum of 5 devices can be submitted per request")
    return devices


def _device_response_results(response: dict[str, Any], title: str, prefix: str) -> CommandResults:
    """Render a DeviceResponse into standard CommandResults.

    Args:
        response: The raw DeviceResponse from the API.
        title: The human-readable table title.
        prefix: The context output suffix (e.g. RedTeamDeviceCreate).

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    devices = response.get("devices") or []

    readable_output = tableToMarkdown(
        title,
        devices,
        headers=["serial_number", "status", "error"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}{prefix}",
        outputs_key_field="serial_number",
        outputs=devices,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_devices_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create one or more devices on a Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    request_body: dict[str, Any] = {
        "instance": _resolve_device_instance(client, tenant_id, args),
        "devices": _build_device_list(args),
    }
    if args.get("created_by"):
        request_body["created_by"] = args.get("created_by")

    # Call Red Team device create endpoint (management plane)
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (createDevices)
    response = client.http_request(
        method="POST",
        url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}/devices",
        json_data=request_body,
        use_redteam_mgmt=True,
    )

    return _device_response_results(response, f"Red Team Devices Created: {tenant_id}", "RedTeamDeviceCreate")


def redteam_devices_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update one or more devices on a Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    request_body: dict[str, Any] = {
        "instance": _resolve_device_instance(client, tenant_id, args),
        "devices": _build_device_list(args),
    }
    if args.get("created_by"):
        request_body["created_by"] = args.get("created_by")

    # Call Red Team device update endpoint (management plane)
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (updateDevices)
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}/devices",
        json_data=request_body,
        use_redteam_mgmt=True,
    )

    return _device_response_results(response, f"Red Team Devices Updated: {tenant_id}", "RedTeamDeviceUpdate")


def redteam_devices_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete one or more devices from a Red Team tenant instance.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    tenant_id = args.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    serial_numbers = argToList(args.get("serial_numbers"))
    if not serial_numbers:
        raise ValueError("serial_numbers is required")
    if len(serial_numbers) > 5:
        raise ValueError("A maximum of 5 devices can be deleted per request")

    # deleteDevices takes a comma-separated serial_numbers query param.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/instances-client.ts (deleteDevices)
    response = client.http_request(
        method="DELETE",
        url_suffix=f"{RED_TEAM_INSTANCES_ENDPOINT}/{tenant_id}/devices",
        params={"serial_numbers": ",".join(serial_numbers)},
        use_redteam_mgmt=True,
    )

    return _device_response_results(response, f"Red Team Devices Deleted: {tenant_id}", "RedTeamDeviceDelete")


def _parse_adapter(adapter: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single Red Team custom target adapter record for context output.

    Full records (get/create/update) carry every field; list rows are a subset. ``assign_params``
    drops absent/empty keys so list outputs are not padded with nulls.

    Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (AdapterResponseSchema)

    Args:
        adapter: A single adapter object from the API response.

    Returns:
        dict: Normalized adapter fields (empty values removed).
    """
    return assign_params(
        uuid=adapter.get("uuid"),
        name=adapter.get("name"),
        status=adapter.get("status"),
        description=adapter.get("description"),
        tsg_id=adapter.get("tsg_id"),
        network_broker_channel_uuid=adapter.get("network_broker_channel_uuid"),
        script_b64=adapter.get("script_b64"),
        variables=adapter.get("variables"),
        target_count=adapter.get("target_count"),
        created_at=adapter.get("created_at"),
        updated_at=adapter.get("updated_at"),
        created_by_user_id=adapter.get("created_by_user_id"),
        updated_by_user_id=adapter.get("updated_by_user_id"),
    )


def _resolve_adapter_script_b64(args: dict[str, Any]) -> str:
    """Resolve the adapter script as base64. Accepts pre-encoded ``script_b64`` or plain ``script``.

    Args:
        args: Command arguments from XSOAR.

    Returns:
        str: The base64-encoded adapter script.

    Raises:
        ValueError: If neither ``script_b64`` nor ``script`` is provided.
    """
    script_b64 = args.get("script_b64")
    if script_b64:
        return script_b64
    script = args.get("script")
    if script:
        return base64.b64encode(script.encode("utf-8")).decode("ascii")
    raise ValueError("Either 'script' (plain text) or 'script_b64' (base64-encoded) is required")


def _build_adapter_variables(raw: Any) -> list[dict[str, Any]] | None:
    """Parse and validate the adapter ``variables`` argument (JSON array of {key,value,type}).

    Args:
        raw: The ``variables`` argument value (JSON string or already-parsed list).

    Returns:
        list | None: The validated variables list, or None when not provided.

    Raises:
        ValueError: If the value is not a valid list of {key, type} objects.
    """
    if not raw:
        return None
    variables = raw if isinstance(raw, list) else json.loads(raw)
    if not isinstance(variables, list):
        raise ValueError("variables must be a JSON array of {key, value, type} objects")
    for var in variables:
        if not isinstance(var, dict) or not var.get("key") or not var.get("type"):
            raise ValueError("each variable requires a non-empty 'key' and 'type' (VAR or SECRET)")
        if var["type"] not in ("VAR", "SECRET"):
            raise ValueError("variable 'type' must be 'VAR' or 'SECRET'")
    return variables


def _assert_channel_online(client: Client, channel_uuid: str) -> None:
    """Advisory preflight: activation/validation needs an ONLINE network broker channel.

    Raises a clear error when the channel is reachable but not ONLINE; stays silent when the
    channel status cannot be looked up so the API remains the source of truth. Mirrors the CLI's
    broker-online check.

    Args:
        client: Prisma AIRs API client.
        channel_uuid: Network broker channel UUID.

    Raises:
        ValueError: If the channel is reachable but its status is not ONLINE.
    """
    try:
        channel = client.http_request(
            method="GET", url_suffix=f"{RED_TEAM_NETWORK_CHANNELS_ENDPOINT}/{channel_uuid}", use_redteam_data=True
        )
    except Exception as exc:  # noqa: BLE001 - preflight is advisory; defer to the API on any lookup failure
        demisto.debug(f"Adapter channel preflight skipped for {channel_uuid}: {exc}")
        return
    status = channel.get("status")
    if status and status != "ONLINE":
        raise ValueError(
            f"Network broker channel {channel_uuid} is '{status}', not ONLINE. Start the network broker "
            "client and wait until the channel is ONLINE before validating or activating the adapter."
        )


def redteam_adapters_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Red Team custom target adapters.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))
    search = args.get("search")

    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    if search:
        params["search"] = search
    if args.get("include_target_count") is not None:
        params["include_target_count"] = str(argToBoolean(args.get("include_target_count"))).lower()

    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (list)
    response = client.http_request(
        method="GET", url_suffix=RED_TEAM_ADAPTERS_ENDPOINT, params=params, use_redteam_mgmt=True
    )

    adapters = [_parse_adapter(adapter) for adapter in response.get("data", [])]

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Adapters",
        adapters,
        headers=["uuid", "name", "status", "target_count", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapter",
        outputs_key_field="uuid",
        outputs=adapters,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_adapters_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single Red Team custom target adapter by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (get)
    response = client.http_request(
        method="GET", url_suffix=f"{RED_TEAM_ADAPTERS_ENDPOINT}/{uuid}", use_redteam_mgmt=True
    )

    adapter_info = _parse_adapter(response)

    readable_output = tableToMarkdown(
        f"Red Team Adapter: {adapter_info.get('name') or uuid}",
        [adapter_info],
        headers=["uuid", "name", "status", "description", "network_broker_channel_uuid", "target_count", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapter",
        outputs_key_field="uuid",
        outputs=adapter_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_adapters_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team custom target adapter.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    name = args.get("name")
    if not name:
        raise ValueError("name is required")
    prompt = args.get("prompt")
    if not prompt:
        raise ValueError("prompt is required")

    # validate defaults to true: run the script end-to-end and save ACTIVE on success, DRAFT on failure.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (create)
    validate = argToBoolean(args.get("validate")) if args.get("validate") is not None else True
    channel_uuid = args.get("network_broker_channel_uuid")
    if validate and channel_uuid:
        _assert_channel_online(client, channel_uuid)

    # Build request body per AdapterCreateRequestSchema.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (AdapterCreateRequestSchema)
    request_body: dict[str, Any] = {
        "name": name,
        "script_b64": _resolve_adapter_script_b64(args),
        "prompt": prompt,
    }
    if args.get("description"):
        request_body["description"] = args.get("description")
    if channel_uuid:
        request_body["network_broker_channel_uuid"] = channel_uuid
    variables = _build_adapter_variables(args.get("variables"))
    if variables is not None:
        request_body["variables"] = variables

    response = client.http_request(
        method="POST",
        url_suffix=RED_TEAM_ADAPTERS_ENDPOINT,
        json_data=request_body,
        params={"validate": str(validate).lower()},
        use_redteam_mgmt=True,
    )

    adapter_info = _parse_adapter(response)

    readable_output = tableToMarkdown(
        f"Red Team Adapter Created: {name}",
        [adapter_info],
        headers=["uuid", "name", "status", "network_broker_channel_uuid", "target_count", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapter",
        outputs_key_field="uuid",
        outputs=adapter_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_adapters_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a Red Team custom target adapter (full-replacement PUT).

    The upstream update is a full replacement: name, script, and prompt are required, and the
    variables list defines the complete desired key set (an omitted key is deleted; a null value
    keeps a stored secret). Missing name/script are backfilled from the current record so callers
    can change one field without wiping the rest.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")
    prompt = args.get("prompt")
    if not prompt:
        # prompt is never stored upstream, so it must be supplied on every update.
        raise ValueError("prompt is required on every update (it is not stored server-side)")

    # Fetch the current adapter to preserve required fields the caller does not override.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (update)
    current = client.http_request(
        method="GET", url_suffix=f"{RED_TEAM_ADAPTERS_ENDPOINT}/{uuid}", use_redteam_mgmt=True
    )

    name = args.get("name") or current.get("name")
    script_b64 = args.get("script_b64")
    if not script_b64 and args.get("script"):
        script_b64 = base64.b64encode(args["script"].encode("utf-8")).decode("ascii")
    if not script_b64:
        script_b64 = current.get("script_b64")

    validate = argToBoolean(args.get("validate")) if args.get("validate") is not None else True
    channel_uuid = args.get("network_broker_channel_uuid")
    if channel_uuid is None:
        channel_uuid = current.get("network_broker_channel_uuid")
    if validate and channel_uuid:
        _assert_channel_online(client, channel_uuid)

    # Build request body per AdapterUpdateRequestSchema (full replacement).
    request_body: dict[str, Any] = {
        "name": name,
        "script_b64": script_b64,
        "prompt": prompt,
    }
    if channel_uuid:
        request_body["network_broker_channel_uuid"] = channel_uuid
    description = args.get("description")
    if description is None:
        description = current.get("description")
    if description is not None:
        request_body["description"] = description

    # variables: explicit arg replaces the whole set; otherwise resend the stored set so nothing is
    # deleted, with secrets passed back as value=null to keep their stored values.
    variables = _build_adapter_variables(args.get("variables"))
    if variables is None:
        stored = current.get("variables") or []
        variables = [
            {
                "key": var.get("key"),
                "value": None if var.get("is_redacted") else var.get("value"),
                "type": var.get("type"),
            }
            for var in stored
            if var.get("key") and var.get("type")
        ]
    if variables:
        request_body["variables"] = variables

    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_ADAPTERS_ENDPOINT}/{uuid}",
        json_data=request_body,
        params={"validate": str(validate).lower()},
        use_redteam_mgmt=True,
    )

    adapter_info = _parse_adapter(response)

    readable_output = tableToMarkdown(
        f"Red Team Adapter Updated: {adapter_info.get('name') or uuid}",
        [adapter_info],
        headers=["uuid", "name", "status", "network_broker_channel_uuid", "target_count", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapter",
        outputs_key_field="uuid",
        outputs=adapter_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_adapters_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a Red Team custom target adapter.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (delete)
    response = client.http_request(
        method="DELETE", url_suffix=f"{RED_TEAM_ADAPTERS_ENDPOINT}/{uuid}", use_redteam_mgmt=True
    )

    delete_info = {
        "uuid": uuid,
        "is_success": (response or {}).get("is_success", True) if isinstance(response, dict) else True,
    }

    readable_output = tableToMarkdown(
        f"Red Team Adapter Deleted: {uuid}",
        [delete_info],
        headers=["uuid", "is_success"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapterDelete",
        outputs_key_field="uuid",
        outputs=delete_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_adapters_validate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Validate a Red Team custom target adapter script without saving it.

    Runs the script end-to-end through the network broker channel using the sample prompt and
    returns the execution outcome (validated + stdout/stderr/traceback), not an adapter record.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    channel_uuid = args.get("network_broker_channel_uuid")
    if not channel_uuid:
        raise ValueError("network_broker_channel_uuid is required")
    prompt = args.get("prompt")
    if not prompt:
        raise ValueError("prompt is required")

    # Advisory broker-online preflight (mirrors the CLI) before the non-persistent validation run.
    _assert_channel_online(client, channel_uuid)

    # Build request body per AdapterValidateRequestSchema (distinct from create: no name).
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (AdapterValidateRequestSchema)
    request_body: dict[str, Any] = {
        "script_b64": _resolve_adapter_script_b64(args),
        "network_broker_channel_uuid": channel_uuid,
        "prompt": prompt,
    }
    variables = _build_adapter_variables(args.get("variables"))
    if variables is not None:
        request_body["variables"] = variables
    if args.get("adapter_uuid"):
        # References an existing adapter so null/redacted variable values resolve from its secrets.
        request_body["adapter_uuid"] = args.get("adapter_uuid")

    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/adapters-client.ts (validate)
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_ADAPTERS_VALIDATE_ENDPOINT, json_data=request_body, use_redteam_mgmt=True
    )

    validation_info = assign_params(
        validated=response.get("validated"),
        stdout=response.get("stdout"),
        stderr=response.get("stderr"),
        traceback=response.get("traceback"),
    )
    # assign_params drops False; keep the explicit validated flag so context always carries it.
    validation_info["validated"] = response.get("validated")

    readable_output = tableToMarkdown(
        "Red Team Adapter Validation",
        [validation_info],
        headers=["validated", "stdout", "stderr", "traceback"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAdapterValidation",
        outputs=validation_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body: dict[str, Any] = {"name": name}

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

        request_body["connection_params"] = json.loads(args.get("connection_params", ""))

    # Probe fields - array of fields to probe (e.g., ["multi_turn", "rate_limit"])
    if args.get("probe_fields"):
        probe_fields_str = args.get("probe_fields") or ""
        request_body["probe_fields"] = [field.strip() for field in probe_fields_str.split(",")]

    # Call Red Team target probe endpoint
    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/targets-client.ts (probe method)
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (TargetResponseSchema)
    response = client.http_request(
        method="POST", url_suffix=f"{RED_TEAM_TARGETS_ENDPOINT}/probe", json_data=request_body, use_redteam_mgmt=True
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
        "connection_type": response.get("connection_type"),
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
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetProbe",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response,
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
    # Response: TargetProfileResponseSchema - { target_id, target_version, status, profiling_status,
    #   target_background, additional_context, ai_generated_fields, other_details }
    url_suffix = f"{RED_TEAM_TARGETS_ENDPOINT}/{target_uuid}/profile"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_mgmt=True)

    # Parse response according to TargetProfileResponseSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (lines 1160-1172)
    profile_info = {
        "target_id": response.get("target_id"),
        "target_version": response.get("target_version"),
        "status": response.get("status"),
        "profiling_status": response.get("profiling_status"),
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
    readable_output = tableToMarkdown(
        "Red Team Target Profile",
        profile_info,
        headers=[
            "target_id",
            "target_version",
            "status",
            "profiling_status",
            "target_background",
            "additional_context",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetProfile",
        outputs_key_field="target_id",
        outputs=profile_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_redteam_mgmt=True)

    # Parse response according to TargetResponseSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (lines 1071-1099)
    target_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "status": response.get("status"),
        "active": response.get("active"),
        "validated": response.get("validated"),
        "updated_at": response.get("updated_at"),
    }

    # Add target_background and additional_context if present in response
    if response.get("target_background"):
        target_info["target_background"] = response.get("target_background")
    if response.get("additional_context"):
        target_info["additional_context"] = response.get("additional_context")

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Target Profile Updated",
        target_info,
        headers=["uuid", "name", "status", "updated_at", "target_background", "additional_context"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetUpdateProfile",
        outputs_key_field="uuid",
        outputs=target_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_mgmt=True)

    # Response is a dictionary of field definitions
    # Example: { "rate_limit": { "type": "number", "required": false }, "multi_turn": { "type": "boolean" } }
    metadata = response if isinstance(response, dict) else {}

    # Create readable output showing field definitions as a table (one row per field).
    metadata_rows = []
    for field_name, definition in metadata.items():
        if isinstance(definition, dict):
            metadata_rows.append({"Field": field_name, **definition})
        else:
            metadata_rows.append({"Field": field_name, "Value": definition})

    readable_output = tableToMarkdown(
        "Red Team Target Field Metadata",
        metadata_rows,
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetMetadata",
        outputs=metadata,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_targets_validate_auth_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Validate authentication credentials for a Red Team target.

    Checks whether the supplied auth configuration is accepted by the target provider
    without creating or modifying a target. Useful for verifying credentials before
    creating a target.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    import json

    # Required arguments
    auth_type = args.get("auth_type")
    if not auth_type:
        raise ValueError("auth_type is required")

    auth_config_raw = args.get("auth_config")
    if not auth_config_raw:
        raise ValueError("auth_config is required (JSON object)")

    # Build request body according to TargetAuthValidationRequestSchema
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/models/red-team.ts (TargetAuthValidationRequestSchema)
    request_body: dict[str, Any] = {
        "auth_type": auth_type,
        "auth_config": json.loads(auth_config_raw),
    }

    # Optional identifiers
    if args.get("target_id"):
        request_body["target_id"] = args.get("target_id")
    if args.get("network_broker_channel_uuid"):
        request_body["network_broker_channel_uuid"] = args.get("network_broker_channel_uuid")

    # Call Red Team target auth validation endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/targets-client.ts (validateAuth method)
    # Endpoint: POST /v1/target/validate-auth
    # Response: TargetAuthValidationResponse - { validated, token_preview?, expires_in? }
    url_suffix = f"{RED_TEAM_TARGETS_ENDPOINT}/validate-auth"
    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_redteam_mgmt=True)

    result = response if isinstance(response, dict) else {}

    validation_info = {
        "auth_type": auth_type,
        "validated": result.get("validated"),
        "token_preview": result.get("token_preview"),
        "expires_in": result.get("expires_in"),
    }

    readable_output = tableToMarkdown(
        "Red Team Target Auth Validation",
        [validation_info],
        headers=["auth_type", "validated", "token_preview", "expires_in"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetAuthValidation",
        outputs=result,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_targets_templates_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Red Team target configuration templates per provider.

    Returns provider-keyed templates (e.g., OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK,
    REST, STREAMING, WEBSOCKET) describing the connection fields expected for each
    target provider type.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team target templates endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/targets-client.ts (getTargetTemplates method)
    # Endpoint: GET /v1/template/target-templates
    # Response: TargetTemplateCollection - provider-keyed dict of template definitions
    url_suffix = f"{RED_TEAM_TEMPLATE_ENDPOINT}/target-templates"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_mgmt=True)

    templates = response if isinstance(response, dict) else {}

    # Summarize as one row per provider showing the available field names.
    template_rows = []
    for provider, definition in templates.items():
        fields = ", ".join(definition.keys()) if isinstance(definition, dict) else str(definition)
        template_rows.append({"Provider": provider, "Fields": fields})

    readable_output = tableToMarkdown(
        "Red Team Target Templates",
        template_rows,
        headers=["Provider", "Fields"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetTemplate",
        outputs=templates,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_targets_error_logs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List target-profile (profiling) error logs for a Red Team target.

    Returns the profiling failures recorded while Prisma AIRs was probing/profiling the
    target (e.g. connection, probe, or authentication errors), newest first.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    target_id = args.get("target_id")
    if not target_id:
        raise ValueError("target_id is required")

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))
    search = args.get("search")

    # The endpoint honors skip/limit/search (serializeListing shape).
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    if search:
        params["search"] = search

    # Target-profile error logs live on the data plane.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getTargetProfileErrorLogs)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_ERROR_LOG_TARGET_PROFILE_ENDPOINT}/{target_id}",
        params=params,
        use_redteam_data=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (ErrorLogListResponseSchema)
    logs = []
    for entry in response.get("data", []):
        logs.append(
            assign_params(
                created_at=entry.get("created_at"),
                updated_at=entry.get("updated_at"),
                job_id=entry.get("job_id"),
                target_id=entry.get("target_id"),
                target_version=entry.get("target_version"),
                attack_id=entry.get("attack_id"),
                error_type=entry.get("error_type"),
                error_source=entry.get("error_source"),
                error_message=entry.get("error_message"),
                target_object=entry.get("target_object"),
                extra_info=entry.get("extra_info"),
                version=entry.get("version"),
            )
        )

    total_items = (response.get("pagination") or {}).get("total_items")
    title = f"Red Team Target-Profile Error Logs: {target_id}"
    if total_items is not None:
        title += f" ({total_items} total)"

    readable_output = tableToMarkdown(
        title,
        logs,
        headers=["created_at", "error_type", "error_source", "error_message", "job_id", "attack_id"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamTargetErrorLog",
        outputs=logs,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_scan_error_logs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List job-level error logs for a Red Team scan.

    Returns the per-attack probe failures recorded while a scan job was running (e.g. timeouts,
    target connection or authentication errors), newest first. Unlike the target-profile error
    logs (which cover profiling), these are scoped to a single scan job.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))
    search = args.get("search")

    # The endpoint honors skip/limit/search (serializeListing shape).
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    if search:
        params["search"] = search

    # Job-level error logs live on the data plane.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getErrorLogs)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_ERROR_LOG_JOB_ENDPOINT}/{job_id}",
        params=params,
        use_redteam_data=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (ErrorLogListResponseSchema)
    logs = []
    for entry in response.get("data", []):
        logs.append(
            assign_params(
                created_at=entry.get("created_at"),
                updated_at=entry.get("updated_at"),
                job_id=entry.get("job_id"),
                target_id=entry.get("target_id"),
                target_version=entry.get("target_version"),
                attack_id=entry.get("attack_id"),
                error_type=entry.get("error_type"),
                error_source=entry.get("error_source"),
                error_message=entry.get("error_message"),
                target_object=entry.get("target_object"),
                extra_info=entry.get("extra_info"),
                version=entry.get("version"),
            )
        )

    total_items = (response.get("pagination") or {}).get("total_items")
    title = f"Red Team Scan Error Logs: {job_id}"
    if total_items is not None:
        title += f" ({total_items} total)"

    readable_output = tableToMarkdown(
        title,
        logs,
        headers=["created_at", "error_type", "error_source", "error_message", "attack_id", "target_id"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanErrorLog",
        outputs=logs,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_dashboard_scan_statistics_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team scan statistics and risk profile (data-plane dashboard telemetry).

    Returns aggregate scan counts and, when available, breakdowns by target type, scan status,
    and risk rating. Optional filters narrow the window (date_range) or a single target (target_id).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    params: dict[str, Any] = {}
    date_range = args.get("date_range")
    target_id = args.get("target_id")
    if date_range:
        params["date_range"] = date_range
    if target_id:
        params["target_id"] = target_id

    # Scan statistics live on the data plane.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getScanStatistics)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_DASHBOARD_ENDPOINT}/scan-statistics",
        params=params or None,
        use_redteam_data=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (ScanStatisticsResponseSchema)
    outputs = assign_params(
        total_scans=response.get("total_scans"),
        targets_scanned=response.get("targets_scanned"),
        targets_scanned_by_type=response.get("targets_scanned_by_type"),
        scan_status=response.get("scan_status"),
        risk_profile=response.get("risk_profile"),
    )

    summary = tableToMarkdown(
        "Red Team Scan Statistics",
        [{"total_scans": response.get("total_scans"), "targets_scanned": response.get("targets_scanned")}],
        headers=["total_scans", "targets_scanned"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    if response.get("scan_status"):
        summary += tableToMarkdown(
            "Scan Status",
            response.get("scan_status"),
            headers=["name", "count"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )
    if response.get("risk_profile"):
        summary += tableToMarkdown(
            "Risk Profile",
            response.get("risk_profile"),
            headers=["risk_rating", "total"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanStatistics",
        outputs=outputs,
        readable_output=summary,
        raw_response=response,
    )


def redteam_dashboard_score_trend_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the Red Team risk score trend for a target (data-plane dashboard telemetry).

    Returns time-bucketed labels plus one or more data series (e.g. risk score over time) for the
    given target.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    target_id = args.get("target_id")
    if not target_id:
        raise ValueError("target_id is required")

    # Score trend lives on the data plane; target_id is required (uuid).
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getScoreTrend)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_DASHBOARD_ENDPOINT}/score-trend",
        params={"target_id": target_id},
        use_redteam_data=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (ScoreTrendResponseSchema)
    labels = response.get("labels") or []
    series = response.get("series") or []
    outputs = assign_params(target_id=target_id, labels=labels, series=series)

    # Render each series as a row of label -> data, aligned to the shared labels.
    table_rows = []
    for s in series:
        row: dict[str, Any] = {"series": s.get("label")}
        for idx, label in enumerate(labels):
            data = s.get("data") or []
            row[label] = data[idx] if idx < len(data) else None
        table_rows.append(row)

    readable_output = tableToMarkdown(
        f"Red Team Score Trend: {target_id}",
        table_rows,
        headers=["series", *labels],
        removeNull=False,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScoreTrend",
        outputs_key_field="target_id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_metering_quota_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the Red Team metering quota summary (data-plane).

    Returns the allocated / consumed / unlimited flags for each quota bucket (static, dynamic,
    custom). Called as a POST with no body, mirroring the SDK.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR (unused).

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Quota lives on the data plane and is a POST with no body.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getQuota)
    response = client.http_request(
        method="POST",
        url_suffix=RED_TEAM_QUOTA_ENDPOINT,
        use_redteam_data=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (QuotaSummarySchema)
    outputs = assign_params(
        static=response.get("static"),
        dynamic=response.get("dynamic"),
        custom=response.get("custom"),
    )

    table_rows = []
    for bucket in ("static", "dynamic", "custom"):
        details = response.get(bucket) or {}
        table_rows.append(
            {
                "quota_type": bucket,
                "allocated": details.get("allocated"),
                "consumed": details.get("consumed"),
                "unlimited": details.get("unlimited"),
            }
        )

    readable_output = tableToMarkdown(
        "Red Team Metering Quota",
        table_rows,
        headers=["quota_type", "allocated", "consumed", "unlimited"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamQuota",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_dashboard_overview_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the Red Team management dashboard overview (mgmt-plane).

    Returns the total target count and, when available, a breakdown of targets by type.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR (unused).

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Dashboard overview is the one telemetry endpoint on the management plane.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/client.ts (getDashboardOverview)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_DASHBOARD_ENDPOINT}/overview",
        use_redteam_mgmt=True,
    )

    # Schema: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/models/red-team.ts (DashboardOverviewResponseSchema)
    outputs = assign_params(
        total_targets=response.get("total_targets"),
        targets_by_type=response.get("targets_by_type"),
    )

    readable_output = tableToMarkdown(
        "Red Team Dashboard Overview",
        [{"total_targets": response.get("total_targets")}],
        headers=["total_targets"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    if response.get("targets_by_type"):
        readable_output += tableToMarkdown(
            "Targets by Type",
            response.get("targets_by_type"),
            headers=["name", "count"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamDashboardOverview",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"name": name, "target": {"uuid": target_uuid}, "job_type": job_type, "job_metadata": job_metadata}

    # Call Red Team scan create endpoint
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/scans-client.ts (create method)
    # Endpoint: POST /ai-red-teaming/data-plane/v1/scan
    # Response: JobResponseSchema
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_SCANS_ENDPOINT, json_data=request_body, use_redteam_data=True
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = ["version", "extra_info", "job_metadata", "time_record", "created_by_user_id", "updated_by_user_id"]
    for field in optional_fields:
        if response.get(field):
            scan_info[field] = response.get(field)

    # Create readable output using XSOAR best practice table format
    readable_output = tableToMarkdown(
        "Red Team Scan Created Successfully",
        [scan_info],
        headers=[
            "uuid",
            "name",
            "job_type",
            "status",
            "target_id",
            "target_type",
            "total",
            "completed",
            "score",
            "asr",
            "created_at",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add helpful note below table
    readable_output += (
        '\n**Next Steps:** Use `!prisma-airs-redteam-scan-get uuid="'
        + str(scan_info.get("uuid"))
        + '"` to check scan status and progress.'
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanCreate",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=RED_TEAM_SCANS_ENDPOINT, params=params, use_redteam_data=True)

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
            "error_message": scan.get("error_message"),
        }
        scans.append(scan_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Scans",
        scans,
        headers=["uuid", "job_type", "status", "target_name", "progress", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScan",
        outputs_key_field="uuid",
        outputs=scans,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_SCANS_ENDPOINT}/{job_id}", use_redteam_data=True)

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
        "invocation_id": response.get("invocation_id"),
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
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanGet",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="POST", url_suffix=f"{RED_TEAM_SCANS_ENDPOINT}/{job_id}/abort", use_redteam_data=True)

    # Parse response according to JobAbortResponseSchema
    # Fields: job_id, message
    abort_info = {"job_id": response.get("job_id"), "message": response.get("message")}

    readable_output = tableToMarkdown(
        "Red Team Scan Aborted",
        abort_info,
        headers=["job_id", "message"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamScanAbort",
        outputs_key_field="job_id",
        outputs=abort_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=RED_TEAM_CATEGORIES_ENDPOINT, use_redteam_data=True)

    # Parse response - returns array of CategoryModel
    # Fields: id, display_name, description, preselect, sub_categories
    categories = []
    categories_response: list = response if isinstance(response, list) else []
    for category in categories_response:
        category_info = {
            "id": category.get("id"),
            "display_name": category.get("display_name"),
            "description": category.get("description"),
            "preselect": category.get("preselect"),
            "sub_category_count": len(category.get("sub_categories", [])),
        }

        # Extract subcategory details
        sub_cats = []
        for sub_cat in category.get("sub_categories", []):
            sub_cat_info = {
                "id": sub_cat.get("id"),
                "display_name": sub_cat.get("display_name"),
                "description": sub_cat.get("description"),
                "preselect": sub_cat.get("preselect"),
                "active": sub_cat.get("active"),
            }
            sub_cats.append(sub_cat_info)

        category_info["sub_categories"] = sub_cats
        categories.append(category_info)

    readable_output = tableToMarkdown(
        "Red Team Attack Categories",
        categories,
        headers=["id", "display_name", "description", "sub_category_count"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCategory",
        outputs_key_field="id",
        outputs=categories,
        readable_output=readable_output,
        raw_response=response,
    )


def _parse_network_channel(channel: dict[str, Any]) -> dict[str, Any]:
    """Extract the fields of a single Red Team network broker channel.

    Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team-network-broker.ts (ChannelSchema)

    Args:
        channel: A single channel object from the API response.

    Returns:
        dict: Normalized channel fields.
    """
    return {
        "uuid": channel.get("uuid"),
        "name": channel.get("name"),
        "description": channel.get("description"),
        "status": channel.get("status"),
        "added_by": channel.get("added_by"),
        "created_at": channel.get("created_at"),
        "updated_at": channel.get("updated_at"),
        "last_online_at": channel.get("last_online_at"),
        "connected_clients_count": channel.get("connected_clients_count"),
        "outdated_clients_count": channel.get("outdated_clients_count"),
        "oldest_client_version": channel.get("oldest_client_version"),
        "features": channel.get("features"),
    }


def redteam_network_channels_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Red Team network broker channels.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))
    search = args.get("search")
    status = argToList(args.get("status"))
    include_all_if_empty = args.get("include_all_if_empty")

    # Build query parameters
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    if search:
        params["search"] = search
    if status:
        # Spec uses style=form, explode=true -> repeated `status` query params.
        params["status"] = status
    if include_all_if_empty is not None:
        params["include_all_if_empty"] = str(argToBoolean(include_all_if_empty)).lower()

    # Call Red Team network broker channels list endpoint (data-plane /network-broker sub-path).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/network-broker-client.ts (listChannels)
    response = client.http_request(
        method="GET", url_suffix=RED_TEAM_NETWORK_CHANNELS_ENDPOINT, params=params, use_redteam_data=True
    )

    channels = [_parse_network_channel(channel) for channel in response.get("data", [])]

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Network Channels",
        channels,
        headers=["uuid", "name", "status", "description", "last_online_at", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamNetworkChannel",
        outputs_key_field="uuid",
        outputs=channels,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_network_channels_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Red Team network broker channel.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    name = args.get("name")
    if not name:
        raise ValueError("name is required")

    # Build request body according to CreateChannelRequestSchema.
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team-network-broker.ts
    request_body: dict[str, Any] = {"name": name}
    if args.get("description"):
        request_body["description"] = args.get("description")

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/network-broker-client.ts (createChannel)
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_NETWORK_CHANNELS_ENDPOINT, json_data=request_body, use_redteam_data=True
    )

    channel_info = _parse_network_channel(response)

    readable_output = tableToMarkdown(
        f"Red Team Network Channel Created: {name}",
        [channel_info],
        headers=["uuid", "name", "status", "description", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamNetworkChannelCreate",
        outputs_key_field="uuid",
        outputs=channel_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_network_channels_stats_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get Red Team network broker channel statistics and deployment info.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/network-broker-client.ts (getChannelStats)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team-network-broker.ts (ChannelStatsSchema)
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_NETWORK_CHANNELS_ENDPOINT}/stats", use_redteam_data=True)

    stats_info = {
        "network_channels_server_domain": response.get("network_channels_server_domain"),
        "docker_registry": response.get("docker_registry"),
        "helm_chart": response.get("helm_chart"),
        "docker_image": response.get("docker_image"),
        "online_channels": response.get("online_channels"),
        "total_channels": response.get("total_channels"),
        "client_version": response.get("client_version"),
    }

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Network Channel Stats",
        [stats_info],
        headers=[
            "network_channels_server_domain",
            "online_channels",
            "total_channels",
            "docker_registry",
            "docker_image",
            "helm_chart",
            "client_version",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamNetworkChannelStats",
        outputs=stats_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_network_channels_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single Red Team network broker channel by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    channel_id = args.get("channel_id")
    if not channel_id:
        raise ValueError("channel_id is required")

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/network-broker-client.ts (getChannel)
    response = client.http_request(
        method="GET", url_suffix=f"{RED_TEAM_NETWORK_CHANNELS_ENDPOINT}/{channel_id}", use_redteam_data=True
    )

    channel_info = _parse_network_channel(response)

    readable_output = tableToMarkdown(
        "Prisma AIRs Red Team Network Channel",
        [channel_info],
        headers=["uuid", "name", "status", "description", "last_online_at", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamNetworkChannel",
        outputs_key_field="uuid",
        outputs=channel_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_network_channels_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a Red Team network broker channel's name and/or description.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    channel_id = args.get("channel_id")
    if not channel_id:
        raise ValueError("channel_id is required")

    # Build request body according to UpdateChannelRequestSchema (only provided fields).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team-network-broker.ts
    request_body: dict[str, Any] = {}
    if args.get("name"):
        request_body["name"] = args.get("name")
    if args.get("description") is not None:
        request_body["description"] = args.get("description")

    if not request_body:
        raise ValueError("At least one of name or description is required")

    # PATCH uses plain application/json (not merge-patch).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/network-broker-client.ts (updateChannel)
    response = client.http_request(
        method="PATCH",
        url_suffix=f"{RED_TEAM_NETWORK_CHANNELS_ENDPOINT}/{channel_id}",
        json_data=request_body,
        use_redteam_data=True,
    )

    channel_info = _parse_network_channel(response)

    readable_output = tableToMarkdown(
        f"Red Team Network Channel Updated: {channel_id}",
        [channel_info],
        headers=["uuid", "name", "status", "description", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamNetworkChannelUpdate",
        outputs_key_field="uuid",
        outputs=channel_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_languages_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the tenant's allowed languages for Red Team scans.

    Served from the data plane by default; set use_management=true to query the
    management plane (identical response shape, possibly a different subset).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    use_management = argToBoolean(args.get("use_management", False))

    # Same path on both planes; the plane selector picks data vs mgmt.
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/client.ts
    #   (getLanguages -> data plane, getManagementLanguages -> mgmt plane)
    # SDK schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (TenantLanguagesResponseSchema)
    if use_management:
        response = client.http_request(method="GET", url_suffix=RED_TEAM_LANGUAGES_ENDPOINT, use_redteam_mgmt=True)
    else:
        response = client.http_request(method="GET", url_suffix=RED_TEAM_LANGUAGES_ENDPOINT, use_redteam_data=True)

    # Keep the metadata attached to the language list in a single output object.
    languages = response.get("languages") or []
    supported_job_types = argToList(response.get("supported_job_types"))
    languages_info = {
        "multilingual_enabled": response.get("multilingual_enabled"),
        "supported_job_types": supported_job_types,
        "plane": "management" if use_management else "data",
        "languages": [{"code": lang.get("code"), "name": lang.get("name")} for lang in languages],
    }

    supported = ", ".join(str(job_type) for job_type in supported_job_types)
    title = (
        f"Prisma AIRs Red Team Supported Languages "
        f"(multilingual_enabled: {languages_info['multilingual_enabled']}; job types: {supported or 'N/A'})"
    )
    readable_output = tableToMarkdown(
        title,
        languages_info["languages"],
        headers=["code", "name"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamLanguages",
        outputs=languages_info,
        readable_output=readable_output,
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

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
            "report_summary": response.get("report_summary"),
        }

        readable_output = tableToMarkdown(
            f"Red Team Report (Dynamic) - Job {job_id}",
            [report_info],
            headers=["job_type", "total_goals", "goals_achieved", "total_threats", "score", "asr"],
            headerTransform=lambda h: h.replace("_", " ").title(),
        )

    else:
        # StaticJobReportSchema fields: severity_report, asr, score, security_report, safety_report,
        #   brand_report, compliance_report, report_summary, recommendations
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
            "report_summary": response.get("report_summary"),
        }

        # Build severity breakdown
        severity_breakdown = []
        for severity_stat in severity_stats:
            severity_breakdown.append(
                {
                    "severity": severity_stat.get("severity"),
                    "successful": severity_stat.get("successful"),
                    "failed": severity_stat.get("failed"),
                }
            )

        report_info["severity_breakdown"] = severity_breakdown

        # Build category reports
        category_reports = []
        for cat_type in ["security_report", "safety_report", "brand_report"]:
            cat_report = response.get(cat_type)
            if cat_report:
                category_reports.append(
                    {
                        "category": cat_type.replace("_report", "").title(),
                        "id": cat_report.get("id"),
                        "display_name": cat_report.get("display_name"),
                        "asr": cat_report.get("asr"),
                        "total_prompts": cat_report.get("total_prompts"),
                        "total_attacks": cat_report.get("total_attacks"),
                        "successful": cat_report.get("successful"),
                        "failed": cat_report.get("failed"),
                    }
                )

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
            headerTransform=lambda h: h.replace("_", " ").title(),
        )

        # Add severity breakdown table
        if severity_breakdown:
            readable_output += "\n\n" + tableToMarkdown(
                "Severity Breakdown",
                severity_breakdown,
                headers=["severity", "successful", "failed"],
                headerTransform=lambda h: h.replace("_", " ").title(),
            )

        # Add category reports table
        if category_reports:
            readable_output += "\n\n" + tableToMarkdown(
                "Category Reports",
                category_reports,
                headers=["category", "display_name", "asr", "total_attacks", "successful", "failed"],
                headerTransform=lambda h: h.replace("_", " ").title(),
            )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamReport",
        outputs_key_field="job_id",
        outputs=report_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_attacks_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List attacks for a Red Team static scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))

    # Build query parameters (pagination + optional filters)
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    for filter_key in ("search", "status", "severity", "category", "sub_category", "attack_type"):
        value = args.get(filter_key)
        if value:
            params[filter_key] = value
    if args.get("threat") is not None:
        params["threat"] = str(argToBoolean(args.get("threat"))).lower()

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (listAttacks)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (AttackListResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_STATIC_ENDPOINT}/{job_id}/list-attacks"
    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_redteam_data=True)

    attacks = []
    for attack in response.get("data", []):
        attacks.append(
            {
                "uuid": attack.get("uuid"),
                "job_id": attack.get("job_id"),
                "target_id": attack.get("target_id"),
                "prompt": attack.get("prompt"),
                "category": attack.get("category"),
                "sub_category": attack.get("sub_category"),
                "category_display_name": attack.get("category_display_name"),
                "sub_category_display_name": attack.get("sub_category_display_name"),
                "status": attack.get("status"),
                "threat": attack.get("threat"),
                "attack_type": attack.get("attack_type"),
                "multi_turn": attack.get("multi_turn"),
                "severity": attack.get("severity"),
                "asr": attack.get("asr"),
                "marked_safe": attack.get("marked_safe"),
            }
        )

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Attacks - Job {job_id}",
        attacks,
        headers=["uuid", "category_display_name", "sub_category_display_name", "severity", "status", "threat"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAttack",
        outputs_key_field="uuid",
        outputs=attacks,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_attack_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get attack details for a Red Team static scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    attack_id = args.get("attack_id")
    if not job_id:
        raise ValueError("job_id is required")
    if not attack_id:
        raise ValueError("attack_id is required")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (getAttackDetail)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (AttackDetailResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_STATIC_ENDPOINT}/{job_id}/attack/{attack_id}"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

    attack = {
        "uuid": response.get("uuid"),
        "job_id": response.get("job_id"),
        "target_id": response.get("target_id"),
        "prompt": response.get("prompt"),
        "category": response.get("category"),
        "sub_category": response.get("sub_category"),
        "category_display_name": response.get("category_display_name"),
        "sub_category_display_name": response.get("sub_category_display_name"),
        "status": response.get("status"),
        "threat": response.get("threat"),
        "attack_type": response.get("attack_type"),
        "multi_turn": response.get("multi_turn"),
        "severity": response.get("severity"),
        "asr": response.get("asr"),
        "marked_safe": response.get("marked_safe"),
        "goal": response.get("goal"),
        "compliance_frameworks": response.get("compliance_frameworks"),
        "outputs": response.get("outputs"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Attack - {attack_id}",
        [attack],
        headers=["uuid", "category_display_name", "sub_category_display_name", "severity", "status", "threat", "goal"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Render model outputs (attack responses) as a supplementary table when present.
    outputs = attack.get("outputs") or []
    if outputs:
        readable_output += "\n\n" + tableToMarkdown(
            "Attack Outputs",
            outputs,
            headers=["target_id", "output", "threat", "marked_safe"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAttack",
        outputs_key_field="uuid",
        outputs=attack,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_attack_multi_turn_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get multi-turn attack details for a Red Team static scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    attack_id = args.get("attack_id")
    if not job_id:
        raise ValueError("job_id is required")
    if not attack_id:
        raise ValueError("attack_id is required")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (getMultiTurnAttackDetail)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (AttackMultiTurnDetailResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_STATIC_ENDPOINT}/{job_id}/attack-multi-turn/{attack_id}"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

    attack = {
        "uuid": response.get("uuid"),
        "job_id": response.get("job_id"),
        "target_id": response.get("target_id"),
        "prompt": response.get("prompt"),
        "category": response.get("category"),
        "sub_category": response.get("sub_category"),
        "category_display_name": response.get("category_display_name"),
        "sub_category_display_name": response.get("sub_category_display_name"),
        "status": response.get("status"),
        "threat": response.get("threat"),
        "attack_type": response.get("attack_type"),
        "multi_turn": response.get("multi_turn"),
        "severity": response.get("severity"),
        "asr": response.get("asr"),
        "marked_safe": response.get("marked_safe"),
        "goal": response.get("goal"),
        "compliance_frameworks": response.get("compliance_frameworks"),
        "outputs": response.get("outputs"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Multi-Turn Attack - {attack_id}",
        [attack],
        headers=["uuid", "category_display_name", "sub_category_display_name", "severity", "status", "threat", "goal"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Render per-turn model outputs as a supplementary table when present.
    # Multi-turn outputs are nested (one list of turns per generation); flatten for display.
    raw_outputs = attack.get("outputs") or []
    flat_turns: list[dict] = []
    for entry in raw_outputs:
        if isinstance(entry, list):
            flat_turns.extend(entry)
        else:
            flat_turns.append(entry)
    if flat_turns:
        readable_output += "\n\n" + tableToMarkdown(
            "Multi-Turn Outputs",
            flat_turns,
            headers=["generation", "turn", "prompt", "output", "error", "threat", "marked_safe"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamAttackMultiTurn",
        outputs_key_field="uuid",
        outputs=attack,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_remediation_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get remediation recommendations for a Red Team scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    job_type = args.get("job_type", "STATIC")
    if not job_id:
        raise ValueError("job_id is required")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts
    #   (getStaticRemediation / getDynamicRemediation)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (RemediationResponseSchema)
    if job_type.upper() == "DYNAMIC":
        base_endpoint = RED_TEAM_REPORT_DYNAMIC_ENDPOINT
    else:
        base_endpoint = RED_TEAM_REPORT_STATIC_ENDPOINT
    url_suffix = f"{base_endpoint}/{job_id}/remediation"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

    remediations = response.get("remediations") or []
    remediation_info = {
        "job_id": job_id,
        "job_type": job_type,
        "remediations": remediations,
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Remediations - Job {job_id}",
        remediations,
        headers=["remediation", "priority_level", "effectiveness_level", "ease_of_implementation_level"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamRemediation",
        outputs_key_field="job_id",
        outputs=remediation_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_runtime_policy_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the runtime security profile config derived from a Red Team scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    job_type = args.get("job_type", "STATIC")
    if not job_id:
        raise ValueError("job_id is required")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts
    #   (getStaticRuntimePolicy / getDynamicRuntimePolicy)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (RuntimeSecurityProfileResponseSchema)
    if job_type.upper() == "DYNAMIC":
        base_endpoint = RED_TEAM_REPORT_DYNAMIC_ENDPOINT
    else:
        base_endpoint = RED_TEAM_REPORT_STATIC_ENDPOINT
    url_suffix = f"{base_endpoint}/{job_id}/runtime-policy-config"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

    runtime_security_profile = response.get("runtime_security_profile") or []
    policy_info = {
        "job_id": job_id,
        "job_type": job_type,
        "runtime_security_profile": runtime_security_profile,
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Runtime Security Profile - Job {job_id}",
        runtime_security_profile,
        headers=["policy_id", "display_name"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamRuntimePolicy",
        outputs_key_field="job_id",
        outputs=policy_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_goals_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List goals for a Red Team dynamic scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))

    # Build query parameters (pagination + optional filters)
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    for filter_key in ("search", "goal_type", "status"):
        value = args.get(filter_key)
        if value:
            params[filter_key] = value
    if args.get("count") is not None:
        params["count"] = str(argToBoolean(args.get("count"))).lower()

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (listGoals)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (GoalListResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_DYNAMIC_ENDPOINT}/{job_id}/list-goals"
    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_redteam_data=True)

    goals = []
    for goal in response.get("data", []):
        goals.append(
            {
                "uuid": goal.get("uuid"),
                "tsg_id": goal.get("tsg_id"),
                "job_id": goal.get("job_id"),
                "goal": goal.get("goal"),
                "goal_to_show": goal.get("goal_to_show"),
                "goal_type": goal.get("goal_type"),
                "custom_goal": goal.get("custom_goal"),
                "threat": goal.get("threat"),
                "version": goal.get("version"),
                "safe_response": goal.get("safe_response"),
                "jailbroken_response": goal.get("jailbroken_response"),
            }
        )

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Goals - Job {job_id}",
        goals,
        headers=["uuid", "goal", "goal_type", "custom_goal", "threat"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamGoal",
        outputs_key_field="uuid",
        outputs=goals,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_goal_streams_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List streams for a goal in a Red Team dynamic scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    goal_id = args.get("goal_id")
    if not job_id:
        raise ValueError("job_id is required")
    if not goal_id:
        raise ValueError("goal_id is required")

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    skip = arg_to_number(args.get("skip"))

    # Build query parameters (pagination + optional search)
    params: dict[str, Any] = {"limit": limit}
    if skip is not None:
        params["skip"] = skip
    if args.get("search"):
        params["search"] = args.get("search")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (listGoalStreams)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (StreamListResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_DYNAMIC_ENDPOINT}/{job_id}/goal/{goal_id}/list-streams"
    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_redteam_data=True)

    streams = []
    for stream in response.get("data", []):
        streams.append(
            {
                "uuid": stream.get("uuid"),
                "tsg_id": stream.get("tsg_id"),
                "job_id": stream.get("job_id"),
                "target_id": stream.get("target_id"),
                "goal_id": stream.get("goal_id"),
                "stream_idx": stream.get("stream_idx"),
                "iteration": stream.get("iteration"),
                "stream_type": stream.get("stream_type"),
                "marked_safe": stream.get("marked_safe"),
                "threat": stream.get("threat"),
                "created_at": stream.get("created_at"),
                "updated_at": stream.get("updated_at"),
            }
        )

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Goal Streams - Goal {goal_id}",
        streams,
        headers=["uuid", "goal_id", "target_id", "stream_type", "threat", "marked_safe"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamStream",
        outputs_key_field="uuid",
        outputs=streams,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_report_stream_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get stream details for a Red Team dynamic scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    stream_id = args.get("stream_id")
    if not stream_id:
        raise ValueError("stream_id is required")

    # Reference: ./knowledge/prisma-airs-sdk-main/src/red-team/reports-client.ts (getStreamDetail)
    # Schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (StreamDetailResponseSchema)
    url_suffix = f"{RED_TEAM_REPORT_DYNAMIC_ENDPOINT}/stream/{stream_id}"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_data=True)

    stream = {
        "uuid": response.get("uuid"),
        "tsg_id": response.get("tsg_id"),
        "job_id": response.get("job_id"),
        "target_id": response.get("target_id"),
        "goal_id": response.get("goal_id"),
        "stream_idx": response.get("stream_idx"),
        "iteration": response.get("iteration"),
        "stream_type": response.get("stream_type"),
        "marked_safe": response.get("marked_safe"),
        "threat": response.get("threat"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
        "first_threat_iteration": response.get("first_threat_iteration"),
        "iterations": response.get("iterations"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Red Team Stream - {stream_id}",
        [stream],
        headers=["uuid", "job_id", "goal_id", "target_id", "stream_type", "threat", "marked_safe"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Render per-iteration attack progression as a supplementary table when present.
    iterations = stream.get("iterations") or []
    if iterations:
        readable_output += "\n\n" + tableToMarkdown(
            "Stream Iterations",
            iterations,
            headers=["iteration", "prompt", "techniques", "score", "threat", "output"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamStream",
        outputs_key_field="uuid",
        outputs=stream,
        readable_output=readable_output,
        raw_response=response,
    )


def _report_download_filename(job_id: str, file_format: str, content: bytes, content_disposition: str) -> str:
    """Derive a filename for a downloaded Red Team report.

    Prefers the server-provided ``Content-Disposition`` filename; otherwise picks an
    extension by sniffing the payload magic bytes (the API zips reports), falling back
    to the requested format.

    Args:
        job_id: Scan job identifier (used to build a fallback filename).
        file_format: Requested format (CSV, JSON, or ALL).
        content: Raw response bytes.
        content_disposition: Value of the response ``Content-Disposition`` header.

    Returns:
        str: A safe filename for the War Room attachment.
    """
    # 1) Honour an explicit server-supplied filename.
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', content_disposition or "")
    if match:
        candidate = os.path.basename(match.group(1).strip())
        if candidate:
            return candidate

    # 2) Sniff the payload: reports come back as a ZIP archive; JSON/CSV may be served raw.
    if content[:4] == b"PK\x03\x04":
        ext = "zip"
    elif content[:1] in (b"{", b"["):
        ext = "json"
    else:
        ext = {"CSV": "csv", "JSON": "json", "ALL": "zip"}.get(file_format, "dat")

    return f"redteam_report_{job_id}.{ext}"


def redteam_report_download_command(client: Client, args: dict[str, Any]) -> dict:
    """Download a Red Team scan report and attach it to the War Room.

    The download endpoint streams the report back as raw bytes — a ZIP archive bundling
    the report file(s) (e.g. ``report_summary.csv``), not a JSON envelope. This fetches
    the raw ``Response`` so the ``Content-Disposition``/``Content-Type`` headers can name
    the file, then returns it as a War Room attachment.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        dict: A ``fileResult`` entry carrying the report bytes.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    file_format = (args.get("file_format") or "CSV").upper()
    if file_format not in ("CSV", "JSON", "ALL"):
        raise ValueError("file_format must be one of: CSV, JSON, ALL.")

    # The download endpoint lives on the data plane and returns the report file as raw
    # bytes (a ZIP archive), so request the full Response instead of JSON parsing.
    # Reference: ./knowledge/versions/20260817/prisma-airs-sdk-main/src/red-team/reports-client.ts (downloadReport)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_REPORTS_ENDPOINT}/{job_id}/download",
        params={"file_format": file_format},
        use_redteam_data=True,
        resp_type="response",
    )

    content = response.content
    content_disposition = response.headers.get("Content-Disposition", "")
    filename = _report_download_filename(job_id, file_format, content, content_disposition)

    return fileResult(filename=filename, data=content)


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
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/status", use_redteam_mgmt=True)

    # Parse response according to EulaResponseSchema
    # Fields: uuid, is_accepted, accepted_at, accepted_by_user_id
    eula_info = {
        "uuid": response.get("uuid"),
        "is_accepted": response.get("is_accepted"),
        "accepted_at": response.get("accepted_at"),
        "accepted_by_user_id": response.get("accepted_by_user_id"),
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
        raw_response=response,
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
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/content", use_redteam_mgmt=True)

    # Parse response according to EulaContentResponseSchema
    # Fields: content (string - full EULA text)
    eula_content = response.get("content", "")

    eula_info = {"content": eula_content, "content_length": len(eula_content)}

    # Truncate content for display (show first 1000 chars)
    display_content = eula_content[:1000]
    if len(eula_content) > 1000:
        display_content += (
            f"\n\n... (truncated, {len(eula_content) - 1000} more characters)\n\nFull content available in context output."
        )

    readable_output = (
        f"## Red Team EULA Content\n\n**Length:** {len(eula_content)} characters\n\n"
        f"**Content Preview:**\n\n```\n{display_content}\n```"
    )

    return CommandResults(
        # Own key, separate from the acceptance record (RedTeamEula) written by status/accept.
        # Singleton current-state snapshot of the legal text; content_length is not an identity, so no key field.
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamEulaContent",
        outputs_key_field=None,
        outputs=eula_info,
        readable_output=readable_output,
        raw_response=response,
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
    content_response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/content", use_redteam_mgmt=True)

    eula_content = content_response.get("content", "")
    if not eula_content:
        raise ValueError("Failed to retrieve EULA content")

    # Build request body according to EulaAcceptRequestSchema
    # Reference: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaAcceptRequestSchema)
    # Fields: eula_content (required), accepted_at (optional)
    request_body = {"eula_content": eula_content}

    # Optional accepted_at timestamp (will use server time if not provided)
    if args.get("accepted_at"):
        request_body["accepted_at"] = args.get("accepted_at")

    # Call Red Team EULA accept endpoint
    # SDK schema: ./knowledge/prisma-airs-sdk-main/src/models/red-team.ts (EulaResponseSchema)
    response = client.http_request(
        method="POST", url_suffix=f"{RED_TEAM_EULA_ENDPOINT}/accept", json_data=request_body, use_redteam_mgmt=True
    )

    # Parse response according to EulaResponseSchema
    # Fields: uuid, is_accepted, accepted_at, accepted_by_user_id
    eula_info = {
        "uuid": response.get("uuid"),
        "is_accepted": response.get("is_accepted"),
        "accepted_at": response.get("accepted_at"),
        "accepted_by_user_id": response.get("accepted_by_user_id"),
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
        raw_response=response,
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
    request_body = {"prompt": prompt_text, "prompt_set_id": prompt_set_uuid}

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
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    if response.get("goal"):
        prompt_info["goal"] = response.get("goal")
    if response.get("properties"):
        prompt_info["properties"] = response.get("properties")

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Created",
        prompt_info,
        headers=["uuid", "prompt_set_id", "status", "active", "user_defined_goal", "prompt", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptCreate",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response,
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
        use_redteam_mgmt=True,
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
            "updated_at": prompt.get("updated_at"),
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
            readable_output += (
                f"| {prompt.get('uuid', 'N/A')} | {prompt.get('status', 'N/A')} "
                f"| {prompt.get('active', 'N/A')} | {prompt.get('user_defined_goal', 'N/A')} | {prompt_preview} |\n"
            )
    else:
        readable_output = "## No prompts found in this prompt set"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPrompts",
        outputs_key_field="uuid",
        outputs=prompts_list,
        readable_output=readable_output,
        raw_response=response,
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
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = ["goal", "properties", "property_assignments", "detector_category", "severity", "extra_info"]
    for field in optional_fields:
        if response.get(field):
            prompt_info[field] = response.get(field)

    # Create detailed readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Details",
        prompt_info,
        headers=[
            "uuid",
            "prompt_set_id",
            "status",
            "active",
            "user_defined_goal",
            "prompt",
            "goal",
            "detector_category",
            "severity",
            "created_at",
            "updated_at",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptGet",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response,
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
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = ["goal", "properties", "property_assignments", "detector_category", "severity", "extra_info"]
    for field in optional_fields:
        if response.get(field):
            prompt_info[field] = response.get(field)

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Updated",
        prompt_info,
        headers=["uuid", "prompt_set_id", "status", "active", "user_defined_goal", "prompt", "goal", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptUpdate",
        outputs_key_field="uuid",
        outputs=prompt_info,
        readable_output=readable_output,
        raw_response=response,
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
        return_empty_response=True,  # Proper XSOAR pattern for DELETE operations (204 No Content)
    )

    # Parse response according to BaseResponseSchema (optional)
    # Fields: message (optional), status (optional)
    # SDK allows an empty body for successful deletion; http_request returns parsed data (dict) when present.
    result_info = {"prompt_uuid": prompt_uuid, "prompt_set_uuid": prompt_set_uuid, "status": "deleted"}

    if isinstance(response, dict):
        if response.get("message"):
            result_info["message"] = response.get("message")
        if response.get("status"):
            result_info["api_status"] = response.get("status")

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Deleted",
        result_info,
        headers=["prompt_uuid", "prompt_set_uuid", "status", "message"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptDeleted",
        outputs_key_field="prompt_uuid",
        outputs=result_info,
        readable_output=readable_output,
        raw_response=result_info,
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
    request_body: dict[str, Any] = {"name": name}

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
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = [
        "description",
        "property_names",
        "properties",
        "stats",
        "extra_info",
        "version",
        "created_by_user_id",
        "updated_by_user_id",
    ]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Set Created",
        prompt_set_info,
        headers=["uuid", "name", "status", "active", "archive", "description", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetCreate",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response,
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
        use_redteam_mgmt=True,
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
            "updated_at": prompt_set.get("updated_at"),
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
            readable_output += (
                f"| {ps.get('uuid', 'N/A')} | {ps.get('name', 'N/A')} | {ps.get('status', 'N/A')} "
                f"| {ps.get('active', 'N/A')} | {ps.get('archive', 'N/A')} | {desc_preview} |\n"
            )
    else:
        readable_output = "## No prompt sets found"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSets",
        outputs_key_field="uuid",
        outputs=prompt_sets_list,
        readable_output=readable_output,
        raw_response=response,
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
        method="GET", url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}", use_redteam_mgmt=True
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = [
        "description",
        "property_names",
        "properties",
        "stats",
        "extra_info",
        "version",
        "created_by_user_id",
        "updated_by_user_id",
    ]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create detailed readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Set Details",
        prompt_set_info,
        headers=[
            "uuid",
            "name",
            "status",
            "active",
            "archive",
            "description",
            "version",
            "created_by_user_id",
            "updated_by_user_id",
            "created_at",
            "updated_at",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetGet",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response,
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
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = [
        "description",
        "property_names",
        "properties",
        "stats",
        "extra_info",
        "version",
        "created_by_user_id",
        "updated_by_user_id",
    ]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    readable_output = tableToMarkdown(
        "Red Team Prompt Set Updated",
        prompt_set_info,
        headers=["uuid", "name", "status", "active", "archive", "description", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetUpdate",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"archive": archive_bool}

    # Call Red Team Custom Attack endpoint to archive/unarchive prompt set
    # SDK: ./knowledge/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (archivePromptSet method)
    # Endpoint: PUT /v1/custom-attack/custom-prompt-set/{uuid}/archive
    response = client.http_request(
        method="PUT",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}/archive",
        json_data=request_body,
        use_redteam_mgmt=True,
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
        "updated_at": response.get("updated_at"),
    }

    # Add optional fields if present
    optional_fields = [
        "description",
        "property_names",
        "properties",
        "stats",
        "extra_info",
        "version",
        "created_by_user_id",
        "updated_by_user_id",
    ]
    for field in optional_fields:
        if response.get(field):
            prompt_set_info[field] = response.get(field)

    # Create readable output
    action = "Archived" if archive_bool else "Unarchived"
    readable_output = tableToMarkdown(
        f"Red Team Prompt Set {action}",
        prompt_set_info,
        headers=["uuid", "name", "status", "active", "archive", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetArchive",
        outputs_key_field="uuid",
        outputs=prompt_set_info,
        readable_output=readable_output,
        raw_response=response,
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
    response = client.http_request(method="POST", url_suffix=RED_TEAM_REGISTRY_CREDENTIALS_ENDPOINT, use_redteam_mgmt=True)

    # Parse response according to RegistryCredentialsSchema
    # Fields: token (required), expiry (required)
    credentials_info = {"token": response.get("token"), "expiry": response.get("expiry")}

    # Create readable output
    # Truncate token for security (show only first and last 8 characters)
    token_display = str(credentials_info.get("token") or "")
    if len(token_display) > 20:
        token_truncated = f"{token_display[:8]}...{token_display[-8:]}"
    else:
        token_truncated = token_display

    # Display the truncated token in the table (full token remains in context for playbook use)
    readable_output = tableToMarkdown(
        "Red Team Registry Credentials",
        {"token": token_truncated, "expiry": credentials_info.get("expiry")},
        headers=["token", "expiry"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )
    readable_output += (
        "\n\n**Note:** These credentials are used to pull Red Team scanner container images from the Prisma AIRs registry."
    )

    return CommandResults(
        # Singleton current-state credentials (expiry is a timestamp, not an identity), so no key field.
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamRegistryCredentials",
        outputs_key_field=None,
        outputs=credentials_info,
        readable_output=readable_output,
        raw_response=response,
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
        resp_type="text",  # CSV response is plain text, not JSON
    )

    # Response is CSV string like:
    # prompt,goal
    # This is a sample prompt,Optional goal text (leave empty for AI-generated goal)

    # Generate filename based on UUID
    filename = f"prompt_set_template_{uuid}.csv"

    # Return file using XSOAR fileResult() pattern
    # Reference: knowledge/CLAUDE.md section "File Handling in XSOAR"
    # fileResult is imported from CommonServerPython at the top of this file
    return fileResult(
        filename=filename,
        data=response,
        file_type=None,  # Auto-detect from extension
    )


def redteam_prompt_sets_upload_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Upload CSV file with prompts to a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
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
        if not file_name.lower().endswith(".csv"):
            raise ValueError(f"File must be a CSV file. Got: {file_name}")

        # Read CSV file content
        with open(file_path, "rb") as f:
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
    full_url = f"{client._base_url}{RED_TEAM_MGMT_PATH}{url_suffix}"

    # Prepare files for multipart upload
    files = {"file": (file_name, file_content, "text/csv")}

    # Get OAuth token
    token = client.get_access_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Make request with files (multipart/form-data)
    response = client._http_request(
        method="POST", full_url=full_url, params=params, headers=headers, files=files, resp_type="json"
    )

    # Parse response according to BaseResponseSchema
    # Fields: message (string), status (number)
    message = response.get("message", "Upload completed")
    status_code = response.get("status", 200)

    upload_info = {"message": message, "status": status_code, "prompt_set_uuid": uuid, "file_name": file_name}

    # Create readable output
    readable_output = "## Red Team Prompt Set Upload\n\n"
    readable_output += f"**Status:** {status_code}\n\n"
    readable_output += f"**Message:** {message}\n\n"
    readable_output += f"**Prompt Set UUID:** {uuid}\n\n"
    readable_output += f"**File:** {file_name}\n"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetUpload",
        outputs_key_field="prompt_set_uuid",
        outputs=upload_info,
        readable_output=readable_output,
        raw_response=response,
    )


def _parse_prompt_set_reference(item: Any) -> dict[str, Any]:
    """Normalize a prompt-set reference object into a flat context dict.

    Args:
        item: A single reference object from the API (CustomPromptSetReferenceSchema).

    Returns:
        dict: Normalized reference record.
    """
    data = item if isinstance(item, dict) else {}
    return {
        "uuid": data.get("uuid"),
        "name": data.get("name"),
        "status": data.get("status"),
        "active": data.get("active"),
        "version": data.get("version"),
        "tsg_id": data.get("tsg_id"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }


def redteam_prompt_sets_reference_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Resolve a prompt set reference (data-plane consumption view).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - uuid (required): UUID of the prompt set.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # Call Red Team Custom Attack prompt-set reference endpoint (mgmt-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (getPromptSetReference)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetReferenceSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}/reference",
        use_redteam_mgmt=True,
    )

    reference = _parse_prompt_set_reference(response)

    readable_output = tableToMarkdown(
        "Red Team Prompt Set Reference",
        [reference],
        headers=["uuid", "name", "status", "active", "version", "tsg_id", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetReference",
        outputs_key_field="uuid",
        outputs=reference,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_prompt_sets_version_info_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get version information for a prompt set.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - uuid (required): UUID of the prompt set.
              - version (optional): A specific version ID to query.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    version = args.get("version")
    params = {"version": version} if version else None

    # Call Red Team Custom Attack prompt-set version-info endpoint (mgmt-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (getPromptSetVersionInfo)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetVersionInfoSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/custom-prompt-set/{uuid}/version-info",
        params=params,
        use_redteam_mgmt=True,
    )

    data = response if isinstance(response, dict) else {}
    version_info = {
        "uuid": data.get("uuid") or uuid,
        "status": data.get("status"),
        "is_latest": data.get("is_latest"),
        "version": data.get("version"),
        "snapshot_created_at": data.get("snapshot_created_at"),
        "stats": data.get("stats"),
    }

    # Flatten stats for the human-readable table while keeping the nested object in context.
    stats = version_info.get("stats") or {}
    readable_row = {
        "uuid": version_info["uuid"],
        "status": version_info["status"],
        "is_latest": version_info["is_latest"],
        "version": version_info["version"],
        "total_prompts": stats.get("total_prompts") if isinstance(stats, dict) else None,
        "active_prompts": stats.get("active_prompts") if isinstance(stats, dict) else None,
        "inactive_prompts": stats.get("inactive_prompts") if isinstance(stats, dict) else None,
        "snapshot_created_at": version_info["snapshot_created_at"],
    }

    readable_output = tableToMarkdown(
        "Red Team Prompt Set Version Info",
        [readable_row],
        headers=[
            "uuid",
            "status",
            "is_latest",
            "version",
            "total_prompts",
            "active_prompts",
            "inactive_prompts",
            "snapshot_created_at",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetVersionInfo",
        outputs_key_field="uuid",
        outputs=version_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_prompt_sets_active_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List active prompt sets (data-plane consumption view).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team Custom Attack active prompt-sets endpoint (mgmt-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attacks-client.ts (listActivePromptSets)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomPromptSetListActiveSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/active-custom-prompt-sets",
        use_redteam_mgmt=True,
    )

    raw_list = response.get("data") or [] if isinstance(response, dict) else []
    prompt_sets = [_parse_prompt_set_reference(item) for item in raw_list]

    readable_output = tableToMarkdown(
        f"Red Team Active Prompt Sets ({len(prompt_sets)})",
        prompt_sets,
        headers=["uuid", "name", "status", "active", "version", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPromptSetActive",
        outputs_key_field="uuid",
        outputs=prompt_sets,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_properties_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List custom-attack property names.

    Property names (e.g., category, severity) form the metadata vocabulary used to tag and
    filter custom attack prompts. Read-only.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    # Call Red Team Custom Attack property-names endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/custom-attacks-client.ts (getPropertyNames)
    # Endpoint: GET /v1/custom-attack/property-names
    # Response: PropertyNamesListResponse - { data: string[] }
    url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/property-names"
    response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_mgmt=True)

    names = response.get("data") or [] if isinstance(response, dict) else []

    readable_output = tableToMarkdown(
        "Red Team Custom-Attack Property Names",
        [{"Property Name": name} for name in names],
        headers=["Property Name"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamProperty",
        outputs=names,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_properties_values_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get allowed values for one or more custom-attack property names.

    Provide either property_name (single lookup) or property_names (comma-separated list for
    a batch lookup). Read-only. Both response shapes are normalized to a flat list of
    {name, values} entries.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    property_name = args.get("property_name")
    property_names = argToList(args.get("property_names"))

    if not property_name and not property_names:
        raise ValueError("Provide either property_name (single) or property_names (comma-separated).")

    normalized: list[dict[str, Any]] = []

    if property_names:
        # Batch lookup across multiple property names.
        # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/custom-attacks-client.ts
        #   (getPropertyValuesMultiple)
        # Endpoint: GET /v1/custom-attack/property-values?property_names=a&property_names=b
        # Response: PropertyValuesMultipleResponse - { data: { name: string[] } }
        url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/property-values"
        response = client.http_request(
            method="GET",
            url_suffix=url_suffix,
            params={"property_names": property_names},
            use_redteam_mgmt=True,
        )
        values_map = response.get("data") or {} if isinstance(response, dict) else {}
        for name, values in values_map.items():
            normalized.append({"name": name, "values": values or []})
    else:
        # Single-name lookup.
        # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/custom-attacks-client.ts
        #   (getPropertyValues)
        # Endpoint: GET /v1/custom-attack/property-values/{name}
        # Response: PropertyValuesResponse - { name, values: string[] }
        url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/property-values/{property_name}"
        response = client.http_request(method="GET", url_suffix=url_suffix, use_redteam_mgmt=True)
        result = response if isinstance(response, dict) else {}
        normalized.append({"name": result.get("name", property_name), "values": result.get("values") or []})

    # Build a readable table with one row per (name, value) pair.
    readable_rows = []
    for entry in normalized:
        for value in entry["values"]:
            readable_rows.append({"Property Name": entry["name"], "Value": value})
        if not entry["values"]:
            readable_rows.append({"Property Name": entry["name"], "Value": None})

    readable_output = tableToMarkdown(
        "Red Team Custom-Attack Property Values",
        readable_rows,
        headers=["Property Name", "Value"],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPropertyValue",
        outputs_key_field="name",
        outputs=normalized,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_properties_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new custom-attack property name.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    name = args.get("name")
    if not name:
        raise ValueError("name is required")

    # Call Red Team Custom Attack property-names endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/custom-attacks-client.ts (createPropertyName)
    # Endpoint: POST /v1/custom-attack/property-names
    # Body: PropertyNameCreateRequest - { name }
    # Response: BaseResponse (optional) - { message, status }
    url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/property-names"
    response = client.http_request(method="POST", url_suffix=url_suffix, json_data={"name": name}, use_redteam_mgmt=True)

    result = response if isinstance(response, dict) else {}
    create_info = {
        "name": name,
        "message": result.get("message"),
        "status": result.get("status"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Custom-Attack Property Name Created: {name}",
        [create_info],
        headers=["name", "message", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPropertyCreate",
        outputs_key_field="name",
        outputs=create_info,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_properties_add_value_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add an allowed value to an existing custom-attack property name.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    property_name = args.get("property_name")
    property_value = args.get("property_value")
    if not property_name:
        raise ValueError("property_name is required")
    if not property_value:
        raise ValueError("property_value is required")

    # Call Red Team Custom Attack property-values endpoint
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/red-team/custom-attacks-client.ts (createPropertyValue)
    # Endpoint: POST /v1/custom-attack/property-values
    # Body: PropertyValueCreateRequest - { property_name, property_value }
    # Response: BaseResponse - { message, status }
    url_suffix = f"{RED_TEAM_CUSTOM_ATTACK_ENDPOINT}/property-values"
    response = client.http_request(
        method="POST",
        url_suffix=url_suffix,
        json_data={"property_name": property_name, "property_value": property_value},
        use_redteam_mgmt=True,
    )

    result = response if isinstance(response, dict) else {}
    add_info = {
        "property_name": property_name,
        "property_value": property_value,
        "message": result.get("message"),
        "status": result.get("status"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Custom-Attack Property Value Added: {property_name}",
        [add_info],
        headers=["property_name", "property_value", "message", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamPropertyValueCreate",
        outputs_key_field="property_name",
        outputs=add_info,
        readable_output=readable_output,
        raw_response=response,
    )


def _normalize_sentiment(response: Any, job_id: str) -> dict[str, Any]:
    """Normalize a sentiment API response into a flat context dict.

    Args:
        response: Raw API response (expected shape: {job_id, up_vote?, down_vote?}).
        job_id: The job UUID the sentiment applies to (fallback if absent in response).

    Returns:
        dict: Normalized sentiment record.
    """
    data = response if isinstance(response, dict) else {}
    return {
        "job_id": data.get("job_id") or job_id,
        "up_vote": data.get("up_vote"),
        "down_vote": data.get("down_vote"),
    }


def redteam_sentiment_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the sentiment (up/down-vote) recorded for a Red Team scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team sentiment get endpoint (data-plane).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/client.ts (getSentiment)
    # SDK schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (SentimentResponseSchema)
    response = client.http_request(method="GET", url_suffix=f"{RED_TEAM_SENTIMENT_ENDPOINT}/{job_id}", use_redteam_data=True)

    sentiment = _normalize_sentiment(response, job_id)

    readable_output = tableToMarkdown(
        f"Red Team Report Sentiment: {sentiment['job_id']}",
        [sentiment],
        headers=["job_id", "up_vote", "down_vote"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamSentiment",
        outputs_key_field="job_id",
        outputs=sentiment,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_sentiment_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update the sentiment (up/down-vote) for a Red Team scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    vote = (args.get("vote") or "").lower()
    if vote not in ("up", "down"):
        raise ValueError("vote is required and must be one of: up, down.")

    # Map the single 'vote' arg to the API's boolean flags.
    # SDK body schema: {job_id, up_vote?, down_vote?}
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (SentimentRequestSchema)
    request_body: dict[str, Any] = {"job_id": job_id}
    if vote == "up":
        request_body["up_vote"] = True
    else:
        request_body["down_vote"] = True

    # Call Red Team sentiment update endpoint (data-plane).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/client.ts (updateSentiment)
    response = client.http_request(
        method="POST", url_suffix=RED_TEAM_SENTIMENT_ENDPOINT, json_data=request_body, use_redteam_data=True
    )

    sentiment = _normalize_sentiment(response, job_id)
    # Fall back to the requested vote if the API echoes an empty body.
    if sentiment["up_vote"] is None and sentiment["down_vote"] is None:
        sentiment["up_vote"] = vote == "up"
        sentiment["down_vote"] = vote == "down"

    readable_output = tableToMarkdown(
        f"Red Team Report Sentiment Updated: {sentiment['job_id']}",
        [sentiment],
        headers=["job_id", "up_vote", "down_vote"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamSentiment",
        outputs_key_field="job_id",
        outputs=sentiment,
        readable_output=readable_output,
        raw_response=response,
    )


def _build_report_listing_params(args: dict[str, Any]) -> dict[str, Any]:
    """Build the canonical skip/limit/search listing params shared by report list endpoints.

    Args:
        args: Command arguments from XSOAR.

    Returns:
        dict: Query parameters populated only with the provided listing fields.
    """
    params: dict[str, Any] = {}
    skip = arg_to_number(args.get("skip"))
    if skip is not None:
        params["skip"] = str(skip)
    limit = arg_to_number(args.get("limit"))
    if limit is not None:
        params["limit"] = str(limit)
    search = args.get("search")
    if search:
        params["search"] = search
    return params


def _parse_prompt_set_summary(item: Any) -> dict[str, Any]:
    """Normalize a custom-attack prompt-set summary object.

    Args:
        item: A single prompt-set summary object from the API.

    Returns:
        dict: Normalized prompt-set summary fields.
    """
    data = item if isinstance(item, dict) else {}
    return {
        "prompt_set_id": data.get("prompt_set_id"),
        "prompt_set_name": data.get("prompt_set_name"),
        "total_prompts": data.get("total_prompts"),
        "total_attacks": data.get("total_attacks"),
        "total_threats": data.get("total_threats"),
        "failed_attacks": data.get("failed_attacks"),
        "threat_rate": data.get("threat_rate"),
        "property_names": data.get("property_names"),
        "property_statistics": data.get("property_statistics"),
    }


def _parse_prompt_detail(item: Any) -> dict[str, Any]:
    """Normalize a custom-attack prompt detail object.

    Args:
        item: A single prompt detail object from the API.

    Returns:
        dict: Normalized prompt detail fields.
    """
    data = item if isinstance(item, dict) else {}
    return {
        "prompt_id": data.get("prompt_id"),
        "prompt_text": data.get("prompt_text"),
        "goal": data.get("goal"),
        "user_defined_goal": data.get("user_defined_goal"),
        "properties": data.get("properties"),
        "attack_id": data.get("attack_id"),
        "threat": data.get("threat"),
        "attack_outputs": data.get("attack_outputs"),
        "asr": data.get("asr"),
        "prompt_set_id": data.get("prompt_set_id"),
        "prompt_set_name": data.get("prompt_set_name"),
    }


def redteam_custom_attack_report_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the custom-attack report summary for a scan job.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team custom-attacks report endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getReport)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomAttackReportResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/report/{job_id}",
        use_redteam_data=True,
    )

    data = response if isinstance(response, dict) else {}
    report = {
        "job_id": job_id,
        "total_prompts": data.get("total_prompts"),
        "total_attacks": data.get("total_attacks"),
        "total_threats": data.get("total_threats"),
        "failed_attacks": data.get("failed_attacks"),
        "score": data.get("score"),
        "asr": data.get("asr"),
        "custom_attack_reports": data.get("custom_attack_reports"),
        "property_statistics": data.get("property_statistics"),
    }

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Report: {job_id}",
        [report],
        headers=["total_prompts", "total_attacks", "total_threats", "failed_attacks", "score", "asr"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackReport",
        outputs_key_field="job_id",
        outputs=report,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attack_report_prompt_sets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the prompt-set breakdown for a custom-attack scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team custom-attacks report prompt-sets endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getPromptSets)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (PromptSetsReportResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/report/{job_id}/prompt-sets",
        use_redteam_data=True,
    )

    data = response if isinstance(response, dict) else {}
    raw_sets = data.get("prompt_sets") or []
    prompt_sets = [_parse_prompt_set_summary(item) for item in raw_sets]

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Report Prompt Sets ({data.get('total_prompt_sets', len(prompt_sets))})",
        prompt_sets,
        headers=[
            "prompt_set_id",
            "prompt_set_name",
            "total_prompts",
            "total_attacks",
            "total_threats",
            "failed_attacks",
            "threat_rate",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackReportPromptSet",
        outputs_key_field="prompt_set_id",
        outputs=prompt_sets,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attack_report_prompts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List prompts for a specific prompt set within a custom-attack scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.
              - prompt_set_id (required): The prompt-set UUID.
              - is_threat (optional): Filter to threat prompts only.
              - skip / limit / search (optional): Pagination and search.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")
    prompt_set_id = args.get("prompt_set_id")
    if not prompt_set_id:
        raise ValueError("prompt_set_id is required")

    params = _build_report_listing_params(args)
    is_threat = args.get("is_threat")
    if is_threat is not None:
        params["is_threat"] = str(argToBoolean(is_threat)).lower()

    # Call Red Team custom-attacks report prompts-by-set endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getPromptsBySet)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (PromptDetailResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/report/{job_id}/prompt-set/{prompt_set_id}/prompts",
        params=params or None,
        use_redteam_data=True,
    )

    raw_prompts: list = response if isinstance(response, list) else []
    prompts = [_parse_prompt_detail(item) for item in raw_prompts]

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Prompts ({len(prompts)})",
        prompts,
        headers=["prompt_id", "prompt_text", "goal", "threat", "asr", "attack_id"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackPrompt",
        outputs_key_field="prompt_id",
        outputs=prompts,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attack_report_prompt_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get details for a single prompt within a custom-attack scan report.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.
              - prompt_id (required): The prompt UUID.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")
    prompt_id = args.get("prompt_id")
    if not prompt_id:
        raise ValueError("prompt_id is required")

    # Call Red Team custom-attacks report prompt-detail endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getPromptDetail)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (PromptDetailResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/report/{job_id}/prompt/{prompt_id}",
        use_redteam_data=True,
    )

    prompt = _parse_prompt_detail(response)

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Prompt: {prompt.get('prompt_id') or prompt_id}",
        [prompt],
        headers=["prompt_id", "prompt_text", "goal", "user_defined_goal", "threat", "asr", "attack_id", "prompt_set_name"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackPrompt",
        outputs_key_field="prompt_id",
        outputs=prompt,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attacks_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List custom attacks for a scan job.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.
              - threat (optional): Filter to threat attacks only.
              - prompt_set_id (optional): Filter by prompt-set UUID.
              - property_value (optional): Filter by property value.
              - skip / limit / search (optional): Pagination and search.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    params = _build_report_listing_params(args)
    threat = args.get("threat")
    if threat is not None:
        params["threat"] = str(argToBoolean(threat)).lower()
    if args.get("prompt_set_id"):
        params["prompt_set_id"] = args.get("prompt_set_id")
    if args.get("property_value"):
        params["property_value"] = args.get("property_value")

    # Call Red Team custom-attacks list endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (listCustomAttacks)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomAttacksListResponseSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/job/{job_id}/list-custom-attacks",
        params=params or None,
        use_redteam_data=True,
    )

    data = response if isinstance(response, dict) else {}
    attacks = data.get("data") or []
    summary = {
        "job_id": job_id,
        "total_attacks": data.get("total_attacks"),
        "total_threats": data.get("total_threats"),
        "total_items": (data.get("pagination") or {}).get("total_items") if isinstance(data.get("pagination"), dict) else None,
    }

    readable_output = tableToMarkdown(
        f"Red Team Custom Attacks (total_attacks={summary['total_attacks']}, total_threats={summary['total_threats']})",
        attacks if attacks else [summary],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttack",
        outputs_key_field="uuid",
        outputs={"job_id": job_id, "attacks": attacks, "summary": summary},
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attack_outputs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the target outputs for a single custom attack.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.
              - attack_id (required): The custom-attack UUID.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")
    attack_id = args.get("attack_id")
    if not attack_id:
        raise ValueError("attack_id is required")

    # Call Red Team custom-attacks attack-outputs endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getAttackOutputs)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (CustomAttackOutputSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/job/{job_id}/attack/{attack_id}/list-outputs",
        use_redteam_data=True,
    )

    raw_outputs: list = response if isinstance(response, list) else []
    outputs = []
    for item in raw_outputs:
        data = item if isinstance(item, dict) else {}
        outputs.append(
            {
                "uuid": data.get("uuid"),
                "tsg_id": data.get("tsg_id"),
                "custom_attack_id": data.get("custom_attack_id"),
                "job_id": data.get("job_id"),
                "target_id": data.get("target_id"),
                "output": data.get("output"),
                "threat": data.get("threat"),
                "marked_safe": data.get("marked_safe"),
            }
        )

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Outputs ({len(outputs)})",
        outputs,
        headers=["uuid", "custom_attack_id", "target_id", "output", "threat", "marked_safe"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackOutput",
        outputs_key_field="uuid",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def redteam_custom_attack_property_stats_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get per-property attack-success statistics for a custom-attack scan.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.
              - job_id (required): The job UUID of the custom-attack scan.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    job_id = args.get("job_id")
    if not job_id:
        raise ValueError("job_id is required")

    # Call Red Team custom-attacks property-stats endpoint (data-plane).
    # SDK: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/red-team/custom-attack-reports-client.ts (getPropertyStats)
    # Schema: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/models/red-team.ts (PropertyStatisticSchema)
    response = client.http_request(
        method="GET",
        url_suffix=f"{RED_TEAM_CUSTOM_ATTACKS_ENDPOINT}/job/{job_id}/property-stats",
        use_redteam_data=True,
    )

    raw_stats: list = response if isinstance(response, list) else []
    stats = []
    flat_rows = []
    for item in raw_stats:
        data = item if isinstance(item, dict) else {}
        property_name = data.get("property_name")
        values = data.get("values") or []
        stats.append({"property_name": property_name, "values": values})
        for value in values:
            v = value if isinstance(value, dict) else {}
            flat_rows.append(
                {
                    "property_name": property_name,
                    "value": v.get("value"),
                    "successful_attack_count": v.get("successful_attack_count"),
                    "total_attack_count": v.get("total_attack_count"),
                    "success_rate": v.get("success_rate"),
                }
            )

    readable_output = tableToMarkdown(
        f"Red Team Custom Attack Property Stats ({len(stats)})",
        flat_rows,
        headers=["property_name", "value", "successful_attack_count", "total_attack_count", "success_rate"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}RedTeamCustomAttackPropertyStat",
        outputs_key_field="property_name",
        outputs=stats,
        readable_output=readable_output,
        raw_response=response,
    )


def main() -> None:
    """Main function for Prisma AIRs AI Red Teaming integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
        # Client configuration (scoped credentials for the AI Red Teaming mgmt/data planes)
        base_url = params.get("url", "https://api.sase.paloaltonetworks.com")
        credentials = params.get("credentials", {})
        client_id = credentials.get("identifier", "")
        client_secret = credentials.get("password", "")
        tsg_id = params.get("tsg_id")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)

        headers: dict[str, str] = {}

        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)


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

        elif command == "prisma-airs-redteam-targets-profile":
            return_results(redteam_targets_profile_command(client, args))

        elif command == "prisma-airs-redteam-targets-update-profile":
            return_results(redteam_targets_update_profile_command(client, args))

        elif command == "prisma-airs-redteam-targets-metadata":
            return_results(redteam_targets_metadata_command(client, args))

        elif command == "prisma-airs-redteam-targets-validate-auth":
            return_results(redteam_targets_validate_auth_command(client, args))

        elif command == "prisma-airs-redteam-targets-templates":
            return_results(redteam_targets_templates_command(client, args))

        elif command == "prisma-airs-redteam-targets-error-logs":
            return_results(redteam_targets_error_logs_command(client, args))

        # Red Team Dashboard / Metering telemetry (5 commands)
        elif command == "prisma-airs-redteam-scan-error-logs":
            return_results(redteam_scan_error_logs_command(client, args))

        elif command == "prisma-airs-redteam-dashboard-scan-statistics":
            return_results(redteam_dashboard_scan_statistics_command(client, args))

        elif command == "prisma-airs-redteam-dashboard-score-trend":
            return_results(redteam_dashboard_score_trend_command(client, args))

        elif command == "prisma-airs-redteam-metering-quota":
            return_results(redteam_metering_quota_command(client, args))

        elif command == "prisma-airs-redteam-dashboard-overview":
            return_results(redteam_dashboard_overview_command(client, args))

        elif command == "prisma-airs-redteam-instances-create":
            return_results(redteam_instances_create_command(client, args))

        elif command == "prisma-airs-redteam-instances-get":
            return_results(redteam_instances_get_command(client, args))

        elif command == "prisma-airs-redteam-instances-update":
            return_results(redteam_instances_update_command(client, args))

        elif command == "prisma-airs-redteam-instances-delete":
            return_results(redteam_instances_delete_command(client, args))

        elif command == "prisma-airs-redteam-devices-create":
            return_results(redteam_devices_create_command(client, args))

        elif command == "prisma-airs-redteam-devices-update":
            return_results(redteam_devices_update_command(client, args))

        elif command == "prisma-airs-redteam-devices-delete":
            return_results(redteam_devices_delete_command(client, args))

        elif command == "prisma-airs-redteam-adapters-list":
            return_results(redteam_adapters_list_command(client, args))

        elif command == "prisma-airs-redteam-adapters-get":
            return_results(redteam_adapters_get_command(client, args))

        elif command == "prisma-airs-redteam-adapters-create":
            return_results(redteam_adapters_create_command(client, args))

        elif command == "prisma-airs-redteam-adapters-update":
            return_results(redteam_adapters_update_command(client, args))

        elif command == "prisma-airs-redteam-adapters-delete":
            return_results(redteam_adapters_delete_command(client, args))

        elif command == "prisma-airs-redteam-adapters-validate":
            return_results(redteam_adapters_validate_command(client, args))

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

        # Red Team Network Broker Channels Commands (5 commands)
        elif command == "prisma-airs-redteam-network-channels-list":
            return_results(redteam_network_channels_list_command(client, args))

        elif command == "prisma-airs-redteam-network-channels-create":
            return_results(redteam_network_channels_create_command(client, args))

        elif command == "prisma-airs-redteam-network-channels-stats":
            return_results(redteam_network_channels_stats_command(client, args))

        elif command == "prisma-airs-redteam-network-channels-get":
            return_results(redteam_network_channels_get_command(client, args))

        elif command == "prisma-airs-redteam-network-channels-update":
            return_results(redteam_network_channels_update_command(client, args))

        elif command == "prisma-airs-redteam-languages-list":
            return_results(redteam_languages_list_command(client, args))

        elif command == "prisma-airs-redteam-report-get":
            return_results(redteam_report_get_command(client, args))

        elif command == "prisma-airs-redteam-report-attacks-list":
            return_results(redteam_report_attacks_list_command(client, args))

        elif command == "prisma-airs-redteam-report-attack-get":
            return_results(redteam_report_attack_get_command(client, args))

        elif command == "prisma-airs-redteam-report-attack-multi-turn-get":
            return_results(redteam_report_attack_multi_turn_get_command(client, args))

        elif command == "prisma-airs-redteam-report-remediation-get":
            return_results(redteam_report_remediation_get_command(client, args))

        elif command == "prisma-airs-redteam-report-runtime-policy-get":
            return_results(redteam_report_runtime_policy_get_command(client, args))

        elif command == "prisma-airs-redteam-report-goals-list":
            return_results(redteam_report_goals_list_command(client, args))

        elif command == "prisma-airs-redteam-report-goal-streams-list":
            return_results(redteam_report_goal_streams_list_command(client, args))

        elif command == "prisma-airs-redteam-report-stream-get":
            return_results(redteam_report_stream_get_command(client, args))

        elif command == "prisma-airs-redteam-report-download":
            return_results(redteam_report_download_command(client, args))

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

        elif command == "prisma-airs-redteam-prompt-sets-reference":
            return_results(redteam_prompt_sets_reference_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-version-info":
            return_results(redteam_prompt_sets_version_info_command(client, args))

        elif command == "prisma-airs-redteam-prompt-sets-active-list":
            return_results(redteam_prompt_sets_active_list_command(client, args))

        elif command == "prisma-airs-redteam-properties-list":
            return_results(redteam_properties_list_command(client, args))

        elif command == "prisma-airs-redteam-properties-values":
            return_results(redteam_properties_values_command(client, args))

        elif command == "prisma-airs-redteam-properties-create":
            return_results(redteam_properties_create_command(client, args))

        elif command == "prisma-airs-redteam-properties-add-value":
            return_results(redteam_properties_add_value_command(client, args))

        elif command == "prisma-airs-redteam-sentiment-get":
            return_results(redteam_sentiment_get_command(client, args))

        elif command == "prisma-airs-redteam-sentiment-update":
            return_results(redteam_sentiment_update_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-report-get":
            return_results(redteam_custom_attack_report_get_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-report-prompt-sets":
            return_results(redteam_custom_attack_report_prompt_sets_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-report-prompts":
            return_results(redteam_custom_attack_report_prompts_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-report-prompt-get":
            return_results(redteam_custom_attack_report_prompt_get_command(client, args))

        elif command == "prisma-airs-redteam-custom-attacks-list":
            return_results(redteam_custom_attacks_list_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-outputs":
            return_results(redteam_custom_attack_outputs_command(client, args))

        elif command == "prisma-airs-redteam-custom-attack-property-stats":
            return_results(redteam_custom_attack_property_stats_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
