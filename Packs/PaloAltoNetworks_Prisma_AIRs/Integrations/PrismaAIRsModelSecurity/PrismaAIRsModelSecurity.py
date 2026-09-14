import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from PrismaAirsApiModule import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

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
            "created_by": scan.get("created_by"),
        }
        scans.append(scan_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Scans",
        scans,
        headers=["uuid", "model_uri", "eval_outcome", "source_type", "security_group_name", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScan",
        outputs_key_field="uuid",
        outputs=scans,
        readable_output=readable_output,
        raw_response=response,
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
    scan_origin = args.get("scan_origin", "MODEL_SECURITY_API")

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
        "scan_origin": scan_origin,
    }

    # Add optional fields if provided
    if args.get("model_name"):
        request_body["model_name"] = args.get("model_name")
    if args.get("model_author"):
        request_body["model_author"] = args.get("model_author")
    if args.get("model_version"):
        request_body["model_version"] = args.get("model_version")

    # Optional labels: array of {key, value} objects (same JSON format as model-security-labels-add).
    # API constraints: key <= 128 chars, value <= 256 chars, both matching ^[a-zA-Z0-9_-]+$.
    if args.get("labels"):
        labels_json = args.get("labels")
        try:
            labels = json.loads(labels_json or "")
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"labels must be a valid JSON array: {e}")
        if not isinstance(labels, list) or not all(
            isinstance(label, dict) and "key" in label and "value" in label for label in labels
        ):
            raise ValueError("labels must be a JSON array of objects, each with 'key' and 'value' fields")
        request_body["labels"] = labels

    # Call Model Security Data API to create scan
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.create(body)
    # Endpoint: POST /v1/scans (data plane, not management)
    url_suffix = "/v1/scans"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_model_sec_data=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Add labels if returned by the API
    if response.get("labels"):
        scan_info["labels"] = response.get("labels")

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
        removeNull=True,
    )

    # Add helpful notes
    readable_output += f"\n**Scan UUID:** `{scan_info.get('uuid')}`"
    readable_output += f"\n**Status:** {scan_info.get('eval_outcome')} (scan is processing)"
    readable_output += (
        f"\n\n**Next Steps:** Use `!prisma-airs-model-security-scans-get uuid=\"{scan_info.get('uuid')}\"` "
        "to check scan status and results."
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScanCreate",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_data=True)

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
        "total_files_skipped": response.get("total_files_skipped"),
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
        headers=[
            "uuid",
            "eval_outcome",
            "model_uri",
            "security_group_name",
            "source_type",
            "rules_passed",
            "rules_failed",
            "total_rules",
            "updated_at",
        ],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add status-specific notes
    eval_outcome = scan_info.get("eval_outcome")
    if eval_outcome == "PENDING":
        readable_output += "\n\n**Status:** Scan is still processing. Poll this command to check for completion."
    elif eval_outcome == "ALLOWED":
        readable_output += (
            f"\n\n**Status:** ✅ Scan complete - model ALLOWED "
            f"({scan_info.get('rules_passed', 0)} rules passed, {scan_info.get('rules_failed', 0)} failed)"
        )
    elif eval_outcome == "BLOCKED":
        readable_output += f"\n\n**Status:** ❌ Scan complete - model BLOCKED ({scan_info.get('rules_failed', 0)} rules failed)"
        readable_output += (
            f'\n\n**Next Steps:** Use `!prisma-airs-model-security-scans-violations uuid="{uuid}"` to see detailed violations.'
        )

    # Add error details if present
    if scan_info.get("error_code") or scan_info.get("error_message"):
        readable_output += f"\n\n**Error Code:** {scan_info.get('error_code', 'N/A')}"
        readable_output += f"\n**Error Message:** {scan_info.get('error_message', 'N/A')}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityScanGet",
        outputs_key_field="uuid",
        outputs=scan_info,
        readable_output=readable_output,
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    if not uuid:
        raise ValueError("uuid is required")

    # Call Model Security Data API to get scan violations
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getViolations(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/rule-violations (data plane)
    url_suffix = f"/v1/scans/{uuid}/rule-violations"
    params = {"limit": limit, "offset": offset}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

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
        violations.append(
            {
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
                "tsg_id": violation.get("tsg_id"),
            }
        )

    # Create readable output using XSOAR table format
    if violations:
        readable_output = tableToMarkdown(
            f"Model Security Scan Violations (Scan: {uuid})",
            violations,
            headers=["rule_name", "description", "threat", "file", "module", "operator", "rule_instance_state"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
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
        "offset": offset,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityViolation",
        # Wrapper per scan ({scan_uuid, violations[], ...}); key by scan_uuid so re-listing a scan updates its
        # entry and listing a different scan adds a new entry (the wrapper has no top-level uuid).
        outputs_key_field="scan_uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    # Call Model Security Data API to get label keys
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getLabelKeys(opts)
    # Endpoint: GET /v1/scans/label-keys (data plane)
    url_suffix = "/v1/scans/label-keys"
    params = {"limit": limit, "offset": offset}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

    # Parse response - SDK schema: LabelKeyListSchema
    # Response: { pagination: {...}, keys: [...] }
    keys = response.get("keys", [])
    pagination = response.get("pagination", {})

    # Create readable output
    if keys:
        # Convert array of strings to list of dicts for table display
        keys_table = [{"Key": key} for key in keys]
        readable_output = tableToMarkdown("Model Security Label Keys", keys_table, headers=["Key"], removeNull=True)
        readable_output += f"\n\n**Total Keys:** {len(keys)}"
        if pagination.get("total_items"):
            readable_output += f" (showing {offset + 1}-{offset + len(keys)} of {pagination.get('total_items')})"
    else:
        readable_output = "No label keys found"

    # Add context output
    context_output = {"keys": keys, "total_items": pagination.get("total_items"), "limit": limit, "offset": offset}

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelKeys",
        # Global snapshot of all label keys (no per-invocation resource to key on); latest run reflects current state
        outputs_key_field=None,
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    if not key:
        raise ValueError("key is required")

    # Call Model Security Data API to get label values
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getLabelValues(key, opts)
    # Endpoint: GET /v1/scans/label-keys/{key}/values (data plane)
    # Note: SDK uses encodeURIComponent for key in path
    from urllib.parse import quote

    url_suffix = f"/v1/scans/label-keys/{quote(key, safe='')}/values"
    params = {"limit": limit, "offset": offset}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

    # Parse response - SDK schema: LabelValueListSchema
    # Response: { pagination: {...}, values: [...] }
    values = response.get("values", [])
    pagination = response.get("pagination", {})

    # Create readable output
    if values:
        # Convert array of strings to list of dicts for table display
        values_table = [{"Value": value} for value in values]
        readable_output = tableToMarkdown(
            f"Model Security Label Values for Key: {key}", values_table, headers=["Value"], removeNull=True
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
        "offset": offset,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelValues",
        outputs_key_field="key",  # Accumulate by queried label key: different keys add entries, same key updates
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"labels": labels}

    # Call Model Security Data API to add labels
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.addLabels(scanUuid, body)
    # Endpoint: POST /v1/scans/{uuid}/labels (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/labels"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_model_sec_data=True)

    # Response is empty object on success per LabelsResponseSchema
    # Create readable output
    labels_summary = ", ".join([f"{label['key']}={label['value']}" for label in labels])
    readable_output = f"✅ Successfully added {len(labels)} label(s) to scan {scan_uuid}\n\n"
    readable_output += f"**Labels Added:** {labels_summary}"

    # Context output
    context_output = {"scan_uuid": scan_uuid, "labels_added": labels, "success": True}

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsAdd",
        outputs_key_field="scan_uuid",  # Accumulate by scan: different scans add entries, same scan updates
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"labels": labels}

    # Call Model Security Data API to set labels (replace all)
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.setLabels(scanUuid, body)
    # Endpoint: PUT /v1/scans/{uuid}/labels (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/labels"

    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_model_sec_data=True)

    # Response is empty object on success per LabelsResponseSchema
    # Create readable output
    labels_summary = ", ".join([f"{label['key']}={label['value']}" for label in labels])
    readable_output = f"✅ Successfully set {len(labels)} label(s) on scan {scan_uuid}\n\n"
    readable_output += f"**Labels (all previous labels replaced):** {labels_summary}"

    # Context output
    context_output = {"scan_uuid": scan_uuid, "labels_set": labels, "success": True}

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsSet",
        outputs_key_field="scan_uuid",  # Accumulate by scan: different scans add entries, same scan updates
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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

    client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        params=params,
        use_model_sec_data=True,
        return_empty_response=True,  # Proper XSOAR pattern for DELETE operations (204 No Content)
    )

    # Response is void/undefined on success per SDK
    # Create readable output
    keys_summary = ", ".join(keys)
    readable_output = f"✅ Successfully deleted {len(keys)} label key(s) from scan {scan_uuid}\n\n"
    readable_output += f"**Deleted Keys:** {keys_summary}"

    # Context output
    context_output = {"scan_uuid": scan_uuid, "keys_deleted": keys, "success": True}

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityLabelsDelete",
        outputs_key_field="scan_uuid",  # Accumulate by scan: different scans add entries, same scan updates
        outputs=context_output,
        readable_output=readable_output,
        raw_response={},  # Empty response
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_data=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Rule Evaluation",
        [evaluation_info],
        headers=["rule_name", "result", "violation_count", "rule_instance_state", "scan_uuid"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
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
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_data=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Violation Details",
        [violation_info],
        headers=["rule_name", "description", "threat", "file", "module", "operator"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
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
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    if not scan_uuid:
        raise ValueError("scan_uuid is required")

    # Call Model Security Data API to get scan files
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getFiles(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/files (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/files"
    params = {"limit": limit, "offset": offset}

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

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

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
            "tsg_id": file.get("tsg_id"),
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
            removeNull=True,
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
        "offset": offset,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityFiles",
        # Wrapper per scan ({scan_uuid, files[], ...}); key by scan_uuid so re-listing a scan updates its
        # entry and listing a different scan adds a new entry (the wrapper has no top-level uuid).
        outputs_key_field="scan_uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    if not scan_uuid:
        raise ValueError("scan_uuid is required")

    # Call Model Security Data API to get scan rule evaluations
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/scans-client.ts
    # SDK: ScansClient.getEvaluations(scanUuid, opts)
    # Endpoint: GET /v1/scans/{uuid}/evaluations (data plane)
    url_suffix = f"/v1/scans/{scan_uuid}/evaluations"
    params = {"limit": limit, "offset": offset}

    # Add optional filters
    if args.get("sort_field"):
        params["sort_field"] = args.get("sort_field")
    if args.get("sort_order"):
        params["sort_order"] = args.get("sort_order")
    if args.get("result"):
        params["result"] = args.get("result")
    if args.get("rule_instance_uuid"):
        params["rule_instance_uuid"] = args.get("rule_instance_uuid")

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_data=True)

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
            "tsg_id": evaluation.get("tsg_id"),
        }
        evaluations.append(eval_info)

    # Create readable output using XSOAR table format
    if evaluations:
        readable_output = tableToMarkdown(
            f"Model Security Scan Rule Evaluations (Scan: {scan_uuid})",
            evaluations,
            headers=["rule_name", "result", "violation_count", "rule_instance_state", "rule_description"],
            headerTransform=lambda h: h.replace("_", " ").title(),
            removeNull=True,
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
        "offset": offset,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityEvaluations",
        # Wrapper per scan ({scan_uuid, evaluations[], ...}); key by scan_uuid so re-listing a scan updates its
        # entry and listing a different scan adds a new entry (the wrapper has no top-level uuid).
        outputs_key_field="scan_uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
    )


def model_security_models_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Model Security model catalog entries (aggregate over their versions).

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    skip = arg_to_number(args.get("skip"))

    # Call Model Security Data API to list models (read-only catalog).
    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/model-security/models-client.ts (listModels)
    # SDK path: /v1/models (data plane)
    params: dict[str, Any] = {"limit": str(limit) if limit else str(DEFAULT_LIMIT)}
    if skip is not None:
        params["skip"] = str(skip)
    # Optional search/sort passthrough (see ModelSecurityModelListOptions in the SDK).
    for key in ("search_query", "sort_field", "sort_order", "latest_version_scan_time_before", "start_time", "end_time"):
        value = args.get(key)
        if value:
            params[key] = value
    # Array filters serialize as repeated query params (validated against the tenant for network-broker).
    for key in ("latest_version_outcomes", "latest_version_formats", "latest_version_source_types"):
        value = argToList(args.get(key))
        if value:
            params[key] = value

    response = client.http_request(method="GET", url_suffix="/v1/models", params=params, use_model_sec_data=True)

    # Parse response - SDK schema: ModelListSchema ({pagination, models[]}).
    models_raw = response.get("models") or []
    models = [
        {
            "uuid": model.get("uuid"),
            "name": model.get("name"),
            "latest_version_uuid": model.get("latest_version_uuid"),
            "latest_version_revision": model.get("latest_version_revision"),
            "latest_version_outcome": model.get("latest_version_outcome"),
            "latest_version_formats": model.get("latest_version_formats"),
            "latest_version_source_types": model.get("latest_version_source_types"),
            "latest_version_scan_time": model.get("latest_version_scan_time"),
            "created_at": model.get("created_at"),
            "updated_at": model.get("updated_at"),
        }
        for model in models_raw
    ]

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Models",
        models,
        headers=["uuid", "name", "latest_version_revision", "latest_version_outcome", "latest_version_scan_time"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityModel",
        outputs_key_field="uuid",
        outputs=models,
        readable_output=readable_output,
        raw_response=response,
    )


def model_security_models_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single Model Security model by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args["uuid"]

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/model-security/models-client.ts (getModel)
    # SDK path: /v1/models/{uuid} (data plane)
    response = client.http_request(method="GET", url_suffix=f"/v1/models/{uuid}", use_model_sec_data=True)

    model_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "latest_version_uuid": response.get("latest_version_uuid"),
        "latest_version_revision": response.get("latest_version_revision"),
        "latest_version_fingerprint": response.get("latest_version_fingerprint"),
        "latest_version_hf_commit_sha": response.get("latest_version_hf_commit_sha"),
        "latest_version_outcome": response.get("latest_version_outcome"),
        "latest_version_formats": response.get("latest_version_formats"),
        "latest_version_source_types": response.get("latest_version_source_types"),
        "latest_version_scan_time": response.get("latest_version_scan_time"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Model Security Model: {model_info.get('name') or uuid}",
        model_info,
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityModel",
        outputs_key_field="uuid",
        outputs=model_info,
        readable_output=readable_output,
        raw_response=response,
    )


def model_security_models_versions_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the versions (revisions) of a Model Security model.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    model_uuid = args["model_uuid"]
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    skip = arg_to_number(args.get("skip"))
    sort_order = args.get("sort_order")

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/model-security/models-client.ts (listModelVersions)
    # SDK path: /v1/models/{modelUuid}/model-versions (data plane)
    params: dict[str, Any] = {"limit": str(limit) if limit else str(DEFAULT_LIMIT)}
    if skip is not None:
        params["skip"] = str(skip)
    if sort_order:
        params["sort_order"] = sort_order

    response = client.http_request(
        method="GET", url_suffix=f"/v1/models/{model_uuid}/model-versions", params=params, use_model_sec_data=True
    )

    # Parse response - SDK schema: ModelVersionListSchema ({pagination, model_versions[]}).
    versions_raw = response.get("model_versions") or []
    versions = [
        {
            "uuid": version.get("uuid"),
            "model_uuid": version.get("model_uuid"),
            "revision": version.get("revision"),
            "file_count": version.get("file_count"),
            "license": version.get("license"),
            "model_formats": version.get("model_formats"),
            "source_types": version.get("source_types"),
            "last_eval_outcome": version.get("last_eval_outcome"),
            "latest_scan_time": version.get("latest_scan_time"),
            "hf_model_name": version.get("hf_model_name"),
            "hf_organization": version.get("hf_organization"),
        }
        for version in versions_raw
    ]

    readable_output = tableToMarkdown(
        f"Prisma AIRs Model Security Model Versions (model {model_uuid})",
        versions,
        headers=["uuid", "revision", "file_count", "last_eval_outcome", "latest_scan_time"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityModelVersion",
        outputs_key_field="uuid",
        outputs=versions,
        readable_output=readable_output,
        raw_response=response,
    )


def model_security_models_version_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single Model Security model version by UUID.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    uuid = args["uuid"]

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/model-security/models-client.ts (getModelVersion)
    # SDK path: /v1/model-versions/{uuid} (data plane)
    response = client.http_request(method="GET", url_suffix=f"/v1/model-versions/{uuid}", use_model_sec_data=True)

    version_info = {
        "uuid": response.get("uuid"),
        "model_uuid": response.get("model_uuid"),
        "revision": response.get("revision"),
        "fingerprint": response.get("fingerprint"),
        "file_count": response.get("file_count"),
        "license": response.get("license"),
        "model_formats": response.get("model_formats"),
        "source_types": response.get("source_types"),
        "last_eval_outcome": response.get("last_eval_outcome"),
        "latest_scan_time": response.get("latest_scan_time"),
        "hf_model_name": response.get("hf_model_name"),
        "hf_organization": response.get("hf_organization"),
        "hf_commit_sha": response.get("hf_commit_sha"),
        "hf_commit_title": response.get("hf_commit_title"),
        "created_at": response.get("created_at"),
        "updated_at": response.get("updated_at"),
    }

    readable_output = tableToMarkdown(
        f"Prisma AIRs Model Security Model Version: {version_info.get('revision') or uuid}",
        version_info,
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityModelVersion",
        outputs_key_field="uuid",
        outputs=version_info,
        readable_output=readable_output,
        raw_response=response,
    )


def model_security_models_files_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the files of a Model Security model version.

    Args:
        client: Prisma AIRs API client.
        args: Command arguments from XSOAR.

    Returns:
        CommandResults: Results to return to XSOAR.
    """
    model_version_uuid = args["model_version_uuid"]
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    skip = arg_to_number(args.get("skip"))

    # Reference: ./knowledge/versions/0-13-2/prisma-airs-sdk-main/src/model-security/models-client.ts (listModelVersionFiles)
    # SDK path: /v1/model-versions/{modelVersionUuid}/files (data plane); same shape as scan files (FileListSchema).
    params: dict[str, Any] = {"limit": str(limit) if limit else str(DEFAULT_LIMIT)}
    if skip is not None:
        params["skip"] = str(skip)

    response = client.http_request(
        method="GET", url_suffix=f"/v1/model-versions/{model_version_uuid}/files", params=params, use_model_sec_data=True
    )

    # Parse response - SDK schema: FileListSchema ({pagination, files[]}).
    files_raw = response.get("files") or []
    files = [
        {
            "uuid": file.get("uuid"),
            "path": file.get("path"),
            "parent_path": file.get("parent_path"),
            "type": file.get("type"),
            "result": file.get("result"),
            "formats": file.get("formats"),
            "model_version_uuid": file.get("model_version_uuid"),
            "scan_uuid": file.get("scan_uuid"),
        }
        for file in files_raw
    ]

    readable_output = tableToMarkdown(
        f"Prisma AIRs Model Security Model Version Files (version {model_version_uuid})",
        files,
        headers=["uuid", "path", "type", "result", "formats"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityModelFile",
        outputs_key_field="uuid",
        outputs=files,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_mgmt=True)

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
            "tsg_id": group.get("tsg_id"),
        }
        groups.append(group_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Groups",
        groups,
        headers=["uuid", "name", "source_type", "state", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroup",
        outputs_key_field="uuid",
        outputs=groups,
        readable_output=readable_output,
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_mgmt=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        f"Model Security Group: {group_info.get('name')}",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "created_at", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroupGet",  # Query tracking context
        outputs_key_field="uuid",  # Enables array appending for multiple gets
        outputs=group_info,
        readable_output=readable_output,
        raw_response=response,
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
    request_body = {"name": name, "source_type": source_type, "description": description}

    # Call Model Security Management API to create security group
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.create(body)
    # Endpoint: POST /v1/security-groups
    url_suffix = "/v1/security-groups"

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=request_body, use_model_sec_mgmt=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        f"Model Security Group Created: {group_info.get('name')}",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "created_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add helpful note
    readable_output += f"\n**UUID:** `{group_info.get('uuid')}`"
    readable_output += f"\n**State:** {group_info.get('state')} (Group will become ACTIVE after rule instances are configured)"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroupAdd",  # Action tracking context (not state)
        outputs_key_field="uuid",  # Enables array appending for multiple creates
        outputs=group_info,
        readable_output=readable_output,
        raw_response=response,
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
    # Returns: 204 No Content (empty response)
    url_suffix = f"/v1/security-groups/{uuid}"

    # XSOAR Best Practice: Use return_empty_response=True for DELETE operations that return 204
    # This allows BaseClient to handle empty responses gracefully without JSON parsing errors
    # Reference: CommonServerPython BaseClient._http_request() - return_empty_response parameter
    client.http_request(
        method="DELETE",
        url_suffix=url_suffix,
        use_model_sec_mgmt=True,
        return_empty_response=True,  # Proper XSOAR pattern for DELETE operations (204 No Content)
    )

    # Response is void on success per SDK
    # Create context output
    context_output = {"uuid": uuid, "deleted": True, "status": "Successfully deleted"}

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Group Deleted",
        [context_output],
        headers=["uuid", "status"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroupDelete",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
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

    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_model_sec_mgmt=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Updated Model Security Group",
        [group_info],
        headers=["uuid", "name", "description", "source_type", "state", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add update summary
    updates = []
    if name:
        updates.append(f"name → '{name}'")
    if description:
        updates.append(f"description → '{description}'")
    readable_output += f"\n\n**Updated:** {', '.join(updates)}"

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityGroupUpdate",  # Action tracking context (not state)
        outputs_key_field="uuid",  # Enables array appending for multiple updates
        outputs=group_info,
        readable_output=readable_output,
        raw_response=response,
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
    params = {"offset": "0", "limit": str(limit) if limit else "100"}

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_mgmt=True)

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
            "default_state": rule.get("default_state"),
        }
        rules.append(rule_info)

    readable_output = tableToMarkdown(
        "Prisma AIRs Model Security Rules",
        rules,
        headers=["uuid", "name", "rule_type", "default_state"],
        headerTransform=lambda h: h.replace("_", " ").title(),
    )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRule",
        outputs_key_field="uuid",
        outputs=rules,
        readable_output=readable_output,
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_mgmt=True)

    # Parse response - SDK schema: ModelSecurityRuleResponseSchema
    # Fields: uuid, name, description, rule_type, compatible_sources, default_state,
    #         remediation (description, steps, url), editable_fields, constant_values, default_values
    rule_info = {
        "uuid": response.get("uuid"),
        "name": response.get("name"),
        "description": response.get("description"),
        "rule_type": response.get("rule_type"),
        "compatible_sources": response.get("compatible_sources", []),
        "default_state": response.get("default_state"),
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
    basic_info = [
        {
            "UUID": rule_info.get("uuid"),
            "Name": rule_info.get("name"),
            "Type": rule_info.get("rule_type"),
            "Default State": rule_info.get("default_state"),
            "Compatible Sources": ", ".join(rule_info.get("compatible_sources", [])),
        }
    ]

    readable_output = tableToMarkdown(
        "Model Security Rule Details",
        basic_info,
        headers=["UUID", "Name", "Type", "Default State", "Compatible Sources"],
        removeNull=True,
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
        readable_output += (
            f"\n\n**Editable Fields:** {len(editable_fields)} field(s) can be customized "
            "when applying this rule to a security group"
        )

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleGet",
        outputs_key_field="uuid",
        outputs=rule_info,
        readable_output=readable_output,
        raw_response=response,
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
    offset = arg_to_number(args.get("offset", 0)) or 0

    if not security_group_uuid:
        raise ValueError("security_group_uuid is required")

    # Call Model Security Management API to list rule instances
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.listRuleInstances(securityGroupUuid, opts)
    # Endpoint: GET /v1/security-groups/{uuid}/rule-instances (management plane)
    url_suffix = f"/v1/security-groups/{security_group_uuid}/rule-instances"
    params = {"limit": limit, "offset": offset}

    # Add optional filters
    if args.get("security_rule_uuid"):
        params["security_rule_uuid"] = args.get("security_rule_uuid")
    if args.get("state"):
        params["state"] = args.get("state")

    response = client.http_request(method="GET", url_suffix=url_suffix, params=params, use_model_sec_mgmt=True)

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
            "tsg_id": instance.get("tsg_id"),
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
            removeNull=True,
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
        "offset": offset,
    }

    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstance",
        outputs_key_field="uuid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=response,
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
    request_body: dict[str, Any] = {"security_group_uuid": security_group_uuid}

    # Add optional state update
    if state:
        request_body["state"] = state

    # Add optional field_values update (JSON object with custom rule configuration)
    # Note: field_values is a JSON object, so we expect it as a JSON string in args
    if args.get("field_values"):
        import json

        try:
            request_body["field_values"] = json.loads(args.get("field_values", ""))
        except json.JSONDecodeError as e:
            raise ValueError(f"field_values must be valid JSON: {e}")

    # Call Model Security Management API to update rule instance
    # Reference: ./knowledge/versions/current/prisma-airs-sdk/src/model-security/security-groups-client.ts
    # SDK: SecurityGroupsClient.updateRuleInstance(securityGroupUuid, ruleInstanceUuid, body)
    # Endpoint: PUT /v1/security-groups/{uuid}/rule-instances/{ruleInstanceUuid} (management plane)
    url_suffix = f"/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}"

    response = client.http_request(method="PUT", url_suffix=url_suffix, json_data=request_body, use_model_sec_mgmt=True)

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
        "tsg_id": response.get("tsg_id"),
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
        removeNull=True,
    )

    # Add helpful context about the update
    if state:
        readable_output += f"\n\n**State Updated:** {state}"
    if response.get("field_values"):
        readable_output += f"\n**Custom Field Values:** {len(response.get('field_values', {}))} field(s) configured"

    return CommandResults(
        # Action-tracking context: keyed by the rule instance's own uuid (globally unique per instance).
        # Separate from list (ModelSecurityRuleInstance) and get (ModelSecurityRuleInstanceGet) to avoid pollution.
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstanceUpdate",
        outputs_key_field="uuid",
        outputs=rule_instance_info,
        readable_output=readable_output,
        raw_response=response,
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

    response = client.http_request(method="GET", url_suffix=url_suffix, use_model_sec_mgmt=True)

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
        "tsg_id": response.get("tsg_id"),
    }

    # Add field_values if present
    if response.get("field_values"):
        rule_instance_info["field_values"] = response.get("field_values")

    # Create readable output using XSOAR table format
    readable_output = tableToMarkdown(
        "Model Security Rule Instance Details",
        [rule_instance_info],
        headers=["rule_name", "state", "rule_type", "uuid", "updated_at"],
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )

    # Add configuration details
    if rule_instance_info.get("field_values"):
        readable_output += f"\n\n**Custom Field Values:** {len(rule_instance_info.get('field_values', {}))} field(s) configured"

    return CommandResults(
        # Query context: keyed by the rule instance's own uuid (globally unique per instance).
        # Separate from list (ModelSecurityRuleInstance) and update (ModelSecurityRuleInstanceUpdate) to avoid pollution.
        outputs_prefix=f"{PA_OUTPUT_PREFIX}ModelSecurityRuleInstanceGet",
        outputs_key_field="uuid",
        outputs=rule_instance_info,
        readable_output=readable_output,
        raw_response=response,
    )


def main() -> None:
    """Main function for Prisma AIRs AI Model Security integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
        # Client configuration (scoped credentials for the Model Security plane)
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

        elif command == "prisma-airs-model-security-models-list":
            return_results(model_security_models_list_command(client, args))

        elif command == "prisma-airs-model-security-models-get":
            return_results(model_security_models_get_command(client, args))

        elif command == "prisma-airs-model-security-models-versions":
            return_results(model_security_models_versions_command(client, args))

        elif command == "prisma-airs-model-security-models-version-get":
            return_results(model_security_models_version_get_command(client, args))

        elif command == "prisma-airs-model-security-models-files":
            return_results(model_security_models_files_command(client, args))

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

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
