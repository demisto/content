import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Optional
from urllib.parse import urlencode
import json
import time
import traceback
import urllib3


urllib3.disable_warnings()

PRESET_PROFILES = [
    "browsing-history",
    "compromise-assessment",
    "event-logs",
    "full",
    "memory-ram-pagefile",
    "quick",
]

TERMINAL_TASK_STATES = {"completed", "complete", "failed", "failure", "cancelled", "canceled", "error"}
SUCCESS_TASK_STATES = {"completed", "complete", "success", "succeeded"}


def _clean_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None and v != "" and v != []}


def _to_bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return argToBoolean(value)


def _to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "":
        return default
    return arg_to_number(value)


def _to_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    return argToList(value)


def _org_ids(value: Any, default: Optional[list[int]] = None) -> list[int]:
    if value is None or value == "":
        return default or []
    result: list[int] = []
    for item in argToList(value):
        try:
            result.append(int(item))
        except Exception:
            result.append(item)
    return result


def _query(params: dict[str, Any]) -> str:
    filtered: dict[str, Any] = {}
    for key, value in params.items():
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, list):
            filtered[key] = ",".join(str(x) for x in value)
        else:
            filtered[key] = value
    return urlencode(filtered)


def _first_entity(result: dict[str, Any]) -> dict[str, Any]:
    payload = result.get("result", result)
    if isinstance(payload, dict):
        entities = payload.get("entities") or payload.get("items") or payload.get("data")
        if isinstance(entities, list) and entities:
            return entities[0]
        return payload
    if isinstance(payload, list) and payload:
        return payload[0]
    return {}


def _status_from_task(task: dict[str, Any]) -> str:
    if not task:
        return "unknown"
    for key in ("status", "state", "taskStatus", "processingStatus", "assignmentStatus"):
        value = task.get(key)
        if value:
            if isinstance(value, dict):
                nested = value.get("name") or value.get("value") or value.get("status")
                if nested:
                    return str(nested).lower()
            return str(value).lower()
    return "unknown"


def _visibility_value(value: str) -> str:
    mapping = {
        "Public to Organization": "public-to-organization",
        "Private to Users": "private-to-users",
        "public-to-organization": "public-to-organization",
        "private-to-users": "private-to-users",
    }
    return mapping.get(value, value)


def _markdown(title: str, data: Any, headers: Optional[list[str]] = None) -> str:
    try:
        if isinstance(data, list):
            return tableToMarkdown(title, data, headers=headers, removeNull=True)
        if isinstance(data, dict):
            return tableToMarkdown(title, data, headers=headers, removeNull=True, headerTransform=string_to_table_header)
    except Exception:
        pass
    return f"### {title}\n```json\n{json.dumps(data, indent=2, default=str)}\n```"


class Client(BaseClient):
    def test_api(self) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix="/api/public/endpoints?filter[organizationIds]=0")

    def get_profile_id(self, profile: str, organization_id: Optional[int]) -> str:
        if profile in PRESET_PROFILES:
            return profile
        suffix = f"/api/public/acquisitions/profiles?filter[name]={profile}&filter[organizationIds]={organization_id}"
        result = self._http_request(method="GET", url_suffix=suffix)
        entities = result.get("result", {}).get("entities", []) if isinstance(result, dict) else []
        for entity in entities:
            if entity.get("name") == profile and entity.get("_id"):
                return entity.get("_id")
        raise DemistoException(f'The acquisition profile "{profile}" was not found.')

    def air_acquire(self, hostname: str, profile: str, case_id: str, organization_id: Optional[int]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "caseId": case_id,
            "droneConfig": {"autoPilot": False, "enabled": False},
            "taskConfig": {"choice": "use-policy"},
            "acquisitionProfileId": self.get_profile_id(profile, organization_id),
            "filter": {"name": hostname, "organizationIds": [organization_id]},
        }
        return self._http_request(method="POST", url_suffix="/api/public/acquisitions/acquire", json_data=payload)

    def air_isolate(self, hostname: str, organization_id: Optional[int], isolation: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "enabled": isolation.lower() == "enable",
            "filter": {"name": hostname, "organizationIds": [organization_id]},
        }
        return self._http_request(method="POST", url_suffix="/api/public/endpoints/tasks/isolation", json_data=payload)

    def create_case(self, organization_id: Any, name: str, owner_user_id: str, visibility: str, assigned_user_ids: list[str]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "organizationId": organization_id,
            "name": name,
            "ownerUserId": owner_user_id,
            "visibility": _visibility_value(visibility),
            "assignedUserIds": assigned_user_ids,
        }
        return self._http_request(method="POST", url_suffix="/api/public/cases", json_data=_clean_dict(payload))

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/cases/{case_id}")

    def list_cases(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "filter[name]": args.get("name"),
            "filter[organizationIds]": args.get("organization_ids"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = "/api/public/cases" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_case_related(self, case_id: str, relation: str, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "taskId": args.get("task_id"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = f"/api/public/cases/{case_id}/{relation}" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def close_case(self, case_id: str, reason: str = "") -> dict[str, Any]:
        payload = _clean_dict({"reason": reason})
        return self._http_request(method="POST", url_suffix=f"/api/public/cases/{case_id}/close", json_data=payload)

    def list_assets(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "filter[name]": args.get("hostname") or args.get("name"),
            "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
            "filter[onlineStatus]": args.get("online_status"),
            "filter[isolationStatus]": args.get("isolation_status"),
            "filter[platform]": args.get("platform"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = "/api/public/endpoints" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/endpoints/{asset_id}")

    def get_asset_by_hostname(self, hostname: str, organization_id: Optional[int]) -> dict[str, Any]:
        params = _query({"filter[name]": hostname, "filter[organizationIds]": organization_id})
        return self._http_request(method="GET", url_suffix=f"/api/public/endpoints?{params}")

    def get_asset_tasks(self, asset_id: str, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({"page": args.get("page"), "limit": args.get("limit")})
        suffix = f"/api/public/endpoints/{asset_id}/tasks" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/tasks/{task_id}")

    def list_tasks(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "filter[caseIds]": args.get("case_id"),
            "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
            "filter[status]": args.get("status"),
            "filter[type]": args.get("task_type"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = "/api/public/tasks" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_task_assignments(self, task_id: str, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({"page": args.get("page"), "limit": args.get("limit")})
        suffix = f"/api/public/tasks/{task_id}/assignments" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def create_triage_rule(self, description: str, rule: str, search_in: str, engine: str, organization_ids: list[Any]) -> dict[str, Any]:
        payload = {
            "description": description,
            "rule": rule,
            "searchIn": search_in,
            "engine": engine,
            "organizationIds": organization_ids,
        }
        return self._http_request(method="POST", url_suffix="/api/public/triages/rules", json_data=_clean_dict(payload))

    def list_triage_rules(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
            "filter[engine]": args.get("engine"),
            "filter[searchIn]": args.get("search_in"),
            "filter[description]": args.get("description"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = "/api/public/triages/rules" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_triage_rule(self, rule_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/triages/rules/{rule_id}")

    def update_triage_rule(self, description: str, rule: str, search_in: str, rule_id: str, organization_ids: list[Any]) -> dict[str, Any]:
        payload = {"description": description, "rule": rule, "searchIn": search_in, "organizationIds": organization_ids}
        return self._http_request(method="PUT", url_suffix=f"/api/public/triages/rules/{rule_id}", json_data=_clean_dict(payload))

    def delete_triage_rule(self, rule_id: str) -> dict[str, Any]:
        return self._http_request(method="DELETE", url_suffix=f"/api/public/triages/rules/{rule_id}")

    def validate_triage_rule(self, rule: str, engine: str) -> dict[str, Any]:
        payload = {"rule": rule, "engine": engine}
        return self._http_request(method="POST", url_suffix="/api/public/triages/rules/validate", json_data=payload)

    def assign_triage_task(self, args: dict[str, Any]) -> dict[str, Any]:
        organization_id = _to_int(args.get("organization_id"), 0)
        body = {
            "caseId": args.get("case_id"),
            "triageRuleIds": _to_list(args.get("triage_rule_ids")),
            "taskConfig": {
                "choice": args.get("task_config_choice", "use-policy"),
                "cpu": {"limit": _to_int(args.get("task_config_cpu_limit"), 8)},
            },
            "mitreAttack": {"enabled": _to_bool(args.get("mitre_attack"), False)},
            "filter": {
                "name": args.get("hostname", ""),
                "groupId": args.get("group_id", ""),
                "groupFullPath": args.get("group_full_path", ""),
                "isolationStatus": _to_list(args.get("isolation_status")),
                "platform": _to_list(args.get("platform")),
                "issue": args.get("issue", ""),
                "onlineStatus": _to_list(args.get("online_status")),
                "tags": _to_list(args.get("tags")),
                "version": args.get("version", ""),
                "policy": args.get("policy", ""),
                "includedEndpointIds": _to_list(args.get("included_endpoint_ids")),
                "excludedEndpointIds": _to_list(args.get("excluded_endpoint_ids")),
                "organizationIds": [organization_id],
            },
            "schedulerConfig": {"when": args.get("when", "now")},
        }
        return self._http_request(method="POST", url_suffix="/api/public/triages/triage", json_data=body)

    def list_acquisition_profiles(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({
            "filter[name]": args.get("name"),
            "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
            "page": args.get("page"),
            "limit": args.get("limit"),
        })
        suffix = "/api/public/acquisitions/profiles" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_acquisition_profile(self, profile_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/acquisitions/profiles/{profile_id}")

    def list_repositories(self, args: dict[str, Any]) -> dict[str, Any]:
        params = _query({"page": args.get("page"), "limit": args.get("limit")})
        suffix = "/api/public/repositories" + (f"?{params}" if params else "")
        return self._http_request(method="GET", url_suffix=suffix)

    def get_repository(self, repository_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/api/public/repositories/{repository_id}")

    def download_file(self, file_name: str) -> Any:
        params = {"filename": file_name}
        return self._http_request(method="GET", url_suffix="/api/public/interact/library/download", params=params, resp_type="response")


def test_connection(client: Client) -> str:
    try:
        client.test_api()
    except DemistoException as ex:
        if "Unauthorized" in str(ex) or "401" in str(ex):
            return f"Authorization Error: Make sure the API key is correct. {str(ex)}"
        if "ConnectionError" in str(ex):
            return f"Connection Error: Test connection failed. {str(ex)}"
        raise
    return "ok"


def generic_command(client_method, args: dict[str, Any], title: str, prefix: str, key_field: str = "ID") -> CommandResults:
    result = client_method(args) if callable(client_method) else client_method
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key_field,
        outputs=result,
        readable_output=_markdown(title, result),
    )


def air_acquire_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.air_acquire(
        hostname=args.get("hostname", ""),
        profile=args.get("profile", ""),
        case_id=args.get("case_id", ""),
        organization_id=_to_int(args.get("organization_id")),
    )
    if result.get("statusCode") == 404:
        return CommandResults(readable_output="No endpoint was found for the queried hostname.")
    res = result.get("result", {})
    formatted = {"ID": res.get("_id"), "Name": res.get("name"), "OrganizationID": res.get("organizationId"), "Raw": res}
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Acquire",
        outputs_key_field="ID",
        outputs={"Result": formatted, "Success": result.get("success"), "RawResponse": result},
        readable_output=_markdown("Binalyze AIR Acquisition Results", result),
    )


def air_isolate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.air_isolate(args.get("hostname", ""), _to_int(args.get("organization_id")), args.get("isolation", ""))
    if result.get("statusCode") == 404:
        return CommandResults(readable_output="No endpoint was found for the queried hostname.")
    res = result.get("result", {})
    formatted = {"ID": res.get("_id"), "Name": res.get("name"), "OrganizationID": res.get("organizationId"), "Raw": res}
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Isolate",
        outputs_key_field="ID",
        outputs={"Result": formatted, "Success": result.get("success"), "RawResponse": result},
        readable_output=_markdown("Binalyze AIR Isolation Results", result),
    )


def create_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.create_case(
        organization_id=_to_int(args.get("organization_id"), args.get("organization_id")),
        name=args.get("name", ""),
        owner_user_id=args.get("owner_user_id", ""),
        visibility=args.get("visibility", "public-to-organization"),
        assigned_user_ids=_to_list(args.get("assigned_user_ids")),
    )
    payload = result.get("result", {}) if isinstance(result, dict) else {}
    formatted = {"ID": payload.get("_id") or payload.get("caseId") or payload.get("id"),
                 "Name": payload.get("name"), "Raw": payload}
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Case",
        outputs_key_field="ID",
        outputs={"Result": formatted, "Success": result.get("success"), "RawResponse": result},
        readable_output=_markdown("Binalyze AIR Create Case Result", result),
    )


def get_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_case(args.get("case_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.Case", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Case", result))


def list_cases_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_cases(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.Cases", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Cases", result))


def close_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.close_case(args.get("case_id", ""), args.get("reason", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.CloseCase", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Close Case Result", result))


def get_case_related_command(client: Client, args: dict[str, Any], relation: str, prefix: str, title: str) -> CommandResults:
    result = client.get_case_related(args.get("case_id", ""), relation, args)
    return CommandResults(outputs_prefix=prefix, outputs_key_field="_id", outputs=result, readable_output=_markdown(title, result))


def list_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_assets(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.Asset", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Assets", result))


def get_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset(args.get("asset_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.Asset", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Asset", result))


def get_asset_by_hostname_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset_by_hostname(args.get("hostname", ""), _to_int(args.get("organization_id")))
    entity = _first_entity(result)
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Asset",
        outputs_key_field="_id",
        outputs={"Result": entity, "RawResponse": result},
        readable_output=_markdown("Binalyze AIR Asset Lookup Result", entity or result),
    )


def get_asset_tasks_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset_tasks(args.get("asset_id", ""), args)
    return CommandResults(outputs_prefix="BinalyzeAIR.AssetTask", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Asset Tasks", result))


def get_task_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_task(args.get("task_id", ""))
    task = result.get("result", result) if isinstance(result, dict) else {}
    status = _status_from_task(task if isinstance(task, dict) else {})
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Task",
        outputs_key_field="_id",
        outputs={"Result": task, "Status": status, "IsDone": status in TERMINAL_TASK_STATES,
                 "IsSuccess": status in SUCCESS_TASK_STATES, "RawResponse": result},
        readable_output=_markdown("Binalyze AIR Task", result),
    )


def wait_task_completion_command(client: Client, args: dict[str, Any]) -> CommandResults:
    task_id = args.get("task_id", "")
    interval = _to_int(args.get("poll_interval_seconds"), 30) or 30
    timeout = _to_int(args.get("timeout_seconds"), 900) or 900
    deadline = time.time() + timeout
    last_result: dict[str, Any] = {}
    last_status = "unknown"
    while time.time() <= deadline:
        last_result = client.get_task(task_id)
        task = last_result.get("result", last_result) if isinstance(last_result, dict) else {}
        last_status = _status_from_task(task if isinstance(task, dict) else {})
        if last_status in TERMINAL_TASK_STATES:
            break
        time.sleep(interval)
    return CommandResults(
        outputs_prefix="BinalyzeAIR.TaskWait",
        outputs_key_field="TaskID",
        outputs={"TaskID": task_id, "Status": last_status,
                 "IsDone": last_status in TERMINAL_TASK_STATES, "RawResponse": last_result},
        readable_output=_markdown("Binalyze AIR Task Wait Result", {
                                  "task_id": task_id, "status": last_status, "raw_response": last_result}),
    )


def list_tasks_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_tasks(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.Task", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Tasks", result))


def get_task_assignments_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_task_assignments(args.get("task_id", ""), args)
    return CommandResults(outputs_prefix="BinalyzeAIR.TaskAssignment", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Task Assignments", result))


def create_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.create_triage_rule(args.get("description", ""), args.get("rule", ""), args.get(
        "search_in", ""), args.get("engine", ""), _to_list(args.get("organization_ids")))
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageRule", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Create Triage Rule Result", result))


def update_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.update_triage_rule(args.get("description", ""), args.get("rule", ""), args.get(
        "search_in", ""), args.get("rule_id", ""), _to_list(args.get("organization_ids")))
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageRule", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Update Triage Rule Result", result))


def validate_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.validate_triage_rule(args.get("rule", ""), args.get("engine", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageRuleValidation", outputs_key_field="Success", outputs={"Result": result.get("result"), "Success": result.get("success"), "RawResponse": result}, readable_output=_markdown("Binalyze AIR Validate Triage Rule Result", result))


def list_triage_rules_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_triage_rules(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageRule", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Triage Rules", result))


def get_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_triage_rule(args.get("rule_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageRule", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Triage Rule", result))


def delete_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.delete_triage_rule(args.get("rule_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.DeleteTriageRule", outputs_key_field="RuleID", outputs={"RuleID": args.get("rule_id", ""), "RawResponse": result}, readable_output=_markdown("Binalyze AIR Delete Triage Rule Result", result))


def assign_triage_task_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.assign_triage_task(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.TriageTask", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Assign Triage Task Result", result))


def list_acquisition_profiles_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_acquisition_profiles(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.AcquisitionProfile", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Acquisition Profiles", result))


def get_acquisition_profile_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_acquisition_profile(args.get("profile_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.AcquisitionProfile", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Acquisition Profile", result))


def list_repositories_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_repositories(args)
    return CommandResults(outputs_prefix="BinalyzeAIR.Repository", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Repositories", result))


def get_repository_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_repository(args.get("repository_id", ""))
    return CommandResults(outputs_prefix="BinalyzeAIR.Repository", outputs_key_field="_id", outputs=result, readable_output=_markdown("Binalyze AIR Repository", result))


def download_file_command(client: Client, args: dict[str, Any]) -> Any:
    file_name = args.get("file_name", "")
    result = client.download_file(file_name)
    if result.status_code == 200:
        return fileResult(file_name, result.content)
    raise DemistoException(f"Failed to download file. Status code: {result.status_code}")


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    api_key = params.get("api_key")
    base_url = params.get("server")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Binalyze AIR Extended Cortex XSOAR Integration",
        "Content-type": "application/json",
        "Accept-Charset": "UTF-8",
    }
    if command == "binalyze-air-download-file":
        headers["Accept"] = "application/octet-stream"

    client = Client(base_url=base_url, verify=verify_certificate, headers=headers,
                    proxy=proxy, ok_codes=(200, 201, 202, 204, 404))

    commands = {
        "binalyze-air-acquire": lambda: air_acquire_command(client, args),
        "binalyze-air-isolate": lambda: air_isolate_command(client, args),
        "binalyze-air-create-case": lambda: create_case_command(client, args),
        "binalyze-air-get-case": lambda: get_case_command(client, args),
        "binalyze-air-list-cases": lambda: list_cases_command(client, args),
        "binalyze-air-close-case": lambda: close_case_command(client, args),
        "binalyze-air-get-case-tasks": lambda: get_case_related_command(client, args, "tasks", "BinalyzeAIR.CaseTask", "Binalyze AIR Case Tasks"),
        "binalyze-air-get-case-endpoints": lambda: get_case_related_command(client, args, "endpoints", "BinalyzeAIR.CaseEndpoint", "Binalyze AIR Case Endpoints"),
        "binalyze-air-get-case-activities": lambda: get_case_related_command(client, args, "activities", "BinalyzeAIR.CaseActivity", "Binalyze AIR Case Activities"),
        "binalyze-air-list-assets": lambda: list_assets_command(client, args),
        "binalyze-air-get-asset": lambda: get_asset_command(client, args),
        "binalyze-air-get-asset-by-hostname": lambda: get_asset_by_hostname_command(client, args),
        "binalyze-air-get-asset-tasks": lambda: get_asset_tasks_command(client, args),
        "binalyze-air-get-task": lambda: get_task_command(client, args),
        "binalyze-air-list-tasks": lambda: list_tasks_command(client, args),
        "binalyze-air-get-task-assignments": lambda: get_task_assignments_command(client, args),
        "binalyze-air-wait-task-completion": lambda: wait_task_completion_command(client, args),
        "binalyze-air-create-triage-rule": lambda: create_triage_rule_command(client, args),
        "binalyze-air-update-triage-rule": lambda: update_triage_rule_command(client, args),
        "binalyze-air-validate-triage-rule": lambda: validate_triage_rule_command(client, args),
        "binalyze-air-list-triage-rules": lambda: list_triage_rules_command(client, args),
        "binalyze-air-get-triage-rule": lambda: get_triage_rule_command(client, args),
        "binalyze-air-delete-triage-rule": lambda: delete_triage_rule_command(client, args),
        "binalyze-air-assign-triage-task": lambda: assign_triage_task_command(client, args),
        "binalyze-air-list-acquisition-profiles": lambda: list_acquisition_profiles_command(client, args),
        "binalyze-air-get-acquisition-profile": lambda: get_acquisition_profile_command(client, args),
        "binalyze-air-list-repositories": lambda: list_repositories_command(client, args),
        "binalyze-air-get-repository": lambda: get_repository_command(client, args),
        "binalyze-air-download-file": lambda: download_file_command(client, args),
    }

    try:
        demisto.debug(f"Command being called is {command}")
        if command == "test-module":
            return_results(test_connection(client))
        elif command in commands:
            return_results(commands[command]())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute "{command}". Error: {str(ex)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
