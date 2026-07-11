import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
try:
    ContentClient
except NameError:
    ContentClient = BaseClient
from typing import Any, Optional
from urllib.parse import quote
import json
import traceback

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


def remove_empty_values(value: Any) -> Any:
    """Recursively removes empty values from dicts and lists."""
    if isinstance(value, dict):
        cleaned = {
            key: remove_empty_values(item)
            for key, item in value.items()
            if item not in (None, "", [])
        }
        return {key: item for key, item in cleaned.items() if item not in (None, "", [], {})}

    if isinstance(value, list):
        cleaned_list = [remove_empty_values(item) for item in value]
        return [item for item in cleaned_list if item not in (None, "", [], {})]

    return value


def clean_params(params: dict[str, Any]) -> dict[str, Any]:
    """Returns a params dictionary suitable for BaseClient/ContentClient _http_request."""
    cleaned: dict[str, Any] = {}
    for key, value in params.items():
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            cleaned[key] = ",".join(str(item) for item in value)
        else:
            cleaned[key] = value
    return cleaned


def url_path(*parts: str) -> str:
    """Safely builds a URL suffix with quoted path variables."""
    return "/" + "/".join(quote(str(part).strip("/"), safe="") for part in parts)


def to_bool(value: Any, default: bool = False) -> bool:
    if value in (None, ""):
        return default
    return argToBoolean(value)


def to_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    return argToList(value)


def required_str_arg(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if value in (None, ""):
        raise DemistoException(f"The {name} argument is required.")
    return str(value)


def optional_int_arg(args: dict[str, Any], name: str) -> Optional[int]:
    value = args.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise DemistoException(f"The {name} argument must be an integer. Invalid value: {value}")


def required_int_arg(args: dict[str, Any], name: str) -> int:
    value = optional_int_arg(args, name)
    if value is None:
        raise DemistoException(f"The {name} argument is required.")
    return value


def int_list_arg(args: dict[str, Any], name: str) -> list[int]:
    value = args.get(name)
    if value in (None, ""):
        return []
    result: list[int] = []
    for item in argToList(value):
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            raise DemistoException(f"The {name} argument must contain only integer values. Invalid value: {item}")
    return result


def first_entity(result: dict[str, Any]) -> dict[str, Any]:
    payload = result.get("result", result)
    if isinstance(payload, dict):
        entities = payload.get("entities") or payload.get("items") or payload.get("data")
        if isinstance(entities, list) and entities:
            return entities[0]
        return payload
    if isinstance(payload, list) and payload:
        return payload[0]
    return {}


def status_from_task(task: dict[str, Any]) -> str:
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


def visibility_value(value: str) -> str:
    mapping = {
        "Public to Organization": "public-to-organization",
        "Private to Users": "private-to-users",
        "public-to-organization": "public-to-organization",
        "private-to-users": "private-to-users",
    }
    return mapping.get(value, value)


def markdown(title: str, data: Any, headers: Optional[list[str]] = None) -> str:
    if isinstance(data, list):
        return tableToMarkdown(title, data, headers=headers, removeNull=True)
    if isinstance(data, dict):
        return tableToMarkdown(title, data, headers=headers, removeNull=True, headerTransform=string_to_table_header)
    return f"### {title}\n```json\n{json.dumps(data, indent=2, default=str)}\n```"


class Client(ContentClient):
    def test_api(self) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/endpoints",
            params={"filter[organizationIds]": 0},
        )

    def get_profile_id(self, profile: str, organization_id: Optional[int]) -> str:
        if profile in PRESET_PROFILES:
            return profile
        if organization_id is None:
            raise DemistoException("The organization_id argument is required for custom acquisition profiles.")
        result = self._http_request(
            method="GET",
            url_suffix="/api/public/acquisitions/profiles",
            params={"filter[name]": profile, "filter[organizationIds]": organization_id},
        )
        entities = result.get("result", {}).get("entities", []) if isinstance(result, dict) else []
        for entity in entities:
            if entity.get("name") == profile and entity.get("_id"):
                return entity.get("_id")
        raise DemistoException(f'The acquisition profile "{profile}" was not found.')

    def air_acquire(self, hostname: str, profile: str, case_id: str, organization_id: int) -> dict[str, Any]:
        payload = {
            "caseId": case_id,
            "droneConfig": {"autoPilot": False, "enabled": False},
            "taskConfig": {"choice": "use-policy"},
            "acquisitionProfileId": self.get_profile_id(profile, organization_id),
            "filter": {"name": hostname, "organizationIds": [organization_id]},
        }
        return self._http_request(method="POST", url_suffix="/api/public/acquisitions/acquire", json_data=payload)

    def air_isolate(self, hostname: str, organization_id: int, isolation: str) -> dict[str, Any]:
        payload = {
            "enabled": isolation.lower() == "enable",
            "filter": {"name": hostname, "organizationIds": [organization_id]},
        }
        return self._http_request(method="POST", url_suffix="/api/public/endpoints/tasks/isolation", json_data=payload)

    def create_case(self, organization_id: int, name: str, owner_user_id: str, visibility: str, assigned_user_ids: list[str]) -> dict[str, Any]:
        payload = {
            "organizationId": organization_id,
            "name": name,
            "ownerUserId": owner_user_id,
            "visibility": visibility_value(visibility),
            "assignedUserIds": assigned_user_ids,
        }
        return self._http_request(method="POST", url_suffix="/api/public/cases", json_data=remove_empty_values(payload))

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "cases", case_id))

    def list_cases(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/cases",
            params=clean_params({
                "filter[name]": args.get("name"),
                "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
                "page": args.get("page"),
                "limit": args.get("limit"),
            }),
        )

    def get_case_related(self, case_id: str, relation: str, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=url_path("api", "public", "cases", case_id, relation),
            params=clean_params({"taskId": args.get("task_id"), "page": args.get("page"), "limit": args.get("limit")}),
        )

    def close_case(self, case_id: str, reason: str = "") -> dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=url_path("api", "public", "cases", case_id, "close"),
            json_data=remove_empty_values({"reason": reason}),
        )

    def list_assets(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/endpoints",
            params=clean_params({
                "filter[name]": args.get("hostname") or args.get("name"),
                "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
                "filter[onlineStatus]": args.get("online_status"),
                "filter[isolationStatus]": args.get("isolation_status"),
                "filter[platform]": args.get("platform"),
                "page": args.get("page"),
                "limit": args.get("limit"),
            }),
        )

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "endpoints", asset_id))

    def get_asset_by_hostname(self, hostname: str, organization_id: int) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/endpoints",
            params={"filter[name]": hostname, "filter[organizationIds]": organization_id},
        )

    def get_asset_tasks(self, asset_id: str, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=url_path("api", "public", "endpoints", asset_id, "tasks"),
            params=clean_params({"page": args.get("page"), "limit": args.get("limit")}),
        )

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "tasks", task_id))

    def list_tasks(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/tasks",
            params=clean_params({
                "filter[caseIds]": args.get("case_id"),
                "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
                "filter[status]": args.get("status"),
                "filter[type]": args.get("task_type"),
                "page": args.get("page"),
                "limit": args.get("limit"),
            }),
        )

    def get_task_assignments(self, task_id: str, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=url_path("api", "public", "tasks", task_id, "assignments"),
            params=clean_params({"page": args.get("page"), "limit": args.get("limit")}),
        )

    def create_triage_rule(self, description: str, rule: str, search_in: str, engine: str, organization_ids: list[int]) -> dict[str, Any]:
        payload = {"description": description, "rule": rule, "searchIn": search_in,
                   "engine": engine, "organizationIds": organization_ids}
        return self._http_request(method="POST", url_suffix="/api/public/triages/rules", json_data=remove_empty_values(payload))

    def list_triage_rules(self, args: dict[str, Any]) -> dict[str, Any]:
        organization_ids = args.get("organization_ids") or args.get("organization_id")
        return self._http_request(
            method="GET",
            url_suffix="/api/public/triages/rules",
            params=clean_params({
                "filter[organizationIds]": organization_ids,
                "filter[engine]": args.get("engine"),
                "filter[searchIn]": args.get("search_in"),
                "filter[description]": args.get("description"),
                "page": args.get("page"),
                "limit": args.get("limit"),
            }),
        )

    def get_triage_rule(self, rule_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "triages", "rules", rule_id))

    def update_triage_rule(self, description: str, rule: str, search_in: str, rule_id: str, organization_ids: list[int]) -> dict[str, Any]:
        payload = {"description": description, "rule": rule, "searchIn": search_in, "organizationIds": organization_ids}
        return self._http_request(method="PUT", url_suffix=url_path("api", "public", "triages", "rules", rule_id), json_data=remove_empty_values(payload))

    def delete_triage_rule(self, rule_id: str) -> dict[str, Any]:
        return self._http_request(method="DELETE", url_suffix=url_path("api", "public", "triages", "rules", rule_id))

    def validate_triage_rule(self, rule: str, engine: str) -> dict[str, Any]:
        return self._http_request(method="POST", url_suffix="/api/public/triages/rules/validate", json_data={"rule": rule, "engine": engine})

    def assign_triage_task(self, args: dict[str, Any]) -> dict[str, Any]:
        organization_id = required_int_arg(args, "organization_id")
        body = {
            "caseId": args.get("case_id"),
            "triageRuleIds": to_list(args.get("triage_rule_ids")),
            "taskConfig": {
                "choice": args.get("task_config_choice", "use-policy"),
                "cpu": {"limit": optional_int_arg(args, "task_config_cpu_limit") or 8},
            },
            "mitreAttack": {"enabled": to_bool(args.get("mitre_attack"), False)},
            "filter": {
                "name": args.get("hostname"),
                "groupId": args.get("group_id"),
                "groupFullPath": args.get("group_full_path"),
                "isolationStatus": to_list(args.get("isolation_status")),
                "platform": to_list(args.get("platform")),
                "issue": args.get("issue"),
                "onlineStatus": to_list(args.get("online_status")),
                "tags": to_list(args.get("tags")),
                "version": args.get("version"),
                "policy": args.get("policy"),
                "includedEndpointIds": to_list(args.get("included_endpoint_ids")),
                "excludedEndpointIds": to_list(args.get("excluded_endpoint_ids")),
                "organizationIds": [organization_id],
            },
            "schedulerConfig": {"when": args.get("when", "now")},
        }
        return self._http_request(method="POST", url_suffix="/api/public/triages/triage", json_data=remove_empty_values(body))

    def list_acquisition_profiles(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/public/acquisitions/profiles",
            params=clean_params({
                "filter[name]": args.get("name"),
                "filter[organizationIds]": args.get("organization_ids") or args.get("organization_id"),
                "page": args.get("page"),
                "limit": args.get("limit"),
            }),
        )

    def get_acquisition_profile(self, profile_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "acquisitions", "profiles", profile_id))

    def list_repositories(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix="/api/public/repositories", params=clean_params({"page": args.get("page"), "limit": args.get("limit")}))

    def get_repository(self, repository_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=url_path("api", "public", "repositories", repository_id))

    def download_file(self, file_name: str) -> Any:
        return self._http_request(method="GET", url_suffix="/api/public/interact/library/download", params={"filename": file_name}, resp_type="response")


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


def command_results(title: str, prefix: str, result: dict[str, Any], outputs: Optional[dict[str, Any]] = None, key_field: str = "ID") -> CommandResults:
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key_field,
        outputs=outputs if outputs is not None else result,
        readable_output=markdown(title, result),
        raw_response=result,
    )


def air_acquire_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.air_acquire(
        hostname=required_str_arg(args, "hostname"),
        profile=required_str_arg(args, "profile"),
        case_id=required_str_arg(args, "case_id"),
        organization_id=required_int_arg(args, "organization_id"),
    )
    res = result.get("result", {})
    formatted = {"ID": res.get("_id"), "Name": res.get("name"), "OrganizationID": res.get("organizationId")}
    return command_results("Binalyze AIR Acquisition Results", "BinalyzeAIR.Acquire", result, {"Result": formatted, "Success": result.get("success")})


def air_isolate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.air_isolate(required_str_arg(args, "hostname"), required_int_arg(
        args, "organization_id"), required_str_arg(args, "isolation"))
    res = result.get("result", {})
    formatted = {"ID": res.get("_id"), "Name": res.get("name"), "OrganizationID": res.get("organizationId")}
    return command_results("Binalyze AIR Isolation Results", "BinalyzeAIR.Isolate", result, {"Result": formatted, "Success": result.get("success")})


def create_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.create_case(
        organization_id=required_int_arg(args, "organization_id"),
        name=required_str_arg(args, "name"),
        owner_user_id=required_str_arg(args, "owner_user_id"),
        visibility=required_str_arg(args, "visibility"),
        assigned_user_ids=to_list(args.get("assigned_user_ids")),
    )
    payload = result.get("result", {}) if isinstance(result, dict) else {}
    formatted = {"ID": payload.get("_id") or payload.get("caseId") or payload.get("id"), "Name": payload.get("name")}
    return command_results("Binalyze AIR Create Case Result", "BinalyzeAIR.Case", result, {"Result": formatted, "Success": result.get("success")})


def get_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_case(required_str_arg(args, "case_id"))
    return command_results("Binalyze AIR Case", "BinalyzeAIR.Case", result, key_field="_id")


def list_cases_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_cases(args)
    return command_results("Binalyze AIR Cases", "BinalyzeAIR.Cases", result, key_field="_id")


def close_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.close_case(required_str_arg(args, "case_id"), args.get("reason", ""))
    return command_results("Binalyze AIR Close Case Result", "BinalyzeAIR.CloseCase", result, key_field="_id")


def get_case_related_command(client: Client, args: dict[str, Any], relation: str, prefix: str, title: str) -> CommandResults:
    result = client.get_case_related(required_str_arg(args, "case_id"), relation, args)
    return command_results(title, prefix, result, key_field="_id")


def list_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_assets(args)
    return command_results("Binalyze AIR Assets", "BinalyzeAIR.Asset", result, key_field="_id")


def get_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset(required_str_arg(args, "asset_id"))
    return command_results("Binalyze AIR Asset", "BinalyzeAIR.Asset", result, key_field="_id")


def get_asset_by_hostname_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset_by_hostname(required_str_arg(args, "hostname"), required_int_arg(args, "organization_id"))
    entity = first_entity(result)
    return command_results("Binalyze AIR Asset Lookup Result", "BinalyzeAIR.Asset", result, {"Result": entity}, key_field="_id")


def get_asset_tasks_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_asset_tasks(required_str_arg(args, "asset_id"), args)
    return command_results("Binalyze AIR Asset Tasks", "BinalyzeAIR.AssetTask", result, key_field="_id")


def get_task_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_task(required_str_arg(args, "task_id"))
    task = result.get("result", result) if isinstance(result, dict) else {}
    status = status_from_task(task if isinstance(task, dict) else {})
    outputs = {"Result": task, "Status": status, "IsDone": status in TERMINAL_TASK_STATES,
               "IsSuccess": status in SUCCESS_TASK_STATES}
    return command_results("Binalyze AIR Task", "BinalyzeAIR.Task", result, outputs, key_field="_id")


def list_tasks_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_tasks(args)
    return command_results("Binalyze AIR Tasks", "BinalyzeAIR.Task", result, key_field="_id")


def get_task_assignments_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_task_assignments(required_str_arg(args, "task_id"), args)
    return command_results("Binalyze AIR Task Assignments", "BinalyzeAIR.TaskAssignment", result, key_field="_id")


def create_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.create_triage_rule(args.get("description", ""), required_str_arg(args, "rule"), args.get(
        "search_in", ""), required_str_arg(args, "engine"), int_list_arg(args, "organization_ids"))
    return command_results("Binalyze AIR Create Triage Rule Result", "BinalyzeAIR.TriageRule", result, key_field="_id")


def update_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.update_triage_rule(args.get("description", ""), args.get("rule", ""), args.get(
        "search_in", ""), required_str_arg(args, "rule_id"), int_list_arg(args, "organization_ids"))
    return command_results("Binalyze AIR Update Triage Rule Result", "BinalyzeAIR.TriageRule", result, key_field="_id")


def validate_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.validate_triage_rule(required_str_arg(args, "rule"), required_str_arg(args, "engine"))
    outputs = {"Result": result.get("result"), "Success": result.get("success")}
    return command_results("Binalyze AIR Validate Triage Rule Result", "BinalyzeAIR.TriageRuleValidation", result, outputs, key_field="Success")


def list_triage_rules_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_triage_rules(args)
    return command_results("Binalyze AIR Triage Rules", "BinalyzeAIR.TriageRule", result, key_field="_id")


def get_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_triage_rule(required_str_arg(args, "rule_id"))
    return command_results("Binalyze AIR Triage Rule", "BinalyzeAIR.TriageRule", result, key_field="_id")


def delete_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    rule_id = required_str_arg(args, "rule_id")
    result = client.delete_triage_rule(rule_id)
    return command_results("Binalyze AIR Delete Triage Rule Result", "BinalyzeAIR.DeleteTriageRule", result, {"RuleID": rule_id}, key_field="RuleID")


def assign_triage_task_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.assign_triage_task(args)
    return command_results("Binalyze AIR Assign Triage Task Result", "BinalyzeAIR.TriageTask", result, key_field="_id")


def list_acquisition_profiles_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_acquisition_profiles(args)
    return command_results("Binalyze AIR Acquisition Profiles", "BinalyzeAIR.AcquisitionProfile", result, key_field="_id")


def get_acquisition_profile_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_acquisition_profile(required_str_arg(args, "profile_id"))
    return command_results("Binalyze AIR Acquisition Profile", "BinalyzeAIR.AcquisitionProfile", result, key_field="_id")


def list_repositories_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.list_repositories(args)
    return command_results("Binalyze AIR Repositories", "BinalyzeAIR.Repository", result, key_field="_id")


def get_repository_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.get_repository(required_str_arg(args, "repository_id"))
    return command_results("Binalyze AIR Repository", "BinalyzeAIR.Repository", result, key_field="_id")


def download_file_command(client: Client, args: dict[str, Any]) -> Any:
    file_name = required_str_arg(args, "file_name")
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
        "Content-Type": "application/json",
        "Accept-Charset": "UTF-8",
    }
    if command == "binalyze-air-download-file":
        headers["Accept"] = "application/octet-stream"

    client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy, ok_codes=(200, 201, 202, 204))

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
        if command in commands:
            return_results(commands[command]())
            return
        raise NotImplementedError(f"Command {command} is not implemented.")
    except (DemistoException, NotImplementedError, ValueError, TypeError) as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute "{command}". Error: {str(ex)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
