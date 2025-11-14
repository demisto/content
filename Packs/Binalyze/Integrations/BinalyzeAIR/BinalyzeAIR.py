import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import re
import urllib3
import json

urllib3.disable_warnings()


class Client(BaseClient):
    def test_api(self):
        return self._http_request(method="GET", url_suffix="/api/public/endpoints?filter[organizationIds]=0")

    def get_profile_id(self, profile: str, organization_id: int | None) -> str:
        """Gets the profile ID based on the profile name and organization ID by making a GET request to the
        '/api/public/acquisitions/profiles' endpoint.
        Args:
        profile (str): The name of the profile to query.
        organization_id (int): The organization ID associated with the profile.
        Returns:
        str: The profile ID obtained from the API response.
        Raises:
        DemistoException: If there is an error making the HTTP request or processing the API response.
        """
        preset_profiles = ["browsing-history", "compromise-assessment", "event-logs", "full", "memory-ram-pagefile", "quick"]
        if profile in preset_profiles:
            return profile
        else:
            result = (
                self._http_request(
                    method="GET",
                    url_suffix=f"/api/public/acquisitions/profiles?filter[name]={profile}&filter[organizationIds]="
                    f"{organization_id}",
                )
                .get("result", {})
                .get("entities", [])
            )
            profile_id = ""
            for entity in result:
                if entity.get("name") == profile:
                    profile_id = entity.get("_id")
                    if profile_id:
                        return profile_id
            # There is no match with profile_id.
            if not profile_id:
                return_error(
                    f'The acquisition profile "{profile}" cannot be found. Please ensure that you enter a valid profile name.'
                )
            return ""

    def air_acquire(self, hostname: str, profile: str, case_id: str, organization_id: int | None) -> dict[str, Any]:
        """Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence

        :param hostname str: endpoint hostname to start acquisition.
        :param profile str: get the profile string makes a query, and uses profile_id for mapping correct profile.

        :param case_id str: The Case ID to associate with in AIR Server.
        :param organization_id int: Organizsation ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/app/info endpoint
        :rtype Dict[str, Any]
        """

        payload: dict[str, Any] = {
            "caseId": case_id,
            "droneConfig": {"autoPilot": False, "enabled": False},
            "taskConfig": {"choice": "use-policy"},
            "acquisitionProfileId": self.get_profile_id(profile, organization_id),
            "filter": {"name": hostname, "organizationIds": [organization_id]},
        }
        return self._http_request(method="POST", url_suffix="/api/public/acquisitions/acquire", json_data=payload)

    def air_isolate(self, hostname: str, organization_id: int | None, isolation: str) -> dict[str, Any]:
        """Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence
        :param hostname str: endpoint hostname to start acquisition.
        :param isolation str: To isolate enable, to disable isolate use disable
        :param organization_id int: Organization ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/public/endpoints/tasks/isolation endpoint
        :rtype Dict[str, Any]
        """

        payload: dict[Any, Any] = {"enabled": True, "filter": {"name": hostname, "organizationIds": [organization_id]}}

        if isolation == "disable":
            disable = {"enabled": False}
            payload.update(disable)

        return self._http_request(method="POST", url_suffix="/api/public/endpoints/tasks/isolation", json_data=payload)

    def create_triage_rule(self, description, rule, searchIn, engine, organizationIds) -> dict[str, Any]:

        payload: dict[Any, Any] = {"description": description, "rule": rule,
                                   "searchIn": searchIn, "engine": engine, "organizationIds": [organizationIds]}

        return self._http_request(method="POST", url_suffix="api/public/triages/rules", json_data=payload)

    def assign_triage_task(self, body) -> dict[str, Any]:

        return self._http_request(method="POST", url_suffix="api/public/triages/triage", json_data=body)

    def download_file(self, file_name):

        params: dict[Any, Any] = {"filename": file_name}
        return self._http_request(method="GET", url_suffix="api/public/interact/library/download", params=params, resp_type="response",)

    def update_triage_rule(self, description, rule, searchIn, rule_id, organizationIds) -> dict[str, Any]:

        payload: dict[Any, Any] = {"description": description, "rule": rule,
                                   "searchIn": searchIn, "organizationIds": [organizationIds]}

        return self._http_request(method="PUT", url_suffix=f"api/public/triages/rules/:{rule_id}", json_data=payload)

    def validate_triage_rule(self, rule, engine) -> dict[str, Any]:

        payload: dict[Any, Any] = {"rule": rule, "engine": engine}

        return self._http_request(method="POST", url_suffix="api/public/triages/rules/validate", json_data=payload)

    def create_case(self, organizationId, name, ownerUserId, visibility, assignedUserIds) -> dict[str, Any]:

        payload: dict[Any, Any] = {"organizationId": [organizationId], "name": name,
                                   "ownerUserId": ownerUserId, "visibility": visibility, "assignedUserIds": assignedUserIds}

        return self._http_request(method="POST", url_suffix="api/public/cases", json_data=payload)


def test_connection(client: Client) -> str:
    """Command for test-connection"""
    try:
        client.test_api()
    except DemistoException as ex:
        if "Unauthorized" in str(ex):
            return demisto.results(f"Authorization Error: Make sure API Key is correctly set.{str(ex)}")
        if "ConnectionError" in str(ex):
            return demisto.results(f"Connection Error: Test connection failed. {str(ex)}")
        else:
            raise ex
    return demisto.results("ok")


def air_acquire_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler for acquire command"""
    hostname = args.get("hostname", "")
    profile = args.get("profile", "")
    case_id = args.get("case_id", "")
    organization_id = args.get("organization_id", "")

    result: dict[str, Any] = client.air_acquire(hostname, profile, case_id, arg_to_number(organization_id))
    readable_output = tableToMarkdown(
        "Binalyze AIR Acquisition Results",
        result,
        headers=("success", "result", "statusCode", "errors"),
        headerTransform=string_to_table_header,
    )

    if result.get("statusCode") == 404:
        return CommandResults(readable_output="No contex for queried hostname.")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Acquisition",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"]},
        readable_output=readable_output,
    )


def air_isolate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler isolate"""

    hostname = args.get("hostname", "")
    organization_id = args.get("organization_id", "")
    isolation = args.get("isolation", "")

    result: dict[Any, Any] = client.air_isolate(hostname, arg_to_number(organization_id), isolation)
    readable_output = tableToMarkdown(
        "Binalyze AIR Isolate Results",
        result,
        headers=("success", "result", "statusCode", "errors"),
        headerTransform=string_to_table_header,
    )
    if result.get("statusCode") == 404:
        return CommandResults(readable_output="No contex for queried hostname.")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Isolate",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"]},
        readable_output=readable_output,
    )


def binalyze_air_download_file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler isolate"""

    file_name = args.get("file_name", "")

    result = client.download_file(file_name)
    return_results(fileResult(file_name, result.content))
    if result.status_code == 200:
        readable_output = "Binalyze AIR Download File commandı basarı ile calıstı"
    else:
        readable_output = "Binalyze AIR Download File commandı hata aldı, hata kodu:{result.status_code}"

    return CommandResults(readable_output=readable_output)


def binalyze_air_assign_triage_task_command(client: Client, args: dict[str, Any]) -> CommandResults:

    caseId = args.get("caseId")
    triageRuleIds = argToList(args.get("triageRuleIds"))
    task_config_choice = args.get("task_config_choice")
    task_config_cpu_limit = int(args.get("task_config_cpu_limit"))
    hostname = args.get("hostname", "")
    mitreAttack = bool(args.get("mitreAttack", False))
    includedEndpointIds = argToList(args.get("includedEndpointIds"))
    excludedEndpointIds = argToList(args.get("excludedEndpointIds"))

    body = {
        "caseId": caseId,
        "triageRuleIds": triageRuleIds,
        "taskConfig": {
            "choice": task_config_choice,
            "cpu": {
                "limit": task_config_cpu_limit
            }
        },
        "mitreAttack": {
            "enabled": mitreAttack
        },
        "filter": {
            "name": hostname,
            "groupId": "",
            "groupFullPath": "",
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": includedEndpointIds,
            "excludedEndpointIds": excludedEndpointIds,
            "organizationIds": [0]
        },
        "schedulerConfig": {
            "when": "now"
        }
    }

    result = client.assign_triage_task(body=body)
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Assign.Triage.Task",
        outputs_key_field="hostname",
        outputs=result,
        readable_output=result,
    )
    """
    readable_output = tableToMarkdown(
        "Binalyze AIR Create Triage Rule Results",
        result,
        headers=("success", "result", "statusCode", "errors"),
        headerTransform=string_to_table_header,
    )


    if result.get("statusCode") == 404:
        return CommandResults(readable_output="Status kod 404.")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Assign.Triage.Task",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"], "Errors": result["errors"], "StatusCode": result["statusCode"]},
        readable_output=readable_output,
    )
    """


def binalyze_air_create_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler isolate"""

    description = args.get("description", "")
    rule = args.get("rule", "")
    searchIn = args.get("searchIn", "")
    engine = args.get("engine", "")
    organizationIds = args.get("organizationIds", "")

    result: dict[Any, Any] = client.create_triage_rule(description, rule, searchIn, engine, [organizationIds])
    """
    rule_res = ""
    try:
        match = re.search(r'rule([\s\S]*?)type:',result["result"])
        if match:
            rule_res = match.group(1).strip()
    except Exception as e:
        return_results(result["result"])
    result["rule"] = rule_res
    """
    result["rule"] = result["result"]["rule"]
    readable_output = tableToMarkdown(
        "Binalyze AIR Create Triage Rule Results",
        result,
        headers=("success", "result", "statusCode", "errors", "rule"),
        headerTransform=string_to_table_header,
    )

    if result.get("statusCode") == 404:
        return CommandResults(readable_output="Status kod 404.")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Create.Triage.Rule",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"], "Rule": result["rule"]},
        readable_output=readable_output,
    )


def binalyze_air_update_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler isolate"""

    description = args.get("description", "")
    rule = args.get("rule", "")
    searchIn = args.get("searchIn", "")
    organizationIds = args.get("organizationIds", "")
    rule_id = args.get("rule", "")
    result: dict[Any, Any] = client.update_triage_rule(description, rule, searchIn, rule_id, [organizationIds])

    result["rule"] = result["result"]["rule"]
    readable_output = tableToMarkdown(
        "Binalyze AIR Update Triage Rule Results",
        result,
        headers=("success", "result", "statusCode", "errors", "rule"),
        headerTransform=string_to_table_header,
    )

    if result.get("statusCode") == 404:
        return CommandResults(readable_output="Status kod 404.")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Update.Triage.Rule",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"], "Rule": result["rule"]},
        readable_output=readable_output,
    )


def binalyze_air_validate_triage_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command handler isolate"""

    rule = args.get("rule", "")
    engine = args.get("engine", "")

    result: dict[Any, Any] = client.validate_triage_rule(rule, engine)

    readable_output = tableToMarkdown(
        "Binalyze AIR Validate Triage Rule Results",
        result,
        headers=("success", "result", "statusCode", "errors"),
        headerTransform=string_to_table_header,
    )

    if result.get("statusCode") == 660:
        return CommandResults(readable_output=" Validation FAİLED!!!")

    return CommandResults(
        outputs_prefix="BinalyzeAIR.Validate.Triage.Rule",
        outputs_key_field="hostname",
        outputs={"Result": result["result"], "Success": result["success"]},
        readable_output=readable_output,
    )

# <<< CREATE-CASE ADDED


def binalyze_air_create_case_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Command handler for `binalyze-air-create-case`.
    """
    organizationId = args.get("organizationId", "")
    name = args.get("name", "")
    ownerUserId = args.get("ownerUserId", "")
    visibility = args.get("visibility", "public-to-organization")
    assignedUserIds = args.get("assignedUserIds", [])          # can be a list or a CSV string

    # If the user passed a CSV string, convert it to a list
    if isinstance(assignedUserIds, str):
        assignedUserIds = [uid.strip() for uid in assignedUserIds.split(",") if uid.strip()]

    result: dict[str, Any] = client.create_case(
        organizationId=organizationId,
        name=name,
        ownerUserId=ownerUserId,
        visibility=visibility,
        assignedUserIds=assignedUserIds,
    )

    if result is None:
        # _http_request döndüğü None, yani 201 kodu ok_codes’da yoktu.
        # Bu durumun tekrar ortaya çıkmaması için (örnek) bir hata fırlatıyoruz.
        return_error(
            "Binalyze AIR returned an empty response while creating the case. "
            "Make sure the integration is configured with ok_codes that include 201 (Created)."
        )

    readable_output = tableToMarkdown(
        "Binalyze AIR – Create Case Result",
        result,
        headers=("success", "result", "statusCode", "errors", "caseId"),
        headerTransform=string_to_table_header,
    )

    # Return the created case ID (if present) in the context data
    case_id = result.get("result", {}).get("_id") or result.get("result", {}).get("caseId")
    return CommandResults(
        outputs_prefix="BinalyzeAIR.Case",
        outputs_key_field="caseId",
        outputs={"CaseID": case_id, "Result": result.get("result"), "Success": result.get("success")},
        readable_output=readable_output,
    )
# <<< END CREATE-CASE


""" Entrypoint """


def main() -> None:  # pragma: no cover
    api_key: str = demisto.params().get("api_key")
    base_url: str = demisto.params()["server"]
    verify_certificate: bool = not demisto.params().get("insecure", False)
    proxy: bool = demisto.params().get("proxy", False)
    command: str = demisto.command()
    args: dict[str, Any] = demisto.args()
    headers: dict[str, Any] = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Binalyze AIR",
        "Content-type": "application/json",
        "Accept-Charset": "UTF-8",
    }

    if command == "binalyze-air-download-file":
        headers["Accept"] = "application/octet-stream"
    try:
        demisto.debug(f"Command being called is {demisto.command()}")
        client: Client = Client(base_url=base_url, verify=verify_certificate, headers=headers,
                                proxy=proxy, ok_codes=(200, 201, 202, 204, 404))
        if command == "test-module":
            return_results(test_connection(client))
        elif command == "binalyze-air-acquire":
            return_results(air_acquire_command(client, args))
        elif command == "binalyze-air-isolate":
            return_results(air_isolate_command(client, args))
        elif command == "binalyze-air-create-triage-rule":
            return_results(binalyze_air_create_triage_rule_command(client, args))
        elif command == "binalyze-air-assign-triage-task":
            return_results(binalyze_air_assign_triage_task_command(client, args))
        elif command == "binalyze-air-download-file":

            return_results(binalyze_air_download_file_command(client, args))
        elif command == "binalyze-air-update-triage-rule":
            return_results(binalyze_air_update_triage_rule_command(client, args))
        elif command == "binalyze-air-validate-triage-rule":
            return_results(binalyze_air_validate_triage_rule_command(client, args))
        elif command == "binalyze-air-create-case":
            return_results(binalyze_air_create_case_command(client, args))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute "{command}". Error: {str(ex)}')


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
