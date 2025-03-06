import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """
from typing import Any, Dict

""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
AUTH_URL = "securitymanager/api/authentication/login"
WORKFLOW_URL = "/policyplanner/api/domain/{0}/workflow/version/latest/all"
CREATE_PP_TICKET_URL = "/policyplanner/api/domain/{0}/workflow/{1}/packet"
PCA_URL_SUFFIX = "/orchestration/api/domain/{}/change/device/{}/pca"
RULE_REC_URL = "orchestration/api/domain/{}/change/rulerec"
PAGED_SEARCH_URL = "securitymanager/api/siql/secrule/paged-search"
COLLECTOR_URL = "securitymanager/api/collector"

create_pp_payload = {
    "sources": [""],
    "destinations": [""],
    "action": "",
    "services": [""],
    "requirementType": "RULE",
    "childKey": "add_access",
    "variables": {},
}


def get_rule_rec_request_payload():
    return {
        "apps": [],
        "destinations": [""],
        "services": [""],
        "sources": [""],
        "users": [],
        "requirementType": "RULE",
        "childKey": "add_access",
        "variables": {"expiration": "null", "review": "null"},
        "action": "",
    }


def get_create_pp_ticket_payload():
    return {
        "variables": {
            "summary": "Request Test06",
            "businessNeed": "",
            "priority": "LOW",
            "dueDate": "2021-05-29 13:44:58",
            "applicationName": "",
            "customer": "",
            "externalTicketId": "",
            "notes": "",
            "requesterName": "System Administrator",
            "requesterEmail": "",
            "applicationOwner": "",
            "integrationRecord": "",
            "carbonCopy": [""],
        },
        "policyPlanRequirements": [],
    }


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, username: str, password: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._username = username
        self._password = password

    def authenticate_user(self):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        api_response = self._http_request(
            method="POST",
            url_suffix=AUTH_URL,
            json_data={"username": self._username, "password": self._password},
            headers=headers,
        )
        return api_response

    def get_all_workflow(self, auth_token, domain_id, parameters):
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-FM-Auth-Token": auth_token}
        workflow_url = WORKFLOW_URL.format(domain_id)
        api_response = self._http_request(method="GET", url_suffix=workflow_url, params=parameters, headers=headers)
        list_of_workflow = []
        for workflow in api_response.get("results"):
            if workflow["workflow"]["pluginArtifactId"] == "access-request":
                workflow_name = workflow["workflow"]["name"]
                list_of_workflow.append(workflow_name)

        return list_of_workflow

    def get_list_of_workflow(self, auth_token, domain_id, parameters):
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-FM-Auth-Token": auth_token}
        workflow_url = WORKFLOW_URL.format(domain_id)
        api_response = self._http_request(method="GET", url_suffix=workflow_url, params=parameters, headers=headers)

        return api_response

    def get_workflow_id_by_workflow_name(self, domain_id, workflow_name, auth_token, parameters):

        list_of_workflow = self.get_list_of_workflow(auth_token, domain_id, parameters)
        count_of_workflow = list_of_workflow.get("total")

        if count_of_workflow > 10:
            parameters = {"includeDisabled": False, "pageSize": count_of_workflow}
            list_of_workflow = self.get_list_of_workflow(auth_token, domain_id, parameters)

        for workflow in list_of_workflow.get("results"):
            if (workflow["workflow"]["pluginArtifactId"] == "access-request") and (
                workflow["workflow"]["name"] == workflow_name
            ):
                workflow_id = workflow["workflow"]["id"]
                return workflow_id

    def create_pp_ticket(self, auth_token, payload):
        parameters = {"includeDisabled": False, "pageSize": 10}
        workflow_id = self.get_workflow_id_by_workflow_name(
            payload["domainId"], payload["workflowName"], auth_token, parameters
        )
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-FM-Auth-Token": auth_token}
        data = get_create_pp_ticket_payload()
        data["variables"]["priority"] = payload["priority"]
        data["variables"]["dueDate"] = payload["due_date"].replace("T", " ")[:-6]
        list_of_requirements = payload["requirements"]
        for i in range(len(list_of_requirements)):
            req_payload = list_of_requirements[i]
            input_data = create_pp_payload
            input_data["sources"] = list(req_payload["sources"].split(","))
            input_data["destinations"] = list(req_payload["destinations"].split(","))
            input_data["services"] = list(req_payload["services"].split(","))
            input_data["action"] = req_payload["action"]
            data["policyPlanRequirements"].append(dict(input_data))

        create_pp_ticket_url = CREATE_PP_TICKET_URL.format(payload["domainId"], workflow_id)
        api_response = self._http_request(
            method="POST", url_suffix=create_pp_ticket_url, headers=headers, json_data=data
        )
        return api_response

    def validate_pca_change(self, payload_pca, pca_url_suffix, headers):
        api_response = self._http_request(
            method="POST", url_suffix=pca_url_suffix, json_data=payload_pca, headers=headers, params=None, timeout=40
        )
        return api_response

    def rule_rec_api(self, auth_token, payload):
        """Calling orchestration rulerec api by passing json data as request body, headers, params and domainId
        which returns you list of rule recommendations for given input as response"""

        parameters = {
            "deviceGroupId": payload["deviceGroupId"],
            "addressMatchingStrategy": "INTERSECTS",
            "modifyBehavior": "MODIFY",
            "strategy": None,
        }
        data = get_rule_rec_request_payload()

        data["destinations"] = payload["destinations"]
        data["sources"] = payload["sources"]
        data["services"] = payload["services"]
        data["action"] = payload["action"]
        rule_rec_api_response = self._http_request(
            method="POST",
            url_suffix=RULE_REC_URL.format(payload["domainId"]),
            json_data=data,
            params=parameters,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-FM-Auth-Token": auth_token,
            },
        )
        return rule_rec_api_response

    def rule_rec_output(self, auth_token, payload):
        """Calling orchestration rulerec api by passing json data as request body, headers, params and domainId
        which returns you list of rule recommendations for given input as response"""

        parameters = {
            "deviceId": payload["deviceId"],
            "addressMatchingStrategy": "INTERSECTS",
            "modifyBehavior": "MODIFY",
            "strategy": None,
        }
        data = get_rule_rec_request_payload()

        data["destinations"] = payload["destinations"]
        data["sources"] = payload["sources"]
        data["services"] = payload["services"]
        data["action"] = payload["action"]
        rule_rec_api_response = self._http_request(
            method="POST",
            url_suffix=RULE_REC_URL.format(payload["domainId"]),
            json_data=data,
            params=parameters,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-FM-Auth-Token": auth_token,
            },
        )
        return rule_rec_api_response

    def get_paged_search_secrule(self, auth_token: str, payload: Dict[str, Any]):
        """Calling siql paged search api for searching security rules
        using `SIQL` language query

        Args:
            auth_token (str): authentication token
            payload (Dict[str, Any]): payload to be used for making request
        """
        parameters: Dict[str, Any] = {
            "q": payload["q"],
            "pageSize": payload["pageSize"],
            "page": payload["page"],
        }

        secrule_page_search_response = self._http_request(
            method="GET",
            url_suffix=PAGED_SEARCH_URL,
            params=parameters,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-FM-Auth-Token": auth_token,
            },
        )
        return secrule_page_search_response

    def get_paged_all_collectors(self, auth_token: str, payload: Dict[str, Any]):
        """Calling get paged search api for collector

        Args:
            auth_token (str): authentication token
            payload (Dict[str, Any]): payload to be used for making request
        """
        parameters: Dict[str, Any] = {
            "pageSize": payload["pageSize"],
            "page": payload["page"],
        }

        paged_all_collectors_response = self._http_request(
            method="GET",
            url_suffix=COLLECTOR_URL,
            params=parameters,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-FM-Auth-Token": auth_token,
            },
        )
        return paged_all_collectors_response

    def get_collector_status_byid(self, auth_token: str, collector_id: int):
        """Calling get collector status api by collector id

        Args:
            auth_token (str): authentication token
            payload (Dict[str, Any]): payload to be used for making request
        """
        collector_status_response = self._http_request(
            method="GET",
            url_suffix=f'{COLLECTOR_URL}/status/{collector_id}',
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-FM-Auth-Token": auth_token,
            },
        )
        return collector_status_response


def test_module(client):
    response = client.authenticate_user()
    if response.get("authorized"):
        return "ok"
    else:
        return "Error in API call in FireMonSecurityManager Integrations"


def authenticate_command(client):
    response = client.authenticate_user()
    return CommandResults(
        outputs_prefix="FireMonSecurityManager.Authentication",
        outputs_key_field="token",
        outputs=response.get("token"),
        readable_output=tableToMarkdown(
            name="FireMon SecurityManager Authentication Token:", t={"token": response.get("token")}, removeNull=True
        ),
        raw_response=response,
    )


def create_pp_ticket_command(client, args):
    auth_token_cmd_result = authenticate_command(client)
    auth_token = auth_token_cmd_result.outputs
    payload = dict(
        domainId=args.get("domain_id"),
        workflowName=args.get("workflow_name"),
        requirements=args.get("requirement"),
        priority=args.get("priority"),
        due_date=args.get("due_date"),
    )
    response = client.create_pp_ticket(auth_token, payload)
    return CommandResults(
        outputs_prefix="FireMonSecurityManager.CreatePPTicket",
        outputs_key_field="pp_ticket",
        outputs=response,
        readable_output=tableToMarkdown(name="FireMon SecurityManager Create PP Ticket:", t=response, removeNull=True),
        raw_response=response,
    )


def pca_command(client, args):
    auth_token_cmd_result = authenticate_command(client)
    auth_token = auth_token_cmd_result.outputs
    payload = dict(
        sources=list(args.get("sources").split(",")),
        destinations=list(args.get("destinations").split(",")),
        services=list(args.get("services").split(",")),
        action=args.get("action"),
        domainId=args.get("domain_id"),
        deviceGroupId=args.get("device_group_id"),
    )
    payload_rule_rec = client.rule_rec_api(auth_token, payload)
    result = {}
    list_of_device_changes = payload_rule_rec["deviceChanges"]
    if len(list_of_device_changes) == 0:
        return CommandResults(
            outputs_prefix="FireMonSecurityManager.PCA",
            outputs_key_field="pca",
            outputs="No matching rule found for this requirement, Please go back and update the requirement",
            readable_output=tableToMarkdown(
                name="FireMon SecurityManager PCA:",
                t={"pca": "No matching rule found for this requirement, Please go back and update the requirement"},
                removeNull=True,
            ),
            raw_response="No matching rule found for this requirement, Please go back and update the requirement",
        )

    for i in range(len(list_of_device_changes)):
        filtered_rules = []
        list_of_rule_changes = list_of_device_changes[i]["ruleChanges"]
        device_id = list_of_device_changes[i]["deviceId"]
        headers = {"Content-Type": "application/json", "accept": "application/json", "X-FM-Auth-Token": auth_token}

        for j in range(len(list_of_rule_changes)):
            if list_of_rule_changes[j]["action"] != "NONE":
                filtered_rules.append(list_of_rule_changes[j])

        if filtered_rules is None:
            return "No Rules Needs to be changed!"

        result[i] = client.validate_pca_change(
            filtered_rules, PCA_URL_SUFFIX.format(args.get("domain_id"), device_id), headers
        )
        if "requestId" in result[i]:
            del result[i]["requestId"]
        if "pcaResult" in result[i]:
            if "startDate" in result[i]["pcaResult"]:
                del result[i]["pcaResult"]["startDate"]
            if "endDate" in result[i]["pcaResult"]:
                del result[i]["pcaResult"]["endDate"]
            if "affectedRules" in result[i]["pcaResult"]:
                del result[i]["pcaResult"]["affectedRules"]

            if "device" in result[i]["pcaResult"]:
                if "parents" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["parents"]
                if "children" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["children"]
                if "gpcDirtyDate" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["gpcDirtyDate"]
                if "gpcComputeDate" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["gpcComputeDate"]
                if "gpcImplementDate" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["gpcImplementDate"]
                if "state" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["state"]
                if "managedType" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["managedType"]
                if "gpcStatus" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["gpcStatus"]
                if "updateMemberRuleDoc" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["updateMemberRuleDoc"]
                if "devicePack" in result[i]["pcaResult"]["device"]:
                    del result[i]["pcaResult"]["device"]["devicePack"]

    return CommandResults(
        outputs_prefix="FireMonSecurityManager.PCA",
        outputs_key_field="pca",
        outputs=result,
        readable_output=tableToMarkdown(
            name="FireMon SecurityManager PCA:",
            t=result[0]["pcaResult"]["preChangeAssessmentControls"],
            removeNull=True,
        ),
        raw_response=list_of_device_changes,
    )


def get_paged_search_secrule(client: Client, auth_token: str, payload: Dict[str, Any]) -> List:
    """Make subsequent requests using client and other arguments

    Args:
        client (Client): `Client` class object
        auth_token (str): authentication token to use
        payload (Dict[str, Any]): parameter payload to use

    Returns:
        (List[Dict[str, Any]]): results list
    """
    result = list()
    response = client.get_paged_search_secrule(auth_token, payload)
    total_pages = response.get("total", 0) // payload.get("pageSize")

    result.extend(response.get("results", list()))

    while payload.get("page") < total_pages:  # NOTE: Check if we can implement async here
        payload["page"] += 1
        response = client.get_paged_search_secrule(auth_token, payload)
        result.extend(response.get("results", list()))

    return result


def secmgr_secrule_search_command(client: Client, args: Dict[str, Any]):
    """Searches for security rules using the SIQL language query

    Args:
        client (Client): `Client` class object
        args (Dict[str, Any]): demisto arguments passed
    """
    auth_token_cmd_result = authenticate_command(client)
    auth_token = auth_token_cmd_result.outputs

    # page size can't be less than 1
    page_size = 1 if int(args.get("pageSize", 10)) < 1 else int(args.get("pageSize", 10))
    payload = dict(
        q=str(args.get("q")),
        pageSize=page_size,
        page=int(args.get("page", 0)),
    )
    results = get_paged_search_secrule(client, auth_token, payload)

    return CommandResults(
        outputs_prefix="FireMonSecurityManager.SIQL",
        outputs_key_field="matchId",
        outputs=results,
        readable_output=tableToMarkdown(
            name="FireMon SecurityManager SIQL:",
            t=results,
            removeNull=True,
            headerTransform=pascalToSpace,
        ),
        raw_response=results,
    )


def get_paged_all_collectors(client: Client, auth_token: str, payload: Dict[str, Any]) -> List:
    """Make subsequent requests using client and other arguments

    Args:
        client (Client): `Client` class object
        auth_token (str): authentication token to use
        payload (Dict[str, Any]): parameter payload to use

    Returns:
        (List[Dict[str, Any]]): results list
    """
    result = list()
    response = client.get_paged_all_collectors(auth_token, payload)
    total_pages = response.get("total", 0) // payload.get("pageSize")

    result.extend(response.get("results", list()))

    while payload.get("page") < total_pages:  # NOTE: Check if we can implement async here
        payload["page"] += 1
        response = client.get_paged_all_collectors(auth_token, payload)
        result.extend(response.get("results", list()))

    return result


def collector_get_all_command(client: Client, args: Dict[str, Any]):
    """List all the collectors in the inventory

    Args:
        client (Client): `Client` class object
        args (Dict[str, Any]): demisto arguments passed
    """
    auth_token_cmd_result = authenticate_command(client)
    auth_token = auth_token_cmd_result.outputs

    page_size = 1 if int(args.get("pageSize", 10)) < 1 else int(args.get("pageSize", 10))
    payload = dict(
        pageSize=page_size,
        page=int(args.get("page", 0)),
    )
    results = get_paged_all_collectors(client, auth_token, payload)

    return CommandResults(
        outputs_prefix="FireMonSecurityManager.Collector",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            name="FireMon Collector:",
            t=results,
            removeNull=True,
            headerTransform=pascalToSpace,
        ),
        raw_response=results,
    )


def collector_get_status_byid_command(client: Client, args: Dict[str, Any]):
    """Get collector status by ID

    Args:
        client (Client): `Client` class object
        args (Dict[str, Any]): demisto arguments passed
    """
    auth_token_cmd_result = authenticate_command(client)
    auth_token = auth_token_cmd_result.outputs

    collector_id = int(args.get("id", 0))
    results = client.get_collector_status_byid(auth_token, collector_id)

    return CommandResults(
        outputs_prefix="FireMonSecurityManager.CollectorStatus",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            name="FireMon Collector:",
            t=results,
            removeNull=True,
            headerTransform=pascalToSpace,
        ),
        raw_response=results,
    )


def main():
    username = demisto.params().get("credentials").get("identifier")
    password = demisto.params().get("credentials").get("password")
    verify_certificate = not demisto.params().get("insecure", False)
    base_url = urljoin(demisto.params()["url"])
    proxy = demisto.params().get("proxy", False)
    try:
        client = Client(
            base_url=base_url, verify=verify_certificate, proxy=proxy, username=username, password=password
        )
        if demisto.command() == "test-module":
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == "firemon-user-authentication":
            return_results(authenticate_command(client))
        elif demisto.command() == "firemon-create-pp-ticket":
            return_results(create_pp_ticket_command(client, demisto.args()))
        elif demisto.command() == "firemon-pca":
            return_results(pca_command(client, demisto.args()))
        elif demisto.command() == "firemon-secmgr-secrule-search":
            return_results(secmgr_secrule_search_command(client, demisto.args()))
        elif demisto.command() == "firemon-collector-get-all":
            return_results(collector_get_all_command(client, demisto.args()))
        elif demisto.command() == "firemon-collector-get-status-byid":
            return_results(collector_get_status_byid_command(client, demisto.args()))
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
