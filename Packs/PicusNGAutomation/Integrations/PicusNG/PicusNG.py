import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key

        if self.api_key:
            self._headers = {"Content-Type": "application/json"}

        self.access_token = self.get_access_token()
        picus_headers = {"Content-Type": "application/json", "Authorization": ""}
        picus_headers["Authorization"] = "Bearer " + self.access_token
        self._headers = picus_headers

    def get_access_token(self):
        picus_token_data = {"refresh_token": ""}
        picus_token_data["refresh_token"] = str(self.api_key)

        picus_auth_endpoint = "/v1/auth/token"
        picus_auth_response = self.http_request(method="POST", json_data=picus_token_data, url_suffix=picus_auth_endpoint)
        picus_accessToken = picus_auth_response["token"]

        return picus_accessToken

    def http_request(
        self,
        method: str,
        url_suffix: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        additional_headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        data: Optional[Dict] = None,
    ):
        headers = {**additional_headers, **self._headers} if additional_headers else self._headers
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            data=data,
            headers=headers,
            timeout=timeout,
            ok_codes=(200,),
        )

    def get_agent_list(self):
        return self.http_request(method="GET", url_suffix="/v1/agents")

    def get_agent_detail(self, agent_id: str):
        return self.http_request(method="GET", url_suffix="/v1/agents/" + agent_id)

    def get_integration_agent_list(self):
        return self.http_request(method="GET", url_suffix="/v1/integrations/agents")

    def get_template_list(self, query_parameters: str):
        return self.http_request(method="GET", url_suffix="/v1/templates" + query_parameters)

    def create_simulation(self, picus_post_data_simulation: Dict):
        return self.http_request(method="POST", url_suffix="/v1/simulations", json_data=picus_post_data_simulation)

    def get_simulation_list(self, query_parameters: str):
        return self.http_request(method="GET", url_suffix="/v1/simulations" + query_parameters)

    def simulate_now(self, simulation_id: str):
        return self.http_request(method="POST", url_suffix="/v1/simulations/" + simulation_id + "/simulate-now")

    def get_simulation_detail(self, simulation_id: str):
        return self.http_request(method="GET", url_suffix="/v1/simulations/" + simulation_id)

    def get_latest_simulation_result(self, simulation_id: str):
        return self.http_request(method="GET", url_suffix="/v1/simulations/" + simulation_id + "/run/latest")

    def get_simulation_result(self, simulation_id: str, run_id: str):
        return self.http_request(method="GET", url_suffix="/v1/simulations/" + simulation_id + "/run/" + run_id)

    def get_simulation_threats(self, query_parameters: str, simulation_id: str, run_id: str):
        return self.http_request(
            method="GET", url_suffix="/v1/simulations/" + simulation_id + "/run/" + run_id + "/threats" + query_parameters
        )

    def get_simulation_actions(self, query_parameters: str, simulation_id: str, run_id: str, threat_id: str):
        return self.http_request(
            method="GET",
            url_suffix="/v1/simulations/"
            + simulation_id
            + "/run/"
            + run_id
            + "/threats/"
            + threat_id
            + "/actions"
            + query_parameters,
        )

    def get_mitigation_devices(self, query_parameters: str):
        return self.http_request(method="GET", url_suffix="/v1/mitigation/devices" + query_parameters)

    def get_signature_list(self, query_parameters: str, device_id: str):
        return self.http_request(
            method="GET", url_suffix="/v1/mitigation/devices/" + device_id + "/signatures" + query_parameters
        )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    picus_accessToken: str = ""

    try:
        client.get_access_token()
        message = "ok"
    except Exception as e:
        if (
            "Forbidden" in str(e)
            or "Authorization" in str(e)
            or "NewConnectionError" in str(e)
            or "Unauthorized" in str(e)
            or picus_accessToken is None
        ):
            message = "Authorization Error: make sure API Key or Picus URL is correctly set"
        else:
            raise e
    return message


def get_agent_list_command(client: Client) -> CommandResults:
    picus_endpoint_response = client.get_agent_list()
    picus_agents = picus_endpoint_response["agents"]
    for agent in picus_agents:
        agent["created_at"] = str(datetime.fromtimestamp(agent["created_at"] / 1000))

    table_name = "Picus Agent List"
    table_headers = ["id", "name", "status", "type", "version", "created_at", "platform_name", "platform_architecture"]
    md_table = tableToMarkdown(
        table_name, picus_agents, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_agents, outputs_prefix="Picus.agentlist")


def get_agent_detail_command(client: Client) -> CommandResults:
    agent_id = demisto.args().get("id")
    tmp_attack_modules: Dict = {}

    picus_endpoint_response = client.get_agent_detail(agent_id)
    picus_agent_detail = picus_endpoint_response
    picus_agent_attack_modules = picus_endpoint_response["attack_modules"]
    picus_agent_detail.pop("attack_modules")

    for modules in picus_agent_attack_modules:
        tmp_attack_modules[modules["name"]] = modules["enabled"]

    picus_agent_detail.update(tmp_attack_modules)

    table_name = "Picus Agent Details"
    table_headers = [
        "id",
        "name",
        "status",
        "File Download",
        "Endpoint Scenario",
        "Web Application",
        "Email",
        "Data Exfiltration",
    ]
    md_table = tableToMarkdown(
        table_name, picus_agent_detail, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    results = CommandResults(readable_output=md_table, outputs=picus_agent_detail, outputs_prefix="Picus.agentdetail")
    return results


def get_integration_agent_list_command(client: Client) -> CommandResults:
    picus_endpoint_response = client.get_integration_agent_list()
    picus_integration_agents = picus_endpoint_response["integration_agents"]
    for agent in picus_integration_agents:
        agent["created_at"] = str(datetime.fromtimestamp(agent["created_at"] / 1000))
        agent["updated_at"] = str(datetime.fromtimestamp(agent["updated_at"] / 1000))

    table_name = "Picus Integration Agent List"
    table_headers = ["id", "name", "status", "created_at", "updated_at", "installed", "token_expired"]
    md_table = tableToMarkdown(
        table_name, picus_integration_agents, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_integration_agents, outputs_prefix="Picus.integrationagentlist")


def get_template_list_command(client: Client) -> CommandResults:
    query_parameters: str = ""
    offset = demisto.args().get("offset")
    limit = demisto.args().get("limit")

    if offset is not None and limit is None:
        raise DemistoException("limit should be set.")
    elif offset is None and limit is not None:
        raise DemistoException("offset should be set.")

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset

    picus_endpoint_response = client.get_template_list(query_parameters)
    picus_templates = picus_endpoint_response["templates"]

    table_name = "Picus Template List"
    table_headers = ["id", "name", "description", "threat_count", "category_name", "content_type", "agent_types"]
    md_table = tableToMarkdown(
        table_name, picus_templates, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_templates, outputs_prefix="Picus.templatelist")


def create_simulation_command(client: Client) -> CommandResults:
    picus_simulation_creation_results: Dict = {}

    agent_id = int(demisto.args().get("agent_id"))
    simulation_description = demisto.args().get("description")
    simulation_name = demisto.args().get("name")
    schedule_now = bool(demisto.args().get("schedule_now"))
    template_id = int(demisto.args().get("template_id"))

    picus_post_data_simulation = {
        "agent_id": agent_id,
        "description": simulation_description,
        "name": simulation_name,
        "schedule_now": schedule_now,
        "template_id": template_id,
    }
    picus_endpoint_response = client.create_simulation(picus_post_data_simulation)

    picus_endpoint_response_all = picus_endpoint_response
    picus_created_simulation = picus_endpoint_response["simulation"]
    picus_simulation_run_info = picus_endpoint_response["run_info"]
    picus_simulation_creation_results["simulation_id"] = picus_created_simulation["id"]
    picus_simulation_creation_results["name"] = picus_created_simulation["name"]
    picus_simulation_creation_results["description"] = picus_created_simulation["description"]
    picus_simulation_creation_results["run_immediately"] = picus_endpoint_response_all["run_immediately"]
    picus_simulation_creation_results["simulation_status"] = picus_simulation_run_info["status"]

    table_name = "Picus Simulation Create Status"
    table_headers = ["simulation_id", "name", "description", "run_immediately", "simulation_status"]
    md_table = tableToMarkdown(
        table_name,
        picus_simulation_creation_results,
        headers=table_headers,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=md_table, outputs=picus_simulation_creation_results, outputs_prefix="Picus.createsimulation"
    )


def get_simulation_list_command(client: Client) -> CommandResults:
    query_parameters: str = ""
    offset = demisto.args().get("offset")
    limit = demisto.args().get("limit")

    if offset is not None and limit is None:
        raise DemistoException("limit should be set.")
    elif offset is None and limit is not None:
        raise DemistoException("offset sohuld be set.")

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset

    picus_endpoint_response = client.get_simulation_list(query_parameters)
    picus_simulations = picus_endpoint_response["simulations"]

    table_name = "Picus Simulation List"
    table_headers = [
        "simulation_id",
        "simulation_name",
        "status",
        "has_detection_analysis",
        "has_last_run_detection_analysis",
        "last_detection_security_score",
        "last_prevention_security_score",
        "agent",
    ]
    md_table = tableToMarkdown(
        table_name, picus_simulations, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_simulations, outputs_prefix="Picus.simulationlist")


def simulate_now_command(client: Client) -> CommandResults:
    simulation_id = demisto.args().get("id")

    picus_endpoint_response = client.simulate_now(simulation_id)
    picus_simulateNow = picus_endpoint_response["run_info"]

    table_name = "Picus Simulate Now Status"
    table_headers = ["browser", "id", "status"]
    md_table = tableToMarkdown(
        table_name, picus_simulateNow, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_simulateNow, outputs_prefix="Picus.simulatenow")


def get_simulation_detail_command(client: Client) -> CommandResults:
    simulation_id = demisto.args().get("id")

    picus_endpoint_response = client.get_simulation_detail(simulation_id)
    picus_simulationDetail = picus_endpoint_response["simulation_run"]
    for sRun in picus_simulationDetail:
        sRun["started_at"] = str(datetime.fromtimestamp(sRun["started_at"] / 1000))
        sRun["completed_at"] = str(datetime.fromtimestamp(sRun["completed_at"] / 1000))

    table_name = "Picus Simulation Detail"
    table_headers = ["id", "started_at", "completed_at", "status"]
    md_table = tableToMarkdown(
        table_name, picus_simulationDetail, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_simulationDetail, outputs_prefix="Picus.simulationDetail")


def get_latest_simulation_result_command(client: Client) -> CommandResults:
    simulation_id = demisto.args().get("id")

    picus_latestSimulation = client.get_latest_simulation_result(simulation_id)

    if picus_latestSimulation["status"] == "COMPLETED":
        picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"] / 1000))
        picus_latestSimulation["completed_at"] = str(datetime.fromtimestamp(picus_latestSimulation["completed_at"] / 1000))
        picus_latestSimulation["prevention_security_score"] = picus_latestSimulation["results"]["prevention"]["security_score"]
        picus_latestSimulation["prevention_total_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
            "total_count"
        ]
        picus_latestSimulation["prevention_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
            "blocked_count"
        ]
        picus_latestSimulation["prevention_not_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
            "not_blocked_count"
        ]
        picus_latestSimulation["prevention_not_tested_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
            "not_tested_count"
        ]
        picus_latestSimulation["prevention_total_attacker_objectives"] = picus_latestSimulation["results"]["prevention"][
            "attacker_objectives"
        ]["total_count"]
        picus_latestSimulation["prevention_achieved_objectives"] = picus_latestSimulation["results"]["prevention"][
            "attacker_objectives"
        ]["achived_count"]
        picus_latestSimulation["prevention_unachieved_objectives"] = picus_latestSimulation["results"]["prevention"][
            "attacker_objectives"
        ]["unachived_count"]
        picus_latestSimulation["prevention_not_tested_objectives"] = picus_latestSimulation["results"]["prevention"][
            "attacker_objectives"
        ]["not_tested_count"]
        picus_latestSimulation["has_detection_analysis"] = picus_latestSimulation["results"]["has_detection_analysis"]
    else:
        picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"] / 1000))

    table_name = "Picus Latest Simulation Result"
    table_headers = [
        "started_at",
        "completed_at",
        "simulation_id",
        "simulation_run_id",
        "template_id",
        "status",
        "prevention_security_score",
        "prevention_total_threat",
        "prevention_blocked_threat",
        "prevention_not_blocked_threat",
        "prevention_not_tested_threat",
        "prevention_total_attacker_objectives",
        "prevention_achieved_objectives",
        "prevention_unachieved_objectives",
        "prevention_not_tested_objectives",
        "has_detection_analysis",
    ]
    md_table = tableToMarkdown(
        table_name, picus_latestSimulation, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_latestSimulation, outputs_prefix="Picus.latestSimulationResult")


def get_simulation_result_command(client: Client) -> CommandResults:
    simulation_id = demisto.args().get("id")
    run_id = demisto.args().get("run_id")

    picus_latestSimulation = client.get_simulation_result(simulation_id, run_id)

    picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"] / 1000))
    picus_latestSimulation["completed_at"] = str(datetime.fromtimestamp(picus_latestSimulation["completed_at"] / 1000))
    picus_latestSimulation["prevention_security_score"] = picus_latestSimulation["results"]["prevention"]["security_score"]
    picus_latestSimulation["prevention_total_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["total_count"]
    picus_latestSimulation["prevention_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
        "blocked_count"
    ]
    picus_latestSimulation["prevention_not_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
        "not_blocked_count"
    ]
    picus_latestSimulation["prevention_not_tested_threat"] = picus_latestSimulation["results"]["prevention"]["threat"][
        "not_tested_count"
    ]
    picus_latestSimulation["prevention_total_attacker_objectives"] = picus_latestSimulation["results"]["prevention"][
        "attacker_objectives"
    ]["total_count"]
    picus_latestSimulation["prevention_achieved_objectives"] = picus_latestSimulation["results"]["prevention"][
        "attacker_objectives"
    ]["achived_count"]
    picus_latestSimulation["prevention_unachieved_objectives"] = picus_latestSimulation["results"]["prevention"][
        "attacker_objectives"
    ]["unachived_count"]
    picus_latestSimulation["prevention_not_tested_objectives"] = picus_latestSimulation["results"]["prevention"][
        "attacker_objectives"
    ]["not_tested_count"]
    picus_latestSimulation["has_detection_analysis"] = picus_latestSimulation["results"]["has_detection_analysis"]

    table_name = "Picus Simulation Result"
    table_headers = [
        "started_at",
        "completed_at",
        "simulation_id",
        "simulation_run_id",
        "template_id",
        "status",
        "prevention_security_score",
        "prevention_total_threat",
        "prevention_blocked_threat",
        "prevention_not_blocked_threat",
        "prevention_not_tested_threat",
        "prevention_total_attacker_objectives",
        "prevention_achieved_objectives",
        "prevention_unachieved_objectives",
        "prevention_not_tested_objectives",
        "has_detection_analysis",
    ]
    md_table = tableToMarkdown(
        table_name, picus_latestSimulation, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_latestSimulation, outputs_prefix="Picus.SimulationResult")


def get_simulation_threats_command(client: Client) -> CommandResults:
    query_parameters: str = ""
    simulation_id = str(demisto.args().get("id"))
    run_id = str(demisto.args().get("run_id"))
    picus_threat_list = ""

    offset = demisto.args().get("offset")
    limit = demisto.args().get("limit")

    if offset is not None and limit is None:
        raise DemistoException("limit should be set.")
    elif offset is None and limit is not None:
        raise DemistoException("offset sohuld be set.")

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset

    picus_endpoint_response = client.get_simulation_threats(query_parameters, simulation_id, run_id)
    picus_simulationThreats = picus_endpoint_response["threats"]
    for threat in picus_simulationThreats:
        action_count = 0
        threat_objectives = threat["objectives"]
        for objective in threat_objectives:
            action_count += len(objective["actions"])
        threat["action_count"] = action_count
        picus_threat_list += str(threat["threat_id"]) + ","

    if len(picus_threat_list) != 0:
        picus_threat_list = picus_threat_list[:-1]

    table_name = "Picus Simulation Threats"
    table_headers = ["threat_id", "threat_name", "severity", "prevention", "action_count"]
    md_table = tableToMarkdown(
        table_name, picus_simulationThreats, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_threat_list, outputs_prefix="Picus.SimulationThreats")


def get_simulation_actions_command(client: Client) -> CommandResults:
    query_parameters: str = ""
    simulation_id = demisto.args().get("id")
    run_id = demisto.args().get("run_id")
    threat_ids = demisto.args().get("threat_ids")
    threat_ids = list(threat_ids.split(","))
    picus_action_raw_results = ""
    picus_action_results: Dict[str, Any] = {"results": []}

    offset = demisto.args().get("offset")
    limit = demisto.args().get("limit")

    if offset is not None and limit is None:
        raise DemistoException("limit should be set.")
    elif offset is None and limit is not None:
        raise DemistoException("offset sohuld be set.")

    for threat_id in threat_ids:
        if offset is not None and limit is not None:
            query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset
        picus_endpoint_response = client.get_simulation_actions(query_parameters, simulation_id, run_id, threat_id)
        picus_simulationActions = picus_endpoint_response["actions"]
        for action in picus_simulationActions:
            picus_action_raw_results += str(action["action_id"]) + "=" + str(action["prevention"]) + ","
        for action in picus_simulationActions:
            picus_action_results["results"].append(action)

    if len(picus_action_raw_results) != 0:
        picus_action_raw_results = picus_action_raw_results[:-1]
    picus_action_results = picus_action_results["results"]

    table_name = "Picus Simulation Actions"
    table_headers = ["action_id", "display_id", "action_name", "affected_os", "attack_module", "category", "prevention"]
    md_table = tableToMarkdown(
        table_name, picus_action_results, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_action_raw_results, outputs_prefix="Picus.SimulationActions")


def get_mitigation_devices_command(client: Client) -> CommandResults:
    query_parameters: str = ""
    simulation_ids = demisto.args().get("ids")

    if simulation_ids is not None:
        query_parameters = "?" + "simulation_ids=" + simulation_ids

    picus_mitigationDevices = client.get_mitigation_devices(query_parameters)

    table_name = "Picus Mitigation Devices"
    table_headers = ["id", "device_name", "score", "total_action_count", "blocked_action_count", "not_blocked_action_count"]
    md_table = tableToMarkdown(
        table_name, picus_mitigationDevices, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(readable_output=md_table, outputs=picus_mitigationDevices, outputs_prefix="Picus.MitigationDevices")


def get_signature_list_command(client: Client) -> CommandResults:
    device_id = demisto.args().get("device_id")
    action_ids = demisto.args().get("action_ids")
    picus_signature_raw_results: Dict[str, Any] = {"results": []}
    picus_signature_all_results: Dict[str, Any] = {"results": []}

    action_ids = action_ids.split(",")
    for action in action_ids:
        query_parameters = "?" + "action_ids=" + action
        picus_mitigationSignatures = client.get_signature_list(query_parameters, device_id)
        for mitigation in picus_mitigationSignatures:
            mitigation["action_id"] = action
        picus_signature_raw_results["results"].append(picus_mitigationSignatures)

    picus_signature_raw_results = picus_signature_raw_results["results"]
    for raw_results_list in picus_signature_raw_results:
        for raw_results in raw_results_list:
            picus_signature_all_results["results"].append(raw_results)
    picus_signature_all_results = picus_signature_all_results["results"]

    table_name = "Picus Mitigation Signature List"
    table_headers = [
        "action_id",
        "signature_id",
        "name",
        "signature_category",
        "signature_version",
        "product_platform",
        "product_version",
        "vendor_severity",
    ]
    md_table = tableToMarkdown(
        table_name, picus_signature_all_results, headers=table_headers, removeNull=True, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=md_table, outputs=picus_signature_all_results, outputs_prefix="Picus.MitigationSignatures"
    )


def setParamPB():
    agent_id = demisto.args().get("agent_id")
    device_id = demisto.args().get("device_id")
    simulation_id = demisto.args().get("simulation_id")

    param_data = {"agent_id": agent_id, "device_id": device_id, "simulation_id": simulation_id}
    return CommandResults(outputs=param_data, outputs_prefix="Picus.param")


def filterInsecureAttacks():
    threatinfo = demisto.args().get("threatinfo")
    threat_ids = ""

    threatinfo = list(threatinfo.split(","))
    threatinfo = [th_info for th_info in threatinfo if "unblocked" in th_info]

    for th_info in threatinfo:
        threat_id = th_info.split("=")[0]
        threat_ids += str(threat_id) + ","

    if len(threat_ids) != 0:
        threat_ids = threat_ids[:-1]

    return CommandResults(readable_output=threat_ids, outputs=threat_ids, outputs_prefix="Picus.filterinsecure")


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    picus_apikey = params.get("picus_apikey")
    picus_server = params.get("picus_server")
    picus_server = picus_server[:-1] if picus_server.endswith("/") else picus_server
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(api_key=picus_apikey, base_url=picus_server, verify=verify_certificate, proxy=proxy)
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == "picus-get-agent-list":
            return_results(get_agent_list_command(client))
        elif command == "picus-get-agent-detail":
            return_results(get_agent_detail_command(client))
        elif command == "picus-create-simulation":
            return_results(create_simulation_command(client))
        elif command == "picus-get-template-list":
            return_results(get_template_list_command(client))
        elif command == "picus-get-integration-agent-list":
            return_results(get_integration_agent_list_command(client))
        elif command == "picus-get-simulation-list":
            return_results(get_simulation_list_command(client))
        elif command == "picus-simulate-now":
            return_results(simulate_now_command(client))
        elif command == "picus-get-simulation-detail":
            return_results(get_simulation_detail_command(client))
        elif command == "picus-get-latest-simulation-result":
            return_results(get_latest_simulation_result_command(client))
        elif command == "picus-get-simulation-result":
            return_results(get_simulation_result_command(client))
        elif command == "picus-get-simulation-threats":
            return_results(get_simulation_threats_command(client))
        elif command == "picus-get-simulation-actions":
            return_results(get_simulation_actions_command(client))
        elif command == "picus-get-mitigation-devices":
            return_results(get_mitigation_devices_command(client))
        elif demisto.command() == "picus-get-signature-list":
            return_results(get_signature_list_command(client))
        elif command == "picus-set-paramPB":
            return_results(setParamPB())
        elif command == "picus-filter-insecure-attacks":
            return_results(filterInsecureAttacks())

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
