import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
import json
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

# flake8: noqa
''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
verify_certificate = not demisto.params().get('insecure', False)


''' COMMAND FUNCTIONS '''


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    picus_accessToken: str = ''

    try:
        picus_server = str(demisto.params().get("picus_server"))
        picus_server = picus_server[:-1] if picus_server.endswith("/") else picus_server
        picus_apikey = demisto.params().get("picus_apikey")
        picus_headers = {"Content-Type": "application/json"}
        picus_token_data = {"refresh_token": ""}
        picus_token_data["refresh_token"] = str(picus_apikey)


        picus_auth_endpoint = "/v1/auth/token"
        picus_req_url = str(picus_server) + picus_auth_endpoint
        picus_session = requests.Session()
        if not demisto.params().get('proxy', False):
            picus_session.trust_env = False
        picus_auth_response = picus_session.post(picus_req_url, headers=picus_headers, verify=verify_certificate,json=picus_token_data)
        picus_auth_response.raise_for_status()
        picus_accessToken = json.loads(picus_auth_response.text)["token"]
        message = 'ok'
    except Exception as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e) or 'NewConnectionError' in str(e) or 'Unauthorized' in str(e) or picus_accessToken is None:
            message = 'Authorization Error: make sure API Key or Picus URL is correctly set'
        else:
            raise e
    return message

def getAccessToken():
    picus_server = str(demisto.params().get("picus_server"))
    picus_server = picus_server[:-1] if picus_server.endswith("/") else picus_server
    picus_apikey = demisto.params().get("picus_apikey")
    picus_headers = {"Content-Type": "application/json"}
    picus_token_data = {"refresh_token": ""}
    picus_token_data["refresh_token"] = str(picus_apikey)

    picus_auth_endpoint = "/v1/auth/token"
    picus_req_url = str(picus_server) + picus_auth_endpoint
    picus_session = requests.Session()
    if not demisto.params().get('proxy', False):
        picus_session.trust_env = False
    picus_auth_response = picus_session.post(picus_req_url, headers=picus_headers, verify=verify_certificate, json=picus_token_data)
    if picus_auth_response.status_code!=200:
        return_error(picus_auth_response.text)
    picus_accessToken = json.loads(picus_auth_response.text)["token"]

    return picus_accessToken

def getAgentList():
    picus_endpoint = "/v1/agents"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers,verify=verify_certificate)
    picus_agents = json.loads(picus_endpoint_response.text)["agents"]
    for agent in picus_agents:
        agent["created_at"] = str(datetime.fromtimestamp(agent["created_at"] / 1000))

    table_name = "Picus Agent List"
    table_headers = ['id','name','status','type','version','created_at','platform_name','platform_architecture']
    md_table = tableToMarkdown(table_name, picus_agents, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_agents, outputs_prefix="Picus.agentlist")
    return results

def getAgentDetail():
    picus_endpoint = "/v1/agents/"
    agent_id = demisto.args().get('id')
    tmp_attack_modules: Dict = {}
    picus_endpoint = picus_endpoint + agent_id
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url,headers=picus_headers, verify=verify_certificate)
    picus_agent_detail = json.loads(picus_endpoint_response.text)
    picus_agent_attack_modules = json.loads(picus_endpoint_response.text)["attack_modules"]
    picus_agent_detail.pop("attack_modules")

    for modules in picus_agent_attack_modules:
        tmp_attack_modules[modules["name"]]=modules["enabled"]

    picus_agent_detail.update(tmp_attack_modules)

    table_name = "Picus Agent Details"
    table_headers = ['id','name','status','File Download','Endpoint Scenario','Web Application','Email','Data Exfiltration']
    md_table = tableToMarkdown(table_name, picus_agent_detail, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_agent_detail, outputs_prefix="Picus.agentdetail")
    return results

def getIntegrationAgentList():
    picus_endpoint = "/v1/integrations/agents"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers,verify=verify_certificate)
    picus_integration_agents = json.loads(picus_endpoint_response.text)["integration_agents"]
    for agent in picus_integration_agents:
        agent["created_at"] = str(datetime.fromtimestamp(agent["created_at"] / 1000))
        agent["updated_at"] = str(datetime.fromtimestamp(agent["updated_at"] / 1000))

    table_name = "Picus Integration Agent List"
    table_headers = ['id','name','status','created_at','updated_at','installed','token_expired']
    md_table = tableToMarkdown(table_name, picus_integration_agents, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_integration_agents, outputs_prefix="Picus.integrationagentlist")
    return results

def getTemplateList():
    picus_endpoint = "/v1/templates"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    offset = demisto.args().get('offset')
    limit = demisto.args().get('limit')

    if offset is not None and limit is None:
        return "limit should be set."
    elif offset is None and limit is not None:
        return "offset sohuld be set."

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset
        picus_req_url = picus_req_url + query_parameters

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_templates = json.loads(picus_endpoint_response.text)["templates"]

    table_name = "Picus Template List"
    table_headers = ['id','name','description','threat_count','category_name','content_type','agent_types']
    md_table = tableToMarkdown(table_name, picus_templates, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_templates, outputs_prefix="Picus.templatelist")
    return results


def createSimulation():
    picus_endpoint = "/v1/simulations"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_simulation_creation_results: Dict = {}

    agent_id = int(demisto.args().get('agent_id'))
    simulation_description = demisto.args().get('description')
    simulation_name = demisto.args().get('name')
    schedule_now = bool(demisto.args().get('schedule_now'))
    template_id = int(demisto.args().get('template_id'))

    picus_post_data_simulation = {"agent_id":agent_id,"description":simulation_description,"name":simulation_name,"schedule_now":schedule_now,"template_id":template_id}
    picus_endpoint_response = requests.post(picus_req_url,headers=picus_headers, verify=verify_certificate,json=picus_post_data_simulation)
    if picus_endpoint_response.status_code == 400:
        return json.loads(picus_endpoint_response.text)

    picus_endpoint_response_all = json.loads(picus_endpoint_response.text)
    picus_created_simulation = json.loads(picus_endpoint_response.text)["simulation"]
    picus_simulation_run_info = json.loads(picus_endpoint_response.text)["run_info"]
    picus_simulation_creation_results["simulation_id"] = picus_created_simulation["id"]
    picus_simulation_creation_results["name"] = picus_created_simulation["name"]
    picus_simulation_creation_results["description"] = picus_created_simulation["description"]
    picus_simulation_creation_results["run_immediately"] = picus_endpoint_response_all["run_immediately"]
    picus_simulation_creation_results["simulation_status"] = picus_simulation_run_info["status"]

    table_name = "Picus Simulation Create Status"
    table_headers = ['simulation_id','name','description','run_immediately','simulation_status']
    md_table = tableToMarkdown(table_name, picus_simulation_creation_results, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_simulation_creation_results, outputs_prefix="Picus.createsimulation")
    return results

def getSimulationList():
    picus_endpoint = "/v1/simulations"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    offset = demisto.args().get('offset')
    limit = demisto.args().get('limit')

    if offset is not None and limit is None:
        return "limit should be set."
    elif offset is None and limit is not None:
        return "offset sohuld be set."

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset
        picus_req_url = picus_req_url + query_parameters

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_simulations = json.loads(picus_endpoint_response.text)["simulations"]

    table_name = "Picus Simulation List"
    table_headers = ['simulation_id','simulation_name','status','has_detection_analysis','has_last_run_detection_analysis','last_detection_security_score','last_prevention_security_score','agent']
    md_table = tableToMarkdown(table_name, picus_simulations, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_simulations, outputs_prefix="Picus.simulationlist")
    return results

def simulateNow():
    picus_endpoint = "/v1/simulations/"
    simulation_id = demisto.args().get('id')
    picus_endpoint = picus_endpoint + simulation_id + "/simulate-now"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
    if picus_endpoint_response.status_code != 200:
        return json.loads(picus_endpoint_response.text)["message"]
    picus_simulateNow = json.loads(picus_endpoint_response.text)["run_info"]

    table_name = "Picus Simulate Now Status"
    table_headers = ['browser','id','status']
    md_table = tableToMarkdown(table_name, picus_simulateNow, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_simulateNow, outputs_prefix="Picus.simulatenow")
    return results

def getSimulationDetail():
    picus_endpoint = "/v1/simulations/"
    simulation_id = demisto.args().get('id')
    picus_endpoint = picus_endpoint + simulation_id
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_simulationDetail = json.loads(picus_endpoint_response.text)["simulation_run"]
    for sRun in picus_simulationDetail:
        sRun["started_at"] = str(datetime.fromtimestamp(sRun["started_at"]/1000))
        sRun["completed_at"] = str(datetime.fromtimestamp(sRun["completed_at"]/1000))

    table_name = "Picus Simulation Detail"
    table_headers = ['id','started_at','completed_at','status']
    md_table = tableToMarkdown(table_name, picus_simulationDetail, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_simulationDetail, outputs_prefix="Picus.simulationDetail")
    return results

def getLatestSimulationResult():
    picus_endpoint = "/v1/simulations/"
    simulation_id = demisto.args().get('id')
    picus_endpoint = picus_endpoint + simulation_id + "/run/latest"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_latestSimulation = json.loads(picus_endpoint_response.text)

    if picus_latestSimulation["status"] == "COMPLETED":
        picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"]/1000))
        picus_latestSimulation["completed_at"] = str(datetime.fromtimestamp(picus_latestSimulation["completed_at"]/1000))
        picus_latestSimulation["prevention_security_score"] = picus_latestSimulation["results"]["prevention"]["security_score"]
        picus_latestSimulation["prevention_total_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["total_count"]
        picus_latestSimulation["prevention_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["blocked_count"]
        picus_latestSimulation["prevention_not_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["not_blocked_count"]
        picus_latestSimulation["prevention_not_tested_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["not_tested_count"]
        picus_latestSimulation["prevention_total_attacker_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["total_count"]
        picus_latestSimulation["prevention_achieved_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["achived_count"]
        picus_latestSimulation["prevention_unachieved_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["unachived_count"]
        picus_latestSimulation["prevention_not_tested_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["not_tested_count"]
        picus_latestSimulation["has_detection_analysis"] = picus_latestSimulation["results"]["has_detection_analysis"]
    else:
        picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"] / 1000))

    table_name = "Picus Latest Simulation Result"
    table_headers = ['started_at','completed_at','simulation_id','simulation_run_id','template_id','status','prevention_security_score','prevention_total_threat','prevention_blocked_threat','prevention_not_blocked_threat','prevention_not_tested_threat','prevention_total_attacker_objectives','prevention_achieved_objectives','prevention_unachieved_objectives','prevention_not_tested_objectives','has_detection_analysis']
    md_table = tableToMarkdown(table_name, picus_latestSimulation, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_latestSimulation, outputs_prefix="Picus.latestSimulationResult")
    return results

def getSimulationResult():
    picus_endpoint = "/v1/simulations/"
    simulation_id = demisto.args().get('id')
    run_id = demisto.args().get('run_id')
    picus_endpoint = picus_endpoint + simulation_id + "/run/" + run_id
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_latestSimulation = json.loads(picus_endpoint_response.text)
    picus_latestSimulation["started_at"] = str(datetime.fromtimestamp(picus_latestSimulation["started_at"]/1000))
    picus_latestSimulation["completed_at"] = str(datetime.fromtimestamp(picus_latestSimulation["completed_at"]/1000))
    picus_latestSimulation["prevention_security_score"] = picus_latestSimulation["results"]["prevention"]["security_score"]
    picus_latestSimulation["prevention_total_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["total_count"]
    picus_latestSimulation["prevention_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["blocked_count"]
    picus_latestSimulation["prevention_not_blocked_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["not_blocked_count"]
    picus_latestSimulation["prevention_not_tested_threat"] = picus_latestSimulation["results"]["prevention"]["threat"]["not_tested_count"]
    picus_latestSimulation["prevention_total_attacker_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["total_count"]
    picus_latestSimulation["prevention_achieved_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["achived_count"]
    picus_latestSimulation["prevention_unachieved_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["unachived_count"]
    picus_latestSimulation["prevention_not_tested_objectives"] = picus_latestSimulation["results"]["prevention"]["attacker_objectives"]["not_tested_count"]
    picus_latestSimulation["has_detection_analysis"] = picus_latestSimulation["results"]["has_detection_analysis"]

    table_name = "Picus Simulation Result"
    table_headers = ['started_at','completed_at','simulation_id','simulation_run_id','template_id','status','prevention_security_score','prevention_total_threat','prevention_blocked_threat','prevention_not_blocked_threat','prevention_not_tested_threat','prevention_total_attacker_objectives','prevention_achieved_objectives','prevention_unachieved_objectives','prevention_not_tested_objectives','has_detection_analysis']
    md_table = tableToMarkdown(table_name, picus_latestSimulation, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_latestSimulation, outputs_prefix="Picus.SimulationResult")
    return results

def getSimulationThreats():
    picus_endpoint = "/v1/simulations/"
    simulation_id = str(demisto.args().get('id'))
    run_id = str(demisto.args().get('run_id'))
    picus_endpoint = picus_endpoint + simulation_id + "/run/" + run_id + "/threats"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_threat_list = ""

    offset = demisto.args().get('offset')
    limit = demisto.args().get('limit')

    if offset is not None and limit is None:
        return "limit should be set."
    elif offset is None and limit is not None:
        return "offset sohuld be set."

    if offset is not None and limit is not None:
        query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset
        picus_req_url = picus_req_url + query_parameters

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_simulationThreats = json.loads(picus_endpoint_response.text)["threats"]
    for threat in picus_simulationThreats:
        action_count = 0
        threat_objectives= threat["objectives"]
        for objective in threat_objectives:
            action_count += len(objective["actions"])
        threat["action_count"] = action_count
        picus_threat_list += str(threat["threat_id"]) + ","

    if len(picus_threat_list) != 0:
        picus_threat_list = picus_threat_list[:-1]

    table_name = "Picus Simulation Threats"
    table_headers = ['threat_id','threat_name','severity','prevention','action_count']
    md_table = tableToMarkdown(table_name, picus_simulationThreats, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_threat_list, outputs_prefix="Picus.SimulationThreats")
    return results

def getSimulationActions():
    simulation_id = demisto.args().get('id')
    run_id = demisto.args().get('run_id')
    threat_ids = demisto.args().get('threat_ids')
    threat_ids = list(threat_ids.split(","))
    picus_action_raw_results = ""
    picus_action_results: Dict[str, Any] = {"results": []}

    offset = demisto.args().get('offset')
    limit = demisto.args().get('limit')

    if offset is not None and limit is None:
        return "limit should be set."
    elif offset is None and limit is not None:
        return "offset sohuld be set."

    for threat_id in threat_ids:
        picus_endpoint = "/v1/simulations/"
        picus_endpoint = picus_endpoint + str(simulation_id) + "/run/" + str(run_id) + "/threats/" + str(threat_id) + "/actions"
        picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
        if offset is not None and limit is not None:
            query_parameters = "?" + "limit=" + limit + "&" + "offset=" + offset
            picus_req_url = picus_req_url + query_parameters
        picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
        picus_simulationActions = json.loads(picus_endpoint_response.text)["actions"]
        for action in picus_simulationActions:
            picus_action_raw_results += str(action["action_id"]) + "=" + str(action["prevention"]) + ","
        for action in picus_simulationActions:
            picus_action_results["results"].append(action)

    if len(picus_action_raw_results) != 0:
        picus_action_raw_results = picus_action_raw_results[:-1]
    picus_action_results = picus_action_results["results"]
        
    table_name = "Picus Simulation Actions"
    table_headers = ['action_id','display_id','action_name','affected_os','attack_module','category','prevention']
    md_table = tableToMarkdown(table_name, picus_action_results, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_action_raw_results, outputs_prefix="Picus.SimulationActions")
    return results

def getMitigationDevices():
    picus_endpoint = "/v1/mitigation/devices"
    simulation_ids = demisto.args().get('ids')
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    if not simulation_ids is None:
        query_parameters = "?" + "simulation_ids=" + simulation_ids
        picus_req_url = picus_req_url + query_parameters

    picus_endpoint_response = requests.get(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_mitigationDevices = json.loads(picus_endpoint_response.text)

    table_name = "Picus Mitigation Devices"
    table_headers = ['id','device_name','score','total_action_count','blocked_action_count','not_blocked_action_count']
    md_table = tableToMarkdown(table_name, picus_mitigationDevices, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_mitigationDevices, outputs_prefix="Picus.MitigationDevices")
    return results

def getSignatureList():
    picus_endpoint = "/v1/mitigation/devices/"
    device_id = demisto.args().get('device_id')
    action_ids = demisto.args().get('action_ids')
    picus_endpoint = picus_endpoint + device_id + "/signatures"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_signature_raw_results: Dict[str, Any] = {"results": []}
    picus_signature_all_results: Dict[str, Any] = {"results": []}

    action_ids = action_ids.split(",")
    for action in action_ids:
        tmp_req_url = ""
        query_parameters = "?" + "action_ids=" + action
        tmp_req_url = picus_req_url + query_parameters
        picus_endpoint_response = requests.get(tmp_req_url, headers=picus_headers, verify=verify_certificate)
        picus_mitigationSignatures = json.loads(picus_endpoint_response.text)
        for mitigation in picus_mitigationSignatures:
            mitigation["action_id"] = action
        picus_signature_raw_results["results"].append(picus_mitigationSignatures)

    picus_signature_raw_results = picus_signature_raw_results["results"]
    for raw_results_list in picus_signature_raw_results:
        for raw_results in raw_results_list:
            picus_signature_all_results["results"].append(raw_results)
    picus_signature_all_results = picus_signature_all_results["results"]

    table_name = "Picus Mitigation Signature List"
    table_headers = ['action_id','signature_id','name','signature_category','signature_version','product_platform','product_version','vendor_severity']
    md_table = tableToMarkdown(table_name, picus_signature_all_results, headers=table_headers, removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_signature_all_results, outputs_prefix="Picus.MitigationSignatures")
    return results

def generateEndpointURL(picus_accessToken,picus_endpoint):
    picus_server = str(demisto.params().get("picus_server"))
    endpointURL = picus_server + picus_endpoint
    picus_headers = {"Content-Type": "application/json","Authorization":""}
    picus_headers["Authorization"] = "Bearer " + picus_accessToken
    return endpointURL, picus_headers

def setParamPB():
    agent_id = demisto.args().get('agent_id')
    device_id = demisto.args().get('device_id')
    simulation_id = demisto.args().get('simulation_id')
    
    param_data = {"agent_id":agent_id,"device_id":device_id,"simulation_id":simulation_id}
    results = CommandResults(outputs=param_data,outputs_prefix="Picus.param")

    return results

def filterInsecureAttacks():
    threatinfo = demisto.args().get('threatinfo')
    threat_ids = ""

    threatinfo = list(threatinfo.split(","))
    threatinfo = [th_info for th_info in threatinfo if "unblocked" in th_info]

    for th_info in threatinfo:
        threat_id = th_info.split("=")[0]
        threat_ids += str(threat_id) + ","

    if len(threat_ids)!=0:
        threat_ids = threat_ids[:-1]

    results = CommandResults(readable_output=threat_ids,outputs_prefix="Picus.filterinsecure",outputs=threat_ids)
    return results

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            return_results(result)
        elif demisto.command() == 'picus-get-access-token':
            result = getAccessToken()
            return_results(result)
        elif demisto.command() == 'picus-get-agent-list':
            result = getAgentList()
            return_results(result)
        elif demisto.command() == 'picus-get-agent-detail':
            result = getAgentDetail()
            return_results(result)
        elif demisto.command() == 'picus-create-simulation':
            result = createSimulation()
            return_results(result)
        elif demisto.command() == 'picus-get-template-list':
            result = getTemplateList()
            return_results(result)
        elif demisto.command() == 'picus-get-integration-agent-list':
            result = getIntegrationAgentList()
            return_results(result)
        elif demisto.command() == 'picus-get-simulation-list':
            result = getSimulationList()
            return_results(result)
        elif demisto.command() == 'picus-simulate-now':
            result = simulateNow()
            return_results(result)
        elif demisto.command() == 'picus-get-simulation-detail':
            result = getSimulationDetail()
            return_results(result)
        elif demisto.command() == 'picus-get-latest-simulation-result':
            result = getLatestSimulationResult()
            return_results(result)
        elif demisto.command() == 'picus-get-simulation-result':
            result = getSimulationResult()
            return_results(result)
        elif demisto.command() == 'picus-get-simulation-threats':
            result = getSimulationThreats()
            return_results(result)
        elif demisto.command() == 'picus-get-simulation-actions':
            result = getSimulationActions()
            return_results(result)
        elif demisto.command() == 'picus-get-mitigation-devices':
            result = getMitigationDevices()
            return_results(result)
        elif demisto.command() == 'picus-get-signature-list':
            result = getSignatureList()
            return_results(result)
        elif demisto.command() == 'picus-set-paramPB':
            result = setParamPB()
            return_results(result)
        elif demisto.command() == "picus-filter-insecure-attacks":
            result = filterInsecureAttacks()
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
