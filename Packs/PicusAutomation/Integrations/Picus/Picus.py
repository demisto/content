import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
import json
import traceback
from datetime import datetime, timedelta
import time
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

# flake8: noqa

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VALID_VARIANTS = ["HTTP", "HTTPS"]
verify_certificate = not demisto.params().get('insecure', False)


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

    message, picus_accessToken = '', None
    try:
        picus_server = str(demisto.params().get("picus_server"))
        picus_server = picus_server[:-1] if picus_server.endswith("/") else picus_server
        picus_apikey = demisto.params().get("picus_apikey")
        picus_headers = {"X-Refresh-Token": "", "Content-Type": "application/json"}
        picus_headers["X-Refresh-Token"] = "Bearer " + str(picus_apikey)

        picus_auth_endpoint = "/authenticator/v1/access-tokens/generate"
        picus_req_url = str(picus_server) + picus_auth_endpoint
        picus_session = requests.Session()
        if not demisto.params().get('proxy', False):
            picus_session.trust_env = False
        picus_auth_response = picus_session.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
        picus_auth_response.raise_for_status()
        picus_accessToken = json.loads(picus_auth_response.text)["data"]["access_token"]
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
    picus_headers = {"X-Refresh-Token": "", "Content-Type": "application/json"}
    picus_headers["X-Refresh-Token"] = "Bearer " + str(picus_apikey)

    picus_auth_endpoint = "/authenticator/v1/access-tokens/generate"
    picus_req_url = str(picus_server) + picus_auth_endpoint
    picus_session = requests.Session()
    if not demisto.params().get('proxy', False):
        picus_session.trust_env = False
    picus_auth_response = picus_session.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
    if picus_auth_response.status_code != 200:
        return_error(picus_auth_response.text)
    picus_accessToken = json.loads(picus_auth_response.text)["data"]["access_token"]

    return picus_accessToken


def getVectorList():
    picus_endpoint = "/user-api/v1/vectors/list"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    add_user_details = demisto.args().get('add_user_details')
    add_user_details = bool(add_user_details) if add_user_details is not None else add_user_details
    page = arg_to_number(demisto.args().get('page'))
    size = arg_to_number(demisto.args().get('size'))
    picus_post_data = {"add_user_details": add_user_details, "size": size, "page": page}
    picus_post_data = assign_params(**picus_post_data)

    picus_endpoint_response = requests.post(picus_req_url, headers=picus_headers,
                                            data=json.dumps(picus_post_data), verify=verify_certificate)
    picus_vectors = json.loads(picus_endpoint_response.text)["data"]["vectors"]

    table_name = "Picus Vector List"
    table_headers = ['name', 'description', 'trusted', 'untrusted', 'is_disabled', 'type']
    md_table = tableToMarkdown(table_name, picus_vectors, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_vectors, outputs_prefix="Picus.vectorlist")

    return results


def getPeerList():
    picus_endpoint = "/user-api/v1/peers/list"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_peers = json.loads(picus_endpoint_response.text)["data"]["peers"]

    table_name = "Picus Peer List"
    table_headers = ['name', 'registered_ip', 'type', 'is_alive']
    md_table = tableToMarkdown(table_name, picus_peers, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_peers, outputs_prefix="Picus.peerlist")

    return results


def getAttackResults():
    picus_endpoint = "/user-api/v1/attack-results/list"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_attack_results: List[Any] = []
    picus_attack_raw_results: Dict[str, Any] = {"results": []}
    tmp_secure_list: List[Any] = []
    tmp_insecure_list: List[Any] = []
    tmp_results: List[Any] = []
    threat_ids = ""

    attacker_peer = demisto.args().get('attacker_peer')
    victim_peer = demisto.args().get('victim_peer')
    days = int(demisto.args().get('days'))
    attack_result = demisto.args().get('result').lower()
    attack_result = attack_result[0].upper() + attack_result[1:]
    valid_attack_results = ["Insecure", "Secure", "All"]
    check_valid = any(result for result in valid_attack_results if (result == attack_result))
    if not check_valid:
        msg = "Wrong result parameter. The result parameter can only be secure,insecure and all"
        return msg

    end_date = datetime.now().strftime("%Y-%m-%d")
    begin_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    picus_post_data_secure = {"attack_result": "secure", "begin_date": begin_date,
                              "end_date": end_date, "vectors": [{"trusted": victim_peer, "untrusted": attacker_peer}]}
    picus_post_data_insecure = {"attack_result": "insecure", "begin_date": begin_date,
                                "end_date": end_date, "vectors": [{"trusted": victim_peer, "untrusted": attacker_peer}]}
    picus_endpoint_response_secure = requests.post(
        picus_req_url, headers=picus_headers, data=json.dumps(picus_post_data_secure), verify=verify_certificate)
    picus_endpoint_response_insecure = requests.post(
        picus_req_url, headers=picus_headers, data=json.dumps(picus_post_data_insecure), verify=verify_certificate)
    picus_attack_results_secure = json.loads(picus_endpoint_response_secure.text)["data"]["results"]
    picus_attack_results_insecure = json.loads(picus_endpoint_response_insecure.text)["data"]["results"]

    if picus_attack_results_secure is not None:
        picus_attack_results_secure.sort(key=returnListTimeKey, reverse=True)
        for i in range(len(picus_attack_results_secure)):
            exists = 0
            list_len = len(tmp_secure_list)
            for j in range(list_len):
                if picus_attack_results_secure[i]["threat_id"] == tmp_secure_list[j]["threat_id"]:
                    exists = 1
            if exists == 0:
                tmp_secure_list.append(picus_attack_results_secure[i])

    if picus_attack_results_insecure is not None:
        picus_attack_results_insecure.sort(key=returnListTimeKey, reverse=True)
        for i in range(len(picus_attack_results_insecure)):
            exists = 0
            list_len = len(tmp_insecure_list)
            for j in range(list_len):
                if picus_attack_results_insecure[i]["threat_id"] == tmp_insecure_list[j]["threat_id"]:
                    exists = 1
            if exists == 0:
                tmp_insecure_list.append(picus_attack_results_insecure[i])

    tmp_results = tmp_secure_list + tmp_insecure_list
    if len(tmp_results) != 0:
        tmp_results.sort(key=returnListTimeKey, reverse=True)
    else:
        message = "No Results Data."
        results = CommandResults(readable_output=message)
        return results

    for i in range(len(tmp_results)):
        exists = 0
        list_len = len(picus_attack_results)
        for j in range(list_len):
            if tmp_results[i]["threat_id"] == picus_attack_results[j]["threat_id"]:
                exists = 1
        if exists == 0:
            picus_attack_results.append(tmp_results[i])

    tmp_results = []
    for i in range(len(picus_attack_results)):
        if attack_result == "All":
            tmp_results.append(picus_attack_results[i])
        elif picus_attack_results[i]["string"] == attack_result:
            tmp_results.append(picus_attack_results[i])
    picus_attack_results = tmp_results

    for i in range(len(picus_attack_results)):
        threat_ids += str(picus_attack_results[i]["threat_id"]) + ","
    threat_ids = threat_ids[:-1]

    picus_attack_raw_results["results"].append({"threat_ids": threat_ids})
    picus_attack_raw_results["results"].append(picus_attack_results)

    table_name = attack_result + " Attack List"
    table_headers = ['begin_time', 'end_time', 'string', 'threat_id', 'threat_name']
    md_table = tableToMarkdown(table_name, picus_attack_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs_prefix="Picus.attackresults",
                             outputs=picus_attack_raw_results, outputs_key_field="results.threat_id")

    return results


def runAttacks():
    picus_endpoint = "/user-api/v1/schedule/attack/single"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_attack_results: Dict[str, Any] = {"results": []}
    picus_attack_raw_results = ""

    threat_ids = demisto.args().get('threat_ids')
    attacker_peer = demisto.args().get('attacker_peer')
    victim_peer = demisto.args().get('victim_peer')
    variant = demisto.args().get('variant')
    if variant not in VALID_VARIANTS:
        return_error("Unknown variant type - " + variant)

    threat_ids = list(threat_ids.split(","))

    t_count = 0
    for threat_id in threat_ids:
        try:
            threat_id = int(threat_id)
            picus_attack_data = {"trusted": victim_peer, "untrusted": attacker_peer, "threat_id": threat_id, "variant": variant}
            picus_attack_response = requests.post(picus_req_url, headers=picus_headers,
                                                  data=json.dumps(picus_attack_data), verify=verify_certificate)
            attack_result_response = json.loads(picus_attack_response.text)["data"]["result"]

            picus_attack_result = {"threat_id": threat_id, "result": attack_result_response}
            picus_attack_results["results"].append(picus_attack_result)
            if attack_result_response == "success":
                picus_attack_raw_results += str(threat_id) + ","
            if t_count == 3:
                time.sleep(1)
                t_count = 0
            else:
                t_count += 1
        except Exception as e:
            picus_attack_result = {"threat_id": threat_id, "result": "unknown error"}
            picus_attack_results["results"].append(picus_attack_result)
            continue

    if len(picus_attack_raw_results) != 0:
        picus_attack_raw_results = picus_attack_raw_results[:-1]

    picus_attack_results = picus_attack_results["results"]
    table_name = "Picus Attack Results"
    table_headers = ['threat_id', 'result']
    md_table = tableToMarkdown(table_name, picus_attack_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs_prefix="Picus.runattacks", outputs=picus_attack_raw_results)

    return results


def getThreatResults():
    picus_endpoint = "/user-api/v1/attack-results/threat-specific-latest"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_threat_results: Dict[str, Any] = {"results": []}
    picus_threat_raw_results = ""
    threat_raw_output: Dict[str, Any] = {"results": []}

    threat_ids = demisto.args().get('threat_ids')
    attacker_peer = demisto.args().get('attacker_peer')
    victim_peer = demisto.args().get('victim_peer')
    variant = demisto.args().get('variant')
    if variant not in VALID_VARIANTS:
        return_error("Unknown variant type - " + variant)

    threat_ids = list(threat_ids.split(","))
    for threat_id in threat_ids:
        try:
            threat_id = int(threat_id)
            picus_threat_data = {"threat_id": threat_id}
            picus_threat_response = requests.post(picus_req_url, headers=picus_headers,
                                                  data=json.dumps(picus_threat_data), verify=verify_certificate)
            picus_threat_json_result = json.loads(picus_threat_response.text)["data"]["results"]
            l1_category = picus_threat_json_result["l1_category_name"]
            vector_name = attacker_peer + " - " + victim_peer
            vectors_results = picus_threat_json_result["vectors"]

            threat_result = ""
            last_time = ""
            for i in range(len(vectors_results)):
                if vectors_results[i]["name"] == vector_name:
                    variants_results = vectors_results[i]["variants"]
                    for j in range(len(variants_results)):
                        if variants_results[j]["name"] == variant:
                            last_time = variants_results[j]["last_time"]
                            threat_result = variants_results[j]["result"]

            picus_threat_result = {"l1_category": l1_category, "result": threat_result,
                                   "threat_id": threat_id, "last_time": last_time, "status": "success"}
            picus_threat_results["results"].append(picus_threat_result)
            picus_threat_raw_results += str(threat_id) + "=" + threat_result + ","
        except Exception as e:
            picus_threat_result = {"l1_category": "null", "result": "null",
                                   "threat_id": threat_id, "last_time": "null", "status": "fail"}
            picus_threat_results["results"].append(picus_threat_result)
            continue

    if len(picus_threat_raw_results) != 0:
        picus_threat_raw_results = picus_threat_raw_results[:-1]
    picus_threat_results = picus_threat_results["results"]

    threat_raw_output["results"].append({"threat_results": picus_threat_raw_results})
    threat_raw_output["results"].append(picus_threat_results)

    table_name = "Picus Threat Results"
    table_headers = ['threat_id', 'result', 'l1_category', 'last_time', 'status']
    md_table = tableToMarkdown(table_name, picus_threat_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs_prefix="Picus.threatresults",
                             outputs=threat_raw_output, outputs_key_field="results.threat_id")

    return results


def filterInsecureAttacks():
    threatinfo = demisto.args().get('threatinfo')
    threat_ids = ""

    threatinfo = list(threatinfo.split(","))
    threatinfo = [th_info for th_info in threatinfo if "Insecure" in th_info]

    for th_info in threatinfo:
        threat_id = th_info.split("=")[0]
        threat_ids += str(threat_id) + ","

    if len(threat_ids) != 0:
        threat_ids = threat_ids[:-1]

    results = CommandResults(readable_output=threat_ids, outputs_prefix="Picus.filterinsecure", outputs=threat_ids)
    return results


def getMitigationList():
    picus_endpoint = "/user-api/v1/threats/mitigations/list"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    picus_mitigation_results: Dict[str, Any] = {"results": []}
    threat_ids = demisto.args().get('threat_ids')
    product = demisto.args().get('product')
    product = list(product.split(","))
    threat_ids = list(threat_ids.split(","))

    for threat_id in threat_ids:
        try:
            threat_id = int(threat_id)
            picus_threat_data = {"threat_id": threat_id, "products": product}
            picus_mitigation_response = requests.post(picus_req_url, headers=picus_headers,
                                                      data=json.dumps(picus_threat_data), verify=verify_certificate)
            picus_mitigation_result = json.loads(picus_mitigation_response.text)["data"]["mitigations"]
            picus_mitigation_count = json.loads(picus_mitigation_response.text)["data"]["total_count"]
            if picus_mitigation_count != 0:
                for threat_mitigation in picus_mitigation_result:
                    mitigation_data = {"threat_id": threat_mitigation["threat"]["id"], "signature_id": threat_mitigation["signature"]
                                       ["id"], "signature_name": threat_mitigation["signature"]["name"], "vendor": threat_mitigation["product"]}
                    picus_mitigation_results["results"].append(mitigation_data)
        except Exception as e:
            continue

    picus_mitigation_results = picus_mitigation_results["results"]
    table_name = "Picus Mitigation List"
    table_headers = ['threat_id', 'signature_id', 'signature_name', 'vendor']
    md_table = tableToMarkdown(table_name, picus_mitigation_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs_prefix="Picus.mitigationresults",
                             outputs=picus_mitigation_results, outputs_key_field="signature_id")

    return results


def getVectorCompare():
    picus_endpoint = "/user-api/v1/attack-results/compare-a-vector"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)
    all_vector_results: Dict[str, Any] = {"results": []}

    attacker_peer = demisto.args().get('attacker_peer')
    victim_peer = demisto.args().get('victim_peer')
    days = int(demisto.args().get('days'))

    end_date = datetime.now().strftime("%Y-%m-%d")
    begin_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    picus_post_data_vector = {"trusted": victim_peer, "untrusted": attacker_peer, "begin_date": begin_date, "end_date": end_date}
    picus_vector_response = requests.post(picus_req_url, headers=picus_headers,
                                          data=json.dumps(picus_post_data_vector), verify=verify_certificate)
    picus_vector_results = json.loads(picus_vector_response.text)["data"]["variants"][0]

    picus_vector_secure_results = picus_vector_results["secures"]
    picus_vector_insecure_results = picus_vector_results["insecures"]
    picus_vector_secure_to_insecures_results = picus_vector_results["secure_to_insecures"]
    picus_vector_insecure_to_secures_results = picus_vector_results["insecure_to_secures"]

    if picus_vector_secure_results is not None:
        for result in picus_vector_secure_results:
            tmp_result = {"status": "secure", "threat_id": result["threat_id"], "name": result["name"]}
            all_vector_results["results"].append(tmp_result)
    else:
        tmp_result = {"status": "secure", "threat_id": "null", "name": "null"}
        all_vector_results["results"].append(tmp_result)

    if picus_vector_insecure_results is not None:
        for result in picus_vector_insecure_results:
            tmp_result = {"status": "insecure", "threat_id": result["threat_id"], "name": result["name"]}
            all_vector_results["results"].append(tmp_result)
    else:
        tmp_result = {"status": "insecure", "threat_id": "null", "name": "null"}
        all_vector_results["results"].append(tmp_result)

    if picus_vector_secure_to_insecures_results is not None:
        for result in picus_vector_secure_to_insecures_results:
            tmp_result = {"status": "secure_to_insecures", "threat_id": result["threat_id"], "name": result["name"]}
            all_vector_results["results"].append(tmp_result)
    else:
        tmp_result = {"status": "secure_to_insecures", "threat_id": "null", "name": "null"}
        all_vector_results["results"].append(tmp_result)

    if picus_vector_insecure_to_secures_results is not None:
        for result in picus_vector_insecure_to_secures_results:
            tmp_result = {"status": "insecure_to_secures", "threat_id": result["threat_id"], "name": result["name"]}
            all_vector_results["results"].append(tmp_result)
    else:
        tmp_result = {"status": "insecure_to_secures", "threat_id": "null", "name": "null"}
        all_vector_results["results"].append(tmp_result)

    all_vector_results = all_vector_results["results"]
    table_name = "Picus Vector Compare Result"
    table_headers = ['status', 'threat_id', 'name']
    md_table = tableToMarkdown(table_name, all_vector_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=all_vector_results,
                             outputs_prefix="Picus.vectorresults", outputs_key_field="threat_id")

    return results


def returnListTimeKey(attack_result_list):
    return attack_result_list.get("end_time")


def setParamPB():
    attacker_peer = demisto.args().get('attacker_peer')
    victim_peer = demisto.args().get('victim_peer')
    variant = demisto.args().get('variant')
    if variant not in VALID_VARIANTS:
        return_error("Unknown variant type - " + variant)

    mitigation_product = demisto.args().get('mitigation_product')
    days = int(demisto.args().get('days'))
    param_data = {"attacker_peer": attacker_peer, "victim_peer": victim_peer,
                  "variant": variant, "mitigation_product": mitigation_product, "days": days}
    results = CommandResults(outputs=param_data, outputs_prefix="Picus.param")

    return results


def getPicusVersion():
    picus_endpoint = "/user-api/v1/settings/version"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_version_results = json.loads(picus_endpoint_response.text)["data"]
    picus_version_info = {"version": picus_version_results["version"],
                          "update_time": picus_version_results["update_time"], "last_update_date": picus_version_results["last_update_date"]}

    table_name = "Picus Version"
    table_headers = ['version', 'update_time', 'last_update_date']
    md_table = tableToMarkdown(table_name, picus_version_info, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_version_info,
                             outputs_prefix="Picus.versioninfo", outputs_key_field="version")

    return results


def triggerUpdate():
    picus_endpoint = "/user-api/v1/settings/trigger-update"
    picus_req_url, picus_headers = generateEndpointURL(getAccessToken(), picus_endpoint)

    picus_endpoint_response = requests.post(picus_req_url, headers=picus_headers, verify=verify_certificate)
    picus_update_results = json.loads(picus_endpoint_response.text)

    table_name = "Picus Trigger Update"
    table_headers = ['data', 'success']
    md_table = tableToMarkdown(table_name, picus_update_results, headers=table_headers,
                               removeNull=True, headerTransform=string_to_table_header)
    results = CommandResults(readable_output=md_table, outputs=picus_update_results, outputs_prefix="Picus.triggerupdate")

    return results


def generateEndpointURL(picus_accessToken, picus_endpoint):
    picus_server = str(demisto.params().get("picus_server"))
    endpointURL = picus_server + picus_endpoint
    picus_headers = {"X-Api-Token": "", "Content-Type": "application/json"}
    picus_headers["X-Api-Token"] = "Bearer " + picus_accessToken
    return endpointURL, picus_headers


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
        elif demisto.command() == 'picus-get-vector-list':
            result = getVectorList()
            return_results(result)
        elif demisto.command() == 'picus-get-peer-list':
            result = getPeerList()
            return_results(result)
        elif demisto.command() == 'picus-get-attack-results':
            result = getAttackResults()
            return_results(result)
        elif demisto.command() == 'picus-run-attacks':
            result = runAttacks()
            return_results(result)
        elif demisto.command() == 'picus-get-threat-results':
            result = getThreatResults()
            return_results(result)
        elif demisto.command() == 'picus-set-paramPB':
            result = setParamPB()
            return_results(result)
        elif demisto.command() == 'picus-filter-insecure-attacks':
            result = filterInsecureAttacks()
            return_results(result)
        elif demisto.command() == 'picus-get-mitigation-list':
            result = getMitigationList()
            return_results(result)
        elif demisto.command() == 'picus-get-vector-compare':
            result = getVectorCompare()
            return_results(result)
        elif demisto.command() == 'picus-version':
            result = getPicusVersion()
            return_results(result)
        elif demisto.command() == 'picus-trigger-update':
            result = triggerUpdate()
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
