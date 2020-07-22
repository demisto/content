from typing import Dict, Optional, List, Tuple, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import jwt
import base64
import pycef
import hashlib
import time
import json

# Disable insecure warnings
urllib3.disable_warnings()
''' CLIENT CLASS'''

UDSOAPIPATH = '/WebApp/api/SuspiciousObjects/UserDefinedSO'
PRODAGENTAPIPATH = '/WebApp/API/AgentResource/ProductAgents'

LOG_NAME_TO_LOG_TYPE = {
    "Data Loss Prevention": "data_loss_prevention",
    "Device Control": "device_access_control",
    "Behavior Monitoring": "behaviormonitor_rule",
    "Virus/Malware": "officescan_virus",
    "Spyware/Grayware": "spyware",
    "Web Violation": "web_security",
    "Content Violation": "security",
    "Network Content Inspection": "ncie",
    "C&C Callback": "cncdetection",
    "Suspicious File Information": "filehashdetection",
    "Predictive Machine Learning": "Predictive_Machine_Learning",
    "Virtual Analyzer Detections": "Sandbox_Detection_Log",
    "Application Control": "EACV_Information",
    "Managed Product User Access": "Managed_Product_Logged_Information",
    "Attack Discovery": "Attack_Discovery_Detections",
    "Pattern Update Status": "pattern_updated_status",
    "Engine Update Status": "engine_updated_status",
    "Product Auditing Events": "product_auditing_events",
    "Intrusion Prevention": "intrusion_prevention"
}

OS_NAME_TO_OS_TYPE = {
    "Windows XP": "WIN_XP",
    "Windows Vista": "WIN_VISTA",
    "Windows 7": "WIN_7",
    "Windows 8": "WIN_8",
    "Windows 10": "WIN_10",
    "Windows 2000": "WIN_2000",
    "Windows 2003": "WIN_2003",
    "Windows 2008": "WIN_2008",
    "Windows 2012": "WIN_2012",
    "Windows 2016": "WIN_2016",
    "iOS": "IOS",
    "Mac OS": "MAC_OS",
    "Android": "ANDROID",
    "Symbian": "SYMBIAN",
    "Windows Mobile": "WIN_MOBILE",
    "Windows General": "WIN"
}

SECURITY_AGENTS_TYPE_TO_NUMBER = {
    "endpoint_name": 1,
    "endpoint_type": 2,
    "endpoint_ip_address": 4,
    "endpoint_OS": 5,
    "partial_OS": 9
}

SCAN_TYPE_TO_NUM = {
    "Custom criteria" : 0,
    "Windows registry": 1,
    "YARA rule file": 2,
    "IOC rule file": 3,
    "Disk IOC rule file": 6
}


class Client(BaseClient):
    def __init__(self, base_url, api_key, app_id, verify, proxy):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.base_url = base_url
        self.api_key = api_key
        self.application_id = app_id
        self.suffix = ''

    @staticmethod
    def __create_checksum(http_method, api_path, headers, request_body):
        string_to_hash = http_method.upper() + '|' + api_path.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    def create_jwt_token(self, http_method, api_path, headers, request_body, iat=time.time(), algorithm='HS256',
                         version='V1', ):
        checksum = self.__create_checksum(http_method, api_path, headers, request_body)

        payload = {'appid': self.application_id,
                   'iat': iat,
                   'version': version,
                   'checksum': checksum}

        token = jwt.encode(payload, self.api_key, algorithm=algorithm).decode('utf-8')
        return token

    def udso_list(self, list_type="", contentfilter=""):
        querystring = "?type=" + list_type + "&contentFilter=" + contentfilter
        headers = {
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='GET', api_path=UDSOAPIPATH + querystring,
                                                               headers='', request_body='')}
        response = (
            self._http_request("GET", UDSOAPIPATH, full_url=self.base_url + UDSOAPIPATH + querystring, headers=headers))
        return response

    def udso_delete(self, list_type="", content=""):
        querystring = "?type=" + list_type + "&content=" + content
        headers = {'Authorization': 'Bearer ' + self.create_jwt_token(http_method='DELETE',
                                                                      api_path=UDSOAPIPATH + querystring, headers='',
                                                                      request_body='')}
        response = (self._http_request("DELETE", UDSOAPIPATH, full_url=self.base_url + UDSOAPIPATH + querystring,
                                       headers=headers))
        return response

    def udso_add(self, add_type=None, content=None, scan_action=None, notes='', expiration=''):
        if add_type and content and scan_action:
            req_body = {
                "param": {
                    "type": add_type,
                    "content": content,
                    "notes": notes,
                    "scan_action": scan_action,
                    "expiration_utc_date": expiration
                }
            }

            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Authorization': 'Bearer ' + self.create_jwt_token(http_method='PUT', api_path=UDSOAPIPATH + '/',
                                                                   headers='', request_body=json.dumps(req_body))}
            response = (self._http_request("PUT", UDSOAPIPATH + '/', full_url=self.base_url + UDSOAPIPATH + '/',
                                           headers=headers, data=json.dumps(req_body)))

            return response

    def udso_add_file(self, file_content_base64_string, file_name, file_scan_action, note):
        payload = {
            "file_name": file_name,
            "file_content_base64_string": file_content_base64_string,
            "file_scan_action": file_scan_action,
            "note": note
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='PUT', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(payload))}
        response = (self._http_request("PUT", self.suffix, headers=headers, data=json.dumps(payload)))
        return response

    def _prodagent_command(self, action, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        act = action

        req_body = {
            "act": act,
            "allow_multiple_match": multi_match,
            "entity_id": entity_id,
            "ip_address": ip_add,
            "mac_address": mac_add,
            "host_name": host,
            "product": prod
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=PRODAGENTAPIPATH + '/',
                                                               headers='', request_body=json.dumps(req_body))}
        response = (
            self._http_request("POST", PRODAGENTAPIPATH + '/', full_url=self.base_url + PRODAGENTAPIPATH + '/',
                               headers=headers,
                               data=json.dumps(req_body)))
        if response.get('result_code') != 1:
            err_msg = f'Operation failed - {response.get("result_description", "")}'
            raise ValueError(err_msg)
        return response

    def prodagent_isolate(self, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        action = "cmd_isolate_agent"
        return self._prodagent_command(action, multi_match, entity_id, ip_add, mac_add, host, prod)

    def prodagent_restore(self, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        action = "cmd_restore_isolated_agent"
        return self._prodagent_command(action, multi_match, entity_id, ip_add, mac_add, host, prod)

    def logs_list(self, log_type, since_time=0, page_token=0):
        log_type = LOG_NAME_TO_LOG_TYPE.get(log_type)
        if log_type in ["pattern_updated_status", "engine_updated_status"] and page_token != 0:
            return_error("For 'Pattern Update Status' and 'Engine Update Status logs' types, \n"
                         "the value of page_token must be '0'.")
        querystring = f'?output_format=1&page_token={page_token}&since_time={since_time}'
        suffix = f'{self.suffix}/{log_type}{querystring}'
        jwt_token = self.create_jwt_token(http_method='GET', api_path=suffix, headers='', request_body='')

        headers = {
            'Authorization': 'Bearer ' + jwt_token,
            'Content-Type': 'application/json;charset=utf-8'
        }

        response = (self._http_request("GET", url_suffix=suffix, headers=headers))
        return response

    @staticmethod
    def build_query_string(entity_id='', ip_address='', mac_address='', host_name='', product='',
                           managing_server_id=''):
        query_string = ''
        if entity_id:
            query_string += f'&entity_id={entity_id}'
        if ip_address:
            query_string += f'&ip_address={ip_address}'
        if mac_address:
            query_string += f'&mac_address={mac_address}'
        if host_name:
            query_string += f'&host_name={host_name}'
        if product:
            query_string += f'&product={product}'
        if managing_server_id:
            query_string += f'&managing_server_id={managing_server_id}'

        query_string = f'?{query_string[1:]}' if query_string else query_string

        return query_string

    def servers_or_agents_list(self, entity_id='', ip_address='', mac_address='', host_name='', product='',
                               managing_server_id=''):
        querystring = self.build_query_string(entity_id, ip_address, mac_address, host_name, product,
                                              managing_server_id)
        suffix = f'{self.suffix}{querystring}'
        jwt_token = self.create_jwt_token(http_method='GET', api_path=suffix,
                                          headers='', request_body='')
        headers = {
            'Authorization': 'Bearer ' + jwt_token,
            'Content-Type': 'application/json;charset=utf-8'
        }

        response = (self._http_request("GET", url_suffix=suffix, headers=headers))

        return response

    @staticmethod
    def create_filter_entry(entry_value, entry_type):
        filter_entry = {
            "type": SECURITY_AGENTS_TYPE_TO_NUMBER[entry_type]
        }
        if "OS" in entry_type:
            filter_entry["value"] = OS_NAME_TO_OS_TYPE[entry_value]  # type: ignore
        else:
            filter_entry["value"] = entry_value

        return filter_entry

    def create_payload_filter(self, endpoint_name, endpoint_type, ip_address, operating_system):
        payload_filter = []
        if endpoint_name:
            payload_filter.append(self.create_filter_entry(entry_value=endpoint_name, entry_type="endpoint_name"))
        if endpoint_type:
            payload_filter.append(self.create_filter_entry(entry_value=endpoint_type, entry_type="endpoint_type"))
        if ip_address:
            ip_range = argToList(ip_address)
            payload_filter.append(self.create_filter_entry(entry_value=ip_range, entry_type="endpoint_ip_address"))
        if operating_system:
            if operating_system == "Windows General":
                # special case - filter by all windows security agents
                payload_filter.append(self.create_filter_entry(entry_value=operating_system, entry_type="partial_OS"))
            else:
                payload_filter.append(self.create_filter_entry(entry_value=operating_system, entry_type="endpoint_OS"))

        return payload_filter

    def endpoint_sensors_list(self, limit=50, offset=0, filter_by_endpoint_name="", filter_by_endpoint_type="",
                              filter_by_ip_address="", filter_by_operating_system=""):

        payload_data = {
            "pagination": {
                "limit": int(limit),
                "offset": int(offset)
            }
        }

        payload_filter = self.create_payload_filter(filter_by_endpoint_name, filter_by_endpoint_type,
                                                    filter_by_ip_address, filter_by_operating_system)
        if payload_filter:
            payload_data["filter"] = payload_filter

        request_data = {
            "Url": "V1/Task/ShowAgentList",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload_data
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='PUT', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}

        response = self._http_request("PUT", self.suffix, headers=headers, data=json.dumps(request_data))
        return response

    @staticmethod
    def parse_cef_logs_to_dict_logs(response):
        logs_list_in_cef_format = response.get('Data', {}).get('Logs', [])
        parsed_logs_list = []
        for log in logs_list_in_cef_format:
            parsed_log = pycef.parse(log)
            parsed_logs_list.append(parsed_log)

        return parsed_logs_list

    @staticmethod
    def update_agents_info_in_payload(payload_data, agent_guids):
        agent_guids_dict = json.loads(agent_guids)  # this is a dict of { server_guids : [agent_guids] }
        payload_data["agentGuid"] = agent_guids_dict
        payload_data["serverGuid"] = [server_guid for server_guid in agent_guids_dict.keys()]

        return payload_data

    def build_process_terminate_payload(self, agent_guids: Dict = {}, server_guids: List = [], object_name: str = "", processes_to_terminate: List = [], filter_by_endpoint_name="", filter_by_endpoint_type="",
                              filter_by_endpoint_ip_address="", filter_by_endpoint_operating_system=""):
        payload_data = {}
        payload_filter = self.create_payload_filter(filter_by_endpoint_name, filter_by_endpoint_type,
                                                    filter_by_endpoint_ip_address, filter_by_endpoint_operating_system)
        if payload_filter:
            payload_data["filter"] = payload_filter

        if agent_guids:
            payload_data = self.update_agents_info_in_payload(payload_data, agent_guids)

        elif server_guids:
            payload_data["serverGuid"] = argToList(server_guids)

        if object_name:
            payload_data["suspiciousObjectName"] = object_name

        if processes_to_terminate:
            processes_to_terminate = argToList(processes_to_terminate)
            payload_data["terminationInfoList"] = [
                {
                    "name": 101,
                    "value": process_sha1
                } for process_sha1 in processes_to_terminate]
        return payload_data

    def process_terminate_request(self,  agent_guids: Dict = {}, server_guids: List = [], object_name: str = "", processes_to_terminate: List = [], filter_by_endpoint_name="", filter_by_endpoint_type="",
                                  filter_by_endpoint_ip_address="", filter_by_endpoint_operating_system=""):

            payload = self.build_process_terminate_payload(agent_guids, server_guids, object_name, processes_to_terminate, filter_by_endpoint_name, filter_by_endpoint_type, filter_by_endpoint_ip_address, filter_by_endpoint_operating_system)
            # return_error(payload)
            request_data = {
                "Url": "V1/Task/CreateProcessTermination",
                "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
                "Payload": payload
            }
            # return_error(request_data)

            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=self.suffix,
                                                                   headers='', request_body=json.dumps(request_data))}

            response = self._http_request("POST", self.suffix, headers=headers, data=json.dumps(request_data))
            return response

    def build_investigation_payload(self, investigation_name: str, scan_type: str, time_range_type: str, agent_guids: Dict = {}, server_guids: List = [],
                                    scan_schedule_guid: str = "", scan_schedule_id: str = "", time_range_start: str = "", time_range_end: str = ""):
        payload = {
            "name": investigation_name,
            "scan_type": SCAN_TYPE_TO_NUM[scan_type],
            "timeRange": {"rangeType": time_range_type}
        }

        if time_range_type == 'Specific':
            # TODO convert times to unix timestamps
            payload["timeRange"]["startUnixTime"] = time_range_start
            payload["timeRange"]["endUnixTime"] = time_range_end

        if agent_guids:
            payload = self.update_agents_info_in_payload(payload, agent_guids)

        elif server_guids:
            payload["serverGuid"] = argToList(server_guids)

        if scan_schedule_guid:
            payload["scanScheduleGuid"] = scan_schedule_guid

        if scan_schedule_id:
            payload["scanScheduleId"] = scan_schedule_id

        return payload

    @staticmethod
    def create_file_content_criteria(entry_id, criteria_hash_id: str = ""):
        file = demisto.getFilePath(entry_id)
        file_path = file['path']
        file_name = file['name']
        with open(file_path, 'rb') as f:
            file_content_base64_string = base64.b64encode(
                f.read()).decode()  # the api is expecting 64based encoded file

        file_content_criteria = {
            "base64EncodedContent": file_content_base64_string,
            "fileName": file_name
        }
        if criteria_hash_id:
            file_content_criteria["criteriaHashId"] = criteria_hash_id

        return file_content_criteria

    def create_file_investigation(self, investigation_name: str, entry_id: str, scan_type: str, time_range_type: str, agent_guids: Dict = {}, server_guids: List = [],
                                  criteria_hash_id: str = "", scan_schedule_guid: str = "", scan_schedule_id: str = "", time_range_start: str ="", time_range_end: str = ""):

        payload = self.build_investigation_payload(investigation_name, scan_type, time_range_type,
                                                        agent_guids, server_guids, scan_schedule_guid, scan_schedule_id,
                                                        time_range_start, time_range_end)

        payload["fileContentCriteria"] = self.create_file_content_criteria(entry_id, criteria_hash_id)

        request_data = {
            "Url": "V1/Task/CreateScan",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}

        response = self._http_request("POST", self.suffix, headers=headers, data=json.dumps(request_data))
        return response

    def create_registry_criteria(self, registry_key, registry_name, match_option, registry_data):
        match_option_to_number = {
            'Equal': 1,
            'Data contains': 2,
            'Data does not contain': 3
        }
        registry_criteria = {
            'item': [
                {
                    'kay': registry_key,
                    'data': registry_data,
                    'matchOption': match_option_to_number[match_option]
                    'value': registry_name
                }
            ]
        }
        return registry_data

    def create_registry_investigation(self, registry_key, registry_name, match_option, registry_data,
                                      investigation_name: str, scan_type: str, time_range_type: str,
                                      agent_guids: Dict = {}, server_guids: List = [], scan_schedule_guid: str = "",
                                      scan_schedule_id: str = "", time_range_start: str = "", time_range_end: str = ""):

        payload = self.build_investigation_payload(investigation_name, scan_type, time_range_type, agent_guids,
                                                   server_guids, scan_schedule_guid, scan_schedule_id, time_range_start,
                                                   time_range_end)

        payload["registryCriteria"] = self.create_registry_criteria(registry_key, registry_name, match_option,
                                                                    registry_data)

        request_data = {
            "Url": "V1/Task/CreateScan",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}

        response = self._http_request("POST", self.suffix, headers=headers, data=json.dumps(request_data))
        return response

    def create_custom_investigation(self,
                                      investigation_name: str, scan_type: str, time_range_type: str,
                                      agent_guids: Dict = {}, server_guids: List = [], scan_schedule_guid: str = "",
                                      scan_schedule_id: str = "", time_range_start: str = "", time_range_end: str = ""):

        payload = self.build_investigation_payload(investigation_name, scan_type, time_range_type, agent_guids,
                                                   server_guids, scan_schedule_guid, scan_schedule_id, time_range_start,
                                                   time_range_end)

        payload["registryCriteria"] = self.create_registry_criteria(registry_key, registry_name, match_option,
                                                                    registry_data)

        request_data = {
            "Url": "V1/Task/CreateScan",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}

        response = self._http_request("POST", self.suffix, headers=headers, data=json.dumps(request_data))
        return response

''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    client.udso_list()
    return 'ok'


def udso_list_command(client: Client, args):
    list_type = args.get('type', '')
    content_filter = args.get('content_filter', '')

    response = client.udso_list(list_type, content_filter)

    data = response.get('Data')

    return (tableToMarkdown("Apex UDSO List", data),
            {"TrendMicroApex.UDSO": data}, response)


def udso_delete_command(client: Client, args):
    list_type = args.get('type', '')
    content = args.get('content', '')

    response = client.udso_delete(list_type, content)

    return f'UDSO {content} of type {list_type} was deleted successfully', None, response


def udso_add_command(client: Client, args):
    add_type = args.get('type')
    content = args.get('content')
    scan_action = args.get('scan_action')

    response = client.udso_add(add_type=add_type, content=content, scan_action=scan_action)

    return f'UDSO {content} of type {add_type} was added successfully with scan action {scan_action}', None, response


def prodagent_isolate_command(client: Client, args):
    multi_match = args.get('multi_match', 'true') == 'true'
    entity_id = args.get('entity_id')
    ip = args.get('ip_address')
    mac = args.get('mac_address')
    host = args.get('host_name')
    product = args.get('product')

    if not any([entity_id, ip, mac, host, product]):
        raise ValueError('At least one of the following arguments must be provided: '
                         'entity_id, ip_address, mac_address, host_name, product')

    response = client.prodagent_isolate(multi_match=multi_match, entity_id=entity_id, ip_add=ip, mac_add=mac, host=host,
                                        prod=product)
    result_content = response.get('result_content', [])
    if result_content:
        return (tableToMarkdown("Apex ProductAgent Isolate", result_content),
                {"TrendMicroApex.ProductAgent": result_content}, response)
    else:
        return 'No agents were affected.', None, None


def prodagent_restore_command(client: Client, args):
    multi_match = args.get('multi_match', 'true') == 'true'
    entity_id = args.get('entity_id')
    ip = args.get('ip_address')
    mac = args.get('mac_address')
    host = args.get('host_name')
    product = args.get('product')

    if not any([entity_id, ip, mac, host, product]):
        raise ValueError('At least one of the following arguments must be provided: '
                         'entity_id, ip_address, mac_address, host_name, product')

    response = client.prodagent_restore(multi_match=multi_match, entity_id=entity_id, ip_add=ip, mac_add=mac, host=host,
                                        prod=product)
    result_content = response.get('result_content', [])
    if result_content:
        return (tableToMarkdown("Apex ProductAgent Restore", result_content),
                {"TrendMicroApex.ProductAgent": result_content}, response)
    else:
        return 'No agents were affected.', None, None


def list_logs_command(client: Client, args):
    client.suffix = '/WebApp/api/v1/logs'
    log_type = args.get('log_type', '')
    since_time = args.get('since_time', 0)
    page_token = args.get('page_token', 0)
    response = client.logs_list(log_type=log_type, since_time=since_time, page_token=page_token)
    parsed_logs_list = []

    if response:
        if response.get('Data', {}).get('Logs'):
            parsed_logs_list = client.parse_cef_logs_to_dict_logs(response)

    readable_output = tableToMarkdown('Logs List', parsed_logs_list, removeNull=True)

    # build the context
    if parsed_logs_list:
        response_data = response.get('Data', {})
        response_data.pop('Logs')
        response = {
            'Logs': parsed_logs_list,
            'Data': response_data
        }

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Log',
        outputs=response,
        outputs_key_field='',
        raw_response=response
    )


def udso_file_add_command(client: Client, args):
    client.suffix = '/WebApp/api/SuspiciousObjectResource/FileUDSO'

    file = demisto.getFilePath(args.get('entry_id'))
    file_path = file['path']
    file_name = file['name']
    with open(file_path, 'rb') as f:
        file_content_base64_string = base64.b64encode(f.read()).decode()  # the api is expecting 64based encoded file

    note = args.get('note')
    file_scan_action = args.get('file_scan_action')

    response = client.udso_add_file(file_content_base64_string, file_name, file_scan_action, note)

    if response.get('result_code') == 1:
        readable_output = f'### The file "{file_name}" was added to the UDSO list successfully'

    else:
        readable_output = f'There has been a problem while trying to create the file: \n' \
                          f'{response.get("result_description")}'

    # TODO need to insert the file to the context?
    return CommandResults(
        readable_output=readable_output,
        raw_response=response
    )


def servers_list_command(client: Client, args):
    client.suffix = '/WebApp/API/ServerResource/ProductServers'

    response = client.servers_or_agents_list(**assign_params(**args))

    for item in response.get('result_content'):  # parse comma separated str to list
        item['ip_address_list'] = item.get('ip_address_list', '').split(',')

    human_readable_table = {}
    if response:
        human_readable_table = response.get('result_content')

    readable_output = tableToMarkdown('Servers List', human_readable_table, headerTransform=string_to_table_header,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Server',
        outputs=response,
        outputs_key_field='',
        raw_response=response
    )


def agents_list_command(client: Client, args):
    client.suffix = '/WebApp/API/AgentResource/ProductAgents'

    response = client.servers_or_agents_list(**assign_params(**args))

    for item in response.get('result_content'):  # parse comma separated str to list
        item['ip_address_list'] = item.get('ip_address_list', '').split(',')

    human_readable_table = {}
    if response:
        human_readable_table = response.get('result_content')

    readable_output = tableToMarkdown('Agents List', human_readable_table, headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Agent',
        outputs=response,
        outputs_key_field='',
        raw_response=response
    )


def endpoint_sensors_list_command(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'

    response = client.endpoint_sensors_list(**assign_params(**args))

    human_readable_table = []
    if response:
        # extract the agents entities from the response
        content_list = response.get('Data', {}).get('Data', {}).get('content', {})
        for content_item in content_list:
            human_readable_table.append(content_item.get('content', {}).get('agentEntity')[0])

    readable_output = tableToMarkdown('Security Agents with Endpoint Sensor enabled', human_readable_table,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.EndpointSensorSecurityAgent',
        outputs=human_readable_table,
        outputs_key_field='',
        raw_response=response
    )


def process_terminate_command(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.process_terminate_request(**assign_params(**args))
    return CommandResults(
        outputs_prefix='TrendMicroApex.TerminatedProcess',
        outputs_key_field='',
        raw_response=response
    )


def create_investigation_from_file(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.create_file_investigation(**assign_params(**args))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.FileInvestigation',
        outputs=human_readable_table,
        outputs_key_field='',
        raw_response=response
    )


def create_investigation_from_registry(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.create_registry_investigation(**assign_params(**args))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.RegistryInvestigation',
        outputs=human_readable_table,
        outputs_key_field='',
        raw_response=response
    )


def create_custom_live_investigation(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.create_custom_investigation(**assign_params(**args))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.CustomInvestigation',
        outputs=human_readable_table,
        outputs_key_field='',
        raw_response=response
    )

# def fetch_incidents(client: Client, last_run: Dict[str, int],
#                     first_fetch_time: Optional[int], log_types: List[str]) -> Tuple[Dict[str, int], List[dict]]:
#
#     last_fetch = last_run.get('last_fetch', None)
#     for log in log_types:
#         if not last_fetch.get(log):
#             last_fetch[log] = first_fetch_time
#     else:
#         last_fetch = int(last_fetch)
#
#     incidents: List[Dict[str, Any]] = []
#
#     for log_type in log_types:
#         log_last_fetch = last_fetch[log]
#         logs_list = client.logs_list(log_type=log_type, since_time=log_last_fetch)
#         if logs_list:
#             parsed_logs_list = client.parse_cef_logs_to_dict_logs(logs_list)
#             for log in parsed_logs_list:
#                 log_creation_time = log.get('rt')  # 'rt' is the log creation time field name. in UTC format
#
#     for alert in alerts:
#         incident_created_time = int(alert.get('created', '0'))
#         incident_created_time_ms = incident_created_time * 1000
#
#         if last_fetch:
#             if incident_created_time <= last_fetch:
#                 continue
#
#         # If no name is present it will throw an exception
#         incident_name = alert['name']
#
#         incident = {
#             'name': incident_name,
#             # 'details': alert['name'],
#             'occurred': timestamp_to_datestring(incident_created_time_ms),
#             'rawJSON': json.dumps(alert),
#         }
#
#         incidents.append(incident)
#
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_created_time > latest_created_time:
#             latest_created_time = incident_created_time
#
#     # Save the next_run as a dict with the last_fetch key to be stored
#     next_run = {'last_fetch': latest_created_time}
#     return next_run, incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """ GLOBALS/PARAMS """

    params = demisto.params()

    api_key = params.get('token')
    app_id = params.get('application_id')

    base_url = urljoin(params.get('url'), '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(base_url, api_key, app_id, verify=verify, proxy=proxy)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        if command == 'test-module':
            test_result = test_module(client)
            return_results(test_result)

        elif command == 'fetch-incidents':

            first_fetch_time = arg_to_timestamp(
                arg=demisto.params().get('first_fetch', '3 days'),
                arg_name='First fetch time',
                required=True
            )

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                log_type=demisto.params().get('log_type')
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'trendmicro-apex-udso-list':
            return_outputs(*udso_list_command(client, demisto.args()))

        elif command == 'trendmicro-apex-udso-list':
            return_outputs(*udso_list_command(client, demisto.args()))

        elif command == 'trendmicro-apex-udso-add':
            return_outputs(*udso_add_command(client, demisto.args()))

        elif command == 'trendmicro-apex-udso-delete':
            return_outputs(*udso_delete_command(client, demisto.args()))

        elif command == 'trendmicro-apex-isolate':
            return_outputs(*prodagent_isolate_command(client, demisto.args()))

        elif command == 'trendmicro-apex-restore':
            return_outputs(*prodagent_restore_command(client, demisto.args()))

        elif command == 'trendmicro-apex-list-logs':
            return_results(list_logs_command(client, demisto.args()))

        elif command == 'trendmicro-apex-udso-file-add':
            return_results(udso_file_add_command(client, demisto.args()))

        elif command == 'trendmicro-apex-managed-servers-list':
            return_results(servers_list_command(client, demisto.args()))

        elif command == 'trendmicro-apex-security-agents-list':
            return_results(agents_list_command(client, demisto.args()))

        elif command == 'trendmicro-apex-endpoint-sensors-list':
            return_results(endpoint_sensors_list_command(client, demisto.args()))

        elif command == 'trendmicro-apex-process-terminate':
            return_results(process_terminate_command(client, demisto.args()))

        elif command == 'trendmicro-apex-create-live-investigation-from-file':
            return_results(create_investigation_from_file(client, demisto.args()))

        elif command == 'trendmicro-apex-create-live-investigation-from-registry':
            return_results(create_investigation_from_registry(client, demisto.args()))

        elif command == 'trendmicro-apex-create-custom-live-investigation':
            return_results(create_custom_live_investigation(client, demisto.args()))

    except ValueError as e:
        return_error(f'Error from TrendMicro Apex integration: {str(e)}', e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
