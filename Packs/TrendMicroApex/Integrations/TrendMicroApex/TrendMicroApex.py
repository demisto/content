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
from datetime import datetime, UTC
from dateutil.parser import parse

# Disable insecure warnings
urllib3.disable_warnings()
''' CLIENT CLASS'''

UDSOAPIPATH = '/WebApp/api/SuspiciousObjects/UserDefinedSO'
PRODAGENTAPIPATH = '/WebApp/API/AgentResource/ProductAgents'
FIELDS_TO_REMOVE_FROM_CONTEXT = ['FeatureCtrl', 'Meta', 'PermissionCtrl', 'SystemCtrl']

CEF_HEADERS_TO_TREND_MICRO_HEADERS = {
    'CEFVersion': 'LogVersion',
    'Name': 'EventName',
    'DeviceEventClassID': 'EventID',
    'DeviceVersion': 'ApplianceVersion',
    'DeviceProduct': 'ApplianceProduct',
    'DeviceVendor': 'ApplianceVendor'
}

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
    "endpoint_user_name": 6,
    "endpoint_OS": 5,
    "partial_OS": 9
}

SCAN_TYPE_TO_NUM = {
    "Custom criteria": 0,
    "Windows registry": 1,
    "YARA rule file": 2,
    "IOC rule file": 3,
    "Disk IOC rule file": 6
}

SCAN_NUM_TO_TYPE = {
    0: "Custom criteria",
    1: "Windows registry",
    2: "YARA rule file",
    3: "IOC rule file",
    6: "Disk IOC rule file"
}

SCAN_STATUS_TO_NUM = {
    "All": 1,
    "Matched": 2,
    "No match": 3,
    "Pending": 4,
    "Unsuccessful": 5
}

CUSTOM_INVESTIGATION_TYPE_TO_ID = {
    'file_name': 3,
    'file_path': 4,
    'account': 7,
    'command_line': 8,
    'registry_key': 9,
    'registry_name': 10,
    'registry_data': 11,
    'host_name': 12
}

REPEAT_TYPE_TO_ID = {
    'Yearly': 1,
    'Monthly': 2,
    'Daily': 3
}
GENERAL_INVESTIGATION_ARGS = ['agent_guids', 'server_guids', 'investigation_name', 'scan_type', 'time_range_type',
                              'time_range_end', 'time_range_start', 'scan_schedule_guid', 'scan_schedule_Id']

SEARCH_PERIOD_NAME_TYPE_TO_NUM = {
    'Default': -1,
    'All': 0,
    'One month': 1,
    'Three months': 3,
    'Six months': 6,
    'Twelve months': 12
}

INVESTIGATION_RESULT_FILTER_TYPE_TO_NUM = {
    'task_name': 10,
    'creator_name': 11,
    'scan_type': 12,
    'criteria_name': 14
}

INVESTIGATION_RESULT_SCAN_TYPE_TO_NUM = {
    'Search Windows registry': 1,
    'Memory scan using YARA': 2,
    'Disk scan using OpenIOC': 6
}

AGENT_ISOLATION_STATUS_NUM_TO_VALUE = {
    0: "Unknown",
    1: "Normal",
    2: "Isolated",
    3: "Isolate command sent -pending",
    4: "Restore agent from isolation -pending",
}

INVESTIGATION_STATUS_NUM_TO_VALUE = {
    0: "Pending",
    1: "Running",
    2: "Cancel",
    3: "Complete",
    4: "Invalid",
    5: "Purged",
    6: "Error (All servers failed)"
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
        token = jwt.encode(payload, self.api_key, algorithm=algorithm)
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
        response = self._http_request("DELETE", UDSOAPIPATH, full_url=self.base_url + UDSOAPIPATH + querystring,
                                      headers=headers)
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
            response = self._http_request("PUT", UDSOAPIPATH + '/', full_url=self.base_url + UDSOAPIPATH + '/',
                                          headers=headers, data=json.dumps(req_body))
            if response.get('Meta', {}).get('ErrorCode', '') != 0:
                raise ValueError(f'Operation failed - {response.get("Meta", {}).get("ErrorMsg")}')

            return response
        return None

    def udso_add_file(self, file_content_base64_string, file_name, file_scan_action, note: str = ""):
        payload = {
            "file_name": file_name,
            "file_content_base64_string": file_content_base64_string,
            "file_scan_action": file_scan_action,
            "note": note if note else ""
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='PUT', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(payload))}
        response = self._http_request("PUT", self.suffix, headers=headers, data=json.dumps(payload))
        if response.get('result_code', '') != 1:
            err_msg = f'Operation failed - {response.get("result_description", "")}'
            raise ValueError(err_msg)
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

    @staticmethod
    def verify_format_and_convert_to_timestamp(since_time: str):
        if since_time == '0':  # '0' is the default timestamp
            return since_time
        if not (since_time.endswith(('GMT+00:00', 'Z'))):
            raise ValueError("'since_time' argument should be in one of the following formats:"
                             "'2020-06-21T08:00:00Z', 'Jun 21 2020 08:00:00 GMT+00:00'")

        since_time_timestamp = int(parse(since_time).timestamp())
        return since_time_timestamp

    def logs_list(self, log_type: str, since_time: str = '0', page_token: str = '0'):
        log_type = LOG_NAME_TO_LOG_TYPE.get(log_type)
        if log_type in ["pattern_updated_status", "engine_updated_status"] and page_token != '0':
            raise ValueError("For 'Pattern Update Status' and 'Engine Update Status' log types, \n"
                             "the value of page_token must be '0'.")
        since_time_timestamp = self.verify_format_and_convert_to_timestamp(since_time)
        querystring = f'?output_format=1&page_token={page_token}&since_time={since_time_timestamp}'
        request_suffix = f'{self.suffix}/{log_type}{querystring}'
        jwt_token = self.create_jwt_token(http_method='GET', api_path=request_suffix, headers='', request_body='')

        headers = {
            'Authorization': 'Bearer ' + jwt_token,
            'Content-Type': 'application/json;charset=utf-8'
        }

        response = self._http_request("GET", url_suffix=request_suffix, headers=headers)
        return response

    @staticmethod
    def convert_timestamps_and_scan_type_to_readable(results_list):
        """
        For every item in the list, convert the time values and the scan_type values to human readable
        Args:
            results_list: List of results returned from the API

        Returns:
            list. The updated list with the readable time and type values
        """
        time_keys = ['triggerTime', 'submitTime', 'finishTime']
        status_keys = ['status', 'statusForUI']
        for result in results_list:
            for time_key in time_keys:
                if result.get(time_key):
                    result[time_key] = datetime.fromtimestamp(result.get(time_key), UTC).isoformat()
            for status_key in status_keys:
                if result.get(status_key):
                    result[status_key] = INVESTIGATION_STATUS_NUM_TO_VALUE[result.get(status_key)]
            if result.get('scanType'):
                result['scanType'] = SCAN_NUM_TO_TYPE[result['scanType']]
        return results_list

    @staticmethod
    def remove_unnecessary_fields_from_response(response):
        for field in FIELDS_TO_REMOVE_FROM_CONTEXT:
            if response.get(field):
                response.pop(field)
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

        response = self._http_request("GET", url_suffix=suffix, headers=headers)
        if response.get('result_code') != 1:
            err_msg = f'Operation failed - {response.get("result_description", "")}'
            raise ValueError(err_msg)
        return response

    @staticmethod
    def create_filter_entry(entry_value, entry_type, type_transformer: dict = SECURITY_AGENTS_TYPE_TO_NUMBER):
        """
        Create a filter entry - a dict with 'type', 'value' keys
        Args:
            entry_value: the value for the filter
            entry_type: the type of the filter
            type_transformer: transformer dict for the type value

        Returns:
            filter entry from the form :
            {
                "type" : type,
                "value": value
            }

        """
        filter_entry = {
            "type": type_transformer[entry_type]
        }
        if "OS" in entry_type:
            filter_entry["value"] = OS_NAME_TO_OS_TYPE[entry_value]  # type: ignore
        if entry_type == "scan_type":
            filter_entry["value"] = INVESTIGATION_RESULT_SCAN_TYPE_TO_NUM[entry_value]
        else:
            filter_entry["value"] = entry_value

        return filter_entry

    def create_payload_filter(self, endpoint_name='', endpoint_type='', ip_address='', operating_system=''):
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

        # return_error(payload_data)
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
        self.validate_response(response, error_message="Endpoint sensors list operation failed")
        return response

    @staticmethod
    def fix_log_headers(log: dict):
        """
        Fix the cef log headers according to TrendMicro headers
        Args:
            log(dict): the cef log to fix.

        Returns:
            the fixed log with the correct headers mapping.

        """

        remove_from_dict = ['DeviceName',
                            'DeviceSeverity']  # duplicate keys from pycef - backwards compatibility reasons
        keys_to_fix = CEF_HEADERS_TO_TREND_MICRO_HEADERS.keys()

        # remove unnecessary keys
        for key in remove_from_dict:
            log.pop(key, None)

        # fix the keys to their correct name
        new_log = log.copy()
        for key in log:
            if key in keys_to_fix:
                new_log[CEF_HEADERS_TO_TREND_MICRO_HEADERS[key]] = new_log.pop(key)
            if key == 'rt':  # this key is always referencing to 'Creation Time' header
                new_log['CreationTime'] = new_log.pop('rt')

        return new_log

    def parse_cef_logs_to_dict_logs(self, response):
        logs_list_in_cef_format = response.get('Data', {}).get('Logs', [])
        parsed_logs_list = []
        for log in logs_list_in_cef_format:
            parsed_log = pycef.parse(log)
            if parsed_log:
                parsed_trendmicro_log = self.fix_log_headers(parsed_log)
                parsed_logs_list.append(parsed_trendmicro_log)

        return parsed_logs_list

    @staticmethod
    def update_agents_info_in_payload(payload_data, agent_guids):
        agent_guids_dict = json.loads(agent_guids)  # this is a dict of { server_guids : [agent_guids] }
        payload_data["agentGuid"] = agent_guids_dict
        payload_data["serverGuid"] = list(agent_guids_dict.keys())

        return payload_data

    @staticmethod
    def validate_response(response, error_message):
        response_message = response.get('Data', {}).get('Message', '')
        if response_message and response_message != 'OK':
            raise DemistoException(f'{error_message}. Reason:\n{response_message}')

    @staticmethod
    def get_file_name_and_base_64_content(entry_id: str):
        file = demisto.getFilePath(entry_id)
        file_path = file['path']
        file_name = file['name']
        with open(file_path, 'rb') as f:
            file_content_base64_string = base64.b64encode(
                f.read()).decode()  # the api is expecting 64based encoded file
        return file_name, file_content_base64_string

    @staticmethod
    def create_custom_criteria(custom_investigation_args):
        custom_criteria = {
            "operator": custom_investigation_args.pop('operator')
        }
        filters = []

        for key, value in custom_investigation_args.items():
            if key.endswith('is'):
                type_id = CUSTOM_INVESTIGATION_TYPE_TO_ID[key[:-3]]  # arg name is : 'NAME_is', pass NAME
                filters.append({
                    "condition": "IS",
                    "value": argToList(value),
                    "typeId": type_id
                })
            if key.endswith('contains'):
                type_id = CUSTOM_INVESTIGATION_TYPE_TO_ID[key[:-9]]  # arg name is : 'NAME_contains', pass NAME
                filters.append({
                    "condition": "CONTAIN",
                    "value": argToList(value),
                    "typeId": type_id
                })
        if filters:
            custom_criteria['item'] = filters

        return custom_criteria

    @staticmethod
    def create_historical_investigation_payload(criteria_kvp, criteria_source, search_period):
        payload = {}
        if criteria_kvp:
            payload['criteriaKvp'] = criteria_kvp
        if criteria_source:
            payload['criteriaSource'] = criteria_source
        if search_period:
            payload['searchPeriod'] = SEARCH_PERIOD_NAME_TYPE_TO_NUM[search_period]

        return payload

    def create_historical_investigation(self, args):
        criteria_kvp = args.get('criteria_kvp', '')
        criteria_source = args.get('criteria_source', '')
        search_period = args.get('search_period', '')

        payload = self.create_historical_investigation_payload(criteria_kvp, criteria_source, search_period)

        payload["criteria"] = self.create_custom_criteria(args)

        request_data = {
            "Url": "V1/Task/CreateQuickScan",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload
        }
        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='POST', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}

        response = self._http_request("POST", self.suffix, headers=headers, data=json.dumps(request_data))
        self.validate_response(response, error_message='The historical investigation creation was unsuccessful')
        return response

    def create_result_list_payload(self, limit, offset, scan_type, filter_by_task_name: str = '',
                                   filter_by_creator_name: str = '', filter_by_scan_type: str = '',
                                   filter_by_criteria_name: str = '', scan_schedule_id: str = ''):
        payload = {
            "pagination": {
                "limit": int(limit),
                "offset": int(offset)
            },
            "scanType": [SCAN_TYPE_TO_NUM[scan_type] for scan_type in argToList(scan_type)]
        }
        if scan_schedule_id:
            payload["scanScheduleId"] = scan_schedule_id

        payload_filter = []
        if filter_by_task_name:
            payload_filter.append(self.create_filter_entry(filter_by_task_name, 'task_name',
                                                           INVESTIGATION_RESULT_FILTER_TYPE_TO_NUM))
        if filter_by_creator_name:
            payload_filter.append(self.create_filter_entry(filter_by_creator_name, 'creator_name',
                                                           INVESTIGATION_RESULT_FILTER_TYPE_TO_NUM))
        if filter_by_scan_type:
            payload_filter.append(self.create_filter_entry(filter_by_scan_type, 'scan_type',
                                                           INVESTIGATION_RESULT_FILTER_TYPE_TO_NUM))
        if filter_by_criteria_name:
            payload_filter.append(self.create_filter_entry(filter_by_criteria_name, 'criteria_name',
                                                           INVESTIGATION_RESULT_FILTER_TYPE_TO_NUM))

        if payload_filter:
            payload["filter"] = payload_filter

        return payload

    def investigation_result_list(self, scan_type: str, limit: str = '50', offset: str = '0',
                                  filter_by_task_name: str = '',
                                  filter_by_creator_name: str = '', filter_by_scan_type: str = '',
                                  filter_by_criteria_name: str = '', scan_schedule_id: str = ''):

        payload = self.create_result_list_payload(limit, offset, scan_type, filter_by_task_name, filter_by_creator_name,
                                                  filter_by_scan_type, filter_by_criteria_name, scan_schedule_id)

        request_data = {
            "Url": "V1/Task/ShowScanSummaryList",
            "TaskType": 4,  # For Endpoint Sensor, the value is always 4.
            "Payload": payload
        }
        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.create_jwt_token(http_method='PUT', api_path=self.suffix,
                                                               headers='', request_body=json.dumps(request_data))}
        response = self._http_request("PUT", self.suffix, headers=headers, data=json.dumps(request_data))
        self.validate_response(response, 'The investigation result list command was unsuccessfu')

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
    list_data = response.get('Data', [])
    readable_output = tableToMarkdown("Apex One UDSO List", list_data)

    context = {
        'TrendMicroApex.UDSO(val.content == obj.content)': list_data,
        'TrendMicroApex.USDO(val.content == obj.content)': list_data,  # for bc reasons
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=context,
        raw_response=response
    )


def udso_delete_command(client: Client, args):
    list_type = args.get('type', '')
    content = args.get('content', '')

    response = client.udso_delete(list_type, content)

    readable_output = f'### UDSO "{content}" of type "{list_type}" was deleted successfully'
    return CommandResults(
        readable_output=readable_output,
        raw_response=response
    )


def udso_add_command(client: Client, args):
    add_type = args.get('type')
    content = args.get('content')
    scan_action = args.get('scan_action')
    notes = args.get('notes', "")
    expiration = args.get('expiration', "")
    response = client.udso_add(add_type=add_type, content=content, scan_action=scan_action, notes=notes,
                               expiration=expiration)

    readable_output = f'### UDSO "{content}" of type "{add_type}" was added successfully with scan action ' \
                      f'"{scan_action}"'
    return CommandResults(
        readable_output=readable_output,
        raw_response=response
    )


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
        readable_output = tableToMarkdown("Apex One ProductAgent Isolate", result_content)

    else:
        readable_output = '### No agents were affected.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.ProductAgent',
        outputs=result_content,
        raw_response=response
    )


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
        readable_output = tableToMarkdown("Apex One ProductAgent Restore", result_content)
    else:
        readable_output = '### No agents were affected.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.ProductAgent',
        outputs=result_content,
        raw_response=response
    )


def list_logs_command(client: Client, args):
    client.suffix = '/WebApp/api/v1/logs'
    limit = int(args.pop('limit', 50))
    response = client.logs_list(**assign_params(**args))
    parsed_logs_list = []

    if response and response.get('Data', {}).get('Logs'):
        parsed_logs_list = client.parse_cef_logs_to_dict_logs(response)[:limit]

    log_type = args.get('log_type')
    headers = ['EventName', 'EventID', 'CreationTime', 'LogVersion', 'ApplianceVersion', 'ApplianceProduct',
               'ApplianceVendor']
    readable_output = tableToMarkdown(f'Trend Micro Apex One - {log_type} Logs', parsed_logs_list, headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Log',
        outputs=parsed_logs_list,
        raw_response=response
    )


def udso_file_add_command(client: Client, args):
    client.suffix = '/WebApp/api/SuspiciousObjectResource/FileUDSO'
    note = args.get('note')
    file_scan_action = args.get('file_scan_action')
    entry_id = args.get('entry_id')

    file_name, file_content_base64_string = client.get_file_name_and_base_64_content(entry_id)
    response = client.udso_add_file(file_content_base64_string, file_name, file_scan_action, note)
    readable_output = f'### The file "{file_name}" was added to the UDSO list successfully'

    return CommandResults(
        readable_output=readable_output,
        raw_response=response
    )


def servers_list_command(client: Client, args):
    client.suffix = '/WebApp/API/ServerResource/ProductServers'

    response = client.servers_or_agents_list(**assign_params(**args))

    for item in response.get('result_content'):  # parse comma separated str to list
        item['ip_address_list'] = item.get('ip_address_list', '').split(',')

    context = human_readable_table = []
    if response and response.get('result_content'):
        context = human_readable_table = response.get('result_content')

    headers = ['entity_id', 'product', 'host_name', 'ip_address_list', 'capabilities']
    readable_output = tableToMarkdown('Trend Micro Apex One Servers List', human_readable_table, headers,
                                      headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Server',
        outputs=context,
        outputs_key_field='entity_id',
        raw_response=response
    )


def agents_list_command(client: Client, args):
    client.suffix = '/WebApp/API/AgentResource/ProductAgents'

    response = client.servers_or_agents_list(**assign_params(**args))

    for item in response.get('result_content'):  # parse comma separated str to list
        item['ip_address_list'] = item.get('ip_address_list', '').split(',')

    context = human_readable_table = []
    if response and response.get('result_content'):
        context = human_readable_table = response.get('result_content')

    readable_output = tableToMarkdown('Trend Micro Apex One Agents List', human_readable_table,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.Agent',
        outputs=context,
        outputs_key_field='entity_id',
        raw_response=response
    )


def endpoint_sensors_list_command(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'

    response = client.endpoint_sensors_list(**assign_params(**args))
    human_readable_table = []
    if response:
        # extract the sensor agents entities from the response
        content_list = response.get('Data', {}).get('Data', {}).get('content', {})
        for content_item in content_list:
            agent = content_item.get('content', {}).get('agentEntity', [])
            if agent:
                if agent[0].get('isolateStatus'):
                    agent['isolateStatus'] = AGENT_ISOLATION_STATUS_NUM_TO_VALUE[agent['isolateStatus']]
                human_readable_table.append(agent[0])

    readable_output = tableToMarkdown('Trend Micro Apex One Security Agents with Endpoint Sensor enabled',
                                      human_readable_table, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.EndpointSensorSecurityAgent',
        outputs=human_readable_table,
        outputs_key_field='agentGuid',
        raw_response=response
    )


def create_historical_investigation(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.create_historical_investigation(args)
    context = response
    if response:
        context = response.get('Data', {}).get('Data', {})

        headers = ['taskId', 'serverName', 'serverGuid']
        readable_output = tableToMarkdown('The historical investigation was created successfully',
                                          context, headers=headers, removeNull=True)
    else:
        readable_output = ''

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.HistoricalInvestigation',
        outputs=context,
        outputs_key_field='taskId',
        raw_response=response
    )


def investigation_result_list_command(client: Client, args):
    client.suffix = '/WebApp/OSCE_iES/OsceIes/ApiEntry'
    response = client.investigation_result_list(**assign_params(**args))
    context = {}
    readable_output = ''
    if response:
        content_list = response.get('Data', {}).get('Data', {}).get('content', [])
        if content_list:
            results_list = content_list[0].get('content', {}).get('scanSummaryEntity')
            if results_list:
                context = results_list = client.convert_timestamps_and_scan_type_to_readable(results_list)

            headers = ['name', 'scanSummaryId', 'scanSummaryGuid', 'submitTime', 'serverGuidList', 'creator']
            readable_output = tableToMarkdown('Investigation result list:', results_list, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroApex.InvestigationResult',
        outputs=context,
        outputs_key_field='scanSummaryGuid',
        raw_response=response
    )


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """ GLOBALS/PARAMS """

    params = demisto.params()

    api_key = params.get('credentials_api_token', {}).get('password') or params.get('token')
    if not api_key:
        return_error('API Key must be provided.')
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

        elif command in ('trendmicro-apex-udso-list', 'trendmicro-apex-usdo-list'):  # For bc reasons.
            return_results(udso_list_command(client, demisto.args()))

        elif command in ('trendmicro-apex-udso-add', 'trendmicro-apex-usdo-add'):  # For bc reasons
            return_results(udso_add_command(client, demisto.args()))

        elif command in ('trendmicro-apex-udso-delete', 'trendmicro-apex-usdo-delete'):  # For bc reasons
            return_results(udso_delete_command(client, demisto.args()))

        elif command == 'trendmicro-apex-isolate':
            return_results(prodagent_isolate_command(client, demisto.args()))

        elif command == 'trendmicro-apex-restore':
            return_results(prodagent_restore_command(client, demisto.args()))

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

        elif command == 'trendmicro-apex-historical-investigation-create':
            return_results(create_historical_investigation(client, demisto.args()))

        elif command == 'trendmicro-apex-investigation-result-list':
            return_results(investigation_result_list_command(client, demisto.args()))

    except ValueError as e:
        return_error(f'Error from TrendMicro Apex One integration: {str(e)}', e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
