import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import os
import requests
import json
from pancloud import LoggingService, Credentials
import base64
from dateutil.parser import parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
AUTH_ID = demisto.params().get('auth_id')
# If there's a stored token in integration context, it's newer than current
TOKEN = demisto.getIntegrationContext().get('token')
if not TOKEN:
    TOKEN = demisto.params().get('token')

ENC_KEY = demisto.params().get('auth_key')

USE_SSL = not demisto.params().get('insecure', False)
TOKEN_RETRIEVAL_URL = 'https://demistobot.demisto.com/panw-token'
FETCH_QUERY = 'Traps Threats'

FIRST_FETCH_TIMESTAMP = demisto.params().get('first_fetch_timestamp', '').strip()
if not FIRST_FETCH_TIMESTAMP:
    FIRST_FETCH_TIMESTAMP = '24 hours'

if not demisto.params().get('proxy', False):
    os.environ.pop('HTTP_PROXY', '')
    os.environ.pop('HTTPS_PROXY', '')
    os.environ.pop('http_proxy', '')
    os.environ.pop('https_proxy', '')

FETCH_QUERY_DICT = {
    'Traps Threats': 'SELECT * FROM tms.threat',
    'Firewall Threats': 'SELECT * FROM panw.threat',
    'Cortex XDR Analytics': 'SELECT * FROM magnifier.alert'
}

THREAT_TABLE_HEADERS = [
    'id', 'score', 'risk-of-app', 'type', 'action', 'app', 'pcap_id', 'proto', 'dst', 'reportid',
    'rule', 'category-of-threatid', 'characteristic-of-app', 'device_name', 'subtype',
    'time_received', 'pcap', 'name-of-threatid', 'severity', 'nat', 'natdport', 'natdst',
    'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc', 'category', 'SHA256', 'filetype', 'filename'
]

TRAFFIC_TABLE_HEADERS = [
    'id', 'score', 'aggregations.size', 'action', 'app', 'proto', 'dst', 'rule', 'characteristic-of-app',
    'device_name', 'risk-of-app', 'natsport', 'start', 'subcategory-of-app', 'time_received',
    'nat', 'natdport', 'natdst', 'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc'
]

COMMON_HEADERS = [
    'id', 'score', 'action', 'app', 'proto', 'dst', 'rule', 'characteristic-of-app', 'device_name',
    'nat', 'natdport', 'natdst', 'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc', 'filetype',
    'SHA256', 'filename'
]

TRAFFIC_FIELDS = [
    'all', 'action', 'container', 'risk-of-app', 'logset', 'bytes_received', 'natsport', 'sessionid', 'url_denied',
    'type', 'parent_start_time', 'packets', 'characteristic-of-app', 'dg_hier_level_4', 'dg_hier_level_1',
    'dg_hier_level_3', 'dg_hier_level_2', 'parent_session_id', 'repeatcnt', 'app', 'vsys', 'nat',
    'technology-of-app', 'pkts_received', 'chunks_sent', 'pbf_s2c', 'pbf_c2s', 'receive_time', 'non-standard-dport',
    'subcategory-of-app', 'chunks_received', 'users', 'captive_portal', 'is_gpaas', 'proxy', 'fwd',
    'log_feat_bit1', 'config_ver', 'cloud_hostname', 'is_fwaas', 'customer-id', 'is_dup_log', 'proto',
    'non_std_dport', 'tunneled-app', 'recon_excluded', 'is-saas-of-app', 'traffic_flags', 'natdport', 'action_source',
    'assoc_id', 'flag', 'dst', 'natdst', 'chunks', 'flags', 'rule', 'decrypt_mirror', 'dport', 'elapsed',
    'sanctioned-state-of-app', 'inbound_if', 'device_name', 'mptcp_on', 'subtype', 'time_received', 'actionflags',
    'tunnelid_imsi', 'session_end_reason', 'sym_return', 'exported', 'natsrc', 'seqno', 'src', 'start',
    'time_generated', 'outbound_if', 'category-of-app', 'bytes_sent', 'srcloc', 'pkts_sent', 'dstloc',
    'tunnel_inspected', 'serial', 'bytes', 'vsys_id', 'ui-srcloc', 'to', 'from', 'category', 'sport', 'packet_capture',
    'tunnel', 'ui-dstloc', 'transaction', 'is_phishing'
]

THREAT_FIELDS = [
    'all', 'sessionid', 'url_idx', 'dg_hier_level_4', 'dg_hier_level_3', 'dg_hier_level_2', 'dg_hier_level_1',
    'action', 'recsize', 'repeatcnt', 'app', 'nat', 'subcategory-of-app', 'pcap_id', 'ppid', 'proxy', 'cloud_hostname',
    'customer-id', 'natdst', 'flags', 'dport', 'pcap', 'threatid', 'natsrc', 'outbound_if', 'category-of-app',
    'srcloc', 'dstloc', 'to', 'transaction', 'risk-of-app', 'natsport', 'url_denied', 'characteristic-of-app',
    'http_method', 'from', 'vsys', 'technology-of-app', 'receive_time', 'users', 'fwd', 'proto', 'natdport', 'dst',
    'rule', 'category-of-threatid', 'inbound_if', 'device_name', 'subtype', 'time_received', 'actionflags',
    'direction', 'misc', 'severity', 'seqno', 'src', 'time_generated', 'serial', 'vsys_id', 'url_domain', 'ui-srcloc',
    'category', 'sport', 'packet_capture', 'ui-dstloc', 'is_phishing'
]

TRAPS_FIELDS = [
    'all', 'severity', 'agentId', 'endPointHeader.osType', 'endPointHeader.isVdi', 'endPointHeader.osVersion',
    'endPointHeader.is64', 'endPointHeader.agentIp', 'endPointHeader.deviceName', 'endPointHeader.deviceDomain',
    'endPointHeader.userName', 'endPointHeader.agentTime', 'endPointHeader.tzOffset', 'endPointHeader.agentVersion',
    'endPointHeader.contentVersion', 'endPointHeader.policyTag', 'endPointHeader.protectionStatus',
    'endPointHeader.dataCollectionStatus', 'recordType', 'trapsId', 'eventType', 'uuid', 'serverHost', 'generatedTime',
    'serverComponentVersion', 'regionId', 'customerId', 'recsize', 'serverTime', 'originalAgentTime', 'facility',
    'messageData.eventCategory', 'messageData.moduleId', 'messageData.moduleStatusId', 'messageData.preventionKey',
    'messageData.processes.pid', 'messageData.processes.parentId', 'messageData.processes.exeFileIdx',
    'messageData.processes.userIdx', 'messageData.processes.commandLine', 'messageData.processes.instanceId',
    'messageData.processes.terminated', 'messageData.files.rawFullPath', 'messageData.files.fileName',
    'messageData.files.sha256', 'messageData.files.fileSize', 'messageData.files.innerObjectSha256',
    'messageData.users.userName', 'messageData.postDetected', 'messageData.terminate', 'messageData.block',
    'messageData.eventParameters', 'messageData.sourceProcessIdx', 'messageData.fileIdx', 'messageData.verdict',
    'messageData.canUpload', 'messageData.targetProcessIdx', 'messageData.moduleCategory', 'messageData.preventionMode',
    'messageData.trapsSeverity', 'messageData.profile', 'messageData.description', 'messageData.cystatusDescription',
    'messageData.sourceProcess.user.userName', 'messageData.sourceProcess.pid', 'messageData.sourceProcess.parentId',
    'messageData.sourceProcess.exeFileIdx', 'messageData.sourceProcess.userIdx',
    'messageData.sourceProcess.commandLine', 'messageData.sourceProcess.instanceId',
    'messageData.sourceProcess.terminated', 'messageData.sourceProcess.rawFullPath'
                                            'messageData.sourceProcess.fileName', 'messageData.sourceProcess.sha256',
    'messageData.sourceProcess.fileSize'
    'messageData.sourceProcess.innerObjectSha256', 'messageData.class', 'messageData.classId'
]

ANALYTICS_FIELDS = [
    'all', 'agentId', 'endPointHeader.osType', 'endPointHeader.isVdi', 'endPointHeader.osVersion',
    'endPointHeader.is64', 'endPointHeader.agentIp', 'endPointHeader.deviceName', 'endPointHeader.deviceDomain',
    'endPointHeader.userName', 'endPointHeader.userDomain', 'endPointHeader.agentTime', 'endPointHeader.tzOffset',
    'endPointHeader.agentVersion', 'endPointHeader.contentVersion', 'endPointHeader.policyTag',
    'endPointHeader.protectionStatus', 'endPointHeader.dataCollectionStatus', 'trapsId', 'eventType', 'uuid',
    'serverHost', 'generatedTime', 'serverComponentVersion', 'regionId', 'customerId', 'recsize', 'serverTime',
    'originalAgentTime', 'facility', 'messageData.eventCategory', 'messageData.sha256', 'messageData.type',
    'messageData.fileName', 'messageData.filePath', 'messageData.fileSize', 'messageData.reported',
    'messageData.blocked', 'messageData.localAnalysisResult.contentVersion', 'messageData.localAnalysisResult.trusted',
    'messageData.localAnalysisResult.publishers'
]

PANW_ARGS_DICT = {
    'ip': ['src=', 'dst='],
    'rule': ['rule='],
    'from_zone': ['from='],
    'to_zone': ['to='],
    'port': ['sport=', 'dport='],
    'action': ['action='],
    'hash': ['filedigest='],
    'url': ['misc LIKE '],
    'query': []
}

TRAPS_ARGS_DICT = {
    'ip': ['endPointHeader.agentIp='],
    'host': ['endPointHeader.deviceName='],
    'user': ['endPointHeader.userName='],
    'category': ['messageData.eventCategory='],
    'hash': ['messageData.files.sha256='],
    'query': []
}

ANALYTICS_ARGS_DICT = {
    'ip': ['endPointHeader.agentIp='],
    'host': ['endPointHeader.deviceName='],
    'user': ['endPointHeader.userName='],
    'category': ['messageData.eventCategory='],
    'hash': ['messageData.sha256='],
    'query': []
}

# This dictionary transforms number values into string representation. The number is correspondent
# to the index in the list. For example VALUE_TRANSFORM_DICT['traps']['messageData']['block'][0] matches the string:
# "File was not blocked".

VALUE_TRANSFORM_DICT: Dict[object, Dict[object, Dict]] = {
    'traps': {
        'messageData': {
            'block': ['File was not blocked', 'File was blocked'],
            'terminate': ['Traps did not terminate the file', 'Traps terminated the file']
        },
        'endPointHeader': {
            'is64': ['The endpoint is not running x64 architecture', 'The endpoint is running x64 architecture'],
            'isVdi': ['The endpoint is not a VDI', 'The endpoint is a VDI'],
            'osType': ['', 'Windows', 'OS X/macOS', 'Android', 'Linux']
        },
        'regionId': {10: 'Americas (N. Virginia)', 70: 'EMEA (Frankfurt)'}
    },
    'analytics': {
        'messageData': {
            'localAnalysisResult': {
                'trustedId': ['Traps did not evaluate the signer of the file', 'The signer is trusted',
                              'The signer is not trusted']
            }
        },
        'endPointHeader': {
            'is64': ['The endpoint is not running x64 architecture', 'The endpoint is running x64 architecture'],
            'isVdi': ['The endpoint is not a VDI', 'The endpoint is a VDI'],
            'osType': ['', 'Windows', 'OS X/macOS', 'Android', 'Linux']
        },
        'regionId': {10: 'Americas (N. Virginia)', 70: 'EMEA (Frankfurt)'}
    }
}

''' HELPER FUNCTIONS '''


def traffic_context_transformer(row_content: dict) -> dict:
    """
    This function retrives data from a row of raw data into context path locations
    :param row_content: a dict representing raw data of a row
    :return: a dict with context paths and their corresponding value
    """
    return {
        'RiskOfApp': row_content.get('risk-of-app'),
        'Natsport': row_content.get('natsport'),
        'SessionID': row_content.get('sessionid'),
        'Packets': row_content.get('packets'),
        'CharacteristicOfApp': row_content.get('characteristic-of-app'),
        'App': row_content.get('app'),
        'Action': row_content.get('action'),
        'Vsys': row_content.get('vsys'),
        'Nat': row_content.get('nat'),
        'ReceiveTime': row_content.get('receive_time'),
        'SubcategoryOfApp': row_content.get('subcategory-of-app'),
        'Proto': row_content.get('proto'),
        'Natdport': row_content.get('natdport'),
        'Dst': row_content.get('dst'),
        'Natdst': row_content.get('natdst'),
        'Rule': row_content.get('rule'),
        'Dport': row_content.get('dport'),
        'Elapsed': row_content.get('elapsed'),
        'DeviceName': row_content.get('device_name'),
        'Subtype': row_content.get('subtype'),
        'Users': row_content.get('users'),
        'TunneledApp': row_content.get('tunneled-app'),
        'TimeReceived': row_content.get('time_received'),
        'IsPhishing': row_content.get('is_phishing'),
        'SessionEndReason': row_content.get('session_end_reason'),
        'Natsrc': row_content.get('natsrc'),
        'Src': row_content.get('src'),
        'Start': row_content.get('start'),
        'TimeGenerated': row_content.get('time_generated'),
        'CategoryOfApp': row_content.get('category-of-app'),
        'Srcloc': row_content.get('srcloc'),
        'Dstloc': row_content.get('dstloc'),
        'Serial': row_content.get('serial'),
        'Bytes': row_content.get('bytes'),
        'VsysID': row_content.get('vsys_id'),
        'To': row_content.get('to'),
        'Category': row_content.get('category'),
        'Sport': row_content.get('sport'),
        'Tunnel': row_content.get('tunnel')
    }


def threat_context_transformer(row_content: dict) -> dict:
    """
    This function retrives data from a row of raw data into context path locations
    :param row_content: a dict representing raw data of a row
    :return: a dict with context paths and their corresponding value
    """
    return {
        'SessionID': row_content.get('sessionid'),
        'Action': row_content.get('action'),
        'App': row_content.get('app'),
        'Nat': row_content.get('nat'),
        'SubcategoryOfApp': row_content.get('subcategory-of-app'),
        'PcapID': row_content.get('pcap_id'),
        'Natdst': row_content.get('natdst'),
        'Flags': row_content.get('flags'),
        'Dport': row_content.get('dport'),
        'ThreatID': row_content.get('threatid'),
        'Natsrc': row_content.get('natsrc'),
        'URLDenied': row_content.get('url_denied'),
        'Users': row_content.get('users'),
        'TimeReceived': row_content.get('time_received'),
        'IsPhishing': row_content.get('is_phishing'),
        'CategoryOfApp': row_content.get('category-of-app'),
        'Srcloc': row_content.get('srcloc'),
        'Dstloc': row_content.get('dstloc'),
        'To': row_content.get('to'),
        'RiskOfApp': row_content.get('risk-of-app'),
        'Natsport': row_content.get('natsport'),
        'CharacteristicOfApp': row_content.get('characteristic-of-app'),
        'HTTPMethod': row_content.get('http_method'),
        'From': row_content.get('from'),
        'Vsys': row_content.get('vsys'),
        'ReceiveTime': row_content.get('receive_time'),
        'Proto': row_content.get('proto'),
        'Natdport': row_content.get('natdport'),
        'Dst': row_content.get('dst'),
        'Rule': row_content.get('rule'),
        'CategoryOfThreatID': row_content.get('category-of-threatid'),
        'DeviceName': row_content.get('device_name'),
        'Subtype': row_content.get('subtype'),
        'Direction': row_content.get('direction'),
        'Misc': row_content.get('misc'),
        'Severity': row_content.get('severity'),
        'Src': row_content.get('src'),
        'TimeGenerated': row_content.get('time_generated'),
        'Serial': row_content.get('serial'),
        'VsysID': row_content.get('vsys_id'),
        'URLDomain': row_content.get('url_domain'),
        'Category': row_content.get('category'),
        'Sport': row_content.get('sport')
    }


def traps_context_transformer(row_content: dict) -> dict:
    """
    This function retrives data from a row of raw data into context path locations
    :param row_content: a dict representing raw data of a row
    :return: a dict with context paths and their corresponding value
    """
    end_point_header = row_content.get('endPointHeader', {})
    message_data = row_content.get('messageData', {})
    source_process = message_data.get('sourceProcess', {})
    return {
        'Severity': row_content.get('severity'),
        'AgentID': row_content.get('agentId'),
        'EndPointHeader': {
            'OsType': VALUE_TRANSFORM_DICT['traps']['endPointHeader']['osType'][end_point_header.get('osType')]
            if end_point_header.get('osType')
            and 1 <= end_point_header.get('osType') <= len(VALUE_TRANSFORM_DICT['traps']['endPointHeader']['osType'])
            else '',
            'IsVdi': VALUE_TRANSFORM_DICT['traps']['endPointHeader']['isVdi'][end_point_header.get('isVdi')]
            if end_point_header.get('isVdi')
            and 0 <= end_point_header.get('isVdi') <= len(VALUE_TRANSFORM_DICT['traps']['endPointHeader']['isVdi'])
            else '',
            'OSVersion': end_point_header.get('osVersion'),
            'Is64': VALUE_TRANSFORM_DICT['traps']['endPointHeader']['is64'][end_point_header.get('is64')]
            if end_point_header.get('is64')
            and 0 <= end_point_header.get('isVdi') <= len(VALUE_TRANSFORM_DICT['traps']['endPointHeader']['is64'])
            else '',
            'AgentIP': end_point_header.get('agentIp'),
            'DeviceName': end_point_header.get('deviceName'),
            'DeviceDomain': end_point_header.get('deviceDomain'),
            'Username': end_point_header.get('userName'),
            'AgentTime': end_point_header.get('agentTime'),
            'AgentVersion': end_point_header.get('agentVersion'),
            'ProtectionStatus': end_point_header.get('protectionStatus')
        },
        'TrapsID': row_content.get('tarpsId'),
        'RecordType': row_content.get('recordType'),
        'UUID': row_content.get('uuid'),
        'EventType': row_content.get('eventType'),
        'ServerHost': row_content.get('serverHost'),
        'GeneratedTime': row_content.get('generatedTime'),
        'ServerComponentVersion': row_content.get('serverComponentVersion'),
        'RegionID': VALUE_TRANSFORM_DICT['traps']['regionId'].get(row_content.get('regionId'))
        if row_content.get('regionId') else '',
        'CustomerID': row_content.get('customerId'),
        'ServerTime': row_content.get('serverTime'),
        'OriginalAgentTime': row_content.get('originalAgentTime'),
        'Facility': row_content.get('facility'),
        'MessageData': {
            'EventCategory': message_data.get('eventCategory'),
            'PreventionKey': message_data.get('preventionKey'),
            'Processes': parse_processes(message_data.get('processes', [])),
            'Files': parse_files(message_data.get('files', [])),
            'Users': parse_users(message_data.get('users', [])),
            'PostDetected': message_data.get('postDetected'),
            'Terminate': VALUE_TRANSFORM_DICT['traps']['messageData']['terminate']
            [message_data.get('terminate')] if message_data.get('terminate') else '',
            'Verdict': message_data.get('verdict'),
            'Blocked': VALUE_TRANSFORM_DICT['traps']['messageData']['block'][message_data.get('blocked')]
            if message_data.get('blocked')
            and 0 <= message_data.get('blocked') <= len(VALUE_TRANSFORM_DICT['traps']['messageData']['block'])
            else '',
            'TargetProcessIdx': message_data.get('targetProcessIdx'),
            'ModuleCategory': message_data.get('moduleCategory'),
            'PreventionMode': message_data.get('preventionMode'),
            'TrapsSeverity': message_data.get('trapsSeverity'),
            'SourceProcess': {
                'User': {'Username': source_process.get('user', {}).get('userName')},
                'PID': source_process.get('pid'),
                'ParentID': source_process.get('parentId'),
                'CommandLine': source_process.get('commandLine'),
                'InstanceID': source_process.get('instanceId'),
                'Terminated': source_process.get('terminated'),
                'RawFullPath': source_process.get('rawFullPath'),
                'FileName': source_process.get('fileName'),
                'SHA256': source_process.get('sha256'),
                'FileSize': source_process.get('fileSize')
            }
        }
    }


def analytics_context_transformer(row_content: dict) -> dict:
    """
    This function retrives data from a row of raw data into context path locations
    :param row_content: a dict representing raw data of a row
    :return: a dict with context paths and their corresponding value
    """
    end_point_header = row_content.get('endPointHeader', {})
    message_data = row_content.get('messageData', {})
    local_analysis_result = message_data.get('localAnalysisResult', {})
    local_analysis_result = message_data.get('localAnalysisResult', {})
    return {
        'AgentID': row_content.get('agentId'),
        'EndPointHeader': {
            'OsType': VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['osType'][end_point_header.get('osType')]
            if end_point_header.get('osType')
            and 1 <= end_point_header.get('osType')
            <= len(VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['osType']) else '',
            'IsVdi': VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['isVdi'][end_point_header.get('isVdi')]
            if end_point_header.get('isVdi')
            and 0 <= end_point_header.get('isVdi') <= len(
                VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['isVdi'])
            else '',
            'OSVersion': end_point_header.get('osVersion'),
            'Is64': VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['is64'][end_point_header.get('is64')]
            if end_point_header.get('is64')
            and 0 <= end_point_header.get('isVdi') <= len(
                VALUE_TRANSFORM_DICT['analytics']['endPointHeader']['is64'])
            else '',
            'AgentIP': end_point_header.get('agentIp'),
            'DeviceName': end_point_header.get('deviceName'),
            'DeviceDomain': end_point_header.get('deviceDomain'),
            'Username': end_point_header.get('userName'),
            'UserDomain': end_point_header.get('userDomain'),
            'AgentTime': end_point_header.get('agentTime'),
            'AgentVersion': end_point_header.get('agentVersion'),
            'ProtectionStatus': end_point_header.get('protectionStatus'),
        },
        'TrapsID': row_content.get('trapsId'),
        'EventType': row_content.get('eventType'),
        'Severity': row_content.get('severity'),
        'UUID': row_content.get('uuid'),
        'GeneratedTime': row_content.get('generatedTime'),
        'RegionID': VALUE_TRANSFORM_DICT['analytics']['regionId'].get(row_content.get('regionId'))
        if row_content.get('regionId') else '',
        'OriginalAgentTime': row_content.get('originalAgentTime'),
        'Facility': row_content.get('facility'),
        'MessageData': {
            '@type': message_data.get('@type'),
            'Type': message_data.get('type'),
            'SHA256': message_data.get('sha256'),
            'FileName': message_data.get('fileName'),
            'FilePath': message_data.get('filePath'),
            'FileSize': message_data.get('fileSize'),
            'Reported': message_data.get('reported'),
            'Blocked': message_data.get('blocked'),
            'LocalAnalysisResult': {
                'Trusted': local_analysis_result.get('trusted'),
                'Publishers': local_analysis_result.get('publishers'),
                'TrustedID': VALUE_TRANSFORM_DICT['analytics']['messageData']['localAnalysisResult']['trustedId']
                [local_analysis_result.get('trustedId')]
                if local_analysis_result.get('trustedId')
                and 0 <= local_analysis_result.get('trustedId')
                <= len(VALUE_TRANSFORM_DICT['analytics']['messageData']['localAnalysisResult']['trustedId']) else ''
            },
            'ExecutionCount': message_data.get('executionCount'),
            'LastSeen': message_data.get('lastSeen')
        }
    }


def logs_human_readable_output_generator(fields: str, table_name: str, results: list) -> str:
    """
    This function gets all relevant data for the human readable output of a specific table.
    By design if the user queries all fields of the table (i.e. enters '*' in the query) than the outputs
    shown in the war room will be the same for each query - the outputs will be the headers list in the code.
    If the user selects different fields in the query than those fields will be shown to the user.
    :param fields: the field of the table named table_name
    :param table_name: the name of the table
    :param results: the results needs to be shown
    :return: a markdown table of the outputs
    """
    filtered_results: list = []
    headers: list = []

    if fields == '*':
        headers_raw_names: list = []
        # if the user queried all fields than we have preset headers
        if table_name == 'traffic' or table_name == 'threat':
            headers = ['Source Address', 'Destination Address', 'Application', 'Action', 'Rule', 'Time Generated']
            headers_raw_names = ['src', 'dst', 'app', 'action', 'rule', 'time_generated']

        elif table_name == 'traps' or table_name == 'analytics':
            headers = ['Severity', 'Event Type', 'User', 'Agent Address', 'Agent Name', 'Agent Time']
            headers_raw_names = ['severity', 'eventType', 'userName', 'agentIp', 'deviceName', 'agentTime']

        for result in results:
            filtered_result = {}
            for key, value in result.items():
                if key in headers_raw_names:
                    if key == 'time_generated':
                        filtered_result[headers[headers_raw_names.index(key)]] = datetime.fromtimestamp(
                            value).isoformat()
                    else:
                        filtered_result[headers[headers_raw_names.index(key)]] = value
                elif isinstance(value, dict) and key == 'endPointHeader':
                    # handle case which headers are in nested dict (1 nest only)
                    for child_key in value.keys():
                        if child_key in headers_raw_names:
                            filtered_result[headers[headers_raw_names.index(child_key)]] = value[child_key]
            filtered_results.append(filtered_result)
    else:
        # if the user has chosen which fields to query then they will be used as headers
        fields_list: list = argToList(fields)
        headers = fields_list

        for result in results:
            filtered_result = {}
            for root in result.keys():
                parsed_tree: dict = parse_tree_by_root_to_leaf_paths(root, result[root])
                filtered_result.update(parsed_tree)
            filtered_results.append(filtered_result)

    return tableToMarkdown(f'Logs {table_name} table', filtered_results, headers=headers, removeNull=True)


def parse_tree_by_root_to_leaf_paths(root: str, body) -> dict:
    """
    This function receives a dict (root and a body) and parses it according to the upcoming example:
    Input: root = 'a', body = {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}.
    So the dict is {'a': {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}}
    The expected output is {'a.b': 2, 'a.c': 3, 'a.d.e': 5, 'a.d.f': 6, 'a.d.g.h': 8, 'a.d.g.i': 9}
    Basically what this function does is when it gets a tree it creates a dict from it which it's keys are all
    root to leaf paths and the corresponding values are the values in the leafs
    Please note that the implementation is similar to DFS on trees (which means we don't have to check for visited
    nodes since there are no cycles)
    :param root: the root string
    :param body: the body of the root
    :return: the parsed tree
    """
    parsed_tree: dict = {}
    help_stack: list = [(root, body)]

    while help_stack:
        node: tuple = help_stack.pop()
        root_to_node_path: str = node[0]
        body = node[1]
        if isinstance(body, dict):
            for key, value in body.items():
                # for each node we append a tuple of it's body and the path from the root to it
                help_stack.append((root_to_node_path + '.' + key, value))
        elif isinstance(body, list):
            for element in body:
                help_stack.append((root_to_node_path, element))
        else:
            parsed_tree[root_to_node_path] = body

    return parsed_tree


def parse_processes(processes_list: list) -> list:
    """
    This function gets a processes list and retrives specific data from each process and builds a new list of the
    parsed process data.
    :param processes_list: the raw processes list
    :return: the parsed processes list
    """
    parsed_processes_list: list = []
    for process_object in processes_list:
        process_new_object: dict = {
            'PID': process_object.get('pid'),
            'ParentID': process_object.get('parentId'),
            'ExeFileIdx': process_object.get('exeFileIdx'),
            'UserIdx': process_object.get('userIdx'),
            'CommandLine': process_object.get('commandLine'),
            'Terminated': process_object.get('terminated')
        }
        parsed_processes_list.append(process_new_object)
    return parsed_processes_list


def parse_files(files_list: list) -> list:
    """
    This function gets a files list and retrives specific data from each file and builds a new list of the
    parsed file data.
    :param files_list: the raw file list
    :return: the parsed file list
    """
    parsed_files_list: list = []
    for file_object in files_list:
        file_new_object: dict = {
            'RawFullPath': file_object.get('rawFullPath'),
            'FileName': file_object.get('fileName'),
            'SHA256': file_object.get('sha256'),
            'FileSize': file_object.get('fileSize')
        }
        parsed_files_list.append(file_new_object)
    return parsed_files_list


def parse_users(users_list: list) -> list:
    """
    This function gets a users list and retrives specific data from each user and builds a new list of the
    parsed user data.
    :param users_list: the raw users list
    :return: the parsed users list
    """
    return [{'Username': user.get('userName')} for user in users_list]


def verify_table_fields(fields: str, table_fields: list) -> str:
    """
    This function check if the entered fields are valid (i.e. exists in the table fields) and returns them
    :param fields: string input of fields list (comma separated)
    :param table_fields: the fields list of the current table
    :return: the fields string
    """
    fields_list: list = argToList(fields, ',')
    parsed_fields: str = ''

    for raw_field in fields_list:

        field = raw_field
        if raw_field == 'all':
            # if fields=all than we don't need to continue
            return '*'
        if raw_field not in table_fields:
            raise DemistoException(f'{raw_field} is not a valid field of the query')
        if raw_field == 'from':
            # if field is from we need to wrap it with '' to prevent confusion of the SQL syntax
            field = "'from'"

        if not parsed_fields:
            # handle first field case
            parsed_fields += field
        else:
            parsed_fields += f',{field}'

    return parsed_fields


def build_where_clause(args: dict, table_args_dict: dict) -> str:
    """
    This function transforms the relevant entries of dict into the where part of a SQL query
    :param args: a dict
    :param table_args_dict: the dict of the transformed fields
    :return: a string represents the where part of a SQL query
    """
    where_clause: str = ''
    for key in args.keys():
        if key in table_args_dict.keys():
            if key == 'query':
                # if query arg is supplied than we just need to parse it and only it
                return args[key].strip()
            else:
                values_list: list = argToList(args[key])
                for raw_value in values_list:
                    for field in table_args_dict[key]:
                        value = raw_value
                        if key == 'url':
                            value = f'*{raw_value}*'
                        if not where_clause:
                            # the beginning of the where part should start without OR
                            where_clause += f"{field}'{value}'"
                        else:
                            where_clause += f" OR {field}'{value}'"
    return where_clause


def delete_empty_value_dict(raw_dict: dict):
    """
    This function filters all items of raw_dict that has empty value (e.g. null/none/''...)
    :param raw_dict: the dict to be filtered
    """
    parsed_dict = {key: value for key, value in raw_dict.items() if value}
    return parsed_dict if parsed_dict else None


def get_context_standards_outputs(results: list) -> dict:
    """
    This function gets a list of all results and retrives from it all needed data for Demisto's indicators, all by
    context standard outputs format.
    :param results: the raw data
    :return: a dict with all retrived data into the exact context locations of each indicator
    """
    endpoints: list = []
    hosts: list = []
    files: list = []
    processes: list = []
    ips: list = []
    domains: list = []
    outputs: dict = {}

    for result in results:

        subtype = result.get('subtype')
        message_data: dict = result.get('messageData', {})
        end_point_header: dict = result.get('endPointHeader', {})

        # Endpoint
        raw_endpoint_data = {
            'Hostname': end_point_header.get('deviceName'),
            'IPAddress': end_point_header.get('agentIp'),
            'Domain': end_point_header.get('deviceDomain'),
            'OSVersion': end_point_header.get('osVersion'),
            'OS': VALUE_TRANSFORM_DICT['traps']['endPointHeader']['osType'][end_point_header.get('osType')]
            if end_point_header.get('osType')
            and 1 <= end_point_header.get('osType')  # type: ignore
            <= len(VALUE_TRANSFORM_DICT['traps']['endPointHeader']['osType'])  # type: ignore
            else '',
            'ID': result.get('agentId')
        }
        endpoint_data = delete_empty_value_dict(raw_endpoint_data)
        if endpoint_data:
            endpoints.append(endpoint_data)
        if endpoints:
            outputs['Endpoint(val.IPAddress === obj.IPAddress)'] = endpoints

        # Host
        if endpoint_data:
            endpoint_data['IP'] = end_point_header.get('agentIp')
            del endpoint_data['IPAddress']
        endpoint_data = delete_empty_value_dict(raw_endpoint_data)
        if endpoint_data:
            hosts.append(endpoint_data)
        if hosts:
            outputs['Host(val.IP === obj.IP)'] = hosts

        # Domain
        domain_data = delete_empty_value_dict({'Name': result.get('url_domain')})
        if domain_data:
            domains.append(domain_data)
        if domains:
            outputs[outputPaths['domain']] = domains

        # IP
        ip_fields = ['src', 'dst', 'natsrc', 'natdst']
        for field in ip_fields:
            ip_data = delete_empty_value_dict({'Address': result.get(field)})
            if ip_data:
                ips.append(ip_data)
        if ips:
            outputs[outputPaths['ip']] = ips

        # File
        raw_files: list = message_data.get('files', [])
        if message_data:
            raw_file_data = {
                'Name': message_data.get('fileName'),
                'Type': message_data.get('type'),
                'Path': message_data.get('filePath'),
                'Size': message_data.get('fileSize'),
                'SHA256': message_data.get('sha256'),
                'DigitalSignature.Publisher': message_data.get('localAnalysisResult', {}).get('publishers')
            }
            file_data = delete_empty_value_dict(raw_file_data)
            if file_data:
                files.append(file_data)
        if subtype and subtype.lower() == 'wildfire':
            raw_file_data = {
                'SHA256': result.get('filedigest'),
                'Name': result.get('misc'),
                'Type': result.get('filetype')
            }
            file_data = delete_empty_value_dict(raw_file_data)
            if file_data:
                files.append(file_data)
        if raw_files:
            for raw_file in raw_files:
                raw_file_data = {
                    'Name': raw_file.get('fileName'),
                    'Path': raw_file.get('rawFullPath'),
                    'SHA256': raw_file.get('sha256'),
                    'Size': raw_file.get('fileSize'),
                    'DigitalSignature.Publisher': raw_file.get('signers'),
                    'Company': raw_file.get('companyName')
                }
                file_data = delete_empty_value_dict(raw_file_data)
                if file_data:
                    files.append(file_data)
        if files:
            outputs[outputPaths['file']] = files

        # Process
        raw_processes: list = message_data.get('processes', [])
        source_process: dict = message_data.get('sourceProcess', {})
        if message_data and source_process:
            raw_process_data = {
                'PID': source_process.get('pid'),
                'Parent': source_process.get('parentId'),
                'SHA256': source_process.get('sha256'),
                'Name': source_process.get('fileName'),
                'Path': source_process.get('rawFullPath'),
                'CommandLine': source_process.get('commandLine')
            }
            process_data = delete_empty_value_dict(raw_process_data)
            if process_data:
                processes.append(process_data)
        if message_data and raw_processes:
            for raw_process in raw_processes:
                raw_process_data = {
                    'PID': raw_process.get('pid'),
                    'Parent': raw_process.get('parentId'),
                    'CommandLine': raw_process.get('commandLine'),
                }
                process_data = delete_empty_value_dict(raw_process_data)
                if process_data:
                    processes.append(process_data)
        if processes:
            outputs['Process(val.PID === obj.PID)'] = processes

    return outputs


def get_encrypted(auth_id: str, key: str) -> str:
    """

    Args:
        auth_id (str): auth_id from Demistobot
        key (str): key from Demistobot

    Returns:

    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = enc_key.encode()
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = epoch_seconds()
    return encrypt(f'{now}:{auth_id}', key).decode('utf-8')


def prepare_fetch_query(fetch_timestamp):
    query = FETCH_QUERY_DICT[demisto.params().get('fetch_query', 'Traps Threats')]
    if 'tms' in query:
        query += f" WHERE serverTime>'{fetch_timestamp}'"
        FETCH_SEVERITY = demisto.params().get('traps_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"messageData.trapsSeverity='{severity}'"
                else:
                    query += f"messageData.trapsSeverity='{severity}' OR "
            query += ')'
    if 'panw' in query:
        query += f' WHERE receive_time>{fetch_timestamp}'
        FETCH_SEVERITY = demisto.params().get('firewall_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        FETCH_SUBTYPE = demisto.params().get('firewall_subtype')
        if not FETCH_SUBTYPE:
            FETCH_SUBTYPE = ['all']
        if 'all' not in FETCH_SUBTYPE:
            query += ' AND ('
            for index, subtype in enumerate(FETCH_SUBTYPE):
                if index == (len(FETCH_SUBTYPE) - 1):
                    query += f"subtype='{subtype}'"
                else:
                    query += f"subtype='{subtype}' OR "
            query += ')'
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"severity='{severity}'"
                else:
                    query += f"severity='{severity}' OR "
            query += ')'
    if 'magnifier' in query:
        query += f' WHERE time_generated>{fetch_timestamp}'
        FETCH_SEVERITY = demisto.params().get('xdr_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        FETCH_CATEGORY = demisto.params().get('xdr_category')
        if not FETCH_CATEGORY:
            FETCH_CATEGORY = ['all']
        if 'all' not in FETCH_CATEGORY:
            query += ' AND ('
            for index, subtype in enumerate(FETCH_CATEGORY):
                if index == (len(FETCH_CATEGORY) - 1):
                    query += f"alert.category.keyword='{subtype}'"
                else:
                    query += f"alert.category.keyword='{subtype}' OR "
            query += ')'
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"alert.severity.keyword='{severity}'"
                else:
                    query += f"alert.severity.keyword='{severity}' OR "
            query += ')'
        # Only get new Alerts
        query += ' AND sub_type.keyword = \'New\''
    return query


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.

    parameter: (date) d
        The date to convert to seconds

    returns:
        The date in seconds
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    stored = integration_context.get('stored')
    if access_token and stored:
        if epoch_seconds() - stored < 60 * 60 - 30:
            return access_token
    headers = {
        'Authorization': AUTH_ID,
        'Accept': 'application/json'
    }

    dbot_response = requests.get(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        params={'token': get_encrypted(TOKEN, ENC_KEY)},
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response: [{}]. Exception: {}'.format(err_response.content, ex))
        raise Exception(msg)
    try:
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    api_url = parsed_response.get('url')
    token = parsed_response.get('token')

    demisto.setIntegrationContext({
        'access_token': access_token,
        'stored': epoch_seconds(),
        'api_url': api_url,
        'token': token
    })
    return access_token


def initial_logging_service():
    api_url = demisto.getIntegrationContext().get('api_url', 'https://api.us.paloaltonetworks.com')
    credentials = Credentials(
        access_token=get_access_token(),
        verify=USE_SSL
    )
    logging_service = LoggingService(
        url=api_url,
        credentials=credentials
    )

    return logging_service


def poll_query_result(query_id):
    logging_service = initial_logging_service()

    poll_params = {  # Prepare 'poll' params
        "maxWaitTime": 30000  # waiting for response up to 3000ms
    }

    # we poll the logging service until we have a complete response
    response = logging_service.poll(query_id, 0, poll_params)

    return response


def query_loggings(query_data):
    """
    This function handles all the querying of Cortex Logging service
    """

    logging_service = initial_logging_service()

    response = logging_service.query(query_data)
    query_result = response.json()

    if not response.ok:
        status_code = query_result.get('statusCode', '')
        error = query_result.get('error', '')
        message = query_result.get('payload', {}).get('message', '')
        raise Exception(f"Error in query to Cortex [{status_code}] - {error}: {message}")

    try:
        query_id = query_result['queryId']  # access 'queryId' from 'query' response
    except Exception as e:
        raise Exception('Received error %s when querying logs.' % e)

    poll_response = poll_query_result(query_id)
    return poll_response


def transform_row_keys(row):
    transformed_row = {}
    for metric, value in row.items():
        if metric == 'filedigest':
            transformed_row['SHA256'] = value
        elif metric == 'misc':
            transformed_row['filename'] = value
        elif metric == 'category' and str(value) == '1':
            transformed_row['category'] = 'malicious'
        else:
            transformed_row[metric] = value
    return transformed_row


def results_screener(table_name, full_results):
    """
    This function is used to make sure we include only pre-defined metrics in the human readable
    """
    screened_results = []

    if table_name == "traffic":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in TRAFFIC_TABLE_HEADERS}
            screened_results.append(screened_row)
    elif table_name == "threat":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in THREAT_TABLE_HEADERS}
            screened_results.append(screened_row)
    elif table_name == "common":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in COMMON_HEADERS}
            screened_results.append(screened_row)
    else:
        return full_results

    return screened_results


def get_start_time(date_type, time_value):
    current_date = datetime.now()
    if date_type == 'minutes':
        return current_date - timedelta(minutes=time_value)
    elif date_type == 'days':
        return current_date - timedelta(days=time_value)
    elif date_type == 'weeks':
        return current_date - timedelta(weeks=time_value)


def convert_log_to_incident(log):
    log_contents = log.get('_source')
    if log_contents.get('id'):
        log_contents['xdr_id'] = log_contents.get('id')  # XDR ID before it is overwritten
    log_contents['id'] = log.get('_id')
    log_contents['score'] = log.get('_score')
    if 'Traps' in FETCH_QUERY:  # type: ignore
        occurred = log_contents.get('generatedTime')
        time_received = log_contents.get('serverTime')
    elif 'Firewall' in FETCH_QUERY:  # type: ignore
        time_generated = log_contents.get('time_generated')
        occurred = datetime.utcfromtimestamp(time_generated).isoformat() + 'Z'
        time_received = log_contents.get('receive_time')
    elif 'XDR' in FETCH_QUERY:  # type: ignore
        # first_detected_at in alert.schedule can be present or not, can be in s or ms
        # if not detected, fallback to time_generated
        try:
            time_received = int(log_contents.get('time_generated')) or 0
        except ValueError:
            time_received = 0

        occurred_raw = 0
        first_detected_at = None
        try:
            first_detected_at = str(log_contents.get('alert', {}).get('schedule', {}).get('first_detected_at'))
        except AttributeError:
            first_detected_at = None
        if first_detected_at is not None:
            if len(first_detected_at) == 13:  # ms
                occurred_raw = int(float(first_detected_at) / 1000)
            elif len(first_detected_at) == 10:  # s
                occurred_raw = int(first_detected_at)
            else:  # unknown length, fallback to time_received
                occurred_raw = int(time_received)
        else:  # not present, fallback to time_received
            occurred_raw = int(time_received)
        occurred = datetime.utcfromtimestamp(occurred_raw).isoformat() + 'Z'

    # stringifying dictionary values for fetching. (json.dumps() doesn't stringify dictionary values)
    event_id = log.get('_id', '')
    incident = {
        'name': 'Cortex Event ' + event_id,
        'rawJSON': json.dumps(log_contents, ensure_ascii=False),
        'occurred': occurred
    }
    return incident, time_received


''' COMMANDS FUNCTIONS '''


def test_module():
    if demisto.params().get('isFetch'):
        last_fetched_event_timestamp, _ = parse_date_range(FIRST_FETCH_TIMESTAMP)
    test_args = {
        'query': f'{FETCH_QUERY_DICT[FETCH_QUERY]} LIMIT 1',
        'startTime': 0,
        'endTime': 1609459200,
    }
    query_loggings(test_args)
    demisto.results('ok')


def query_logs_command():
    """
    Return the result of querying the Logging service
    """
    args = demisto.args()
    start_time = args.get('startTime')
    end_time = args.get('endTime')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        time_format = '%Y-%m-%d %H:%M:%S'
        # Thu Jan 01 02:00:00 IST 1970' does not match format '%Y-%m-%d %H:%M:%S'
        service_start_date = datetime.strptime(start_time, time_format)
        service_end_date = datetime.strptime(end_time, time_format)

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime('%s'))
    service_end_date_epoch = int(service_end_date.strftime('%s'))

    query = args.get('query')

    if 'limit' not in query.lower():
        query += ' LIMIT 100'

    query_data = {
        "query": query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        response_json = response.json()
        query_status = response_json.get('queryStatus', '')
        if query_status in {'RUNNING', 'JOB_FAILED'}:
            raise Exception(f'Logging query job failed with status: {query_status}')
        result = response_json.get('result', {})
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('common', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id === obj.id)': output
        }
    }

    return entry


def get_critical_logs_command():
    """
    Queries Cortex Logging according to a pre-set query
    """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.threat WHERE severity = '5' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('threat', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id === obj.id)': output
        }
    }
    return entry


def get_social_applications_command():
    """ Queries Cortex Logging according to a pre-set query """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.traffic WHERE subcategory-of-app = 'social-networking' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('traffic', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id === obj.id)': output
        }
    }
    return entry


def search_by_file_hash_command():
    """
    Queries Cortex Logging according to a pre-set query
    """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')
    filehash = args.get('SHA256')

    if (time_range):
        if (time_value):
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Please enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.threat WHERE filedigest='" + filehash + "' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('threat', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id === obj.id)': output
        }
    }
    return entry


def query_traffic_logs_command():
    """
    The function of the command that queries panw.traffic table
    :return: a Demisto's entry with all the parsed data
    """
    table_fields: list = TRAFFIC_FIELDS
    table_args: dict = PANW_ARGS_DICT
    query_table_name: str = 'panw.traffic'
    context_transformer_function = traffic_context_transformer
    table_context_path: str = 'Cortex.Logging.Traffic(val.id === obj.id)'
    return query_table_logs(table_fields, table_args, query_table_name, context_transformer_function,
                            table_context_path)


def query_threat_logs_command():
    """
    The function of the command that queries panw.threat table
    :return: a Demisto's entry with all the parsed data
    """
    table_fields: list = THREAT_FIELDS
    table_args: dict = PANW_ARGS_DICT
    query_table_name: str = 'panw.threat'
    context_transformer_function = threat_context_transformer
    table_context_path: str = 'Cortex.Logging.Threat(val.id === obj.id)'
    return query_table_logs(table_fields, table_args, query_table_name, context_transformer_function,
                            table_context_path)


def query_traps_logs_command():
    """
    The function of the command that queries tms.threat table
    :return: a Demisto's entry with all the parsed data
    """
    table_fields: list = TRAPS_FIELDS
    table_args: dict = TRAPS_ARGS_DICT
    query_table_name: str = 'tms.threat'
    context_transformer_function = traps_context_transformer
    table_context_path: str = 'Cortex.Logging.Traps(val.id === obj.id)'
    return query_table_logs(table_fields, table_args, query_table_name, context_transformer_function,
                            table_context_path)


def query_analytics_logs_command():
    """
    The function of the command that queries tms.analytics table
    :return: a Demisto's entry with all the parsed data
    """
    table_fields: list = ANALYTICS_FIELDS
    table_args: dict = ANALYTICS_ARGS_DICT
    query_table_name: str = 'tms.analytics'
    context_transformer_function = analytics_context_transformer
    table_context_path: str = 'Cortex.Logging.Analytics(val.id === obj.id)'
    return query_table_logs(table_fields, table_args, query_table_name, context_transformer_function,
                            table_context_path)


def query_table_logs(table_fields: list, table_args: dict, query_table_name: str, context_transformer_function,
                     table_context_path: str):
    """
    This function is a generic function that get's all the data needed for a specific table of Cortex and acts as a
    regular command function
    :param table_fields: the fields of the table named query_table_name (fields that can be selected in a query)
    :param table_args: all the args of the table that can be queried
    :param query_table_name: the name of the table in Cortex
    :param context_transformer_function: the context transformer function to parse the data
    :param table_context_path: the context path where the parsed data should be located
    :return: the function return's a Demisto's entry
    """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    limit = args.get('limit', '5')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise DemistoException('Enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object - using dateutil.parser.parse
        service_start_date = parse(start_time)
        service_end_date = parse(end_time)

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.timestamp())
    service_end_date_epoch = int(service_end_date.timestamp())

    unverified_fields = args.get('fields', 'all')
    fields = verify_table_fields(unverified_fields, table_fields)

    where = build_where_clause(args, table_args)

    if where:
        query = f'SELECT {fields} FROM {query_table_name} WHERE {where} LIMIT {limit}'
    else:
        query = f'SELECT {fields} FROM {query_table_name} LIMIT {limit}'

    query_data = {
        'query': query,
        'startTime': service_start_date_epoch,
        'endTime': service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        response_json = response.json()
        query_status = response_json.get('queryStatus', '')
        if query_status in {'RUNNING', 'JOB_FAILED'}:
            raise DemistoException(f'Logging query job failed with status: {query_status}')
        result = response_json.get('result', {})
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1] if query_table_name != 'tms.threat' else 'traps'
    except ValueError:
        raise DemistoException('Failed to parse the response from Cortex')

    outputs: list = []
    results: list = []

    for page in pages:
        row_contents = page.get('_source')
        results.append(row_contents)
        transformed_row = context_transformer_function(row_contents)
        transformed_row['id'] = page.get('_id')
        transformed_row['score'] = page.get('_score')
        transformed_row = {key: value for key, value in transformed_row.items() if value}
        outputs.append(transformed_row)

    human_readable = logs_human_readable_output_generator(fields, table_name, results)

    context_standards_outputs: dict = get_context_standards_outputs(results)
    context_outputs: dict = {table_context_path: outputs}
    # merge the two dicts into one dict that outputs to context
    context_outputs.update(context_standards_outputs)

    try:
        contents = response.json()
    except ValueError as e:
        raise DemistoException(str(e))

    entry = {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context_outputs
    }
    return entry if pages else 'No logs found.'


def process_incident_pairs(incident_pairs, max_incidents):
    sorted_pairs = sorted(incident_pairs, key=lambda x: x[1])
    sorted_pairs = sorted_pairs[:max_incidents]
    max_timestamp = sorted_pairs[-1][1]
    return list(map(lambda x: x[0], sorted_pairs)), max_timestamp


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetched_event_timestamp = last_run.get('last_fetched_event_timestamp')
    last_query_id = last_run.get('last_query_id')

    if last_query_id:
        # Need to poll query results fron last run
        response = poll_query_result(last_query_id)
    else:
        if last_fetched_event_timestamp is not None:
            last_fetched_event_timestamp = datetime.strptime(last_fetched_event_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
        else:
            last_fetched_event_timestamp, _ = parse_date_range(FIRST_FETCH_TIMESTAMP)

        # Need sometime in the future, so the timestamp will be taken from the query
        service_end_date_epoch = int(datetime.now().strftime('%s')) + 1000

        if 'Firewall' in FETCH_QUERY or 'XDR' in FETCH_QUERY:  # type: ignore
            fetch_timestamp = int(last_fetched_event_timestamp.strftime('%s'))
        elif 'Traps' in FETCH_QUERY:  # type: ignore
            fetch_timestamp = last_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        query = prepare_fetch_query(fetch_timestamp)
        demisto.debug('Query being fetched: {}'.format(query))

        query_data = {
            'query': query,
            'startTime': 0,
            'endTime': service_end_date_epoch,
        }

        response = query_loggings(query_data)

    try:
        response_json = response.json()
        query_status = response_json.get('queryStatus', '')
        if query_status == 'JOB_FAILED':
            demisto.debug(f'Logging query job failed with status: JOB_FAILED\nResponse: {response.text}')
        elif query_status == 'RUNNING':
            if isinstance(last_fetched_event_timestamp, datetime):
                # In case we don't have query ID from previous run
                last_fetched_event_timestamp = last_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')
            # If query job is still running after 30 seconds (max timeout), pass it to next run
            demisto.setLastRun({
                'last_fetched_event_timestamp': last_fetched_event_timestamp,
                'last_query_id': response_json.get('queryId', '')
            })
            demisto.incidents([])
            return
        result = response_json.get('result', {})
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
    except ValueError:
        demisto.debug('Failed to parse the response from Cortex')

    incident_pairs = []

    max_fetched_event_timestamp = last_fetched_event_timestamp
    for page in pages:
        incident, time_received = convert_log_to_incident(page)
        if 'Firewall' in FETCH_QUERY or 'XDR' in FETCH_QUERY:  # type: ignore
            time_received_dt = datetime.fromtimestamp(time_received)
        elif 'Traps' in FETCH_QUERY:  # type: ignore
            time_received_dt = datetime.strptime(time_received, '%Y-%m-%dT%H:%M:%S.%fZ')
        incident_pairs.append((incident, time_received_dt))
    if incident_pairs:
        incidents, max_fetched_event_timestamp = process_incident_pairs(incident_pairs, 100)  # max 100 per run
        demisto.setLastRun({
            'last_fetched_event_timestamp': max_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')
        })
        demisto.incidents(incidents)
    else:
        demisto.incidents([])


''' EXECUTION CODE '''


def main():
    global FETCH_QUERY
    FETCH_QUERY = demisto.params().get('fetch_query', 'Traps Threats')

    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'cortex-query-logs':
            demisto.results(query_logs_command())
        elif demisto.command() == 'cortex-get-critical-threat-logs':
            demisto.results(get_critical_logs_command())
        elif demisto.command() == 'cortex-get-social-applications':
            demisto.results(get_social_applications_command())
        elif demisto.command() == 'cortex-search-by-file-hash':
            demisto.results(search_by_file_hash_command())
        elif demisto.command() == 'cortex-query-traffic-logs':
            demisto.results(query_traffic_logs_command())
        elif demisto.command() == 'cortex-query-threat-logs':
            demisto.results(query_threat_logs_command())
        elif demisto.command() == 'cortex-query-traps-logs':
            demisto.results(query_traps_logs_command())
        elif demisto.command() == 'cortex-query-analytics-logs':
            demisto.results(query_analytics_logs_command())
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
    except Exception as e:
        error_message = str(e)
        if demisto.command() == 'fetch-incidents':
            LOG(error_message)
            LOG.print_log()
            raise
        else:
            return_error(error_message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
