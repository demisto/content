from CommonServerPython import *
import json
import requests
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

'''Constants'''
CATEGORY = 'alarm'  # only focus on alarms

AUTH_SERVER = demisto.getParam('auth_url')
AUTH_URL = AUTH_SERVER + '/as/token.oauth2'
ARC_URL = demisto.getParam('arc_url')
ARC_URL += '/rest/1.0'

CLIENT_ID = demisto.getParam('client_id')
CLIENT_SECRET = demisto.getParam('client_secret')
VERIFY_CERT = not demisto.params().get('insecure', False)
AUTH_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
CLIENT_HEADERS = {'Authorization': ''}
PROXY = demisto.getParam('proxy')


def request_api_token():
    """
    Request an API token from the authentication server.
    Token is injected into global CLIENT_HEADERS.
    """
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials',
        'scope': 'client'
    }

    r = requests.post(url=AUTH_URL, headers=AUTH_HEADERS, data=payload, verify=VERIFY_CERT)
    response_json = r.json()
    if 200 <= r.status_code <= 299:
        api_key = response_json.get('access_token')
        CLIENT_HEADERS['Authorization'] = 'Bearer ' + api_key
    else:
        return_error(f'Error in request_api_token [{r.status_code}] - {r.reason}')


def test_module():
    """
    Performs basic get request to get item samples
    """
    r = requests.get(url=ARC_URL + '/watchlists', headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    try:
        _ = r.json() if r.text else {}
        if not r.ok:
            return_error(f'Cannot connect to ARC, Response {r.status_code}: {r.text}')
        demisto.results('ok')
    except TypeError as ex:
        return_error(str(ex))


def get_watchlist_id(watchlist_name: str) -> str:
    """
    Get the watchlist id by watchlist name.
    :param watchlist_name:
    :return: watchlist id
    """
    full_url = ARC_URL + '/watchlists/'
    r = requests.get(url=full_url, headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    json_text = json.loads(r.text)
    list_id = None
    if 200 <= r.status_code <= 299:
        for item in json_text:
            if item.get('display_name', '').lower() == watchlist_name.lower():
                list_id = item.get('name')
    else:
        return_error(f'Error retrieving watchlist_id for {watchlist_name}, {r.status_code}: {r.text}')

    if not list_id:
        return_error(f'Unable to find watchlist_id for {watchlist_name}')

    return str(list_id)


def get_list_id(list_name: str, list_type: str) -> str:
    """
    Get List ID by name and type
    """
    full_url = ARC_URL + '/lists/' + list_type
    r = requests.get(url=full_url, headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    json_text = json.loads(r.text)
    list_id = None
    if 200 <= r.status_code <= 299:
        for jText in json_text:
            if str(jText.get('name', '')).lower() == list_name.lower():
                list_id = jText.get('id')
    else:
        return_error(f'Error retrieving list_id for {list_name}, {r.status_code}: {r.text}')

    if not list_id:
        return_error(f'List id not found for name {list_name} and type {list_type}')

    return str(list_id)


def get_watchlist_entry_id(watchlist_name: str, watchlist_entry: str) -> str:
    """
    Get watchlist entry id by list name and entry

    :param watchlist_name:
    :param watchlist_entry:

    :return: ID of watchlist entry
    """
    if watchlist_name is None or watchlist_entry is None:
        return_error('Please provide both watchlist_name and watchlist_entry')

    watchlist_entry_id = None
    watchlist_id = get_watchlist_id(watchlist_name)

    if watchlist_id:
        full_url = ARC_URL + '/watchlists/'
        r = requests.get(url=full_url + watchlist_id + '/values?limit=100000', headers=CLIENT_HEADERS,
                         verify=VERIFY_CERT)
        json_text = json.loads(r.text)
        if r.status_code != requests.codes.ok:
            return_error('Unable to retrieve watchlist entries')
        for jText in json_text:
            if str(jText.get('value_name', '')).lower() == watchlist_entry.lower():
                watchlist_entry_id = jText.get('value_id')

    return str(watchlist_entry_id)


def add_entry_to_componentlist():
    """
    Add componentlist_entry to component list identified by componentlist_name
    """
    componentlist_name = demisto.args().get('componentlist_name', None)
    componentlist_entry = demisto.args().get('componentlist_entry', None)

    if componentlist_name is None or componentlist_entry is None:
        return_error('Please provide both componentlist_name and componentlist_entry')
    else:
        list_id = get_list_id(componentlist_name, 'component_list')
        CLIENT_HEADERS['Content-Type'] = 'application/json'
        if list_id:
            full_url = ARC_URL + '/remediation/lists/'
            list_entry_json = '{"items":["' + componentlist_entry + '"]}'
            r = requests.put(url=full_url + list_id + '/append', headers=CLIENT_HEADERS, data=list_entry_json,
                             verify=VERIFY_CERT)
            if 200 <= r.status_code <= 299:
                demisto.results('added componentlist entry ({}) to componentlist name ({})'.format(componentlist_entry,
                                                                                                   componentlist_name))
            else:
                return_error(
                    'Failed to add componentlist entry({}) to componentlist name ({}). The response failed with status '
                    'code {}. The '
                    'response was: {}'.format(componentlist_entry, componentlist_name, r.status_code, r.text))
        else:
            return_error('Failed to find componentlist name ({})').format(componentlist_name)


def check_componentlist_entry():
    """
    Does the componentlist_entry exist in the component list identified by componentlist_name

    Sets DigitalGuardian.Componentlist.Found flag.
    """
    componentlist_name = demisto.args().get('componentlist_name', '')
    componentlist_entry = demisto.args().get('componentlist_entry', '')
    if not componentlist_name or not componentlist_entry:
        return_error('Please provide both componentlist_name and componentlist_entry')

    componentlist = None
    list_id = get_list_id(componentlist_name, 'component_list')
    if list_id:
        full_url = ARC_URL + '/lists/'
        r = requests.get(url=full_url + list_id + '/values?limit=100000', headers=CLIENT_HEADERS, verify=VERIFY_CERT)
        json_text = json.loads(r.text)

        if 200 <= r.status_code <= 299:
            for jText in json_text:
                if str(jText.get('content_value', '')).lower() == componentlist_entry.lower():
                    componentlist = jText.get('content_value')
        else:
            return_error(f'Unable to find componentlist named {componentlist_name}, {r.status_code}')

    if componentlist:
        return_outputs(readable_output='Componentlist found', outputs={
            'DigitalGuardian.Componentlist.Found': True}, raw_response='Componentlist entry not found')
    else:
        return_outputs(readable_output='Componentlist not found', outputs={
            'DigitalGuardian.Componentlist.Found': False}, raw_response='Componentlist entry not found')


def rm_entry_from_componentlist():
    """
    Remove entry from component list
    """
    componentlist_name = demisto.args().get('componentlist_name', None)
    componentlist_entry = demisto.args().get('componentlist_entry', None)
    if componentlist_name is None or componentlist_entry is None:
        return_error('Please provide either componentlist_name and componentlist_entry')

    list_id = get_list_id(componentlist_name, 'component_list')
    full_url = ARC_URL + '/remediation/lists/'
    CLIENT_HEADERS['Content-Type'] = 'application/json'
    list_entry_json = '{"items":["' + componentlist_entry + '"]}'
    r = requests.post(url=full_url + list_id + '/delete', headers=CLIENT_HEADERS, data=list_entry_json,
                      verify=VERIFY_CERT)
    if 200 <= r.status_code <= 299:
        demisto.results('removed componentlist entry ({}) from componentlist name ({})'.format(componentlist_entry,
                                                                                               componentlist_name))
    else:
        return_error(
            'Failed to remove componentlist entry({}) from componentlist name ({}). The response failed with '
            'status code {}. The response was: {}'.format(componentlist_entry, componentlist_name, r.status_code,
                                                          r.text))


def add_entry_to_watchlist():
    """
    Add watchlist_entry to watchlist_name
    """
    watchlist_name = demisto.args().get('watchlist_name', None)
    watchlist_entry = demisto.args().get('watchlist_entry', None)
    if watchlist_name is None or watchlist_entry is None:
        return_error('Please provide both watchlist_name and watchlist_entry')

    watchlist_id = get_watchlist_id(watchlist_name)
    watchlist_entry_json = '[{"value_name":"' + watchlist_entry + '"}]'
    full_url = ARC_URL + '/watchlists/'
    r = requests.post(url=full_url + watchlist_id + '/values/', data=watchlist_entry_json,
                      headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    if 200 <= r.status_code <= 299:
        demisto.results(f'added watchlist entry ({watchlist_entry}) to watchlist name ({watchlist_name})')
    else:
        return_error(
            'Failed to add watchlist entry({}) to watchlist name ({}). The response failed with status code {}. '
            'The response was: {}'.format(watchlist_entry, watchlist_name, r.status_code, r.text))


def check_watchlist_entry():
    """
    Does the watchlist_entry exist in the watchlist identified by watchlist_name?

    Sets DigitalGuardian.Watchlist.Found flag
    """
    watchlist_name = demisto.args().get('watchlist_name', None)
    watchlist_entry = demisto.args().get('watchlist_entry', None)
    if watchlist_name is None or watchlist_entry is None:
        return_error('Please provide both watchlist_name and watchlist_entry')

    watchlist_entry_id = get_watchlist_entry_id(watchlist_name, watchlist_entry)

    if watchlist_entry_id:
        return_outputs(readable_output='Watchlist found', outputs={'DigitalGuardian.Watchlist.Found': True},
                       raw_response='Watchlist found')
    else:
        return_outputs(readable_output='Watchlist not found', outputs={
            'DigitalGuardian.Watchlist.Found': False}, raw_response='Watchlist not found')


def rm_entry_from_watchlist():
    """
    Remove watchlist_entry from watchlist identified by watchlist_name
    """
    watchlist_name = demisto.args().get('watchlist_name', None)
    watchlist_entry = demisto.args().get('watchlist_entry', None)
    if watchlist_name is None or watchlist_entry is None:
        return_error('Please provide both watchlist_name and watchlist_entry')
    watchlist_id = get_watchlist_id(watchlist_name)
    watchlist_entry_id = get_watchlist_entry_id(watchlist_name, watchlist_entry)
    demisto.debug('wli= ' + str(watchlist_entry_id) + ' wld=' + str(watchlist_id))
    full_url = ARC_URL + '/watchlists/'
    r = requests.delete(url=full_url + watchlist_id + '/values/' + watchlist_entry_id,
                        headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    if 200 <= r.status_code <= 299:
        demisto.results(
            f'removed watchlist entry ({watchlist_entry}) from watchlist name ({watchlist_name})')
    else:
        return_error(
            'Failed to remove watchlist entry({}) from watchlist name ({}). The response failed with status code {}. '
            'The response was: {}'.format(watchlist_entry, watchlist_name, r.status_code, r.text))


def get_items_request():
    """
    Request data from export profile.
    """
    incident_list = []
    oldname = ''

    export_profile = demisto.params().get('export_profile', None)

    if export_profile is None:
        return_error('Export Profile parameter is required')

    full_url = ARC_URL + '/export_profiles/' + export_profile + '/export_and_ack'
    r = requests.post(url=full_url, headers=CLIENT_HEADERS, verify=VERIFY_CERT)
    json_text = json.loads(r.text)

    if r.status_code == 200:
        header_field = []

        for field in json_text.get('fields'):
            header_field.append(field.get('name'))
        exportdata = []
        if json_text.get('total_hits') == 0:
            DEBUG('found no data')
            return None
        else:
            DEBUG('found data')

            for data in json_text.get('data'):
                entry_line = {}
                header_position = 0

                for dataValue in data:
                    entry_line[header_field[header_position]] = dataValue
                    header_position += 1
                exportdata.append(entry_line)

            for items in exportdata:
                if items.get('dg_alert.dg_detection_source') != 'alert' and items.get('dg_tags'):
                    comm = items.get('dg_alarm_name', "").find(',')
                    if comm == -1:
                        comm = 100
                    name = '{alarm_name}-{id}'.format(alarm_name=items.get('dg_alarm_name', "")[0:comm], id=items.get('dg_guid'))
                    DEBUG(name + " != " + oldname)
                    if name != oldname:
                        DEBUG("create_artifacts...")
                        artifacts_creation_msg = create_artifacts(alert=items)
                        if artifacts_creation_msg:
                            incident_list.append(artifacts_creation_msg)
                        oldname = name
            return incident_list
    else:
        return_error('DigitalGuardian ARC Export Failed '
                     'Please check authentication related parameters. ' + json.dumps(r.json(), indent=4,
                                                                                     sort_keys=True))
        return None


def convert_to_demisto_severity(dg_severity: str) -> int:
    """
    Convert dg_severity to demisto severity

    :param dg_severity:
    :return: int demisto severity
    """

    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
    }

    return severity_map.get(dg_severity, 1)


def convert_to_demisto_class(was_classified: str) -> int:
    """
    Convert was_classified to demisto classification
    :param was_classified:
    :return:
    """
    if was_classified == 'Yes':
        demisto_class = 1
    else:
        demisto_class = 0
    return demisto_class


def convert_to_demisto_sensitivity(dg_classification: str) -> str:
    """
    Convert dg_classification to demisto sensitivity
    :param dg_classification:
    :return:
    """
    demisto_sensitivity = 'none'

    if dg_classification:
        if dg_classification[-3:] == 'ext':
            demisto_sensitivity = 'Critical'
        elif dg_classification[-3:] == 'IGH':
            demisto_sensitivity = 'High'
        elif dg_classification[-3:] == 'MED':
            demisto_sensitivity = 'Medium'
        elif dg_classification[-3:] == 'LOW':
            demisto_sensitivity = 'Low'

    return demisto_sensitivity


def DEBUG(msg: str):
    demisto.debug("-----=====***** " + msg + " *****=====-----")


def create_artifacts(alert):
    """
    Create artifacts
    :param alert:
    :return:
    """
    artifacts_list = {}
    specific_alert_mapping = {
        'alarm': {
            'Alarm_Name': ('dg_alarm_name', []),
            'Alarm_Severity': ('dg_alarm_sev', []),
            'Threat_Type': ('dg_tags', []),
            'Detection_Name': ('dg_det_name', []),
            'Alert_Category': ('dg_alert.dg_category_name', []),
            'Policy_Name': ('dg_alert.dg_alert.dg_alert.dg_policy.dg_name', []),
            'Action_Was_Blocked': ('dg_alert.dg_hc', []),
            'File_Name': ('dg_src_file_name', ['fileName']),
            'File_Size': ('dg_alert.dg_total_size', ['fileSize']),
            'File_Was_Classified': ('dg_hc', []),
            'Classification': ('dg_class.dg_name', []),
            'File_Type': ('dg_src_file_ext', []),
            'File_Path': ('dg_alert.uad_sp', []),
            'Destination_File_Path': ('dg_alert.uad_dp', []),
            'Process_Name': ('dg_proc_file_name', []),
            'Parent_Process_Name': ('dg_parent_name', []),
            'Process_Path': ('pi_fp', []),
            'Command_Line': ('pi_cmdln', []),
            'MD5': ('dg_md5', ['filehash']),
            'SHA1': ('dg_sha1', ['filehash']),
            'SHA256': ('dg_sha256', ['filehash']),
            'VirusTotal_Status': ('dg_vt_status', []),
            'Attachment_File_Name': ('dg_attachments.dg_src_file_name', []),
            'Attachment_Was_Classified': ('dg_attachments.uad_sfc', []),
            'Email_Subject': ('ua_msb', []),
            'Email_Sender': ('ua_ms', []),
            'Email_Recipient': ('dg_recipients.uad_mr', []),
            'Email_Recipient_Domain': ('dg_recipients.dg_rec_email_domain', []),
            'Destination_Address': ('ua_ra', []),
            'Request_URL': ('ua_up', []),
            'Destination_DNS_Domain': ('ua_hn', []),
            'Remote_Port': ('ua_rp', []),
            'Computer_Name': ('dg_machine_name', []),
            'Computer_Type': ('dg_machine_type', []),
            'Source_Host_Name': ('dg_shn', []),
            'Source_IP': ('ua_sa', []),
            'Source_Address': ('ua_sa', []),
            'User_Name': ('dg_user', []),
            'NTDomain': ('ua_dn', []),
            'dgarcUID': ('dg_guid', []),
            'dg_process_time': ('dg_process_time', []),
            'Activity': ('dg_utype', []),
            'os_version': ('os_version', []),
            'Policy': ('dg_alert.dg_policy.dg_name', []),
            'Printer_Name': ('uad_pn', []),
            'os': ('os', []),
            'browser': ('browser', []),
            'App_Category': ('appcategory', []),
        }
    }

    DEBUG("before alert")
    DEBUG(json.dumps(alert))
    if CATEGORY in specific_alert_mapping:
        temp_dict: dict[str | Any, str | int | Any] = {}
        cef: dict[str | Any, str | int | Any] = {}
        cef_types = {}
        cef['Vendor ID'] = 'DG'
        cef['Vendor Product'] = 'Digital Guardian'
        cef['severity'] = convert_to_demisto_severity(alert.get('dg_alarm_sev'))
        cef['sensitivity'] = convert_to_demisto_sensitivity(alert.get('dg_class.dg_name'))

        DEBUG("cef: " + json.dumps(cef))
        for artifact_key, artifact_tuple in specific_alert_mapping.get(CATEGORY).items():  # type: ignore
            if alert.get(artifact_tuple[0]):
                cef[artifact_key] = alert[artifact_tuple[0]]
                cef_types[artifact_key] = artifact_tuple[1]
        if cef:
            comm = alert.get('dg_alarm_name', '').find(',')
            if comm == -1:
                comm = 100
            name = '{alarm_name}-{id}'.format(alarm_name=alert.get('dg_alarm_name')[0:comm], id=alert.get('dg_guid'))
            temp_dict['name'] = name
            temp_dict['severity'] = convert_to_demisto_severity(alert.get('dg_alarm_sev'))
            temp_dict['type'] = alert.get('dg_tags')
            temp_dict['occurred'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            temp_dict['rawJSON'] = json.dumps(cef)
            artifacts_list.update(temp_dict)
    return artifacts_list


def fetch_incidents():
    """
    Fetch incidents from the ARC
    :return:
    """
    incidents = []  # type: List
    demisto.debug(incidents)
    incidents = get_items_request()
    DEBUG('fetching incidents')
    demisto.debug(incidents)
    demisto.incidents(incidents)


def main():
    """
    Main
    """

    commands = {
        'test-module': test_module,

        'fetch-incidents': fetch_incidents,

        'digitalguardian-add-watchlist-entry': add_entry_to_watchlist,
        'digitalguardian-check-watchlist-entry': check_watchlist_entry,
        'digitalguardian-remove-watchlist-entry': rm_entry_from_watchlist,

        'digitalguardian-add-componentlist-entry': add_entry_to_componentlist,
        'digitalguardian-check-componentlist-entry': check_componentlist_entry,
        'digitalguardian-remove-componentlist-entry': rm_entry_from_componentlist,
    }

    try:
        handle_proxy()

        command = demisto.command()

        LOG(f'Command being called is {command}')

        if command not in commands:
            return_error(f'Command "{command}" not implemented')

        command_fn = commands[command]

        request_api_token()

        command_fn()

    except Exception as e:
        return_error(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
