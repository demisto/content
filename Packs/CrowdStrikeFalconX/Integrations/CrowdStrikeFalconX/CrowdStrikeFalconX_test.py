from CrowdStrikeFalconX import Client, test_module,\
    upload_file_command, send_uploaded_file_to_sandbox_analysis_command, send_url_to_sandbox_analysis_command,\
    get_full_report_command, get_report_summary_command, get_analysis_status_command, download_ioc_command, \
    check_quota_status_command, find_sandbox_reports_command, find_submission_id_command
import pytest

UPLOAD_FILE_ARGS = {
    "file": "/Users/ohaim/dev/demisto/content/Packs/Alexa/Integrations/Alexa/Alexa.py",
    "file_name": "Alexa.py",
    "comment": "234",
    "is_confidential": "true"
}
UPLOAD_FILE_HTTP_RESPONSE = {'meta': {'query_time': 1.88e-07, 'trace_id': 'trace_id'},
                             'resources': [
                                 {'sha256': 'sha256',
                                  'file_name': 'file_name'}], 'errors': []}
UPLOAD_FILE_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'file_name': 'file_name',
            'sha256': 'sha256'
        }
}

SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS = {
    "sha256": "sha256",
    "environment_id": 160,
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "enable_tor": "false",
    "submit_name": "",
    "system_date": "",
    "system_time": ""
}
SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_HTTP_RESPONSE = {
    'meta': {'query_time': 0.163158146, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 36, 'in_progress': 3}}, 'resources': [
        {'id': 'id',
         'cid': 'cid', 'origin': 'apigateway', 'state': 'created',
         'created_timestamp': '2020-05-12T15:34:11Z', 'sandbox': [
            {'sha256': 'sha256', 'environment_id': 160}]}],
    'errors': []}

SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {'id': 'id',
         'state': 'created',
         'created_timestamp': '2020-05-12T15:34:11Z',
         'environment_id': 160,
         'sha256': 'sha256'
         }
}

SEND_URL_TO_SANDBOX_ANALYSIS_ARGS = {
    "url": "https://www.google.com",
    "environment_id": 160,
    "enable_tor": "False",
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "enable_tor": "",
    "submit_name": "",
    "system_date": "",
    "system_time": ""
}

SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE = {
    'meta': {'query_time': 0.12387683, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 44, 'in_progress': 5}}, 'resources': [
        {'id': 'id',
         'cid': 'cid', 'origin': 'apigateway', 'state': 'created',
         'created_timestamp': '2020-05-12T16:40:52Z',
         'sandbox': [{'url': 'https://www.google.com', 'environment_id': 160}]}], 'errors': []}

SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'id': 'id',
            'state': 'created',
            'created_timestamp': '2020-05-12T16:40:52Z',
            'environment_id': 160
        }
}

GET_FULL_REPORT_ARGS = {
    "ids": "ids",
}

GET_FULL_REPORT_HTTP_RESPONSE = {
    'meta': {'query_time': 0.006237549, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': 'id',
         'cid': 'cid', 'created_timestamp': '2020-03-16T17:04:48Z', 'origin': 'apigateway',
         'verdict': 'no specific threat',
         'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
         'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
         'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
         'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
         'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
         'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
         'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
         'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id',
         'sandbox': [
             {'sha256': 'sha256', 'environment_id': 160,
              'environment_description': 'Windows 10 64 bit', 'submit_url': 'hxxps://www.google.com',
              'submission_type': 'page_url', 'verdict': 'no specific threat', 'threat_score': 13,
              'windows_version_name': 'Windows 10', 'windows_version_edition': 'Professional',
              'windows_version_version': '10.0 (build 16299)', 'windows_version_bitness': 64,
              'incidents': [{'name': 'Network Behavior', 'details': ['Contacts 4 domains and 4 hosts']}],
              'classification': ['91.6% (.URL) Windows URL shortcut', '8.3% (.INI) Generic INI configuration'],
              'dns_requests': [
                  {'domain': 'googleads.g.doubleclick.net', 'address': '111.111.1.1', 'country': 'United States',
                   'registrar_name': 'registrar_name', 'registrar_organization': 'registrar_organization',
                   'registrar_creation_timestamp': '1996-01-16T00:00:00+00:00'},
                  {'domain': 'domain', 'address': '172.217.7.163', 'country': 'United States'},
                  {'domain': 'ssl.gstatic.com', 'address': '111.27.12.67', 'country': 'United States',
                   'registrar_name': 'registrar_name', 'registrar_organization': 'Google Inc.',
                   'registrar_creation_timestamp': '2008-02-11T00:00:00+00:00'},
                  {'domain': 'www.gstatic.com', 'address': '172.217.14.163', 'country': 'United States',
                   'registrar_name': 'registrar_name', 'registrar_organization': 'registrar_organization',
                   'registrar_creation_timestamp': '2008-02-11T00:00:00+00:00'}], 'contacted_hosts': [
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428},
                                         {'name': 'name.exe', 'pid': 9372}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 80, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428},
                                         {'name': 'name.exe', 'pid': 9372}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '111.27.12.67', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'name.exe', 'pid': 6428}], 'country': 'United States'}],
              'http_requests': [{'host': 'host', 'host_ip': '111.27.12.67', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'host', 'host_ip': '111.27.12.67', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': 'url',
                                 'method': 'GET',
                                 'header': 'header'}],
              'extracted_interesting_strings': [{
                                                    'value': 'value',
                                                    'type': 'Ansi', 'source': 'Process Commandline',
                                                    'filename': 'rundll32.exe'},
                                                {'value': 'value', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'filename'},
                                                {'value': 'value', 'type': 'Ansi',
                                                 'source': 'Image Processing', 'filename': 'filename'},
                                                {'value': 'value', 'type': 'Ansi', 'source': 'Image Processing',
                                                 'filename': 'screen_3.png'},
                                                {'value': 'value', 'type': 'Ansi',
                                                 'source': 'Image Processing', 'filename': 'filename'},
                                                {'value': 'value', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'filename'},
                                                {'value': 'value', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'filename'}], 'signatures': [
                 {'threat_level_human': 'informative', 'category': 'General', 'identifier': 'network-0', 'type': 7,
                  'relevance': 1, 'name': 'Contacts domains',
                  'description': 'description',
                  'origin': 'Network Traffic'},
                 {'threat_level_human': 'informative', 'category': 'General', 'identifier': 'network-1', 'type': 7,
                  'relevance': 1, 'name': 'Contacts server',
                  'description': 'description',
                  'origin': 'Network Traffic'},
                 {'threat_level_human': 'informative', 'category': 'Network Related', 'identifier': 'string-3',
                  'type': 2, 'relevance': 10, 'name': 'Found potential URL in binary/memory',
                  'description': 'description',
                  'origin': 'String'},
                 {'threat_level_human': 'informative', 'category': 'External Systems', 'identifier': 'suricata-0',
                  'type': 18, 'relevance': 10, 'name': 'Detected Suricata Alert',
                  'description': 'description',
                  'origin': 'Suricata Alerts'},
                 {'threat_level': 1, 'threat_level_human': 'suspicious', 'category': 'Ransomware/Banking',
                  'identifier': 'string-12', 'type': 2, 'relevance': 10,
                  'name': 'Detected text artifact in screenshot that indicate file could be ransomware',
                  'description': 'description',
                  'origin': 'String'},
                 {'threat_level': 1, 'threat_level_human': 'suspicious', 'category': 'Network Related',
                  'identifier': 'network-23', 'type': 7, 'relevance': 5,
                  'name': 'Sends traffic on typical HTTP outbound port, but without HTTP header',
                  'description': 'description',
                  'origin': 'Network Traffic'}], 'processes': [{'uid': '00074182-00006648', 'name': 'rundll32.exe',
                                                                'normalized_path': 'normalized_path.exe',
                                                                'command_line': 'command_line',
                                                                'sha256': 'sha256',
                                                                'pid': 6648,
                                                                'icon_artifact_id': 'icon_artifact_id',
                                                                'process_flags': [{'name': 'Reduced Monitoring'}]}],
              'screenshots_artifact_ids': ['screenshots_artifact_ids1',
                                           'screenshots_artifact_ids2',
                                           'screenshots_artifact_ids3',
                                           'screenshots_artifact_ids4'],
              'suricata_alerts': [{'destination_ip': 'destination_ip', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': 'sid'},
                                  {'destination_ip': 'destination_ip', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': 'sid'},
                                  {'destination_ip': 'destination_ip', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': 'sid'},
                                  {'destination_ip': '172.217.9.206', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': 'sid'}],
              'architecture': 'WINDOWS', 'sample_flags': ['Network Traffic'],
              'pcap_report_artifact_id': 'pcap_report_artifact_id'}],
         'malquery': [{'verdict': 'whitelisted', 'input': 'input', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'input', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'input', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'input', 'type': 'url'}]}], 'errors': []}
get_full_report_context = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'id': 'id',
            'verdict': 'no specific threat',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
            'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
            'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
            'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
            'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
            'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
            'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
            'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id',
            'environment_id': 160,
            'environment_description': 'Windows 10 64 bit',
            'threat_score': 13,
            'submit_url': 'hxxps://www.google.com',
            'submission_type': 'page_url',
            'sha256': 'sha256'
        }
}

GET_REPORT_SUMMARY_ARGS = {
    "ids": "ids",
}

GET_REPORT_SUMMARY_HTTP_RESPONSE = {
    'meta': {'query_time': 0.008725752, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': 'id',
         'cid': 'cid', 'created_timestamp': '2020-03-16T17:04:48Z', 'origin': 'apigateway',
         'sandbox': [
             {'sha256': 'sha256', 'environment_id': 160,
              'environment_description': 'Windows 10 64 bit', 'submit_url': 'hxxps://www.google.com',
              'submission_type': 'page_url', 'threat_score': 13, 'verdict': 'no specific threat',
              'incidents': [{'name': 'Network Behavior', 'details': ['Contacts 4 domains and 4 hosts']}],
              'sample_flags': ['Network Traffic']}], 'verdict': 'no specific threat',
         'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
         'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
         'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
         'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
         'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
         'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
         'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
         'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id'}],
    'errors': []}

GET_REPORT_SUMMARY_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'id': 'id',
            'verdict': 'no specific threat',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
            'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
            'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
            'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
            'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
            'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
            'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
            'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id',
            'environment_id': 160,
            'environment_description': 'Windows 10 64 bit',
            'threat_score': 13,
            'submit_url': 'hxxps://www.google.com',
            'submission_type': 'page_url',
            'sha256': 'sha256'
        }
}

GET_ANALYSIS_STATUS_ARGS = {
    "ids": "ids",
}

GET_ANALYSIS_STATUS_HTTP_RESPONSE = {
    'meta': {'query_time': 0.004325809, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': 'id',
         'cid': 'cid', 'origin': 'apigateway', 'state': 'success',
         'created_timestamp': '2020-03-16T17:04:48Z',
         'sandbox': [{'url': 'hxxps://www.google.com', 'environment_id': 160}]}], 'errors': []}

GET_ANALYSIS_STATUS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'id': 'id',
            'state': 'success',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'environment_id': 160
        }
}

CHECK_QUOTA_STATUS_HTTP_RESPONSE = {
    'meta': {'query_time': 0.008237956, 'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': None, 'errors': []}

CHECK_QUOTA_STATUS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'total': 100,
            'used': 47,
            'in_progress': 2
        }
}

FIND_SANDBOX_REPORTS_ARGS = {
        "offset": "",
        "limit": "",
        "sort": "",
        "filter": "",
}

FIND_SANDBOX_REPORTS_HTTP_RESPONSE = {
    'meta': {'query_time': 0.008271345, 'pagination': {'offset': 0, 'limit': 10, 'total': 69},
             'powered_by': 'falconx-api', 'trace_id': 'trace_id',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}},
    'resources': ['resources1',
                  'resources2',
                  'resources3',
                  'resources4'], 'errors': []}

FIND_SANDBOX_REPORTS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'resources': ['resources1', 'resources2', 'resources3', 'resources4']
        }
}

FIND_SUBMISSION_ID_ARGS = {
        "offset": "",
        "limit": "",
        "sort": "",
        "filter": "",
}

FIND_SUBMISSION_ID_HTTP_RESPONSE = {'meta': {'query_time': 0.008812114, 'pagination': {'offset': 0, 'limit': 10, 'total': 72},
                          'powered_by': 'falconx-api', 'trace_id': 'trace_id',
                          'quota': {'total': 100, 'used': 47, 'in_progress': 2}},
                            'resources': ['resources1',
                                          'resources2',
                                          'resources3',
                                          'resources4'], 'errors': []}

FIND_SUBMISSION_ID_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        {
            'resources': ['resources1', 'resources2', 'resources3', 'resources4']
        }
}


@pytest.mark.parametrize('command, args, http_response, context', [
    (upload_file_command, UPLOAD_FILE_ARGS, UPLOAD_FILE_HTTP_RESPONSE, UPLOAD_FILE_CONTEXT),
    (send_uploaded_file_to_sandbox_analysis_command, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_HTTP_RESPONSE, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT),
    (send_url_to_sandbox_analysis_command, SEND_URL_TO_SANDBOX_ANALYSIS_ARGS, SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT),
    (get_full_report_command, GET_FULL_REPORT_ARGS, GET_FULL_REPORT_HTTP_RESPONSE, get_full_report_context),
    (get_report_summary_command, GET_REPORT_SUMMARY_ARGS, GET_REPORT_SUMMARY_HTTP_RESPONSE, GET_REPORT_SUMMARY_CONTEXT),
    (get_analysis_status_command, GET_ANALYSIS_STATUS_ARGS, GET_ANALYSIS_STATUS_HTTP_RESPONSE, GET_ANALYSIS_STATUS_CONTEXT),
    (check_quota_status_command, {}, CHECK_QUOTA_STATUS_HTTP_RESPONSE, CHECK_QUOTA_STATUS_CONTEXT),
    (find_sandbox_reports_command, FIND_SANDBOX_REPORTS_ARGS, FIND_SANDBOX_REPORTS_HTTP_RESPONSE, FIND_SANDBOX_REPORTS_CONTEXT),
    (find_submission_id_command, FIND_SUBMISSION_ID_ARGS, FIND_SUBMISSION_ID_HTTP_RESPONSE, FIND_SUBMISSION_ID_CONTEXT),
])
def test_cs_falconx_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False
                    , proxy=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    _, outputs, _ = command(client, **args)
    assert outputs == context
