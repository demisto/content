from FalconX import Client, test_module,\
    upload_file_command, send_uploaded_file_to_sendbox_analysis_command, send_url_to_sandbox_analysis_command,\
    get_full_report_command, get_report_summary_command, get_analysis_status_command, download_ioc_command, \
    check_quota_status_command, find_sandbox_reports_command, find_submission_id_command
import pytest


def test_upload_file_command(mocker):
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345")
    upload_file_args = {
            "file": "/Users/ohaim/dev/demisto/content/Packs/Alexa/Integrations/Alexa/Alexa.py",
            "file_name": "Alexa.py",
            "comment": "234",
            "is_confidential": "true"
        }
    upload_file_http_response = {'meta': {'query_time': 1.88e-07, 'trace_id': '3497fd7e-5781-4348-bcd9-3370092f7072'}, 'resources': [{'sha256': '1a79e1c5286a65da9f8e5d82b17a6383f7585c6b6bf2bdaba68af9cdd51f38ac', 'file_name': 'Alexa.py'}], 'errors': []}
    upload_file_context = {'csfalconx.resource(val.resource === obj.resource)': {'sha256': '1a79e1c5286a65da9f8e5d82b17a6383f7585c6b6bf2bdaba68af9cdd51f38ac', 'file_name': 'Alexa.py'}}
    _, outputs, _ = upload_file_command(client, **args)
    assert outputs == context





#####################################
check_quota_status_args = {
}
upload_file_args = {
    "file": "/Users/ohaim/dev/demisto/content/Packs/Alexa/Integrations/Alexa/Alexa.py",
    "file_name": "Alexa.py",
    "comment": "234",
    "is_confidential": "true"
}
upload_file_http_response = {'meta': {'query_time': 1.88e-07, 'trace_id': '3497fd7e-5781-4348-bcd9-3370092f7072'},
                             'resources': [
                                 {'sha256': '1a79e1c5286a65da9f8e5d82b17a6383f7585c6b6bf2bdaba68af9cdd51f38ac',
                                  'file_name': 'Alexa.py'}], 'errors': []}
upload_file_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'sha256': '1a79e1c5286a65da9f8e5d82b17a6383f7585c6b6bf2bdaba68af9cdd51f38ac', 'file_name': 'Alexa.py'}}

send_uploaded_file_to_sendbox_analysis_args = {
    "sha256": "89fbf6496093bda4420586a947705780f9ab5c92bcd2f21199e5b7316af6feb0",
    "environment_id": 160,
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "enable_tor": "false",
    "submit_name": "",
    "system_date": "",
    "system_time": ""
}
send_uploaded_file_to_sendbox_analysis_http_response = {
    'meta': {'query_time': 0.163158146, 'powered_by': 'falconx-api', 'trace_id': '30a12e4e-2593-4c1c-9508-185b3143e9a2',
             'quota': {'total': 100, 'used': 36, 'in_progress': 3}}, 'resources': [
        {'id': '1c9fe398b2294301aa3080ede8d77356_5e45bb4fb3a142eba24f07ef822e7741',
         'cid': '1c9fe398b2294301aa3080ede8d77356', 'origin': 'apigateway', 'state': 'created',
         'created_timestamp': '2020-05-12T15:34:11Z', 'sandbox': [
            {'sha256': '89fbf6496093bda4420586a947705780f9ab5c92bcd2f21199e5b7316af6feb0', 'environment_id': 160}]}],
    'errors': []}
send_uploaded_file_to_sendbox_analysis_context = {
    'csfalconx.resource(val.resource === obj.resource)':
        {
            'id': '1c9fe398b2294301aa3080ede8d77356_5e45bb4fb3a142eba24f07ef822e7741',
            'state': 'created',
            'created_timestamp': '2020-05-12T15:34:11Z',
            'sha256': '89fbf6496093bda4420586a947705780f9ab5c92bcd2f21199e5b7316af6feb0',
            'environment_id': 160
        }
}

send_url_to_sandbox_analysis_args = {
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
send_url_to_sandbox_analysis_http_response = {
    'meta': {'query_time': 0.12387683, 'powered_by': 'falconx-api', 'trace_id': 'f4993861-388a-47a9-acef-2d4593e632e3',
             'quota': {'total': 100, 'used': 44, 'in_progress': 5}}, 'resources': [
        {'id': '1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c',
         'cid': '1c9fe398b2294301aa3080ede8d77356', 'origin': 'apigateway', 'state': 'created',
         'created_timestamp': '2020-05-12T16:40:52Z',
         'sandbox': [{'url': 'https://www.google.com', 'environment_id': 160}]}], 'errors': []}
send_url_to_sandbox_analysis_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c', 'state': 'created',
    'created_timestamp': '2020-05-12T16:40:52Z', 'sha256': None, 'environment_id': 160}}

get_full_report_args = {
    "ids": "1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f",
}
get_full_report_http_response = {
    'meta': {'query_time': 0.006237549, 'powered_by': 'falconx-api', 'trace_id': '1a38780e-4721-4f18-abe0-8b3cc29408f3',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f',
         'cid': '1c9fe398b2294301aa3080ede8d77356', 'created_timestamp': '2020-03-16T17:04:48Z', 'origin': 'apigateway',
         'verdict': 'no specific threat',
         'ioc_report_strict_csv_artifact_id': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
         'ioc_report_broad_csv_artifact_id': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
         'ioc_report_strict_json_artifact_id': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
         'ioc_report_broad_json_artifact_id': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
         'ioc_report_strict_stix_artifact_id': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
         'ioc_report_broad_stix_artifact_id': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
         'ioc_report_strict_maec_artifact_id': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945',
         'ioc_report_broad_maec_artifact_id': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945',
         'sandbox': [
             {'sha256': '15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3', 'environment_id': 160,
              'environment_description': 'Windows 10 64 bit', 'submit_url': 'hxxps://www.google.com',
              'submission_type': 'page_url', 'verdict': 'no specific threat', 'threat_score': 13,
              'windows_version_name': 'Windows 10', 'windows_version_edition': 'Professional',
              'windows_version_version': '10.0 (build 16299)', 'windows_version_bitness': 64,
              'incidents': [{'name': 'Network Behavior', 'details': ['Contacts 4 domains and 4 hosts']}],
              'classification': ['91.6% (.URL) Windows URL shortcut', '8.3% (.INI) Generic INI configuration'],
              'dns_requests': [
                  {'domain': 'googleads.g.doubleclick.net', 'address': '172.217.14.162', 'country': 'United States',
                   'registrar_name': 'MarkMonitor, Inc.', 'registrar_organization': 'Google Inc.',
                   'registrar_creation_timestamp': '1996-01-16T00:00:00+00:00'},
                  {'domain': 'ocsp.pki.goog', 'address': '172.217.7.163', 'country': 'United States'},
                  {'domain': 'ssl.gstatic.com', 'address': '172.217.12.67', 'country': 'United States',
                   'registrar_name': 'MarkMonitor, Inc.', 'registrar_organization': 'Google Inc.',
                   'registrar_creation_timestamp': '2008-02-11T00:00:00+00:00'},
                  {'domain': 'www.gstatic.com', 'address': '172.217.14.163', 'country': 'United States',
                   'registrar_name': 'MarkMonitor, Inc.', 'registrar_organization': 'Google Inc.',
                   'registrar_creation_timestamp': '2008-02-11T00:00:00+00:00'}], 'contacted_hosts': [
                 {'address': '172.217.15.68', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428},
                                         {'name': 'microsoftedge.exe', 'pid': 9372}], 'country': 'United States'},
                 {'address': '172.217.7.163', 'port': 80, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428},
                                         {'name': 'microsoftedge.exe', 'pid': 9372}], 'country': 'United States'},
                 {'address': '172.217.8.3', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '172.217.12.227', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '172.217.164.130', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '172.217.9.206', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428}], 'country': 'United States'},
                 {'address': '172.217.8.2', 'port': 443, 'protocol': 'TCP',
                  'associated_runtime': [{'name': 'microsoftedgecp.exe', 'pid': 6428}], 'country': 'United States'}],
              'http_requests': [{'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D',
                                 'method': 'GET',
                                 'header': 'GET /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEC4G%2Bv2mHN8jAgAAAABcZ3g%3D',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEC4G%2Bv2mHN8jAgAAAABcZ3g%3D HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQCuvwBRDDb68AgAAAAAMM4r',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQCuvwBRDDb68AgAAAAAMM4r HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D',
                                 'method': 'GET',
                                 'header': 'GET /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEC4G%2Bv2mHN8jAgAAAABcZ3g%3D',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEC4G%2Bv2mHN8jAgAAAABcZ3g%3D HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEGFA%2F%2Fi5YNGTCAAAAAAyCrg%3D',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEGFA%2F%2Fi5YNGTCAAAAAAyCrg%3D HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQDlLaJJOdB%2BwQIAAAAAW2d0',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQDlLaJJOdB%2BwQIAAAAAW2d0 HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'},
                                {'host': 'ocsp.pki.goog', 'host_ip': '172.217.7.163', 'host_port': 80,
                                 'url': '/gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQDL%2FQslYWVuogIAAAAAXGdc',
                                 'method': 'GET',
                                 'header': 'GET /gts1o1/MFIwUDBOMEwwSjAJBgUrDgMCGgUABBRCRjDCJxnb3nDwj%2Fxz5aZfZjgXvAQUmNH4bhDrz5vsYJ8YkBug630J%2FSsCEQDL%2FQslYWVuogIAAAAAXGdc HTTP/1.1\nConnection: Keep-Alive\nAccept: */*\nUser-Agent: Microsoft-CryptoAPI/10.0\nHost: ocsp.pki.goog'}],
              'extracted_interesting_strings': [{
                                                    'value': '"%WINDIR%\\system32\\ieframe.dll",OpenURL C:\\15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3.url',
                                                    'type': 'Ansi', 'source': 'Process Commandline',
                                                    'filename': 'rundll32.exe'},
                                                {'value': 'googleads.g.doubleclick.net', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'PCAP'},
                                                {'value': 'Hel_s1o_coronavirus', 'type': 'Ansi',
                                                 'source': 'Image Processing', 'filename': 'screen_5.png'},
                                                {'value': 'mm.goog_ecom', 'type': 'Ansi', 'source': 'Image Processing',
                                                 'filename': 'screen_3.png'},
                                                {'value': 'rttc;:;,mm.go0g_e.com,_', 'type': 'Ansi',
                                                 'source': 'Image Processing', 'filename': 'screen_5.png'},
                                                {'value': 'ssl.gstatic.com', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'PCAP'},
                                                {'value': 'www.gstatic.com', 'type': 'Ansi',
                                                 'source': 'PCAP Processing', 'filename': 'PCAP'}], 'signatures': [
                 {'threat_level_human': 'informative', 'category': 'General', 'identifier': 'network-0', 'type': 7,
                  'relevance': 1, 'name': 'Contacts domains',
                  'description': '"ocsp.pki.goog"\n "googleads.g.doubleclick.net"\n "ssl.gstatic.com"\n "www.gstatic.com"',
                  'origin': 'Network Traffic'},
                 {'threat_level_human': 'informative', 'category': 'General', 'identifier': 'network-1', 'type': 7,
                  'relevance': 1, 'name': 'Contacts server',
                  'description': '"172.217.15.68:443"\n "172.217.7.163:80"\n "172.217.8.3:443"\n "172.217.12.227:443"\n "172.217.164.130:443"\n "172.217.9.206:443"\n "172.217.8.2:443"',
                  'origin': 'Network Traffic'},
                 {'threat_level_human': 'informative', 'category': 'Network Related', 'identifier': 'string-3',
                  'type': 2, 'relevance': 10, 'name': 'Found potential URL in binary/memory',
                  'description': 'Heuristic match: "googleads.g.doubleclick.net"\n Heuristic match: "ssl.gstatic.com"\n Pattern match: "www.gstatic.com"',
                  'origin': 'String'},
                 {'threat_level_human': 'informative', 'category': 'External Systems', 'identifier': 'suricata-0',
                  'type': 18, 'relevance': 10, 'name': 'Detected Suricata Alert',
                  'description': 'Detected alert "ET JA3 Hash - Possible Malware - Banking Phish" (SID: 2028362, Rev: 2, Severity: 3) categorized as "Unknown Traffic"',
                  'origin': 'Suricata Alerts'},
                 {'threat_level': 1, 'threat_level_human': 'suspicious', 'category': 'Ransomware/Banking',
                  'identifier': 'string-12', 'type': 2, 'relevance': 10,
                  'name': 'Detected text artifact in screenshot that indicate file could be ransomware',
                  'description': '"Hel_s1o_coronavirus" (Source: screen_5.png, Indicator: "virus")',
                  'origin': 'String'},
                 {'threat_level': 1, 'threat_level_human': 'suspicious', 'category': 'Network Related',
                  'identifier': 'network-23', 'type': 7, 'relevance': 5,
                  'name': 'Sends traffic on typical HTTP outbound port, but without HTTP header',
                  'description': 'TCP traffic to 172.217.15.68 on port 443 is sent without HTTP header\n TCP traffic to 172.217.7.163 on port 80 is sent without HTTP header\n TCP traffic to 172.217.8.3 on port 443 is sent without HTTP header\n TCP traffic to 172.217.12.227 on port 443 is sent without HTTP header\n TCP traffic to 172.217.164.130 on port 443 is sent without HTTP header\n TCP traffic to 172.217.9.206 on port 443 is sent without HTTP header\n TCP traffic to 172.217.8.2 on port 443 is sent without HTTP header',
                  'origin': 'Network Traffic'}], 'processes': [{'uid': '00074182-00006648', 'name': 'rundll32.exe',
                                                                'normalized_path': '%WINDIR%\\System32\\rundll32.exe',
                                                                'command_line': '"%WINDIR%\\system32\\ieframe.dll",OpenURL C:\\15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3.url',
                                                                'sha256': 'b1e6a7a3e2597e51836277a32b2bc61aa781c8f681d44dfddea618b32e2bf2a6',
                                                                'pid': 6648,
                                                                'icon_artifact_id': '234d8337ea32822a26e511c4e8e955976a2c78d7e2136e5bcbd854ec0d204021',
                                                                'process_flags': [{'name': 'Reduced Monitoring'}]}],
              'screenshots_artifact_ids': ['aa1c389b8ae3ccf0ae03874b0f0372d8fc51d633e6a1569871404b671b491345',
                                           'e31707c9057d3810a50f7bdfcfac56049bf2670a06c23b6425c3af8c10821917',
                                           '4c609bf21d541849209fce52e0cd9bf5802db1c16b5d93825e9ec0e575444528',
                                           '414f9e855c80990f9f4c023ca0ec4036d2b2613d26c7737803ba6558d18cbf09',
                                           'bcfed96416fff753bbd8f76b3c9238634ca433811c8efaf8ad5d8c9527b50dc6',
                                           'fa1d06b21ea5ea5aa58e536071a451afa505e1a406fd908710b623e8e1b111b7'],
              'suricata_alerts': [{'destination_ip': '172.217.15.68', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.15.68', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.8.3', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.8.3', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.12.227', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.12.227', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.9.206', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.164.130', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.8.2', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.8.2', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.164.130', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.9.206', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.9.206', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'},
                                  {'destination_ip': '172.217.9.206', 'destination_port': 443, 'protocol': 'TCP',
                                   'category': 'Unknown Traffic',
                                   'description': 'ET JA3 Hash - Possible Malware - Banking Phish', 'sid': '2028362'}],
              'architecture': 'WINDOWS', 'sample_flags': ['Network Traffic'],
              'pcap_report_artifact_id': 'aeb3ccf8b6ce8fb7984f7be36ba4d42339d82fadc1ac165014e9c1cd62c4f542'}],
         'malquery': [{'verdict': 'whitelisted', 'input': 'http://googleads.g.doubleclick.net', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'http://ssl.gstatic.com', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'http://www.gstatic.com', 'type': 'url'},
                      {'verdict': 'whitelisted', 'input': 'https://www.google.com', 'type': 'url'}]}], 'errors': []}
get_full_report_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f', 'verdict': 'no specific threat',
    'created_timestamp': '2020-03-16T17:04:48Z', 'environment_id': 160, 'environment_description': 'Windows 10 64 bit',
    'sandbox_threat_score': 13, 'sandbox_submit_url': 'hxxps://www.google.com', 'submission_type': 'page_url',
    'sandbox_filetyp': None, 'sandbox_filesize': None,
    'sandbox_sha256': '15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3',
    'ioc_strict_csv': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
    'ioc_broad_csv': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
    'ioc_strict_jason': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
    'ioc_broad_jason': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
    'ioc_strict_stix': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
    'ioc_broad_stix': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
    'ioc_strict_maec': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945',
    'ioc_broad_maec': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945'}}

get_report_summary_args = {
    "ids": "1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f",
}
get_report_summary_http_response = {
    'meta': {'query_time': 0.008725752, 'powered_by': 'falconx-api', 'trace_id': 'c144ed88-4123-4329-ac04-11e8c2ff9da6',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f',
         'cid': '1c9fe398b2294301aa3080ede8d77356', 'created_timestamp': '2020-03-16T17:04:48Z', 'origin': 'apigateway',
         'sandbox': [
             {'sha256': '15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3', 'environment_id': 160,
              'environment_description': 'Windows 10 64 bit', 'submit_url': 'hxxps://www.google.com',
              'submission_type': 'page_url', 'threat_score': 13, 'verdict': 'no specific threat',
              'incidents': [{'name': 'Network Behavior', 'details': ['Contacts 4 domains and 4 hosts']}],
              'sample_flags': ['Network Traffic']}], 'verdict': 'no specific threat',
         'ioc_report_strict_csv_artifact_id': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
         'ioc_report_broad_csv_artifact_id': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
         'ioc_report_strict_json_artifact_id': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
         'ioc_report_broad_json_artifact_id': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
         'ioc_report_strict_stix_artifact_id': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
         'ioc_report_broad_stix_artifact_id': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
         'ioc_report_strict_maec_artifact_id': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945',
         'ioc_report_broad_maec_artifact_id': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945'}],
    'errors': []}
get_report_summary_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f', 'verdict': 'no specific threat',
    'created_timestamp': '2020-03-16T17:04:48Z', 'environment_id': 160, 'environment_description': 'Windows 10 64 bit',
    'sandbox_threat_score': 13, 'sandbox_submit_url': 'hxxps://www.google.com', 'submission_type': 'page_url',
    'sandbox_filetyp': None, 'sandbox_filesize': None,
    'sandbox_sha256': '15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3',
    'ioc_strict_csv': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
    'ioc_broad_csv': '910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04',
    'ioc_strict_jason': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
    'ioc_broad_jason': 'b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8',
    'ioc_strict_stix': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
    'ioc_broad_stix': '90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1',
    'ioc_strict_maec': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945',
    'ioc_broad_maec': '16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945'}}

get_analysis_status_args = {
    "ids": "1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f",
}
get_analysis_status_http_response = {
    'meta': {'query_time': 0.004325809, 'powered_by': 'falconx-api', 'trace_id': 'a9f38cb0-e950-4100-8f53-8b6b03a92b32',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': [
        {'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f',
         'cid': '1c9fe398b2294301aa3080ede8d77356', 'origin': 'apigateway', 'state': 'success',
         'created_timestamp': '2020-03-16T17:04:48Z',
         'sandbox': [{'url': 'hxxps://www.google.com', 'environment_id': 160}]}], 'errors': []}
get_analysis_status_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f', 'state': 'success',
    'created_timestamp': '2020-03-16T17:04:48Z', 'sha256': None, 'environment_id': 160}}

check_quota_status_http_response = {
    'meta': {'query_time': 0.008237956, 'powered_by': 'falconx-api', 'trace_id': 'ccdc9e02-2ade-4563-b3c0-d20a386d93db',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}}, 'resources': None, 'errors': []}

check_quota_status_context = {
    'csfalconx.resource(val.resource === obj.resource)': {'quota_total': 100, 'quota_used': 47, 'quota_in_progress': 2}}

find_sandbox_reports_args = {
        "offset": "",
        "limit": "",
        "sort": "",
        "filter": "",
}

find_sandbox_reports_http_response = {
    'meta': {'query_time': 0.008271345, 'pagination': {'offset': 0, 'limit': 10, 'total': 69},
             'powered_by': 'falconx-api', 'trace_id': 'acd021de-483d-4434-9a89-4b7d336a3770',
             'quota': {'total': 100, 'used': 47, 'in_progress': 2}},
    'resources': ['1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c',
                  '1c9fe398b2294301aa3080ede8d77356_233432b2a44f4d5d9ee2e04a20dffbf5',
                  '1c9fe398b2294301aa3080ede8d77356_7e0b6c996c6d467f825c8fb08354394b',
                  '1c9fe398b2294301aa3080ede8d77356_5ee5378e6b054b9c91e8465ce3dea226',
                  '1c9fe398b2294301aa3080ede8d77356_0f3f2ac1b66348f2a1700ef3a8967018',
                  '1c9fe398b2294301aa3080ede8d77356_9c8c3d58e1544295a0bdb484f167f49c',
                  '1c9fe398b2294301aa3080ede8d77356_e263b6182ec3493284e2f5a2a6c2c431',
                  '1c9fe398b2294301aa3080ede8d77356_cd2cf828fa2a473587679278ab1df417',
                  '1c9fe398b2294301aa3080ede8d77356_75b7fcd97cb243babb90fe9c74abaaf1',
                  '1c9fe398b2294301aa3080ede8d77356_879799a6a73b4fcf94076b619c9d74c0'], 'errors': []}

find_sandbox_reports_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c'}}

find_submission_id_args = {
        "offset": "",
        "limit": "",
        "sort": "",
        "filter": "",
    }
find_submission_id_http_response = {'meta': {'query_time': 0.008812114, 'pagination': {'offset': 0, 'limit': 10, 'total': 72},
                          'powered_by': 'falconx-api', 'trace_id': 'c0cb36bc-491f-4f53-b682-8e85095256de',
                          'quota': {'total': 100, 'used': 47, 'in_progress': 2}},
                 'resources': ['1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c',
                               '1c9fe398b2294301aa3080ede8d77356_233432b2a44f4d5d9ee2e04a20dffbf5',
                               '1c9fe398b2294301aa3080ede8d77356_7e0b6c996c6d467f825c8fb08354394b',
                               '1c9fe398b2294301aa3080ede8d77356_5ee5378e6b054b9c91e8465ce3dea226',
                               '1c9fe398b2294301aa3080ede8d77356_0f3f2ac1b66348f2a1700ef3a8967018',
                               '1c9fe398b2294301aa3080ede8d77356_9c8c3d58e1544295a0bdb484f167f49c',
                               '1c9fe398b2294301aa3080ede8d77356_e263b6182ec3493284e2f5a2a6c2c431',
                               '1c9fe398b2294301aa3080ede8d77356_cd2cf828fa2a473587679278ab1df417',
                               '1c9fe398b2294301aa3080ede8d77356_082a529aa6bc4c1fbaefb764927e3797',
                               '1c9fe398b2294301aa3080ede8d77356_75b7fcd97cb243babb90fe9c74abaaf1'], 'errors': []}

find_submission_id_context = {'csfalconx.resource(val.resource === obj.resource)': {
    'id': '1c9fe398b2294301aa3080ede8d77356_c2787038514f4d9581af622565b0c43c'}}


@pytest.mark.parametrize('command, args, http_response, context', [
    (get_full_report_command, get_full_report_args, get_full_report_http_response, get_full_report_context),
    (get_report_summary_command, get_report_summary_args, get_report_summary_http_response, get_report_summary_context),
    (get_analysis_status_command, get_analysis_status_args, get_analysis_status_http_response, get_analysis_status_context),
    (check_quota_status_command, {}, check_quota_status_http_response, check_quota_status_context),
    (find_sandbox_reports_command, find_sandbox_reports_args, find_sandbox_reports_http_response, find_sandbox_reports_context),
    (find_submission_id_command, find_submission_id_args, find_submission_id_http_response, find_submission_id_context),
])
def test_sql_queries(command, args, http_response, context, mocker):
    """Unit test
    Given
    - select query
    - raw response of the database
    When
    - mock the database result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345")

    mocker.patch.object(Client, 'http_request', return_value=http_response)

    _, outputs, _ = command(client, **args)
    assert outputs == context
