import json
import os

BASE_URL = 'https://api.cymulate.com/v1'


def util_load_json(file_name):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    with open(f'{current_dir}/test_data/{file_name}', mode='r', encoding='utf-8') as file:
        return json.loads(file.read())


def test_list_agents_command(mocker):
    from Cymulate_v2 import list_agents_command
    mocked_client = mocker.Mock()
    mocked_client.get_agents.return_value = util_load_json('list_agents.json')
    result = list_agents_command(mocked_client).outputs
    assert len(result) == 7
    assert result[0].get("agentAddress") == "agent@cymulate.com"


def test_cymulate_list_exfiltration_template_command(mocker):
    from Cymulate_v2 import list_exfiltration_template_command
    mocked_client = mocker.Mock()
    mocked_client.list_templates.return_value = util_load_json('list_exfiltration_template.json')
    result = list_exfiltration_template_command(mocked_client).outputs
    assert result[0].get('id') == '12345'
    assert result[0].get('name') == 'Cymulate Best Practice'


def test_cymulate_list_email_gateway_template_command(mocker):
    from Cymulate_v2 import list_email_gateway_template_command
    mocked_client = mocker.Mock()
    mocked_client.list_templates.return_value = util_load_json('list_email_gateway_templates.json')
    result = list_email_gateway_template_command(mocked_client).outputs
    assert result[0].get('id') == '12345'
    assert result[0].get('name') == 'free assessment'


def test_cymulate_list_endpoint_security_template_command(mocker):
    from Cymulate_v2 import list_endpoint_security_template_command
    mocked_client = mocker.Mock()
    mocked_client.list_templates.return_value = util_load_json('list_endpoint_security_templates.json')
    result = list_endpoint_security_template_command(mocked_client).outputs
    assert result[0].get('id') == '12345'
    assert result[0].get('name') == 'Free Assessment'


def test_cymulate_list_waf_template_command(mocker):
    from Cymulate_v2 import list_waf_template_command
    mocked_client = mocker.Mock()
    mocked_client.list_templates.return_value = util_load_json('list_waf_templates.json')
    result = list_waf_template_command(mocked_client).outputs
    assert result[0].get('id') == '12345'
    assert result[0].get('name') == 'free assessment'


def test_cymulate_list_lateral_movement_template_command(mocker):
    from Cymulate_v2 import list_lateral_movement_template_command
    mocked_client = mocker.Mock()
    mocked_client.list_templates.return_value = util_load_json('list_lateral_movement_templates.json')
    result = list_lateral_movement_template_command(mocked_client).outputs
    assert result[0].get('id') == '12345'
    assert result[0].get('name') == 'SMB Pass The Hash'


def test_cymulate_exfiltration_start_assessment_command(mocker):
    from Cymulate_v2 import start_exfiltration_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_exfiltration_assessment_command(mocked_client, 'id_123', 'agent_007', False, 'one-time').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_email_gateway_start_assessment_command(mocker):
    from Cymulate_v2 import start_email_gateway_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_email_gateway_assessment_command(mocked_client, 'id_123', 'agent@007.com', False, 'one-time').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_endpoint_security_start_assessment_command(mocker):
    from Cymulate_v2 import start_endpoint_security_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_endpoint_security_assessment_command(mocked_client, 'id_123', 'agent_007', False, 'one-time').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_waf_start_assessment_command(mocker):
    from Cymulate_v2 import start_waf_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_waf_assessment_command(mocked_client, 'id_123', 'site_01', False, 'one-time').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_immediate_threats_start_assessment_command(mocker):
    from Cymulate_v2 import start_immediate_threat_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_immediate_threat_assessment_command(mocked_client, 'id_123', 'browsing').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_lateral_movement_start_assessment_command(mocker):
    from Cymulate_v2 import start_lateral_movement_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.start_assessment.return_value = util_load_json('start_attack.json')
    result = start_lateral_movement_assessment_command(mocked_client, 'id_123', 'agent_007', False, False, 'one-time').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_exfiltration_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_exfiltration_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_exfiltration_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_email_gateway_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_email_gateway_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_email_gateway_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_endpoint_security_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_endpoint_security_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_endpoint_security_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_waf_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_waf_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_waf_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_immediate_threats_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_immediate_threat_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_immediate_threat_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_lateral_movement_stop_assessment_command(mocker):
    from Cymulate_v2 import stop_lateral_movement_assessment_command
    mocked_client = mocker.Mock()
    mocked_client.stop_assessment.return_value = util_load_json('stop_assessment.json')
    result = stop_lateral_movement_assessment_command(mocked_client).outputs
    assert result.get('data') == 'ok'


def test_cymulate_exfiltration_assessment_status_command(mocker):
    from Cymulate_v2 import get_exfiltration_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('exfiltration_assessment_status.json')
    result = get_exfiltration_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'
    assert result.get('categories') == ["dns-tunneling"]


def test_cymulate_email_gateway_assessment_status_command(mocker):
    from Cymulate_v2 import get_email_gateway_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('email_gateway_assessment_status.json')
    result = get_email_gateway_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'
    assert result.get('addresses') == ['test@cymulate.com']


def test_cymulate_endpoint_security_assessment_status_command(mocker):
    from Cymulate_v2 import get_endpoint_security_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('endpoint_security_assessment_status.json')
    result = get_endpoint_security_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'
    assert result.get('categories') == ['ransomware']


def test_cymulate_waf_assessment_status_command(mocker):
    from Cymulate_v2 import get_waf_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('waf_assessment_status.json')
    result = get_waf_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'
    assert result.get('categories') == ["XML Injection", "Command Injection", "File Inclusion",
                                        "XSS", "XML Injection", "SQL Injection"]


def test_cymulate_immediate_threats_assessment_status_command(mocker):
    from Cymulate_v2 import get_immediate_threat_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('immediate_threats_assessment_status.json')
    result = get_immediate_threat_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'
    assert result.get('categories') == ['antivirus']


def test_cymulate_lateral_movement_assessment_status_command(mocker):
    from Cymulate_v2 import get_lateral_movement_assessment_status_command
    mocked_client = mocker.Mock()
    mocked_client.get_assessment_status.return_value = util_load_json('lateral_movement_assessment_status.json')
    result = get_lateral_movement_assessment_status_command(mocked_client, 'id_123').outputs
    assert result.get('id') == 'id_12345'


def test_cymulate_list_phishing_awareness_contact_group_command(mocker):
    from Cymulate_v2 import list_phishing_awareness_contact_groups_command
    mocked_client = mocker.Mock()
    mocked_client.list_phishing_contacts.return_value = util_load_json('list_phishing_awareness_contact_group.json')
    result = list_phishing_awareness_contact_groups_command(mocked_client).outputs
    assert len(result) == 5
    assert result[0].get('id') == 'id_12345'
    assert result[0].get('name') == 'new name'


def test_cymulate_get_phishing_awareness_contact_group_command(mocker):
    from Cymulate_v2 import get_phishing_awareness_contact_groups_command
    mocked_client = mocker.Mock()
    mocked_client.get_phishing_contacts.return_value = util_load_json('get_phishing_awareness_group.json')
    result = get_phishing_awareness_contact_groups_command(mocked_client, 'id_123').outputs
    assert len(result) == 3
    assert result[0].get('id') == 'id_12'
    assert result[0].get('firstName') == 'James'
    assert result[0].get('lastName') == 'Bonds'


def test_list_attack_simulations_command(mocker):
    from Cymulate_v2 import list_attack_simulations_command
    mocked_client = mocker.Mock()
    mocked_client.list_attack_ids_by_date.return_value = util_load_json('list_attack_simulation_ids.json').get('data')
    result = list_attack_simulations_command(mocked_client, 'kill-chain', '2021-01-01').outputs
    assert len(result) == 3
    assert result[0].get('ID') == 'id_12345'
    assert result[0].get('Agent') == 'LAPTOP-1'
    assert result[0].get('Template') == 'Cy Group'


def test_attack_simulations_command(mocker):
    from Cymulate_v2 import list_simulations_command
    mocked_client = mocker.Mock()
    mocked_client.get_simulations_by_id.return_value = util_load_json('list__attack_simulation.json')
    result = list_simulations_command(mocked_client, 'kill-chain', 'id-123').outputs
    assert len(result) == 3
    assert result[0].get('Module') == 'Web Application Firewall'


def test_cymulate_create_phishing_awareness_contact_group_command(mocker):
    from Cymulate_v2 import add_phishing_awareness_contact_groups_command
    mocked_client = mocker.Mock()
    mocked_client.create_phishing_contacts.return_value = util_load_json('create_phishing_awareness_group.json')
    result = add_phishing_awareness_contact_groups_command(mocked_client, 'new_group').outputs
    assert result.get('id') == 'id_12345'


def test_extract_status_output():
    from Cymulate_v2 import extract_status_commands_output
    status_response = util_load_json('exfiltration_assessment_status.json')
    result = extract_status_commands_output(status_response)
    assert result.get('id') == 'id_12345'


def test_validate_timestamp():
    from Cymulate_v2 import validate_timestamp
    good_verdict_1 = validate_timestamp('2021-02-22 22:53:10')
    good_verdict_2 = validate_timestamp('2021-02-25T13:23:20.958Z')
    bad_verdict_1 = validate_timestamp('No Timestamp')
    bad_verdict_2 = validate_timestamp(' ')
    assert good_verdict_1 is True
    assert good_verdict_2 is True
    assert bad_verdict_1 is False
    assert bad_verdict_2 is False


def test_format_id_list():
    from Cymulate_v2 import format_id_list
    id_data = util_load_json('immediate_threats_id_data.json')
    result = format_id_list(id_data)
    assert result[0] == 'id_12345'
    assert result[1] == 'id_67890'


def test_extract_event_name():
    from Cymulate_v2 import extract_event_name
    event = util_load_json('extract_name_from_event.json')
    result = extract_event_name(event, 'exfiltration')
    assert result == 'Cymulate - exfiltration - Google cloud configuration-source code'


def test_extract_event_description():
    from Cymulate_v2 import extract_event_description
    event = util_load_json('extract_name_from_event.json')
    result = extract_event_description(event)
    assert result == 'This is very interesting...'


def test_event_status_changed():
    from Cymulate_v2 import event_status_changed
    event = util_load_json('extract_name_from_event.json')
    result = event_status_changed(event)
    assert result is False


def test_build_incident_dict():
    from Cymulate_v2 import build_incident_dict
    event = util_load_json('extract_name_from_event.json')
    result = build_incident_dict(event, 'exfiltration')
    assert result.get('occurred') == '2021-02-24T16:16:47Z'
    assert result.get('severity') == 3
    assert result.get('rawJSON') == '{"cymulateStatus": "Exfiltrated", ' \
                                    '"module": "Data Exfiltration", ' \
                                    '"source": "LAPTOP-1234", ' \
                                    '"attackType": "HTTP Exfiltration", ' \
                                    '"description": "This is very interesting..."}'


def test_convert_to_xsoar_severity():
    from Cymulate_v2 import convert_to_xsoar_severity
    assert convert_to_xsoar_severity('low') == 1
    assert convert_to_xsoar_severity('medium') == 2
    assert convert_to_xsoar_severity('high') == 3
    assert convert_to_xsoar_severity('critical') == 4
    assert convert_to_xsoar_severity('This is not a valid option') == 0


def test_format_exfiltration_incidents():
    from Cymulate_v2 import format_incidents
    events = util_load_json('list_exfiltration_incidents.json')
    incidents, offset, timestamp, _ = format_incidents(events.get('data'), 0, 1604079530000, 'exfiltration')
    assert offset == 12
    assert timestamp == 1614183490000
    assert incidents[0] == {'name': 'Cymulate - exfiltration - Google cloud configuration-source code',
                            'occurred': '2021-02-24T16:16:57Z',
                            'rawJSON': '{"cymulateStatus": "Exfiltrated", '
                                       '"module": "Data Exfiltration", '
                                       '"source": "LAPTOP-123", '
                                       '"attackType": "HTTPS Exfiltration", '
                                       '"description": "description data..."}',
                            'severity': 3}


def test_format_endpoint_security_incidents():
    from Cymulate_v2 import format_incidents
    events = util_load_json('list_endpoint_security_incidents.json')
    incidents, offset, timestamp, _ = format_incidents(events.get('data'), 0, 1604079530000, 'endpoint-security')
    assert offset == 13
    assert timestamp == 1613887930000
    assert incidents[0] == {'name': 'Cymulate - endpoint-security - DLL Inject - SMB Worm SCM',
                            'occurred': '2021-02-21T06:12:10Z',
                            'severity': 0,
                            'rawJSON': '{"module": "Endpoint Security", '
                                       '"source": "LAPTOP-123", '
                                       '"attackType": "Worm", "templateName": "Mundo Hacker Academy", '
                                       '"command": "N/A", '
                                       '"description": "Listing all running processes to find a target process to inject the '
                                       'malicious DLL and the username owning that process.\\n'
                                       'Step 2:\\nN/A is Injecting the DLL to the target process. using WINAPI CreateRemoteThread'
                                       ' with LoadLibrary in order load DLL to a running target process.\\n'
                                       'Step 3:\\nThe Malicious DLL was injected to the target process memory, executing the'
                                       ' payload.\\n'
                                       'Step 4:\\nThe DLL is loaded to the target process memory.\\n'
                                       'Step 5:\\nListing all running processes to find a logged-on users tokens.\\n'
                                       'Step 6:\\nDuplicating Tokens from each running process on the machine to use for'
                                       ' Pass-The-Token.\\n'
                                       'Step 7:\\n0 Tokens collected from all processes running on the machine\\n'
                                       'Step 8:\\nScanning port 445 (SMB) on 255.255.255.0 Subnet for potential targets.\\n'
                                       'Step 9:\\n0 targets discovered with port 445 opened\\n'
                                       'Step 10:\\nRetrieve shares on discovered targets:\\n'
                                       'Step 11:\\nUsing collected tokens to copy the malicious payload to the scanned targets'
                                       ' using Server Message Block (SMB) infrastructure on port 445. Attempts: 0\\n'
                                       'Step 12:\\nCreate service on the remote target computer to execute the copied payload '
                                       'using the Service Control Manager (SCM).\\n'
                                       'Step 13:\\nTriggering execution of the service created on the remote target computer '
                                       'executing the payload.", "md5": "N/A", "sha256": "N/A", "sha1": "N/A"}'
                            }


def test_extract_template_output():
    from Cymulate_v2 import extract_template_output
    raw_data = util_load_json('list_lateral_movement_templates.json')
    output = extract_template_output(raw_data.get('data'))
    assert raw_data.get('data')[0].get('_id') == '12345'
    assert output[0].get('id') == '12345'
