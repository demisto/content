import io
import json


def util_load_json(path) -> dict:
    with io.open(path, mode='r', encoding='utf-8') as file:
        return json.loads(file.read())


def test_cisco_stealthwatch_query_flows_initialize_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_query_flows_initialize_command
    mock_response = util_load_json('test_data/query_flow_initialize.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar', 'XSRF-TOKEN': 'some token'})
    req_mock = requests_mock.post('https://sw-reporting/v2/tenants//flows/queries', json=mock_response,
                                  headers={'X-XSRF-TOKEN': 'some token'})
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_query_flows_initialize_command(client, '', time_range='1 week')
    outputs = response.raw_response['data']['query']
    assert req_mock.last_request.headers['X-XSRF-TOKEN']
    assert response.outputs_prefix == 'CiscoStealthwatch.FlowStatus'
    assert response.outputs_key_field == 'id'
    assert response.outputs == outputs


def test_cisco_stealthwatch_query_flows_status_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_query_flows_status_command
    mock_response = util_load_json('test_data/query_flow_status.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v2/tenants//flows/queries/602a96e7e4b0d6d2a200ea94',
                      json=mock_response, headers={'X-XSRF-TOKEN': 'some token'})
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_query_flows_status_command(client, '', '602a96e7e4b0d6d2a200ea94')

    assert response.outputs_prefix == 'CiscoStealthwatch.FlowStatus'
    assert response.outputs_key_field == 'id'
    assert response.outputs.get('id') == '602a96e7e4b0d6d2a200ea94'


def test_cisco_stealthwatch_query_flows_results_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_query_flows_results_command
    mock_response = util_load_json('test_data/query_flow_results.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v2/tenants//flows/queries//results',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_query_flows_results_command(client, '', '')

    assert response.outputs_prefix == 'CiscoStealthwatch.FlowResults'
    assert response.outputs_key_field == 'id'
    assert len(response.outputs) == 1
    assert response.outputs[0].get('id') == 876742


def test_cisco_stealthwatch_list_tags_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_list_tags_command
    mock_response = util_load_json('test_data/list_tags.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants//internalHosts/tags',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_tags_command(client, '')

    assert response.outputs_prefix == 'CiscoStealthwatch.Tag'
    assert response.outputs_key_field == 'id'
    assert response.outputs[0].get('id') == 1


def test_cisco_stealthwatch_get_tag_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_get_tag_command
    mock_response = util_load_json('test_data/get_tag.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://smc-configuration/rest/v1/tenants//tags/',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_get_tag_command(client, '', '')

    assert response.outputs_prefix == 'CiscoStealthwatch.Tag'
    assert response.outputs_key_field == 'id'
    assert response.outputs == response.raw_response.get('data')


def test_cisco_stealthwatch_list_tenants_all_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_list_tenants_command
    mock_response = util_load_json('test_data/list_tenants.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_tenants_command(client)

    assert response.outputs_prefix == 'CiscoStealthwatch.Tenant'
    assert response.outputs_key_field == 'id'
    assert response.outputs[0].get('id') == 102
    assert response.outputs[0].get('displayName') == 'companyname'


def test_cisco_stealthwatch_list_tenants_one_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_list_tenants_command
    mock_response = util_load_json('test_data/get_tenant.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants/x',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_tenants_command(client, 'x')

    assert response.outputs_prefix == 'CiscoStealthwatch.Tenant'
    assert response.outputs_key_field == 'id'
    assert response.outputs.get('id') == 102
    assert response.outputs.get('displayName') == 'companyname'


def test_cisco_stealthwatch_get_tag_hourly_traffic_report_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_get_tag_hourly_traffic_report_command
    mock_response = util_load_json('test_data/get_tag_hourly_traffic_report.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants/x/internalHosts/tags/y/traffic/hourly',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_get_tag_hourly_traffic_report_command(client, 'x', 'y')

    assert response.outputs_prefix == 'CiscoStealthwatch.TagHourlyTraffic'
    assert response.outputs_key_field == ['tag_id', 'tenant_id', 'timestamp']
    assert response.outputs[0].get('tenant_id') == 'x'
    assert response.outputs[0].get('tag_id') == 'y'


def test_cisco_stealthwatch_get_top_alarming_tags_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_get_top_alarming_tags_command
    mock_response = util_load_json('test_data/get_top_alarming_tags.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants/x/internalHosts/alarms/topHosts',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_get_top_alarming_tags_command(client, 'x')

    assert response.outputs_prefix == 'CiscoStealthwatch.AlarmingTag'
    assert response.outputs_key_field == ['tenant_id', 'hostGroupIds']
    assert response.outputs[0].get('tenant_id') == 'x'


def test_cisco_stealthwatch_list_security_events_initialize_command(requests_mock):
    from CiscoStealthwatch import Client, \
        cisco_stealthwatch_list_security_events_initialize_command
    mock_response = util_load_json('test_data/list_security_events_initialize.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.post('https://sw-reporting/v1/tenants/x/security-events/queries',
                       json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_security_events_initialize_command(client, 'x',
                                                                          time_range='1 day')

    assert response.outputs_prefix == 'CiscoStealthwatch.SecurityEventStatus'
    assert response.outputs_key_field == 'id'
    assert response.outputs.get('id') == '6029011fe4b0d6d2a1ffd2d7'
    assert response.outputs.get('searchJobStatus') == 'IN_PROGRESS'
    assert response.outputs.get('percentComplete') == 0


def test_cisco_stealthwatch_list_security_events_status_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_list_security_events_status_command
    mock_response = util_load_json('test_data/list_security_events_status.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants//security-events/queries/x',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_security_events_status_command(client, '', 'x')

    assert response.outputs_prefix == 'CiscoStealthwatch.SecurityEventStatus'
    assert response.outputs_key_field == 'id'
    assert response.outputs.get('id') == 'x'


def test_cisco_stealthwatch_list_security_events_results_command(requests_mock):
    from CiscoStealthwatch import Client, cisco_stealthwatch_list_security_events_results_command
    mock_response = util_load_json('test_data/list_security_events_results.json')
    requests_mock.post('https://token/v2/authenticate', cookies={'cookies': 'jar'})
    requests_mock.get('https://sw-reporting/v1/tenants//security-events/results/x',
                      json=mock_response)
    client = Client(base_url='https://', auth=('', ''), verify=False, proxy=False)
    response = cisco_stealthwatch_list_security_events_results_command(client, '', 'x', 2)

    assert response.outputs_prefix == 'CiscoStealthwatch.SecurityEventResults'
    assert response.outputs_key_field == 'id'
    assert len(response.outputs) == 2
    assert response.outputs[0].get('id') == 5223
