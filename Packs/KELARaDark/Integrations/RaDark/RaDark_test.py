import json
import os
import RaDark as integration

API_KEY = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
MONITOR_ID = '0000'
CLIENT = integration.Client(base_url=integration.BASE_URL, verify=True, headers={}, proxy=False)


def load_mock_response(file_name: str) -> dict:
    data_path = os.path.normpath(os.path.join(os.path.dirname(__file__), "test_data", file_name))
    with open(data_path, mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


def test_incident_get_items_command(requests_mock):
    mock_data = load_mock_response('incident_get_items_info.json')
    incident_get_items_response = mock_data.get('INCIDENT_GET_ITEMS_RESPONSE', {})
    incident_get_items_args = mock_data.get('INCIDENT_GET_ITEMS_ARGS', {})
    incident_get_items_command_results = mock_data.get('INCIDENT_GET_ITEMS_COMMAND_RESULTS', {})

    incident_id = incident_get_items_args.get('incident_id', '')

    api = integration.FETCH_ITEMS_API.format(incident_id=incident_id, MONITOR_ID=MONITOR_ID, API_KEY=API_KEY)
    url = f'{integration.BASE_URL}/{api}'
    requests_mock.get(url, json=incident_get_items_response)
    command_results = integration.incident_get_items_command(CLIENT, incident_get_items_args)

    assert command_results.readable_output == incident_get_items_command_results.get('readable_output', '')
    assert command_results.outputs_prefix == incident_get_items_command_results.get('outputs_prefix', '')
    assert command_results.outputs_key_field == incident_get_items_command_results.get('outputs_key_field', '')
    assert command_results.outputs == incident_get_items_command_results.get('outputs', '')


def test_email_enrich_command(requests_mock):
    mock_data = load_mock_response('email_enrich_info.json')
    email_enrich_response = mock_data.get('EMAIL_ENRICH_RESPONSE', {})
    email_enrich_args = mock_data.get('EMAIL_ENRICH_ARGS', {})
    email_enrich_command_results = mock_data.get('EMAIL_ENRICH_COMMAND_RESULTS', {})
    api = integration.EMAIL_ENRICHMENT_API.format(MONITOR_ID=MONITOR_ID, API_KEY=API_KEY)
    url = f'{integration.BASE_URL}/{api}'
    requests_mock.post(url, json=email_enrich_response)
    command_results = integration.email_enrich_command(CLIENT, email_enrich_args)

    assert command_results.readable_output == email_enrich_command_results.get('readable_output', '')
    assert command_results.outputs_prefix == email_enrich_command_results.get('outputs_prefix', '')
    assert command_results.outputs_key_field == email_enrich_command_results.get('outputs_key_field', '')
    assert command_results.outputs == email_enrich_command_results.get('outputs', '')


def test_item_handle_command(requests_mock):
    mock_data = load_mock_response('item_handle_info.json')
    item_handle_response = mock_data.get('ITEM_HANDLE_RESPONSE', {})
    item_handle_args = mock_data.get('ITEM_HANDLE_ARGS', {})
    item_handle_command_results = mock_data.get('ITEM_HANDLE_COMMAND_RESULTS', {})
    api = integration.INCIDENT_ACTION_API.format(
        item_id=item_handle_args.get('item_id', ''),
        action="handled",
        API_KEY=API_KEY)
    url = f'{integration.BASE_URL}/{api}'
    requests_mock.post(url, json=item_handle_response)
    command_results = integration.item_handle_command(CLIENT, item_handle_args)

    assert command_results.readable_output == item_handle_command_results.get('readable_output', '')


def test_item_purchase_command(requests_mock):
    mock_data = load_mock_response('item_purchase_info.json')
    item_purchase_response = mock_data.get('ITEM_PURCHASE_RESPONSE', [{}, {}, {}, {}, {}])
    item_purchase_args = mock_data.get('ITEM_PURCHASE_ARGS', {})
    item_purchase_runtime_params = mock_data.get('ITEM_PURCHASE_RUNTIME_PARAMS', {})
    item_purchase_command_results = mock_data.get('ITEM_PURCHASE_COMMAND_RESULTS', {})

    item_id = item_purchase_args.get('item_id', '')
    incident_id = item_purchase_runtime_params.get('incident_id', '')

    api0 = integration.MENTIONS_LIST_API.format(API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
    url0 = f'{integration.BASE_URL}/{api0}'
    requests_mock.get(url0, json=item_purchase_response[0])

    api1 = integration.FETCH_AN_ITEM_API.format(item_id=item_id, API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
    url1 = f'{integration.BASE_URL}/{api1}'
    requests_mock.get(url1, json=item_purchase_response[1])

    api2 = integration.FETCH_ITEMS_API.format(incident_id=incident_id, API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
    url2 = f'{integration.BASE_URL}/{api2}'
    requests_mock.get(url2, json=item_purchase_response[2])

    api3 = integration.INCIDENT_ACTION_API.format(item_id=item_id, action='request', API_KEY=API_KEY)
    url3 = f'{integration.BASE_URL}/{api3}'
    requests_mock.post(url3, json=item_purchase_response[3])

    api4 = integration.MESSAGE_API.format(API_KEY=API_KEY)
    url4 = f'{integration.BASE_URL}/{api4}'
    requests_mock.post(url4, json=item_purchase_response[4])

    command_results = integration.item_purchase_command(CLIENT, item_purchase_args)

    assert command_results.readable_output == item_purchase_command_results.get('readable_output', '')
