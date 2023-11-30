import json
import os
import RaDark as integration

API_KEY = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
MONITOR_ID = '0000'
CLIENT = integration.Client(
    base_url=integration.BASE_URL,
    verify=True,
    headers={},
    proxy=False,
    api_key=API_KEY,
    monitor_id=MONITOR_ID)


def load_mock_response(file_name: str) -> dict:
    data_path = os.path.normpath(os.path.join(os.path.dirname(__file__), "test_data", file_name))
    with open(data_path, encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


def test_fetch_incidents(requests_mock):
    mock_data = load_mock_response('fetch_incidents_info.json')
    fetch_incidents_response = mock_data.get('FETCH_INCIDENTS_RESPONSE', {})
    fetch_incidents_params = mock_data.get('FETCH_INCIDENTS_PARAMS', {})
    fetch_incidents_results = mock_data.get('FETCH_INCIDENTS_RESULTS', {})

    api = integration.FETCH_INCIDENTS_API.format(
        MONITOR_ID=MONITOR_ID,
        API_KEY=API_KEY,
        max_results=fetch_incidents_params.get('max_results', 0))

    url = f'{integration.BASE_URL}/{api}'
    requests_mock.post(url, json=fetch_incidents_response)
    next_run, incidents = integration.fetch_incidents(
        CLIENT,
        max_results=fetch_incidents_params.get('max_results', 0),
        last_run=fetch_incidents_params.get('last_run', {}),
        first_fetch_time=fetch_incidents_params.get('first_fetch_time', 0),
        incident_types=fetch_incidents_params.get('incident_types', []))

    assert next_run == fetch_incidents_results.get('next_run')
    assert len(incidents) == len(fetch_incidents_results.get('incidents', [])) == 1
    assert isinstance(incidents, list) == isinstance(fetch_incidents_results.get('incidents', []), list)
    assert incidents[0]["name"] == fetch_incidents_results.get('incidents', [])[0]["name"]
    assert incidents[0]["occurred"] == fetch_incidents_results.get('incidents', [])[0]["occurred"]
    assert json.loads(incidents[0]["rawJSON"]) == fetch_incidents_results.get('incidents', [])[0]["rawJSON"]


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


def test_parse_email_enrichment_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_EMAIL_ENRICHMENT_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_email_enrichment_markdown_table(args.get('DATA', {}))

    assert results == tuple(return_value)


def test_parse_leaked_credentials_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_LEAKED_CREDENTIALS_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_leaked_credentials_markdown_table(args.get('ITEMS', {}), args.get('SUB_TYPE', 0))

    assert results == return_value


def test_parse_botnets_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_BOTNETS_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_botnets_markdown_table(args.get('ITEMS', {}), args.get('SUB_TYPE', 0))

    assert results == return_value


def test_parse_network_vulnerabilities_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_NETWORK_VULNERABILITIES_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_network_vulnerabilities_markdown_table(args.get('ITEMS', {}), args.get('SUB_TYPE', 0))

    assert results == return_value


def test_parse_credit_cards_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_CREDIT_CARDS_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_credit_cards_markdown_table(args.get('ITEMS', {}), args.get('SUB_TYPE', 0))

    assert results == return_value


def test_parse_hacking_discussions_markdown_table():
    mock_data = load_mock_response('helper_functions_info.json').get('PARSE_HACKING_DISCUSSIONS_MARKDOWN_TABLE', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.parse_hacking_discussions_markdown_table(args.get('ITEMS', {}), args.get('AGGR', {}))

    assert results == return_value


def test_extract_available_data_from_item():
    mock_data = load_mock_response('helper_functions_info.json').get('EXTRACT_AVAILABLE_DATA_FROM_ITEM', {})
    args = mock_data.get("ARGS", {})
    return_value = mock_data.get("RETURN_VALUE", [])
    results = integration.extract_available_data_from_item(args.get('ITEM', {}))

    assert results == tuple(return_value)
