import pytest

from CarbonBlackEndpointStandardV3 import *
from freezegun import freeze_time


API_SECRET_KEY = "api_secret_key"
API_KEY = "api_key"
POLICY_API_KEY = "policy_api_key"
POLICY_API_SECRET_KEY = "policy_api_secret_key"
ORGANIZATION_KEY = "organization_key"

HEADERS = {'X-Auth-Token': f'{API_SECRET_KEY}/{API_KEY}', 'Content-Type': 'application/json'}
POLICY_HEADERS = {'X-Auth-Token': f'{POLICY_API_SECRET_KEY}/{POLICY_API_KEY}',
                  'Content-Type': 'application/json'}


@pytest.fixture
def mock_client():
    return Client(
        base_url='example.com',
        verify=False,
        proxies=1234,
        api_secret_key=API_SECRET_KEY,
        api_key=API_KEY,
        policy_api_key=POLICY_API_KEY,
        policy_api_secret_key=POLICY_API_SECRET_KEY,
        organization_key=ORGANIZATION_KEY
    )


@pytest.mark.parametrize(
    "params, client_setup, expected",
    [
        (
            {"isFetch": True, "min_severity": 2, "policy_id": "policy", "device_username": "user",
             "device_id": "device", "type": "type", "query": "query"},
            {"api_key": None, "api_secret_key": None, "policy_api_key": None, "policy_api_secret_key": None},
            'To fetch incidents you must fill the following parameters: Custom API key, '
            'Custom API secret key and Organization key.'
        ),
        (
            {"isFetch": True, "min_severity": 2, "policy_id": "policy", "device_username": "user",
             "device_id": "device", "type": "type", "query": "query"},
            {"api_key": "api_key", "api_secret_key": "api_secret_key", "policy_api_key": None, "policy_api_secret_key": None},
            'ok'
        ),
        (
            {"isFetch": False},
            {"api_key": "api_key", "api_secret_key": None, "policy_api_key": None, "policy_api_secret_key": None},
            'Missing custom API parameters. Please fill all the relevant parameters: Custom API key, '
            'Custom API secret key and Organization key.'
        ),
        (
            {"isFetch": False},
            {"api_key": None, "api_secret_key": None, "policy_api_key": "policy_api_key",
             "policy_api_secret_key": "policy_api_secret_key"},
            'ok'
        ),
        (
            {"isFetch": False},
            {"api_key": None, "api_secret_key": None, "policy_api_key": "policy_api_key", "policy_api_secret_key": None},
            'Missing API parameters. Please fill all the relevant parameters: API key, API secret key and Organization key.'
        ),
    ]
)
def test_module_test_command(mocker, mock_client, params, client_setup, expected):
    mock_client.api_key = client_setup["api_key"]
    mock_client.api_secret_key = client_setup["api_secret_key"]
    mock_client.policy_api_key = client_setup["policy_api_key"]
    mock_client.policy_api_secret_key = client_setup["policy_api_secret_key"]

    mock_client.module_test_request = mocker.MagicMock()
    mock_client.search_alerts_request = mocker.MagicMock()
    mock_client.policy_test_module_request = mocker.MagicMock()

    if expected == 'ok':
        # Simulate successful requests
        mock_client.module_test_request.return_value = None
        mock_client.policy_test_module_request.return_value = None

    result = module_test_command(client=mock_client, params=params)
    assert result == expected


@pytest.mark.parametrize("args", [({'alertId': '1234'})])
def test_get_alerts_details_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})

    get_alert_details_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="GET",
        url_suffix=f"api/alerts/v7/orgs/{ORGANIZATION_KEY}/alerts/{args['alertId']}",
        headers=HEADERS,
    )


@pytest.mark.parametrize("args", [({'reputation': 'NOT_LISTED', 'rows': '3', 'type': 'all', 'policy_id': '1234'})])
def test_alerts_search_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})

    alerts_search_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"api/alerts/v7/orgs/{ORGANIZATION_KEY}/alerts/_search",
        headers=HEADERS,
        json_data={
            'criteria': {
                'device_policy_id': ['1234'],
                'process_reputation': ['NOT_LISTED'],
            },
            'rows': 3
        },
    )


@pytest.mark.parametrize("args, last_run, mock_results", [
    (
        {'rows': '3', 'type': 'all', 'policy_id': '1234'},
        {'last_fetched_alert_id': ['44', '22'], 'last_fetched_alert_create_time': "2024-07-13T19:16:47.495Z"},
        [
            {'id': '44', 'backend_timestamp': "2024-07-13T19:16:47.495Z"},
            {'id': '22', 'backend_timestamp': "2024-07-13T19:16:47.495Z"},
            {'id': '11', 'backend_timestamp': "2024-07-14T19:00:00.000Z"},
            {'id': '12', 'backend_timestamp': "2024-07-14T19:00:00.000Z"},
        ],
    )
])
@freeze_time("2024-07-15 16:35:39")
def test_fetch_incidents(mocker, mock_client, args, last_run, mock_results):
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    http_request = mocker.patch.object(Client, "_http_request", return_value={'results': mock_results})

    now = datetime.utcnow()
    start_time = last_run['last_fetched_alert_create_time']
    end_time = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    next_run, incidents = fetch_incidents(client=mock_client, params=args)

    assert next_run['last_fetched_alert_create_time'] == "2024-07-14T19:00:00.000Z"
    assert next_run['last_fetched_alert_id'] == ['11', '12']
    assert len(incidents) == 2
    assert '11' in incidents[0]['rawJSON']
    assert '12' in incidents[1]['rawJSON']
    http_request.assert_called_with(
        "POST",
        f"api/alerts/v7/orgs/{ORGANIZATION_KEY}/alerts/_search",
        headers=HEADERS,
        json_data={
            'criteria': {
                'device_policy_id': ['1234'],
            },
            'sort': [{'field': 'backend_timestamp', 'order': 'ASC'}],
            'time_range': {'start': start_time, 'end': end_time},
            'rows': 51
        },
    )


@pytest.mark.parametrize("args", [({'policyId': '1234'})])
def test_get_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    get_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="GET",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policyId']}",
        headers=POLICY_HEADERS,
    )


def test_get_policies_summary_command(mocker, mock_client):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    get_policies_summary_command(client=mock_client)

    http_request.assert_called_with(
        method="GET",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/summary",
        headers=POLICY_HEADERS,
    )


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "name": "test4",
                "policy": '{"description": "aaaaaaaa", "priority_level": "MEDIUM", "rules": [],\
                    "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}',
            }
        )
    ],
)
def test_create_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    create_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies",
        headers=POLICY_HEADERS,
        json_data={"name": "test4", "description": "aaaaaaaa", "org_key": "organization_key", "priority_level": "MEDIUM",
                   "rules": [], "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}
    )


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "id": "1234",
                "name": "test4",
                "policy": '{"description": "aaaaaaaa", "priority_level": "MEDIUM", "rules": [],\
                    "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}',
            }
        )
    ],
)
def test_update_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    update_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['id']}",
        headers=POLICY_HEADERS,
        json_data={"id": int(args["id"]), "name": "test4", "description": "aaaaaaaa", "org_key": "organization_key",
                   "priority_level": "MEDIUM", "rules": [], "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}
    )


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "policy": "1234",
                "keyValue": '{"name": "test4", "description": "aaaaaaaa", "priority_level": "MEDIUM", "rules": [],\
                    "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}',
            }
        )
    ],
)
def test_set_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    set_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policy']}",
        headers=POLICY_HEADERS,
        json_data={"id": int(args["policy"]), "name": "test4", "description": "aaaaaaaa", "org_key": "organization_key",
                   "priority_level": "MEDIUM", "rules": [], "sensor_settings": [{"name": "ALLOW_UNINSTALL", "value": "true"}]}
    )


@pytest.mark.parametrize("args", [({'policyId': '1234'})])
def test_delete_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"id": "1234"})

    delete_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="DELETE",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policyId']}",
        headers=POLICY_HEADERS,
        return_empty_response=True
    )


@pytest.mark.parametrize("args", [({'action': 'IGNORE', 'operation': 'RANSOM', 'policyId': '1234',
                                    'required': 'false', 'type': 'NAME_PATH', 'value': 'COMMON_WHITE_LIST'})])
def test_add_rule_to_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})
    mocker.patch("CarbonBlackEndpointStandardV3.get_policy_command", return_value={"id": "1234"})

    add_rule_to_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policyId']}/rules",
        headers=POLICY_HEADERS,
        json_data={
            'action': 'IGNORE',
            'operation': 'RANSOM',
            'required': False,
            'application': {
                'type': 'NAME_PATH',
                'value': 'COMMON_WHITE_LIST'
            }
        },
    )


@pytest.mark.parametrize("args", [({'id': '1111', 'action': 'IGNORE', 'operation': 'RANSOM', 'policyId': '1234',
                                    'required': 'false', 'type': 'NAME_PATH', 'value': 'COMMON_WHITE_LIST'})])
def test_update_rule_in_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})
    mocker.patch("CarbonBlackEndpointStandardV3.get_policy_command", return_value={"id": "1234"})

    update_rule_in_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policyId']}/rules/{args['id']}",
        headers=POLICY_HEADERS,
        json_data={
            'id': int(args['id']),
            'action': 'IGNORE',
            'operation': 'RANSOM',
            'required': False,
            'application': {
                'type': 'NAME_PATH',
                'value': 'COMMON_WHITE_LIST'
            }
        },
    )


@pytest.mark.parametrize("args", [({'ruleId': '1111', 'policyId': '1234'})])
def test_delete_rule_from_policy_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})

    delete_rule_from_policy_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="DELETE",
        url_suffix=f"policyservice/v1/orgs/{ORGANIZATION_KEY}/policies/{args['policyId']}/rules/{args['ruleId']}",
        headers=POLICY_HEADERS,
        return_empty_response=True
    )


@pytest.mark.parametrize(
    "args", [
        (
            {
                'device_timestamp': '1970-01-01T00:00:00.000Z',
                'alert_category': 'THREAT',
                'rows': '6',
                'device_name': 'Win7x64',
                "polling": "true"
            }
        ),
    ]
)
def test_find_processes_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"job_id": "abc123"})

    find_processes_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"api/investigate/v2/orgs/{ORGANIZATION_KEY}/processes/search_jobs",
        headers=HEADERS,
        json_data={
            'criteria': {
                'alert_category': ['THREAT'],
                'device_name': ['Win7x64'],
                'backend_timestamp': ['1970-01-01T00:00:00.000Z'],
            },
            'rows': 6
        }
    )


@pytest.mark.parametrize("args", [({'event_ids': '1234', "polling": "true"}), ({'observation_ids': '1234', "polling": "true"})])
def test_find_observation_details_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"job_id": "abc123"})

    find_observation_details_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"api/investigate/v2/orgs/{ORGANIZATION_KEY}/observations/detail_jobs",
        headers=HEADERS,
        json_data={
            'observation_ids': ['1234'],
        },
    )


@pytest.mark.parametrize(
    "args", [
        (
            {
                'device_timestamp': '1970-01-01T00:00:00.000Z',
                'alert_category': 'THREAT',
                'rows': '6',
                'device_name': 'Win7x64',
                "polling": "true"
            }
        ),
    ]
)
def test_find_observation_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={"job_id": "abc123"})

    find_observation_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"api/investigate/v2/orgs/{ORGANIZATION_KEY}/observations/search_jobs",
        headers=HEADERS,
        json_data={
            'criteria': {
                'alert_category': ['THREAT'],
                'device_name': ['Win7x64'],
                'backend_timestamp': ['1970-01-01T00:00:00.000Z'],
            },
            'rows': 6
        }
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_quarantine_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_quarantine_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'QUARANTINE',
            "device_id": ['1234'],
            "options": {"toggle": "ON"}
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_unquarantine_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_unquarantine_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'QUARANTINE',
            "device_id": ['1234'],
            "options": {"toggle": "OFF"}
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_background_scan_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_background_scan_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'BACKGROUND_SCAN',
            "device_id": ['1234'],
            "options": {"toggle": "ON"},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_background_scan_stop_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_background_scan_stop_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'BACKGROUND_SCAN',
            "device_id": ['1234'],
            "options": {"toggle": "OFF"},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_bypass_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_bypass_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'BYPASS',
            "device_id": ['1234'],
            "options": {"toggle": "ON"},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234'})])
def test_device_unbypass_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_unbypass_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'BYPASS',
            "device_id": ['1234'],
            "options": {"toggle": "OFF"},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234', 'policy_id': '9876'})])
def test_device_policy_update_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_policy_update_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'UPDATE_POLICY',
            "device_id": ['1234'],
            "options": {"policy_id": '9876'},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234', 'sensor_version': '{\"XP\":\"1.2.3.4\"}'})])
def test_device_update_sensor_version_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value='')

    device_update_sensor_version_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/device_actions",
        headers=HEADERS,
        json_data={
            "action_type": 'UPDATE_SENSOR_VERSION',
            "device_id": ['1234'],
            "options": {"sensor_version": {'XP': '1.2.3.4'}},
        },
        resp_type='text'
    )


@pytest.mark.parametrize("args", [({'device_id': '1234', 'rows': '5', 'os': 'LINUX', 'target_priority': 'LOW',
                                    'status': 'REGISTERED', 'start_time': '2021-01-27T12:43:26.243Z',
                                    'end_time': '2021-02-27T12:43:26.243Z'})])
def test_device_search_command(mocker, mock_client, args):
    http_request = mocker.patch.object(Client, "_http_request", return_value={})

    device_search_command(client=mock_client, args=args)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"appservices/v6/orgs/{ORGANIZATION_KEY}/devices/_search",
        headers=HEADERS,
        json_data={
            'criteria': {
                'id': ['1234'],
                'status': ['REGISTERED'],
                'os': ['LINUX'],
                'last_contact_time': {'start': '2021-01-27T12:43:26.243Z', 'end': '2021-02-27T12:43:26.243Z'},
                'target_priority': ['LOW']
            },
            'rows': 5
        },
    )


@pytest.mark.parametrize("request_body, expected_exception", [
    ({"alert_id": "alert123"}, None),
    ({"observation_ids": ["obs1", "obs2"]}, None),
    ({"process_hash": "hash123"}, None),
    ({"process_hash": "hash123", "device_id": 1}, None),
    ({"process_hash": "hash123", "count_unique_devices": True}, None),
    ({"alert_id": "alert123", "observation_ids": ["obs1", "obs2"]}, ValueError),
    ({"alert_id": "alert123", "process_hash": "hash123"}, ValueError),
    ({"observation_ids": ["obs1", "obs2"], "device_id": 1}, ValueError),
    ({"process_hash": "hash123", "device_id": 1, "count_unique_devices": True}, ValueError),
    ({}, ValueError),
    ({"alert_id": "alert123", "max_rows": 10}, ValueError),
    ({"observation_ids": ["obs1", "obs2"], "max_rows": 10}, ValueError),
    ({"process_hash": "hash123", "max_rows": 10}, None)
])
def test_validate_observation_details_request_body(request_body, expected_exception):
    if expected_exception:
        with pytest.raises(expected_exception):
            validate_observation_details_request_body(request_body)
    else:
        validate_observation_details_request_body(request_body)


@pytest.mark.parametrize("args, expected", [
    ({'process_name': 'C:\\Program'}, {'process_name': 'C:\\\\Program'}),
    ({'parent_name': 'C:\\Windows\\System32'}, {'parent_name': 'C:\\\\Windows\\\\System32'}),
    ({'device_name': 'D:\\Device\\Name'}, {'device_name': 'D:\\\\Device\\\\Name'}),
    ({'process_cmdline': 'E:\\Cmdline\\Args'}, {'process_cmdline': 'E:\\\\Cmdline\\\\Args'}),
    ({'process_username': 'F:\\Username\\Path'}, {'process_username': 'F:\\\\Username\\\\Path'}),
    ({'process_name': 'C:\\Path\\To\\App', 'parent_name': 'D:\\Parent\\Path'},
     {'process_name': 'C:\\\\Path\\\\To\\\\App', 'parent_name': 'D:\\\\Parent\\\\Path'}),
    ({'unrelated_field': 'G:\\Unrelated\\Path'}, {'unrelated_field': 'G:\\Unrelated\\Path'})
])
def test_fixe_winds_path(args, expected):
    fixe_winds_path(args)
    assert args == expected


@pytest.mark.parametrize("response, expected", [
    ({'id': 1, 'name': 'Policy1', 'description': 'Test policy',
      'priority_level': 'high', 'version': 'v1', 'extra': 'extra_field'},
     {'id': 1, 'name': 'Policy1', 'description': 'Test policy',
      'priorityLevel': 'high', 'version': 'v1', 'policy': {'extra': 'extra_field'}}),
    ({'id': 2, 'priority_level': 'medium', 'extra': 'extra_field'},
     {'id': 2, 'priorityLevel': 'medium', 'policy': {'extra': 'extra_field'}}),
    ({'id': 3, 'name': 'Policy3'},
     {'id': 3, 'name': 'Policy3'})
])
def test_format_policy_response(response, expected):
    result = format_policy_response(response)
    assert result == expected
