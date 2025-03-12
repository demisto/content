"""Test File for RubrikPolaris Integration."""
import json
import time

import pytest
import os
from CommonServerPython import remove_empty_elements
from RubrikPolaris import ERROR_MESSAGES, MAXIMUM_PAGINATION_LIMIT, OUTPUT_PREFIX, MESSAGES, \
    TOKEN_EXPIRY_TIME_SPAN, TOKEN_EXPIRY_BUFFER_TIME, IOC_TYPE_ENUM
from unittest.mock import patch

BASE_URL = "https://demo.my.rubrik.com/api"
BASE_URL_GRAPHQL = BASE_URL + "/graphql"
BASE_URL_SESSION = BASE_URL + "/session"
last_fetch = "2021-10-22T14:55:51.616000Z"
first_fetch = "2021-10-22T14:55:51.616Z"
sonar_on_demand_file_path = "test_data/sonar_ondemand_scan_success_response.json"
enum_values_file_path = "test_data/enum_values.json"
mock_command = 'demistomock.command'
mock_params = 'demistomock.params'

MOCK_INTEGRATION_CONTEXT = {
    'api_token': "dummy_token",
    'valid_until': int(time.time()) + TOKEN_EXPIRY_TIME_SPAN - TOKEN_EXPIRY_BUFFER_TIME
}

SDK_ERROR_MESSAGES = {
    'INVALID_SLA_LIST_OBJECT_TYPE': "'{}' is an invalid value for 'object types'. "
                                    "Value must be in ['UNKNOWN_OBJECT_TYPE', 'SAP_HANA_OBJECT_TYPE', "
                                    "'AWS_EC2_EBS_OBJECT_TYPE', 'AWS_RDS_OBJECT_TYPE', 'AZURE_OBJECT_TYPE', "
                                    "'GCP_OBJECT_TYPE', 'O365_OBJECT_TYPE', 'VSPHERE_OBJECT_TYPE', "
                                    "'KUPR_OBJECT_TYPE', 'FILESET_OBJECT_TYPE', 'CASSANDRA_OBJECT_TYPE', "
                                    "'VOLUME_GROUP_OBJECT_TYPE', 'MSSQL_OBJECT_TYPE', "
                                    "'AZURE_SQL_DATABASE_OBJECT_TYPE', 'AZURE_SQL_MANAGED_INSTANCE_OBJECT_TYPE'].",
    'INVALID_SORT_ORDER': "'{}' is an invalid value for 'sort_order'. Value must be in ['ASC', 'DESC'].",
    'INVALID_OBJECT_SNAPSHOT_SORT_ORDER': "'{}' is an invalid value for 'sort_order'. "
                                          "Value must be in ['ASC', 'DESC'].",
    'INVALID_REQUESTED_HASH_TYPE': "'{}' is an invalid value for 'requested_hash_types'. "
                                   "Value must be in ['HASH_TYPE_M_D5', 'HASH_TYPE_SH_A1', 'HASH_TYPE_SH_A256']."
}


def util_load_json(path):
    """Load file in JSON format."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text_data(path: str) -> str:
    """Load a text file."""
    with open(path, encoding='utf-8') as f:
        return f.read()


def test_main_incorrect_credentials(requests_mock, monkeypatch, capfd, caplog):
    """Tests the execution of main function when incorrect credentials are provided."""
    from RubrikPolaris import main
    monkeypatch.setattr(mock_params, lambda: {
        "url": "demo",
        "email": {
            "identifier": "incorrect@account.com",
            "password": "password"

        }})
    monkeypatch.setattr(mock_command, lambda: "rubrik-sonar-policy-analyzer-groups-list")
    monkeypatch.setattr('demistomock.args', dict)
    response_data = {
        "code": 401,
        "uri": "/api/session",
        "traceSpan": {
            "traceId": "dummy-trace",
            "operation": "/api/session",
            "spanId": "qi0QREAFDyE="
        },
        "message": "UNAUTHENTICATED: wrong username or password"
    }
    requests_mock.post(BASE_URL_SESSION, json=response_data)
    with pytest.raises(SystemExit):
        caplog.set_level(50)
        capfd.close()
        main()


def test_main_unknown_commmand(requests_mock, monkeypatch, capfd):
    """Tests the execution of main function when unknown command name is provided."""
    from RubrikPolaris import main
    monkeypatch.setattr(mock_params, lambda: {
        "url": "demo",
        "email": {
            "identifier": "username@domain.com",
            "password": "password"

        }})
    monkeypatch.setattr(mock_command, lambda: "unknown_command")
    response_data = {
        "access_token": "",
        "mfa_token": "dummy_token"
    }
    requests_mock.post(BASE_URL_SESSION, json=response_data)
    with pytest.raises(SystemExit):
        capfd.close()
        main()


def test_main_no_json_no_email(monkeypatch, capfd):
    """Tests the execution of main function when neither service account json nor email-password have been provided."""
    from RubrikPolaris import main
    monkeypatch.setattr(mock_params, lambda: {
        "url": "demo"})
    monkeypatch.setattr(mock_command, lambda: "some_command")
    with pytest.raises(SystemExit):
        capfd.close()
        main()


@pytest.mark.parametrize("service_account_json", ['{', '{"client_id":}', '{"client_id"=""}',
                                                  '{"client_id": "client", "name": "name","client_secret": "secret"}'])
def test_main_incorrect_json_structure(monkeypatch, capfd, service_account_json, caplog):
    """Tests the execution of main function when incorrectly formatted service account json is provided."""
    from RubrikPolaris import main
    monkeypatch.setattr(mock_params, lambda: {
        "url": "demo",
        "service_account_json": service_account_json})

    monkeypatch.setattr(mock_command, lambda: "some_command")
    with pytest.raises(SystemExit):
        capfd.close()
        caplog.set_level(50)
        main()


@pytest.fixture()
def client(requests_mock, capfd):
    """Client fixture."""
    from RubrikPolaris import MyClient
    data = {
        "access_token": "dummy_token",
        "mfa_token": "dummy_token"
    }
    requests_mock.post(BASE_URL_SESSION, json=data)
    capfd.close()
    client_obj = MyClient(
        domain="demo",
        username="dummy_username",
        password="dummy_password",
        insecure=True
    )
    return client_obj


def test_test_module_for_correct_params(client, monkeypatch, requests_mock):
    """Test test_module function when correct parameters are passed."""
    from RubrikPolaris import test_module
    params = {
        "isFetch": True,
        "max_fetch": "30",
        "first_fetch": "3 days"
    }
    list_policies_response = {
        "data": {
        }
    }
    fetch_data_response = {
        "data": {
        }
    }

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': list_policies_response},
        {'json': enum_values.get('activity_type_enum')},
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')},
        {'json': fetch_data_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    assert test_module(client, params) == 'ok'


@pytest.mark.parametrize("max_fetch, first_fetch", [("-1", "3 days"), ("20", "abc")])
def test_test_module_for_incorrect_params(client, monkeypatch, requests_mock, max_fetch, first_fetch):
    """Test test_module function to raise ValueError with appropriate message when incorrect parameters are passed."""
    from RubrikPolaris import test_module
    params = {
        "isFetch": True,
        "max_fetch": max_fetch,
        "first_fetch": first_fetch
    }
    list_policies_response = {
        "data": {
        }
    }
    requests_mock.post(BASE_URL_GRAPHQL, json=list_policies_response)

    with pytest.raises(ValueError):
        test_module(client, params)


@pytest.mark.parametrize("integration_context", [
    ({}),
    ({'api_token': "dummy_token"}),
    ({'api_token': "dummy_token", 'valid_until': time.time() - 1})
])
@patch('demistomock.getIntegrationContext')
def test_get_api_token_when_not_found_in_integration_context(mocker_get_context, client,
                                                             integration_context):
    """Test cases for scenario when there is no api_token or valid_until in integration context."""
    mocker_get_context.return_value = integration_context

    api_token = client.get_api_token()

    assert not api_token


@patch('demistomock.getIntegrationContext')
def test_get_api_token_when_found_in_integration_context(mocker_get_context, client):
    """Test cases for scenario when there is api_token and valid_until in integration context."""
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT

    api_token = client.get_api_token()

    assert api_token == "dummy_token"
    assert mocker_get_context.call_count == 1


def test_fetch_incidents_success_without_last_run(client, requests_mock):
    """Test fetch_incidents function to return incidents and new last run with provided empty last run."""
    from RubrikPolaris import fetch_incidents
    fetch_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/fetch_incidents_success_response.json"))
    incidents = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/fetch_incidents_success_incidents.json"))
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('activity_type_enum')},
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')},
        {'json': fetch_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    fetch_incidents_last_run, fetch_incidents_incidents = fetch_incidents(client, {},
                                                                          {"first_fetch": f"{first_fetch}",
                                                                           "max_fetch": 2})
    last_run = {'last_fetch': f'{last_fetch}',
                'next_page_token':
                    fetch_response["data"]["activitySeriesConnection"]["pageInfo"]["endCursor"]}
    assert fetch_incidents_last_run == last_run
    assert fetch_incidents_incidents == incidents


def test_fetch_incidents_success_with_last_run(client, requests_mock):
    """Test fetch_incidents function to return incidents and new last run with a provided last run."""
    from RubrikPolaris import fetch_incidents
    fetch_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/fetch_incidents_success_response.json"))
    incidents = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/fetch_incidents_success_incidents.json"))
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('activity_type_enum')},
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')},
        {'json': fetch_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    fetch_incidents_last_run, fetch_incidents_incidents = fetch_incidents(client,
                                                                          {"last_fetch": f"{last_fetch}",
                                                                           "next_page_token": "dummy-token"},
                                                                          {"first_fetch": f"{first_fetch}",
                                                                           "max_fetch": 2})

    last_run = {'last_fetch': f'{last_fetch}',
                'next_page_token':
                    fetch_response["data"]["activitySeriesConnection"]["pageInfo"]["endCursor"]}
    assert fetch_incidents_last_run == last_run
    assert fetch_incidents_incidents == incidents


def test_fetch_incidents_empty_response_without_last_run(client, requests_mock):
    """Test fetch_incidents function to return empty incidents and new last run without a provided last run."""
    from RubrikPolaris import fetch_incidents

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    fetch_incidents_empty_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                 "test_data/fetch_incidents_empty_response.json"))
    responses = [
        {'json': enum_values.get('activity_type_enum')},
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')},
        {'json': fetch_incidents_empty_response}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    fetch_incidents_last_run, fetch_incidents_incidents = fetch_incidents(client, {},
                                                                          {"first_fetch": f"{first_fetch}",
                                                                           "max_fetch": 2})
    last_run = {'last_fetch': f'{last_fetch}'}
    assert fetch_incidents_last_run == last_run
    assert fetch_incidents_incidents == []


def test_fetch_incidents_empty_response_with_last_run(client, requests_mock):
    """Test fetch_incidents function to return empty incidents and new last run with a provided last run."""
    from RubrikPolaris import fetch_incidents

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    fetch_incidents_empty_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                 "test_data/fetch_incidents_empty_response.json"))
    responses = [
        {'json': enum_values.get('activity_type_enum')},
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')},
        {'json': fetch_incidents_empty_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    fetch_incidents_last_run, fetch_incidents_incidents = fetch_incidents(client,
                                                                          {"last_fetch": f"{last_fetch}",
                                                                           "next_page_token": "dummy-token"},
                                                                          {"first_fetch": f"{first_fetch}",
                                                                           "max_fetch": 2})

    last_run = {'last_fetch': f'{last_fetch}',
                'next_page_token': 'dummy-token'}
    assert fetch_incidents_last_run == last_run
    assert fetch_incidents_incidents == []


def test_object_search_success(client, requests_mock):
    """Tests success for rubrik_polaris_object_search."""
    from RubrikPolaris import rubrik_polaris_object_search_command

    args = {
        "object_name": "admin"
    }

    object_search_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                         "test_data/object_search_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/object_search_hr1.md")) as f:
        object_search_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': object_search_response.get('raw_response')}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    response = rubrik_polaris_object_search_command(client, args)

    assert response.raw_response == object_search_response.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["GLOBAL_SEARCH"]}(val.id == obj.id)') \
        == remove_empty_elements(object_search_response.get('outputs'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_GLOBAL_SEARCH"]}(val.name == obj.name)') \
        == remove_empty_elements(object_search_response.get('page_token'))
    assert response.readable_output == object_search_response_hr


def test_object_search_with_token_hr_success(client, requests_mock):
    """Tests success for hr with next token for rubrik_polaris_object_search."""
    from RubrikPolaris import rubrik_polaris_object_search_command

    args = {
        "object_name": "admin",
        "limit": 2
    }

    object_search_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                         "test_data/object_search_response2.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/object_search_hr2.md")) as f:
        object_search_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': object_search_response.get('raw_response')}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    response = rubrik_polaris_object_search_command(client, args)

    assert response.raw_response == object_search_response.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["GLOBAL_SEARCH"]}(val.id == obj.id)') \
        == remove_empty_elements(object_search_response.get('outputs'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_GLOBAL_SEARCH"]}(val.name == obj.name)') \
        == remove_empty_elements(object_search_response.get('page_token'))
    assert response.readable_output == object_search_response_hr


@pytest.mark.parametrize("args, exception, error", [
    ({"object_name": ""}, ValueError, ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format("object_name")),
    ({"object_name": "abc", "limit": "ab"}, ValueError, '"ab" is not a valid number'),
    ({"object_name": "abc", "limit": 1001}, ValueError, ERROR_MESSAGES['INVALID_LIMIT'].format("1001")),
    ({"object_name": "abc", "limit": -1}, ValueError, ERROR_MESSAGES['INVALID_LIMIT'].format("-1"))
])
def test_object_search_arguments_failure(client, requests_mock, args, exception, error):
    """Tests failure for rubrik_polaris_object_search."""
    from RubrikPolaris import rubrik_polaris_object_search_command

    response = {"data": {}}
    requests_mock.post(BASE_URL_GRAPHQL, json=response)

    with pytest.raises(exception) as e:
        rubrik_polaris_object_search_command(client, args)

    assert str(e.value) == error


def test_sonar_policies_list_when_empty_response(client, requests_mock):
    """Tests rubrik_sonar_policies_list when empty response is returned."""
    from RubrikPolaris import rubrik_sonar_policies_list_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/sonar_policies_list_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)

    list_policies_command_results = rubrik_sonar_policies_list_command(client, {})

    assert list_policies_command_results.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("sonar policies")
    assert list_policies_command_results.outputs is None


def test_sonar_policies_list_success(client, requests_mock):
    """Tests rubrik_sonar_policies_list when response is not empty."""
    from RubrikPolaris import rubrik_sonar_policies_list_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/sonar_policies_list_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_policies_list_success_hr.md")) as f:
        sonar_policies_list_hr = f.read()

    sonar_policies_list_outputs = util_load_json(os.path.join(os.path.dirname(__file__),
                                                              'test_data/sonar_policies_list_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)

    list_policies_command_results = rubrik_sonar_policies_list_command(client, {})

    assert list_policies_command_results.raw_response == raw_response
    assert list_policies_command_results.readable_output == sonar_policies_list_hr
    assert list_policies_command_results.outputs == sonar_policies_list_outputs


def test_sonar_policy_analyzer_groups_list_when_empty_response(client, requests_mock):
    """Tests rubrik_sonar_policy_analyzer_groups_list_command when empty response is returned."""
    from RubrikPolaris import rubrik_sonar_policy_analyzer_groups_list_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/sonar_policy_analyzer_groups_list_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)

    list_policy_analyzer_groups_command_results = rubrik_sonar_policy_analyzer_groups_list_command(client, {})

    assert list_policy_analyzer_groups_command_results.readable_output == MESSAGES["NO_RECORDS_FOUND"] \
        .format("sonar policy analyzer groups")
    assert list_policy_analyzer_groups_command_results.outputs is None


def test_sonar_policy_analyzer_groups_list_success(client, requests_mock):
    """Tests rubrik_sonar_policy_analyzer_groups_list_command when response is not empty."""
    from RubrikPolaris import rubrik_sonar_policy_analyzer_groups_list_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/sonar_policy_analyzer_groups_list_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_policy_analyzer_groups_list_success_hr.md")) as f:
        sonar_policy_analyzer_groups_list_hr = f.read()

    sonar_policy_analyzer_groups_list_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/sonar_policy_analyzer_groups_list_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)

    list_policy_analyzer_groups_command_results = rubrik_sonar_policy_analyzer_groups_list_command(client, {})

    assert list_policy_analyzer_groups_command_results.raw_response == raw_response
    assert list_policy_analyzer_groups_command_results.readable_output == sonar_policy_analyzer_groups_list_hr
    assert list_policy_analyzer_groups_command_results.outputs == sonar_policy_analyzer_groups_list_outputs


@pytest.mark.parametrize("response", [
    "empty_response", "raw_response"
])
def test_vm_object_metadata_when_valid_response_is_returned(client, requests_mock, response):
    """Tests success for rubrik_polaris_vm_object_metadata_get."""
    from RubrikPolaris import rubrik_polaris_vm_object_metadata_get_command

    args = {"object_id": "e060116b-f9dc-56a1-82a6-1b968d2f6cef"}

    data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       "test_data/vm_object_metadata_get.json"))

    requests_mock.post(BASE_URL_GRAPHQL, json=data.get(f"{response}"))
    object_response = rubrik_polaris_vm_object_metadata_get_command(client, args)

    if response == "empty_response":
        assert object_response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("vm object metadata")
    else:
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               "test_data/vm_object_metadata_get.md")) as f:
            object_response_hr = f.read()

        assert object_response.raw_response == data.get('raw_response')
        assert object_response.outputs == remove_empty_elements(data.get('outputs'))
        assert object_response.readable_output == object_response_hr


@pytest.mark.parametrize("args", [
    {"object_id": ""}
])
def test_vm_object_metadata_invalid_object_id(client, requests_mock, args):
    """Tests incorrect object_id for rubrik_polaris_vm_object_metadata_get."""
    from RubrikPolaris import rubrik_polaris_vm_object_metadata_get_command

    response = {"data": {}}
    requests_mock.post(BASE_URL_GRAPHQL, json=response)

    with pytest.raises(ValueError) as e:
        rubrik_polaris_vm_object_metadata_get_command(client, args)

    assert str(e.value) == ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')


def test_vm_objects_list_success(client, requests_mock):
    """Tests success for rubrik_polaris_vm_objects_list."""
    from RubrikPolaris import rubrik_polaris_vm_objects_list_command

    objects_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                        "test_data/objects_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/objects_list_hr.md")) as f:
        objects_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': objects_list_response.get('raw_response')}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    response = rubrik_polaris_vm_objects_list_command(client, args={"limit": 2})

    assert response.raw_response == objects_list_response.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["VM_OBJECT"]}(val.id == obj.id)') \
        == remove_empty_elements(objects_list_response.get('outputs'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_VM_OBJECT"]}(val.name == obj.name)') \
        == remove_empty_elements(objects_list_response.get('page_token'))
    assert response.readable_output == objects_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"is_relic": "a"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("a", "is_relic")),
    ({"is_replicated": "tr"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("tr", "is_replicated")),
    ({"limit": "a"}, "\"a\" is not a valid number"),
    ({"limit": 1001}, ERROR_MESSAGES['INVALID_LIMIT'].format("1001"))
])
def test_vm_objects_list_when_invalid_arguments_are_provided(client, requests_mock, args, error):
    """Tests invalid arguments for rubrik_polaris_vm_objects_list."""
    from RubrikPolaris import rubrik_polaris_vm_objects_list_command

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    with pytest.raises(ValueError) as e:
        rubrik_polaris_vm_objects_list_command(client, args=args)
    assert str(e.value) == error


def test_sonar_on_demand_scan_when_success_response(client, requests_mock):
    """Tests rubrik_sonar_ondemand_scan_command when response is success."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               f'{sonar_on_demand_file_path}'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_ondemand_scan_success_hr.md")) as f:
        sonar_ondemand_scan_hr = f.read()

    sonar_on_demand_scan_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/sonar_ondemand_scan_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "scan_name": "dummy",
        "objects_to_scan": "1234-abc, 2345-bcd",
        "sonar_policy_analyzer_groups": '{ "id": 1, "name":"ABC", "groupType":"ABC",'
                                        '"analyzers": [{ "id": 1, "name": "anc", "analyzerType": "xyz"},'
                                        '{"id": 2, "name": "xyz", "analyzerType": "klm"} ]}',
    }
    sonar_on_demand_scan_command_results = rubrik_sonar_ondemand_scan_command(client, args)

    assert sonar_on_demand_scan_command_results.raw_response == raw_response
    assert sonar_on_demand_scan_command_results.readable_output == sonar_ondemand_scan_hr
    assert sonar_on_demand_scan_command_results.outputs == sonar_on_demand_scan_outputs


@pytest.mark.parametrize("objects_to_scan, sonar_policy_analyzer_groups, exception, error",
                         [("", '', ValueError, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("objects_to_scan")),
                          ("1234-abc, 2345-bcd", "", ValueError,
                           ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("sonar_policy_analyzer_groups")),
                          ("1234-abc, 2345-bcd", "{}", ValueError,
                           ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("sonar_policy_analyzer_groups")),
                          ("1234-abc, 2345-bcd", "{", ValueError,
                           ERROR_MESSAGES['JSON_DECODE'].format("sonar_policy_analyzer_groups")),
                          ("1234-abc, 2345-bcd", '[{"id": dummy-id', ValueError,
                           ERROR_MESSAGES['JSON_DECODE'].format("sonar_policy_analyzer_groups")),
                          ("1234-abc, 2345-bcd", '[]', ValueError,
                           ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("sonar_policy_analyzer_groups"))
                          ])
def test_sonar_on_demand_scan_when_invalid_input(client, requests_mock, objects_to_scan, sonar_policy_analyzer_groups,
                                                 exception, error):
    """Tests rubrik_sonar_ondemand_scan_command when invalid inputs are provided."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               f'{sonar_on_demand_file_path}'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "scan_name": "",
        "objects_to_scan": objects_to_scan,
        "sonar_policy_analyzer_groups": sonar_policy_analyzer_groups,
    }

    with pytest.raises(exception) as e:
        rubrik_sonar_ondemand_scan_command(client, args)

    assert str(e.value) == error


def test_sonar_ondemand_scan_when_empty_response(client, requests_mock):
    """Tests rubrik_sonar_ondemand_scan_command when empty response is returned."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/sonar_policy_analyzer_groups_list_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)
    args = {
        "scan_name": "dummy",
        "objects_to_scan": "1234-abc, 2345-bcd",
        "sonar_policy_analyzer_groups": '{ "id": 1, "name":"ABC", "groupType":"ABC",'
                                        '"analyzers": [{ "id": 1, "name": "anc", "analyzerType": "xyz"},'
                                        '{"id": 2, "name": "xyz", "analyzerType": "klm"} ]}',
    }
    sonar_on_demand_scan_command_results = rubrik_sonar_ondemand_scan_command(client, args)

    assert sonar_on_demand_scan_command_results.readable_output == MESSAGES["NO_RESPONSE"]
    assert sonar_on_demand_scan_command_results.outputs is None


@pytest.mark.parametrize("file_suffix", ["complete", "fail", "progress"])
def test_sonar_on_demand_scan_status_when_success_response(client, requests_mock, file_suffix):
    """Tests rubrik_sonar_ondemand_scan_status_command when response is success."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_status_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               f'test_data/sonar_ondemand_scan_status_success'
                                               f'_{file_suffix}_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           f"test_data/sonar_ondemand_scan_status_success_{file_suffix}_hr.md")) as f:
        sonar_ondemand_scan_status_hr = f.read()

    sonar_on_demand_scan_status_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), f'test_data/sonar_ondemand_scan_status_success_{file_suffix}_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "crawl_id": "587d147a-add9-4152-b7a0-5a667d99f395"
    }
    sonar_on_demand_scan_status_command_results = rubrik_sonar_ondemand_scan_status_command(client, args)

    assert sonar_on_demand_scan_status_command_results.raw_response == raw_response
    assert sonar_on_demand_scan_status_command_results.readable_output == sonar_ondemand_scan_status_hr
    assert sonar_on_demand_scan_status_command_results.outputs == sonar_on_demand_scan_status_outputs


@pytest.mark.parametrize("crawl_id, exception, error",
                         [("", ValueError, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("crawl_id")),
                          (None, ValueError, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("crawl_id"))
                          ])
def test_sonar_on_demand_scan_status_when_invalid_input(client, crawl_id,
                                                        exception, error):
    """Tests rubrik_sonar_ondemand_scan_status_command when invalid inputs are provided."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_status_command

    args = {
        "crawl_id": crawl_id,
    }

    with pytest.raises(exception) as e:
        rubrik_sonar_ondemand_scan_status_command(client, args)

    assert str(e.value) == error


def test_sonar_ondemand_scan_status_when_empty_response(client, requests_mock):
    """Tests rubrik_sonar_ondemand_scan_status_command when empty response is returned."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_status_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/sonar_ondemand_scan_status_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)
    args = {
        "crawl_id": "dummy-id"
    }
    sonar_on_demand_scan_status_command_results = rubrik_sonar_ondemand_scan_status_command(client, args)

    assert sonar_on_demand_scan_status_command_results.readable_output == MESSAGES["NO_RESPONSE"]
    assert sonar_on_demand_scan_status_command_results.outputs is None


@pytest.mark.parametrize("crawl_id, file_type, exception, error",
                         [("", "", ValueError, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("crawl_id")),
                          ("dummy_crawl_id", "", ValueError,
                           ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("file_type")),
                          ("dummy_crawl_id", "not_valid_file_type", ValueError,
                           "'not_valid_file_type' is an invalid value for 'file type'. Value must be in "
                           "['ANY', 'HITS', 'STALE', 'OPEN_ACCESS', 'STALE_HITS', 'OPEN_ACCESS_HITS'].")])
def test_sonar_on_demand_scan_result_when_invalid_input(client, requests_mock, crawl_id, file_type, exception, error):
    """Tests rubrik_sonar_ondemand_scan_result_command when response is success."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_result_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               f'{sonar_on_demand_file_path}'))
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('file_count_type_enum')},
        {'json': raw_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    args = {
        "crawl_id": crawl_id,
        "file_type": file_type,
    }

    with pytest.raises(exception) as e:
        rubrik_sonar_ondemand_scan_result_command(client, args)

    assert str(e.value) == error


def test_sonar_ondemand_scan_result_when_empty_response(client, requests_mock):
    """Tests rubrik_sonar_ondemand_scan_result_command when empty response is returned."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_result_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/sonar_ondemand_scan_result_empty_response.json'))

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('file_count_type_enum')},
        {'json': empty_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    args = {
        "crawl_id": "dummy_id",
        "file_type": "HITS",
    }
    sonar_on_demand_scan_result_command_results = rubrik_sonar_ondemand_scan_result_command(client, args)

    assert sonar_on_demand_scan_result_command_results.readable_output == MESSAGES["NO_RESPONSE"]
    assert sonar_on_demand_scan_result_command_results.outputs is None


def test_sonar_on_demand_scan_result_when_success_response(client, requests_mock):
    """Tests rubrik_sonar_ondemand_scan_result_command when response is success."""
    from RubrikPolaris import rubrik_sonar_ondemand_scan_result_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/sonar_ondemand_scan_result_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_ondemand_scan_result_success_hr.md")) as f:
        sonar_ondemand_scan_hr = f.read()

    sonar_on_demand_scan_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/sonar_ondemand_scan_result_success_outputs.json'))

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('file_count_type_enum')},
        {'json': raw_response}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    args = {
        "crawl_id": "dummy_id",
        "file_type": "HITS",
    }
    sonar_on_demand_scan_result_command_results = rubrik_sonar_ondemand_scan_result_command(client, args)

    assert sonar_on_demand_scan_result_command_results.raw_response == raw_response
    assert sonar_on_demand_scan_result_command_results.readable_output == sonar_ondemand_scan_hr
    assert sonar_on_demand_scan_result_command_results.outputs == sonar_on_demand_scan_outputs


@pytest.mark.parametrize("empty_response", [True, False])
def test_vm_object_snapshot_get_success(client, requests_mock, empty_response):
    """Tests success for rubrik_polaris_vm_object_snapshot_get."""
    from RubrikPolaris import rubrik_polaris_vm_object_snapshot_list_command

    object_snapshot_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                           "test_data/vm_object_snapshot_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/vm_object_snapshot_get_hr.md")) as f:
        object_snapshot_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    args = {"object_id": "dummy_id", "start_date": "2020-03-21", "end_date": "2020-06-21", "timezone_offset": "1"}

    if empty_response:
        responses = [
            {'json': enum_values.get('snapshot_group_by_enum')},
            {'json': enum_values.get('missed_snapshot_group_by_enum')},
            {'json': object_snapshot_response.get('empty_response')}
        ]
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_vm_object_snapshot_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vm object snapshots')

    else:
        responses = [
            {'json': enum_values.get('snapshot_group_by_enum')},
            {'json': enum_values.get('missed_snapshot_group_by_enum')},
            {'json': object_snapshot_response.get('raw_response')}
        ]
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_vm_object_snapshot_list_command(client, args=args)

        assert response.raw_response == object_snapshot_response.get('raw_response')
        assert response.outputs == remove_empty_elements(object_snapshot_response.get('outputs'))
        assert response.readable_output == object_snapshot_response_hr


@pytest.mark.parametrize("args, error", [
    ({"object_id": "", "start_date": "tr", "end_date": "tr", "timezone_offset": "1.5"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
    ({"object_id": "dummy_id", "start_date": "", "end_date": "tr", "timezone_offset": "1.5"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('start_date')),
    ({"object_id": "dummy_id", "start_date": "tr", "end_date": "", "timezone_offset": "1.5"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('end_date')),
    ({"object_id": "dummy_id", "start_date": "abc", "end_date": "tr", "timezone_offset": "1.5"},
     '"abc" is not a valid date'),
    ({"object_id": "dummy_id", "start_date": "tr", "end_date": "tr", "timezone_offset": "1.5",
      "cluster_connected": "tr"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format('tr', 'cluster_connected')),
])
def test_vm_object_snapshot_get_when_invalid_arguments_are_provided(client, requests_mock, args, error):
    """Tests invalid arguments for rubrik_polaris_vm_object_snapshot_get."""
    from RubrikPolaris import rubrik_polaris_vm_object_snapshot_list_command

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))

    responses = [
        {'json': enum_values.get('snapshot_group_by_enum')},
        {'json': enum_values.get('missed_snapshot_group_by_enum')}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)

    with pytest.raises(ValueError) as e:
        rubrik_polaris_vm_object_snapshot_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response, download_file", [
    (True, "True"),
    (True, "False"),
    (False, "True"),
    (False, "False")
])
def test_radar_anomaly_csv_analysis_success(client, requests_mock, empty_response, download_file):
    """Tests success for rubrik_radar_anomaly_csv_analysis."""
    from RubrikPolaris import rubrik_radar_anomaly_csv_analysis_command

    radar_anomaly_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                         "test_data/radar_anomaly_csv_analysis_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_anomaly_csv_analysis_hr.md")) as f:
        radar_anomaly_hr = f.read()

    args = {"object_id": "dummy", "cluster_id": "dummy", "snapshot_id": "dummy", "download_file": download_file}

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_anomaly_csv_analysis_file.csv"), 'r') as f:
        file_data = f.read()
    requests_mock.get('https://dummy_link/snapshot_000-000-000.csv', text=file_data, status_code=200)

    if empty_response:
        response = radar_anomaly_response.get('empty_response')
        requests_mock.post(BASE_URL_GRAPHQL, json=response)
        response = rubrik_radar_anomaly_csv_analysis_command(client, args=args)
        assert response[0].readable_output == MESSAGES['NO_RESPONSE']

    else:
        responses = radar_anomaly_response.get('raw_response')
        requests_mock.post(BASE_URL_GRAPHQL, json=responses)
        response = rubrik_radar_anomaly_csv_analysis_command(client, args=args)

        assert response[0].raw_response == radar_anomaly_response.get('raw_response')
        assert response[0].outputs == remove_empty_elements(radar_anomaly_response.get('outputs'))
        assert response[0].readable_output == radar_anomaly_hr
        if download_file == 'True' and isinstance(response[1], dict):
            assert response[1].get('File') == 'snapshot_000-000-000.csv'


@pytest.mark.parametrize("args, error", [
    ({"object_id": "dummy", "cluster_id": "dummy"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('snapshot_id')),
    ({"object_id": "dummy_id", "cluster_id": "", "snapshot_id": "tr"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('cluster_id')),
    ({"object_id": "", "cluster_id": " dummy", "snapshot_id": "dummy"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
])
def test_radar_anomaly_csv_analysis_when_invalid_arguments_are_provided(client, requests_mock, args, error):
    """Tests invalid arguments for rubrik_radar_anomaly_csv_analysis."""
    from RubrikPolaris import rubrik_radar_anomaly_csv_analysis_command

    with pytest.raises(ValueError) as e:
        rubrik_radar_anomaly_csv_analysis_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_sonar_csv_download_success(client, requests_mock, empty_response):
    """Tests success for rubrik_sonar_csv_download."""
    from RubrikPolaris import rubrik_sonar_csv_download_command

    sonar_csv_download_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                              "test_data/sonar_csv_download_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_csv_download_hr.md")) as f:
        sonar_csv_download_hr = f.read()

    args = {"object_id": "dummy", "snapshot_id": "dummy"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=sonar_csv_download_response.get('empty_response'))
        response = rubrik_sonar_csv_download_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RESPONSE"]
    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=sonar_csv_download_response.get('raw_response'))
        response = rubrik_sonar_csv_download_command(client, args=args)
        assert response.raw_response == sonar_csv_download_response.get('raw_response')
        assert response.outputs == remove_empty_elements(sonar_csv_download_response.get('outputs'))
        assert response.readable_output == sonar_csv_download_hr


@pytest.mark.parametrize("args, error", [
    ({"object_id": "dummy"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('snapshot_id')),
    ({"object_id": "", "snapshot_id": "dummy"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
])
def test_sonar_csv_download_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik_sonar_csv_download."""
    from RubrikPolaris import rubrik_sonar_csv_download_command

    with pytest.raises(ValueError) as e:
        rubrik_sonar_csv_download_command(client, args=args)
    assert str(e.value) == error


def test_snapshot_files_list_success(client, requests_mock):
    """Tests rubrik_gps_snapshot_files_list_command when response is not empty."""
    from RubrikPolaris import rubrik_gps_snapshot_files_list_command

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/snapshot_files_list_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/snapshot_files_list_success_hr.md")) as f:
        snapshot_files_list_hr = f.read()

    snapshot_files_list_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/snapshot_files_list_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        'snapshot_id': "90858c2f-e572-5b9c-b455-ba309d50c1a2"
    }
    list_snapshot_files_command_results = rubrik_gps_snapshot_files_list_command(client, args)

    assert list_snapshot_files_command_results.raw_response == raw_response
    assert list_snapshot_files_command_results.readable_output == snapshot_files_list_hr
    assert list_snapshot_files_command_results.outputs == snapshot_files_list_outputs


def test_snapshot_files_list_when_empty_response(client, requests_mock):
    """Tests rubrik_gps_snapshot_files_list_command when empty response is returned."""
    from RubrikPolaris import rubrik_gps_snapshot_files_list_command

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/snapshot_files_list_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)
    args = {
        'snapshot_id': "90858c2f-e572-5b9c-b455-ba309d50c1a2"
    }
    list_snapshot_files_command_results = rubrik_gps_snapshot_files_list_command(client, args)

    assert list_snapshot_files_command_results.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("files")
    assert list_snapshot_files_command_results.outputs is None


@pytest.mark.parametrize("args, error", [
    ({"snapshot_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("snapshot_id")),
    ({"snapshot_id": "1234-5678-9012", "limit": "a"}, "\"a\" is not a valid number"),
    ({"snapshot_id": "1234-5678-9012", "limit": 1001}, ERROR_MESSAGES['INVALID_LIMIT'].format("1001"))

])
def test_snapshot_files_list_when_invalid_arguments_are_provided(client, requests_mock, args, error):
    """Tests rubrik_gps_snapshot_files_list_command when invalid arguments provided."""
    from RubrikPolaris import rubrik_gps_snapshot_files_list_command

    response = {"data": {}}
    requests_mock.post(BASE_URL_GRAPHQL, json=response)

    with pytest.raises(ValueError) as e:
        rubrik_gps_snapshot_files_list_command(client, args)

    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_vm_export_success(client, requests_mock, empty_response):
    """Tests success for rubrik-gps-vm-export."""
    from RubrikPolaris import rubrik_gps_vm_export_command

    vm_export_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     "test_data/gps_vm_export_success.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/gps_vm_export_hr.md")) as f:
        vm_export_response_hr = f.read()

    args = {
        "object_id": "dc4f1b47-da71-5a62-a4eb-b94406d74cbc",
        "datastore_id": "711f8a94-c7dd-5ea9-afe9-2d8e44d09d3d",
        "host_id": "f57bfebf-c7c9-5310-a5fd-1f0aeea5ba25",
        "snapshot_id": "e9e1980f-11f0-53f3-84d6-15f60264b63b"
    }
    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=vm_export_response.get('empty_response'))
        response = rubrik_gps_vm_export_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vm export')

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=vm_export_response.get('raw_response'))
        response = rubrik_gps_vm_export_command(client, args=args)

        assert response.raw_response == vm_export_response.get('raw_response')
        assert response.outputs == remove_empty_elements(vm_export_response.get('outputs'))
        assert response.readable_output == vm_export_response_hr


@pytest.mark.parametrize("args, error", [
    ({"datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "snapshot_id": "dummy_id"},
     ERROR_MESSAGES['MISSING_EXPORT_DESTINATION']),
    ({"object_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('datastore_id')),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "snapshot_id": "dummy_id"},
     ERROR_MESSAGES['MISSING_EXPORT_DESTINATION']),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('snapshot_id')),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id",
      "power_on": "dummy"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("dummy", "power_on")),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id",
      "keep_mac_addresses": "dummy"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("dummy", "keep_mac_addresses")),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id",
      "remove_network_devices": "dummy"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("dummy", "remove_network_devices")),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id",
      "recover_tags": "dummy"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("dummy", "recover_tags")),
    ({"object_id": "dummy_id", "datastore_id": "dummy_id", "host_id": "dummy_id", "snapshot_id": "dummy_id",
      "disable_network": "dummy"}, ERROR_MESSAGES['INVALID_BOOLEAN'].format("dummy", "disable_network"))
])
def test_gps_vm_export_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-gps-vm-export."""
    from RubrikPolaris import rubrik_gps_vm_export_command

    with pytest.raises(ValueError) as e:
        rubrik_gps_vm_export_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("object_type, show_cluster_slas_only, exception, error",
                         [("ABC_OBJECT", "", ValueError,
                           SDK_ERROR_MESSAGES['INVALID_SLA_LIST_OBJECT_TYPE'].format(['ABC_OBJECT'])),
                          ("ABC_OBJECT, DEF_OBJECT", "", ValueError,
                           SDK_ERROR_MESSAGES['INVALID_SLA_LIST_OBJECT_TYPE'].format(['ABC_OBJECT', 'DEF_OBJECT'])),
                          ("FILESET_OBJECT_TYPE", "abc", ValueError,
                           ERROR_MESSAGES['INVALID_BOOLEAN'].format("abc", "show_cluster_slas_only"))
                          ])
def test_gps_sla_domain_list_when_invalid_input(client, requests_mock, object_type, show_cluster_slas_only, exception,
                                                error):
    """Tests rubrik_gps_sla_domain_list when inputs are invalid."""
    from RubrikPolaris import rubrik_gps_sla_domain_list

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_sla_domain_list_response.json'))
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sla_object_type_enum')},
        {'json': enum_values.get('sla_query_sort_by_field_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': raw_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    args = {
        "name": "",
        "cluster_id": "",
        "object_type": object_type,
        "show_cluster_slas_only": show_cluster_slas_only,
        "sort_by": "",
        "sort_order": "",
        "next_page_token": ""
    }

    with pytest.raises(exception) as e:
        rubrik_gps_sla_domain_list(client, args)

    assert str(e.value) == error


def test_gps_sla_domain_list_when_empty_response(client, requests_mock):
    """Tests rubrik_gps_sla_domain_list when empty response is returned."""
    from RubrikPolaris import rubrik_gps_sla_domain_list

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_sla_domain_list_empty_response.json'))
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sla_query_sort_by_field_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': raw_response}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    gps_sla_domain_list_command_results = rubrik_gps_sla_domain_list(client, {})

    assert gps_sla_domain_list_command_results.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("sla domains")
    assert gps_sla_domain_list_command_results.outputs is None


def test_gps_sla_domain_list_when_success_response(client, requests_mock):
    """Tests rubrik_gps_sla_domain_list when response is success."""
    from RubrikPolaris import rubrik_gps_sla_domain_list

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_sla_domain_list_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_sla_domain_list_success_hr.md")) as f:
        gps_sla_domain_list_hr = f.read()

    gps_sla_domain_list_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/gps_sla_domain_list_success_outputs.json'))

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sla_object_type_enum')},
        {'json': enum_values.get('sla_query_sort_by_field_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': raw_response}
    ]

    requests_mock.post(BASE_URL_GRAPHQL, responses)
    args = {
        "name": "",
        "cluster_id": "",
        "object_type": "FILESET_OBJECT_TYPE, VSPHERE_OBJECT_TYPE",
        "show_cluster_slas_only": "false",
        "sort_by": "NAME",
        "sort_order": "DESC",
        "limit": "2",
        "next_page_token": ""
    }
    gps_sla_domain_list_command_results = rubrik_gps_sla_domain_list(client, args)

    assert gps_sla_domain_list_command_results.raw_response == [edge["node"] for edge in
                                                                raw_response["data"]["slaDomains"]["edges"]]
    assert gps_sla_domain_list_command_results.readable_output == gps_sla_domain_list_hr
    assert gps_sla_domain_list_command_results.outputs == gps_sla_domain_list_outputs


@pytest.mark.parametrize("empty_response", [True, False])
def test_user_downloads_list_success(client, requests_mock, empty_response):
    """Tests success for rubrik_user_downloads_list."""
    from RubrikPolaris import rubrik_user_downloads_list_command

    user_downloads_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                          "test_data/user_downloads_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/user_downloads_get_hr.md")) as f:
        user_downloads_hr = f.read()

    args = {"object_id": "dummy", "cluster_id": "dummy", "snapshot_id": "dummy"}

    if empty_response:
        response = user_downloads_response.get('empty_response')
        requests_mock.post(BASE_URL_GRAPHQL, json=response)
        response = rubrik_user_downloads_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('user downloads')

    else:
        responses = user_downloads_response.get('raw_response')
        requests_mock.post(BASE_URL_GRAPHQL, json=responses)
        response = rubrik_user_downloads_list_command(client, args=args)

        assert response.raw_response == user_downloads_response.get('raw_response')
        assert response.outputs == remove_empty_elements(user_downloads_response.get('outputs'))
        assert response.readable_output == user_downloads_hr


@pytest.mark.parametrize("empty_response", [True, False])
def test_sonar_csv_result_download_success(client, requests_mock, empty_response):
    """Tests success for rubrik_sonar_csv_result_download."""
    from RubrikPolaris import rubrik_sonar_csv_result_download_command

    sonar_csv_download_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                              "test_data/sonar_csv_result_download_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_csv_result_download_hr.md")) as f:
        sonar_csv_download_hr = f.read()

    args = {"download_id": 1}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=sonar_csv_download_response.get('empty_response'))
        response = rubrik_sonar_csv_result_download_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RESPONSE"]
    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=sonar_csv_download_response.get('raw_response'))
        response = rubrik_sonar_csv_result_download_command(client, args=args)
        assert response.raw_response == sonar_csv_download_response.get('raw_response')
        assert response.outputs == remove_empty_elements(sonar_csv_download_response.get('outputs'))
        assert response.readable_output == sonar_csv_download_hr


@pytest.mark.parametrize("args, error", [
    ({"download_id": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('download_id')),
    ({"download_id": "a"}, "\"a\" is not a valid number")
])
def test_sonar_csv_result_download_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik_sonar_csv_result_download."""
    from RubrikPolaris import rubrik_sonar_csv_result_download_command

    with pytest.raises(ValueError) as e:
        rubrik_sonar_csv_result_download_command(client, args=args)
    assert str(e.value) == error


def test_gps_vm_snapshot_create_when_object_id_is_not_provided(client):
    """Tests invalid arguments for rubrik_gps_vm_snapshot_create."""
    from RubrikPolaris import rubrik_gps_vm_snapshot_create

    args = {
        "object_id": "",
        "sla_domain_id": ""
    }
    with pytest.raises(ValueError) as e:
        rubrik_gps_vm_snapshot_create(client, args=args)
    assert str(e.value) == ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')


def test_gps_vm_snapshot_create_when_empty_response(client, requests_mock):
    """Tests rubrik_gps_vm_snapshot_create when empty response is returned."""
    from RubrikPolaris import rubrik_gps_vm_snapshot_create

    empty_response = util_load_json(
        os.path.join(os.path.dirname(__file__), 'test_data/gps_vm_snapshot_create_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=empty_response)
    args = {
        "object_id": "dummy-object-id",
        "sla_domain_id": ""
    }
    gps_vm_snapshot_create_command_results = rubrik_gps_vm_snapshot_create(client, args)

    assert gps_vm_snapshot_create_command_results.readable_output == MESSAGES["NO_RESPONSE"]
    assert gps_vm_snapshot_create_command_results.outputs is None


def test_gps_vm_snapshot_create_when_success_response(client, requests_mock):
    """Tests rubrik_gps_vm_snapshot_create when response is success."""
    from RubrikPolaris import rubrik_gps_vm_snapshot_create

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_vm_snapshot_create_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_vm_snapshot_create_success_hr.md")) as f:
        gps_vm_snapshot_create_scan_hr = f.read()

    gps_vm_snapshot_create_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/gps_vm_snapshot_create_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "object_id": "dummy-object-id",
        "sla_domain_id": ""
    }

    gps_vm_snapshot_create_command_results = rubrik_gps_vm_snapshot_create(client, args)

    assert gps_vm_snapshot_create_command_results.raw_response == raw_response
    assert gps_vm_snapshot_create_command_results.readable_output == gps_vm_snapshot_create_scan_hr
    assert gps_vm_snapshot_create_command_results.outputs == gps_vm_snapshot_create_outputs


@pytest.mark.parametrize("empty_response, object_type", [
    (True, ""), (False, "WindowsFileset"), (False, "VolumeGroup"), (False, "VmwareVm")])
def test_gps_snapshot_file_download_success(client, requests_mock, empty_response, object_type):
    """Tests success for rubrik_gps_snapshot_file_download."""
    from RubrikPolaris import rubrik_gps_snapshot_files_download_command

    gps_snapshot_file_download_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                      "test_data/gps_snapshot_file_download_response"
                                                                      ".json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_snapshot_file_download_hr.md")) as f:
        gps_snapshot_file_download_hr = f.read()

    args = {"snapshot_id": 1, "file_path": "a", "object_type": object_type}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_snapshot_file_download_response.get('empty_response'))
        response = rubrik_gps_snapshot_files_download_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RESPONSE"]
    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_snapshot_file_download_response.get('raw_response'))
        response = rubrik_gps_snapshot_files_download_command(client, args=args)
        assert response.raw_response == gps_snapshot_file_download_response.get('raw_response')
        assert response.outputs == remove_empty_elements(gps_snapshot_file_download_response.get('outputs'))
        assert response.readable_output == gps_snapshot_file_download_hr


@pytest.mark.parametrize("args, error", [
    ({"snapshot_id": "", "file_path": "abc"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('snapshot_id')),
    ({"file_path": "", "snapshot_id": "abc"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('file_path')),
])
def test_gps_snapshot_file_download_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik_gps_snapshot_file_download."""
    from RubrikPolaris import rubrik_gps_snapshot_files_download_command

    with pytest.raises(ValueError) as e:
        rubrik_gps_snapshot_files_download_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("snappable_id, bool_value, field_name, exception, error",
                         [("", None, None, ValueError,
                           ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("snappable_id")),
                          ("dummy_id", 'Abc', "power_on", ValueError,
                           ERROR_MESSAGES['INVALID_BOOLEAN'].format("Abc", "power_on")),
                          ("dummy_id", 'Abc', "keep_mac_addresses", ValueError,
                           ERROR_MESSAGES['INVALID_BOOLEAN'].format("Abc", "keep_mac_addresses")),
                          ("dummy_id", 'Abc', "remove_network_devices", ValueError,
                           ERROR_MESSAGES['INVALID_BOOLEAN'].format("Abc", "remove_network_devices")),
                          ("dummy_id", 'Abc', "should_recover_tags", ValueError,
                           ERROR_MESSAGES['INVALID_BOOLEAN'].format("Abc", "should_recover_tags"))
                          ])
def test_gps_vm_livemount_when_invalid_input(requests_mock, snappable_id, bool_value, field_name, exception, error):
    """Tests rubrik_gps_vm_livemount when inputs are invalid."""
    from RubrikPolaris import rubrik_gps_vm_livemount

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_vm_livemount_success_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "snappable_id": snappable_id,
        f"{field_name}": bool_value
    }

    with pytest.raises(exception) as e:
        rubrik_gps_vm_livemount(client, args)

    assert str(e.value) == error


def test_gps_vm_livemount_when_empty_response(client, requests_mock):
    """Tests rubrik_gps_vm_livemount when empty response is returned."""
    from RubrikPolaris import rubrik_gps_vm_livemount

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_vm_livemount_empty_response.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)

    gps_vm_livemount_command_results = rubrik_gps_vm_livemount(client, {"snappable_id": "dummy_id"})

    assert gps_vm_livemount_command_results.readable_output == MESSAGES["NO_RESPONSE"]
    assert gps_vm_livemount_command_results.outputs is None


def test_gps_vm_livemount_list_when_success_response(client, requests_mock):
    """Tests rubrik_gps_vm_livemount when response is success."""
    from RubrikPolaris import rubrik_gps_vm_livemount

    raw_response = util_load_json(os.path.join(os.path.dirname(__file__),
                                               'test_data/gps_vm_livemount_success_response.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_vm_livemount_success_hr.md")) as f:
        gps_vm_livemount_hr = f.read()

    gps_vm_livemount_outputs = util_load_json(os.path.join(
        os.path.dirname(__file__), 'test_data/gps_vm_livemount_success_outputs.json'))

    requests_mock.post(BASE_URL_GRAPHQL, json=raw_response)
    args = {
        "snappable_id": "dummy_id"
    }
    gps_vm_livemount_command_results = rubrik_gps_vm_livemount(client, args)

    assert gps_vm_livemount_command_results.raw_response == raw_response
    assert gps_vm_livemount_command_results.readable_output == gps_vm_livemount_hr
    assert gps_vm_livemount_command_results.outputs == gps_vm_livemount_outputs


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_vm_host_list_success(client, requests_mock, empty_response):
    """Tests success for rubrik-gps-vm-host-list."""
    from RubrikPolaris import rubrik_gps_vm_host_list_command

    vm_host_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                        "test_data/gps_vm_host_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/gps_vm_host_list_hr.md")) as f:
        vm_host_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')}
    ]
    if empty_response:
        responses.append({'json': vm_host_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_vm_host_list_command(client, args={})
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vm hosts')

    else:
        responses.append({'json': vm_host_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_vm_host_list_command(client, args={})

        assert response.raw_response == vm_host_list_response.get('raw_response')
        assert response.outputs.get(f'{OUTPUT_PREFIX["GPS_VM_HOSTS"]}(val.id == obj.id)') == \
            remove_empty_elements(vm_host_list_response.get('outputs'))
        assert response.readable_output == vm_host_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"limit": "a"}, '"a" is not a valid number')
])
def test_gps_vm_host_list_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-gps-vm-host-list."""
    from RubrikPolaris import rubrik_gps_vm_host_list_command

    with pytest.raises(ValueError) as e:
        rubrik_gps_vm_host_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_vm_datastore_list_success(client, requests_mock, empty_response):
    """Tests success for rubrik-gps-vm-datastore-list."""
    from RubrikPolaris import rubrik_gps_vm_datastore_list_command

    vm_datastore_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                             "test_data/gps_vm_datastore_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/gps_vm_datastore_list_hr.md")) as f:
        vm_datastore_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')}
    ]
    args = {"host_id": "dummy_id", "name": "vm"}
    if empty_response:
        responses.append({'json': vm_datastore_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_vm_datastore_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vm datastores')

    else:
        responses.append({'json': vm_datastore_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_vm_datastore_list_command(client, args=args)

        assert response.raw_response == vm_datastore_list_response.get('raw_response')
        assert response.outputs.get(f'{OUTPUT_PREFIX["GPS_VM_HOSTS"]}(val.id == obj.id)') == \
            remove_empty_elements(vm_datastore_list_response.get('outputs'))
        assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_VM_HOSTS"]}(val.name == obj.name)') == \
            {"Datastore": remove_empty_elements(vm_datastore_list_response.get('page_token'))}
        assert response.readable_output == vm_datastore_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"limit": "a"}, '"a" is not a valid number')
])
def test_gps_vm_datastore_list_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-gps-vm-datastore-list."""
    from RubrikPolaris import rubrik_gps_vm_datastore_list_command

    with pytest.raises(ValueError) as e:
        rubrik_gps_vm_datastore_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_cdm_cluster_connection_state_command_success(client, requests_mock, empty_response):
    """Tests success for rubrik-cdm-cluster-connection-state."""
    from RubrikPolaris import cdm_cluster_connection_state_command

    cdm_cluster_connection_state_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                        "test_data/cdm_cluster_connection_state_"
                                                                        "response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/cdm_cluster_connection_state_hr.md")) as f:
        cdm_cluster_connection_state_hr = f.read()

    args = {"clusterId": "dummy"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=cdm_cluster_connection_state_response.get('empty_response'))
        with pytest.raises(Exception) as e:
            cdm_cluster_connection_state_command(client, args=args)
        assert str(e.value) == "A CDM Cluster with an ID of {} was not found.".format("dummy")

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=cdm_cluster_connection_state_response.get('raw_response'))
        response = cdm_cluster_connection_state_command(client, args=args)

        assert response.raw_response == cdm_cluster_connection_state_response.get('outputs').get('Cluster') \
            .get('ConnectionState')
        assert response.outputs == remove_empty_elements(cdm_cluster_connection_state_response.get('outputs'))
        assert response.readable_output == cdm_cluster_connection_state_hr


@pytest.mark.parametrize("args, error", [
    ({"clusterId": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('clusterId'))
])
def test_cdm_cluster_connection_state_command_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-cdm-cluster-connection-state."""
    from RubrikPolaris import cdm_cluster_connection_state_command

    with pytest.raises(ValueError) as e:
        cdm_cluster_connection_state_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_cdm_cluster_location_command_command_success(client, requests_mock, empty_response):
    """Tests success for rubrik-cdm-cluster-location."""
    from RubrikPolaris import cdm_cluster_location_command

    cdm_cluster_location_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/cdm_cluster_location_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/cdm_cluster_location_hr.md")) as f:
        cdm_cluster_location_hr = f.read()

    args = {"clusterId": "dummy"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=cdm_cluster_location_response.get('empty_response'))
        with pytest.raises(Exception) as e:
            cdm_cluster_location_command(client, args=args)
        assert str(e.value) == "A CDM Cluster with an ID of {} was not found.".format("dummy")

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=cdm_cluster_location_response.get('raw_response'))
        response = cdm_cluster_location_command(client, args=args)
        assert response.raw_response == cdm_cluster_location_response.get('outputs').get('Cluster').get('Location')
        assert response.outputs == remove_empty_elements(cdm_cluster_location_response.get('outputs'))
        assert response.readable_output == cdm_cluster_location_hr


def test_cdm_cluster_location_command_when_key_not_present(client, requests_mock):
    """Tests rubrik-cdm-cluster-location command when some of the keys are not present in response."""
    from RubrikPolaris import cdm_cluster_location_command

    cdm_cluster_location_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/cdm_cluster_location_response.json"))

    requests_mock.post(BASE_URL_GRAPHQL, json=cdm_cluster_location_response.get('empty_location'))

    response = cdm_cluster_location_command(client, args={"clusterId": "dummy"})
    assert response.readable_output == MESSAGES['NO_RESPONSE']


@pytest.mark.parametrize("args, error", [
    ({"clusterId": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('clusterId'))
])
def test_cdm_cluster_location_command_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-cdm-cluster-location."""
    from RubrikPolaris import cdm_cluster_location_command

    with pytest.raises(ValueError) as e:
        cdm_cluster_location_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_radar_analysis_status_command_success(client, requests_mock, empty_response):
    """Tests success for rubrik-radar-analysis-status."""
    from RubrikPolaris import radar_analysis_status_command

    radar_analysis_status_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                 "test_data/radar_analysis_status_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_analysis_status_hr.md")) as f:
        radar_analysis_status_hr = f.read()

    args = {"activitySeriesId": "dummy", "clusterId": "dummy"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=radar_analysis_status_response.get('empty_response'))
        response = radar_analysis_status_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("radar analysis status")

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=radar_analysis_status_response.get('raw_response'))
        response = radar_analysis_status_command(client, args=args)

        assert response.raw_response == radar_analysis_status_response.get('raw_response')
        assert response.outputs == remove_empty_elements(radar_analysis_status_response.get('outputs'))
        assert response.readable_output == radar_analysis_status_hr


@pytest.mark.parametrize("args, error", [
    ({"activitySeriesId": "", "clusterId": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('activitySeriesId')),
    ({"activitySeriesId": "", "clusterId": "dummy"},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('activitySeriesId')),
    ({"activitySeriesId": "dummy", "clusterId": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('clusterId'))
])
def test_radar_analysis_status_command_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-radar-analysis-status."""
    from RubrikPolaris import radar_analysis_status_command

    with pytest.raises(ValueError) as e:
        radar_analysis_status_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_event_list_success(client, requests_mock, empty_response):
    """Tests success for rubrik-event-list."""
    from RubrikPolaris import rubrik_event_list_command

    event_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                      "test_data/event_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/event_list_response_hr.md")) as f:
        event_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('event_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')}
    ]
    args = {}
    if empty_response:
        responses.append({'json': event_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_event_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('events')

    else:
        responses.append({'json': event_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_event_list_command(client, args=args)

        assert response.raw_response == event_list_response.get('raw_response')
        assert response.outputs.get(f'{OUTPUT_PREFIX["EVENT"]}(val.id == obj.id)') == \
            remove_empty_elements(event_list_response.get('outputs'))
        assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_EVENT"]}(val.name == obj.name)') == \
            remove_empty_elements(event_list_response.get('page_token'))
        assert response.readable_output == event_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"limit": "a"}, '"a" is not a valid number'),
    ({"start_date": "aaa"}, '"aaa" is not a valid date'),
    ({"end_date": "a111"}, '"a111" is not a valid date'),
    ({"limit": -1}, ERROR_MESSAGES['INVALID_LIMIT'].format(-1))
])
def test_event_list_when_invalid_arguments_are_provided(client, args, error):
    """Tests invalid arguments for rubrik-event-list."""
    from RubrikPolaris import rubrik_event_list_command

    with pytest.raises(ValueError) as e:
        rubrik_event_list_command(client, args=args)
    assert str(e.value) == error


def test_sonar_sensitive_hits_success(client, requests_mock):
    """
    Test case scenario for successful execution of rubrik-sonar-sensitive-hits command with a valid response.

    When:
        -calling rubrik-sonar-sensitive-hits command
    Then:
        -Verifies mock response with actual response obtained
    """
    from RubrikPolaris import sonar_sensitive_hits_command

    sonar_sensitive_hits_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/sonar_sensitive_hits_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_sensitive_hits_response_hr.md")) as f:
        sonar_sensitive_hits_response_hr = f.read()
    responses = [
        {'json': sonar_sensitive_hits_response.get('raw_response_list')},
        {'json': sonar_sensitive_hits_response.get('raw_response')}
    ]
    args = {}
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    response = sonar_sensitive_hits_command(client, args=args)

    assert response.raw_response == sonar_sensitive_hits_response.get('raw_response')
    assert response.outputs == remove_empty_elements(sonar_sensitive_hits_response.get('outputs'))
    assert response.readable_output == sonar_sensitive_hits_response_hr


def test_sonar_sensitive_hits_when_response_is_empty(client, requests_mock):
    """
    Test case scenario for successful execution of rubrik-sonar-sensitive-hits command with an empty response.

    When:
        -calling rubrik-sonar-sensitive-hits command
    Then:
        -Verifies mock response with empty message obtained in HR
    """
    from RubrikPolaris import sonar_sensitive_hits_command

    sonar_sensitive_hits_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/sonar_sensitive_hits_response.json"))
    responses = [
        {'json': sonar_sensitive_hits_response.get('raw_response_list')},
        {'json': sonar_sensitive_hits_response.get('empty_response')}
    ]
    args = {}
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    response = sonar_sensitive_hits_command(client, args=args)

    assert response.raw_response is None
    assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('sensitive hits')


@pytest.mark.parametrize("args, error", [
    ({"searchTimePeriod": "a"}, '"a" is not a valid number')
])
def test_sonar_sensitive_hits_when_invalid_arguments_are_provided(client, args, error):
    """
    Tests invalid arguments for rubrik-sonar-sensitive-hits.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import sonar_sensitive_hits_command

    with pytest.raises(ValueError) as e:
        sonar_sensitive_hits_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_object_list_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-polaris-object-list command with a valid and an empty response.

    When:
        -calling rubrik-polaris-object-list command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_polaris_object_list_command

    object_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                       "test_data/object_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/object_list_response_hr.md")) as f:
        object_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': enum_values.get('hierarchy_object_type_enum')}
    ]
    args = {"sort_order": "ASC", "type_filter": "MONGODB_DATABASE"}
    if empty_response:
        responses.append({'json': object_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_object_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('objects')

    else:
        responses.append({'json': object_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_object_list_command(client, args=args)

        assert response.raw_response == object_list_response.get('raw_response')
        assert response.outputs.get(f'{OUTPUT_PREFIX["OBJECT"]}(val.id == obj.id)') == \
            remove_empty_elements(object_list_response.get('outputs'))
        assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_OBJECT"]}(val.name == obj.name)') == \
            remove_empty_elements(object_list_response.get('page_token'))
        assert response.readable_output == object_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"limit": "a"}, "'type_filter' field is required. Please provide correct input."),
    ({"type_filter": "MONGODB_DATABASE", "limit": -1}, ERROR_MESSAGES['INVALID_LIMIT'].format(-1)),
    ({"type_filter": "MONGODB_DATABASE", "sort_order": "asc"}, SDK_ERROR_MESSAGES['INVALID_SORT_ORDER'].format('asc'))
])
def test_object_list_when_invalid_arguments_are_provided(client, args, error, requests_mock):
    """
    Test case scenario for invalid arguments for rubrik-polaris-object-list.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_polaris_object_list_command
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('sort_by_enum')},
        {'json': enum_values.get('sort_order_enum')},
        {'json': enum_values.get('hierarchy_object_type_enum')}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    with pytest.raises(ValueError) as e:
        rubrik_polaris_object_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_polaris_object_snapshot_list_success(client, requests_mock, empty_response):
    """Tests success for rubrik-polaris-object-snapshot-list."""
    from RubrikPolaris import rubrik_polaris_object_snapshot_list_command

    object_snapshot_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/object_snapshot_list_response.json"))
    with open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/object_snapshot_list_response_hr.md")) as f:
        object_snapshot_list_response_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('event_sort_order_enum')}
    ]
    args = {"object_id": "06515737-388a-57aa-9c8e-54b3f1ee5d8b", "sort_order": "ASC"}
    if empty_response:
        responses.append({'json': object_snapshot_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_object_snapshot_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('object snapshots')

    else:
        responses.append({'json': object_snapshot_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_polaris_object_snapshot_list_command(client, args=args)

        assert response.raw_response == object_snapshot_list_response.get('raw_response')
        assert response.outputs.get(f'{OUTPUT_PREFIX["OBJECT"]}(val.id == obj.id)') == \
            remove_empty_elements(object_snapshot_list_response.get('outputs'))
        assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_OBJECT"]}(val.name == obj.name)') == \
            remove_empty_elements(object_snapshot_list_response.get('page_token'))
        assert response.readable_output == object_snapshot_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"object_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
    ({"object_id": "1", "limit": "a"}, '"a" is not a valid number'),
    ({"object_id": "1", "start_date": "aaa"}, '"aaa" is not a valid date'),
    ({"object_id": "1", "end_date": "a111"}, '"a111" is not a valid date'),
    ({"object_id": "1", "limit": -1}, ERROR_MESSAGES['INVALID_LIMIT'].format(-1)),
    ({"object_id": "1", "sort_order": "as"}, SDK_ERROR_MESSAGES['INVALID_OBJECT_SNAPSHOT_SORT_ORDER'].format('as'))
])
def test_polaris_object_snapshot_list_when_invalid_arguments_are_provided(client, args, error, requests_mock):
    """Tests invalid arguments for rubrik-polaris-object-snapshot-list."""
    from RubrikPolaris import rubrik_polaris_object_snapshot_list_command
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))

    responses = [
        {'json': enum_values.get('event_sort_order_enum')}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)

    with pytest.raises(ValueError) as e:
        rubrik_polaris_object_snapshot_list_command(client, args=args)
    assert str(e.value) == error


radar_ioc_scan_invalid_args = [
    ({"cluster_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('cluster_id')),
    ({"cluster_id": "dummy-cluster-id", "object_id": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('object_id')),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "start_date": "abc"}, 'Invalid date: "start_date"="abc"'),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "end_date": "abc"}, 'Invalid date: "end_date"="abc"'),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "max_snapshots_per_object": "abc"}, 'Invalid number: "max_snapshots_per_object"="abc"'),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1, dummy-object-id-2",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "snapshot_id": "dummy-snapshot-id-1-1, dummy-snapshot-id-1-2"}, ERROR_MESSAGES['LEN_SNAPSHOT_NE_LEN_OBJECT']),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1, dummy-object-id-2",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "snapshot_id": "dummy-snapshot-id-1-1, dummy-snapshot-id-1-2: dummy-snapshot-id-2-1: dummy-snapshot-id-3-1"},
     ERROR_MESSAGES['LEN_SNAPSHOT_NE_LEN_OBJECT']),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "snapshot_id": "dummy-snapshot-id-1-1, dummy-snapshot-id-1-2: dummy-snapshot-id-2-1"},
     ERROR_MESSAGES['LEN_SNAPSHOT_NE_LEN_OBJECT']),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "abc", "ioc_value": ""},
     ERROR_MESSAGES["INVALID_SELECT"].format('abc', 'ioc_type', IOC_TYPE_ENUM)),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": ""},
     ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"]),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": ""},
     ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"]),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "{}"},
     ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"]),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "[]"},
     ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"]),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "["},
     ERROR_MESSAGES["JSON_DECODE"].format('advance_ioc')),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "{\"path_or_filename\": \"\""},
     ERROR_MESSAGES["JSON_DECODE"].format('advance_ioc')),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "[\"path_or_filename\": \"\"]"},
     ERROR_MESSAGES["JSON_DECODE"].format('advance_ioc')),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "", "ioc_value": "", "advance_ioc": "[{\"path_or_filename\": \"\"}]"},
     ERROR_MESSAGES["INVALID_FORMAT"].format('advance_ioc')),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "", "requested_hash_types": "WRONG_HASH_TYPE"},
     SDK_ERROR_MESSAGES["INVALID_REQUESTED_HASH_TYPE"].format(["WRONG_HASH_TYPE"])),
    ({"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
      "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": "",
      "requested_hash_types": "WRONG_HASH_TYPE1, WRONG_HASH_TYPE2"},
     SDK_ERROR_MESSAGES["INVALID_REQUESTED_HASH_TYPE"].format(["WRONG_HASH_TYPE1", "WRONG_HASH_TYPE2"])),
]


@pytest.mark.parametrize("args, error", radar_ioc_scan_invalid_args)
def test_radar_ioc_scan_when_invalid_arguments_are_provided(client, requests_mock, args, error):
    """
    Test case scenario for invalid arguments for rubrik-radar-ioc-scan.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_command

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              "test_data/enum_values.json"))

    requests_mock.post(BASE_URL + "/graphql", json=enum_values.get('hash_type_enum'))
    with pytest.raises(ValueError) as e:
        rubrik_radar_ioc_scan_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_radar_ioc_scan_when_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-radar-ioc-scan command with a valid and an empty response.

    When:
        -calling rubrik-radar-ioc-scan command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_command
    ioc_scan_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ioc_scan_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ioc_scan_response_hr.md")) as f:
        ioc_scan_response_hr = f.read()
    args = {"cluster_id": "dummy-cluster-id", "object_id": "dummy-object-id-1",
            "ioc_type": "INDICATOR_OF_COMPROMISE_TYPE_HASH", "ioc_value": ""}
    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_response.get('empty_response'))
        response = rubrik_radar_ioc_scan_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RESPONSE']
    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_response.get('raw_response'))
        response = rubrik_radar_ioc_scan_command(client, args=args)

        assert response.raw_response == ioc_scan_response.get('raw_response')
        assert response.outputs == ioc_scan_response.get('outputs')
        assert response.readable_output == ioc_scan_response_hr


@pytest.mark.parametrize("args, error", [
    ({"cluster_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("cluster_id"))
])
def test_radar_ioc_scan_list_when_invalid_arguments_are_provided(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik-radar-ioc-scan-list.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_list_command

    with pytest.raises(ValueError) as e:
        rubrik_radar_ioc_scan_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_radar_ioc_scan_list_when_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-radar-ioc-scan-list command with a valid and an empty response.

    When:
        -calling rubrik-radar-ioc-scan command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_list_command
    ioc_scan_list_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ioc_scan_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ioc_scan_list_response_hr.md")) as f:
        ioc_scan_list_response_hr = f.read()

    args = {"cluster_id": "dummy-cluster-id"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_list_response.get('empty_response'))
        response = rubrik_radar_ioc_scan_list_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format("ioc scans")
    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_list_response.get('raw_response'))
        response = rubrik_radar_ioc_scan_list_command(client, args=args)

        assert response.raw_response == ioc_scan_list_response.get('raw_response')
        assert response.outputs == ioc_scan_list_response.get('outputs')
        assert response.readable_output == ioc_scan_list_response_hr


@pytest.mark.parametrize("args, error", [
    ({"scan_id": "", "cluster_id": "dummy-cluster-id"}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('scan_id')),
    ({"scan_id": "dummy-scan-id", "cluster_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('cluster_id'))
])
def test_radar_ioc_scan_results_when_invalid_arguments_are_provided(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik-radar-ioc-scan-results.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_results_command

    with pytest.raises(ValueError) as e:
        rubrik_radar_ioc_scan_results_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_radar_ioc_scan_results_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-radar-ioc-scan-results command with a valid and an empty response.

    When:
        -calling rubrik-radar-ioc-scan-results command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_radar_ioc_scan_results_command

    ioc_scan_results_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                            "test_data/radar_ioc_scan_results_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_ioc_scan_results_response_hr.md")) as f:
        ioc_scan_results_response_hr = f.read()

    args = {"scan_id": "dummy-scan-id", "cluster_id": "dummy-cluster-id"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_results_response.get('empty_response'))
        response = rubrik_radar_ioc_scan_results_command(client, args=args)
        assert response.readable_output == MESSAGES['NO_RESPONSE']

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=ioc_scan_results_response.get('raw_response'))
        response = rubrik_radar_ioc_scan_results_command(client, args=args)

        assert response.raw_response == ioc_scan_results_response.get('raw_response')
        assert response.outputs == ioc_scan_results_response.get('outputs')
        assert response.readable_output == ioc_scan_results_response_hr


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_async_result_command_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-gps-async-result command with a valid and an empty response.

    When:
        -calling rubrik-gps-async-result command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_gps_async_result_command

    gps_async_result_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                            "test_data/gps_async_result_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_async_result_response_hr.md")) as f:
        gps_async_result_hr = f.read()

    args = {"request_id": "dummy", "cluster_id": "dummy"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_async_result_response.get('empty_response'))
        response = rubrik_gps_async_result_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RESPONSE"]

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_async_result_response.get('raw_response'))
        response = rubrik_gps_async_result_command(client, args=args)

        assert response.raw_response == gps_async_result_response.get('raw_response')
        assert response.outputs == remove_empty_elements(gps_async_result_response.get('outputs'))
        assert response.readable_output == gps_async_result_hr


@pytest.mark.parametrize("args, error", [
    ({"request_id": "", "cluster_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('request_id')),
    ({"request_id": "dummy", "cluster_id": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('cluster_id'))
])
def test_gps_async_result_command_when_invalid_arguments_are_provided(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik-gps-async-result.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_gps_async_result_command

    with pytest.raises(ValueError) as e:
        rubrik_gps_async_result_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_cluster_list_command_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-gps-cluster-list command with a valid and an empty response.

    When:
        -calling rubrik-gps-cluster-list command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_gps_cluster_list_command

    gps_cluster_list_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                            "test_data/gps_cluster_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_cluster_list_response_hr.md")) as f:
        gps_cluster_list_hr = f.read()

    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('cluster_list_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')}
    ]
    args = {}

    if empty_response:
        responses.append({'json': gps_cluster_list_response.get('empty_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_cluster_list_command(client, args=args)
        assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format('clusters')

    else:
        responses.append({'json': gps_cluster_list_response.get('raw_response')})
        requests_mock.post(BASE_URL_GRAPHQL, responses)
        response = rubrik_gps_cluster_list_command(client, args=args)

        assert response.raw_response == [edge["node"] for edge in
                                         gps_cluster_list_response.get('raw_response')["data"]["clusterConnection"]["edges"]]
        assert response.outputs == remove_empty_elements(gps_cluster_list_response.get('outputs'))
        assert response.readable_output == gps_cluster_list_hr


def test_gps_cluster_list_command_when_invalid_argument_is_provided(client, requests_mock):
    """
    Test case scenario for invalid argument for rubrik-gps-cluster-list.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_gps_cluster_list_command
    enum_values = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              enum_values_file_path))
    responses = [
        {'json': enum_values.get('cluster_list_sort_by_enum')},
        {'json': enum_values.get('event_sort_order_enum')}
    ]
    requests_mock.post(BASE_URL_GRAPHQL, responses)
    with pytest.raises(ValueError) as e:
        rubrik_gps_cluster_list_command(client, args={"sort_order": "asc"})
    assert str(e.value) == SDK_ERROR_MESSAGES['INVALID_OBJECT_SNAPSHOT_SORT_ORDER'].format('asc')


@pytest.mark.parametrize("args, error", [
    ({"snapshot_id": ""}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('snapshot_id')),
    ({"snapshot_id": "dummy-snapshot-id", "cluster_id": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('cluster_id')),
    ({"snapshot_id": "dummy-snapshot-id", "cluster_id": "dummy-cluster-id", "paths_to_recover": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('paths_to_recover')),
    ({"snapshot_id": "dummy-snapshot-id", "cluster_id": "dummy-cluster-id", "paths_to_recover": "/etc,/home",
      "restore_path": ""},
     ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format('restore_path')),
])
def test_gps_vm_recover_files_command_when_invalid_arguments_are_provided(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik-gps-vm-recover-files.

    Given:
        -args: contains arguments for the command
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_gps_vm_recover_files

    with pytest.raises(ValueError) as e:
        rubrik_gps_vm_recover_files(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response", [True, False])
def test_gps_vm_recover_files_command_success(client, requests_mock, empty_response):
    """
    Test case scenario for successful execution of rubrik-gps-vm-recover-files command with a valid and an empty response.

    When:
        -calling rubrik-gps-vm-recover-files command
    Then:
        -Verifies mock response with actual response
    """
    from RubrikPolaris import rubrik_gps_vm_recover_files

    gps_vm_recover_files_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                "test_data/gps_vm_recover_files_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/gps_vm_recover_files_response_hr.md")) as f:
        gps_vm_recover_files_hr = f.read()

    args = {"snapshot_id": "dummy-snapshot-id", "cluster_id": "dummy-cluster-id", "paths_to_recover": "/etc,/home",
            "restore_path": "/"}

    if empty_response:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_vm_recover_files_response.get('empty_response'))
        response = rubrik_gps_vm_recover_files(client, args=args)
        assert response.readable_output == MESSAGES["NO_RESPONSE"]

    else:
        requests_mock.post(BASE_URL_GRAPHQL, json=gps_vm_recover_files_response.get('raw_response'))
        response = rubrik_gps_vm_recover_files(client, args=args)

        assert response.raw_response == gps_vm_recover_files_response.get('raw_response')
        assert response.outputs == gps_vm_recover_files_response.get('outputs')
        assert response.readable_output == gps_vm_recover_files_hr


def test_rubrik_sonar_user_access_list_command_success_with_empty_response(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_list_command with valid case and empty response.

    When:
        - Calling rubrik_sonar_user_access_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_list_response.json"))

    args = {"sort_order": "ASC", "limit": 1, "page_number": 1, "include_whitelisted_results": True,
            "user_email": "demo"}
    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('empty_response')}])
    response = rubrik_sonar_user_access_list_command(client, args=args)
    assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('user accesses')


@pytest.mark.parametrize("limit, page_number", [(1, 1), (1, 2), (2, 1)])
def test_rubrik_sonar_user_access_list_command_success(client, requests_mock, limit, page_number):
    """
    Test case scenario for rubrik_sonar_user_access_list_command with valid case.

    When:
        - Calling rubrik_sonar_user_access_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           f"test_data/sonar_user_access_list_response_hr_{limit}_{page_number}.md")) as f:
        hr_data = f.read()

    args = {"sort_order": "ASC", "limit": limit, "page_number": page_number, "include_whitelisted_results": True,
            "user_email": "demo"}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response')}])
    response = rubrik_sonar_user_access_list_command(client, args=args)
    outputs = response_data.get(f'outputs_{limit}_{page_number}')
    page_token = response_data.get(f'page_token_{limit}_{page_number}')

    assert response.raw_response == response_data.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["USER_ACCESS"]}(val.principalId == obj.principalId)') == \
        remove_empty_elements(outputs)
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_USER_ACCESS"]}(val.name == obj.name)') == \
        remove_empty_elements(page_token)
    assert response.readable_output == hr_data


def test_rubrik_sonar_user_access_list_command_success_with_invalid_user_email(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_list_command when irrelevant user email is provided.

    When:
        - Calling rubrik_sonar_user_access_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_list_response.json"))
    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response')}])

    args = {"sort_order": "ASC", "limit": "1",
            "user_email": "invalid_user_email", "next_page_token": "cursor_1"}

    page_token = remove_empty_elements(response_data.get('page_token_2_1'))

    response = rubrik_sonar_user_access_list_command(client, args=args)
    assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format(
        'user accesses') + f"\n\n{MESSAGES['NEXT_PAGE_TOKEN'].format('cursor_2')}"
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_USER_ACCESS"]}(val.name == obj.name)', {}) == page_token


def test_rubrik_sonar_user_access_list_command_success_with_not_whitelisted(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_list_command when not whitelisting response.

    When:
        - Calling rubrik_sonar_user_access_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_user_access_list_response_hr_2_1.md")) as f:
        hr_data = f.read()

    args = {"sort_order": "Asc", "limit": "2", "include_whitelisted_results": False}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response_when_not_whitelisted')}])
    response = rubrik_sonar_user_access_list_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response_when_not_whitelisted')
    assert response.outputs.get(f'{OUTPUT_PREFIX["USER_ACCESS"]}(val.principalId == obj.principalId)') == \
        remove_empty_elements(response_data.get('outputs_when_not_whitelisted'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_USER_ACCESS"]}(val.name == obj.name)') == \
        remove_empty_elements(response_data.get('page_token_2_1'))
    assert response.readable_output == hr_data


@pytest.mark.parametrize("args, error", [
    ({"limit": "0"}, ERROR_MESSAGES['INVALID_LIMIT'].format(0)),
    ({"limit": MAXIMUM_PAGINATION_LIMIT + 1}, ERROR_MESSAGES['INVALID_LIMIT'].format(MAXIMUM_PAGINATION_LIMIT + 1)),
    ({"sort_order": "INC"}, ERROR_MESSAGES['INVALID_SORT_ORDER'].format("INC")),
])
def test_rubrik_sonar_user_access_list_command_with_invalid_args(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik_sonar_user_access_list_command.

    Given:
        -args: Contains arguments for the command.
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_sonar_user_access_list_command

    with pytest.raises(ValueError) as e:
        rubrik_sonar_user_access_list_command(client, args=args)
    assert str(e.value) == error


def test_rubrik_sonar_user_access_get_command_success_with_empty_response(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_get_command with valid case and empty response.

    When:
        - Calling rubrik_sonar_user_access_get_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_get_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_get_response.json"))

    args = {"user_id": "S-1-0-01-0000000000-0000000000-000000000-0001", "include_whitelisted_results": True}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('empty_response')}])
    response = rubrik_sonar_user_access_get_command(client, args=args)
    assert response.readable_output == MESSAGES["NO_RESPONSE"]


def test_rubrik_sonar_user_access_get_command_success(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_get_command with valid case.

    When:
        - Calling rubrik_sonar_user_access_get_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_get_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_user_access_get_response_hr.md")) as f:
        hr_data = f.read()

    args = {"user_id": "S-1-0-01-0000000000-0000000000-000000000-0001", "include_whitelisted_results": True}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response')}])
    response = rubrik_sonar_user_access_get_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["USER_ACCESS"]}(val.principalId == obj.principalId)') == \
        remove_empty_elements(response_data.get('outputs'))
    assert response.readable_output == hr_data


def test_rubrik_sonar_user_access_get_command_success_when_not_whitelisted(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_user_access_get_command when not whitelisting response.

    When:
        - Calling rubrik_sonar_user_access_get_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_user_access_get_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_user_access_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_user_access_get_response_hr.md")) as f:
        hr_data = f.read()

    args = {"user_id": "S-1-0-01-0000000000-0000000000-000000000-0001", "include_whitelisted_results": False}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response_when_not_whitelisted')}])
    response = rubrik_sonar_user_access_get_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response_when_not_whitelisted')
    assert response.outputs.get(f'{OUTPUT_PREFIX["USER_ACCESS"]}(val.principalId == obj.principalId)') == \
        remove_empty_elements(response_data.get('outputs_when_not_whitelisted'))
    assert response.readable_output == hr_data


@pytest.mark.parametrize("args, error", [
    ({}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("user_id"))
])
def test_rubrik_sonar_user_access_get_command_with_invalid_args(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik_sonar_user_access_get_command.

    Given:
        -args: Contains arguments for the command.
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_sonar_user_access_get_command

    with pytest.raises(ValueError) as e:
        rubrik_sonar_user_access_get_command(client, args=args)
    assert str(e.value) == error


def test_rubrik_sonar_file_context_list_command_success_with_empty_response(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_file_context_list_command with valid case and empty response.

    When:
        - Calling rubrik_sonar_file_context_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_file_context_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_file_context_list_response.json"))

    args = {"object_id": "1", "snapshot_id": "1",
            "sort_order": "ASC", "limit": "1", "include_whitelisted_results": True}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('empty_response')}])
    response = rubrik_sonar_file_context_list_command(client, args=args)
    assert response.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('file contexts')


def test_rubrik_sonar_file_context_list_command_success(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_file_context_list_command with valid case.

    When:
        - Calling rubrik_sonar_file_context_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_file_context_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_file_context_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_file_context_list_response_hr.md")) as f:
        hr_data = f.read()

    args = {"object_id": "1", "snapshot_id": "1",
            "sort_order": "ASC", "limit": "1", "include_whitelisted_results": True}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response')}])
    response = rubrik_sonar_file_context_list_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["FILE_CONTEXT"]}(val.stdPath == obj.stdPath)') == \
        remove_empty_elements(response_data.get('outputs'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_FILE_CONTEXT"]}(val.name == obj.name)') == \
        remove_empty_elements(response_data.get('page_token'))
    assert response.readable_output == hr_data


def test_rubrik_sonar_file_context_list_command_success_when_not_whitelisted(client, requests_mock):
    """
    Test case scenario for rubrik_sonar_file_context_list_command when not whitelisting response.

    When:
        - Calling rubrik_sonar_file_context_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_sonar_file_context_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/sonar_file_context_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/sonar_file_context_list_response_hr.md")) as f:
        hr_data = f.read()

    args = {"object_id": "1", "snapshot_id": "1", "user_id": "1", "next_page_token": "cursor_0",
            "sort_order": "Asc", "limit": "1", "include_whitelisted_results": False}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response_when_not_whitelisted')}])
    response = rubrik_sonar_file_context_list_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response_when_not_whitelisted')
    assert response.outputs.get(f'{OUTPUT_PREFIX["FILE_CONTEXT"]}(val.stdPath == obj.stdPath)') == \
        remove_empty_elements(response_data.get('outputs_when_not_whitelisted'))
    assert response.outputs.get(f'{OUTPUT_PREFIX["PAGE_TOKEN_FILE_CONTEXT"]}(val.name == obj.name)') == \
        remove_empty_elements(response_data.get('page_token'))
    assert response.readable_output == hr_data


@pytest.mark.parametrize("args, error", [
    ({"limit": "0"}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("object_id")),
    ({"object_id": "1", "limit": "0"}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("snapshot_id")),
    ({"object_id": "1", "snapshot_id": "1", "limit": "0"}, ERROR_MESSAGES['INVALID_LIMIT'].format(0)),
    ({"object_id": "1", "snapshot_id": "1", "limit": MAXIMUM_PAGINATION_LIMIT + 1},
     ERROR_MESSAGES['INVALID_LIMIT'].format(MAXIMUM_PAGINATION_LIMIT + 1)),
    ({"object_id": "1", "snapshot_id": "1", "sort_order": "INC"}, ERROR_MESSAGES['INVALID_SORT_ORDER'].format("INC")),
])
def test_rubrik_sonar_file_context_list_command_with_invalid_args(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik_sonar_file_context_list_command.

    Given:
        -args: Contains arguments for the command.
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_sonar_file_context_list_command

    with pytest.raises(ValueError) as e:
        rubrik_sonar_file_context_list_command(client, args=args)
    assert str(e.value) == error


@pytest.mark.parametrize("empty_response_type, message",
                         [("empty_response", MESSAGES["NO_RECORD_FOUND"].format("snapshot")),
                          ("empty_response_cdm_id", MESSAGES["NO_RECORD_FOUND"].format("snapshot")),
                          ("empty_response_cluster_id", MESSAGES["NO_RECORD_FOUND"].format("snapshot")),
                          ("empty_response_suspicious_file", MESSAGES["NO_RECORDS_FOUND"].format("suspicious files"))])
def test_rubrik_radar_suspicious_file_list_command_success_with_empty_response(client, requests_mock,
                                                                               empty_response_type, message):
    """
    Test case scenario for rubrik_radar_suspicious_file_list_command with valid case and empty response.

    When:
        - Calling rubrik_radar_suspicious_file_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_radar_suspicious_file_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/radar_suspicious_file_list_response.json"))

    args = {"snapshot_id": "00000000-0000-0000-0000-000000000001"}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get(empty_response_type)}])
    response = rubrik_radar_suspicious_file_list_command(client, args=args)
    assert response.readable_output == message


def test_rubrik_radar_suspicious_file_list_command_success(client, requests_mock):
    """
    Test case scenario for rubrik_radar_suspicious_file_list_command with valid case.

    When:
        - Calling rubrik_radar_suspicious_file_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_radar_suspicious_file_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/radar_suspicious_file_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_suspicious_file_list_hr.md")) as f:
        hr_data = f.read()

    args = {"snapshot_id": "00000000-0000-0000-0000-000000000001"}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response')}])
    response = rubrik_radar_suspicious_file_list_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response')
    assert response.outputs.get(f'{OUTPUT_PREFIX["SUSPICIOUS_FILE"]}(val.id == obj.id)') == \
        remove_empty_elements(response_data.get('outputs'))
    assert response.readable_output == hr_data


def test_rubrik_radar_suspicious_file_list_command_success_when_no_anomalies(client, requests_mock):
    """
    Test case scenario for rubrik_radar_suspicious_file_list_command when no anomalies detected.

    When:
        - Calling rubrik_radar_suspicious_file_list_command.
    Then:
        - Verifies mock response with actual response.
    """
    from RubrikPolaris import rubrik_radar_suspicious_file_list_command

    # Load test data
    response_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/radar_suspicious_file_list_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/radar_suspicious_file_list_no_anomalies_hr.md")) as f:
        hr_data = f.read()

    args = {"snapshot_id": "00000000-0000-0000-0000-000000000001"}

    requests_mock.post(BASE_URL_GRAPHQL, [{"json": response_data.get('raw_response_no_anomalies')}])
    response = rubrik_radar_suspicious_file_list_command(client, args=args)

    assert response.raw_response == response_data.get('raw_response_no_anomalies')
    assert response.outputs.get(f'{OUTPUT_PREFIX["SUSPICIOUS_FILE"]}(val.id == obj.id)') == \
        remove_empty_elements(response_data.get('outputs_when_no_anomalies'))
    assert response.readable_output == hr_data


@pytest.mark.parametrize("args, error", [
    ({}, ERROR_MESSAGES['MISSING_REQUIRED_FIELD'].format("snapshot_id"))
])
def test_rubrik_radar_suspicious_file_list_command_with_invalid_args(client, args, error):
    """
    Test case scenario for invalid arguments for rubrik_radar_suspicious_file_list_command.

    Given:
        -args: Contains arguments for the command.
    When:
        -Invalid value is passed in arguments
    Then:
        -Raises ValueError and asserts error message
    """
    from RubrikPolaris import rubrik_radar_suspicious_file_list_command

    with pytest.raises(ValueError) as e:
        rubrik_radar_suspicious_file_list_command(client, args=args)
    assert str(e.value) == error


@patch('RubrikPolaris.return_warning')
def test_ip_command_success(mock_return, client, requests_mock, capfd):
    '''
    Test case scenario for successful execution of ip_command.

    Given:
       - mocked client.
    When:
       - Calling `ip_command` function.
    Then:
       - Returns CommandResult.
    '''
    response = util_load_json('test_data/ip_command_success_response.json')
    output = util_load_json('test_data/ip_command_success_output.json')
    ip_hr = util_load_text_data('test_data/ip_command_success_hr.md')
    ip_indicator = util_load_json('test_data/ip_indicator.json')

    requests_mock.get(f'{BASE_URL}/thirdparty/workload_summary?search_string=0.0.0.1&search_type=ipv4',
                      json=response, status_code=200)
    requests_mock.get(f'{BASE_URL}/thirdparty/workload_summary?search_string=0.0.0.2&search_type=ipv4', json={}, status_code=200)

    args = {"ip": "0.0.0.1,\"  0.0.0.2  \",0.0.0.256"}

    capfd.close()
    from RubrikPolaris import ip_command
    command_output = ip_command(client, args=args)

    assert MESSAGES["IP_NOT_FOUND"].format('0.0.0.2') == mock_return.call_args[0][0]
    assert output == command_output[0].outputs
    assert response == command_output[0].raw_response
    assert ip_hr == command_output[0].readable_output
    assert command_output[0].outputs_key_field == 'ip'
    assert OUTPUT_PREFIX['IP'] == command_output[0].outputs_prefix
    assert ip_indicator == command_output[0].indicator.to_context()


def test_ip_command_when_all_ips_invalid(client, capfd):
    '''
    Test case scenario for the execution of ip_command with invalid ip addresses.

    Given:
       - mocked client.
    When:
       - Calling `ip_command` function.
    Then:
       - Returns exception.
    '''
    from RubrikPolaris import ip_command

    args = {'ip': '0: 0: 85a3: 0000: asv: 8a2e: 0370: 7334, 2.2.2, \" a.b.c.d \"'}
    capfd.close()
    with pytest.raises(SystemExit) as err:
        ip_command(client, args)

    assert err.value.code == 0


@patch('RubrikPolaris.return_warning')
def test_domain_command_success(mock_return, client, requests_mock, capfd):
    '''
    Test case scenario for successful execution of domain_command.

    Given:
       - mocked client.
    When:
       - Calling `domain_command` function.
    Then:
       - Returns CommandResult.
    '''
    response = util_load_json('test_data/domain_command_success_response.json')
    output = util_load_json('test_data/domain_command_success_output.json')
    domain_hr = util_load_text_data('test_data/domain_command_success_hr.md')
    domain_indicator = util_load_json('test_data/domain_indicator.json')

    requests_mock.get(f'{BASE_URL}/thirdparty/workload_summary?search_string=DEMO-RADAR&search_type=name',
                      json=response, status_code=200)
    requests_mock.get(f'{BASE_URL}/thirdparty/workload_summary?search_string=DEMO-RADAR02&search_type=name',
                      json={}, status_code=200)

    args = {"domain": "DEMO-RADAR, ,DEMO-RADAR02"}

    capfd.close()
    from RubrikPolaris import domain_command
    command_output = domain_command(client, args=args)

    assert MESSAGES["DOMAIN_NOT_FOUND"].format('DEMO-RADAR02') == mock_return.call_args[0][0]
    assert output == command_output[0].outputs
    assert response == command_output[0].raw_response
    assert domain_hr == command_output[0].readable_output
    assert command_output[0].outputs_key_field == 'domain'
    assert OUTPUT_PREFIX['DOMAIN'] == command_output[0].outputs_prefix
    assert domain_indicator == command_output[0].indicator.to_context()
