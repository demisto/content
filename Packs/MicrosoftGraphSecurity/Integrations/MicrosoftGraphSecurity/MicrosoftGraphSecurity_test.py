from MicrosoftGraphSecurity import MsGraphClient, create_search_alerts_filters, search_alerts_command, \
    get_users_command, fetch_incidents, get_alert_details_command, main, MANAGED_IDENTITIES_TOKEN_URL, \
    Resources, create_data_to_update, create_alert_comment_command, create_filter_query
from CommonServerPython import DemistoException
import pytest
import json
import io
import demistomock as demisto
import re


API_V2 = "Alerts v2"
API_V1 = "Legacy Alerts"
client_mocker = MsGraphClient(tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
                              base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed')


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.load(f)


def test_get_users_command(mocker):
    test_data = load_json("./test_data/test_get_users_command.json")
    mocker.patch.object(client_mocker, "get_users", return_value=test_data.get('raw_user_data'))
    hr, ec, _ = get_users_command(client_mocker, {})
    assert hr == test_data.get('expected_hr')
    assert ec == test_data.get('expected_ec')


def mock_request(method, url_suffix, params):
    return params


@pytest.mark.parametrize(
    'test_case', [
        "test_case_1", "test_case_2", "test_case_3"
    ])
def test_get_alert_details_command(mocker, test_case):
    """
        Given:
        - test case that point to the relevant test case in the json test data which include:
          args including alert_id and fields_to_include, response mock, expected hr and ec outputs, and api version.
        - Case 1: args with all fields to include in fields_to_include, response of a Legacy Alerts alert and,
                  api version Legacy Alerts flag.
        - Case 2: args with only FileStates to include in fields_to_include, response of a Legacy Alerts alert and,
                  api version Legacy Alerts flag.
        - Case 3: args with only FileStates to include in fields_to_include, response of a Legacy Alerts alert and,
                  api version Alerts v2 flag.

        When:
        - Running get_alert_details_command.

        Then:
        - Ensure that the alert was parsed correctly and right HR and EC outputs are returned.
        - Case 1: Should parse all the response information into the HR,
                  and only the relevant fields from the response into the ec.
        - Case 2: Should parse only the FileStates section from the response into the HR,
                  and only the relevant fields from the response into the ec.
        - Case 3: Should ignore the the fields_to_include argument and parse all the response information into the HR,
                  and all fields from the response into the ec.
    """
    test_data = load_json("./test_data/test_get_alert_details_command.json").get(test_case)
    mocker.patch.object(client_mocker, 'get_alert_details', return_value=test_data.get('mock_response'))
    mocker.patch('MicrosoftGraphSecurity.API_VER', test_data.get('api_version'))
    hr, ec, _ = get_alert_details_command(client_mocker, test_data.get('args'))
    assert hr == test_data.get('expected_hr')
    assert ec == test_data.get('expected_ec')


@pytest.mark.parametrize(
    'test_case', [
        "test_case_1", "test_case_2",
    ])
def test_search_alerts_command(mocker, test_case):
    """
        Given:
        - test case that point to the relevant test case in the json test data which include:
          args, api version, response mock, expected hr and ec outputs.
        - Case 1: args with medium severity and limit of 50 incidents, response of a Legacy Alerts search_alert command results,
                  and a Legacy Alerts api version flag.
        - Case 2: args with limit of 1 incident, response of a Legacy Alerts search_alert command results with 2 alerts,
                  and a Alerts v2 api version flag.

        When:
        - Running search_alerts_command.

        Then:
        - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
        - Case 1: Should parse all the response information into the HR,
                  and only the relevant fields from the response into the ec.
        - Case 2: Should concat the second incident from the response,
                  parse all only the first incident response information into the HR,
                  and all fields from the first incident response into the ec.
    """
    test_data = load_json("./test_data/test_search_alerts_command.json").get(test_case)
    mocker.patch.object(client_mocker, 'search_alerts', return_value=test_data.get('mock_response'))
    mocker.patch('MicrosoftGraphSecurity.API_VER', test_data.get('api_version'))
    hr, ec, _ = search_alerts_command(client_mocker, test_data.get('args'))
    assert hr == test_data.get('expected_hr')
    assert ec == test_data.get('expected_ec')


@pytest.mark.parametrize(
    'test_case', [
        "test_case_1",
    ])
def test_fetch_incidents_command(mocker, test_case):
    """
        Given:
        - test case that point to the relevant test case in the json test data which include a response mock.
        - Case 1: Response of a Legacy Alerts search_alert command results.

        When:
        - Running fetch_incidents.

        Then:
        - Ensure that the length of the results and the different fields of the fetched incidents are returned correctly.
        - Case 1: Ensure that the len of the incidents returned in the first iteration is 3, then 1 and then 0.
    """
    mocker.patch('MicrosoftGraphSecurity.parse_date_range', return_value=("2020-04-19 08:14:21", 'never mind'))
    test_data = load_json("./test_data/test_fetch_incidents_command.json").get(test_case)
    mocker.patch.object(client_mocker, 'search_alerts', return_value=test_data.get('mock_response'))
    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=10, providers='', filter='', service_sources='')
    assert len(incidents) == 3
    assert incidents[0].get('severity') == 2
    assert incidents[2].get('occurred') == '2020-04-20T16:54:50.2722072Z'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=1, providers='', filter='', service_sources='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'test alert - da637218501473413212_-1554891308'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=0, providers='', filter='', service_sources='')
    assert len(incidents) == 0


@pytest.mark.parametrize('args, expected_params, is_fetch, api_version', [
    ({'filter': "Category eq 'Malware' and Severity eq 'High'", "status": "resolved"},
     {'$filter': "Category eq 'Malware' and Severity eq 'High'"}, True, API_V1),
    ({'filter': "Category eq 'Malware' and Severity eq 'High'", "status": "resolved"},
     {'$filter': "Category eq 'Malware' and Severity eq 'High' and status eq 'resolved'"}, True, API_V2),
    ({'filter': "Category eq 'Malware' and Severity eq 'High'", "status": "resolved"},
     {'$top': '50', '$filter': "Category eq 'Malware' and Severity eq 'High'"}, False, API_V1),
    ({'page': "2"}, {'$top': '50', '$skip': 100, '$filter': ''}, False, API_V1)
])
def test_create_search_alerts_filters(mocker, args, expected_params, is_fetch, api_version):
    """
        Given:
        - args, expected_params results, is_fetch flag, and a api_version flag.
        - Case 1: args with filter and status (relevant only for Alerts v2) fields, is_fetch is True and,
                  API version flag is Legacy Alerts.
        - Case 2: args with filter and status (relevant only for Alerts v2) fields, is_fetch is True and,
                  API version flag is Alerts v2.
        - Case 3: args with filter and status (relevant only for Alerts v2) fields, is_fetch is False and,
                  API version flag is Legacy Alerts.
        - Case 4: args with only page field, is_fetch is False and API version flag is Legacy Alerts.

        When:
        - Running create_search_alerts_filters.

        Then:
        - Ensure that the right fields were parsed into the query.
        - Case 1: Should include only the value of the filter field from the args.
        - Case 2: Should include both the value of the filter field from the args and the status.
        - Case 3: Should include only the value of the filter field from the args in the $filter field in the params,
          and 50 in the $top field.
        - Case 4: Should return a params dict with empty $filter field, 50 in the $top field, and 100 in the $skip field.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    params = create_search_alerts_filters(args, is_fetch=is_fetch)
    assert params == expected_params


@pytest.mark.parametrize('args, expected_error, api_version', [
    ({"page_size": "1001"}, "Please note that the page size limit for Legacy Alerts is 1000", API_V1),
    ({"page_size": "1000", "page": "3"}, 'Please note that the maximum amount of alerts you can skip in Legacy Alerts is 500',
     API_V1),
    ({"page_size": "2001"}, "Please note that the page size limit for Alerts v2 is 2000", API_V2)
])
def test_create_search_alerts_filters_errors(mocker, args, expected_error, api_version):
    """
        Given:
        - args, expected_error, and a api_version flag.
        - Case 1: Args with page_size = 1001, and API version flag is Legacy Alerts.
        - Case 2: Args with page_size = 1000 and page = 3 (total of page=3000) and API version flag is Legacy Alerts.
        - Case 3: Args with page_size = 2001, and API version flag is Alerts v2.

        When:
        - Running create_search_alerts_filters.

        Then:
        - Ensure that the right error was thrown.
        - Case 1: Should throw an error for page_size too big for Legacy Alerts limitations.
        - Case 2: Should throw an error for too many alerts to skip for Legacy Alerts limitations.
        - Case 3: Should throw an error for page_size too big for Alerts v2 limitations.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    with pytest.raises(DemistoException) as e:
        create_search_alerts_filters(args, is_fetch=False)
    assert str(e.value.message) == expected_error


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={'value': []})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'resource_group': 'test_resource_group',
        'host': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]['Contents']
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


@pytest.mark.parametrize('args, expected_results, api_version', [
    ({'vendor_information': 'vendor_information', 'provider_information': 'provider_information', 'assigned_to': 'someone'},
     {'vendorInformation': {'provider': 'provider_information', 'vendor': 'vendor_information'}, 'assignedTo': 'someone'},
     API_V1),
    ({'vendor_information': 'vendor_information', 'provider_information': 'provider_information', 'comments': 'comment'},
     {'vendorInformation': {'provider': 'provider_information', 'vendor': 'vendor_information'}, 'comments': ['comment']},
     API_V1),
    ({'comments': 'comment', 'status': 'new'}, {'status': 'new'}, API_V2)
])
def test_create_data_to_update(mocker, args, expected_results, api_version):
    """
        Given:
        - args, expected_results, and a api_version flag.
        - Case 1: args with vendor_information, provider information, and assigned_to fields.
                  And API version flag is Legacy Alerts.
        - Case 2: args with vendor_information, provider information, and comment (relevant only for Legacy Alerts) fields,
                  and API version flag is Legacy Alerts.
        - Case 3: args with status ('new' which is supported only by Alerts v2) and comment (relevant only for Legacy Alerts),
                  and API version flag is Alerts v2.

        When:
        - Running create_data_to_update.

        Then:
        - Ensure that the right fields were parsed into the data dict.
        - Case 1: Should parse vendor_information and provider information fields into an inner dictionary,
                  and add the assigned_to as assignedTo into the data dict.
        - Case 2: Should parse vendor_information and provider information fields into an inner dictionary,
                  and add the comments as a list into the data dict.
        - Case 3: Should parse only status into the data dict.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    data = create_data_to_update(args)
    assert data == expected_results


@pytest.mark.parametrize('args, expected_error, api_version', [
    ({'assigned_to': 'someone'}, 'When using Legacy Alerts, both vendor_information and provider_information must be provided.',
     API_V1),
    ({'closed_date_time': 'now'}, "No data relevant for Alerts v2 to update was provided, please provide at least one of the "
     "following: assigned_to, determination, classification, status.", API_V2)
])
def test_create_data_to_update_errors(mocker, args, expected_error, api_version):
    """
        Given:
        - args, expected_error, and a api_version flag.
        - Case 1: args with only assigned_to field, and API version flag is Legacy Alerts.
        - Case 2: Args with only 'closed_date_time' field (relevant only for Legacy Alerts),  and API version flag is Alerts v2.

        When:
        - Running create_data_to_update.

        Then:
        - Ensure that the right error was thrown.
        - Case 1: Should throw an error for missing vendor and provider information.
        - Case 2: Should throw an error for missingAlerts v2 relevant data to update.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    with pytest.raises(DemistoException) as e:
        create_data_to_update(args)
    assert str(e.value.message) == expected_error


@pytest.mark.parametrize('args, expected_error, api_version', [
    ({'alert_id': 'alert_id', "comment": "comment"}, "This command is available only for Alerts v2."
     " If you wish to add a comment to an alert with Legacy Alerts please use 'msg-update-alert' command.", API_V1)
])
def test_create_alert_comment_command_error(mocker, args, expected_error, api_version):
    """
        Given:
        - args, expected_error, and a api_version flag.
        - Case 1: args with alert_id and a comment to add, and API version flag is Legacy Alerts.

        When:
        - Running create_alert_comment_command.

        Then:
        - Ensure that the right error was thrown.
        - Case 1: Should throw an error for running the command using Legacy Alerts of the API.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    with pytest.raises(DemistoException) as e:
        create_alert_comment_command(client_mocker, args)
    assert str(e.value.message) == expected_error


@pytest.mark.parametrize('test_case', [
    "test_case_1", "test_case_2"
])
def test_create_alert_comment_command(mocker, test_case):
    """
        Given:
        - test case that point to the relevant test case in the json test data which include:
          args including alert_id and comment to add, response mock, and expected hr and ec outputs
        - Case 1: Mock response of a comment with only one comment (the one that just got added).
        - Case 2: Mock response of a comment with two comments.
        When:
        - Running create_alert_comment_command.

        Then:
        - Ensure that the alert was parsed correctly and right HR and EC outputs are returned.
        - Case 1: Should return a table with one entry.
        - Case 2: Should return a table with two entries, one for each comment.
    """
    test_data = load_json("./test_data/test_create_alert_comment_command.json").get(test_case)
    mocker.patch.object(client_mocker, 'create_alert_comment', return_value=test_data.get('mock_response'))
    hr, ec, _ = create_alert_comment_command(client_mocker, test_data.get('args'))
    assert hr == test_data.get('expected_hr')
    assert ec == test_data.get('expected_ec')


@pytest.mark.parametrize('param, providers_param, service_sources_param, expected_results, api_version', [
    ("param", "providers_param", "service_sources_param", "param", API_V1),
    ("param", "providers_param", "service_sources_param", "param", API_V2),
    ("", "providers_param", "service_sources_param", "vendorInformation/provider eq 'providers_param'", API_V1),
    ("", "providers_param", "service_sources_param", "serviceSource eq 'service_sources_param'", API_V2),
    ("", "", "", "", API_V2)
])
def test_create_filter_query(mocker, param, providers_param, service_sources_param, expected_results, api_version):
    """
        Given:
        - param, providers_param, service_sources_param function arguments,
          expected_results, and a api_version flag.
        - Case 1: param, providers_param, and service_sources_param function arguments filled,
                  and API version flag is Legacy Alerts.
        - Case 2: param, providers_param, and service_sources_param function arguments filled, and API version flag is Alerts v2.
        - Case 3: Only providers_param and service_sources_param function arguments filled, and API version flag is Legacy Alerts.
        - Case 4: Only providers_param and service_sources_param function arguments filled, and API version flag is Alerts v2.
        - Case 5: param, providers_param, and service_sources_param function arguments Empty, and API version flag is Alerts v2.
        When:
        - Running create_filter_query.

        Then:
        - Ensure that the right option was returned.
        - Case 1: Should return param.
        - Case 2: Should return param.
        - Case 3: Should return providers_param.
        - Case 4: Should return service_sources_param.
        - Case 5: Should return an empty string.
    """
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_version)
    filter_query = create_filter_query(param, providers_param, service_sources_param)
    assert filter_query == expected_results
