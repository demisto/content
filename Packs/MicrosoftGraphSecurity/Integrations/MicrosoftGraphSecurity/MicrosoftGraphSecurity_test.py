import itertools
from types import SimpleNamespace

from MicrosoftGraphSecurity import MsGraphClient, create_search_alerts_filters, search_alerts_command, \
    get_users_command, fetch_incidents, get_alert_details_command, main, MANAGED_IDENTITIES_TOKEN_URL, \
    Resources, create_data_to_update, create_alert_comment_command, create_filter_query, to_msg_command_results, \
    list_ediscovery_custodian_site_sources_command, update_ediscovery_case_command, update_ediscovery_search_command, \
    capitalize_dict_keys_first_letter, created_by_fields_to_hr, list_ediscovery_search_command, purge_ediscovery_data_command, \
    list_ediscovery_non_custodial_data_source_command, list_ediscovery_case_command, activate_ediscovery_custodian_command, \
    release_ediscovery_custodian_command, close_ediscovery_case_command, reopen_ediscovery_case_command, \
    create_ediscovery_non_custodial_data_source_command, list_ediscovery_custodian_command, \
    create_mail_assessment_request_command, create_email_file_request_command, create_file_assessment_request_command, \
    create_url_assessment_request_command, list_threat_assessment_requests_command, get_message_user, \
    update_incident_command, advanced_hunting_command, get_list_security_incident_command
from CommonServerPython import DemistoException
import pytest
import json
import demistomock as demisto
import re

API_V2 = "Alerts v2"
API_V1 = "Legacy Alerts"
client_mocker = MsGraphClient(tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
                              base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed')


def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


@pytest.mark.parametrize(
    'api_response, keys_to_replace, expected_output', [
        ({'keyOne': {'keyTwo': {'keyThree': 'a'}, 'keyFour': {'keyFive': 'b'}}},
         {},
         {'KeyOne': {'KeyFour': {'KeyFive': 'b'}, 'KeyTwo': {'KeyThree': 'a'}}}),

        ({'keyOne': {'keyTwo': 'a'}, 'customOverride': 'a'},
         {'customOverride': 'SOMETHING'},
         {'KeyOne': {'KeyTwo': 'a'}, 'SOMETHING': 'a'})
    ])
def test_capitalize_dict_keys_first_letter(api_response, keys_to_replace, expected_output):
    """
    Given
        a response from the api
    When
        calling capitalize_dict_keys_first_letter with optional keys_to_replace
    Then
        Results are recursively formatted, manual keys are replaces

    """
    assert capitalize_dict_keys_first_letter(api_response, keys_to_replace) == expected_output


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
    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=10, providers='', filter='',
                                service_sources='')
    assert len(incidents) == 3
    assert incidents[0].get('severity') == 2
    assert incidents[2].get('occurred') == '2020-04-20T16:54:50.2722072Z'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=1, providers='', filter='',
                                service_sources='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'test alert - da637218501473413212_-1554891308'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=0, providers='', filter='',
                                service_sources='')
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
    ({"page_size": "1000", "page": "3"},
     'Please note that the maximum amount of alerts you can skip in Legacy Alerts is 500',
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
    ({'vendor_information': 'vendor_information', 'provider_information': 'provider_information',
      'assigned_to': 'someone'},
     {'vendorInformation': {'provider': 'provider_information', 'vendor': 'vendor_information'},
      'assignedTo': 'someone'},
     API_V1),
    (
        {'vendor_information': 'vendor_information', 'provider_information': 'provider_information',
         'comments': 'comment'},
        {'vendorInformation': {'provider': 'provider_information', 'vendor': 'vendor_information'},
         'comments': ['comment']},
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
    ({'assigned_to': 'someone'},
     'When using Legacy Alerts, both vendor_information and provider_information must be provided.',
     API_V1),
    ({'closed_date_time': 'now'},
     "No data relevant for Alerts v2 to update was provided, please provide at least one of the "
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
    ({'alert_id': 'alert_id', "comment": "comment"},
     "This command is available only for Alerts v2."
     " If you wish to add a comment to an alert with Legacy Alerts please use 'msg-update-alert' command.",
     API_V1)
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


def test_to_msg_command_results():
    """
    Given: An example msg edsicvoery response
    When: calling to_msg_command_results
    Then:
        1. Outputs are replaced properly
        2. data.context is stripped out
        3. none is removed

    """
    res = load_json("./test_data/list_cases_response.json")

    results = to_msg_command_results(raw_object_list=res.get('value'),
                                     raw_res=res,
                                     outputs_prefix='MsGraph.SomePrefix',
                                     output_key_field='SomeId',
                                     raw_keys_to_replace={'status': 'SomeStatus', 'id': 'SomeId'})

    assert all('@odata.context' not in o for o in results.outputs)
    assert all('SomeId' in o for o in results.outputs)
    assert all('SomeId' in o for o in results.outputs)
    assert all(None not in o.values() for o in results.outputs)


def test_create_ediscovery_custodian_site_source_command(mocker):
    """
    Given: An example msg edsicvoery list site source response
    When: calling list_ediscovery_custodian_site_sources_command
    Then:
        1. The proper URL is used in the request
        2. @odata.id is stripped out of context
        3. The proper ids and output prefixes are used

    """
    mock = mocker.patch.object(client_mocker.ms_client, "http_request",
                               return_value=load_json("./test_data/list_site_source_single.json"))

    results = list_ediscovery_custodian_site_sources_command(client_mocker,
                                                             {'case_id': 'case_id', 'custodian_id': 'custodian_id'})
    assert mock.call_args.kwargs['url_suffix'] == \
        'security/cases/ediscoveryCases/case_id/custodians/custodian_id/siteSources'
    assert not any('@odata.id' in o for o in results.outputs)
    assert results.outputs_prefix == 'MsGraph.CustodianSiteSource'
    assert results.outputs_key_field == 'SiteSourceId'
    assert all('SiteSourceId' in o for o in results.outputs)
    assert 'Created By Name' in results.readable_output


@pytest.mark.parametrize('command_function, description, external_id',
                         list(itertools.product(
                             [update_ediscovery_case_command, update_ediscovery_search_command],
                             ['value', '', None], ['value', '', None])))
def test_update_ediscovery_case_command(mocker, command_function, description, external_id):
    """
    Given:
        update ediscovery commands
    When:
        an empty value is recieved as an argument
    Then:
        the argument shouldnt be sent to the api (dont want to override a real value with an update)
    """
    mock = mocker.patch.object(client_mocker.ms_client, "http_request")

    some_id = 'some_id'
    command_function(client_mocker,
                     {'display_name': 'name', 'description': description,
                      'external_id': external_id, 'case_id': some_id})
    assert not set(mock.call_args.kwargs['json_data'].values()) & {None, ''}


def test_created_by_fields_to_hr():
    """
    Given
        A context dictionary
    When
        Calling created_by_fields_to_hr
    Then
        get the created fields flattened onto main dict
    """
    assert created_by_fields_to_hr(
        {'Field1': 'val1', 'CreatedBy': {'User': {'DisplayName': 'Bob', 'UserPrincipalName': 'Frank'}}}) == \
        {'CreatedByAppName': None, 'CreatedByName': 'Bob', 'CreatedByUPN': 'Frank', 'Field1': 'val1'}


def test_list_ediscovery_search_command(mocker):
    """

    Given:
        A raw response with one result
    When:
        calling list search command
    Then:
    Prefixes are correct, nested value is in the readable output
    """
    raw_response = load_json("./test_data/list_search_single_response.json")
    mocker.patch.object(client_mocker, "list_ediscovery_search",
                        return_value=raw_response)

    results = list_ediscovery_search_command(client_mocker, {})

    assert results.raw_response == raw_response
    assert results.outputs_key_field == 'SearchId'
    assert results.outputs_key_field == 'SearchId'
    assert results.outputs_prefix == 'MsGraph.eDiscoverySearch'
    assert results.outputs[0]['CreatedBy']['User']['DisplayName'] in results.readable_output


@pytest.mark.parametrize('command_to_check', ['all', 'ediscovery', 'alerts'])
def test_test_auth_code_command(mocker, command_to_check):
    """
    Given
        a permission set to test
    When
        Calling test_auth_code_command

    Then
        The proper permissions are called

    """
    from MicrosoftGraphSecurity import test_auth_code_command

    mock_ediscovery = mocker.patch.object(client_mocker, "list_ediscovery_cases",
                                          return_value=load_json("./test_data/list_cases_response.json"))
    mock_alerts = mocker.patch('MicrosoftGraphSecurity.test_function')
    mock_threat_assessment = mocker.patch.object(client_mocker, "list_threat_assessment_requests",
                                                 return_value=load_json("./test_data/list_threat_assessment.json"))
    test_auth_code_command(client_mocker, {'permission_type': command_to_check})

    if command_to_check == 'alerts':
        assert not mock_ediscovery.called
        assert not mock_threat_assessment.called
        assert mock_alerts.called
    elif command_to_check == 'any':
        assert mock_ediscovery.called
        assert mock_alerts.called
        assert mock_threat_assessment.called
    elif command_to_check == 'ediscovery':
        assert mock_ediscovery.called
        assert not mock_alerts.called
        assert not mock_threat_assessment.called
    elif command_to_check == 'threat assessment':
        assert not mock_ediscovery.called
        assert not mock_alerts.called
        assert mock_threat_assessment.called


def test_purge_ediscovery_data_command(mocker):
    mocker.patch.object(client_mocker, 'purge_ediscovery_data', return_value=SimpleNamespace(headers={}))
    assert purge_ediscovery_data_command(client_mocker, {}).readable_output == 'eDiscovery purge status is success.'


def test_list_ediscovery_non_custodial_data_source_command_empty_output(mocker):
    mocker.patch.object(client_mocker, 'list_ediscovery_noncustodial_datasources', return_value={'value': []})
    assert list_ediscovery_non_custodial_data_source_command(client_mocker, {}).readable_output == \
        '### Results:\n**No entries.**\n'


def test_list_ediscovery_case_command(mocker):
    raw_response = load_json("./test_data/list_cases_response.json")
    mocker.patch.object(client_mocker, 'list_ediscovery_cases',
                        return_value=raw_response)
    results = list_ediscovery_case_command(client_mocker, {})
    assert len(raw_response['value']) == len(results.outputs)
    assert all(output['CreatedDateTime'] in results.readable_output for output in results.outputs)


def test_activate_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, 'activate_edsicovery_custodian', return_value=None)
    assert activate_ediscovery_custodian_command(client_mocker, {'case_id': 'caseid', 'custodian_id': 'custodian_id'}) \
        .readable_output == 'Custodian with id custodian_id Case was reactivated on case with id caseid successfully.'


def test_release_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, 'release_edsicovery_custodian', return_value=None)
    assert release_ediscovery_custodian_command(client_mocker, {'case_id': 'caseid', 'custodian_id': 'custodian_id'}) \
        .readable_output == 'Custodian with id custodian_id was released from case with id caseid successfully.'


def test_close_ediscovery_case_command(mocker):
    mocker.patch.object(client_mocker, 'close_edsicovery_case', return_value=None)
    assert close_ediscovery_case_command(client_mocker, {'case_id': 'caseid'}) \
        .readable_output == 'Case with id caseid was closed successfully.'


def test_reopen_ediscovery_case_command(mocker):
    mocker.patch.object(client_mocker, 'reopen_edsicovery_case', return_value=None)
    assert reopen_ediscovery_case_command(client_mocker, {'case_id': 'caseid'}) \
        .readable_output == 'Case with id caseid was reopened successfully.'


@pytest.mark.parametrize('site, email, should_error', [('exists', None, False),
                                                       ('', 'Exists', False),
                                                       ('exists', 'also exists', True),
                                                       (None, None, True)])
def test_create_ediscovery_non_custodial_data_source_command_invalid_args(mocker, site, email, should_error):
    """
    Given:
        Arguments that arent valid for this command
    When:
        Calling the command
    Then
        An exception is raised

    """
    mocker.patch.object(client_mocker, 'create_ediscovery_non_custodial_data_source', return_value=None)
    try:
        create_ediscovery_non_custodial_data_source_command(client_mocker, {'site': site, 'email': email})
        assert not should_error
    except ValueError:
        assert should_error


def test_empty_list_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, 'list_ediscovery_custodians', return_value={})
    assert list_ediscovery_custodian_command(client_mocker, {}).readable_output == '### Results:\n**No entries.**\n'


THREAT_ASSESSMENT_COMMANDS = {
    'mail_assessment_request': create_mail_assessment_request_command,
    'email_file_assessment_request': create_email_file_request_command,
    'file_assessment_request': create_file_assessment_request_command,
    'url_assessment_request': create_url_assessment_request_command,
    'list_assessment_requests': list_threat_assessment_requests_command
}


@pytest.mark.parametrize('mock_func, command_name, expected_result',
                         [
                             ('create_mail_assessment_request', 'mail_assessment_request', 'mail_assessment_request.json'),
                             ('create_email_file_assessment_request', 'email_file_assessment_request',
                              'email_file_assessment_request.json'),
                             ('create_file_assessment_request', 'file_assessment_request', 'file_assessment_request.json'),
                             ('create_url_assessment_request', 'url_assessment_request', 'url_assessment_request.json')])
def test_create_mail_assessment_request_command(mocker, mock_func, command_name, expected_result):
    """

    Given:
        A raw response with one result
    When:
        calling list search command
    Then:
        Nested value is in the readable output
    """
    raw_response = load_json(f"./test_data/{expected_result}")
    mocker.patch.object(client_mocker, mock_func,
                        return_value={'request_id': '123'})
    mocker.patch.object(client_mocker, "get_threat_assessment_request_status",
                        return_value={'status': 'completed'})
    mocker.patch.object(client_mocker, "get_threat_assessment_request",
                        return_value=raw_response)
    mocker.patch("MicrosoftGraphSecurity.get_content_data", return_value="content_data")
    mocker.patch("MicrosoftGraphSecurity.get_message_user", return_value="user_mail")
    mocker.patch("CommonServerPython.is_demisto_version_ge", return_value=True)
    results = THREAT_ASSESSMENT_COMMANDS[command_name]({}, client_mocker)

    assert results.raw_response == raw_response
    assert results.outputs.get('ID') == raw_response.get('id')
    assert results.outputs.get("Content Type") == raw_response.get("contentType")


def test_list_threat_assessment_requests_command(mocker):
    raw_response = load_json("./test_data/list_threat_assessment.json")
    mocker.patch.object(client_mocker, "list_threat_assessment_requests",
                        return_value=raw_response)

    result = list_threat_assessment_requests_command(client_mocker, {})
    assert len(result) == 2
    assert result[0].outputs_prefix == 'MSGraphMail.AssessmentRequest'
    assert len(result[0].outputs) == 4
    assert result[1].outputs_prefix == 'MsGraph.AssessmentRequestNextToken'
    assert result[1].outputs == {'next_token': 'test_token'}


@pytest.mark.parametrize('user, expected_result',
                         [
                             ('testuser@test.com', 'test user id'),
                             ('test user id', 'test user id')
                         ])
def test_get_message_user(mocker, user, expected_result):
    mocker.patch.object(client_mocker, "get_user_id",
                        return_value={'value': [{"id": "test user id"}]})
    message_user = get_message_user(client_mocker, user)
    assert message_user == expected_result


def test_advanced_hunting_command(mocker):
    response = load_json('./test_data/advanced_hunting_response.json')
    mocker.patch.object(client_mocker, "advanced_hunting_request", return_value=response)
    args = {'query': 'AlertInfo', 'limit': 2, 'timeout': 50}

    results = advanced_hunting_command(client_mocker, args)

    expected_results = load_json('./test_data/advanced_hunting_results.json')
    assert results.outputs_prefix == expected_results['outputs_prefix']
    assert results.outputs_key_field == expected_results['outputs_key_field']
    assert results.outputs == expected_results['outputs']
    assert results.readable_output == expected_results['readable_output']

    mocker.patch.object(demisto, 'params', return_value={'microsoft_365_defender_context': True})
    results = advanced_hunting_command(client_mocker, args)

    expected_results = load_json('./test_data/advanced_hunting_results_365_defenfer.json')
    assert results[1].outputs_prefix == expected_results['outputs_prefix']
    assert results[1].outputs_key_field == expected_results['outputs_key_field']
    assert results[1].outputs == expected_results['outputs']
    assert results[1].readable_output == expected_results['readable_output']


def test_get_list_security_incident_command_single_case(mocker):
    response = load_json('./test_data/incidents_single_response.json')
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=response)
    args = {'incident_id': 12345, 'limit': 1, 'timeout': 50}
    results = get_list_security_incident_command(client_mocker, args)
    expected_results = load_json('./test_data/incidents_single_results.json')
    assert results.outputs_prefix == expected_results['outputs_prefix']
    assert results.outputs_key_field == expected_results['outputs_key_field']
    assert results.outputs == expected_results['outputs']
    assert results.readable_output == expected_results['readable_output']


def test_get_list_security_incident_command_list_case(mocker):
    response = load_json('./test_data/incidents_list_response.json')
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=response)
    args = {'limit': 2, 'timeout': 50}
    results = get_list_security_incident_command(client_mocker, args)
    expected_results = load_json('./test_data/incidents_list_results.json')
    assert results.outputs_prefix == expected_results['outputs_prefix']
    assert results.outputs_key_field == expected_results['outputs_key_field']
    assert results.outputs == expected_results['outputs']
    assert results.readable_output == expected_results['readable_output']


def test_update_incident_command(mocker):
    response = load_json("./test_data/incident_update_response.json")
    mocker.patch.object(client_mocker, "update_incident_request", return_value=response)
    args = {'incident_id': '12345', 'custom_tags': 'test1,test2', 'status': 'active', 'classification': 'unknown',
            'determination': 'unknown', 'assigned_to': "", 'timeout': 50}

    results = update_incident_command(client_mocker, args)

    expected_results = load_json("./test_data/incident_update_results.json")

    assert results.outputs_prefix == expected_results['outputs_prefix']
    assert results.outputs_key_field == expected_results['outputs_key_field']
    assert results.outputs == expected_results['outputs']
    assert results.readable_output == expected_results['readable_output']
