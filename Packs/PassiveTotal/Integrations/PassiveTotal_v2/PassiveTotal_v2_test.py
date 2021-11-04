import json
from unittest import mock
from unittest.mock import patch

import pytest
from requests.exceptions import MissingSchema, InvalidSchema, ConnectionError

import demistomock as demisto
from CommonServerPython import DemistoException
from test_data import input_data

MOCK_URL = 'http://123-fake-api.com'  # NOSONAR

SSL_ARGS = {
    'field': 'serialNumber',
    'query': 'dummy serial number'
}

PDNS_ARGS = {
    'query': 'dummy domain',
    'start': '2020-01-01 00:00:00',
    'end': '2020-01-31'
}

HOST_ATTRIBUTE_ARGS = {
    'component_by_domain': {
        'query': 'dummy domain',
        'start': '2020-05-25 00:05:25'
    },
    'component_by_ip': {
        'query': 'dummy ip',
        'end': '2020-05-25 00:05:25'
    },
    'tracker_by_domain': {
        'query': 'dummy domain',
        'start': '2020-05-25 00:05:25'
    },
    'tracker_by_ip': {
        'query': 'dummy ip',
        'end': '2020-05-25 00:05:25'
    },
    'host_pair': {
        'query': 'dummy child',
        'direction': 'parents',
        'start': '2020-05-25 00:05:25'
    }
}

COOKIE_ARGS = {
    "query": "dummy.domain",
    "search_by": "get addresses by cookie domain",
    "order": "desc",
    "sort": "last seen",
    "page": '0'
}


@pytest.fixture()
def client():
    from PassiveTotal_v2 import Client
    return Client(MOCK_URL, '10', False, False, ('USERNAME', 'API_SECRET'))


def mock_http_response(status=200, json_data=None, raise_for_status=None):
    mock_resp = mock.Mock()
    # mock raise_for_status call w/optional error
    mock_resp.raise_for_status = mock.Mock()
    if raise_for_status:
        mock_resp.raise_for_status.side_effect = raise_for_status
    # set status code
    mock_resp.status_code = status
    # add json data if provided
    if json_data:
        mock_resp.json = mock.Mock(
            return_value=json_data
        )
    return mock_resp


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_authentication_error(mock_base_http_request, client):
    """
        When http request return status code 401 then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=401)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Unauthenticated. Check the configured Username and API secret.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_page_not_found_error(mock_base_http_request, client):
    """
        When http request return status code 404 then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=404)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'No record(s) found.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_proxy_error_based_on_status(mock_base_http_request, client):
    """
        When http request return status code 407 then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=407)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or check ' \
           'the host, authentication details and connection details for the proxy.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_internal_server_error(mock_base_http_request, client):
    """
        When http request return status code 500 then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=500)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'The server encountered an internal error for PassiveTotal and was unable to complete your request.' == str(
        e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_raise_for_status(mock_base_http_request, client):
    """
        When http request return invalid status code then appropriate error message should display.
    """
    # Configure
    mock_raise_for_status = mock.Mock()
    mock_raise_for_status.return_value = None
    mock_response = mock_http_response(status=300, raise_for_status=mock_raise_for_status)
    mock_base_http_request.return_value = mock_response

    # Execute
    client.http_request('GET', '/test/url/suffix')

    # Assert
    assert mock_raise_for_status.called


def test_main_success(mocker, client):
    """
        When main function called test function should call.
    """
    import PassiveTotal_v2

    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(PassiveTotal_v2, 'test_function', return_value='ok')
    PassiveTotal_v2.main()
    assert PassiveTotal_v2.test_function.called


@patch('PassiveTotal_v2.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function get some exception then valid message should be print.
    """
    import PassiveTotal_v2

    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(PassiveTotal_v2, 'test_function', side_effect=Exception)
    with capfd.disabled():
        PassiveTotal_v2.main()

    mock_return_error.assert_called_once_with('Error: ')


@patch('PassiveTotal_v2.Client.http_request')
def test_function_success(request_mocker, client):
    """
       When success response come then test_function command should pass.
    """
    from PassiveTotal_v2 import test_function

    mock_response = {
        'results': 0,
        'domains': []
    }
    request_mocker.return_value = mock_response

    assert test_function(client) == 'ok'


def test_request_timeout_success(mocker):
    """
        When provided valid request timeout then test should be passed.
    """
    from PassiveTotal_v2 import get_request_timeout
    request_timeout = 5
    params = {
        'request_timeout': str(request_timeout)
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    get_request_timeout()
    assert int(request_timeout) == request_timeout


def test_request_timeout_invalid_value(mocker):
    """
        When provided invalid request timeout then display error message.
    """
    from PassiveTotal_v2 import get_request_timeout

    # Configure
    request_timeout = 'invalid_str_value'
    params = {
        'request_timeout': str(request_timeout)
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    # Execute
    with pytest.raises(ValueError) as e:
        get_request_timeout()

    # Assert
    assert 'HTTP(S) Request timeout parameter must be a positive integer.' == str(e.value)


def test_request_timeout_failure(mocker):
    """
        When invalid input provided for request timeout then appropriate error message should display.
    """
    from PassiveTotal_v2 import get_request_timeout
    request_timeout = -5

    params = {
        'request_timeout': str(request_timeout)
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    # Execute
    with pytest.raises(ValueError) as e:
        get_request_timeout()

    assert 'HTTP(S) Request timeout parameter must be a positive integer.' == str(e.value)


def test_request_timeout_large_value_failure(mocker):
    """
        When too large value provided for request timeout then raised value error and
        appropriate error message should display.
    """
    from PassiveTotal_v2 import get_request_timeout
    request_timeout = 990000000000000000

    params = {
        'request_timeout': str(request_timeout)
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    # Execute
    with pytest.raises(ValueError) as e:
        get_request_timeout()

    assert 'Value is too large for HTTP(S) Request Timeout.' == str(e.value)


def test_get_components_command_main_success(mocker, client):
    """
        When "pt-get-components" command executes the get_components_command function should be called from main.
    """
    import PassiveTotal_v2

    mocker.patch.object(demisto, 'command', return_value='pt-get-components')
    mocker.patch.object(PassiveTotal_v2, 'get_components_command',
                        return_value='No component(s) were found for the given argument(s).')
    PassiveTotal_v2.main()
    assert PassiveTotal_v2.get_components_command.called


@patch('PassiveTotal_v2.Client.http_request')
def test_get_components_command_domain_success(mocker_http_request, client):
    """
        When "pt-get-components" command executes successfully for domain then context output and response should match.
    """
    from PassiveTotal_v2 import get_components_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Component/component_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successDomain')
    mocker_http_request.return_value = expected_res

    # Fetch the expected custom entry context from file
    with open('test_data/HostAttribute/Component/component_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successDomain')

    # Fetch the expected human readable details from file
    with open('test_data/HostAttribute/Component/component_domain_hr.md') as f:
        expected_hr = f.read()

    result = get_components_command(client, HOST_ATTRIBUTE_ARGS['component_by_domain'])

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ''
    assert result[0].outputs_prefix == 'PassiveTotal.Component'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_components_command_ip_success(mocker_http_request, client):
    """
        When "pt-get-components" command executes successfully for ip then context output and response should match.
    """
    from PassiveTotal_v2 import get_components_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Component/component_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successIP')
    mocker_http_request.return_value = expected_res

    # Fetch the expected custom entry context from file
    with open('test_data/HostAttribute/Component/component_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successIP')

    # Fetch the expected human readable details from file
    with open('test_data/HostAttribute/Component/component_ip_hr.md') as f:
        expected_hr = f.read()

    result = get_components_command(client, HOST_ATTRIBUTE_ARGS['component_by_ip'])

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ''
    assert result[0].outputs_prefix == 'PassiveTotal.Component'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_components_command_no_record_found(mocker_http_request, client):
    """
        When no records found from Components response then result string should match.
    """
    from PassiveTotal_v2 import get_components_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Component/component_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('emptyContent')
    mocker_http_request.return_value = expected_res

    result = get_components_command(client, HOST_ATTRIBUTE_ARGS['component_by_domain'])
    assert result == 'No component(s) were found for the given argument(s).'


def test_get_trackers_command_main_success(mocker, client):
    """
        When "pt-get-trackers" command executes the get_trackers_command function should be called from main.
    """
    import PassiveTotal_v2

    mocker.patch.object(demisto, 'command', return_value='pt-get-trackers')
    mocker.patch.object(PassiveTotal_v2, 'get_trackers_command',
                        return_value='No tracker(s) were found for the given argument(s).')
    PassiveTotal_v2.main()
    assert PassiveTotal_v2.get_trackers_command.called


@patch('PassiveTotal_v2.Client.http_request')
def test_get_trackers_command_domain_success(mocker_http_request, client):
    """
        When "pt-get-trackers" command executes successfully for domain then context output and response should match.
    """
    from PassiveTotal_v2 import get_trackers_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Tracker/tracker_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successDomain')
    mocker_http_request.return_value = expected_res

    # Fetch the expected custom entry context from file
    with open('test_data/HostAttribute/Tracker/tracker_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successDomain')

    # Fetch the expected human readable details from file
    with open('test_data/HostAttribute/Tracker/tracker_domain_hr.md') as f:
        expected_hr = f.read()

    result = get_trackers_command(client, HOST_ATTRIBUTE_ARGS['tracker_by_domain'])

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ''
    assert result[0].outputs_prefix == 'PassiveTotal.Tracker'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_trackers_command_ip_success(mocker_http_request, client):
    """
        When "pt-get-trackers" command executes successfully for ip then context output and response should match.
    """
    from PassiveTotal_v2 import get_trackers_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Tracker/tracker_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successIP')
    mocker_http_request.return_value = expected_res

    # Fetch the expected custom entry context from file
    with open('test_data/HostAttribute/Tracker/tracker_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successIP')

    # Fetch the expected human readable details from file
    with open('test_data/HostAttribute/Tracker/tracker_ip_hr.md') as f:
        expected_hr = f.read()

    result = get_trackers_command(client, HOST_ATTRIBUTE_ARGS['tracker_by_ip'])

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ''
    assert result[0].outputs_prefix == 'PassiveTotal.Tracker'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_trackers_command_no_record_found(mocker_http_request, client):
    """
        When no records found from Trackers response then result string should match.
    """
    from PassiveTotal_v2 import get_trackers_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Tracker/tracker_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('emptyContent')
    mocker_http_request.return_value = expected_res

    result = get_trackers_command(client, HOST_ATTRIBUTE_ARGS['tracker_by_domain'])
    assert result == 'No tracker(s) were found for the given argument(s).'


def test_get_host_pairs_command_main_success(mocker, client):
    """
        When "pt-get-host-pairs" command executes the get_host_pairs_command function should be called from main.
    """
    import PassiveTotal_v2

    mocker.patch.object(demisto, 'command', return_value='pt-get-host-pairs')
    mocker.patch.object(PassiveTotal_v2, 'get_host_pairs_command',
                        return_value='No host pair(s) were found for the given argument(s).')
    PassiveTotal_v2.main()
    assert PassiveTotal_v2.get_host_pairs_command.called


@patch('PassiveTotal_v2.Client.http_request')
def test_get_host_pairs_command_success(mocker_http_request, client):
    """
        When "pt-get-host-pairs" command executes successfully then context output and response should match.
    """
    from PassiveTotal_v2 import get_host_pairs_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Host_Pair/host_pair_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('success')
    mocker_http_request.return_value = expected_res

    # Fetch the expected custom entry context from file
    with open('test_data/HostAttribute/Host_Pair/host_pair_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('success')

    # Fetch the expected human readable details from file
    with open('test_data/HostAttribute/Host_Pair/host_pair_hr.md') as f:
        expected_hr = f.read()

    result = get_host_pairs_command(client, HOST_ATTRIBUTE_ARGS['host_pair'])

    assert result.raw_response == expected_res
    assert result.outputs == expected_custom_ec
    assert result.readable_output == expected_hr
    assert result.outputs_key_field == ''
    assert result.outputs_prefix == 'PassiveTotal.HostPair'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_host_pairs_command_no_record_found(mocker_http_request, client):
    """
        When no records found from Host Pairs response then result string should match.
    """
    from PassiveTotal_v2 import get_host_pairs_command

    # Fetch the expected response from file
    with open('test_data/HostAttribute/Host_Pair/host_pair_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('emptyContent')
    mocker_http_request.return_value = expected_res

    result = get_host_pairs_command(client, HOST_ATTRIBUTE_ARGS['host_pair'])
    assert result == 'No host pair(s) were found for the given argument(s).'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_host_pairs_command_invalid_value_for_direction(client):
    """
        When invalid value is provided for direction argument in 'pt-get-host-pairs' then error message should match.
    """
    from PassiveTotal_v2 import get_host_pairs_command

    # Configure
    args = {
        'query': 'dummy domain',
        'direction': 'invalid direction'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        get_host_pairs_command(client, args)

    # Assert
    assert 'The given value for direction is invalid. Supported values: children, parents.' == str(e.value)


def test_get_common_arguments_invalid_value_for_query():
    """
        When invalid value is provided for query argument then error message should match.
    """
    from PassiveTotal_v2 import get_common_arguments

    # Configure
    args = {
        'query': '',
        'start': '2016-02-02 02:32:44'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        get_common_arguments(args)

    # Assert
    assert 'The given value for query is invalid.' == str(e.value)


def test_get_valid_whois_search_arguments_empty_value_in_query():
    """
        When empty value enter for command argument then should raise error with proper message
    """
    from PassiveTotal_v2 import get_valid_whois_search_arguments

    # Configure
    args = {
        'query': '',
        'field': 'email'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        get_valid_whois_search_arguments(args)

    # Assert
    assert 'query or field argument should not be empty.' == str(e.value)


def test_get_valid_whois_search_invalid_value_for_field_arguemnts():
    """
    When invalid value for command argument field then should raise error with proper message
    """
    from PassiveTotal_v2 import get_valid_whois_search_arguments

    # Configure
    args = {
        'query': 'test-query@test.com',
        'field': 'field'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        get_valid_whois_search_arguments(args)

    # Assert
    assert 'Invalid field type field. Valid field types are domain, email, name, organization, address, phone, ' \
           'nameserver.' == str(e.value)


@patch('PassiveTotal_v2.CommandResults')
@patch('PassiveTotal_v2.Client.http_request')
def test_pt_whois_search_command_success(request_mocker, mock_cr, client):
    """
        Proper Readable output and context should be set via CommonResults in case of proper response from whois-search
    API endpoint
    """
    from PassiveTotal_v2 import pt_whois_search_command
    from PassiveTotal_v2 import get_human_readable_for_whois_commands
    from PassiveTotal_v2 import get_context_for_whois_commands

    # Configure
    args = {
        'query': 'test-query@test.com',
        'field': 'email'
    }
    with open('test_data/whois_command/whois_command_response.json', 'rb') as f:
        dummy_response = json.load(f)
    with open('test_data/whois_command/whois_custom_context.json', 'rb') as f:
        dummy_custom_context = json.load(f)
    with open('test_data/whois_command/whois_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()
    with open('test_data/whois_command/whois_command_standard_domain_readable_output.md', 'r') as f:
        dummy_standard_domain_readable_output = f.read()
    request_mocker.return_value = dummy_response

    # Execute
    domains = dummy_response.get('results')
    # get human readable via dummy response
    readable_output = get_human_readable_for_whois_commands(domains)
    # get custom context via dummy response
    custom_context = get_context_for_whois_commands(domains)[1]
    pt_whois_search_command(client, args)

    # Assert
    # asserts the readable output
    assert readable_output == dummy_readable_output
    # asserts the custom context
    assert custom_context == dummy_custom_context
    # assert the standard domain readable output
    assert dummy_standard_domain_readable_output == mock_cr.call_args_list[0][1]['readable_output']
    # assert overall command output
    mock_cr.assert_called_with(
        outputs_prefix='PassiveTotal.WHOIS',
        outputs_key_field=['domain', 'lastLoadedAt'],
        outputs=dummy_custom_context,
        readable_output=dummy_readable_output,
        raw_response=dummy_response
    )


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_whois_search_empty_response(request_mocker, client):
    """
        Proper message should be display in case of empty response from whois-search API endpoint
    """
    from PassiveTotal_v2 import pt_whois_search_command

    # Configure
    args = {
        'query': 'test-query@test.com',
        'field': 'email'
    }
    empty_response = '{"results": []}'
    dummy_response = json.loads(empty_response)

    request_mocker.return_value = dummy_response

    # Execute
    message = pt_whois_search_command(client, args)

    # Assert
    assert message == 'No domain information were found for the given argument(s).'


@patch("PassiveTotal_v2.Client.http_request")
def test_ssl_cert_search_command_success(mocker_http_request, client):
    """
        When "ssl-cert-search" command executes successfully then context output and response should match.
    """
    from PassiveTotal_v2 import ssl_cert_search_command

    # Fetching expected raw response from file
    with open('test_data/SSL/ssl_cert_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('success')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open("test_data/SSL/ssl_cert_ec.json", encoding='utf-8') as f:
        expected_ec = json.load(f)

    # Fetching expected entry context details from file
    with open("test_data/SSL/ssl_cert_hr.md") as f:
        expected_hr = f.read()

    result = ssl_cert_search_command(client, SSL_ARGS)

    assert result.raw_response == expected_res
    assert result.outputs == expected_ec
    assert result.readable_output == expected_hr
    assert result.outputs_key_field == 'sha1'
    assert result.outputs_prefix == 'PassiveTotal.SSL'


@patch("PassiveTotal_v2.Client.http_request")
def test_ssl_cert_search_no_record_found(mocker_http_request, client):
    """
        When no record found from SSL response then result string should match.
    """
    from PassiveTotal_v2 import ssl_cert_search_command

    # Fetching expected raw response from file
    with open("test_data/SSL/ssl_cert_resp.json", encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('zeroRecords')
    mocker_http_request.return_value = expected_res

    result = ssl_cert_search_command(client, SSL_ARGS)
    assert result == 'No SSL certificate(s) were found for the given argument(s).'


@patch("PassiveTotal_v2.Client.http_request")
def test_get_pdns_details_command_success(mocker_http_request, client):
    """
        When "get-pdns-details" command executes successfully then context output and response should match.
    """
    from PassiveTotal_v2 import get_pdns_details_command

    # Fetching expected raw response from file
    with open('test_data/PDNS/get_pdns_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('success')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open("test_data/PDNS/get_pdns_ec.json", encoding='utf-8') as f:
        expected_ec = json.load(f)

    # Fetching expected entry context details from file
    with open("test_data/PDNS/get_pdns_hr.md") as f:
        expected_hr = f.read()

    result = get_pdns_details_command(client, PDNS_ARGS)

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_prefix == 'PassiveTotal.PDNS(val.resolve == obj.resolve && val.recordType == ' \
                                       'obj.recordType' \
                                       ' && val.resolveType == obj.resolveType)'


@patch("PassiveTotal_v2.Client.http_request")
def test_get_pdns_details_no_record_found(mocker_http_request, client):
    """
        When no record found from PDNS response then result string should match.
    """
    from PassiveTotal_v2 import get_pdns_details_command

    # Fetching expected raw response from file
    with open("test_data/PDNS/get_pdns_resp.json", encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('zeroRecords')
    mocker_http_request.return_value = expected_res

    result = get_pdns_details_command(client, SSL_ARGS)
    assert result == 'No PDNS Record(s) were found for the given argument(s).'


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_missing_schema_error(mock_base_http_request, client):
    """
        When http request return MissingSchema exception then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.side_effect = MissingSchema

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Invalid API URL. No schema supplied: http(s).' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_invalid_schema_error(mock_base_http_request, client):
    """
        When http request return invalid schema exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = InvalidSchema

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Invalid API URL. Supplied schema is invalid, supports http(s).' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_proxy_error(mock_base_http_request, client):
    """
        When http request return proxy error with exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('Proxy Error')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or' \
           ' check the host, authentication details and connection details for the proxy.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_connection_error(mock_base_http_request, client):
    """
        When http request return connection error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ConnectionError')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Connectivity failed. Check your internet connection, the API URL or try increasing the HTTP(s) Request' \
           ' Timeout.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_connect_timeout_error(mock_base_http_request, client):
    """
        When http request return connect timeout error with Demisto exception then appropriate error message
        should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ConnectTimeout')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Connectivity failed. Check your internet connection, the API URL or try increasing the HTTP(s) Request' \
           ' Timeout.' == str(e.value)


@patch('PassiveTotal_v2.Client._http_request')
def test_http_request_other_demisto_exception(mock_base_http_request, client):
    """
        When http request return other custom Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('custom')

    # Execute
    with pytest.raises(Exception) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'custom' == str(e.value)


def test_init():
    """
        test init function
    """
    import PassiveTotal_v2
    with mock.patch.object(PassiveTotal_v2, "main", return_value=42):
        with mock.patch.object(PassiveTotal_v2, "__name__", "__main__"):
            PassiveTotal_v2.init()


def test_domain_reputation_command_empty_domain_arguments_values(client):
    """
        When multiple empty value enter for command argument then should raise error with proper message
    """
    from PassiveTotal_v2 import domain_reputation_command

    # Configure
    args = {
        'domain': ',,'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        domain_reputation_command(client, args)

    # Assert
    assert 'domain argument should not be empty.' == str(e.value)


def test_domain_reputation_command_not_specify_domain_arguments_values(client):
    """
        When no value enter for command argument then should raise error with proper message
    """
    from PassiveTotal_v2 import domain_reputation_command

    # Configure
    args = {
        'domain': ''
    }

    # Execute
    with pytest.raises(ValueError) as e:
        domain_reputation_command(client, args)

    # Assert
    assert 'domain(s) not specified' == str(e.value)


@patch('PassiveTotal_v2.Client.http_request')
def test_domain_reputation_command_success(mocker_http_request, client):
    """
        Proper Readable output and context should be set via CommonResults in case of proper response from whois-search
        and reputation API endpoint
    """
    from PassiveTotal_v2 import domain_reputation_command
    from PassiveTotal_v2 import get_context_for_whois_commands

    # Configure
    args = {
        'domain': 'somedomain.com'
    }
    with open('test_data/domain_reputation/domain_reputation_response.json', 'rb') as f:
        dummy_response = json.load(f)
    with open('test_data/domain_reputation/domain_reputation_context.json', 'rb') as f:
        dummy_custom_context = json.load(f)
    with open('test_data/domain_reputation/domain_reputation_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()
    with open('test_data/domain_reputation/domain_reputation_command_reputation_response.json', 'rb') as f:
        dummy_custom_reputation_context = json.load(f)
    mocker_http_request.return_value = dummy_response

    _, custom_context = get_context_for_whois_commands(dummy_response.get('results'))
    custom_context.append(dummy_custom_reputation_context)
    final_context = [{k: v for x in custom_context for k, v in x.items()}]
    assert final_context == dummy_custom_context
    command_response = domain_reputation_command(client, args)

    assert command_response[0].outputs_prefix == 'PassiveTotal.Domain'
    assert command_response[0].outputs_key_field == 'domain'
    assert command_response[0].readable_output == dummy_readable_output


@patch('PassiveTotal_v2.CommandResults')
@patch('PassiveTotal_v2.Client.http_request')
def test_domain_reputation_command_empty_response(request_mocker, mock_cr, client):
    """
        Proper message should be display in case of empty response from whois-search and reputation API endpoint
    """
    from PassiveTotal_v2 import domain_reputation_command

    # Configure
    args = {
        'domain': 'somedomain.com'
    }
    empty_response = '{"results": []}'
    dummy_response = json.loads(empty_response)

    request_mocker.return_value = dummy_response

    # Execute
    domain_reputation_command(client, args)

    # Assert
    mock_cr.assert_called_with(
        outputs_prefix='PassiveTotal.Domain',
        outputs_key_field='domain',
        outputs=[],
        readable_output="### Domain(s)\n**No entries.**\nThe reputation score for 'somedomain.com' is  "
                        "and is classified as ''.\n### Reputation Rules\n**No entries.**\n"
    )


@patch('PassiveTotal_v2.Client.http_request')
def test_get_services_command_empty_response(request_mocker, client):
    """
        Empty response body should not throw any error if API returns.
    """
    from PassiveTotal_v2 import get_services_command

    # Configure
    args = {
        'ip': '127.0.0.1'
    }
    request_mocker.return_value = {}

    # Execute
    command_response = get_services_command(client, args)

    # Assert
    assert command_response.readable_output == "No services were found for the given argument(s)."


@patch('PassiveTotal_v2.Client.http_request')
def test_get_services_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import get_services_command

    # Configure
    args = {
        'ip': '127.0.0.1'
    }

    with open('test_data/services_command/services_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/services_command/services_command_context.json', 'rb') as f:
        context_output = json.load(f)

    with open('test_data/services_command/services_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = get_services_command(client, args)

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.Service'
    assert command_response.outputs_key_field == ['ip', 'portNumber']
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args", [
    {"ip": "1234"},
    {"ip": "1.1.1"},
    {"ip": "124.2222.2.2"},
    {"ip": "abc"}
])
def test_get_services_command_failure(args, client):
    """
        Validation error should be validated if business logic/method is throwing any error.
    """
    from PassiveTotal_v2 import get_services_command

    with pytest.raises(ValueError):
        get_services_command(client, args)


@patch('PassiveTotal_v2.CommandResults')
@patch('PassiveTotal_v2.Client.http_request')
def test_pt_get_whois_command_success(request_mocker, mock_cr, client):
    """
        Proper Readable output and context should be set via CommonResults in case of proper response from get-whois
    API endpoint
    """
    from PassiveTotal_v2 import pt_get_whois_command
    from PassiveTotal_v2 import get_human_readable_for_whois_commands
    from PassiveTotal_v2 import get_context_for_get_whois_commands

    # Configure
    args = {
        'query': 'test-query@test.com',
        'history': 'true'
    }
    with open('test_data/whois_command/whois_command_response.json', 'rb') as f:
        dummy_response = json.load(f)
    with open('test_data/whois_command/whois_custom_context.json', 'rb') as f:
        dummy_custom_context = json.load(f)
    with open('test_data/whois_command/whois_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()
    request_mocker.return_value = dummy_response

    # Execute
    domains = dummy_response.get('results')
    # get human readable via dummy response
    readable_output = get_human_readable_for_whois_commands(domains)
    # get custom context via dummy response
    custom_context = get_context_for_get_whois_commands(domains)
    pt_get_whois_command(client, args)

    # Assert
    # asserts the readable output
    assert readable_output == dummy_readable_output
    # asserts the custom context
    assert custom_context == dummy_custom_context
    # assert overall command output
    mock_cr.assert_called_with(
        outputs_prefix='PassiveTotal.WHOIS',
        outputs_key_field=['domain', 'lastLoadedAt'],
        outputs=dummy_custom_context,
        readable_output=dummy_readable_output,
        raw_response=dummy_response
    )


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_get_whois_empty_response(request_mocker, client):
    """
        Proper message should be display in case of empty response from get-whois API endpoint
    """
    from PassiveTotal_v2 import pt_get_whois_command

    # Configure
    args = {
        'query': 'test-query@test.com',
        'history': 'true'
    }
    empty_response = '{"results": []}'
    dummy_response = json.loads(empty_response)

    request_mocker.return_value = dummy_response

    # Execute
    response = pt_get_whois_command(client, args)

    # Assert
    assert response.readable_output == 'No domain information were found for the given argument(s).'


@patch("PassiveTotal_v2.Client.http_request")
def test_get_cookies_no_record_found(mocker_http_request, client):
    """
        When no record found from Cookies response then result string should match.
    """
    from PassiveTotal_v2 import get_cookies_command

    # Fetching expected raw response from file
    with open("test_data/Cookie/cookie_resp.json", encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('zeroRecords')
    mocker_http_request.return_value = expected_res

    result = get_cookies_command(client, COOKIE_ARGS)
    assert result == 'Total Record(s): 0\nNo cookies were found for the given argument(s).'


@patch("PassiveTotal_v2.Client.http_request")
def test_get_cookies_command_success(mocker_http_request, client):
    """
        When get cookies command executes successfully then context output and response should match.
    """
    from PassiveTotal_v2 import get_cookies_command

    # Fetching expected raw response from file
    with open('test_data/Cookie/cookie_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('success')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open("test_data/Cookie/cookie_ec.json", encoding='utf-8') as f:
        expected_ec = json.load(f)

    # Fetching expected entry context details from file
    with open("test_data/Cookie/cookie_hr.md") as f:
        expected_hr = f.read()

    result = get_cookies_command(client, COOKIE_ARGS)

    assert result.raw_response == expected_res
    assert result.outputs == expected_ec
    assert result.readable_output == expected_hr
    assert result.outputs_key_field == ['hostname', 'cookieName', 'cookieDomain']
    assert result.outputs_prefix == 'PassiveTotal.Cookie'


@pytest.mark.parametrize("query,search_by,sort,order,page", [
    ("abc", "get addresses by cookie name", "last seen", "desc", "-2"),
    ("abc", "get addresses by cookie name", "last seen", "desc", "13t"),
    ("abc", "cookie domain", "last seen", "desc", "0"),
    ("abc", "Get Addresses By Cookie", "last seen", "desc", "0"),
    ("abc", "get addresses by cookie name", "seen", "desc", "0"),
    ("abc", "get addresses by cookie name", "lastseen", "desc", "0"),
    ("abc", "get addresses by cookie name", "FirstSeen", "desc", "0"),
    ("abc", "get addresses by cookie name", "last seen", "des", "0"),
    ("abc", "get addresses by cookie name", "last seen", "ascending", "0"),
    ("abc", "get addresses by cookie name", "last seen", "desc", "0"),
    ("abc?", "get addresses by cookie name", "last seen", "desc", "0"),
    ("abc:", "get addresses by cookie name", "last seen", "desc", "0"),
    ("a bc", "get addresses by cookie name", "last seen", "desc", "0"),
    ("abc.?org", "get addresses by cookie domain", "last seen", "desc", "0"),
    ("abc\\.com", "get addresses by cookie domain", "last seen", "desc", "0"),
    ("a.b.c", "get addresses by cookie domain", "last seen", "desc", "0"),
    ("-abc.eu.org", "get addresses by cookie domain", "last seen", "desc", "0"),
    ("abc.eu.org-", "get addresses by cookie domain", "last seen", "desc", "0"),
])
def test_get_cookies_failures(client, query, search_by, sort, order, page):
    """
        When erroneous arguments are provided to get cookies command, it throws ValueError.
    """
    from PassiveTotal_v2 import get_cookies_command

    args = {
        "query": query,
        "search_by": search_by,
        "sort": sort,
        "order": order,
        "page": page
    }

    with pytest.raises(ValueError):
        get_cookies_command(client, args)


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_get_articles_command_success(request_mocker, client):
    """
        Proper Readable output and context should be set via CommonResults in case of proper response from get-articles
    API endpoint
    """
    from PassiveTotal_v2 import pt_get_articles_command

    # Configure
    args = {
        'query': 'dummy.com',
    }
    with open('test_data/Articles/articles_command_response.json', 'r') as f:
        dummy_response = json.load(f)
    with open('test_data/Articles/articles_custom_context.json', 'r') as f:
        dummy_custom_context = json.load(f)
    with open('test_data/Articles/articles_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()
    request_mocker.return_value = dummy_response

    # Execute
    response = pt_get_articles_command(client, args)

    # Assert
    # asserts the readable output
    assert response.readable_output == dummy_readable_output
    # asserts the custom context
    assert response.outputs == dummy_custom_context
    # asserts raw response
    assert response.raw_response == dummy_response


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_get_articles_empty_response(request_mocker, client):
    """
        Proper message should be display in case of empty response from get-articles API endpoint
    """
    from PassiveTotal_v2 import pt_get_articles_command

    # Configure
    args = {
        'query': 'dummy.com',
    }
    empty_response = '{"success": false,"articles": null,"totalRecords": 0}'

    dummy_response = json.loads(empty_response)

    request_mocker.return_value = dummy_response

    # Execute
    response = pt_get_articles_command(client, args)

    # Assert
    assert response.readable_output == 'No articles were found for the given argument(s).'


@patch('PassiveTotal_v2.Client.http_request')
def test_get_data_card_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import get_data_card_summary_command

    # Configure
    args = {
        'query': '1.1.1.1'
    }

    with open('test_data/Data_Card/data_card_command.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Data_Card/data_card_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = get_data_card_summary_command(client, args)

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.DataCard'
    assert command_response.outputs_key_field == 'name'
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response


def test_get_data_card_command_failure(client):
    """Test case scenario for failure execution of pt-data-card-get command."""

    from PassiveTotal_v2 import get_data_card_summary_command, MESSAGES
    args = {
        "query": ""
    }
    with pytest.raises(ValueError) as err:
        get_data_card_summary_command(client, args)
    assert str(err.value) == MESSAGES["REQUIRED_ARGUMENT"].format("query")


@patch('PassiveTotal_v2.Client.http_request')
def test_get_reputation_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import get_reputation_command

    # Configure
    args = {
        'query': '2020-windows.com'
    }

    with open('test_data/Reputation/reputation_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Reputation/reputation_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    with open('test_data/Reputation/reputation_command_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    request_mocker.return_value = dummy_response

    # Execute
    command_response = get_reputation_command(client, args)

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.Reputation'
    assert command_response.outputs_key_field == 'query'
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_custom_context


def test_get_reputation_command_failure(client):
    """Test case scenario for failure execution of pt-reputation-get command."""

    from PassiveTotal_v2 import get_reputation_command, MESSAGES
    args = {
        "query": ""
    }
    with pytest.raises(ValueError) as err:
        get_reputation_command(client, args)
    assert str(err.value) == MESSAGES["REQUIRED_ARGUMENT"].format("query")


def test_ip_reputation_command_empty_arguments_values(client):
    """
        When no value enter for command argument then should raise error with proper message
    """
    from PassiveTotal_v2 import ip_reputation_command

    # Configure
    args = {
        'ip': ',,'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        ip_reputation_command(client, args)

    # Assert
    assert 'IP(s) not specified' == str(e.value)


def test_ip_reputation_command_when_invalid_args_provided(client):
    """
        When invalid IP value enter for command argument then should raise error with proper message
    """
    from PassiveTotal_v2 import ip_reputation_command

    # Configure
    args = {
        'ip': '2020-windows.com'
    }

    # Execute
    with pytest.raises(ValueError) as e:
        ip_reputation_command(client, args)

    # Assert
    assert 'Invalid IP - 2020-windows.com' == str(e.value)


@patch('PassiveTotal_v2.Client.http_request')
def test_ip_reputation_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import ip_reputation_command

    # Configure
    args = {
        'ip': '1.1.1.1'
    }

    with open('test_data/ip_reputation/ip_reputation_command_response.json', 'rb') as f:
        dummy_response = json.load(f)
    with open('test_data/ip_reputation/ip_reputation_command_context.json', 'r') as f:
        dummy_custom_context = json.load(f)
    with open('test_data/ip_reputation/ip_reputation_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = ip_reputation_command(client, args)

    # Assert
    assert command_response[0].outputs_prefix == 'PassiveTotal.IP'
    assert command_response[0].outputs_key_field == 'query'
    assert command_response[0].readable_output == readable_output
    assert command_response[0].outputs == dummy_custom_context
    assert command_response[0].indicator.ip == "1.1.1.1"


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_list_intel_profile_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import get_intel_profile_command

    # Configure
    args = {
        'indicator_value': 'conglomeratoid.com',
        'type': 'actor',
        'source': 'osint',
        'category': 'network'
    }
    with open('test_data/IntelProfile/intel_profile_command_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/IntelProfile/intel_profile_command_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    with open('test_data/IntelProfile/intel_profile_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = get_intel_profile_command(client, args)

    # Assert
    assert response.outputs_prefix == 'PassiveTotal.IntelProfile'
    assert response.outputs_key_field == "id"
    assert response.readable_output == dummy_readable_output
    assert response.outputs == dummy_custom_context


@pytest.mark.parametrize("args, err_msg", input_data.list_intel_profile_invalid_args)
def test_pt_list_intel_profile_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test pt-list-intel-profiles command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import get_intel_profile_command
    with pytest.raises(ValueError) as de:
        get_intel_profile_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_list_intel_profile_command_when_empty_response_is_returned(request_mocker, client):
    """
    To test pt-list-intel-profiles command when empty response returned.
    """
    from PassiveTotal_v2 import get_intel_profile_command

    request_mocker.return_value = {"totalCount": 0, "results": []}

    args = {
        "query": "abc"
    }

    response = get_intel_profile_command(client, args)

    assert response.readable_output == "No profiles were found for the given argument(s)."


@patch('PassiveTotal_v2.Client.http_request')
def test_list_intel_profile_indicators_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_intel_profile_indicators_command

    # Configure
    args = {
        'id': 'apt33',
        'page_size': 2
    }

    with open('test_data/Intel_Profile_Indicator/intel_profile_indicator_command.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Intel_Profile_Indicator/intel_profile_indicator_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = list_intel_profile_indicators_command(client, args)

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.IntelProfile'
    assert command_response.outputs_key_field == 'id'
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response


@pytest.mark.parametrize("args, error_msg", input_data.intel_profile_indicator_invalid_args)
def test_list_intel_profile_indicators_command_failure(args, error_msg, client):
    """Test case scenario for failure execution of list-intel-profile-indicators command."""

    from PassiveTotal_v2 import list_intel_profile_indicators_command

    with pytest.raises(ValueError) as err:
        list_intel_profile_indicators_command(client, args)
    assert str(err.value) == error_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_intel_profile_indicators_command_when_empty_response_is_returned(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-intel-profile-indicators command with an empty response.
    """
    from PassiveTotal_v2 import list_intel_profile_indicators_command, MESSAGES

    request_mocker.return_value = {"results": []}
    command_results = list_intel_profile_indicators_command(client, {"id": "apt33", "page_size": "1"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('indicators')


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_list_my_asi_insights_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_insights_command

    # Configure
    args = {
        'priority': 'high',
    }
    with open('test_data/ASI_Insights/asi_insights_command_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = list_my_asi_insights_command(client, args)

    # Assert
    assert response.readable_output == dummy_readable_output
    assert response.outputs == dummy_custom_context
    assert response.raw_response == dummy_response


@pytest.mark.parametrize("args, err_msg", input_data.list_asi_insights_invalid_args)
def test_pt_list_my_asi_insights_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-intel-profiles command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_my_asi_insights_command
    with pytest.raises(ValueError) as de:
        list_my_asi_insights_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_list_my_asi_insights_command_key_not_present(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_insights_command

    # Configure
    args = {
        'priority': 'high',
    }
    with open('test_data/ASI_Insights/asi_insights_command_key_not_present_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_key_not_present_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_key_not_present_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = list_my_asi_insights_command(client, args)

    # Assert
    assert response.readable_output == dummy_readable_output
    assert response.outputs == dummy_custom_context
    assert response.raw_response == dummy_response


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_attack_surfaces_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_attack_surfaces_command

    with open('test_data/Attack_Surface/attack_surface_command.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = list_my_attack_surfaces_command(client, {})

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.AttackSurface'
    assert command_response.outputs_key_field == 'id'
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, err_msg", input_data.list_my_attack_surface_invalid_args)
def test_list_my_attack_surfaces_command_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-my-attack-surfaces command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_my_attack_surfaces_command
    with pytest.raises(ValueError) as de:
        list_my_attack_surfaces_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_attack_surfaces_command_when_object_not_present_success(request_mocker, client):
    """
       To test pt-list-my-attack-surfaces command when valid response with missing some objects return.
    """
    from PassiveTotal_v2 import list_my_attack_surfaces_command

    with open('test_data/Attack_Surface/attack_surface_object_not_present.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_object_not_present_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_object_not_present.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    command_response = list_my_attack_surfaces_command(client, {})

    # Assert
    assert command_response.outputs_prefix == 'PassiveTotal.AttackSurface'
    assert command_response.outputs_key_field == 'id'
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_asi_command

    with open('test_data/Attack_Surface/attack_surface_command.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Attack_Surface/third_party_attack_surface_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response[0]

    # Execute
    command_response = list_third_party_asi_command(client, {"id": "88256"})

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response[0]
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_command_when_object_not_present_success(request_mocker, client):
    """
       To test pt-list-third-party-attack-surface command when valid response with missing some objects return.
    """
    from PassiveTotal_v2 import list_third_party_asi_command

    with open('test_data/Attack_Surface/attack_surface_object_not_present.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/Attack_Surface/third_party_attack_surface_object_not_present_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/Attack_Surface/attack_surface_object_not_present.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response[0]

    # Execute
    command_response = list_third_party_asi_command(client, {"id": "88256", "page_size": 1})

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response[0]
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, error_msg", input_data.list_third_party_asi_invalid_args)
def test_list_third_party_asi_command_failure(args, error_msg, client):
    """
    Test case scenario for failure execution of list_third_party_asi command.
    """
    from PassiveTotal_v2 import list_third_party_asi_command

    with pytest.raises(ValueError) as err:
        list_third_party_asi_command(client, args)
    assert str(err.value) == error_msg


@pytest.mark.parametrize("args, err_msg", input_data.list_asi_assets_invalid_args)
def test_pt_list_my_asi_assets_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test pt-list-my-attack-surface-assets command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_my_asi_assets_command
    with pytest.raises(ValueError) as de:
        list_my_asi_assets_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_assets_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_assets_command

    with open('test_data/ASI_Assets/asi_assets_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": "40466",
        "segment_by": "savedfilter_metric_29644"
    }
    # Execute
    command_response = list_my_asi_assets_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_assets_command_success_object_not_present(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_assets_command

    with open('test_data/ASI_Assets/asi_assets_command_object_not_present_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_object_not_present_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_object_not_present_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": "40466",
        "segment_by": "savedfilter_metric_29644"
    }
    # Execute
    command_response = list_my_asi_assets_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_insights_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_asi_insights_command

    # Configure
    args = {
        'id': 88256,
        'priority': 'high',
    }
    with open('test_data/ASI_Insights/asi_insights_command_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Insights/third_party_asi_insights_command_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = list_third_party_asi_insights_command(client, args)

    # Assert
    assert response.readable_output == dummy_readable_output
    assert response.outputs == dummy_custom_context
    assert response.raw_response == dummy_response


@pytest.mark.parametrize("args, err_msg", input_data.list_third_party_asi_insights_invalid_args)
def test_list_third_party_asi_insights_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-third-party-attack-surface-insights command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_third_party_asi_insights_command
    with pytest.raises(ValueError) as de:
        list_third_party_asi_insights_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_insights_command_key_not_present(request_mocker, client):
    """
        To test pt-list-third-party-attack-surface-insights command when valid response with missing key return.
    """
    from PassiveTotal_v2 import list_third_party_asi_insights_command

    # Configure
    args = {
        'id': 88256,
        'priority': 'high',
    }
    with open('test_data/ASI_Insights/asi_insights_command_key_not_present_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Insights/third_party_asi_insights_key_not_present_context.json', 'r') as f:
        dummy_custom_context = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_key_not_present_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = list_third_party_asi_insights_command(client, args)

    # Assert
    assert response.readable_output == dummy_readable_output
    assert response.outputs == dummy_custom_context
    assert response.raw_response == dummy_response


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_vulnerable_components_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_vulnerable_components_command

    with open('test_data/ASI_VulnerableComponents/asi_vulnerable_components_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_VulnerableComponents/asi_vulnerable_components_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_VulnerableComponents/asi_vulnerable_components_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_my_asi_vulnerable_components_command(client, args)

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, expected_params", input_data.common_args)
def test_validate_page_and_size_args(args, expected_params):
    """Test case scenario when valid arguments are provided."""
    from PassiveTotal_v2 import validate_page_and_size_args

    assert validate_page_and_size_args(args) == expected_params


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_vulnerable_components_command_when_empty_response_is_returned(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-my-attack-surface-vulnerable-components command with an empty response.
    """
    from PassiveTotal_v2 import list_my_asi_vulnerable_components_command, MESSAGES

    request_mocker.return_value = {"vulnerableComponents": []}
    command_results = list_my_asi_vulnerable_components_command(client, {"page_number": "100"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vulnerable components')


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_vulnerabilities_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_vulnerabilities_command

    with open('test_data/ASI_Vulnerability/asi_vulnerability_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Vulnerability/asi_vulnerability_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Vulnerability/asi_vulnerability_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_my_asi_vulnerabilities_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_vulnerabilities_command_when_empty_response_is_returned(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-my-attack-surface-vulnerabilities command with an empty response.
    """
    from PassiveTotal_v2 import list_my_asi_vulnerabilities_command, MESSAGES

    request_mocker.return_value = {"cves": []}
    command_results = list_my_asi_vulnerabilities_command(client, {"page_number": "100"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('vulnerabilities')


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_observations_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_observations_command

    with open('test_data/ASI_Observations/asi_observation_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Observations/asi_observation_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Observations/asi_observation_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_my_asi_observations_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, err_msg", input_data.list_asi_observation_invalid_args)
def test_list_my_asi_observations_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-my-attack-surface-observations command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_my_asi_observations_command
    with pytest.raises(ValueError) as de:
        list_my_asi_observations_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_observations_command_success_object_not_present(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_my_asi_observations_command

    with open('test_data/ASI_Observations/asi_observation_command_object_not_present_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Observations/asi_observation_command_object_not_present_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Observations/asi_observations_command_object_not_present_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_my_asi_observations_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, err_msg", input_data.list_third_party_asi_assets_invalid_args)
def test_pt_list_third_party_asi_assets_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-third-party-attack-surface-assets command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_third_party_asi_assets_command
    with pytest.raises(ValueError) as de:
        list_third_party_asi_assets_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_assets_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_asi_assets_command

    with open('test_data/ASI_Assets/asi_assets_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Assets/third_party_asi_assets_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "vendor_id": 45998,
        "id": 123,
        "segment_by": "savedfilter_metric_29644"
    }
    # Execute
    command_response = list_third_party_asi_assets_command(client, args)

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_assets_command_success_object_not_present(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-third-party-attack-surface-assets command with an empty response.
    """
    from PassiveTotal_v2 import list_third_party_asi_assets_command

    with open('test_data/ASI_Assets/asi_assets_command_object_not_present_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Assets/third_party_asi_assets_command_object_not_present_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Assets/asi_assets_command_object_not_present_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "vendor_id": 45998,
        "id": 123,
        "segment_by": "savedfilter_metric_29644"
    }
    # Execute
    command_response = list_third_party_asi_assets_command(client, args)

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_pt_list_my_asi_insights_command_sorted_hr(request_mocker, client):
    """
        Test case scenario for sorted hr response for pt-list-my-attack-surface-insights
    """
    from PassiveTotal_v2 import list_my_asi_insights_command

    # Configure
    args = {
        'priority': 'high',
    }
    with open('test_data/ASI_Insights/asi_insights_command_sorted_hr_response.json', 'r') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Insights/asi_insights_command_sorted_readable_output.md', 'r') as f:
        dummy_readable_output = f.read()

    request_mocker.return_value = dummy_response

    # Execute
    response = list_my_asi_insights_command(client, args)

    # Assert
    assert response.readable_output == dummy_readable_output
    assert response.raw_response == dummy_response


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_vulnerable_components_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_asi_vulnerable_components_command

    with open('test_data/ASI_VulnerableComponents/asi_vulnerable_components_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_VulnerableComponents/third_party_asi_vulnerable_components_command_context.json',
              'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_VulnerableComponents/asi_vulnerable_components_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": 45998,
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_third_party_asi_vulnerable_components_command(client, args)

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, err_msg", input_data.list_third_party_asi_vulnerable_component_invalid_args)
def test_list_third_party_asi_vulnerable_components_command_when_invalid_args_provided(args, err_msg, client):
    """Test case scenario when invalid arguments are provided for pt-list-third-party-asi-vulnerable-components."""
    from PassiveTotal_v2 import list_third_party_asi_vulnerable_components_command

    with pytest.raises(ValueError) as de:
        list_third_party_asi_vulnerable_components_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_vulnerable_components_command_when_empty_response_is_returned(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-third-party-asi-vulnerable-components command with an empty
    response.
    """
    from PassiveTotal_v2 import list_third_party_asi_vulnerable_components_command, MESSAGES

    request_mocker.return_value = {"vulnerableComponents": []}
    command_results = list_third_party_asi_vulnerable_components_command(client, {"id": 45998, "page_number": "100"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('third party vulnerable components')


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_attack_surface_vulnerabilities_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_attack_surface_vulnerabilities_command

    with open('test_data/ASI_Vulnerability/asi_vulnerability_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Vulnerability/third_party_asi_vulnerability_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Vulnerability/asi_vulnerability_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": 45998,
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_third_party_attack_surface_vulnerabilities_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_attack_surface_vulnerabilities_command_when_empty_response_is_returned(request_mocker,
                                                                                                 client):
    """
    Test case scenario for successful execution of pt-list-third-party-attack-surface-vulnerabilities command with an
    empty response.
    """
    from PassiveTotal_v2 import list_third_party_attack_surface_vulnerabilities_command, MESSAGES

    request_mocker.return_value = {"cves": []}
    command_results = list_third_party_attack_surface_vulnerabilities_command(client,
                                                                              {"id": 45998, "page_number": "100"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('third party vulnerabilities')


@pytest.mark.parametrize("args, err_msg", input_data.list_third_party_asi_vulnerable_component_invalid_args)
def test_list_third_party_attack_surface_vulnerabilities_command_when_invalid_args_provided(args, err_msg, client):
    """Test case scenario when invalid arguments are provided for pt-list-third-party-attack-surface-vulnerabilities."""
    from PassiveTotal_v2 import list_third_party_attack_surface_vulnerabilities_command

    with pytest.raises(ValueError) as de:
        list_third_party_attack_surface_vulnerabilities_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_observations_command_success(request_mocker, client):
    """
        Positive case (HR and contextData) should be validated.
    """
    from PassiveTotal_v2 import list_third_party_asi_observations_command

    with open('test_data/ASI_Observations/asi_observation_command_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Observations/third_party_asi_observation_command_context.json', 'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Observations/asi_observation_command_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": 45998,
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_third_party_asi_observations_command(client, args)

    # Assert
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@pytest.mark.parametrize("args, err_msg", input_data.list_third_party_asi_observation_invalid_args)
def test_list_third_party_asi_observations_command_when_invalid_args_are_provided(args, err_msg, client):
    """
    To test pt-list-third-party-attack-surface-observations command when invalid arguments are provided.
    """
    from PassiveTotal_v2 import list_third_party_asi_observations_command
    with pytest.raises(ValueError) as de:
        list_third_party_asi_observations_command(client, args)
    assert str(de.value) == err_msg


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_asi_observations_command_success_object_not_present(request_mocker, client):
    """
        Test case scenario for pt-list-third-party-attack-surface-observations when object not present
    """
    from PassiveTotal_v2 import list_third_party_asi_observations_command

    with open('test_data/ASI_Observations/asi_observation_command_object_not_present_response.json', 'rb') as f:
        dummy_response = json.load(f)

    with open('test_data/ASI_Observations/third_party_asi_observation_command_object_not_present_context.json',
              'rb') as f:
        dummy_context = json.load(f)

    with open('test_data/ASI_Observations/asi_observations_command_object_not_present_readable_output.md', 'r') as f:
        readable_output = f.read()

    request_mocker.return_value = dummy_response

    args = {
        "id": 45998,
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }
    # Execute
    command_response = list_third_party_asi_observations_command(client, args)

    # Assert

    assert command_response.readable_output == readable_output
    assert command_response.raw_response == dummy_response
    assert command_response.outputs == dummy_context


@patch('PassiveTotal_v2.Client.http_request')
def test_list_third_party_attack_surface_observations_command_when_empty_response_is_returned(request_mocker,
                                                                                              client):
    """
    Test case scenario for successful execution of pt-list-third-party-attack-surface-observations command with an
    empty response.
    """
    from PassiveTotal_v2 import list_third_party_asi_observations_command, MESSAGES

    request_mocker.return_value = {"assets": []}

    args = {
        "id": 45998,
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }

    command_results = list_third_party_asi_observations_command(client, args)

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('third party observations')


@patch('PassiveTotal_v2.Client.http_request')
def test_list_my_asi_observations_command_when_empty_response_is_returned(request_mocker, client):
    """
    Test case scenario for successful execution of pt-list-my-attack-surface-observations command with an
    empty response.
    """
    from PassiveTotal_v2 import list_my_asi_observations_command, MESSAGES

    request_mocker.return_value = {"assets": []}

    args = {
        "cve_id": "CVE-2021-23017",
        "page_size": 2,
        "page_number": 0
    }

    command_results = list_my_asi_observations_command(client, args)

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('observations')
