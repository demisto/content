import json
from unittest import mock
from unittest.mock import patch

import pytest
from requests.exceptions import MissingSchema, InvalidSchema

import demistomock as demisto
from CommonServerPython import DemistoException

MOCK_URL = 'http://123-fake-api.com'


@pytest.fixture()
def client():
    from RiskIQDigitalFootprint import Client
    return Client(MOCK_URL, 30, False, False, ('API_TOKEN', 'API_SECRET'))


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


@patch('RiskIQDigitalFootprint.Client._http_request')
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


@patch('RiskIQDigitalFootprint.Client._http_request')
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


@patch("RiskIQDigitalFootprint.Client._http_request")
def test_http_request_bad_request_error(mock_base_http_request, client):
    # Configure
    resp_json = json.loads('{"error": "Id:dummy could not be normalized"}')
    mock_base_http_request.return_value = mock_http_response(status=400, json_data=resp_json)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'An error occurred while fetching the data.' \
           ' Reason: Id:dummy could not be normalized' == str(e.value)


@patch("RiskIQDigitalFootprint.Client._http_request")
def test_http_request_authentication_error(mock_base_http_request, client):
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=401)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Unauthenticated. Check the configured API token and API secret.' == str(e.value)


@patch("RiskIQDigitalFootprint.Client._http_request")
def test_http_request_page_not_found_error(mock_base_http_request, client):
    # Configure
    resp_json = json.loads('{"error": "Asset with id: dummy not found"}')
    mock_base_http_request.return_value = mock_http_response(status=404, json_data=resp_json)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'No record(s) found. Reason: Asset with id: dummy not found' == str(e.value)


@patch("RiskIQDigitalFootprint.Client._http_request")
def test_http_request_internal_server_error(mock_base_http_request, client):
    # Configure
    mock_base_http_request.return_value = mock_http_response(status=500)

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'The server encountered an internal error for RiskIQ Digital Footprint and' \
           ' was unable to complete your request.' == str(e.value)


@patch("RiskIQDigitalFootprint.Client._http_request")
def test_http_request_raise_for_status(mock_base_http_request, client):
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
    import RiskIQDigitalFootprint

    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(RiskIQDigitalFootprint, 'test_function', return_value='ok')
    RiskIQDigitalFootprint.main()
    assert RiskIQDigitalFootprint.test_function.called


@patch('RiskIQDigitalFootprint.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function get some exception then valid message should be print.
    """
    import RiskIQDigitalFootprint

    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(RiskIQDigitalFootprint, 'test_function', side_effect=Exception)
    with capfd.disabled():
        RiskIQDigitalFootprint.main()

    mock_return_error.assert_called_once_with('Error: ')


def test_init():
    """
        test init function
    """
    import RiskIQDigitalFootprint
    with mock.patch.object(RiskIQDigitalFootprint, "main", return_value=42):
        with mock.patch.object(RiskIQDigitalFootprint, "__name__", "__main__"):
            RiskIQDigitalFootprint.init()


@patch('RiskIQDigitalFootprint.Client._http_request')
def test_http_request_proxy_error(mock_base_http_request, client):
    """
        When http request return proxy error with exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ProxyError')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or' \
           ' check the host, authentication details and connection details for the proxy.' == str(e.value)


@patch('RiskIQDigitalFootprint.Client._http_request')
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


@patch('RiskIQDigitalFootprint.Client._http_request')
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
    assert 'Connectivity failed. Check your internet connection or the API URL.' == str(e.value)


@patch('RiskIQDigitalFootprint.Client._http_request')
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
    assert 'Connection timed out. Check your internet connection or try decreasing the' \
           ' value of the size argument if specified.' == str(e.value)


@patch('RiskIQDigitalFootprint.Client._http_request')
def test_http_request_read_timeout_error(mock_base_http_request, client):
    """
        When http request return read timeout error with Demisto exception then appropriate error message
        should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ReadTimeoutError')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', '/test/url/suffix')

    # Assert
    assert 'Connection timed out. Check your internet connection or try decreasing the' \
           ' value of the size argument if specified.' == str(e.value)


@patch('RiskIQDigitalFootprint.Client._http_request')
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


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_function_success(request_mocker, client):
    """
       When response is successfully fetched then test_function command should pass.
    """
    from RiskIQDigitalFootprint import test_function

    mock_response = {
        'results': 0,
        'domains': []
    }
    request_mocker.return_value = mock_response

    assert test_function(client) == 'ok'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_connections_success(mocker_http_request, client):
    """
        When df-asset-connections command is provided valid arguments it should pass
    """
    from RiskIQDigitalFootprint import asset_connections_command

    # Fetching expected raw response from file
    with open('test_data/asset_connections_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('success')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/asset_connections_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/asset_connections_hr.md') as f:
        expected_hr = f.read()

    result = asset_connections_command(client, args={'name': 'dummy', 'type': 'ASN', 'global': 'true',
                                                     'size': 2})

    assert result[1].raw_response == expected_res
    assert result[1].outputs == expected_custom_ec[0]
    assert result[2].outputs == expected_custom_ec[1]
    assert result[3].outputs == expected_custom_ec[2]
    assert result[4].outputs == expected_custom_ec[3]
    for res in result:
        assert res.readable_output in expected_hr
    assert result[1].outputs_key_field == 'uuid'
    assert result[1].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_connections_no_record_found(mocker_http_request, client):
    """
        When df-asset-connections command is provided valid arguments but no records are found in
        response it should pass
    """
    from RiskIQDigitalFootprint import asset_connections_command

    # Fetching expected raw response from file
    with open('test_data/asset_connections_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('zeroRecords')
    mocker_http_request.return_value = expected_res

    result = asset_connections_command(client, args={'name': 'dummy', 'type': 'ASN', 'global': 'false'})
    assert result == 'No connected assets were found for the given argument(s). If the page argument is specified, try' \
                     ' decreasing its value.'


def test_asset_connections_invalid_type(client):
    """
        When df-asset-connections command is provided invalid type argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_connections_args_and_get_params

    with pytest.raises(ValueError) as e:
        validate_asset_connections_args_and_get_params(args={'type': 'dummy'})

    assert 'The given value for type is invalid. Valid Types: Domain, Host,' \
           ' IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only.' \
           == str(e.value)


def test_asset_connections_invalid_global(client):
    """
        When df-asset-connections command is provided invalid global argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_connections_args_and_get_params

    with pytest.raises(ValueError) as e:
        validate_asset_connections_args_and_get_params(args={'type': 'DOMAIN', 'global': 'dummy'})

    assert 'The given value for global argument is invalid. Valid values: true, false.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_connections_exceeding_page_lower_limit(client):
    """
        When df-asset-connections command is provided with a value that exceeds lower limit of page
         argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_connections_args_and_get_params

    with pytest.raises(ValueError) as e:
        validate_asset_connections_args_and_get_params(args={'type': 'DOMAIN', 'page': '-2'})

    assert 'Page argument must be 0 or a positive integer. The index is zero based so the first page is page 0.'\
           == str(e.value)


def test_asset_connections_invalid_page(client):
    """
        When df-asset-connections command is provided with an invalid value of page
         argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_connections_args_and_get_params

    with pytest.raises(ValueError) as e:
        validate_asset_connections_args_and_get_params(args={'type': 'DOMAIN', 'page': '-2'})

    assert 'Page argument must be 0 or a positive integer. The index is zero based so the first page is page 0.'\
           == str(e.value)


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_changes_summary_success(mocker_http_request, client):
    """
        When df-asset-connections command is provided valid arguments it should pass
    """
    from RiskIQDigitalFootprint import asset_changes_summary_command

    # Fetching expected raw response from file
    with open('test_data/asset_changes_summary_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/asset_changes_summary_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/asset_changes_summary_hr.md') as f:
        expected_hr = f.read()

    result = asset_changes_summary_command(client, args={'date': '2020-05-12', 'range': '7', 'tag': 'Dummy',
                                                         'organization': 'Dummy', 'brand': 'Dummy'})

    assert result.raw_response == expected_res
    assert result.outputs == expected_custom_ec
    assert result.readable_output == expected_hr
    assert result.outputs_key_field == 'runDate'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.AssetSummary'


def test_asset_changes_summary_deep_link_with_only_date(client):
    """
        When df-asset-changes-summary command is provided valid date argument it should give a proper deep link
    """
    from RiskIQDigitalFootprint import prepare_deep_link_for_asset_changes_summary

    args = {
        'date': '2020-06-05',
        'range': ''
    }

    # Fetching expected raw response from file
    with open('test_data/asset_changes_summary_resp.json', encoding='utf-8') as f:
        resp = json.load(f)

    deep_link = prepare_deep_link_for_asset_changes_summary(resp, args['date'], args['range'])

    assert 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/2020-06-05' == deep_link


def test_asset_changes_summary_deep_link_with_only_range(client):
    """
        When df-asset-changes-summary command is provided valid range argument it should give a proper deep link
    """
    from RiskIQDigitalFootprint import prepare_deep_link_for_asset_changes_summary

    args = {
        'date': '',
        'range': '30'
    }

    # Fetching expected raw response from file
    with open('test_data/asset_changes_summary_resp.json', encoding='utf-8') as f:
        resp = json.load(f)

    deep_link = prepare_deep_link_for_asset_changes_summary(resp, args['date'], args['range'])

    assert 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/2020-05-26/30' == deep_link


def test_asset_changes_summary_invalid_date(client):
    """
        When df-asset-changes-summary command is provided invalid date argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_changes_summary_args

    args = {
        'date': '2002-2-05',
        'range': ''
    }
    with pytest.raises(ValueError) as e:
        validate_asset_changes_summary_args(args['date'], args['range'])

    assert 'The given value for date is invalid. The accepted format for date is YYYY-MM-DD.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_summary_invalid_date_exception(client):
    """
        When df-asset-changes-summary command is provided invalid date argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_changes_summary_args

    args = {
        'date': '2002-2-055',
        'range': ''
    }
    with pytest.raises(ValueError) as e:
        validate_asset_changes_summary_args(args['date'], args['range'])

    assert 'The given value for date is invalid. The accepted format for date is YYYY-MM-DD.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_summary_invalid_range(client):
    """
        When df-asset-changes-summary command is provided invalid range argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_asset_changes_summary_args

    args = {
        'date': '2020-05-12',
        'range': '5'
    }

    with pytest.raises(ValueError) as e:
        validate_asset_changes_summary_args(args['date'], args['range'])

    assert 'The given value for range is invalid. Valid values: 1, 7, 30.' \
           ' This argument supports a single value only.' == str(e.value)


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_changes_success_asset_type(mocker_http_request, client):
    """
        When df-asset-changes command is provided valid arguments with valid asset type it should pass
    """
    from RiskIQDigitalFootprint import asset_changes_command

    # Fetching expected raw response from file
    with open('test_data/asset_changes_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successAssetType')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/asset_changes_custom_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successAssetType')

    # Fetching expected human readable from file
    with open('test_data/asset_changes_hr.md') as f:
        expected_hr = f.read()

    result = asset_changes_command(client, args={'range': '30', 'type': 'DOMAIN', 'organization': 'dummy',
                                                 'measure': 'Added', 'size': 1})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ['name', 'type']
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.AssetChanges'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_changes_success_asset_detail_type(mocker_http_request, client):
    """
        When df-asset-changes command is provided valid arguments with valid asset detail type it should pass
    """
    from RiskIQDigitalFootprint import asset_changes_command

    # Fetching expected raw response from file
    with open('test_data/asset_changes_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('successAssetDetailType')
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/asset_changes_custom_ec.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_custom_ec = json_file.get('successAssetDetailType')

    # Fetching expected human readable from file
    with open('test_data/asset_changes_resource_hr.md') as f:
        expected_hr = f.read()

    result = asset_changes_command(client, args={'type': 'SELF_HOSTED_RESOURCE', 'range': '1', 'measure': 'Added',
                                                 'size': 200})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == ['id', 'resource']
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.AssetChanges'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_asset_changes_no_record_found(mocker_http_request, client):
    """
        When df-asset-changes command is provided valid arguments but no records are found in
        response it should pass
    """
    from RiskIQDigitalFootprint import asset_changes_command

    # Fetching expected raw response from file
    with open('test_data/asset_changes_resp.json', encoding='utf-8') as f:
        json_file = json.load(f)
    expected_res = json_file.get('zeroRecords')
    mocker_http_request.return_value = expected_res

    result = asset_changes_command(client, args={'type': 'DOMAIN', 'size': 200})
    assert result == 'No inventory change(s) were found for the given argument(s).'


def test_asset_changes_deep_link_with_only_date(client):
    """
        When df-asset-changes command is provided valid date argument it should give a proper deep link
    """
    from RiskIQDigitalFootprint import prepare_deep_link_for_asset_changes

    args = {
        'type': 'DOMAIN',
        'measure': 'Removed',
        'date': '2020-06-05',
        'range': ''
    }

    # Fetching expected raw response from file
    with open('test_data/asset_changes_resp.json', encoding='utf-8') as f:
        resp = json.load(f)
    resp = resp.get('successAssetType')

    deep_link = prepare_deep_link_for_asset_changes(resp.get('content')[0].get('runDate'), args['type'],
                                                    args['measure'], args['date'], args['range'])

    assert 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/details/date=2020-06-05' \
           '&measure=REMOVED&range=1&type=DOMAIN' == deep_link


def test_asset_changes_deep_link_with_date_and_range(client):
    """
        When df-asset-changes command is provided valid date and range arguments it should give a proper deep link
    """
    from RiskIQDigitalFootprint import prepare_deep_link_for_asset_changes

    args = {
        'type': 'IP_ADDRESS',
        'measure': 'Added',
        'date': '2020-06-13',
        'range': '30'
    }

    # Fetching expected raw response from file
    with open('test_data/asset_changes_resp.json', encoding='utf-8') as f:
        resp = json.load(f)
    resp = resp.get('successAssetType')

    deep_link = prepare_deep_link_for_asset_changes(resp.get('content')[0].get('runDate'), args['type'],
                                                    args['measure'], args['date'], args['range'])

    assert 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/details/date=2020-06-13' \
           '&measure=ADDED&range=30&type=IP_ADDRESS' == deep_link


def test_asset_changes_invalid_type(client):
    """
        When df-asset-changes command is provided invalid type argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'type': 'dummy'})

    assert 'The given value for type is invalid. Valid asset types: Domain, Host, IP Address, IP Block, ASN, Page,' \
           ' SSL Cert, Contact. Valid asset detail types: Self Hosted Resource, ThirdParty Hosted Resource.' \
           ' This argument supports a single value only.' \
           == str(e.value)


def test_asset_changes_invalid_date_exception(client):
    """
        When df-asset-changes command is provided invalid date argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'type': 'ASN', 'date': '2020-5-222'})

    assert 'The given value for date is invalid. The accepted format for date is YYYY-MM-DD.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_invalid_date(client):
    """
        When df-asset-changes command is provided invalid date argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'type': 'ASN', 'date': '2020-05-2'})

    assert 'The given value for date is invalid. The accepted format for date is YYYY-MM-DD.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_invalid_range_for_asset_type(client):
    """
        When df-asset-changes command is provided invalid range argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'range': '5', 'tag': 'dummy', 'brand': 'dummy',
                                       'organization': 'dummy', 'type': 'DOMAIN', 'date': '2020-05-20'})

    assert 'The given value for range is invalid. Valid values: 1, 7, 30.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_invalid_range_for_asset_detail_type(client):
    """
        When df-asset-changes command is provided invalid range argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'range': '30', 'tag': 'dummy', 'brand': 'dummy',
                                       'organization': 'dummy', 'type': 'SELF_HOSTED_RESOURCE'})

    assert 'The given value for range is invalid. Only single day changes can be shown for Self Hosted Resource type.' \
           ' Valid value: 1. This argument supports a single value only.' == str(e.value)


def test_asset_changes_invalid_measure_for_asset_type(client):
    """
        When df-asset-changes command is provided invalid range argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'measure': 'CHANGED', 'type': 'DOMAIN'})

    assert 'The given value for measure(type of change) is invalid. Valid options are Added or Removed.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_invalid_measure_for_asset_detail_type(client):
    """
        When df-asset-changes command is provided invalid range argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'measure': 'REMOVED', 'type': 'SELF_HOSTED_RESOURCE'})

    assert 'The given value for measure(type of change) is invalid. Valid options are Added or Changed.' \
           ' This argument supports a single value only.' == str(e.value)


def test_asset_changes_exceeding_page_lower_limit(client):
    """
        When df-asset-changes command is provided with a value that exceeds lower limit of page
         argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'type': 'DOMAIN', 'size': 100, 'page': '-2'})

    assert 'Page argument must be 0 or a positive integer. The index is zero based so the first page is page 0.'\
           == str(e.value)


def test_asset_changes_invalid_page(client):
    """
        When df-asset-changes command is provided with an invalid value of page
         argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_changes_params

    with pytest.raises(ValueError) as e:
        get_asset_changes_params(args={'type': 'DOMAIN', 'size': 100, 'page': 'dummy'})

    assert 'Page argument must be 0 or a positive integer. The index is zero based so the first page is page 0.'\
           == str(e.value)


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_domain(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid Domain uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_domain_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_domain_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_domain_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': '42696470-7b2a-617b-2f5e-ab674438e4f5', 'global': 'true',
                                             'recent': 'true'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_host(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid Host uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_host_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_host_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_host_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': 'dffa643e-7d39-4687-d35d-f37a217f339c', 'global': 'true'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_ip_address(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid IP Address uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_ip_address_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_ip_address_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_ip_address_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': '72ca2677-2276-90cc-048a-546ebed63e2f'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_ip_block(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid IP Block uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_ip_block_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_ip_block_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_ip_block_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': '92b3f425-d5ba-385a-f10c-6c6678d6369f'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_as(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid AS uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_as_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_as_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_as_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': '9ca2cd53-af69-cbca-f398-e891ecf413d3'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_page(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid Page uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_page_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_page_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_page_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': '8dfdd21e-5012-3bd6-f9a5-c3151f1b9e40'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_ssl_cert(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid SSL Cert uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_ssl_cert_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_ssl_cert_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_ssl_cert_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': 'd02ea1d1-7129-094a-50b0-3b285798d28d'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_success_for_contact(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_contact_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_contact_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_contact_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'uuid': 'd02ea1d1-7129-094a-50b0-3b285798d28d'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_by_name_and_type_success_for_host(mocker_http_request, client):
    """
        When df-get_asset command isa provided valid arguments with valid Host name and type it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_by_name_host_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_by_name_host_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_by_name_host_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'name': 'www.dummy.com', 'type': 'HOST', 'global': 'true',
                                             'recent': 'true'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_by_name_and_type_success_for_ip_address(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid IP Address name and type it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_by_name_ip_address_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_by_name_ip_address_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_by_name_ip_address_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'name': 'dummy.ip', 'type': 'IP_ADDRESS',
                                             'recent': 'true'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_get_asset_by_name_and_type_success_for_as(mocker_http_request, client):
    """
        When df-get_asset command is provided valid arguments with valid AS name and type it should pass
    """
    from RiskIQDigitalFootprint import get_asset_command

    # Fetching expected raw response from file
    with open('test_data/get_asset_by_name_as_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res

    # Fetching expected entry context details from file
    with open('test_data/get_asset_by_name_as_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)

    # Fetching expected human readable from file
    with open('test_data/get_asset_by_name_as_hr.md') as f:
        expected_hr = f.read()

    result = get_asset_command(client, args={'name': '63245', 'type': 'ASN',
                                             'recent': 'true'})

    assert result[0].raw_response == expected_res
    assert result[0].outputs == expected_custom_ec
    assert result[0].readable_output == expected_hr
    assert result[0].outputs_key_field == 'uuid'
    assert result[0].outputs_prefix == 'RiskIQDigitalFootprint.Asset'


def test_get_asset_invalid_global(client):
    """
        When df-get-asset command is provided invalid global argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_params

    args = {
        'uuid': 'dummy',
        'global': 'dummy'
    }

    with pytest.raises(ValueError) as e:
        get_asset_params(args)

    assert 'The given value for global argument is invalid. Valid values: true, false.' \
           ' This argument supports a single value only.' == str(e.value)


def test_get_asset_invalid_recent(client):
    """
        When df-get-asset command is provided invalid global argument it should give an error message
    """
    from RiskIQDigitalFootprint import get_asset_params

    args = {
        'uuid': 'dummy',
        'recent': 'dummy'
    }

    with pytest.raises(ValueError) as e:
        get_asset_params(args)

    assert 'The given value for recent argument is invalid. Valid values: true, false.' \
           ' This argument supports a single value only.' == str(e.value)


def test_get_asset_invalid_asset_type(client):
    """
        When df-get-asset command is provided invalid type argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_and_fetch_get_asset_arguments

    args = {
        'name': 'dummy',
        'type': 'dummy'
    }

    with pytest.raises(ValueError) as e:
        validate_and_fetch_get_asset_arguments(args)

    assert 'The given value for type is invalid. Valid Types: Domain, Host, IP Address, IP Block, ASN, Page,' \
           ' SSL Cert, Contact. This argument supports a single value only.' == str(e.value)


def test_get_asset_invalid_combination_of_arguments(client):
    """
        When df-get-asset command is provided invalid combination of arguments it should give an error message
    """
    from RiskIQDigitalFootprint import validate_and_fetch_get_asset_arguments

    args = {
        'name': 'dummy',
        'uuid': 'dummy'
    }

    with pytest.raises(ValueError) as e:
        validate_and_fetch_get_asset_arguments(args)

    assert 'Argument uuid cannot be used with other arguments except global and recent.' == str(e.value)


def test_get_asset_when_type_is_not_passed_with_name_argument(client):
    """
        When df-get-asset command is provided valid name but no type argument it should give an error message
    """
    from RiskIQDigitalFootprint import validate_and_fetch_get_asset_arguments

    args = {
        'name': 'dummy'
    }

    with pytest.raises(ValueError) as e:
        validate_and_fetch_get_asset_arguments(args)

    assert 'Required argument(s) uuid or [name, type] to get asset details. One or more of them are not present.'\
           == str(e.value)


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_success_for_single_asset(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import add_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskComplete']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['success']

    result = add_assets_command(client, args={'name': 'test', 'type': 'Domain', 'state': 'Candidate',
                                              'priority': 'High', 'enterprise': 'true', 'tag': 'dummy',
                                              'confirm': 'true', 'target_asset_types': 'IP_ADDRESS',
                                              'fail_on_error': 'true'})

    assert result.raw_response == expected_res['taskComplete']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The requested asset(s) have been successfully added.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_success_for_asset_json(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import add_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskComplete']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['success']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    result = add_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskComplete']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The requested asset(s) have been successfully added.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_failed_for_asset_json(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import add_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskFailed']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['failed']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    result = add_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskFailed']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The request for adding asset(s) failed. Reason: An unexpected error occurred.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_incomplete_for_asset_json(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import add_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskIncomplete']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['incomplete']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    result = add_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskIncomplete']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The request for adding asset(s) is incomplete.' \
                                     ' Reason: An unexpected error occurred.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_warning_for_asset_json(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import add_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskWarning']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['warning']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    result = add_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskWarning']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The request for adding asset(s) is completed with a warning.' \
                                     ' Reason: An unexpected error occurred.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_update_asset_success_for_single_asset(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import update_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskComplete']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['success']

    result = update_assets_command(client, args={'name': 'test', 'type': 'ASN', 'removed_state': 'Dismissed',
                                                 'target_asset_types': 'IP_ADDRESS', 'fail_on_error': 'true',
                                                 'action': 'Remove'})

    assert result.raw_response == expected_res['taskComplete']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The requested asset(s) have been successfully updated.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_update_asset_success_for_asset_json(mocker_http_request, client):
    """
        When df-add-assets command is provided valid arguments with valid Contact uuid it should pass
    """
    from RiskIQDigitalFootprint import update_assets_command

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskComplete']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['success']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    result = update_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskComplete']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The requested asset(s) have been successfully updated.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


def test_add_and_update_asset_invalid_type(client):
    """
        When df-add-assets or df-update-assets command is provided invalid type argument it should give an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='add')
    assert 'The given value for type is invalid. Valid Types: Domain, Host,' \
           ' IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only.' \
           == str(e.value)


def test_add_and_update_asset_with_no_properties(client):
    """
        When df-add-assets or df-update-assets command is not provided any property argument it should give an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='update')
    assert 'At least one property argument should have a value in order to update the asset. ' \
           'The property arguments are: state, priority, removed_state, brand, ' \
           'organization, tag and enterprise.' == str(e.value)


def test_add_and_update_asset_invalid_state(client):
    """
        When df-add-assets or df-update-assets command is provided invalid state argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'state': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='update')
    assert 'The given value for state is invalid. Valid States: Candidate, Approved Inventory, ' \
           'Requires Investigation, Dependencies, Monitor Only. This argument supports a single value only.'\
           == str(e.value)


def test_add_and_update_asset_invalid_priority(client):
    """
        When df-add-assets or df-update-assets command is provided invalid priority argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'priority': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='add')
    assert 'The given value for priority is invalid. Valid Priority levels: High, Medium, Low, None. This argument' \
           ' supports a single value only.' == str(e.value)


def test_add_and_update_asset_invalid_enterprise(client):
    """
        When df-add-assets or df-update-assets command is provided invalid enterprise argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'enterprise': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='update')
    assert 'The given value for enterprise argument is invalid. Valid values: true, false. ' \
           'This argument supports a single value only.' == str(e.value)


def test_add_and_update_asset_invalid_confirm(client):
    """
        When df-add-assets or df-update-assets command is provided invalid confirm argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'confirm': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='add')
    assert 'The given value for confirm argument is invalid. Valid values: true, false. ' \
           'This argument supports a single value only.' == str(e.value)


def test_add_and_update_asset_invalid_removed_state(client):
    """
        When df-add-assets or df-update-assets command is provided invalid removed state argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'removed_state': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='update')
    assert 'The given value for removed state is invalid. Valid value: Dismissed. This argument supports a' \
           ' single value only.' == str(e.value)


def test_update_asset_invalid_action(client):
    """
        When df-update-assets command is provided invalid action argument it should give
        an error message
    """
    from RiskIQDigitalFootprint import prepare_single_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'action': 'dummy',
        'brand': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        prepare_single_asset_payload(args, operation='update')
    assert 'The given value for action is invalid. Valid values: Add, Remove, Update. This argument supports' \
           ' a single value only.' == str(e.value)


def test_add_and_update_asset_invalid_arguments(client):
    """
        When df-add-assets or df-update-assets command is provided with asset_json and other arguments it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        'name': 'xyz',
        'type': 'IP_ADDRESS',
        'asset_json': '{"assets":[{"name": "xyz"}]}'
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='add')
    assert 'Argument asset_json cannot be used with other arguments except fail_on_error.' == str(e.value)


def test_add_and_update_asset_required_arguments(client):
    """
        When df-add-assets or df-update-assets command is not provided with required arguments it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        'state': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='add')
    assert 'Argument asset_json or arguments name and type are required to add an asset.' == str(e.value)


def test_add_and_update_asset_required_keys(client):
    """
        When df-add-assets or df-update-assets command is not provided with required keys in json it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        'asset_json': {"assets": [{"name": "xyz"}]}
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='add')
    assert "Required keys for add asset(s) are ['assets', 'properties']. One or more of them are not present in the" \
           " asset JSON." == str(e.value)


def test_add_and_update_asset_required_keys_in_asset(client):
    """
        When df-add-assets or df-update-assets command is not provided with required keys in json it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        'asset_json': {"assets": [{"name": "xyz"}], "properties": []}
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='update')
    assert "Required keys for update asset(s) are ['name', 'type'] in assets key." \
           " One or more of them are not present in the asset JSON." == str(e.value)


def test_add_and_update_asset_invalid_value_fail_on_error(client):
    """
        When df-add-assets or df-update-assets command is not provided with required keys in json it should give
        an error message
    """
    from RiskIQDigitalFootprint import get_add_and_update_assets_params

    args = {
        'name': 'dummy',
        'type': 'IP_ADDRESS',
        'fail_on_error': 'dummy'
    }
    with pytest.raises(ValueError) as e:
        get_add_and_update_assets_params(args)
    assert 'The given value for fail_on_error argument is invalid. Valid values: true, false. ' \
           'This argument supports a single value only.' == str(e.value)


def test_update_asset_required_keys_in_asset_json(client):
    """
        When df-add-assets or df-update-assets command is not provided with required keys in json it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        "asset_json": {
            "query": {
                "filters": {
                    "condition": "AND",
                    "value": [
                        {"name": "type", "operator": "IN", "value": ["IP_BLOCK"]},
                        {"name": "state", "operator": "IN", "value": ["CANDIDATE"]}
                    ]
                }
            },
            "dummy": [{"name": "tag", "value": ["Tag1"], "action": "ADD"}]
        }
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='update')
    assert "Required keys for update asset(s) are ['assets', 'properties'] or ['query', 'properties']. One or more of" \
           " them are not present in the asset JSON." == str(e.value)


def test_add_and_update_asset_required_keys_in_asset_json(client):
    """
        When df-add-assets or df-update-assets command is not provided with required keys in json it should give
        an error message
    """
    from RiskIQDigitalFootprint import validate_asset_payload

    args = {
        "asset_json": {
            "dummyQuery": {
                "filters": {
                    "condition": "AND",
                    "value": [
                        {"name": "type", "operator": "IN", "value": ["IP_BLOCK"]},
                        {"name": "state", "operator": "IN", "value": ["CANDIDATE"]}
                    ]
                }
            },
            "dummy": [{"name": "tag", "value": ["Tag1"], "action": "ADD"}]
        }
    }
    with pytest.raises(ValueError) as e:
        validate_asset_payload(args, operation='update')
    assert "Required keys for update asset(s) are ['assets', 'properties'] or ['query', 'properties']. One or more of" \
           " them are not present in the asset JSON." == str(e.value)


def task_status(client, resp):
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    task_resp = expected_res['taskRunning']
    return task_resp


@patch('RiskIQDigitalFootprint.Client.http_request')
def test_add_asset_success_for_asset_json_retries(mocker_http_request, client, mocker):
    """
        When df-add-assets command is provided valid arguments with valid arguments it should pass
    """
    import RiskIQDigitalFootprint

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_resp.json', encoding='utf-8') as f:
        expected_res = json.load(f)
    mocker_http_request.return_value = expected_res['taskRunning']

    # Fetching expected entry context details from file
    with open('test_data/add_and_update_assets_custom_ec.json', encoding='utf-8') as f:
        expected_custom_ec = json.load(f)
    expected_custom_ec = expected_custom_ec['running']

    # Fetching expected raw response from file
    with open('test_data/add_and_update_assets_asset_json.json', encoding='utf-8') as f:
        asset_json_arg = json.load(f)

    mocker.patch.object(RiskIQDigitalFootprint, 'check_task_status', side_effect=task_status)

    result = RiskIQDigitalFootprint.add_assets_command(client, args={'asset_json': asset_json_arg})

    assert result.raw_response == expected_res['taskRunning']
    assert result.outputs == expected_custom_ec
    assert result.readable_output == '### The request for adding asset(s) has been successfully submitted. ' \
                                     'You can check its status using this task identifier/reference: ' \
                                     '3fa02425-f8d8-4f75-a630-4a4b92222153 in RiskIQ Digital Footprint.'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs_prefix == 'RiskIQDigitalFootprint.Task'


def args_validation(client, args):
    assert args == {'name': 'dummy', 'type': 'ASN', 'global': 'true'}


def test_command_with_strip_args_from_main_success(mocker, client):
    """
        When main function is called get_asset_command should be called and the arguments should be stripped.
    """
    import RiskIQDigitalFootprint

    mocker.patch.object(demisto, 'command', return_value='df-get-asset')
    mocker.patch.object(demisto, 'args', return_value={'name': 'dummy', 'type': '      ASN          ',
                                                       'global': '   true'})
    mocker.patch.object(RiskIQDigitalFootprint, 'get_asset_command', side_effect=args_validation)
    RiskIQDigitalFootprint.main()


@patch('RiskIQDigitalFootprint.return_error')
def test_command_with_strip_args_from_main_failure(mock_return_error, mocker, client, capfd):
    """
        When main function is called get_asset_command should be called with invalid arguments that cannot stripped
         and appropriate error message should be given.
    """
    import RiskIQDigitalFootprint

    mocker.patch.object(demisto, 'command', return_value='df-asset-connections')
    mocker.patch.object(demisto, 'args', return_value={'name': 'dummy', 'type': 'AS  N'})
    mocker.patch.object(RiskIQDigitalFootprint, 'asset_connections_command',
                        side_effect=ValueError('The given value for type is invalid. Valid Types: Domain, Host,'
                                               ' IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument'
                                               ' supports a single value only.'))

    with capfd.disabled():
        RiskIQDigitalFootprint.main()

    mock_return_error.assert_called_once_with('Error: The given value for type is invalid. Valid Types: Domain, Host,'
                                              ' IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument'
                                              ' supports a single value only.')


def test_request_timeout_and_size_success():
    """
         When valid value for size is passed it should pass
    """
    from RiskIQDigitalFootprint import get_timeout_and_size
    expected_request_timeout, expected_size = 60, 501
    actual_request_timeout_and_size = get_timeout_and_size('501')
    assert actual_request_timeout_and_size == (expected_request_timeout, expected_size)


def test_request_timeout_and_size_failure():
    """
        When invalid value exceeding upper limit is passed for size param it should return an error message
    """
    from RiskIQDigitalFootprint import get_timeout_and_size

    with pytest.raises(ValueError) as e:
        get_timeout_and_size('1001')

    assert 'Size argument must be a positive integer. The value of this argument should be between 1 and 1000.'\
           == str(e.value)


def test_request_timeout_and_size_invalid_value():
    """
        When invalid value is passed for size param it should return an error message
    """
    from RiskIQDigitalFootprint import get_timeout_and_size

    with pytest.raises(ValueError) as e:
        get_timeout_and_size('dummy')

    assert 'Size argument must be a positive integer. The value of this argument should be between 1 and 1000.'\
           == str(e.value)


def validate_size(client, args):
    assert args == {'name': 'dummy', 'type': 'ASN', 'global': 'true', 'size': 400}


def test_command_with_size_arg_from_main_success(mocker, client):
    """
        When main function is called get_asset_command should be called with size argument and it should pass.
    """
    import RiskIQDigitalFootprint

    mocker.patch.object(demisto, 'command', return_value='df-get-asset')
    mocker.patch.object(demisto, 'args', return_value={'name': 'dummy', 'type': '      ASN          ',
                                                       'global': '   true', 'size': '400'})
    mocker.patch.object(RiskIQDigitalFootprint, 'get_asset_command', side_effect=validate_size)
    RiskIQDigitalFootprint.main()
