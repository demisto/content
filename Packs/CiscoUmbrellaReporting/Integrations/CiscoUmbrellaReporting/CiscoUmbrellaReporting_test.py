"""
Tests module for Cisco Umbrella Reporting integration
"""

import pytest
import json
import io
import os
from CommonServerPython import DemistoException
from CiscoUmbrellaReporting import Client, get_destinations_list_command, \
    get_categories_list_command, get_identities_list_command, \
    get_file_list_command, create_cisco_umbrella_args, \
    get_threat_list_command, \
    get_event_types_list_command, get_activity_list_command, \
    get_activity_by_traffic_type_command, \
    get_summary_list_command, pagination, check_valid_indicator_value, \
    get_command_title_string, activity_build_data

client = Client(
    base_url="http://test.com",
    organisation_id="1234567",
    secret_key="test_123",
    client_key="test@12345",
    proxy=False
)


def util_load_json(path):
    with io.open(path, mode='r') as f:
        return json.loads(f.read())


DESTINATION_LIST_RESPONSE = util_load_json('test_data/context_data_output/destination_data.json')
CATEGORY_LIST_RESPONSE = util_load_json('test_data/context_data_output/category_data.json')
IDENTITY_LIST_RESPONSE = util_load_json('test_data/context_data_output/identity_data.json')
FILE_LIST_RESPONSE = util_load_json("test_data/context_data_output/file_data.json")
THREAT_LIST_RESPONSE = util_load_json("test_data/context_data_output/threat_data.json")
EVENT_TYPE_LIST_RESPONSE = util_load_json("test_data/context_data_output/event_type_data.json")
ACTIVITY_LIST_RESPONSE = util_load_json("test_data/context_data_output/activity_data.json")
ACTIVITY_DNS_LIST_RESPONSE = util_load_json("test_data/context_data_output/activity_dns_data.json")
SUMMARY_LIST_RESPONSE = util_load_json("test_data/context_data_output/summary_data.json")
DESTINATION_SUMMARY_LIST_RESPONSE = util_load_json("test_data/context_data_output/destination_summary_data.json")
ACCESS_TOKEN_RESPONSE = util_load_json("test_data/context_data_output/access_token_data.json")
ACTIVITY_FIREWALL_LIST_RESPONSE = util_load_json("test_data/context_data_output/file_data.json")


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_LIST_RESPONSE,
                                                     DESTINATION_LIST_RESPONSE)])
def test_get_destinations_list_command(mocker, raw_response, expected):
    """
    Tests get_destinations_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_destinations_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join("test_data", "command_readable_output/destination_command_readable_output.md"), 'r') as f:
        readable_output = f.read()
    command_results = get_destinations_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(CATEGORY_LIST_RESPONSE,
                                                     CATEGORY_LIST_RESPONSE)])
def test_get_category_list_command(mocker, raw_response, expected):
    """
    Tests get_category_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_category_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join("test_data", "command_readable_output/category_command_readable_output.md"), 'r') as f:
        readable_output = f.read()
    results_without_traffic = get_categories_list_command(client, args)
    # print(results_without_traffic.readable_output)
    args['traffic_type'] = "dns"
    results_with_traffic = get_categories_list_command(client, args)
    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()['Contents']
    detail_with_traffic = results_with_traffic.to_context()['Contents']
    assert detail_without_traffic == expected.get("data")
    assert results_without_traffic.readable_output == readable_output
    assert detail_with_traffic == expected.get("data")
    with pytest.raises(ValueError):
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_categories_list_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(IDENTITY_LIST_RESPONSE,
                                                     IDENTITY_LIST_RESPONSE)])
def test_get_identities_list_command(mocker, raw_response, expected):
    """
    Tests get_identities_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_identities_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/identity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    results_without_traffic = get_identities_list_command(client, args)
    args['traffic_type'] = "dns"
    results_with_traffic = get_identities_list_command(client, args)
    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()['Contents']
    detail_with_traffic = results_with_traffic.to_context()['Contents']
    assert detail_without_traffic == expected.get("data")
    assert results_without_traffic.readable_output == readable_output
    assert detail_with_traffic == expected.get("data")

    with pytest.raises(ValueError):
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_identities_list_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(FILE_LIST_RESPONSE,
                                                     FILE_LIST_RESPONSE)])
def test_get_file_list_command(mocker, raw_response, expected):
    """
    Tests get_file_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_file_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/file_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_file_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(THREAT_LIST_RESPONSE,
                                                     THREAT_LIST_RESPONSE)])
def test_get_threat_list_command(mocker, raw_response, expected):
    """
    Tests get_threat_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_threat_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/threat_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_threat_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(EVENT_TYPE_LIST_RESPONSE,
                                                     EVENT_TYPE_LIST_RESPONSE)])
def test_get_event_types_list_command(mocker, raw_response, expected):
    """
    Tests get_event_types_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_event_types_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/event_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_event_types_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_LIST_RESPONSE,
                                                     ACTIVITY_LIST_RESPONSE)])
def test_get_activity_list_command(mocker, raw_response, expected):
    """
    Tests get_activity_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/activity_list_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["domains"] = "1234"
        get_activity_list_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_by_dns_traffic_type_command(mocker, raw_response,
                                                  expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "dns"
    }
    with open(os.path.join('test_data', 'command_readable_output/dns_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["domains"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["ports"] = "443"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_proxy_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "proxy"
    }
    with open(os.path.join('test_data', 'command_readable_output/proxy_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_ip_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "ip"
    }
    with open(os.path.join('test_data', 'command_readable_output/ip_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_firewall_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "firewall"
    }
    with open(os.path.join('test_data', 'command_readable_output/firewall_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_amp_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "amp"
    }
    with open(os.path.join('test_data', 'command_readable_output/amp_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["sha256"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["domains"] = "google.com"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_intrusion_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "intrusion"
    }
    with open(os.path.join('test_data', 'command_readable_output/intrusion_get_activity_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(ValueError):
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    with pytest.raises(DemistoException):
        args["domains"] = "google.com"
        get_activity_by_traffic_type_command(client, args)


@pytest.mark.parametrize('raw_response, expected', [(SUMMARY_LIST_RESPONSE,
                                                     SUMMARY_LIST_RESPONSE)])
def test_get_summary_list_command(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    with open(os.path.join('test_data', 'command_readable_output/summary_list_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected',
                         [(DESTINATION_SUMMARY_LIST_RESPONSE,
                           DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_category_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "category"
    }
    with open(os.path.join('test_data', 'command_readable_output/category_summary_list_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list_command(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(DESTINATION_SUMMARY_LIST_RESPONSE,
                           DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_destination_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "destination"
    }
    with open(os.path.join('test_data', 'command_readable_output/destination_summary_list_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list_command(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(DESTINATION_SUMMARY_LIST_RESPONSE,
                           DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_intrusion_rule_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks the output of the command function with the expected
            output.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "intrusion_rule"
    }
    with open(os.path.join('test_data',
                           'command_readable_output/intrusion_rule_summary_list_command_readable_output.md'), 'r') as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output
    with pytest.raises(DemistoException):
        args["domains"] = 345678
        get_summary_list_command(client, args)


def test_pagination():
    """
    Tests the pagination function.

        Given:
            no argument required

        When:
            - Running the 'pagination function'.

        Then:
            -  Checks the output of the command function with the
            expected output.
    """
    page = 2
    page_size = 5
    expected_response = (5, 5)

    context_detail = pagination(page, page_size)
    assert context_detail == expected_response


@pytest.mark.parametrize('raw_response', [DESTINATION_LIST_RESPONSE])
def test_test_module(requests_mock, raw_response):
    """
        Tests the test_module function.

            Given:
                no argument required

            When:
                - Running the 'test_module function'.

            Then:
                -  Check weather the given credentials are correct or not
    """
    from CiscoUmbrellaReporting import test_module
    post_req_url = client.token_url
    requests_mock.post(post_req_url, json={'access_token': '12345'})
    access_token = client.access_token()
    get_req_url = f'{client._base_url}/v2/organizations' \
                  f'/{client.organisation_id}/activity'
    headers = {'Authorization': f'Bearer {access_token}'}
    requests_mock.get(get_req_url, headers=headers, json=raw_response)
    output = test_module(client)
    assert output == 'ok'
    with pytest.raises(DemistoException):
        error_output = {
            "meta": {},
            "data": {
                "error": "unauthorized"
            }
        }
        requests_mock.get(get_req_url, headers=headers, status_code=401,
                          json=error_output)
        test_module(client)


def test_access_token(requests_mock):
    """
        Tests the access_token function.

            Given:
                - requests_mock object.

            When:
                - Running the 'get_activity_list_command function'.

            Then:
                -  Checks the output of the command function with the
                expected output.
    """
    req_url = client.token_url

    requests_mock.post(req_url, json={'access_token': '12345'})

    response = client.access_token()
    assert response == "12345"
    with pytest.raises(DemistoException):
        requests_mock.post(req_url, status_code=401)
        client.access_token()
        requests_mock.post(req_url, status_code=400)
        client.access_token()


def test_check_valid_indicator_value():
    """
        Tests the check_valid_indicator_value function

            Given:
                - no argument required.

            When:
                - Running the 'check_valid_indicator_value function'.

            Then:
                -  Checks the output of the command function with the
                expected output.
    """
    indicator = {
        'domains': 'google.com',
        'ip': '1.1.1.1',
        'urls': 'http://www.google.com',
        'intrusion_action': 'would_block'
    }
    for indicator_type, indicator_value in indicator.items():
        result = check_valid_indicator_value(indicator_type, indicator_value)
        assert result
    with pytest.raises(ValueError):
        indicator_value = "abcd23r, google.com"
        check_valid_indicator_value('domains', indicator_value)
    with pytest.raises(ValueError):
        indicator_value = "dummy_sha256"
        check_valid_indicator_value('sha256', indicator_value)


def test_get_command_title_string():
    """
        Tests the get_command_title_string function

            Given:
                - no argument required.

            When:
                - Running the 'get_command_title_string function'.

            Then:
                -  Checks the output of the command function with the
                expected output.
    """

    sub_context = 'Activity'
    result_with_pagination = get_command_title_string(sub_context, 1, 10)
    result_without_pagination = get_command_title_string(sub_context, 0, 0)
    assert result_without_pagination == 'Activity List'
    assert result_with_pagination == 'Activity List\nCurrent page size: ' \
                                     '10\nShowing page 1 out of others that ' \
                                     'may exist'


def test_activity_build_data():
    """
        Tests the activity_build_data function

            Given:
                - no argument required.

            When:
                - Running the 'activity_build_data function'.

            Then:
                -  Checks the output of the command function with the
                expected output.
    """
    activity_data = ACTIVITY_LIST_RESPONSE['data'][0]
    expected_output = {
        'category': [
            'Infrastructure and Content Delivery Networks'
        ],
        'identity': [
            'DESKTOP'
        ],
        'all_application': [],
        'application_category': [],
        'timestamp_string': '2022-09-07T22:49:44Z',
        'signature_cve': [],
        'signature_lebel': ''
    }
    result = activity_build_data(activity_data)
    assert result == expected_output


def test_create_cisco_umbrella_args():
    """
        Tests the create_cisco_umbrella_args function

            Given:
                - no argument required.

            When:
                - Running the 'create_cisco_umbrella_args function'.

            Then:
                -  Checks the output of the command function with the
                expected output.
    """
    args = {
        'domains': 'google.com',
        'amp_disposition': 'clean',
        'limit': "30"
    }
    expected_output = {
        'limit': 30,
        'offset': 1,
        'from': '-7days',
        'to': 'now',
        'threattypes': None,
        'identitytypes': None,
        'ampdisposition': 'clean',
        'filename': None,
        'intrusionaction': None,
        'domains': 'google.com',
        'urls': None,
        'ip': None,
        'ports': None,
        'verdict': None,
        'threats': None,
        'signatures': None,
        'sha256': None
    }
    result = create_cisco_umbrella_args(50, 1, args)
    assert result == expected_output
    with pytest.raises(ValueError):
        args['intrusion_action'] = 'abcd'
        create_cisco_umbrella_args(50, 1, args)
