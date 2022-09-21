import pytest
import json
import io
from CommonServerPython import DemistoException
from CiscoUmbrellaReporting import Client, get_destinations_list, \
    get_categories_list, get_identities_list, get_file_list, get_threat_list,\
    get_event_types_list, get_activity_list, get_activity_by_traffic_type,\
    get_summary_list, pagination

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


DESTINATION_LIST_RESPONSE = util_load_json('test_data/destination_data.json')
CATEGORY_LIST_RESPONSE = util_load_json('test_data/category_data.json')
IDENTITY_LIST_RESPONSE = util_load_json('test_data/identity_data.json')
FILE_LIST_RESPONSE = util_load_json("test_data/file_data.json")
THREAT_LIST_RESPONSE = util_load_json("test_data/threat_data.json")
EVENT_TYPE_LIST_RESPONSE = util_load_json("test_data/event_type_data.json")
ACTIVITY_LIST_RESPONSE = util_load_json("test_data/activity_data.json")
ACTIVITY_DNS_LIST_RESPONSE = util_load_json("test_data/activity_dns_data.json")
SUMMARY_LIST_RESPONSE = util_load_json("test_data/summary_data.json")
DESTINATION_SUMMARY_LIST_RESPONSE = util_load_json(
    "test_data/destination_summary_data.json")
ACCESS_TOKEN_RESPONSE = util_load_json("test_data/access_token_data.json")
ACTIVITY_FIREWALL_LIST_RESPONSE = util_load_json("test_data/file_data.json")
PAGINATION_DATA_LIST = util_load_json("test_data/pagination_data.json")
PAGE_1_PAGE_SIZE_5_LIST = util_load_json("test_data/page_1_paze_size_5.json")
PAGE_2_PAGE_SIZE_5_LIST = util_load_json("test_data/page_2_paze_size_5.json")


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_LIST_RESPONSE,
                                                    DESTINATION_LIST_RESPONSE)])
def test_get_destinations_list(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_destinations_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(CATEGORY_LIST_RESPONSE,
                                                     CATEGORY_LIST_RESPONSE)])
def test_get_category_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    results_without_traffic = get_categories_list(client, args)
    args['traffic_type'] = "dns"
    results_with_traffic = get_categories_list(client, args)
    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()['Contents']
    detail_with_traffic = results_with_traffic.to_context()['Contents']
    assert detail_without_traffic == expected.get("data")
    assert detail_with_traffic == expected.get("data")
    with pytest.raises(ValueError):
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_categories_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(IDENTITY_LIST_RESPONSE,
                                                     IDENTITY_LIST_RESPONSE)])
def test_get_identities_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }
    results_without_traffic = get_identities_list(client, args)
    args['traffic_type'] = "dns"
    results_with_traffic = get_identities_list(client, args)
    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()['Contents']
    detail_with_traffic = results_with_traffic.to_context()['Contents']
    assert detail_without_traffic == expected.get("data")
    assert detail_with_traffic == expected.get("data")

    with pytest.raises(ValueError):
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_identities_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(FILE_LIST_RESPONSE,
                                                     FILE_LIST_RESPONSE)])
def test_get_file_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_file_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(THREAT_LIST_RESPONSE,
                                                     THREAT_LIST_RESPONSE)])
def test_get_threat_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_threat_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(EVENT_TYPE_LIST_RESPONSE,
                                                     EVENT_TYPE_LIST_RESPONSE)])
def test_get_event_types_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_event_types_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_LIST_RESPONSE,
                                                     ACTIVITY_LIST_RESPONSE)])
def test_get_activity_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_activity_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "dns"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_proxy_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "proxy"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(ACTIVITY_DNS_LIST_RESPONSE,
                                                     ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_ip_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "ip"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_firewall_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "firewall"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_amp_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "amp"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected',
                         [(ACTIVITY_FIREWALL_LIST_RESPONSE,
                           ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_intrusion_by_traffic_type(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "intrusion"
    }

    command_results = get_activity_by_traffic_type(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["doamins"] = "jcgsdg"
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(SUMMARY_LIST_RESPONSE,
                                                     SUMMARY_LIST_RESPONSE)])
def test_get_summary_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0
    }

    command_results = get_summary_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']

    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_SUMMARY_LIST_RESPONSE,
                                                     DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_category_summary_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "category"
    }

    command_results = get_summary_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']

    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_SUMMARY_LIST_RESPONSE,
                                                     DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_destination_summary_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "destination"
    }

    command_results = get_summary_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']

    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["signatures"] = 1
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_SUMMARY_LIST_RESPONSE,
                                                     DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_intrusion_rule_summary_list(mocker, raw_response, expected):

    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "summary_type": "intrusion_rule"
    }

    command_results = get_summary_list(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']

    assert context_detail == expected.get("data")
    with pytest.raises(DemistoException):
        args["domains"] = 345678
        get_summary_list(client, args)


@pytest.mark.parametrize('raw_response, expected', [(DESTINATION_LIST_RESPONSE,
                                                     DESTINATION_LIST_RESPONSE)])
def test_fetch_data_from_cisco_api(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    endpoint = "top-destinations"
    args = {
        "limit": 5,
        "from": 1662015255000,
        "to": 1662447255000,
        "offset": 0,
        "traffic_type": "dns"
    }

    command_results = client.fetch_data_from_cisco_api(endpoint, args)

    context_detail = command_results.get("data")

    assert context_detail == expected.get("data")


@pytest.mark.parametrize('raw_response', [PAGINATION_DATA_LIST])
def test_pagination_record_first_page(mocker, raw_response):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "limit": 5,
        "from": 1662422400000,
        "to": 1662768000000,
        "offset": 0,
    }
    page_1 = PAGE_1_PAGE_SIZE_5_LIST
    first_page = get_activity_list(client, args)
    # results is CommandResults list
    first_page = first_page.to_context()['Contents']
    assert first_page[:5] == page_1.get("data")


@pytest.mark.parametrize('raw_response', [PAGINATION_DATA_LIST])
def test_pagination_record_new_page(mocker, raw_response):
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    args = {
        "limit": 5,
        "from": 1662422400000,
        "to": 1662768000000,
        "offset": 5,
    }
    page_2 = PAGE_2_PAGE_SIZE_5_LIST
    command_results_new = get_activity_list(client, args)
    # results is CommandResults list
    next_page = command_results_new.to_context()['Contents']
    assert next_page[5:10] == page_2.get("data")


def test_pagination():
    args = {
        "page": 2,
        "page_size": 5
    }
    expected_response = {
        'limit': 5,
        'offset': 5
    }
    context_detail = pagination(args)
    assert context_detail == expected_response
