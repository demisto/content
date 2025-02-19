import json
from CTIXv3 import (
    Client,
    create_tag_command,
    get_tags_command,
    delete_tag_command,
    whitelist_iocs_command,
    get_whitelist_iocs_command,
    remove_whitelisted_ioc_command,
    get_threat_data_command,
    get_saved_searches_command,
    get_server_collections_command,
    get_actions_command,
    add_indicator_as_false_positive_command,
    add_ioc_manual_review_command,
    deprecate_ioc_command,
    add_analyst_tlp_command,
    add_analyst_score_command,
    saved_result_set_command,
    tag_indicator_updation_command,
    search_for_tag_command,
    get_indicator_details_command,
    get_indicator_tags_command,
    get_indicator_relations_command,
    get_indicator_observations_command,
    get_conversion_feed_source_command,
    get_lookup_threat_data_command,
    domain,
    url,
    ip,
    file,
    get_all_notes,
    get_note_details,
    create_note,
    update_note,
    delete_note,
    make_request,
    cve_command,
)

"""CONSTANTS"""
BASE_URL = "http://test.com/"
ACCESS_ID = "access_id"
SECRET_KEY = "secret_key"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_create_tag(requests_mock):
    mock_response = util_load_json("test_data/create_tag.json")
    requests_mock.post(f"{BASE_URL}ingestion/tags/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"tag_name": "demisto_test_temp", "color": "blue"}

    response = create_tag_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Tag"
    assert response.outputs_key_field == "name"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 8


def test_create_tag_command_already_exists(requests_mock):
    requests_mock.post(f"{BASE_URL}ingestion/tags/", json=[])

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"tag_name": "demisto_test_temp", "color": "blue"}
    response = create_tag_command(client, args)

    assert response.outputs is None


def test_get_tags(requests_mock):
    mock_response = util_load_json("test_data/get_tags.json")
    requests_mock.get(f"{BASE_URL}ingestion/tags/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1}

    response = get_tags_command(client, args)
    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.Tag"
    assert response[0].outputs_key_field == "name"

    assert isinstance(response, list)
    assert len(response) == 1


def test_get_tags_not_found(requests_mock):
    requests_mock.get(f"{BASE_URL}ingestion/tags/", json={})

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1}

    response = get_tags_command(client, args)
    assert response[0].outputs is None


def test_delete_tag(requests_mock):
    mock_response = util_load_json("test_data/delete_tag.json")
    mock_response_get_tags = util_load_json("test_data/get_tags.json")
    requests_mock.get(f"{BASE_URL}ingestion/tags/", json=mock_response_get_tags)
    requests_mock.post(f"{BASE_URL}ingestion/tags/bulk-actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"tag_name": "test, test1"}

    response = delete_tag_command(client, args)
    assert response.outputs[0] == mock_response
    assert response.outputs_prefix == "CTIX.DeleteTag"
    assert response.outputs_key_field == "result"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 2


def test_delete_tags_no_input(requests_mock):
    mock_response = util_load_json("test_data/delete_tag.json")
    mock_response_get_tags = util_load_json("test_data/get_tags.json")
    requests_mock.get(f"{BASE_URL}ingestion/tags/", json=mock_response_get_tags)
    requests_mock.post(f"{BASE_URL}ingestion/tags/bulk-actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {}
    response = delete_tag_command(client, args)
    assert response.outputs is None
    assert response.outputs_prefix is None
    assert response.outputs_key_field is None

    assert not isinstance(response.raw_response, list)
    assert response.raw_response is None


def test_whitelist_iocs_command(requests_mock):
    mock_response = util_load_json("test_data/whitelist_iocs.json")
    requests_mock.post(f"{BASE_URL}conversion/allowed_indicators/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"type": "indicator", "values": "127.0.0.1, 127.0.0.2", "reason": "test"}

    resp = whitelist_iocs_command(client, args)
    response = resp.raw_response

    assert response == mock_response["details"]
    assert resp.outputs_prefix == "CTIX.AllowedIOC"

    assert isinstance(response, dict)
    assert len(response) == 3


def test_whitelist_iocs_command_fallback(requests_mock):
    mock_response = util_load_json("test_data/whitelist_iocs.json")
    requests_mock.post(f"{BASE_URL}conversion/allowed_indicators/", status_code=404)
    requests_mock.post(f"{BASE_URL}conversion/whitelist/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"type": "indicator", "values": "127.0.0.1, 127.0.0.2", "reason": "test"}

    resp = whitelist_iocs_command(client, args)
    response = resp.raw_response

    assert response == mock_response["details"]
    assert resp.outputs_prefix == "CTIX.AllowedIOC"

    assert isinstance(response, dict)
    assert len(response) == 3


def test_get_whitelist_iocs_command_fallback(requests_mock):
    mock_response = util_load_json("test_data/get_whitelist_iocs.json")
    requests_mock.get(f"{BASE_URL}conversion/allowed_indicators/", status_code=404)
    requests_mock.get(f"{BASE_URL}conversion/whitelist/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1}

    resp = get_whitelist_iocs_command(client, args)
    response = resp[0].raw_response

    assert response == mock_response["results"][0]
    assert resp[0].outputs_prefix == "CTIX.IOC"

    assert isinstance(response, dict)
    assert len(response) == 11


def test_get_whitelist_iocs_command(requests_mock):
    mock_response = util_load_json("test_data/get_whitelist_iocs.json")
    requests_mock.get(f"{BASE_URL}conversion/allowed_indicators/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1}

    resp = get_whitelist_iocs_command(client, args)
    response = resp[0].raw_response

    assert response == mock_response["results"][0]
    assert resp[0].outputs_prefix == "CTIX.IOC"

    assert isinstance(response, dict)
    assert len(response) == 11


def test_remove_whitelisted_ioc_command(requests_mock):
    mock_response = util_load_json("test_data/remove_whitelist_ioc.json")
    requests_mock.post(
        f"{BASE_URL}conversion/whitelist/bulk-actions/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"ids": "a,b,c"}

    response = remove_whitelisted_ioc_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.RemovedIOC"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_get_threat_data_command(requests_mock):
    mock_response = util_load_json("test_data/get_threat_data.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = get_threat_data_command(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatData"

    assert isinstance(response[0].outputs, dict)
    assert len(response[0].outputs) == 37


def test_get_saved_searches_command(requests_mock):
    mock_response = util_load_json("test_data/get_threat_data.json")
    requests_mock.get(f"{BASE_URL}ingestion/saved-searches/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = get_saved_searches_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.SavedSearch"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_get_server_collections_command(requests_mock):
    mock_response = util_load_json("test_data/get_threat_data.json")
    requests_mock.get(f"{BASE_URL}publishing/collection/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = get_server_collections_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.ServerCollection"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_get_actions_command(requests_mock):
    mock_response = util_load_json("test_data/get_actions.json")
    requests_mock.get(f"{BASE_URL}ingestion/actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
        "actions_type": "manual",
        "object_type": "indicator",
    }

    response = get_actions_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.Action"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_add_indicator_as_false_positive_command(requests_mock):
    mock_response = util_load_json("test_data/add_indicator_as_false_positive.json")
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/bulk-action/false_positive/",
        json=mock_response,
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"object_ids": "foo", "object_type": "indicator"}

    response = add_indicator_as_false_positive_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorFalsePositive"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_add_ioc_manual_review_command(requests_mock):
    mock_response = util_load_json("test_data/ioc_manual_review.json")
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/bulk-action/manual_review/",
        json=mock_response,
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"object_ids": "foo", "object_type": "indicator"}

    response = add_ioc_manual_review_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IOCManualReview"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_deprecate_ioc_command(requests_mock):
    mock_response = util_load_json("test_data/deprecate_ioc.json")
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/bulk-action/deprecate/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"object_ids": "foo", "object_type": "indicator"}

    response = deprecate_ioc_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.DeprecateIOC"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_add_analyst_tlp_command(requests_mock):
    mock_response = util_load_json("test_data/add_analyst_tlp.json")
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/action/analyst_tlp/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "object_id": "foo",
        "object_type": "indicator",
        "data": '{"analyst_tlp":"GREEN"}',
    }

    response = add_analyst_tlp_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.AddAnalystTLP"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_add_analyst_score_command(requests_mock):
    mock_response = util_load_json("test_data/add_analyst_score.json")
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/action/analyst_score/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "object_id": "foo",
        "object_type": "indicator",
        "data": '{"analyst_score":10}',
    }

    response = add_analyst_score_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.AddAnalystScore"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_saved_result_set_command(requests_mock):
    mock_response = util_load_json("test_data/saved_result_set.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "label_name": "test", "query": "type=indicator"}

    response = saved_result_set_command(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.SavedResultSet"

    assert isinstance(response[0].outputs, dict)
    assert len(response[0].outputs) == 37


def test_add_tag_indicator_updation_command(requests_mock):
    mock_response = util_load_json("test_data/add_tag_indicator.json")
    mock_response_get = util_load_json("test_data/get_indicator_tags.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/indicator/foo/quick-actions/",
        json=mock_response_get,
    )
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/action/add_tag/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
        "object_id": "foo",
        "object_type": "indicator",
        "tag_id": "foo, bar",
        "q": "",
    }

    response = tag_indicator_updation_command(
        client, args, operation="add_tag_indicator"
    )

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.TagUpdation"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_remove_tag_indicator_updation_command(requests_mock):
    mock_response = util_load_json("test_data/add_tag_indicator.json")
    mock_response_get = util_load_json("test_data/get_indicator_tags.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/indicator/foo/quick-actions/",
        json=mock_response_get,
    )
    requests_mock.post(
        f"{BASE_URL}ingestion/threat-data/action/remove_tag/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
        "object_id": "foo",
        "object_type": "indicator",
        "tag_id": "foo,bar",
        "q": "",
    }

    response = tag_indicator_updation_command(
        client, args, operation="remove_tag_from_indicator"
    )

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.TagUpdation"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_search_for_tag_command(requests_mock):
    mock_response = util_load_json("test_data/search_for_tag.json")
    requests_mock.get(f"{BASE_URL}ingestion/tags/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = search_for_tag_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.SearchTag"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_get_indicator_details_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_details.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/indicator/foo/basic/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_details_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorDetails"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 34


def test_get_indicator_tags_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_tags.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/indicator/foo/quick-actions/",
        json=mock_response,
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_tags_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorTags"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 13


def test_get_indicator_relations_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_relations.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/indicator/foo/relations/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_relations_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.IndicatorRelations"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_get_indicator_observations_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_observations.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/source-references/", json=mock_response
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_observations_command(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.IndicatorObservations"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 1


def test_get_conversion_feed_source_command(requests_mock):
    mock_response = util_load_json("test_data/get_conversion_feed_source.json")
    requests_mock.get(f"{BASE_URL}conversion/feed-sources/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_conversion_feed_source_command(client, args)

    assert response.outputs[0] == mock_response["results"][0]
    assert response.outputs_prefix == "CTIX.ConversionFeedSource"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response) == 10


def test_get_lookup_threat_data_command(requests_mock):
    mock_response = util_load_json("test_data/get_lookup_threat_data.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
        "object_type": "indicator",
        "object_names": "foo,bar",
    }

    response = get_lookup_threat_data_command(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatDataLookup"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 37


def test_domain(requests_mock):
    mock_response = util_load_json("test_data/domain.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "domain": "google.com",
        "page": 1,
        "page_size": 1,
        "object_type": "indicator",
        "object_names": "foo,bar",
    }

    response = domain(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatDataLookup"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 37


def test_url(requests_mock):
    mock_response = util_load_json("test_data/url.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "url": "https://example.com/",
        "page": 1,
        "page_size": 1,
        "object_type": "indicator",
        "object_names": "foo,bar",
    }

    response = url(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatDataLookup"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 37


def test_ip(requests_mock):
    mock_response = util_load_json("test_data/ip.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "ip": "1.2.3.4",
        "page": 1,
        "page_size": 1,
        "object_type": "indicator",
        "object_names": "foo,bar",
    }

    response = ip(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatDataLookup"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 37


def test_file(requests_mock):
    mock_response = util_load_json("test_data/file.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "file": "a6a91e61a729bb4c12cc3db3eb9ea746",
        "page": 1,
        "page_size": 1,
        "object_type": "indicator",
        "object_names": "foo,bar",
    }

    response = file(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.ThreatDataLookup"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 37


def test_get_all_notes(requests_mock):
    mock_response = util_load_json("test_data/get_all_notes.json")
    requests_mock.get(f"{BASE_URL}ingestion/notes/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 10,
    }

    response = get_all_notes(client, args)

    assert response.outputs == mock_response["results"]
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, list)
    assert len(response.raw_response[0]) == 11


def test_get_note_details(requests_mock):
    mock_response = util_load_json("test_data/get_note_details.json")
    id = "b1800a11-7fa5-423e-93bf-f8ef8d3890a4"
    requests_mock.get(f"{BASE_URL}ingestion/notes/{id}/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "id": id
    }

    response = get_note_details(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 11


def test_create_note(requests_mock):
    mock_response = util_load_json("test_data/create_note.json")
    requests_mock.post(f"{BASE_URL}ingestion/notes/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "text": "this note will have this text",
        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
        "object_type": "indicator"
    }

    response = create_note(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 11


def test_update_note(requests_mock):
    mock_response = util_load_json("test_data/update_note.json")
    id = "04bb5f2c-78a6-4e84-82ae-011666733998"
    requests_mock.put(f"{BASE_URL}ingestion/notes/{id}/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "id": id,
        "text": "this is the new text",
        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
        "object_type": "indicator"
    }

    response = update_note(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 11


def test_delete_note(requests_mock):
    mock_response = util_load_json("test_data/delete_note.json")
    id = "04bb5f2c-78a6-4e84-82ae-011666733998"
    requests_mock.delete(f"{BASE_URL}ingestion/notes/{id}/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "id": id
    }

    response = delete_note(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response) == 1


def test_make_request_get(requests_mock):
    mock_response = util_load_json("test_data/make_request_get.json")
    requests_mock.get(f"{BASE_URL}ingestion/notes/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "type": "GET",
        "endpoint": "ingestion/notes/",
        "page": 2,
        "page_size": 10,
    }

    response = make_request(client, args)

    assert response[0].outputs == mock_response["results"][0]
    assert response[0].outputs_prefix == "CTIX.Request.GET.ingestion/notes/"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 11


def test_make_request_post(requests_mock):
    mock_response = util_load_json("test_data/make_request_post.json")
    requests_mock.post(f"{BASE_URL}ingestion/notes/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "type": "POST",
        "endpoint": "ingestion/notes/",
        "body": """{
            \"text\": \"this is the old text\",
            \"type\": \"threatdata\",
            \"meta_data\": {
                \"component\": \"threatdata\",
                \"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\",
                \"type\": \"indicator\"
            },
            \"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\"
        }"""
    }

    response = make_request(client, args)

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == "CTIX.Request.POST.ingestion/notes/"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 11


def test_make_request_put(requests_mock):
    mock_response = util_load_json("test_data/make_request_put.json")
    requests_mock.put(f"{BASE_URL}ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "type": "PUT",
        "endpoint": "ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/",
        "body": """{
            \"text\": \"this is the new text\",
            \"type\": \"threatdata\",
            \"meta_data\": {
                \"component\": \"threatdata\",
                \"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\",
                \"type\": \"indicator\"
            },
            \"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\"
        }"""
    }

    response = make_request(client, args)

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == "CTIX.Request.PUT.ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 11


def test_make_request_delete(requests_mock):
    mock_response = util_load_json("test_data/make_request_delete.json")
    requests_mock.delete(f"{BASE_URL}ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "type": "DELETE",
        "endpoint": "ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/",
    }

    response = make_request(client, args)

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == "CTIX.Request.DELETE.ingestion/notes/40c57c4a-1b5d-4cb4-bd89-d146c0d30ed4/"

    assert isinstance(response[0].raw_response, dict)
    assert len(response[0].raw_response) == 1


def test_cve_command(requests_mock):
    mock_threat_list_response = util_load_json("test_data/get_cve_threat_data.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_threat_list_response)
    obj_id = mock_threat_list_response["results"][0]["id"]
    mock_product_details_response = util_load_json("test_data/get_vulnerability_product_details.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/product-details/",
                      json=mock_product_details_response)
    source_id = mock_product_details_response["results"][0]["source"]["id"]
    mock_cvss_score_response = util_load_json("test_data/get_cvss_score.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/cvss-score/", json=mock_cvss_score_response)
    mock_source_description_response = util_load_json("test_data/get_vulnerability_source_description.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/source-description/?source_id={source_id}",
                      json=mock_source_description_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={},
    )

    args = {
        "cve": "CVE-2023-33250",
    }

    response = cve_command(client, args)

    assert response[0].outputs["uuid"] == obj_id
    assert response[0].outputs_prefix == "CTIX.VulnerabilityLookup"

    assert isinstance(response[0].outputs, dict)
    assert len(response[0].outputs) == 10
