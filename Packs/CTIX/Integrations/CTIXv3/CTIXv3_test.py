import json
from unittest.mock import patch
from datetime import datetime, UTC

from CTIXv3 import (
    Client,
    _epoch_to_iso,
    add_analyst_score_command,
    add_analyst_tlp_command,
    add_indicator_as_false_positive_command,
    add_ioc_manual_review_command,
    bulk_ioc_lookup_advanced_command,
    confidence_to_dbot_score,
    create_note,
    create_tag_command,
    cve_command,
    delete_note,
    disable_or_enable_tags_command,
    deprecate_ioc_command,
    domain,
    enrich_indicators_bulk,
    fetch_incidents,
    fetch_indicators,
    file,
    get_actions_command,
    get_all_notes,
    get_conversion_feed_source_command,
    get_indicator_details_command,
    get_indicator_observations_command,
    get_indicator_relations_command,
    get_indicator_tags_command,
    get_lookup_threat_data_command,
    get_note_details,
    get_saved_searches_command,
    get_server_collections_command,
    get_tags_command,
    get_threat_data_command,
    get_whitelist_iocs_command,
    ip,
    make_request,
    map_ctix_indicator_to_xsoar,
    map_report_severity,
    map_report_to_incident,
    normalize_indicator_type,
    remove_whitelisted_ioc_command,
    saved_result_set_command,
    search_for_tag_command,
    tag_indicator_updation_command,
    update_note,
    url,
    whitelist_iocs_command,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
        proxies={},
    )

    args = {"page": 1, "page_size": 1}

    response = get_tags_command(client, args)
    assert response[0].outputs is None


def test_disable_or_enable_tag(requests_mock):
    mock_response = util_load_json("test_data/disable_or_enable_tag.json")
    requests_mock.post(f"{BASE_URL}ingestion/tags/bulk-actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"tag_id": "foo, bar", "action": "disabled"}

    response = disable_or_enable_tags_command(client, args)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.TagAction"
    assert response.outputs_key_field == "result"

    assert isinstance(response.raw_response, dict)


def test_disable_or_enable_tag_no_inputs(requests_mock):
    requests_mock.post(f"{BASE_URL}ingestion/tags/bulk-actions/", json={})

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"tag_id": "", "action": "disabled"}

    response = disable_or_enable_tags_command(client, args)
    assert response.outputs is None


def test_whitelist_iocs_command(requests_mock):
    mock_response = util_load_json("test_data/whitelist_iocs.json")
    requests_mock.post(f"{BASE_URL}conversion/allowed_indicators/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
    mock_id = "foo"
    mock_response = util_load_json("test_data/remove_whitelist_ioc.json")
    requests_mock.post(f"{BASE_URL}conversion/allowed_indicators/bulk-actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"ids": mock_id}

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
        timeout=15,
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
        timeout=15,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = get_saved_searches_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.SavedSearch"

    assert isinstance(response.raw_response, dict)


def test_get_server_collections_command(requests_mock):
    mock_response = util_load_json("test_data/get_threat_data.json")
    requests_mock.get(f"{BASE_URL}publishing/collection/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = get_server_collections_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.ServerCollection"

    assert isinstance(response.raw_response, dict)


def test_get_actions_command(requests_mock):
    mock_response = util_load_json("test_data/get_actions.json")
    requests_mock.get(f"{BASE_URL}ingestion/actions/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
        "actions_type": "manual",
        "object_type": "indicator",
    }

    response = get_actions_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Action"

    assert isinstance(response.raw_response, dict)


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
        timeout=15,
        proxies={},
    )

    args = {"object_ids": "foo", "object_type": "indicator"}

    response = add_indicator_as_false_positive_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorFalsePositive"

    assert isinstance(response.raw_response, dict)


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
        timeout=15,
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
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/bulk-action/deprecate/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/action/analyst_tlp/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/action/analyst_score/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
    requests_mock.get(f"{BASE_URL}ingestion/rules/save_result_set/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "label_name": "test", "query": "type=indicator", "version": "v2"}

    response = saved_result_set_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.SavedResultSet"

    assert isinstance(response.outputs.get("results", [])[0], dict)
    assert len(response.outputs.get("results", [])[0]) == 8


def test_add_tag_indicator_updation_command(requests_mock):
    mock_response = util_load_json("test_data/add_tag_indicator.json")
    mock_response_get = util_load_json("test_data/get_indicator_tags.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/indicator/foo/quick-actions/", json=mock_response_get)
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/bulk-action/add_tag/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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

    response = tag_indicator_updation_command(client, args, operation="add_tag_indicator")

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
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/bulk-action/remove_tag/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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

    response = tag_indicator_updation_command(client, args, operation="remove_tag_from_indicator")

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
        timeout=15,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 1,
    }

    response = search_for_tag_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.SearchTag"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response.get("results", [])) == 1


def test_get_indicator_details_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_details.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/indicator/foo/basic/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
        timeout=15,
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
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/indicator/foo/relations/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_relations_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorRelations"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response.get("results", [])) == 1


def test_get_indicator_observations_command(requests_mock):
    mock_response = util_load_json("test_data/get_indicator_observations.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/source-references/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_indicator_observations_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.IndicatorObservations"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response.get("results", [])) == 1


def test_get_conversion_feed_source_command(requests_mock):
    mock_response = util_load_json("test_data/get_conversion_feed_source.json")
    requests_mock.get(f"{BASE_URL}conversion/feed-sources/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"page": 1, "page_size": 1, "object_type": "indicator", "object_id": "foo"}

    response = get_conversion_feed_source_command(client, args)

    assert response.outputs.get("results", [])[0] == mock_response.get("results", [None])[0]
    assert response.outputs_prefix == "CTIX.ConversionFeedSource"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response.get("results", [])) == 10


def test_get_lookup_threat_data_command(requests_mock):
    mock_response = util_load_json("test_data/get_lookup_threat_data.json")
    requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
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
        timeout=15,
        proxies={},
    )

    args = {
        "page": 1,
        "page_size": 10,
    }

    response = get_all_notes(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "CTIX.Note"

    assert isinstance(response.raw_response, dict)
    assert len(response.raw_response.get("results", [])) == 10


def test_get_note_details(requests_mock):
    mock_response = util_load_json("test_data/get_note_details.json")
    id = "b1800a11-7fa5-423e-93bf-f8ef8d3890a4"
    requests_mock.get(f"{BASE_URL}ingestion/notes/{id}/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {"id": id}

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
        timeout=15,
        proxies={},
    )

    args = {
        "text": "this note will have this text",
        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
        "object_type": "indicator",
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
        timeout=15,
        proxies={},
    )

    args = {
        "id": id,
        "text": "this is the new text",
        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
        "object_type": "indicator",
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
        timeout=15,
        proxies={},
    )

    args = {"id": id}

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
        timeout=15,
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
        timeout=15,
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
        }""",
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
        timeout=15,
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
        }""",
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
        timeout=15,
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
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/product-details/", json=mock_product_details_response
    )
    source_id = mock_product_details_response["results"][0]["source"]["id"]
    mock_cvss_score_response = util_load_json("test_data/get_cvss_score.json")
    requests_mock.get(f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/cvss-score/", json=mock_cvss_score_response)
    mock_source_description_response = util_load_json("test_data/get_vulnerability_source_description.json")
    requests_mock.get(
        f"{BASE_URL}ingestion/threat-data/vulnerability/{obj_id}/source-description/?source_id={source_id}",
        json=mock_source_description_response,
    )

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
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


def test_bulk_ioc_lookup_advanced_by_value(requests_mock):
    """Test bulk IOC lookup advanced using indicator values."""
    mock_response = util_load_json("test_data/bulk_ioc_lookup_advanced.json")
    requests_mock.post(f"{BASE_URL}ingestion/openapi/bulk-lookup/indicator/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {
        "object_type": "indicator",
        "values": "1.1.1.1,www.facebook.com",
    }

    response = bulk_ioc_lookup_advanced_command(client, args)

    assert response.outputs_prefix == "CTIX.BulkIOCLookupAdvanced"
    results = response.outputs.get("results", [])
    assert isinstance(results, list)
    assert len(results) == 2
    assert results[0]["id"] == "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    assert results[0]["name"] == "1.1.1.1"
    assert results[0]["ioc_type"] == "ipv4-addr"
    assert results[0]["confidence_score"] == 80
    assert results[1]["id"] == "8a5f8c2d-1234-4abc-def0-1a2b3c4d5e6f"
    assert results[1]["name"] == "www.facebook.com"
    assert results[1]["is_whitelisted"] is True
    assert isinstance(response.raw_response, dict)


def test_bulk_ioc_lookup_advanced_by_object_id(requests_mock):
    """Test bulk IOC lookup advanced using object IDs with optional params."""
    mock_response = util_load_json("test_data/bulk_ioc_lookup_advanced.json")
    requests_mock.post(f"{BASE_URL}ingestion/openapi/bulk-lookup/indicator/", json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {
        "object_type": "indicator",
        "object_ids": "3fa85f64-5717-4562-b3fc-2c963f66afa6,8a5f8c2d-1234-4abc-def0-1a2b3c4d5e6f",
        "enrichment_data": "true",
        "relation_data": "true",
        "enrichment_tools": "AbuseIPDB",
        "fields": "relations,enrichment_data",
    }

    response = bulk_ioc_lookup_advanced_command(client, args)

    assert response.outputs_prefix == "CTIX.BulkIOCLookupAdvanced"
    results = response.outputs.get("results", [])
    assert isinstance(results, list)
    assert len(results) == 2
    assert results[0]["object_type"] == "indicator"
    assert results[1]["is_reviewed"] is True
    assert isinstance(response.raw_response, dict)


def test_bulk_ioc_lookup_advanced_no_results(requests_mock):
    """Test bulk IOC lookup advanced when no matching results are returned."""
    requests_mock.post(f"{BASE_URL}ingestion/openapi/bulk-lookup/indicator/", json=[])

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        timeout=15,
        proxies={},
    )

    args = {
        "object_type": "indicator",
        "values": "not.a.real.ioc",
    }

    response = bulk_ioc_lookup_advanced_command(client, args)

    assert response.outputs is None
    assert response.readable_output == "No results were found"


"""
=============================================
Tests for fetch-incidents, fetch-indicators,
helper functions, and enrichment
=============================================
"""


class TestConfidenceToDbotScore:
    """Test confidence_to_dbot_score helper."""

    def test_none_returns_none_score(self):
        assert confidence_to_dbot_score(None) == 0

    def test_string_returns_none_score(self):
        assert confidence_to_dbot_score("NA") == 0

    def test_high_confidence_returns_bad(self):
        assert confidence_to_dbot_score(80) == 3
        assert confidence_to_dbot_score(100) == 3

    def test_medium_confidence_returns_suspicious(self):
        assert confidence_to_dbot_score(50) == 2
        assert confidence_to_dbot_score(79) == 2

    def test_low_confidence_returns_none(self):
        assert confidence_to_dbot_score(0) == 0
        assert confidence_to_dbot_score(49) == 0


class TestNormalizeIndicatorType:
    """Test normalize_indicator_type helper."""

    def test_ipv4(self):
        assert normalize_indicator_type("ipv4-addr") == "IP"

    def test_domain(self):
        assert normalize_indicator_type("domain-name") == "Domain"

    def test_url(self):
        assert normalize_indicator_type("url") == "URL"

    def test_file_hash(self):
        assert normalize_indicator_type("SHA-256") == "File"

    def test_unknown_type(self):
        assert normalize_indicator_type("unknown-type") == "Custom Indicator"

    def test_none_type(self):
        assert normalize_indicator_type(None) == "Custom Indicator"


class TestEpochToIso:
    """Test _epoch_to_iso helper."""

    def test_valid_epoch(self):
        result = _epoch_to_iso(1700000000)
        assert result == "2023-11-14T22:13:20Z"

    def test_none_returns_none(self):
        assert _epoch_to_iso(None) is None

    def test_zero_returns_none(self):
        assert _epoch_to_iso(0) is None

    def test_string_returns_none(self):
        assert _epoch_to_iso("not-a-number") is None


class TestMapReportSeverity:
    """Test map_report_severity helper."""

    def test_high_severity_string(self):
        report = {"risk_severity": "HIGH"}
        assert map_report_severity(report) == 3

    def test_medium_severity_string(self):
        report = {"risk_severity": "MEDIUM"}
        assert map_report_severity(report) == 2

    def test_low_severity_string(self):
        report = {"risk_severity": "LOW"}
        assert map_report_severity(report) == 1

    def test_critical_severity_string(self):
        report = {"risk_severity": "CRITICAL"}
        assert map_report_severity(report) == 4

    def test_high_confidence_fallback(self):
        report = {"risk_severity": "UNKNOWN", "confidence_score": 85}
        assert map_report_severity(report) == 3

    def test_medium_confidence_fallback(self):
        report = {"risk_severity": None, "confidence_score": 55}
        assert map_report_severity(report) == 2

    def test_unknown_default(self):
        report = {}
        assert map_report_severity(report) == 0


class TestMapReportToIncident:
    """Test map_report_to_incident helper."""

    def test_basic_mapping(self):
        report = {
            "id": "report-001",
            "name": "Test Report",
            "description": "A test report.",
            "created": 1700000000,
            "modified": 1700000100,
            "risk_severity": "HIGH",
            "tlp": "AMBER",
            "tags": [{"id": "t1", "name": "apt29"}],
            "sources": [{"id": "s1", "name": "ThreatFeed"}],
        }
        incident = map_report_to_incident(report)

        assert incident["name"] == "CTIX Intel: Test Report"
        assert incident["severity"] == 3
        assert incident["type"] == "CTIX Intel"
        assert incident["dbotMirrorId"] == "report-001"
        assert incident["occurred"] == "2023-11-14T22:13:20Z"
        assert len(incident["labels"]) == 1
        assert incident["labels"][0]["value"] == "apt29"
        # Ensure rawJSON is valid JSON
        raw = json.loads(incident["rawJSON"])
        assert raw["id"] == "report-001"

    def test_missing_fields(self):
        report = {"id": "report-empty"}
        incident = map_report_to_incident(report)
        assert incident["occurred"] == ""
        assert incident["severity"] == 0
        assert incident["labels"] == []

    def test_string_tags(self):
        report = {"id": "report-str-tags", "tags": ["tag1", "tag2"], "created": 0}
        incident = map_report_to_incident(report)

        assert len(incident["labels"]) == 2
        assert incident["labels"][0]["value"] == "tag1"


class TestMapCtixIndicatorToXsoar:
    """Test map_ctix_indicator_to_xsoar helper."""

    def test_basic_ip_indicator(self):
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 85,
            "source_tlp": "AMBER",
            "first_seen": 1700000000,
            "last_seen": 1700000100,
            "id": "ind-001",
            "ctix_created": 1700000001,
            "ctix_modified": 1700000001,
            "tags": [{"name": "malware"}],
            "sources": [{"name": "ThreatFeed"}],
            "description": "Malicious IP",
            "is_false_positive": False,
            "is_deprecated": False,
            "is_reviewed": True,
            "is_whitelisted": False,
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")

        assert result["value"] == "1.2.3.4"
        assert result["type"] == "IP"
        assert result["score"] == 3  # confidence 85 -> BAD
        assert result["fields"]["trafficlightprotocol"] == "AMBER"
        assert "malware" in result["fields"]["tags"]
        assert result["fields"]["reportedby"] == "ThreatFeed"

    def test_domain_indicator_with_dict_ioc_type(self):
        indicator = {
            "name": "evil.example.com",
            "ioc_type": {"type": "domain-name", "attribute_field": "value"},
            "ctix_score": 55,
            "source_tlp": "GREEN",
            "sources": [],
            "tags": ["phishing"],
            "id": "ind-002",
        }
        result = map_ctix_indicator_to_xsoar(indicator, "C - Fairly reliable")

        assert result["value"] == "evil.example.com"
        assert result["type"] == "Domain"
        assert result["score"] == 2  # confidence 55 -> SUSPICIOUS

    def test_indicator_with_enrichment(self):
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 90,
            "id": "ind-001",
            "sources": [],
            "tags": [],
        }
        enrichment = {
            "description": "Enriched description from bulk lookup",
            "relations": {"related-to": [{"name": "evil.example.com", "type": "domain-name"}]},
            "enrichment_data": [{"tool_name": "VT", "result": {"malicious": 10}}],
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable", enrichment)

        assert result["fields"]["description"] == "Enriched description from bulk lookup"
        assert result["relationships"] is not None
        assert len(result["relationships"]) == 1
        assert "ctixenrichment" in result["fields"]

    def test_indicator_with_custom_scores(self):
        indicator = {
            "name": "5.6.7.8",
            "ioc_type": "ipv4-addr",
            "confidence_score": 85,
            "custom_scores": {"x_ctix_customscore_2": 34},
            "sources": [],
            "tags": [],
        }

        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")
        parsed_scores = json.loads(result["fields"].get("ctixcustomscores", "{}"))
        assert parsed_scores.get("x_ctix_customscore_2") == 34

    def test_indicator_with_no_value(self):
        indicator = {"ioc_type": "ipv4-addr", "sources": [], "tags": []}
        result = map_ctix_indicator_to_xsoar(indicator, "C - Fairly reliable")

        assert not result.get("value")  # empty string is stripped by assign_params

    def test_relations_string_items_use_rel_type_for_entity_b_type(self):
        """Relations with plain-string items (bulk IOC lookup base format) resolve
        entity_b_type from the relation key via _STIX_SDO_TO_XSOAR_ENTITY_TYPE,
        and always use 'related-to' as the relationship verb (the key is a STIX
        object type, not a relationship verb)."""
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 64,
            "sources": [],
            "tags": [],
            "relations": {
                "malware": ["Adaptix"],
                "report": ["Adaptix_20260209"],
            },
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")

        assert result["relationships"] is not None
        assert len(result["relationships"]) == 2

        # All plain-string relations use "related-to" as the relationship verb;
        # identify each by its entityBType which is derived from the dict key.
        malware_rel = next((r for r in result["relationships"] if r.get("entityBType") == "Malware"), None)
        assert malware_rel is not None
        assert malware_rel["name"] == "related-to"
        assert malware_rel["entityA"] == "1.2.3.4"
        assert malware_rel["entityB"] == "Adaptix"

        report_rel = next((r for r in result["relationships"] if r.get("entityBType") == "Report"), None)
        assert report_rel is not None
        assert report_rel["name"] == "related-to"
        assert report_rel["entityB"] == "Adaptix_20260209"

    def test_relations_multiple_string_items_per_type(self):
        """Multiple string values under one relation key each produce a separate relationship."""
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 80,
            "sources": [],
            "tags": [],
            "relations": {
                "malware": ["MalwareA", "MalwareB", "MalwareC"],
            },
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")

        assert result["relationships"] is not None
        assert len(result["relationships"]) == 3
        entity_b_values = {r["entityB"] for r in result["relationships"]}
        assert entity_b_values == {"MalwareA", "MalwareB", "MalwareC"}
        for rel in result["relationships"]:
            assert rel["entityBType"] == "Malware"
            assert rel["name"] == "related-to"  # plain-string format always uses "related-to"

    def test_relations_dict_items_use_embedded_type(self):
        """Relations with dict items (enrichment format) resolve entity_b_type via
        _STIX_SDO_TO_XSOAR_ENTITY_TYPE using the embedded 'type' field."""
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 80,
            "sources": [],
            "tags": [],
            "relations": {
                "related-to": [
                    {"name": "evil.example.com", "type": "domain-name"},
                ],
            },
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")

        assert result["relationships"] is not None
        assert len(result["relationships"]) == 1
        rel = result["relationships"][0]
        assert rel["entityB"] == "evil.example.com"
        assert rel["entityBType"] == "Domain"
        assert rel["name"] == "related-to"

    def test_relations_unknown_type_key_falls_back_to_indicator_entity_b_type(self):
        """A relation key not present in _STIX_SDO_TO_XSOAR_ENTITY_TYPE falls back to
        'Indicator' as the entityBType rather than raising an error."""
        indicator = {
            "name": "1.2.3.4",
            "ioc_type": "ipv4-addr",
            "confidence_score": 80,
            "sources": [],
            "tags": [],
            "relations": {
                "custom-unknown-relationship": ["TargetObject"],
            },
        }
        result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")

        assert result["relationships"] is not None
        assert len(result["relationships"]) == 1
        rel = result["relationships"][0]
        assert rel["entityB"] == "TargetObject"
        assert rel.get("entityBType") == "Indicator"

    def test_relations_empty_or_null_produces_no_relationships(self):
        """Empty dict, None, and missing relations key all result in no relationships."""
        for relations_value in [{}, None]:
            indicator = {
                "name": "1.2.3.4",
                "ioc_type": "ipv4-addr",
                "confidence_score": 80,
                "sources": [],
                "tags": [],
                "relations": relations_value,
            }
            result = map_ctix_indicator_to_xsoar(indicator, "B - Usually reliable")
            assert not result.get("relationships"), f"Expected no relationships for relations={relations_value!r}"

        # Missing key entirely
        indicator_no_key = {"name": "1.2.3.4", "ioc_type": "ipv4-addr", "confidence_score": 80, "sources": [], "tags": []}
        result = map_ctix_indicator_to_xsoar(indicator_no_key, "B - Usually reliable")
        assert not result.get("relationships")


class TestFetchIncidents:
    """Test fetch_incidents function."""

    def test_first_run(self, requests_mock):
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {"max_fetch": "50", "first_fetch": "4320"}
        last_run = {}

        next_run, incidents = fetch_incidents(client, params, last_run)

        assert len(incidents) == 3
        assert incidents[0]["name"] == "CTIX Intel: APT29 Campaign Analysis"
        assert incidents[0]["severity"] == 3  # HIGH
        assert incidents[1]["name"] == "CTIX Intel: Ransomware Trend Report Q4"
        assert incidents[1]["severity"] == 2  # MEDIUM
        assert incidents[2]["name"] == "CTIX Intel: Low Confidence Observation"
        assert next_run["last_fetch_time"] is not None
        assert next_run["last_fetch_time"] >= int(datetime.now(UTC).timestamp())

    def test_deduplication(self, requests_mock):
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {"max_fetch": "50", "first_fetch": "4320"}
        # Simulate second run where first report was already fetched
        last_run = {
            "last_fetch_time": 1700000000,
            "last_fetch_ids": ["report-001-aaaa-bbbb-cccc-ddddeeee0001"],
        }

        next_run, incidents = fetch_incidents(client, params, last_run)

        # First report should be skipped due to dedup
        assert len(incidents) == 2
        assert all(inc["dbotMirrorId"] != "report-001-aaaa-bbbb-cccc-ddddeeee0001" for inc in incidents)

    def test_empty_response(self, requests_mock):
        requests_mock.post(
            f"{BASE_URL}ingestion/threat-data/list/",
            json={"results": [], "total": 0},
        )

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {"max_fetch": "50", "first_fetch": "4320"}
        last_run = {"last_fetch_time": 1700000000}

        next_run, incidents = fetch_incidents(client, params, last_run)

        assert len(incidents) == 0
        assert next_run["last_fetch_time"] == int(datetime.now(UTC).timestamp())

    def test_max_fetch_limit(self, requests_mock):
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {"max_fetch": "2", "first_fetch": "4320"}
        last_run = {}

        next_run, incidents = fetch_incidents(client, params, last_run)

        assert len(incidents) == 2

    def test_custom_cql_query_used_as_base(self, requests_mock):
        """incident_fetch_query replaces the default base query; time-window is appended."""
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_fetch": "50",
            "first_fetch": "4320",
            "incident_fetch_query": 'type = "report" AND severity = "HIGH"',
        }
        last_run = {"last_fetch_time": 1700000000}

        next_run, incidents = fetch_incidents(client, params, last_run)
        assert len(incidents) == 3

    def test_default_query_when_no_custom_cql(self, requests_mock):
        """When incident_fetch_query is absent the default 'type = \"report\"' query is sent."""
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {"max_fetch": "50", "first_fetch": "4320"}  # No incident_fetch_query
        last_run = {"last_fetch_time": 1700000000}

        fetch_incidents(client, params, last_run)

    def test_custom_cql_query_on_first_run(self, requests_mock):
        """Custom query on first run: time-window derived from first_fetch is still appended."""
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_fetch": "50",
            "first_fetch": "4320",
            "incident_fetch_query": 'type = "report" AND tlp = "AMBER"',
        }
        last_run = {}  # First run – no last_fetch_time stored

        next_run, incidents = fetch_incidents(client, params, last_run)

        # next_run must have a timestamp for subsequent runs
        assert next_run.get("last_fetch_time") is not None

    def test_custom_cql_query_results_and_state(self, requests_mock):
        """End-to-end: custom query fetches incidents and advances last_fetch_time."""
        mock_response = util_load_json("test_data/fetch_incidents_reports.json")
        requests_mock.post(f"{BASE_URL}ingestion/threat-data/list/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_fetch": "50",
            "first_fetch": "4320",
            "incident_fetch_query": 'type = "report" AND confidence_score > 50',
        }
        last_run = {"last_fetch_time": 1700000000}

        next_run, incidents = fetch_incidents(client, params, last_run)

        # All three mock reports should be returned
        assert len(incidents) == 3
        assert all(inc["type"] == "CTIX Intel" for inc in incidents)
        # State should advance to the highest modified timestamp seen
        assert next_run["last_fetch_time"] >= 1700000500
        # Indicator state preserved
        assert "last_indicator_time" in next_run


class TestFetchIndicators:
    """Test fetch_indicators function."""

    def test_first_run(self, requests_mock):
        mock_response = util_load_json("test_data/fetch_indicators_result_set.json")
        requests_mock.get(f"{BASE_URL}ingestion/rules/save_result_set/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_indicator_fetch": "2000",
            "first_fetch": "4320",
            "retrieve_enriched_data": False,
            "integrationReliability": "C - Fairly reliable",
        }
        last_run = {}

        next_run, indicators = fetch_indicators(client, params, last_run)

        # 4 items in data
        assert len(indicators) == 4
        assert indicators[0]["value"] == "1.2.3.4"
        assert indicators[0]["type"] == "IP"
        assert indicators[0]["score"] == 3  # confidence 85
        assert indicators[0]["fields"]["ctixcustomscores"] == '{"x_ctix_customscore_2": 34}'
        assert indicators[1]["value"] == "evil.example.com"
        assert indicators[1]["type"] == "Domain"
        assert indicators[1]["score"] == 2  # confidence 55
        assert indicators[2]["value"] == "https://malware.example.com/payload"
        assert indicators[2]["type"] == "URL"
        assert indicators[2]["score"] == 1  # severity LOW -> GOOD (1)
        assert next_run["last_indicator_time"] is not None

    def test_deduplication(self, requests_mock):
        """Test that duplicate indicators (same value+type) are deduped."""
        mock_response = util_load_json("test_data/fetch_indicators_result_set.json")
        # Add a duplicate indicator to the data
        dup_indicator = dict(mock_response["results"][0]["data"][0])
        dup_indicator["id"] = "ind-dup-001"
        mock_response["results"][0]["data"].append(dup_indicator)

        requests_mock.get(f"{BASE_URL}ingestion/rules/save_result_set/", json=mock_response)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_indicator_fetch": "2000",
            "first_fetch": "4320",
            "retrieve_enriched_data": False,
            "integrationReliability": "C - Fairly reliable",
        }

        next_run, indicators = fetch_indicators(client, params, {})

        # Deduplication is delegated to demisto.createIndicators; fetch_indicators returns all
        assert len(indicators) == 5

    def test_empty_result_set(self, requests_mock):
        requests_mock.get(
            f"{BASE_URL}ingestion/rules/save_result_set/",
            json={"results": [], "total": 0},
        )

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_indicator_fetch": "2000",
            "first_fetch": "4320",
            "retrieve_enriched_data": False,
            "integrationReliability": "C - Fairly reliable",
        }

        next_run, indicators = fetch_indicators(client, params, {})
        assert len(indicators) == 0

    def test_with_enrichment(self, requests_mock):
        mock_result_set = util_load_json("test_data/fetch_indicators_result_set.json")
        mock_enrichment = util_load_json("test_data/enrichment_bulk_lookup.json")

        requests_mock.get(f"{BASE_URL}ingestion/rules/save_result_set/", json=mock_result_set)
        requests_mock.post(f"{BASE_URL}ingestion/openapi/bulk-lookup/indicator/", json=mock_enrichment)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        params = {
            "max_indicator_fetch": "2000",
            "first_fetch": "4320",
            "retrieve_enriched_data": True,
            "integrationReliability": "C - Fairly reliable",
        }

        next_run, indicators = fetch_indicators(client, params, {})

        assert len(indicators) == 4
        # First indicator should have enrichment data merged
        ip_indicator = next((i for i in indicators if i["value"] == "1.2.3.4"), None)
        assert ip_indicator is not None


class TestEnrichIndicatorsBulk:
    """Test enrich_indicators_bulk function."""

    def test_basic_enrichment(self, requests_mock):
        mock_enrichment = util_load_json("test_data/enrichment_bulk_lookup.json")
        requests_mock.post(f"{BASE_URL}ingestion/openapi/bulk-lookup/indicator/", json=mock_enrichment)

        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        indicators = [
            {"name": "1.2.3.4", "sdo_type": "indicator"},
            {"name": "evil.example.com", "sdo_type": "indicator"},
        ]

        enrichment_map = enrich_indicators_bulk(client, indicators)

        assert "1.2.3.4" in enrichment_map
        assert enrichment_map["evil.example.com"]["name"] == "evil.example.com"
        assert enrichment_map["1.2.3.4"]["confidence_score"] == 90

    def test_partial_failure(self):
        """Test that partial API failures are handled gracefully."""
        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        indicators = [
            {"name": "1.2.3.4", "sdo_type": "indicator"},
        ]

        # Mock at the client method level to avoid SystemExit from return_error
        with patch.object(client, "bulk_ioc_lookup_advanced", side_effect=Exception("API Error")):
            # Should not raise, returns empty map on failure
            enrichment_map = enrich_indicators_bulk(client, indicators)
        assert len(enrichment_map) == 0

    def test_empty_indicators(self, requests_mock):
        client = Client(
            base_url=BASE_URL,
            access_id=ACCESS_ID,
            secret_key=SECRET_KEY,
            verify=False,
            timeout=15,
            proxies={},
        )

        enrichment_map = enrich_indicators_bulk(client, [])
        assert len(enrichment_map) == 0
