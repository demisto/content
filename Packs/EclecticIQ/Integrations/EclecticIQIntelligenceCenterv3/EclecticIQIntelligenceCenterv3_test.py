import pytest  # noqa: F401
import json
import re
import demistomock as demisto  # noqa: F401
import EclecticIQIntelligenceCenterv3
from datetime import datetime
from EclecticIQIntelligenceCenterv3 import (EclecticIQ_api, create_sighting, create_indicator, prepare_entity_observables,
                                            domain_command, ip_command, url_command, file_command, email_command,
                                            parse_reputation_results, extract_uuid_from_url, observable_id_from_url,
                                            taxonomie_id_from_url, format_ts, format_ts_human, request_get, request_patch,
                                            request_post, request_put, request_delete, get_entity, get_entity_by_id,
                                            get_indicators, fetch_indicators)


SERVER = "https://test.eclecticiq.com"
EIQ_USER = "test@test.test"
PASSWORD = "123"
EIQ_FEED_IDs = "12"
USE_SSL = "false"
API_VERSION = "v2"

EclecticIQIntelligenceCenterv3.DOMAIN_THRESHOLD = "low"
EclecticIQIntelligenceCenterv3.IP_THRESHOLD = "low"
EclecticIQIntelligenceCenterv3.URL_THRESHOLD = "low"
EclecticIQIntelligenceCenterv3.FILE_THRESHOLD = "low"
EclecticIQIntelligenceCenterv3.EMAIL_THRESHOLD = "low"


def platform_auth_mock_response(*args, **kwargs):
    return_value = "test OK"
    return return_value


def test_get_outh_token_success(requests_mock):
    requests_mock.get('https://test.eclecticiq.com/private', json={"message": "Auth"}, status_code=201)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL,
                            init_cred_test=False
                            )

    try:
        client.get_outh_token()
    except Exception as excinfo:
        pytest.fail(f"Unexpected exception raised: {excinfo}")


def test_send_api_request_good(requests_mock):
    requests_mock.get('https://test.eclecticiq.com/test', json={"message": "ok"}, status_code=201)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL,
                            init_cred_test=False
                            )

    try:
        client.send_api_request(method="get", path="/test")
    except Exception as excinfo:
        pytest.fail(f"Unexpected exception raised: {excinfo}")


def entity_create_response(*args, **kwargs):
    return_value = "123-123-123"
    return return_value


def test_entity(mocker):
    """Test for sighting."""
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.create_entity", entity_create_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    response = client.create_entity(
        observable_dict={
            "classification": "bad",
            "confidence": "medium",
            "observable_type": "ipv4",
            "observable_value": "1.1.1.1",
        },
        source_group_name="test",
        entity_title="Sighting",
        entity_description="description",
        entity_confidence="medium",
        entity_tags=[],
        entity_impact_value="medium",
    )

    assert isinstance(response, str)


def sighting_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "type": " EclecticIQ-sighting",
                "timestamp": "2022-03-10T05:37:42Z",
                "title": "EIQ-title",
                "security_control": {
                    "type": "information-source",
                    "identity": {
                        "name": " EclecticIQ Platform App for cortex XSOAR",
                        "type": "identity",
                    },
                    "time": {
                        "type": "time",
                        "start_time": "2022-03-10T05:37:42Z",
                        "start_time_precision": "second",
                    },
                },
            },
            "meta": {"tags": ["XSOAR Alert"], "ingest_time": "2022-03-10T05:37:42Z"},
        }
    }
    return return_value


def test_create_sighting(mocker):
    """Test for sighting."""
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.create_entity", entity_create_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"observable_type": "ipv4", "observable_value": "1.1.1.1",
                                                       "sighting_title": "EIQ-title", "sighting_description": "sighting",
                                                       "observable_maliciousness": "Malicious (Medium confidence)"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = create_sighting(client)

    assert isinstance(response.raw_response, dict)
    assert response.outputs_prefix == "EclecticIQ.Sightings"
    assert response.raw_response["sighting_details"]["observable_maliciousness"] == 'Malicious (Medium confidence)'
    assert response.outputs["SightingId"] == "123-123-123"
    assert response.raw_response["sighting_details"]["sighting_title"] == sighting_mock_response()["data"]["data"]["title"]


def test_create_indicator(mocker):
    """Test for sighting."""
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.create_entity", entity_create_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"observable_type": "ipv4", "observable_value": "1.1.1.1",
                                                       "indicator_title": "EIQ-title", "indicator_description": "indicator",
                                                       "observable_maliciousness": "Malicious (Medium confidence)"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = create_indicator(client)

    assert isinstance(response.raw_response, dict)
    assert response.outputs_prefix == "EclecticIQ.Indicators"
    assert response.raw_response["indicator_title"] == "EIQ-title"
    assert response.outputs["IndicatorId"] == "123-123-123"


def test_prepare_entity_observables(mocker):
    response = prepare_entity_observables("1.1.1.1", "ipv4", "Malicious (High confidence)",
                                          '[{"type":"ipv4", "value": "2.2.2.2", "maliciousness": "medium"}]')
    assert isinstance(response, list)
    assert isinstance(response[0], dict)
    assert response[1]["observable_classification"] == "bad"


def observable_mock_response_domain(*args, **kwargs):
    result = {"created": "01-01-1900",
              "last_updated": "01-01-1910",
              "maliciousness": "low",
              "type": "domain",
              "value": "test.com",
              "id": "123",
              "source_name": "testing group",
              "platform_link": "eclecticiq.test/main/intel/all/browse/observable?tab=overview&id="}

    return result


def observable_mock_response_ip(*args, **kwargs):
    result = {"created": "01-01-1900",
              "last_updated": "01-01-1910",
              "maliciousness": "medium",
              "type": "ip",
              "value": "1.1.1.1",
              "id": "123",
              "source_name": "testing group",
              "platform_link": "eclecticiq.test/main/intel/all/browse/observable?tab=overview&id="}

    return result


def observable_mock_response_email(*args, **kwargs):
    result = {"created": "01-01-1900",
              "last_updated": "01-01-1910",
              "maliciousness": "medium",
              "type": "email",
              "value": "test@test.test",
              "id": "123",
              "source_name": "testing group",
              "platform_link": "eclecticiq.test/main/intel/all/browse/observable?tab=overview&id="}

    return result


def observable_mock_response_url(*args, **kwargs):
    result = {"created": "01-01-1900",
              "last_updated": "01-01-1910",
              "maliciousness": "medium",
              "type": "url",
              "value": "http://test.test",
              "id": "123",
              "source_name": "testing group",
              "platform_link": "eclecticiq.test/main/intel/all/browse/observable?tab=overview&id="}

    return result


def observable_mock_response_file(*args, **kwargs):
    result = {"created": "01-01-1900",
              "last_updated": "01-01-1910",
              "maliciousness": "medium",
              "type": "file",
              "value": "e489ed8f638df3faa75ef9b76fa68ef9",
              "id": "123",
              "source_name": "testing group",
              "platform_link": "eclecticiq.test/main/intel/all/browse/observable?tab=overview&id="}

    return result


def test_parse_reputation_results(mocker):
    response_domain = parse_reputation_results(observable_mock_response_domain(), "test.com", "domain", "low", "Domain")
    response_ip = parse_reputation_results(observable_mock_response_ip(), "1.1.1.1", "ip", "low", "ipv4")

    assert isinstance(response_domain, list)
    assert response_domain[0].raw_response['maliciousness'] == "low"
    assert response_domain[0].outputs_prefix == "EclecticIQ.Domain"
    assert isinstance(response_ip, list)
    assert response_ip[0].raw_response['maliciousness'] == "medium"
    assert response_ip[0].outputs_prefix == "EclecticIQ.IP"


def test_parse_reputation_results_empty_reply(mocker):
    response = parse_reputation_results(None, "test.com", "domain", "low", "Domain")
    assert response[0].raw_response["result"] == 'Observable not found in EclecticIQ IC.'


def test_domain_command(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.lookup_observable", observable_mock_response_domain)
    mocker.patch.object(demisto, 'args', return_value={"domain": "test.com"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = domain_command(client)

    assert response[0].raw_response['maliciousness'] == "low"
    assert response[0].outputs_prefix == "EclecticIQ.Domain"


def test_url_command(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.lookup_observable", observable_mock_response_url)
    mocker.patch.object(demisto, 'args', return_value={"url": "http://test.test"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = url_command(client)

    assert response[0].raw_response['maliciousness'] == "medium"
    assert response[0].outputs_prefix == "EclecticIQ.URL"


def test_file_command(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.lookup_observable", observable_mock_response_file)
    mocker.patch.object(demisto, 'args', return_value={"file": "e489ed8f638df3faa75ef9b76fa68ef9"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = file_command(client)

    assert response[0].raw_response['maliciousness'] == "medium"
    assert response[0].outputs_prefix == "EclecticIQ.File"


def test_email_command(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.lookup_observable", observable_mock_response_email)
    mocker.patch.object(demisto, 'args', return_value={"email": "test@test.test"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = email_command(client)

    assert response[0].raw_response['maliciousness'] == "medium"
    assert response[0].outputs_prefix == "EclecticIQ.Email"


def test_ip_command(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.lookup_observable", observable_mock_response_ip)
    mocker.patch.object(demisto, 'args', return_value={"ip": "1.1.1.1"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = ip_command(client)

    assert response[0].raw_response['maliciousness'] == "medium"
    assert response[0].outputs_prefix == "EclecticIQ.IP"


def test_get_source_group_uid(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "data":
            [
                {
                    "created_at": "2023-05-08T11:23:13.870452+00:00",
                    "description": "",
                    "id": 1,
                    "last_updated_at": "2023-05-08T11:23:13.870452+00:00",
                    "name": "Testing Group",
                    "source": [
                        "https://ic-playground.eclecticiq.com/api/v2/sources/95c654c9-e1de-4639-9d17-b12a883164b6"
                    ],
                    "users": [
                        "https://ic-playground.eclecticiq.com/api/v2/users/48?role=member",
                        "https://ic-playground.eclecticiq.com/api/v2/users/63?role=member",
                        "https://ic-playground.eclecticiq.com/api/v2/users/9?role=admin"
                    ]
                }
            ]
    }

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_source_group_uid("testing_group")

    assert isinstance(response, list)
    assert response[0] == "https://ic-playground.eclecticiq.com/api/v2/sources/95c654c9-e1de-4639-9d17-b12a883164b6"


def test_get_source_group_order_id(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": [{"id": "order_id"}]}
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_source_group_order_id("example_group")

    assert response == "order_id"
    assert isinstance(response, str)


def test_get_enrichers_list(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": ["enricher1", "enricher2"]}
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_enrichers_list()

    assert response == ["enricher1", "enricher2"]


def test_extract_uuid_from_url():
    url = "https://example.com/123-def456-ghi789-jkl012-ghi789-jkl0"
    assert extract_uuid_from_url(url) == "123-def456-ghi789-jkl012-ghi789-jkl0"


def test_extract_uuid_from_url_empty():
    invalid_url = "https://example.com/no-uuid-here"
    assert extract_uuid_from_url(invalid_url) is None


def test_observable_id_from_url():
    url = "https://example.com/observables/42"
    assert observable_id_from_url(url) == "42"

    invalid_url = "https://example.com/no-id-here"
    assert observable_id_from_url(invalid_url) is None


def test_taxonomie_id_from_url():
    url = "https://example.com/taxonomies/123"
    assert taxonomie_id_from_url(url) == "123"

    invalid_url = "https://example.com/no-id-here"
    assert taxonomie_id_from_url(invalid_url) is None


def test_format_ts():
    dt = datetime(2024, 2, 6, 12, 34, 56)
    expected_result = "2024-02-06T12:34:56Z"
    assert format_ts(dt) == expected_result


def test_format_ts_human():
    dt = datetime(2024, 2, 6, 12, 34, 56)
    expected_result = "2024-02-06T12:34:56Z"
    assert format_ts_human(dt) == expected_result


def test_create_outgoing_feed(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": "123321"}
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'get_source_group_order_id', return_value="123-123-123")
    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.create_outgoing_feed("CSV Observables", "8", "New Feed", "http download", "REPLACE", "testing Group")

    assert response == "123321"


def test_lookup_observable(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({
        "count": 1,
        "data": [
            {
                "created_at": "2023-05-24T16:52:29.715750+00:00",
                "entities": [
                    "https://ic-playground.eclecticiq.com/api/v2/entities/4de74eae-68fd-427b-808c-45dc7fb8c650",
                    "https://ic-playground.eclecticiq.com/api/v2/entities/dfd0d6ae-7dd6-435f-ab73-66088b46ea7c"
                ],
                "id": 2,
                "last_updated_at": "2024-01-29T07:42:07.059329+00:00",
                "meta": {
                    "maliciousness": "low"
                },
                "sources": [
                    "https://ic-playground.eclecticiq.com/api/v2/sources/5601ee2a-f85a-4b14-a626-00052600b313",
                    "https://ic-playground.eclecticiq.com/api/v2/sources/0ce29afd-bdac-47bd-9f11-f6a4f479bc1c"
                ],
                "type": "ipv4",
                "value": "1.1.1.1"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    })

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'get_group_name', return_value={"name": "Testing", "type": "user"})
    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.lookup_observable("1.1.1.1", "ipv4")

    assert response['type'] == 'ipv4'
    assert response['source_name'] == 'user: Testing; user: Testing; '


def test_get_feed_content_blocks(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "count": 2,
        "data":
        {
            "content_blocks": "urn:eclecticiq.com:csv-extracts:1.0",
            "created_at": "2023-06-20T18:06:08.632279",
            "delivery_status": "null",
            "filename": "qradarfeedtest2-5d6c9551-1.csv",
            "id": 11,
            "items_count": 25,
            "meta": {
                "destination": "a80e31f1-3123-4f96-a15c-944e5f72f302"
            },
            "outgoing_feed": "https://ic-playground.eclecticiq.com/api/v2/outgoing-feeds/10",
            "run_id": "5d6c9551-9ad4-4c88-9936-01620a2fe5e7",
            "size": 12991
        },
        "limit": 100,
        "offset": 0,
        "total_count": 2
    }

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    feed_to_request = {"packaging_status": "SUCCESS", "update_strategy": "REPLACE",
                       "id": "10", "created_at": "2023-06-20T18:06:08.632279"}
    feed_last_run = {"last_ingested": "2023-06-20T18:06:08.632279", "created_at": "2023-06-20T18:06:08.632279"}

    response = client.get_feed_content_blocks(feed_to_request, feed_last_run)

    assert response == "urn:eclecticiq.com:csv-extracts:1.0"
    assert isinstance(response, str)


def test_get_feed_content_blocks_append(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "count": 2,
        "data":
        {
            "content_blocks": "urn:eclecticiq.com:csv-extracts:1.0",
            "created_at": "2023-06-20T18:06:08.632279",
            "delivery_status": "null",
            "filename": "qradarfeedtest2-5d6c9551-1.csv",
            "id": 11,
            "items_count": 25,
            "meta": {
                "destination": "a80e31f1-3123-4f96-a15c-944e5f72f302"
            },
            "outgoing_feed": "https://ic-playground.eclecticiq.com/api/v2/outgoing-feeds/10",
            "run_id": "5d6c9551-9ad4-4c88-9936-01620a2fe5e7",
            "size": 12991
        },
        "limit": 100,
        "offset": 0,
        "total_count": 2
    }

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    feed_to_request = {"packaging_status": "SUCCESS", "update_strategy": "APPEND",
                       "id": "10", "created_at": "2023-06-20T18:06:08.632279"}
    feed_last_run = {"last_ingested": "2023-06-20T18:06:08.632279", "created_at": "2023-06-20T18:06:08.632271"}

    response = client.get_feed_content_blocks(feed_to_request, feed_last_run)

    assert response == "urn:eclecticiq.com:csv-extracts:1.0"
    assert isinstance(response, str)


def test_request_get(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"status": "OK"}
    mock_response.status_code = "200"
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"uri": "test"})

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = request_get(client)

    assert response.outputs["ReplyStatus"] == "200"
    assert response.outputs_prefix == "EclecticIQ.GET"


def test_request_post(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"status": "OK"}
    mock_response.status_code = "200"
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"uri": "test"})

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = request_post(client)

    assert response.outputs["ReplyStatus"] == "200"
    assert response.outputs_prefix == "EclecticIQ.POST"


def test_request_put(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"status": "OK"}
    mock_response.status_code = "200"
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"uri": "test"})

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = request_put(client)

    assert response.outputs["ReplyStatus"] == "200"
    assert response.outputs_prefix == "EclecticIQ.PUT"


def test_request_patch(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"status": "OK"}
    mock_response.status_code = "200"
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"uri": "test"})

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = request_patch(client)

    assert response.outputs["ReplyStatus"] == "200"
    assert response.outputs_prefix == "EclecticIQ.PATCH"


def test_request_delete(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"status": "OK"}
    mock_response.status_code = "200"
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"uri": "test"})

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = request_delete(client)

    assert response.outputs["ReplyStatus"] == "200"
    assert response.outputs_prefix == "EclecticIQ.DELETE"


def test_get_feed_info(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "data": {
            "content_type": "urn:eclecticiq.com:csv-extracts:1.0",
            "created_at": "2023-06-20T18:05:06.625499+00:00",
            "id": "10",
            "is_active": True,
            "last_triggered_at": "2023-11-15T17:52:24.733800+00:00",
            "last_updated_at": "2023-07-13T10:29:52.787017+00:00",
            "name": "qradarfeedtest2",
            "packaging_last_run_at": "2023-11-15T17:52:24.733800+00:00",
            "packaging_status": "SUCCESS",
            "transport_type": "eiq.outgoing-transports.http-download",
            "update_strategy": "DIFF",
            "update_task": "https://ic-playground.eclecticiq.com/api/v2/tasks/195"
        }
    }

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_feed_info("10")

    assert response[0]["id"] == "10"
    assert isinstance(response[0], dict)


def test_eiq_get_entity_by_id(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({
        "data": {
            "attachments": [],
            "created_at": "2024-02-06T15:36:35.251514+00:00",
            "data": {
                "id": "indicator-2c082ad0-cd32-47c2-8ff1-7c6adde759d4",
                "timestamp": "2024-02-06T15:36:35.251514+00:00",
                "title": "test IOC",
                "type": "indicator"
            },
            "datasets": [],
            "id": "2c082ad0-cd32-47c2-8ff1-7c6adde759d4",
            "incoming_feed": "null",
            "last_updated_at": "2024-02-06T15:36:36.805980+00:00",
            "meta": {
                "attacks": [],
                "estimated_observed_time": "2024-02-06T15:36:35.251514+00:00",
                "estimated_threat_start_time": "2024-02-06T15:36:35.251514+00:00",
                "half_life": "30",
                "source_reliability": "C",
                "taxonomies": [],
                "title": "parth 6 feb test 15",
                "tlp_color": "null"
            },
            "observables": [
                "https://ic-playground.eclecticiq.com/api/v2/observables/651905"
            ],
            "outgoing_feeds": [],
            "relevancy": "1",
            "sources": [
                "https://ic-playground.eclecticiq.com/api/v2/sources/2411da8d-9b07-4507-8e9e-ed64abd179c8"
            ]
        }
    })

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_taxonomy_dict", [])

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    client.taxonomie_dict = ["1", "2"]

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_entity_by_id("2c082ad0-cd32-47c2-8ff1-7c6adde759d4",
                                       observables_lookup=False, relationships_lookup=False)

    assert response["entity_title"] == "test IOC"
    assert isinstance(response, dict)


def test_eiq_get_enrichers_list(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "data": [{"name": "enricher1", "is_active": True}]
    }

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_enrichers_list()

    assert isinstance(response, list)
    assert len(response) == 1


def test_eiq_get_status(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": {"status": "GREEN"}}

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_status()

    assert isinstance(response, dict)
    assert response["status"] == "GREEN"


def test_eiq_get_status_red_component(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    service_return = {"health": "GREEN", "celery_states": [{"health": "RED", "component": "celery"}],
                      "service_states": [{"health": "RED", "component": "db"}]}
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_status", return_value=service_return)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    response = client.get_status_red_component()

    assert isinstance(response, dict)
    assert response["components"][0]["health"] == "RED"


def test_eiq_get_active_enrichers_list(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mock_result = {"name": "enricher1", "is_active": "True"}
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_enrichers_list", return_result=mock_result)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    response = client.get_active_enrichers_list()

    assert isinstance(response, list)


def test_lookup_observable_many(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({
        "count": 2,
        "data": [
            {
                "created_at": "2023-05-24T16:52:29.715750+00:00",
                "entities": [
                    "https://ic-playground.eclecticiq.com/api/v2/entities/4de74eae-68fd-427b-808c-45dc7fb8c650",
                    "https://ic-playground.eclecticiq.com/api/v2/entities/dfd0d6ae-7dd6-435f-ab73-66088b46ea7c"
                ],
                "id": 2,
                "last_updated_at": "2024-01-29T07:42:07.059329+00:00",
                "meta": {
                    "maliciousness": "low"
                },
                "sources": [
                    "https://ic-playground.eclecticiq.com/api/v2/sources/5601ee2a-f85a-4b14-a626-00052600b313",
                    "https://ic-playground.eclecticiq.com/api/v2/sources/0ce29afd-bdac-47bd-9f11-f6a4f479bc1c"
                ],
                "type": "ipv4",
                "value": "1.1.1.1"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    })

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'get_group_name', return_value={"name": "Testing", "type": "user"})
    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.lookup_observable("1.1.1.1", "ipv4")

    assert response['type'] == 'ipv4'
    assert response['source_name'] == 'user: Testing; user: Testing; '


def test_search_entity(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": [{"title": "test entity", "id": "1"}]})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'get_entity_by_id', return_value={"title": "test entity", "id": "1"})
    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.search_entity("\"test entity\"", "Indicator")

    assert response[0]['title'] == "test entity"
    assert isinstance(response, list)


def test_eiq_enrich_observable(mocker):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": {"status": "done"}}

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.enrich_observable(enricher_id=1, observable_id=2)

    assert isinstance(response, dict)
    assert response["status"] == "done"


def test_eiq_create_incoming_feed(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": {"status": "done"}})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.create_incoming_feed(feed_title="new_feed", content_type="CSV Observable",
                                           password="secret", username="user")

    assert isinstance(response, dict)
    assert response["status"] == "done"


def test_eiq_download_incoming_feed(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": {"status": "done"}})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.download_incoming_feed(feed_id=1, feed_provider_task=2)

    assert isinstance(response, dict)
    assert response["status"] == "done"


def test_eiq_get_incoming_feed_blobs_pending(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": [{"id": 1, "n_blobs_pending": ["123-123-123", "123-123-124", "123-123-125"]}]})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_incoming_feed_blobs_pending(feed_id=1)

    assert isinstance(response, list)
    assert len(response) == 3


def test_eiq_get_full_feed_info(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": [{"id": 1, "blobs": ["123-123-123", "123-123-124", "123-123-125"],
                                     "content_type": "CSV"}]})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_full_feed_info(feed_id="*")

    assert isinstance(response, list)
    assert len(response) == 1
    assert response[0]["content_type"] == "CSV"


def test_eiq_get_incoming_feed_full_info(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": [{"id": 1, "blobs": ["123-123-123", "123-123-124", "123-123-125"],
                                     "content_type": "CSV"}]})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_incoming_feed_full_info(feed_id="*")

    assert isinstance(response, list)
    assert len(response) == 1
    assert response[0]["content_type"] == "CSV"


def test_eiq_download_block_list(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": "dummy_data"})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.download_block_list("feed_123_block_432.csv")

    assert isinstance(response, str)
    assert json.loads(response)["data"] == "dummy_data"


def test_eiq_get_observable_by_id(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": "dummy_data"})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_observable_by_id(id=123)

    assert isinstance(response, dict)
    assert response["data"] == "dummy_data"


def test_eiq_get_all_observables(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": "dummy_data"})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_all_observables()

    assert isinstance(response, dict)
    assert response["data"] == "dummy_data"


def test_eiq_get_taxonomy_dict(mocker):
    mock_response = mocker.Mock()
    mock_response.text = json.dumps({"data": [{"id": "1", "name": "Confidence High"}, {"id": "2", "name": "Confidence Low"}]})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', return_value=mock_response)

    response = client.get_taxonomy_dict()

    assert isinstance(response, dict)
    assert response["2"] == "Confidence Low"


def relationship_payload():
    payload = {
        "data": [{
            "created_at": "2024-02-08T17:02:47.539388+00:00",
            "data": {
                "key": "related-to",
                "source": "https://ic-playground.eclecticiq.com/api/v2/entities/379e06ed-d06f-425e-ab8d-79b157c18e48",
                "target": "https://ic-playground.eclecticiq.com/api/v2/entities/379e8ffd-8c0c-4d1e-b17f-a29c05c49bfd",
                "timestamp": "2024-02-08T17:02:47.539388+00:00"
            },
            "id": "379ef6bc-02ac-444d-a30a-18845c583cef",
            "last_updated_at": "2024-02-08T17:02:47.544644+00:00",
            "meta": {
                "source_reliability": "B",
                "stix_id": "{http://not-yet-configured.example.org/}relation-379ef6bc-02ac-444d-a30a-18845c583cef",
                "tlp_color": "null"
            },
            "sources": [
                "https://ic-playground.eclecticiq.com/api/v2/sources/0a80459d-282d-40c1-8cff-e2980535283c"
            ],
            "strict_stix_1": False,
            "strict_stix_2": True
        }]
    }

    return payload


def test_eiq_get_entity_realtionships(mocker):
    mock_response_1 = mocker.Mock()
    mock_response_2 = mocker.Mock()
    mock_response_1.text = json.dumps(relationship_payload())
    mock_response_2.text = json.dumps({"data": {"data": {"type": "indicator", "title": "New Entity"},
                                       "id": "123-12-12", "observables": []}})

    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)

    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)

    mocker.patch.object(client, 'send_api_request', side_effect=[mock_response_1, mock_response_2])

    response = client.get_entity_realtionships(source_id="379ef6bc-02ac-444d-a30a-18845c583cef")

    assert isinstance(response, list)
    assert response[0]["entity_id"] == '123-12-12'
    assert response[0]["observables_count"] == 0


def entity_mock_response(*args, **kwargs):
    entity = [{"title": "test entity", "type": "indicator", "observables_list": [{"value": "1.1.1.1", "type": "ipv4"}],
               "relationships_list": []}]
    return entity


def test_get_entity(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.search_entity", entity_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"entity_title": "test entity", "entity_type": "all"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = get_entity(client)

    assert response.raw_response[0]['title'] == "test entity"
    assert len(response.raw_response[0]['observables_list']) == 1


def test_get_entity_by_id(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_entity_by_id", entity_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"entity_id": "123-123-123"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = get_entity_by_id(client)

    assert response.raw_response[0]['title'] == "test entity"
    assert len(response.raw_response[0]['observables_list']) == 1


def csv_block_mock_response(*args, **kwargs):
    csv = '''value,type,entity.id,entity.title,entity.type,source.names,entity.description,meta.confidence
1.1.1.1,ipv4,123-123-123,"test Entity",test_indicator,test_source,"test description",medium
1.1.1.2,ipv4,1234-1234-1234,"test Entity2",test_indicator2,test_source2,"test description2",medium'''
    return csv


def feed_info_mock_response(*args, **kwargs):
    feedinfo = [{"id": "1", "update_strategy": "REPLACE", "created_at": "01-01-1900", "name": "test feed"}]
    return feedinfo


def feed_cb_mock_response(*args, **kwargs):
    feedcb = ["block1"]
    return feedcb


def test_get_indicators(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_feed_info", feed_info_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_feed_content_blocks", feed_cb_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.download_block_list", csv_block_mock_response)
    mocker.patch.object(demisto, 'params', return_value={"feedId": "1"})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )
    response = get_indicators(client)

    assert isinstance(response.readable_output, str)
    assert bool(re.search(r"| test description | 123-123-123 | test Entity | test_indicator |", response.readable_output))


def test_fetch_indicators(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_feed_info", feed_info_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_feed_content_blocks", feed_cb_mock_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.download_block_list", csv_block_mock_response)
    mocker.patch.object(demisto, 'params', return_value={"feedId": "1"})
    mocker.patch.object(demisto, 'getLastRun', return_value={})

    client = EclecticIQ_api(
        baseurl=SERVER,
        eiq_api_version=API_VERSION,
        username="",
        password=PASSWORD,
        verify_ssl=USE_SSL,
    )

    response = fetch_indicators(client)

    assert isinstance(response, list)
    assert len(response) == 2
    assert response[0]['rawJSON']['entity.id'] == '123-123-123'
