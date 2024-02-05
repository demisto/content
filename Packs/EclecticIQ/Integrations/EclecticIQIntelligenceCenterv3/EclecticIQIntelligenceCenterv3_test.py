import pytest  # noqa: F401
import demistomock as demisto  # noqa: F401
import EclecticIQIntelligenceCenterv3
from EclecticIQIntelligenceCenterv3 import (EclecticIQ_api, create_sighting, create_indicator, prepare_entity_observables,
                                            domain_command, ip_command, url_command, file_command, email_command,
                                            parse_reputation_results)


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


def test_auth(mocker):
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    client = EclecticIQ_api(baseurl=SERVER,
                            eiq_api_version=API_VERSION,
                            username="",
                            password=PASSWORD,
                            verify_ssl=USE_SSL)
    response = client.get_outh_token()
    assert isinstance(response, str)


def entity_create_response(*args, **kwargs):
    return_value = str("123-123-123")
    return return_value


# Test cases for sighting


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
