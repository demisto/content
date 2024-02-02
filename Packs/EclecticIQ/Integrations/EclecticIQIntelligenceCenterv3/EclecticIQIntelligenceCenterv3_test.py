import pytest  # noqa: F401
import demistomock as demisto  # noqa: F401
from EclecticIQIntelligenceCenterv3 import EclecticIQ_api, create_sighting, create_indicator, prepare_entity_observables


SERVER = "https://test.eclecticiq.com"
EIQ_USER = "test@test.test"
PASSWORD = "123"
EIQ_FEED_IDs = "12"
USE_SSL = "false"
API_VERSION = "v2"


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
    client = EclecticIQ_api(
            baseurl=SERVER,
            eiq_api_version=API_VERSION,
            username="",
            password=PASSWORD,
            verify_ssl=USE_SSL,
        )
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
    mocker.patch.object(demisto, 'args', return_value={"observable_type": "ipv4", "observable_value": "1.1.1.1", "sighting_title": "EIQ-title",
            "sighting_description": "sighting", "observable_maliciousness": "Malicious (Medium confidence)"})

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


def test_create_indicator(mocker):
    """Test for sighting."""
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.create_entity", entity_create_response)
    mocker.patch("EclecticIQIntelligenceCenterv3.EclecticIQ_api.get_outh_token", platform_auth_mock_response)
    mocker.patch.object(demisto, 'args', return_value={"observable_type": "ipv4", "observable_value": "1.1.1.1", "indicator_title": "EIQ-title",
            "indicator_description": "indicator", "observable_maliciousness": "Malicious (Medium confidence)"})

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
    response = prepare_entity_observables("1.1.1.1","ipv4", "Malicious (High confidence)", '[{"type":"ipv4", "value": "2.2.2.2", "maliciousness": "medium"}]')
    assert isinstance(response, list)
    assert isinstance(response[0], dict)
    assert response[1]["observable_classification"] == "bad"











