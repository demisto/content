import pytest  # noqa: F401
import demistomock as demisto  # noqa: F401
from EclecticIQIntelligenceCenterv3 import EclecticIQ_api, maliciousness_to_dbotscore


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
    client = EclecticIQ_api(
            baseurl=SERVER,
            eiq_api_version=API_VERSION,
            username="",
            password=PASSWORD,
            verify_ssl=USE_SSL,
        )
    response = client.get_outh_token()
    assert isinstance(response, str)


def sighting_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "type": " EclecticIQ-sighting",
                "timestamp": "2022-03-10T05:37:42Z",
                "title": "title1",
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


def entity_create_response(*args, **kwargs):
    return_value = "123-123-123"
    return return_value


# Test cases for sighting


def test_sighting(mocker):
    """Test for sighting."""
    mocker.patch("EclecticIQIntelligenceCenterv3.create_sighting", sighting_mock_response)
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
