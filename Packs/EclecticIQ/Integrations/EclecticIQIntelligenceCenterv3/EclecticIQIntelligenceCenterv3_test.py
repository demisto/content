import pytest   # noqa: F401
import demistomock as demisto   # noqa: F401
from EclecticIQIntelligenceCenterv3 import (
    EclecticIQ_api
)

SERVER = "https://ic-playground.eclecticiq.com"
EIQ_USER = "test@test.test"
PASSWORD = "123"
EIQ_FEED_IDs = "12"
USE_SSL = "false"
API_VERSION = "v2"

# Mock function for sighting


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
                                "type": "identity"
                            },
                            "time": {
                                "type": "time",
                                "start_time": "2022-03-10T05:37:42Z",
                                "start_time_precision": "second"
                            }
                        }
            },
            "meta": {"tags": ["XSOAR Alert"], "ingest_time": "2022-03-10T05:37:42Z"}
        }
    }
    return return_value


# Test cases for sighting


def test_sighting(mocker):
    """Test for sighting."""
    mocker.patch(
        "EclecticIQIntelligenceCenterv3.create_sighting",
        sighting_mock_response
    )
    client = EclecticIQ_api(baseurl=SERVER, eiq_api_version=API_VERSION, username="", password=PASSWORD, verify_ssl=USE_SSL, init_cred_test=False)
    response = client.create_entity(observable_dict={"classification": "bad", "confidence": "medium", 'observable_type': "ipv4", 'observable_value': "1.1.1.1"},
                                    source_group_name="test", entity_title="Sighting",
                                    entity_description="description", entity_confidence="medium",
                                    entity_tags=[], entity_impact_value="medium")

    assert isinstance(response, dict)
    # print(response)
    assert response['data']['data']['confidence'] == 'medium'
    assert response['data']['data']['description'] == 'test_desc'
    assert response['data']['data']['type'] == ' EclecticIQ-sighting'
    assert response["data"]["meta"]["tags"] == ['XSOAR Alert']
    assert response["data"]["data"]["security_control"]["type"] == 'information-source'
    assert response["data"]["data"]["timestamp"] == '2022-03-10T05:37:42Z'
