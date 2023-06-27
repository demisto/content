import pytest
import demistomock as demisto
from EclecticIQv2 import (
    Client,
    EclecticIQ_lookup_observables,
    EclecticIQ_create_sighting,
    EclecticIQ_create_observable,
    get_platform_permission_ids,
    authenticate_user,
    get_permission_name_from_id,
    maliciousness_to_dbotscore,
    prepare_observable_data,
    prepare_entity_data,
    validate_type,
    get_entity_data,
    data_ingestion,
    main
)
api_key = "test_api_key"
proxy = "False"
Base_url = "https://example.com"
verify = "False"
# Mock function for get_user_granted_permissions


def get_user_granted_permissions_mock_response(*args, **kwargs):
    return_value = {'data': {'permissions': 'https://example//permissions/1'}}
    return return_value


# Test cases for  get_user_granted_permissions

def test_get_user_granted_permissions(mocker):
    """Test for get_user_granted_permissions."""
    mocker.patch("EclecticIQv2.Client._http_request", get_user_granted_permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    response = client.get_user_granted_permissions()
    assert isinstance(response, str)

# Mock function for get user granted permissions scenario


def permissions_mock_response(*args, **kwargs):
    return_value = {'id': 1}
    return return_value

# Test cases for get user granted permissions scenario


def test_permissions_scenario(mocker):
    """Test for get_user_granted_permissions."""
    mocker.patch("EclecticIQv2.Client._http_request", permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    response = client.get_user_granted_permissions()
    assert isinstance(response, dict)


# Mock function for get_user_granted_permissions


def get_platform_permissions_mock_response(*args, **kwargs):
    return_value = {'data': {'id': 1, 'name': 'read history-events'}}
    return return_value


# Test cases for  get_platform_permissions

def test_get_platform_permissions(mocker):
    """Test for get_platform_permissions."""
    mocker.patch("EclecticIQv2.Client._http_request", get_platform_permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    response = client.get_platform_permissions()
    assert isinstance(response, dict)
    assert response == {'id': 1, 'name': 'read history-events'}
# Mock function for platform permissions


def platform_permissions_mock_response(*args, **kwargs):
    return_value = {'id': 1}
    return return_value
# Test cases for platform permission


def test_permissions(mocker):
    """Test for get_platform_permissions."""
    mocker.patch("EclecticIQv2.Client._http_request", permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    response = client.get_platform_permissions()
    assert isinstance(response, dict)
# Mock function for get_observable_by_id


def get_observable_by_id_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "created_at": "2022-08-24T10:02:04.609448+00:00",
            "entities": [
                "https://example//entities/7fda61ec-852e"
            ],
            "id": 7938475,
            "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
            "meta": {
                "maliciousness": "unknown"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": "ipv4",
            "value": "001.001.001.001"
        }
    }
    return return_value


# Test cases for get_observable_by_id

def test_get_observable_by_id(mocker):
    """Test for get_observable_by_id."""
    mocker.patch(
        "EclecticIQv2.Client._http_request",
        get_observable_by_id_mock_response
    )
    client = Client(Base_url, api_key, proxy)
    response = client.get_observable_by_id(id=7938475)
    assert isinstance(response, dict)

# Mock function for observable


def observable_mock_response(*args, **kwargs):
    return_value = {
        "count": 1,
        "data": [
            {
                "created_at": "2022-08-24T10:02:04.609448+00:00",
                "entities": [
                    "https://example//entities/7fda61ec-852e"
                ],
                "id": 7938475,
                "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
                "meta": {
                    "maliciousness": "safe"
                },
                "sources": [
                    "https://example//sources/9a479225-37d1"
                ],
                "type": "ipv4",
                "value": "001.001.001.001"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    }
    return return_value


# Test cases for observable

def test_observable(mocker):
    """Test for observable."""
    mocker.patch(
        "EclecticIQv2.Client._http_request",
        observable_mock_response
    )
    client = Client(Base_url, api_key, proxy)
    response = client.observable(type_eiq="ipv4", value="001.001.001.001", maliciousness="safe")
    assert isinstance(response, dict)
    assert response['count'] == 1
    assert response['offset'] == 0


# Mock function for observable


def lookup_obs_mock_response(*args, **kwargs):
    return_value = {
        "count": 1,
        "data": [
            {
                "created_at": "2022-08-24T10:02:04.609448+00:00",
                "entities": [
                    "https://example//entities/7fda61ec-852e"
                ],
                "id": 7938475,
                "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
                "meta": {
                    "maliciousness": "safe"
                },
                "sources": [
                    "https://example//sources/9a479225-37d1"
                ],
                "type": "ipv4",
                "value": "001.001.001.001"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    }
    return return_value


# Test cases for lookup_obs

def test_lookup_obs(mocker):
    """Test for lookup_obs."""
    mocker.patch(
        "EclecticIQv2.Client._http_request", lookup_obs_mock_response)
    client = Client(Base_url, api_key, proxy)
    response = client.lookup_obs(type_eiq="ipv4", value="001.001.001.001")
    assert isinstance(response, dict)
    assert response['limit'] == 100
    assert response['count'] == 1


# Mock function forsighting


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
        "EclecticIQv2.Client._http_request",
        sighting_mock_response
    )
    client = Client(Base_url, api_key, proxy)
    response = client.sighting(value="001.001.001.001", description="test_desc", title="title1",
                               tags="XSOAR Alert", type_eiq="ipv4", confidence_level="medium")
    assert isinstance(response, dict)
    # print(response)
    assert response['data']['data']['confidence'] == 'medium'
    assert response['data']['data']['description'] == 'test_desc'
    assert response['data']['data']['type'] == ' EclecticIQ-sighting'
    assert response["data"]["meta"]["tags"] == ['XSOAR Alert']
    assert response["data"]["data"]["security_control"]["type"] == 'information-source'
    assert response["data"]["data"]["timestamp"] == '2022-03-10T05:37:42Z'
# Mock function for fetch_entity


def fetch_entity_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "attachments": [],
            "created_at": "2022-11-08T04:22:45.250875+00:00",
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "id": "{https://example.com} EclecticIQ-sighting-fe5e61a4-5f1c-11ed-8eb2-067b5e23fb5e",
                "timestamp": "2022-03-10T05:37:42+00:00",
                "title": "title1"
            },
            "datasets": [],
            "id": "2a06537f-8a3b-4228-96d8-afd7ceefd38a",
            "incoming_feed": "null",
            "last_updated_at": "2022-11-08T04:22:44.924888+00:00",
            "meta": {
                "attacks": [],
                "estimated_observed_time": "2022-11-08T04:22:45.250875+00:00",
                "estimated_threat_end_time": "null",
                "estimated_threat_start_time": "2022-03-10T05:37:42+00:00",
                "half_life": 182,
                "source_reliability": "A",
                "tags": [
                    "XSOAR Alert"
                ],
                "taxonomies": [],
                "tlp_color": "null"
            },
            "observables": {
                "data": {
                    "maliciousness": "medium",
                    "type": "ipv4",
                    "value": "001.001.001.001"
                }},
            "outgoing_feeds": [],
            "relevancy": 0.39634678110477484,
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": " EclecticIQ-sighting"
        }
    }
    return return_value


# Test cases for fetch_entity

def test_fetch_entity(mocker):
    """Test for fetch_entity."""
    mocker.patch(
        "EclecticIQv2.Client._http_request",
        fetch_entity_mock_response
    )
    client = Client(Base_url, api_key, proxy)
    response = client.fetch_entity(id="2a06537f-8a3b-4228-96d8-afd7ceefd38a")
    assert isinstance(response, dict)
    assert response['data']['data']['confidence'] == 'medium'
    assert response['data']['data']['title'] == 'title1'
    assert response['data']['data']['timestamp'] == "2022-03-10T05:37:42+00:00"


# Mock function for get_platform_permission_ids


def get_platform_permission_ids_mock_response(*args, **kwargs):
    return_value = [33, 59, 66, 78]
    return return_value


# Test cases for get_platform_permission_ids

def test_get_platform_permission_ids(mocker):
    """Test for get_platform_permission_ids."""
    mocker.patch(
        "EclecticIQv2.get_platform_permission_ids",
        get_platform_permission_ids_mock_response
    )
    response = get_platform_permission_ids(permissions_data=[{'id': 33, 'name': 'modify entities'}, {
        'id': 66, 'name': 'read entities'}, {
        'id': 59, 'name': 'read outgoing-feeds'}, {'id': 78, 'name': 'read extracts'}])
    assert isinstance(response, list)
    assert response[0] == 33
    assert response[-1] == 78


# Mock function for authenticate_user_positive_response


def authenticate_user_mock_positive_response(*args, **kwargs):
    return_value = (False, ['6', '9', ' ', '8', '5', ',', '7'])
    return return_value


# Test cases for authenticate_user_positive_response

def test_authenticate_user_positive_response(mocker):
    """Test for authenticate_user."""
    mocker.patch("EclecticIQv2.authenticate_user", authenticate_user_mock_positive_response)
    response = authenticate_user(ids_of_user="[33]", ids_required_for_user="[33, 59, 66, 78]")
    assert isinstance(response, tuple)
# Mock function for authenticate_user_positive_response


def authenticate_user_mock_negative_response(*args, **kwargs):
    return_value = (True, [])
    return return_value


# Test cases for authenticate_user_negative_response
def test_authenticate_user_negative_response(mocker):
    """Test for authenticate_user."""
    mocker.patch("EclecticIQv2.authenticate_user", authenticate_user_mock_negative_response)
    response = authenticate_user(ids_of_user="[90]", ids_required_for_user="[9]")
    assert isinstance(response, tuple)

# Mock function for get_permission_name_from_id


def get_permission_name_from_id_mock_response(*args, **kwargs):
    return_value = ['modify entities', 'read entities', 'read outgoing-feeds', 'read extracts']
    return return_value


# Test cases for get_permission_name_from_id

def test_get_permission_name_from_id(mocker):
    """Test for get_permission_name_from_id."""
    mocker.patch(
        "EclecticIQv2.get_permission_name_from_id",
        get_permission_name_from_id_mock_response
    )
    response = get_permission_name_from_id(permission_data=({'id': 33, 'name': 'modify entities'}, {
        'id': 66, 'name': 'read entities'}, {
        'id': 59, 'name': 'read outgoing-feeds'}, {'id': 78, 'name': 'read extracts'}), permission_ids=[33, 59, 66, 78])
    assert isinstance(response, list)
    assert len(response) == 4


# Mock function for maliciousness_to_dbotscore


def maliciousness_to_dbotscore_mock_response(*args, **kwargs):
    return_value = 3
    return return_value


# Test cases for maliciousness_to_dbotscore

def test_maliciousness_to_dbotscore(mocker):
    """Test for maliciousness_to_dbotscore."""
    mocker.patch(
        "EclecticIQv2.maliciousness_to_dbotscore",
        maliciousness_to_dbotscore_mock_response
    )
    response = maliciousness_to_dbotscore(maliciousness="high")
    assert isinstance(response, int)
    assert response == 3

# Mock function for prepare_observable_data


def prepare_observable_data_mock_response(*args, **kwargs):
    return_value = {'new_data': {'type': 'ipv4', 'value': '001.001.001.001', 'classification': 'safe'}}
    return return_value


# Test cases for prepare_observable_data

def test_prepare_observable_data(mocker):
    """Test for prepare_observable_data."""
    mocker.patch(
        "EclecticIQv2.prepare_observable_data",
        prepare_observable_data_mock_response
    )
    response = prepare_observable_data(data={
        "data":
        {
            "created_at": "2022-08-24T10:02:04.609448+00:00",
            "entities": [
                "https://example//entities/7fda61ec-852e"
            ],
            "id": 7938475,
            "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
            "meta": {
                "maliciousness": "safe"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": "ipv4",
            "value": "001.001.001.001"
        }
    })
    assert isinstance(response, dict)


# Mock function for prepare_entity_data


def prepare_entity_data_mock_response(*args, **kwargs):
    return_value = {"new_data": {
        'title': 'title1',
        'description': 'testdesc',
        'confidence': 'medium',
        'tags': 'Alerts',
        'threat_start_time': '2022-03-10T05:37:42Z',
        'source_name': 'information-technology',
        'observables': {
                "created_at": "2022-08-24T10:20:09.083527+00:00",
                "entities": [
                    "https://example//entities/7fec8fc8-a174-4bb8-acc9-3b4e02b95a99"],
                "id": 7938476,
                "last_updated_at": "2022-08-24T10:20:08.996741+00:00",
                "meta": {
                    "maliciousness": "safe"
                },
            "sources": [
                    "https://example//sources/9a479225-37d1"],
            "type": "ipv4",
            "value": "001.001.001.001"}}}
    return return_value


# Test cases for  prepare_entity_data

def test_prepare_entity_data(mocker):
    """Test for  prepare_entity_data."""
    mocker.patch("EclecticIQv2.prepare_entity_data", prepare_entity_data_mock_response)
    response = prepare_entity_data(data={
        "data": {
            "confidence": "medium",
            "description": " EclecticIQ",
            "title": "testcase",
            "tags": "XSOAR Alert",
            "producer": {
                "identity": "information-technology"}},
        "meta": {
            "estimated_threat_start_time": "2022-03-10T05:37:42+00:00",
            "source_reliability": "A",
            "tlp_color": "null"
        },
        "observables": [],
        "outgoing_feeds": [],
        "relevancy": 0.39634678110477484}, obs_data={
        "created_at": "2022-11-09T04:25:49.960811+00:00",
        "entities": [
            "https://example//entities/2fa938f2-d1a5-4033-8b3c-8261794c8242"
        ],
        "data": {
            "id": 8936495,
            "last_updated_at": "2022-11-09T04:25:49.800562+00:00",
            "meta": {
                "maliciousness": "medium"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ]},
        "observables": {
            "data": {
                "maliciousness": "medium",
                "type": "ipv4",
                "value": "001.001.001.001"
            }}})
    assert isinstance(response, dict)

# Test cases for  prepare_entity_data_scenario


def test_prepare_entity_data_scenario(mocker):
    """Test for  prepare_entity_data."""
    mocker.patch("EclecticIQv2.prepare_entity_data", prepare_entity_data_mock_response)
    response = prepare_entity_data(data={
        "data": {
            "severity": "medium"},
        "meta": {
            "source_reliability": "A",
            "tlp_color": "null"
        },
        "observables": [],
        "outgoing_feeds": [],
        "relevancy": 0.39634678110477484}, obs_data={
        "created_at": "2022-11-09T04:25:49.960811+00:00",
        "entities": [
            "https://example//entities/2fa938f2-d1a5-4033-8b3c-8261794c8242"
        ],
        "data": {
            "id": 8936495,
            "last_updated_at": "2022-11-09T04:25:49.800562+00:00",
            "meta": {
                "maliciousness": "medium"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ]},
        "observables": {
            "data": {
                "maliciousness": "medium",
                "type": "ipv4",
                "value": "001.001.001.001"
            }}})
    assert isinstance(response, dict)
# Mock function for validate_type


def validate_type_mock_response(*args, **kwargs):
    return_value = True
    return return_value


# Test cases for validate_type

def test_validate_type(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="hash-sha512", value="3b7fc7cc370707c1df045c35342f3d64ea7076abd84f8a8c046a7cca2b85901|\
        689f3cf4bdc1f5fc232a60456cb9d2f48702bf8f8f1064f9bcc7d70edad9f860e")
    assert isinstance(response, bool)
# Test cases for validate_type scenario-1


def test_validate_scenario_1(mocker):
    """Test for validate_type."""
    mocker.patch(
        "EclecticIQv2.validate_type",
        validate_type_mock_response
    )
    response = validate_type(
        s_type="hash-sha1",
        value="2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
    assert isinstance(response, bool)
# Test case for validate_type scenario-2


def test_validate_scenario_2(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="hash-sha256", value="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert isinstance(response, bool)
# Test case for validate_type scenario-3


def test_validate_scenario_3(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="hash-md5", value="e5dadf6524624f79c3127e247f04b541")
    assert isinstance(response, bool)
# Test case for validate_type scenario -4


def test_validate_scenario_4(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="domain", value="abcd1.com")
    assert isinstance(response, bool)
# Test case for validate_type scenario -5


def test_validate_scenario_5(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="uri", value="https://examples.com")
    assert isinstance(response, bool)
# Test case for validate_type scenario -6


def test_validate_scenario_6(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="email", value="example@example.com")
    assert isinstance(response, bool)
# Test case for validate_type scenario -7


def test_validate_scenario_7(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_type_mock_response)
    response = validate_type(s_type="ipv6", value=" 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert isinstance(response, bool)
# mock response for validation function


def validate_mock_response(*args, **kwargs):
    return_value = False
    return return_value
# Test case for validate_type scenario -8


def test_validate_scenario_8(mocker):
    """Test for validate_type."""
    mocker.patch("EclecticIQv2.validate_type", validate_mock_response)
    response = validate_type(s_type="file", value="2001:0000:0000:FEFB")
    assert isinstance(response, bool)


# # Test case for data_ingestion
def test_data_ingestion(mocker):
    """Test case for data_ingestion"""
    mocker.patch("EclecticIQv2.Client.get_user_granted_permissions", user_permissions_mock_response)
    mocker.patch("EclecticIQv2.Client.get_platform_permissions", get_platform_permissions_mock_response)
    mocker.patch("EclecticIQv2.get_platform_permission_ids", get_platform_permission_ids_mock_response)
    mocker.patch("EclecticIQv2.authenticate_user", authenticate_user_mock_positive_response)
    mocker.patch("EclecticIQv2.get_permission_name_from_id", get_permission_name_from_id_mock_response)
    client = Client(Base_url, api_key, proxy)
    result = data_ingestion(client)
    assert isinstance(result, str)
# mock response for user pemissions


def user_permissions_mock_response(*args, **kwargs):
    return_value = ['https://example//permissions/1',
                    'https://example//permissions/2',
                    'https://example//permissions/3']
    return return_value
# Test case for data ingestion scenario


def test_data_ingestion_scenario(mocker):
    """Test case for data_ingestion"""
    mocker.patch("EclecticIQv2.Client.get_user_granted_permissions", user_permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    with pytest.raises(Exception)as e_info:
        data_ingestion(client)
        assert e_info == "API Key does not have access to view permissions."
# Mock function for platform permissions


def platform_mock_response(*args, **kwargs):
    return_value = ['https://example//permissions/1',
                    'https://example//permissions/2']
    return return_value
# Test cases for data ingestion scenario-1


def test_data_ingestion_scenario_1(mocker):
    """Test case for data_ingestion"""
    mocker.patch("EclecticIQv2.Client.get_user_granted_permissions", user_permissions_mock_response)
    client = Client(Base_url, api_key, proxy)
    result = data_ingestion(client)
    assert isinstance(result, str)
# Mock function for get_entity_data


def get_entity_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "attachments": [],
            "created_at": "2022-11-04T05:13:40.120477+00:00",
            "data": {
                "confidence": "medium",
                "description": "sighting",
                "id": "{https://example.com} EclecticIQ-sighting-71b48da2-5bff-11ed-ac3f-067b5e23fb5e",
                "timestamp": "2022-11-04T05:13:39+00:00",
                "title": "EIQ"
            },
            "datasets": [],
            "id": "13b9d24c-4c38-4c41-9de8-8c2a78b4850b",
            "incoming_feed": "null",
            "last_updated_at": "2022-11-04T05:13:40.064917+00:00",
            "meta": {
                "attacks": [],
                "estimated_observed_time": "2022-11-04T05:13:40.120477+00:00",
                "estimated_threat_end_time": "null",
                "estimated_threat_start_time": "2022-11-04T05:13:39+00:00",
                "half_life": 182,
                "source_reliability": "A",
                "tags": [
                    "alerts"
                ],
                "taxonomies": [],
                "tlp_color": "null"
            },
            "observables": [
                "https://example//observables/8625571"
            ],
            "outgoing_feeds": [],
            "relevancy": 0.9774081009139535,
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": " EclecticIQ-sighting"
        }
    }
    return return_value
# # Test cases for get_entity_data


def test_get_entity_data(mocker):
    """Test for get_entity_data."""
    mocker.patch("EclecticIQv2.Client.fetch_entity", fetch_entity_mock_response)
    mocker.patch("EclecticIQv2.Client.get_observable_by_id", get_observable_by_id_mock_response)
    mocker.patch("EclecticIQv2.prepare_observable_data", prepare_observable_data_mock_response)
    mocker.patch("EclecticIQv2.prepare_entity_data", prepare_entity_data_mock_response)
    client = Client("https://example/", api_key, proxy)
    response = get_entity_data(client, data_item={
        "created_at": "2022-11-09T04:25:49.960811+00:00",
        "entities": [
            "https://example//entities/2fa938f2-d1a5-4033-8b3c-8261794c8242"
        ],
        "data": {
            "id": 8936495,
            "last_updated_at": "2022-11-09T04:25:49.800562+00:00",
            "meta": {
                "maliciousness": "medium"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ]},
        "observables": {
            "data": {
                "maliciousness": "medium",
                "type": "ipv4",
                "value": "001.001.001.001"
            }}})
    assert isinstance(response, list)

# Test cases for lookup observables


def test_EclecticIQ_lookup_observables(mocker):
    """Test for lookup observables function."""
    mocker.patch("EclecticIQv2.Client.lookup_obs", lookup_obs_mock_response)
    mocker.patch("EclecticIQv2.Client.fetch_entity", fetch_entity_mock_response)
    mocker.patch("EclecticIQv2.get_entity_data", get_entity_mock_response)
    mocker.patch("EclecticIQv2.maliciousness_to_dbotscore", maliciousness_to_dbotscore_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "001.001.001.001"}
    result = EclecticIQ_lookup_observables(client, args)
    assert result.outputs_prefix == 'EclecticIQ'
    assert result.outputs_key_field == 'value'


# Test cases for lookup observables scenario


def test_EclecticIQ_lookup_observables_scenario(mocker):
    """Test for lookup observables function."""
    mocker.patch("EclecticIQv2.Client.lookup_obs", lookup_obs_mock_response)
    mocker.patch("EclecticIQv2.Client.fetch_entity", fetch_entity_mock_response)
    mocker.patch("EclecticIQv2.maliciousness_to_dbotscore", maliciousness_to_dbotscore_mock_response)
    mocker.patch("EclecticIQv2.get_entity_data", get_entity_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "24.161"}
    with pytest.raises(ValueError) as e_info:
        EclecticIQ_lookup_observables(client, args)
        assert e_info == "Type does not match specified value"

# mock response for lookup_observables


def EclecticIQ_lookup_observables_scenario_mock_response(*args, **kwargs):
    return_value = {"count": 0, "data": [], "limit": 100, "offset": 0, "total_count": 0}
    return return_value
# Test cases for lookup observables scenario-1


def test_EclecticIQ_lookup_observables_scenario_1(mocker):
    """Test for EclecticIQ lookup observables function."""
    mocker.patch("EclecticIQv2.Client.lookup_obs", EclecticIQ_lookup_observables_scenario_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "001.001.001.001"}
    result = EclecticIQ_lookup_observables(client, args)
    assert result.readable_output == "No observable data found."
# Test cases for create sighting


def test_EclecticIQ_create_sighting(mocker):
    """Test for EclecticIQ create sighting function."""
    mocker.patch("EclecticIQv2.Client.sighting", sighting_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "001.001.001.001", "title": "EIQ", "tags": "cortex alert",
            "description": "sighting", "confidence_level": "medium"}
    result = EclecticIQ_create_sighting(client, args)
    assert result.outputs_prefix == 'Sighting'
    assert result.outputs_key_field == 'value'

# Test cases for create sighting scenario


def test_EclecticIQ_create_sighting_scenario(mocker):
    """Test for EclecticIQ create sighting function."""
    mocker.patch("EclecticIQv2.Client.sighting", sighting_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "1124.161", "title": "EIQ", "tags": "cortex alert",
            "description": "sighting", "confidence_level": "medium"}
    with pytest.raises(ValueError) as e_info:
        EclecticIQ_create_sighting(client, args)
        assert e_info == "Type does not match specified value"


# Test cases for lookup observables


def test_EclecticIQ_create_observable(mocker):
    """Test for create observable function."""
    mocker.patch("EclecticIQv2.Client.observable", observable_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "001.001.001.001", "maliciousness": "safe"}
    result = EclecticIQ_create_observable(client, args)
    assert result.outputs_prefix == 'Observables'
    assert result.outputs_key_field == 'value'

# Test cases for create observable scenario


def test_EclecticIQ_create_observable_scenario(mocker):
    """Test for create observable function."""
    mocker.patch("EclecticIQv2.Client.observable", observable_mock_response)
    client = Client(Base_url, api_key, proxy)
    args = {"type": "ipv4", "value": "2175.161", "maliciousness": "safe"}
    with pytest.raises(ValueError) as e_info:
        EclecticIQ_create_observable(client, args)
        assert e_info == "Type does not match specified value"
# Test cases for main function


def test_main(mocker):
    """Test case for main function"""
    mocker.patch.object(
        demisto, 'params', return_value={
            'url': Base_url,
            'apikey': {'password': api_key},
        }
    )
    mocker.patch('EclecticIQv2.EclecticIQ_lookup_observables', return_value={'name': 'test'})
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_sighting')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_observable')
    mocker.patch.object(
        demisto, 'command',
        return_value='test-module'
    )
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
# # Test cases for main scenario


def test_main_scenario(mocker):
    """Test case for main function"""
    mocker.patch.object(
        demisto, 'params', return_value={
            'url': Base_url,
            'apikey': {'password': api_key},
            'verify_certificate': verify,
            'proxy': proxy
        }
    )
    mocker.patch('EclecticIQv2.data_ingestion', return_value="ok")
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_sighting')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_observable')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_lookup_observables')
    mocker.patch('EclecticIQv2.Client.lookup_obs', return_value={
        "count": 1,
        "data": [
            {
                "created_at": "2022-08-24T10:02:04.609448+00:00",
                "entities": [
                    "https://example//entities/7fda61ec-852e"
                ],
                "id": 7938475,
                "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
                "meta": {
                    "maliciousness": "safe"
                },
                "sources": [
                    "https://example//sources/9a479225-37d1"
                ],
                "type": "ipv4",
                "value": "001.001.001.001"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    }, autospec=True)
    mocker.patch("EclecticIQv2.Client.fetch_entity", return_value={
        "data": {
            "attachments": [],
            "created_at": "2022-11-08T04:22:45.250875+00:00",
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "id": "{https://example.com} EclecticIQv2  -sighting-fe5e61a4-5f1c-11ed-8eb2-067b5e23fb5e",
                "timestamp": "2022-03-10T05:37:42+00:00",
                "title": "title1"
            },
            "datasets": [],
            "id": "2a06537f-8a3b-4228-96d8-afd7ceefd38a",
            "incoming_feed": "null",
            "last_updated_at": "2022-11-08T04:22:44.924888+00:00",
            "meta": {
                "attacks": [],
                "estimated_observed_time": "2022-11-08T04:22:45.250875+00:00",
                "estimated_threat_end_time": "null",
                "estimated_threat_start_time": "2022-03-10T05:37:42+00:00",
                "half_life": 182,
                "source_reliability": "A",
                "tags": [
                    "XSOAR Alert"
                ],
                "taxonomies": [],
                "tlp_color": "null"
            },
            "observables": {
                "data": {
                    "maliciousness": "medium",
                    "type": "ipv4",
                    "value": "001.001.001.001"
                }},
            "outgoing_feeds": [],
            "relevancy": 0.39634678110477484,
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": "EclecticIQ-sighting"
        }
    })
    mocker.patch("EclecticIQv2.Client.get_observable_by_id", return_value={
        "data": {
            "created_at": "2022-08-24T10:02:04.609448+00:00",
            "entities": [
                "https://example//entities/7fda61ec-852e"
            ],
            "id": 7938475,
            "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
            "meta": {
                "maliciousness": "unknown"
            },
            "sources": [
                "https://example//sources/9a479225-37d1"
            ],
            "type": "ipv4",
            "value": "001.001.001.001"
        }
    })
    mocker.patch.object(demisto, 'args', return_value={"type": "ipv4", "value": "001.001.001.001"})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
# Test cases for main scenario-1


def test_main_scenario_1(mocker):
    """Test case for main function"""
    mocker.patch.object(
        demisto, 'params', return_value={
            'url': Base_url,
            'apikey': {'password': api_key},
            'verify_certificate': verify,
            'proxy': proxy
        }
    )
    mocker.patch('EclecticIQv2.data_ingestion', return_value="test")
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_lookup_observables')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_observable')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_sighting')
    mocker.patch('EclecticIQv2.Client.sighting', return_value={
        "data": {
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "type": "EclecticIQ-sighting",
                        "timestamp": "2022-03-10T05:37:42Z",
                        "title": "title1",
                        "security_control": {
                            "type": "information-source",
                            "identity": {
                                "name": "EclecticIQ Platform App for cortex XSOAR",
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
    })
    mocker.patch.object(demisto, 'args', return_value={"type": "ipv4", "value": "001.001.001.001", "title": "EIQ",
                                                       "tags": "cortex alert", "description": "sighting",
                                                       "confidence_level": "medium"})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
# # # Test cases for main scenario-2


def test_main_scenario_2(mocker):
    """Test case for main function"""
    mocker.patch.object(
        demisto, 'params', return_value={
            'url': Base_url,
            'apikey': {'password': api_key},
            'verify_certificate': verify,
            'proxy': proxy
        }
    )
    mocker.patch('EclecticIQv2.data_ingestion', return_value="test")
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_lookup_observables')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_sighting')
    mocker.patch.object(demisto, 'command', return_value='EclecticIQ_create_observable')
    mocker.patch('EclecticIQv2.Client.observable', return_value={
        "count": 1,
        "data": [
            {
                "created_at": "2022-08-24T10:02:04.609448+00:00",
                "entities": [
                    "https://example//entities/7fda61ec-852e"
                ],
                "id": 7938475,
                "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
                "meta": {
                    "maliciousness": "safe"
                },
                "sources": [
                    "https://example//sources/9a479225-37d1"
                ],
                "type": "ipv4",
                "value": "001.001.001.001"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    })
    mocker.patch.object(demisto, 'args', return_value={"type": "ipv4", "value": "001.001.001.001", "maliciousness": "safe"})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1

# # Test case for scenario_3


def test_main_scenario_3(mocker):
    """Test cases for main function."""
    mocker.patch.object(
        demisto, 'params', return_value={
            'url': Base_url,
            'apikey': {'password': api_key},
            'verify_certificate': verify,
            'proxy': proxy
        }
    )
    mocker.patch.object(demisto, 'command', return_value='lookp obserble')
    mocker.patch.object(demisto, 'error', return_value='Failed to execute  command.\nError:\n command is not implemented.')
    with pytest.raises(SystemExit):
        main()
