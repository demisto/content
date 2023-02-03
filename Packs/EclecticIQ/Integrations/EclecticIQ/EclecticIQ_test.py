from EclecticIQ import (
    Client,
    lookup_observables,
    create_sighting,
    create_observable
)

# Provide valid API KEY
api_key = "test_api_key"
proxy = "false"

# Mock function for lookup observable


def lookup_observables_mock_response(*args, **kwargs):
    return_value = {
        "count": 1,
        "data": [
            {
                "created_at": "2022-08-24T10:02:04.609448+00:00",
                "entities": [
                    "https://ic-playground.eclecticiq.com/api/v1/entities/7fda61ec-852e-4065-a421-cad8c08ad40e"
                ],
                "id": 7938475,
                "last_updated_at": "2022-08-24T10:02:04.531505+00:00",
                "meta": {
                    "maliciousness": "unknown"
                },
                "sources": [
                    "https://ic-playground.eclecticiq.com/api/v1/sources/9a479225-37d1-4dae-9554-172eeccea193"
                ],
                "type": "ipv4",
                "value": "172.175.124.161"
            }
        ],
        "limit": 100,
        "offset": 0,
        "total_count": 1
    }
    return return_value

# Test cases for lookup observables


def test_lookup_observables(mocker):
    """Test for lookup observables function."""
    mocker.patch(
        "EclecticIQ.Client.lookup_obs",
        lookup_observables_mock_response)
    mocker.patch(
        "EclecticIQ.Client.fetch_entity",
        lookup_observables_mock_response)
    mocker.patch(
        "EclecticIQ.get_entity_data",
        lookup_observables_mock_response)
    client = Client(
        "https://ic-playground.eclecticiq.com/api/v1", api_key, proxy)
    args = {
        "type": "ipv4",
        "value": "172.175.124.161"
    }
    result = lookup_observables(client, args)
    assert result.outputs_prefix == 'EclecticIQ'
    assert result.outputs_key_field == 'value'

# Mock function for create sighting


def create_sighting_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "data": {
                "confidence": "medium",
                "description": "test_desc",
                "type": "eclecticiq-sighting",
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
    }
    return return_value

# Test cases for create sighting


def test_create_sighting(mocker):
    """Test for create sighting function."""
    mocker.patch(
        "EclecticIQ.Client.sighting",
        create_sighting_mock_response)
    client = Client(
        "https://ic-playground.eclecticiq.com/api/v1", api_key, proxy)
    args = {
        "type": "ipv4",
        "value": "172.175.124.161",
        "title": "EIQ",
        "tags": "cortex alert",
        "description": "sighting",
        "confidence_level": "medium"
    }
    result = create_sighting(client, args)
    assert result.outputs_prefix == 'Sighting.Data'
    assert result.outputs_key_field == 'value'


# Mock function for create observable


def create_observable_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "created_at": "2022-08-24T10:20:09.083527+00:00",
            "entities": [
                "https://ic-playground.eclecticiq.com/api/v1/entities/7fec8fc8-a174-4bb8-acc9-3b4e02b95a99"
            ],
            "id": 7938476,
            "last_updated_at": "2022-08-24T10:20:08.996741+00:00",
            "meta": {
                "maliciousness": "safe"
            },
            "sources": [
                "https://ic-playground.eclecticiq.com/api/v1/sources/9a479225-37d1-4dae-9554-172eeccea193"
            ],
            "type": "ipv4",
            "value": "172.175.124.161"
        }
    }
    return return_value

# Test cases for lookup observables


def test_create_observable(mocker):
    """Test for create observable function."""
    mocker.patch(
        "EclecticIQ.Client.observable",
        create_observable_mock_response)
    client = Client(
        "https://ic-playground.eclecticiq.com/api/v1", api_key, proxy)
    args = {
        "type": "ipv4",
        "value": "172.175.124.161",
        "maliciousness": "safe"
    }
    result = create_observable(client, args)
    assert result.outputs_prefix == 'Observables.Data'
    assert result.outputs_key_field == 'value'
