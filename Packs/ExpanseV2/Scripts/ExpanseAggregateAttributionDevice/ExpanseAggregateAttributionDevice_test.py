import demistomock as demisto  # noqa

import ExpanseAggregateAttributionDevice


INPUT = [
    {"serial_number": "serialA", "count": 2, "src": "1.1.1.1"},
    {"serial": "serialB", "src": "8.8.8.8", "vsys": "vsys1"},
    {"log_source_id": "serialB", "src_ip": "10.0.0.1", "vsys": "vsys1", "count": 5},
    {"serial_number": "serialA", "src": "192.168.1.1", "vsys": "vsys1", "count": 5},
    {"log_source_id": "serialC", "src": "195.103.76.33", "count": 5},
]

CURRENT = [
    {
        'serial': "serialA",
        'vsys': "",
        'sightings': 1,
        'exposing_service': False,
        'device-group': None,
        'expanse-tag': None,
    }
]

RESULT = [
    {
        'serial': "serialA",
        'vsys': "",
        'sightings': 3,
        'exposing_service': True,
        'device-group': None,
        'expanse-tag': None,
    },
    {
        'serial': "serialB",
        'vsys': "vsys1",
        'sightings': 6,
        'exposing_service': False,
        'device-group': None,
        'expanse-tag': None,
    },
    {
        'serial': "serialA",
        'vsys': "vsys1",
        'sightings': 5,
        'exposing_service': False,
        'device-group': None,
        'expanse-tag': None,
    },
    {
        'serial': "serialC",
        'vsys': "",
        'sightings': 5,
        'exposing_service': True,
        'device-group': None,
        'expanse-tag': None,
    }
]


def test_aggregate_command():
    """
    Given:
        - previous list aggregated devices
        - new data source with device/sightings information
        - merged aggregated data with new information
        - list of internal ip networks
    When
        - merging new sightings to existing aggregated data
    Then
        - data is merged
        - expected output is returned
    """
    result = ExpanseAggregateAttributionDevice.aggregate_command({
        'input': INPUT,
        'current': CURRENT,
        'internal_ip_networks': "192.168.0.0/16,10.0.0.0/8,8.0.0.0/8"
    })

    assert result.outputs_prefix == "Expanse.AttributionDevice"
    assert result.outputs_key_field == ["serial", "vsys"]
    assert result.outputs == RESULT
