import demistomock as demisto  # noqa

import ExpanseAggregateAttributionIP


INPUT = [
    {"src": "1.1.1.1", "count": 2},
    {"src_ip": "8.8.8.8"},
    {"src": "8.8.8.8", "count": 10}
]

CURRENT = [
    {"ip": "1.1.1.1", "sightings": 1, "internal": False}
]

RESULT = [
    {"ip": "1.1.1.1", "sightings": 3, "internal": False},
    {"ip": "8.8.8.8", "sightings": 11, "internal": True}
]


def test_aggregate_command():
    result = ExpanseAggregateAttributionIP.aggregate_command({
        'input': INPUT,
        'current': CURRENT,
        'internal_ip_networks': "192.168.0.0/16,10.0.0.0/8,8.0.0.0/8"
    })

    assert result.outputs_prefix == "Expanse.AttributionIP"
    assert result.outputs_key_field == "ip"
    assert result.outputs == RESULT
