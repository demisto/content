import demistomock as demisto  # noqa

import ExpanseAggregateAttributionUser


INPUT = [
    {"user": "lmori", "count": 10},
    {"srcuser": "fvigo"},
    {"source_user": "DEVREL\\lmori"},
]

CURRENT = [
    {"username": "fvigo", "sightings": 1, "groups": [], "description": None, "domain": ""}
]

RESULT = [
    {"username": "fvigo", "sightings": 2, "groups": [], "description": None, "domain": ""},
    {"username": "lmori", "sightings": 10, "groups": [], "description": None, "domain": ""},
    {"username": "lmori", "sightings": 1, "groups": [], "description": None, "domain": "DEVREL"},
]


def test_aggregate_command():
    """
    Given:
        - previous list aggregated users
        - new data source with users/sightings information
        - merged aggregated data with new information
        - list of internal ip networks
    When
        - merging new sightings to existing aggregated data
    Then
        - data is merged
        - expected output is returned
    """
    result = ExpanseAggregateAttributionUser.aggregate_command({
        'input': INPUT,
        'current': CURRENT
    })

    assert result.outputs_prefix == "Expanse.AttributionUser"
    assert result.outputs_key_field == ["username", "domain"]
    assert result.outputs == RESULT
