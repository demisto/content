import demistomock as demisto  # noqa

import ExpanseAggregateAttributionCI


INPUT = [
    {
        "Attributes": {
            "name": "server 1",
            "sys_id": "1234",
            "sys_class_name": "cmdb_ci",
            "asset": {
                "display_value": "server 1",
                "link": "https://servicenow.com/5678",
                "value": "5678"
            }
        }
    }
]

CURRENT = []

RESULT = [
    {
        "name": "server 1",
        "sys_id": "1234",
        "sys_class_name": "cmdb_ci",
        "asset_display_value": "server 1",
        "asset_link": "https://servicenow.com/5678",
        "asset_value": "5678"
    }
]


def test_aggregate_command():
    """
    Given:
        - previous list aggregated IPs
        - new data source with IP/sightings information
        - merged aggregated data with new information
        - list of internal ip networks
    When
        - merging new sightings to existing aggregated data
    Then
        - data is merged
        - expected output is returned
    """
    result = ExpanseAggregateAttributionCI.aggregate_command({
        'input': INPUT,
        'current': CURRENT,
    })

    assert result.outputs_prefix == "Expanse.AttributionCI"
    assert result.outputs_key_field == ["sys_id"]
    assert result.outputs == RESULT
