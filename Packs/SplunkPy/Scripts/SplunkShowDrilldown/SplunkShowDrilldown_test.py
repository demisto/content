import SplunkShowDrilldown
from pytest import raises


def test_incident_with_empty_custom_fields(mocker):
    """
    Given:
        incident without CustomFields
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {'CustomFields': {}}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown was not configured for notable.'


def test_incident_not_notabledrilldown(mocker):
    """
    Given:
        incident without notabledrilldown
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {'CustomFields': {"notabledrilldown": {}}}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown was not configured for notable.'


def test_incident_not_successful(mocker):
    """
    Given:
        incident with successfuldrilldownenrichment == false
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {'labels': [{'type': 'successful_drilldown_enrichment', 'value': 'false'}]}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown enrichment failed.'


def test_json_loads_fails(mocker):
    """
    Given:
        incident with CustomFields that can't be loaded by JSON
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {'labels': [{'type': 'Drilldown', 'value': {'not json'}}]}
    mocker.patch('demistomock.incident', return_value=incident)
    with raises(ValueError):
        SplunkShowDrilldown.main()
