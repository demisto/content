import SplunkShowDrilldown
from pytest import raises


def test_incident_with_empty_custom_fields(mocker):
    incident = {'CustomFields': {}}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown was not configured for notable.'


def test_incident_not_notabledrilldown(mocker):
    incident = {'CustomFields': {"notabledrilldown": {}}}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown was not configured for notable.'


def test_incident_not_successful(mocker):
    incident = {'CustomFields': {"notabledrilldown": {"name": "test"}, "successfuldrilldownenrichment": "false"}}
    mocker.patch('demistomock.incident', return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.readable_output == 'Drilldown enrichment failed.'


def test_json_loads_fails(mocker):
    incident = {'CustomFields': {"notabledrilldown": {"name"}, "successfuldrilldownenrichment": "true"}}
    mocker.patch('demistomock.incident', return_value=incident)
    with raises(ValueError):
        SplunkShowDrilldown.main()
