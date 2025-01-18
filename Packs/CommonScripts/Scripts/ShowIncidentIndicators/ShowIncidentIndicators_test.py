import demistomock as demisto
from ShowIncidentIndicators import group_by_type, get_indicators_from_incident


def test_group_by_type():
    indicators = [{'Contents': [{"indicator_type": "IP", "value": "1.1.1.1"},
                  {"indicator_type": "IP", "value": "2.2.2.2"},
                  {"indicator_type": "Domain", "value": "test.com"}]}]
    expected = ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- Domain ---", "test.com", ""]
    result = group_by_type(indicators)
    assert result == expected


def test_get_indicators_from_incident(mocker):
    execute_command_output = [{'Contents': [{"indicator_type": "IP", "value": "1.1.1.1"},
                              {"indicator_type": "IP", "value": "2.2.2.2"},
                              {"indicator_type": "Domain", "value": "test.com"}]}]
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_output)
    mocker.patch.object(demisto, 'incidents', return_value=[{"id": 123}])

    expected = {"hidden": False, "options": ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- Domain ---", "test.com", ""]}
    result = get_indicators_from_incident()
    assert result == expected
