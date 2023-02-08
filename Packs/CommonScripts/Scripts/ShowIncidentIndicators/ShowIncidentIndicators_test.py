import pytest
from ShowIncidentIndicators import group_by_type, get_indicators_from_incident


def test_group_by_type():
    indicators = [{"indicator_type": "IP", "value": "1.1.1.1"},
                  {"indicator_type": "IP", "value": "2.2.2.2"},
                  {"indicator_type": "Domain", "value": "test.com"}]
    expected = ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- Domain ---", "test.com", ""]
    result = group_by_type(indicators)
    assert result == expected


def test_get_indicators_from_incident():
    def mock_execute_command(command, args):
        return [{"indicator_type": "IP", "value": "1.1.1.1"},
                  {"indicator_type": "IP", "value": "2.2.2.2"},
                  {"indicator_type": "Domain", "value": "test.com"}]

    def mock_incident():
        return {"id": 123}

    demisto.execute_command = mock_execute_command
    demisto.incident = mock_incident

    expected = {"hidden": False, "options": ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- Domain ---", "test.com", ""]}
    result = get_indicators_from_incident()
    assert result == expected
