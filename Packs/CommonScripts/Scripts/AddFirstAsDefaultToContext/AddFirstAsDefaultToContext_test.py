from AddFirstAsDefaultToContext import get_incidenttype, get_incidentfields
import pytest
from CommonServerPython import *


@pytest.mark.parametrize(
    'incident_type_name, mock_response, expected',
    [
        (
            "type1",
            {"Contents": {"response": [{"id": "type1", "name": "Incident Type 1"}, {"id": "type2", "name": "Incident Type 2"}]}},
            {"id": "type1", "name": "Incident Type 1"}
        ),
        (
            "type3",
            {"Contents": {"response": [{"id": "type1", "name": "Incident Type 1"}, {"id": "type2", "name": "Incident Type 2"}]}},
            {}
        )
    ]
)
def test_get_incidenttype(mocker, incident_type_name, mock_response, expected):
    """
    Given:
        - Incident type name.
    When:
        - get_incidenttype function is executed.
    Then:
        - Return incident type details if found.
    """
    mocker.patch('demistomock.executeCommand', return_value=[mock_response])
    assert get_incidenttype(incident_type_name) == expected


@pytest.mark.parametrize(
    'type_name, name_fields, mock_response, expected',
    [
        (
            "singleSelect",
            ["field1", "field3", "field4"],
            {"Contents": {"response": [{"type": "singleSelect", "cliName": "field1"}, {
                "type": "multiSelect", "cliName": "field2"}, {"type": "singleSelect", "cliName": "field3"}]}},
            [{"type": "singleSelect", "cliName": "field1"}, {"type": "singleSelect", "cliName": "field3"}]
        )
    ]
)
def test_get_incidentfields(mocker, type_name, name_fields, mock_response, expected):
    """
    Given:
        - Type name and field names.
    When:
        - get_incidentfields function is executed.
    Then:
        - Return list of incident fields matching the type and names.
    """
    mocker.patch('demistomock.executeCommand', return_value=[mock_response])
    assert get_incidentfields(type_name, name_fields) == expected
