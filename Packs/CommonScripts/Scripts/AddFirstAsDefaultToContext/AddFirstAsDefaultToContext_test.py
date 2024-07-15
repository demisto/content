from AddFirstAsDefaultToContext import get_incidenttype
import pytest
import demistomock as demisto
from CommonServerPython import *


ARGS_GET_INCIDENTTYPE = [
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


@pytest.mark.parametrize('incident_type_name, mock_response, expected', ARGS_GET_INCIDENTTYPE)
def test_get_incidenttype(incident_type_name, mock_response, expected, mocker):
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



# # Test cases for get_fieldname_and_default_val
# ARGS_GET_FIELDNAME_AND_DEFAULT_VAL = [
#     (
#         [{"cliName": "field1", "selectValues": ["value1", "value2"]}, {"cliName": "field2", "selectValues": ["value3"]}],
#         {"field1": "value1", "field2": "value3"}
#     ),
#     (
#         [{"cliName": "field3", "selectValues": []}, {"cliName": "field4"}],
#         {}
#     )
# ]

# @pytest.mark.parametrize('fields, expected', ARGS_GET_FIELDNAME_AND_DEFAULT_VAL)
# def test_get_fieldname_and_default_val(fields, expected):
#     """
#     Given:
#         - Fields with select values.
#     When:
#         - get_fieldname_and_default_val function is executed.
#     Then:
#         - Return dictionary with field names and their first select value.
#     """
#     assert get_fieldname_and_default_val(fields) == expected





# # Test cases for update_context
# ARGS_UPDATE_CONTEXT = [
#     (
#         {"field1": "value1", "field2": "value2"},
#         {"field3": "value3"},
#         {"field1": "value1", "field2": "value2"}
#     ),
#     (
#         {"field4": "value4"},
#         {"field4": "value4"},
#         {}
#     )
# ]

# @pytest.mark.parametrize('fields, context, expected_outputs', ARGS_UPDATE_CONTEXT)
# def test_update_context(fields, context, expected_outputs, mocker):
#     """
#     Given:
#         - Fields and context.
#     When:
#         - update_context function is executed.
#     Then:
#         - It should update the context with the correct default values for single select fields.
#     """
#     mocker.patch('demistomock.executeCommand')
#     update_context(fields, context)
#     demisto.executeCommand.assert_called_once_with("setIncident", expected_outputs)


# # Test cases for common_strings
# ARGS_COMMON_STRINGS = [
#     (
#         ["field1", "field2"],
#         [{"cliName": "field1", "value": "value1"}, {"cliName": "field3", "value": "value3"}, {"cliName": "field2", "value": "value2"}],
#         [{"cliName": "field1", "value": "value1"}, {"cliName": "field2", "value": "value2"}]
#     ),
#     (
#         ["field5"],
#         [{"cliName": "field1", "value": "value1"}, {"cliName": "field3", "value": "value3"}],
#         []
#     )
# ]

# @pytest.mark.parametrize('list1, list2, expected', ARGS_COMMON_STRINGS)
# def test_common_strings(list1, list2, expected):
#     """
#     Given:
#         - Two lists of strings.
#     When:
#         - common_strings function is executed.
#     Then:
#         - Return list of common strings in dictionary format.
#     """
#     assert common_strings(list1, list2) == expected


# # Test cases for get_incidentfields
# ARGS_GET_INCIDENTFIELDS = [
#     (
#         "singleSelect",
#         ["field1", "field3", "field4"],
#         {"Contents": {"response": [{"type": "singleSelect", "cliName": "field1"}, {"type": "multiSelect", "cliName": "field2"}, {"type": "singleSelect", "cliName": "field3"}]}},
#         [{"type": "singleSelect", "cliName": "field1"}, {"type": "singleSelect", "cliName": "field3"}]
#     )
# ]

# @pytest.mark.parametrize('type_name, name_fields, mock_response, expected', ARGS_GET_INCIDENTFIELDS)
# def test_get_incidentfields(type_name, name_fields, mock_response, expected, mocker):
#     """
#     Given:
#         - Type name and field names.
#     When:
#         - get_incidentfields function is executed.
#     Then:
#         - Return list of incident fields matching the type and names.
#     """
#     mocker.patch('demistomock.executeCommand', return_value=[mock_response])
#     assert get_incidentfields(type_name, name_fields) == expected


# # Test cases for main function
# ARGS_MAIN = [
#     (
#         {"type": "type1"},
#         {"Contents": {"response": [{"id": "type1", "layout": "layout1"}]}},
#         {"Contents": {"response": [{"type": "singleSelect", "cliName": "field1", "selectValues": ["value1"]}]}}
#     )
# ]

# @pytest.mark.parametrize('incident, incidenttype_response, incidentfields_response', ARGS_MAIN)
# def test_main(incident, incidenttype_response, incidentfields_response, mocker):
#     """
#     Given:
#         - Incident type and corresponding API responses.
#     When:
#         - The main function is executed.
#     Then:
#         - It should update the context with the correct default values for single select fields.
#     """
#     mocker.patch.object(demisto, "incident", return_value=incident)
#     mocker.patch('demistomock.executeCommand', side_effect=[
#         incidenttype_response,
#         incidentfields_response,
#         {}
#     ])
#     mock_return_results = mocker.patch('AddFirstAsDefaultToContext.return_results')
#     mock_return_error = mocker.patch('AddFirstAsDefaultToContext.return_error')

#     main()

#     # Expected output after running main function
#     expected_outputs = {'field1': 'value1'}
#     mock_return_results.assert_called_once_with(None)  # Since update_context does not return a value
#     demisto.executeCommand.assert_called_with("setIncident", expected_outputs)
#     mock_return_error.assert_not_called()

# if __name__ == "__main__":
#     pytest.main()
