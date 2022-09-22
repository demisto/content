"""
    Tests module for InfoArmor HideFieldsOnNewIncident script
"""
import demistomock as demisto
import pytest


@pytest.mark.parametrize('incident, mock_demisto_get, expected_results', [
    ({'id': ""}, {}, {'hidden': True, 'options': []}),
    ({'id': "test"}, {}, {'hidden': False, 'options': []}),
    ({'id': "test"}, {'Select': 'select_test'}, {'hidden': False, 'options': {'Select': 'select_test'}})
])
def test_hide_fields_on_new_incident(mocker, incident, mock_demisto_get, expected_results):
    """
        Given:
                - A dictionary represent an XSOAR incident, and a mock response for the 'demisto.get' function.
        When:
                - Running the 'hide_fields_on_new_incident' function.
        Then:
                - Verify that the demisto.results are as expected.
    """
    from HideFieldsOnNewIncident import hide_fields_on_new_incident

    field = 'test_field'

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'get', return_value=mock_demisto_get)
    hide_fields_on_new_incident(incident, field)
    results = demisto.results.call_args[0][0]

    assert results == expected_results
