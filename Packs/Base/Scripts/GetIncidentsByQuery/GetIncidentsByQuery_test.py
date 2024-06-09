import pytest
from CommonServerPython import DemistoException, EntryType
import demistomock as demisto
import GetIncidentsByQuery

import json
import pickle


def test_encode_outputs():
    """
    Given: Search incidents results
    When: Running encode_outputs():
    - once with "json" format
    - once with "pickle" format
    - once with unexpected format
    Then: Ensure the results are encoded correctly, or an error is raised in case of unexpected format
    """
    from GetIncidentsByQuery import encode_outputs
    incidents = [{"id": 1}]
    assert json.loads(encode_outputs(incidents, "json")) == incidents
    assert pickle.loads(encode_outputs(incidents, "pickle")) == incidents  # guardrails-disable-line
    with pytest.raises(DemistoException):
        encode_outputs(incidents, "oyvey")


def test_to_file_entry(mocker):
    """
    Given: Search incidents results
    When: Running to_file_entry() with "json" format
    Then: Ensure a file entry is returned in the expected format
    """
    incidents = [{"id": 1}]
    mocker.patch.object(demisto, "investigation", return_value={"id": "inv"})
    res = GetIncidentsByQuery.to_file_entry(incidents, "json")
    assert res["Type"] == EntryType.FILE
    assert res["EntryContext"]["GetIncidentsByQuery"]["FileFormat"] == "json"
    assert res["Contents"] == incidents


def test_get_incidents_by_query_sanity_test(mocker):
    """
    Given: Search incidents query arguments
    When: Running main()
    Then: Ensure the expected incident is returned
    """
    mocker.patch.object(demisto, "args", return_value={"query": "oyvey", "outputFormat": "json"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": [{"id": 1}]}, "Type": "json"}])
    demisto_results = mocker.patch.object(demisto, "results")
    GetIncidentsByQuery.main()
    incidents = demisto_results.call_args[0][0]["Contents"]
    assert len(incidents) == 1
    assert incidents[0]["id"] == 1


def test_get_incidents_by_query_bad_inputs(mocker):
    """
    Given: Search incidents with no query arguments
    When: Running main()
    Then: Ensure an error entry is returned
    """
    return_error = mocker.patch.object(GetIncidentsByQuery, "return_error")
    GetIncidentsByQuery.main()
    assert "Incidents query is empty" in return_error.call_args[0][0]
