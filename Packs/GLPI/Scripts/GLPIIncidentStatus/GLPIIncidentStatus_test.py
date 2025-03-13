"""GLPIIncidentStatus Script for Cortex XSOAR - Unit Tests file"""

from unittest.mock import Mock
import ast
import demistomock as demisto
from CommonServerPython import formats, entryTypes
from GLPIIncidentStatus import glpi_incident_status, glpi_incident_status_command


def util_load_mock(path):
    with open(path) as f:
        data = f.read()
    return ast.literal_eval(data)


def test_glpi_incident_status(mocker):
    mock_incident = util_load_mock("test_data/glpi_incidentstatus.mock")
    mocker.patch.object(demisto, "incidents", return_value=mock_incident)
    color, text = glpi_incident_status()
    assert color == "#7995D4"
    assert text == "Processing (assigned)"


def test_glpi_incident_status_command(mocker):
    mock_incident = util_load_mock("test_data/glpi_incidentstatus.mock")
    mock_result = Mock(
        Contents="<div style='color:#7995D4;text-align:center;'><h2>Processing (assigned)</h2></div>",
        ContentsFormat=formats["html"],
        Type=entryTypes["note"],
    )
    mocker.patch.object(demisto, "incidents", return_value=mock_incident)
    mocker.patch.object(demisto, "results", return_value=mock_result)
    result = glpi_incident_status_command()
    assert result.ContentsFormat == "html"
    assert result.Type == 1
    assert result.Contents == "<div style='color:#7995D4;text-align:center;'><h2>Processing (assigned)</h2></div>"
