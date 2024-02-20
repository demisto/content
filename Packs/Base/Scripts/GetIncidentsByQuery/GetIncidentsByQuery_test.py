from CommonServerPython import EntryType
from GetIncidentsByQuery import encode_outputs, to_file_entry
import demistomock as demisto

import json
import pickle


def test_encode_outputs():
    incidents = [{"id": 1}]
    assert json.loads(encode_outputs(incidents, "json")) == incidents
    assert pickle.loads(encode_outputs(incidents, "pickle")) == incidents


def test_to_file_entry(mocker):
    incidents = [{"id": 1}]
    mocker.patch.object(demisto, "investigation", return_value={"id": "inv"})
    res = to_file_entry(incidents, "json")
    assert res["Type"] == EntryType.FILE
    assert res["EntryContext"]["GetIncidentsByQuery"]["FileFormat"] == "json"
    assert res["Contents"] == incidents
