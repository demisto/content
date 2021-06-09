import demistomock as demisto
from GIBIncidentUpdate import prevent_duplication


INCOMING_INCIDENT = [
    {
        "Contents": {
            "total": 1,
            "data": [
                {"id": "1"}
            ]
        }
    }
]


def test_prevent_duplication(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=INCOMING_INCIDENT)
    result = prevent_duplication({"gibid": "12v"})
    assert not result
