import demistomock as demisto
from GIBIncidentUpdate import prevent_duplication


EXISTING_INCIDENT = [
    {
        "Contents": {
            "total": 1,
            "data": [
                {"id": "1",
                 "gibid": "12v"}
            ]
        }
    }
]
INCOMING_INCIDENT = {"gibid": "12v"}


def test_prevent_duplication_existing_duplication(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=EXISTING_INCIDENT)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert not result


def test_prevent_duplication_no_duplication(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert result
