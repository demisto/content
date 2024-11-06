import demistomock as demisto
import SekoiaXDRCloseAlert  # type: ignore
from SekoiaXDRCloseAlert import get_status_name, close_alert, main  # type: ignore


def test_get_status_name(mocker):
    output_data = [{"Type": 3, "Contents": {"status": {"name": "Ongoing"}}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_status_name("1") == "Ongoing"


def test_close_alert(mocker):
    mocker.patch.object(SekoiaXDRCloseAlert, "get_status_name", return_value="Ongoing")
    output_data = [{"Type": 3, "Contents": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    mocker.patch.object(demisto, "results")
    close_alert("1", "false", "reason", "notes", "admin")
    assert (
        demisto.results.call_args[0][0]["Contents"]
        == "**** The alert 1 has been closed. ****"
    )

    close_alert("1", "true", "reason", "notes", "admin")
    assert (
        demisto.results.call_args[0][0]["Contents"]
        == "**** The alert 1 has been rejected. ****"
    )

    mocker.patch.object(SekoiaXDRCloseAlert, "get_status_name", return_value="Closed")
    try:
        close_alert("1", "false", "reason", "notes", "admin")
    except Exception as e:
        assert str(e) == "**** The alert is already closed or rejected. ****"


def test_main(mocker):
    mocker.patch.object(
        demisto,
        "incidents",
        return_value=[
            {
                "dbotMirrorDirection": "Out",
                "CustomFields": {"alertid": "1"},
                "owner": "admin",
            }
        ],
    )
    mocker.patch.object(demisto, "getArg", return_value="admin")
    mocker.patch.object(SekoiaXDRCloseAlert, "close_alert", return_value=None)

    assert main() is None
