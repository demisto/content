import demistomock as demisto
import SekoiaXDRCloseAlert  # type: ignore
from SekoiaXDRCloseAlert import (
    get_status_name,
    get_username,
    post_closure_comment,
    close_alert,
    main,
)  # type: ignore


def test_get_status_name(mocker):
    output_data = [{"Type": 3, "Contents": {"status": {"name": "Ongoing"}}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_status_name("1") == "Ongoing"


def test_get_username(mocker):
    output_data = [{"Type": 3, "Contents": {"name": "admin1"}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_username("admin") == "admin1"


def test_post_closure_comment(mocker):
    output_data = [{"Type": 3, "Contents": {"name": "admin1"}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    mocker.patch.object(SekoiaXDRCloseAlert, "get_username", return_value="admin1")
    assert post_closure_comment("1", "reason", "notes", "admin") is None


def test_close_alert(mocker):
    mocker.patch.object(SekoiaXDRCloseAlert, "get_status_name", return_value="Ongoing")
    output_data = [{"Type": 3, "Contents": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    mocker.patch.object(SekoiaXDRCloseAlert, "post_closure_comment", return_value=None)
    mocker.patch.object(demisto, "results")
    close_alert("1", "false", "reason", "notes", "admin", "In", True)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been closed. ****"

    close_alert("1", "false", "reason", "notes", "admin", None, True)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been closed. ****"

    close_alert("1", "false", "reason", "notes", "admin", None, False)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been closed. ****"

    close_alert("1", "true", "reason", "notes", "admin", "In", False)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been rejected. ****"

    close_alert("1", "true", "reason", "notes", "admin", None, True)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been rejected. ****"

    close_alert("1", "true", "reason", "notes", "admin", None, False)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been rejected. ****"


def test_close_alert_closed_cond(mocker):
    mocker.patch.object(SekoiaXDRCloseAlert, "get_status_name", return_value="Closed")
    output_data = [{"Type": 3, "Contents": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    mocker.patch.object(demisto, "results")
    close_alert("1", "true", "reason", "notes", "admin", None, True)
    assert demisto.results.call_args[0][0]["Contents"] == "**** The alert 1 has been closed. ****"


def test_main(mocker):
    mocker.patch.object(
        demisto,
        "incidents",
        return_value=[
            {
                "dbotMirrorDirection": "In",
                "CustomFields": {"alertid": "1"},
                "owner": "admin",
            }
        ],
    )
    mocker.patch.object(demisto, "getArg", return_value="admin")
    mocker.patch.object(SekoiaXDRCloseAlert, "close_alert", return_value=None)

    assert main() is None
