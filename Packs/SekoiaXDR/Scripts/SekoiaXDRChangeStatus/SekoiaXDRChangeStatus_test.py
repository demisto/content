import demistomock as demisto
from SekoiaXDRChangeStatus import get_username, main, update_status, post_comment  # type: ignore


def test_get_username(mocker):
    output_data = [{"Type": 3, "Contents": [{"name": "admin", "PrettyRoles": "Administrator"}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_username() == "admin"


def test_post_comment(mocker):
    output_data = [{"Type": 3, "Contents": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert post_comment("1", "test", "admin") is None


def test_update_status(mocker):
    output_data = [{"Type": 3, "Contents": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert update_status("Ongoing", "In", False, "1") is None
    assert update_status("Ongoing", "In", True, "1") is None
    assert update_status("Ongoing", None, True, "1") is None
    assert update_status("Ongoing", None, False, "1") is None


def test_main(mocker):
    mocker.patch.object(
        demisto, "incidents", return_value=[{"dbotMirrorDirection": "In", "CustomFields": {"sekoiaxdrmirrorout": True}}]
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={"short_id": "1", "status": "Ongoing", "comment": "test"},
    )
    mocker.patch.object(demisto, "results")
    mocker.patch("SekoiaXDRChangeStatus.get_username", return_value="admin")
    main()
    assert demisto.results.call_args[0][0]["Contents"] == "### Status of the alert changed to:\n Ongoing"
