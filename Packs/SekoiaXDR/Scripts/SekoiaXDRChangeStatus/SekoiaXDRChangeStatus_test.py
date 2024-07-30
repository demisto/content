import demistomock as demisto
from SekoiaXDRChangeStatus import get_username, main  # type: ignore


def test_get_username(mocker):
    output_data = [
        {"Type": 3, "Contents": [{"name": "admin", "PrettyRoles": "Administrator"}]}
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_username() == "admin"


def test_main(mocker):
    mocker.patch.object(
        demisto,
        "args",
        return_value={"short_id": "1", "status": "Ongoing", "comment": "test"},
    )
    mocker.patch.object(demisto, "results")
    mocker.patch("SekoiaXDRChangeStatus.get_username", return_value="admin")
    main()
    assert (
        demisto.results.call_args[0][0]["Contents"]
        == "### Status of the alert changed to:\n Ongoing"
    )
