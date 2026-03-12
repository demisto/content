import demistomock as demisto
from SekoiaXDRAddComment import get_username, post_comment, main  # type: ignore


def test_get_username(mocker):
    output_data = [{"Type": 3, "Contents": [{"name": "admin", "PrettyRoles": "Administrator"}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_username() == "admin"


def test_post_comment(mocker):
    output_data = [{"Type": 3, "Contents": [{"id": "1", "comment": "test", "author": "admin"}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert not post_comment("1", "test", "admin")


def test_main(mocker):
    mocker.patch.object(demisto, "args", return_value={"short_id": "1", "comment": "test"})
    mocker.patch("SekoiaXDRAddComment.get_username", return_value="admin")
    mocker.patch("SekoiaXDRAddComment.post_comment", return_value=None)
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_args[0][0]["HumanReadable"] == "### Comment added by admin:\n test"
