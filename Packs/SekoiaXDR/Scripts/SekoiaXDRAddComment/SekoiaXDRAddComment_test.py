import demistomock as demisto
from SekoiaXDRAddComment import get_username, post_comment  # type: ignore


def test_get_username(mocker):
    output_data = [
        {"Type": 3, "Contents": [{"name": "admin", "PrettyRoles": "Administrator"}]}
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert get_username() == "admin"


def test_post_comment(mocker):
    output_data = [
        {"Type": 3, "Contents": [{"id": "1", "comment": "test", "author": "admin"}]}
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=output_data)
    assert not post_comment("1", "test", "admin")
