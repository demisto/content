import pytest

import demistomock as demisto
import NetskopeGetXsoarListContent
from NetskopeGetXsoarListContent import get_or_create_list_content, main


def test_get_or_create_list_content_returns_existing_content(mocker):
    """
    Given:
        - getList succeeds and returns existing content for the list.
    When:
        - Running get_or_create_list_content.
    Then:
        - The existing content is returned, and createList is never called.
    """
    execute_mock = mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "a,b,c"}]
    )
    content = get_or_create_list_content("MyList")
    assert content == "a,b,c"
    execute_mock.assert_called_once_with("getList", {"listName": "MyList"})


def test_get_or_create_list_content_creates_missing_list(mocker):
    """
    Given:
        - getList errors because the list doesn't exist yet.
    When:
        - Running get_or_create_list_content.
    Then:
        - createList is called to create it empty, and an empty string is returned.
    """
    def fake_execute(command, args):
        if command == "getList":
            return [{"Type": 4, "Contents": "Item not found - MyList"}]
        return [{"Type": 1, "Contents": ""}]

    execute_mock = mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)
    content = get_or_create_list_content("MyList")
    assert content == ""
    execute_mock.assert_any_call("createList", {"listName": "MyList", "listData": ""})


def test_main_requires_list_name(mocker):
    """
    Given:
        - listName is not provided.
    When:
        - Running main.
    Then:
        - return_error is called with a clear message.
    """
    mocker.patch.object(demisto, "args", return_value={})
    return_error_mock = mocker.patch.object(NetskopeGetXsoarListContent, "return_error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        main()

    return_error_mock.assert_called_once_with("listName is required")


def test_main_returns_list_content(mocker):
    """
    Given:
        - listName is provided and the list already has content.
    When:
        - Running main.
    Then:
        - XsoarList.name/content are set from the list.
    """
    mocker.patch.object(demisto, "args", return_value={"listName": "MyList"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "a,b"}])
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["XsoarList(val.name && val.name == obj.name)"]
    assert outputs["name"] == "MyList"
    assert outputs["content"] == "a,b"
