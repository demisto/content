from RemoveKeyFromList import remove_key_from_list_command
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from typing import Any
import json

MOCK_LIST_NAME = "TestList"
MOCK_KEY_NAME = "TestKey"


def test_remove_nonexisting_key_in_nonempty_list(mocker):
    """
    Given:
        - a nonempty list with some value
        - a key that doesn't exist in the list
    When
        - trying to remove a key that doesn't exist in the list
    Then
        - a message saying the key was not found is returned
    """
    MOCKED_START_LIST: dict = {
        "AnotherKey": "SomeValue"
    }

    def executeCommand(name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = remove_key_from_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
    })

    assert result.readable_output == f'Key {MOCK_KEY_NAME} not found in list {MOCK_LIST_NAME}, cannot remove.'
    assert len(mocked_ec.call_args_list) == 1


def test_remove_nonexisting_key_in_empty_list(mocker):
    """
    Given:
        - an empty list
        - a key that doesn't exist in the list
    When
        - trying to remove a key
    Then
        - a message saying the key was not found is returned
    """
    MOCKED_START_LIST: dict = {}

    def executeCommand(name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = remove_key_from_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
    })

    assert result.readable_output == f'Key {MOCK_KEY_NAME} not found in list {MOCK_LIST_NAME}, cannot remove.'
    assert len(mocked_ec.call_args_list) == 1


def test_remove_existing_key(mocker):
    """
    Given:
        - a nonempty list with 2 values
        - a key that exists in the list
    When
        - trying to remove a key exists exist in the list
    Then
        - requested key is removed from list
        - list is left with only one item
    """
    MOCKED_START_LIST: dict = {
        MOCK_KEY_NAME: "Value",
        "AnotherKey": "AnotherValue"
    }
    MOCKED_END_LIST: dict = {
        "AnotherKey": "AnotherValue"
    }

    def executeCommand(name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = remove_key_from_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
    })

    assert result.readable_output == f'Successfully removed key {MOCK_KEY_NAME} from list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_remove_existing_last_key(mocker):
    """
    Given:
        - a nonempty list with 1 value
        - a key that exists in the list (the only one that exists)
    When
        - trying to remove the last key of the list
    Then
        - requested key is removed from list
        - list is empty
    """
    MOCKED_START_LIST: dict = {
        MOCK_KEY_NAME: "Value"
    }
    MOCKED_END_LIST: dict = {}

    def executeCommand(name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = remove_key_from_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
    })

    assert result.readable_output == f'Successfully removed key {MOCK_KEY_NAME} from list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST
