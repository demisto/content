from RemoveKeyFromList import remove_key_from_list_command
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from typing import List, Dict, Any
import json

MOCK_LIST_NAME = "TestList"
MOCK_KEY_NAME = "TestKey"


def test_remove_nonexisting_key_in_nonempty_list(mocker):
    MOCKED_START_LIST: Dict = {
        "AnotherKey": "SomeValue"
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    MOCKED_START_LIST: Dict = {}

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: "Value",
        "AnotherKey": "AnotherValue"
    }
    MOCKED_END_LIST: Dict = {
        "AnotherKey": "AnotherValue"
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: "Value"
    }
    MOCKED_END_LIST: Dict = {}

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
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
