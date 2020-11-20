from AddKeyToList import add_key_to_list_command
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from typing import List, Dict, Any
import json

MOCK_LIST_NAME = "TestList"
MOCK_KEY_NAME = "TestKey"
MOCK_VALUE = "TestValue"


def test_add_new_key_in_empty_list(mocker):
    MOCKED_START_LIST: Dict = {}
    MOCKED_END_LIST: Dict = {
        MOCK_KEY_NAME: MOCK_VALUE
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'false',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_add_new_key_in_nonempty_list(mocker):
    MOCKED_START_LIST: Dict = {
        "ExistingKey": "ExistingValue"
    }
    MOCKED_END_LIST: Dict = {
        "ExistingKey": "ExistingValue",
        MOCK_KEY_NAME: MOCK_VALUE
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'false',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_replace_key_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: "OldValue"
    }
    MOCKED_END_LIST: Dict = {
        MOCK_KEY_NAME: MOCK_VALUE
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'false',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_no_change_same_value_same_key_no_dup_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: MOCK_VALUE
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'true',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Value already present in key {MOCK_KEY_NAME} of list {MOCK_LIST_NAME}: not appending.'
    assert len(mocked_ec.call_args_list) == 1


def test_append_value_to_existing_key_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: "OldValue"
    }
    MOCKED_END_LIST: Dict = {
        MOCK_KEY_NAME: ["OldValue", MOCK_VALUE]
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'true',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_append_value_to_existing_list_key_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: ["OldValue1", "OldValue2"]
    }
    MOCKED_END_LIST: Dict = {
        MOCK_KEY_NAME: ["OldValue1", "OldValue2", MOCK_VALUE]
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'true',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST


def test_no_append_existing_value_same_list_key_no_dup_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: ["OldValue", MOCK_VALUE]
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'true',
        'allowDups': 'false'
    })

    assert result.readable_output == f'Value already present in key {MOCK_KEY_NAME} of list {MOCK_LIST_NAME}: not appending.'
    assert len(mocked_ec.call_args_list) == 1


def test_append_duplicate_value_to_existing_key_in_existing_list(mocker):
    MOCKED_START_LIST: Dict = {
        MOCK_KEY_NAME: MOCK_VALUE
    }
    MOCKED_END_LIST: Dict = {
        MOCK_KEY_NAME: [MOCK_VALUE, MOCK_VALUE]
    }

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getList':
            return [{"Contents": json.dumps(MOCKED_START_LIST)}]
        elif name == 'setList':
            return [{"Contents": f"Done: list {name} was updated"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = add_key_to_list_command({
        'listName': MOCK_LIST_NAME,
        'keyName': MOCK_KEY_NAME,
        'value': MOCK_VALUE,
        'append': 'true',
        'allowDups': 'true'
    })

    assert result.readable_output == f'Successfully updated list {MOCK_LIST_NAME}.'
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'setList'
    assert json.loads(mocked_ec.call_args_list[1][0][1]['listData']) == MOCKED_END_LIST
