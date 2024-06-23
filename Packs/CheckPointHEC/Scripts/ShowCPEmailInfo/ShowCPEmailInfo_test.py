import json

import demistomock as demisto
from ShowCPEmailInfo import get_email_info, dict_to_md


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_email_info_error(mocker):
    error = 'Error: Entity not found'

    def execute_command(name, args):
        if name == 'checkpointhec-get-entity':
            return [{'Contents': error}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    success, email_info = get_email_info('0000', 'CheckPointHEC-instance-1')
    assert success is False
    assert email_info == error


def test_get_email_info_success(mocker):
    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')

    def execute_command(name, args):
        if name == 'checkpointhec-get-entity':
            return [{'Contents': mock_response['responseData'][0]['entityPayload']}]

        if name == 'setIncident':
            return None

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    success, email_info = get_email_info('0000', 'CheckPointHEC-instance-1')
    assert success is True
    assert email_info == dict_to_md(mock_response['responseData'][0]['entityPayload'])


def test_dict_to_md():
    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    md = dict_to_md(mock_response['responseData'][0]['entityPayload'])
    lines = [
        '|field|value|',
        '|-|-|',
        '|fromEmail|example@checkpoint.com|',
        '|to|unicode@avanandevus1.onmicrosoft.com, user1@avanandevus1.onmicrosoft.com|',
        '|recipients|user1@avanandevus1.onmicrosoft.com, unicode@avanandevus1.onmicrosoft.com|',
        '|subject|Fw: dnp-split-quarantine-2|',
        '|received|2022-08-15T21:24:15|',
        '|isDeleted|False|',
        '|isIncoming|True|',
        '|isOutgoing|False|',
        '|internetMessageId|<00000000.00000000000000.00000000000000.00000000@mail.example.com>|',
        '|isUserExposed|True|'
    ]
    assert md == '\n'.join(lines)
