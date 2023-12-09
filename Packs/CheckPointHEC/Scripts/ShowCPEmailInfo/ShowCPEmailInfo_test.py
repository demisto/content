import json

import demistomock as demisto
from ShowCPEmailInfo import get_email_info, dict_to_md


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_email_info(mocker):
    mock_response = util_load_json('./test_data/checkpointhec-get_email_info.json')

    def execute_command(name, args):
        if name == 'checkpointhec-get-email-info':
            return [{'Contents': mock_response['responseData'][0]['entityPayload']}]

        if name == 'setIncident':
            return None

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = get_email_info('0000')
    email_info = result[0]['Contents']
    custom_fields = json.dumps({
        'checkpointhecemailsender': email_info['fromEmail'],
        'checkpointhecemailsubject': email_info['subject']
    })
    assert result == [{'Contents': mock_response['responseData'][0]['entityPayload']}]
    assert mocked_ec.call_args_list[1][0][0] == 'setIncident'
    assert mocked_ec.call_args_list[1][0][1] == {'customFields': custom_fields}


def test_dict_to_md():
    mock_response = util_load_json('./test_data/checkpointhec-get_email_info.json')
    md = dict_to_md(mock_response['responseData'][0]['entityPayload'])
    lines = [
        '|field|value|',
        '|-|-|',
        '|fromEmail|example@checkpoint.com|',
        '|to|unicode@avanandevus1.onmicrosoft.com, user1@avanandevus1.onmicrosoft.com|',
        '|recipients|user1@avanandevus1.onmicrosoft.com, unicode@avanandevus1.onmicrosoft.com|',
        '|subject|Fw: dnp-split-quarantine-2|',
        '|received|2022-08-15T21:24:15|',
        '|isIncoming|True|',
        '|internetMessageId|<00000000.00000000000000.00000000000000.00000000@mail.example.com>|',
        '|isUserExposed|True|'
    ]
    assert md == '\n'.join(lines)
