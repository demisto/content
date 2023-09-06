import json

import demistomock as demisto
from ShowCPScanInfo import get_scan_info


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_scan_info(mocker):
    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')

    def execute_command(name, args):
        if name == 'checkpointhec-get-scan-info':
            return [{'Contents': {'av': mock_response['responseData'][0]['entitySecurityResult']['av']}}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = get_scan_info('0000')
    assert result == [{'Contents': {'av': mock_response['responseData'][0]['entitySecurityResult']['av']}}]
