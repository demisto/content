import demistomock as demisto
from Penfield import main
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_main(mocker):
    mock_users = util_load_json('test_data/test_2_users.json')
    mock_incident = util_load_json('test_data/test_incident.json')

    mocker.patch.object(demisto, 'command', return_value="penfield-api-call")
    mocker.patch.object(demisto, 'args', return_value={'analysts': mock_users, 'incident': mock_incident})
    mocker.patch('Penfield.get_assignee', return_value="test")
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://fakeurl.ai/api/v1/xsoar_live_assign/'})

    main()

    assert demisto.results.call_args.args[0] == 'test'
