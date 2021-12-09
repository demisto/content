import demistomock as demisto
from Penfield import main, get_assignee, Client
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_main(mocker):
    mock_users = "username1,username2"
    mock_incident = util_load_json('test_data/test_incident.json')

    mocker.patch.object(demisto, 'command', return_value="penfield-get-assignee")
    mocker.patch.object(demisto, 'args', return_value={'analysts': mock_users, 'incident': mock_incident})
    mocker.patch('Penfield.get_assignee', return_value="test")
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://fakeurl.ai/api/v1/xsoar_live_assign/'})

    main()

    assert demisto.results.call_args.args[0] == 'test'


def test_get_assignee(mocker):

    mock_users = "username1,username2"

    mocker.patch.object(demisto, 'args', return_value={
        'analyst_ids': mock_users,
        'category': 'test_category',
        'created': '2021-03-02',
        'arg_id': 123,
        'name': 'test name',
        'severity': 'high'
    })
    mocker.patch('Penfield.Client.live_assign_get', return_value="test_cr_response")

    api_key = demisto.params().get('apikey')
    base_url = 'https://test.com'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        proxy=proxy
    )

    assert type(get_assignee(client, demisto.args())).__name__ == "CommandResults"
