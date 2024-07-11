import json
import io

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_command(mocker):
    """
        Scenario: executing command impartner-get-account-list.

        Given:
        - client and no specific parameters

        When:
        - Calling command impartner-get-account-list

        Then:
        - return the relevant results
    """
    from Impartner import Client, impartner_get_account_list_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {'dummy': 'dummy arg'}
    api_response = util_load_json('test_data/list_command_response.json')
    mocker.patch('Impartner.Client.get_accounts_list', return_value=api_response)
    response = impartner_get_account_list_command(client, args)

    mock_response = util_load_json('test_data/list_command_commandresults.json')

    assert response.outputs == mock_response


def test_id_command(mocker):
    """
        Scenario: executing command impartner-get-account-id.

        Given:
        - client and the id

        When:
        - Calling command impartner-get-account-id

        Then:
        - return the relevant results
    """
    from Impartner import Client, impartner_get_account_id_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {'id': '1111'}
    api_response = util_load_json('test_data/id_command_response.json')
    mocker.patch('Impartner.Client.get_accounts_id', return_value=api_response)
    response = impartner_get_account_id_command(client, args)

    mock_response = util_load_json('test_data/id_command_commandresults.json')

    assert response.outputs == mock_response