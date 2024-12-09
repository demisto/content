"""The file contains the Unit tests for the Doppel XSOAR integration
The unit tests are suppose to run to make sure that with the modification of the pack, there is not failures
Please write a new unit test for the behavior whenever the pack is modified for new features
"""

import pytest
import json
import io
import requests
import demistomock as demisto
import requests_mock

from Doppel import Client, main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


get_alert_mock_response_200 = util_load_json('test_data/get-alert-command-200.json')
@pytest.mark.parametrize("api_path, command, args, api_response",
                         [
                             ("https://api.doppel.com/v1/alert?id=TST-31222", "get-alert", {"id": "TST-31222"}, get_alert_mock_response_200)
                         ]
                         )
def test_command_success(mocker, requests_mock, api_path, command, args, api_response):
    """Tests the current command
    """
    mocker.patch.object(demisto, 'params', return_value={"url": "https://api.doppel.com", "credentials": {"password": "<API-KEY>"}})
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'args', return_value=args)
    results_checker = mocker.patch.object(demisto, 'results', return_value=None)
    
    adapter = requests_mock.get(api_path, status_code=200, json=api_response)
    
    # Call the main function so that the command will be called
    main()
    
    assert adapter.call_count == 1
    assert adapter.called
    assert api_response == json.loads(requests.get(api_path).text)
    assert 200 == requests.get(api_path).status_code
    assert sorted(results_checker.call_args.args[0].get('Contents')) == sorted(dict(api_response))
         
    
    