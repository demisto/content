"""The file contains the Unit tests for the Doppel XSOAR integration
The unit tests are suppose to run to make sure that with the modification of the pack, there is not failures
Please write a new unit test for the behavior whenever the pack is modified for new features
"""

import pytest
import json
import io
import requests
import demistomock as demisto

from Doppel import main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize("command, args, api_path, api_response",
                         [
                             ("doppel-get-alert",
                              {"id": "TST-31222"},
                              "https://api.doppel.com/v1/alert?id=TST-31222",
                              util_load_json('test_data/get-alert-success-200.json'))
                         ]
                         )
def test_command_success(mocker, requests_mock, command, args, api_path, api_response):
    """Tests the current command
    """
    mocker.patch.object(demisto, 'params', return_value={"url": "https://api.doppel.com", "credentials": {"password": "SAMPLE-API-KEY"}})
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'args', return_value=args)
    results_checker = mocker.patch.object(demisto, 'results', return_value=None)
    
    adapter = requests_mock.get(api_path, status_code=200, json=api_response)
    
    # Call the main function so that the command will be called
    main()
    
    assert adapter.call_count == 1
    assert api_response == json.loads(requests.get(api_path).text)
    assert 200 == requests.get(api_path).status_code
    assert sorted(results_checker.call_args.args[0].get('Contents')) == sorted(dict(api_response))
    

@pytest.mark.parametrize("command, args, api_path, status_code, api_response",
                         [
                             ("doppel-get-alert",
                              {"entity": "123"},
                              "https://api.doppel.com/v1/alert?entity=123",
                              400,
                              util_load_json('test_data/get-alert-failure-400-invalid-entity.json')),
                             ("doppel-get-alert",
                              {"id": "1234"},
                              "https://api.doppel.com/v1/alert?id=1234",
                              400,
                              util_load_json('test_data/get-alert-failure-400-invalid-alert-id.json')),
                         ]
                         )
def test_command_failure(mocker, requests_mock, command, args, api_path, status_code, api_response):
    """Tests the current command
    """
    mocker.patch.object(demisto, 'params', return_value={"url": "https://api.doppel.com", "credentials": {"password": "SAMPLE-API-KEY"}})
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results', return_value=None)
    
    adapter = requests_mock.get(api_path, status_code=status_code, json=api_response)
    
    # Call the main function so that the command will be called
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main()
        
    assert pytest_wrapped_e.type is SystemExit
    assert pytest_wrapped_e.value.code == 0
    assert adapter.call_count == 1
    assert api_response == json.loads(requests.get(api_path).text)
    assert status_code == requests.get(api_path).status_code
         
    
@pytest.mark.parametrize("command, args, api_path, status_code, exception_message",
                         [
                             ("doppel-get-alert",
                              {"id": "TST-31",
                               "entity": "http://dummyrul.com"},
                              "https://api.doppel.com/v1/alert?id=TST-31&entity=http://dummyrul.com",
                              400,
                              "Failed to execute doppel-get-alert command.\nError:\nBoth id and entity is specified. We need exactly single input for this command")
                         ]
                         )
def test_command_exception(mocker, requests_mock, command, args, api_path, status_code, exception_message):
    """Tests the current command
    """
    mocker.patch.object(demisto, 'params', return_value={"url": "https://api.doppel.com", "credentials": {"password": "SAMPLE-API-KEY"}})
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'args', return_value=args)
    results_checker = mocker.patch.object(demisto, 'results', return_value=None)
    
    adapter = requests_mock.get(api_path, status_code=status_code, json=None)
    
    # Call the main function so that the command will be called
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main()
        
    assert pytest_wrapped_e.type is SystemExit
    assert pytest_wrapped_e.value.code == 0
    # Notice that the API was not called, but the app itself has raised an exception before making the API call
    assert adapter.call_count == 0
    assert results_checker.call_args.args[0].get('Contents') == exception_message
    