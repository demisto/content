from CommonServerPython import *


import pytest
import FeedThreatVault
from FeedThreatVault import main, fetch_indicators_command, Client, threatvault_get_indicators_command, parse_indicator_for_fetch

CLIENT = Client(
    base_url='example.com',
    api_key='api_key',
    verify=False,
    proxy=False,
    reliability='B - Usually reliable',
)


EDL_RESPONSE = {
    "success": "true",
    "link": {"next": "null", "previous": "null"},
    "count": 1001,
    "data": {
        "version": "1",
        "name": "panw-bulletproof-ip-list",
        "ipaddr": [
            "192.168.1.0-192.168.1.255",
            "192.168.0.0-192.168.0.255",
        ],
    },
    "message": "Successful",
}

EDL_RESPONSE_2 = {
    "success": "true",
    "link": {"next": "null", "previous": "null"},
    "count": 1001,
    "data": {
        "version": "1",
        "name": "panw-bulletproof-ip-list",
        "ipaddr": [
        ],
    },
    "message": "Successful",
}


def _open_json_file(path):
    with open(path) as f:
        return json.loads(f.read())


def test_fetch_indicators_command(mocker):
    expected_response = _open_json_file('test_data/fetch_indicators_results.json')
    mocker.patch.object(CLIENT, "get_indicators_request", side_effect=[EDL_RESPONSE, EDL_RESPONSE_2])
    run_time, results = fetch_indicators_command(CLIENT, 'example-edl-list', 'array', 'TLP:CLEAR', 'EXAMPLE')
    assert results == expected_response


def test_fetch_indicators_command_raises_exception(mocker):
    mocker.patch.object(CLIENT, "get_indicators_request", side_effect=DemistoException("Test exception"))
    with pytest.raises(DemistoException):
        fetch_indicators_command(CLIENT, 'example-edl-list', 'array', 'TLP:CLEAR', 'EXAMPLE')


def test_threatvault_get_indicators_command(mocker):
    expected_results = _open_json_file('test_data/threatvault_get_indicators_results.json')
    mocker.patch.object(CLIENT, "get_indicators_request", side_effect=[EDL_RESPONSE, EDL_RESPONSE_2])
    args = {'name': 'test', 'version': '1'}
    results = threatvault_get_indicators_command(client=CLIENT, list_format='array', args=args)
    assert results.to_context() == expected_results


def test_threatvault_get_indicators_command_raises_exception(mocker):
    mocker.patch.object(CLIENT, "get_indicators_request", side_effect=DemistoException("Test exception"))
    args = {'name': 'test', 'version': '1'}
    with pytest.raises(DemistoException):
        threatvault_get_indicators_command(client=CLIENT, list_format='array', args=args)


def test_parse_indicator_for_fetch():
    expected_results = _open_json_file('test_data/expected_parsed_indicator.json')
    indicator = _open_json_file('test_data/fetch_indicators_results.json')[0]
    parsed_indicator = parse_indicator_for_fetch(indicator, tags="tag1, tag2", tlp_color="TLP:CLEAR", feed_tag_name="EXAMPLE")
    assert parsed_indicator.items() <= expected_results.items()


def test_threatvault_main_command_success(mocker):
    expected_results = _open_json_file("test_data/expected_return_results.json")
    mocker.patch.object(demisto, "params", return_value={
        "url": "https://example.com",
        "name": "EDL_name",
        "api_key": "api_key",
        "list_format": "array",
        "proxy": False,
        "verify_certificate": False,
        "reliability": "B - Usually reliable"
    })
    mocker.patch.object(CLIENT, "get_indicators_request", return_value=EDL_RESPONSE)
    mocker.patch.object(demisto, "args", return_value={'name': 'test', 'version': '1'})
    mocker.patch.object(demisto, "command", return_value="threatvault-get-indicators")
    mocker.patch.object(FeedThreatVault, "threatvault_get_indicators_command",
                        return_value=_open_json_file('test_data/threatvault_get_indicators_results.json'))
    mock_return_results = mocker.patch.object(FeedThreatVault, "return_results")
    main()
    assert mock_return_results.called
    assert mock_return_results.call_args[0][0] == expected_results


def test_threatvault_main_bad_command(mocker):
    mocker.patch.object(demisto, "params", return_value={
        "url": "https://example.com",
        "name": "EDL_name",
        "api_key": "api_key",
        "list_format": "array",
        "proxy": False,
        "verify_certificate": False,
        "reliability": "B - Usually reliable"
    })
    mocker.patch.object(demisto, "command", return_value="bad-command")
    mock_return_error = mocker.patch.object(FeedThreatVault, "return_error")
    mocker.patch('sys.stdout', new=mocker.MagicMock())

    main()

    assert mock_return_error.called
    error_message = mock_return_error.call_args[0][0]
    assert "Failed to execute bad-command command. The command not implemented" in error_message
