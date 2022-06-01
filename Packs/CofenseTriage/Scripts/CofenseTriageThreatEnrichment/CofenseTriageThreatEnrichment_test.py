from unittest.mock import patch
import json


@patch('demistomock.executeCommand')
def test_get_threat_indicator_list_when_valid_response_is_returned(mock_execute_command):
    """
    Test get_threat_indicator_list when command execution is successfull.
    """
    from CofenseTriageThreatEnrichment import get_threat_indicator_list

    with open("test_data/threat_indicator_response.json") as data:
        mock_response = json.load(data)

    mock_execute_command.return_value = mock_response
    args = {
        'threat_value': 'd9cd2a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d1234567'
    }
    response = get_threat_indicator_list(args)

    assert response == mock_response
