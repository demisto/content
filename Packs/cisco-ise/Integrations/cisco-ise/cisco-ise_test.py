import importlib
import demistomock as demisto
import pytest

cisco_ise = importlib.import_module("cisco-ise")

MAC_ADDRESS = '11:22:33:44:55:66'
EMPTY_SEARCH_RES = {'SearchResult': {'resources': []}}


def test_get_endpoint_id_command(mocker):
    """
    Given:
        - Mac address.
    When:
        - Calling get_endpoint_id_command.
    Then:
        - The command is not failed even when there is no endpoint for the mac address.
    """
    m = mocker.patch.object(cisco_ise, 'return_outputs')
    mocker.patch.object(demisto, 'args', return_value={'macAddress': MAC_ADDRESS})
    mocker.patch.object(cisco_ise, 'get_endpoint_id', return_value=EMPTY_SEARCH_RES)
    
    cisco_ise.get_endpoint_id_command()
    assert m.call_args[0][0] == 'The endpoint ID is: None'
    assert m.call_args[0][1] == {'Endpoint(val.ID === obj.ID)': {'ID': None, 'MACAddress': MAC_ADDRESS}}



def test_get_endpoint_details_command(mocker, requests_mock):
    """
    Given:
        - Mac address.
    When:
        - Calling get_endpoint_details_command.
    Then:
        - The command returns error entry for Endpoint was not found.
    """


    results = mocker.spy(demisto, 'results')

    mocker.patch.object(cisco_ise, 'http_request', return_value=None)
    mocker.patch.object(demisto, 'args', return_value={'macAddress': MAC_ADDRESS})
    mocker.patch.object(cisco_ise, 'get_endpoint_id', return_value=EMPTY_SEARCH_RES)
    
    with pytest.raises(SystemExit):
        cisco_ise.get_endpoint_details_command()

    assert results.call_args[0][0]["Contents"] == 'Endpoint was not found.'
    assert results.call_args[0][0]["Type"] == 4 #error entry
        


def test_update_endpoint_group_command(mocker):
    """
    Given:
        - Group name.
    When:
        - Calling update_endpoint_group_command.
    Then:
        - The command returns error entry for Endpoint was not found for the group.
    """
    
    results = mocker.spy(demisto, 'results')

    mocker.patch.object(demisto, 'args', return_value={'groupName': 'group1'})
    mocker.patch.object(cisco_ise, 'get_endpoint_id', return_value=EMPTY_SEARCH_RES)
    

    with pytest.raises(SystemExit):
        cisco_ise.update_endpoint_group_command()

    assert results.call_args[0][0]["Contents"] == 'No endpoints were found. Please make sure you entered the correct group name'
    assert results.call_args[0][0]["Type"] == 4 #error entry



def test_get_blacklist_endpoints_request(mocker):
    """
    When:
        - Calling get_blacklist_endpoints_request.
    Then:
        - The command returns error entry for No blacklist endpoint were found.
    """
    
    results = mocker.spy(demisto, 'results')
    mocker.patch.object(cisco_ise, 'get_blacklist_group_id', return_value=EMPTY_SEARCH_RES)
    
    with pytest.raises(SystemExit):
        cisco_ise.get_blacklist_endpoints_request()

    assert results.call_args[0][0]["Contents"] == 'No blacklist endpoint were found.'
    assert results.call_args[0][0]["Type"] == 4 #error entry

