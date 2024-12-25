import importlib
import demistomock as demisto
import pytest

PARAMS = {'serverURL': 'http://example.com', 'serverPort': '1234', 'credentials':
          {'identifier': 'test@example.com', 'password': '1234'}}
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
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    cisco_ise = importlib.import_module("cisco-ise")
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
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    cisco_ise = importlib.import_module("cisco-ise")
    results = mocker.spy(demisto, 'results')

    mocker.patch.object(cisco_ise, 'http_request', return_value=None)
    mocker.patch.object(demisto, 'args', return_value={'macAddress': MAC_ADDRESS})
    mocker.patch.object(cisco_ise, 'get_endpoint_id', return_value=EMPTY_SEARCH_RES)

    with pytest.raises(SystemExit):
        cisco_ise.get_endpoint_details_command()

    assert results.call_args[0][0]["Contents"] == 'Endpoint was not found.'
    assert results.call_args[0][0]["Type"] == 4  # error entry


def test_update_endpoint_group_command(mocker):
    """
    Given:
        - Group name.
    When:
        - Calling update_endpoint_group_command.
    Then:
        - The command returns error entry for Endpoint was not found for the group.
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    cisco_ise = importlib.import_module("cisco-ise")
    results = mocker.spy(demisto, 'results')

    mocker.patch.object(demisto, 'args', return_value={'groupName': 'group1'})
    mocker.patch.object(cisco_ise, 'get_endpoint_id', return_value=EMPTY_SEARCH_RES)

    with pytest.raises(SystemExit):
        cisco_ise.update_endpoint_group_command()

    assert results.call_args[0][0]["Contents"] == 'No endpoints were found. Please make sure you entered the correct group name'
    assert results.call_args[0][0]["Type"] == 4  # error entry


def test_update_endpoint_group_command_populate_endpoint_data(mocker):
    """
    Given:
        - Endpoint details and group id.
    When:
        - Calling update_endpoint_group_command.
    Then:
        - The update_endpoint_by_id method args contains the data from get_endpoint_details res.
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    cisco_ise = importlib.import_module("cisco-ise")
    m = mocker.patch.object(cisco_ise, 'update_endpoint_by_id', return_value={'ERSResponse': {}})
    mocker.patch.object(demisto, 'args', return_value={'groupId': '1', 'id': '2', 'macAddress': MAC_ADDRESS})
    mocker.patch.object(cisco_ise, 'get_endpoint_details', return_value={
                        'ERSEndPoint': {'id': '3', 'mac': MAC_ADDRESS, 'name': 'endpoint1'}})

    cisco_ise.update_endpoint_group_command()
    assert m.call_args[0][1] == {'ERSEndPoint': {'groupId': '1', 'id': '3', 'mac': MAC_ADDRESS, 'name': 'endpoint1'}}


def test_get_blacklist_endpoints_request(mocker):
    """
    When:
        - Calling get_blacklist_endpoints_request.
    Then:
        - The command returns error entry for No blacklist endpoint were found.
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    cisco_ise = importlib.import_module("cisco-ise")
    results = mocker.spy(demisto, 'results')
    mocker.patch.object(cisco_ise, 'get_blacklist_group_id', return_value=EMPTY_SEARCH_RES)

    with pytest.raises(SystemExit):
        cisco_ise.get_blacklist_endpoints_request()

    assert results.call_args[0][0]["Contents"] == 'No blacklist endpoint were found.'
    assert results.call_args[0][0]["Type"] == 4  # error entry
