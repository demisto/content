from CommonServerPython import *
from BluecatAddressManager import Client, get_entity_by_name_command


def test_get_entity_by_name_command(mocker):
    """
    Tests the bluecat-am-get-entity-by-name command.
    """
    mock_client = mocker.Mock(spec=Client)
    mock_client.conf = 123

    mock_client.get_entity_by_name.return_value = {
        "id": 456,
        "name": "test.example.com",
        "type": "HostRecord",
        "properties": "absoluteName=test.example.com|addresses=1.1.1.1|",
    }

    # Mock get_entity_parents (which calls get_entity_parent in a loop)
    # We'll mock the helper function directly to simplify
    mocker.patch(
        "BluecatAddressManager.get_entity_parents", return_value=[{"ID": 123, "Name": "Config", "Type": "Configuration"}]
    )

    mocker.patch.object(
        demisto, "args", return_value={"name": "test.example.com", "parent_id": None, "type": "HostRecord", "include_ha": "true"}
    )

    results_mock = mocker.patch("BluecatAddressManager.return_results")

    get_entity_by_name_command(mock_client)

    assert results_mock.called
    results = results_mock.call_args[0][0]

    assert results.outputs_prefix == "BlueCat.AddressManager.Entity"
    assert results.outputs["ID"] == 456
    assert results.outputs["Name"] == "test.example.com"
    assert results.outputs["AbsoluteName"] == "test.example.com"
    assert results.outputs["Addresses"] == "1.1.1.1"

    mock_client.get_entity_by_name.assert_called_with("test.example.com", None, "HostRecord", True)


def test_get_entity_by_name_not_found(mocker):
    """
    Tests the bluecat-am-get-entity-by-name command when entity is not found.
    """
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_entity_by_name.return_value = None

    mocker.patch.object(
        demisto, "args", return_value={"name": "test.example.com", "parent_id": None, "type": "HostRecord", "include_ha": "true"}
    )
    results_mock = mocker.patch("BluecatAddressManager.return_results")

    get_entity_by_name_command(mock_client)

    assert results_mock.called
    results = results_mock.call_args[0][0]
    assert results.entry_type == EntryType.ERROR
    assert "was not found" in results.readable_output
