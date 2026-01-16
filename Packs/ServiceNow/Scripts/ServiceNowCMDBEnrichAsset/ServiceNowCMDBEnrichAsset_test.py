import pytest
from ServiceNowCMDBEnrichAsset import (
    NetworkAdapter,
    ConfigurationItem,
    get_command_results,
    get_network_adapter,
    get_related_configuration_item,
    main,
)


@pytest.fixture
def mock_network_adapter_data():
    return {
        "result": {
            "attributes": {
                "name": "eth0",
                "ip_address": "192.168.1.1",
                "assigned_to": {"display_value": "John Doe", "value": "user123"},
                "cmdb_ci": {"display_value": "Server123", "value": "ci123"},
                "sys_domain": {"link": "https://instance.service-now.com/api/now/table/sys_user_group/global"},
            }
        }
    }


@pytest.fixture
def mock_ci_data():
    return {
        "result": {
            "attributes": {
                "sys_class_name": "cmdb_ci_linux_server",
                "name": "Server123",
                "ip_address": "192.168.1.1",
                "assigned_to": {"display_value": "John Doe", "value": "user123"},
                "host_name": "server123.company.com",
                "os": "Linux",
                "os_version": "Ubuntu 20.04",
                "used_for": "Production",
            }
        }
    }


@pytest.fixture
def mock_demisto_args():
    return {"ip_address": "192.168.1.1"}


def test_network_adapter_initialization():
    """
    Given a set of network adapter attributes
    When a NetworkAdapter instance is created
    Then it should correctly initialize all properties
    """
    adapter = NetworkAdapter(
        sys_id="na123",
        name="eth0",
        ip="192.168.1.1",
        owner="John Doe",
        owner_id="user123",
        related_configuration_item_name="Server123",
        related_configuration_item_id="ci123",
        instance_url="https://instance.service-now.com",
        url="https://instance.service-now.com/nav_to.do?uri=cmdb_ci_network_adapter.do?sys_id=na123",
    )

    assert adapter.sys_id == "na123"
    assert adapter.name == "eth0"
    assert adapter.ip == "192.168.1.1"
    assert adapter.owner == "John Doe"
    assert adapter.owner_id == "user123"
    assert adapter.related_configuration_item_name == "Server123"
    assert adapter.related_configuration_item_id == "ci123"
    assert adapter.instance_url == "https://instance.service-now.com"


def test_get_command_results(mocker):
    """
    Given a command and arguments
    When get_command_results is called
    Then it should return the expected command results
    """
    mock_command = "test-command"
    mock_args = {"key": "value"}
    expected_result = {"result": "success"}

    mocker.patch("ServiceNowCMDBEnrichAsset.demisto.executeCommand", return_value=[{"Contents": {"result": expected_result}}])

    result = get_command_results(mock_command, mock_args)
    assert result == expected_result


def test_get_network_adapter(mocker, mock_network_adapter_data):
    """
    Given a network adapter sys_id
    When get_network_adapter is called
    Then it should return a properly populated NetworkAdapter instance
    """
    mocker.patch("ServiceNowCMDBEnrichAsset.get_command_results", return_value=mock_network_adapter_data["result"])

    adapter = get_network_adapter("na123")

    assert isinstance(adapter, NetworkAdapter)
    assert adapter.name == "eth0"
    assert adapter.ip == "192.168.1.1"
    assert adapter.owner == "John Doe"
    assert adapter.owner_id == "user123"
    assert adapter.related_configuration_item_name == "Server123"
    assert adapter.related_configuration_item_id == "ci123"


def test_get_related_configuration_item(mocker, mock_ci_data):
    """
    Given a configuration item sys_id and instance URL
    When get_related_configuration_item is called
    Then it should return a properly populated ConfigurationItem instance
    """
    # First call returns the CI class
    mocker.patch(
        "ServiceNowCMDBEnrichAsset.get_command_results",
        side_effect=[{"attributes": {"sys_class_name": "cmdb_ci_linux_server"}}, mock_ci_data["result"]],
    )

    ci = get_related_configuration_item("ci123", "https://instance.service-now.com")

    assert isinstance(ci, ConfigurationItem)
    assert ci.name == "Server123"
    assert ci.ip == "192.168.1.1"
    assert ci.owner == "John Doe"
    assert ci.owner_id == "user123"
    assert ci.hostname == "server123.company.com"
    assert ci.os == "Linux"
    assert ci.os_version == "Ubuntu 20.04"
    assert ci.ci_class == "cmdb_ci_linux_server"
    assert ci.use == "Production"


def test_main_success(mocker, mock_demisto_args, mock_network_adapter_data, mock_ci_data):
    """
    Given valid input parameters
    When main is called
    Then it should process the network adapters and return the expected results
    """
    # Mock demisto functions
    mocker.patch("ServiceNowCMDBEnrichAsset.demisto.args", return_value=mock_demisto_args)

    # Mock command execution
    mocker.patch(
        "ServiceNowCMDBEnrichAsset.get_command_results",
        side_effect=[
            [{"sys_id": "na123"}],  # First call to get network adapters
            mock_network_adapter_data["result"],  # Get network adapter details
            {"attributes": {"sys_class_name": "cmdb_ci_linux_server"}},  # Get CI class
            mock_ci_data["result"],  # Get CI details
        ],
    )

    # Mock return_results
    mock_return = mocker.patch("ServiceNowCMDBEnrichAsset.return_results")

    main()

    # Verify return_results was called with expected data
    assert mock_return.called
    call_args = mock_return.call_args[0][0]
    assert call_args.outputs_prefix == "ServiceNowCMDBAssetEnrichment"
    assert len(call_args.outputs["network_adapters"]) == 1
    assert len(call_args.outputs["related_configuration_items"]) == 1


def test_main_no_ip(mocker):
    """
    Given no IP address is provided
    When main is called
    Then it should raise a validation error
    """
    mocker.patch("ServiceNowCMDBEnrichAsset.demisto.args", return_value={"ip_address": None})
    mock_error = mocker.patch("ServiceNowCMDBEnrichAsset.return_error")

    main()

    assert mock_error.called
    assert "IP address is required" in mock_error.call_args[0][0]


def test_main_no_results(mocker, mock_demisto_args):
    """
    Given a request that returns no results
    When main is called
    Then it should return empty result sets
    """
    mocker.patch("ServiceNowCMDBEnrichAsset.demisto.args", return_value=mock_demisto_args)
    mocker.patch("ServiceNowCMDBEnrichAsset.get_command_results", return_value=[])
    mock_return = mocker.patch("ServiceNowCMDBEnrichAsset.return_results")

    main()

    assert mock_return.called
    call_args = mock_return.call_args[0][0]
    assert len(call_args.outputs["network_adapters"]) == 0
    assert len(call_args.outputs["related_configuration_items"]) == 0
