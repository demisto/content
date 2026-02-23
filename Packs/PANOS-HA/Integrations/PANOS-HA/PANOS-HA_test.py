import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import xml.etree.ElementTree as ET
from importlib import import_module
from unittest.mock import MagicMock

mod = import_module("PANOS-HA")


@pytest.fixture(autouse=True)
def mock_demisto_debug(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")


class TestGetPanDevice:
    """Tests for get_pan_device function."""

    def test_firewall_device(self, mocker):
        mock_fw_class = mocker.patch.object(mod, "Firewall")
        mock_fw_class.return_value = MagicMock()
        result = mod.get_pan_device("Firewall", "10.0.0.1", "key", "vsys1", False)
        mock_fw_class.assert_called_once_with(
            hostname="10.0.0.1",
            api_key="key",
            vsys="vsys1",
            ssl_verify=True,
        )
        assert result is not None

    def test_panorama_device(self, mocker):
        mock_pan_class = mocker.patch.object(mod, "Panorama")
        mock_pan_class.return_value = MagicMock()
        result = mod.get_pan_device("Panorama", "10.0.0.2", "key", None, True)
        mock_pan_class.assert_called_once_with(
            hostname="10.0.0.2",
            api_key="key",
            ssl_verify=False,
        )
        assert result is not None

    def test_invalid_device_type(self):
        with pytest.raises(ValueError, match="Invalid device type"):
            mod.get_pan_device("InvalidType", "10.0.0.1", "key", None, False)


class TestGetHaStateCommand:
    """Tests for get_ha_state_command function."""

    def test_ha_state_active_passive(self):
        xml_str = """<response status="success">
            <result>
                <enabled>yes</enabled>
                <group>
                    <mode>active-passive</mode>
                    <local-info>
                        <state>active</state>
                        <priority>100</priority>
                        <serial-num>001122334455</serial-num>
                        <preemptive>yes</preemptive>
                    </local-info>
                    <peer-info>
                        <state>passive</state>
                        <conn-status>up</conn-status>
                        <serial-num>556677889900</serial-num>
                    </peer-info>
                </group>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.show_highavailability_state.return_value = xml_element

        result = mod.get_ha_state_command(client, {})

        assert "active" in result.readable_output.lower()
        assert result.outputs is not None
        assert result.outputs["enabled"] == "yes"
        assert result.outputs["LocalState"] == "active"
        assert result.outputs["PeerState"] == "passive"
        assert result.outputs["PeerConnStatus"] == "up"

    def test_ha_not_enabled(self):
        xml_str = """<response status="success">
            <result>
                <enabled>no</enabled>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.show_highavailability_state.return_value = xml_element

        result = mod.get_ha_state_command(client, {})
        assert "not enabled" in result.readable_output.lower()

    def test_ha_state_tuple_response(self):
        xml_str = """<response status="success">
            <result>
                <enabled>yes</enabled>
                <group>
                    <mode>active-passive</mode>
                    <local-info>
                        <state>passive</state>
                        <priority>50</priority>
                        <serial-num>AABBCCDDEE</serial-num>
                        <preemptive>no</preemptive>
                    </local-info>
                    <peer-info>
                        <state>active</state>
                        <conn-status>up</conn-status>
                        <serial-num>EEDDCCBBAA</serial-num>
                    </peer-info>
                </group>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.show_highavailability_state.return_value = (True, xml_element)

        result = mod.get_ha_state_command(client, {})
        assert result.outputs is not None
        assert result.outputs["LocalState"] == "passive"

    def test_ha_state_not_firewall(self):
        from panos.panorama import Panorama

        client = MagicMock(spec=Panorama)

        with pytest.raises(ValueError, match="only applicable"):
            mod.get_ha_state_command(client, {})


class TestGetHaConfigCommand:
    """Tests for get_ha_config_command function."""

    def test_ha_config_basic(self):
        xml_str = """<response status="success">
            <result>
                <high-availability>
                    <enabled>yes</enabled>
                    <group>
                        <group-id>1</group-id>
                        <mode>
                            <active-passive>
                                <passive-link-state>auto
                                </passive-link-state>
                            </active-passive>
                        </mode>
                        <peer-ip>192.168.1.2</peer-ip>
                        <configuration-synchronization>
                            <enabled>yes</enabled>
                        </configuration-synchronization>
                        <state-synchronization>
                            <enabled>yes</enabled>
                        </state-synchronization>
                        <election-option>
                            <device-priority>100</device-priority>
                            <preemptive>yes</preemptive>
                            <heartbeat-backup>no
                            </heartbeat-backup>
                        </election-option>
                    </group>
                    <interface>
                        <ha1>
                            <port>ha1-a</port>
                            <ip-address>192.168.26.1</ip-address>
                            <netmask>255.255.255.252</netmask>
                        </ha1>
                        <ha2>
                            <port>ha2-a</port>
                            <ip-address>192.168.27.1</ip-address>
                            <netmask>255.255.255.252</netmask>
                        </ha2>
                    </interface>
                </high-availability>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_ha_config_command(client)
        assert result.readable_output is not None
        assert result.outputs is not None
        assert result.outputs["enabled"] == "yes"
        assert result.outputs["GroupId"] == "1"
        assert result.outputs["PeerIp"] == "192.168.1.2"
        assert result.outputs["Ha1Port"] == "ha1-a"
        assert result.outputs["Ha2Port"] == "ha2-a"

    def test_ha_not_configured(self):
        xml_str = """<response status="success">
            <result/>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_ha_config_command(client)
        assert "not configured" in result.readable_output.lower()


class TestRequestHaFailoverCommand:
    """Tests for request_ha_failover_command function."""

    def test_suspend_peer(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.request_ha_failover_command(client, suspend=True)
        assert "suspend" in result.readable_output.lower()
        client.xapi.op.assert_called_once()

    def test_make_functional(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.request_ha_failover_command(client, suspend=False)
        assert "functional" in result.readable_output.lower()
        client.xapi.op.assert_called_once()


class TestSynchronizeHaPeersCommand:
    """Tests for synchronize_ha_peers_command function."""

    def test_sync_config(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.synchronize_ha_peers_command(client, "config")
        assert "configuration" in result.readable_output.lower()
        client.xapi.op.assert_called_once()

    def test_sync_state(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.synchronize_ha_peers_command(client, "state")
        assert "state" in result.readable_output.lower()
        client.xapi.op.assert_called_once()

    def test_invalid_sync_type(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        with pytest.raises(ValueError, match="Invalid sync_type"):
            mod.synchronize_ha_peers_command(client, "invalid")


class TestListInterfacesCommand:
    """Tests for list_interfaces_command function."""

    def test_list_interfaces(self, mocker):
        mocker.patch.object(
            mod,
            "get_available_interfaces",
            return_value=[
                "ethernet1/1",
                "ethernet1/2",
                "ha1-a",
                "ha2-a",
            ],
        )

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        result = mod.list_interfaces_command(client)
        assert result.outputs is not None
        assert result.outputs["InterfaceCount"] == 4
        assert "ethernet1/1" in result.outputs["Interfaces"]

    def test_no_interfaces(self, mocker):
        mocker.patch.object(
            mod,
            "get_available_interfaces",
            return_value=[],
        )

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        result = mod.list_interfaces_command(client)
        assert "no interfaces" in result.readable_output.lower()


class TestValidateInterfacesCommand:
    """Tests for validate_interfaces_command function."""

    def test_all_valid(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(True, []),
        )

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        args = {"interfaces": "ha1-a,ha2-a"}
        result = mod.validate_interfaces_command(client, args)
        assert result.outputs["AllValid"] is True
        assert result.outputs["MissingInterfaces"] == []

    def test_missing_interfaces(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(False, ["ha3"]),
        )

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        args = {"interfaces": "ha1-a,ha3"}
        result = mod.validate_interfaces_command(client, args)
        assert result.outputs["AllValid"] is False
        assert "ha3" in result.outputs["MissingInterfaces"]

    def test_empty_interfaces(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)

        with pytest.raises(ValueError, match="required"):
            mod.validate_interfaces_command(client, {"interfaces": ""})


class TestSetHaEnabledState:
    """Tests for set_ha_enabled_state function."""

    def test_enable_ha(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.set_ha_enabled_state(client, {"commit": "false"}, enabled=True)
        assert "enabled" in result.readable_output.lower()
        client.xapi.edit.assert_called_once()

    def test_disable_ha(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        result = mod.set_ha_enabled_state(client, {"commit": "false"}, enabled=False)
        assert "disabled" in result.readable_output.lower()

    def test_enable_with_commit(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()
        client.commit.return_value = "Commit OK"

        result = mod.set_ha_enabled_state(client, {"commit": "true"}, enabled=True)
        assert "commit" in result.readable_output.lower()
        client.commit.assert_called_once_with(sync=True)


class TestPanoramaReconfigureHaCommand:
    """Tests for panorama_reconfigure_ha_command function."""

    def test_panorama_reconfigure(self, mocker):
        mock_ha = MagicMock()
        mocker.patch.object(mod, "HighAvailability", return_value=mock_ha)

        from panos.panorama import Panorama

        client = MagicMock(spec=Panorama)
        client.hostname = "10.0.0.2"

        result = mod.panorama_reconfigure_ha_command(client)
        assert "panorama" in result.readable_output.lower()
        client.add.assert_called_once_with(mock_ha)
        mock_ha.revert_to_running.assert_called_once()

    def test_not_panorama(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)

        with pytest.raises(ValueError, match="Panorama"):
            mod.panorama_reconfigure_ha_command(client)


class TestGetAvailableInterfaces:
    """Tests for get_available_interfaces function."""

    def test_returns_all_interface_types(self):
        xml_str = """<response status="success">
            <result>
                <interface>
                    <ethernet>
                        <entry name="ethernet1/1"/>
                        <entry name="ethernet1/2"/>
                    </ethernet>
                    <aggregate-ethernet>
                        <entry name="ae1"/>
                    </aggregate-ethernet>
                    <loopback>
                        <entry name="1"/>
                    </loopback>
                    <tunnel>
                        <entry name="1"/>
                    </tunnel>
                    <vlan>
                        <entry name="100"/>
                    </vlan>
                </interface>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_available_interfaces(client)
        assert "ethernet1/1" in result
        assert "ethernet1/2" in result
        assert "ae1" in result
        assert "loopback.1" in result
        assert "tunnel.1" in result
        assert "vlan.100" in result
        assert "ha1-a" in result
        assert "ha2-a" in result

    def test_no_interface_config(self):
        xml_str = """<response status="success">
            <result/>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_available_interfaces(client)
        assert result == []

    def test_none_response(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.xapi = MagicMock()
        client.xapi.get.return_value = None

        result = mod.get_available_interfaces(client)
        assert result == []


class TestValidateInterfacesExist:
    """Tests for validate_interfaces_exist function."""

    def test_all_valid(self, mocker):
        mocker.patch.object(
            mod,
            "get_available_interfaces",
            return_value=["ethernet1/1", "ha1-a", "ha2-a"],
        )
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        all_valid, missing = mod.validate_interfaces_exist(client, ["ha1-a", "ha2-a"])
        assert all_valid is True
        assert missing == []

    def test_missing_interface(self, mocker):
        mocker.patch.object(
            mod,
            "get_available_interfaces",
            return_value=["ethernet1/1", "ha1-a"],
        )
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        all_valid, missing = mod.validate_interfaces_exist(client, ["ha1-a", "ha3"])
        assert all_valid is False
        assert "ha3" in missing

    def test_empty_list(self):
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        all_valid, missing = mod.validate_interfaces_exist(client, [])
        assert all_valid is True
        assert missing == []


class TestConfigureHaCommand:
    """Tests for configure_ha_command function."""

    def test_basic_config(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(True, []),
        )
        mock_ha_class = mocker.patch.object(mod, "HighAvailability")
        mock_ha_instance = MagicMock()
        mock_ha_instance.element_str.return_value = (
            "<entry><group><group-id>1</group-id></group></entry>"
        )
        mock_ha_class.return_value = mock_ha_instance

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        args = {
            "peer_ip": "192.168.1.2",
            "group_id": "1",
            "device_priority": "100",
            "commit": "false",
        }
        result = mod.configure_ha_command(client, args)
        assert "candidate config" in result.readable_output.lower()
        client.xapi.edit.assert_called_once()

    def test_config_with_ha1_ha2(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(True, []),
        )
        mock_ha_class = mocker.patch.object(mod, "HighAvailability")
        mock_ha_instance = MagicMock()
        mock_ha_instance.element_str.return_value = (
            "<entry><group><group-id>1</group-id></group></entry>"
        )
        mock_ha_class.return_value = mock_ha_instance

        mock_ha1 = mocker.patch.object(mod, "HA1")
        mock_ha2 = mocker.patch.object(mod, "HA2")

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        args = {
            "peer_ip": "192.168.1.2",
            "group_id": "1",
            "device_priority": "100",
            "ha1_port": "ha1-a",
            "ha1_ip_address": "192.168.26.1",
            "ha1_netmask": "255.255.255.252",
            "ha2_port": "ha2-a",
            "ha2_ip_address": "192.168.27.1",
            "ha2_netmask": "255.255.255.252",
            "commit": "false",
        }
        result = mod.configure_ha_command(client, args)
        assert "candidate config" in result.readable_output.lower()
        mock_ha1.assert_called_once()
        mock_ha2.assert_called_once()

    def test_config_with_commit(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(True, []),
        )
        mock_ha_class = mocker.patch.object(mod, "HighAvailability")
        mock_ha_instance = MagicMock()
        mock_ha_instance.element_str.return_value = (
            "<entry><group><group-id>1</group-id></group></entry>"
        )
        mock_ha_class.return_value = mock_ha_instance

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()
        client.commit.return_value = "Commit OK"

        args = {
            "peer_ip": "192.168.1.2",
            "commit": "true",
        }
        result = mod.configure_ha_command(client, args)
        assert "commit" in result.readable_output.lower()
        client.commit.assert_called_once_with(sync=True)

    def test_config_missing_interface_fails(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(False, ["ha3"]),
        )
        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"

        args = {
            "peer_ip": "192.168.1.2",
            "ha1_port": "ha3",
        }
        with pytest.raises(DemistoException, match="not found"):
            mod.configure_ha_command(client, args)

    def test_config_not_firewall(self):
        from panos.panorama import Panorama

        client = MagicMock(spec=Panorama)

        with pytest.raises(ValueError, match="only applicable"):
            mod.configure_ha_command(client, {})

    def test_config_with_backup_interfaces(self, mocker):
        mocker.patch.object(
            mod,
            "validate_interfaces_exist",
            return_value=(True, []),
        )
        mock_ha_class = mocker.patch.object(mod, "HighAvailability")
        mock_ha_instance = MagicMock()
        mock_ha_instance.element_str.return_value = (
            "<entry><group><group-id>1</group-id></group></entry>"
        )
        mock_ha_class.return_value = mock_ha_instance

        mock_ha1_backup = mocker.patch.object(mod, "HA1Backup")
        mock_ha2_backup = mocker.patch.object(mod, "HA2Backup")
        mocker.patch.object(mod, "HA1")
        mocker.patch.object(mod, "HA2")

        from panos.firewall import Firewall

        client = MagicMock(spec=Firewall)
        client.hostname = "10.0.0.1"
        client.xapi = MagicMock()

        args = {
            "peer_ip": "192.168.1.2",
            "ha1_port": "ha1-a",
            "ha1_ip_address": "192.168.26.1",
            "ha1_netmask": "255.255.255.252",
            "ha1_backup_port": "ha1-b",
            "ha1_backup_ip_address": "192.168.28.1",
            "ha1_backup_netmask": "255.255.255.252",
            "ha2_port": "ha2-a",
            "ha2_ip_address": "192.168.27.1",
            "ha2_netmask": "255.255.255.252",
            "ha2_backup_port": "ha2-b",
            "ha2_backup_ip_address": "192.168.29.1",
            "ha2_backup_netmask": "255.255.255.252",
            "heartbeat_backup": "true",
            "commit": "false",
        }
        result = mod.configure_ha_command(client, args)
        assert "candidate config" in result.readable_output.lower()
        mock_ha1_backup.assert_called_once()
        mock_ha2_backup.assert_called_once()


class TestMain:
    """Tests for main function."""

    def test_test_module(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "hostname": "10.0.0.1",
                "api_key": {"password": "testkey"},
                "device_type": "Firewall",
                "insecure": False,
                "vsys": "vsys1",
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return = mocker.patch.object(mod, "return_results")
        mock_device = MagicMock()
        mocker.patch.object(mod, "get_pan_device", return_value=mock_device)
        mocker.patch.object(mod, "handle_proxy")

        mod.main()

        mock_device.refresh_system_info.assert_called_once()
        mock_return.assert_called_once_with("ok")

    def test_get_state_command_dispatch(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "hostname": "10.0.0.1",
                "api_key": "testkey",
                "device_type": "Firewall",
                "insecure": False,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="panos-ha-get-state")
        mock_return = mocker.patch.object(mod, "return_results")
        mock_cmd = mocker.patch.object(
            mod, "get_ha_state_command", return_value="result"
        )
        mock_device = MagicMock()
        mocker.patch.object(mod, "get_pan_device", return_value=mock_device)
        mocker.patch.object(mod, "handle_proxy")

        mod.main()

        mock_cmd.assert_called_once()
        mock_return.assert_called_once_with("result")

    def test_unknown_command(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "hostname": "10.0.0.1",
                "api_key": {"password": "testkey"},
                "device_type": "Firewall",
                "insecure": False,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch.object(mod, "return_error")
        mock_device = MagicMock()
        mocker.patch.object(mod, "get_pan_device", return_value=mock_device)
        mocker.patch.object(mod, "handle_proxy")

        mod.main()

        mock_return_error.assert_called_once()
        assert "not implemented" in mock_return_error.call_args[0][0].lower()

    def test_missing_hostname(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "hostname": "",
                "api_key": "testkey",
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return_error = mocker.patch.object(mod, "return_error")
        mocker.patch.object(mod, "handle_proxy")

        mod.main()

        mock_return_error.assert_called_once()
        assert "hostname" in mock_return_error.call_args[0][0].lower()
