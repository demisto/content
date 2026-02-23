import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import xml.etree.ElementTree as ET
from importlib import import_module
from unittest.mock import MagicMock

mod = import_module('PANOS-HA')


@pytest.fixture(autouse=True)
def mock_demisto_debug(mocker):
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'error')


class TestGetPanDevice:
    """Tests for get_pan_device function."""

    def test_firewall_device(self, mocker):
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = MagicMock()
        result = mod.get_pan_device(
            'Firewall', '10.0.0.1', 'key', 'vsys1', False
        )
        mock_fw_class.assert_called_once_with(
            hostname='10.0.0.1', api_key='key',
            vsys='vsys1', ssl_verify=True,
        )
        assert result is not None

    def test_panorama_device(self, mocker):
        mock_pan_class = mocker.patch.object(mod, 'Panorama')
        mock_pan_class.return_value = MagicMock()
        result = mod.get_pan_device(
            'Panorama', '10.0.0.2', 'key', None, True
        )
        mock_pan_class.assert_called_once_with(
            hostname='10.0.0.2', api_key='key',
            ssl_verify=False,
        )
        assert result is not None

    def test_invalid_device_type(self):
        with pytest.raises(ValueError, match="Invalid device type"):
            mod.get_pan_device(
                'InvalidType', '10.0.0.1', 'key', None, False
            )


class TestGetHaStateCommand:
    """Tests for get_ha_state_command function."""

    def test_ha_state_active_passive(self, mocker):
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

        mock_temp_fw = MagicMock()
        mock_temp_fw.show_highavailability_state.return_value = (
            xml_element
        )
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.get_ha_state_command(client, {}, False)

        assert 'active' in result.readable_output.lower()
        assert result.outputs is not None
        assert result.outputs['enabled'] == 'yes'
        assert result.outputs['LocalState'] == 'active'
        assert result.outputs['PeerState'] == 'passive'
        assert result.outputs['PeerConnStatus'] == 'up'

    def test_ha_not_enabled(self, mocker):
        xml_str = """<response status="success">
            <result>
                <enabled>no</enabled>
            </result>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        mock_temp_fw = MagicMock()
        mock_temp_fw.show_highavailability_state.return_value = (
            xml_element
        )
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.get_ha_state_command(client, {}, False)
        assert 'not enabled' in result.readable_output.lower()

    def test_ha_state_tuple_response(self, mocker):
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

        mock_temp_fw = MagicMock()
        mock_temp_fw.show_highavailability_state.return_value = (
            True, xml_element,
        )
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.get_ha_state_command(client, {}, False)
        assert result.outputs is not None
        assert result.outputs['LocalState'] == 'passive'

    def test_ha_state_not_firewall(self):
        from panos.panorama import Panorama
        client = MagicMock(spec=Panorama)

        with pytest.raises(ValueError, match="only applicable"):
            mod.get_ha_state_command(client, {}, False)


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
        client.hostname = '10.0.0.1'
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_ha_config_command(client)
        assert result.readable_output is not None
        assert result.outputs is not None
        assert result.outputs['enabled'] == 'yes'
        assert result.outputs['GroupId'] == '1'
        assert result.outputs['PeerIp'] == '192.168.1.2'
        assert result.outputs['Ha1Port'] == 'ha1-a'
        assert result.outputs['Ha2Port'] == 'ha2-a'

    def test_ha_not_configured(self):
        xml_str = """<response status="success">
            <result/>
        </response>"""
        xml_element = ET.fromstring(xml_str)

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.xapi = MagicMock()
        client.xapi.get.return_value = xml_element

        result = mod.get_ha_config_command(client)
        assert 'not configured' in result.readable_output.lower()


class TestRequestHaFailoverCommand:
    """Tests for request_ha_failover_command function."""

    def test_suspend_peer(self, mocker):
        mock_temp_fw = MagicMock()
        mock_temp_fw.xapi = MagicMock()
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.request_ha_failover_command(
            client, suspend=True, insecure=False
        )
        assert 'suspend' in result.readable_output.lower()

    def test_make_functional(self, mocker):
        mock_temp_fw = MagicMock()
        mock_temp_fw.xapi = MagicMock()
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.request_ha_failover_command(
            client, suspend=False, insecure=False
        )
        assert 'functional' in result.readable_output.lower()


class TestSynchronizeHaPeersCommand:
    """Tests for synchronize_ha_peers_command function."""

    def test_sync_config(self, mocker):
        mock_temp_fw = MagicMock()
        mock_temp_fw.xapi = MagicMock()
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.synchronize_ha_peers_command(
            client, 'config', insecure=False
        )
        assert 'configuration' in result.readable_output.lower()

    def test_sync_state(self, mocker):
        mock_temp_fw = MagicMock()
        mock_temp_fw.xapi = MagicMock()
        mock_fw_class = mocker.patch.object(mod, 'Firewall')
        mock_fw_class.return_value = mock_temp_fw

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        result = mod.synchronize_ha_peers_command(
            client, 'state', insecure=False
        )
        assert 'state' in result.readable_output.lower()

    def test_invalid_sync_type(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.api_key = 'test-key'

        with pytest.raises(ValueError, match="Invalid sync_type"):
            mod.synchronize_ha_peers_command(
                client, 'invalid', insecure=False
            )


class TestListInterfacesCommand:
    """Tests for list_interfaces_command function."""

    def test_list_interfaces(self, mocker):
        mocker.patch.object(
            mod, 'get_available_interfaces',
            return_value=[
                'ethernet1/1', 'ethernet1/2', 'ha1-a', 'ha2-a',
            ],
        )

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'

        result = mod.list_interfaces_command(client)
        assert result.outputs is not None
        assert result.outputs['InterfaceCount'] == 4
        assert 'ethernet1/1' in result.outputs['Interfaces']

    def test_no_interfaces(self, mocker):
        mocker.patch.object(
            mod, 'get_available_interfaces',
            return_value=[],
        )

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'

        result = mod.list_interfaces_command(client)
        assert 'no interfaces' in result.readable_output.lower()


class TestValidateInterfacesCommand:
    """Tests for validate_interfaces_command function."""

    def test_all_valid(self, mocker):
        mocker.patch.object(
            mod, 'validate_interfaces_exist',
            return_value=(True, []),
        )

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'

        args = {'interfaces': 'ha1-a,ha2-a'}
        result = mod.validate_interfaces_command(client, args)
        assert result.outputs['AllValid'] is True
        assert result.outputs['MissingInterfaces'] == []

    def test_missing_interfaces(self, mocker):
        mocker.patch.object(
            mod, 'validate_interfaces_exist',
            return_value=(False, ['ha3']),
        )

        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'

        args = {'interfaces': 'ha1-a,ha3'}
        result = mod.validate_interfaces_command(client, args)
        assert result.outputs['AllValid'] is False
        assert 'ha3' in result.outputs['MissingInterfaces']

    def test_empty_interfaces(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)

        with pytest.raises(ValueError, match="required"):
            mod.validate_interfaces_command(
                client, {'interfaces': ''}
            )


class TestSetHaEnabledState:
    """Tests for set_ha_enabled_state function."""

    def test_enable_ha(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.xapi = MagicMock()

        result = mod.set_ha_enabled_state(
            client, {'commit': 'false'}, enabled=True
        )
        assert 'enabled' in result.readable_output.lower()
        client.xapi.edit.assert_called_once()

    def test_disable_ha(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.xapi = MagicMock()

        result = mod.set_ha_enabled_state(
            client, {'commit': 'false'}, enabled=False
        )
        assert 'disabled' in result.readable_output.lower()

    def test_enable_with_commit(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)
        client.hostname = '10.0.0.1'
        client.xapi = MagicMock()
        client.commit.return_value = 'Commit OK'

        result = mod.set_ha_enabled_state(
            client, {'commit': 'true'}, enabled=True
        )
        assert 'commit' in result.readable_output.lower()
        client.commit.assert_called_once_with(sync=True)


class TestPanoramaReconfigureHaCommand:
    """Tests for panorama_reconfigure_ha_command function."""

    def test_panorama_reconfigure(self, mocker):
        mock_ha = MagicMock()
        mocker.patch.object(
            mod, 'HighAvailability', return_value=mock_ha
        )

        from panos.panorama import Panorama
        client = MagicMock(spec=Panorama)
        client.hostname = '10.0.0.2'

        result = mod.panorama_reconfigure_ha_command(client)
        assert 'panorama' in result.readable_output.lower()
        client.add.assert_called_once_with(mock_ha)
        mock_ha.revert_to_running.assert_called_once()

    def test_not_panorama(self):
        from panos.firewall import Firewall
        client = MagicMock(spec=Firewall)

        with pytest.raises(ValueError, match="Panorama"):
            mod.panorama_reconfigure_ha_command(client)
