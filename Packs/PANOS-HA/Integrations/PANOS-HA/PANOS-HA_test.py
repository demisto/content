"""
Unit tests for PANOS-HA integration.

The panos library is imported at module level in PANOS-HA.py inside a try/except block.
We must inject mock modules into sys.modules BEFORE importing the integration module.
"""
import sys
import importlib
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch, PropertyMock
import pytest

# ---------------------------------------------------------------------------
# 1. Build mock panos module hierarchy and inject into sys.modules
# ---------------------------------------------------------------------------

# Create real exception classes so isinstance checks and raise statements work
class MockPanDeviceError(Exception):
    pass


class MockPanXapiError(Exception):
    pass


# Create a real base class so isinstance(client, Firewall) works
class _MockPanDevice:
    def __init__(self, **kwargs):
        self.hostname = kwargs.get('hostname')
        self.api_key = kwargs.get('api_key')
        self.ssl_verify = kwargs.get('ssl_verify', True)
        self.xapi = MagicMock()

    def add(self, child):
        pass

    def commit(self, sync=False):
        return "commit successful"

    def refresh_system_info(self):
        pass

    def show_highavailability_state(self):
        return None


class _MockFirewall(_MockPanDevice):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vsys = kwargs.get('vsys')


class _MockPanorama(_MockPanDevice):
    pass


class _MockHighAvailability:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.children = []

    def add(self, child):
        self.children.append(child)

    def apply(self):
        pass

    def revert_to_running(self):
        pass


class _MockHA1:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class _MockHA2:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class _MockHA1Backup:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class _MockHA2Backup:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# Build module mocks
mock_panos = MagicMock()
mock_panos_base = MagicMock()
mock_panos_firewall = MagicMock()
mock_panos_panorama = MagicMock()
mock_panos_ha = MagicMock()
mock_panos_errors = MagicMock()

# Wire real classes into mock modules
mock_panos_errors.PanDeviceError = MockPanDeviceError
mock_panos_errors.PanXapiError = MockPanXapiError
mock_panos_base.PanDevice = _MockPanDevice
mock_panos_firewall.Firewall = _MockFirewall
mock_panos_panorama.Panorama = _MockPanorama
mock_panos_ha.HighAvailability = _MockHighAvailability
mock_panos_ha.HA1 = _MockHA1
mock_panos_ha.HA2 = _MockHA2
mock_panos_ha.HA1Backup = _MockHA1Backup
mock_panos_ha.HA2Backup = _MockHA2Backup

# Inject into sys.modules BEFORE importing the integration
sys.modules['panos'] = mock_panos
sys.modules['panos.base'] = mock_panos_base
sys.modules['panos.firewall'] = mock_panos_firewall
sys.modules['panos.panorama'] = mock_panos_panorama
sys.modules['panos.ha'] = mock_panos_ha
sys.modules['panos.errors'] = mock_panos_errors

# ---------------------------------------------------------------------------
# 2. Import the module under test (hyphenated name requires importlib)
# ---------------------------------------------------------------------------
_mod_spec = importlib.util.spec_from_file_location(
    "PANOS_HA",
    __file__.replace("PANOS-HA_test.py", "PANOS-HA.py"),
)
panos_ha_module = importlib.util.module_from_spec(_mod_spec)
_mod_spec.loader.exec_module(panos_ha_module)

# Pull references to functions / constants we will test
get_pan_device = panos_ha_module.get_pan_device
get_available_interfaces = panos_ha_module.get_available_interfaces
validate_interfaces_exist = panos_ha_module.validate_interfaces_exist
get_ha_state_command = panos_ha_module.get_ha_state_command
get_ha_config_command = panos_ha_module.get_ha_config_command
request_ha_failover_command = panos_ha_module.request_ha_failover_command
synchronize_ha_peers_command = panos_ha_module.synchronize_ha_peers_command
panorama_reconfigure_ha_command = panos_ha_module.panorama_reconfigure_ha_command
list_interfaces_command = panos_ha_module.list_interfaces_command
validate_interfaces_command = panos_ha_module.validate_interfaces_command
configure_ha_command = panos_ha_module.configure_ha_command
set_ha_enabled_state = panos_ha_module.set_ha_enabled_state
main = panos_ha_module.main

DEVICE_TYPE_FIREWALL = panos_ha_module.DEVICE_TYPE_FIREWALL
DEVICE_TYPE_PANORAMA = panos_ha_module.DEVICE_TYPE_PANORAMA

# Re-export module-level references used by functions (Firewall, Panorama etc.)
Firewall = panos_ha_module.Firewall
Panorama = panos_ha_module.Panorama


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firewall(**overrides):
    """Create a mock Firewall instance that passes isinstance checks."""
    defaults = dict(hostname='fw1.local', api_key='TESTKEY', vsys='vsys1', ssl_verify=True)
    defaults.update(overrides)
    return Firewall(**defaults)


def _make_panorama(**overrides):
    defaults = dict(hostname='panorama.local', api_key='TESTKEY', ssl_verify=True)
    defaults.update(overrides)
    return Panorama(**defaults)


def _build_ha_state_xml(
    enabled='yes',
    mode='active-passive',
    local_state='active',
    local_priority='100',
    local_serial='0001A',
    local_preemptive='yes',
    peer_state='passive',
    peer_conn='up',
    peer_serial='0002B',
):
    """Build a realistic HA state XML response."""
    xml_str = f"""<response status="success">
  <result>
    <enabled>{enabled}</enabled>
    <groups>
      <group>
        <mode>{mode}</mode>
        <local-info>
          <state>{local_state}</state>
          <priority>{local_priority}</priority>
          <serial-num>{local_serial}</serial-num>
          <preemptive>{local_preemptive}</preemptive>
        </local-info>
        <peer-info>
          <state>{peer_state}</state>
          <conn-status>{peer_conn}</conn-status>
          <serial-num>{peer_serial}</serial-num>
        </peer-info>
      </group>
    </groups>
  </result>
</response>"""
    return ET.fromstring(xml_str)


def _build_interfaces_xml(ethernet_names=None, loopback_names=None,
                          tunnel_names=None, vlan_names=None, ae_names=None):
    """Build XML response for get_available_interfaces."""
    root = ET.Element('response')
    result = ET.SubElement(root, 'result')
    interface = ET.SubElement(result, 'interface')

    if ethernet_names:
        eth = ET.SubElement(interface, 'ethernet')
        for name in ethernet_names:
            entry = ET.SubElement(eth, 'entry')
            entry.set('name', name)

    if ae_names:
        ae = ET.SubElement(interface, 'aggregate-ethernet')
        for name in ae_names:
            entry = ET.SubElement(ae, 'entry')
            entry.set('name', name)

    if loopback_names:
        lo = ET.SubElement(interface, 'loopback')
        for name in loopback_names:
            entry = ET.SubElement(lo, 'entry')
            entry.set('name', name)

    if tunnel_names:
        tun = ET.SubElement(interface, 'tunnel')
        for name in tunnel_names:
            entry = ET.SubElement(tun, 'entry')
            entry.set('name', name)

    if vlan_names:
        vlan = ET.SubElement(interface, 'vlan')
        for name in vlan_names:
            entry = ET.SubElement(vlan, 'entry')
            entry.set('name', name)

    return root


def _build_ha_config_xml(
    enabled='yes', group_id='1', peer_ip='10.0.0.2', peer_ip_backup=None,
    ha1_port='ha1-a', ha1_ip='10.10.0.1', ha1_netmask='255.255.255.0',
    ha2_port='ha2-a', ha2_ip='10.20.0.1', ha2_netmask='255.255.255.0',
    device_priority='100', preemptive='yes',
):
    """Build HA config XML for get_ha_config_command tests."""
    backup_el = f"<peer-ip-backup>{peer_ip_backup}</peer-ip-backup>" if peer_ip_backup else ""
    ha2_block = ""
    if ha2_port:
        ha2_block = f"""<ha2>
              <port>{ha2_port}</port>
              <ip-address>{ha2_ip}</ip-address>
              <netmask>{ha2_netmask}</netmask>
            </ha2>"""

    xml_str = f"""<response status="success">
  <result>
    <high-availability>
      <enabled>{enabled}</enabled>
      <group>
        <group-id>{group_id}</group-id>
        <peer-ip>{peer_ip}</peer-ip>
        {backup_el}
        <mode>
          <active-passive>
            <passive-link-state>auto</passive-link-state>
          </active-passive>
        </mode>
        <configuration-synchronization>
          <enabled>yes</enabled>
        </configuration-synchronization>
        <state-synchronization>
          <enabled>yes</enabled>
        </state-synchronization>
        <election-option>
          <device-priority>{device_priority}</device-priority>
          <preemptive>{preemptive}</preemptive>
          <heartbeat-backup>no</heartbeat-backup>
          <timers><recommended/></timers>
        </election-option>
        <monitoring>
          <link-monitoring><enabled>yes</enabled></link-monitoring>
          <path-monitoring><enabled>no</enabled></path-monitoring>
        </monitoring>
      </group>
      <interface>
        <ha1>
          <port>{ha1_port}</port>
          <ip-address>{ha1_ip}</ip-address>
          <netmask>{ha1_netmask}</netmask>
          <encryption><enabled>no</enabled></encryption>
        </ha1>
        {ha2_block}
      </interface>
    </high-availability>
  </result>
</response>"""
    return ET.fromstring(xml_str)


# ===========================================================================
# Test Classes
# ===========================================================================

class TestGetPanDevice:
    def test_create_firewall(self):
        dev = get_pan_device(DEVICE_TYPE_FIREWALL, 'fw.local', 'KEY', 'vsys1', False)
        assert isinstance(dev, Firewall)
        assert dev.hostname == 'fw.local'

    def test_create_panorama(self):
        dev = get_pan_device(DEVICE_TYPE_PANORAMA, 'pan.local', 'KEY', None, True)
        assert isinstance(dev, Panorama)
        assert dev.hostname == 'pan.local'

    def test_invalid_device_type(self):
        with pytest.raises(ValueError, match="Invalid device type"):
            get_pan_device('Router', 'x', 'y', None, False)


class TestGetAvailableInterfaces:
    def test_with_ethernet_interfaces(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1', 'ethernet1/2'])
        client.xapi.get.return_value = xml_resp

        result = get_available_interfaces(client)
        assert 'ethernet1/1' in result
        assert 'ethernet1/2' in result
        # HA interfaces are always appended
        assert 'ha1-a' in result

    def test_with_mixed_interfaces(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(
            ethernet_names=['ethernet1/1'],
            loopback_names=['1'],
            tunnel_names=['1'],
            vlan_names=['100'],
            ae_names=['ae1'],
        )
        client.xapi.get.return_value = xml_resp

        result = get_available_interfaces(client)
        assert 'ethernet1/1' in result
        assert 'loopback.1' in result
        assert 'tunnel.1' in result
        assert 'vlan.100' in result
        assert 'ae1' in result

    def test_no_interfaces_found(self):
        client = _make_firewall()
        # Return XML with no <interface> element inside <result>
        root = ET.fromstring('<response><result></result></response>')
        client.xapi.get.return_value = root

        result = get_available_interfaces(client)
        assert result == []

    def test_none_response(self):
        client = _make_firewall()
        client.xapi.get.return_value = None

        result = get_available_interfaces(client)
        assert result == []

    def test_api_error(self):
        client = _make_firewall()
        client.xapi.get.side_effect = MockPanDeviceError("connection failed")

        with pytest.raises(Exception, match="Failed to retrieve interface list"):
            get_available_interfaces(client)


class TestValidateInterfacesExist:
    def test_all_valid(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1', 'ethernet1/2'])
        client.xapi.get.return_value = xml_resp

        valid, missing = validate_interfaces_exist(client, ['ethernet1/1', 'ha1-a'])
        assert valid is True
        assert missing == []

    def test_some_missing(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1'])
        client.xapi.get.return_value = xml_resp

        valid, missing = validate_interfaces_exist(client, ['ethernet1/1', 'ethernet1/99'])
        assert valid is False
        assert 'ethernet1/99' in missing

    def test_empty_list(self):
        client = _make_firewall()
        valid, missing = validate_interfaces_exist(client, [])
        assert valid is True
        assert missing == []


class TestGetHaStateCommand:
    def test_active_passive_state(self):
        client = _make_firewall()
        ha_xml = _build_ha_state_xml()

        # Patch Firewall constructor so the temp client returns our XML
        with patch.object(Firewall, 'show_highavailability_state', return_value=ha_xml):
            # The function creates a new Firewall internally; we patch via the class
            result = get_ha_state_command(client, {}, insecure=False)

        assert 'active' in result.readable_output.lower()
        assert result.outputs is not None
        assert result.outputs['local-info']['state'] == 'active'
        assert result.outputs['peer-info']['state'] == 'passive'

    def test_ha_not_configured_tuple(self):
        """When HA is not configured, the response may be a tuple without XML Element."""
        client = _make_firewall()
        tuple_resp = ('success', 'HA is not configured on this device')

        with patch.object(Firewall, 'show_highavailability_state', return_value=tuple_resp):
            result = get_ha_state_command(client, {}, insecure=False)

        assert 'HA is not configured' in result.readable_output

    def test_ha_not_enabled_no_local_info(self):
        """XML response with no local-info should return 'HA Not enabled'."""
        client = _make_firewall()
        xml_str = """<response status="success">
          <result><enabled>no</enabled></result>
        </response>"""
        ha_xml = ET.fromstring(xml_str)

        with patch.object(Firewall, 'show_highavailability_state', return_value=ha_xml):
            result = get_ha_state_command(client, {}, insecure=False)

        assert 'HA Not enabled' in result.readable_output

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            get_ha_state_command(client, {}, insecure=False)

    def test_direct_xml_element(self):
        """Response is a direct ET.Element (not a tuple)."""
        client = _make_firewall()
        ha_xml = _build_ha_state_xml(local_state='passive', peer_state='active')

        with patch.object(Firewall, 'show_highavailability_state', return_value=ha_xml):
            result = get_ha_state_command(client, {}, insecure=False)

        assert result.outputs['local-info']['state'] == 'passive'

    def test_tuple_with_xml_element(self):
        """Response is a tuple where second element is an XML Element."""
        client = _make_firewall()
        ha_xml = _build_ha_state_xml()
        tuple_resp = ('success', ha_xml)

        with patch.object(Firewall, 'show_highavailability_state', return_value=tuple_resp):
            result = get_ha_state_command(client, {}, insecure=False)

        assert result.outputs['local-info']['state'] == 'active'


class TestGetHaConfigCommand:
    def test_full_config(self):
        client = _make_firewall()
        config_xml = _build_ha_config_xml()
        client.xapi.get.return_value = config_xml

        result = get_ha_config_command(client)
        assert 'High Availability Configuration' in result.readable_output
        assert 'ha1-a' in result.readable_output
        assert '10.0.0.2' in result.readable_output

    def test_ha_not_configured(self):
        client = _make_firewall()
        # Response with no high-availability element
        xml_str = '<response status="success"><result></result></response>'
        client.xapi.get.return_value = ET.fromstring(xml_str)

        result = get_ha_config_command(client)
        assert 'not configured' in result.readable_output.lower()

    def test_none_response(self):
        client = _make_firewall()
        client.xapi.get.return_value = None

        result = get_ha_config_command(client)
        assert 'No configuration found' in result.readable_output

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            get_ha_config_command(client)

    def test_api_error(self):
        client = _make_firewall()
        client.xapi.get.side_effect = MockPanDeviceError("API timeout")

        with pytest.raises(Exception, match="API Error"):
            get_ha_config_command(client)


def _patch_firewall_constructor(temp_fw):
    """Context manager that patches the Firewall constructor to return temp_fw
    while keeping Firewall as a valid type for isinstance() checks."""
    original_init = Firewall.__init__

    def patched_init(self, **kwargs):
        # Copy attributes from temp_fw to self
        self.hostname = temp_fw.hostname
        self.api_key = temp_fw.api_key
        self.ssl_verify = temp_fw.ssl_verify
        self.xapi = temp_fw.xapi

    return patch.object(Firewall, '__init__', patched_init)


class TestRequestHaFailoverCommand:
    def _make_temp_fw(self, xapi_return=None, xapi_side_effect=None):
        """Create a mock Firewall with pre-configured xapi."""
        temp_fw = _MockFirewall(hostname='fw1.local', api_key='TESTKEY')
        temp_fw.xapi = MagicMock()
        if xapi_side_effect:
            temp_fw.xapi.op.side_effect = xapi_side_effect
        elif xapi_return is not None:
            temp_fw.xapi.op.return_value = xapi_return
        return temp_fw

    def test_suspend_success(self):
        client = _make_firewall()
        response_xml = ET.fromstring('<response status="success"/>')
        temp_fw = self._make_temp_fw(xapi_return=response_xml)

        with _patch_firewall_constructor(temp_fw):
            result = request_ha_failover_command(client, suspend=True, insecure=False)

        assert 'suspend' in result.readable_output.lower()
        temp_fw.xapi.op.assert_called_once()

    def test_functional_success(self):
        client = _make_firewall()
        response_xml = ET.fromstring('<response status="success"/>')
        temp_fw = self._make_temp_fw(xapi_return=response_xml)

        with _patch_firewall_constructor(temp_fw):
            result = request_ha_failover_command(client, suspend=False, insecure=False)

        assert 'functional' in result.readable_output.lower()

    def test_already_suspended(self):
        client = _make_firewall()
        temp_fw = self._make_temp_fw(xapi_side_effect=MockPanXapiError("already in suspend state"))

        with _patch_firewall_constructor(temp_fw):
            result = request_ha_failover_command(client, suspend=True, insecure=False)

        assert 'already suspended' in result.readable_output.lower()

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            request_ha_failover_command(client, suspend=True, insecure=False)


class TestSynchronizeHaPeersCommand:
    def _make_temp_fw(self, xapi_return=None, xapi_side_effect=None):
        temp_fw = _MockFirewall(hostname='fw1.local', api_key='TESTKEY')
        temp_fw.xapi = MagicMock()
        if xapi_side_effect:
            temp_fw.xapi.op.side_effect = xapi_side_effect
        elif xapi_return is not None:
            temp_fw.xapi.op.return_value = xapi_return
        return temp_fw

    def test_sync_config(self):
        client = _make_firewall()
        response_xml = ET.fromstring('<response status="success"/>')
        temp_fw = self._make_temp_fw(xapi_return=response_xml)

        with _patch_firewall_constructor(temp_fw):
            result = synchronize_ha_peers_command(client, 'config', insecure=False)

        assert 'configuration synchronization' in result.readable_output.lower()

    def test_sync_state(self):
        client = _make_firewall()
        response_xml = ET.fromstring('<response status="success"/>')
        temp_fw = self._make_temp_fw(xapi_return=response_xml)

        with _patch_firewall_constructor(temp_fw):
            result = synchronize_ha_peers_command(client, 'state', insecure=False)

        assert 'state' in result.readable_output.lower()

    def test_sync_api_error(self):
        client = _make_firewall()
        temp_fw = self._make_temp_fw(xapi_side_effect=MockPanXapiError("sync failed"))

        with _patch_firewall_constructor(temp_fw):
            with pytest.raises(Exception, match="Failed to execute HA sync"):
                synchronize_ha_peers_command(client, 'config', insecure=False)

    def test_invalid_sync_type(self):
        client = _make_firewall()
        with pytest.raises(ValueError, match="Invalid sync_type"):
            synchronize_ha_peers_command(client, 'invalid', insecure=False)

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            synchronize_ha_peers_command(client, 'config', insecure=False)


class TestPanoramaReconfigureHaCommand:
    def test_success(self):
        client = _make_panorama()
        result = panorama_reconfigure_ha_command(client)
        assert 'reconfiguration' in result.readable_output.lower()

    def test_non_panorama_raises(self):
        client = _make_firewall()
        with pytest.raises(ValueError, match="only applicable to Panorama"):
            panorama_reconfigure_ha_command(client)

    def test_api_error(self):
        client = _make_panorama()
        # We need the HighAvailability.revert_to_running to raise
        original_revert = _MockHighAvailability.revert_to_running

        def raise_error(self):
            raise MockPanDeviceError("revert failed")

        _MockHighAvailability.revert_to_running = raise_error
        try:
            with pytest.raises(Exception, match="Failed to send HA reconfiguration"):
                panorama_reconfigure_ha_command(client)
        finally:
            _MockHighAvailability.revert_to_running = original_revert


class TestConfigureHaCommand:
    def test_basic_config(self):
        client = _make_firewall()
        # get_available_interfaces is called by validate_interfaces_exist
        # when ha1_port etc. are provided; skip interface validation by not providing ports
        args = {
            'group_id': '1',
            'peer_ip': '10.0.0.2',
            'commit': 'false',
        }
        result = configure_ha_command(client, args)
        assert 'successfully applied' in result.readable_output.lower()

    def test_full_config_with_all_interfaces(self):
        client = _make_firewall()
        # Mock get_available_interfaces to return valid interfaces
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1', 'ethernet1/2'])
        client.xapi.get.return_value = xml_resp

        args = {
            'group_id': '1',
            'peer_ip': '10.0.0.2',
            'ha1_port': 'ha1-a',
            'ha1_ip_address': '10.10.0.1',
            'ha1_netmask': '255.255.255.0',
            'ha1_backup_port': 'ha1-b',
            'ha1_backup_ip_address': '10.10.1.1',
            'ha1_backup_netmask': '255.255.255.0',
            'ha2_port': 'ha2-a',
            'ha2_ip_address': '10.20.0.1',
            'ha2_netmask': '255.255.255.0',
            'ha2_backup_port': 'ha2-b',
            'ha2_backup_ip_address': '10.20.1.1',
            'ha2_backup_netmask': '255.255.255.0',
            'commit': 'false',
        }
        result = configure_ha_command(client, args)
        assert 'successfully applied' in result.readable_output.lower()

    def test_with_commit(self):
        client = _make_firewall()
        # Patch client.commit to verify it gets called
        client.commit = MagicMock(return_value="Commit OK")
        args = {
            'group_id': '1',
            'peer_ip': '10.0.0.2',
            'commit': 'true',
        }
        result = configure_ha_command(client, args)
        client.commit.assert_called_once_with(sync=True)
        assert 'commit successful' in result.readable_output.lower() or 'commit ok' in result.readable_output.lower()

    def test_without_commit(self):
        client = _make_firewall()
        client.commit = MagicMock()
        args = {
            'group_id': '1',
            'peer_ip': '10.0.0.2',
            'commit': 'false',
        }
        result = configure_ha_command(client, args)
        client.commit.assert_not_called()

    def test_invalid_interface_raises(self):
        client = _make_firewall()
        # Return XML with only ethernet1/1 so 'nonexistent_port' is missing
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1'])
        client.xapi.get.return_value = xml_resp

        args = {
            'group_id': '1',
            'peer_ip': '10.0.0.2',
            'ha1_port': 'nonexistent_port',
            'ha1_ip_address': '10.10.0.1',
            'ha1_netmask': '255.255.255.0',
            'commit': 'false',
        }
        with pytest.raises(Exception, match="Interface Validation Error|do not exist"):
            configure_ha_command(client, args)

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            configure_ha_command(client, {'group_id': '1', 'peer_ip': '10.0.0.2'})


class TestSetHaEnabledState:
    def test_enable_ha(self):
        client = _make_firewall()
        args = {'commit': 'false'}
        result = set_ha_enabled_state(client, args, enabled=True)
        # Verify xapi.edit was called with enabled=yes
        client.xapi.edit.assert_called_once()
        call_kwargs = client.xapi.edit.call_args
        assert '<enabled>yes</enabled>' in call_kwargs.kwargs.get('element', call_kwargs[1].get('element', ''))

    def test_disable_ha(self):
        client = _make_firewall()
        args = {'commit': 'false'}
        result = set_ha_enabled_state(client, args, enabled=False)
        call_kwargs = client.xapi.edit.call_args
        assert '<enabled>no</enabled>' in call_kwargs.kwargs.get('element', call_kwargs[1].get('element', ''))

    def test_with_commit(self):
        client = _make_firewall()
        client.commit = MagicMock(return_value="Commit OK")
        args = {'commit': 'true'}
        result = set_ha_enabled_state(client, args, enabled=True)
        client.commit.assert_called_once_with(sync=True)

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            set_ha_enabled_state(client, {}, enabled=True)

    def test_api_error(self):
        client = _make_firewall()
        client.xapi.edit.side_effect = MockPanDeviceError("edit failed")

        with pytest.raises(Exception, match="Failed to"):
            set_ha_enabled_state(client, {'commit': 'false'}, enabled=True)


class TestListInterfacesCommand:
    def test_with_interfaces(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(
            ethernet_names=['ethernet1/1', 'ethernet1/2'],
            loopback_names=['1'],
        )
        client.xapi.get.return_value = xml_resp

        result = list_interfaces_command(client)
        assert 'ethernet1/1' in result.readable_output
        assert 'Ethernet' in result.readable_output
        assert result.outputs['InterfaceCount'] > 0

    def test_no_interfaces(self):
        client = _make_firewall()
        root = ET.fromstring('<response><result></result></response>')
        client.xapi.get.return_value = root

        result = list_interfaces_command(client)
        assert 'No interfaces found' in result.readable_output

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            list_interfaces_command(client)


class TestValidateInterfacesCommand:
    def test_all_valid(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1', 'ethernet1/2'])
        client.xapi.get.return_value = xml_resp

        args = {'interfaces': 'ethernet1/1,ha1-a'}
        result = validate_interfaces_command(client, args)
        assert 'validated successfully' in result.readable_output.lower()
        assert result.outputs['AllValid'] is True

    def test_some_missing(self):
        client = _make_firewall()
        xml_resp = _build_interfaces_xml(ethernet_names=['ethernet1/1'])
        client.xapi.get.return_value = xml_resp

        args = {'interfaces': 'ethernet1/1,ethernet1/99'}
        result = validate_interfaces_command(client, args)
        assert 'Not Found' in result.readable_output
        assert result.outputs['AllValid'] is False
        assert 'ethernet1/99' in result.outputs['MissingInterfaces']

    def test_missing_arg(self):
        client = _make_firewall()
        with pytest.raises(ValueError, match="interfaces.*required"):
            validate_interfaces_command(client, {})

    def test_non_firewall_raises(self):
        client = _make_panorama()
        with pytest.raises(ValueError, match="only applicable to Firewalls"):
            validate_interfaces_command(client, {'interfaces': 'ha1-a'})


class TestMain:
    @patch.object(panos_ha_module.demisto, 'command', return_value='test-module')
    @patch.object(panos_ha_module.demisto, 'params', return_value={
        'hostname': 'fw.local',
        'api_key': {'password': 'KEY'},
        'device_type': 'Firewall',
        'insecure': False,
        'vsys': 'vsys1',
    })
    @patch.object(panos_ha_module.demisto, 'args', return_value={})
    @patch.object(panos_ha_module, 'return_results')
    def test_test_module(self, mock_return, mock_args, mock_params, mock_cmd):
        main()
        mock_return.assert_called_once_with('ok')

    @patch.object(panos_ha_module.demisto, 'command', return_value='unknown-command')
    @patch.object(panos_ha_module.demisto, 'params', return_value={
        'hostname': 'fw.local',
        'api_key': 'KEY',
        'device_type': 'Firewall',
        'insecure': False,
    })
    @patch.object(panos_ha_module.demisto, 'args', return_value={})
    @patch.object(panos_ha_module, 'return_error')
    def test_unknown_command(self, mock_return_error, mock_args, mock_params, mock_cmd):
        main()
        mock_return_error.assert_called_once()
        assert 'not implemented' in mock_return_error.call_args[0][0].lower()

    @patch.object(panos_ha_module.demisto, 'command', return_value='test-module')
    @patch.object(panos_ha_module.demisto, 'params', return_value={
        'hostname': '',
        'api_key': '',
        'device_type': 'Firewall',
    })
    @patch.object(panos_ha_module.demisto, 'args', return_value={})
    @patch.object(panos_ha_module, 'return_error')
    def test_missing_credentials(self, mock_return_error, mock_args, mock_params, mock_cmd):
        main()
        mock_return_error.assert_called_once()
        assert 'must be provided' in mock_return_error.call_args[0][0].lower()
