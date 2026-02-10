import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Optional, Any
import xml.etree.ElementTree as ET

# PAN-OS-PYTHON IMPORTS
try:
    from panos.base import PanDevice
    from panos.firewall import Firewall
    from panos.panorama import Panorama
    from panos.ha import HighAvailability, HA1, HA2, HA1Backup, HA2Backup
    from panos.errors import PanDeviceError, PanXapiError
except ImportError as e:
    # Make the error message more specific
    raise DemistoException(f"The 'pan-os-python' library is required, but an import failed: {e}. Please check the Docker image.")

# CONSTANTS
DEVICE_TYPE_FIREWALL = 'Firewall'
DEVICE_TYPE_PANORAMA = 'Panorama'
INTEGRATION_NAME = 'PAN-OS HA'

# HELPER FUNCTIONS
def get_pan_device(device_type: str, hostname: str, api_key: str, vsys: Optional[str], insecure: bool) -> PanDevice:
    """
    Initializes and returns a Firewall or Panorama device object.
    Includes vsys context for firewalls and handles SSL verification.
    """
    ssl_verify = not insecure
    if device_type == DEVICE_TYPE_FIREWALL:
        return Firewall(hostname=hostname, api_key=api_key, vsys=vsys, ssl_verify=ssl_verify)
    elif device_type == DEVICE_TYPE_PANORAMA:
        return Panorama(hostname=hostname, api_key=api_key, ssl_verify=ssl_verify)
    else:
        raise ValueError(f"Invalid device type specified: {device_type}. Must be '{DEVICE_TYPE_FIREWALL}' or '{DEVICE_TYPE_PANORAMA}'.")


def get_available_interfaces(client: Firewall) -> list:
    """
    Retrieves a list of all available interfaces on a firewall.
    Returns a list of interface names (e.g., ['ethernet1/1', 'ethernet1/2', 'ha1-a', 'ha1-b']).
    """
    demisto.debug("Fetching available interfaces from firewall.")
    try:
        # Query the network interfaces configuration
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface"
        response = client.xapi.get(xpath=xpath)

        if response is None:
            demisto.debug("No interface configuration found.")
            return []

        interfaces_xml = response.find('./result/interface')
        if interfaces_xml is None:
            demisto.debug("No interfaces found in response.")
            return []

        interface_list = []

        # Parse ethernet interfaces
        for eth_entry in interfaces_xml.findall('./ethernet/entry'):
            if_name = eth_entry.get('name')
            if if_name:
                interface_list.append(if_name)

        # Parse aggregate ethernet interfaces
        for ae_entry in interfaces_xml.findall('./aggregate-ethernet/entry'):
            if_name = ae_entry.get('name')
            if if_name:
                interface_list.append(if_name)

        # Parse loopback interfaces
        for lo_entry in interfaces_xml.findall('./loopback/entry'):
            if_name = lo_entry.get('name')
            if if_name:
                interface_list.append(f"loopback.{if_name}")

        # Parse tunnel interfaces
        for tun_entry in interfaces_xml.findall('./tunnel/entry'):
            if_name = tun_entry.get('name')
            if if_name:
                interface_list.append(f"tunnel.{if_name}")

        # Parse VLAN interfaces
        for vlan_entry in interfaces_xml.findall('./vlan/entry'):
            if_name = vlan_entry.get('name')
            if if_name:
                interface_list.append(f"vlan.{if_name}")

        # Add HA interfaces (these are typically predefined and may not appear in network/interface)
        # Common HA interface names in PAN-OS
        ha_interfaces = ['ha1-a', 'ha1-b', 'ha2-a', 'ha2-b', 'ha3']
        interface_list.extend(ha_interfaces)

        demisto.debug(f"Found {len(interface_list)} interfaces: {interface_list}")
        return interface_list

    except PanDeviceError as e:
        demisto.debug(f"Error retrieving interfaces: {e}")
        raise DemistoException(f"Failed to retrieve interface list: {e}")


def validate_interfaces_exist(client: Firewall, interfaces_to_check: list) -> tuple:
    """
    Validates that specified interfaces exist on the firewall.

    Args:
        client: Firewall object
        interfaces_to_check: List of interface names to validate

    Returns:
        tuple: (bool, list) - (all_valid, missing_interfaces)
               all_valid: True if all interfaces exist, False otherwise
               missing_interfaces: List of interfaces that don't exist
    """
    if not interfaces_to_check:
        return True, []

    demisto.debug(f"Validating interfaces: {interfaces_to_check}")
    available_interfaces = get_available_interfaces(client)

    missing_interfaces = []
    for iface in interfaces_to_check:
        if iface not in available_interfaces:
            missing_interfaces.append(iface)

    all_valid = len(missing_interfaces) == 0

    if all_valid:
        demisto.debug("All interfaces validated successfully.")
    else:
        demisto.debug(f"Validation failed. Missing interfaces: {missing_interfaces}")

    return all_valid, missing_interfaces

# COMMAND FUNCTIONS
def get_ha_state_command(client: PanDevice, args: dict, insecure: bool) -> CommandResults:
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    demisto.debug("Phase 1: Creating temporary, vsys-free client for HA state check.")
    try:
        ssl_verify = not insecure
        temp_fw_client = Firewall(hostname=client.hostname, api_key=client.api_key, ssl_verify=ssl_verify)
        ha_state_response = temp_fw_client.show_highavailability_state()
    except Exception as e:
        raise DemistoException(f"Failed to create temporary client or get HA state: {e}")

    demisto.debug(f"Phase 2: Received response from firewall. Type: {type(ha_state_response)}")

    ha_state_xml = None
    if isinstance(ha_state_response, tuple):
        demisto.debug("Response is a tuple. Checking contents.")
        if len(ha_state_response) > 1 and isinstance(ha_state_response[1], ET.Element):
            demisto.debug("Tuple contains an XML Element. Extracting it for processing.")
            ha_state_xml = ha_state_response[1]
        else:
            reason = ha_state_response[1] if len(ha_state_response) > 1 else "Device is not configured for High Availability."
            demisto.debug(f"Tuple does not contain a valid XML element. Reason: {reason}")
            return CommandResults(readable_output=str(reason))
    elif isinstance(ha_state_response, ET.Element):
        demisto.debug("Response is a direct XML Element.")
        ha_state_xml = ha_state_response

    try:
        raw_xml_string = ET.tostring(ha_state_xml, encoding='unicode')
        demisto.debug(f"Phase 3: Raw XML Response to be parsed:\n{raw_xml_string}")
    except Exception as e:
        demisto.debug(f"Could not convert final response to string for logging. Error: {e}. Raw object: {ha_state_xml!r}")

    if not ha_state_xml or ha_state_xml.tag != 'response' or ha_state_xml.attrib.get('status') != 'success':
        return CommandResults(readable_output="Device did not return a successful HA state response. HA may not be configured.")

    result = ha_state_xml.find('./result')
    if result is None:
        return CommandResults(readable_output="HA state response was successful, but contained no result data.")

    demisto.debug("Phase 4: Starting XML parsing logic...")
    local_info, peer_info, group = None, None, None
    if result.find('.//groups/group/local-info') is not None:
        group = result.find('.//groups/group')
    elif result.find('.//group/local-info') is not None:
        group = result.find('.//group')

    if group is not None:
        local_info = group.find('local-info')
        peer_info = group.find('peer-info')
    else:
        local_info = result.find('local-info')
        peer_info = result.find('peer-info')

    if local_info is None:
        return CommandResults(readable_output="HA Not enabled.")

    mode_element = group.find('mode') if group is not None else result.find('mode')

    readable_info = {
        'Enabled': result.findtext('enabled', 'N/A'),
        'Mode': mode_element.text if mode_element is not None else 'N/A'
    }
    context_data = {
        'enabled': result.findtext('enabled'),
        'mode': mode_element.text if mode_element is not None else None,
        'local-info': {},
        'peer-info': {}
    }

    if local_info is not None:
        readable_info['Local State'] = local_info.findtext('state', 'N/A')
        readable_info['Local Priority'] = local_info.findtext('priority', 'N/A')
        readable_info['Local Serial'] = local_info.findtext('serial-num', 'N/A')
        context_data['local-info'] = {
            'state': local_info.findtext('state'),
            'priority': local_info.findtext('priority'),
            'serial': local_info.findtext('serial-num'),
            'preemptive': local_info.findtext('preemptive')
        }

    if peer_info is not None:
        readable_info['Peer State'] = peer_info.findtext('state', 'N/A')
        readable_info['Peer Connection'] = peer_info.findtext('conn-status', 'N/A')
        readable_info['Peer Serial'] = peer_info.findtext('serial-num', 'N/A')
        context_data['peer-info'] = {
            'state': peer_info.findtext('state'),
            'conn-status': peer_info.findtext('conn-status'),
            'serial': peer_info.findtext('serial-num')
        }

    demisto.debug(f"Phase 5: Final readable_info dictionary before creating markdown: {readable_info}")

    md = f"### High Availability State for {client.hostname}\n"
    md += "|Property|Value|\n|---|---|\n"
    for key, value in readable_info.items():
        md += f"|{key}|{value}|\n"

    demisto.debug(f"Phase 6: Markdown created successfully:\n{md}")

    return CommandResults(
        readable_output=md,
        outputs_prefix=f"{INTEGRATION_NAME}.HAState",
        outputs_key_field="local-info.serial",
        outputs=context_data
    )


def get_ha_config_command(client: PanDevice) -> CommandResults:
    """Retrieves and displays the detailed HA configuration from a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability"
    demisto.debug(f"Phase 1: Retrieving HA configuration with XPath: {xpath}")

    try:
        response = client.xapi.get(xpath=xpath)
        if response is None:
             return CommandResults(readable_output="No configuration found at the specified path.")
        ha_config = response.find('./result/high-availability')
        if ha_config is None:
            return CommandResults(readable_output="High Availability is not configured on this device.")
    except PanDeviceError as e:
        raise DemistoException(f"API Error while fetching HA configuration: {e}")

    demisto.debug(f"Phase 2: Raw XML received:\n{ET.tostring(ha_config, encoding='unicode')}")

    def find_text(el: Optional[ET.Element], path: str, default: str = 'N/A') -> str:
        if el is None:
            return default
        node = el.find(path)
        return node.text if node is not None and node.text is not None else default

    # --- Main Details ---
    group = ha_config.find('group')
    interface = ha_config.find('interface')

    main_details = {
        "Enabled": find_text(ha_config, 'enabled', 'no').capitalize(),
        "Group ID": find_text(group, 'group-id'),
        "Mode": "Active/Passive" if group is not None and group.find('mode/active-passive') is not None else "Active/Active",
        "Passive Link State": find_text(group, 'mode/active-passive/passive-link-state'),
        "Config Sync Enabled": find_text(group, 'configuration-synchronization/enabled', 'no').capitalize(),
        "State Sync Enabled": find_text(group, 'state-synchronization/enabled', 'no').capitalize(),
    }

    # --- Peer Information ---
    peer_info = {
        "Primary Peer IP": find_text(group, 'peer-ip'),
        "Backup Peer IP": find_text(group, 'peer-ip-backup'),
    }

    # --- Election Settings ---
    election_settings = {
        "Device Priority": find_text(group, 'election-option/device-priority'),
        "Preemptive": find_text(group, 'election-option/preemptive', 'no').capitalize(),
        "Heartbeat Backup": find_text(group, 'election-option/heartbeat-backup', 'no').capitalize(),
        "Timers": "Recommended" if group is not None and group.find('election-option/timers/recommended') is not None else "Custom"
    }

    # --- HA1 Interface (Primary Control Link) ---
    ha1_details = {
        "Port": find_text(interface, 'ha1/port'),
        "IP Address": find_text(interface, 'ha1/ip-address'),
        "Netmask": find_text(interface, 'ha1/netmask'),
        "Gateway": find_text(interface, 'ha1/gateway', 'Not configured'),
        "Encryption": find_text(interface, 'ha1/encryption/enabled', 'no').capitalize(),
    }

    # --- HA1-Backup Interface ---
    ha1_backup_details = {
        "Port": find_text(interface, 'ha1-backup/port'),
        "IP Address": find_text(interface, 'ha1-backup/ip-address'),
        "Netmask": find_text(interface, 'ha1-backup/netmask'),
        "Gateway": find_text(interface, 'ha1-backup/gateway', 'Not configured'),
    }

    # --- HA2 Interface (Primary Data Link) ---
    ha2_details = {
        "Port": find_text(interface, 'ha2/port'),
        "IP Address": find_text(interface, 'ha2/ip-address'),
        "Netmask": find_text(interface, 'ha2/netmask'),
    }

    # --- HA2-Backup Interface ---
    ha2_backup_details = {
        "Port": find_text(interface, 'ha2-backup/port'),
        "IP Address": find_text(interface, 'ha2-backup/ip-address'),
        "Netmask": find_text(interface, 'ha2-backup/netmask'),
    }

    # --- Monitoring Settings ---
    monitoring_settings = {
        "Link Monitoring": find_text(group, 'monitoring/link-monitoring/enabled', 'no').capitalize(),
        "Path Monitoring": find_text(group, 'monitoring/path-monitoring/enabled', 'no').capitalize(),
    }

    # --- Build Markdown ---
    md = f"# High Availability Configuration\n"
    md += f"**Device:** {client.hostname}\n\n"

    md += "## 📊 Overview\n"
    md += tableToMarkdown("Main Details", main_details, headers=main_details.keys())

    md += "\n## 🔗 Peer Configuration\n"
    md += tableToMarkdown("Peer Information", peer_info, headers=peer_info.keys())

    md += "\n## ⚡ Election Settings\n"
    md += tableToMarkdown("Election Configuration", election_settings, headers=election_settings.keys())

    md += "\n## 🔌 Interface Configuration\n"

    md += "\n### HA1 - Primary Control Link\n"
    md += tableToMarkdown("HA1 Interface", ha1_details, headers=ha1_details.keys())

    md += "\n### HA1-Backup - Backup Control Link\n"
    if ha1_backup_details["Port"] != "N/A":
        md += tableToMarkdown("HA1-Backup Interface", ha1_backup_details, headers=ha1_backup_details.keys())
    else:
        md += "*Not configured*\n"

    md += "\n### HA2 - Primary Data Link\n"
    if ha2_details["Port"] != "N/A":
        md += tableToMarkdown("HA2 Interface", ha2_details, headers=ha2_details.keys())
    else:
        md += "*Not configured*\n"

    md += "\n### HA2-Backup - Backup Data Link\n"
    if ha2_backup_details["Port"] != "N/A":
        md += tableToMarkdown("HA2-Backup Interface", ha2_backup_details, headers=ha2_backup_details.keys())
    else:
        md += "*Not configured*\n"

    md += "\n## 📡 Monitoring\n"
    md += tableToMarkdown("Monitoring Settings", monitoring_settings, headers=monitoring_settings.keys())

    # --- Link Monitoring Groups ---
    if group is not None:
        link_groups = group.findall('monitoring/link-monitoring/link-group/entry')
        if link_groups:
            md += "\n### Link Monitoring Groups\n"
            for lg in link_groups:
                group_name = lg.get('name', 'Unknown')
                enabled = find_text(lg, 'enabled', 'yes')
                failure_condition = find_text(lg, 'failure-condition', 'any')
                interfaces = lg.findall('interface/member')
                interface_list = [iface.text for iface in interfaces if iface.text]

                status = "✅ Enabled" if enabled.lower() == 'yes' else "❌ Disabled"
                md += f"\n**{group_name}** - {status}\n"
                md += f"- **Failure Condition:** {failure_condition}\n"
                md += f"- **Monitored Interfaces:** {', '.join(interface_list) if interface_list else 'None'}\n"

    return CommandResults(readable_output=md)


def request_ha_failover_command(client: PanDevice, suspend: bool, insecure: bool) -> CommandResults:
    """Suspends or makes functional an HA peer using the reliable xapi.op() method."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    demisto.debug("Phase 1: Determining failover action.")
    action_tag = "suspend" if suspend else "functional"
    cmd_xml = f"<request><high-availability><state><{action_tag}/></state></high-availability></request>"
    demisto.debug(f"Action: {action_tag}. XML command to be sent:\n{cmd_xml}")

    try:
        demisto.debug("Phase 2: Creating temporary, vsys-free client for HA operational command.")
        ssl_verify = not insecure
        temp_fw_client = Firewall(hostname=client.hostname, api_key=client.api_key, ssl_verify=ssl_verify)

        demisto.debug("Phase 3: Sending command via low-level client.xapi.op() method.")
        response = temp_fw_client.xapi.op(cmd=cmd_xml)
        demisto.debug(f"Phase 4: Command sent successfully. Response: {ET.tostring(response, encoding='unicode')}")

        message = f"Successfully requested HA peer to become '{action_tag}' on {client.hostname}."
        return CommandResults(readable_output=message)
    except PanXapiError as e:
        demisto.debug(f"Caught PanXapiError: {e}")
        error_message = str(e)
        if "already in suspend state" in error_message and suspend:
             return CommandResults(readable_output=f"Device {client.hostname} is already suspended.")
        elif "Cannot make this firewall active" in error_message and not suspend:
             return CommandResults(readable_output=f"Device {client.hostname} cannot be made active. It may already be active or in a non-functional state.")
        raise DemistoException(f"Failed to execute HA state change command: {e}")
    except Exception as e:
        demisto.debug(f"Caught unexpected exception: {e}")
        raise DemistoException(f"An unexpected error occurred: {e}")


def synchronize_ha_peers_command(client: PanDevice, sync_type: str, insecure: bool) -> CommandResults:
    """Synchronizes configuration or state between HA peers using the reliable xapi.op() method."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    demisto.debug("Phase 1: Determining sync type.")
    if sync_type == 'config':
        sync_tag = "running-config"
        message = f"Successfully initiated configuration synchronization from {client.hostname}."
    elif sync_type == 'state':
        sync_tag = "state"
        message = f"Successfully initiated state (session) synchronization from {client.hostname}."
    else:
        raise ValueError("Invalid sync_type. Must be 'config' or 'state'.")

    # Corrected XML structure for sync operations
    cmd_xml = f"<request><high-availability><sync><to-peer><{sync_tag}/></to-peer></sync></high-availability></request>"
    demisto.debug(f"Sync type: {sync_type}. XML command to be sent:\n{cmd_xml}")

    try:
        demisto.debug("Phase 2: Creating temporary, vsys-free client for HA sync command.")
        ssl_verify = not insecure
        temp_fw_client = Firewall(hostname=client.hostname, api_key=client.api_key, ssl_verify=ssl_verify)

        demisto.debug("Phase 3: Sending sync request via low-level client.xapi.op() method.")
        response = temp_fw_client.xapi.op(cmd=cmd_xml)
        demisto.debug(f"Phase 4: Command sent successfully. Response: {ET.tostring(response, encoding='unicode')}")

        return CommandResults(readable_output=message)
    except PanXapiError as e:
        demisto.debug(f"Caught PanXapiError during sync: {e}")
        raise DemistoException(f"Failed to execute HA sync command: {e}")
    except Exception as e:
        demisto.debug(f"Caught unexpected exception during sync: {e}")
        raise DemistoException(f"An unexpected error occurred during sync: {e}")


def panorama_reconfigure_ha_command(client: PanDevice) -> CommandResults:
    if not isinstance(client, Panorama):
        raise ValueError("This command is only applicable to Panorama devices.")
    ha_config = HighAvailability()
    client.add(ha_config)
    try:
        ha_config.revert_to_running()
        message = f"Successfully sent HA reconfiguration (revert to running) command to Panorama at {client.hostname}."
    except PanDeviceError as e:
        raise DemistoException(f"Failed to send HA reconfiguration command to Panorama: {e}")
    return CommandResults(readable_output=message)


def list_interfaces_command(client: PanDevice) -> CommandResults:
    """Lists all available interfaces on a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    demisto.debug("Executing list-interfaces command.")
    interfaces = get_available_interfaces(client)

    if not interfaces:
        return CommandResults(readable_output="No interfaces found on this device.")

    md = f"### Available Interfaces on {client.hostname}\n"
    md += f"Total interfaces found: {len(interfaces)}\n\n"
    md += "|Interface Name|Type|\n|---|---|\n"

    for iface in sorted(interfaces):
        if iface.startswith('ethernet'):
            iface_type = 'Ethernet'
        elif iface.startswith('ae'):
            iface_type = 'Aggregate Ethernet'
        elif iface.startswith('ha'):
            iface_type = 'HA Control/Data'
        elif iface.startswith('loopback'):
            iface_type = 'Loopback'
        elif iface.startswith('tunnel'):
            iface_type = 'Tunnel'
        elif iface.startswith('vlan'):
            iface_type = 'VLAN'
        else:
            iface_type = 'Other'

        md += f"|{iface}|{iface_type}|\n"

    context_data = {
        'Hostname': client.hostname,
        'InterfaceCount': len(interfaces),
        'Interfaces': interfaces
    }

    return CommandResults(
        readable_output=md,
        outputs_prefix='PANOS-HA.AvailableInterfaces',
        outputs_key_field='Hostname',
        outputs=context_data
    )


def validate_interfaces_command(client: PanDevice, args: dict) -> CommandResults:
    """Validates that specified interfaces exist on the firewall."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    # Get comma-separated list of interfaces to validate
    interfaces_str = args.get('interfaces', '')
    if not interfaces_str:
        raise ValueError("The 'interfaces' argument is required.")

    interfaces_to_check = [iface.strip() for iface in interfaces_str.split(',')]
    demisto.debug(f"Validating interfaces: {interfaces_to_check}")

    all_valid, missing_interfaces = validate_interfaces_exist(client, interfaces_to_check)

    if all_valid:
        md = f"### Interface Validation Result for {client.hostname}\n"
        md += f"✅ **All {len(interfaces_to_check)} interface(s) validated successfully.**\n\n"
        md += "|Interface|Status|\n|---|---|\n"
        for iface in interfaces_to_check:
            md += f"|{iface}|✅ Exists|\n"

        context_data = {
            'Hostname': client.hostname,
            'AllValid': True,
            'ValidatedInterfaces': interfaces_to_check,
            'MissingInterfaces': []
        }
    else:
        md = f"### Interface Validation Result for {client.hostname}\n"
        md += f"❌ **Validation failed. {len(missing_interfaces)} interface(s) not found.**\n\n"
        md += "|Interface|Status|\n|---|---|\n"
        for iface in interfaces_to_check:
            if iface in missing_interfaces:
                md += f"|{iface}|❌ Not Found|\n"
            else:
                md += f"|{iface}|✅ Exists|\n"

        md += f"\n**Missing interfaces:** {', '.join(missing_interfaces)}\n"

        context_data = {
            'Hostname': client.hostname,
            'AllValid': False,
            'ValidatedInterfaces': interfaces_to_check,
            'MissingInterfaces': missing_interfaces
        }

    return CommandResults(
        readable_output=md,
        outputs_prefix='PANOS-HA.InterfaceValidation',
        outputs_key_field='Hostname',
        outputs=context_data
    )


def configure_ha_command(client: PanDevice, args: dict) -> CommandResults:
    """Configures a detailed HA setup on a firewall using the pan-os-python object model."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    demisto.debug("=" * 80)
    demisto.debug("PANOS-HA: Starting HA configuration process")
    demisto.debug("=" * 80)
    demisto.debug(f"Target device: {client.hostname}")
    demisto.debug(f"Received parameters: {', '.join([f'{k}={v}' for k, v in args.items() if v is not None])}")

    demisto.debug("\n--- Phase 1: Validating HA interfaces before configuration ---")

    # Collect all interfaces that will be configured
    interfaces_to_validate = []
    if args.get('ha1_port'):
        interfaces_to_validate.append(args['ha1_port'])
    if args.get('ha1_backup_port'):
        interfaces_to_validate.append(args['ha1_backup_port'])
    if args.get('ha2_port'):
        interfaces_to_validate.append(args['ha2_port'])
    if args.get('ha2_backup_port'):
        interfaces_to_validate.append(args['ha2_backup_port'])

    # CRITICAL: Validate interfaces exist before attempting configuration
    if interfaces_to_validate:
        demisto.debug(f"Validating {len(interfaces_to_validate)} interface(s): {interfaces_to_validate}")
        all_valid, missing_interfaces = validate_interfaces_exist(client, interfaces_to_validate)

        if not all_valid:
            error_msg = f"❌ **HA Configuration Failed: Interface Validation Error**\n\n"
            error_msg += f"The following interface(s) do not exist on {client.hostname}:\n"
            for iface in missing_interfaces:
                error_msg += f"- {iface}\n"
            error_msg += f"\nPlease verify the interface names and ensure they are configured on the device.\n"
            error_msg += f"Use `!panos-ha-list-interfaces` to see all available interfaces."

            raise DemistoException(error_msg)

        demisto.debug("✅ All interfaces validated successfully. Proceeding with HA configuration.")

    demisto.debug("\n--- Phase 2: Building HighAvailability object from arguments ---")

    # Main HA configuration
    group_id = arg_to_number(args.get('group_id', '1'))
    peer_ip = args.get('peer_ip')
    peer_ip_backup = args.get('peer_ip_backup')
    passive_link_state = args.get('passive_link_state', 'auto')
    device_priority = arg_to_number(args.get('device_priority', '100'))

    demisto.debug(f"Creating HighAvailability object:")
    demisto.debug(f"  - enabled=True")
    demisto.debug(f"  - group_id={group_id}")
    demisto.debug(f"  - peer_ip={peer_ip}")
    demisto.debug(f"  - peer_ip_backup={peer_ip_backup if peer_ip_backup else 'Not configured'}")
    demisto.debug(f"  - mode=active-passive")
    demisto.debug(f"  - passive_link_state={passive_link_state}")
    demisto.debug(f"  - device_priority={device_priority}")
    demisto.debug(f"  - config_sync=True")

    ha_config = HighAvailability(
        enabled=True,
        group_id=group_id,
        peer_ip=peer_ip,
        peer_ip_backup=peer_ip_backup,
        mode='active-passive',
        passive_link_state=passive_link_state,
        config_sync=True
    )

    # Set device_priority as a property (not a constructor parameter)
    if device_priority is not None and device_priority != 100:
        try:
            ha_config.device_priority = device_priority
            demisto.debug(f"✅ Device priority set to {device_priority}")
        except Exception as e:
            demisto.debug(f"⚠️ Warning: Could not set device_priority: {e}")

    demisto.debug("✅ HighAvailability base object created successfully.")

    # HA1 Interface
    demisto.debug("\nConfiguring HA1 (Primary Control Link):")
    if all(args.get(k) for k in ['ha1_port', 'ha1_ip_address', 'ha1_netmask']):
        demisto.debug(f"  - port={args['ha1_port']}")
        demisto.debug(f"  - ip_address={args['ha1_ip_address']}")
        demisto.debug(f"  - netmask={args['ha1_netmask']}")
        demisto.debug(f"  - gateway={args.get('ha1_gateway', 'Not configured')}")
        try:
            ha1 = HA1(
                port=args['ha1_port'],
                ip_address=args['ha1_ip_address'],
                netmask=args['ha1_netmask'],
                gateway=args.get('ha1_gateway')
            )
            ha_config.add(ha1)
            demisto.debug("✅ HA1 object created and added successfully.")
        except Exception as e:
            demisto.debug(f"❌ Failed to create HA1 object: {e}")
            raise
    else:
        demisto.debug("⚠️  HA1 parameters incomplete - skipping HA1 configuration.")

    # HA1 Backup Interface
    demisto.debug("\nConfiguring HA1-Backup (Backup Control Link):")
    if all(args.get(k) for k in ['ha1_backup_port', 'ha1_backup_ip_address', 'ha1_backup_netmask']):
        demisto.debug(f"  - port={args['ha1_backup_port']}")
        demisto.debug(f"  - ip_address={args['ha1_backup_ip_address']}")
        demisto.debug(f"  - netmask={args['ha1_backup_netmask']}")
        try:
            ha1_backup = HA1Backup(
                port=args['ha1_backup_port'],
                ip_address=args['ha1_backup_ip_address'],
                netmask=args['ha1_backup_netmask']
            )
            ha_config.add(ha1_backup)
            demisto.debug("✅ HA1-Backup object created and added successfully.")
        except Exception as e:
            demisto.debug(f"❌ Failed to create HA1-Backup object: {e}")
            raise
    else:
        demisto.debug("⚠️  HA1-Backup parameters incomplete - skipping HA1-Backup configuration.")

    # HA2 Interface
    demisto.debug("\nConfiguring HA2 (Primary Data Link):")
    if all(args.get(k) for k in ['ha2_port', 'ha2_ip_address', 'ha2_netmask']):
        demisto.debug(f"  - port={args['ha2_port']}")
        demisto.debug(f"  - ip_address={args['ha2_ip_address']}")
        demisto.debug(f"  - netmask={args['ha2_netmask']}")
        try:
            ha2 = HA2(
                port=args['ha2_port'],
                ip_address=args['ha2_ip_address'],
                netmask=args['ha2_netmask']
            )
            ha_config.add(ha2)
            demisto.debug("✅ HA2 object created and added successfully.")
        except Exception as e:
            demisto.debug(f"❌ Failed to create HA2 object: {e}")
            raise
    else:
        demisto.debug("⚠️  HA2 parameters incomplete - skipping HA2 configuration.")

    # HA2 Backup Interface
    demisto.debug("\nConfiguring HA2-Backup (Backup Data Link):")
    if all(args.get(k) for k in ['ha2_backup_port', 'ha2_backup_ip_address', 'ha2_backup_netmask']):
        demisto.debug(f"  - port={args['ha2_backup_port']}")
        demisto.debug(f"  - ip_address={args['ha2_backup_ip_address']}")
        demisto.debug(f"  - netmask={args['ha2_backup_netmask']}")
        try:
            ha2_backup = HA2Backup(
                port=args['ha2_backup_port'],
                ip_address=args['ha2_backup_ip_address'],
                netmask=args['ha2_backup_netmask']
            )
            ha_config.add(ha2_backup)
            demisto.debug("✅ HA2-Backup object created and added successfully.")
        except Exception as e:
            demisto.debug(f"❌ Failed to create HA2-Backup object: {e}")
            raise
    else:
        demisto.debug("⚠️  HA2-Backup parameters incomplete - skipping HA2-Backup configuration.")

    try:
        demisto.debug("\n--- Phase 3: Applying HA configuration object to the device ---")
        demisto.debug("Adding HA configuration object to client's object tree...")
        # First add the object to the client's object tree
        client.add(ha_config)
        demisto.debug("✅ HA configuration object added to client.")

        demisto.debug("Applying configuration to candidate config...")
        # Then apply the configuration to the candidate config
        ha_config.apply()
        demisto.debug("✅ Configuration successfully written to candidate config.")

        message = "✅ **Configuration successfully applied to candidate config.**"

        if argToBoolean(args.get('commit', 'false')):
            demisto.debug("\n--- Phase 4: Committing configuration ---")
            demisto.debug("Commit flag is true. Initiating commit (this may take 30-60 seconds)...")
            commit_result = str(client.commit(sync=True))
            demisto.debug(f"✅ Commit completed successfully. Result: {commit_result}")
            message += f"\n\n💾 **Commit successful!** The configuration is now active. Details: {commit_result}"
        else:
            demisto.debug("\n--- Phase 4: Commit phase skipped (commit=false) ---")
            demisto.debug("⚠️  Configuration is in candidate mode. Manual commit required.")
            message += "\n\n> **Action Required:** A commit is needed to apply these changes."

        demisto.debug("\n" + "=" * 80)
        demisto.debug("PANOS-HA: Configuration process completed successfully")
        demisto.debug("=" * 80)
        return CommandResults(readable_output=message)
    except PanDeviceError as e:
        demisto.debug(f"\n❌ PAN-OS API Error during configuration: {e}")
        demisto.debug(f"Error type: {type(e).__name__}")
        demisto.debug(f"Error details: {str(e)}")
        raise DemistoException(f"Failed to apply HA configuration: {e}")
    except Exception as e:
        demisto.debug(f"\n❌ Unexpected error during configuration: {e}")
        demisto.debug(f"Error type: {type(e).__name__}")
        demisto.debug(f"Error details: {str(e)}")
        raise


def set_ha_enabled_state(client: PanDevice, args: dict, enabled: bool) -> CommandResults:
    """Enables or disables HA on a firewall using a non-destructive XML edit."""
    if not isinstance(client, Firewall):
        raise ValueError("This command is only applicable to Firewalls.")

    action = "Enabling" if enabled else "Disabling"
    enabled_str = "yes" if enabled else "no"
    demisto.debug(f"Phase 1: Preparing to set HA enabled state to '{enabled_str}'.")

    xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability/enabled"
    element = f"<enabled>{enabled_str}</enabled>"

    try:
        demisto.debug(f"Phase 2: Sending XML edit command to XPath: {xpath}")
        client.xapi.edit(xpath=xpath, element=element)
        demisto.debug("Phase 3: XML edit command sent successfully.")

        status_verb = "Enabled" if enabled else "Disabled"
        message = f"✅ **'{status_verb}' setting successfully applied to candidate config.**"

        if argToBoolean(args.get('commit', 'false')):
            demisto.debug("Commit flag is true. Committing changes.")
            commit_result = str(client.commit(sync=True))
            message += f"\n\n💾 **Commit successful!** The configuration is now active. Details: {commit_result}"
        else:
            message += "\n\n> **Action Required:** A commit is needed to apply these changes."
        return CommandResults(readable_output=message)
    except PanDeviceError as e:
        raise DemistoException(f"Failed to {action.lower()} HA configuration: {e}")


# MAIN FUNCTION
def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    hostname = params.get('hostname')

    api_key_param = params.get('api_key')
    if isinstance(api_key_param, dict):
        api_key = api_key_param.get('password')
    else:
        api_key = api_key_param

    device_type = params.get('device_type', DEVICE_TYPE_FIREWALL)
    insecure = params.get('insecure', False)
    vsys = params.get('vsys') or None

    if not (hostname and api_key):
        return_error("Hostname and API Key must be provided.")

    try:
        client = get_pan_device(device_type, hostname, api_key, vsys, insecure=insecure)

        if command == 'test-module':
            client.refresh_system_info()
            return_results('ok')
        elif command == 'panos-ha-get-state':
            return_results(get_ha_state_command(client, args, insecure))
        elif command == 'panos-ha-get-config':
            return_results(get_ha_config_command(client))
        elif command == 'panos-ha-suspend-peer':
            return_results(request_ha_failover_command(client, suspend=True, insecure=insecure))
        elif command == 'panos-ha-make-peer-functional':
            return_results(request_ha_failover_command(client, suspend=False, insecure=insecure))
        elif command == 'panos-ha-sync-config':
            return_results(synchronize_ha_peers_command(client, 'config', insecure=insecure))
        elif command == 'panos-ha-sync-state':
            return_results(synchronize_ha_peers_command(client, 'state', insecure=insecure))
        elif command == 'panos-panorama-ha-reconfigure':
            return_results(panorama_reconfigure_ha_command(client))
        elif command == 'panos-ha-configure':
            return_results(configure_ha_command(client, args))
        elif command == 'panos-ha-enable':
            return_results(set_ha_enabled_state(client, args, enabled=True))
        elif command == 'panos-ha-disable':
            return_results(set_ha_enabled_state(client, args, enabled=False))
        elif command == 'panos-ha-list-interfaces':
            return_results(list_interfaces_command(client))
        elif command == 'panos-ha-validate-interfaces':
            return_results(validate_interfaces_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
