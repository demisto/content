import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Optional
import xml.etree.ElementTree as ET  # type: ignore[no-redef]

# PAN-OS-PYTHON IMPORTS
try:
    from panos.base import PanDevice
    from panos.firewall import Firewall
    from panos.panorama import Panorama
    from panos.ha import HighAvailability, HA1, HA2, HA1Backup, HA2Backup
    from panos.errors import PanDeviceError, PanXapiError
except ImportError as e:
    raise DemistoException(
        f"The 'pan-os-python' library is required, but an import failed: {e}. "
        "Please check the Docker image."
    )

# CONSTANTS
DEVICE_TYPE_FIREWALL = 'Firewall'
DEVICE_TYPE_PANORAMA = 'Panorama'
INTEGRATION_NAME = 'PANOS-HA'


# HELPER FUNCTIONS
def get_pan_device(
    device_type: str, hostname: str, api_key: str,
    vsys: Optional[str], insecure: bool
) -> PanDevice:
    """Initializes and returns a Firewall or Panorama device object."""
    ssl_verify = not insecure
    if device_type == DEVICE_TYPE_FIREWALL:
        return Firewall(
            hostname=hostname, api_key=api_key,
            vsys=vsys, ssl_verify=ssl_verify
        )
    elif device_type == DEVICE_TYPE_PANORAMA:
        return Panorama(
            hostname=hostname, api_key=api_key,
            ssl_verify=ssl_verify
        )
    else:
        raise ValueError(
            f"Invalid device type specified: {device_type}. "
            f"Must be '{DEVICE_TYPE_FIREWALL}' or "
            f"'{DEVICE_TYPE_PANORAMA}'."
        )


def get_available_interfaces(client: Firewall) -> list:
    """
    Retrieves a list of all available interfaces on a firewall.
    Returns a list of interface names.
    """
    demisto.debug("Fetching available interfaces from firewall.")
    try:
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            "/network/interface"
        )
        response = client.xapi.get(xpath=xpath)

        if response is None:
            demisto.debug("No interface configuration found.")
            return []

        interfaces_xml = response.find('./result/interface')
        if interfaces_xml is None:
            demisto.debug("No interfaces found in response.")
            return []

        interface_list = []

        for eth_entry in interfaces_xml.findall('./ethernet/entry'):
            if_name = eth_entry.get('name')
            if if_name:
                interface_list.append(if_name)

        for ae_entry in interfaces_xml.findall(
            './aggregate-ethernet/entry'
        ):
            if_name = ae_entry.get('name')
            if if_name:
                interface_list.append(if_name)

        for lo_entry in interfaces_xml.findall('./loopback/entry'):
            if_name = lo_entry.get('name')
            if if_name:
                interface_list.append(f"loopback.{if_name}")

        for tun_entry in interfaces_xml.findall('./tunnel/entry'):
            if_name = tun_entry.get('name')
            if if_name:
                interface_list.append(f"tunnel.{if_name}")

        for vlan_entry in interfaces_xml.findall('./vlan/entry'):
            if_name = vlan_entry.get('name')
            if if_name:
                interface_list.append(f"vlan.{if_name}")

        ha_interfaces = [
            'ha1-a', 'ha1-b', 'ha2-a', 'ha2-b', 'ha3'
        ]
        interface_list.extend(ha_interfaces)

        demisto.debug(
            f"Found {len(interface_list)} interfaces: "
            f"{interface_list}"
        )
        return interface_list

    except PanDeviceError as e:
        demisto.debug(f"Error retrieving interfaces: {e}")
        raise DemistoException(
            f"Failed to retrieve interface list: {e}"
        )


def validate_interfaces_exist(
    client: Firewall, interfaces_to_check: list
) -> tuple:
    """
    Validates that specified interfaces exist on the firewall.

    Args:
        client: Firewall object
        interfaces_to_check: List of interface names to validate

    Returns:
        tuple: (all_valid, missing_interfaces)
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
        demisto.debug(
            f"Validation failed. Missing interfaces: "
            f"{missing_interfaces}"
        )

    return all_valid, missing_interfaces


# COMMAND FUNCTIONS
def get_ha_state_command(
    client: PanDevice, args: dict, insecure: bool
) -> CommandResults:
    """Retrieves the current HA state of a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    demisto.debug("Creating temporary client for HA state check.")
    try:
        ssl_verify = not insecure
        temp_fw_client = Firewall(
            hostname=client.hostname,
            api_key=client.api_key,
            ssl_verify=ssl_verify
        )
        ha_state_response = (
            temp_fw_client.show_highavailability_state()
        )
    except Exception as e:
        raise DemistoException(
            f"Failed to create temporary client or get HA state: {e}"
        )

    demisto.debug(
        f"Received response. Type: {type(ha_state_response)}"
    )

    ha_state_xml = None
    if isinstance(ha_state_response, tuple):
        if (
            len(ha_state_response) > 1
            and isinstance(ha_state_response[1], ET.Element)
        ):
            ha_state_xml = ha_state_response[1]
        else:
            reason = (
                ha_state_response[1]
                if len(ha_state_response) > 1
                else "Device is not configured for HA."
            )
            return CommandResults(readable_output=str(reason))
    elif isinstance(ha_state_response, ET.Element):
        ha_state_xml = ha_state_response

    if (
        not ha_state_xml
        or ha_state_xml.tag != 'response'
        or ha_state_xml.attrib.get('status') != 'success'
    ):
        return CommandResults(
            readable_output=(
                "Device did not return a successful HA state "
                "response. HA may not be configured."
            )
        )

    result = ha_state_xml.find('./result')
    if result is None:
        return CommandResults(
            readable_output=(
                "HA state response was successful, "
                "but contained no result data."
            )
        )

    demisto.debug("Starting XML parsing logic...")
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

    mode_element = (
        group.find('mode') if group is not None
        else result.find('mode')
    )

    readable_info = {
        'Enabled': result.findtext('enabled', 'N/A'),
        'Mode': (
            mode_element.text if mode_element is not None
            else 'N/A'
        ),
    }
    context_data = {
        'enabled': result.findtext('enabled'),
        'mode': (
            mode_element.text if mode_element is not None
            else None
        ),
        'LocalState': None,
        'LocalPriority': None,
        'LocalSerial': None,
        'LocalPreemptive': None,
        'PeerState': None,
        'PeerConnStatus': None,
        'PeerSerial': None,
    }

    if local_info is not None:
        readable_info['Local State'] = local_info.findtext(
            'state', 'N/A'
        )
        readable_info['Local Priority'] = local_info.findtext(
            'priority', 'N/A'
        )
        readable_info['Local Serial'] = local_info.findtext(
            'serial-num', 'N/A'
        )
        context_data['LocalState'] = local_info.findtext('state')
        context_data['LocalPriority'] = local_info.findtext(
            'priority'
        )
        context_data['LocalSerial'] = local_info.findtext(
            'serial-num'
        )
        context_data['LocalPreemptive'] = local_info.findtext(
            'preemptive'
        )

    if peer_info is not None:
        readable_info['Peer State'] = peer_info.findtext(
            'state', 'N/A'
        )
        readable_info['Peer Connection'] = peer_info.findtext(
            'conn-status', 'N/A'
        )
        readable_info['Peer Serial'] = peer_info.findtext(
            'serial-num', 'N/A'
        )
        context_data['PeerState'] = peer_info.findtext('state')
        context_data['PeerConnStatus'] = peer_info.findtext(
            'conn-status'
        )
        context_data['PeerSerial'] = peer_info.findtext(
            'serial-num'
        )

    md = tableToMarkdown(
        f"High Availability State for {client.hostname}",
        readable_info,
        headers=list(readable_info.keys()),
    )

    return CommandResults(
        readable_output=md,
        outputs_prefix=f'{INTEGRATION_NAME}.State',
        outputs_key_field='LocalSerial',
        outputs=context_data,
    )


def get_ha_config_command(client: PanDevice) -> CommandResults:
    """Retrieves the detailed HA configuration from a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/deviceconfig/high-availability"
    )
    demisto.debug(f"Retrieving HA configuration with XPath: {xpath}")

    try:
        response = client.xapi.get(xpath=xpath)
        if response is None:
            return CommandResults(
                readable_output=(
                    "No configuration found at the specified path."
                )
            )
        ha_config = response.find('./result/high-availability')
        if ha_config is None:
            return CommandResults(
                readable_output=(
                    "High Availability is not configured "
                    "on this device."
                )
            )
    except PanDeviceError as e:
        raise DemistoException(
            f"API Error while fetching HA configuration: {e}"
        )

    def find_text(
        el: Optional[ET.Element], path: str,
        default: str = 'N/A'
    ) -> str:
        if el is None:
            return default
        node = el.find(path)
        if node is not None and node.text is not None:
            return node.text
        return default

    group = ha_config.find('group')
    interface = ha_config.find('interface')

    main_details = {
        "Enabled": find_text(
            ha_config, 'enabled', 'no'
        ).capitalize(),
        "Group ID": find_text(group, 'group-id'),
        "Mode": (
            "Active/Passive"
            if (
                group is not None
                and group.find('mode/active-passive') is not None
            )
            else "Active/Active"
        ),
        "Passive Link State": find_text(
            group, 'mode/active-passive/passive-link-state'
        ),
        "Config Sync Enabled": find_text(
            group, 'configuration-synchronization/enabled', 'no'
        ).capitalize(),
        "State Sync Enabled": find_text(
            group, 'state-synchronization/enabled', 'no'
        ).capitalize(),
    }

    peer_info = {
        "Primary Peer IP": find_text(group, 'peer-ip'),
        "Backup Peer IP": find_text(group, 'peer-ip-backup'),
    }

    election_settings = {
        "Device Priority": find_text(
            group, 'election-option/device-priority'
        ),
        "Preemptive": find_text(
            group, 'election-option/preemptive', 'no'
        ).capitalize(),
        "Heartbeat Backup": find_text(
            group, 'election-option/heartbeat-backup', 'no'
        ).capitalize(),
    }

    ha1_details = {
        "Port": find_text(interface, 'ha1/port'),
        "IP Address": find_text(interface, 'ha1/ip-address'),
        "Netmask": find_text(interface, 'ha1/netmask'),
        "Gateway": find_text(
            interface, 'ha1/gateway', 'Not configured'
        ),
    }

    ha1_backup_details = {
        "Port": find_text(interface, 'ha1-backup/port'),
        "IP Address": find_text(
            interface, 'ha1-backup/ip-address'
        ),
        "Netmask": find_text(interface, 'ha1-backup/netmask'),
    }

    ha2_details = {
        "Port": find_text(interface, 'ha2/port'),
        "IP Address": find_text(interface, 'ha2/ip-address'),
        "Netmask": find_text(interface, 'ha2/netmask'),
    }

    ha2_backup_details = {
        "Port": find_text(interface, 'ha2-backup/port'),
        "IP Address": find_text(
            interface, 'ha2-backup/ip-address'
        ),
        "Netmask": find_text(interface, 'ha2-backup/netmask'),
    }

    # Build markdown
    md = tableToMarkdown(
        "HA Configuration Overview",
        main_details,
        headers=list(main_details.keys()),
    )
    md += tableToMarkdown(
        "Peer Configuration",
        peer_info,
        headers=list(peer_info.keys()),
    )
    md += tableToMarkdown(
        "Election Settings",
        election_settings,
        headers=list(election_settings.keys()),
    )
    md += tableToMarkdown(
        "HA1 - Primary Control Link",
        ha1_details,
        headers=list(ha1_details.keys()),
    )
    if ha1_backup_details["Port"] != "N/A":
        md += tableToMarkdown(
            "HA1-Backup",
            ha1_backup_details,
            headers=list(ha1_backup_details.keys()),
        )
    if ha2_details["Port"] != "N/A":
        md += tableToMarkdown(
            "HA2 - Primary Data Link",
            ha2_details,
            headers=list(ha2_details.keys()),
        )
    if ha2_backup_details["Port"] != "N/A":
        md += tableToMarkdown(
            "HA2-Backup",
            ha2_backup_details,
            headers=list(ha2_backup_details.keys()),
        )

    # Build link monitoring groups
    link_monitoring_data = []
    if group is not None:
        link_groups = group.findall(
            'monitoring/link-monitoring/link-group/entry'
        )
        for lg in link_groups:
            group_name = lg.get('name', 'Unknown')
            enabled = find_text(lg, 'enabled', 'yes')
            failure_condition = find_text(
                lg, 'failure-condition', 'any'
            )
            interfaces = lg.findall('interface/member')
            interface_list = [
                iface.text for iface in interfaces if iface.text
            ]
            link_monitoring_data.append({
                'Name': group_name,
                'Enabled': enabled,
                'FailureCondition': failure_condition,
                'Interfaces': ', '.join(interface_list),
            })

    if link_monitoring_data:
        md += tableToMarkdown(
            "Link Monitoring Groups",
            link_monitoring_data,
            headers=[
                'Name', 'Enabled', 'FailureCondition',
                'Interfaces',
            ],
        )

    # Build context data matching YAML outputs
    context_data = {
        'enabled': find_text(ha_config, 'enabled', 'no'),
        'GroupId': find_text(group, 'group-id'),
        'mode': main_details["Mode"],
        'PeerIp': find_text(group, 'peer-ip'),
        'PeerIpBackup': find_text(group, 'peer-ip-backup'),
        'Ha1Port': find_text(interface, 'ha1/port'),
        'Ha1Ip': find_text(interface, 'ha1/ip-address'),
        'Ha1BackupPort': find_text(interface, 'ha1-backup/port'),
        'Ha1BackupIp': find_text(
            interface, 'ha1-backup/ip-address'
        ),
        'Ha2Port': find_text(interface, 'ha2/port'),
        'Ha2Ip': find_text(interface, 'ha2/ip-address'),
        'Ha2BackupPort': find_text(interface, 'ha2-backup/port'),
        'Ha2BackupIp': find_text(
            interface, 'ha2-backup/ip-address'
        ),
        'LinkMonitoring': link_monitoring_data or None,
    }

    return CommandResults(
        readable_output=md,
        outputs_prefix=f'{INTEGRATION_NAME}.Config',
        outputs_key_field='GroupId',
        outputs=context_data,
    )


def request_ha_failover_command(
    client: PanDevice, suspend: bool, insecure: bool
) -> CommandResults:
    """Suspends or makes functional an HA peer."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    action_tag = "suspend" if suspend else "functional"
    cmd_xml = (
        f"<request><high-availability><state>"
        f"<{action_tag}/></state></high-availability></request>"
    )
    demisto.debug(f"Action: {action_tag}. Command: {cmd_xml}")

    try:
        ssl_verify = not insecure
        temp_fw_client = Firewall(
            hostname=client.hostname,
            api_key=client.api_key,
            ssl_verify=ssl_verify,
        )
        temp_fw_client.xapi.op(cmd=cmd_xml)

        message = (
            f"Successfully requested HA peer to become "
            f"'{action_tag}' on {client.hostname}."
        )
        return CommandResults(readable_output=message)
    except PanXapiError as e:
        error_message = str(e)
        if "already in suspend state" in error_message and suspend:
            return CommandResults(
                readable_output=(
                    f"Device {client.hostname} is already "
                    "suspended."
                )
            )
        elif (
            "Cannot make this firewall active" in error_message
            and not suspend
        ):
            return CommandResults(
                readable_output=(
                    f"Device {client.hostname} cannot be made "
                    "active. It may already be active."
                )
            )
        raise DemistoException(
            f"Failed to execute HA state change command: {e}"
        )
    except Exception as e:
        raise DemistoException(
            f"An unexpected error occurred: {e}"
        )


def synchronize_ha_peers_command(
    client: PanDevice, sync_type: str, insecure: bool
) -> CommandResults:
    """Synchronizes configuration or state between HA peers."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    if sync_type == 'config':
        sync_tag = "running-config"
        message = (
            "Successfully initiated configuration "
            f"synchronization from {client.hostname}."
        )
    elif sync_type == 'state':
        sync_tag = "state"
        message = (
            "Successfully initiated state (session) "
            f"synchronization from {client.hostname}."
        )
    else:
        raise ValueError(
            "Invalid sync_type. Must be 'config' or 'state'."
        )

    cmd_xml = (
        f"<request><high-availability><sync-to-remote>"
        f"<{sync_tag}/></sync-to-remote>"
        "</high-availability></request>"
    )
    demisto.debug(f"Sync type: {sync_type}. Command: {cmd_xml}")

    try:
        ssl_verify = not insecure
        temp_fw_client = Firewall(
            hostname=client.hostname,
            api_key=client.api_key,
            ssl_verify=ssl_verify,
        )
        temp_fw_client.xapi.op(cmd=cmd_xml)
        return CommandResults(readable_output=message)
    except PanXapiError as e:
        raise DemistoException(
            f"Failed to execute HA sync command: {e}"
        )
    except Exception as e:
        raise DemistoException(
            f"An unexpected error occurred during sync: {e}"
        )


def panorama_reconfigure_ha_command(
    client: PanDevice,
) -> CommandResults:
    """Issues a revert to running HA state command to Panorama."""
    if not isinstance(client, Panorama):
        raise ValueError(
            "This command is only applicable to "
            "Panorama devices."
        )
    ha_config = HighAvailability()
    client.add(ha_config)
    try:
        ha_config.revert_to_running()
        message = (
            "Successfully sent HA reconfiguration command "
            f"to Panorama at {client.hostname}."
        )
    except PanDeviceError as e:
        raise DemistoException(
            "Failed to send HA reconfiguration command "
            f"to Panorama: {e}"
        )
    return CommandResults(readable_output=message)


def list_interfaces_command(client: PanDevice) -> CommandResults:
    """Lists all available interfaces on a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    demisto.debug("Executing list-interfaces command.")
    interfaces = get_available_interfaces(client)

    if not interfaces:
        return CommandResults(
            readable_output="No interfaces found on this device."
        )

    table_data = []
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
        table_data.append({
            'Interface': iface,
            'Type': iface_type,
        })

    md = tableToMarkdown(
        f"Available Interfaces on {client.hostname}",
        table_data,
        headers=['Interface', 'Type'],
    )

    context_data = {
        'Hostname': client.hostname,
        'InterfaceCount': len(interfaces),
        'Interfaces': interfaces,
    }

    return CommandResults(
        readable_output=md,
        outputs_prefix=f'{INTEGRATION_NAME}.AvailableInterfaces',
        outputs_key_field='Hostname',
        outputs=context_data,
    )


def validate_interfaces_command(
    client: PanDevice, args: dict
) -> CommandResults:
    """Validates that specified interfaces exist on the firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    interfaces_to_check = argToList(args.get('interfaces', ''))
    if not interfaces_to_check:
        raise ValueError("The 'interfaces' argument is required.")

    demisto.debug(f"Validating interfaces: {interfaces_to_check}")

    all_valid, missing_interfaces = validate_interfaces_exist(
        client, interfaces_to_check
    )

    table_data = []
    for iface in interfaces_to_check:
        status = (
            'Not Found' if iface in missing_interfaces
            else 'Exists'
        )
        table_data.append({
            'Interface': iface,
            'Status': status,
        })

    if all_valid:
        title = (
            f"Interface Validation - {client.hostname} "
            f"- All {len(interfaces_to_check)} valid"
        )
    else:
        title = (
            f"Interface Validation - {client.hostname} "
            f"- {len(missing_interfaces)} missing"
        )

    md = tableToMarkdown(title, table_data)

    context_data = {
        'Hostname': client.hostname,
        'AllValid': all_valid,
        'ValidatedInterfaces': interfaces_to_check,
        'MissingInterfaces': missing_interfaces,
    }

    return CommandResults(
        readable_output=md,
        outputs_prefix=f'{INTEGRATION_NAME}.InterfaceValidation',
        outputs_key_field='Hostname',
        outputs=context_data,
    )


def configure_ha_command(
    client: PanDevice, args: dict
) -> CommandResults:
    """Configures HA setup on a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    demisto.debug(f"Starting HA configuration on {client.hostname}")

    # Collect and validate interfaces
    interfaces_to_validate = []
    for key in [
        'ha1_port', 'ha1_backup_port',
        'ha2_port', 'ha2_backup_port',
    ]:
        if args.get(key):
            interfaces_to_validate.append(args[key])

    if interfaces_to_validate:
        demisto.debug(
            f"Validating interfaces: {interfaces_to_validate}"
        )
        all_valid, missing_interfaces = validate_interfaces_exist(
            client, interfaces_to_validate
        )
        if not all_valid:
            missing_str = ', '.join(missing_interfaces)
            raise DemistoException(
                "HA Configuration Failed: Interface(s) not found "
                f"on {client.hostname}: {missing_str}. "
                "Use panos-ha-list-interfaces to see available "
                "interfaces."
            )

    # Main HA configuration
    group_id = arg_to_number(args.get('group_id', '1'))
    peer_ip = args.get('peer_ip')
    peer_ip_backup = args.get('peer_ip_backup')
    passive_link_state = args.get('passive_link_state', 'auto')
    device_priority = arg_to_number(
        args.get('device_priority', '100')
    )

    state_sync = argToBoolean(args.get('state_sync', 'false'))
    ha2_keepalive = argToBoolean(
        args.get('ha2_keepalive', 'false')
    )
    ha2_keepalive_threshold = arg_to_number(
        args.get('ha2_keepalive_threshold', '10000')
    )
    ha2_keepalive_action = args.get(
        'ha2_keepalive_action', 'log-only'
    )

    ha_config = HighAvailability(
        enabled=True,
        group_id=group_id,
        peer_ip=peer_ip,
        peer_ip_backup=peer_ip_backup,
        mode='active-passive',
        passive_link_state=passive_link_state,
        config_sync=True,
        state_sync=state_sync,
        ha2_keepalive=ha2_keepalive,
        ha2_keepalive_threshold=(
            ha2_keepalive_threshold if ha2_keepalive else None
        ),
        ha2_keepalive_action=(
            ha2_keepalive_action if ha2_keepalive else None
        ),
    )

    # HA1 Interface
    if all(
        args.get(k)
        for k in ['ha1_port', 'ha1_ip_address', 'ha1_netmask']
    ):
        ha1 = HA1(
            port=args['ha1_port'],
            ip_address=args['ha1_ip_address'],
            netmask=args['ha1_netmask'],
            gateway=args.get('ha1_gateway'),
        )
        ha_config.add(ha1)
        demisto.debug("HA1 configured.")

    # HA1 Backup Interface
    if all(
        args.get(k) for k in [
            'ha1_backup_port', 'ha1_backup_ip_address',
            'ha1_backup_netmask',
        ]
    ):
        ha1_backup = HA1Backup(
            port=args['ha1_backup_port'],
            ip_address=args['ha1_backup_ip_address'],
            netmask=args['ha1_backup_netmask'],
        )
        ha_config.add(ha1_backup)
        demisto.debug("HA1-Backup configured.")

    # HA2 Interface
    if all(
        args.get(k)
        for k in ['ha2_port', 'ha2_ip_address', 'ha2_netmask']
    ):
        ha2 = HA2(
            port=args['ha2_port'],
            ip_address=args['ha2_ip_address'],
            netmask=args['ha2_netmask'],
        )
        ha_config.add(ha2)
        demisto.debug("HA2 configured.")

    # HA2 Backup Interface
    if all(
        args.get(k) for k in [
            'ha2_backup_port', 'ha2_backup_ip_address',
            'ha2_backup_netmask',
        ]
    ):
        ha2_backup = HA2Backup(
            port=args['ha2_backup_port'],
            ip_address=args['ha2_backup_ip_address'],
            netmask=args['ha2_backup_netmask'],
        )
        ha_config.add(ha2_backup)
        demisto.debug("HA2-Backup configured.")

    try:
        client.add(ha_config)

        # Generate XML and inject election settings
        xml_str = ha_config.element_str()
        heartbeat_backup = argToBoolean(
            args.get('heartbeat_backup', 'false')
        )

        if device_priority is not None or heartbeat_backup:
            root = ET.fromstring(xml_str)
            group_el = root.find('.//group')
            if group_el is not None:
                election = group_el.find('election-option')
                if election is None:
                    election = ET.SubElement(
                        group_el, 'election-option'
                    )

                if device_priority is not None:
                    priority_elem = election.find(
                        'device-priority'
                    )
                    if priority_elem is None:
                        priority_elem = ET.SubElement(
                            election, 'device-priority'
                        )
                    priority_elem.text = str(device_priority)

                if heartbeat_backup:
                    hb_elem = election.find('heartbeat-backup')
                    if hb_elem is None:
                        hb_elem = ET.SubElement(
                            election, 'heartbeat-backup'
                        )
                    hb_elem.text = 'yes'

                timers = election.find('timers')
                if timers is None:
                    timers = ET.SubElement(election, 'timers')
                    ET.SubElement(timers, 'recommended')

                xml_str = ET.tostring(root, encoding='unicode')

        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            "/deviceconfig/high-availability"
        )
        client.xapi.edit(xpath=xpath, element=xml_str)
        demisto.debug("Configuration applied to candidate config.")

        message = (
            "Configuration successfully applied to "
            "candidate config."
        )

        if argToBoolean(args.get('commit', 'false')):
            commit_result = str(client.commit(sync=True))
            demisto.debug(f"Commit result: {commit_result}")
            message += (
                f"\nCommit successful. Details: {commit_result}"
            )
        else:
            message += (
                "\nA commit is needed to apply these changes."
            )

        return CommandResults(readable_output=message)
    except PanDeviceError as e:
        raise DemistoException(
            f"Failed to apply HA configuration: {e}"
        )


def set_ha_enabled_state(
    client: PanDevice, args: dict, enabled: bool
) -> CommandResults:
    """Enables or disables HA on a firewall."""
    if not isinstance(client, Firewall):
        raise ValueError(
            "This command is only applicable to Firewalls."
        )

    action = "Enabling" if enabled else "Disabling"
    enabled_str = "yes" if enabled else "no"
    demisto.debug(
        f"{action} HA (setting enabled to '{enabled_str}')."
    )

    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/deviceconfig/high-availability/enabled"
    )
    element = f"<enabled>{enabled_str}</enabled>"

    try:
        client.xapi.edit(xpath=xpath, element=element)

        status_verb = "Enabled" if enabled else "Disabled"
        message = (
            f"'{status_verb}' setting successfully applied "
            "to candidate config."
        )

        if argToBoolean(args.get('commit', 'false')):
            commit_result = str(client.commit(sync=True))
            message += (
                f"\nCommit successful. Details: {commit_result}"
            )
        else:
            message += (
                "\nA commit is needed to apply these changes."
            )
        return CommandResults(readable_output=message)
    except PanDeviceError as e:
        raise DemistoException(
            f"Failed to {action.lower()} HA configuration: {e}"
        )


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

    handle_proxy()

    if not (hostname and api_key):
        return_error("Hostname and API Key must be provided.")
        return

    try:
        client = get_pan_device(
            device_type, hostname, str(api_key), vsys,
            insecure=insecure,
        )

        if command == 'test-module':
            client.refresh_system_info()
            return_results('ok')
        elif command == 'panos-ha-get-state':
            return_results(
                get_ha_state_command(client, args, insecure)
            )
        elif command == 'panos-ha-get-config':
            return_results(get_ha_config_command(client))
        elif command == 'panos-ha-suspend-peer':
            return_results(
                request_ha_failover_command(
                    client, suspend=True, insecure=insecure
                )
            )
        elif command == 'panos-ha-make-peer-functional':
            return_results(
                request_ha_failover_command(
                    client, suspend=False, insecure=insecure
                )
            )
        elif command == 'panos-ha-sync-config':
            return_results(
                synchronize_ha_peers_command(
                    client, 'config', insecure=insecure
                )
            )
        elif command == 'panos-ha-sync-state':
            return_results(
                synchronize_ha_peers_command(
                    client, 'state', insecure=insecure
                )
            )
        elif command == 'panos-panorama-ha-reconfigure':
            return_results(
                panorama_reconfigure_ha_command(client)
            )
        elif command == 'panos-ha-configure':
            return_results(configure_ha_command(client, args))
        elif command == 'panos-ha-enable':
            return_results(
                set_ha_enabled_state(client, args, enabled=True)
            )
        elif command == 'panos-ha-disable':
            return_results(
                set_ha_enabled_state(client, args, enabled=False)
            )
        elif command == 'panos-ha-list-interfaces':
            return_results(list_interfaces_command(client))
        elif command == 'panos-ha-validate-interfaces':
            return_results(
                validate_interfaces_command(client, args)
            )
        else:
            raise NotImplementedError(
                f"Command '{command}' is not implemented."
            )
    except Exception as e:
        return_error(
            f"Failed to execute {command}. Error: {str(e)}"
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
