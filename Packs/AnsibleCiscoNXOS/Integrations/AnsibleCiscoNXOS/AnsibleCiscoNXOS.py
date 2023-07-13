import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import ssh_agent_setup

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'nxos'

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    # Common Inputs
    command = demisto.command()
    args = demisto.args()
    int_params = demisto.params()

    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = generic_ansible('CiscoNXOS', 'nxos_facts', args, int_params, host_type)

            if result:
                return_results('ok')
            else:
                return_results(result)

        elif command == 'nxos-aaa-server':
            return_results(generic_ansible('CiscoNXOS', 'nxos_aaa_server', args, int_params, host_type))
        elif command == 'nxos-aaa-server-host':
            return_results(generic_ansible('CiscoNXOS', 'nxos_aaa_server_host', args, int_params, host_type))
        elif command == 'nxos-acl':
            return_results(generic_ansible('CiscoNXOS', 'nxos_acl', args, int_params, host_type))
        elif command == 'nxos-acl-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_acl_interface', args, int_params, host_type))
        elif command == 'nxos-banner':
            return_results(generic_ansible('CiscoNXOS', 'nxos_banner', args, int_params, host_type))
        elif command == 'nxos-bfd-global':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bfd_global', args, int_params, host_type))
        elif command == 'nxos-bfd-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bfd_interfaces', args, int_params, host_type))
        elif command == 'nxos-bgp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bgp', args, int_params, host_type))
        elif command == 'nxos-bgp-af':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bgp_af', args, int_params, host_type))
        elif command == 'nxos-bgp-neighbor':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bgp_neighbor', args, int_params, host_type))
        elif command == 'nxos-bgp-neighbor-af':
            return_results(generic_ansible('CiscoNXOS', 'nxos_bgp_neighbor_af', args, int_params, host_type))
        elif command == 'nxos-command':
            return_results(generic_ansible('CiscoNXOS', 'nxos_command', args, int_params, host_type))
        elif command == 'nxos-config':
            return_results(generic_ansible('CiscoNXOS', 'nxos_config', args, int_params, host_type))
        elif command == 'nxos-evpn-global':
            return_results(generic_ansible('CiscoNXOS', 'nxos_evpn_global', args, int_params, host_type))
        elif command == 'nxos-evpn-vni':
            return_results(generic_ansible('CiscoNXOS', 'nxos_evpn_vni', args, int_params, host_type))
        elif command == 'nxos-facts':
            return_results(generic_ansible('CiscoNXOS', 'nxos_facts', args, int_params, host_type))
        elif command == 'nxos-feature':
            return_results(generic_ansible('CiscoNXOS', 'nxos_feature', args, int_params, host_type))
        elif command == 'nxos-gir':
            return_results(generic_ansible('CiscoNXOS', 'nxos_gir', args, int_params, host_type))
        elif command == 'nxos-gir-profile-management':
            return_results(generic_ansible('CiscoNXOS', 'nxos_gir_profile_management', args, int_params, host_type))
        elif command == 'nxos-hsrp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_hsrp', args, int_params, host_type))
        elif command == 'nxos-igmp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_igmp', args, int_params, host_type))
        elif command == 'nxos-igmp-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_igmp_interface', args, int_params, host_type))
        elif command == 'nxos-igmp-snooping':
            return_results(generic_ansible('CiscoNXOS', 'nxos_igmp_snooping', args, int_params, host_type))
        elif command == 'nxos-install-os':
            return_results(generic_ansible('CiscoNXOS', 'nxos_install_os', args, int_params, host_type))
        elif command == 'nxos-interface-ospf':
            return_results(generic_ansible('CiscoNXOS', 'nxos_interface_ospf', args, int_params, host_type))
        elif command == 'nxos-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_interfaces', args, int_params, host_type))
        elif command == 'nxos-l2-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_l2_interfaces', args, int_params, host_type))
        elif command == 'nxos-l3-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_l3_interfaces', args, int_params, host_type))
        elif command == 'nxos-lacp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_lacp', args, int_params, host_type))
        elif command == 'nxos-lacp-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_lacp_interfaces', args, int_params, host_type))
        elif command == 'nxos-lag-interfaces':
            return_results(generic_ansible('CiscoNXOS', 'nxos_lag_interfaces', args, int_params, host_type))
        elif command == 'nxos-lldp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_lldp', args, int_params, host_type))
        elif command == 'nxos-lldp-global':
            return_results(generic_ansible('CiscoNXOS', 'nxos_lldp_global', args, int_params, host_type))
        elif command == 'nxos-logging':
            return_results(generic_ansible('CiscoNXOS', 'nxos_logging', args, int_params, host_type))
        elif command == 'nxos-ntp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ntp', args, int_params, host_type))
        elif command == 'nxos-ntp-auth':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ntp_auth', args, int_params, host_type))
        elif command == 'nxos-ntp-options':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ntp_options', args, int_params, host_type))
        elif command == 'nxos-nxapi':
            return_results(generic_ansible('CiscoNXOS', 'nxos_nxapi', args, int_params, host_type))
        elif command == 'nxos-ospf':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ospf', args, int_params, host_type))
        elif command == 'nxos-ospf-vrf':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ospf_vrf', args, int_params, host_type))
        elif command == 'nxos-overlay-global':
            return_results(generic_ansible('CiscoNXOS', 'nxos_overlay_global', args, int_params, host_type))
        elif command == 'nxos-pim':
            return_results(generic_ansible('CiscoNXOS', 'nxos_pim', args, int_params, host_type))
        elif command == 'nxos-pim-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_pim_interface', args, int_params, host_type))
        elif command == 'nxos-pim-rp-address':
            return_results(generic_ansible('CiscoNXOS', 'nxos_pim_rp_address', args, int_params, host_type))
        elif command == 'nxos-ping':
            return_results(generic_ansible('CiscoNXOS', 'nxos_ping', args, int_params, host_type))
        elif command == 'nxos-reboot':
            return_results(generic_ansible('CiscoNXOS', 'nxos_reboot', args, int_params, host_type))
        elif command == 'nxos-rollback':
            return_results(generic_ansible('CiscoNXOS', 'nxos_rollback', args, int_params, host_type))
        elif command == 'nxos-rpm':
            return_results(generic_ansible('CiscoNXOS', 'nxos_rpm', args, int_params, host_type))
        elif command == 'nxos-smu':
            return_results(generic_ansible('CiscoNXOS', 'nxos_smu', args, int_params, host_type))
        elif command == 'nxos-snapshot':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snapshot', args, int_params, host_type))
        elif command == 'nxos-snmp-community':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_community', args, int_params, host_type))
        elif command == 'nxos-snmp-contact':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_contact', args, int_params, host_type))
        elif command == 'nxos-snmp-host':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_host', args, int_params, host_type))
        elif command == 'nxos-snmp-location':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_location', args, int_params, host_type))
        elif command == 'nxos-snmp-traps':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_traps', args, int_params, host_type))
        elif command == 'nxos-snmp-user':
            return_results(generic_ansible('CiscoNXOS', 'nxos_snmp_user', args, int_params, host_type))
        elif command == 'nxos-static-route':
            return_results(generic_ansible('CiscoNXOS', 'nxos_static_route', args, int_params, host_type))
        elif command == 'nxos-system':
            return_results(generic_ansible('CiscoNXOS', 'nxos_system', args, int_params, host_type))
        elif command == 'nxos-telemetry':
            return_results(generic_ansible('CiscoNXOS', 'nxos_telemetry', args, int_params, host_type))
        elif command == 'nxos-udld':
            return_results(generic_ansible('CiscoNXOS', 'nxos_udld', args, int_params, host_type))
        elif command == 'nxos-udld-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_udld_interface', args, int_params, host_type))
        elif command == 'nxos-user':
            return_results(generic_ansible('CiscoNXOS', 'nxos_user', args, int_params, host_type))
        elif command == 'nxos-vlans':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vlans', args, int_params, host_type))
        elif command == 'nxos-vpc':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vpc', args, int_params, host_type))
        elif command == 'nxos-vpc-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vpc_interface', args, int_params, host_type))
        elif command == 'nxos-vrf':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vrf', args, int_params, host_type))
        elif command == 'nxos-vrf-af':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vrf_af', args, int_params, host_type))
        elif command == 'nxos-vrf-interface':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vrf_interface', args, int_params, host_type))
        elif command == 'nxos-vrrp':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vrrp', args, int_params, host_type))
        elif command == 'nxos-vtp-domain':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vtp_domain', args, int_params, host_type))
        elif command == 'nxos-vtp-password':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vtp_password', args, int_params, host_type))
        elif command == 'nxos-vtp-version':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vtp_version', args, int_params, host_type))
        elif command == 'nxos-vxlan-vtep':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vxlan_vtep', args, int_params, host_type))
        elif command == 'nxos-vxlan-vtep-vni':
            return_results(generic_ansible('CiscoNXOS', 'nxos_vxlan_vtep_vni', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
