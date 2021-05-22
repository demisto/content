import json
import traceback
import ansible_runner
import ssh_agent_setup
from typing import Dict, cast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type =  'nxos'

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'nxos-aaa-server':
            return_results(generic_ansible('cisconxos', 'nxos_aaa_server', demisto.args()))
        elif demisto.command() == 'nxos-aaa-server-host':
            return_results(generic_ansible('cisconxos', 'nxos_aaa_server_host', demisto.args()))
        elif demisto.command() == 'nxos-acl':
            return_results(generic_ansible('cisconxos', 'nxos_acl', demisto.args()))
        elif demisto.command() == 'nxos-acl-interface':
            return_results(generic_ansible('cisconxos', 'nxos_acl_interface', demisto.args()))
        elif demisto.command() == 'nxos-banner':
            return_results(generic_ansible('cisconxos', 'nxos_banner', demisto.args()))
        elif demisto.command() == 'nxos-bfd-global':
            return_results(generic_ansible('cisconxos', 'nxos_bfd_global', demisto.args()))
        elif demisto.command() == 'nxos-bfd-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_bfd_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-bgp':
            return_results(generic_ansible('cisconxos', 'nxos_bgp', demisto.args()))
        elif demisto.command() == 'nxos-bgp-af':
            return_results(generic_ansible('cisconxos', 'nxos_bgp_af', demisto.args()))
        elif demisto.command() == 'nxos-bgp-neighbor':
            return_results(generic_ansible('cisconxos', 'nxos_bgp_neighbor', demisto.args()))
        elif demisto.command() == 'nxos-bgp-neighbor-af':
            return_results(generic_ansible('cisconxos', 'nxos_bgp_neighbor_af', demisto.args()))
        elif demisto.command() == 'nxos-command':
            return_results(generic_ansible('cisconxos', 'nxos_command', demisto.args()))
        elif demisto.command() == 'nxos-config':
            return_results(generic_ansible('cisconxos', 'nxos_config', demisto.args()))
        elif demisto.command() == 'nxos-evpn-global':
            return_results(generic_ansible('cisconxos', 'nxos_evpn_global', demisto.args()))
        elif demisto.command() == 'nxos-evpn-vni':
            return_results(generic_ansible('cisconxos', 'nxos_evpn_vni', demisto.args()))
        elif demisto.command() == 'nxos-facts':
            return_results(generic_ansible('cisconxos', 'nxos_facts', demisto.args()))
        elif demisto.command() == 'nxos-feature':
            return_results(generic_ansible('cisconxos', 'nxos_feature', demisto.args()))
        elif demisto.command() == 'nxos-gir':
            return_results(generic_ansible('cisconxos', 'nxos_gir', demisto.args()))
        elif demisto.command() == 'nxos-gir-profile-management':
            return_results(generic_ansible('cisconxos', 'nxos_gir_profile_management', demisto.args()))
        elif demisto.command() == 'nxos-hsrp':
            return_results(generic_ansible('cisconxos', 'nxos_hsrp', demisto.args()))
        elif demisto.command() == 'nxos-igmp':
            return_results(generic_ansible('cisconxos', 'nxos_igmp', demisto.args()))
        elif demisto.command() == 'nxos-igmp-interface':
            return_results(generic_ansible('cisconxos', 'nxos_igmp_interface', demisto.args()))
        elif demisto.command() == 'nxos-igmp-snooping':
            return_results(generic_ansible('cisconxos', 'nxos_igmp_snooping', demisto.args()))
        elif demisto.command() == 'nxos-install-os':
            return_results(generic_ansible('cisconxos', 'nxos_install_os', demisto.args()))
        elif demisto.command() == 'nxos-interface-ospf':
            return_results(generic_ansible('cisconxos', 'nxos_interface_ospf', demisto.args()))
        elif demisto.command() == 'nxos-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-l2-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_l2_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-l3-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_l3_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-lacp':
            return_results(generic_ansible('cisconxos', 'nxos_lacp', demisto.args()))
        elif demisto.command() == 'nxos-lacp-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_lacp_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-lag-interfaces':
            return_results(generic_ansible('cisconxos', 'nxos_lag_interfaces', demisto.args()))
        elif demisto.command() == 'nxos-lldp':
            return_results(generic_ansible('cisconxos', 'nxos_lldp', demisto.args()))
        elif demisto.command() == 'nxos-lldp-global':
            return_results(generic_ansible('cisconxos', 'nxos_lldp_global', demisto.args()))
        elif demisto.command() == 'nxos-logging':
            return_results(generic_ansible('cisconxos', 'nxos_logging', demisto.args()))
        elif demisto.command() == 'nxos-ntp':
            return_results(generic_ansible('cisconxos', 'nxos_ntp', demisto.args()))
        elif demisto.command() == 'nxos-ntp-auth':
            return_results(generic_ansible('cisconxos', 'nxos_ntp_auth', demisto.args()))
        elif demisto.command() == 'nxos-ntp-options':
            return_results(generic_ansible('cisconxos', 'nxos_ntp_options', demisto.args()))
        elif demisto.command() == 'nxos-nxapi':
            return_results(generic_ansible('cisconxos', 'nxos_nxapi', demisto.args()))
        elif demisto.command() == 'nxos-ospf':
            return_results(generic_ansible('cisconxos', 'nxos_ospf', demisto.args()))
        elif demisto.command() == 'nxos-ospf-vrf':
            return_results(generic_ansible('cisconxos', 'nxos_ospf_vrf', demisto.args()))
        elif demisto.command() == 'nxos-overlay-global':
            return_results(generic_ansible('cisconxos', 'nxos_overlay_global', demisto.args()))
        elif demisto.command() == 'nxos-pim':
            return_results(generic_ansible('cisconxos', 'nxos_pim', demisto.args()))
        elif demisto.command() == 'nxos-pim-interface':
            return_results(generic_ansible('cisconxos', 'nxos_pim_interface', demisto.args()))
        elif demisto.command() == 'nxos-pim-rp-address':
            return_results(generic_ansible('cisconxos', 'nxos_pim_rp_address', demisto.args()))
        elif demisto.command() == 'nxos-ping':
            return_results(generic_ansible('cisconxos', 'nxos_ping', demisto.args()))
        elif demisto.command() == 'nxos-reboot':
            return_results(generic_ansible('cisconxos', 'nxos_reboot', demisto.args()))
        elif demisto.command() == 'nxos-rollback':
            return_results(generic_ansible('cisconxos', 'nxos_rollback', demisto.args()))
        elif demisto.command() == 'nxos-rpm':
            return_results(generic_ansible('cisconxos', 'nxos_rpm', demisto.args()))
        elif demisto.command() == 'nxos-smu':
            return_results(generic_ansible('cisconxos', 'nxos_smu', demisto.args()))
        elif demisto.command() == 'nxos-snapshot':
            return_results(generic_ansible('cisconxos', 'nxos_snapshot', demisto.args()))
        elif demisto.command() == 'nxos-snmp-community':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_community', demisto.args()))
        elif demisto.command() == 'nxos-snmp-contact':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_contact', demisto.args()))
        elif demisto.command() == 'nxos-snmp-host':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_host', demisto.args()))
        elif demisto.command() == 'nxos-snmp-location':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_location', demisto.args()))
        elif demisto.command() == 'nxos-snmp-traps':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_traps', demisto.args()))
        elif demisto.command() == 'nxos-snmp-user':
            return_results(generic_ansible('cisconxos', 'nxos_snmp_user', demisto.args()))
        elif demisto.command() == 'nxos-static-route':
            return_results(generic_ansible('cisconxos', 'nxos_static_route', demisto.args()))
        elif demisto.command() == 'nxos-system':
            return_results(generic_ansible('cisconxos', 'nxos_system', demisto.args()))
        elif demisto.command() == 'nxos-telemetry':
            return_results(generic_ansible('cisconxos', 'nxos_telemetry', demisto.args()))
        elif demisto.command() == 'nxos-udld':
            return_results(generic_ansible('cisconxos', 'nxos_udld', demisto.args()))
        elif demisto.command() == 'nxos-udld-interface':
            return_results(generic_ansible('cisconxos', 'nxos_udld_interface', demisto.args()))
        elif demisto.command() == 'nxos-user':
            return_results(generic_ansible('cisconxos', 'nxos_user', demisto.args()))
        elif demisto.command() == 'nxos-vlans':
            return_results(generic_ansible('cisconxos', 'nxos_vlans', demisto.args()))
        elif demisto.command() == 'nxos-vpc':
            return_results(generic_ansible('cisconxos', 'nxos_vpc', demisto.args()))
        elif demisto.command() == 'nxos-vpc-interface':
            return_results(generic_ansible('cisconxos', 'nxos_vpc_interface', demisto.args()))
        elif demisto.command() == 'nxos-vrf':
            return_results(generic_ansible('cisconxos', 'nxos_vrf', demisto.args()))
        elif demisto.command() == 'nxos-vrf-af':
            return_results(generic_ansible('cisconxos', 'nxos_vrf_af', demisto.args()))
        elif demisto.command() == 'nxos-vrf-interface':
            return_results(generic_ansible('cisconxos', 'nxos_vrf_interface', demisto.args()))
        elif demisto.command() == 'nxos-vrrp':
            return_results(generic_ansible('cisconxos', 'nxos_vrrp', demisto.args()))
        elif demisto.command() == 'nxos-vtp-domain':
            return_results(generic_ansible('cisconxos', 'nxos_vtp_domain', demisto.args()))
        elif demisto.command() == 'nxos-vtp-password':
            return_results(generic_ansible('cisconxos', 'nxos_vtp_password', demisto.args()))
        elif demisto.command() == 'nxos-vtp-version':
            return_results(generic_ansible('cisconxos', 'nxos_vtp_version', demisto.args()))
        elif demisto.command() == 'nxos-vxlan-vtep':
            return_results(generic_ansible('cisconxos', 'nxos_vxlan_vtep', demisto.args()))
        elif demisto.command() == 'nxos-vxlan-vtep-vni':
            return_results(generic_ansible('cisconxos', 'nxos_vxlan_vtep_vni', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()