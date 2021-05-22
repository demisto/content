import json
import traceback
import ansible_runner
import ssh_agent_setup
from typing import Dict, cast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type =  'ios'

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
        elif demisto.command() == 'ios-banner':
            return_results(generic_ansible('ciscoios', 'ios_banner', demisto.args()))
        elif demisto.command() == 'ios-bgp':
            return_results(generic_ansible('ciscoios', 'ios_bgp', demisto.args()))
        elif demisto.command() == 'ios-command':
            return_results(generic_ansible('ciscoios', 'ios_command', demisto.args()))
        elif demisto.command() == 'ios-config':
            return_results(generic_ansible('ciscoios', 'ios_config', demisto.args()))
        elif demisto.command() == 'ios-facts':
            return_results(generic_ansible('ciscoios', 'ios_facts', demisto.args()))
        elif demisto.command() == 'ios-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_interfaces', demisto.args()))
        elif demisto.command() == 'ios-l2-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_l2_interfaces', demisto.args()))
        elif demisto.command() == 'ios-l3-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_l3_interfaces', demisto.args()))
        elif demisto.command() == 'ios-lacp':
            return_results(generic_ansible('ciscoios', 'ios_lacp', demisto.args()))
        elif demisto.command() == 'ios-lacp-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lacp_interfaces', demisto.args()))
        elif demisto.command() == 'ios-lag-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lag_interfaces', demisto.args()))
        elif demisto.command() == 'ios-linkagg':
            return_results(generic_ansible('ciscoios', 'ios_linkagg', demisto.args()))
        elif demisto.command() == 'ios-lldp':
            return_results(generic_ansible('ciscoios', 'ios_lldp', demisto.args()))
        elif demisto.command() == 'ios-lldp-global':
            return_results(generic_ansible('ciscoios', 'ios_lldp_global', demisto.args()))
        elif demisto.command() == 'ios-lldp-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lldp_interfaces', demisto.args()))
        elif demisto.command() == 'ios-logging':
            return_results(generic_ansible('ciscoios', 'ios_logging', demisto.args()))
        elif demisto.command() == 'ios-ntp':
            return_results(generic_ansible('ciscoios', 'ios_ntp', demisto.args()))
        elif demisto.command() == 'ios-ping':
            return_results(generic_ansible('ciscoios', 'ios_ping', demisto.args()))
        elif demisto.command() == 'ios-static-route':
            return_results(generic_ansible('ciscoios', 'ios_static_route', demisto.args()))
        elif demisto.command() == 'ios-system':
            return_results(generic_ansible('ciscoios', 'ios_system', demisto.args()))
        elif demisto.command() == 'ios-user':
            return_results(generic_ansible('ciscoios', 'ios_user', demisto.args()))
        elif demisto.command() == 'ios-vlans':
            return_results(generic_ansible('ciscoios', 'ios_vlans', demisto.args()))
        elif demisto.command() == 'ios-vrf':
            return_results(generic_ansible('ciscoios', 'ios_vrf', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()