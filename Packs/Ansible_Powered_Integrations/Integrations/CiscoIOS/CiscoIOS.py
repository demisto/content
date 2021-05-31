import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'ios'

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

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'ios-banner':
            return_results(generic_ansible('ciscoios', 'ios_banner', args, int_params))
        elif demisto.command() == 'ios-bgp':
            return_results(generic_ansible('ciscoios', 'ios_bgp', args, int_params))
        elif demisto.command() == 'ios-command':
            return_results(generic_ansible('ciscoios', 'ios_command', args, int_params))
        elif demisto.command() == 'ios-config':
            return_results(generic_ansible('ciscoios', 'ios_config', args, int_params))
        elif demisto.command() == 'ios-facts':
            return_results(generic_ansible('ciscoios', 'ios_facts', args, int_params))
        elif demisto.command() == 'ios-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_interfaces', args, int_params))
        elif demisto.command() == 'ios-l2-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_l2_interfaces', args, int_params))
        elif demisto.command() == 'ios-l3-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_l3_interfaces', args, int_params))
        elif demisto.command() == 'ios-lacp':
            return_results(generic_ansible('ciscoios', 'ios_lacp', args, int_params))
        elif demisto.command() == 'ios-lacp-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lacp_interfaces', args, int_params))
        elif demisto.command() == 'ios-lag-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lag_interfaces', args, int_params))
        elif demisto.command() == 'ios-linkagg':
            return_results(generic_ansible('ciscoios', 'ios_linkagg', args, int_params))
        elif demisto.command() == 'ios-lldp':
            return_results(generic_ansible('ciscoios', 'ios_lldp', args, int_params))
        elif demisto.command() == 'ios-lldp-global':
            return_results(generic_ansible('ciscoios', 'ios_lldp_global', args, int_params))
        elif demisto.command() == 'ios-lldp-interfaces':
            return_results(generic_ansible('ciscoios', 'ios_lldp_interfaces', args, int_params))
        elif demisto.command() == 'ios-logging':
            return_results(generic_ansible('ciscoios', 'ios_logging', args, int_params))
        elif demisto.command() == 'ios-ntp':
            return_results(generic_ansible('ciscoios', 'ios_ntp', args, int_params))
        elif demisto.command() == 'ios-ping':
            return_results(generic_ansible('ciscoios', 'ios_ping', args, int_params))
        elif demisto.command() == 'ios-static-route':
            return_results(generic_ansible('ciscoios', 'ios_static_route', args, int_params))
        elif demisto.command() == 'ios-system':
            return_results(generic_ansible('ciscoios', 'ios_system', args, int_params))
        elif demisto.command() == 'ios-user':
            return_results(generic_ansible('ciscoios', 'ios_user', args, int_params))
        elif demisto.command() == 'ios-vlans':
            return_results(generic_ansible('ciscoios', 'ios_vlans', args, int_params))
        elif demisto.command() == 'ios-vrf':
            return_results(generic_ansible('ciscoios', 'ios_vrf', args, int_params))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
