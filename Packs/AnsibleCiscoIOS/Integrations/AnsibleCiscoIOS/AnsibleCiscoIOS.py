import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

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

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = generic_ansible('CiscoIOS', 'ios_facts', args, int_params, host_type)

            if result:
                return_results('ok')
            else:
                return_results(result)

        elif command == 'ios-banner':
            return_results(generic_ansible('CiscoIOS', 'ios_banner', args, int_params, host_type))
        elif command == 'ios-bgp':
            return_results(generic_ansible('CiscoIOS', 'ios_bgp', args, int_params, host_type))
        elif command == 'ios-command':
            return_results(generic_ansible('CiscoIOS', 'ios_command', args, int_params, host_type))
        elif command == 'ios-config':
            return_results(generic_ansible('CiscoIOS', 'ios_config', args, int_params, host_type))
        elif command == 'ios-facts':
            return_results(generic_ansible('CiscoIOS', 'ios_facts', args, int_params, host_type))
        elif command == 'ios-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_interfaces', args, int_params, host_type))
        elif command == 'ios-l2-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_l2_interfaces', args, int_params, host_type))
        elif command == 'ios-l3-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_l3_interfaces', args, int_params, host_type))
        elif command == 'ios-lacp':
            return_results(generic_ansible('CiscoIOS', 'ios_lacp', args, int_params, host_type))
        elif command == 'ios-lacp-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_lacp_interfaces', args, int_params, host_type))
        elif command == 'ios-lag-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_lag_interfaces', args, int_params, host_type))
        elif command == 'ios-linkagg':
            return_results(generic_ansible('CiscoIOS', 'ios_linkagg', args, int_params, host_type))
        elif command == 'ios-lldp':
            return_results(generic_ansible('CiscoIOS', 'ios_lldp', args, int_params, host_type))
        elif command == 'ios-lldp-global':
            return_results(generic_ansible('CiscoIOS', 'ios_lldp_global', args, int_params, host_type))
        elif command == 'ios-lldp-interfaces':
            return_results(generic_ansible('CiscoIOS', 'ios_lldp_interfaces', args, int_params, host_type))
        elif command == 'ios-logging':
            return_results(generic_ansible('CiscoIOS', 'ios_logging', args, int_params, host_type))
        elif command == 'ios-ntp':
            return_results(generic_ansible('CiscoIOS', 'ios_ntp', args, int_params, host_type))
        elif command == 'ios-ping':
            return_results(generic_ansible('CiscoIOS', 'ios_ping', args, int_params, host_type))
        elif command == 'ios-static-route':
            return_results(generic_ansible('CiscoIOS', 'ios_static_route', args, int_params, host_type))
        elif command == 'ios-system':
            return_results(generic_ansible('CiscoIOS', 'ios_system', args, int_params, host_type))
        elif command == 'ios-user':
            return_results(generic_ansible('CiscoIOS', 'ios_user', args, int_params, host_type))
        elif command == 'ios-vlans':
            return_results(generic_ansible('CiscoIOS', 'ios_vlans', args, int_params, host_type))
        elif command == 'ios-vrf':
            return_results(generic_ansible('CiscoIOS', 'ios_vrf', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
