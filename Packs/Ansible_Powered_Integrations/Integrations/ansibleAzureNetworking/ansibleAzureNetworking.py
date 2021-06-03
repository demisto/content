import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'local'

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
            result = generic_ansible('azurenetworking', 'azure_rm_virtualnetwork_info', args, int_params, host_type)

            return_results(result)

        elif command == 'azure-rm-azurefirewall':
            return_results(generic_ansible('azurenetworking', 'azure_rm_azurefirewall', args, int_params, host_type))
        elif command == 'azure-rm-azurefirewall-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_azurefirewall_info', args, int_params, host_type))
        elif command == 'azure-rm-virtualnetwork':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetwork', args, int_params, host_type))
        elif command == 'azure-rm-virtualnetwork-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetwork_info', args, int_params, host_type))
        elif command == 'azure-rm-virtualnetworkgateway':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkgateway', args, int_params, host_type))
        elif command == 'azure-rm-virtualnetworkpeering':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkpeering', args, int_params, host_type))
        elif command == 'azure-rm-virtualnetworkpeering-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkpeering_info', args, int_params, host_type))
        elif command == 'azure-rm-subnet':
            return_results(generic_ansible('azurenetworking', 'azure_rm_subnet', args, int_params, host_type))
        elif command == 'azure-rm-subnet-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_subnet_info', args, int_params, host_type))
        elif command == 'azure-rm-trafficmanagerendpoint':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerendpoint', args, int_params, host_type))
        elif command == 'azure-rm-trafficmanagerendpoint-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerendpoint_info', args, int_params, host_type))
        elif command == 'azure-rm-trafficmanagerprofile':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerprofile', args, int_params, host_type))
        elif command == 'azure-rm-trafficmanagerprofile-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerprofile_info', args, int_params, host_type))
        elif command == 'azure-rm-networkinterface':
            return_results(generic_ansible('azurenetworking', 'azure_rm_networkinterface', args, int_params, host_type))
        elif command == 'azure-rm-networkinterface-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_networkinterface_info', args, int_params, host_type))
        elif command == 'azure-rm-publicipaddress':
            return_results(generic_ansible('azurenetworking', 'azure_rm_publicipaddress', args, int_params, host_type))
        elif command == 'azure-rm-publicipaddress-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_publicipaddress_info', args, int_params, host_type))
        elif command == 'azure-rm-route':
            return_results(generic_ansible('azurenetworking', 'azure_rm_route', args, int_params, host_type))
        elif command == 'azure-rm-routetable':
            return_results(generic_ansible('azurenetworking', 'azure_rm_routetable', args, int_params, host_type))
        elif command == 'azure-rm-routetable-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_routetable_info', args, int_params, host_type))
        elif command == 'azure-rm-securitygroup':
            return_results(generic_ansible('azurenetworking', 'azure_rm_securitygroup', args, int_params, host_type))
        elif command == 'azure-rm-securitygroup-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_securitygroup_info', args, int_params, host_type))
        elif command == 'azure-rm-dnsrecordset':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnsrecordset', args, int_params, host_type))
        elif command == 'azure-rm-dnsrecordset-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnsrecordset_info', args, int_params, host_type))
        elif command == 'azure-rm-dnszone':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnszone', args, int_params, host_type))
        elif command == 'azure-rm-dnszone-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnszone_info', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
