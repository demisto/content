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

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'azure-rm-azurefirewall':
            return_results(generic_ansible('azurenetworking', 'azure_rm_azurefirewall', demisto.args()))
        elif demisto.command() == 'azure-rm-azurefirewall-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_azurefirewall_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualnetwork':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetwork', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualnetwork-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetwork_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualnetworkgateway':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkgateway', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualnetworkpeering':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkpeering', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualnetworkpeering-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_virtualnetworkpeering_info', demisto.args()))
        elif demisto.command() == 'azure-rm-subnet':
            return_results(generic_ansible('azurenetworking', 'azure_rm_subnet', demisto.args()))
        elif demisto.command() == 'azure-rm-subnet-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_subnet_info', demisto.args()))
        elif demisto.command() == 'azure-rm-trafficmanagerendpoint':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerendpoint', demisto.args()))
        elif demisto.command() == 'azure-rm-trafficmanagerendpoint-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerendpoint_info', demisto.args()))
        elif demisto.command() == 'azure-rm-trafficmanagerprofile':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerprofile', demisto.args()))
        elif demisto.command() == 'azure-rm-trafficmanagerprofile-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_trafficmanagerprofile_info', demisto.args()))
        elif demisto.command() == 'azure-rm-networkinterface':
            return_results(generic_ansible('azurenetworking', 'azure_rm_networkinterface', demisto.args()))
        elif demisto.command() == 'azure-rm-networkinterface-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_networkinterface_info', demisto.args()))
        elif demisto.command() == 'azure-rm-publicipaddress':
            return_results(generic_ansible('azurenetworking', 'azure_rm_publicipaddress', demisto.args()))
        elif demisto.command() == 'azure-rm-publicipaddress-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_publicipaddress_info', demisto.args()))
        elif demisto.command() == 'azure-rm-route':
            return_results(generic_ansible('azurenetworking', 'azure_rm_route', demisto.args()))
        elif demisto.command() == 'azure-rm-routetable':
            return_results(generic_ansible('azurenetworking', 'azure_rm_routetable', demisto.args()))
        elif demisto.command() == 'azure-rm-routetable-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_routetable_info', demisto.args()))
        elif demisto.command() == 'azure-rm-securitygroup':
            return_results(generic_ansible('azurenetworking', 'azure_rm_securitygroup', demisto.args()))
        elif demisto.command() == 'azure-rm-securitygroup-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_securitygroup_info', demisto.args()))
        elif demisto.command() == 'azure-rm-dnsrecordset':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnsrecordset', demisto.args()))
        elif demisto.command() == 'azure-rm-dnsrecordset-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnsrecordset_info', demisto.args()))
        elif demisto.command() == 'azure-rm-dnszone':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnszone', demisto.args()))
        elif demisto.command() == 'azure-rm-dnszone-info':
            return_results(generic_ansible('azurenetworking', 'azure_rm_dnszone_info', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
