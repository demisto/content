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
    args = demisto.args()
    int_params = demisto.params()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'hcloud-datacenter-info':
            return_results(generic_ansible('hcloud', 'hcloud_datacenter_info', args, int_params))
        elif demisto.command() == 'hcloud-floating-ip-info':
            return_results(generic_ansible('hcloud', 'hcloud_floating_ip_info', args, int_params))
        elif demisto.command() == 'hcloud-image-info':
            return_results(generic_ansible('hcloud', 'hcloud_image_info', args, int_params))
        elif demisto.command() == 'hcloud-location-info':
            return_results(generic_ansible('hcloud', 'hcloud_location_info', args, int_params))
        elif demisto.command() == 'hcloud-network':
            return_results(generic_ansible('hcloud', 'hcloud_network', args, int_params))
        elif demisto.command() == 'hcloud-network-info':
            return_results(generic_ansible('hcloud', 'hcloud_network_info', args, int_params))
        elif demisto.command() == 'hcloud-rdns':
            return_results(generic_ansible('hcloud', 'hcloud_rdns', args, int_params))
        elif demisto.command() == 'hcloud-route':
            return_results(generic_ansible('hcloud', 'hcloud_route', args, int_params))
        elif demisto.command() == 'hcloud-server':
            return_results(generic_ansible('hcloud', 'hcloud_server', args, int_params))
        elif demisto.command() == 'hcloud-server-info':
            return_results(generic_ansible('hcloud', 'hcloud_server_info', args, int_params))
        elif demisto.command() == 'hcloud-server-network':
            return_results(generic_ansible('hcloud', 'hcloud_server_network', args, int_params))
        elif demisto.command() == 'hcloud-server-type-info':
            return_results(generic_ansible('hcloud', 'hcloud_server_type_info', args, int_params))
        elif demisto.command() == 'hcloud-ssh-key':
            return_results(generic_ansible('hcloud', 'hcloud_ssh_key', args, int_params))
        elif demisto.command() == 'hcloud-ssh-key-info':
            return_results(generic_ansible('hcloud', 'hcloud_ssh_key_info', args, int_params))
        elif demisto.command() == 'hcloud-subnetwork':
            return_results(generic_ansible('hcloud', 'hcloud_subnetwork', args, int_params))
        elif demisto.command() == 'hcloud-volume':
            return_results(generic_ansible('hcloud', 'hcloud_volume', args, int_params))
        elif demisto.command() == 'hcloud-volume-info':
            return_results(generic_ansible('hcloud', 'hcloud_volume_info', args, int_params))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
