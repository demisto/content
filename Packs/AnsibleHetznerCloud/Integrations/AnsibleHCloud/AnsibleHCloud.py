import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

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
    creds_mapping = {
        "password": "api_token"
    }

    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = generic_ansible('HCloud', 'hcloud_datacenter_info', args, int_params, host_type, creds_mapping)

            if result:
                return_results('ok')
            else:
                return_results(result)

        elif command == 'hcloud-datacenter-info':
            return_results(generic_ansible('HCloud', 'hcloud_datacenter_info', args, int_params, host_type,
                                           creds_mapping))
        elif command == 'hcloud-floating-ip-info':
            return_results(generic_ansible('HCloud', 'hcloud_floating_ip_info', args, int_params, host_type,
                                           creds_mapping))
        elif command == 'hcloud-image-info':
            return_results(generic_ansible('HCloud', 'hcloud_image_info', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-location-info':
            return_results(generic_ansible('HCloud', 'hcloud_location_info', args, int_params, host_type,
                                           creds_mapping))
        elif command == 'hcloud-network':
            return_results(generic_ansible('HCloud', 'hcloud_network', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-network-info':
            return_results(generic_ansible('HCloud', 'hcloud_network_info', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-rdns':
            return_results(generic_ansible('HCloud', 'hcloud_rdns', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-route':
            return_results(generic_ansible('HCloud', 'hcloud_route', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-server':
            return_results(generic_ansible('HCloud', 'hcloud_server', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-server-info':
            return_results(generic_ansible('HCloud', 'hcloud_server_info', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-server-network':
            return_results(generic_ansible('HCloud', 'hcloud_server_network', args, int_params, host_type,
                                           creds_mapping))
        elif command == 'hcloud-server-type-info':
            return_results(generic_ansible('HCloud', 'hcloud_server_type_info', args, int_params, host_type,
                                           creds_mapping))
        elif command == 'hcloud-ssh-key':
            return_results(generic_ansible('HCloud', 'hcloud_ssh_key', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-ssh-key-info':
            return_results(generic_ansible('HCloud', 'hcloud_ssh_key_info', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-subnetwork':
            return_results(generic_ansible('HCloud', 'hcloud_subnetwork', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-volume':
            return_results(generic_ansible('HCloud', 'hcloud_volume', args, int_params, host_type, creds_mapping))
        elif command == 'hcloud-volume-info':
            return_results(generic_ansible('HCloud', 'hcloud_volume_info', args, int_params, host_type, creds_mapping))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
