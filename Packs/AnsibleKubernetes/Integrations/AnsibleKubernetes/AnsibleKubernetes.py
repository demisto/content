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
        "identifier": "username",
        "password": "password"
    }

    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('This integration does not support testing from this screen. \
                           Please refer to the documentation for details on how to perform \
                           configuration tests.')
        elif command == 'k8s-k8s':
            return_results(generic_ansible('Kubernetes', 'k8s', args, int_params, host_type, creds_mapping))
        elif command == 'k8s-info':
            return_results(generic_ansible('Kubernetes', 'k8s_info', args, int_params, host_type, creds_mapping))
        elif command == 'k8s-scale':
            return_results(generic_ansible('Kubernetes', 'k8s_scale', args, int_params, host_type, creds_mapping))
        elif command == 'k8s-service':
            return_results(generic_ansible('Kubernetes', 'k8s_service', args, int_params, host_type, creds_mapping))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
