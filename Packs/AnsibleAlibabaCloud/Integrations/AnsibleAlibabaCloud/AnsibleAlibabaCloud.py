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
        "identifier": "alicloud_access_key",
        "password": "alicloud_secret_key"  # guardrails-disable-line
    }

    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = generic_ansible('AlibabaCloud', 'ali_instance_info', args, int_params, host_type, creds_mapping)

            if result:
                return_results('ok')
            else:
                return_results(result)

        elif command == 'ali-instance':
            return_results(generic_ansible('AlibabaCloud', 'ali_instance', args, int_params, host_type, creds_mapping))
        elif command == 'ali-instance-info':
            return_results(generic_ansible('AlibabaCloud', 'ali_instance_info', args, int_params, host_type,
                                           creds_mapping))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
