import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'ssh'

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
            return_results('This integration does not support testing from this screen. \
                           Please refer to the documentation for details on how to perform \
                           configuration tests.')
        elif command == 'acme-account':
            return_results(generic_ansible('ACME', 'acme_account', args, int_params, host_type))
        elif command == 'acme-account-info':
            return_results(generic_ansible('ACME', 'acme_account_info', args, int_params, host_type))
        elif command == 'acme-certificate':
            return_results(generic_ansible('ACME', 'acme_certificate', args, int_params, host_type))
        elif command == 'acme-certificate-revoke':
            return_results(generic_ansible('ACME', 'acme_certificate_revoke', args, int_params, host_type))
        elif command == 'acme-challenge-cert-helper':
            return_results(generic_ansible('ACME', 'acme_challenge_cert_helper', args, int_params, host_type))
        elif command == 'acme-inspect':
            return_results(generic_ansible('ACME', 'acme_inspect', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
