import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

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
    args = demisto.args()
    int_params = demisto.params()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'openssl-certificate':
            return_results(generic_ansible('openssl', 'openssl_certificate', args, int_params))
        elif demisto.command() == 'openssl-certificate-info':
            return_results(generic_ansible('openssl', 'openssl_certificate_info', args, int_params))
        elif demisto.command() == 'openssl-csr':
            return_results(generic_ansible('openssl', 'openssl_csr', args, int_params))
        elif demisto.command() == 'openssl-csr-info':
            return_results(generic_ansible('openssl', 'openssl_csr_info', args, int_params))
        elif demisto.command() == 'openssl-dhparam':
            return_results(generic_ansible('openssl', 'openssl_dhparam', args, int_params))
        elif demisto.command() == 'openssl-pkcs12':
            return_results(generic_ansible('openssl', 'openssl_pkcs12', args, int_params))
        elif demisto.command() == 'openssl-privatekey':
            return_results(generic_ansible('openssl', 'openssl_privatekey', args, int_params))
        elif demisto.command() == 'openssl-privatekey-info':
            return_results(generic_ansible('openssl', 'openssl_privatekey_info', args, int_params))
        elif demisto.command() == 'openssl-publickey':
            return_results(generic_ansible('openssl', 'openssl_publickey', args, int_params))
        elif demisto.command() == 'openssl-certificate-complete-chain':
            return_results(generic_ansible('openssl', 'certificate_complete_chain', args, int_params))
        elif demisto.command() == 'openssl-get-certificate':
            return_results(generic_ansible('openssl', 'get_certificate', args, int_params))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
