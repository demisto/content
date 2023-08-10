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
        elif command == 'openssl-certificate':
            return_results(generic_ansible('OpenSSL', 'openssl_certificate', args, int_params, host_type))
        elif command == 'openssl-certificate-info':
            return_results(generic_ansible('OpenSSL', 'openssl_certificate_info', args, int_params, host_type))
        elif command == 'openssl-csr':
            return_results(generic_ansible('OpenSSL', 'openssl_csr', args, int_params, host_type))
        elif command == 'openssl-csr-info':
            return_results(generic_ansible('OpenSSL', 'openssl_csr_info', args, int_params, host_type))
        elif command == 'openssl-dhparam':
            return_results(generic_ansible('OpenSSL', 'openssl_dhparam', args, int_params, host_type))
        elif command == 'openssl-pkcs12':
            return_results(generic_ansible('OpenSSL', 'openssl_pkcs12', args, int_params, host_type))
        elif command == 'openssl-privatekey':
            return_results(generic_ansible('OpenSSL', 'openssl_privatekey', args, int_params, host_type))
        elif command == 'openssl-privatekey-info':
            return_results(generic_ansible('OpenSSL', 'openssl_privatekey_info', args, int_params, host_type))
        elif command == 'openssl-publickey':
            return_results(generic_ansible('OpenSSL', 'openssl_publickey', args, int_params, host_type))
        elif command == 'openssl-certificate-complete-chain':
            return_results(generic_ansible('OpenSSL', 'certificate_complete_chain', args, int_params, host_type))
        elif command == 'openssl-get-certificate':
            return_results(generic_ansible('OpenSSL', 'get_certificate', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
