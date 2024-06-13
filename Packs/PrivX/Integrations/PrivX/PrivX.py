"""Base Integration for Cortex XSOAR (aka Demisto)

This integration adds support for PrivX by SSH Communications Security.

PrivX documentation: https://privx.docs.ssh.com
Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""
from typing import Any

import urllib3
import privx_api

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

params = demisto.params()

CA_CERT = params.get('ca-certificate')

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''

HOSTNAME = params.get('hostname')
HOSTPORT = params.get('port')

api = privx_api.PrivXAPI(
    HOSTNAME,
    HOSTPORT,
    params.get('ca-certificate'),
    params.get('oauth-client-id'),
    params.get('oauth-client-secret'),
)

API_CLIENT_ID = params.get('api-client-id')
API_CLIENT_SECRET = params.get('api-client-secret')


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def get_cert(self, target_host_config):
        """ Fetch ephemeral certificate from PrivX server """
        cert = api.get_target_host_credentials(target_host_config)
        if cert.ok:
            certificates = cert.data.get("certificates")
            if certificates is None or len(certificates) == 0:
                raise Exception(f'Certificate error: {cert.data}')

            return [c.get("data_string", "") for c in certificates]
        return cert.data.get("details")

    def clean_pubkey(self, pubkey):
        """ Remove padding from the public key before sending via API """
        if pubkey is None:
            raise ValueError("Public key is None")
        _prefix, key_data, *_suffix = pubkey.split(" ")
        return key_data.replace("=", "")

    def privx_get_cert(self, args: dict[str, Any]) -> dict[str, str]:
        """Returns short-term certificates for authenticating against the target host.

        :type args: ``dict``
        :param args: command line arguments

        :return: dict as {"certificates": certificates}
        :rtype: ``dict``
        """

        # The arguments of the API call
        # NOTE: Make sure that you have the "Use with PrivX Agent" permission in your role
        conf = {
            # User's public key (MANDATORY)
            "public_key": args.get('public-key', params.get('public-key', '')),
            # UUID of role that is used for accessing the target host (Optional)
            "roleid": args.get('role-id', ''),
            # Target host service: SSH, RDP or WEB (Optional)
            "service": args.get('service', ''),
            # Target username (Optional)
            "username": args.get('username', ''),
            # Target hostname (Optional)
            "hostname": args.get('hostname', ''),
            # Target host UUID (Optional)
            "hostid": args.get('host-id', ''),
        }

        # No auth when running unit test
        if not args.get('api-client-id'):
            api.authenticate(API_CLIENT_ID, API_CLIENT_SECRET)
        conf["public_key"] = self.clean_pubkey(conf["public_key"])

        # Fetch certificates from PrivX instance
        cert_list = self.get_cert(conf)
        cert = ""
        for i in range(len(cert_list)):
            cert += f"{'-'*12} Cert{i+1} {'-'*12}\n{cert_list[i]}"

        return {"certificates": cert}

    def privx_get_secret(self, args: dict[str, Any]) -> dict[str, str]:
        """Returns secret with the given name from PrivX secrets vault.

        :type args: ``dict``
        :param args: command line arguments

        :return: dict as {"secret": secret}
        :rtype: ``dict``
        """

        name = args.get('name')
        if not name:
            raise ValueError("Secret name is None")

        # No auth when running unit test
        if not args.get('api-client-id'):
            api.authenticate(API_CLIENT_ID, API_CLIENT_SECRET)

        # Fetch certificates from PrivX instance
        secret = api.get_secret(name)
        if not secret.ok:
            return secret.data["details"]

        return secret.data["data"]


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # Test connectivity and authentication to PrivX instance.
        # This should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.

        resp = api.get_auth_service_status()
        if resp.ok:
            message = 'ok'
        else:
            message = resp.data
    except DemistoException as dex:
        if 'Forbidden' in str(dex) or 'Authorization' in str(dex):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise dex
    return message


def privx_get_cert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get certificate from the server """
    result = client.privx_get_cert(args)

    return CommandResults(
        outputs_prefix='PrivX',
        outputs_key_field='',
        outputs=result,
    )


def privx_get_secret_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """ Get secret from the server """
    result = client.privx_get_secret(args)

    return CommandResults(
        outputs_prefix='PrivX',
        outputs_key_field='',
        outputs=result,
    )


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    # base_url = urljoin(demisto.params()['name'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: dict = {}

        client = Client(
            base_url='',
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            return_results(result)

        elif demisto.command() == 'privx-get-cert':
            return_results(privx_get_cert_command(client, demisto.args()))

        elif demisto.command() == 'privx-get-secret':
            return_results(privx_get_secret_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as gex:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(gex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
