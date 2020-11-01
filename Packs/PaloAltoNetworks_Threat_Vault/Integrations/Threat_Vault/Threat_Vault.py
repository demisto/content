from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(self, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url='https://autofocus.paloaltonetworks.com/api/intel/v1/threatvault', verify=verify,
                         proxy=proxy, headers={'Content-Type': 'application/json'})
        self._params = {'api_key': api_key}
        self.name = 'ThreatVault'
        self._a = api_key

    def antivirus_signature_get_request(self, sha256: str) -> dict:
        """Get antivirus signature by sending a GET request.

        Args:
            sha256: antivirus sha256.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/ips/signature/{sha256}', params=self._params)

    def dns_signature_get_request(self, dns_signature_id: str) -> dict:
        """Get DNS signature by sending a GET request.

        Args:
            dns_signature_id: DNS signature ID.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/dns/signature/{dns_signature_id}', params=self._params)

    def antispyware_get_by_id_request(self, signature_id: str) -> dict:
        """Get DNS signature by sending a GET request.

        Args:
            signature_id: signature ID.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/ips/signature/{signature_id}', params=self._params)


def test_module(client: Client, *_) -> str:
    """Performs basic get request to get a DNS signature

    Args:
        client: Client object with request.

    Returns:
        string.
    """
    client.dns_signature_get_request(dns_signature_id='325235352')
    return 'ok'


def antivirus_signature_get(client: Client, args: dict) -> CommandResults:
    """Get antivirus signature

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    sha256 = str(args.get('sha256', ''))
    response = client.antivirus_signature_get_request(sha256)
    demisto.log(str(response))
    # headers = ['objectId', 'alias', 'firstName', 'middleName', 'lastName', 'email']
    # readable_output = tableToMarkdown(name=f"Number of users found: {total_elements}. {table_name}",
    #                                   t=users_data, headers=headers, removeNull=True)
    #
    # command_results = CommandResults(
    #     outputs_prefix=f'{client.name}.Users',
    #     outputs_key_field='objectId',
    #     outputs=users_data,
    #     readable_output=readable_output,
    #     raw_response=users
    # )
    #
    # return command_results


def dns_get_by_id(client: Client, args: dict) -> CommandResults:
    """Get DNS signature

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    dns_signature_id = str(args.get('dns_signature_id', ''))
    response = client.dns_signature_get_request(dns_signature_id)

    headers = ['signatureId', 'signatureName', 'domainName', 'createTime', 'category']
    readable_output = tableToMarkdown(name=f"DNS Signature:", t=response, headers=headers, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.DNS',
        outputs_key_field='signatureId',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def antispyware_get_by_id(client: Client, args: dict) -> CommandResults:
    """Get anti spyware signature

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    signature_id = str(args.get('signature_id', ''))
    response = client.antispyware_get_by_id_request(signature_id)
    headers = ['signatureId', 'signatureName', 'signatureType', 'status', 'firstReleaseTime', 'latestReleaseTime']
    readable_output = tableToMarkdown(name=f"Anti Spyware Signature:", t=response, headers=headers, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.AntiSpyware',
        outputs_key_field='signatureId',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('api_key')
    verify = not params.get('insecure', False)
    proxy = demisto.params().get('proxy') is True

    try:
        command = demisto.command()
        LOG(f'Command being called is {demisto.command()}')
        client = Client(api_key=api_key, verify=verify, proxy=proxy)
        commands = {
            'threatvault-antivirus-signtature-get': antivirus_signature_get,
            'threatvault-dns-signature-get-by-id': dns_get_by_id,
            'threatvault-antispyware-signature-get-by-id': antispyware_get_by_id,
        }
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
