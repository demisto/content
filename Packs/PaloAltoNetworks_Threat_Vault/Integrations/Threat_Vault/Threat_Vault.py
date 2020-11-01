from typing import Dict

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(self, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url='https://autofocus.paloaltonetworks.com/api/intel/v1', verify=verify, proxy=proxy,
                         headers={'Content-Type': 'application/json'})
        self._params = {'api_key': api_key}
        self.name = 'ThreatVault'

    def antivirus_signature_get_request(self, sha256: str) -> dict:
        """Get antivirus signature by sending a GET request.

        Args:
            sha256: antivirus sha256.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/threatvault/ips/signature/{sha256}', params=self._params)

    def dns_signature_get_request(self, dns_signature_id: str) -> dict:
        """Get DNS signature by sending a GET request.

        Args:
            dns_signature_id: DNS signature ID.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/threatvault/dns/signature/{dns_signature_id}',
                                  params=self._params)

    def antispyware_get_by_id_request(self, signature_id: str) -> dict:
        """Get DNS signature by sending a GET request.

        Args:
            signature_id: signature ID.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/threatvault/ips/signature/{signature_id}',
                                  params=self._params)

    def ip_geo_get_request(self, ip_: str) -> dict:
        """Get IP geolocation by sending a GET request.

        Args:
            ip_: ip address.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/ip/{ip_}/geolocation', params=self._params)

    def search_request(self, path: str, signature_name: str = '', from_: int = 0, size: int = 10,
                       domain_name: str = '', vendor: str = '', cve: str = '') -> dict:
        """Initiate a search by sending a POST request.

        Args:
            path: API endpoint path to search.
            signature_name: signature name.
            from_: todo
            size: todo
            domain_name: domain name
            vendor: vendor ID
            cve: cve ID
        Returns:
            Response from API.
        """
        if path == 'dns':  # DNS search
            if signature_name and domain_name:
                raise Exception('Please provide either a signature_name or a domain_name')

        data: Dict[str, Any] = {
            'from': from_,
            'size': size
        }
        if signature_name:
            data['field'] = 'signatureName'
            data['value'] = signature_name
        if domain_name:
            data['field'] = 'domainName'
            data['value'] = domain_name

        return self._http_request(method='POST', url_suffix=f'/threatvault/{path}/search', params=self._params,
                                  json_data=data)


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
    readable_output = tableToMarkdown(name="Antivirus:", t=response, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.Antivirus',
        outputs_key_field='SHA256',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


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
    readable_output = tableToMarkdown(name="DNS Signature:", t=response, headers=headers, removeNull=True)

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
    readable_output = tableToMarkdown(name="Anti Spyware Signature:", t=response, headers=headers, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.AntiSpyware',
        outputs_key_field='signatureId',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def ip_geo_get(client: Client, args: dict) -> CommandResults:
    """Get IP geo location

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    ip_ = str(args.get('ip', ''))

    response = client.ip_geo_get_request(ip_)

    readable_output = tableToMarkdown(name="Anti Spyware Signature:", t=response, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.IP',
        outputs_key_field='ipAddress',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def antivirus_signature_search(client: Client, args: dict) -> CommandResults:
    """Initiate antivirus signature search

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    signature_name = str(args.get('signature_name', ''))
    from_ = int(args.get('from', 0))
    size = int(args.get('size', 10))

    response = client.search_request('panav', signature_name, from_, size)
    readable_output = tableToMarkdown(name="Antivirus Signature Search:", t=response, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.Search',
        outputs_key_field='search_request_id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def dns_signature_search(client: Client, args: dict) -> CommandResults:
    """Initiate DNS signature search

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    signature_name = str(args.get('signature_name', ''))
    from_ = int(args.get('from', 0))
    size = int(args.get('size', 10))
    domain_name = str(args.get('domain_name', ''))

    response = client.search_request('dns', signature_name, from_, size, domain_name=domain_name)
    readable_output = tableToMarkdown(name="DNS Signature Search:", t=response, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.Search',
        outputs_key_field='search_request_id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def antispyware_signature_search(client: Client, args: dict) -> CommandResults:
    """Initiate anti spyware signature search

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    signature_name = str(args.get('signature_name', ''))
    from_ = int(args.get('from', 0))
    size = int(args.get('size', 10))
    vendor = str(args.get('vendor', ''))
    cve = str(args.get('cve', ''))

    response = client.search_request('ips', signature_name, from_, size, vendor=vendor, cve=cve)
    readable_output = tableToMarkdown(name="Anti Spyware Signature Search:", t=response, removeNull=True)

    return CommandResults(
        outputs_prefix=f'{client.name}.Search',
        outputs_key_field='search_request_id',
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
            'threatvault-antivirus-signature-get': antivirus_signature_get,
            'threatvault-dns-signature-get-by-id': dns_get_by_id,
            'threatvault-antispyware-signature-get-by-id': antispyware_get_by_id,
            'threatvault-ip-geo-get': ip_geo_get,
            'threatvault-antivirus-signature-search': antivirus_signature_search,
            'threatvault-dns-signature-search': dns_signature_search,
            'threatvault-antispyware-signature-search': antispyware_signature_search,
            # 'threatvault-signature-search-results', signature_search_results,
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
