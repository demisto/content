import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CLIENT CLASS '''


class Client(BaseClient):

    def censys_view_request(self, index: str, query: str) -> Dict:

        if index == 'ipv4':
            url_suffix = f'v2/hosts/{query}'
        else:
            url_suffix = f'v1/view/certificates/{query}'
        res = self._http_request('GET', url_suffix)
        return res

    def censys_search_ip_request(self, query: Dict, page_size: int) -> Dict:
        url_suffix = 'v2/hosts/search'
        params = {
            'q': query,
            'per_page': page_size
        }
        res = self._http_request('GET', url_suffix, params=params)
        return res

    def censys_search_certs_request(self, data: Dict) -> Dict:
        url_suffix = 'v1/search/certificates'
        res = self._http_request('POST', url_suffix, json_data=data)
        return res


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.censys_view_request('ipv4', '8.8.8.8')
    return 'ok'


def censys_view_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns host information for the specified IP address or structured certificate data for the specified SHA-256
    """
    index = args.get('index', '')
    query = args.get('query', '')
    res = client.censys_view_request(index, query)
    if index == 'ipv4':
        result = res.get('result', {})
        content = {
            'Name': result.get('autonomous_system', {}).get('name'),
            'Bgp Prefix': result.get('autonomous_system', {}).get('bgp_prefix'),
            'ASN': result.get('autonomous_system', {}).get('asn'),
            'Service': [{
                'Port': service.get('port'),
                'Service Name': service.get('service_name')
            } for service in result.get('services', [])],
            'Last Updated': result.get('last_updated_at')
        }

        human_readable = tableToMarkdown(f'Information for IP {query}', content)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='Censys.View',
            outputs_key_field='ip',
            outputs=result,
            raw_response=res
        )
    else:
        metadata = res.get('metadata', {})
        content = {
            'SHA 256': res.get('fingerprint_sha256'),
            'Tags': res.get('tags'),
            'Source': metadata.get('source'),
            'Added': metadata.get('added_at'),
            'Updated': metadata.get('updated_at')
        }
        human_readable = tableToMarkdown('Information for certificate', content)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='Censys.View',
            outputs_key_field='fingerprint_sha256',
            outputs=res,
            raw_response=res
        )


def censys_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns previews of hosts matching a specified search query or a list of certificates that match the given query.
    """
    index = args.get('index')
    query = args.get('query', '')
    page_size: int = arg_to_number(args.get('page_size', 50))  # type: ignore[assignment]
    limit = arg_to_number(args.get('limit'))
    contents = []

    if index == 'ipv4':
        if limit and limit < page_size:
            page_size = limit
        res = client.censys_search_ip_request(query, page_size)
        hits = res.get('result', {}).get('hits', [])

        for hit in hits:
            contents.append({
                'IP': hit.get('ip'),
                'Services': hit.get('services'),
                'Location Country code': hit.get('location', {}).get('country_code'),
                'Registered Country Code': hit.get('location', {}).get('registered_country_code'),
                'ASN': hit.get('autonomous_system', {}).get('asn'),
                'Description': hit.get('autonomous_system', {}).get('description'),
                'Name': hit.get('autonomous_system', {}).get('name')
            })
        headers = ['IP', 'Name', 'Description', 'ASN', 'Location Country code', 'Registered Country Code', 'Services']
        human_readable = tableToMarkdown(f'Search results for query "{query}"', contents, headers)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='Censys.Search',
            outputs_key_field='ip',
            outputs=hits,
            raw_response=res
        )
    else:
        response = search_certs_command(client, args, query, limit)
        return response


def search_certs_command(client: Client, args: Dict[str, Any], query: str, limit: Optional[int]):
    fields = ['parsed.fingerprint_sha256', 'parsed.subject_dn', 'parsed.issuer_dn', 'parsed.issuer.organization',
              'parsed.validity.start', 'parsed.validity.end', 'parsed.names']
    search_fields = argToList(args.get('fields'))
    if search_fields:
        fields.extend(search_fields)
    contents = []
    data = {
        'query': query,
        'page': int(args.get('page', 1)),
        'fields': fields,
        'flatten': False
    }

    res = client.censys_search_certs_request(data)
    results = res.get('results', {})[:limit]
    for result in results:
        contents.append({
            'SHA256': result.get('parsed').get('fingerprint_sha256'),
            'Issuer dn': result.get('parsed').get('issuer_dn'),
            'Subject dn': result.get('parsed').get('subject_dn'),
            'Names': result.get('parsed').get('names'),
            'Validity': result.get('parsed').get('validity'),
            'Issuer': result.get('parsed').get('issuer'),
        })

    human_readable = tableToMarkdown(f'Search results for query "{query}"', contents)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Censys.Search',
        outputs_key_field='fingerprint_sha256',
        outputs=results,
        raw_response=res
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    base_url = 'https://search.censys.io/api/'
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            auth=(username, password),
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'cen-view':
            return_results(censys_view_command(client, demisto.args()))
        elif command == 'cen-search':
            return_results(censys_search_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
