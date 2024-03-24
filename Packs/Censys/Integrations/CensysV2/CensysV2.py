import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CLIENT CLASS '''


class Client(BaseClient):

    def censys_view_request(self, index: str, query: str) -> dict:

        if index == 'ipv4':
            url_suffix = f'/api/v2/hosts/{query}'
        else:
            url_suffix = f'/api/v2/certificates/{query}'
        res = self._http_request('GET', url_suffix)
        return res

    def censys_search_ip_request(self, query: dict, page_size: int) -> dict:
        url_suffix = '/api/v2/hosts/search'
        params = {
            'q': query,
            'per_page': page_size
        }
        res = self._http_request('GET', url_suffix, params=params)
        return res

    def censys_search_certs_request(self, data: dict) -> dict:
        url_suffix = '/api/v2/certificates/search'
        res = self._http_request('GET', url_suffix, json_data=data)
        return res

    def censys_host_history_request(self, ip: str, ip_b: str = '', at_time: str = '', at_time_b: str = '') -> dict:
        """
        Retrieve the diff between two hosts (or the same host at different times).

        :param ip: The IP Address of the original host (Host A).
        :param ip_b: The IP Address of the other host (Host B). Defaults to the host provided in the path if not set.
        :param at_time: The point in time used as the basis for Host A.
        :param at_time_b: The point in time used as the basis for Host B.
        :return: The diff between the hosts.
        """
        url_suffix = f'/api/v2/hosts/{ip}/diff'
        params = {}
        if ip_b:
            params['ip_b'] = ip_b
        if at_time:
            params['at_time'] = at_time
        if at_time_b:
            params['at_time_b'] = at_time_b
        res = self._http_request('GET', url_suffix, params=params)
        return res


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.censys_view_request('ipv4', '8.8.8.8')
    return 'ok'


def censys_view_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

        city = demisto.get(result, 'location.city')
        province = demisto.get(result, 'location.province')
        postal = demisto.get(result, 'location.postal_code')
        country_code = demisto.get(result, 'location.country_code')
        country = demisto.get(result, 'location.country')

        description = ', '.join(filter(None, [city, province, postal, country_code]))
        lat = demisto.get(result, 'location.coordinates.latitude')
        lon = demisto.get(result, 'location.coordinates.longitude')

        indicator = Common.IP(
            ip=query,
            dbot_score=Common.DBotScore(indicator=query,
                                        indicator_type=DBotScoreType.IP,
                                        score=Common.DBotScore.NONE),
            asn=demisto.get(result, 'autonomous_system.asn'),
            geo_latitude=str(lat) if lat else None,
            geo_longitude=str(lon) if lon else None,
            geo_description=description or None,
            geo_country=country,
            as_owner=demisto.get(result, 'autonomous_system.name'))

        human_readable = tableToMarkdown(f'Information for IP {query}', content)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='Censys.View',
            outputs_key_field='ip',
            outputs=result,
            indicator=indicator,
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


def censys_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def search_certs_command(client: Client, args: dict[str, Any], query: str, limit: Optional[int]):
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


def censys_host_history_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns the diff between two hosts (or the same host at different times).

    :param client: The Censys client.
    :param args: Command arguments.
    :return: Command results.
    """
    ip = args.get("ip", '')
    ip_b = args.get("ip_b", ip)
    at_time = args.get("at_time", '')
    at_time_b = args.get("at_time_b", '')

    res = client.censys_host_history_request(ip, ip_b, at_time, at_time_b)
    human_readable = tableToMarkdown(f'Host Diff for IP {ip}', res)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Censys.HostHistory',
        outputs_key_field='ip',
        outputs=res,
        raw_response=res
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    base_url = params.get("server_url") or 'https://search.censys.io'

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
            return_results(test_module(client))

        elif command == 'cen-view':
            return_results(censys_view_command(client, demisto.args()))
        elif command == 'cen-search':
            return_results(censys_search_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
