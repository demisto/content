from requests import RequestException
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

    def ip_reputation_request(self, ip):
        url_suffix = f"/api/v2/hosts/search?q=labels: * and ip={ip} or ip={ip}"
        res = self._http_request('GET', url_suffix)
        return res

    def domain_reputation_request(self, domain):
        url_suffix = f"/api/v2/hosts/search?q=labels: * and dns.names={domain} or dns.names={domain}"
        res = self._http_request('GET', url_suffix)
        return res


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict[str, Any]) -> str:
    if not params.get('premium_access') and (params.get('malicious_labels') or params.get('suspicious_labels')):
        raise DemistoException("The reputation labels feature only works with Censys premium access.")
    client.censys_view_request('ipv4', '8.8.8.8')
    return 'ok'


def censys_view_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns host information for the specified IP address or structured certificate data for the specified SHA-256
    """
    index = args.get('index', '')
    query = args.get('query', '')
    res = client.censys_view_request(index, query)
    result = res.get('result', {})
    if index == 'ipv4':
        content = {
            'Network': result.get('autonomous_system', {}).get('name'),
            'Routing': result.get('autonomous_system', {}).get('bgp_prefix'),
            'ASN': result.get('autonomous_system', {}).get('asn'),
            'Protocols': ', '.join([
                f"{service.get('port')}/{service.get('service_name')}"
                for service in result.get('services', [])]),
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
        content = {
            'Added At': result.get('added_at'),
            'Modified At': result.get('modified_at'),
            'Browser Trust': [
                f"{name}: {'Valid' if val.get('is_valid') else 'Invalid'}"
                for name, val in result.get('validation', {}).items()],
            'SHA 256': result.get('fingerprint_sha256'),
            'Tags': result.get('tags'),
            'Source': result.get('source'),
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
                'Services': ', '.join([
                    f"{service.get('port')}/{service.get('service_name')}"
                    for service in hit.get('services', [])]),
                'Location Country code': hit.get('location', {}).get('country_code'),
                'ASN': hit.get('autonomous_system', {}).get('asn'),
                'Description': hit.get('autonomous_system', {}).get('description'),
                'Name': hit.get('autonomous_system', {}).get('name'),
                'Registered Country Code': hit.get('location', {}).get('registered_country_code'),
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

    raw_response = client.censys_search_certs_request(data).get('result', {}).get('hits')
    if not raw_response or not isinstance(raw_response, list):
        error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
        raise DemistoException(error_msg)
    results = raw_response[:limit]
    for result in results:
        contents.append({
            'Issuer DN': result.get('parsed', {}).get('issuer_dn'),
            'Subject DN': result.get('parsed', {}).get('subject_dn'),
            'Validity not before': result.get('parsed', {}).get('validity_period', {}).get('not_before'),
            'Validity not after': result.get('parsed', {}).get('validity_period', {}).get('not_after'),
            'SHA256': result.get('fingerprint_sha256'),
            'Names': result.get('names'),
            'Issuer': result.get('parsed').get('issuer'),
        })

    human_readable = tableToMarkdown(f'Search results for query "{query}"', contents)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Censys.Search',
        outputs_key_field='fingerprint_sha256',
        outputs=results,
        raw_response=raw_response
    )


def censys_host_history_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns the diff between two hosts (or the same host at different times).

    :param client: The Censys client.
    :param args: Command arguments.
    :return: Command results.
    """
    ip = args.get("ip", '')
    ip_b = args.get("ip_b", '')
    at_time = args.get("at_time", '')
    at_time_b = args.get("at_time_b", '')

    res = client.censys_host_history_request(ip, ip_b, at_time, at_time_b).get("result", {})
    return CommandResults(
        outputs_prefix='Censys.HostHistory',
        outputs_key_field='ip',
        outputs=res,
        raw_response=res
    )


def ip_command(client: Client, args: dict):
    ips: list = argToList(args.get('ip'))
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    for ip in ips:
        try:
            raw_response = client.ip_reputation_request(ip).get('result', {}).get('hits')
            if not raw_response or not isinstance(raw_response, list):
                error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
                raise DemistoException(error_msg)
            res = raw_response[0]
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name="Censys",
                score=get_dbot_score(args, res),
                reliability=args.get('reliability')
            )
            content = {
                'ip': ip,
                'asn': res.get("autonomous_system", {}).get('asn'),
                'region': res.get('location', {}).get('country'),
                'updated_date': res.get('last_updated_at'),
                'geo_latitude': res.get('location', {}).get('coordinates', {}).get('latitude'),
                'geo_longitude': res.get('location', {}).get('coordinates', {}).get('longitude'),
                'geo_country': res.get('location', {}).get('country'),
                'port': ', '.join([f"{service.get('port')}" for service in res.get('services', [])]),
            }
            indicator = Common.IP(dbot_score=dbot_score, **content)
            results.append(CommandResults(
                outputs_prefix='Censys.IP',
                outputs_key_field='IP',
                readable_output=tableToMarkdown(f'censys results for IP: {ip}', content, headerTransform=string_to_table_header),
                outputs=res,
                raw_response=res,
                indicator=indicator,
            ))

            execution_metrics.success += 1
        except RequestException as e:
            should_break = handle_exceptions(e, results, execution_metrics, ip)
            if should_break:
                break

    if execution_metrics.metrics:
        results.append(execution_metrics.metrics)
        
    return results


def domain_command(client: Client, args: dict):
    domains: list = argToList(args.get('domain'))
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    for domain in domains:
        try:
            raw_response = client.domain_reputation_request(domain).get('result', {}).get('hits')
            if not raw_response or not isinstance(raw_response, list):
                error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
                raise DemistoException(error_msg)
            res = raw_response[0]

            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name="Censys",
                score=get_dbot_score(args, res),
                reliability=args.get('reliability')
            )
            content = {
                'domain': domain,
                'description': res.get('autonomous_system', {}).get('description'),
                'updated_date': res.get('last_updated_at'),
                'geo_country': res.get('location', {}).get('country'),
                'port': ', '.join([f"{service.get('port')}" for service in res.get('services', [])]),
            }
            indicator = Common.Domain(dbot_score=dbot_score, **content)
            results.append(CommandResults(
                outputs_prefix='Censys.Domain',
                outputs_key_field='Domain',
                readable_output=tableToMarkdown(
                    f'Censys results for Domain: {domain}',
                    content, headerTransform=string_to_table_header),
                outputs=res,
                raw_response=res,
                indicator=indicator,
            ))

            execution_metrics.success += 1
        except RequestException as e:
            should_break = handle_exceptions(e, results, execution_metrics, domain)
            if should_break:
                break

    if execution_metrics.metrics:
        results.append(execution_metrics.metrics)

    return results


''' HELPER FUNCTIONS '''


def handle_exceptions(e: RequestException, results, execution_metrics, item):
    if e.response.status_code == 403 and 'quota' in e.response.json().get('error'):
        # Handle quota exceeded error
        execution_metrics.quota_error += 1
        results.append(CommandResults(readable_output=f"Quota exceeded. {e.response.json()}"))
        return True
    if e.response.status_code == 401:
        # Raise unauthorized access error
        raise e
    # Handle general error
    execution_metrics.general_error += 1
    error_msg = f"An error occurred for item: {item}. Error: {e.response.json()}"
    results.append(CommandResults(readable_output=error_msg))
    return False


def get_dbot_score(args, result_labels):
    malicious_labels = set(args.get("malicious_labels", []))
    suspicious_labels = set(args.get("suspicious_labels", []))
    malicious_threshold = args.get("malicious_labels_threshold", 0)
    suspicious_threshold = args.get("suspicious_labels_threshold", 0)

    num_malicious = len(malicious_labels.intersection(result_labels))
    if num_malicious >= malicious_threshold and num_malicious > 0:
        return Common.DBotScore.BAD

    num_suspicious = len(suspicious_labels.intersection(result_labels))
    if num_suspicious >= suspicious_threshold and num_suspicious > 0:
        return Common.DBotScore.SUSPICIOUS

    return Common.DBotScore.NONE


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
            return_results(test_module(client, params))

        elif command == 'cen-view':
            return_results(censys_view_command(client, demisto.args()))
        elif command == 'cen-search':
            return_results(censys_search_command(client, demisto.args()))
        elif command == 'cen-host-history':
            return_results(censys_host_history_command(client, demisto.args()))
        elif command == 'ip':
            return_results(ip_command(client, demisto.args()))
        elif command == 'domain':
            return_results(domain_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
