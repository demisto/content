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

    def ip_reputation_request(self, ip: str, fields: list | None):
        url_suffix = f"/api/v2/hosts/search?q=ip={ip}"
        if fields:
            url_suffix += f"&fields={','.join(fields)}"

        res = self._http_request('GET', url_suffix)
        return res

    def domain_reputation_request(self, domain: str):
        url_suffix = f"/api/v2/hosts/search?q=dns.names={domain}"
        res = self._http_request('GET', url_suffix)
        return res


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict[str, Any]) -> str:
    # Check if the user has selected malicious or suspicious labels without premium access
    if not params.get('premium_access') and (params.get('malicious_labels') or params.get('suspicious_labels')):
        raise DemistoException(
            "The 'Determine IP score by label' feature only works for Censys paid subscribers."
            "if you have paid access select the 'Determine IP score by label' option "
            "to utilize this functionality, or deselect labels")

    fields = ['labels'] if params.get('premium_access') else None

    try:
        client.ip_reputation_request('8.8.8.8', fields)
        return 'ok'
    except DemistoException as e:
        # Handle permission error for non-premium users attempting to access premium features
        if e.res.status_code == 403 and 'specific fields' in e.message:
            raise DemistoException(
                "Your user does not have permission for premium features. "
                "Please ensure that you deselect the 'Determine IP score by label' option "
                "for non-premium access.")
        raise e


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

        human_readable = tableToMarkdown(f'Information for IP {query}', content, removeNull=True)
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
        human_readable = tableToMarkdown('Information for certificate', content, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='Censys.View',
            outputs_key_field='fingerprint_sha256',
            outputs=result,
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
        human_readable = tableToMarkdown(f'Search results for query "{query}"', contents, headers, removeNull=True)
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
        raise ValueError(error_msg)
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

    human_readable = tableToMarkdown(f'Search results for query "{query}"', contents, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Censys.Search',
        outputs_key_field='fingerprint_sha256',
        outputs=results,
        raw_response=raw_response
    )


def ip_command(client: Client, args: dict, params: dict):
    fields = [
        "labels", "autonomous_system.asn", "autonomous_system.name",
        "autonomous_system.bgp_prefix", "autonomous_system.country_code",
        "autonomous_system.description", "location.country_code",
        "location.timezone", "location.province", "location.postal_code",
        "location.coordinates.latitude", "location.coordinates.longitude",
        "location.city", "location.continent", "location.country", "services.service_name",
        "services.port", "services.transport_protocol", "services.extended_service_name",
        "services.certificate", "last_updated_at", "dns.reverse_dns.names",
        "operating_system.source", "operating_system.part", "operating_system.version"
    ] if params.get('premium_access') else None

    ips: list = argToList(args.get('ip'))
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    for ip in ips:
        try:
            raw_response = client.ip_reputation_request(ip, fields)
            response = raw_response.get('result', {}).get('hits')
            if not response or not isinstance(response, list):
                error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
                raise ValueError(error_msg)

            hit = response[0]
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name="Censys",
                score=get_dbot_score(params, hit.get('labels', [])),
                reliability=params.get('integration_reliability')
            )
            content = {
                'ip': hit.get('ip'),
                'asn': hit.get("autonomous_system", {}).get('asn'),
                'updated_date': hit.get('last_updated_at'),
                'geo_latitude': hit.get('location', {}).get('coordinates', {}).get('latitude'),
                'geo_longitude': hit.get('location', {}).get('coordinates', {}).get('longitude'),
                'geo_country': hit.get('location', {}).get('country'),
                'port': ', '.join([str(service.get('port')) for service in hit.get('services', [])]),
            }
            indicator = Common.IP(dbot_score=dbot_score, **content)
            content['reputation'] = dbot_score.score
            results.append(CommandResults(
                outputs_prefix='Censys.IP',
                outputs_key_field='IP',
                readable_output=tableToMarkdown(
                    f'censys results for IP: {ip}',
                    content, headerTransform=string_to_table_header,
                    removeNull=True),
                outputs=hit,
                raw_response=raw_response,
                indicator=indicator,
            ))

            execution_metrics.success += 1
        except Exception as e:
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
            response = client.domain_reputation_request(domain).get('result', {})
            hits = response.get('hits')
            if not hits or not isinstance(hits, list):
                error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {response}"
                raise ValueError(error_msg)

            relationships = [EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=domain,
                entity_a_type='Domain',
                entity_b=hit.get('ip'),
                entity_b_type='IP',
                reverse_name=EntityRelationship.Relationships.RELATED_TO,
                brand='Censys') for hit in hits]

            dbot_score = Common.DBotScore(indicator=domain, indicator_type=DBotScoreType.DOMAIN, score=Common.DBotScore.NONE)
            indicator = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

            results.append(CommandResults(
                outputs_prefix='Censys.Domain',
                outputs_key_field='Domain',
                readable_output=tableToMarkdown(
                    f'Censys results for Domain: {domain}',
                    {'domain': domain}, headerTransform=string_to_table_header, removeNull=True),
                outputs=hits,
                raw_response=response,
                indicator=indicator,
                relationships=relationships
            ))

            execution_metrics.success += 1
        except Exception as e:
            should_break = handle_exceptions(e, results, execution_metrics, domain)
            if should_break:
                break

    if execution_metrics.metrics:
        results.append(execution_metrics.metrics)

    return results


''' HELPER FUNCTIONS '''


def handle_exceptions(e: Exception, results: list[CommandResults], execution_metrics: ExecutionMetrics, item: str):
    status_code = 0
    message = str(e)

    if isinstance(e, DemistoException) and hasattr(e.res, 'status_code'):
        status_code = e.res.status_code
        message = e.message

    if status_code == 403 and 'quota' in message:
        # Handle quota exceeded error
        execution_metrics.quota_error += 1
        results.append(CommandResults(readable_output=f"Quota exceeded. Error: {message}"))
        return True

    elif status_code == 429:
        # Handle rate limits error
        execution_metrics.general_error += 1
        results.append(CommandResults(readable_output=f"Too many requests. Error: {message}"))
        return True

    elif status_code == 403 and 'specific fields' in message:
        # Handle non-premium access error
        raise DemistoException(
            "Your user does not have permission for premium features. "
            "Please ensure that you deselect the 'Labels premium feature available' option "
            f"for non-premium access. Error: {message}")

    elif status_code == 401 or status_code == 403:
        # Handle unauthorized access error
        raise e

    else:
        # Handle general error
        execution_metrics.general_error += 1
        error_msg = f"An error occurred for item: {item}. Error: {message}"
        results.append(CommandResults(readable_output=error_msg))
        return False


def get_dbot_score(params: dict, result_labels: list):
    malicious_labels = set(params.get("malicious_labels", []))
    suspicious_labels = set(params.get("suspicious_labels", []))
    malicious_threshold = arg_to_number(params.get("malicious_labels_threshold")) or 0
    suspicious_threshold = arg_to_number(params.get("suspicious_labels_threshold")) or 0
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
        elif command == 'ip':
            return_results(ip_command(client, demisto.args(), params))
        elif command == 'domain':
            return_results(domain_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
