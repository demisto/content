import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import socket
import socks
import ipwhois
import whois
from typing import Dict, List, Optional, Type
import urllib


RATE_LIMIT_RETRY_COUNT_DEFAULT: int = 3
RATE_LIMIT_WAIT_SECONDS_DEFAULT: int = 120
RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT: bool = False

# flake8: noqa
ipwhois_exception_mapping: Dict[Type, str] = {

    # General Errors
    ipwhois.exceptions.WhoisLookupError: "general_error",
    ipwhois.exceptions.ASNLookupError: "general_error",
    ipwhois.exceptions.ASNOriginLookupError: "general_error",
    ipwhois.exceptions.ASNRegistryError: "general_error",
    ipwhois.exceptions.ASNParseError: "general_error",
    ipwhois.exceptions.ASNRegistryError: "general_error",
    ipwhois.exceptions.BaseIpwhoisException: "general_error",
    urllib.error.HTTPError: "general_error",
    ValueError: "general_error",
    ipwhois.exceptions.IPDefinedError: "general_error",

    # Service Errors
    ipwhois.exceptions.BlacklistError: "service_error",
    ipwhois.exceptions.HTTPLookupError: "connection_error",

    # Connection Errors
    ipwhois.exceptions.NetError: "connection_error",

    # Rate Limit Errors
    ipwhois.exceptions.HTTPRateLimitError: "quota_error",
    ipwhois.exceptions.WhoisRateLimitError: "quota_error",
}


class WhoisInvalidDomain(Exception):
    pass


class WhoisEmptyResponse(Exception):
    pass


class WhoisException(Exception):
    pass


# whois domain exception to execution metrics attribute mapping
whois_exception_mapping: Dict[Type, str] = {
    socket.error: "connection_error",
    OSError: "connection_error",
    socket.timeout: "timeout_error",
    socket.herror: "connection_error",
    socket.gaierror: "connection_error",
    WhoisInvalidDomain: "general_error",
    WhoisEmptyResponse: "service_error",
    TypeError: "general_error"
}


class InvalidDateHandler:
    """
        A class to represent an anparseble date by the datetime module.
        mainly for dates containing day, year, or month with an unvalid value of 0.
        """

    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day

    def strftime(self, *args):
        if self.year == 2000:
            return f'{self.day}-{self.month}-{0}'
        return f'{self.day}-{self.month}-{self.year}'


def increment_metric(execution_metrics: ExecutionMetrics, mapping: Dict[type, str], caught_exception: Type) -> ExecutionMetrics:
    """
    Helper method to increment the API execution metric according to the caught exception

    Args:
        - `execution_metrics` (``ExecutionMetrics``): The instance of the API execution metrics.
        - `mapping` (``Dict[type, str]``): The exception type to execution metrics mapping.
        - `caught_exception` (``Exception``): The exception caught.
    """

    demisto.debug(
        f"Exception of type '{caught_exception}' caught. Trying to find the matching Execution Metric attribute to increment...")
    try:
        metric_attribute = mapping[caught_exception]
        execution_metrics.__setattr__(metric_attribute, execution_metrics.__getattribute__(metric_attribute) + 1)

    # Treat any other exception as a ErrorTypes.GENERAL_ERROR
    except Exception as e:
        demisto.debug(
            f"Exception attempting to find and update execution metric attribute: {str(e)}. Defaulting to GENERAL_ERROR...")
        execution_metrics.general_error += 1

    finally:
        demisto.debug(f"Returning updated execution_metrics")
        return execution_metrics


def is_good_query_result(raw_result):
    """ Good result is one where the raw_result does not contains `NOT FOUND` or `No match` """
    return 'NOT FOUND' not in raw_result and 'No match' not in raw_result


def create_outputs(whois_result, domain, reliability, query=None):
    md = {'Name': domain}
    ec = {'Name': domain,
          'QueryResult': is_good_query_result(str(whois_result.get('raw', 'NOT FOUND')))}
    standard_ec = {}  # type:dict
    standard_ec['WHOIS'] = {}
    if 'status' in whois_result:
        ec['DomainStatus'] = whois_result.get('status')
        standard_ec['DomainStatus'] = whois_result.get('status')
        standard_ec['WHOIS']['DomainStatus'] = whois_result.get('status')
        md['Domain Status'] = whois_result.get('status')
    if 'raw' in whois_result:
        ec['Raw'] = whois_result.get('raw')
    if 'nameservers' in whois_result:
        ec['NameServers'] = whois_result.get('nameservers')
        standard_ec['NameServers'] = whois_result.get('nameservers')
        standard_ec['WHOIS']['NameServers'] = whois_result.get('nameservers')
        md['NameServers'] = whois_result.get('nameservers')
    try:
        if 'creation_date' in whois_result:
            ec['CreationDate'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
            standard_ec['CreationDate'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
            standard_ec['WHOIS']['CreationDate'] = whois_result.get('creation_date')[0].strftime(
                '%d-%m-%Y')
            md['Creation Date'] = whois_result.get('creation_date')[0].strftime('%d-%m-%Y')
        if 'updated_date' in whois_result:
            ec['UpdatedDate'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
            standard_ec['UpdatedDate'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
            standard_ec['WHOIS']['UpdatedDate'] = whois_result.get('updated_date')[0].strftime(
                '%d-%m-%Y')
            md['Updated Date'] = whois_result.get('updated_date')[0].strftime('%d-%m-%Y')
        if 'expiration_date' in whois_result:
            ec['ExpirationDate'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
            standard_ec['ExpirationDate'] = whois_result.get('expiration_date')[0].strftime(
                '%d-%m-%Y')
            standard_ec['WHOIS']['ExpirationDate'] = whois_result.get('expiration_date')[
                0].strftime(
                '%d-%m-%Y')
            md['Expiration Date'] = whois_result.get('expiration_date')[0].strftime('%d-%m-%Y')
    except ValueError as e:
        return_error('Date could not be parsed. Please check the date again.\n{}'.format(e))
    if 'registrar' in whois_result:
        ec.update({'Registrar': {'Name': whois_result.get('registrar')}})
        standard_ec['WHOIS']['Registrar'] = whois_result.get('registrar')
        md['Registrar'] = whois_result.get('registrar')
        standard_ec['Registrar'] = {'Name': whois_result.get('registrar')}
    if 'id' in whois_result:
        ec['ID'] = whois_result.get('id')
        md['ID'] = whois_result.get('id')
    if 'contacts' in whois_result:
        contacts = whois_result['contacts']
        if 'registrant' in contacts and contacts['registrant'] is not None:
            md['Registrant'] = contacts['registrant']
            standard_ec['Registrant'] = contacts['registrant'].copy()
            for key, val in list(contacts['registrant'].items()):
                standard_ec['Registrant'][key.capitalize()] = val
            ec['Registrant'] = contacts['registrant']
            if 'organization' in contacts['registrant']:
                standard_ec['Organization'] = contacts['registrant']['organization']
        if 'admin' in contacts and contacts['admin'] is not None:
            md['Administrator'] = contacts['admin']
            ec['Administrator'] = contacts['admin']
            standard_ec['Admin'] = contacts['admin'].copy()
            for key, val in list(contacts['admin'].items()):
                standard_ec['Admin'][key.capitalize()] = val
            standard_ec['WHOIS']['Admin'] = contacts['admin']
        if 'tech' in contacts and contacts['tech'] is not None:
            md['Tech Admin'] = contacts['tech']
            ec['TechAdmin'] = contacts['tech']
            standard_ec['Tech'] = {}
            if 'country' in contacts['tech']:
                standard_ec['Tech']['Country'] = contacts['tech']['country']
            if 'email' in contacts['tech']:
                standard_ec['Tech']['Email'] = contacts['tech']['email']
            if 'organization' in contacts['tech']:
                standard_ec['Tech']['Organization'] = contacts['tech']['organization']
        if 'billing' in contacts and contacts['billing'] is not None:
            md['Billing Admin'] = contacts['billing']
            ec['BillingAdmin'] = contacts['billing']
            standard_ec['Billing'] = contacts['billing']
    if 'emails' in whois_result:
        ec['Emails'] = whois_result.get('emails')
        md['Emails'] = whois_result.get('emails')
        standard_ec['FeedRelatedIndicators'] = [{'type': 'Email', 'value': email}
                                                for email in whois_result.get('emails')]
    ec['QueryStatus'] = 'Success'
    md['QueryStatus'] = 'Success'

    standard_ec['Name'] = domain
    standard_ec['Whois'] = ec
    standard_ec['Whois']['QueryValue'] = query

    dbot_score = Common.DBotScore(indicator=domain, indicator_type='domain', integration_name='Whois', score=0,
                                  reliability=reliability)

    return md, standard_ec, dbot_score.to_context()


def prepare_readable_ip_data(response):
    network_data = response.get('network', {})
    return {'query': response.get('query'),
            'asn': response.get('asn'),
            'asn_cidr': response.get('asn_cidr'),
            'asn_date': response.get('asn_date'),
            'country_code': network_data.get('country'),
            'network_name': network_data.get('name')
            }


'''COMMANDS'''


def get_whois_ip(ip: str,
                 retry_count: int = RATE_LIMIT_RETRY_COUNT_DEFAULT,
                 rate_limit_timeout: int = RATE_LIMIT_WAIT_SECONDS_DEFAULT,
                 rate_limit_errors_suppressed: bool = RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT
                 ) -> Optional[Dict[str, Any]]:
    """
    Performs an Registration Data Access Protocol (RDAP) lookup for an IP.

    See https://ipwhois.readthedocs.io/en/latest/RDAP.html

    Arguments:
        - `ip` (``str``): The IP to perform the lookup for.
        - `retry_count` (``int``): The number of times to retry the lookup in case of rate limiting error.
        - `rate_limit_timeout` (``int``): How long in seconds to wait before retrying the lookup in case of rate limiting error.

    Returns:
        - `Dict[str, None]` with the result of the lookup.
    """

    from urllib.request import build_opener, ProxyHandler

    proxy_opener = None
    if demisto.params().get('proxy'):
        proxies = assign_params(http=handle_proxy().get('http'), https=handle_proxy().get('https'))
        handler = ProxyHandler(proxies)
        proxy_opener = build_opener(handler)
        ip_obj = ipwhois.IPWhois(ip, proxy_opener=proxy_opener)
    else:
        ip_obj = ipwhois.IPWhois(ip)

    try:
        return ip_obj.lookup_rdap(depth=1, retry_count=retry_count, rate_limit_timeout=rate_limit_timeout)
    except urllib.error.HTTPError as e:
        if rate_limit_errors_suppressed:
            demisto.debug(f'Suppressed HTTPError when trying to lookup rdap info. Error: {e}')
            return None

        demisto.error(f'HTTPError when trying to lookup rdap info. Error: {e}')
        raise e


def get_param_or_arg(param_key: str, arg_key: str):
    return demisto.params().get(param_key) or demisto.args().get(arg_key)


def ip_command(reliability: str, should_error: bool) -> List[CommandResults]:
    """
    Performs RDAP lookup for the IP(s) and returns a list of CommandResults.
    Sets API execution metrics functionality (if supported) and adds them to the list of CommandResults.

    Args:
        - `reliability` (``str``): RDAP lookup source reliability.
        - `should_error` (``bool``): Whether to return an error entry if the lookup fails.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    ips = demisto.args().get('ip', '1.1.1.1')
    rate_limit_retry_count: int = int(get_param_or_arg('rate_limit_retry_count',
                                      'rate_limit_retry_count') or RATE_LIMIT_RETRY_COUNT_DEFAULT)
    rate_limit_wait_seconds: int = int(get_param_or_arg('rate_limit_wait_seconds',
                                       'rate_limit_wait_seconds') or RATE_LIMIT_WAIT_SECONDS_DEFAULT)
    rate_limit_errors_suppressed: bool = bool(get_param_or_arg(
        'rate_limit_errors_suppressed', 'rate_limit_errors_suppressed') or RATE_LIMIT_ERRORS_SUPPRESSEDL_DEFAULT)

    execution = ExecutionMetrics()
    results: List[CommandResults] = []
    for ip in argToList(ips):

        try:
            response = get_whois_ip(ip, retry_count=rate_limit_retry_count, rate_limit_timeout=rate_limit_wait_seconds,
                                    rate_limit_errors_suppressed=rate_limit_errors_suppressed)
            if response:
                execution.success += 1
                dbot_score = Common.DBotScore(
                    indicator=ip,
                    indicator_type=DBotScoreType.IP,
                    integration_name='Whois',
                    score=Common.DBotScore.NONE,
                    reliability=reliability
                )
                related_feed = Common.FeedRelatedIndicators(
                    value=response.get('network', {}).get('cidr'),
                    indicator_type='CIDR'
                )
                network_data: Dict[str, Any] = response.get('network', {})
                ip_output = Common.IP(
                    ip=ip,
                    asn=response.get('asn'),
                    geo_country=network_data.get('country'),
                    organization_name=network_data.get('name'),
                    dbot_score=dbot_score,
                    feed_related_indicators=[related_feed]
                )
                readable_data = prepare_readable_ip_data(response)
                result = CommandResults(
                    outputs_prefix='Whois.IP',
                    outputs_key_field='query',
                    outputs=response,
                    readable_output=tableToMarkdown('Whois results:', readable_data),
                    raw_response=response,
                    indicator=ip_output
                )
            else:
                execution.general_error += 1

                if should_error:
                    result = CommandResults(readable_output=f"No results returned for IP {ip}", entry_type=EntryType.ERROR)
                else:
                    result = CommandResults(readable_output=f"No results returned for IP {ip}", entry_type=EntryType.WARNING)

            results.append(result)

        except Exception as e:
            demisto.error(f"Exception type {e.__class__.__name__} caught performing RDAP lookup for IP {ip}: {e}")

            output = {
                'query': ip,
                'raw': f"Query failed for {ip}: {e.__class__.__name__}, {e}"
            }

            execution = increment_metric(
                execution_metrics=execution,
                mapping=ipwhois_exception_mapping,
                caught_exception=type(e)
            )

            if should_error:
                results.append(
                    CommandResults(
                        outputs_prefix="Whois.IP",
                        outputs_key_field="query",
                        outputs=output,
                        entry_type=EntryType.ERROR,
                        readable_output=f"Error performing RDAP lookup for IP {ip}: {e.__class__.__name__} {e}"
                    ))
            else:
                results.append(
                    CommandResults(
                        outputs_prefix="Whois.IP",
                        outputs_key_field="query",
                        outputs=output,
                        entry_type=EntryType.WARNING,
                        readable_output=f"Error performing RDAP lookup for IP {ip}: {e.__class__.__name__} {e}"
                    ))

    return append_metrics(execution_metrics=execution, results=results)


def generic_domain_command(reliability: str, args: dict, execution_metrics: ExecutionMetrics) -> List[CommandResults]:
    results: List[CommandResults] = []

    query = args.get("query", "paloaltonetworks.com")
    domain = args.get("domain")
    is_recursive = argToBoolean(args.get("recursive", 'false'))
    verbose = argToBoolean(args.get("verbose", "false"))
    should_error = argToBoolean(demisto.params().get('with_error', False))

    domains = domain or query
    for domain in argToList(domains):
        try:
            whois_result = whois.whois(domain, flags=is_recursive)
            execution_metrics.success += 1
            md, standard_ec, dbot_score = create_outputs(whois_result, domain, reliability, query)
            context_res = {}
            context_res.update(dbot_score)
            context_res[Common.Domain.CONTEXT_PATH] = standard_ec

            if verbose:
                demisto.info('Verbose response')
                whois_result['query'] = query
                json_res = json.dumps(whois_result, indent=4, sort_keys=True, default=str)
                context_res['Whois(val.query==obj.query)'] = json.loads(json_res)

            result = CommandResults(
                outputs=context_res,
                entry_type=EntryType.NOTE,
                content_format=EntryFormat.MARKDOWN,
                readable_output=tableToMarkdown(
                    f'Whois results for {domain}', md
                ),
                raw_response=str(whois_result),
            )

            results.append(result)

        except Exception as e:
            demisto.error(
                f"Exception of type {e.__class__.__name__} was caught while performing whois lookup with the domain '{domain}'")
            execution_metrics = increment_metric(
                execution_metrics=execution_metrics,
                mapping=whois_exception_mapping,
                caught_exception=type(e)
            )

            output = ({
                outputPaths['domain']: {
                    'Name': domain,
                    'Whois': {
                        'QueryStatus': f"Failed lookup: {e}"
                    }
                },
            })

            if should_error:
                results.append(CommandResults(
                    outputs=output,
                    readable_output=f"Exception of type {e.__class__.__name__} was caught while performing whois lookup with the domain '{domain}': {e}",
                    entry_type=EntryType.ERROR,
                    raw_response=str(e)
                ))
            else:
                results.append(CommandResults(
                    outputs=output,
                    readable_output=f"Exception of type {e.__class__.__name__} was caught while performing whois lookup with the domain '{domain}': {e}",
                    entry_type=EntryType.WARNING,
                    raw_response=str(e)
                ))

    return append_metrics(execution_metrics=execution_metrics, results=results)


def whois_command(reliability: str) -> List[CommandResults]:
    """
    Runs Whois domain query.

    Arguments:
        - `reliability` (``str``): The source reliability. Set in the integration instance settings.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    args = demisto.args()
    query = args.get("query", "paloaltonetworks.com")

    demisto.info(f"whois command is called with the query '{query}'")

    execution_metrics = ExecutionMetrics()

    return generic_domain_command(reliability=reliability, args=args, execution_metrics=execution_metrics)


def domain_command(reliability: str) -> List[CommandResults]:
    """
    Runs Whois domain query.

    Arguments:
        - `reliability` (``str``): The source reliability. Set in the integration instance settings.
    Returns:
        - `List[CommandResults]` with the command results and API execution metrics (if supported).
    """

    args = demisto.args()
    domains = args.get("domain", [])

    demisto.info(f"whois command is called with the query '{domains}'")

    execution_metrics = ExecutionMetrics()
    return generic_domain_command(reliability=reliability, args=args, execution_metrics=execution_metrics)


def test_command():
    test_domain = 'google.co.uk'
    demisto.debug(f"Testing module using domain '{test_domain}'...")
    whois_result = whois.whois(test_domain)

    try:
        if whois_result.name_servers == 'ns1.google.com':
            return 'ok'
    except Exception as e:
        raise WhoisException(f"Failed testing module using domain '{test_domain}': {e.__class__.__name__} {e}")


def setup_proxy():
    scheme_to_proxy_type = {
        'socks5': [socks.PROXY_TYPE_SOCKS5, False],
        'socks5h': [socks.PROXY_TYPE_SOCKS5, True],
        'socks4': [socks.PROXY_TYPE_SOCKS4, False],
        'socks4a': [socks.PROXY_TYPE_SOCKS4, True],
        'http': [socks.PROXY_TYPE_HTTP, True]
    }
    proxy_url = demisto.params().get('proxy_url')
    def_scheme = 'socks5h'
    if proxy_url == 'system_http' or not proxy_url and demisto.params().get('proxy'):
        system_proxy = handle_proxy('proxy')
        # use system proxy. Prefer https and fallback to http
        proxy_url = system_proxy.get('https') if system_proxy.get('https') else system_proxy.get('http')
        def_scheme = 'http'
    if not proxy_url and not demisto.params().get('proxy'):
        return
    scheme, host = (def_scheme, proxy_url) if '://' not in proxy_url else proxy_url.split('://')
    host, port = (host, None) if ':' not in host else host.split(':')
    if port:
        port = int(port)
    proxy_type = scheme_to_proxy_type.get(scheme)
    if not proxy_type:
        raise ValueError("Un supported proxy scheme: {}".format(scheme))
    socks.set_default_proxy(proxy_type[0], host, port, proxy_type[1])
    socket.socket = socks.socksocket  # type: ignore


''' EXECUTION CODE '''


def main():  # pragma: no cover
    demisto.debug(f"command is {demisto.command()}")
    command = demisto.command()
    should_error = argToBoolean(demisto.params().get('with_error', False))

    reliability = demisto.params().get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    org_socket = None
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")
    try:
        results: List[CommandResults] = []
        if command == 'ip':
            results = ip_command(reliability=reliability, should_error=should_error)

        else:
            org_socket = socket.socket
            setup_proxy()
            if command == 'test-module':
                results = test_command()

            elif command == 'whois':
                results = whois_command(reliability=reliability)

            elif command == "domain":
                results = domain_command(reliability=reliability)

            else:
                raise NotImplementedError()

        return_results(results)
    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(msg)
        return_error(message=msg, error=e)
    finally:
        if command != 'ip':
            socks.set_default_proxy()  # clear proxy settings
            socket.socket = org_socket  # type: ignore


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
