import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

import dateparser
import requests

import urllib3

urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def test_connect(self, api_key):
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': 'pulsedive.com',
                'key': api_key
            }
        )

    def get_ip_reputation(self, ip: str, api_key) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': ip,
                'pretty': '1',
                'key': api_key
            }
        )

    def get_domain_reputation(self, domain: str, api_key) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': domain,
                'pretty': '1',
                'key': api_key
            }
        )

    def get_url_reputation(self, url: str, api_key) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': url,
                'pretty': '1',
                'key': api_key
            }
        )

    def post_value_scan(self, value: str, probe: str, api_key) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/analyze.php',
            params={
                'value': value,
                'probe': probe,
                'pretty': '1',
                'key': api_key
            }
        )

    def get_value_scan(self, qid: str, api_key) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/analyze.php?',
            params={
                'qid': qid,
                'pretty': '1',
                'key': api_key
            }
        )


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: list[str] | str, date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> str | None:
    """Converts whois date format to an ISO8601 string
    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.
    :type domain_date: ``Union[List[str],str]``
    :param severity:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'
    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        if _date := dateparser.parse(domain_date).strftime(date_format):  # type: ignore[union-attr]
            return _date
        return None
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        return dateparser.parse(domain_date[0]).strftime(date_format)  # type: ignore[union-attr]
    # in any other case return nothing
    return None


def convert_to_xsoar_severity(pulsedive_severity) -> int:
    if (pulsedive_severity == 'unknown' or pulsedive_severity == 'none'):
        xsoar_severity = Common.DBotScore.NONE  # unknown
    elif pulsedive_severity == 'high':
        xsoar_severity = Common.DBotScore.SUSPICIOUS  # suspicious
    elif pulsedive_severity == 'critical':
        xsoar_severity = Common.DBotScore.BAD  # bad
    else:
        xsoar_severity = Common.DBotScore.GOOD  # good
    return xsoar_severity


''' COMMAND FUNCTIONS '''


def test_module(client: Client, api_key) -> str:
    """Tests API connectivity and authentication"""

    try:
        client.test_connect(api_key)
    except DemistoException:
        return 'Could not connect to Pulsedive'
    return 'ok'


def ip_reputation_command(client: Client, args: dict[str, Any], api_key) -> list[CommandResults]:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    command_results: list[CommandResults] = []
    for ip in ips:
        try:
            ip_data = client.get_ip_reputation(ip, api_key)
            indicator_ip = ip_data['indicator']
            reputation = ip_data['risk']
            score = convert_to_xsoar_severity(reputation)

            # Create the DBotScore structure first using the Common.DBotScore class.
            dbot_score = Common.DBotScore(
                indicator=indicator_ip,
                indicator_type=DBotScoreType.IP,
                integration_name='Pulsedive',
                score=score,
                malicious_description=f'Pulsedive returned reputation {reputation}'
            )

            # Create the IP Standard Context structure using Common.IP and add
            # dbot_score to it.
            ip_standard_context = Common.IP(
                ip=indicator_ip,
                dbot_score=dbot_score
            )

            ip_data.pop('objects', None)
            ip_data.pop('nir', None)
            command_results.append(CommandResults(
                readable_output=tableToMarkdown('IP Details:', ip_data),
                outputs_prefix='Pulsedive.IP',
                outputs_key_field='indicator',
                outputs=ip_data,
                indicator=ip_standard_context
            ))
        except DemistoException:
            # Create the DBotScore structure first using the Common.DBotScore class.
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name='Pulsedive',
                score=Common.DBotScore.NONE,
                malicious_description='Pulsedive returned reputation None'
            )

            # Create the IP Standard Context structure using Common.IP and add
            # dbot_score to it.
            ip_standard_context = Common.IP(
                ip=ip,
                dbot_score=dbot_score
            )

            command_results.append(CommandResults(
                readable_output=str(ip) + ' not found in indicator data',
                outputs_prefix='Pulsedive.IP',
                outputs_key_field='indicator',
                indicator=ip_standard_context
            ))

    return command_results


def domain_reputation_command(client: Client, args: dict[str, Any], api_key) -> list[CommandResults]:
    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    command_results: list[CommandResults] = []
    for domain in domains:
        try:
            domain_data = client.get_domain_reputation(domain, api_key)
            indicator_domain = domain_data['indicator']
            reputation = domain_data['risk']
            score = convert_to_xsoar_severity(reputation)

            if 'creation_date' in domain_data:
                domain_data['creation_date'] = parse_domain_date(domain_data['creation_date'])
            if 'expiration_date' in domain_data:
                domain_data['expiration_date'] = parse_domain_date(domain_data['expiration_date'])
            if 'updated_date' in domain_data:
                domain_data['updated_date'] = parse_domain_date(domain_data['updated_date'])

            dbot_score = Common.DBotScore(
                indicator=indicator_domain,
                integration_name='Pulsedive',
                indicator_type=DBotScoreType.DOMAIN,
                score=score,
                malicious_description='Pulsedive returned reputation {reputation}'
            )

            domain_standard_context = Common.Domain(
                domain=indicator_domain,
                dbot_score=dbot_score
            )

            command_results.append(CommandResults(
                readable_output=tableToMarkdown('Domain Details:', domain_data),
                outputs_prefix='Pulsedive.Domain',
                outputs_key_field='indicator',
                outputs=domain_data,
                indicator=domain_standard_context
            ))
        except DemistoException:
            # Create the DBotScore structure first using the Common.DBotScore class.
            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name='Pulsedive',
                score=Common.DBotScore.NONE,
                malicious_description='Pulsedive returned reputation None'
            )

            domain_standard_context = Common.Domain(
                domain=domain,
                dbot_score=dbot_score
            )

            command_results.append(CommandResults(
                readable_output=str(domain) + ' not found in indicator data',
                outputs_prefix='Pulsedive.Domain',
                outputs_key_field='indicator',
                indicator=domain_standard_context
            ))

    return command_results


def url_reputation_command(client: Client, args: dict[str, Any], api_key) -> list[CommandResults]:

    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    command_results: list[CommandResults] = []
    for url in urls:
        try:
            url_data = client.get_url_reputation(url, api_key)
            indicator_url = url_data['indicator']
            reputation = url_data['risk']
            score = convert_to_xsoar_severity(reputation)

            dbot_score = Common.DBotScore(
                indicator=str(indicator_url),
                indicator_type=DBotScoreType.URL,
                integration_name='Pulsedive',
                score=score,
                malicious_description=f'Pulsedive returned reputation {reputation}'
            )

            url_standard_context = Common.URL(
                url=indicator_url,
                dbot_score=dbot_score
            )

            url_data.pop('objects', None)
            url_data.pop('nir', None)
            command_results.append(CommandResults(
                readable_output=tableToMarkdown('URL Details:', url_data),
                outputs_prefix='Pulsedive.URL',
                outputs_key_field='indicator',
                outputs=url_data,
                indicator=url_standard_context
            ))
        except DemistoException:
            # Create the DBotScore structure first using the Common.DBotScore class.
            dbot_score = Common.DBotScore(
                indicator=str(url),
                indicator_type=DBotScoreType.URL,
                integration_name='Pulsedive',
                score=Common.DBotScore.NONE,
                malicious_description='Pulsedive returned reputation None'
            )

            url_standard_context = Common.URL(
                url=str(url),
                dbot_score=dbot_score
            )

            command_results.append(CommandResults(
                readable_output=str(url) + ' not found in indicator data',
                outputs_prefix='Pulsedive.URL',
                outputs_key_field='indicator',
                indicator=url_standard_context
            ))

    return command_results


def scan_value_command(client: Client, args: dict[str, Any], api_key) -> list[CommandResults]:
    values = argToList(args.get('value'))
    if len(values) == 0:
        raise ValueError('Value(s) not specified')

    scan_type_value = '0' if args.get('scan_type') == 'passiv' else '1'

    command_results: list[CommandResults] = []
    for value in values:
        try:
            value_data = client.post_value_scan(value, scan_type_value, api_key)
            value_data.update({'value': value})
            command_results.append(CommandResults(
                readable_output=tableToMarkdown('Value Details:', value_data),
                outputs_prefix='Pulsedive.Scan',
                outputs_key_field='value',
                outputs=value_data
            ))
        except DemistoException:
            raise DemistoException(
                f'Failed to execute {demisto.command()} command. Error: Problem submitting the data for scanning'
            )

    return command_results


def scan_result_command(client: Client, args: dict[str, Any], api_key) -> list[CommandResults]:
    """
    Scan result command
    """
    qids = argToList(args.get('qid'))
    if len(qids) == 0:
        raise ValueError('QID(s) not specified')

    command_results: list[CommandResults] = []
    for qid in qids:
        try:
            qid_data = client.get_value_scan(qid, api_key)
            if 'data' in qid_data and qid_data['data']:
                qid_data.update({'qid': qid, 'indicator': qid_data['data']['indicator']})
                if qid_data['data']['type'] == 'url' or qid_data['data']['type'] == 'domain':
                    if 'dom' in qid_data['data']['properties']:
                        screenshot = requests.get(qid_data['data']['properties']['dom']['screenshot'])
                        screenshot_file = fileResult(
                            qid_data['data']['properties']['dom']['screenshot'],
                            screenshot.content,
                            file_type=EntryType.ENTRY_INFO_FILE
                        )
                        screenshot_file['Type'] = entryTypes['image']
                        demisto.results(screenshot_file)
                    else:
                        demisto.results("No screenshot available")
                reputation = qid_data['data']['risk']
                score = convert_to_xsoar_severity(reputation)
                if qid_data['data']['type'] == 'url':
                    dbot_score = Common.DBotScore(
                        indicator=qid_data['data']['indicator'],
                        indicator_type=DBotScoreType.URL,
                        integration_name='Pulsedive',
                        score=score
                    )

                    url_indicator = Common.URL(
                        url=qid_data['data']['indicator'],
                        dbot_score=dbot_score
                    )

                    command_results.append(CommandResults(
                        readable_output=tableToMarkdown(
                            'Value Details:',
                            qid_data,
                            headers=('indicator', 'qid', 'status', 'success')
                        ),
                        outputs_prefix='Pulsedive.ScanResult',
                        outputs_key_field='qid',
                        outputs=qid_data['data'],
                        indicator=url_indicator
                    ))

                if qid_data['data']['type'] == 'ip':
                    dbot_score = Common.DBotScore(
                        indicator=qid_data['data']['indicator'],
                        indicator_type=DBotScoreType.IP,
                        integration_name='Pulsedive',
                        score=score
                    )

                    if 'geo' in qid_data['data']['properties']:
                        ip_indicator = Common.IP(
                            ip=qid_data['data']['indicator'],
                            asn=qid_data['data']['properties']['geo'].get('asn'),
                            geo_country=qid_data['data']['properties']['geo'].get('country'),
                            port=qid_data.get('data', {}).get('attributes', {}).get(
                                'port') if qid_data['data']['attributes'] != [] else None,
                            dbot_score=dbot_score
                        )
                    else:
                        ip_indicator = Common.IP(
                            ip=qid_data['data']['indicator'],
                            dbot_score=dbot_score
                        )

                    command_results.append(CommandResults(
                        readable_output=tableToMarkdown(
                            'Value Details:',
                            qid_data,
                            headers=('indicator', 'qid', 'status', 'success')
                        ),
                        outputs_prefix='Pulsedive.ScanResult',
                        outputs_key_field='qid',
                        outputs=qid_data['data'],
                        indicator=ip_indicator
                    ))

                if qid_data['data']['type'] == 'domain':
                    dbot_score = Common.DBotScore(
                        indicator=qid_data['data']['indicator'],
                        indicator_type=DBotScoreType.DOMAIN,
                        integration_name='Pulsedive',
                        score=score
                    )

                    if 'whois' in qid_data['data']['properties']:
                        domain_indicator = Common.Domain(
                            domain=qid_data['data']['indicator'],
                            domain_status=qid_data['data']['properties']['whois'].get('status'),
                            name_servers=qid_data['data']['properties']['whois'].get('nserver'),
                            dbot_score=dbot_score
                        )
                    else:
                        domain_indicator = Common.Domain(
                            domain=qid_data['data']['indicator'],
                            dbot_score=dbot_score
                        )

                    command_results.append(CommandResults(
                        readable_output=tableToMarkdown(
                            'Value Details:',
                            qid_data,
                            headers=('indicator', 'qid', 'status', 'success')
                        ),
                        outputs_prefix='Pulsedive.ScanResult',
                        outputs_key_field='qid',
                        outputs=qid_data['data'],
                        indicator=domain_indicator
                    ))

            else:
                command_results.append(CommandResults(
                    readable_output=tableToMarkdown('Value Details:', qid_data),
                    outputs_prefix='Pulsedive.ScanResult',
                    outputs_key_field='qid',
                    outputs=qid_data
                ))
        except DemistoException:
            return_error(
                f'Failed to execute {demisto.command()} command. Error: Problem with processing the scan results'
            )

    return command_results


''' MAIN FUNCTION '''


def main() -> None:

    api_key = demisto.params().get('apikey')
    base_url = 'https://www.pulsedive.com/api'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    headers = {'User-Agent': 'XSOAR - Integration'}

    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, api_key))

        elif demisto.command() == 'ip':
            return_results(ip_reputation_command(client, demisto.args(), api_key))

        elif demisto.command() == 'domain':
            return_results(domain_reputation_command(client, demisto.args(), api_key))

        elif demisto.command() == 'url':
            return_results(url_reputation_command(client, demisto.args(), api_key))

        elif demisto.command() == 'pulsedive-scan':
            return_results(scan_value_command(client, demisto.args(), api_key))

        elif demisto.command() == 'pulsedive-scan-result':
            return_results(scan_result_command(client, demisto.args(), api_key))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
