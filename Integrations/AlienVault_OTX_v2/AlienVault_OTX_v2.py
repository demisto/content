import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''
from typing import Dict, Tuple, Union
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'AlienVault OTX v2'
INTEGRATION_COMMAND_NAME = 'alienvault'
INTEGRATION_CONTEXT_NAME = 'AlienVaultOTX'
DEFAULT_THRESHOLD = int(demisto.params().get('default_threshold', 2))
TOKEN = demisto.params().get('api_token')


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self.query(section='IPv4', argument='8.8.8.8')

    def query(self, section: str, argument: str = None, sub_section: str = 'general', params: dict = None) -> Dict:
        """Query the specified kwargs.

        Args:
            section: indicator type
            argument: indicator value
            sub_section: sub section of api
            params: params to send in http request

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        if section == 'pulses':
            suffix = f'{section}/{argument}'
        elif argument and sub_section:
            suffix = f'indicators/{section}/{argument}/{sub_section}'
        else:
            suffix = f'{section}/{sub_section}'
        # Send a request using our http_request wrapper
        if sub_section == 'passive_dns':
            return self._http_request('GET',
                                      url_suffix=suffix,
                                      params=params,
                                      timeout=30)
        return self._http_request('GET',
                                  url_suffix=suffix,
                                  params=params)


''' HELPER FUNCTIONS '''


def calculate_dbot_score(pulse_info: Union[dict, None]) -> float:
    """
    calculate DBot score for query
    :param pulse_info: returned from general section as dictionary
    :return: score - good (if 0), bad (if grater than default), suspicious if between
    """
    default_threshold = int(DEFAULT_THRESHOLD)
    if isinstance(pulse_info, dict):
        count = int(pulse_info.get('count', '0'))
        if count and count >= 0:
            if count == 0:
                return dbotscores['Low']

            if 0 < count < default_threshold:
                return dbotscores['Medium']

            if count >= default_threshold:
                return dbotscores['High']
    return 0


def create_list_by_ec(list_entries: list, list_type: str) -> list:
    def create_entry_by_ec(entry: dict) -> dict:
        if list_type == 'passive_dns':
            return ({
                'Hostname': entry.get('hostname'),
                'IP': entry.get('address'),
                'Type': entry.get('asset_type'),
                'FirstSeen': entry.get('first'),
                'LastSeen': entry.get('last')
            })

        if list_type == 'url_list':
            return assign_params(**{
                'Data': entry.get('url')
            })

        if list_type == 'hash_list':
            return assign_params(**{
                'Hash': entry.get('hash')
            })

        # should not get here
        return {}

    return [create_entry_by_ec(entry) for entry in list_entries]


def create_pulse_by_ec(entry: dict) -> dict:
    pulse_by_ec = {
        'ID': entry.get('id'),
        'Author': {
            'ID': entry.get('author', {}).get('id'),
            'Username': entry.get('author', {}).get('username')
        },
        'Count': entry.get('indicator_count'),
        'Modified': entry.get('modified_text'),
        'Name': entry.get('name'),
        'Source': entry.get('pulse_source'),
        'SubscriberCount': entry.get('subscriber_count'),
        'Tags': entry.get('tags'),
        'Description': entry.get('description')
    }
    return assign_params(**pulse_by_ec)


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> Tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'city' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def ip_command(client: Client, ip_address: str, ip_version: str) -> Tuple[str, Dict, Dict]:
    """ Enrichment for IPv4/IPv6

    Args:
        client: Client object with request
        ip_address: ip address
        ip_version: IPv4 or IPv6

    Returns:
        Outputs
    """
    raw_response = client.query(section=ip_version,
                                argument=ip_address)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for {ip_version} query'
        context_entry: dict = {
            outputPaths.get("ip"): {
                'Address': raw_response.get('indicator'),
                'ASN': raw_response.get('asn'),
                'Geo': {
                    'Country': raw_response.get('country_code'),
                    'Location': f'{raw_response.get("latitude")},{raw_response.get("longitude")}'
                }
            },
            f'AlienVaultOTX.IP(val.IP && val.IP === obj.IP)': {
                'IP': {
                    'Reputation': raw_response.get('reputation'),
                    'IP': ip_address
                }
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(raw_response.get('pulse_info', {})),
                'Type': ip_version,
                'Vendor': 'AlienVault OTX v2'
            }
        }

        human_readable = tableToMarkdown(t=context_entry.get(outputPaths.get("ip")),
                                         name=title)
        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def domain_command(client: Client, domain: str) -> Tuple[str, Dict, Dict]:
    """Enrichment for domain

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.query(section='domain',
                                argument=domain)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for Domain query'
        context_entry: dict = {
            outputPaths.get("domain"): {
                'Name': raw_response.get('indicator')
            },
            f'AlienVaultOTX.Domain(val.Alexa && val.Alexa === obj.Alexa &&'
            f'val.Whois && val.Whois === obj.Whois)': {
                'Name': raw_response.get('indicator'),
                'Alexa': raw_response.get('alexa'),
                'Whois': raw_response.get('whois')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(raw_response.get('pulse_info')),
                'Type': 'domain',
                'Vendor': 'AlienVault OTX v2'
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            f'AlienVaultOTX.Domain(val.Alexa && val.Alexa === obj.Alexa &&'
            f'val.Whois && val.Whois === obj.Whois)'),
            name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def file_command(client: Client, file: str) -> Tuple[str, Dict, Dict]:
    """Enrichment for file hash MD5/SHA1/SHA256

    Args:
        client: Client object with request
        file: File hash MD5/SHA1/SHA256

    Returns:
        Outputs
    """
    raw_response_analysis = client.query(section='file',
                                         argument=file,
                                         sub_section='analysis')
    raw_response_general = client.query(section='file',
                                        argument=file)
    if raw_response_analysis and raw_response_general:
        title = f'{INTEGRATION_NAME} - Results for File hash query'
        shortcut = raw_response_analysis.get('analysis', {}).get('info', {}).get('results', {})
        context_entry: dict = {
            outputPaths.get("file"): {
                'MD5': shortcut.get('md5'),
                'SHA1': shortcut.get('sha1'),
                'SHA256': shortcut.get('sha256'),
                'SSDeep': shortcut.get('ssdeep'),
                'Size': shortcut.get('filesize'),
                'Type': shortcut.get('file_type'),
                'Malicious': {
                    'PulseIDs': raw_response_general.get('pulse_info', {}).get('pulses')
                }
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response_general.get('indicator'),
                'Score': calculate_dbot_score(raw_response_general.get('pulse_info', {})),
                'Type': 'file',
                'Vendor': 'AlienVault OTX v2'
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=context_entry.get(outputPaths.get("file")))

        return human_readable, context_entry, {**raw_response_general, **raw_response_analysis}
    else:
        return f'{INTEGRATION_NAME} - Could not find any raw_response_analysis for given query', {}, {}


@logger
def url_command(client: Client, url: str) -> Tuple[str, Dict, Dict]:
    """Enrichment for url

    Args:
        client: Client object with request
        url:  url address

    Returns:
        Outputs
    """
    raw_response = client.query(section='url',
                                argument=url)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for url query'
        context_entry: dict = {
            outputPaths.get("url"): {
                'Data': raw_response.get('indicator')
            },
            f'AlienVaultOTX.URL(val.Url && val.Url === obj.Url)': {
                'Url': url,
                'Hostname': raw_response.get('hostname'),
                'Domain': raw_response.get('domain'),
                'Alexa': raw_response.get('alexa'),
                'Whois': raw_response.get('whois')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': str(calculate_dbot_score(raw_response.get('pulse_info'))),
                'Type': 'url',
                'Vendor': 'AlienVault OTX v2'
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(f'AlienVaultOTX.URL(val.Url && val.Url === obj.Url)', {}).get('URL'),
                                         name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_search_hostname_command(client: Client, hostname: str) -> Tuple[str, Dict, Dict]:
    """Search for hostname details

    Args:
        client: Client object with request
        hostname: hostname address

    Returns:
        Outputs
    """
    raw_response = client.query(section='hostname',
                                argument=hostname)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for Hostname query'
        context_entry: dict = {
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': {
                'Hostname': raw_response.get('indicator')
            },
            f'AlienVaultOTX.Endpoint(val.Alexa && val.Alexa === obj.Alexa &&'
            f'val.Whois && val.Whois === obj.Whois)': {
                'Hostname': raw_response.get('indicator'),
                'Alexa': raw_response.get('alexa'),
                'Whois': raw_response.get('whois')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(raw_response.get('pulse_info')),
                'Type': 'hostname',
                'Vendor': 'AlienVault OTX v2'
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=context_entry.get(
                                             f'AlienVaultOTX.Endpoint(val.Alexa && val.Alexa === obj.Alexa &&'
                                             f'val.Whois && val.Whois === obj.Whois)'))

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_search_cve_command(client: Client, cve_id: str) -> Tuple[str, Dict, Dict]:
    """Get Common Vulnerabilities and Exposures by id

    Args:
        client: Client object with request
        cve_id: CVE id

    Returns:
        Outputs
    """
    raw_response = client.query(section='cve',
                                argument=cve_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for Hostname query'
        context_entry: dict = {
            outputPaths.get("cve"): {
                'ID': raw_response.get('indicator'),
                'CVSS': raw_response.get('cvss', {}).get('Score'),
                'Published': raw_response.get('date_created'),
                'Modified': raw_response.get('date_modified'),
                'Description': raw_response.get('description')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(raw_response.get('pulse_info')),
                'Type': 'cve',
                'Vendor': 'AlienVault OTX v2'
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(outputPaths.get("cve")),
                                         name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_related_urls_by_indicator_command(client: Client, indicator_type: str, indicator: str)\
        -> Tuple[str, Dict, Dict]:
    """Get related urls by indicator (IPv4,IPv6,domain,hostname,url)

    Args:
        client: Client object with request
        indicator_type: IPv4,IPv6,domain,hostname,url
        indicator: indicator its self (google.com)

    Returns:
        Outputs
    """
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='url_list')
    if raw_response:
        title = f'{INTEGRATION_NAME} - Related url list to queried indicator'
        context_entry: list = create_list_by_ec(list_entries=raw_response.get('url_list', {}), list_type='url_list')
        context: dict = {
            f'AlienVaultOTX.URL(val.URL.Data && val.URL.Data == obj.URL.Data)': context_entry
        }
        human_readable = tableToMarkdown(t=context_entry,
                                         name=title)

        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_related_hashes_by_indicator_command(client: Client, indicator_type: str, indicator: str)\
        -> Tuple[str, Dict, Dict]:
    """Get related file hashes by indicator (IPv4,IPv6,domain,hostname)

       Args:
           client: Client object with request
           indicator_type: IPv4,IPv6,domain,hostname
           indicator: indicator its self (google.com)

       Returns:
           Outputs
       """
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='malware')
    if raw_response:
        title = f'{INTEGRATION_NAME} - Related malware list to queried indicator'
        context_entry: dict = {
            f'AlienVaultOTX.File(val.File.Hash && val.File.Hash == obj.File.Hash)':
            create_list_by_ec(list_entries=raw_response.get('data', {}), list_type='hash_list')
        }
        human_readable = tableToMarkdown(t=context_entry.get(f'AlienVaultOTX.File(val.File.Hash && val.File.Hash \
                                            == obj.File.Hash)'),
                                         name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_passive_dns_data_by_indicator_command(client: Client, indicator_type: str, indicator: str)\
        -> Tuple[str, Dict, Dict]:
    """Get related file hashes by indicator (IPv4,IPv6,domain,hostname)

       Args:
           client: Client object with request
           indicator_type: IPv4,IPv6,domain,hostname
           indicator: indicator its self (google.com)

       Returns:
           Outputs
       """
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='passive_dns')
    if raw_response:
        title = f'{INTEGRATION_NAME} - Related passive dns list to queried indicator'
        context_entry: dict = {
            f'AlienVaultOTX.PassiveDNS(val.PassiveDNS.Hostname && val.PassiveDNS.Hostname == obj.PassiveDNS.Hostname &&'
            f'val.PassiveDNS.LastSeen && val.PassiveDNS.LastSeen == obj.PassiveDNS.LastSeen &&'
            f'val.PassiveDNS.IP && val.PassiveDNS.IP == obj.PassiveDNS.IP)':
            create_list_by_ec(list_entries=raw_response.get('passive_dns', {}), list_type='passive_dns')
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            f'AlienVaultOTX.PassiveDNS(val.PassiveDNS.Hostname && val.PassiveDNS.Hostname == obj.PassiveDNS.Hostname &&'
            f'val.PassiveDNS.LastSeen && val.PassiveDNS.LastSeen == obj.PassiveDNS.LastSeen &&'
            f'val.PassiveDNS.IP && val.PassiveDNS.IP == obj.PassiveDNS.IP)'),
            name=title)
        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_search_pulses_command(client: Client, page: str) -> Tuple[str, Dict, Dict]:
    """Get pulse page by number of the page

    Args:
        client: Client object with request
        page: pulse page number

    Returns:
        Outputs
    """
    raw_response = client.query(section='search',
                                sub_section='pulses',
                                params={'page': page})
    if raw_response:
        title = f'{INTEGRATION_NAME} - pulse page {page}'
        context_entry: dict = {
            f'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID && '
            f'val.Modified && val.Modified == obj.Modified)':
            [create_pulse_by_ec(entry) for entry in raw_response.get('results', {})]
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            f'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID && '
            f'val.Modified && val.Modified == obj.Modified)'),
            name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_pulse_details_command(client: Client, pulse_id: str) -> Tuple[str, Dict, Dict]:
    """Get pulse by ID

    Args:
        client: Client object with request
        pulse_id: pulse ID

    Returns:
        Outputs
    """
    raw_response = client.query(section='pulses',
                                argument=pulse_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - pulse id details'
        context_entry: dict = {
            f'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID)': {
                'Description': raw_response.get('description'),
                'Created': raw_response.get('created'),
                'Author': {
                    'Username': raw_response.get('author', {}).get('username')
                },
                'ID': raw_response.get('id'),
                'Name': raw_response.get('name'),
                'Tags': raw_response.get('tags'),
                'TargetedCountries': raw_response.get('targeted_countries')
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            f'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID)'),
            name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    base_url = urljoin(params.get('url'), '/api/v1/')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(
        base_url=base_url,
        headers={'X-OTX-API-KEY': TOKEN},
        verify=verify_ssl,
        proxy=proxy
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        'ip': ip_command,
        'domain': domain_command,
        'file': file_command,
        'url': url_command,
        f'{INTEGRATION_COMMAND_NAME}-search-hostname': alienvault_search_hostname_command,
        f'{INTEGRATION_COMMAND_NAME}-search-ipv6': ip_command,
        f'{INTEGRATION_COMMAND_NAME}-search-cve': alienvault_search_cve_command,
        f'{INTEGRATION_COMMAND_NAME}-get-related-urls-by-indicator': alienvault_get_related_urls_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-get-related-hashes-by-indicator': alienvault_get_related_hashes_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-get-passive-dns-data-by-indicator': alienvault_get_passive_dns_data_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-search-pulses': alienvault_search_pulses_command,
        f'{INTEGRATION_COMMAND_NAME}-get-pulse-details': alienvault_get_pulse_details_command
    }
    try:
        if command == f'{INTEGRATION_COMMAND_NAME}-search-ipv6':
            readable_output, outputs, raw_response = commands[command](client=client,
                                                                       ip_address=demisto.args().get('ip'),
                                                                       ip_version='IPv6')
        elif command == 'ip':
            readable_output, outputs, raw_response = commands[command](client=client,
                                                                       ip_address=demisto.args().get('ip'),
                                                                       ip_version='IPv4')
        else:
            readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
        return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
