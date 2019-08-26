import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Integration configuration
USE_SSL_VERIFY = not demisto.params().get('insecure', False)

# Service base URL
BASE_URL = demisto.params().get('server', 'https://otx.alienvault.com')

# TOKEN
TOKEN = demisto.params().get('api_token')


''' HELPER FUNCTIONS '''


def http_request(source, value=None, command=None, section=None, params=None):
    if source == 'pulses':
        headers = {
            'X-OTX-API-KEY': TOKEN
        }
        if not (params or command):
            url = f'{BASE_URL}/api/v1/{source}/{value}'
        else:
            url = f'{BASE_URL}/api/v1/{command}/{source}'
    else:
        url = f'{BASE_URL}/api/v1/{source}/{command}/{value}/{section}'
        headers = {}

    res = requests.request(
        method='GET',
        url=url,
        verify=USE_SSL_VERIFY,
        params=params,
        data=None,
        headers=headers
    )

    if res.status_code not in {200}:
        raise Exception(f'Error in API call to AlienVault_OTX_V2 {res.status_code} - {res.reason}')

    return res.json()


def geo_by_ec(lat: str, long_: str):
    """
    return geo point by entry context format lat,long
    :param lat: latitude
    :param long_: longitude
    :return: latitude,longitude
    """
    if lat and long_:
        return str(lat) + ',' + str(long_)
    return None


def dbot_score(pulse_info: dict):
    """
    calculate dBot score for query
    :param pulse_info: returned from general section as dictionary
    :return: score - good (if 0), bad (if grater than default), suspicious if between
    """
    default_threshold = 2
    count = pulse_info.get('count')
    if isinstance(count, int) and count >= 0:
        if count == 0:
            return 'good'
        if 0 < count < default_threshold:
            return 'suspicious'
        if count >= default_threshold:
            return 'bad'
    return 'unknown'


def create_page_pulse(page_entry: list) -> list:
    """
    Rearrange all key in the pulses by entry context definition
    :param page_entry: list of pulses in a page
    :return: page entry by entry context definition
    """
    def create_pulse_by_ec(entry: dict) -> dict:
        pulse_by_ec = {
            'ID': entry.get('id'),
            'Author': {
                'Id': entry.get('author', {}).get('id'),
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
        return remove_none(pulse_by_ec)

    return [create_pulse_by_ec(entry) for entry in page_entry]


def create_list_by_ec(list_entries: list, list_type: str):
    def create_entry_by_ec(entry: dict):
        if list_type == 'passive_dns':
            return ({
                'Hostname': entry.get('hostname'),
                'Ip': entry.get('address'),
                'Type:': entry.get('asset_type'),
                'FirstSeen': entry.get('first'),
                'LastSeen': entry.get('last')
            })
        elif list_type == 'url_list':
            return remove_none({
                'Data': entry.get('url')
            })
        elif list_type == 'hash_list':
            return remove_none({
                'Hash': entry.get('hash')
            })
    return [create_entry_by_ec(entry) for entry in list_entries]


def remove_none(obj):
    """
    Get objects and remove None or empty strings.
    :param obj: iterable object
    :return: Obj with None value removed
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(remove_none(x) for x in obj if x is not None)
    elif isinstance(obj, dict):
        return type(obj)((remove_none(k), remove_none(v)) for k, v in obj.items() if v is not None)
    else:
        return obj


''' COMMANDS + REQUESTS FUNCTIONS '''


# Test button
def test_module():
    """
    Performs basic get request to get item samples
    """
    ipv4(ip='8.8.8.8')
    demisto.results('ok')


# IP command
@logger
def ipv4(ip):
    api_path = {
        'source': 'indicators',
        'command': 'IPv4',
        'value': ip,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'IP': {
            'Address': raw.get('indicator'),
            'ASN': raw.get('asn'),
            'Geo': {
                'Country': raw.get('country_code'),
                'Location': geo_by_ec(raw.get('latitude'), raw.get('longitude'))
            }
        },
        'AlienVaultOTX': {
            'IP': {
                'Reputation': raw.get('reputation')
            }
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'IPv6',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)

    return raw, ec


@logger
def ipv4_command(ip):
    raw, ec = ipv4(ip)

    human_readable = ''
    # Table 1
    if ec.get('IP'):
        if ec.get('IP', {}).get('Geo'):
            human_readable += tableToMarkdown(t=ec.get('IP').get('Geo'),
                                              name='Geographic info')
    # Table 2
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX', {}).get('IP'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX').get('IP'),
                                              name='Reputation score')
    # Table 3
    keys_others = ['ASN', 'Address']
    ec_others = {k: ec['IP'][k] for k in ec['IP'] if k in keys_others}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='General')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# Domain command
@logger
def domain_sub(domain):
    api_path = {
        'source': 'indicators',
        'command': 'domain',
        'value': domain,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'Domain': {
            'Name': raw.get('indicator'),
        },
        'AlienVaultOTX': {
            'Domain': {
                'Alexa': raw.get('alexa'),
                'Whois': raw.get('whois')
            }
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'Domain',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)

    return raw, ec


@logger
def domain_command(domain):
    raw, ec = domain_sub(domain)

    human_readable = ''
    # Table 1
    if ec.get('Domain'):
        human_readable += tableToMarkdown(t=ec.get('Domain'),
                                          name='Domain')
    # Table 2
    if ec.get('AlienVaultOTX', {}).get('Domain'):
        human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX', {}).get('Domain'),
                                          name='Domain extra services')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-ipv6 command
@logger
def alienvault_search_ipv6(ip):
    api_path = {
        'source': 'indicators',
        'command': 'IPv6',
        'value': ip,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'IP': {
            'Address': raw.get('indicator'),
            'ASN': raw.get('asn'),
            'Geo': {
                'Country': raw.get('country_code'),
                'Location': geo_by_ec(raw.get('latitude'), raw.get('longitude'))
            }
        },
        'AlienVaultOTX': {
            'IP': {
                'Reputation': raw.get('reputation')
            }
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'IPv6',
            'Vendor': 'AlienVault OTX'
        }
    }
    ec = remove_none(ec)

    return raw, ec


@logger
def alienvault_search_ipv6_command(ip):
    raw, ec = alienvault_search_ipv6(ip)

    human_readable = ''
    # Table 1
    if ec.get('IP'):
        if ec.get('IP', {}).get('Geo'):
            human_readable += tableToMarkdown(t=ec.get('IP').get('Geo'),
                                              name='Geographic info')
    # Table 2
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX', {}).get('IP'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX').get('IP'),
                                              name='Reputation score')
    # Table 3
    keys_others = ['ASN', 'Address']
    ec_others = {k: ec['IP'][k] for k in ec['IP'] if k in keys_others}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='General')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-hostname command
@logger
def alienvault_search_hostname(hostname):
    api_path = {
        'source': 'indicators',
        'command': 'hostname',
        'value': hostname,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'Endpoint': {
            'Hostname': raw.get('indicator'),
            'AlienVaultOTX': {
                'Alexa': raw.get('alexa'),
                'Whois': raw.get('whois')
            }
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'Hostname',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)

    return raw, ec


@logger
def alienvault_search_hostname_command(hostname):
    raw, ec = alienvault_search_hostname(hostname)
    human_readable = ''

    # Table 1
    if ec.get('Endpoint'):
        if ec['Endpoint'].get('AlienVaultOTX'):
            human_readable += tableToMarkdown(t=ec['Endpoint'].get('AlienVaultOTX'),
                                              name='Other services')
        # Table 2
        keys_others = ['Hostname']
        ec_others = {k: ec['Endpoint'][k] for k in ec['Endpoint'] if k in keys_others}
        human_readable += tableToMarkdown(t=ec_others,
                                          name='General')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# file command
@logger
def file_sub(file):
    api_path = {
        'source': 'indicators',
        'command': 'file',
        'value': file,
        'section': ['analysis', 'general']
    }
    # raw_data
    raw_analysis = http_request(source=api_path['source'],
                                command=api_path['command'],
                                value=api_path['value'],
                                section=api_path['section'][0])
    raw_general = http_request(source=api_path['source'],
                               command=api_path['command'],
                               value=api_path['value'],
                               section=api_path['section'][1])
    # Entry context
    ec = {
        'File': {
            'MD5': raw_analysis.get('analysis').get('info').get('results').get('md5'),
            'SHA1': raw_analysis.get('analysis').get('info').get('results').get('sha1'),
            'SHA256': raw_analysis.get('analysis').get('info').get('results').get('sha256'),
            'SSDeep': raw_analysis.get('analysis').get('info').get('results').get('ssdeep'),
            'Size': raw_analysis.get('analysis').get('info').get('results').get('filesize'),
            'Type': raw_analysis.get('analysis').get('info').get('results').get('file_type'),
            'Malicious': {
                'PulseIDs': raw_general.get('pulse_info').get('pulses')
            }
        },
        'DBotScore': {
            'Indicator': raw_general.get('indicator'),
            'Score': dbot_score(raw_general.get('pulse_info')),
            'Type': 'File',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)
    raw = [raw_general, raw_analysis]

    return raw, ec


@logger
def file_command(file):
    raw, ec = file_sub(file)

    human_readable = ''
    # Table 1
    key_not_need = ['Malicious']
    ec_others = {k: ec['File'][k] for k in ec['File'] if k not in key_not_need}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='File')
    # Table 2
    if ec.get('Malicious'):
        human_readable += tableToMarkdown(t=ec.get('Malicious'),
                                          name='Malicioud pulse ids')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-cve command
@logger
def alienvault_search_cve(cve_id):
    api_path = {
        'source': 'indicators',
        'command': 'cve',
        'value': cve_id,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'CVE': {
            'Id': raw.get('indicator'),
            'CVSS': raw['cvss'].get('Score') if raw.get('cvss') else None,
            'Published': raw.get('date_created'),
            'Modified': raw.get('date_modified'),
            'Description': raw.get('description')
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'CVE',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)

    return raw, ec


@logger
def alienvault_search_cve_command(cve_id):
    raw, ec = alienvault_search_cve(cve_id)

    human_readable = ''
    # Table 1
    if ec.get('CVE'):
        human_readable = tableToMarkdown(t=ec['CVE'],
                                         name='Common Vulnerabilities and Exposures')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-related-urls-by-indicator command
@logger
def alienvault_get_related_urls_by_indicator(indicator_type, indicator):
    api_path = {
        'source': 'indicators',
        'command': indicator_type,
        'value': indicator,
        'section': 'url_list'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'AlienVaultOTX': {
            'URL': {
                'Data': create_list_by_ec(list_entries=raw.get('url_list'), list_type='url_list')
            }
        }
    }
    return raw, ec


@logger
def alienvault_get_related_urls_by_indicator_command(indicator_type, indicator, threshold_results=3):
    raw, ec = alienvault_get_related_urls_by_indicator(indicator_type, indicator)

    human_readable = ''
    # Add three tables at most by threshold 3, change value for more
    counter = 1
    entries = ec['AlienVaultOTX'].get('URL').get('Data')
    total_num_entries = len(entries)
    for entry in entries:
        human_readable += tableToMarkdown(t=entry,
                                          name=f'Url list entry {counter}/{total_num_entries}')
        counter += 1
        if counter > int(threshold_results):
            break

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-related-hashes-by-indicator
@logger
def alienvault_get_related_hashes_by_indicator(indicator_type, indicator):
    api_path = {
        'source': 'indicators',
        'command': indicator_type,
        'value': indicator,
        'section': 'malware'
    }

    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'AlienVaultOTX': {
            'File': {
                'Hash': create_list_by_ec(list_entries=raw.get('data'), list_type='hash_list')
            }
        }
    }

    return raw, ec


@logger
def alienvault_get_related_hashes_by_indicator_command(indicator_type, indicator, threshold_results=3):
    raw, ec = alienvault_get_related_hashes_by_indicator(indicator_type, indicator)

    human_readable = ''
    # Add three tables at most by threshold 3, change value for more
    counter = 1
    pulses = ec['AlienVaultOTX']['File']['Hash']
    total_num_pulse = len(pulses)
    for pulse in pulses:
        human_readable += tableToMarkdown(t=pulse,
                                          name=f'Hash number {counter}/{total_num_pulse}')
        counter += 1
        if counter > int(threshold_results):
            break

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-passive-dns-data-by-indicator command
@logger
def alienvault_get_passive_dns_data_by_indicator(indicator_type, indicator):
    api_path = {
        'source': 'indicators',
        'command': indicator_type,
        'value': indicator,
        'section': 'passive_dns'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'AlienVaultOTX': {
            'PassiveDNS': create_list_by_ec(list_entries=raw.get('passive_dns'), list_type='passive_dns')
        }
    }
    return raw, ec


@logger
def alienvault_get_passive_dns_data_by_indicator_command(indicator_type, indicator, threshold_results=3):
    raw, ec = alienvault_get_passive_dns_data_by_indicator(indicator_type, indicator)

    human_readable = ''
    # Add three tables at most by threshold 3, change value for more
    counter = 1
    entries = ec['AlienVaultOTX'].get('PassiveDNS')
    total_num_entries = len(entries)
    for entry in entries:
        human_readable += tableToMarkdown(t=entry,
                                          name=f'Passive DNS entry {counter}/{total_num_entries}')
        counter += 1
        if counter > int(threshold_results):
            break

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-pulses command
@logger
def alienvault_search_pulses(page):
    api_path = {
        'source': 'pulses',
        'command': 'search',
        'params': {'page': page}
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'AlienVaultOTX': {
            'Pulses': create_page_pulse(raw.get('results'))
        }
    }

    return raw, ec


@logger
def alienvault_search_pulses_command(page, threshold_results=3):
    raw, ec = alienvault_search_pulses(page)

    human_readable = ''
    # Add three tables at most by threshold 3, change value for more
    counter = 1
    page_num = page
    pulses = ec.get('AlienVaultOTX', {}).get('Pulses')
    total_num_pulse = len(pulses)
    for pulse in pulses:
        human_readable += tableToMarkdown(t=pulse,
                                          name=f'Pulse number {counter}/{total_num_pulse} from page {page_num}')
        counter += 1
        if counter > int(threshold_results):
            break

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-pulse-details command
@logger
def alienvault_get_pulse_details(pulse_id):
    api_path = {
        'source': 'pulses',
        'value': pulse_id,
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'AlienVaultOTX': {
            'Pulses': {
                'Description': raw.get('description'),
                'Created': raw.get('created'),
                'Author': {
                    'Username': raw.get('author').get('username')
                },
                'ID': raw.get('id'),
                'Name': raw.get('name'),
                'Tags': raw.get('tags'),
                'TargetedCountries': raw.get('targeted_countries')
            }
        }
    }

    ec = remove_none(ec)

    return raw, ec


@logger
def alienvault_get_pulse_details_command(pulse_id):
    raw, ec = alienvault_get_pulse_details(pulse_id)

    human_readable = ''
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX', {}).get('Pulses'):
            if ec.get('AlienVaultOTX', {}).get('Pulses').get('Author'):
                # Table 1
                human_readable = tableToMarkdown(t=ec['AlienVaultOTX']['Pulses']['Author'],
                                                 name='Pulse author')
            if ec.get('AlienVaultOTX', {}).get('Pulses').get('Tags'):
                # Table 2
                human_readable = tableToMarkdown(t={'Tags': ec['AlienVaultOTX']['Pulses']['Tags']},
                                                 name='Tags')
            key_not_need = ['Author', 'Tags']
            ec_other = {k: ec['AlienVaultOTX']['Pulses'][k] for k in ec['AlienVaultOTX']['Pulses'] if k not in key_not_need}
            # Table 3
            human_readable += tableToMarkdown(t=ec_other,
                                              name='Pulses General')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# url command
@logger
def url_sub(url):
    api_path = {
        'source': 'indicators',
        'command': 'url',
        'value': url,
        'section': 'general'
    }
    # raw_data
    raw = http_request(**api_path)
    # Entry context
    ec = {
        'URL': {
            'Data': raw.get('indicator')
        },
        'AlienVaultOTX': {
            'URL': {
                'Hostname': raw.get('hostname'),
                'Domain': raw.get('domain'),
                'Alexa': raw.get('alexa'),
                'Whois': raw.get('whois')
            }
        },
        'DBotScore': {
            'Indicator': raw.get('indicator'),
            'Score': dbot_score(raw.get('pulse_info')),
            'Type': 'URL',
            'Vendor': 'AlienVault OTX'
        }
    }

    ec = remove_none(ec)
    return raw, ec


@logger
def url_command(url):
    raw, ec = url_sub(url)

    human_readable = ''
    # Table 1
    if ec.get('URL'):
        human_readable += tableToMarkdown(t=ec.get('URL'),
                                          name='URL')
    # Table 2
    if ec.get('AlienVaultOTX', {}).get('URL'):
        human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX', {}).get('URL'),
                                          name='URL AlienVaultOTX')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'ip': ipv4_command,
    'domain': domain_command,
    'url': url_command,
    'file': file_command,
    'alienvault-search-ipv6': alienvault_search_ipv6_command,
    'alienvault-search-hostname': alienvault_search_hostname_command,
    'alienvault-search-cve': alienvault_search_cve_command,
    'alienvault-get-related-urls-by-indicator': alienvault_get_related_urls_by_indicator_command,
    'alienvault-get-related-hashes-by-indicator': alienvault_get_related_hashes_by_indicator_command,
    'alienvault-get-passive-dns-data-by-indicator': alienvault_get_passive_dns_data_by_indicator_command,
    'alienvault-search-pulses': alienvault_search_pulses_command,
    'alienvault-get-pulse-details': alienvault_get_pulse_details_command,
}


def main():
    LOG(f'Alienvault OTX called with command {demisto.command()}')
    handle_proxy()
    try:
        COMMANDS[demisto.command()](**demisto.args())
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()
