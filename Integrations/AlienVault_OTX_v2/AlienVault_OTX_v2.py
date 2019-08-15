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
BASE_URL = 'https://otx.alienvault.com'

# TOKEN
TOKEN = demisto.params().get('api_token')


''' HELPER FUNCTIONS '''


def http_request(source, value, command=None, section=None, params=None):
    if source == 'pulses':
        headers = {
            'X-OTX-API-KEY': TOKEN
        }
        if params == {}:
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
        raise Exception('Error in API call to AlienVault_OTX_V2 [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def geo_by_ec(lat: str, long: str):
    """
    return geo point by entry context format lat,long
    :param lat: latitude
    :param long: longitude
    :return: latitude,longitude
    """
    if lat and long:
        return str(lat) + ',' + str(long)
    return None


def dbot_score(pulse_info: dict):
    """
    calculate score for query
    :param pulse_info: returned from general section as dictionary
    :return: score - good (if 0), bad (if grater than default), suspicious if between
    """
    bad_score = 1
    count = pulse_info.get('count')
    if isinstance(count, int):
        if count == 0:
            return 'good'
        if 0 < count < bad_score:
            return 'suspicious'
        if count > bad_score:
            return 'bad'
    return 'unknown'


def create_page_pulse(page_entry: list):
    """"""
    def create_pulse_by_ec(pulse: dict) -> dict:
        pulse_by_ec = {
            'ID': pulse.get('id'),
            'Author': {
                'Id': pulse['author'].get('id') if pulse.get('author') else None,
                'Username': pulse['author'].get('username') if pulse.get('author') else None
            },
            'Count': pulse.get('indicator_count'),
            'Modified': pulse.get('modified_text'),
            'Name': pulse.get('name'),
            'Source': pulse.get('pulse_source'),
            'SubscriberCount': pulse.get('subscriber_count'),
            'Tags': pulse.get('tags'),
            'Description': pulse.get('description')
        }
        return remove_none(pulse_by_ec)

    return [create_pulse_by_ec(pulse) for pulse in page_entry]


def remove_none(obj):
    """
    Get objects and remove None or empty strings.
    :param obj: iterable object
    :return: Obj with None value removed
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(remove_none(x) for x in obj if x is not (None or ''))
    elif isinstance(obj, dict):
        return type(obj)((remove_none(k), remove_none(v))
                         for k, v in obj.items() if k is not None and v is not (None or ''))
    else:
        return obj


''' COMMANDS + REQUESTS FUNCTIONS '''


# Test button
def test_module():
    """
    Performs basic get request to get item samples
    """
    pass


# IP commmand
def ip():
    api_path = {
        'source': 'indicators',
        'command': 'IPv4',
        'value': demisto.args().get('ip'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])

    # Define entry context
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


def ip_command():
    raw, ec = ip()

    human_readable = ''
    # Table 1
    if ec.get('IP'):
        if ec.get('IP').get('Geo'):
            human_readable += tableToMarkdown(t=ec.get('IP').get('Geo'),
                                              name='Geographic info')
    # Table 2
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX').get('IP'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX').get('IP'),
                                              name='Reputation score')
    # Table 3
    keys_others = ['ASN', 'Address']
    ec_others = {k: ec['IP'][k] for k in ec['IP'] if k in keys_others}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='General')

    # Table 4
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# Domain command
def domain():
    api_path = {
        'source': 'indicators',
        'command': 'domain',
        'value': demisto.args().get('domain'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])
    ec = {
        'Domain': {
            'Name': raw.get('indicator'),
        },
        'AlienVaultOtx': {
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


def domain_command():
    raw, ec = domain()

    human_readable = ''
    # Table 1
    if ec.get('Domain'):
        human_readable += tableToMarkdown(t=ec.get('Domain'),
                                          name='Domain')
    # Table 2
    if ec.get('AlienVaultOtx'):
        if ec.get('Domain'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOtx').get('Domain'),
                                              name='Domain exrta serivces')
    # Table 3
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-ipv6 command
def alienvault_search_ipv6():
    api_path = {
        'source': 'indicators',
        'command': 'IPv6',
        'value': demisto.args().get('ip'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])

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


def alienvault_search_ipv6_command():
    raw, ec = alienvault_search_ipv6()

    human_readable = ''
    # Table 1
    if ec.get('IP'):
        if ec.get('IP').get('Geo'):
            human_readable += tableToMarkdown(t=ec.get('IP').get('Geo'),
                                              name='Geographic info')
    # Table 2
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX').get('IP'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX').get('IP'),
                                              name='Reputation score')
    # Table 3
    keys_others = ['ASN', 'Address']
    ec_others = {k: ec['IP'][k] for k in ec['IP'] if k in keys_others}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='General')

    # Table 4
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-hostname command
def alienvault_search_hostname():
    api_path = {
        'source': 'indicators',
        'command': 'hostname',
        'value': demisto.args().get('hostname'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])
    ec = {
        'Hostname': raw.get('indicator'),
        'AlienVaultOTX': {
            'Alexa': raw.get('alexa'),
            'Whois': raw.get('whois')
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


def alienvault_search_hostname_command():
    raw, ec = alienvault_search_hostname()
    human_readable = ''

    # Table 1
    human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX'),
                                      name='Hostname')
    # Table 2
    keys_others = ['Hostname']
    ec_others = {k: ec[k] for k in ec if k in keys_others}
    human_readable += tableToMarkdown(t=ec_others,
                                      name='General')
    # Table 3
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# file command
def file():
    api_path = {
        'source': 'indicators',
        'command': 'file',
        'value': demisto.args().get('file'),
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


def file_command():
    raw, ec = file()

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
    # Table 3
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-search-cve command
def alienvault_search_cve():
    api_path = {
        'source': 'indicators',
        'command': 'cve',
        'value': demisto.args().get('cve-id'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])

    ec = {
        'CVE': {
            'Id': raw.get('indicator'),
            # TODO Define
            'CVSS': '',
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


def alienvault_search_cve_command():
    raw, ec = alienvault_search_cve()

    # TODO change after define CVSS

    human_readable = ''
    # Table 1
    if ec.get('CVE'):
        human_readable = tableToMarkdown(t=ec['CVE'],
                                         name='Common Vulnerabilities and Exposures')
    # Table 2
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-related-urls-by-indicator command
def alienvault_get_related_urls_by_indicator():
    ec = {
        'URL': {
            'Data': ''
        }
    }
    return ec


def alienvault_get_related_urls_by_indicator_command():
    pass


# alienvault-get-related-hashes-by-indicator command
def alienvault_get_related_hashes_by_indicator():
    ec = {
        'AlienVaultOTX': {
            'File': {
                'Hash': ''
            }
        }
    }
    return ec


def alienvault_get_related_hashes_by_indicator_command():
    pass


# alienvault-get-passive-dns-data-by-indicator command
def alienvault_get_passive_dns_data_by_indicator():
    ec = {
        'AlienVaultOTX': {
            'PassiveDNS': {
                'Domain': '',
                'IP': '',
                'Type:': '',
                'FirstSeen': '',
                'LastSeen': ''
            }
        }
    }
    return ec


def alienvault_get_passive_dns_data_by_indicator_command():
    pass


# alienvault-search-pulses command
def alienvault_search_pulses():
    api_path = {
        'source': 'pulses',
        'value': demisto.args().get('pulse-id'),
        'command': 'search',
        'params': {'page': demisto.args().get('page')}
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       value=api_path['value'],
                       params=api_path['params'],
                       command=api_path['command'])

    ec = {
        'AlienVaultOTX': {
            'Pulses': create_page_pulse(raw.get('results'))
        }
    }

    return raw, ec


def alienvault_search_pulses_command():
    raw, ec = alienvault_search_pulses()

    human_readable = ''
    page = demisto.args().get('page')
    count = 1
    pulses = ec.get('AlienVaultOTX').get('Pulses')
    for pulse in pulses:
        human_readable += tableToMarkdown(t=pulse,
                                          name=f'Pulse number {count} from page {page}')
        count += 1

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


# alienvault-get-pulse-details command
def alienvault_get_pulse_details():
    api_path = {
        'source': 'pulses',
        'value': demisto.args().get('pulse-id'),
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       value=api_path['value'])

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


def alienvault_get_pulse_details_command():
    raw, ec = alienvault_get_pulse_details()

    human_readable = ''
    if ec.get('AlienVaultOTX'):
        if ec.get('AlienVaultOTX').get('Pulses'):
            if ec.get('AlienVaultOTX').get('Pulses').get('Author'):
                # Table 1
                human_readable = tableToMarkdown(t=ec['AlienVaultOTX']['Pulses']['Author'],
                                                 name='Pulse author')
            if ec.get('AlienVaultOTX').get('Pulses').get('Tags'):
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
def url():
    api_path = {
        'source': 'indicators',
        'command': 'url',
        'value': demisto.args().get('url'),
        'section': 'general'
    }

    # raw_data
    raw = http_request(source=api_path['source'],
                       command=api_path['command'],
                       value=api_path['value'],
                       section=api_path['section'])
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


def url_command():
    raw, ec = url()

    human_readable = ''
    # Table 1
    if ec.get('URL'):
        human_readable += tableToMarkdown(t=ec.get('URL'),
                                          name='URL')
    # Table 2
    if ec.get('AlienVaultOTX'):
        if ec.get('URL'):
            human_readable += tableToMarkdown(t=ec.get('AlienVaultOTX').get('URL'),
                                              name='URL AlienVaultOTX')
    # Table 3
    if ec.get('DBotScore'):
        human_readable += tableToMarkdown(t=ec.get('DBotScore'),
                                          name='DBotScore')

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


''' COMMANDS MANAGER / SWITCH PANEL '''

commands = {
    'test-module': test_module,
    'ip': ip_command,
    'domain': domain_command,
    'alienvault-search-ipv6': alienvault_search_ipv6_command,
    'alienvault-search-hostname': alienvault_search_hostname_command,
    'file': file_command,
    'alienvault-search-cve': alienvault_search_cve_command,
    'alienvault-get-related-urls-by-indicator': alienvault_get_related_urls_by_indicator_command,
    'alienvault-get-related-hashes-by-indicator': alienvault_get_related_hashes_by_indicator_command,
    'alienvault-get-passive-dns-data-by-indicator': alienvault_get_passive_dns_data_by_indicator_command,
    'alienvault-search-pulses': alienvault_search_pulses_command,
    'alienvault-get-pulse-details': alienvault_get_pulse_details_command,
    'url': url_command
}


def main():
    handle_proxy()
    try:
        commands[demisto.command()]()
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

main()
