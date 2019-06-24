import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import traceback
import requests
from datetime import datetime as dt

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

THRESHOLD = int(demisto.params().get('threshold', 1))

COMPROMISED_IS_MALICIOUS = demisto.params().get('compromised_is_malicious', False)

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
}

''' HELPER FUNCTIONS '''


def http_request(method, command, data=None):
    url = f'{API_URL}/{command}/'
    demisto.info(f'{method} {url}')
    res = requests.request(method,
                           url,
                           verify=USE_SSL,
                           data=data,
                           headers=HEADERS)

    if res.status_code != 200:
        raise Exception(f'Error in API call {url} [{res.status_code}] - {res.reason}')

    return res


def query_url_information(url):
    return http_request('POST',
                        'url',
                        f'url={url}')


def query_host_information(host):
    return http_request('POST',
                        'host',
                        f'host={host}')


def query_payload_information(hash_type, hash):
    return http_request('POST',
                        'https://urlhaus-api.abuse.ch/v1/payload/',  # disable-secrets-detection
                        f'{hash_type}_hash={hash}')


def query_tag_information(tag):
    return http_request('POST',
                        'https://urlhaus-api.abuse.ch/v1/tag/',  # disable-secrets-detection
                        f'tag={tag}')


def query_signature_information(signature):
    return http_request('POST',
                        'https://urlhaus-api.abuse.ch/v1/signature/',  # disable-secrets-detection
                        f'signature={signature}')


def download_malware_sample(sha256, dest):
    res = requests.get(f'https://urlhaus-api.abuse.ch/v1/download/{sha256}/')  # disable-secrets-detection
    with open(dest, 'wb') as malware_sample:
        malware_sample.write(res.content)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('POST', 'url')


def calculate_dbot_score(blacklists, threshold, compromised_is_malicious):
    blacklist_appearances = []
    for blacklist, status in blacklists.items():
        if blacklist == 'spamhaus_dbl':
            if status.endswith('domain') or (status.startswith('abused') and compromised_is_malicious):
                blacklist_appearances.append((blacklist, status))
        elif status == 'listed':
            blacklist_appearances.append((blacklist,))

    if len(blacklist_appearances) >= threshold:
        description = ''
        for appearance in blacklist_appearances:
            if len(appearance) == 1:
                description += f'Listed in {appearance[0]}. '
            elif len(appearance) == 2:
                description += f'Listed as {appearance[1]} in {appearance[0]}. '
            else:
                raise Exception('Unknown blacklist format in the response')

        return 3, description
    elif len(blacklist_appearances) > 0:
        return 2, None
    else:
        return 1, None


def url_command():
    url = demisto.args().get('url')
    try:
        url_information = query_url_information(url).json()

        ec = {
            'URL': {
                'Data': url
            },
            'DBotScore': {
                'Type': 'url',
                'Vendor': 'URLhaus',
                'Indicator': url
            }
        }

        if url_information['query_status'] == 'ok':
            # URLHaus output
            date_added = dt.strptime(url_information.get('date_added', '1970-01-01 00:00:00 UTC'),
                                     '%Y-%m-%d %H:%M:%S UTC').strftime('%Y-%m-%dT%H:%M:%S')
            urlhaus_data = {
                'ID': url_information.get('id', ''),
                'Status': url_information.get('url_status', ''),
                'Host': url_information.get('host', ''),
                'DateAdded': date_added,
                'Threat': url_information.get('threat', ''),
                'Blacklist': url_information.get('blacklists', {}),
                'Tags': url_information.get('tags', [])
            }

            payloads = []
            for payload in url_information.get('payloads', []):
                payloads.append({
                    'Name': payload.get('filename', 'unknown'),
                    'Type': payload.get('file_type', ''),
                    'MD5': payload.get('response_md5', ''),
                    'VT': payload.get('virustotal', None)
                })

            urlhaus_data['Payloads'] = payloads

            # DBot score calculation
            dbot_score, description = calculate_dbot_score(url_information.get('blacklists', {}), THRESHOLD,
                                                           COMPROMISED_IS_MALICIOUS)

            ec['DBotScore']['Score'] = dbot_score
            if dbot_score == 3:
                ec['URL']['Malicious'] = {
                    'Vendor': 'URLhaus',
                    'Description': description
                }

            ec['URLhaus.URL(val.ID && val.ID === obj.ID)'] = urlhaus_data

            human_readable = f'## URLhaus reputation for {url}\n' \
                f'URLhaus link: {url_information.get("urlhaus_reference", "None")}\n' \
                f'Threat: {url_information.get("threat", "")}\n' \
                f'Date added: {date_added}'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': url_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif url_information['query_status'] == 'no_results':
            ec['DBotScore']['Score'] = 0

            human_readable = f'## URLhaus reputation for {url}\n' \
                f'No results!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': url_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif url_information['query_status'] == 'invalid_url':
            human_readable = f'## URLhaus reputation for {url}\n' \
                f'Invalid URL!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': url_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': f'Query results = {url_information["query_status"]}'
            })

    except Exception:
        demisto.debug(traceback.format_exc())
        return_error('Failed getting url data, please verify the arguments and parameters')


def ip_command():
    ip = demisto.args()['ip']

    try:
        ip_information = query_host_information(ip).json()

        ec = {
            'URL': {
                'Data': ip
            },
            'DBotScore': {
                'Type': 'ip',
                'Vendor': 'URLhaus',
                'Indicator': ip
            }
        }

        if ip_information['query_status'] == 'ok':
            # URLHaus output
            first_seen = dt.strptime(ip_information.get('date_added', '1970-01-01 00:00:00 UTC'),
                                     '%Y-%m-%d %H:%M:%S UTC').strftime('%Y-%m-%dT%H:%M:%S')

            urlhaus_data = {
                'FirstSeen': first_seen,
                'Blacklist': ip_information.get('blacklists', {}),
                'URLs': ip_information.get('urls', [])
            }

            # DBot score calculation
            dbot_score, description = calculate_dbot_score(ip_information.get('blacklists', {}), THRESHOLD,
                                                           COMPROMISED_IS_MALICIOUS)

            ec['DBotScore']['Score'] = dbot_score
            if dbot_score == 3:
                ec['IP']['Malicious'] = {
                    'Vendor': 'URLhaus',
                    'Description': description
                }

            ec['URLhaus.IP(val.Address && val.Address === obj.Address)'] = urlhaus_data

            human_readable = f'## URLhaus reputation for {ip}\n' \
                f'URLhaus link: {ip_information.get("urlhaus_reference", "None")}\n' \
                f'First seen: {first_seen}'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': ip_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif ip_information['query_status'] == 'no_results':
            ec['DBotScore']['Score'] = 0

            human_readable = f'## URLhaus reputation for {ip}\n' \
                f'No results!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': ip_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif ip_information['query_status'] == 'invalid_host':
            human_readable = f'## URLhaus reputation for {ip}\n' \
                f'Invalid IP!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': ip_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': f'Query results = {ip_information["query_status"]}'
            })

    except Exception:
        demisto.debug(traceback.format_exc())
        return_error('Failed getting IP data, please verify the arguments and parameters')


def domain_command():
    domain = demisto.args()['domain']

    try:
        domain_information = query_host_information(domain).json()

        ec = {
            'Domain': {
                'Name': domain
            },
            'DBotScore': {
                'Type': 'domain',
                'Vendor': 'URLhaus',
                'Indicator': domain
            }
        }

        if domain_information['query_status'] == 'ok':
            # URLHaus output
            first_seen = dt.strptime(domain_information.get('firstseen', '1970-01-01 00:00:00 UTC'),
                                     '%Y-%m-%d %H:%M:%S UTC').strftime('%Y-%m-%dT%H:%M:%S')

            urlhaus_data = {
                'FirstSeen': first_seen,
                'Blacklist': domain_information.get('blacklists', {}),
                'URLs': domain_information.get('urls', [])
            }

            # DBot score calculation
            dbot_score, description = calculate_dbot_score(domain_information.get('blacklists', {}), THRESHOLD,
                                                           COMPROMISED_IS_MALICIOUS)

            ec['DBotScore']['Score'] = dbot_score
            if dbot_score == 3:
                ec['domain']['Malicious'] = {
                    'Vendor': 'URLhaus',
                    'Description': description
                }

            ec['URLhaus.Domain(val.Name && val.Name === obj.Name)'] = urlhaus_data

            human_readable = f'## URLhaus reputation for {domain}\n' \
                f'URLhaus link: {domain_information.get("urlhaus_reference", "None")}\n' \
                f'First seen: {first_seen}'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': domain_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif domain_information['query_status'] == 'no_results':
            ec['DBotScore']['Score'] = 0

            human_readable = f'## URLhaus reputation for {domain}\n' \
                f'No results!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': domain_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif domain_information['query_status'] == 'invalid_host':
            human_readable = f'## URLhaus reputation for {domain}\n' \
                f'Invalid domain!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': domain_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': f'Query results = {domain_information["query_status"]}'
            })

    except Exception:
        demisto.debug(traceback.format_exc())
        return_error('Failed getting domain data, please verify the arguments and parameters')

''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'url':
        url_command()
    elif demisto.command() == 'ip':
        ip_command()
    elif demisto.command() == 'domain':
        domain_command()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
