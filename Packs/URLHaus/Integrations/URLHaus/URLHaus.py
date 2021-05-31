import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import traceback
import requests
import zipfile
import io
from datetime import datetime as dt

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


# disable-secrets-detection-start
# Whether compromised websites are considered malicious or not. See the blacklists output in
# https://urlhaus-api.abuse.ch/
# disable-secrets-detection-end
COMPROMISED_IS_MALICIOUS = demisto.params().get('compromised_is_malicious', False)

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
}

''' HELPER FUNCTIONS '''


def http_request(method, command, api_url, use_ssl, data=None):
    retry = int(demisto.params().get('retry', 3))
    try_num = 0

    while try_num < retry:
        try_num += 1
        url = f'{api_url}/{command}/'
        res = requests.request(method,
                               url,
                               verify=use_ssl,
                               data=data,
                               headers=HEADERS)

        if res.status_code == 200:
            return res

    raise Exception(f'Error in API call {url} [{res.status_code}] - {res.reason}')


def reformat_date(date):
    try:
        return dt.strptime(date.rstrip(' UTC'), '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S')
    except Exception:
        return 'Unknown'


def extract_zipped_buffer(buffer):
    with io.BytesIO() as bio:
        bio.write(buffer)
        with zipfile.ZipFile(bio) as z:
            return z.read(z.namelist()[0])


def query_url_information(url, api_url, use_ssl):
    return http_request('POST', 'url', api_url, use_ssl, f'url={url}')


def query_host_information(host, api_url, use_ssl):
    return http_request('POST', 'host', api_url, use_ssl, f'host={host}')


def query_payload_information(hash_type, api_url, use_ssl, hash):
    return http_request('POST', 'payload', api_url, use_ssl, f'{hash_type}_hash={hash}')


def download_malware_sample(sha256, api_url, use_ssl):
    return http_request('GET', f'download/{sha256}', api_url=api_url, use_ssl=use_ssl,)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(**kwargs):
    """
    Performs basic get request to get item samples
    """
    http_request('POST', 'url', kwargs.get('api_url'), kwargs.get('use_ssl'))


def calculate_dbot_score(blacklists, threshold, compromised_is_malicious):
    dbot_score = 0
    description = 'Not listed in any blacklist'
    blacklist_appearances = []
    for blacklist, status in blacklists.items():
        if blacklist == 'spamhaus_dbl':
            if status.endswith('domain') or (status.startswith('abused') and compromised_is_malicious):
                blacklist_appearances.append((blacklist, status))
        elif status == 'listed':
            blacklist_appearances.append((blacklist, None))

    if len(blacklist_appearances) >= threshold:
        description = ''
        for appearance in blacklist_appearances:
            if appearance[1] is not None:
                description += f'Listed in {appearance[0]}. '
            else:
                description += f'Listed as {appearance[1]} in {appearance[0]}. '
        dbot_score = 3
    elif len(blacklist_appearances) > 0:
        dbot_score = 2
    else:
        dbot_score = 1

    return dbot_score, description


def url_command(**kwargs):
    url = demisto.args().get('url')

    url_information = query_url_information(url, kwargs.get('api_url'), kwargs.get('use_ssl')).json()

    ec = {
        'URL': {
            'Data': url,
        },
        'DBotScore': {
            'Type': 'url',
            'Vendor': 'URLhaus',
            'Indicator': url,
            'Reliability': kwargs.get('reliability'),
        },
    }

    if url_information['query_status'] == 'ok':
        # URLhaus output
        blacklist_information = []
        blacklists = url_information.get('blacklists', {})
        for bl_name, bl_status in blacklists.items():
            blacklist_information.append({'Name': bl_name,
                                          'Status': bl_status})

        date_added = reformat_date(url_information.get('date_added'))
        urlhaus_data = {
            'ID': url_information.get('id', ''),
            'Status': url_information.get('url_status', ''),
            'Host': url_information.get('host', ''),
            'DateAdded': date_added,
            'Threat': url_information.get('threat', ''),
            'Blacklist': blacklist_information,
            'Tags': url_information.get('tags', []),
        }

        payloads = []
        for payload in url_information.get('payloads') or []:
            vt_data = payload.get('virustotal', None)
            vt_information = None
            if vt_data:
                vt_information = {
                    'Result': float(vt_data.get('percent', 0)),
                    'Link': vt_data.get('link', '')
                }
            payloads.append({
                'Name': payload.get('filename', 'unknown'),
                'Type': payload.get('file_type', ''),
                'MD5': payload.get('response_md5', ''),
                'VT': vt_information,
            })

        urlhaus_data['Payload'] = payloads

        # DBot score calculation
        dbot_score, description = calculate_dbot_score(url_information.get('blacklists', {}),
                                                       kwargs.get('threshold'), COMPROMISED_IS_MALICIOUS)

        ec['DBotScore']['Score'] = dbot_score
        if dbot_score == 3:
            ec['URL']['Malicious'] = {
                'Vendor': 'URLhaus',
                'Description': description
            }

        ec['URLhaus.URL(val.ID && val.ID === obj.ID)'] = urlhaus_data

        human_readable = tableToMarkdown(f'URLhaus reputation for {url}',
                                         {
                                             'URLhaus link': url_information.get("urlhaus_reference", "None"),
                                             'Description': description,
                                             'URLhaus ID': urlhaus_data['ID'],
                                             'Status': urlhaus_data['Status'],
                                             'Threat': url_information.get("threat", ""),
                                             'Date added': date_added
                                         })

    elif url_information['query_status'] == 'no_results':
        ec['DBotScore']['Score'] = 0

        human_readable = f'## URLhaus reputation for {url}\n' \
            f'No results!'

    elif url_information['query_status'] == 'invalid_url':
        human_readable = f'## URLhaus reputation for {url}\n' \
            f'Invalid URL!'

    else:
        raise DemistoException(f'Query results = {url_information["query_status"]}', res=url_information)

    return_results(CommandResults(
        readable_output=human_readable,
        outputs=ec,
        raw_response=url_information,
    ))


def domain_command(**kwargs):
    domain = demisto.args()['domain']

    try:
        domain_information = query_host_information(domain, kwargs.get('api_url'), kwargs.get('use_ssl')).json()

        ec = {
            'Domain': {
                'Name': domain
            },
            'DBotScore': {
                'Type': 'domain',
                'Vendor': 'URLhaus',
                'Indicator': domain,
                'Reliability': kwargs.get('reliability')
            }
        }

        if domain_information['query_status'] == 'ok':
            # URLHaus output
            blacklist_information = []
            blacklists = domain_information.get('blacklists', {})
            for bl_name, bl_status in blacklists.items():
                blacklist_information.append({'Name': bl_name,
                                              'Status': bl_status})

            first_seen = reformat_date(domain_information.get('firstseen'))

            urlhaus_data = {
                'FirstSeen': first_seen,
                'Blacklist': blacklists,
                'URL': domain_information.get('urls', [])
            }

            # DBot score calculation
            dbot_score, description = calculate_dbot_score(domain_information.get('blacklists', {}),
                                                           kwargs.get('threshold'), COMPROMISED_IS_MALICIOUS)

            ec['DBotScore']['Score'] = dbot_score
            if dbot_score == 3:
                ec['domain']['Malicious'] = {
                    'Vendor': 'URLhaus',
                    'Description': description
                }

            ec['URLhaus.Domain(val.Name && val.Name === obj.Name)'] = urlhaus_data

            human_readable = tableToMarkdown(f'URLhaus reputation for {domain}',
                                             {
                                                 'URLhaus link': domain_information.get('urlhaus_reference', 'None'),
                                                 'Description': description,
                                                 'First seen': first_seen,
                                             })
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


def file_command(**kwargs):
    hash = demisto.args()['file']
    if len(hash) == 32:
        hash_type = 'md5'
    elif len(hash) == 64:
        hash_type = 'sha256'
    else:
        return_error('Only accepting MD5 (32 bytes) or SHA256 (64 bytes) hash types')

    try:
        file_information = query_payload_information(hash_type, kwargs.get('api_url'), kwargs.get('use_ssl'), hash).json()

        if file_information['query_status'] == 'ok' and file_information['md5_hash']:
            # URLhaus output
            first_seen = reformat_date(file_information.get('firstseen'))
            last_seen = reformat_date(file_information.get('lastseen'))

            urlhaus_data = {
                'MD5': file_information.get('md5_hash', ''),
                'SHA256': file_information.get('sha256_hash', ''),
                'Type': file_information.get('file_type', ''),
                'Size': int(file_information.get('file_size', '')),
                'Signature': file_information.get('signature', ''),
                'FirstSeen': first_seen,
                'LastSeen': last_seen,
                'DownloadLink': file_information.get('urlhaus_download', ''),
                'URL': file_information.get('urls', [])
            }

            virus_total_data = file_information.get('virustotal')
            if virus_total_data:
                urlhaus_data['VirusTotal'] = {
                    'Percent': float(file_information.get('virustotal', {'percent': 0})['percent']),
                    'Link': file_information.get('virustotal', {'link': ''})['link']
                }

            ec = {
                'File': {
                    'Size': urlhaus_data.get('Size', 0),
                    'MD5': urlhaus_data.get('MD5', ''),
                    'SHA256': urlhaus_data.get('SHA256')
                },
                'URLhaus.File(val.MD5 && val.MD5 === obj.MD5)': urlhaus_data
            }

            human_readable = tableToMarkdown(f'URLhaus reputation for {hash_type.upper()} : {hash}',
                                             {
                                                 'URLhaus link': urlhaus_data.get('DownloadLink', ''),
                                                 'Signature': urlhaus_data.get('Signature', ''),
                                                 'MD5': urlhaus_data.get('MD5', ''),
                                                 'SHA256': urlhaus_data.get('SHA256', ''),
                                                 'First seen': first_seen,
                                                 'Last seen': last_seen
                                             })
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': file_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })
        elif (file_information['query_status'] == 'ok' and not file_information['md5_hash']) or \
                file_information['query_status'] == 'no_results':
            human_readable = f'## URLhaus reputation for {hash_type.upper()} : {hash}\n' \
                f'No results!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': file_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
            })
        elif file_information['query_status'] in ['invalid_md5', 'invalid_sha256']:
            human_readable = f'## URLhaus reputation for {hash_type.upper()} : {hash}\n' \
                f'Invalid {file_information["query_status"].lstrip("invalid_").upper()}!'

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': file_information,
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
            })
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': f'Query results = {file_information["query_status"]}'
            })

    except Exception:
        demisto.debug(traceback.format_exc())
        return_error('Failed getting file data, please verify the arguments and parameters')


def urlhaus_download_sample_command(**kwargs):
    """
    The response can be either the zipped sample (content-type = application/zip), or JSON (content-type = text/html)
    containing the query status.
    """
    file_sha256 = demisto.args()['file']
    res = download_malware_sample(file_sha256, kwargs.get('api_url'), kwargs.get('use_ssl'))

    try:
        if len(res.content) == 0:
            demisto.results({
                'Type': entryTypes['note'],
                'HumanReadable': f'No results for SHA256: {file_sha256}',
                'HumanReadableFormat': formats['markdown']
            })
        elif res.headers['content-type'] in ['text/html', 'application/json'] and \
                res.json()['query_status'] == 'not_found':
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': res.json(),
                'HumanReadable': f'No results for SHA256: {file_sha256}',
                'HumanReadableFormat': formats['markdown']
            })
        elif res.headers['content-type'] == 'application/zip':
            demisto.results(fileResult(file_sha256, extract_zipped_buffer(res.content)))
        else:
            raise Exception
            # Handle like an exception
    except Exception:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': str(res.content)
        })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))


def main():
    try:
        demisto_params = demisto.params()
        command = demisto.command()

        params = {
            'api_url': demisto_params['url'].rstrip('/'),
            'use_ssl': not demisto_params.get('insecure', False),
            'threshold': int(demisto_params.get('threshold', 1)),
        }

        reliability = params.get('integrationReliability')
        reliability = reliability if reliability else DBotScoreReliability.C

        if DBotScoreReliability.is_valid_type(reliability):
            params['reliability'] = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            Exception("Please provide a valid value for the Source Reliability parameter.")

        # Remove proxy if not set to true in params
        handle_proxy()

        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(**params)
            demisto.results('ok')
        elif command == 'url':
            url_command(**params)
        elif command == 'domain':
            domain_command(**params)
        elif command == 'file':
            file_command(**params)
        elif command == 'urlhaus-download-sample':
            urlhaus_download_sample_command(**params)

    # Log exceptions
    except Exception as exc:
        return_error(f'Failed to execute command "{command}".\nError: {exc}', error=exc)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
