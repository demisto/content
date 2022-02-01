import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import traceback
import requests
import zipfile
import io
from datetime import datetime as dt
from urllib.parse import urlparse

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
    return http_request('GET', f'download/{sha256}', api_url=api_url, use_ssl=use_ssl)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(**kwargs):
    """
    Performs basic get request to get item samples
    """
    http_request('POST', 'url', kwargs.get('api_url'), kwargs.get('use_ssl'))


def url_calculate_score(status):
    status_dict = {'online': (Common.DBotScore.BAD, "The URL is active (online) and currently serving a payload"),
                   'offline': (Common.DBotScore.SUSPICIOUS, "The URL is inadctive (offline) and serving no payload"),
                   'unknown': (Common.DBotScore.NONE, "The URL status could not be determined")}
    if status_dict.get(status):
        return status_dict[status]
    return Common.DBotScore.GOOD, "The URL is not listed"


def domain_calculate_score(blacklist):
    spamhaus_dbl = blacklist.get('spamhaus_dbl', '')
    surbl = blacklist.get('surbl', '')

    if spamhaus_dbl:
        if spamhaus_dbl == 'spammer_domain':
            return Common.DBotScore.BAD, "The queried Domain is a known spammer domain"
        if spamhaus_dbl == 'phishing_domain':
            return Common.DBotScore.BAD, "The queried Domain is a known phishing domain"
        if spamhaus_dbl == 'botnet_cc_domain':
            return Common.DBotScore.BAD, "The queried Domain is a known botnet C&C domain"
    if surbl:
        if surbl == 'listed':
            return Common.DBotScore.BAD, "The queried Domain is listed on SURBL"
    if spamhaus_dbl:
        if spamhaus_dbl == 'not_listed':
            return Common.DBotScore.NONE, "The queried Domain is not listed on Spamhaus DBL"
    if surbl:
        if surbl == 'not_listed':
            return Common.DBotScore.NONE, "The queried Domain is not listed on SURBL"
    return Common.DBotScore.GOOD, "There is no information about Domain in the blacklist"


def file_calculate_score(args):
    return Common.DBotScore.BAD


def calculate_dbot_score(command, arg):
    calculate_dbot_score_dic = {'url': url_calculate_score, 'domain': domain_calculate_score,
                                'file': file_calculate_score}
    func_to_run = calculate_dbot_score_dic.get(command)
    if func_to_run:
        return func_to_run(arg)


def parse_host(host):
    return "ip" if is_ip_valid(host) else "domain"


def url_create_relationships(uri, host, files, **kwargs):
    relationships = []
    if kwargs.get('create_relationships'):
        if host:
            parsed_host = parse_host(host)
            if parsed_host == "domain":
                relationships.append(EntityRelationship(
                    name=EntityRelationship.Relationships.RELATIONSHIPS_NAMES.get('hosts'), entity_a=uri,
                    entity_a_type=FeedIndicatorType.URL,
                    entity_b=host, entity_b_type=FeedIndicatorType.Domain,
                    reverse_name=EntityRelationship.Relationships.HOSTS))
            if parsed_host == "ip":
                relationships.append(EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO, entity_a=uri, entity_a_type=FeedIndicatorType.URL,
                    entity_b=host, entity_b_type=FeedIndicatorType.IP,
                    reverse_name=EntityRelationship.Relationships.RELATED_TO))
        if files:
            for file in files:
                if len(relationships) >= kwargs.get('max_num_of_relationships'):
                    break

                file_sh256 = file.get('SHA256')
                if file_sh256:
                    relationships.append(EntityRelationship(
                        name=EntityRelationship.Relationships.RELATIONSHIPS_NAMES.get('related-to'), entity_a=uri,
                        entity_a_type=FeedIndicatorType.URL,
                        entity_b=file_sh256, entity_b_type=FeedIndicatorType.File,
                        reverse_name=EntityRelationship.Relationships.RELATED_TO))
    return relationships


def url_create_tags(urlhaus_data):
    tags = urlhaus_data.get('Tags', [])
    if urlhaus_data.get("Threat"):
        tags.append(urlhaus_data.get("Threat"))
    return tags


def url_create_payloads(url_information):
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
            'SHA256': payload.get('response_sha256', ''),
            'VT': vt_information,
        })
    return payloads


def url_create_blacklist(url_information):
    blacklist_information = []
    blacklists = url_information.get('blacklists', {})
    for bl_name, bl_status in blacklists.items():
        blacklist_information.append({'Name': bl_name,
                                      'Status': bl_status})
    return blacklist_information


def build_context_url_ok_status(url_information, uri, **kwargs):
    # URLhaus output

    blacklist_information = url_create_blacklist(url_information)
    date_added = reformat_date(url_information.get('date_added'))
    payloads = url_create_payloads(url_information)
    urlhaus_data = {
        'ID': url_information.get('id', ''),
        'Status': url_information.get('url_status', ''),
        'Host': url_information.get('host', ''),
        'DateAdded': date_added,
        'Threat': url_information.get('threat', ''),
        'Blacklist': blacklist_information,
        'Tags': url_information.get('tags', []),
        'Payload': payloads
    }

    # DBot score calculation
    score, description = calculate_dbot_score('url', url_information.get('url_status', {}))
    dbot_score = Common.DBotScore(
        indicator=uri,
        integration_name='URLhaus',
        indicator_type=DBotScoreType.URL,
        reliability=kwargs.get('reliability'),
        score=score,
        malicious_description=description
    )
    relationships = url_create_relationships(uri, url_information.get('host'), payloads, **kwargs)
    url_indicator = Common.URL(url=uri, dbot_score=dbot_score, tags=url_create_tags(urlhaus_data),
                               relationships=relationships) if relationships else Common.URL(url=uri,
                                                                                             dbot_score=dbot_score,
                                                                                             tags=url_create_tags(
                                                                                                 urlhaus_data))
    human_readable = tableToMarkdown(f'URLhaus reputation for {uri}',
                                     {
                                         'URLhaus link': url_information.get("urlhaus_reference", "None"),
                                         'Description': description,
                                         'URLhaus ID': urlhaus_data['ID'],
                                         'Status': urlhaus_data['Status'],
                                         'Threat': url_information.get("threat", ""),
                                         'Date added': date_added
                                     })

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='URLhaus.URL',
        outputs_key_field='url',
        outputs=urlhaus_data,
        raw_response=url_information,
        indicator=url_indicator)


def build_context_url_no_results_status(url_information, uri, **kwargs):
    dbot_score = Common.DBotScore(
        indicator=uri,
        integration_name='URLhaus',
        indicator_type=DBotScoreType.URL,
        reliability=kwargs.get('reliability'),
        score=Common.DBotScore.NONE
    )
    url_indicator = Common.URL(url=uri, dbot_score=dbot_score)
    human_readable = f'## URLhaus reputation for {uri}\n' \
                     f'No results!'
    return CommandResults(
        readable_output=human_readable,
        raw_response=url_information,
        indicator=url_indicator
    )


def process_query_info(url_information, uri, **kwargs):
    if url_information['query_status'] == 'ok':
        return build_context_url_ok_status(url_information, uri, **kwargs)

    elif url_information['query_status'] == 'no_results':
        return build_context_url_no_results_status(url_information, uri, **kwargs)

    elif url_information['query_status'] == 'invalid_url':
        human_readable = f'## URLhaus reputation for {uri}\n' \
                         f'Invalid URL!'
        return CommandResults(
            readable_output=human_readable,
            raw_response=url_information,
        )
    else:
        raise DemistoException(f'Query results = {url_information["query_status"]}', res=url_information)


def url_command(**kwargs):
    url = demisto.args().get('url')
    try:
        url_information = query_url_information(url, kwargs.get('api_url'), kwargs.get('use_ssl')).json()
    except UnicodeEncodeError:
        return_results(CommandResults(
            readable_output="Service Does not support special characters.",
        ))
        return
    return process_query_info(url_information, url, **kwargs)


def domain_create_relationships(urls, domain, **kwargs):
    relationships = []
    if kwargs.get('create_relationships'):
        for url in urls:
            if len(relationships) >= kwargs.get('max_num_of_relationships'):
                break
            relationships.append(EntityRelationship(
                name=EntityRelationship.Relationships.HOSTS, entity_a=domain,
                entity_a_type=FeedIndicatorType.Domain,
                entity_b=url.get('url'), entity_b_type=FeedIndicatorType.URL,
                reverse_name=EntityRelationship.Relationships.HOSTED_ON).to_context())
    return relationships


def domain_add_tags(bl_status, tags):
    if bl_status:
        status_prefix = bl_status.split("_")[0] if bl_status.endswith("domain") else \
            bl_status.split("_")[-1] if bl_status.startswith("abused") else ''
        if status_prefix:
            tags.append(status_prefix)


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

        tags = []
        if domain_information['query_status'] == 'ok':
            # URLHaus output
            blacklist_information = []
            blacklists = domain_information.get('blacklists', {})
            for bl_name, bl_status in blacklists.items():
                blacklist_information.append({'Name': bl_name,
                                              'Status': bl_status})
                domain_add_tags(bl_status, tags)
            if tags:
                ec['Domain']['Tags'] = tags
            first_seen = reformat_date(domain_information.get('firstseen'))

            urlhaus_data = {
                'FirstSeen': first_seen,
                'Blacklist': blacklists,
                'URL': domain_information.get('urls', [])
            }

            # DBot score calculation
            dbot_score, description = calculate_dbot_score('domain', domain_information.get('blacklists', {}))
            ec['DBotScore']['Score'] = dbot_score
            if dbot_score == Common.DBotScore.BAD:
                ec['domain']['Malicious'] = {
                    'Vendor': 'URLhaus',
                    'Description': description
                }
            relationships = domain_create_relationships(urlhaus_data.get('URL'), domain, **kwargs)
            if relationships:
                ec['Domain']['Relationships'] = relationships
            ec['URLhaus.Domain(val.Name && val.Name === obj.Name)'] = urlhaus_data

            human_readable = tableToMarkdown(f'URLhaus reputation for {domain}',
                                             {
                                                 'URLhaus link': domain_information.get('urlhaus_reference', 'None'),
                                                 'Description': description,
                                                 'First seen': first_seen,
                                             })
            return (CommandResults(
                readable_output=human_readable,
                outputs=ec,
                raw_response=domain_information))
        elif domain_information['query_status'] == 'no_results':
            ec['DBotScore']['Score'] = Common.DBotScore.NONE

            human_readable = f'## URLhaus reputation for {domain}\n' \
                             f'No results!'
            return (CommandResults(
                readable_output=human_readable,
                outputs=ec,
                raw_response=domain_information))
        elif domain_information['query_status'] == 'invalid_host':
            human_readable = f'## URLhaus reputation for {domain}\n' \
                             f'Invalid domain!'
            return (CommandResults(
                readable_output=human_readable,
                outputs=ec,
                raw_response=domain_information))
        else:
            raise DemistoException(f'Query results = {domain_information["query_status"]}', res=domain_information)


    except Exception:
        demisto.debug(traceback.format_exc())
        return_error('Failed getting domain data, please verify the arguments and parameters')


def file_create_relationships(urls, sig, file, **kwargs):
    relationships = []
    if kwargs.get('create_relationships'):
        relationships.append(EntityRelationship(
            name=EntityRelationship.Relationships.INDICATOR_OF, entity_a=file,
            entity_a_type=FeedIndicatorType.File,
            entity_b=sig, entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
            reverse_name=EntityRelationship.Relationships.INDICATED_BY).to_context())

        for url in urls:
            if len(relationships) >= kwargs.get('max_num_of_relationships'):
                break
            relationships.append(EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO, entity_a=file,
                entity_a_type=FeedIndicatorType.File,
                entity_b=url.get('url'), entity_b_type=FeedIndicatorType.URL,
                reverse_name=EntityRelationship.Relationships.RELATED_TO).to_context())
    return relationships


def file_command(**kwargs):
    hash = demisto.args()['file']
    if len(hash) == 32:
        hash_type = 'md5'
    elif len(hash) == 64:
        hash_type = 'sha256'
    else:
        return_error('Only accepting MD5 (32 bytes) or SHA256 (64 bytes) hash types')

    try:
        file_information = query_payload_information(hash_type, kwargs.get('api_url'), kwargs.get('use_ssl'),
                                                     hash).json()

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

            dbot_score = Common.DBotScore(
                indicator=hash,
                integration_name='URLhaus',
                indicator_type=DBotScoreType.FILE,
                reliability=kwargs.get('reliability'),
                score=calculate_dbot_score('file', ""),
            ).to_context()

            ec = {
                'File': {
                    'Size': urlhaus_data.get('Size', 0),
                    'MD5': urlhaus_data.get('MD5', ''),
                    'SHA256': urlhaus_data.get('SHA256'),
                    'Type': urlhaus_data.get('Type'),
                    'SSDeep': file_information.get('ssdeep', '')
                },
                'DBotScore': dbot_score,
                'URLhaus.File(val.MD5 && val.MD5 === obj.MD5)': urlhaus_data
            }
            relationships = file_create_relationships(urlhaus_data['URL'], urlhaus_data['Signature'], hash, **kwargs)

            if relationships:
                ec['File']['Relationships'] = relationships
            human_readable = tableToMarkdown(f'URLhaus reputation for {hash_type.upper()} : {hash}',
                                             {
                                                 'URLhaus link': urlhaus_data.get('DownloadLink', ''),
                                                 'Signature': urlhaus_data.get('Signature', ''),
                                                 'MD5': urlhaus_data.get('MD5', ''),
                                                 'SHA256': urlhaus_data.get('SHA256', ''),
                                                 'First seen': first_seen,
                                                 'Last seen': last_seen
                                             })
            return (CommandResults(
                readable_output=human_readable,
                outputs=ec,
                raw_response=file_information))

        elif (file_information['query_status'] == 'ok' and not file_information['md5_hash']) or \
                file_information['query_status'] == 'no_results':
            human_readable = f'## URLhaus reputation for {hash_type.upper()} : {hash}\n' \
                             f'No results!'

            return (CommandResults(
                readable_output=human_readable,
                raw_response=file_information))

        elif file_information['query_status'] in ['invalid_md5', 'invalid_sha256']:
            human_readable = f'## URLhaus reputation for {hash_type.upper()} : {hash}\n' \
                             f'Invalid {file_information["query_status"].lstrip("invalid_").upper()}!'
            return (CommandResults(
                readable_output=human_readable,
                raw_response=file_information))
        else:
            raise DemistoException(f'Query results = {file_information["query_status"]}', res=file_information)


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
            'create_relationships': bool(demisto_params.get('create_relationships', True)),
            'max_num_of_relationships': int(demisto_params.get('max_num_of_relationships', 1)) if int(
                demisto_params.get('max_num_of_relationships', 1)) < 1000 else 1000,
        }

        reliability = demisto_params.get('integrationReliability', DBotScoreReliability.C)

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
            return_results(results=url_command(**params))
        elif command == 'domain':
            return_results(results=domain_command(**params))
        elif command == 'file':
            return_results(results=file_command(**params))
        elif command == 'urlhaus-download-sample':
            urlhaus_download_sample_command(**params)

    # Log exceptions
    except Exception as exc:
        return_error(f'Failed to execute command "{command}".\nError: {exc}', error=exc)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
