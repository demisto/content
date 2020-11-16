import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
import json
import time
import sys

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Define utf8 as default encoding
reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=E1101

''' GLOBAL VARS '''
SERVER_URL = 'https://www.virustotal.com/vtapi/v2/'
API_KEY = demisto.params().get('APIKey', '')

USE_SSL = False if demisto.params().get('insecure') else True
PREFERRED_VENDORS = demisto.params().get("preferredVendors", None)
PREFERRED_VENDORS_THRESHOLD = demisto.params().get("preferredVendorsThreshold", None)

FULL_RESPONSE = demisto.params().get("fullResponseGlobal", False)

DEFAULT_HEADERS = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent": "gzip,  My Python requests library example client or username"
}

''' HELPER FUNCTIONS '''


def is_enough_preferred_vendors(scan_results):
    if not (PREFERRED_VENDORS and PREFERRED_VENDORS_THRESHOLD):
        return False
    if PREFERRED_VENDORS and not PREFERRED_VENDORS_THRESHOLD:
        return_error("Error: If you entered Preferred Vendors you must also enter Preferred Vendors Threshold")
    if "scans" not in scan_results:
        return False

    counter_of_malicious_detections = 0

    vendors_scans_dict = scan_results["scans"]
    list_of_preferred_vendors = PREFERRED_VENDORS.split(',')

    for i in range(len(list_of_preferred_vendors)):
        list_of_preferred_vendors[i] = list_of_preferred_vendors[i].lower().strip()

    for vendor_name in vendors_scans_dict:
        cur_vendor_scan = vendors_scans_dict[vendor_name]
        vendor_name_in_lowercase = vendor_name.lower()

        if vendor_name_in_lowercase in list_of_preferred_vendors:
            if cur_vendor_scan.get("detected"):
                counter_of_malicious_detections += 1

    return int(PREFERRED_VENDORS_THRESHOLD) <= counter_of_malicious_detections


def http_request(method, url_suffix, params_dict, headers):
    req_params = {
        'apikey': API_KEY
    }
    if params_dict is not None:
        req_params.update(params_dict)

    url = SERVER_URL + url_suffix

    LOG('running %s request with url=%s\theaders=%s\nparams=%s' % (method, url, headers, json.dumps(req_params)))

    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=req_params,
                               headers=headers
                               )
        res.raise_for_status()

        if res.status_code == 200:
            return res.json()
        # 204 HTTP status code is returned when api rate limit has been exceeded
        elif res.status_code == 204:
            return_error("You've reached your API call quota. Contact your VirusTotal representative.")

    except Exception as e:
        error_message = str(e)
        error_message = re.sub('apikey=[a-zA-Z0-9]+', 'apikey=*apikey*', error_message)
        LOG(error_message)
        raise type(e)(error_message)


def create_scans_table(scans):
    """
    Returns a table with the scan result for each vendor
    """

    scans_table = []  # type:ignore
    positives_scans_table = []
    negative_scans_table = []
    for scan in scans:
        dict_for_table = {
            "Source": scan,
            "Detected": scans.get(scan).get('detected', None),
            "Result": scans.get(scan).get('result', None),
            "Update": scans.get(scan).get('update', None),
            "Details": scans.get(scan).get('detail', None)
        }
        if dict_for_table['Detected'] is not None and dict_for_table['Detected']:
            positives_scans_table.append(dict_for_table)
        else:
            negative_scans_table.append(dict_for_table)

    positives_scans_table = sorted(positives_scans_table, key=lambda scan_: scan_['Source'])
    negative_scans_table = sorted(negative_scans_table, key=lambda scan_: scan_['Source'])

    scans_table = positives_scans_table + negative_scans_table
    return scans_table


def create_file_output(file_hash, threshold, vt_response, short_format):
    ec = {}  # type: dict
    md = ''

    positives = demisto.get(vt_response, 'positives')
    ec['DBotScore'] = []

    md += '## VirusTotal Hash Reputation for: ' + str(vt_response.get('resource')) + '\n'
    md += 'Scan ID: **' + str(vt_response.get('scan_id')) + '**\n'
    md += 'Scan date: **' + str(vt_response.get('scan_date')) + '**\n'
    md += 'Detections / Total: **' + str(positives) + '/' + str(vt_response.get('total')) + '**\n'
    md += 'Resource: ' + str(vt_response.get('resource')) + '\n'
    md += 'VT Link: [' + str(vt_response.get('permalink')) + '](' + str(vt_response.get('permalink')) + ')\n'
    dbotScore = 0

    if positives >= threshold or is_enough_preferred_vendors(vt_response):
        ec.update({
            outputPaths['file']: {
                'MD5': vt_response.get('md5'),
                'SHA1': vt_response.get('sha1'),
                'SHA256': vt_response.get('sha256'),
                'Malicious': {
                    'Vendor': 'VirusTotal - Private API',
                    'Detections': positives,
                    'TotalEngines': demisto.get(vt_response, 'total')
                },
            }
        })
        if vt_response.get('ssdeep', False):
            ec[outputPaths['file']].update({'SSDeep': vt_response.get('ssdeep')})
        if vt_response.get('type', False):
            ec[outputPaths['file']].update({'Type': vt_response.get('type')})
        if vt_response.get('size', False):
            ec[outputPaths['file']].update({'Size': vt_response.get('size')})
        dbotScore = 3
    elif positives >= threshold / 2:
        dbotScore = 2
    else:
        dbotScore = 1
    if is_demisto_version_ge('5.5.0'):
        ec['DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type'
           ' == obj.Type)'] = get_dbot_file_context(file_hash, dbotScore)
    else:
        ec['DBotScore'] = get_dbot_file_context(file_hash, dbotScore)

    md += 'MD5: **' + vt_response.get('md5') + '**\n'
    md += 'SHA1: **' + vt_response.get('sha1') + '**\n'
    md += 'SHA256: **' + vt_response.get('sha256') + '**\n'

    if vt_response.get('scans', False) and not short_format:
        scans = vt_response.pop('scans')
        scans_table = create_scans_table(scans)
        scans_table_md = tableToMarkdown('Scans', scans_table)
        md += scans_table_md
        md += '\n'
        if ec.get(outputPaths['file'], False):
            ec[outputPaths['file']]['VirusTotal'] = {
                'Scans': scans_table
            }
        else:
            ec.update({
                outputPaths['file']: {
                    'MD5': vt_response.get('md5'),
                    'VirusTotal': {
                        'Scans': scans_table
                    },
                }
            })

    if vt_response.get('tags', False):
        ec[outputPaths['file']]['VirusTotal'].update({'Tags': vt_response.get('tags')})
        ec[outputPaths['file']].update({'Tags': vt_response.get('tags')})
    if vt_response.get('magic', False):
        ec[outputPaths['file']]['VirusTotal'].update({'MagicLiteral': vt_response.get('magic')})
    if vt_response.get('first_seen', False):
        ec[outputPaths['file']]['VirusTotal'].update({'FirstSeen': vt_response.get('first_seen')})
    if vt_response.get('community_reputation', False):
        ec[outputPaths['file']]['VirusTotal'].update({'CommunityReputation': vt_response.get('community_reputation')})
    if vt_response.get('community_comments', False):
        ec[outputPaths['file']]['VirusTotal'].update({'CommunityComments': vt_response.get('community_comments')})
    if vt_response.get('authentihash', False):
        ec[outputPaths['file']]['VirusTotal'].update({'AuthentiHash': vt_response.get('authentihash')})
        ec[outputPaths['file']]['Signature'].update(
            {'Authentihash': vt_response.get('authentihash')})
    if vt_response.get('imphash', False):
        ec[outputPaths['file']]['VirusTotal'].update({'ImpHash': vt_response.get('imphash')})
    ec['VirusTotal(val.ID == obj.ID)'] = {'ID': file_hash,
                                          'Status': 'Ready'}

    entry = {
        'Type': entryTypes['note'],
        'Contents': vt_response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    }
    return entry


def get_dbot_file_context(file_hash, dbotscore):

    return {'Indicator': file_hash, 'Type': 'file', 'Vendor': 'VirusTotal - Private API', 'Score': dbotscore}


''' COMMANDS FUNCTIONS '''


def check_file_behaviour(file_hash):
    """
    Returns the file execution report.
    """

    params = {
        'hash': file_hash
    }

    api_endpoint = 'file/behaviour'
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def check_file_behaviour_command():
    """
    corresponds to 'vt-private-check-file-behaviour' command. Retrieves a report about the execution of a file
    """
    # variables
    args = demisto.args()
    file_hash = args.get('resource')
    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    if full_response:
        max_len = 1000
    else:
        max_len = 50
    md = ''
    # VT response
    response = check_file_behaviour(file_hash)

    ec = {}
    if response.get('response_code', None) == 0:

        if is_demisto_version_ge('5.5.0'):
            ec['DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type'
               ' == obj.Type)'] = get_dbot_file_context(file_hash, 0)

        else:
            ec['DBotScore'] = get_dbot_file_context(file_hash, 0)
        return {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'EntryContext': ec,

            'HumanReadable': "A report wasn't found for file " + file_hash + ". Virus Total returned the following "
                                                                             "response: " + json.dumps
                             (response.get('verbose_msg'))
        }

    # data processing

    # network data contains all the communication data
    network_data = response.get('network', {})

    hosts = network_data.get('hosts')
    if hosts:
        hosts = list(set(hosts))[:max_len]
        md += tableToMarkdown('Hosts that the hash communicates with are:', [{'Host': host} for host in hosts])

    ips_list = []
    domains_list = []
    urls_list = []

    udp_communication = network_data.get('udp')
    if udp_communication:
        for entry in udp_communication:
            ips_list.append(entry.get('dst'))

    http_communication = network_data.get('http')
    if http_communication:
        for entry in http_communication:
            urls_list.append(entry.get('uri'))
            domains_list.append(entry.get('host'))

    tcp_communication = network_data.get('tcp')
    if tcp_communication:
        for entry in tcp_communication:
            ips_list.append(entry.get('dst'))

    dns_communication = network_data.get('dns')
    if dns_communication:
        for entry in dns_communication:
            ips_list.append(entry.get('ip'))
            domains_list.append(entry.get('hostname'))

    if len(ips_list) > 0:
        ips_list = list(set(ips_list))[:max_len]
        md += tableToMarkdown('IPs that the hash communicates with are:', [{'IP': ip} for ip in ips_list])

    if len(domains_list) > 0:
        domains_list = list(set(domains_list))[:max_len]
        md += tableToMarkdown('Domains that the hash communicates with are:',
                              [{'Domain': domain} for domain in domains_list])

    if len(urls_list) > 0:
        urls_list = list(set(urls_list))[:max_len]
        md += tableToMarkdown('URLs that the hash communicates with are:', [{'URL': url} for url in urls_list])

    files_data, keys_data, mutex_data = None, None, None

    behavior_data = response.get('behavior', None)
    if behavior_data is not None:
        summary_data = behavior_data.get('summary', None)
        if summary_data is not None:
            files_data = summary_data.get('files', None)
            keys_data = summary_data.get('keys', None)
            mutex_data = summary_data.get('mutexes', None)

    if files_data:
        files_data = list(set(files_data))[:max_len]
        md += tableToMarkdown('Files that are related the hash', [{'File': file} for file in files_data])

    if keys_data:
        keys_data = list(set(keys_data))[:max_len]
        md += tableToMarkdown('Registry Keys that are related to the hash', [{'Key': k} for k in keys_data])

    if mutex_data:
        mutex_data = list(set(mutex_data))[:max_len]
        md += tableToMarkdown('Opened mutexes that are related to the hash', [{'Mutex': m} for m in mutex_data])

    hash_length = len(file_hash)
    if hash_length == 32:
        hashtype_dic = {
            "MD5": file_hash
        }
    elif hash_length == 40:
        hashtype_dic = {
            "SHA1": file_hash
        }
    else:
        hashtype_dic = {
            "SHA256": file_hash
        }

    hash_ec = {
        "VirusTotal": {
            'RelatedDomains': domains_list,
            'RelatedURLs': urls_list,
            'RelatedIPs': ips_list,
            'RelatedHosts': hosts,
            'RelatedFiles': files_data,
            'RelatedRegistryKeys': keys_data,
            'RelatedMutexes': mutex_data
        }
    }

    hash_ec.update(hashtype_dic)

    if md:
        md = 'We found the following data about hash ' + file_hash + ':\n' + md
    else:
        md = 'No data were found for hash ' + file_hash

    return {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            outputPaths['file']: hash_ec,
        }
    }


def get_domain_report(domain):
    """
    Returns the domain report.
    """

    params = {
        'domain': domain
    }

    api_endpoint = 'domain/report'
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def get_domain_report_command():
    """
    corresponds to 'vt-get-domain-report' command. Retrieves a report about a domain
    """

    # variables
    args = demisto.args()
    domain = args['domain']
    threshold = int(args.get('threshold', None) or demisto.params().get('domainThreshold', None) or 10)
    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    if full_response:
        max_len = 1000
    else:
        max_len = 50
    md = ''

    # VT Response
    response = get_domain_report(domain)
    if response.get('response_code') == -1:
        return "Invalid domain"
    elif response.get('response_code') == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'EntryContext': {
                "DBotScore": {
                    'Indicator': domain,
                    'Type': 'domain',
                    'Vendor': 'VirusTotal - Private API',
                    'Score': 0
                }
            },
            'HumanReadable': "Domain "
                             + domain
                             + " not in Virus Total's dataset. Virus Total returned the following response: "
                             + json.dumps(response.get('verbose_msg'))
        }

    communicating_hashes = response.get('detected_communicating_samples', None)
    communicating_malware_hashes = []
    if communicating_hashes:
        for d_hash in communicating_hashes:
            positives = d_hash.get('positives')
            if positives >= threshold:
                communicating_malware_hashes.append(d_hash)

        communicating_malware_hashes = communicating_malware_hashes[:max_len]
        md += tableToMarkdown("Latest detected files that communicated with " + domain, communicating_malware_hashes)

    downloaded_hashes = response.get('detected_downloaded_samples', None)
    downloaded_malware_hashes = []
    if downloaded_hashes:
        for d_hash in downloaded_hashes:
            positives = d_hash.get('positives')
            if positives >= threshold:
                downloaded_malware_hashes.append(d_hash)
        downloaded_malware_hashes = downloaded_malware_hashes[:max_len]
        md += tableToMarkdown("Latest detected files that were downloaded from " + domain, downloaded_malware_hashes)

    resolutions = response.get('resolutions', None)
    resolutions_list = []
    if resolutions:
        for res in resolutions:
            resolutions_list.append(res)
        resolutions_list = resolutions_list[:max_len]
        md += tableToMarkdown(domain + " has been resolved to the following IP addresses:", resolutions_list)

    whois = response.get('whois', None)
    if whois is not None:
        md += "## Whois analysis: \n"
        md += whois + '\n'

    subdomains = response.get('subdomains', None)
    if subdomains is not None:
        subdomains = list(set(subdomains))[:max_len]
        md += tableToMarkdown("Observed subdomains", [{'Domain': d} for d in subdomains])

    categories = response.get('categories', None)
    if categories is not None:
        categories = list(set(categories))[:max_len]

    domain_ec = {
        'DownloadedHashes': downloaded_malware_hashes,
        'CommunicatingHashes': communicating_malware_hashes,
        'Resolutions': resolutions_list,
        'Whois': whois,
        'Subdomains': subdomains,
        'Categories': categories
    }

    return {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            outputPaths['domain']: {
                "Name": domain,
                "VirusTotal": domain_ec
            }
        }
    }


def get_file_report(file_hash, all_info):
    """
    Returns the file execution report.
    """

    params = {
        'resource': file_hash,
        'allinfo': all_info
    }

    api_endpoint = 'file/report'
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def get_file_report_command():
    """
    corresponds to 'vt-get-file-report' command. Retrieves a report about the execution of a file
    If a file was recently uploaded it might not be ready yet. In this case it is "Queued" and the response code
    we get is -2.
    In general from the documentation:
    response_code: if the item you searched for was not present in VirusTotal's dataset this result will be 0.
    If the requested item is still queued for analysis it will be -2.
    If the item was indeed present and it could be retrieved it will be 1.
    """

    args = demisto.args()
    file_hash = args.get('resource')
    short_format = args.get('shortFormat', None) == 'true'
    all_info = args.get('allInfo', None)
    all_info = 1 if all_info == 'true' else 0
    threshold = int(args.get('threshold', None) or demisto.params().get('fileThreshold', None) or 10)

    response = get_file_report(file_hash, all_info)

    if response.get('response_code', None) == -2:
        hr = "The file is queued for analysis. Try again in a short while."
        ec = {'VirusTotal(val.ID == obj.ID)': {'ID': file_hash,
                                               'Status': 'Queued'}}
        return {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }

    if response.get('response_code', None) == 0:
        return "A report wasn't found. Virus Total returned the following response: " + json.dumps(
            response.get('verbose_msg'))

    del response['response_code']

    output = create_file_output(file_hash, threshold, response, short_format)

    return output


def get_url_report(url, all_info):
    """
    Returns a report about an url.
    """

    params = {
        'resource': url,
        'allinfo': all_info,
        'scan': 1
    }

    api_endpoint = 'url/report'
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def get_url_report_command():
    """
    corresponds to 'vt-get-url-report' command. Retrieves a report about a url
    """
    args = demisto.args()
    urls = argToList(args.get('resource'))
    all_info = 1 if args.get('allInfo', None) == 'true' else 0
    short_format = args.get('shortFormat', None) == 'true'
    retries = int(args.get('retries', 2))
    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    threshold = int(args.get('threshold', None) or demisto.params().get('urlThreshold', None) or 10)
    scan_finish_time_in_seconds = int(args.get('retry_time', 6))
    if full_response:
        max_len = 1000
    else:
        max_len = 50

    responses_dict = get_url_reports_with_retries(urls, all_info, retries, scan_finish_time_in_seconds)
    entries = []

    for url, res in responses_dict.iteritems():
        url_md, url_ec, dbot_score = create_url_report_output(url, res, threshold, max_len, short_format)
        entry = {
            'Type': entryTypes['note'],
            'Contents': res,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': url_md,
            'EntryContext': {
                'DBotScore': dbot_score,
                outputPaths['url']: url_ec,
            }
        }
        entries.append(entry)

    if len(entries) == 0:
        md = "No scans were completed in the elapsed time. Please run the command again in a few seconds."
        entries.append({
            'Type': entryTypes['note'],
            'Contents': None,
            'ContentsFormat': formats['text'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md
        })

    return entries


def get_url_reports_with_retries(urls, all_info, retries_left, scan_finish_time_in_seconds):
    """
    Returns dict of responses, where its keys are the URL related to the response.
    """
    requests_responses_dict = {}

    for url in urls:
        response = get_url_report(url, all_info)
        if response.get('response_code', None) == -1:
            return_error("Invalid url provided: {}.".format(url))

        if is_url_response_complete(response):
            requests_responses_dict[url] = response

    urls_scanned_count = len(requests_responses_dict)
    urls_count = len(urls)
    while urls_count > urls_scanned_count and retries_left > 0:
        retries_left -= 1
        # In case there were url scans that have not finished: try again after giving them enough time to finish
        time.sleep(scan_finish_time_in_seconds)  # pylint: disable=sleep-exists
        for url in urls:
            if url not in requests_responses_dict:
                response = get_url_report(url, all_info)
                if is_url_response_complete(response):
                    requests_responses_dict[url] = response
                    urls_scanned_count = len(requests_responses_dict)

    return requests_responses_dict


def is_url_response_complete(res):
    return bool(res.get('total'))


def update_entry_context_url(ec_url, url, field_name, field_value):
    if ec_url:
        if 'VirusTotal' not in ec_url:
            ec_url['VirusTotal'] = {
                field_name: field_value
            }
        else:
            ec_url['VirusTotal'][field_name] = field_value
    else:
        ec_url.update({
            'VirusTotal': {field_name: field_value},
            'Data': url
        })


def create_url_report_output(url, response, threshold, max_len, short_format):
    """
    Returns 3 results:
    1. human readable string.
    2. url entry context.
    3. dbot entry context.
    """
    positives = demisto.get(response, 'positives')
    md = ''
    md += '## VirusTotal URL report for: ' + url + '\n'
    md += 'Scan ID: **' + str(response.get('scan_id', '')) + '**\n'
    md += 'Scan date: **' + str(response.get('scan_date', '')) + '**\n'
    md += 'Detections / Total: **' + str(positives) + '/' + str(response.get('total', '')) + '**\n'
    md += 'Resource: ' + str(response.get('resource')) + '\n'
    md += 'VT Link: [' + str(response.get('permalink')) + '](' + str(response.get('permalink')) + ')\n'

    dbot_score = 1
    ec_url = {}
    if positives >= threshold or is_enough_preferred_vendors(response):
        ec_url.update({
            'Data': url,
            'Malicious': {
                'Description': 'Detections / Total: ' + str(positives) + ' / ' + str(response.get('total', '')),
                'Vendor': 'VirusTotal - Private API'
            },
        })
        dbot_score = 3
    elif positives >= threshold / 2:
        dbot_score = 2

    ec_dbot = {
        'Indicator': url,
        'Type': 'url',
        'Vendor': 'VirusTotal - Private API',
        'Score': dbot_score
    }
    if dbot_score < 3:
        ec_url.update({'Data': url})

    additional_info = response.get('additional_info', None)
    if additional_info is not None:
        resolution = additional_info.get('resolution', None)
        if resolution:
            md += 'IP address resolution for this domain is: ' + resolution + '\n'
        update_entry_context_url(ec_url, url, field_name='Resolutions', field_value=resolution[:max_len])

        response_sha256 = additional_info.get('Response content SHA-256', None)
        if response_sha256:
            md += 'Response content SHA-256: {}\n'.format(response_sha256)
            update_entry_context_url(ec_url, url, field_name='ResponseContentSHA256', field_value=response_sha256)

        response_headers = additional_info.get('Response headers', None)
        if response_headers:
            update_entry_context_url(ec_url, url, field_name='ResponseHeaders', field_value=response_headers)

    scans = response.get('scans', None)

    if scans is not None and not short_format:
        scans_table = create_scans_table(scans)
        scans_table_md = tableToMarkdown('Scans', scans_table)
        if ec_url.get('VirusTotal', False):
            ec_url['VirusTotal']['Scans'] = scans_table
        else:
            ec_url['VirusTotal'] = {
                'Scans': scans_table
            }
        md += scans_table_md

    dropped_files = response.get('filescan_id', None)

    if dropped_files is not None:
        if ec_url.get('VirusTotal', False):
            ec_url['VirusTotal']['DroppedFiles'] = dropped_files
        else:
            ec_url['VirusTotal'] = {
                'DroppedFiles': dropped_files
            }
    return md, ec_url, ec_dbot


def get_ip_report(ip):
    """
    Returns an ip report.
    """

    params = {
        'ip': ip
    }

    api_endpoint = 'ip-address/report'
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def check_detected_urls_threshold(detected_urls, threshold):
    for url in detected_urls:
        if url.get("positives") >= threshold:
            return True
    return False


def get_ip_report_command():
    """
    corresponds to 'vt-get-ip-report' command. Retrieves a report about an ip
    """

    args = demisto.args()
    ip = args['ip']
    threshold = int(args.get('threshold', None) or demisto.params().get('ipThreshold', None) or 10)
    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    if full_response:
        max_len = 1000
    else:
        max_len = 50

    response = get_ip_report(ip)

    if response.get('response_code') == -1:
        return "Invalid IP address "
    elif response.get('response_code') == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'EntryContext': {
                "DBotScore": {
                    'Indicator': ip,
                    'Type': 'ip',
                    'Vendor': 'VirusTotal - Private API',
                    'Score': 0
                }
            },
            'HumanReadable': "IP "
                             + ip
                             + "not in Virus Total's dataset. Virus Total returned the following response: "
                             + json.dumps(response.get('verbose_msg'))
        }

    ec = {}  # type: dict
    md = '## VirusTotal IP report for: ' + ip + '\n'
    asn = str(response.get('asn', None)) if response.get('asn', None) else None
    if asn is not None:
        md += 'ASN: **' + asn + ' (' + str(response.get('as_owner', '')) + ')**\n'
    md += 'Country: **' + response.get('country', '') + '**\n'

    resolutions = response.get('resolutions', None)

    if resolutions:
        resolutions = resolutions[:max_len]
        md += tableToMarkdown("The following domains resolved to the given IP address:", resolutions)

    detected_urls = response.get('detected_urls', None)

    if detected_urls:
        detected_urls = detected_urls[:max_len]
        md += tableToMarkdown(
            "Latest URLs hosted in this IP address detected by at least one URL scanner or malicious URL dataset:",
            detected_urls)

    detected_downloaded_samples = response.get('detected_downloaded_samples', None)

    if detected_downloaded_samples:
        detected_downloaded_samples = detected_downloaded_samples[:max_len]
        md += tableToMarkdown(
            "Latest files that are detected by at least one antivirus solution and were downloaded by VirusTotal from"
            " the IP address provided",
            detected_downloaded_samples)

    undetected_downloaded_samples = response.get('undetected_downloaded_samples', None)

    if undetected_downloaded_samples:
        undetected_downloaded_samples = undetected_downloaded_samples[:max_len]
        md += tableToMarkdown(
            "Latest files that are not detected by any antivirus solution and were downloaded by VirusTotal from the "
            "IP address provided",
            undetected_downloaded_samples)

    detected_communicating_samples = response.get('detected_communicating_samples', None)

    if detected_communicating_samples:
        detected_communicating_samples = detected_communicating_samples[:max_len]
        md += tableToMarkdown("Latest detected files that communicate with this IP address",
                              detected_communicating_samples)

    undetected_communicating_samples = response.get('undetected_communicating_samples', None)

    if undetected_communicating_samples:
        undetected_communicating_samples = undetected_communicating_samples[:max_len]
        md += tableToMarkdown("Latest undetected files that communicate with this IP address",
                              undetected_communicating_samples)

    detected_referrer_samples = response.get('detected_referrer_samples', None)

    if detected_referrer_samples:
        detected_referrer_samples = detected_referrer_samples[:max_len]
        md += tableToMarkdown("Latest detected files that embed this IP address in their strings",
                              detected_referrer_samples)

    undetected_referrer_samples = response.get('undetected_referrer_samples', None)

    if undetected_referrer_samples:
        undetected_referrer_samples = undetected_referrer_samples[:max_len]
        md += tableToMarkdown("Latest undetected files that embed this IP address in their strings",
                              undetected_referrer_samples)

    ec['DBotScore'] = []
    bad_downloads_amount = len(detected_communicating_samples) if detected_communicating_samples else 0
    detected_url_is_above_threshold = check_detected_urls_threshold(detected_urls,
                                                                    demisto.params().get('urlThreshold', None) or 10)
    if bad_downloads_amount >= threshold or detected_url_is_above_threshold:
        ec.update({
            outputPaths['ip']: {
                'Address': ip,
                'ASN': asn,
                'Geo': {
                    'Country': response.get('country', '')
                },
                'Malicious': {
                    'Description': 'Recent malicious downloads: ' + str(bad_downloads_amount),
                    'Vendor': 'VirusTotal - Private API'
                }
            }
        })
        dbotScore = 3
    elif bad_downloads_amount >= threshold / 2 or len(detected_urls) >= threshold / 2:
        dbotScore = 2
    else:
        dbotScore = 1

    ec['DBotScore'] = {'Indicator': ip, 'Type': 'ip', 'Vendor': 'VirusTotal - Private API', 'Score': dbotScore}
    if dbotScore < 3:
        ec.update({
            outputPaths['ip']: {
                'Address': ip,
                'ASN': asn,
                'Geo': {
                    'Country': response.get('country', '')
                }
            }
        })

    ip_ec = {
        'Address': ip,
        'VirusTotal': {
            'DownloadedHashes': detected_downloaded_samples,
            'UnAVDetectedDownloadedHashes': undetected_downloaded_samples,
            "DetectedURLs": detected_urls,
            'CommunicatingHashes': detected_communicating_samples,
            'UnAVDetectedCommunicatingHashes': undetected_communicating_samples,
            'Resolutions': resolutions,
            'ReferrerHashes': detected_referrer_samples,
            'UnAVDetectedReferrerHashes': undetected_referrer_samples
        }
    }

    if ec.get(outputPaths['ip'], False):
        ec[outputPaths['ip']]['VirusTotal'] = {
            'DownloadedHashes': detected_downloaded_samples,
            'UnAVDetectedDownloadedHashes': undetected_downloaded_samples,
            "DetectedURLs": detected_urls,
            'CommunicatingHashes': detected_communicating_samples,
            'UnAVDetectedCommunicatingHashes': undetected_communicating_samples,
            'Resolutions': resolutions,
            'ReferrerHashes': detected_referrer_samples,
            'UnAVDetectedReferrerHashes': undetected_referrer_samples
        }
    else:
        ec[outputPaths['ip']].update(ip_ec)

    return {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    }


def search_file(query):
    """
    Returns the hashes of files that fits the query.
    """

    params = {
        'query': query
    }

    api_endpoint = 'file/search'
    return http_request('POST', api_endpoint, params, DEFAULT_HEADERS)


def search_file_command():
    """
    corresponds to 'vt-search-file' command. Returns the hashes of files that fits the query
    """

    args = demisto.args()
    query = args['query']

    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    if full_response:
        max_len = 1000
    else:
        max_len = 50
    response = search_file(query)

    if response.get('response_code') == -1:
        return "There was some sort of error with your query. Virus Total returned the following response: " + \
               json.dumps(response.get('verbose_msg'))
    elif response.get('response_code') == 0:
        return "No files matched your query"

    del response['response_code']
    hashes = response.get('hashes', None)[:max_len]

    md = '## Found the following hashes for the query :' + query + '\n'
    md += tableToMarkdown('Hashes are: ', [{'Hash': h} for h in hashes])

    ec = {
        "Query": query,
        "SearchResult": hashes[:max_len]
    }

    return {
        'Type': entryTypes['note'],
        'Contents': ec,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'VirusTotal.SearchFile(val.Query==obj.Query)': ec
        }
    }


def hash_communication_command():
    # variables
    args = demisto.args()
    file_hash = args.get('hash')
    full_response = FULL_RESPONSE or args.get('fullResponse', None) == 'true'
    if full_response:
        max_len = 1000
    else:
        max_len = 50
    md = ''
    # VT response
    response = check_file_behaviour(file_hash)

    if response.get('response_code') == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'EntryContext': {
                'DBotScore': get_dbot_file_context(file_hash, 0)
            },

            'HumanReadable': "A report wasn't found for file " + file_hash + ". Virus Total returned the following"
                                                                             " response: " + json.dumps
                             (response.get('verbose_msg'))
        }

    # network data contains all the communication data
    network_data = response.get('network', {})

    hosts = network_data.get('hosts')
    if hosts:
        hosts = list(set(hosts))[:max_len]
        md += tableToMarkdown('Hosts that the hash communicates with are:', [{'Host': host} for host in hosts])

    ips_list = []
    domains_list = []
    urls_list = []

    udp_communication = network_data.get('udp')
    if udp_communication:
        for entry in udp_communication:
            ips_list.append(entry.get('dst'))

    http_communication = network_data.get('http')
    if http_communication:
        for entry in http_communication:
            urls_list.append(entry.get('uri'))
            domains_list.append(entry.get('host'))

    tcp_communication = network_data.get('tcp')
    if tcp_communication:
        for entry in tcp_communication:
            ips_list.append(entry.get('dst'))

    dns_communication = network_data.get('dns')
    if dns_communication:
        for entry in dns_communication:
            ips_list.append(entry.get('ip'))
            domains_list.append(entry.get('hostname'))

    if len(ips_list) > 0:
        ips_list = list(set(ips_list))[:max_len]
        md += tableToMarkdown('IPs that the hash communicates with are:', [{'IP': ip} for ip in ips_list])

    if len(domains_list) > 0:
        domains_list = list(set(domains_list))[:max_len]
        md += tableToMarkdown('Domains that the hash communicates with are:',
                              [{'Domain': domain} for domain in domains_list])

    if len(urls_list) > 0:
        urls_list = list(set(urls_list))[:max_len]
        md += tableToMarkdown('URLs that the hash communicates with are:', [{'URL': url} for url in urls_list])

    hash_length = len(file_hash)
    if hash_length == 32:
        hashtype_dic = {
            "MD5": file_hash
        }
    elif hash_length == 40:
        hashtype_dic = {
            "SHA1": file_hash
        }
    else:
        hashtype_dic = {
            "SHA256": file_hash
        }

    hash_ec = {
        "VirusTotal": {
            "CommunicatedDomains": domains_list,
            "CommunicatedURLs": urls_list,
            "CommunicatedIPs": ips_list,
            "CommunicatedHosts": hosts
        }
    }

    hash_ec.update(hashtype_dic)

    if md:
        md = 'Communication result for hash ' + file_hash + '\n' + md
    else:
        md = 'No communication results were found for hash ' + file_hash

    return {
        'Type': entryTypes['note'],
        'Contents': network_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            outputPaths['file']: hash_ec
        }
    }


def download_file(file_hash):
    params = {
        'hash': file_hash,
        'apikey': API_KEY
    }

    response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)

    return response


def download_file_command():
    args = demisto.args()
    file_hash = args['hash']

    response = download_file(file_hash)

    if response.status_code == 404:
        return "File was not found in Virus Total's store"

    file_name = file_hash + "-vt-file"
    file_json = fileResult(file_name, response.content)

    return {
        'Contents': 'File downloaded successfully',
        'ContentsFormat': formats['text'],
        'Type': entryTypes['file'],
        'File': file_name,
        'FileID': file_json['FileID']
    }


''' EXECUTION CODE '''


def main():
    LOG('command is %s' % (demisto.command(),))
    try:
        handle_proxy(proxy_param_name='useProxy')
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            # disable-secrets-detection-start
            if check_file_behaviour(
                    '10676cf66244cfa91567fbc1a937f4cb19438338b35b69d4bcc2cf0d3a44af5e'):  # guardrails-disable-line
                # disable-secrets-detection-end
                demisto.results('ok')
            else:
                demisto.results('test failed')
        elif demisto.command() == 'vt-private-check-file-behaviour':
            demisto.results(check_file_behaviour_command())
        elif demisto.command() == 'vt-private-get-domain-report':
            demisto.results(get_domain_report_command())
        elif demisto.command() == 'vt-private-get-file-report':
            demisto.results(get_file_report_command())
        elif demisto.command() == 'vt-private-get-url-report':
            demisto.results(get_url_report_command())
        elif demisto.command() == 'vt-private-get-ip-report':
            demisto.results(get_ip_report_command())
        elif demisto.command() == 'vt-private-search-file':
            demisto.results(search_file_command())
        elif demisto.command() == 'vt-private-hash-communication':
            demisto.results(hash_communication_command())
        elif demisto.command() == 'vt-private-download-file':
            demisto.results(download_file_command())

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
