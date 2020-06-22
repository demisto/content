import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import time
import json
import random

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
CLOUD_NAME = demisto.params()['cloud']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
API_KEY = str(demisto.params()['key'])
BASE_URL = CLOUD_NAME + '/api/v1'
USE_SSL = not demisto.params().get('insecure', False)
PROXY = demisto.params().get('proxy', True)
DEFAULT_HEADERS = {
    'content-type': 'application/json'
}
EXCEEDED_RATE_LIMIT_STATUS_CODE = 429
MAX_SECONDS_TO_WAIT = 30
ERROR_CODES_DICT = {
    400: 'Invalid or bad request',
    401: 'Session is not authenticated or timed out',
    403: 'One of the following permission errors occurred:\n-The API key was disabled by your service provider\n'
         '-User role has no access permissions or functional scope\n-A required SKU subscription is missing\n'
         'Contact support or your account team for assistance.',
    404: 'Resource does not exist',
    409: 'Request could not be processed because of possible edit conflict occurred. Another admin might be saving a '
         'configuration change at the same time. In this scenario, the client is expected to retry after a short '
         'time period.',
    415: 'Unsupported media type.',
    429: 'Exceeded the rate limit or quota.',
    500: 'Unexpected error',
    503: 'Service is temporarily unavailable'
}

''' HANDLE PROXY '''
if not PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, data=None, headers=None, num_of_seconds_to_wait=3):
    if headers is None:
        headers = DEFAULT_HEADERS
    data = {} if data is None else data
    url = BASE_URL + url_suffix
    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               data=data,
                               headers=headers
                               )
        if res.status_code not in (200, 204):
            if res.status_code == EXCEEDED_RATE_LIMIT_STATUS_CODE and num_of_seconds_to_wait <= MAX_SECONDS_TO_WAIT:
                random_num_of_seconds = random.randint(num_of_seconds_to_wait, num_of_seconds_to_wait + 3)
                time.sleep(random_num_of_seconds)
                return http_request(method, url_suffix, data, headers=headers,
                                    num_of_seconds_to_wait=num_of_seconds_to_wait + 3)
            else:
                raise Exception('Your request failed with the following error: ' + ERROR_CODES_DICT[res.status_code])
    except Exception as e:
        LOG('Zscaler request failed with url={url}\tdata={data}'.format(url=url, data=data))
        LOG(e)
        raise e
    return res


def validate_urls(urls):
    for url in urls:
        if url.startswith('http://') or url.startswith('https://'):
            return_error(
                'Enter a valid URL address without an http:// or https:// prefix. URL should have at least host.'
                'domain pattern to qualify.')


''' FUNCTIONS '''


def login():
    cmd_url = '/authenticatedSession'

    def obfuscateApiKey(seed):
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += seed[int(n[i])]
        for j in range(0, len(r), 1):
            key += seed[int(r[j]) + 2]
        return now, key

    ts, key = obfuscateApiKey(API_KEY)
    data = {
        'username': USERNAME,
        'timestamp': ts,
        'password': PASSWORD,
        'apiKey': key
    }
    json_data = json.dumps(data)
    result = http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    return result.headers['Set-Cookie']


def activate_changes():
    cmd_url = '/status/activate'
    http_request('POST', cmd_url, None, DEFAULT_HEADERS)


def logout():
    cmd_url = '/authenticatedSession'
    http_request('DELETE', cmd_url, None, DEFAULT_HEADERS)


def blacklist_url(url):
    urls_to_blacklist = argToList(url)
    validate_urls(urls_to_blacklist)
    cmd_url = '/security/advanced/blacklistUrls?action=ADD_TO_LIST'
    data = {
        'blacklistUrls': urls_to_blacklist
    }
    json_data = json.dumps(data)
    http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ''
    for url in urls_to_blacklist:
        list_of_urls += '- ' + url + '\n'
    return 'Added the following URLs to the blacklist successfully:\n' + list_of_urls


def unblacklist_url(url):
    urls_to_unblacklist = argToList(url)
    cmd_url = '/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST'

    # Check if given URLs is blacklisted
    blacklisted_urls = get_blacklist()['blacklistUrls']
    if len(urls_to_unblacklist) == 1:  # Given only one URL to unblacklist
        if urls_to_unblacklist[0] not in blacklisted_urls:
            raise Exception('Given URL is not blacklisted.')
    elif not any(url in urls_to_unblacklist for url in blacklisted_urls):  # Given more than one URL to blacklist
        raise Exception('Given URLs are not blacklisted.')

    data = {
        'blacklistUrls': urls_to_unblacklist
    }
    json_data = json.dumps(data)
    http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ''
    for url in urls_to_unblacklist:
        list_of_urls += '- ' + url + '\n'
    return 'Removed the following URLs from the blacklist successfully:\n' + list_of_urls


def blacklist_ip(ip):
    ips_to_blacklist = argToList(ip)
    cmd_url = '/security/advanced/blacklistUrls?action=ADD_TO_LIST'
    data = {
        'blacklistUrls': ips_to_blacklist
    }
    json_data = json.dumps(data)
    http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ''
    for ip in ips_to_blacklist:
        list_of_ips += '- ' + ip + '\n'
    return 'Added the following IP addresses to the blacklist successfully:\n' + list_of_ips


def unblacklist_ip(ip):
    ips_to_unblacklist = argToList(ip)
    cmd_url = '/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST'
    # Check if given IPs is blacklisted
    blacklisted_ips = get_blacklist()['blacklistUrls']
    if len(ips_to_unblacklist) == 1:  # Given only one IP address to blacklist
        if ips_to_unblacklist[0] not in blacklisted_ips:
            raise Exception('Given IP address is not blacklisted.')
    elif not set(ips_to_unblacklist).issubset(set(blacklisted_ips)):  # Given more than one IP address to blacklist
        raise Exception('Given IP addresses are not blacklisted.')
    data = {
        'blacklistUrls': ips_to_unblacklist
    }
    json_data = json.dumps(data)
    http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ''
    for ip in ips_to_unblacklist:
        list_of_ips += '- ' + ip + '\n'
    return 'Removed the following IP addresses from the blacklist successfully:\n' + list_of_ips


def whitelist_url(url):
    cmd_url = '/security'
    urls_to_whitelist = argToList(url)
    # Get the current whitelist
    whitelist_urls = get_whitelist()
    if not whitelist_urls:
        whitelist_urls['whitelistUrls'] = []

    whitelist_urls['whitelistUrls'] += urls_to_whitelist
    json_data = json.dumps(whitelist_urls)
    http_request('PUT', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ''
    for url in urls_to_whitelist:
        list_of_urls += '- ' + url + '\n'
    return 'Added the following URLs to the whitelist successfully:\n' + list_of_urls


def unwhitelist_url(url):
    cmd_url = '/security'
    urls_to_unwhitelist = argToList(url)
    # Get the current whitelist
    whitelist_urls = get_whitelist()
    if not whitelist_urls:
        whitelist_urls['whitelistUrls'] = []

    # Check if given URL is whitelisted
    if len(urls_to_unwhitelist) == 1:  # Given only one URL to whitelist
        if urls_to_unwhitelist[0] not in whitelist_urls['whitelistUrls']:
            raise Exception('Given host address is not whitelisted.')
    elif not set(urls_to_unwhitelist).issubset(set(whitelist_urls['whitelistUrls'])):  # Given more than one URL to whitelist
        raise Exception('Given host addresses are not whitelisted.')
    # List comprehension to remove requested URLs from the whitelist
    whitelist_urls['whitelistUrls'] = [x for x in whitelist_urls['whitelistUrls'] if x not in urls_to_unwhitelist]
    json_data = json.dumps(whitelist_urls)
    http_request('PUT', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_urls = ''
    for url in whitelist_urls:
        list_of_urls += '- ' + url + '\n'
    return 'Removed the following URLs from the whitelist successfully:\n' + list_of_urls


def whitelist_ip(ip):
    cmd_url = '/security'
    ips_to_whitelist = argToList(ip)
    # Get the current whitelist
    whitelist_ips = get_whitelist()
    if not whitelist_ips:
        whitelist_ips['whitelistUrls'] = []

    whitelist_ips['whitelistUrls'] += ips_to_whitelist
    json_data = json.dumps(whitelist_ips)
    http_request('PUT', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ''
    for ip in ips_to_whitelist:
        list_of_ips += '- ' + ip + '\n'
    return 'Added the following URLs to the whitelist successfully:\n' + list_of_ips


def unwhitelist_ip(ip):
    cmd_url = '/security'
    ips_to_unwhitelist = argToList(ip)
    # Get the current whitelist
    whitelist_ips = get_whitelist()
    if not whitelist_ips:
        whitelist_ips['whitelistUrls'] = []

    # Check if given IP is whitelisted
    if len(ips_to_unwhitelist) == 1:  # Given only one IP to whitelist
        if ips_to_unwhitelist[0] not in whitelist_ips['whitelistUrls']:
            raise Exception('Given IP address is not whitelisted.')
    elif not set(ips_to_unwhitelist).issubset(set(whitelist_ips['whitelistUrls'])):  # Given more than one IP to whitelist
        raise Exception('Given IP address is not whitelisted.')
    # List comprehension to remove requested IPs from the whitelist
    whitelist_ips['whitelistUrls'] = [x for x in whitelist_ips['whitelistUrls'] if x not in ips_to_unwhitelist]
    json_data = json.dumps(whitelist_ips)
    http_request('PUT', cmd_url, json_data, DEFAULT_HEADERS)
    list_of_ips = ''
    for ip in ips_to_unwhitelist:
        list_of_ips += '- ' + ip + '\n'
    return 'Removed the following IP addresses from the whitelist successfully:\n' + list_of_ips


def get_blacklist_command():
    blacklist = get_blacklist().get('blacklistUrls')
    if blacklist:
        hr = '### Zscaler blacklist\n'
        for url in blacklist:
            hr += '- ' + url + '\n'
        ec = {
            'Zscaler.Blacklist': blacklist
        }
        entry = {
            'Type': entryTypes['note'],
            'Contents': blacklist,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return 'No results found'


def get_blacklist():
    cmd_url = '/security/advanced'
    result = http_request('GET', cmd_url, None, DEFAULT_HEADERS)
    return json.loads(result.content)


def get_whitelist_command():
    whitelist = get_whitelist().get('whitelistUrls')
    if whitelist:
        hr = '### Zscaler whitelist\n'
        for url in whitelist:
            hr += '- ' + url + '\n'
        ec = {
            'Zscaler.Whitelist': whitelist
        }
        entry = {
            'Type': entryTypes['note'],
            'Contents': whitelist,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return 'No results found'


def get_whitelist():
    cmd_url = '/security'
    result = http_request('GET', cmd_url, None, DEFAULT_HEADERS)
    return json.loads(result.content)


def url_lookup(args):
    url = args.get('url', '')
    multiple = args.get('multiple', 'true').lower() == 'true'
    response = lookup_request(url, multiple)
    hr = json.loads(response.content)
    if hr:
        data = hr[0]
        suspicious_categories = ['SUSPICIOUS_DESTINATION', 'SPYWARE_OR_ADWARE']
        ioc_context = {'Address': data['url'], 'Data': data['url']}
        score = 1
        if len(data['urlClassifications']) == 0:
            data['urlClassifications'] = ''
        else:
            data['urlClassifications'] = ''.join(data['urlClassifications'])
            ioc_context['urlClassifications'] = data['urlClassifications']
            if data['urlClassifications'] == 'MISCELLANEOUS_OR_UNKNOWN':
                score = 0
        if len(data['urlClassificationsWithSecurityAlert']) == 0:
            data['urlClassificationsWithSecurityAlert'] = ''
        else:
            data['urlClassificationsWithSecurityAlert'] = ''.join(data['urlClassificationsWithSecurityAlert'])
            if data['urlClassificationsWithSecurityAlert'] in suspicious_categories:
                score = 2
            else:
                score = 3
            ioc_context['Malicious'] = {
                'Vendor': 'Zscaler',
                'Description': data['urlClassificationsWithSecurityAlert']
            }
            data['ip'] = data.pop('url')
        ioc_context = createContext(data=ioc_context, removeNull=True)
        ec = {
            outputPaths['url']: ioc_context,
            'DBotScore': [
                {
                    "Indicator": url,
                    "Score": score,
                    "Type": "url",
                    "Vendor": "Zscaler"
                }
            ]
        }
        title = 'Zscaler URL Lookup'
        entry = {
            'Type': entryTypes['note'],
            'Contents': hr,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, data, removeNull=True),
            'EntryContext': ec
        }
    else:
        entry = 'No results found.'  # type: ignore
    return entry


def ip_lookup(ip):
    response = lookup_request(ip)
    hr = json.loads(response.content)
    if hr:
        ioc_context = [None] * len(hr)  # type: List[Any]
        suspicious_categories = ['SUSPICIOUS_DESTINATION', 'SPYWARE_OR_ADWARE']
        dbot_score_array = [None] * len(hr)  # type: List[Any]
        for i in range(len(hr)):
            ioc_context[i] = {}
            dbot_score_array[i] = {}
            ioc_context[i]['Address'] = hr[i]['url']
            dbot_score_array[i]['Indicator'] = hr[i]['url']
            score = 1
            if len(hr[i]['urlClassifications']) == 0:
                hr[i]['iplClassifications'] = ''
            else:
                hr[i]['ipClassifications'] = ''.join(hr[i]['urlClassifications'])
                ioc_context[i]['ipClassifications'] = hr[i]['ipClassifications']
            del hr[i]['urlClassifications']
            if len(hr[i]['urlClassificationsWithSecurityAlert']) == 0:
                hr[i]['ipClassificationsWithSecurityAlert'] = ''
            else:
                hr[i]['ipClassificationsWithSecurityAlert'] = ''.join(hr[i]['urlClassificationsWithSecurityAlert'])
                if hr[i]['urlClassificationsWithSecurityAlert'] in suspicious_categories:
                    score = 2
                else:
                    score = 3
                ioc_context[i]['Malicious'] = {
                    'Vendor': 'Zscaler',
                    'Description': hr[i]['ipClassificationsWithSecurityAlert']
                }
            del hr[i]['urlClassificationsWithSecurityAlert']
            hr[i]['ip'] = hr[i].pop('url')
            dbot_score_array[i]['Score'] = score
            dbot_score_array[i]['Type'] = 'ip'
            dbot_score_array[i]['Vendor'] = 'Zscaler'

        ioc_context = createContext(data=ioc_context, removeNull=True)
        ec = {
            outputPaths['ip']: ioc_context,
            'DBotScore': dbot_score_array
        }
        title = 'Zscaler IP Lookup'
        entry = {
            'Type': entryTypes['note'],
            'Contents': hr,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, hr, removeNull=True),
            'EntryContext': ec
        }
    else:
        entry = 'No results found.'  # type: ignore
    return entry


def lookup_request(ioc, multiple=True):
    cmd_url = '/urlLookup'
    if multiple:
        ioc_list = ioc.split(',')
    else:
        ioc_list = [ioc]
    json_data = json.dumps(ioc_list)
    response = http_request('POST', cmd_url, json_data, DEFAULT_HEADERS)
    return response


def category_add_url(category_id, url):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category['id'] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        url_list = argToList(url)
        all_urls = url_list[:]
        all_urls.extend(list(map(lambda x: x.strip(), category_data['urls'])))
        category_data['urls'] = all_urls
        category_ioc_update(category_data)
        context = {
            'ID': category_id,
            'CustomCategory': category_data['customCategory'],
            'URL': category_data['urls']
        }
        if 'description' in category_data and category_data['description']:  # Custom might not have description
            context['Description'] = category_data['description']
        ec = {
            'Zscaler.Category(val.ID && val.ID === obj.ID)': context
        }
        urls = ''
        for url in url_list:
            urls += '- ' + url + '\n'
        hr = 'Added the following URL addresses to category {}:\n{}'.format(category_id, urls)
        entry = {
            'Type': entryTypes['note'],
            'Contents': ec,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return return_error('Category could not be found.')


def category_add_ip(category_id, ip):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category['id'] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        ip_list = ip.split(',')
        all_ips = ip_list[:]
        all_ips.extend(category_data['urls'])
        category_data['urls'] = all_ips
        response = category_ioc_update(category_data)
        context = {
            'ID': category_id,
            'CustomCategory': category_data['customCategory'],
            'URL': category_data['urls']
        }
        if 'description' in category_data and category_data['description']:  # Custom might not have description
            context['Description'] = category_data['description']
        ec = {
            'Zscaler.Category(val.ID && val.ID === obj.ID)': context
        }
        ips = ''
        for ip in ip_list:
            ips += '- ' + ip + '\n'
        hr = 'Added the following IP addresses to category {}:\n{}'.format(category_id, ips)
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return return_error('Category could not be found.')


def category_remove_url(category_id, url):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category['id'] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        url_list = argToList(url)
        updated_urls = [url for url in category_data['urls'] if url not in url_list]  # noqa
        if updated_urls == category_data['urls']:
            return return_error('Could not find given URL in the category.')
        category_data['urls'] = updated_urls
        response = category_ioc_update(category_data)
        context = {
            'ID': category_id,
            'CustomCategory': category_data['customCategory'],
            'URL': category_data['urls']
        }
        if 'description' in category_data and category_data['description']:  # Custom might not have description
            context['Description'] = category_data['description']
        ec = {
            'Zscaler.Category(val.ID && val.ID === obj.ID)': context
        }
        urls = ''
        for url in url_list:
            urls += '- ' + url + '\n'
        hr = 'Removed the following URL addresses to category {}:\n{}'.format(category_id, urls)
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return return_error('Category could not be found.')


def category_remove_ip(category_id, ip):
    categories = get_categories()
    found_category = False
    for category in categories:
        if category['id'] == category_id:
            category_data = category
            found_category = True
            break
    if found_category:
        ip_list = ip.split(',')
        updated_ips = [ip for ip in category_data['urls'] if ip not in ip_list]  # noqa
        if updated_ips == category_data['urls']:
            return return_error('Could not find given IP in the category.')
        category_data['urls'] = updated_ips
        response = category_ioc_update(category_data)
        context = {
            'ID': category_id,
            'CustomCategory': category_data['customCategory'],
            'URL': category_data['urls']
        }
        if 'description' in category_data and category_data['description']:  # Custom might not have description
            context['Description'] = category_data['description']
        ec = {
            'Zscaler.Category(val.ID && val.ID === obj.ID)': context
        }
        ips = ''
        for ip in ip_list:
            ips += '- ' + ip + '\n'
        hr = 'Removed the following IP addresses to category {}:\n{}'.format(category_id, ips)
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        }
        return entry
    else:
        return return_error('Category could not be found.')


def category_ioc_update(category_data):
    cmd_url = '/urlCategories/' + category_data['id']
    data = {
        'customCategory': category_data['customCategory'],
        'urls': category_data['urls'],
        'id': category_data['id']
    }
    if 'description' in category_data:
        data['description'] = category_data['description']
    if 'configuredName' in category_data:
        data['configuredName'] = category_data['configuredName']
    json_data = json.dumps(data)
    response = http_request('PUT', cmd_url, json_data).json()
    return response


def get_categories_command(display_url):
    display_urls = True if display_url == 'true' else False
    raw_categories = get_categories()
    categories = []
    for raw_category in raw_categories:
        category = {
            'ID': raw_category['id'],
            'CustomCategory': raw_category['customCategory']
        }
        if raw_category['urls']:
            category['URL'] = raw_category['urls']
        if 'description' in raw_category:
            category['Description'] = raw_category['description']
        if 'configuredName' in raw_category:
            category['Name'] = raw_category['configuredName']
        categories.append(category)
    ec = {
        'Zscaler.Category(val.ID && val.ID === obj.ID)': categories
    }
    if display_urls:
        headers = ['ID', 'Description', 'URL', 'CustomCategory', 'Name']
    else:
        headers = ['ID', 'Description', 'CustomCategory', 'Name']
    title = 'Zscaler Categories'
    entry = {
        'Type': entryTypes['note'],
        'Contents': raw_categories,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, categories, headers),
        'EntryContext': ec
    }
    return entry


def get_categories():
    cmd_url = '/urlCategories'
    response = http_request('GET', cmd_url).json()
    return response


def sandbox_report_command():
    md5 = demisto.getArg('md5')
    details = demisto.getArg('details')
    res = sandbox_report(md5, details)

    report = 'Full Details' if details == 'full' else 'Summary'
    ctype = demisto.get(res, '{}.Classification.Type'.format(report))
    dbot_score = 3 if ctype == "MALICIOUS" else 2 if ctype == "SUSPICIOUS" else 1 if ctype == "BENIGN" else 0

    ec = {outputPaths['dbotscore']: {
        'Indicator': md5,
        'Type': 'file',
        'Vendor': 'Zscaler',
        'Score': dbot_score
    }}

    human_readable_report = ec['DBotScore'].copy()
    human_readable_report["Detected Malware"] = str(
        demisto.get(res, '{}.Classification.DetectedMalware'.format(report)))
    human_readable_report["Zscaler Score"] = demisto.get(res, '{}.Classification.Score'.format(report))
    human_readable_report["Category"] = demisto.get(res, '{}.Classification.Category'.format(report))
    ec[outputPaths['file']] = {
        'MD5': md5,
        'Zscaler': {
            'DetectedMalware': demisto.get(res, '{}.Classification.DetectedMalware'.format(report)),
            'FileType': demisto.get(res, '{}.File Properties.File Type'.format(report)),
        }
    }
    if dbot_score == 3:
        ec[outputPaths['file']]['Malicious'] = {
            'Vendor': 'Zscaler',
            'Description': 'Classified as Malicious, with threat score: ' + str(human_readable_report["Zscaler Score"])
        }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Full Sandbox Report', human_readable_report, removeNull=True),
        'EntryContext': ec
    })


def sandbox_report(md5, details):
    cmd_url = '/sandbox/report/{md5Hash}?details={details}'.format(md5Hash=md5, details=details)

    response = http_request('GET', cmd_url).json()
    return response


''' EXECUTION CODE '''


def main():
    auth = login()
    jsession_id = auth[:auth.index(';')]
    DEFAULT_HEADERS['cookie'] = jsession_id

    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            # Checks if there is an authenticated session
            http_request('GET', '/authenticatedSession', None, DEFAULT_HEADERS)
            demisto.results('ok')
        elif demisto.command() == 'url':
            demisto.results(url_lookup(demisto.args()))
        elif demisto.command() == 'ip':
            demisto.results(ip_lookup(demisto.args()['ip']))
        elif demisto.command() == 'zscaler-blacklist-url':
            demisto.results(blacklist_url(demisto.args()['url']))
        elif demisto.command() == 'zscaler-undo-blacklist-url':
            demisto.results(unblacklist_url(demisto.args()['url']))
        elif demisto.command() == 'zscaler-whitelist-url':
            demisto.results(whitelist_url(demisto.args()['url']))
        elif demisto.command() == 'zscaler-undo-whitelist-url':
            demisto.results(unwhitelist_url(demisto.args()['url']))
        elif demisto.command() == 'zscaler-blacklist-ip':
            demisto.results(blacklist_ip(demisto.args()['ip']))
        elif demisto.command() == 'zscaler-undo-blacklist-ip':
            demisto.results(unblacklist_ip(demisto.args()['ip']))
        elif demisto.command() == 'zscaler-whitelist-ip':
            demisto.results(whitelist_ip(demisto.args()['ip']))
        elif demisto.command() == 'zscaler-undo-whitelist-ip':
            demisto.results(unwhitelist_ip(demisto.args()['ip']))
        elif demisto.command() == 'zscaler-category-add-url':
            demisto.results(category_add_url(demisto.args()['category-id'], demisto.args()['url']))
        elif demisto.command() == 'zscaler-category-add-ip':
            demisto.results(category_add_ip(demisto.args()['category-id'], demisto.args()['ip']))
        elif demisto.command() == 'zscaler-category-remove-url':
            demisto.results(category_remove_url(demisto.args()['category-id'], demisto.args()['url']))
        elif demisto.command() == 'zscaler-category-remove-ip':
            demisto.results(category_remove_ip(demisto.args()['category-id'], demisto.args()['ip']))
        elif demisto.command() == 'zscaler-get-categories':
            demisto.results(get_categories_command(demisto.args()['displayURL']))
        elif demisto.command() == 'zscaler-get-blacklist':
            demisto.results(get_blacklist_command())
        elif demisto.command() == 'zscaler-get-whitelist':
            demisto.results(get_whitelist_command())
        elif demisto.command() == 'zscaler-sandbox-report':
            demisto.results(sandbox_report_command())
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise
    finally:
        try:
            activate_changes()
            logout()
        except Exception as err:
            demisto.info("Zscaler error: " + str(err))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
