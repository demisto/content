import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import time
import requests
import collections
import json as JSON
from urlparse import urlparse
from requests.utils import quote  # type: ignore


""" POLLING FUNCTIONS"""
try:
    from Queue import Queue
except ImportError:
    from queue import Queue  # type: ignore

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


'''GLOBAL VARS'''
BASE_URL = 'https://urlscan.io/api/v1/'
APIKEY = demisto.params().get('apikey')
THRESHOLD = int(demisto.params().get('url_threshold', '1'))
USE_SSL = not demisto.params().get('insecure', False)
BLACKLISTED_URL_ERROR_MESSAGE = 'The submitted domain is on our blacklist. ' \
                                'For your own safety we did not perform this scan...'

'''HELPER FUNCTIONS'''


def http_request(method, url_suffix, json=None, wait=0, retries=0):
    if method == 'GET':
        headers = {'API-Key': APIKEY,
                   'Accept': 'application/json'}  # type: ignore
    elif method == 'POST':
        headers = {
            'API-Key': APIKEY,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    demisto.debug(
        'requesting https request with method: {}, url: {}, data: {}'.format(method, BASE_URL + url_suffix, json))
    r = requests.request(
        method,
        BASE_URL + url_suffix,
        data=json,
        headers=headers,
        verify=USE_SSL
    )

    rate_limit_remaining = int(r.headers.get('X-Rate-Limit-Remaining', 99))
    if rate_limit_remaining < 10:
        return_warning('Your available rate limit remaining is {} and is about to be exhausted. '
                       'The rate limit will reset at {}'.format(str(rate_limit_remaining),
                                                                r.headers.get("X-Rate-Limit-Reset")))
    if r.status_code != 200:
        if r.status_code == 429:
            if retries <= 0:
                # Error in API call to URLScan.io [429] - Too Many Requests
                return_error('API rate limit reached [%d] - %s.\nUse the retries and wait arguments when submitting '
                             'multiple URls' % (r.status_code, r.reason))
            else:
                time.sleep(wait)  # pylint: disable=sleep-exists
                return http_request(method, url_suffix, json, wait, retries - 1)

        response_json = r.json()
        error_description = response_json.get('description')
        should_continue_on_blacklisted_urls = argToBoolean(demisto.args().get('continue_on_blacklisted_urls', False))
        if should_continue_on_blacklisted_urls and error_description == BLACKLISTED_URL_ERROR_MESSAGE:
            response_json['url_is_blacklisted'] = True
            requested_url = JSON.loads(json)['url']
            blacklisted_message = 'The URL {} is blacklisted, no results will be returned for it.'.format(requested_url)
            demisto.results(blacklisted_message)
            return response_json

        return_error('Error in API call to URLScan.io [%d] - %s: %s' % (r.status_code, r.reason, error_description))

    return r.json()


# Allows nested keys to be accesible
def makehash():
    return collections.defaultdict(makehash)


def get_result_page():
    uuid = demisto.args().get('uuid')
    uri = BASE_URL + 'result/{}'.format(uuid)
    return uri


def polling(uuid):
    TIMEOUT = int(demisto.args().get('timeout', 60))
    uri = BASE_URL + 'result/{}'.format(uuid)

    ready = poll(
        lambda: requests.get(uri, headers={'API-Key': APIKEY}, verify=USE_SSL).status_code == 200,
        step=5,
        ignore_exceptions=(requests.exceptions.ConnectionError),
        timeout=int(TIMEOUT)
    )
    return ready


def poll_uri():
    uri = demisto.args().get('uri')
    demisto.results(requests.get(uri, verify=USE_SSL).status_code)


def step_constant(step):
    return step


def is_truthy(val):
    return bool(val)


def poll(target, step, args=(), kwargs=None, timeout=60,
         check_success=is_truthy, step_function=step_constant,
         ignore_exceptions=(), collect_values=None, **k):

    kwargs = kwargs or dict()
    values = collect_values or Queue()

    max_time = time.time() + timeout
    tries = 0
    # According to the doc - The most efficient approach would be to wait at least 10 seconds before starting to poll
    time.sleep(10)
    while True:
        demisto.debug('Number of Polling attempts: {}'.format(tries))
        try:
            val = target(*args, **kwargs)
            last_item = val
        except ignore_exceptions as e:
            last_item = e
            demisto.debug('Polling request failed with exception {}'.format(str(e)))
        else:
            if check_success(val):
                return val
        demisto.debug('Polling request returned False')
        values.put(last_item)
        tries += 1
        if max_time is not None and time.time() >= max_time:
            demisto.results('The operation timed out. Please try again with a longer timeout period.')
            demisto.debug('The operation timed out.')
            return False
        time.sleep(step)  # pylint: disable=sleep-exists
        step = step_function(step)


'''MAIN FUNCTIONS'''


def urlscan_submit_url():
    submission_dict = {}
    if demisto.args().get('public'):
        if demisto.args().get('public') == 'public':
            submission_dict['visibility'] = 'public'
    else:
        if demisto.params().get('is_public') is True:
            submission_dict['visibility'] = 'public'

    submission_dict['url'] = demisto.args().get('url')
    sub_json = json.dumps(submission_dict)
    wait = int(demisto.args().get('wait', 5))
    retries = int(demisto.args().get('retries', 0))
    r = http_request('POST', 'scan/', sub_json, wait, retries)
    return r


def format_results(uuid):
    response = urlscan_submit_request(uuid)
    demisto.debug('urlscan_submit_request response: {}'.format(response))
    scan_data = response.get('data', {})
    scan_lists = response.get('lists', {})
    scan_tasks = response.get('task', {})
    scan_page = response.get('page', {})
    scan_stats = response.get('stats', {})
    scan_meta = response.get('meta', {})
    url_query = scan_tasks.get('url', {})
    scan_verdicts = response.get('verdicts', {})

    ec = makehash()
    dbot_score = makehash()
    human_readable = makehash()
    cont = makehash()
    file_context = makehash()
    url_cont = makehash()

    LIMIT = int(demisto.args().get('limit', 20))
    if 'certificates' in scan_lists:
        cert_md = []
        cert_ec = []
        certs = scan_lists['certificates']
        for x in certs[:LIMIT]:
            info, ec_info = cert_format(x)
            cert_md.append(info)
            cert_ec.append(ec_info)
        CERT_HEADERS = ['Subject Name', 'Issuer', 'Validity']
        cont['Certificates'] = cert_ec
    url_cont['Data'] = url_query
    if 'urls' in scan_lists:
        url_cont['Data'] = demisto.args().get('url')
        cont['URL'] = demisto.args().get('url')
    # effective url of the submitted url
    human_readable['Effective URL'] = scan_page.get('url')
    cont['EffectiveURL'] = scan_page.get('url')
    if 'uuid' in scan_tasks:
        ec['URLScan']['UUID'] = scan_tasks['uuid']
    if 'ips' in scan_lists:
        ip_asn_MD = []
        ip_ec_info = makehash()
        ip_list = scan_lists['ips']
        asn_list = scan_lists['asns']

        ip_asn_dict = dict(zip(ip_list, asn_list))
        i = 1
        for k in ip_asn_dict:
            if i - 1 == LIMIT:
                break
            v = ip_asn_dict[k]
            ip_info = {
                'Count': i,
                'IP': k,
                'ASN': v
            }
            ip_ec_info[i]['IP'] = k
            ip_ec_info[i]['ASN'] = v
            ip_asn_MD.append(ip_info)
            i = i + 1
        cont['RelatedIPs'] = ip_ec_info
        IP_HEADERS = ['Count', 'IP', 'ASN']
    # add redirected URLs
    if 'requests' in scan_data:
        redirected_urls = []
        for o in scan_data['requests']:
            if 'redirectResponse' in o['request']:
                if 'url' in o['request']['redirectResponse']:
                    url = o['request']['redirectResponse']['url']
                    redirected_urls.append(url)
        cont['RedirectedURLs'] = redirected_urls
    if 'countries' in scan_lists:
        countries = scan_lists['countries']
        human_readable['Associated Countries'] = countries
        cont['Country'] = countries
    if None not in scan_lists.get('hashes', []):
        hashes = scan_lists.get('hashes', [])
        cont['RelatedHash'] = hashes
        human_readable['Related Hashes'] = hashes
    if 'domains' in scan_lists:
        subdomains = scan_lists['domains']
        cont['Subdomains'] = subdomains
        human_readable['Subdomains'] = subdomains
    if 'asn' in scan_page:
        cont['ASN'] = scan_page['asn']
    if 'overall' in scan_verdicts:
        human_readable['Malicious URLs Found'] = scan_stats['malicious']
        if scan_verdicts['overall'].get('malicious'):
            human_readable['Malicious'] = 'Malicious'
            url_cont['Data'] = demisto.args().get('url')
            cont['Data'] = demisto.args().get('url')
            dbot_score['Indicator'] = demisto.args().get('url')
            url_cont['Malicious']['Vendor'] = 'urlscan.io'
            cont['Malicious']['Vendor'] = 'urlscan.io'
            dbot_score['Vendor'] = 'urlscan.io'
            url_cont['Malicious']['Description'] = 'Match found in Urlscan.io database'
            cont['Malicious']['Description'] = 'Match found in Urlscan.io database'
            dbot_score['Score'] = 3
            dbot_score['Type'] = 'url'
        else:
            dbot_score['Vendor'] = 'urlscan.io'
            dbot_score['Indicator'] = demisto.args().get('url')
            dbot_score['Score'] = 0
            dbot_score['Type'] = 'url'
            human_readable['Malicious'] = 'Benign'
    processors_data = scan_meta['processors']
    if 'download' in processors_data and len(scan_meta['processors']['download']['data']) > 0:
        meta_data = processors_data['download']['data'][0]
        sha256 = meta_data['sha256']
        filename = meta_data['filename']
        filesize = meta_data['filesize']
        filetype = meta_data['mimeType']
        human_readable['File']['Hash'] = sha256
        cont['File']['Hash'] = sha256
        file_context['SHA256'] = sha256
        human_readable['File']['Name'] = filename
        cont['File']['FileName'] = filename
        file_context['Name'] = filename
        human_readable['File']['Size'] = filesize
        cont['File']['FileSize'] = filesize
        file_context['Size'] = filesize
        human_readable['File']['Type'] = filetype
        cont['File']['FileType'] = filetype
        file_context['Type'] = filetype
        file_context['Hostname'] = demisto.args().get('url')

    ec = {
        'URLScan(val.URL && val.URL == obj.URL)': cont,
        'DBotScore': dbot_score,
        'URL': url_cont,
        outputPaths['file']: file_context
    }

    if 'screenshotURL' in scan_tasks:
        human_readable['Screenshot'] = scan_tasks['screenshotURL']
        screen_path = scan_tasks['screenshotURL']
        response_img = requests.request("GET", screen_path, verify=USE_SSL)
        stored_img = fileResult('screenshot.png', response_img.content)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response,
        'HumanReadable': tableToMarkdown('{} - Scan Results'.format(url_query), human_readable),
        'EntryContext': ec
    })

    if len(cert_md) > 0:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': tableToMarkdown('Certificates', cert_md, CERT_HEADERS),
            'HumanReadable': tableToMarkdown('Certificates', cert_md, CERT_HEADERS)
        })
    if 'ips' in scan_lists:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': tableToMarkdown('Related IPs and ASNs', ip_asn_MD, IP_HEADERS),
            'HumanReadable': tableToMarkdown('Related IPs and ASNs', ip_asn_MD, IP_HEADERS)
        })

    if 'screenshotURL' in scan_tasks:
        demisto.results({
            'Type': entryTypes['image'],
            'ContentsFormat': formats['text'],
            'File': stored_img['File'],
            'FileID': stored_img['FileID'],
            'Contents': ''
        })


def urlscan_submit_request(uuid):
    response = http_request('GET', 'result/{}'.format(uuid))
    return response


def get_urlscan_submit_results_polling(uuid):
    ready = polling(uuid)
    if ready is True:
        format_results(uuid)


def urlscan_submit_command():
    urls = argToList(demisto.args().get('url'))
    for url in urls:
        demisto.args()['url'] = url
        response = urlscan_submit_url()
        if response.get('url_is_blacklisted'):
            pass
        uuid = response.get('uuid')
        get_urlscan_submit_results_polling(uuid)


def urlscan_search(search_type, query):
    r = http_request('GET', 'search/?q=' + search_type + ':"' + query + '"')
    return r


def cert_format(x):
    valid_to = datetime.fromtimestamp(x['validTo']).strftime('%Y-%m-%d %H:%M:%S')
    valid_from = datetime.fromtimestamp(x['validFrom']).strftime('%Y-%m-%d %H:%M:%S')
    info = {
        'Subject Name': x['subjectName'],
        'Issuer': x['issuer'],
        'Validity': "{} - {}".format(valid_to, valid_from)
    }
    ec_info = {
        'SubjectName': x['subjectName'],
        'Issuer': x['issuer'],
        'ValidFrom': valid_from,
        'ValidTo': valid_to
    }
    return info, ec_info


def urlscan_search_command():
    LIMIT = int(demisto.args().get('limit'))
    HUMAN_READBALE_HEADERS = ['URL', 'Domain', 'IP', 'ASN', 'Scan ID', 'Scan Date']
    raw_query = demisto.args().get('searchParameter', '')
    if is_ip_valid(raw_query, accept_v6_ips=True):
        search_type = 'ip'
    else:
        # Parsing query to see if it's a url
        parsed = urlparse(raw_query)
        # Checks to see if Netloc is present. If it's not a url, Netloc will not exist
        if parsed[1] == '' and len(raw_query) == 64:
            search_type = 'hash'
        else:
            search_type = 'page.url'

    # Making the query string safe for Elastic Search
    query = quote(raw_query, safe='')

    r = urlscan_search(search_type, query)

    if r['total'] == 0:
        demisto.results('No results found for {}'.format(raw_query))
        return
    if r['total'] > 0:
        demisto.results('{} results found for {}'.format(r['total'], raw_query))

    # Opening empty string for url comparison
    last_url = ''
    hr_md = []
    cont_array = []
    ip_array = []
    dom_array = []
    url_array = []

    for res in r['results'][:LIMIT]:
        ec = makehash()
        cont = makehash()
        url_cont = makehash()
        ip_cont = makehash()
        dom_cont = makehash()
        file_context = makehash()
        res_dict = res
        res_tasks = res_dict['task']
        res_page = res_dict['page']

        if last_url == res_tasks['url']:
            continue

        human_readable = makehash()

        if 'url' in res_tasks:
            url = res_tasks['url']
            human_readable['URL'] = url
            cont['URL'] = url
            url_cont['Data'] = url
        if 'domain' in res_page:
            domain = res_page['domain']
            human_readable['Domain'] = domain
            cont['Domain'] = domain
            dom_cont['Name'] = domain
        if 'asn' in res_page:
            asn = res_page['asn']
            cont['ASN'] = asn
            ip_cont['ASN'] = asn
            human_readable['ASN'] = asn
        if 'ip' in res_page:
            ip = res_page['ip']
            cont['IP'] = ip
            ip_cont['Address'] = ip
            human_readable['IP'] = ip
        if '_id' in res_dict:
            scanID = res_dict['_id']
            cont['ScanID'] = scanID
            human_readable['Scan ID'] = scanID
        if 'time' in res_tasks:
            scanDate = res_tasks['time']
            cont['ScanDate'] = scanDate
            human_readable['Scan Date'] = scanDate
        if 'files' in res_dict:
            HUMAN_READBALE_HEADERS = ['URL', 'Domain', 'IP', 'ASN', 'Scan ID', 'Scan Date', 'File']
            files = res_dict['files'][0]
            sha256 = files['sha256']
            filename = files['filename']
            filesize = files['filesize']
            filetype = files['mimeType']
            url = res_tasks['url']
            human_readable['File']['Hash'] = sha256
            cont['Hash'] = sha256
            file_context['SHA256'] = sha256
            human_readable['File']['Name'] = filename
            cont['FileName'] = filename
            file_context['File']['Name'] = filename
            human_readable['File']['Size'] = filesize
            cont['FileSize'] = filesize
            file_context['Size'] = filesize
            human_readable['File']['Type'] = filetype
            cont['FileType'] = filetype
            file_context['File']['Type'] = filetype
            file_context['File']['Hostname'] = url

        ec[outputPaths['file']] = file_context
        hr_md.append(human_readable)
        cont_array.append(cont)
        ip_array.append(ip_cont)
        url_array.append(url_cont)
        dom_array.append(dom_cont)

        # Storing last url in memory for comparison on next loop
        last_url = url

    ec = ({
        'URLScan(val.URL && val.URL == obj.URL)': cont_array,
        'URL': url_array,
        'IP': ip_array,
        'Domain': dom_array
    })
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': r,
        'HumanReadable': tableToMarkdown('URLScan.io query results for {}'.format(raw_query), hr_md,
                                         HUMAN_READBALE_HEADERS, removeNull=True),
        'EntryContext': ec
    })


def format_http_transaction_list():
    url = demisto.args().get('url')
    uuid = demisto.args().get('uuid')

    # Scan Lists sometimes returns empty
    scan_lists = {}  # type: dict
    while not scan_lists:
        response = urlscan_submit_request(uuid)
        scan_lists = response.get('lists', {})

    limit = int(demisto.args().get('limit'))
    metadata = None
    if limit > 100:
        limit = 100
        metadata = "Limited the data to the first 100 http transactions"

    url_list = scan_lists.get('urls', [])[:limit]

    context = {
        'URL': url,
        'httpTransaction': url_list
    }

    ec = {
        'URLScan(val.URL && val.URL == obj.URL)': context,
    }

    human_readable = tableToMarkdown('{} - http transaction list'.format(url), url_list, ['URLs'], metadata=metadata)
    return_outputs(human_readable, ec, response)


"""COMMAND FUNCTIONS"""


def main():
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            search_type = 'ip'
            query = '8.8.8.8'
            urlscan_search(search_type, query)
            demisto.results('ok')
        if demisto.command() in {'urlscan-submit', 'url'}:
            urlscan_submit_command()
        if demisto.command() == 'urlscan-search':
            urlscan_search_command()
        if demisto.command() == 'urlscan-submit-url-command':
            demisto.results(urlscan_submit_url().get('uuid'))
        if demisto.command() == 'urlscan-get-http-transaction-list':
            format_http_transaction_list()
        if demisto.command() == 'urlscan-get-result-page':
            demisto.results(get_result_page())
        if demisto.command() == 'urlscan-poll-uri':
            poll_uri()

    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(e.message)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
