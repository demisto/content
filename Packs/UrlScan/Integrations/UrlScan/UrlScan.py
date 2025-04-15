from concurrent.futures import ThreadPoolExecutor
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''IMPORTS'''
import collections
import json as JSON
import time
from urllib.parse import urlparse

import requests
from requests.utils import quote  # type: ignore

""" POLLING FUNCTIONS"""
try:
    from Queue import Queue
except ImportError:
    from queue import Queue  # type: ignore

'''GLOBAL VARS'''
BLACKLISTED_URL_ERROR_MESSAGES = [
    'The submitted domain is on our blacklist. For your own safety we did not perform this scan...',
    'The submitted domain is on our blacklist, we will not scan it.'
]
BRAND = 'urlscan.io'
DEFAULT_LIMIT = 20
MAX_WORKERS = 5

""" RELATIONSHIP TYPE"""
RELATIONSHIP_TYPE = {
    'page': {
        'domain': {
            'indicator_type': FeedIndicatorType.Domain,
            'name': EntityRelationship.Relationships.HOSTED_ON,
            'detect_type': False
        },
        'ip': {
            'indicator_type': FeedIndicatorType.IP,
            'name': EntityRelationship.Relationships.HOSTED_ON,
            'detect_type': False
        }
    }
}


class Client:
    def __init__(self, api_key='', user_agent='', scan_visibility=None, threshold=None, use_ssl=False,
                 reliability=DBotScoreReliability.C, country=None):
        self.base_url = 'https://urlscan.io/'
        self.base_api_url = 'https://urlscan.io/api/v1/'
        self.api_key = api_key
        self.user_agent = user_agent
        self.threshold = threshold
        self.scan_visibility = scan_visibility
        self.use_ssl = use_ssl
        self.reliability = reliability
        self.country = country


'''HELPER FUNCTIONS'''


def detect_ip_type(indicator):
    """
    Helper function which detects wheather an IP is a IP or IPv6 by string
    """
    indicator_type = ''
    if '::' in indicator:
        indicator_type = FeedIndicatorType.IPv6
    else:
        indicator_type = FeedIndicatorType.IP
    return indicator_type


def schedule_polling(items_to_schedule, next_polling_interval):
    """
    Schedules a polling command for the items in the list.
    Args:
        items_to_schedule: List of items to schedule.
        next_polling_interval: The time in seconds for the scheduled command to re-run
    """
    # Prepare scheduled url entries
    args = demisto.args()
    polling_args = {}
    for arg in args:
        if arg != 'url':
            polling_args[arg] = args[arg]
    polling_args['url'] = items_to_schedule
    polling_args['polling'] = True
    scheduled_items = ScheduledCommand(
        command=demisto.command(),
        args=polling_args,
        items_remaining=len(items_to_schedule),
        next_run_in_seconds=next_polling_interval
    )
    return CommandResults(scheduled_command=scheduled_items)


def http_request(client, method, url_suffix, json=None, retries=0):
    headers = {'API-Key': client.api_key,
               'Accept': 'application/json'}
    if client.user_agent:
        headers['User-Agent'] = client.user_agent
    if method == 'POST':
        headers.update({'Content-Type': 'application/json'})
    demisto.debug(
        f'requesting https request with method: {method}, url: {client.base_api_url + url_suffix}, data: {json}')
    r = requests.request(
        method,
        client.base_api_url + url_suffix,
        data=json,
        headers=headers,
        verify=client.use_ssl
    )

    rate_limit_remaining = int(r.headers.get('X-Rate-Limit-Remaining', 99))
    rate_limit_reset_after = int(r.headers.get('X-Rate-Limit-Reset-After', 60))

    if rate_limit_remaining < 10:
        return_warning('Your available rate limit remaining is {} and is about to be exhausted. '
                       'The rate limit will reset at {}'.format(str(rate_limit_remaining),
                                                                r.headers.get("X-Rate-Limit-Reset")))
    if r.status_code != 200:
        if r.status_code == 429:
            return {}, ErrorTypes.QUOTA_ERROR, rate_limit_reset_after

        response_json = r.json()
        error_description = response_json.get('description') or response_json.get('message')
        should_continue_on_blacklisted_urls = argToBoolean(demisto.args().get('continue_on_blacklisted_urls', False))
        if should_continue_on_blacklisted_urls and error_description in BLACKLISTED_URL_ERROR_MESSAGES:
            response_json['url_is_blacklisted'] = True
            requested_url = JSON.loads(json)['url']
            blacklisted_message = f'The URL {requested_url} is blacklisted, no results will be returned for it.'
            demisto.results(blacklisted_message)
            return response_json, ErrorTypes.GENERAL_ERROR, None

        response_json['is_error'] = True
        response_json['error_string'] = 'Error in API call to URLScan.io [%d] - %s: %s' % (r.status_code, r.reason,
                                                                                           error_description)
        return response_json, ErrorTypes.GENERAL_ERROR, None
    return r.json(), None, None


# Allows nested keys to be accessible
def makehash():
    return collections.defaultdict(makehash)


def schedule_and_report(command_results, items_to_schedule, execution_metrics, rate_limit_reset_after):
    """
    Before the command is done running, or going to raise an error, we need to dump all the currently collected data
    Args:
        command_results: List of CommandResults objects
        items_to_schedule: List of urls to schedule
        execution_metrics: ExecutionMetrics object
        rate_limit_reset_after: The time in seconds for the scheduled command to re-run
    """
    if ScheduledCommand.supports_polling() and len(items_to_schedule) > 0:
        command_results.append(schedule_polling(items_to_schedule, rate_limit_reset_after))
    if execution_metrics.metrics is not None and execution_metrics.is_supported():
        command_results.append(execution_metrics.metrics)


def get_result_page(client):
    uuid = demisto.args().get('uuid')
    uri = client.base_api_url + f'result/{uuid}'
    return uri


def polling(client, uuid):
    TIMEOUT = int(demisto.args().get('timeout', 60))
    uri = client.base_api_url + f'result/{uuid}'

    headers = {'API-Key': client.api_key}
    if client.user_agent:
        headers['User-Agent'] = client.user_agent
    ready = poll(
        lambda: requests.get(uri, headers=headers, verify=client.use_ssl).status_code == 200,
        step=5,
        ignore_exceptions=(requests.exceptions.ConnectionError),
        timeout=int(TIMEOUT)
    )
    return ready


def poll_uri(client):
    uri = demisto.args().get('uri')
    demisto.results(requests.get(uri, verify=client.use_ssl).status_code)


def step_constant(step):
    return step


def is_truthy(val):
    return bool(val)


def poll(target, step, args=(), kwargs=None, timeout=60,
         check_success=is_truthy, step_function=step_constant,
         ignore_exceptions=(), collect_values=None, **k):
    kwargs = kwargs or {}
    values = collect_values or Queue()

    max_time = time.time() + timeout
    tries = 0
    # According to the doc - The most efficient approach would be to wait at least 10 seconds before starting to poll
    time.sleep(10)
    while True:
        demisto.debug(f'Number of Polling attempts: {tries}')
        try:
            val = target(*args, **kwargs)
            last_item = val
        except ignore_exceptions as e:
            last_item = e
            demisto.debug(f'Polling request failed with exception {str(e)}')
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


def urlscan_submit_url(client, url):
    submission_dict = {}
    if demisto.args().get('scan_visibility'):
        submission_dict['visibility'] = demisto.args().get('scan_visibility')
    elif client.scan_visibility:
        submission_dict['visibility'] = client.scan_visibility
    elif demisto.args().get('public'):
        if demisto.args().get('public') == 'public':
            submission_dict['visibility'] = 'public'
    elif demisto.params().get('is_public') is True:
        # this parameter is now hidden and it is default value is false.
        # Hence, we do not expect to be entering this code block,
        # and it is merely here for Backward Compatibility reasons.
        submission_dict['visibility'] = 'public'

    submission_dict['url'] = url

    if demisto.args().get('useragent'):
        submission_dict['customagent'] = demisto.args().get('useragent')
    elif demisto.params().get('useragent'):
        submission_dict['customagent'] = demisto.params().get('useragent')

    if client.country:
        submission_dict['country'] = client.country.split(' ')[0]

    sub_json = json.dumps(submission_dict)
    retries = int(demisto.args().get('retries', 0))
    r, metric, rate_limit_reset_after = http_request(client, 'POST', 'scan/', sub_json, retries)
    return r, metric, rate_limit_reset_after


def create_relationship(scan_type, field, entity_a, entity_a_type, entity_b, entity_b_type, reliability):
    """
    Create a single relation with the given arguments.
    """
    return EntityRelationship(name=RELATIONSHIP_TYPE.get(scan_type, {}).get(field, {}).get('name', ''),
                              entity_a=entity_a,
                              entity_a_type=entity_a_type,
                              entity_b=entity_b,
                              entity_b_type=entity_b_type,
                              source_reliability=reliability,
                              brand=BRAND)


def create_list_relationships(scans_dict, url, reliability):
    """
    Creates a list of EntityRelationships object from all of the lists in scans_dict according to RELATIONSHIP_TYPE dict.
    """
    relationships_list = []
    for scan_name, scan_dict in scans_dict.items():
        fields = RELATIONSHIP_TYPE.get(scan_name, {}).keys()
        for field in fields:
            indicators = scan_dict.get(field)
            if not isinstance(indicators, list):
                indicators = [indicators]
            relationship_dict = RELATIONSHIP_TYPE.get(scan_name, {}).get(field, {})
            indicator_type = relationship_dict.get('indicator_type', '')
            for indicator in indicators:
                # For a case where the destination side does not exist
                if not indicator:
                    pass
                # For a case where the type of the IP indicator should be detected, whether its IPv6/IP
                if not indicator_type and relationship_dict.get('detect_type'):
                    indicator_type = detect_ip_type(indicator)
                relationship = create_relationship(scan_type=scan_name, field=field, entity_a=url,
                                                   entity_a_type=FeedIndicatorType.URL, entity_b=indicator,
                                                   entity_b_type=indicator_type, reliability=reliability)
                relationships_list.append(relationship)
    return relationships_list


def format_results(client, uuid, use_url_as_name, scan_lists_attempts=True):
    # Scan Lists sometimes returns empty
    num_of_attempts = 0
    relationships = []
    response, _, _ = urlscan_submit_request(client, uuid)
    scan_lists = response.get('lists')
    while scan_lists is None and scan_lists_attempts:
        try:
            num_of_attempts += 1
            demisto.debug(f'Attempting to get scan lists {num_of_attempts} times')
            response, _, _ = urlscan_submit_request(client, uuid)
            scan_lists = response.get('lists')
        except Exception:
            if num_of_attempts == 5:
                break
            demisto.debug('Could not get scan lists, sleeping for 5 minutes before trying again')
            time.sleep(5)
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

    feed_related_indicators = []

    cont['ResultPage'] = client.base_url + f'result/{uuid}'

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
    else:
        CERT_HEADERS = []
        demisto.debug(f"certificates isn't in {scan_lists=}. {CERT_HEADERS=}")
    url_cont['Data'] = url_query
    if 'urls' in scan_lists:
        url_cont['Data'] = demisto.args().get('url')
        cont['URL'] = demisto.args().get('url')
        if isinstance(scan_lists.get('urls'), list):
            for url in scan_lists['urls']:
                feed_related_indicators.append({'value': url, 'type': 'URL'})
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
        if isinstance(scan_lists.get('ips'), list):
            for ip in scan_lists.get('ips'):
                feed_related_indicators.append({'value': ip, 'type': 'IP'})
        IP_HEADERS = ['Count', 'IP', 'ASN']
    if 'links' in scan_data:
        links = []
        for o in scan_data['links']:
            if 'href' in o:
                links.append(o['href'])
        cont['links'] = links
    # add redirected URLs
    if 'requests' in scan_data:
        redirected_urls = []
        for o in scan_data['requests']:
            if 'redirectResponse' in o['request'] and 'url' in o['request']['redirectResponse']:
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
        for hashe in hashes:
            feed_related_indicators.append({'value': hashe, 'type': 'File'})
    if 'domains' in scan_lists:
        subdomains = scan_lists.get('domains', [])
        cont['Subdomains'] = subdomains
        human_readable['Subdomains'] = subdomains
        for domain in subdomains:
            feed_related_indicators.append({'value': domain, 'type': 'Domain'})
    if 'linkDomains' in scan_lists:
        link_domains = scan_lists.get('domains', [])
        for domain in link_domains:
            feed_related_indicators.append({'value': domain, 'type': 'Domain'})
    if 'asn' in scan_page:
        cont['ASN'] = scan_page['asn']
        url_cont['ASN'] = scan_page.get('asn')
    if 'asnname' in scan_page:
        url_cont['ASOwner'] = scan_page['asnname']
    if 'country' in scan_page:
        url_cont['Geo']['Country'] = scan_page['country']
    if 'domain' in scan_page:
        feed_related_indicators.append({'value': scan_page['domain'], 'type': 'Domain'})
    if 'ip' in scan_page:
        feed_related_indicators.append({'value': scan_page['ip'], 'type': 'IP'})
    if 'url' in scan_page:
        feed_related_indicators.append({'value': scan_page['url'], 'type': 'URL'})
    if 'overall' in scan_verdicts:
        human_readable['Malicious URLs Found'] = scan_stats['malicious']
        if scan_verdicts['overall'].get('malicious'):
            human_readable['Verdict'] = 'Malicious'
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
            human_readable['Verdict'] = 'Unknown'
        dbot_score['Reliability'] = client.reliability
    if 'urlscan' in scan_verdicts and 'tags' in scan_verdicts['urlscan']:
        url_cont['Tags'] = scan_verdicts['urlscan']['tags']
    processors_data = scan_meta['processors']
    if 'download' in processors_data and len(scan_meta['processors']['download']['data']) > 0:
        meta_data = processors_data['download']['data'][0]
        sha256 = meta_data.get('sha256')
        filename = meta_data.get('filename')
        filesize = meta_data.get('filesize')
        filetype = meta_data.get('mimeType')
        if sha256:
            human_readable['File']['Hash'] = sha256
            cont['File']['Hash'] = sha256
            file_context['SHA256'] = sha256
        if filename:
            human_readable['File']['Name'] = filename
            cont['File']['FileName'] = filename
            file_context['Name'] = filename
        if filesize:
            human_readable['File']['Size'] = filesize
            cont['File']['FileSize'] = filesize
            file_context['Size'] = filesize
        if filetype:
            human_readable['File']['Type'] = filetype
            cont['File']['FileType'] = filetype
            file_context['Type'] = filetype
        file_context['Hostname'] = demisto.args().get('url')
    if feed_related_indicators:
        related_indicators = []
        for related_indicator in feed_related_indicators:
            related_indicators.append(Common.FeedRelatedIndicators(value=related_indicator['value'],
                                                                   indicator_type=related_indicator['type']))
        url_cont['FeedRelatedIndicators'] = related_indicators
    if demisto.params().get('create_relationships') is True:
        relationships = create_list_relationships({'page': scan_page}, url_query,
                                                  client.reliability)
    outputs = {
        'URLScan(val.URL && val.URL == obj.URL)': cont,
        outputPaths['file']: file_context
    }

    if 'screenshotURL' in scan_tasks:
        human_readable['Screenshot'] = scan_tasks['screenshotURL']
        screen_path = scan_tasks['screenshotURL']
        response_img = requests.request("GET", screen_path, verify=client.use_ssl)
        if use_url_as_name:
            screenshot_name = cont['EffectiveURL'].replace('http://', '').replace('https://', '').replace('/', '_')
        else:
            screenshot_name = 'screenshot'
        stored_img = fileResult(f'{screenshot_name}.png', response_img.content)

    dbot_score = Common.DBotScore(indicator=dbot_score.get('Indicator'), indicator_type=dbot_score.get('Type'),
                                  integration_name=BRAND, score=dbot_score.get('Score'),
                                  reliability=dbot_score.get('Reliability'))

    url = Common.URL(url=url_cont.get('Data'), dbot_score=dbot_score, relationships=relationships,
                     feed_related_indicators=url_cont.get('FeedRelatedIndicators'))

    command_result = CommandResults(
        readable_output=tableToMarkdown(f'{url_query} - Scan Results', human_readable),
        outputs=outputs,
        indicator=url,
        raw_response=response,
        relationships=relationships
    )

    demisto.results(command_result.to_context())

    if len(cert_md) > 0:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': tableToMarkdown('Certificates', cert_md, CERT_HEADERS),
            'HumanReadable': tableToMarkdown('Certificates', cert_md, CERT_HEADERS)
        })
    if 'ips' in scan_lists:
        if isinstance(scan_lists.get('ips'), list):
            feed_related_indicators += scan_lists.get('ips')
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


def urlscan_submit_request(client, uuid):
    response, metrics, _ = http_request(client, 'GET', f'result/{uuid}')
    return response, metrics, _


def get_urlscan_submit_results_polling(client, uuid, use_url_as_name):
    ready = polling(client, uuid)
    if ready is True:
        format_results(client, uuid, use_url_as_name)


def urlscan_submit_command(client):
    execution_metrics = ExecutionMetrics()
    command_results: list = []
    items_to_schedule: list = []
    rate_limit_reset_after: int = 60

    urls = argToList(demisto.args().get('url'))
    if is_time_sensitive():
        args = ((client, url, command_results, execution_metrics) for url in urls)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(lambda p: urlscan_search_only(*p), args)
    else:
        for url in urls:
            demisto.args()['url'] = url
            response, metrics, rate_limit_reset_after = urlscan_submit_url(client, url)
            if response.get('url_is_blacklisted') or response.get('is_error'):
                execution_metrics.general_error += 1
                if response.get('is_error'):
                    schedule_and_report(command_results=command_results, items_to_schedule=items_to_schedule,
                                        execution_metrics=execution_metrics, rate_limit_reset_after=rate_limit_reset_after)
                    return_results(results=command_results)
                    return_error(response.get('error_string'))
                continue
            if metrics == ErrorTypes.QUOTA_ERROR:
                if not is_scheduled_command_retry():
                    execution_metrics.quota_error += 1
                items_to_schedule.append(url)
                continue
            uuid = response.get('uuid')
            use_url_as_name = demisto.args()['use_url_as_name'] == 'true'
            get_urlscan_submit_results_polling(client, uuid, use_url_as_name)
            execution_metrics.success += 1
    schedule_and_report(command_results=command_results, items_to_schedule=items_to_schedule,
                        execution_metrics=execution_metrics, rate_limit_reset_after=rate_limit_reset_after)
    return command_results


def urlscan_search_only(client: Client, url: str, command_results: list, execution_metrics: ExecutionMetrics):
    demisto.args()["url"] = url
    response = urlscan_search(client, "page.url", quote(url, safe=""), size=1000)
    if response.get("is_error"):
        execution_metrics.general_error += 1
        error_message = f"The search for the url '{url}' returned an error:\n{response.get('error_string', '')}"
        command_results.append(
            CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=error_message,
                raw_response=error_message,
            )
        )
        return

    found_result = False
    for result in response.get("results", []):
        page = result.get("page", {})
        if page.get("url").rstrip("/") == url.rstrip("/"):
            format_results(
                client,
                result["task"]["uuid"],
                use_url_as_name=False,
                scan_lists_attempts=False,
            )
            execution_metrics.success += 1
            found_result = True
            break
    if not found_result:
        no_results_message = f"No results found for {url}"
        demisto.debug(no_results_message)
        command_results.append(
            CommandResults(
                readable_output=no_results_message, raw_response=no_results_message
            )
        )
    return


def urlscan_search(client, search_type, query, size=None):

    if search_type == 'advanced':
        r, _, _ = http_request(client, 'GET', 'search/?q=' + query)
    else:
        url_suffix = 'search/?q=' + search_type + ':"' + query + '"' + (f'&size={size}' if size else '')
        r, _, _ = http_request(client, 'GET', url_suffix)

    return r


def cert_format(x):
    valid_to = datetime.fromtimestamp(x['validTo']).strftime('%Y-%m-%d %H:%M:%S')
    valid_from = datetime.fromtimestamp(x['validFrom']).strftime('%Y-%m-%d %H:%M:%S')
    info = {
        'Subject Name': x['subjectName'],
        'Issuer': x['issuer'],
        'Validity': f"{valid_to} - {valid_from}"
    }
    ec_info = {
        'SubjectName': x['subjectName'],
        'Issuer': x['issuer'],
        'ValidFrom': valid_from,
        'ValidTo': valid_to
    }
    return info, ec_info


def urlscan_search_command(client):
    LIMIT = int(demisto.args().get('limit', DEFAULT_LIMIT))
    HUMAN_READBALE_HEADERS = ['URL', 'Domain', 'IP', 'ASN', 'Scan ID', 'Scan Date']
    raw_query = demisto.args().get('searchParameter', '')
    search_type = demisto.args().get('searchType', '')
    if not search_type:
        if is_ip_valid(raw_query, accept_v6_ips=True):
            search_type = 'ip'
        else:
            # Parsing query to see if it's a url
            parsed = urlparse(raw_query)
            # Checks to see if Netloc is present. If it's not a url, Netloc will not exist
            if parsed.netloc == '' and len(raw_query) == 64:
                search_type = 'hash'
            else:
                search_type = 'page.url'

    # Making the query string safe for Elastic Search
    query = quote(raw_query, safe='')

    r = urlscan_search(client, search_type, query)

    if r['total'] == 0:
        demisto.results(f'No results found for {raw_query}')
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
            sha256 = files.get('sha256')
            filename = files.get('filename')
            filesize = files.get('filesize')
            filetype = files.get('mimeType')
            url = res_tasks['url']
            if sha256:
                human_readable['File']['Hash'] = sha256
                cont['Hash'] = sha256
                file_context['SHA256'] = sha256
            if filename:
                human_readable['File']['Name'] = filename
                cont['FileName'] = filename
                file_context['File']['Name'] = filename
            if filesize:
                human_readable['File']['Size'] = filesize
                cont['FileSize'] = filesize
                file_context['Size'] = filesize
            if filetype:
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
        'HumanReadable': tableToMarkdown(f'URLScan.io query results for {raw_query}', hr_md,
                                         HUMAN_READBALE_HEADERS, removeNull=True),
        'EntryContext': ec
    })


def format_http_transaction_list(client):
    url = demisto.args().get('url')
    uuid = demisto.args().get('uuid')

    # Scan Lists sometimes returns empty
    scan_lists = {}  # type: dict
    while not scan_lists:
        response, _, _ = urlscan_submit_request(client, uuid)
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

    human_readable = tableToMarkdown(f'{url} - http transaction list', url_list, ['URLs'], metadata=metadata)
    return_outputs(human_readable, ec, response)


"""COMMAND FUNCTIONS"""


def main():
    params = demisto.params()

    api_key = params.get('apikey') or (params.get('creds_apikey') or {}).get('password', '')
    # to safeguard the visibility of the scan,
    # if the customer did not choose a visibility, we will set it to private by default.
    scan_visibility = params.get('scan_visibility', 'private')
    threshold = int(params.get('url_threshold', '1'))
    use_ssl = not params.get('insecure', False)
    reliability = params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.C
    country = params.get('country', '')

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")

    demisto_version = get_demisto_version_as_str()
    instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')
    client = Client(
        api_key=api_key,
        user_agent=f'xsoar-{demisto_version}/urlscan-{instance_name}',
        scan_visibility=scan_visibility,
        threshold=threshold,
        use_ssl=use_ssl,
        reliability=reliability,
        country=country
    )

    demisto.debug(f'Command being called is {demisto.command()}')
    demisto.debug(f'Is time sensitive: {is_time_sensitive()}')

    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            search_type = 'ip'
            query = '8.8.8.8'
            urlscan_search(client, search_type, query)
            demisto.results('ok')
        if demisto.command() in {'urlscan-submit', 'url'}:
            results = urlscan_submit_command(client)
            return_results(results=results)
        if demisto.command() == 'urlscan-search':
            urlscan_search_command(client)
        if demisto.command() == 'urlscan-submit-url-command':
            url = demisto.args().get('url')
            result, _, _ = urlscan_submit_url(client, url)
            demisto.results(result.get('uuid'))
        if demisto.command() == 'urlscan-get-http-transaction-list':
            format_http_transaction_list(client)
        if demisto.command() == 'urlscan-get-result-page':
            demisto.results(get_result_page(client))
        if demisto.command() == 'urlscan-poll-uri':
            poll_uri(client)

    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
