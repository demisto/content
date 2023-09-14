import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import collections
import time

import requests

import trustar

''' IMPORTS '''

handle_proxy()

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server']
API_KEY = str(demisto.params()['key'])
API_SECRET = str(demisto.params()['secret'])
BASE_URL = SERVER + '/api/1.3'
INSECURE = demisto.params()['insecure']

''' HELPER FUNCTIONS '''


def translate_indicators(ts_indicators, context_path=''):
    if context_path and context_path[-1] != '.':
        context_path += '.'
    indicators = []
    file_context = []
    url_context = []
    ip_context = []
    email_context = []
    key_context = []
    cve_context = []
    for indicator in ts_indicators:
        current_indicator = indicator if isinstance(indicator, dict) else indicator.to_dict(remove_nones=True)
        indicator_type = current_indicator['indicatorType']
        value = current_indicator['value']
        if indicator_type == 'SOFTWARE':
            # Extracts the filename out of file path
            if "\\" in r"%r" % value:
                file_name = value.split('\\')[-1]  # Handles file path with backslash
            else:
                file_name = value.split('/')[-1]  # Handles file path with slash
            current_indicator['value'] = file_name
            context_dict = {'Name': file_name}
            file_context.append(context_dict)
        elif indicator_type in {'SHA256', 'SHA1', 'MD5'}:
            context_dict = {indicator_type: value}
            file_context.append(context_dict)
        elif indicator_type == 'URL':
            context_dict = {'Address': value}
            url_context.append(context_dict)
        elif indicator_type == 'IP':
            context_dict = {'Address': value}
            ip_context.append(context_dict)
        elif indicator_type == 'EMAIL_ADDRESS':
            context_dict = {'Address': value}
            email_context.append(context_dict)
        elif indicator_type == 'REGISTRY_KEY':
            context_dict = {'Path': value}
            key_context.append(context_dict)
        elif indicator_type == 'CVE':
            context_dict = {'ID': value}
            cve_context.append(context_dict)
        indicators.append(current_indicator)
    # Build Entry Context
    ec = {}
    if file_context:
        ec['{}File(val.Name && val.Name === obj.Name)'.format(context_path)] = file_context
    if url_context:
        ec['{}URL(val.Address && val.Address === obj.Address)'.format(context_path)] = url_context
    if ip_context:
        ec['{}IP(val.Address && val.Address === obj.Address)'.format(context_path)] = ip_context
    if email_context:
        ec['{}Account.Email(val.Address && val.Address === obj.Address)'.format(context_path)] = email_context
    if key_context:
        ec['{}RegistryKey(val.Path && val.Path === obj.Path)'.format(context_path)] = key_context
    if cve_context:
        ec['{}CVE(val.ID && val.ID === obj.ID)'.format(context_path)] = cve_context
    return indicators, ec


def translate_triage_submission(submissions):
    submission_dicts = [s.to_dict(remove_nones=True) for s in submissions]
    ec = {'TruSTAR.PhishingSubmission(val.submissionId == obj.submissionId)': submission_dicts}
    return submission_dicts, ec


def translate_phishing_indicators(indicators):
    indicator_dicts = [i.to_dict(remove_nones=True) for i in indicators]
    ec = {'TruSTAR.PhishingIndicator(val.value == obj.value)': indicator_dicts}
    return indicator_dicts, ec


def translate_specific_indicators(ts_indicators, specific_types):
    res = []
    for indicator in ts_indicators:
        current_indicator = indicator.to_dict(remove_nones=True)
        indicator_type = current_indicator['indicatorType']
        value = current_indicator['value']
        whitelisted = current_indicator.get('whitelisted')
        if indicator_type in specific_types:
            res.append({
                'value': value,
                'whitelisted': whitelisted,
                'indicatorType': indicator_type
            })
    return res


def priority_level_to_score(priority_level):
    if priority_level == 'LOW':
        return 1
    elif priority_level == 'MEDIUM':
        return 2
    elif priority_level == 'HIGH':
        return 3
    return 0


def normalize_time(timestamp):
    '''
    Converts unix epoch time to GMT
    '''
    if isinstance(timestamp, str):
        return timestamp
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp / 1000.0))


def date_to_unix(timestamp):
    d = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return int(d.strftime("%s")) * 1000


def create_file_ec(indicators, file, threshold):
    '''DEPRECATED this function relies on priorityLevel score which TruSTAR no longer supports.
    This function will be removed in a future release
    '''
    if not indicators:
        return {
            'DBotScore': {
                'Indicator': file,
                'Type': 'file',
                'Score': 0,
                'Vendor': 'TruSTAR',
            }
        }
    trustar_ec = {}
    file_ec = {}
    dbot_ec = {}
    for indicator in indicators:
        file_ec.update({
            indicator['indicatorType']: indicator['value'],
        })
        trustar_ec.update({
            'Value': indicator['value'],
            'Whitelisted': indicator['whitelisted'],
            'Priority': indicator['priorityLevel']
        })
        indicator_score = priority_level_to_score(indicator['priorityLevel'])
        dbot_ec.update({
            'Indicator': file,
            'Type': 'file',
            'Vendor': 'TruSTAR',
            'Score': 0 if indicator_score == 0 else (2 if threshold > indicator_score else 3)
        })
        if threshold <= indicator_score:
            file_ec.update({
                'Malicious': {
                    'Vendor': 'TruSTAR',
                    'Description': 'Priority level above {0}'.format(indicator['priorityLevel'])
                }
            })
    return {
        outputPaths['dbotscore']: dbot_ec,
        outputPaths['file']: file_ec,
        'TruSTAR.File(val.Value === obj.Value)': trustar_ec
    }


def create_ip_ec(indicators, ip, threshold):
    '''DEPRECATED this function relies on priorityLevel score which TruSTAR no longer supports.
    This function will be removed in a future release
    '''
    if not indicators:
        return {
            'DBotScore': {
                'Indicator': ip,
                'Type': 'ip',
                'Score': 0,
                'Vendor': 'TruSTAR',
            }
        }
    trustar_ec = {}
    ip_ec = {}
    dbot_ec = {}
    for indicator in indicators:
        ip_ec.update({
            'Address': indicator['value'],
        })
        trustar_ec.update({
            'Value': indicator['value'],
            'Whitelisted': indicator['whitelisted'],
            'Priority': indicator['priorityLevel']
        })
        indicator_score = priority_level_to_score(indicator['priorityLevel'])
        dbot_ec.update({
            'Indicator': ip,
            'Type': 'ip',
            'Vendor': 'TruSTAR',
            'Score': 0 if indicator_score == 0 else (2 if threshold > indicator_score else 3)
        })
        if threshold <= indicator_score:
            ip_ec.update({
                'Malicious': {
                    'Vendor': 'TruSTAR',
                    'Description': 'Priority level above {0}'.format(indicator['priorityLevel'])
                }
            })
    return {
        outputPaths['dbotscore']: dbot_ec,
        outputPaths['ip']: ip_ec,
        'TruSTAR.IP(val.Value === obj.Value)': trustar_ec
    }


def create_url_ec(indicators, url, threshold):
    '''DEPRECATED this function relies on priorityLevel score which TruSTAR no longer supports.
    This function will be removed in a future release
    '''
    if not indicators:
        return {
            'DBotScore': {
                'Indicator': url,
                'Type': 'url',
                'Score': 0,
                'Vendor': 'TruSTAR',
            }
        }
    trustar_ec = {}
    url_ec = {}
    dbot_ec = {}
    for indicator in indicators:
        url_ec.update({
            'Data': indicator['value'],
        })
        trustar_ec.update({
            'Value': indicator['value'],
            'Whitelisted': indicator['whitelisted'],
            'Priority': indicator['priorityLevel']
        })
        indicator_score = priority_level_to_score(indicator['priorityLevel'])
        dbot_ec.update({
            'Indicator': url,
            'Type': 'url',
            'Vendor': 'TruSTAR',
            'Score': 0 if indicator_score == 0 else (2 if threshold > indicator_score else 3)
        })
        if threshold <= indicator_score:
            url_ec.update({
                'Malicious': {
                    'Vendor': 'TruSTAR',
                    'Description': 'Priority level above {0}'.format(indicator['priorityLevel'])
                }
            })
    return {
        outputPaths['dbotscore']: dbot_ec,
        outputPaths['url']: url_ec,
        'TruSTAR.URL(val.Value === obj.Value)': trustar_ec
    }


def create_domain_ec(indicators, url, threshold):
    '''DEPRECATED this function relies on priorityLevel score which TruSTAR no longer supports.
    This function will be removed in a future release
    '''
    if not indicators:
        return {
            'DBotScore': {
                'Indicator': url,
                'Type': 'domain',
                'Score': 0,
                'Vendor': 'TruSTAR',
            }
        }
    trustar_ec = {}
    domain_ec = {}
    dbot_ec = {}
    for indicator in indicators:
        domain_ec.update({
            'Name': indicator['value'],
        })
        trustar_ec.update({
            'Value': indicator['value'],
            'Whitelisted': indicator['whitelisted'],
            'Priority': indicator['priorityLevel']
        })
        indicator_score = priority_level_to_score(indicator['priorityLevel'])
        dbot_ec.update({
            'Indicator': url,
            'Type': 'domain',
            'Vendor': 'TruSTAR',
            'Score': 0 if indicator_score == 0 else (2 if threshold > indicator_score else 3)
        })
        if threshold <= indicator_score:
            domain_ec.update({
                'Malicious': {
                    'Vendor': 'TruSTAR',
                    'Description': 'Priority level above {0}'.format(indicator['priorityLevel'])
                }
            })
    return {
        outputPaths['dbotscore']: dbot_ec,
        outputPaths['domain']: domain_ec,
        'TruSTAR.Domain(val.Value === obj.Value)': trustar_ec
    }


def encode_cursor(page_size, page_number):
    cursor = '{' + '"pageSize":{},"pageNumber":{}'.format(page_size, page_number) + '}'
    return base64.b64encode(cursor.encode()).decode()


''' FUNCTIONS '''


def get_related_indicators(indicators, enclave_ids, page_size, page_number):
    # To display priority score
    items_list = []
    related_indicator_response = ts.get_related_indicators_page(indicators, enclave_ids, page_size, page_number)
    for related_indicator in related_indicator_response:
        current_indicator = related_indicator.to_dict(remove_nones=True)
        search_indicator_response = ts.search_indicators_page(current_indicator['value'], enclave_ids, page_size,
                                                              page_number)
        for found_indicator in search_indicator_response:
            current_found_indicator = found_indicator.to_dict(remove_nones=True)
            if current_indicator['value'] == current_found_indicator['value']:
                break
        items_list.append(current_indicator)
    related_indicators, ec = translate_indicators(items_list)
    if related_indicators:
        title = 'TruSTAR indicators related to ' + indicators
        entry = {
            'Type': entryTypes['note'],
            'Contents': related_indicators,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, related_indicators),
            'EntryContext': ec
        }
    else:
        entry = 'No indicators related to ' + indicators + ' were found.'
    return entry


def get_trending_indicators(indicator_type, days_back):
    if indicator_type == 'other':
        indicator_type = None
    response = ts.get_community_trends(indicator_type, days_back)
    trending_indicators, ec = translate_indicators(response)
    if trending_indicators:
        title = 'TruSTAR Community Trending Indicators'
        entry = {
            'Type': entryTypes['note'],
            'Contents': trending_indicators,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, trending_indicators),
            'EntryContext': ec
        }
        return entry
    return 'No trending indicators were found.'


def search_indicators(search_term, enclave_ids, page_size, page_number):
    response = ts.search_indicators_page(search_term, enclave_ids, page_size, page_number)
    indicators, ec = translate_indicators(response)
    if indicators:
        title = 'TruSTAR indicators that contain the term ' + search_term
        entry = {
            'Type': entryTypes['note'],
            'Contents': indicators,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, indicators),
            'EntryContext': ec
        }
        return entry
    return 'No indicators were found.'


def generic_search_indicator(search_term, threshold, search_type, ec_function):
    if demisto.args().get('threshold'):
        threshold = demisto.args().get('threshold')
    response = ts.search_indicators_page(search_term=search_term)
    indicators = translate_specific_indicators(response, search_type)
    threshold = priority_level_to_score(threshold)
    title = 'TruSTAR results for {0} indicator: {1}'.format(search_type[0], search_term)
    ec = ec_function(indicators, search_term, threshold)
    entry = {
        'Type': entryTypes['note'],
        'Contents': indicators,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, indicators),
        'EntryContext': ec
    }
    return entry


def submit_report(title, report_body, enclave_ids, external_url, time_began, distribution_type):
    if distribution_type == 'ENCLAVE' and enclave_ids is None:
        return 'Distribution type is ENCLAVE, but no enclave ID was given.'
    ts_report = trustar.models.Report(
        title=title,
        body=report_body,
        enclave_ids=[enclave_ids] if enclave_ids else enclave_ids,
        is_enclave=True if distribution_type == 'ENCLAVE' else False,
        time_began=time_began,
        external_url=external_url
    )
    response = ts.submit_report(ts_report)
    deep_link = '{server_url}/constellation/reports/{report_id}'.format(server_url=SERVER, report_id=response.id)
    report = collections.OrderedDict()  # type: OrderedDict
    report['id'] = response.id
    report['reportTitle'] = title
    report['reportDeepLink'] = '[{}]({})'.format(deep_link, deep_link)
    report['reportBody'] = report_body
    ec = {
        'TruSTAR.Report(val.id && val.id === obj.id)': report
    }
    title = 'TruSTAR report was successfully created'
    entry = {
        'Type': entryTypes['note'],
        'Contents': report,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, report),
        'EntryContext': ec
    }
    return entry


def update_report(report_id, title, report_body, enclave_ids, external_url, time_began, distribution_type):
    ts_report = trustar.models.Report(
        id=report_id,
        title=title,
        body=report_body,
        enclave_ids=[enclave_ids] if enclave_ids else enclave_ids,
        is_enclave=True if distribution_type == 'ENCLAVE' else False,
        time_began=time_began,
        external_url=external_url
    )
    ts.update_report(ts_report)
    deep_link = '{server_url}/constellation/reports/{report_id}'.format(server_url=SERVER, report_id=report_id)
    report = collections.OrderedDict()  # type: OrderedDict
    report['id'] = report_id
    report['reportTitle'] = title
    report['reportDeepLink'] = '[{}]({})'.format(deep_link, deep_link)
    report['reportBody'] = report_body
    ec = {
        'TruSTAR.Report(val.id && val.id === obj.id)': report
    }
    title = 'TruSTAR report was successfully updated'
    entry = {
        'Type': entryTypes['note'],
        'Contents': report,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, report),
        'EntryContext': ec
    }
    return entry


def get_report_details(report_id, id_type):
    response = ts.get_report_details(report_id, id_type)
    current_report_dict = response.to_dict(remove_nones=True)
    report_details = collections.OrderedDict()  # type: OrderedDict
    report_details['id'] = current_report_dict['id']
    report_details['title'] = current_report_dict['title']
    deep_link = '{server_url}/constellation/reports/{report_id}'.format(server_url=SERVER,
                                                                        report_id=current_report_dict['id'])
    report_details['reportDeepLink'] = '[{}]({})'.format(deep_link, deep_link)
    if current_report_dict['enclaveIds']:
        report_details['enclaveIds'] = ', '.join(current_report_dict['enclaveIds'])  # Prettify list of enclave IDs
    report_details['updated'] = normalize_time(current_report_dict['updated'])
    report_details['created'] = normalize_time(current_report_dict['created'])
    report_details['timeBegan'] = normalize_time(current_report_dict['timeBegan'])
    report_details['distributionType'] = current_report_dict['distributionType']
    if current_report_dict.get('externalUrl'):
        report_details['externalUrl'] = current_report_dict['externalUrl']
    report_details['reportBody'] = current_report_dict['reportBody']
    report_context = {
        'reportTitle': report_details['title'],
        'reportBody': report_details['reportBody'],
        'id': report_details['id']
    }
    ec = {
        'TruSTAR.Report(val.id && val.id === obj.id)': report_context
    }
    title = 'TruSTAR report ID ' + report_id + ' details'
    entry = {
        'Type': entryTypes['note'],
        'Contents': report_details,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, report_details),
        'EntryContext': ec
    }
    return entry


def delete_report(report_id, id_type):
    ts.delete_report(report_id, id_type)
    return 'Report ' + report_id + ' was successfully deleted'


def get_reports(from_time, to_time, enclave_ids, distribution_type, tags, excluded_tags):
    is_encalve = True if distribution_type == 'ENCLAVE' else False
    from_time = date_to_unix(from_time) if from_time else from_time
    to_time = date_to_unix(to_time) if to_time else to_time
    response = ts.get_reports(is_encalve, enclave_ids, tags, excluded_tags, from_time, to_time)
    reports = []
    reports_context = []
    for report in response:
        current_report_dict = report.to_dict(remove_nones=True)
        current_report = collections.OrderedDict()  # type: OrderedDict
        current_report['id'] = current_report_dict['id']
        current_report['title'] = current_report_dict['title']
        deep_link = '{server_url}/constellation/reports/{report_id}'.format(
            server_url=SERVER, report_id=current_report_dict['id'])
        current_report['reportDeepLink'] = '[{}]({})'.format(deep_link, deep_link)
        if current_report_dict['enclaveIds']:
            current_report['enclaveIds'] = ', '.join(current_report_dict['enclaveIds'])  # Prettify list of enclave IDs
        current_report['updated'] = normalize_time(current_report_dict['updated'])
        current_report['created'] = normalize_time(current_report_dict['created'])
        current_report['timeBegan'] = normalize_time(current_report_dict['timeBegan'])
        current_report['distributionType'] = current_report_dict['distributionType']
        if current_report_dict.get('externalUrl'):
            current_report['externalUrl'] = current_report_dict['externalUrl']
        current_report['reportBody'] = current_report_dict['reportBody']
        reports.append(current_report)
        reports_context.append({
            'reportTitle': current_report['title'],
            'reportBody': current_report['reportBody'],
            'id': current_report['id']
        })
    if reports:
        ec = {
            'TruSTAR.Report(val.id && val.id === obj.id)': reports_context
        }
        title = 'TruSTAR reports'
        entry = {
            'Type': entryTypes['note'],
            'Contents': reports,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, reports),
            'EntryContext': ec
        }
        return entry
    return 'No reports were found.'


def get_correlated_reports(indicators, enclave_ids, distribution_type, page_size, page_number):
    response = ts.get_correlated_reports_page(indicators, enclave_ids, page_number, page_size)
    correlated_reports = []
    for report in response:
        current_report = report.to_dict(remove_nones=True)
        current_report['updated'] = normalize_time(current_report['updated'])
        current_report['created'] = normalize_time(current_report['created'])
        current_report['timeBegan'] = normalize_time(current_report['timeBegan'])
        correlated_reports.append(current_report)
    if correlated_reports:
        title = 'TruSTAR correlated reports'
        entry = {
            'Type': entryTypes['note'],
            'Contents': correlated_reports,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, correlated_reports)
        }
        return entry
    return 'No reports were found.'


def search_reports(search_term, enclave_ids):
    response = ts.search_reports(search_term, enclave_ids)
    reports = []
    report_context = []
    for i, report in enumerate(response):
        current_report = report.to_dict(remove_nones=True)
        current_report['updated'] = normalize_time(current_report['updated'])
        current_report['created'] = normalize_time(current_report['created'])
        current_report['timeBegan'] = normalize_time(current_report['timeBegan'])
        reports.append(current_report)
        report_context.append({
            'reportTitle': current_report['title'],
            'id': current_report['id']
        })
        if 'reportBody' in current_report:
            report_context[i]['reportBody'] = current_report['reportBody']

    ec = {
        'TruSTAR.Report(val.id && val.id === obj.id)': report_context
    }

    title = 'TruSTAR reports that contain the term ' + search_term
    entry = {
        'Type': entryTypes['note'],
        'Contents': reports,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, reports),
        'EntryContext': ec
    }
    return entry


def add_to_whitelist(indicators):
    response = ts.add_terms_to_whitelist([indicators])
    if response:
        return 'Added to the whitelist successfully'
    else:
        return 'Indicator could not be added to the whitelist.'


def remove_from_whitelist(indicator, indicator_type):
    ts_indicator = trustar.models.Indicator(
        value=indicator,
        type=indicator_type
    )
    try:
        ts.delete_indicator_from_whitelist(ts_indicator)
        return 'Removed from the whitelist successfully'
    except Exception:
        return 'Indicator could not be removed from the whitelist.'


def get_enclaves():
    response = ts.get_user_enclaves()
    enclave_ids = []
    for enclave in response:
        enclave_ids.append(enclave.to_dict(remove_nones=True))
    title = 'TruSTAR Enclaves'
    entry = {
        'Type': entryTypes['note'],
        'Contents': enclave_ids,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, enclave_ids),
    }
    return entry


def get_all_phishing_indicators(priority_event_score,
                                normalized_indicator_score,
                                from_time,
                                to_time,
                                status):
    cursor = encode_cursor(1000, 0)
    args = {'priority_event_score': priority_event_score,
            'normalized_indicator_score': normalized_indicator_score,
            'status': status,
            'cursor': cursor,
            'from_time': date_to_unix(from_time) if from_time else None,
            'to_time': date_to_unix(to_time) if to_time else None}
    response = ts.get_phishing_indicators_page(**args)
    indicators, ec = translate_phishing_indicators(response.items)
    if indicators:
        title = 'TruSTAR phishing indicators'
        entry = {
            'Type': entryTypes['note'],
            'Contents': indicators,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, indicators),
            'EntryContext': ec
        }
        return entry
    return 'No phishing indicators were found.'


def get_phishing_submissions(priority_event_score,
                             from_time,
                             to_time,
                             status):
    cursor = encode_cursor(1000, 0)
    args = {'priority_event_score': priority_event_score,
            'status': status,
            'cursor': cursor,
            'from_time': date_to_unix(from_time) if from_time else None,
            'to_time': date_to_unix(to_time) if to_time else None}
    response = ts.get_phishing_submissions_page(**args)
    if not response.items:
        return 'No phishing submissions were found.'
    submissions, ec = translate_triage_submission(response.items)
    title = 'TruSTAR phishing triage submissions'
    entry = {
        'Type': entryTypes['note'],
        'Contents': submissions,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, submissions),
        'EntryContext': ec
    }
    return entry


def set_triage_status(submission_id, status):
    try:
        response = ts.mark_triage_status(submission_id, status)
        response.raise_for_status()
        return "Submission ID {} is {}".format(submission_id, status)
    except requests.exceptions.HTTPError as err:
        return str(err)


''' EXECUTION CODE '''
config = {
    'user_api_key': API_KEY,
    'user_api_secret': API_SECRET,
    'api_endpoint': BASE_URL,
    'verify': INSECURE,
    'client_type': "Python_SDK",
    'client_metatag': "demisto-xsoar"
}
ts = trustar.TruStar(config=config)

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        demisto.results('ok')

    elif demisto.command() == 'trustar-related-indicators':
        enclave_ids = demisto.args().get('enclave-ids', None)
        demisto.results(get_related_indicators(demisto.args()['indicators'], enclave_ids, demisto.args()[
                        'page-size'], demisto.args()['page-number']))

    elif demisto.command() == 'trustar-trending-indicators':
        demisto.results(get_trending_indicators(demisto.args()['type'], demisto.args()['days-back']))

    elif demisto.command() == 'trustar-search-indicators':
        enclave_ids = demisto.args().get('enclave-ids', None)
        demisto.results(search_indicators(demisto.args()['search-term'], enclave_ids,
                                          demisto.args()['page-size'], demisto.args()['page-number']))

    elif demisto.command() == 'trustar-submit-report':
        enclave_ids = demisto.args().get('enclave-ids', None)
        external_url = demisto.args().get('external-url', None)
        time_began = demisto.args().get('time-began', None)
        demisto.results(submit_report(demisto.args()['title'], demisto.args()[
                        'report-body'], enclave_ids, external_url, time_began, demisto.args()['distribution-type']))

    elif demisto.command() == 'trustar-update-report':
        enclave_ids = demisto.args().get('enclave-ids', None)
        external_url = demisto.args().get('external-url', None)
        time_began = demisto.args().get('time-began', None)
        demisto.results(update_report(demisto.args()['report-id'], demisto.args()['title'],
                                      demisto.args()['report-body'], enclave_ids, external_url, time_began,
                                      demisto.args()['distribution-type']))

    elif demisto.command() == 'trustar-report-details':
        demisto.results(get_report_details(demisto.args()['report-id'], demisto.args()['id-type']))

    elif demisto.command() == 'trustar-delete-report':
        demisto.results(delete_report(demisto.args()['report-id'], demisto.args()['id-type']))

    elif demisto.command() == 'trustar-get-reports':
        from_time = demisto.args().get('from', None)
        to_time = demisto.args().get('to', None)
        enclave_ids = demisto.args().get('enclave-ids', None)
        tags = demisto.args().get('tags', None)
        excluded_tags = demisto.args().get('excluded-tags', None)
        demisto.results(get_reports(from_time, to_time, enclave_ids,
                                    demisto.args()['distribution-type'], tags, excluded_tags))

    elif demisto.command() == 'trustar-correlated-reports':
        enclave_ids = demisto.args().get('enclave-ids', None)
        demisto.results(get_correlated_reports(demisto.args()['indicators'], enclave_ids, demisto.args()[
                        'distribution-type'], demisto.args()['page-size'], demisto.args()['page-number']))

    elif demisto.command() == 'trustar-search-reports':
        enclave_ids = demisto.args().get('enclave-ids', None)
        demisto.results(search_reports(demisto.args()['search-term'], enclave_ids))

    elif demisto.command() == 'trustar-add-to-whitelist':
        demisto.results(add_to_whitelist(demisto.args()['indicators']))

    elif demisto.command() == 'trustar-remove-from-whitelist':
        demisto.results(remove_from_whitelist(demisto.args()['indicator'], demisto.args()['indicator-type']))

    elif demisto.command() == 'trustar-get-enclaves':
        demisto.results(get_enclaves())

    elif demisto.command() == 'file':
        demisto.results(generic_search_indicator(demisto.args().get('file'), demisto.params().get(
            'file_threshold'), ('File', 'MD5', 'SHA1', 'SHA256'), create_file_ec))

    elif demisto.command() == 'ip':
        demisto.results(generic_search_indicator(demisto.args().get('ip'),
                                                 demisto.params().get('ip_threshold'), ('IP',), create_ip_ec))

    elif demisto.command() == 'url':
        demisto.results(generic_search_indicator(demisto.args().get('url'),
                                                 demisto.params().get('url_threshold'), ('URL',), create_url_ec))

    elif demisto.command() == 'domain':
        demisto.results(generic_search_indicator(demisto.args().get('domain'),
                                                 demisto.params().get('domain_threshold'),
                                                 ('Domain', 'URL',), create_domain_ec))

    elif demisto.command() == 'trustar-get-phishing-indicators':
        nts = argToList(demisto.args().get('priority_event_score'))
        nss = argToList(demisto.args().get('normalized_indicator_score'))
        ft = demisto.args().get('from_time')
        tt = demisto.args().get('to_time')
        st = argToList(demisto.args().get('status'))
        demisto.results(get_all_phishing_indicators(nts, nss, ft, tt, st))

    elif demisto.command() == 'trustar-get-phishing-submissions':
        nts = argToList(demisto.args().get('priority_event_score'))
        ft = demisto.args().get('from_time')
        tt = demisto.args().get('to_time')
        st = argToList(demisto.args().get('status'))
        demisto.results(get_phishing_submissions(nts, ft, tt, st))

    elif demisto.command() == 'trustar-set-triage-status':
        demisto.results(set_triage_status(demisto.args().get('submission_id'),
                                          demisto.args().get('status')))

except Exception as e:
    return_error(str(e))
