import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import json
import requests

''' GLOBAL VARS '''
USE_SSL = True

EMAIL = demisto.params()['Email']
TOKEN = demisto.params()['Token']
CORPNAME = demisto.params()['corpName']

SERVER_URL = 'https://dashboard.signalsciences.net/api/v0/'

'''SUFFIX ENDPOINTS'''
GET_SITES_SUFFIX = 'corps/{0}/sites'
WHITELIST_SUFFIX = 'corps/{0}/sites/{1}/whitelist'
BLACKLIST_SUFFIX = 'corps/{0}/sites/{1}/blacklist'
DELETE_WHITELIST_IP_SUFFIX = 'corps/{0}/sites/{1}/whitelist/{2}'
DELETE_BLACKLIST_IP_SUFFIX = 'corps/{0}/sites/{1}/blacklist/{2}'
SITE_CREATE_LIST_SUFFIX = 'corps/{0}/sites/{1}/lists'
SITE_ACCESS_LIST_SUFFIX = 'corps/{0}/sites/{1}/lists/{2}'
SITE_CREATE_ALERT_SUFFIX = 'corps/{0}/sites/{1}/alerts'
SITE_ACCESS_ALERT_SUFFIX = 'corps/{0}/sites/{1}/alerts/{2}'
CREATE_CORP_LIST_SUFFIX = 'corps/{0}/lists'
ACCESS_CORP_LIST_SUFFIX = 'corps/{0}/lists/{1}'
GET_EVENTS_SUFFIX = '/corps/{0}/sites/{1}/events'
ACCESS_EVENT_SUFFIX = '/corps/{0}/sites/{1}/events/{2}'
EXPIRE_EVENT_SUFFIX = '/corps/{0}/sites/{1}/events/{2}/expire'
GET_REQUESTS_SUFFIX = '/corps/{0}/sites/{1}/requests'
ACCESS_REQUEST_SUFFIX = '/corps/{0}/sites/{1}/requests/{2}'

'''TABLE TITLES'''
WHITELIST_TITLE = 'Signal Sciences - Whitelist'
BLACKLIST_TITLE = 'Signal Sciences - Blacklist'
SITE_LIST_TITLE = ""
SITES_LIST_TITLE = "Sites list"
CREATE_SITE_LIST_TITLE = "Signal Sciences - creating a new list"
ADD_IP_TO_WHITELIST_TITLE = 'Signal Sciences - Adding an IP to Whitelist'
ADD_IP_TO_BLACKLIST_TITLE = 'Signal Sciences - Adding an IP to Blacklist'
ADD_ALERT_TITLE = 'Signal Sciences - Adding a new custom alert'
UPDATE_LIST_TITLE = 'Signal Sciences - Updating a list'
ALERT_LIST_TITLE = 'Signal Sciences - Alert list'
LIST_OF_SITE_LISTS_TITLE = 'Signal Sciences - list of site lists'
LIST_OF_CORP_LISTS_TITLE = 'Signal Sciences - list of corp lists'
LIST_OF_EVENTS_TITLE = 'Signal Sciences - list of events'
LIST_OF_REQUESTS_TITLE = 'Signal Sciences - list of requests'

'''TABLE HEADERS'''
ADD_IP_HEADERS = ['Source', 'Note', 'Expiration data']
WHITELIST_HEADERS = ['ID', 'Source', 'ExpiryDate', 'Note', 'CreatedDate', 'CreatedBy']
SITE_LIST_HEADERS = ['Name', 'Type', 'Entries', 'ID', 'Description', 'CreatedBy', 'CreatedDate', 'UpdatedDate']

'''List Types dict'''

LEGAL_SIGSCI_LIST_TYPES = {
    'ip',
    'country',
    'string',
    'wildcard'
}


''' HELPER FUNCTIONS '''


# Signal Sciences API returns only a "message" field when it failed to complete the request
def are_results_empty(res):
    if 'message' in res:
        return True
    return False


def is_error_status(status):
    if str(status)[0] == "5" or str(status)[0] == "4":
        return True
    return False


def return_error_message(results_json):
    error_message = results_json.get("message", None)
    if error_message is None:
        return_error("Error: An error occured")
    return_error("Error: {0}".format(error_message))


def http_request(method, url, params_dict=None, data=None, use_format_instead_of_raw=False):
    LOG('running %s request with url=%s\nparams=%s' % (method, url, json.dumps(params_dict)))

    headers = {
        'Content-Type': 'application/json',
        'x-api-user': EMAIL,
        'x-api-token': TOKEN
    }

    try:
        if use_format_instead_of_raw:
            res = requests.request(method,
                                   url,
                                   verify=USE_SSL,
                                   params=params_dict,
                                   headers=headers,
                                   data=json.dumps(data))
        else:
            res = requests.request(method,
                                   url,
                                   verify=USE_SSL,
                                   params=params_dict,
                                   headers=headers,
                                   json=data)

        if is_error_status(res.status_code):
            return_error_message(res.json())

        # references to delete from whitelist/blacklist only
        if 'whitelist/' in url or 'blacklist/' in url:
            return None
        if res.status_code == 204:
            return None
        res_json = res.json()
        if are_results_empty(res_json):
            return None
        return res_json

    except Exception, e:
        LOG(e)
        raise (e)


def is_legal_list_type(list_type):
    return list_type.lower() in LEGAL_SIGSCI_LIST_TYPES


def is_legal_ip_list(list_of_ips):
    for ip_addr in list_of_ips:
        if not is_ip_valid(ip_addr):
            return False
    return True


def represents_int(string_var):
    if '.' in string_var:
        return False
    if string_var[0] in ('-', '+'):
        return string_var[1:].isdigit()
    return string_var.isdigit()


def is_legal_interval_for_alert(interval):
    if not represents_int(interval):
        return False
    interval_int = int(interval)
    if not (interval_int == 1 or interval_int == 10 or interval_int == 60):
        return False
    return True

def validate_list_description_length(description):
    if description is not None:
        if len(description) > 140:
            return_error("Error: Description given is too long. Description must be 140 characters or shorter")

def validate_update_list_args(method, description):
    if not (method == "Add" or method == "Remove"):
        return_error("Error: Method given is illegal. Method must be 'Add' or 'Remove'")
    validate_list_description_length(description)


def validate_create_list_args(list_type, description):
    if not is_legal_list_type(list_type):
        return_error("Error: {0} is not a legal type for a list. Legal types are IP, String, "
                     "Country or Wildcard".format(list_type))
    validate_list_description_length(description)

def validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action):
    if not represents_int(threshold):
        return_error("Error: {0} is not a valid threshold value. Threshold must be an integer".format(threshold))
    if not is_legal_interval_for_alert(interval):
        return_error("Error: {0} is not a valid interval value. Interval value must be 1, 10 or 60".format(interval))
    if len(long_name) < 3 or len(long_name) > 25:
        return_error("Error: Illegal value for long_name argument - long_name must be between 3 and 25 characters long")
    if not (enabled == 'True' or enabled == 'False'):
        return_error("Error: Illegal value for 'enabled' argument - value must be 'True' or 'False'")
    if not (action == 'info' or action == 'flagged'):
        return_error("Error: Illegal value for 'action' argument - value must be 'info' or 'flagged'")



def validate_fetch_events_args(from_time, until_time, sort, since_id, max_id,
                               limit, page, action, tag, ip, status):
    if from_time is not None and not represents_int(from_time):
        return_error("Error: from_time must be an integer.")
    if until_time is not None and not represents_int(until_time):
        return_error("Error: until_time must be an integer.")
    if sort is not None and not (sort == "asc" or sort == "desc"):
        return_error("Error: sort value must be 'asc' or 'desc'.")
    if limit is not None and (not represents_int(limit) or int(limit) < 0 or int(limit) > 1000):
        return_error("Error: limit must be an integer, larger than 0 and at most 1000")
    if action is not None and not (action == "flagged" or action == "info"):
        return_error("Error: action value must be 'flagged' or 'info'")
    if ip is not None and not is_ip_valid(ip):
        return_error("Error: illegal value for 'ip' argument. Must be a valid ip address")
    if status is not None and not (status == 'active' or status == 'expired'):
        return_error("Error: status value must be 'active' or 'expired'")


def gen_fetch_event_data_from_args(from_time, until_time, sort, since_id, max_id,
                                   limit, page, action, tag, ip, status):
    fetch_events_request_data = {}
    if from_time is not None:
        fetch_events_request_data['from'] = int(from_time)
    if until_time is not None:
        fetch_events_request_data['until'] = int(until_time)
    if sort is not None:
        fetch_events_request_data['sort'] = sort
    if since_id is not None:
        fetch_events_request_data['since_id'] = since_id
    if max_id is not None:
        fetch_events_request_data['max_id'] = max_id
    if limit is not None:
        fetch_events_request_data['limit'] = int(limit)
    if page is not None:
        fetch_events_request_data['page'] = int(page)
    if action is not None:
        fetch_events_request_data['action'] = action
    if tag is not None:
        fetch_events_request_data['tag'] = tag
    if ip is not None:
        fetch_events_request_data['ip'] = ip
    if status is not None:
        fetch_events_request_data['status'] = status
    return fetch_events_request_data;


def event_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'Timestamp': response_data.get('timestamp', ''),
        'Source': response_data.get('source', ''),
        'RemoteCountryCode': response_data.get('remoteCountryCode', ''),
        'RemoteHostname': response_data.get('remoteHostname', ''),
        'UserAgents': response_data.get('userAgents', ''),
        'Action': response_data.get('action', ''),
        'Reasons': response_data.get('reasons', ''),
        'RequestCount': response_data.get('requestCount', ''),
        'TagCount': response_data.get('tagCount', ''),
        'Window': response_data.get('window', ''),
        'DateExpires': response_data.get('expires', ''),
        'ExpiredBy': response_data.get('expiredBy', ''),
    }
    return entry_context


def validate_fetch_requests_args(page, limit):
    if limit is not None and (not represents_int(limit) or int(limit) < 0 or int(limit) > 1000):
        return_error("Error: limit must be an integer, larger than 0 and at most 1000")
    if page is not None and not represents_int(page):
        return_error("Error: page must be an integer")


# should translate inner keys within the records in the tags array?
def request_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'ServerHostName': response_data.get('serverHostName', ''),
        'RemoteIP': response_data.get('remoteIP', ''),
        'RemoteHostName': response_data.get('remoteHostName', ''),
        'RemoteCountryCode': response_data.get('remoteCountryCode', ''),
        'UserAgent': response_data.get('userAgent', ''),
        'Timestamp': response_data.get('timestamp', ''),
        'Method': response_data.get('method', ''),
        'ServerName': response_data.get('serverName', ''),
        'Protocol': response_data.get('protocol', ''),
        'Path': response_data.get('path', ''),
        'URI': response_data.get('uri', ''),
        'ResponseCode': response_data.get('responseCode', ''),
        'ResponseSize': response_data.get('responseSize', ''),
        'ResponseMillis': response_data.get('responseMillis', ''),
        'AgentResponseCode': response_data.get('agentResponseCode', ''),
        'Tags': response_data.get('tags', ''),
    }
    return entry_context


def list_entry_context_from_response(response_data):
    entry_context = {
        'Name': response_data.get('name', ''),
        'Type': response_data.get('type', ''),
        'Entries': response_data.get('entries', ''),
        'ID': response_data.get('id', ''),
        'Description': response_data.get('description', ''),
        'CreatedBy': response_data.get('createdBy', ''),
        'CreatedDate': response_data.get('created', ''),
        'UpdatedDate': response_data.get('updated', '')
    }
    return entry_context


# where do skip notifications come from
def alert_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'SiteID': response_data.get('siteId', ''),
        'TagName': response_data.get('tagName', ''),
        'LongName': response_data.get('longName', ''),
        'Interval': response_data.get('interval', ''),
        'Threshold': response_data.get('threshold', ''),
        'BlockDurationSeconds': response_data.get('blockDurationSeconds', ''),
        'SkipNotifications': response_data.get('skipNotifications', ''),
        'Enabled': response_data.get('enabled', ''),
        'Action': response_data.get('action', ''),
        'CreatedDate': response_data.get('created', ''),
    }
    return entry_context


def check_ip_is_valid(ip):
    if not is_ip_valid(ip):
        return_error("Error: IP argument is invalid. Please enter a valid IP address")


def gen_entries_data_for_update_list_request(entries_list, method):
    """
    Args:
        entries_list: an array of IP addresses
        method: a string, either 'Add' or 'Remove'.
            States if the IPs should be added or removed to the site/corp list.

    Returns:
        An 'entries' dict, in the expected format by the SigSciences API
    """
    entries = {
        "additions": [],
        "deletions": []
    }
    entries_list_in_list_format = entries_list.split(',')
    if method == "Add":
        entries["additions"] = entries_list_in_list_format
    else:
        entries["deletions"] = entries_list_in_list_format
    return entries


def generate_whitelist_or_blacklist_ip_context(response_data):
    ips_contexts = []
    for item in response_data:
        output = {}
        output['ID'] = item.get('id', '')
        output['Source'] = item.get('source', '')
        output['ExpiryDate'] = item.get('expires', '')
        output['Note'] = item.get('note', '')
        output['CreatedDate'] = item.get('created', '')
        output['CreatedBy'] = item.get('createdBy', '')
        ips_contexts.append(output)
    return ips_contexts


def gen_human_readable_for_add_to_whitelist_or_blacklist(ip_context):
    human_readable = {}
    human_readable['Note'] = ip_context['Note']
    human_readable['Source'] = ip_context['Source']
    human_readable['Expiration data'] = ip_context['ExpiryDate'] if ip_context['ExpiryDate'] else "Not Set"
    return human_readable


def gen_context_for_add_to_whitelist_or_blacklist(response_data):
    ip_context = {}
    ip_context['ID'] = response_data.get('id', '')
    ip_context['Note'] = response_data.get('note', '')
    ip_context['Source'] = response_data.get('source', '')
    ip_context['CreatedBy'] = response_data.get('createdBy', '')
    ip_context['CreatedDate'] = response_data.get('created', '')
    ip_context['ExpiryDate'] = response_data.get('expires', '')
    return ip_context


def add_ip_to_whitelist_or_blacklist(url, ip, note, expires=None):
    check_ip_is_valid(ip)
    data = {
        'source': ip,
        'note': note
    }
    if expires is not None:
        data['expires'] = expires
    res = http_request('PUT', url, data=data)
    return res


'''COMMANDS'''


def test_module():
    try:
        url = SERVER_URL + 'corps'
        http_request('GET', url)
    except Exception, e:
        raise Exception(e.message)

    demisto.results('ok')


def create_corp_list(list_name, list_type, entries_list, description=None):
    """
    Note:
        Illegal entries (not compatible with the type) will result in a 404.
        They will be handled by the http_request function.
    """
    validate_create_list_args(list_type, description)

    url = SERVER_URL + CREATE_CORP_LIST_SUFFIX.format(CORPNAME)
    entries_list_in_list_format = entries_list.split(',')
    data_for_request = {
        'name': list_name.lower(),
        'type': list_type.lower(),
        'entries': entries_list_in_list_format
    }
    if description is not None:
        data_for_request['description'] = description
    new_list_data = http_request('POST', url, data=data_for_request)
    return new_list_data


def create_corp_list_command():
    args = demisto.args()
    response_data = create_corp_list(args['list_name'], args['list_type'], args['entries_list'],
                                             args.get('description', None))
    entry_context = list_entry_context_from_response(response_data)
    TITLE = "Signal Sciences - creating a new corp list \n\n The list has been succesfully created"
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.CorpLists(val.ID==obj.ID)': entry_context,
        }
    })


def get_corp_list(list_id):
    url = SERVER_URL + ACCESS_CORP_LIST_SUFFIX.format(CORPNAME, list_id)
    list_data = http_request('GET', url)
    return list_data


def get_corp_list_command():
    args = demisto.args()
    response_data = get_corp_list(args['list_id'])
    entry_context = list_entry_context_from_response(response_data)
    TITLE = "Found data about list with ID: {0}".format(args['list_id'])
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.CorpLists(val.ID==obj.ID)': entry_context,
        }
    })


def delete_corp_list(list_id):
    url = SERVER_URL + ACCESS_CORP_LIST_SUFFIX.format(CORPNAME, list_id)
    list_data = http_request('DELETE', url)
    return list_data


def delete_corp_list_command():
    args = demisto.args()
    response_data = delete_corp_list(args['list_id'])
    HUMAN_READABLE = "### Signal Sciences - deleting corp list \n\n The list has been succesfully removed"
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE
    })


# currently not handling IPv6 and will return error
def update_corp_list(list_id, method, entries_list, description=None):
    validate_update_list_args(method, description)
    entries_in_update_format = gen_entries_data_for_update_list_request(entries_list, method)
    url = SERVER_URL + ACCESS_CORP_LIST_SUFFIX.format(CORPNAME, list_id)
    data_for_request = {
        'entries': entries_in_update_format
    }
    if description is not None:
        data_for_request['description'] = description
    response_data = http_request('PATCH', url, data=data_for_request)
    return response_data


def update_corp_list_command():
    args = demisto.args()
    response_data = update_corp_list(args['list_id'], args['method'], args['entries_list'],
                                             args.get('description', None))
    entry_context = list_entry_context_from_response(response_data)
    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.CorpLists(val.ID==obj.ID)': entry_context,
        }
    })


def get_all_corp_lists():
    url = SERVER_URL + CREATE_CORP_LIST_SUFFIX.format(CORPNAME)
    response_data = http_request('GET', url)
    return response_data


def get_all_corp_lists_command():
    response_data = get_all_corp_lists()
    list_of_corp_lists = response_data.get('data', [])

    corp_lists_contexts = []
    for corp_list_data in list_of_corp_lists:
        cur_corp_list_context = list_entry_context_from_response(corp_list_data)
        corp_lists_contexts.append(cur_corp_list_context)
        
    sidedata = "Number of corp lists in corp: {0}".format(len(list_of_corp_lists))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_CORP_LISTS_TITLE, corp_lists_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.CorpLists(val.ID==obj.ID)': corp_lists_contexts,
        }
    })


# check if should add the use_format_instead_of_raw to the http request
def fetch_events(siteName, from_time=None, until_time=None, sort=None,
                 since_id=None, max_id=None, limit=None, page=None, action=None,
                 tag=None, ip=None, status=None):
    validate_fetch_events_args(from_time, until_time, sort, since_id, max_id,
                               limit, page, action, tag, ip, status)
    url = SERVER_URL + GET_EVENTS_SUFFIX.format(CORPNAME, siteName)
    data_for_request = gen_fetch_event_data_from_args(from_time, until_time, sort, since_id, max_id,
                                                      limit, page, action, tag, ip, status)
    events_data_response = http_request('GET', url, data=data_for_request)
    return events_data_response


def fetch_events_command():
    args = demisto.args()
    response_data = fetch_events(args['siteName'], args.get('from_time', None),
                                         args.get('until_time', None), args.get('sort', None),
                                         args.get('since_id', None),
                                         args.get('max_id', None), args.get('limit', None), args.get('page', None),
                                         args.get('action', None), args.get('tag', None), args.get('ip', None),
                                         args.get('status', None))

    list_of_events = response_data.get('data', [])
    events_contexts = []
    for event_data in list_of_events:
        cur_event_context = event_entry_context_from_response(event_data)
        events_contexts.append(cur_event_context)
        
    sidedata = "Number of events in site: {0}".format(len(list_of_events))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_EVENTS_TITLE, events_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Events(val.ID==obj.ID)': events_contexts,
        }
    })


def get_event_by_id(siteName, event_id):
    url = SERVER_URL + ACCESS_EVENT_SUFFIX.format(CORPNAME, siteName, event_id)
    event_data_response = http_request('GET', url)
    return event_data_response


def get_event_by_id_command():
    args = demisto.args()
    response_data = get_event_by_id(args['siteName'], args['event_id'])
    entry_context = event_entry_context_from_response(response_data)
    TITLE = "Found data about event with ID: {0}".format(args['event_id'])
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.Events(val.ID==obj.ID)': entry_context,
        }
    })


def expire_event(siteName, event_id):
    url = SERVER_URL + EXPIRE_EVENT_SUFFIX.format(CORPNAME, siteName, event_id)
    event_data_response = http_request('POST', url)
    return event_data_response


def expire_event_command():
    args = demisto.args()
    response_data = expire_event(args['siteName'], args['event_id'])
    HUMAN_READABLE = "### Signal Sciences - expiring event \n\n The event has been succesfully expired"
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE
    })


# check what happens if no arg is sent, is sending empty dict as data ok?
# check if should add the use_format_instead_of_raw to the http request
def get_requests(siteName, page, limit, query):
    url = SERVER_URL + GET_REQUESTS_SUFFIX.format(CORPNAME, siteName)
    validate_fetch_requests_args(page, limit)
    data_for_request = {}
    if page is not None:
        data_for_request['page'] = page
    if limit is not None:
        data_for_request['limit'] = limit
    if query is not None:
        data_for_request['q'] = query
        
    requests_data_response = http_request('GET', url, data=data_for_request)
    return requests_data_response


def get_requests_command():
    args = demisto.args()
    response_data = get_requests(args['siteName'], args.get('page', None), args.get('limit', None),
                                         args.get('query', None))
    list_of_requests = response_data.get('data', [])
    requests_contexts = []
    for request_data in list_of_requests:
        cur_request_context = request_entry_context_from_response(request_data)
        requests_contexts.append(cur_request_context)

    sidedata = "Number of requests in site: {0}".format(len(list_of_requests))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_REQUESTS_TITLE, requests_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Requests(val.ID==obj.ID)': requests_contexts,
        }
    })


def get_request_by_id(siteName, request_id):
    url = SERVER_URL + ACCESS_REQUEST_SUFFIX.format(CORPNAME, siteName, request_id)
    request_data_response = http_request('GET', url)
    return request_data_response


def get_request_by_id_command():
    args = demisto.args()
    response_data = get_request_by_id(args['siteName'], args['request_id'])
    entry_context = request_entry_context_from_response(response_data)
    TITLE = "Found data about request with ID: {0}".format(args['request_id'])
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.Requests(val.ID==obj.ID)': entry_context,
        }
    })


def create_site_list(siteName, list_name, list_type, entries_list, description=None):
    validate_create_list_args(list_type, description)
    url = SERVER_URL + SITE_CREATE_LIST_SUFFIX.format(CORPNAME, siteName)
    entries_list_in_list_format = entries_list.split(',')
    data_for_request = {
        'name': list_name.lower(),
        'type': list_type.lower(),
        'entries': entries_list_in_list_format
    }
    if description is not None:
        data_for_request['description'] = description
        
    new_list_data = http_request('POST', url, data=data_for_request)
    return new_list_data


def create_site_list_command():
    args = demisto.args()
    response_data = create_site_list(args['siteName'], args['list_name'],
                                             args['list_type'], args['entries_list'], args.get('description', None))
    entry_context = list_entry_context_from_response(response_data)
    TITLE = "Signal Sciences - creating a new site list \n\n The list has been succesfully created"
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': entry_context,
        }
    })


def get_site_list(siteName, list_id):
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    list_data = http_request('GET', url)
    return list_data


def get_site_list_command():
    args = demisto.args()
    response_data = get_site_list(args['siteName'], args['list_id'])
    entry_context = list_entry_context_from_response(response_data)
    TITLE = "Found data about list with ID: {0}".format(args['list_id'])
    human_readable = tableToMarkdown(TITLE, entry_context, SITE_LIST_HEADERS)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': entry_context,
        }
    })


# should be names "remove_site_list"? that's what the interface says
def delete_site_list(siteName, list_id):
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    list_data = http_request('DELETE', url)
    return list_data


def delete_site_list_command():
    args = demisto.args()
    response_data = delete_site_list(args['siteName'], args['list_id'])
    HUMAN_READABLE = "### Signal Sciences - deleting site list \n\n The list has been succesfully removed"
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE
    })


def update_site_list(siteName, list_id, method, entries_list, description=None):
    validate_update_list_args(method, description)
    
    entries_in_update_format = gen_entries_data_for_update_list_request(entries_list, method)
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    data_for_request = {
        'entries': entries_in_update_format
    }
    if description is not None:
        data_for_request['description'] = description
    response_data = http_request('PATCH', url, data=data_for_request)
    return response_data


def update_site_list_command():
    args = demisto.args()
    response_data = update_site_list(args['siteName'], args['list_id'],
                                             args['method'], args['entries_list'], args.get('description', None))
    entry_context = list_entry_context_from_response(response_data)
    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': entry_context,
        }
    })


def get_all_site_lists(siteName):
    url = SERVER_URL + SITE_CREATE_LIST_SUFFIX.format(CORPNAME, siteName)
    response_data = http_request('GET', url)
    return response_data


def get_all_site_lists_command():
    args = demisto.args()
    response_data = get_all_site_lists(args['siteName'])
    list_of_site_lists = response_data.get('data', [])

    site_lists_contexts = []
    for site_list_data in list_of_site_lists:
        cur_site_context = list_entry_context_from_response(site_list_data)
        site_lists_contexts.append(cur_site_context)
        
    sidedata = "Number of site lists in site: {0}".format(len(list_of_site_lists))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_SITE_LISTS_TITLE, site_lists_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': site_lists_contexts,
        }
    })


# should be called "add alert" like the UI? or "create alert" like the API?
def add_alert(siteName, long_name, tag_name, interval, threshold, enabled, action):
    validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action)
    url = SERVER_URL + SITE_CREATE_ALERT_SUFFIX.format(CORPNAME, siteName)
    data_for_request = {
        'tagName': tag_name,
        'longName': long_name,
        'interval': int(interval),
        'threshold': int(threshold),
        'enabled': bool(enabled),
        'action': action
    }
    response_data = http_request('POST', url, data=data_for_request)
    return response_data


def add_alert_command():
    args = demisto.args()
    response_data = add_alert(args['siteName'], args['long_name'], args['tag_name'],
                                      args['interval'], args['threshold'], args['enabled'], args['action'])
    entry_context = alert_entry_context_from_response(response_data)
    human_readable = tableToMarkdown(ADD_ALERT_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.Alerts(val.ID==obj.ID)': entry_context,
        }
    })


def get_alert(siteName, alert_id):
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    response_data = http_request('GET', url)
    return response_data


def get_alert_command():
    args = demisto.args()
    response_data = get_alert(args['siteName'], args['alert_id'])
    entry_context = alert_entry_context_from_response(response_data)
    TITLE = "Data found for alert id: {0}".format(args['alert_id'])
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.Alerts(val.ID==obj.ID)': entry_context,
        }
    })


def delete_alert(siteName, alert_id):
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    response_data = http_request('DELETE', url)
    return response_data


def delete_alert_command():
    args = demisto.args()
    response_data = delete_alert(args['siteName'], args['alert_id'])
    HUMAN_READABLE = "Alert {0} deleted succesfully".format(args['alert_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE
    })


def update_alert(siteName, alert_id, tag_name, long_name, interval, threshold, enabled, action):
    validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action)
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    data_for_request = {
        'tagName': tag_name,
        'longName': long_name,
        'interval': int(interval),
        'threshold': int(threshold),
        'action': action
    }
    if enabled == "True":
        data_for_request['enabled'] = True
    else:
        data_for_request['enabled'] = False
    request_response = http_request('PATCH', url, data=data_for_request)
    return request_response


def update_alert_command():
    args = demisto.args()
    response_data = update_alert(args['siteName'], args['alert_id'], args['tag_name'], args['long_name'],
                                         args['interval'], args['threshold'], args['enabled'], args['action'])
    TITLE = "Updated alert {0}. new values:".format(args['alert_id'])
    entry_context = alert_entry_context_from_response(response_data)
    human_readable = tableToMarkdown(TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.Alerts(val.ID==obj.ID)': entry_context,
        }
    })


def get_all_alerts(siteName):
    url = SERVER_URL + SITE_CREATE_ALERT_SUFFIX.format(CORPNAME, siteName)
    response_data = http_request('GET', url)
    return response_data


def get_all_alerts_command():
    args = demisto.args()
    response_data = get_all_alerts(args['siteName'])
    alerts_list = response_data.get('data', [])
    alerts_contexts = []
    for alert_data in alerts_list:
        cur_alert_context = alert_entry_context_from_response(alert_data)
        alerts_contexts.append(cur_alert_context)
        
    sidedata = "Number of alerts in site: {0}".format(len(alerts_list))
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(ALERT_LIST_TITLE, alerts_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Alerts(val.ID==obj.ID)': alerts_contexts,
        }
    })


def get_whitelist(siteName):
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    site_whitelist = http_request('GET', url)
    return site_whitelist


def get_whitelist_command():
    """Get the whitelist data for siteName"""
    args = demisto.args()
    site_whitelist = get_whitelist(args['siteName'])
    data = site_whitelist.get('data', [])
    whitelist_ips_contexts = generate_whitelist_or_blacklist_ip_context(data)
        
    sidedata = "Number of IPs in the Whitelist {0}".format(len(data))
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': site_whitelist,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(WHITELIST_TITLE, whitelist_ips_contexts, WHITELIST_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Whitelist(val.ID==obj.ID)': whitelist_ips_contexts,
        }
    })


def get_blacklist(siteName):
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    site_blacklist = http_request('GET', url)
    return site_blacklist


def get_blacklist_command():
    """Get blacklist data for siteName"""
    args = demisto.args()
    site_blacklist = get_blacklist(args['siteName'])
    data = site_blacklist.get('data', [])
    blacklist_ips_contexts = generate_whitelist_or_blacklist_ip_context(data)

    sidedata = "Number of IPs in the Blacklist {0}".format(len(data))
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': site_blacklist,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(BLACKLIST_TITLE, blacklist_ips_contexts, WHITELIST_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Blacklist(val.ID==obj.ID)': blacklist_ips_contexts,
        }
    })


def add_ip_to_whitelist(siteName, ip, note, expires=None):
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    res = add_ip_to_whitelist_or_blacklist(url, ip, note, expires)
    return res


def add_ip_to_whitelist_command():
    """Add an ip to the whitelist"""
    args = demisto.args()
    response_data = add_ip_to_whitelist(args['siteName'], args['ip'], args['note'], args.get('expires', None))
    whitelist_ip_context = gen_context_for_add_to_whitelist_or_blacklist(response_data)
    human_readable = gen_human_readable_for_add_to_whitelist_or_blacklist(whitelist_ip_context)

    sidedata = "The IP has been successfully added to whitelist."
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(ADD_IP_TO_WHITELIST_TITLE, human_readable, ADD_IP_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Whitelist(val.ID==obj.ID)': whitelist_ip_context,
        }
    })


def add_ip_to_blacklist(siteName, ip, note, expires=None):
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    res = add_ip_to_whitelist_or_blacklist(url, ip, note, expires)
    return res


def add_ip_to_blacklist_command():
    """Add an ip to the blacklist"""
    args = demisto.args()
    response_data = add_ip_to_blacklist(args['siteName'], args['ip'], args['note'], args.get('expires', None))
    blacklist_ip_context = gen_context_for_add_to_whitelist_or_blacklist(response_data)
    human_readable = gen_human_readable_for_add_to_whitelist_or_blacklist(blacklist_ip_context)

    sidedata = "The IP has been successfully added to blacklist."
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(ADD_IP_TO_BLACKLIST_TITLE, human_readable, ADD_IP_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Blacklist(val.ID==obj.ID)': blacklist_ip_context,
        }
    })


def whitelist_remove_ip(siteName, ip):
    check_ip_is_valid(ip)
    site_whitelist = get_whitelist(siteName)
    data = site_whitelist.get('data', [])
    for item in data:
        if item.get('source', '') == ip:
            url = SERVER_URL + DELETE_WHITELIST_IP_SUFFIX.format(CORPNAME, siteName, item.get('id', ''))
            res = http_request('DELETE', url)

    if 'res' not in locals():
        raise Exception("The IP {0} was not found on the Whitelist".format(ip))

    return site_whitelist


def whitelist_remove_ip_command():
    """Remove an ip from the whitelist"""
    args = demisto.args()
    response_data = whitelist_remove_ip(args['siteName'], args['IP'])

    HUMAN_READABLE = '### Signal Sciences - Removing an IP from Whitelist \n\n '\
                     'The IP has been successfully removed from Whitelist.'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE,
    })


def blacklist_remove_ip(siteName, ip):
    check_ip_is_valid(ip)
    site_blacklist = get_blacklist(siteName)
    data = site_blacklist.get('data', [])
    for item in data:
        if item.get('source', '') == ip:
            url = SERVER_URL + DELETE_BLACKLIST_IP_SUFFIX.format(CORPNAME, siteName, item.get('id', ''))
            res = http_request('DELETE', url)

    if 'res' not in locals():
        raise Exception("The IP {0} was not found on the Blacklist".format(ip))

    return site_blacklist


def blacklist_remove_ip_command():
    """Remove an ip from the blacklist"""
    args = demisto.args()
    response_data = blacklist_remove_ip(args['siteName'], args['IP'])

    HUMAN_READABLE = '### Signal Sciences - Removing an IP from Blacklist \n\n ' \
                     'The IP has been successfully removed from Blacklist.'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': HUMAN_READABLE,
    })


def get_sites():
    url = SERVER_URL + GET_SITES_SUFFIX.format(CORPNAME)
    res = http_request('GET', url)
    return res


def get_sites_command():
    """Get the sites list"""
    res = get_sites()
    data = res.get('data', [])

    outputs = []
    for item in data:
        output = {}
        output['Name'] = item.get('name', '')
        output['CreatedDate'] = item.get('created', '')

        outputs.append(output)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(SITES_LIST_TITLE, outputs, ['Name', 'CreatedDate']),
        'EntryContext': {
            'SigSciences.Sites(val.Name==obj.Name)': outputs,
        }
    })


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(),))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'sigsci-get-whitelist':
        get_whitelist_command()
    elif demisto.command() == 'sigsci-get-blacklist':
        get_blacklist_command()
    elif demisto.command() == 'sigsci-whitelist-add-ip':
        add_ip_to_whitelist_command()
    elif demisto.command() == 'sigsci-blacklist-add-ip':
        add_ip_to_blacklist_command()
    elif demisto.command() == 'sigsci-whitelist-remove-ip':
        whitelist_remove_ip_command()
    elif demisto.command() == 'sigsci-blacklist-remove-ip':
        blacklist_remove_ip_command()
    elif demisto.command() == 'sigsci-get-sites':
        get_sites_command()
    elif demisto.command() == 'sigsci-create-corp-list':
        create_corp_list_command()
    elif demisto.command() == 'sigsci-get-corp-list':
        get_corp_list_command()
    elif demisto.command() == 'sigsci-delete-corp-list':
        delete_corp_list_command()
    elif demisto.command() == 'sigsci-update-corp-list':
        update_corp_list_command()
    elif demisto.command() == 'sigsci-get-all-corp-lists':
        get_all_corp_lists_command()
    elif demisto.command() == 'sigsci-create-site-list':
        create_site_list_command()
    elif demisto.command() == 'sigsci-get-site-list':
        get_site_list_command()
    elif demisto.command() == 'sigsci-delete-site-list':
        delete_site_list_command()
    elif demisto.command() == 'sigsci-update-site-list':
        update_site_list_command()
    elif demisto.command() == 'sigsci-get-all-site-lists':
        get_all_site_lists_command()
    elif demisto.command() == 'sigsci-add-alert':
        add_alert_command()
    elif demisto.command() == 'sigsci-get-alert':
        get_alert_command()
    elif demisto.command() == 'sigsci-delete-alert':
        delete_alert_command()
    elif demisto.command() == 'sigsci-update-alert':
        update_alert_command()
    elif demisto.command() == 'sigsci-get-all-alerts':
        get_all_alerts_command()
    elif demisto.command() == 'sigsci-fetch-events':
        fetch_events_command()
    elif demisto.command() == 'sigsci-expire-event':
        expire_event_command()
    elif demisto.command() == 'sigsci-get-event-by-id':
        get_event_by_id_command()
    elif demisto.command() == 'sigsci-get-requests':
        get_requests_command()
    elif demisto.command() == 'sigsci-get-request-by-id':
        get_request_by_id_command()


except Exception as e:
    return_error(e.message)
