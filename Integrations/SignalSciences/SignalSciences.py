import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import os
import json
import requests
import datetime

''' GLOBAL VARS '''
USE_SSL = True

EMAIL = demisto.params()['Email']
TOKEN = demisto.params()['Token']
CORPNAME = demisto.params()['corpName']

SERVER_URL = 'https://dashboard.signalsciences.net/api/v0/'

TAG_NAME_TEMPORARY_GLOBAL = 'USERAGENT'

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


'''TABLE HEADERS'''
ADD_IP_HEADERS = ['Source', 'Note', 'Expiration data']
WHITELIST_HEADERS = ['ID', 'Source', 'ExpiryDate', 'Note', 'CreatedDate', 'CreatedBy']
SITE_LIST_HEADERS = ['Name', 'Type', 'Entries', 'ID', 'Description', 'CreatedBy', 'CreatedDate', 'UpdatedDate']


'''List Types dict'''
list_type_dict = {
    'ip': True,
    'country': True,
    'string': True,
    'wildcard': True
}

'''Valid Alert Tags dict'''
valid_alert_tags_dict = {
    'Attack Tooling': True,
    'Backdoor': True,
    'Command Execution': True,
    'Cross Site Scripting': True,
    'Directory Traversal': True,
    'SQL Injection': True,
    'Blocked Requests': True,
    'Code Injection': True,
    'Datacenter Traffic': True,
    'Double Encoding': True,
    'Forceful Browsing': True,
    'HTTP 403 Errors': True,
    'HTTP 404 Errors': True,
    'HTTP 429 Errors': True,
    'HTTP 4XX Errors': True,
    'HTTP 500 Errors': True,
    'HTTP 503 Errors': True,
    'HTTP 5XX Errors': True,
    'HTTP Response Splitting': True,
    'Invalid Encoding': True,
    'Malformed Data in the request body': True,
    'Malicious IP Traffic': True,
    'Missing "Content-Type" request header': True,
    'No User Agent': True,
    'Null Byte': True,
    'Private Files': True,
    'Scanner': True,
    'SearchBot Impostors': True,
    'SigSci Malicious IPs': True,
    'Tor Traffic': True,
    'Weak TLS': True
}

''' HELPER FUNCTIONS '''
#Signal Sciences API returns only a "message" field when it failed to complete the request
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

def http_request(method, url, params_dict=None, data=None):
    LOG('running %s request with url=%s\nparams=%s' % (method, url, json.dumps(params_dict)))

    headers = {
                  'Content-Type': 'application/json',
                  'x-api-user': EMAIL,
                  'x-api-token': TOKEN
              }

    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=params_dict,
                               headers=headers,
                               json=data
                              )

        if is_error_status(res.status_code):
            return_error_message(res.json())

        #references to delete from whitelist/blacklist only
        if 'whitelist/' in url or 'blacklist/' in url:
            return None
        if (res.status_code == 204):
            return None
        res_json = res.json()
        if are_results_empty(res_json):
            return None
        return res_json

    except Exception, e:
        LOG(e)
        raise(e)


def is_legal_list_type(list_type):
    return list_type.lower() in list_type_dict

def is_legal_ip_list(list_of_ips):
    for ip_addr in list_of_ips:
        if not is_ip_valid(ip_addr):
            return False
    return True

def is_valid_alert_tag(alert_tag):
    return alert_tag in valid_alert_tags_dict

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

#the validity of the tagName argument is currently unchecked, until further information is provided
def validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action):
    if not represents_int(threshold):
        return_error("Error: {0} is not a valid threshold value. Threshold must be an integer".format(threshold))
    if not is_legal_interval_for_alert(interval):
        return_error("Error: {0} is not a valid interval value. Interval value must be 1, 10 or 60".format(interval))
    if len(long_name) < 3 or len(long_name) > 25:
        return_error("Error: Illegal value for long_name argument - long_name must be between 3 and 25 characters long")
    if not (enabled == 'True' or enabled=='False'):
        return_error("Error: Illegal value for 'enabled' argument - value must be 'True' or 'False'")
    if not (action == 'info' or action == 'flagged'):
        return_error("Error: Illegal value for 'action' argument - value must be 'info' or 'flagged'")

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

#where do skip notifications come from
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

def format_update_list_entries(entries_list, method):
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


'''COMMANDS'''
def test_module():
    try:
        url = SERVER_URL + 'corps'
        res = http_request('GET', url)
    except Exception, e:
        raise Exception(e.message)

    demisto.results('ok')

#list entries that don't match the type will return a 404, and will be handled at the http_request method
def create_corp_list(list_name, list_type, entries_list, description = None):
    if not is_legal_list_type(list_type):
        return_error("Error: {0} is not a legal type for a list. Legal types are IP, String, Country or Wildcard".format(list_type))
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
    request_response_data = create_corp_list(args.get('list_name',''), args.get('list_type',''), args.get('entries_list',''), args.get('description', None))
    entry_context = list_entry_context_from_response(request_response_data)
    title = "Signal Sciences - creating a new corp list \n\n The list has been succesfully created"
    human_readable = tableToMarkdown(title, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_corp_list(args['list_id'])
    entry_context = list_entry_context_from_response(request_response_data)
    title = "Found data about list with ID: {0}".format(args['list_id'])
    human_readable = tableToMarkdown(title, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = delete_corp_list(args['list_id'])
    human_readable = "### Signal Sciences - deleting corp list \n\n The list has been succesfully removed"
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable
    })


#what about IPv6? currently not handling and will return error
def update_corp_list(list_id, method, entries_list, description=None):
    if not (method == "Add" or method == "Remove"):
        return_error("Error: Method given is illegal. Method must be 'Add' or 'Remove'")
    if description is not None:
        if len(description) > 140:
            return_error("Error: Description given is too long. Description must be 140 characters or shorter")
    entries_in_update_format = format_update_list_entries(entries_list, method)
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
    request_response_data = update_corp_list(args['list_id'], args['method'], args['entries_list'], args.get('description', None))
    entry_context = list_entry_context_from_response(request_response_data)
    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_all_corp_lists()
    list_of_corp_lists = request_response_data.get('data', [])

    corp_lists_contexts = []
    for corp_list_data in list_of_corp_lists:
        cur_corp_list_context = list_entry_context_from_response(corp_list_data)
        corp_lists_contexts.append(cur_corp_list_context)
    sidedata = "Number of corp lists in corp: {0}".format(len(list_of_corp_lists))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_CORP_LISTS_TITLE, corp_lists_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.CorpLists(val.ID==obj.ID)': corp_lists_contexts,
        }
    })


def create_site_list(siteName, list_name, list_type, entries_list, description = None):
    if not is_legal_list_type(list_type):
        return_error("Error: {0} is not a legal type for a list. Legal types are IP, String, Country or Wildcard".format(list_type))
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
    request_response_data = create_site_list(args.get('siteName', ''), args.get('list_name',''), args.get('list_type',''), args.get('entries_list',''), args.get('description', None))
    entry_context = list_entry_context_from_response(request_response_data)
    title = "Signal Sciences - creating a new site list \n\n The list has been succesfully created"
    human_readable = tableToMarkdown(title, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_site_list(args['siteName'], args['list_id'])
    entry_context = list_entry_context_from_response(request_response_data)
    title = "Found data about list with ID: {0}".format(args['list_id'])
    human_readable = tableToMarkdown(title, entry_context, SITE_LIST_HEADERS)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': entry_context,
        }
    })


#should be names "remove_site_list"? that's what the interface says
def delete_site_list(siteName, list_id):
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    list_data = http_request('DELETE', url)
    return list_data


def delete_site_list_command():
    args = demisto.args()
    request_response_data = delete_site_list(args['siteName'], args['list_id'])
    human_readable = "### Signal Sciences - deleting site list \n\n The list has been succesfully removed"
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable
    })


def update_site_list(siteName, list_id, method, entries_list, description=None):
    if not (method == "Add" or method == "Remove"):
        return_error("Error: Method given is illegal. Method must be 'Add' or 'Remove'")
    if description is not None:
        if len(description) > 140:
            return_error("Error: Description given is too long. Description must be 140 characters or shorter")
    entries_in_update_format = format_update_list_entries(entries_list, method)
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
    request_response_data = update_site_list(args['siteName'], args['list_id'], args['method'], args['entries_list'], args.get('description', None))
    entry_context = list_entry_context_from_response(request_response_data)
    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_all_site_lists(args['siteName'])
    list_of_site_lists = request_response_data.get('data', [])

    site_lists_contexts = []
    for site_list_data in list_of_site_lists:
        cur_site_context = list_entry_context_from_response(site_list_data)
        site_lists_contexts.append(cur_site_context)
    sidedata = "Number of site lists in site: {0}".format(len(list_of_site_lists))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(LIST_OF_SITE_LISTS_TITLE, site_lists_contexts, metadata=sidedata),
        'EntryContext': {
            'SigSciences.SiteLists(val.ID==obj.ID)': site_lists_contexts,
        }
    })




#should be called "add alert" like the UI? or "create alert" like the API?
def add_alert(siteName, long_name, tag_name, interval, threshold, enabled, action):
    validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action)
    url = SERVER_URL + SITE_CREATE_ALERT_SUFFIX.format(CORPNAME, siteName)
    data_for_request = {
        'tagName': TAG_NAME_TEMPORARY_GLOBAL,
        'longName': long_name,
        'interval': int(interval),
        'threshold': int(threshold),
        'enabled': enabled,
        'action': action
    }
    if enabled == "True":
        data_for_request['enabled'] = True
    else:
        data_for_request['enabled'] = False
    response_data = http_request('POST', url, data=data_for_request)
    return response_data

def add_alert_command():
    args = demisto.args()
    request_response_data = add_alert(args['siteName'],  args['long_name'], args['tag_name'], args['interval'], args['threshold'], args['enabled'], args['action'])
    entry_context = alert_entry_context_from_response(request_response_data)
    human_readable = tableToMarkdown(ADD_ALERT_TITLE, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_alert(args['siteName'], args['alert_id'])
    entry_context = alert_entry_context_from_response(request_response_data)
    get_alert_title = "Data found for alert id: {0}".format(args['alert_id'])
    human_readable = tableToMarkdown(get_alert_title, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = delete_alert(args['siteName'], args['alert_id'])
    human_readable = "Alert {0} deleted succesfully".format(args['alert_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable
    })


def update_alert(siteName, alert_id, tag_name, long_name, interval, threshold, enabled, action):
    validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action)
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    data_for_request = {
        'tagName': TAG_NAME_TEMPORARY_GLOBAL,
        'longName': long_name,
        'interval': int(interval),
        'threshold': int(threshold),
        'action': action
    }
    if enabled == "True":
        data_for_request['enabled'] = True
    else:
        data_for_request['enabled'] = False
    request_response = http_request('PATCH', url, data = data_for_request)
    return request_response


def update_alert_command():
    args = demisto.args()
    request_response_data=update_alert(args['siteName'], args['alert_id'], args['tag_name'], args['long_name'], args['interval'], args['threshold'], args['enabled'], args['action'])
    update_alert_title = "Updated alert {0}. new values:".format(args['alert_id'])
    entry_context = alert_entry_context_from_response(request_response_data)
    human_readable = tableToMarkdown(update_alert_title, entry_context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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
    request_response_data = get_all_alerts(args['siteName'])
    alerts_list = request_response_data.get('data', [])

    alerts_contexts = []
    for alert_data in alerts_list:
        cur_alert_context = alert_entry_context_from_response(alert_data)
        alerts_contexts.append(cur_alert_context)
    sidedata = "Number of alerts in site: {0}".format(len(alerts_list))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': request_response_data,
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

    outputs = []
    for item in data:
        output = {}

        output['ID'] = item.get('id', '')
        output['Source'] = item.get('source', '')
        output['ExpiryDate'] = item.get('expires', '')
        output['Note'] = item.get('note', '')
        output['CreatedDate'] = item.get('created', '')
        output['CreatedBy'] = item.get('createdBy', '')

        outputs.append(output)

    sidedata = "Number of IPs in the Whitelist {0}".format(len(data))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': site_whitelist,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(WHITELIST_TITLE, outputs, WHITELIST_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Whitelist(val.ID==obj.ID)': outputs,
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

    outputs = []
    for item in data:
        output = {}

        output['ID'] = item.get('id', '')
        output['Source'] = item.get('source', '')
        output['ExpiryDate'] = item.get('expires', '')
        output['Note'] = item.get('note', '')
        output['CreatedDate'] = item.get('created', '')
        output['CreatedBy'] = item.get('createdBy', '')

        outputs.append(output)

    sidedata = "Number of IPs in the Blacklist {0}".format(len(data))

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': site_blacklist,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(BLACKLIST_TITLE, outputs, WHITELIST_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Blacklist(val.ID==obj.ID)': outputs,
        }
    })


def add_ip_to_whitelist(siteName, ip, note, expires=None):
    check_ip_is_valid(ip)
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    data = {
               'source': ip,
               'note': note
           }
    if expires is not None:
        data['expires'] = expires

    res = http_request('PUT', url, data=data)
    return res


def add_ip_to_whitelist_command():
    """Add an ip to the whitelist"""

    args = demisto.args()
    res = add_ip_to_whitelist(args['siteName'], args['ip'], args['note'], args.get('expires', None))

    output = {}
    human_readable = {}
    output['ID'] = res.get('id', '')
    output['Note'] = res.get('note', '')
    output['Source'] = res.get('source', '')
    output['CreatedBy'] = res.get('createdBy', '')
    output['CreatedDate'] = res.get('created', '')
    output['ExpiryDate'] = res.get('expires', '')

    human_readable['Note'] = output['Note']
    human_readable['Source'] = output['Source']
    human_readable['Expiration data'] = output['ExpiryDate'] if output['ExpiryDate'] else "Not Set"

    sidedata = "The IP has been successfully added to whitelist."

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(ADD_IP_TO_WHITELIST_TITLE, human_readable, ADD_IP_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Whitelist(val.ID==obj.ID)': output,
        }
    })


def add_ip_to_blacklist(siteName, ip, note, expires=None):
    check_ip_is_valid(ip)
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    data = {
              'source': ip,
              'note': note
           }
    if expires is not None:
        data['expires'] = expires

    res = http_request('PUT', url, data=data)
    return res


def add_ip_to_blacklist_command():
    """Add an ip to the blacklist"""
    args = demisto.args()
    res = add_ip_to_blacklist(args['siteName'], args['ip'], args['note'], args.get('expires', None))

    output = {}
    human_readable = {}
    output['ID'] = res.get('id', '')
    output['Note'] = res.get('note', '')
    output['Source'] = res.get('source', '')
    output['CreatedBy'] = res.get('createdBy', '')
    output['CreatedDate'] = res.get('created', '')
    output['ExpiryDate'] = res.get('expires', '')

    human_readable['Note'] = output['Note']
    human_readable['Source'] = output['Source']
    human_readable['Expiration data'] = output['ExpiryDate'] if output['ExpiryDate'] else "Not Set"

    sidedata = "The IP has been successfully added to blacklist."

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(ADD_IP_TO_BLACKLIST_TITLE, human_readable, ADD_IP_HEADERS, metadata=sidedata),
        'EntryContext': {
            'SigSciences.Blacklist(val.ID==obj.ID)': output,
        }
    })


def whitelist_remove_ip(siteName, IP):
    check_ip_is_valid(IP)
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    site_whitelist = http_request('GET', url)
    return site_whitelist


def whitelist_remove_ip_command():
    """Remove an ip from the whitelist"""
    args = demisto.args()
    site_whitelist = whitelist_remove_ip(args['siteName'], args['IP'])
    data = site_whitelist.get('data', [])
    IP = args['IP']
    for item in data:
        if item.get('source', '') == IP:
            url = SERVER_URL + DELETE_WHITELIST_IP_SUFFIX.format(CORPNAME, args['siteName'], item.get('id', ''))
            res = http_request('DELETE', url)

    if 'res' not in locals():
        raise Exception("The IP {0} was not found on the WhiteList".format(IP))

    else:
        human_readable = '### Signal Sciences - Removing an IP from Whitelist \n\n The IP has been successfully removed from Whitelist.'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
    })


def blacklist_remove_ip(siteName, IP):
    check_ip_is_valid(IP)
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    site_blacklist = http_request('GET', url)
    return site_blacklist


def blacklist_remove_ip_command():
    """Remove an ip from the blacklist"""
    args = demisto.args()
    site_blacklist = blacklist_remove_ip(args['siteName'], args['IP'])
    data = site_blacklist.get('data', [])
    IP = args['IP']
    for item in data:
        if item.get('source', '') == IP:
            url = SERVER_URL + DELETE_BLACKLIST_IP_SUFFIX.format(CORPNAME, args['siteName'], item.get('id', ''))
            res = http_request('DELETE', url)

    if 'res' not in locals():
        raise Exception("The IP {0} was not found on the BlackList".format(IP))

    else:
        human_readable = '### Signal Sciences - Removing an IP from Blacklist \n\n The IP has been successfully removed from Blacklist.'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
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

LOG('command is %s' % (demisto.command(), ))

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



except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise