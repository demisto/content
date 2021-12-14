import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import json
import requests

''' GLOBAL VARS '''
''' GLOBAL VARS '''
USE_SSL = not demisto.params().get('insecure', False)
handle_proxy()

EMAIL = demisto.params()['Email']
TOKEN = demisto.params()['Token']
CORPNAME = demisto.params()['corpName']
FETCH_INTERVAL = demisto.params()['fetch_interval']
SITES_TO_FETCH = demisto.params().get('sites_to_fetch', None)

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
SITES_LIST_TITLE = "Sites list"
ADD_IP_TO_WHITELIST_TITLE = 'Signal Sciences - Adding an IP to Whitelist'
ADD_IP_TO_BLACKLIST_TITLE = 'Signal Sciences - Adding an IP to Blacklist'
ADD_ALERT_TITLE = 'Signal Sciences - Adding a new custom alert'
UPDATE_LIST_TITLE = 'Signal Sciences - Updating a list'
ALERT_LIST_TITLE = 'Signal Sciences - Alert list'
LIST_OF_SITE_LISTS_TITLE = 'Signal Sciences - list of site lists'
LIST_OF_CORP_LISTS_TITLE = 'Signal Sciences - list of corp lists'
LIST_OF_EVENTS_TITLE = 'Signal Sciences - list of events'
LIST_OF_REQUESTS_TITLE = 'Signal Sciences - list of requests'
CREATE_SITE_LIST_TITLE = "Signal Sciences - creating a new site list \n\n List {0} has been successfully created"
CREATE_CORP_LIST_TITLE = "Signal Sciences - creating a new corp list \n\n List {0} has been successfully created"
DELETE_CORP_LIST_TITLE = "### Signal Sciences - deleting corp list \n\n List {0} has been successfully removed"
EXPIRE_EVENT_TITLE = "### Signal Sciences - expiring event \n\n Event {0} has been successfully expired"
WHITELIST_REMOVE_IP_TITLE = '### Signal Sciences - Removing an IP from Whitelist \n\n ' \
                            'The IP {0} has been successfully removed from Whitelist.'
DELETE_SITE_LIST_TITLE = "### Signal Sciences - deleting site list \n\n The list has been succesfully removed"
BLACKLIST_REMOVE_IP_TITLE = '### Signal Sciences - Removing an IP from Blacklist \n\n ' \
                            'The IP {0} has been successfully removed from Blacklist.'
IP_ADDED_TO_WHITELIST_TITLE = "The IP {0} has been successfully added to whitelist."
IP_ADDED_TO_BLACKLIST_TITLE = "The IP {0} has been successfully added to blacklist."


'''TABLE HEADERS'''
ADD_IP_HEADERS = ['Source', 'Note', 'Expiration date']
WHITELIST_OR_BLACKLIST_HEADERS = ['ID', 'Source', 'Expiry Date', 'Note', 'Created Date', 'Created By']
LIST_HEADERS = ['Name', 'ID', 'Type', 'Entries', 'Description', 'Created By', 'Created Date', 'Updated Date']
GET_SITE_HEADERS = ['Name', 'Created Date']
EVENT_HEADERS = ['ID', 'Timestamp', 'Source', 'Remote Country Code', 'Action', 'Reasons', 'Remote Hostname',
                 'User Agents', 'Request Count', 'Tag Count', 'Window', 'Date Expires', 'Expired By']
REQUEST_HEADER = ['ID', 'Timestamp', 'Remote Country Code', 'Remote Hostname', 'Remote IP', 'User Agent',
                  'Method', 'Server Name', 'Protocol', 'Path', 'URI', 'Response Code', 'Response Size',
                  'Response Millis', 'Agent Response Code', 'Tags']
ALERT_HEADERS = ['ID', 'Site ID', 'Created Date', 'Tag Name', 'Action', 'Long Name', 'Interval (In Minutes)',
                 'Threshold', 'Block Duration Seconds', 'Skip Notifications', 'Enabled']


'''List Types dict'''

LEGAL_SIGSCI_LIST_TYPES = {
    'ip',
    'country',
    'string',
    'wildcard'
}


''' HELPER FUNCTIONS '''


def camel_case_to_spaces(string_in_camel_case):
    """Given a string in camelcase, will turn it into spaces

    Args:
        string_in_camel_case(String): the string in camel case

    Returns:
        A new string, separated by spaces and every word starts with a capital letter
    """
    string_with_underscores = camel_case_to_underscore(string_in_camel_case)
    new_string_with_spaces = string_with_underscores.replace('_', ' ')
    return new_string_with_spaces.title()


def dict_keys_from_camelcase_to_spaces(dict_with_camelcase_keys):
    """Given a dict with keys in camelcase, returns a copy of it with keys in spaces (helloWorld becomes Hello World)

    Args:
        dict_with_camelcase_keys(Dictionary): the original dictionary, with keys in camelcase

    Returns:
        A new dictionary, with keys separated by spaces
    """
    dict_with_spaces_in_keys = {}
    for key in dict_with_camelcase_keys:
        key_with_spaces = camel_case_to_spaces(key)
        dict_with_spaces_in_keys[key_with_spaces] = dict_with_camelcase_keys[key]
    return dict_with_spaces_in_keys


def return_list_of_dicts_with_spaces(list_of_camelcase_dicts):
    """Given a list of dicts, iterates over it and for each dict makes all the keys with spaces instead of camelcase

    Args:
        list_of_camelcase_dicts(List): array of dictionaries

    Returns:
        A new array of dictionaries, with keys including spaces instead of camelcase
    """
    dicts_with_spaces = []
    for dict_camelcase in list_of_camelcase_dicts:
        dict_with_spaces = dict_keys_from_camelcase_to_spaces(dict_camelcase)
        dicts_with_spaces.append(dict_with_spaces)

    return dicts_with_spaces


def has_api_call_failed(res):
    """
    Note: In SigSci, if an API call fails it returns a json with only 'message' in it.
    """
    if 'message' in res:
        return True
    return False


def is_error_status(status):
    if int(status) >= 400:
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
        # Some commands in Signal Sciences require sending the data in raw, and some in format
        # To send in format, we use the 'data' argument in requests. for raw, we use the 'json' argument.
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
            return {}
        if res.status_code == 204:
            return {}
        res_json = res.json()
        if has_api_call_failed(res_json):
            return {}
        return res_json

    except Exception as e:
        LOG(e)
        raise (e)


def is_legal_list_type(list_type):
    return list_type.lower() in LEGAL_SIGSCI_LIST_TYPES


def represents_int(string_var):
    if '.' in string_var:
        return False
    if string_var[0] in ('-', '+'):
        return string_var[1:].isdigit()
    return string_var.isdigit()


def is_legal_interval_for_alert(interval):
    """
    Note: legal values for the interval on an alert are only 1, 10 or 60.
    This function verifies the value given is compatible with this demand.
    """
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
    if not (enabled.lower() == 'true' or enabled.lower() == 'false'):
        return_error("Error: Illegal value for 'enabled' argument - value must be 'True' or 'False'")
    if not (action == 'info' or action == 'flagged'):
        return_error("Error: Illegal value for 'action' argument - value must be 'info' or 'flagged'")


def validate_get_events_args(from_time, until_time, sort, limit, page, action, ip, status):
    if from_time is not None and not represents_int(str(from_time)):
        return_error("Error: from_time must be an integer.")
    if until_time is not None and not represents_int(str(until_time)):
        return_error("Error: until_time must be an integer.")
    if sort is not None and not (sort == "asc" or sort == "desc"):
        return_error("Error: sort value must be 'asc' or 'desc'.")
    if limit is not None and (not represents_int(str(limit)) or int(limit) < 0 or int(limit) > 1000):
        return_error("Error: limit must be an integer, larger than 0 and at most 1000")
    if action is not None and not (action == "flagged" or action == "info"):
        return_error("Error: action value must be 'flagged' or 'info'")
    if ip is not None and not is_ip_valid(str(ip)):
        return_error("Error: illegal value for 'ip' argument. Must be a valid ip address")
    if status is not None and not (status == 'active' or status == 'expired'):
        return_error("Error: status value must be 'active' or 'expired'")
    if page is not None and not represents_int(str(page)):
        return_error("Error: page must be an integer.")


def create_get_event_data_from_args(from_time, until_time, sort, since_id, max_id,
                                    limit, page, action, tag, ip, status):
    get_events_request_data = {}
    if from_time is not None:
        get_events_request_data['from'] = int(from_time)
    if until_time is not None:
        get_events_request_data['until'] = int(until_time)
    if sort is not None:
        get_events_request_data['sort'] = sort
    if since_id is not None:
        get_events_request_data['since_id'] = since_id
    if max_id is not None:
        get_events_request_data['max_id'] = max_id
    if limit is not None:
        get_events_request_data['limit'] = int(limit)
    if page is not None:
        get_events_request_data['page'] = int(page)
    if action is not None:
        get_events_request_data['action'] = action
    if tag is not None:
        get_events_request_data['tag'] = tag
    if ip is not None:
        get_events_request_data['ip'] = ip
    if status is not None:
        get_events_request_data['status'] = status
    return get_events_request_data


def event_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'Timestamp': response_data.get('timestamp', ''),
        'Source': response_data.get('source', ''),
        'Action': response_data.get('action', ''),
        'Reasons': response_data.get('reasons', ''),
        'RemoteCountryCode': response_data.get('remoteCountryCode', ''),
        'RemoteHostname': response_data.get('RemoteHostname', ''),
        'UserAgents': response_data.get('userAgents', ''),
        'RequestCount': response_data.get('requestCount', ''),
        'TagCount': response_data.get('tagCount', ''),
        'Window': response_data.get('window', ''),
        'DateExpires': response_data.get('expires', ''),
        'ExpiredBy': response_data.get('expiredBy', ''),
    }
    return entry_context


def adjust_event_human_readable(entry_context_with_spaces, entry_context):
    """Change keys in human readable data to match the headers.
    """
    entry_context_with_spaces["ID"] = entry_context.get("ID", "")


def validate_fetch_requests_args(page, limit):
    if limit is not None and (not represents_int(limit) or int(limit) < 0 or int(limit) > 1000):
        return_error("Error: limit must be an integer, larger than 0 and at most 1000")
    if page is not None and not represents_int(page):
        return_error("Error: page must be an integer")


def request_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'ServerHostName': response_data.get('serverHostName', ''),
        'RemoteIP': response_data.get('remoteIP', ''),
        'RemoteHostname': response_data.get('RemoteHostname', ''),
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


def adjust_request_human_readable(entry_context_with_spaces, entry_context):
    """Change keys in human readable data to match the headers.
    """
    entry_context_with_spaces["ID"] = entry_context.get("ID", "")
    entry_context_with_spaces["URI"] = entry_context.get("URI", "")
    entry_context_with_spaces["Remote IP"] = entry_context.get("RemoteIP", "")


def list_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'Name': response_data.get('name', ''),
        'Type': response_data.get('type', ''),
        'Entries': response_data.get('entries', ''),
        'Description': response_data.get('description', ''),
        'CreatedBy': response_data.get('createdBy', ''),
        'CreatedDate': response_data.get('created', ''),
        'UpdatedDate': response_data.get('updated', '')
    }
    return entry_context


def adjust_list_human_readable(entry_context_with_spaces, entry_context):
    """Change keys in human readable data to match the headers.
    """
    entry_context_with_spaces["ID"] = entry_context.get("ID", "")


def alert_entry_context_from_response(response_data):
    entry_context = {
        'ID': response_data.get('id', ''),
        'LongName': response_data.get('longName', ''),
        'SiteID': response_data.get('siteId', ''),
        'TagName': response_data.get('tagName', ''),
        'Interval': response_data.get('interval', ''),
        'Threshold': response_data.get('threshold', ''),
        'BlockDurationSeconds': response_data.get('blockDurationSeconds', ''),
        'SkipNotifications': response_data.get('skipNotifications', ''),
        'Enabled': response_data.get('enabled', ''),
        'Action': response_data.get('action', ''),
        'CreatedDate': response_data.get('created', ''),
    }
    return entry_context


def adjust_alert_human_readable(entry_context_with_spaces, entry_context):
    """Change keys in human readable data to match the headers.
    """
    entry_context_with_spaces["Interval (In Minutes)"] = entry_context_with_spaces.get("Interval", "")
    entry_context_with_spaces["ID"] = entry_context.get("ID", "")
    entry_context_with_spaces["Site ID"] = entry_context.get("siteID", "")


def check_ip_is_valid(ip):
    if not is_ip_valid(ip):
        return_error("Error: {} is invalid IP. Please enter a valid IP address".format(ip))


def gen_entries_data_for_update_list_request(entries_list, method):
    """Using the recieved args, generates the data object required by the API
    in order to update a list (site or corp alike).
    Args:
        entries_list (list): a list containing IP addresses
        method (string): The method we want to apply on the entries, either 'Add' or 'Remove'.
            States if the IPs should be added or removed to the site/corp list.

    Returns:
        dict. Contains additions and deletions list with the entries we want to act on.
    """
    entries = {
        "additions": [],
        "deletions": []
    }  # type: Dict
    entries_list_in_list_format = entries_list.split(',')
    if method == "Add":
        entries["additions"] = entries_list_in_list_format
    else:
        entries["deletions"] = entries_list_in_list_format
    return entries


def gen_context_for_add_to_whitelist_or_blacklist(response_data):
    full_data = []
    for data in response_data:
        full_data.append({
            'ID': data.get('id', ''),
            'Note': data.get('note', ''),
            'Source': data.get('source', ''),
            'CreatedBy': data.get('createdBy', ''),
            'CreatedDate': data.get('created', ''),
            'ExpiryDate': data.get('expires', '')
        })
    return full_data


def gen_human_readable_for_add_to_whitelist_or_blacklist(ip_context):
    human_readable = []
    for context in ip_context:
        human_readable.append({
            'Note': context['Note'],
            'Source': context['Source'],
            'Expiration date': context['ExpiryDate'] if context['ExpiryDate'] else "Not Set"
        })
    return human_readable


def add_ip_to_whitelist_or_blacklist(url, ip, note, expires=None):
    res_list = []
    error_list = []
    for single_ip in argToList(ip):
        try:
            check_ip_is_valid(single_ip)
            data = {
                'source': single_ip,
                'note': note
            }
            if expires is not None:
                data['expires'] = expires
            res_list.append(http_request('PUT', url, data=data))
        except SystemExit:
            # handle exceptions in return_error
            pass
        except Exception as e:
            error_list.append('failed adding ip: {} to balcklist error: {}'.format(single_ip, e))
            demisto.error('failed adding ip: {} to balcklist\n{}'.format(single_ip, traceback.format_exc()))
    return res_list, error_list


def get_all_sites_in_corp():
    get_sites_request_response = get_sites()
    data_of_sites_in_corp = get_sites_request_response.get('data', [])
    return data_of_sites_in_corp


def get_list_of_all_site_names_in_corp():
    data_of_sites_in_corp = get_all_sites_in_corp()
    list_of_all_sites_names_in_corp = []
    for site_data in data_of_sites_in_corp:
        site_name = site_data['name']
        list_of_all_sites_names_in_corp.append(site_name)
    return list_of_all_sites_names_in_corp


def get_list_of_site_names_to_fetch():
    list_of_site_names_to_fetch = None
    if SITES_TO_FETCH:
        list_of_site_names_to_fetch = SITES_TO_FETCH.split(',')
    else:
        list_of_site_names_to_fetch = get_list_of_all_site_names_in_corp()
    return list_of_site_names_to_fetch


def remove_milliseconds_from_iso(date_in_iso_format):
    date_parts_arr = date_in_iso_format.split('.')
    date_in_iso_without_milliseconds = date_parts_arr[0]
    return date_in_iso_without_milliseconds


def get_events_from_given_sites(list_of_site_names_to_fetch, desired_from_time_in_posix):
    events_from_given_sites = []  # type: List[Any]
    for site_name in list_of_site_names_to_fetch:
        fetch_from_site_response_json = get_events(siteName=site_name, from_time=desired_from_time_in_posix)

        events_fetched_from_site = fetch_from_site_response_json.get('data', [])
        events_from_given_sites.extend(events_fetched_from_site)
    return events_from_given_sites


def datetime_to_posix_without_milliseconds(datetime_object):
    timestamp_in_unix_millisecond = date_to_timestamp(datetime_object, 'datetime.datetime')
    posix_with_ms = timestamp_in_unix_millisecond
    posix_without_ms = str(posix_with_ms).split(',')[0]
    return posix_without_ms


'''COMMANDS'''


def test_module():
    try:
        url = SERVER_URL + 'corps'
        http_request('GET', url)
    except Exception as e:
        raise Exception(e.message)
    demisto.results("ok")


def create_corp_list(list_name, list_type, entries_list, description=None):
    """This method sends a request to the Signal Sciences API to create a new corp list.
    Note:
        Illegal entries (not compatible with the type) will result in a 404.
        They will be handled by the http_request function.

    Args:
        list_name (string): A name for the newly created list.
        list_type (string): The desired type for the newly created list.
        entries_list (list): A list of entries, consistent with the given type.
        description (string): A description for the newly created list.

    Returns:
        dict. The data returned from the Signal Sciences API in response to the request, loaded into a json.
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
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    human_readable = tableToMarkdown(CREATE_CORP_LIST_TITLE.format(args['list_name']), entry_context_with_spaces,
                                     headers=LIST_HEADERS, removeNull=True)

    adjust_list_human_readable(entry_context_with_spaces, entry_context)

    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.List(val.ID==obj.ID)': entry_context,
        }
    )


def get_corp_list(list_id):
    url = SERVER_URL + ACCESS_CORP_LIST_SUFFIX.format(CORPNAME, list_id)
    list_data = http_request('GET', url)
    return list_data


def get_corp_list_command():
    args = demisto.args()
    response_data = get_corp_list(args['list_id'])
    entry_context = list_entry_context_from_response(response_data)
    title = "Found data about list with ID: {0}".format(args['list_id'])
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_list_human_readable(entry_context_with_spaces, entry_context)
    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=LIST_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.List(val.ID==obj.ID)': entry_context,
        }
    )


def delete_corp_list(list_id):
    url = SERVER_URL + ACCESS_CORP_LIST_SUFFIX.format(CORPNAME, list_id)
    list_data = http_request('DELETE', url)
    return list_data


def delete_corp_list_command():
    args = demisto.args()
    response_data = delete_corp_list(args['list_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': DELETE_CORP_LIST_TITLE.format(args['list_id'])
    })


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
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_list_human_readable(entry_context_with_spaces, entry_context)
    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context_with_spaces,
                                     headers=LIST_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.List(val.ID==obj.ID)': entry_context,
        }
    )


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
    corp_lists_contexts_with_spaces = return_list_of_dicts_with_spaces(corp_lists_contexts)

    for i in range(len(corp_lists_contexts)):
        adjust_list_human_readable(corp_lists_contexts_with_spaces[i], corp_lists_contexts[i])

    human_readable = tableToMarkdown(LIST_OF_CORP_LISTS_TITLE, corp_lists_contexts_with_spaces, headers=LIST_HEADERS,
                                     removeNull=True, metadata=sidedata)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.List(val.ID==obj.ID)': corp_lists_contexts,
        }
    )


def get_events(siteName, from_time=None, until_time=None, sort=None, since_id=None, max_id=None, limit=None, page=None,
               action=None, tag=None, ip=None, status=None):

    validate_get_events_args(from_time, until_time, sort, limit, page, action, ip, status)
    url = SERVER_URL + GET_EVENTS_SUFFIX.format(CORPNAME, siteName)
    data_for_request = create_get_event_data_from_args(from_time, until_time, sort, since_id, max_id,
                                                       limit, page, action, tag, ip, status)
    events_data_response = http_request('GET', url, data=data_for_request)

    return events_data_response


def get_events_command():
    args = demisto.args()
    response_data = get_events(args['siteName'], args.get('from_time', None),
                               args.get('until_time', None), args.get('sort', None),
                               args.get('since_id', None), args.get('max_id', None),
                               args.get('limit', None), args.get('page', None),
                               args.get('action', None), args.get('tag', None),
                               args.get('ip', None), args.get('status', None))

    list_of_events = response_data.get('data', [])
    events_contexts = []
    for event_data in list_of_events:
        cur_event_context = event_entry_context_from_response(event_data)
        events_contexts.append(cur_event_context)

    events_contexts_with_spaces = return_list_of_dicts_with_spaces(events_contexts)

    for i in range(len(events_contexts)):
        adjust_list_human_readable(events_contexts_with_spaces[i], events_contexts[i])

    sidedata = "Number of events in site: {0}".format(len(list_of_events))
    human_readable = tableToMarkdown(LIST_OF_EVENTS_TITLE, events_contexts_with_spaces, removeNull=True,
                                     headers=EVENT_HEADERS, metadata=sidedata)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Event(val.ID==obj.ID)': events_contexts,
        }
    )


def get_event_by_id(siteName, event_id):
    url = SERVER_URL + ACCESS_EVENT_SUFFIX.format(CORPNAME, siteName, event_id)
    event_data_response = http_request('GET', url)
    return event_data_response


def get_event_by_id_command():
    args = demisto.args()
    response_data = get_event_by_id(args['siteName'], args['event_id'])
    entry_context = event_entry_context_from_response(response_data)
    title = "Found data about event with ID: {0}".format(args['event_id'])

    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_event_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=EVENT_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Event(val.ID==obj.ID)': entry_context,
        }
    )


def expire_event(siteName, event_id):
    url = SERVER_URL + EXPIRE_EVENT_SUFFIX.format(CORPNAME, siteName, event_id)
    event_data_response = http_request('POST', url)
    return event_data_response


def expire_event_command():
    args = demisto.args()
    response_data = expire_event(args['siteName'], args['event_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': EXPIRE_EVENT_TITLE.format(args['event_id'])
    })


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

    requests_contexts_with_spaces = return_list_of_dicts_with_spaces(requests_contexts)

    for i in range(len(requests_contexts)):
        adjust_list_human_readable(requests_contexts_with_spaces[i], requests_contexts[i])

    sidedata = "Number of requests in site: {0}".format(len(list_of_requests))
    human_readable = tableToMarkdown(LIST_OF_REQUESTS_TITLE, requests_contexts_with_spaces, headers=REQUEST_HEADER,
                                     removeNull=True, metadata=sidedata)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Request(val.ID==obj.ID)': requests_contexts,
        }
    )


def get_request_by_id(siteName, request_id):
    url = SERVER_URL + ACCESS_REQUEST_SUFFIX.format(CORPNAME, siteName, request_id)
    request_data_response = http_request('GET', url)
    return request_data_response


def get_request_by_id_command():
    args = demisto.args()
    response_data = get_request_by_id(args['siteName'], args['request_id'])
    entry_context = request_entry_context_from_response(response_data)
    title = "Found data about request with ID: {0}".format(args['request_id'])

    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_request_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=REQUEST_HEADER, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Request(val.ID==obj.ID)': entry_context,
        }
    )


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
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_list_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(CREATE_SITE_LIST_TITLE.format(args['list_name']), entry_context_with_spaces,
                                     headers=LIST_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.List(val.ID==obj.ID)': entry_context,
        }
    )


def get_site_list(siteName, list_id):
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    list_data = http_request('GET', url)
    return list_data


def get_site_list_command():
    args = demisto.args()
    response_data = get_site_list(args['siteName'], args['list_id'])
    entry_context = list_entry_context_from_response(response_data)
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_list_human_readable(entry_context_with_spaces, entry_context)

    title = "Found data about list with ID: {0}".format(args['list_id'])
    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=LIST_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.List(val.ID==obj.ID)': entry_context,
        }
    )


def delete_site_list(siteName, list_id):
    url = SERVER_URL + SITE_ACCESS_LIST_SUFFIX.format(CORPNAME, siteName, list_id)
    list_data = http_request('DELETE', url)
    return list_data


def delete_site_list_command():
    args = demisto.args()
    response_data = delete_site_list(args['siteName'], args['list_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': DELETE_SITE_LIST_TITLE.format(args['list_id'])
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
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    adjust_list_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(UPDATE_LIST_TITLE, entry_context_with_spaces,
                                     headers=LIST_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.List(val.ID==obj.ID)': entry_context,
        }
    )


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

    site_lists_contexts_with_spaces = return_list_of_dicts_with_spaces(site_lists_contexts)

    for i in range(len(site_lists_contexts)):
        adjust_list_human_readable(site_lists_contexts_with_spaces[i], site_lists_contexts[i])

    sidedata = "Number of site lists in site: {0}".format(len(list_of_site_lists))
    human_readable = tableToMarkdown(LIST_OF_SITE_LISTS_TITLE, site_lists_contexts_with_spaces, headers=LIST_HEADERS,
                                     removeNull=True, metadata=sidedata)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.List(val.ID==obj.ID)': site_lists_contexts,
        }
    )


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
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)
    # changing key of Interval to Interval (In Minutes) for human readable
    adjust_alert_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(ADD_ALERT_TITLE, entry_context_with_spaces, headers=ALERT_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Alert(val.ID==obj.ID)': entry_context,
        }
    )


def get_alert(siteName, alert_id):
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    response_data = http_request('GET', url)
    return response_data


def get_alert_command():
    args = demisto.args()
    response_data = get_alert(args['siteName'], args['alert_id'])
    entry_context = alert_entry_context_from_response(response_data)
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)

    # changing key of Interval to Interval (In Minutes) for human readable
    adjust_alert_human_readable(entry_context_with_spaces, entry_context)

    title = "Data found for alert id: {0}".format(args['alert_id'])
    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=ALERT_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Alert(val.ID==obj.ID)': entry_context,
        }
    )


def delete_alert(siteName, alert_id):
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    response_data = http_request('DELETE', url)
    return response_data


def delete_alert_command():
    args = demisto.args()
    response_data = delete_alert(args['siteName'], args['alert_id'])
    title = "Alert {0} deleted succesfully".format(args['alert_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': title
    })


def update_alert(siteName, alert_id, tag_name, long_name, interval, threshold, enabled, action):
    validate_alert_args(siteName, long_name, tag_name, interval, threshold, enabled, action)
    url = SERVER_URL + SITE_ACCESS_ALERT_SUFFIX.format(CORPNAME, siteName, alert_id)
    data_for_request = {
        'tagName': tag_name,
        'longName': long_name,
        'interval': int(interval),
        'threshold': int(threshold),
        'action': action,
        'enabled': bool(enabled)
    }
    request_response = http_request('PATCH', url, data=data_for_request)
    return request_response


def update_alert_command():
    args = demisto.args()
    response_data = update_alert(args['siteName'], args['alert_id'], args['tag_name'], args['long_name'],
                                 args['interval'], args['threshold'], args['enabled'], args['action'])
    title = "Updated alert {0}. new values:".format(args['alert_id'])
    entry_context = alert_entry_context_from_response(response_data)
    entry_context_with_spaces = dict_keys_from_camelcase_to_spaces(entry_context)

    # changing key of Interval to Interval (In Minutes) for human readable
    adjust_alert_human_readable(entry_context_with_spaces, entry_context)

    human_readable = tableToMarkdown(title, entry_context_with_spaces, headers=ALERT_HEADERS, removeNull=True)
    return_outputs(
        raw_response=response_data,
        readable_output=human_readable,
        outputs={
            'SigSciences.Corp.Site.Alert(val.ID==obj.ID)': entry_context,
        }
    )


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

    alerts_contexts_with_spaces = return_list_of_dicts_with_spaces(alerts_contexts)

    # changing key of Interval to Interval (In Minutes) for human readable in all alert contexts
    for i in range(len(alerts_contexts)):
        adjust_alert_human_readable(alerts_contexts_with_spaces[i], alerts_contexts[i])

    sidedata = "Number of alerts in site: {0}".format(len(alerts_list))
    return_outputs(
        raw_response=response_data,
        readable_output=tableToMarkdown(ALERT_LIST_TITLE, alerts_contexts_with_spaces,
                                        headers=ALERT_HEADERS, removeNull=True, metadata=sidedata),
        outputs={
            'SigSciences.Corp.Site.Alert(val.ID==obj.ID)': alerts_contexts,
        }
    )


def get_whitelist(siteName):
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    site_whitelist = http_request('GET', url)
    return site_whitelist


def get_whitelist_command():
    """Get the whitelist data for siteName"""
    args = demisto.args()
    site_whitelist = get_whitelist(args['siteName'])
    data = site_whitelist.get('data', [])
    whitelist_ips_contexts = gen_context_for_add_to_whitelist_or_blacklist(data)
    whitelist_ips_contexts_with_spaces = return_list_of_dicts_with_spaces(whitelist_ips_contexts)

    sidedata = "Number of IPs in the Whitelist {0}".format(len(data))
    return_outputs(
        raw_response=site_whitelist,
        readable_output=tableToMarkdown(WHITELIST_TITLE, whitelist_ips_contexts_with_spaces,
                                        WHITELIST_OR_BLACKLIST_HEADERS, removeNull=True, metadata=sidedata),
        outputs={
            'SigSciences.Corp.Site.Whitelist(val.ID==obj.ID)': whitelist_ips_contexts,
        }
    )


def get_blacklist(siteName):
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    site_blacklist = http_request('GET', url)
    return site_blacklist


def get_blacklist_command():
    """Get blacklist data for siteName"""
    args = demisto.args()
    site_blacklist = get_blacklist(args['siteName'])
    data = site_blacklist.get('data', [])
    blacklist_ips_contexts = gen_context_for_add_to_whitelist_or_blacklist(data)
    blacklist_ips_contexts_with_spaces = return_list_of_dicts_with_spaces(blacklist_ips_contexts)

    sidedata = "Number of IPs in the Blacklist {0}".format(len(data))
    return_outputs(
        raw_response=site_blacklist,
        readable_output=tableToMarkdown(BLACKLIST_TITLE, blacklist_ips_contexts_with_spaces,
                                        WHITELIST_OR_BLACKLIST_HEADERS, removeNull=True, metadata=sidedata),
        outputs={
            'SigSciences.Corp.Site.Blacklist(val.ID==obj.ID)': blacklist_ips_contexts,
        }
    )


def add_ip_to_whitelist(siteName, ip, note, expires=None):
    url = SERVER_URL + WHITELIST_SUFFIX.format(CORPNAME, siteName)
    return add_ip_to_whitelist_or_blacklist(url, ip, note, expires)


def add_ip_to_whitelist_command():
    """Add an ip to the whitelist"""
    args = demisto.args()
    response_data, errors_data = add_ip_to_whitelist(args['siteName'], args['ip'], args['note'], args.get('expires', None))
    if response_data:
        whitelist_ip_context = gen_context_for_add_to_whitelist_or_blacklist(response_data)
        human_readable = gen_human_readable_for_add_to_whitelist_or_blacklist(whitelist_ip_context)

        return_outputs(
            raw_response=response_data,
            readable_output=tableToMarkdown(ADD_IP_TO_WHITELIST_TITLE, human_readable, headers=ADD_IP_HEADERS,
                                            removeNull=True, metadata=IP_ADDED_TO_WHITELIST_TITLE.format(args['ip'])),
            outputs={
                'SigSciences.Corp.Site.Whitelist(val.ID==obj.ID)': whitelist_ip_context,
            }
        )
    if errors_data:
        return_error('\n'.join(errors_data))


def add_ip_to_blacklist(siteName, ip, note, expires=None):
    url = SERVER_URL + BLACKLIST_SUFFIX.format(CORPNAME, siteName)
    return add_ip_to_whitelist_or_blacklist(url, ip, note, expires)


def add_ip_to_blacklist_command():
    """Add an ip to the blacklist"""
    args = demisto.args()
    response_data, errors_data = add_ip_to_blacklist(args['siteName'], args['ip'], args['note'], args.get('expires', None))
    if response_data:
        blacklist_ip_context = gen_context_for_add_to_whitelist_or_blacklist(response_data)
        human_readable = gen_human_readable_for_add_to_whitelist_or_blacklist(blacklist_ip_context)

        return_outputs(
            raw_response=response_data,
            readable_output=tableToMarkdown(ADD_IP_TO_BLACKLIST_TITLE, human_readable,
                                            headers=ADD_IP_HEADERS, removeNull=True,
                                            metadata=IP_ADDED_TO_BLACKLIST_TITLE.format(args['ip'])),
            outputs={
                'SigSciences.Corp.Site.Blacklist(val.ID==obj.ID)': blacklist_ip_context,
            }
        )
    if errors_data:
        return_error('/n'.join(errors_data))


def whitelist_remove_ip(siteName, ip):
    check_ip_is_valid(ip)
    site_whitelist = get_whitelist(siteName)
    data = site_whitelist.get('data', [])
    for item in data:
        if item.get('source', '') == ip:
            url = SERVER_URL + DELETE_WHITELIST_IP_SUFFIX.format(CORPNAME, siteName, item.get('id', ''))
            res = http_request('DELETE', url)

    if 'res' not in locals():
        return_error("The IP {0} was not found on the Whitelist".format(ip))

    return site_whitelist


def whitelist_remove_ip_command():
    """Remove an ip from the whitelist"""
    args = demisto.args()
    response_data = whitelist_remove_ip(args['siteName'], args['IP'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': WHITELIST_REMOVE_IP_TITLE.format(args['IP']),
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
        return_error("The IP {0} was not found on the Blacklist".format(ip))

    return site_blacklist


def blacklist_remove_ip_command():
    """Remove an ip from the blacklist"""
    args = demisto.args()
    response_data = blacklist_remove_ip(args['siteName'], args['IP'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response_data,
        'HumanReadable': BLACKLIST_REMOVE_IP_TITLE.format(args['IP']),
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

    outputs_with_spaces = return_list_of_dicts_with_spaces(outputs)

    return_outputs(
        raw_response=res,
        readable_output=tableToMarkdown(SITES_LIST_TITLE, outputs_with_spaces, headers=GET_SITE_HEADERS,
                                        removeNull=True),
        outputs={
            'SigSciences.Sites(val.Name==obj.Name)': outputs,
        }
    )


def fetch_incidents():
    now_utc = datetime.utcnow()
    most_recent_event_time = None

    last_run_data = demisto.getLastRun()
    if last_run_data:
        last_run_time = last_run_data['time']
    else:
        date_time_interval_ago = now_utc - timedelta(minutes=int(FETCH_INTERVAL))
        date_time_interval_ago_posix = datetime_to_posix_without_milliseconds(date_time_interval_ago)
        last_run_time = date_time_interval_ago_posix

    list_of_sites_to_fetch = get_list_of_site_names_to_fetch()
    events_array = get_events_from_given_sites(list_of_sites_to_fetch, last_run_time)
    incidents = []
    for event in events_array:
        event_time = event['timestamp']
        event_time = datetime.strptime(event_time[:-1], "%Y-%m-%dT%H:%M:%S")
        event_time = datetime_to_posix_without_milliseconds(event_time)
        if event_time > last_run_time:
            incidents.append({
                'name': str(event['id']) + " - SignalSciences",
                'occurred': event['timestamp'],
                'rawJSON': json.dumps(event)
            })
        if event_time > most_recent_event_time:
            most_recent_event_time = event_time

    demisto.incidents(incidents)
    demisto.setLastRun({'time': most_recent_event_time})


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(),))
try:
    if not re.match(r'[0-9a-z_.-]+', CORPNAME):
        raise ValueError('Corporation Name should match the pattern [0-9a-z_.-]+')

    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
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
    elif demisto.command() == 'sigsci-get-events':
        get_events_command()
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
