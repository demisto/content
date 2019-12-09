import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import os
import json
import requests
import traceback
import urllib
from requests.exceptions import HTTPError
from copy import deepcopy

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
CREDENTIALS = demisto.params().get('credentials')
USERNAME = CREDENTIALS['identifier'] if CREDENTIALS else ''
PASSWORD = CREDENTIALS['password'] if CREDENTIALS else ''
TOKEN = demisto.params().get('token')
USE_SSL = not demisto.params().get('insecure', False)
AUTH_HEADERS = {'Content-Type': 'application/json'}
if TOKEN:
    AUTH_HEADERS['SEC'] = str(TOKEN)
OFFENSES_PER_CALL = int(demisto.params().get('offensesPerCall', 50))
OFFENSES_PER_CALL = 50 if OFFENSES_PER_CALL > 50 else OFFENSES_PER_CALL

if not TOKEN and not (USERNAME and PASSWORD):
    raise Exception('Either credentials or auth token should be provided.')

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' Header names transformation maps '''
# Format: {'OldName': 'NewName'}

OFFENSES_NAMES_MAP = {
    'follow_up': 'Followup',
    'id': 'ID',
    'description': 'Description',
    'source_address_ids': 'SourceAddress',
    'local_destination_address_ids': 'DestinationAddress',
    'remote_destination_count': 'RemoteDestinationCount',
    'start_time': 'StartTime',
    'event_count': 'EventCount',
    'magnitude': 'Magnitude',
    'last_updated_time': 'LastUpdatedTime',
    'offense_type': 'OffenseType'
}

SINGLE_OFFENSE_NAMES_MAP = {
    'credibility': 'Credibility',
    'relevance': 'Relevance',
    'severity': 'Severity',
    'assigned_to': 'AssignedTo',
    'destination_networks': 'DestinationHostname',
    'status': 'Status',
    'closing_user': 'ClosingUser',
    'closing_reason_id': 'ClosingReason',
    'close_time': 'CloseTime',
    'categories': 'Categories',
    'follow_up': 'Followup',
    'id': 'ID',
    'description': 'Description',
    'source_address_ids': 'SourceAddress',
    'local_destination_address_ids': 'DestinationAddress',
    'remote_destination_count': 'RemoteDestinationCount',
    'start_time': 'StartTime',
    'event_count': 'EventCount',
    'flow_count': 'FlowCount',
    'offense_source': 'OffenseSource',
    'magnitude': 'Magnitude',
    'last_updated_time': 'LastUpdatedTime',
    'offense_type': 'OffenseType',
    'protected': 'Protected'
}

SEARCH_ID_NAMES_MAP = {
    'search_id': 'ID',
    'status': 'Status'
}

ASSET_PROPERTIES_NAMES_MAP = {
    'Unified Name': 'Name',
    'CVSS Collateral Damage Potential': 'AggregatedCVSSScore',
    'Weight': 'Weight'
}
ASSET_PROPERTIES_ENDPOINT_NAMES_MAP = {
    'Primary OS ID': 'OS'
}

FULL_ASSET_PROPERTIES_NAMES_MAP = {
    'Compliance Notes': 'ComplianceNotes',
    'Compliance Plan': 'CompliancePlan',
    'CVSS Collateral Damage Potential': 'CollateralDamagePotential',
    'Location': 'Location',
    'Switch ID': 'SwitchID',
    'Switch Port ID': 'SwitchPort',
    'Group Name': 'GroupName',
    'Vulnerabilities': 'Vulnerabilities'
}

REFERENCE_NAMES_MAP = {
    'number_of_elements': 'NumberOfElements',
    'name': 'Name',
    'creation_time': 'CreationTime',
    'element_type': 'ElementType',
    'time_to_live': 'TimeToLive',
    'timeout_type': 'TimeoutType',
    'data': 'Data',
    'last_seen': 'LastSeen',
    'source': 'Source',
    'value': 'Value',
    'first_seen': 'FirstSeen'
}

DEVICE_MAP = {
    'asset_scanner_ids': 'AssetScannerIDs',
    'custom_properties': 'CustomProperties',
    'deleted': 'Deleted',
    'description': 'Description',
    'event_collector_ids': 'EventCollectorIDs',
    'flow_collector_ids': 'FlowCollectorIDs',
    'flow_source_ids': 'FlowSourceIDs',
    'id': 'ID',
    'log_source_ids': 'LogSourceIDs',
    'log_source_group_ids': 'LogSourceGroupIDs',
    'name': 'Name',
    'qvm_scanner_ids': 'QVMScannerIDs',
    'tenant_id': 'TenantID'
}

''' Utility methods '''


# Filters recursively null values from dictionary
def filter_dict_null(d):
    if isinstance(d, dict):
        return dict((k, filter_dict_null(v)) for k, v in d.items() if filter_dict_null(v) is not None)
    elif isinstance(d, list):
        if len(d) > 0:
            return list(map(filter_dict_null, d))
        return None
    return d


# Converts unicode elements of obj (incl. dictionary and list) to string recursively
def unicode_to_str_recur(obj):
    if isinstance(obj, dict):
        obj = {unicode_to_str_recur(k): unicode_to_str_recur(v) for k, v in obj.iteritems()}
    elif isinstance(obj, list):
        obj = map(unicode_to_str_recur, obj)
    elif isinstance(obj, unicode):
        obj = obj.encode('utf-8')
    return obj


# Converts to an str
def convert_to_str(obj):
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    try:
        return str(obj)
    except ValueError:
        return obj


# Filters recursively from dictionary (d1) all keys that do not appear in d2
def filter_dict_non_intersection_key_to_value(d1, d2):
    if isinstance(d1, list):
        return map(lambda x: filter_dict_non_intersection_key_to_value(x, d2), d1)
    elif isinstance(d1, dict) and isinstance(d2, dict):
        d2values = d2.values()
        return dict((k, v) for k, v in d1.items() if k in d2values)
    return d1


# Change the keys of a dictionary according to a conversion map
# trans_map - { 'OldKey': 'NewKey', ...}
def replace_keys(src, trans_map):
    def replace(key, trans_map):
        if key in trans_map:
            return trans_map[key]
        return key

    if trans_map:
        if isinstance(src, list):
            return map(lambda x: replace_keys(x, trans_map), src)
        else:
            src = {replace(k, trans_map): v for k, v in src.iteritems()}
    return src


# Transforms flat dictionary to comma separated values
def dict_values_to_comma_separated_string(dic):
    return ','.join(convert_to_str(v) for v in dic.itervalues())


# Sends request to the server using the given method, url, headers and params
def send_request(method, url, headers=AUTH_HEADERS, params=None):
    try:
        log_hdr = deepcopy(headers)
        log_hdr.pop('SEC', None)
        LOG('qradar is attempting {method} request sent to {url} with headers:\n{headers}\nparams:\n{params}'
            .format(method=method, url=url, headers=json.dumps(log_hdr, indent=4), params=json.dumps(params, indent=4)))
        if TOKEN:
            res = requests.request(method, url, headers=headers, params=params, verify=USE_SSL)
        else:
            res = requests.request(method, url, headers=headers, params=params, verify=USE_SSL,
                                   auth=(USERNAME, PASSWORD))
        res.raise_for_status()
    except HTTPError:
        err_json = res.json()
        err_msg = ''
        if 'message' in err_json:
            err_msg = err_msg + 'Error: {0}.\n'.format(err_json['message'])
        elif 'http_response' in err_json:
            err_msg = err_msg + 'Error: {0}.\n'.format(err_json['http_response'])
        if 'code' in err_json:
            err_msg = err_msg + 'QRadar Error Code: {0}'.format(err_json['code'])
        raise Exception(err_msg)
    return res.json()


# Generic function that receives a result json, and turns it into an entryObject
def get_entry_for_object(title, obj, contents, headers=None, context_key=None, human_readable=None):
    if len(obj) == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': contents,
            'ContentsFormat': formats['json'],
            'HumanReadable': "There is no output result"
        }
    obj = filter_dict_null(obj)
    if headers:
        if isinstance(headers, str):
            headers = headers.split(',')
        if isinstance(obj, dict):
            headers = list(set(headers).intersection(set(obj.keys())))
    ec = {context_key: obj} if context_key else obj
    return {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable if human_readable else tableToMarkdown(title, obj, headers),
        'EntryContext': ec
    }


# Converts epoch (miliseconds) to ISO string
def epoch_to_ISO(ms_passed_since_epoch):
    if ms_passed_since_epoch >= 0:
        return datetime.utcfromtimestamp(ms_passed_since_epoch / 1000.0).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return ms_passed_since_epoch


# Converts closing reason name to id
def convert_closing_reason_name_to_id(closing_name, closing_reasons=None):
    if not closing_reasons:
        closing_reasons = get_closing_reasons(include_deleted=True, include_reserved=True)
    for closing_reason in closing_reasons:
        if closing_reason['text'] == closing_name:
            return closing_reason['id']
    return closing_name


# Converts closing reason id to name
def convert_closing_reason_id_to_name(closing_id, closing_reasons=None):
    if not closing_reasons:
        closing_reasons = get_closing_reasons(include_deleted=True, include_reserved=True)
    for closing_reason in closing_reasons:
        if closing_reason['id'] == closing_id:
            return closing_reason['text']
    return closing_id


# Converts offense type id to name
def convert_offense_type_id_to_name(offense_type_id, offense_types=None):
    if not offense_types:
        offense_types = get_offense_types()
    if offense_types:
        for o_type in offense_types:
            if o_type['id'] == offense_type_id:
                return o_type['name']
    return offense_type_id


''' Request/Response methods '''


# Returns the result of an offenses request
def get_offenses(_range, _filter='', _fields=''):
    full_url = '{0}/api/siem/offenses'.format(SERVER)
    params = {'filter': _filter} if _filter else {}
    headers = dict(AUTH_HEADERS)
    if _fields:
        params['fields'] = _fields
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', full_url, headers, params)


# Returns the result of a single offense request
def get_offense_by_id(offense_id, _filter='', _fields=''):
    full_url = '{0}/api/siem/offenses/{1}'.format(SERVER, offense_id)
    params = {"filter": _filter} if _filter else {}
    headers = dict(AUTH_HEADERS)
    if _fields:
        params['fields'] = _fields
    return send_request('GET', full_url, headers, params)


# Updates a single offense and returns the updated offense
def update_offense(offense_id):
    url = '{0}/api/siem/offenses/{1}'.format(SERVER, offense_id)
    return send_request('POST', url, params=demisto.args())


# Posts a search in QRadar and returns the search object
def search(args):
    url = '{0}/api/ariel/searches'.format(SERVER)
    return send_request('POST', url, AUTH_HEADERS, params=args)


# Returns a search object (doesn't contain reuslt)
def get_search(search_id):
    url = '{0}/api/ariel/searches/{1}'.format(SERVER, convert_to_str(search_id))
    return send_request('GET', url, AUTH_HEADERS)


# Returns a search result
def get_search_results(search_id, _range=''):
    url = '{0}/api/ariel/searches/{1}/results'.format(SERVER, convert_to_str(search_id))
    headers = dict(AUTH_HEADERS)
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', url, headers)


# Returns the result of an assets request
def get_assets(_range='', _filter='', _fields=''):
    url = '{0}/api/asset_model/assets'.format(SERVER)
    params = {"filter": _filter} if _filter else {}
    headers = dict(AUTH_HEADERS)
    if _fields:
        params['fields'] = _fields
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', url, headers, params)


# Returns the result of a closing reasons request
def get_closing_reasons(_range='', _filter='', _fields='', include_deleted=False, include_reserved=False):
    url = '{0}/api/siem/offense_closing_reasons'.format(SERVER)
    params = {}
    if _filter:
        params['filter'] = _filter
    if include_deleted:
        params['include_deleted'] = include_deleted
    if include_reserved:
        params['include_reserved'] = include_reserved
    headers = AUTH_HEADERS
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', url, headers, params)


# Returns the result of a offense types request
def get_offense_types():
    url = '{0}/api/siem/offense_types'.format(SERVER)
    # Due to a bug in QRadar, this functions does not work if username/password was not provided
    if USERNAME and PASSWORD:
        return send_request('GET', url)
    return {}


# Returns the result of a get note request
def get_note(offense_id, note_id, fields):
    if note_id:
        url = '{0}/api/siem/offenses/{1}/notes/{2}'.format(SERVER, offense_id, note_id)
    else:
        url = '{0}/api/siem/offenses/{1}/notes'.format(SERVER, offense_id)
    params = {'fields': fields} if fields else {}
    return send_request('GET', url, AUTH_HEADERS, params=params)


# Creates a note and returns the note as a result
def create_note(offense_id, note_text, fields):
    url = '{0}/api/siem/offenses/{1}/notes'.format(SERVER, offense_id)
    params = {'fields': fields} if fields else {}
    params['note_text'] = note_text
    return send_request('POST', url, AUTH_HEADERS, params=params)


# Returns the result of a reference request
def get_reference_by_name(ref_name, _range='', _filter='', _fields=''):
    url = '{0}/api/reference_data/sets/{1}'.format(SERVER, urllib.quote(convert_to_str(ref_name), safe=''))
    params = {'filter': _filter} if _filter else {}
    headers = dict(AUTH_HEADERS)
    if _fields:
        params['fields'] = _fields
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', url, headers, params=params)


def create_reference_set(ref_name, element_type, timeout_type, time_to_live):
    url = '{0}/api/reference_data/sets'.format(SERVER)
    params = {'name': ref_name, 'element_type': element_type}
    if timeout_type:
        params['timeout_type'] = timeout_type
    if time_to_live:
        params['time_to_live'] = time_to_live
    return send_request('POST', url, params=params)


def delete_reference_set(ref_name):
    url = '{0}/api/reference_data/sets/{1}'.format(SERVER, urllib.quote(convert_to_str(ref_name), safe=''))
    return send_request('DELETE', url)


def update_reference_set_value(ref_name, value, source=None):
    url = '{0}/api/reference_data/sets/{1}'.format(SERVER, urllib.quote(convert_to_str(ref_name), safe=''))
    params = {'name': ref_name, 'value': value}
    if source:
        params['source'] = source
    return send_request('POST', url, params=params)


def delete_reference_set_value(ref_name, value):
    url = '{0}/api/reference_data/sets/{1}/{2}'.format(SERVER, urllib.quote(convert_to_str(ref_name), safe=''),
                                                       urllib.quote(convert_to_str(value), safe=''))
    params = {'name': ref_name, 'value': value}
    return send_request('DELETE', url, params=params)


def get_devices(_range='', _filter='', _fields=''):
    url = '{0}/api/config/domain_management/domains'.format(SERVER)
    params = {'filter': _filter} if _filter else {}
    headers = dict(AUTH_HEADERS)
    if _fields:
        params['fields'] = _fields
    if _range:
        headers['Range'] = 'items={0}'.format(_range)
    return send_request('GET', url, headers, params=params)


def get_domains_by_id(domain_id, _fields=''):
    url = '{0}/api/config/domain_management/domains/{1}'.format(SERVER, domain_id)
    headers = dict(AUTH_HEADERS)
    params = {'fields': _fields} if _fields else {}
    return send_request('GET', url, headers, params=params)


''' Command methods '''


def test_module():
    get_offenses('0-0')
    # If encountered error, send_request will return_error
    return 'ok'


def fetch_incidents():
    query = demisto.params().get('query')
    last_run = demisto.getLastRun()
    offense_id = last_run['id'] if last_run and 'id' in last_run else 0
    if last_run and offense_id == 0:
        start_time = last_run['startTime'] if 'startTime' in last_run else '0'
        fetch_query = 'start_time>{0}{1}'.format(start_time, ' AND ({0})'.format(query) if query else '')
    else:
        fetch_query = 'id>{0} {1}'.format(offense_id, 'AND ({0})'.format(query) if query else '')
        # qradar returns offenses sorted desc on id and there's no way to change sorting.
        # if we get `offensesPerCall` offenses it means we (probably) have more than that so we
        # start looking for the end of the list by doubling the page position until we're empty.
        # then start binary search back until you find the end of the list and finally return
        # `offensesPerCall` from the end.
    raw_offenses = get_offenses(_range='0-{0}'.format(OFFENSES_PER_CALL), _filter=fetch_query)
    if len(raw_offenses) >= OFFENSES_PER_CALL:
        last_offense_pos = find_last_page_pos(fetch_query)
        raw_offenses = get_offenses(_range='{0}-{1}'.format(last_offense_pos - OFFENSES_PER_CALL + 1, last_offense_pos),
                                    _filter=fetch_query)
    raw_offenses = unicode_to_str_recur(raw_offenses)
    incidents = []
    enrich_offense_res_with_source_and_destination_address(raw_offenses)
    for offense in raw_offenses:
        offense_id = max(offense_id, offense['id'])
        incidents.append(create_incident_from_offense(offense))
    demisto.setLastRun({'id': offense_id})
    return incidents


# Finds the last page position for QRadar query that receives a range parameter
def find_last_page_pos(fetch_query):
    # Make sure it wasn't a fluke we have exactly OFFENSES_PER_CALL results
    if len(get_offenses(_range='{0}-{0}'.format(OFFENSES_PER_CALL), _filter=fetch_query)) == 0:
        return OFFENSES_PER_CALL - 1
    # Search up until we don't have any more results
    pos = OFFENSES_PER_CALL * 2
    while len(get_offenses(_range='{0}-{0}'.format(pos), _filter=fetch_query)) == 1:
        pos = pos * 2
    # Binary search the gap from the las step
    high = pos
    low = pos / 2
    while high > low + 1:
        pos = (high + low) / 2
        if len(get_offenses(_range='{0}-{0}'.format(pos), _filter=fetch_query)) == 1:
            # we still have results, raise the bar
            low = pos
        else:
            # we're too high, lower the bar
            high = pos
    # low holds the last pos of the list
    return low


# Creates incidents from offense
def create_incident_from_offense(offense):
    occured = epoch_to_ISO(offense['start_time'])
    keys = offense.keys()
    labels = []
    for i in range(len(keys)):
        labels.append({'type': keys[i], 'value': convert_to_str(offense[keys[i]])})
    return {
        'name': '{0} {1}'.format(offense['id'], offense['description']),
        'labels': labels,
        'rawJSON': json.dumps(offense),
        'occurred': occured
    }


def get_offenses_command():
    raw_offenses = get_offenses(demisto.args().get('range'), demisto.args().get('filter'), demisto.args().get('fields'))
    offenses = deepcopy(raw_offenses)
    enrich_offense_result(offenses)
    offenses = filter_dict_non_intersection_key_to_value(replace_keys(offenses, OFFENSES_NAMES_MAP), OFFENSES_NAMES_MAP)

    # prepare for printing:
    headers = demisto.args().get('headers')
    if not headers:
        offenses_names_map_cpy = dict(OFFENSES_NAMES_MAP)
        offenses_names_map_cpy.pop('id', None)
        offenses_names_map_cpy.pop('description', None)
        headers = 'ID,Description,' + dict_values_to_comma_separated_string(offenses_names_map_cpy)

    return get_entry_for_object('QRadar offenses', offenses, raw_offenses, headers, 'QRadar.Offense(val.ID === obj.ID)')


# Enriches the values of a given offense result (full_enrichment adds more enrichment options)
def enrich_offense_result(response, full_enrichment=False):
    enrich_offense_res_with_source_and_destination_address(response)
    if isinstance(response, list):
        type_dict = get_offense_types()
        closing_reason_dict = get_closing_reasons(include_deleted=True, include_reserved=True)
        for offense in response:
            enrich_single_offense_result(offense, full_enrichment, type_dict, closing_reason_dict)
    else:
        enrich_single_offense_result(response, full_enrichment)

    return response


# Convert epoch to iso and closing_reason_id to closing reason name, and if full_enrichment then converts
# closing_reason_id to name
def enrich_single_offense_result(offense, full_enrichment, type_dict=None, closing_reason_dict=None):
    enrich_offense_times(offense)
    if 'offense_type' in offense:
        offense['offense_type'] = convert_offense_type_id_to_name(offense['offense_type'], type_dict)
    if full_enrichment and 'closing_reason_id' in offense:
        offense['closing_reason_id'] = convert_closing_reason_id_to_name(offense['closing_reason_id'],
                                                                         closing_reason_dict)


# Enriches offense result dictionary with source and destination addresses
def enrich_offense_res_with_source_and_destination_address(response):
    src_adrs, dst_adrs = extract_source_and_destination_addresses_ids(response)
    # This command might encounter HTML error page in certain cases instead of JSON result. Fallback: cancel the
    # enrichment
    try:
        if src_adrs:
            enrich_source_addresses_dict(src_adrs)
        if dst_adrs:
            enrich_destination_addresses_dict(dst_adrs)
        if isinstance(response, list):
            for offense in response:
                enrich_single_offense_res_with_source_and_destination_address(offense, src_adrs, dst_adrs)
        else:
            enrich_single_offense_res_with_source_and_destination_address(response, src_adrs, dst_adrs)
    # The function is meant to be safe, so it shouldn't raise any error
    finally:
        return response


# Helper method: Extracts all source and destination addresses ids from an offense result
def extract_source_and_destination_addresses_ids(response):
    src_ids = {}  # type: dict
    dst_ids = {}  # type: dict
    if isinstance(response, list):
        for offense in response:
            populate_src_and_dst_dicts_with_single_offense(offense, src_ids, dst_ids)
    else:
        populate_src_and_dst_dicts_with_single_offense(response, src_ids, dst_ids)

    return src_ids, dst_ids


# Helper method: Populates source and destination id dictionaries with the id key/values
def populate_src_and_dst_dicts_with_single_offense(offense, src_ids, dst_ids):
    if 'source_address_ids' in offense and isinstance(offense['source_address_ids'], list):
        for source_id in offense['source_address_ids']:
            src_ids[source_id] = source_id
    if 'local_destination_address_ids' in offense and isinstance(offense['local_destination_address_ids'], list):
        for destination_id in offense['local_destination_address_ids']:
            dst_ids[destination_id] = destination_id
    return None


# Helper method: Enriches the source addresses ids dictionary with the source addresses values corresponding to the ids
def enrich_source_addresses_dict(src_adrs):
    src_ids_str = dict_values_to_comma_separated_string(src_adrs)
    source_url = '{0}/api/siem/source_addresses?filter=id in ({1})'.format(SERVER, src_ids_str)
    src_res = send_request('GET', source_url, AUTH_HEADERS)
    for src_adr in src_res:
        src_adrs[src_adr['id']] = convert_to_str(src_adr['source_ip'])
    return src_adrs


# Helper method: Enriches the destination addresses ids dictionary with the source addresses values corresponding to
# the ids
def enrich_destination_addresses_dict(dst_adrs):
    dst_ids_str = dict_values_to_comma_separated_string(dst_adrs)
    destination_url = '{0}/api/siem/local_destination_addresses?filter=id in ({1})'.format(SERVER, dst_ids_str)
    dst_res = send_request('GET', destination_url, AUTH_HEADERS)
    for dst_adr in dst_res:
        dst_adrs[dst_adr['id']] = convert_to_str(dst_adr['local_destination_ip'])
    return dst_adrs


# Helper method: For a single offense replaces the source and destination ids with the actual addresses
def enrich_single_offense_res_with_source_and_destination_address(offense, src_adrs, dst_adrs):
    if isinstance(offense.get('source_address_ids'), list):
        for i in range(len(offense['source_address_ids'])):
            offense['source_address_ids'][i] = src_adrs[offense['source_address_ids'][i]]
    if isinstance(offense.get('local_destination_address_ids'), list):
        for i in range(len(offense['local_destination_address_ids'])):
            offense['local_destination_address_ids'][i] = dst_adrs[offense['local_destination_address_ids'][i]]

    return None


# Helper method: For a single offense replaces the epoch times with ISO string
def enrich_offense_times(offense):
    if 'start_time' in offense:
        offense['start_time'] = epoch_to_ISO(offense['start_time'])
    if 'last_updated_time' in offense:
        offense['last_updated_time'] = epoch_to_ISO(offense['last_updated_time'])
    if offense.get('close_time'):
        offense['close_time'] = epoch_to_ISO(offense['close_time'])

    return None


def get_offense_by_id_command():
    offense_id = demisto.args().get('offense_id')
    raw_offense = get_offense_by_id(offense_id, demisto.args().get('filter'), demisto.args().get('fields'))
    offense = deepcopy(raw_offense)
    enrich_offense_result(offense, full_enrichment=True)
    offense = filter_dict_non_intersection_key_to_value(replace_keys(offense, SINGLE_OFFENSE_NAMES_MAP),
                                                        SINGLE_OFFENSE_NAMES_MAP)
    return get_entry_for_object('QRadar Offenses', offense, raw_offense, demisto.args().get('headers'),
                                'QRadar.Offense(val.ID === obj.ID)')


def update_offense_command():
    args = demisto.args()
    if 'closing_reason_name' in args:
        args['closing_reason_id'] = convert_closing_reason_name_to_id(args.get('closing_reason_name'))
    elif 'CLOSED' == args.get('status') and not args.get('closing_reason_id'):
        raise ValueError(
            'Invalid input - must provide closing reason name or id (may use "qradar-get-closing-reasons" command to '
            'get them) to close offense')
    offense_id = args.get('offense_id')
    raw_offense = update_offense(offense_id)
    offense = deepcopy(raw_offense)
    enrich_offense_result(offense, full_enrichment=True)
    offense = filter_dict_non_intersection_key_to_value(replace_keys(offense, SINGLE_OFFENSE_NAMES_MAP),
                                                        SINGLE_OFFENSE_NAMES_MAP)
    return get_entry_for_object('QRadar Offense', offense, raw_offense, demisto.args().get('headers'),
                                'QRadar.Offense(val.ID === obj.ID)')


def search_command():
    raw_search = search(demisto.args())
    search_res = deepcopy(raw_search)
    search_res = filter_dict_non_intersection_key_to_value(replace_keys(search_res, SEARCH_ID_NAMES_MAP),
                                                           SEARCH_ID_NAMES_MAP)
    return get_entry_for_object('QRadar Search', search_res, raw_search, demisto.args().get('headers'),
                                'QRadar.Search(val.ID === obj.ID)')


def get_search_command():
    search_id = demisto.args().get('search_id')
    raw_search = get_search(search_id)
    search = deepcopy(raw_search)
    search = filter_dict_non_intersection_key_to_value(replace_keys(search, SEARCH_ID_NAMES_MAP), SEARCH_ID_NAMES_MAP)
    return get_entry_for_object('QRadar Search Info', search, raw_search, demisto.args().get('headers'),
                                'QRadar.Search(val.ID === "{0}")'.format(search_id))


def get_search_results_command():
    search_id = demisto.args().get('search_id')
    raw_search_results = get_search_results(search_id, demisto.args().get('range'))
    result_key = raw_search_results.keys()[0]
    title = 'QRadar Search Results from {}'.format(convert_to_str(result_key))
    context_key = demisto.args().get('output_path') if demisto.args().get(
        'output_path') else 'QRadar.Search(val.ID === "{0}").Result.{1}'.format(search_id, result_key)
    context_obj = unicode_to_str_recur(raw_search_results[result_key])
    human_readable = tableToMarkdown(title, context_obj, None).replace('\t', ' ')
    return get_entry_for_object(title, context_obj, raw_search_results, demisto.args().get('headers'), context_key,
                                human_readable=human_readable)


def get_assets_command():
    raw_assets = get_assets(demisto.args().get('range'), demisto.args().get('filter'), demisto.args().get('fields'))
    assets_result, human_readable_res = create_assets_result(deepcopy(raw_assets))
    return get_entry_for_assets('QRadar Assets', assets_result, raw_assets, human_readable_res,
                                demisto.args().get('headers'))


def get_asset_by_id_command():
    _filter = "id=" + convert_to_str(demisto.args().get('asset_id'))
    raw_asset = get_assets(_filter=_filter)
    asset_result, human_readable_res = create_assets_result(deepcopy(raw_asset), full_values=True)
    return get_entry_for_assets('QRadar Asset', asset_result, raw_asset, human_readable_res,
                                demisto.args().get('headers'))


# Specific implementation for assets commands, that turns asset result to entryObject
def get_entry_for_assets(title, obj, contents, human_readable_obj, headers=None):
    if len(obj) == 0:
        return "There is no output result"
    obj = filter_dict_null(obj)
    human_readable_obj = filter_dict_null(human_readable_obj)
    if headers:
        if isinstance(headers, str):
            headers = headers.split(',')
        headers = list(filter(lambda x: x in headers, list_entry) for list_entry in human_readable_obj)
    human_readable_md = ''
    for k, h_obj in human_readable_obj.iteritems():
        human_readable_md = human_readable_md + tableToMarkdown(k, h_obj, headers)
    return {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "### {0}\n{1}".format(title, human_readable_md),
        'EntryContext': obj
    }


def create_assets_result(assets, full_values=False):
    trans_assets = {}
    human_readable_trans_assets = {}
    endpoint_dict = create_empty_endpoint_dict(full_values)
    for asset in assets:
        asset_key = 'QRadar.Asset(val.ID === "{0}")'.format(asset['id'])
        human_readable_key = 'Asset(ID:{0})'.format(asset['id'])
        populated_asset = create_single_asset_result_and_enrich_endpoint_dict(asset, endpoint_dict, full_values)
        trans_assets[asset_key] = populated_asset
        human_readable_trans_assets[human_readable_key] = transform_single_asset_to_hr(populated_asset)
    # Adding endpoints context items
    trans_assets['Endpoint'] = endpoint_dict
    human_readable_trans_assets['Endpoint'] = endpoint_dict
    return trans_assets, human_readable_trans_assets


def transform_single_asset_to_hr(asset):
    """
    Prepares asset for human readable
    """
    hr_asset = []
    for k, v in asset.iteritems():
        if isinstance(v, dict):
            hr_item = v
            hr_item['Property Name'] = k
            hr_asset.append(hr_item)
    return hr_asset


def create_single_asset_result_and_enrich_endpoint_dict(asset, endpoint_dict, full_values):
    asset_dict = {'ID': asset['id']}
    for interface in asset['interfaces']:
        if full_values:
            endpoint_dict['MACAddress'].append(interface['mac_address'])
        for ip_address in interface['ip_addresses']:
            endpoint_dict['IPAddress'].append(ip_address['value'])
    if full_values:
        domain_name = get_domain_name(asset['domain_id'])
        endpoint_dict['Domain'].append(domain_name)
    # Adding values found in properties of the asset
    enrich_dict_using_asset_properties(asset, asset_dict, endpoint_dict, full_values)
    return asset_dict


def enrich_dict_using_asset_properties(asset, asset_dict, endpoint_dict, full_values):
    for prop in asset['properties']:
        if prop['name'] in ASSET_PROPERTIES_NAMES_MAP:
            asset_dict[ASSET_PROPERTIES_NAMES_MAP[prop['name']]] = {'Value': prop['value'],
                                                                    'LastUser': prop['last_reported_by']}
        elif prop['name'] in ASSET_PROPERTIES_ENDPOINT_NAMES_MAP:
            endpoint_dict[ASSET_PROPERTIES_ENDPOINT_NAMES_MAP[prop['name']]] = prop['value']
        elif full_values:
            if prop['name'] in FULL_ASSET_PROPERTIES_NAMES_MAP:
                asset_dict[FULL_ASSET_PROPERTIES_NAMES_MAP[prop['name']]] = {'Value': prop['value'],
                                                                             'LastUser': prop['last_reported_by']}
    return None


# Creates an empty endpoint dictionary (for use in other methods)
def create_empty_endpoint_dict(full_values):
    endpoint_dict = {'IPAddress': [], 'OS': []}  # type: dict
    if full_values:
        endpoint_dict['MACAddress'] = []
        endpoint_dict['Domain'] = []
    return endpoint_dict


# Retrieves domain name using domain id
def get_domain_name(domain_id):
    try:
        query_param = {
            'query_expression': "SELECT DOMAINNAME({0}) AS 'Domain name' FROM events GROUP BY 'Domain name'".format(
                domain_id)}
        search_id = search(query_param)['search_id']
        return get_search_results(search_id)['events'][0]['Domain name']
    except Exception as e:
        demisto.results({
            'Type': 11,
            'Contents': 'No Domain name was found.{error}'.format(error=str(e)),
            'ContentsFormat': formats['text']
        })
        return domain_id


def get_closing_reasons_command():
    args = demisto.args()
    closing_reasons_map = {
        'id': 'ID',
        'text': 'Name',
        'is_reserved': 'IsReserved',
        'is_deleted': 'IsDeleted'
    }
    raw_closing_reasons = get_closing_reasons(args.get('range'), args.get('filter'), args.get('fields'),
                                              args.get('include_deleted'), args.get('include_reserved'))
    closing_reasons = replace_keys(raw_closing_reasons, closing_reasons_map)

    # prepare for printing:
    closing_reasons_map.pop('id', None)
    closing_reasons_map.pop('text', None)
    headers = 'ID,Name,' + dict_values_to_comma_separated_string(closing_reasons_map)

    return get_entry_for_object('Offense Closing Reasons', closing_reasons, raw_closing_reasons,
                                context_key='QRadar.Offense.ClosingReasons', headers=headers)


def get_note_command():
    raw_note = get_note(demisto.args().get('offense_id'), demisto.args().get('note_id'), demisto.args().get('fields'))
    note_names_map = {
        'id': 'ID',
        'note_text': 'Text',
        'create_time': 'CreateTime',
        'username': 'CreatedBy'
    }
    notes = replace_keys(raw_note, note_names_map)
    if not isinstance(notes, list):
        notes = [notes]
    for note in notes:
        if 'CreateTime' in note:
            note['CreateTime'] = epoch_to_ISO(note['CreateTime'])
    return get_entry_for_object('QRadar note for offense: {0}'.format(str(demisto.args().get('offense_id'))), notes,
                                raw_note, demisto.args().get('headers'),
                                'QRadar.Note(val.ID === "{0}")'.format(demisto.args().get('note_id')))


def create_note_command():
    raw_note = create_note(demisto.args().get('offense_id'), demisto.args().get('note_text'),
                           demisto.args().get('fields'))
    note_names_map = {
        'id': 'ID',
        'note_text': 'Text',
        'create_time': 'CreateTime',
        'username': 'CreatedBy'
    }
    note = replace_keys(raw_note, note_names_map)
    note['CreateTime'] = epoch_to_ISO(note['CreateTime'])
    return get_entry_for_object('QRadar Note', note, raw_note, demisto.args().get('headers'), 'QRadar.Note')


def get_reference_by_name_command():
    raw_ref = get_reference_by_name(demisto.args().get('ref_name'))
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    convert_date_elements = True if demisto.args().get('date_value') == 'True' and ref[
        'ElementType'] == 'DATE' else False
    enrich_reference_set_result(ref, convert_date_elements)
    return get_entry_for_reference_set(ref)


def enrich_reference_set_result(ref, convert_date_elements=False):
    if 'Data' in ref:
        ref['Data'] = replace_keys(ref['Data'], REFERENCE_NAMES_MAP)
        for item in ref['Data']:
            item['FirstSeen'] = epoch_to_ISO(item['FirstSeen'])
            item['LastSeen'] = epoch_to_ISO(item['LastSeen'])
            if convert_date_elements:
                try:
                    item['Value'] = epoch_to_ISO(int(item['Value']))
                except ValueError:
                    pass
    if 'CreationTime' in ref:
        ref['CreationTime'] = epoch_to_ISO(ref['CreationTime'])
    return ref


def get_entry_for_reference_set(ref, title='QRadar References'):
    ref_cpy = deepcopy(ref)
    data = ref_cpy.pop('Data', None)
    ec_key = 'QRadar.Reference(val.Name === obj.Name)'
    entry = get_entry_for_object(title, ref_cpy, ref, demisto.args().get('headers'), ec_key)
    # Add another table for the data values
    if data:
        entry['HumanReadable'] = entry['HumanReadable'] + tableToMarkdown("Reference Items", data)
        entry['EntryContext'][ec_key]['Data'] = data
    return entry


def create_reference_set_command():
    args = demisto.args()
    raw_ref = create_reference_set(args.get('ref_name'), args.get('element_type'), args.get('timeout_type'),
                                   args.get('time_to_live'))
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(ref)


def delete_reference_set_command():
    ref_name = demisto.args().get('ref_name')
    raw_ref = delete_reference_set(ref_name)
    return {
        'Type': entryTypes['note'],
        'Contents': raw_ref,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Reference Data Deletion Task for '{0}' was initiated. Reference set '{0}' should be deleted "
                         "shortly.".format(ref_name)
    }


def update_reference_set_value_command():
    args = demisto.args()
    if args.get('date_value') == 'True':
        value = date_to_timestamp(args.get('value'), date_format="%Y-%m-%dT%H:%M:%S.%f000Z")
    else:
        value = args.get('value')
    raw_ref = update_reference_set_value(args.get('ref_name'), value, args.get('source'))
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(ref, title='Element value was updated successfully in reference set:')


def delete_reference_set_value_command():
    args = demisto.args()
    if args.get('date_value') == 'True':
        value = date_to_timestamp(args.get('value'), date_format="%Y-%m-%dT%H:%M:%S.%f000Z")
    else:
        value = args.get('value')
    raw_ref = delete_reference_set_value(args.get('ref_name'), value)
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(ref, title='Element value was deleted successfully in reference set:')


def get_domains_command():
    args = demisto.args()
    raw_domains = get_devices(args.get('range'), args.get('filter'), args.get('fields'))
    domains = []

    for raw_domain in raw_domains:
        domain = replace_keys(raw_domain, DEVICE_MAP)
        domains.append(domain)
    if len(domains) == 0:
        return demisto.results('No Domains Found')
    else:
        ec = {'QRadar.Domains': createContext(domains, removeNull=True)}
        return {
            'Type': entryTypes['note'],
            'Contents': domains,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Domains Found', domains),
            'EntryContext': ec
        }


def get_domains_by_id_command():
    args = demisto.args()
    raw_domains = get_domains_by_id(args.get('id'), args.get('fields'))
    formatted_domain = replace_keys(raw_domains, DEVICE_MAP)

    if len(formatted_domain) == 0:
        return demisto.results('No Domain Found')
    else:
        ec = {'QRadar.Domains': createContext(formatted_domain, removeNull=True)}
        return {
            'Type': entryTypes['note'],
            'Contents': raw_domains,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Domains Found', formatted_domain, removeNull=True),
            'EntryContext': ec
        }


# Command selector
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        demisto.results(test_module())
    elif demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents())
    elif demisto.command() in ['qradar-offenses', 'qr-offenses']:
        demisto.results(get_offenses_command())
    elif demisto.command() == 'qradar-offense-by-id':
        demisto.results(get_offense_by_id_command())
    elif demisto.command() in ['qradar-update-offense', 'qr-update-offense']:
        demisto.results(update_offense_command())
    elif demisto.command() in ['qradar-searches', 'qr-searches']:
        demisto.results(search_command())
    elif demisto.command() in ['qradar-get-search', 'qr-get-search']:
        demisto.results(get_search_command())
    elif demisto.command() in ['qradar-get-search-results', 'qr-get-search-results']:
        demisto.results(get_search_results_command())
    elif demisto.command() in ['qradar-get-assets', 'qr-get-assets']:
        demisto.results(get_assets_command())
    elif demisto.command() == 'qradar-get-asset-by-id':
        demisto.results(get_asset_by_id_command())
    elif demisto.command() == 'qradar-get-closing-reasons':
        demisto.results(get_closing_reasons_command())
    elif demisto.command() == 'qradar-get-note':
        demisto.results(get_note_command())
    elif demisto.command() == 'qradar-create-note':
        demisto.results(create_note_command())
    elif demisto.command() == 'qradar-get-reference-by-name':
        demisto.results(get_reference_by_name_command())
    elif demisto.command() == 'qradar-create-reference-set':
        demisto.results(create_reference_set_command())
    elif demisto.command() == 'qradar-delete-reference-set':
        demisto.results(delete_reference_set_command())
    elif demisto.command() in ('qradar-create-reference-set-value', 'qradar-update-reference-set-value'):
        demisto.results(update_reference_set_value_command())
    elif demisto.command() == 'qradar-delete-reference-set-value':
        demisto.results(delete_reference_set_value_command())
    elif demisto.command() == 'qradar-get-domains':
        demisto.results(get_domains_command())
    elif demisto.command() == 'qradar-get-domain-by-id':
        demisto.results(get_domains_by_id_command())
except Exception as e:
    message = e.message if hasattr(e, 'message') else convert_to_str(e)
    error = 'Error has occurred in the QRadar Integration: {error}\n {message}'.format(error=type(e), message=message)
    LOG(traceback.format_exc())
    if demisto.command() == 'fetch-incidents':
        LOG(error)
        LOG.print_log()
        raise Exception(error)
    else:
        return_error(error)
