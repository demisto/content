import demistomock as demisto
from CommonServerPython import *

###############################################################################
# import required libraries package
###############################################################################

import os
import ast
import json
import jwt
from datetime import datetime, timedelta
import requests
from typing import List
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)
# disable insecure warnings
requests.packages.urllib3.disable_warnings()

###############################################################################
# packages to handle IOerror
###############################################################################

if not demisto.params().get('proxy', False) \
        or demisto.params()['proxy'] == 'false':
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


"""GLOBAL VARS"""

VERIFY_CERT = True if not demisto.params().get('insecure') else False
KEY = demisto.params().get('key')
SECRET = demisto.params().get('secret')
DOMAIN = demisto.params().get('domain')
CUSTOMER_ID = demisto.params().get('customer_id')
FETCH_TIME = demisto.params().get('fetch_time')

"""HELPER FUNCTIONS"""


def generate_headers(key, secret):
    header = {}
    utcnow = datetime.utcnow()
    date = utcnow.strftime("%a, %d %b %Y %H:%M:%S GMT")
    auth_var = jwt.encode({'iss': key}, secret, algorithm='HS256')
    authorization = "Bearer " + str(auth_var)
    header['date'] = date
    header['Authorization'] = authorization
    return header


def restcall(method, api, **kwargs):

    header = generate_headers(KEY, SECRET)

    url = ("https://%s/public/api/customers/%s%s" %
           (DOMAIN, CUSTOMER_ID, api))

    try:
        request_func = getattr(requests, method)
    except AttributeError:
        return_error("Invalid method: {0}".format(method))

    try:
        response = request_func(
            url,
            headers=header,
            verify=VERIFY_CERT,
            **kwargs)
    except Exception as e:
        return_error("Error Connecting to server. Details: {0}".format(str(e)))

    return response.json()


def severity_to_int(level_string):
    level_int = 0
    if level_string == 'low':
        level_int = 1

    if level_string == 'medium':
        level_int = 2

    if level_string == 'high':
        level_int = 3

    return level_int


def remove_context_entries(context, context_entries_to_keep):
    for index in range(len(context)):
        for key in list(context[index]):
            if key not in context_entries_to_keep:
                context[index].pop(key, None)

    return context


def apply_os_cut(query, os):
    if "WHERE" not in query:
        query = ("%s WHERE" % query)
    else:
        query = ("%s AND" % query)

    op_systems = os.split("/")
    for index in range(len(op_systems)):
        query = ("%s os LIKE '%%%s%%'" % (query, op_systems[index]))
        if index < len(op_systems) - 1:
            query = ("%s OR" % query)

    return query


def apply_equals_cuts(query, cuts):
    if all(value is None for value in cuts.values()):
        return query
    else:
        if "WHERE" not in query:
            query = ("%s WHERE" % query)
        else:
            query = ("%s AND" % query)

        use_and = False
        for key in cuts:
            if cuts.get(key) is not None:
                if use_and:
                    query = ("%s AND" % query)
                if "time" in key:
                    query = ("%s %s=CAST('%s' AS TIMESTAMP)" % (query, key,
                                                                cuts.get(key)))
                    use_and = True
                else:
                    if type(cuts.get(key)) == str:
                        query = ("%s %s='%s'" % (query, key, cuts.get(key)))
                    if type(cuts.get(key)) == int:
                        query = ("%s %s=%s" % (query, key, cuts.get(key)))
                    use_and = True

        return query


def apply_like_cuts(query, cuts):
    if all(value is None for value in cuts.values()):
        return query
    else:
        if "WHERE" not in query:
            query = ("%s WHERE" % query)
        else:
            query = ("%s AND" % query)
        i = 0
        for key in cuts:
            i = i + 1
            if cuts.get(key) is not None:
                query = ("%s %s LIKE '%%%s%%'" % (query, key, cuts.get(key)))
                if i < len(cuts):
                    query = ("%s AND" % query)

        return query


def apply_datetime_cuts(query, name, start, finish):
    if start is None and finish is None:
        return query

    if "WHERE" not in query:
        query = ("%s WHERE" % query)
    else:
        query = ("%s AND" % query)

    if finish is None:
        query = ("%s %s AFTER CAST('%s' AS TIMESTAMP)" % (query, name,
                                                          start))
    if start is None:
        query = ("%s %s BEFORE CAST('%s' AS TIMESTAMP)" % (query, name,
                                                           finish))
    if start is not None and finish is not None:
        query = ("%s %s BETWEEN CAST('%s' AS TIMESTAMP) AND \
CAST('%s' AS TIMESTAMP)"
                 % (query, name, start, finish))

    return query


def uptycs_parse_date_range(timeago, start_time, end_time):

    if timeago is None:
        timeago = "1 day"

    if end_time is not None and start_time is None:
        number = timeago.split(" ")[0]
        unit = timeago.split(" ")[1]
        if unit == 'minutes' or unit == 'minute':
            temp_time_ago = datetime.strftime(
                datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.000")
                - timedelta(minutes=number), "%Y-%m-%d %H:%M:%S.000")
        if unit == 'hours' or unit == 'hour':
            temp_time_ago = datetime.strftime(
                datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.000") -
                - timedelta(hours=number), "%Y-%m-%d %H:%M:%S.000")
        if unit == 'days' or unit == 'day':
            temp_time_ago = datetime.strftime(
                datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.000") -
                - timedelta(days=number), "%Y-%m-%d %H:%M:%S.000")
        if unit == 'months' or unit == 'month':
            temp_time_ago = datetime.strftime(
                datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.000") -
                - timedelta(days=number * 30), "%Y-%m-%d %H:%M:%S.000")
        if unit == 'years' or unit == 'year':
            temp_time_ago = datetime.strftime(
                datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.000") -
                - timedelta(days=number * 365), "%Y-%m-%d %H:%M:%S.000")
    else:
        temp_time_ago, now = parse_date_range(timeago,
                                              date_format="%Y-%m-%d \
%H:%M:%S.000")

    end = (end_time if end_time is not None else now)
    begin = (start_time if start_time is not None else temp_time_ago)

    return begin, end


"""COMMAND FUNCTIONS"""


def uptycs_run_query():
    """
    return results of posted query
    """
    http_method = 'post'
    query = demisto.args().get('query')
    if demisto.args().get('query_type') == 'global':
        api_call = '/query'
        post_data = {
            'query': query
        }
    else:
        api_call = '/assets/query'
        if demisto.args().get('asset_id') is not None:
            _id = {
                "_id": {
                    "equals": demisto.args().get('asset_id')
                }
            }
        elif demisto.args().get('host_name_is') is not None:
            _id = {
                "host_name": {
                    "equals": demisto.args().get(
                        'host_name_is')
                }
            }
        elif demisto.args().get('host_name_like') is not None:
            _id = {
                "host_name": {
                    "like": "%{0}%".format(demisto.args().get(
                        'host_name_like'))
                }
            }
        else:
            _id = {
                "host_name": {
                    "like": '%%'
                }
            }

        post_data = {
            "query": query,
            "type": "realtime",
            "filtering": {
                "filters": _id
            }
        }

    return restcall(http_method, api_call, json=post_data)


def uptycs_run_query_command():
    query_results = uptycs_run_query()
    human_readable = tableToMarkdown('Uptycs Query Result',
                                     query_results.get('items'))
    context = query_results.get('items')

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.QueryResults': context
        }
    }

    return entry


def uptycs_get_assets():
    """
    return list of assets enrolled in Uptycs
    """
    http_method = 'post'
    api_call = "/query"
    query = 'SELECT * FROM upt_assets'
    limit = demisto.args().get('limit')

    equal_cuts = {
        "id": demisto.args().get('asset_id'),
        "host_name": demisto.args().get('host_name_is'),
        "object_group_id": demisto.args().get('object_group_id')
    }
    query = apply_equals_cuts(query, equal_cuts)
    like_cuts = {
        "host_name": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    os = demisto.args().get('os')
    if os:
        query = apply_os_cut(query, os)

    query = ("%s ORDER BY last_activity_at DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        "query": query,
        "queryType": query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_assets_command():
    query_results = uptycs_get_assets()
    human_readable = tableToMarkdown('Uptycs Assets',
                                     query_results.get('items'),
                                     ['id', 'host_name', 'os', 'os_version',
                                      'osquery_version', 'last_activity_at'])
    context = query_results.get('items')
    context_entries_to_keep = ['id', 'location', 'latitude', 'longitude',
                               'os_flavor', 'os', 'last_enrolled_at',
                               'status', 'host_name', 'os_version',
                               'osquery_version', 'last_activity_at',
                               'upt_asset_id', 'created_at']
    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results.get('items'),
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Assets(val.id == obj.id)': context
        }
    }

    return entry


def uptycs_get_alerts():
    """
    return list of alerts
    """
    http_method = 'post'
    api_call = "/query"
    query = 'SELECT a.*, u.host_name FROM upt_alerts a JOIN upt_assets u ON \
a.upt_asset_id=u.id'
    limit = demisto.args().get('limit')

    alert_id = demisto.args().get('alert_id')
    if alert_id is not None:
        equal_cuts = {
            "a.id": alert_id
        }

        query = apply_equals_cuts(query, equal_cuts)
    else:
        equal_cuts = {
            "upt_asset_id": demisto.args().get('asset_id'),
            "code": demisto.args().get('code'),
            "host_name": demisto.args().get('host_name_is'),
            "value": demisto.args().get('value'),
            "key": demisto.args().get('key')
        }

        query = apply_equals_cuts(query, equal_cuts)
        like_cuts = {
            "host_name": demisto.args().get('host_name_like')
        }
        query = apply_like_cuts(query, like_cuts)

        time_ago = demisto.args().get('time_ago')
        start_window = demisto.args().get('start_window')
        end_window = demisto.args().get('end_window')

        if time_ago is not None or (start_window is not None
                                    or end_window is not None):
            begin, end = uptycs_parse_date_range(time_ago,
                                                 start_window, end_window)
            query = apply_datetime_cuts(query, "alert_time", begin, end)

        query = ("%s ORDER BY a.alert_time DESC" % query)

        if limit != -1 and limit is not None:
            query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        "query": query,
        "queryType": query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_alerts_command():
    query_results = uptycs_get_alerts()
    context = query_results.get('items')
    context_entries_to_keep = ['id', 'host_name', 'grouping', 'code',
                               'assigned_to', 'alert_time', 'updated_at',
                               'metadata', 'asset', 'status', 'upt_asset_id',
                               'created_at', 'description', 'severity',
                               'value', 'key']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    if context is not None:
        for index in range(len(context)):
            if bool(json.loads(context[index].get('metadata')).get('pid')):
                context[index]['pid'] = json.loads(
                    context[index].get('metadata')).get('pid')
            else:
                context[index]['pid'] = 'Not applicable or unknown'
            if bool(json.loads(
                    context[index].get('metadata')).get('indicatorId')):
                context[index]['threat_indicator_id'] =\
                    json.loads(
                        context[index].get('metadata')).get('indicatorId')
                context[index]['threat_source_name'] =\
                    json.loads(
                        context[index].get('metadata')).get(
                            'indicatorSummary').get('threatSourceName')
            else:
                context[index]['threat_indicator_id'] = 'No threat indicator \
for this alert'
                context[index]['threat_source_name'] = 'No threat source for \
this alert'

    human_readable = tableToMarkdown('Uptycs Alerts: ',
                                     context,
                                     ['upt_asset_id', 'host_name', 'grouping',
                                      'alert_time', 'description', 'value',
                                      'severity', 'threat_indicator_id',
                                      'threat_source_name'])
    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Alerts(val.id == obj.id)': context
        }
    }

    return entry


def uptycs_get_events():
    """
    return list of events
    """
    http_method = 'post'
    api_call = "/query"
    query = 'SELECT a.*, u.host_name FROM upt_events a JOIN upt_assets u ON \
a.upt_asset_id=u.id'
    limit = demisto.args().get('limit')

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "code": demisto.args().get('code'),
        "host_name": demisto.args().get('host_name_is'),
        "key": demisto.args().get('key'),
        "value": demisto.args().get('value')
    }
    query = apply_equals_cuts(query, equal_cuts)
    like_cuts = {
        "host_name": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time_ago is not None or (start_window is not None
                                or end_window is not None):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "event_time", begin, end)

    query = ("%s ORDER BY a.event_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        "query": query,
        "queryType": query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_events_command():
    query_results = uptycs_get_events()
    context = query_results.get('items')
    context_entries_to_keep = ['upt_asset_id', 'host_name', 'grouping',
                               'code', 'assigned_to', 'event_time',
                               'updated_at', 'metadata', 'asset', 'status',
                               'id', 'created_at', 'description', 'severity',
                               'value', 'key']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    human_readable = tableToMarkdown('Uptycs Events',
                                     query_results.get('items'),
                                     ['host_name', 'grouping', 'event_time',
                                      'description', 'value', 'severity'])
    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Events(val.id == obj.id)': query_results.get('items')
        }
    }

    return entry


def uptycs_get_alert_rules():
    """
    return list of alert rules
    """
    http_method = 'get'
    api_call = "/alertRules"
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_alert_rules_command():
    query_results = uptycs_get_alert_rules()
    human_readable = tableToMarkdown('Uptycs Alert Rules',
                                     query_results.get('items'),
                                     ['name', 'description', 'grouping',
                                      'enabled', 'updatedAt', 'code'])

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results.get('items'),
        'HumanReadable': human_readable,
    }

    return entry


def uptycs_get_event_rules():
    """
    return list of event rules
    """
    http_method = 'get'
    api_call = "/eventRules"
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_event_rules_command():
    query_results = uptycs_get_event_rules()
    human_readable = tableToMarkdown('Uptycs Event Rules',
                                     query_results.get('items'),
                                     ['name', 'description', 'grouping',
                                      'enabled', 'updatedAt', 'code'])

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results.get('items'),
        'HumanReadable': human_readable,
    }

    return entry


def uptycs_get_process_open_files():
    """
    return information for processes which opened a file
    """
    http_method = 'post'
    api_call = '/query'
    query = "select * from process_open_files"
    limit = demisto.args().get('limit')

    time = demisto.args().get('time')
    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                                                  or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_open_files_command():
    query_results = uptycs_get_process_open_files()
    human_readable = tableToMarkdown('Process which has opened a file',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'path', 'fd',
                                      'upt_time'])
    context = query_results.get('items')
    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid',
                               'path', 'fd', 'upt_time']
    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Files': context
        }
    }

    return entry


def uptycs_get_process_open_sockets():
    """
    return information for processes which opened a socket
    """
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from process_open_sockets"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "remote_address": demisto.args().get('ip'),
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                                                  or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_open_sockets_command():
    query_results = uptycs_get_process_open_sockets()
    human_readable = tableToMarkdown('process_open_sockets',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'local_address',
                                      'remote_address', 'upt_time',
                                      'local_port', 'remote_port', 'socket'])
    context = query_results.get('items')
    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid',
                               'local_address', 'remote_address', 'upt_time',
                               'local_port', 'remote_port', 'socket', 'family',
                               'path', 'state', 'protocol']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Sockets': context
        }
    }

    return entry


def uptycs_get_socket_events():
    """
    return information for processes which opened a socket
    """
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from socket_events"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "remote_address": demisto.args().get('ip'),
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                                                  or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_socket_events_command():
    query_results = uptycs_get_socket_events()
    human_readable = tableToMarkdown('Socket events',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'local_address',
                                      'remote_address', 'upt_time',
                                      'local_port', 'action'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid',
                               'local_address', 'remote_address', 'upt_time',
                               'local_port', 'remote_port', 'socket',
                               'family', 'path', 'action', 'protocol']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.SocketEvents': context
        }
    }

    return entry


def uptycs_get_socket_event_information():
    """
    return process event information
    """
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = ("SELECT * FROM socket_events WHERE upt_day = %s AND \
upt_time <= CAST('%s' AS TIMESTAMP) AND remote_address='%s' \
ORDER BY upt_time DESC LIMIT 1" %
             (uptday, time, demisto.args().get('ip')))

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is')
    }

    query = apply_equals_cuts(query, equal_cuts)

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_socket_event_information_command():
    query_results = uptycs_get_socket_event_information()
    human_readable = tableToMarkdown('Socket event information',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'local_address',
                                      'remote_address', 'upt_time',
                                      'local_port', 'action'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid',
                               'local_address', 'remote_address', 'upt_time',
                               'local_port', 'remote_port', 'socket',
                               'family', 'path', 'action', 'protocol']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.SocketEvent': context
        }
    }

    return entry


def uptycs_get_processes():
    """
    return process which are running or have run on a registered Uptycs asset
    """
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from processes"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                         or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_processes_command():
    query_results = uptycs_get_processes()
    human_readable = tableToMarkdown('Processes',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'name', 'path',
                                      'upt_time', 'parent', 'cmdline'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'name',
                               'path', 'upt_time', 'parent', 'cmdline',
                               'pgroup', 'cwd']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Process': context
        }
    }

    return entry


def uptycs_get_process_events():
    """return process events which have executed on a \
        registered Uptycs asset"""
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from process_events"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                                                  or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_events_command():
    query_results = uptycs_get_process_events()
    human_readable = tableToMarkdown('Process events',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'path',
                                      'upt_time', 'parent', 'cmdline'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'path',
                               'upt_time', 'parent', 'cmdline', 'cwd']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ProcessEvents': context
        }
    }

    return entry


def uptycs_get_process_information():
    """return process information"""
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = ("WITH add_times AS (SELECT * FROM processes WHERE upt_added=True), \
remove_times AS (SELECT upt_time, upt_hash FROM processes WHERE \
upt_added=False), temp_proc AS (SELECT aa.upt_asset_id, aa.pid, \
aa.name, aa.path, aa.cmdline, aa.cwd, aa.parent, aa.pgroup, \
aa.upt_hostname, aa.upt_day, aa.upt_time as upt_add_time, \
rr.upt_time as temp_remove_time FROM add_times aa LEFT JOIN \
remove_times rr ON aa.upt_hash=rr.upt_hash), new_proc AS \
(SELECT upt_asset_id, pid, name, path, cmdline, cwd, parent, \
pgroup, upt_hostname, upt_day, upt_add_time, \
coalesce(temp_remove_time, current_timestamp) AS upt_remove_time \
FROM temp_proc) SELECT * FROM new_proc WHERE pid=%s AND \
CAST('%s' AS TIMESTAMP) BETWEEN upt_add_time AND upt_remove_time"
             % (demisto.args().get('pid'), time))

    equal_cuts = {
        "upt_day": uptday,
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is')
    }

    query = apply_equals_cuts(query, equal_cuts)

    query = ("%s ORDER BY upt_add_time DESC LIMIT 1" % query)

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_information_command():
    query_results = uptycs_get_process_information()
    human_readable = tableToMarkdown('Process information',
                                     query_results.get('items'),
                                     ['upt_hostname', 'parent', 'pid',
                                      'name', 'path', 'cmdline'])
    context = query_results.get('items')

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Proc': context
        }
    }

    return entry


def uptycs_get_process_event_information():
    """return process event information"""
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = ("SELECT * FROM process_events WHERE upt_day = %s AND pid=%s AND \
upt_time<=CAST('%s' AS TIMESTAMP)" %
             (uptday, demisto.args().get('pid'), time))

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is')
    }

    query = apply_equals_cuts(query, equal_cuts)

    query = ("%s ORDER BY upt_time DESC LIMIT 1" % query)

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_event_information_command():
    query_results = uptycs_get_process_event_information()
    human_readable = tableToMarkdown('Process event information',
                                     query_results.get('items'),
                                     ['upt_hostname', 'parent', 'pid',
                                      'path', 'cmdline', 'ancestor_list'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'path',
                               'upt_time', 'parent', 'cmdline', 'cwd', 'ancestor_list']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ProcEvent': context
        }
    }

    return entry


def uptycs_get_parent_information():
    """return parent process information"""
    http_method = 'post'
    api_call = '/query'
    child_add_time = demisto.args().get('child_add_time')
    if child_add_time is not None:
        day = child_add_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_child_add_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_child_add_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = ("WITH add_times AS (SELECT * FROM processes WHERE upt_added=True), \
remove_times AS (SELECT upt_time, upt_hash FROM processes WHERE \
upt_added=False), temp_proc AS (SELECT aa.upt_asset_id, aa.pid, \
aa.name, aa.path, aa.cmdline, aa.cwd, aa.parent, aa.pgroup, \
aa.upt_hostname, aa.upt_day, aa.upt_time as upt_add_time, \
rr.upt_time as temp_remove_time FROM add_times aa LEFT JOIN \
remove_times rr ON aa.upt_hash=rr.upt_hash), new_proc AS \
(SELECT upt_asset_id, pid, name, path, cmdline, cwd, parent, \
pgroup, upt_hostname, upt_day, upt_add_time, \
coalesce(temp_remove_time, current_timestamp) AS upt_remove_time \
FROM temp_proc) SELECT * FROM new_proc WHERE pid=%s AND \
CAST('%s' AS TIMESTAMP) BETWEEN upt_add_time AND upt_remove_time AND \
upt_day <= %s"
             % (demisto.args().get('parent'), child_add_time, uptday))

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is')
    }

    query = apply_equals_cuts(query, equal_cuts)

    query = ("%s ORDER BY upt_add_time DESC LIMIT 1" % query)

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_parent_information_command():
    query_results = uptycs_get_parent_information()
    human_readable = tableToMarkdown('Parent process information',
                                     query_results.get('items'),
                                     ['upt_hostname', 'parent', 'pid',
                                      'name', 'path', 'cmdline'])
    context = query_results.get('items')

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Parent': context
        }
    }

    return entry


def uptycs_get_parent_event_information():
    """return process event information"""
    http_method = 'post'
    api_call = '/query'
    child_add_time = demisto.args().get('child_add_time')
    child_ancestor_list = demisto.args().get('child_ancestor_list')
    parent = demisto.args().get('parent')

    if child_add_time is not None:
        day = child_add_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_child_add_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_child_add_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = ""
    if child_ancestor_list is not None:
        child_ancestor_list = child_ancestor_list[2:len(child_ancestor_list) - 2].split('}, {')
        ancestors = []
        for ancestor in child_ancestor_list:
            ancestors.append(json.loads("{" + ancestor + "}"))

        if ancestors[0].get("upt_rid", None) is not None:
            query = "SELECT * FROM process_events WHERE upt_day <= {0} \
AND upt_rid = '{1}'".format(uptday, ancestors[0].get("upt_rid", None))

    if query == "":
        query = "SELECT * FROM process_events WHERE upt_day <= {0} AND pid={1} \
AND upt_time<=CAST('{2}' AS TIMESTAMP)".format(uptday, parent, child_add_time)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is')
    }

    query = apply_equals_cuts(query, equal_cuts)

    query = ("%s ORDER BY upt_time DESC LIMIT 1" % query)

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_parent_event_information_command():
    query_results = uptycs_get_parent_event_information()
    human_readable = tableToMarkdown('Parent process event information',
                                     query_results.get('items'),
                                     ['upt_hostname', 'parent', 'pid',
                                      'path', 'cmdline'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'path',
                               'upt_time', 'parent', 'cmdline', 'cwd']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ParentEvent': context
        }
    }

    return entry


def uptycs_get_process_child_processes():
    """return child processes for a given parent process"""
    http_method = 'post'
    api_call = '/query'
    parent = demisto.args().get('parent')
    limit = demisto.args().get('limit')
    asset_id = demisto.args().get('asset_id')
    parent_start = demisto.args().get('parent_start_time')
    parent_end = demisto.args().get('parent_end_time')
    if parent_start is not None:
        day = parent_start.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_parent_start = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_parent_start.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    if parent_end is None:
        query = ("SELECT upt_time FROM process_events WHERE pid = %s AND \
upt_asset_id = '%s' AND upt_time > CAST('%s' AS TIMESTAMP) \
ORDER BY upt_time ASC limit 1" %
                 (parent, asset_id, parent_start))
        query_type = 'global'

        post_data = {
            'query': query,
            'queryType': query_type
        }
        temp_results = restcall(http_method, api_call, json=post_data)
        if len(temp_results.get('items')) > 0:
            parent_end = temp_results.get('items')[0].get('upt_time')
        else:
            parent_end = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    query = ("WITH add_times AS (SELECT * FROM processes WHERE upt_added=True), \
remove_times AS (SELECT upt_time, upt_hash FROM processes WHERE \
upt_added=False), temp_proc AS (SELECT aa.upt_asset_id, aa.pid, \
aa.name, aa.path, aa.cmdline, aa.cwd, aa.parent, aa.pgroup, \
aa.upt_hostname, aa.upt_day, aa.upt_time as upt_add_time, \
rr.upt_time as temp_remove_time FROM add_times aa LEFT JOIN \
remove_times rr on aa.upt_hash=rr.upt_hash), new_proc AS \
(SELECT upt_asset_id, pid, name, path, cmdline, cwd, parent, \
pgroup, upt_hostname, upt_day, upt_add_time, \
coalesce(temp_remove_time, current_timestamp) AS upt_remove_time \
FROM temp_proc) SELECT * FROM new_proc WHERE upt_day>=%s AND \
parent = %s AND upt_asset_id = '%s' AND upt_add_time BETWEEN \
CAST('%s' AS TIMESTAMP) AND CAST('%s' AS TIMESTAMP) ORDER BY \
upt_add_time DESC"
             % (uptday, parent, asset_id, parent_start, parent_end))

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_child_processes_command():
    query_results = uptycs_get_process_child_processes()
    human_readable = tableToMarkdown('Child processes of a specified pid',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'name',
                                      'path', 'cmdline', 'upt_add_time'])
    context = query_results.get('items')

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Children': context
        }
    }

    return entry


def uptycs_set_alert_status():
    """set the status of an alert"""
    http_method = 'put'
    api_call = ('/alerts/%s' % demisto.args().get('alert_id'))

    post_data = {
        'status': demisto.args().get('status')
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_set_alert_status_command():
    query_results = uptycs_set_alert_status()
    human_readable = tableToMarkdown('Uptycs Alert Status',
                                     query_results, ['id', 'code', 'status',
                                                     'createdAt', 'updatedAt'])
    context = query_results
    context['updatedBy'] = context.get('updatedByUser').get('name')
    context['updatedByAdmin'] = context.get('updatedByUser').get('admin')
    context['updatedByEmail'] = context.get('updatedByUser').get('email')
    context_entries_to_keep = ['id', 'code', 'status', 'createdAt',
                               'updatedAt', 'updatedBy', 'updatedByAdmin',
                               'updatedByEmail']
    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AlertStatus': context
        }
    }

    return entry


def uptycs_get_asset_tags():
    """set a tag on an asset"""
    http_method = 'get'
    api_call = ('/assets/%s' % demisto.args().get('asset_id'))
    return restcall(http_method, api_call).get('tags')


def uptycs_get_asset_tags_command():
    query_results = uptycs_get_asset_tags()
    human_readable = tableToMarkdown('Uptycs Asset Tags for asset id: %s' %
                                     demisto.args().get('asset_id'),
                                     query_results, 'Tags')
    context = query_results

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AssetTags': context
        }
    }

    return entry


def uptycs_set_asset_tag():
    """set a tag on an asset"""
    http_method = 'get'
    api_call = ('/assets/%s' % demisto.args().get('asset_id'))
    tags = restcall(http_method, api_call).get('tags')

    tag_set = False
    tag_key = demisto.args().get('tag_key')
    tag_value = demisto.args().get('tag_value')
    for tag in tags:
        if tag_key in tag:
            temp_tag = tag.split('=')
            new_tag = temp_tag[0] + '=' + temp_tag[1] + ', ' + tag_value
            tags.remove(tag)
            tag_set = True

    if tag_set:
        tags.append(new_tag)
    elif tag_value is not None:
        tags.append(tag_key + '=' + tag_value)
    else:
        tags.append(tag_key)

    http_method = 'put'
    post_data = {
        'tags': tags
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_set_asset_tag_command():
    query_results = uptycs_set_asset_tag()
    human_readable = tableToMarkdown('Uptycs Asset Tag',
                                     query_results, ['hostName', 'tags'])
    context = query_results
    context_entries_to_keep = ['hostName', 'tags']

    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AssetTags': context
        }
    }

    return entry


def uptycs_get_users():
    """return a list of uptycs users"""
    http_method = 'get'
    api_call = '/users'
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_users_command():
    query_results = uptycs_get_users()
    human_readable = tableToMarkdown('Uptycs Users',
                                     query_results.get(
                                         'items'), ['name', 'email', 'id',
                                                    'admin', 'active',
                                                    'createdAt', 'updatedAt'])
    context = query_results.get('items')
    context_entries_to_keep = ['name', 'email', 'id', 'admin', 'active',
                               'createdAt', 'updatedAt']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Users': context
        }
    }

    return entry


def uptycs_get_user_information():
    """return information about a specfic Uptycs user"""
    http_method = 'get'
    api_call = '/users/%s' % demisto.args().get('user_id')

    return restcall(http_method, api_call)


def uptycs_get_user_information_command():
    query_results = uptycs_get_user_information()
    human_readable = tableToMarkdown('Uptycs User Information',
                                     query_results, ['name', 'email', 'id'])
    context = query_results
    context['userRoles'] = {
        context.get('userRoles')[0].get('role').get('name'):
            context.get('userRoles')[0].get('role')
    }

    context_entries_to_keep = ['name', 'email', 'id', 'userRoles',
                               'userObjectGroups']

    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.UserInfo': context
        }
    }

    return entry


def uptycs_get_user_asset_groups():
    """return a list of users in a particular asset group"""
    http_method = 'get'
    api_call = '/users'

    users = restcall(http_method, api_call).get('items')
    user_ids = []
    for index in range(len(users)):
        user_ids.append(users[index].get('id'))

    asset_group_id = demisto.args().get('asset_group_id')
    users_in_group = {}
    for user_id in user_ids:
        http_method = 'get'
        api_call = '/users/%s' % user_id
        user_info = restcall(http_method, api_call)
        obj_groups = user_info.get('userObjectGroups')
        for obj_group in obj_groups:
            if obj_group.get('objectGroupId') == asset_group_id:
                users_in_group[user_info.get('name')] = {
                    'email': user_info.get('email'),
                    'id': user_info.get('id')
                }

    return users_in_group


def uptycs_get_user_asset_groups_command():
    query_results = uptycs_get_user_asset_groups()
    human_readable = tableToMarkdown('Uptycs User Asset Groups',
                                     query_results)
    context = query_results

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.UserGroups': context
        }
    }

    return entry


def uptycs_get_asset_groups():
    """return a list of asset groups"""
    http_method = 'get'
    api_call = '/objectGroups'
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_asset_groups_command():
    query_results = uptycs_get_asset_groups()
    human_readable = tableToMarkdown('Uptycs Users',
                                     query_results.get('items'),
                                     ['id', 'name', 'description',
                                      'objectType', 'custom', 'createdAt',
                                      'updatedAt'])
    context = query_results.get('items')
    context_entries_to_keep = ['id', 'name', 'description', 'objectType',
                               'custom', 'createdAt', 'updatedAt']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AssetGroups': context
        }
    }

    return entry


def uptycs_get_threat_indicators():
    """return a list of threat indcicators"""
    http_method = 'get'
    api_call = '/threatIndicators'
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    indicator = demisto.args().get('indicator')
    if indicator is not None:
        api_call = '%s?filters={"indicator":{"like":"%s"}}' %\
            (api_call, indicator)

    return restcall(http_method, api_call)


def uptycs_get_threat_indicators_command():
    query_results = uptycs_get_threat_indicators()
    human_readable = tableToMarkdown('Uptycs Threat Indicators',
                                     query_results.get('items'),
                                     ['id', 'indicator', 'description',
                                      'indicatorType', 'createdAt',
                                      'isActive', 'threatId'])
    context = query_results.get('items')
    context_entries_to_keep = ['id', 'indicator', 'description',
                               'indicatorType', 'createdAt', 'isActive',
                               'threatId']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ThreatIndicators': context
        }
    }

    return entry


def uptycs_get_threat_indicator():
    """return information about a particular threat indicator"""
    http_method = 'get'
    api_call = '/threatIndicators/%s' % demisto.args().get('indicator_id')

    return restcall(http_method, api_call)


def uptycs_get_threat_indicator_command():
    query_results = uptycs_get_threat_indicator()
    human_readable = tableToMarkdown('Uptycs Threat Indicator',
                                     query_results, ['id', 'indicator',
                                                     'description',
                                                     'indicatorType',
                                                     'createdAt', 'isActive',
                                                     'threatId'])
    context = query_results
    context['threat_source_id'] = context.get('threat').get('threatSourceId')
    context['threat_vendor_id'] = context.get('threat').get('threatSource').\
        get('threatVendorId')
    context['threat_source_name'] = context.get('threat').get('threatSource').\
        get('name')

    context_entries_to_keep = ['id', 'indicator', 'description',
                               'indicatorType', 'createdAt', 'updatedAt',
                               'isActive', 'threatId', 'threat_source_id',
                               'threat_vendor_id', 'threat_source_name']

    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ThreatIndicator': context
        }
    }

    return entry


def uptycs_get_threat_sources():
    """return a list of threat sources"""
    http_method = 'get'
    api_call = '/threatSources'
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_threat_sources_command():
    query_results = uptycs_get_threat_sources()
    human_readable = tableToMarkdown('Uptycs Threat Sources',
                                     query_results.get('items'),
                                     ['name', 'description', 'url', 'enabled',
                                      'custom', 'createdAt', 'lastDownload'])
    context = query_results.get('items')
    context_entries_to_keep = ['name', 'description', 'url', 'enabled',
                               'custom', 'createdAt', 'lastDownload']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ThreatSources': context
        }
    }

    return entry


def uptycs_get_threat_source():
    """return information about a particular threat source"""
    http_method = 'get'
    api_call = '/threatSources'

    threat_source_id = demisto.args().get('threat_source_id')
    if threat_source_id is not None:
        api_call = '%s/%s' % (api_call, threat_source_id)

    return restcall(http_method, api_call)


def uptycs_get_threat_source_command():
    query_results = uptycs_get_threat_source()
    human_readable = tableToMarkdown('Uptycs Threat Sources',
                                     query_results,
                                     ['name', 'description', 'url', 'enabled',
                                      'custom', 'createdAt', 'lastDownload'])
    context = query_results
    context_entries_to_keep = ['name', 'description', 'url', 'enabled',
                               'custom', 'createdAt', 'lastDownload']

    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ThreatSources': context
        }
    }

    return entry


def uptycs_get_threat_vendors():
    """return a list of threat vendors"""
    http_method = 'get'
    api_call = '/threatVendors'
    limit = demisto.args().get('limit')

    if limit != -1 and limit is not None:
        api_call = ("%s?limit=%s" % (api_call, limit))

    return restcall(http_method, api_call)


def uptycs_get_threat_vendors_command():
    query_results = uptycs_get_threat_vendors()
    context = query_results.get('items')

    if context is not None:
        for index in range(len(context)):
            context[index].pop('links', None)

    human_readable = tableToMarkdown('Uptycs Threat Vendors',
                                     context)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ThreatVendors': context
        }
    }

    return entry


def uptycs_post_threat_source():
    """post a new threat source"""

    url = ("https://%s/public/api/customers/%s/threatSources" %
           (DOMAIN, CUSTOMER_ID))
    header = generate_headers(KEY, SECRET)

    filepath = demisto.getFilePath(demisto.args().get('entry_id'))
    post_data = {
        "name": demisto.args().get('name'),
        "filename": filepath.get('name'),
        "description": demisto.args().get('description')
    }

    files = {'file': open(filepath.get('path'), 'rb')}

    response = requests.post(url, headers=header, data=post_data,
                             files=files, verify=VERIFY_CERT)

    return response


def uptycs_post_threat_source_command():
    response = uptycs_post_threat_source()
    human_readable = 'Uptycs Posted Threat Source'

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': response.json(),
        'HumanReadable': human_readable,
    }

    return entry


def uptycs_get_saved_queries():
    """return a list of threat vendors"""
    http_method = 'get'
    api_call = '/queries'

    query_id = demisto.args().get('query_id')
    if query_id is not None:
        api_call = '%s/%s' % (api_call, query_id)

    name = demisto.args().get('name')
    if name is not None:
        api_call = '%s?name=%s' % (api_call, name)

    return restcall(http_method, api_call)


def uptycs_get_saved_queries_command():
    query_results = uptycs_get_saved_queries()
    context = query_results.get('items')

    if context is not None:
        for index in range(len(context)):
            context[index].pop('links', None)

    human_readable = tableToMarkdown('Uptycs Saved Queries',
                                     context,
                                     ['name', 'description', 'query',
                                      'executionType', 'grouping', 'id'])

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.SavedQueries': context
        }
    }

    return entry


def uptycs_run_saved_query():
    """return a list of threat vendors"""
    http_method = 'get'
    api_call = '/queries'

    query_id = demisto.args().get('query_id')
    if query_id is not None:
        api_call = '%s/%s' % (api_call, query_id)

    name = demisto.args().get('name')
    if name is not None:
        api_call = '%s?name=%s' % (api_call, name)

    query_results = restcall(http_method, api_call).get('items')[0]
    query = query_results.get('query')
    var_args = demisto.args().get('variable_arguments')

    if var_args is not None:
        while type(var_args) is not dict:
            var_args = ast.literal_eval(var_args)
        for key, value in var_args.items():
            query = query.replace(key, value)

    http_method = 'post'

    if query_results.get('executionType') == 'realtime':
        api_call = '/assets/query'
        if demisto.args().get('asset_id') is not None:
            _id = {
                "id": {
                    "equals": demisto.args().get('asset_id')
                }
            }
        elif demisto.args().get('host_name_is') is not None:
            _id = {
                "host_name": {
                    "equals": demisto.args().get('host_name_is')
                }
            }
        elif demisto.args().get('host_name_like') is not None:
            _id = {
                "host_name": {
                    "like": '%' + demisto.args().get('host_name_like') + '%'
                }
            }
        else:
            _id = {
                "host_name": {
                    "like": '%%'
                }
            }

        post_data = {
            "type": "realtime",
            "query": query,
            "filtering": {
                "filters": _id
            }
        }
    else:
        post_data = {"query": query}
        api_call = '/query'

    return restcall(http_method, api_call, json=post_data)


def uptycs_run_saved_query_command():
    query_results = uptycs_run_saved_query()
    context = query_results.get('items')

    if context is not None:
        for index in range(len(context)):
            context[index].pop('links', None)

    human_readable = tableToMarkdown('Uptycs Query Results', context)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.RunQuery': context
        }
    }

    return entry


def uptycs_post_saved_query():
    """return a list of threat vendors"""
    http_method = 'post'
    api_call = '/queries'

    post_data = {
        "name": demisto.args().get('name'),
        "type": demisto.args().get('type'),
        "description": demisto.args().get('description'),
        "query": demisto.args().get('query'),
        "executionType": demisto.args().get('execution_type'),
        "grouping": demisto.args().get('grouping'),
        "custom": True
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_post_saved_query_command():
    query_results = uptycs_post_saved_query()
    if query_results.get("status") == 500:
        return_error("Internal Server Error, check whether a query with this \
        name has already been saved")

    human_readable = tableToMarkdown('Uptycs Posted Query',
                                     query_results,
                                     ['name', 'type', 'description', 'query',
                                      'executionType', 'grouping', 'custom'])

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.PostedQuery': query_results
        }
    }

    return entry


def uptycs_test_module():
    """check whether Uptycs API responds correctly"""
    http_method = 'get'
    api_call = '/assets?limit=1'

    query_results = restcall(http_method, api_call)

    if query_results == 0:
        return False
    else:
        return True


def uptycs_fetch_incidents():
    """fetch alerts from Uptycs"""
    this_run = datetime.utcnow().strftime("%m/%d/%y %H:%M:%S")
    if bool(demisto.getLastRun()) is False:
        last_run, _ = parse_date_range(FETCH_TIME)
    else:
        last_run = demisto.getLastRun()['time']

    http_method = 'get'
    api_call = ('/alerts?filters={"alertTime":{"between":["%s","%s"]}}'
                % (last_run, this_run))

    query_results = restcall(http_method, api_call)

    incidents = []  # type: List[dict]
    if len(query_results.get('items')) == 0:
        return incidents
    if query_results.get('items') is not None:
        for index in range(len(query_results.get('items'))):
            context = query_results.get('items')[index]
            context['alertId'] = context.get('id')
            context['hostName'] = context.get('asset').get('hostName')
            if bool(context.get('metadata').get('indicatorId')):
                context['indicatorId'] = context.get('metadata').\
                    get('indicatorId')
                context['threatId'] = context.get('metadata').\
                    get('indicatorSummary').get('threatId')
                context['threatSourceName'] = context.get('metadata').\
                    get('indicatorSummary').get('threatSourceName')
                context['indicatorType'] = context.get('metadata').\
                    get('indicatorSummary').get('indicatorType')

            context_entries_to_keep = ['id', 'hostName', 'grouping',
                                       'assignedTo', 'alertTime', 'alertId',
                                       'updatedAt', 'status', 'assetId',
                                       'createdAt', 'description', 'severity',
                                       'value', 'threatId',
                                       'threatSourceName', 'indicatorType',
                                       'indicatorId']

            for key in list(context):
                if key not in context_entries_to_keep:
                    context.pop(key, None)

            alert_time = context.get('alertTime')

            incident = {
                "Name": "Uptycs Alert: %s for asset: %s" %
                        (context.get('description'), context.get('hostName')),
                "Occurred": alert_time,
                "Severity": severity_to_int(context.get('severity')),
                "Details": json.dumps(context, indent=4),
                "rawJSON": json.dumps(context)
            }
            incidents.insert(0, incident)

    demisto.setLastRun({'time': this_run})
    return incidents


def main():
    ###########################################################################
    # main function
    ###########################################################################

    try:
        if demisto.command() == 'uptycs-run-query':
            demisto.results(uptycs_run_query_command())

        if demisto.command() == 'uptycs-get-assets':
            demisto.results(uptycs_get_assets_command())

        if demisto.command() == 'uptycs-get-alerts':
            demisto.results(uptycs_get_alerts_command())

        if demisto.command() == 'uptycs-get-events':
            demisto.results(uptycs_get_events_command())

        if demisto.command() == 'uptycs-get-alert-rules':
            demisto.results(uptycs_get_alert_rules_command())

        if demisto.command() == 'uptycs-get-event-rules':
            demisto.results(uptycs_get_event_rules_command())

        if demisto.command() == 'uptycs-get-process-open-files':
            demisto.results(uptycs_get_process_open_files_command())

        if demisto.command() == 'uptycs-get-socket-events':
            demisto.results(uptycs_get_socket_events_command())

        if demisto.command() == 'uptycs-get-socket-event-information':
            demisto.results(uptycs_get_socket_event_information_command())

        if demisto.command() == 'uptycs-get-process-open-sockets':
            demisto.results(uptycs_get_process_open_sockets_command())

        if demisto.command() == 'uptycs-get-processes':
            demisto.results(uptycs_get_processes_command())

        if demisto.command() == 'uptycs-get-process-information':
            demisto.results(uptycs_get_process_information_command())

        if demisto.command() == 'uptycs-get-parent-information':
            demisto.results(uptycs_get_parent_information_command())

        if demisto.command() == 'uptycs-get-process-child-processes':
            demisto.results(uptycs_get_process_child_processes_command())

        if demisto.command() == 'uptycs-get-process-events':
            demisto.results(uptycs_get_process_events_command())

        if demisto.command() == 'uptycs-get-process-event-information':
            demisto.results(uptycs_get_process_event_information_command())

        if demisto.command() == 'uptycs-get-parent-event-information':
            demisto.results(uptycs_get_parent_event_information_command())

        if demisto.command() == 'uptycs-set-alert-status':
            demisto.results(uptycs_set_alert_status_command())

        if demisto.command() == 'uptycs-get-asset-tags':
            demisto.results(uptycs_get_asset_tags_command())

        if demisto.command() == 'uptycs-set-asset-tag':
            demisto.results(uptycs_set_asset_tag_command())

        if demisto.command() == 'uptycs-get-users':
            demisto.results(uptycs_get_users_command())

        if demisto.command() == 'uptycs-get-user-information':
            demisto.results(uptycs_get_user_information_command())

        if demisto.command() == 'uptycs-get-user-asset-groups':
            demisto.results(uptycs_get_user_asset_groups_command())

        if demisto.command() == 'uptycs-get-asset-groups':
            demisto.results(uptycs_get_asset_groups_command())

        if demisto.command() == 'uptycs-get-threat-indicators':
            demisto.results(uptycs_get_threat_indicators_command())

        if demisto.command() == 'uptycs-get-threat-indicator':
            demisto.results(uptycs_get_threat_indicator_command())

        if demisto.command() == 'uptycs-get-threat-sources':
            demisto.results(uptycs_get_threat_sources_command())

        if demisto.command() == 'uptycs-get-threat-source':
            demisto.results(uptycs_get_threat_source_command())

        if demisto.command() == 'uptycs-get-threat-vendors':
            demisto.results(uptycs_get_threat_vendors_command())

        if demisto.command() == 'uptycs-get-saved-queries':
            demisto.results(uptycs_get_saved_queries_command())

        if demisto.command() == 'uptycs-run-saved-query':
            demisto.results(uptycs_run_saved_query_command())

        if demisto.command() == 'uptycs-post-saved-query':
            demisto.results(uptycs_post_saved_query_command())

        if demisto.command() == 'uptycs-post-threat-source':
            demisto.results(uptycs_post_threat_source_command())

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            if uptycs_test_module():
                demisto.results('ok')
            else:
                demisto.results('test failed')

        if demisto.command() == 'fetch-incidents':
            demisto.incidents(uptycs_fetch_incidents())

    except Exception as ex:
        if demisto.command() == 'fetch-incidents':
            raise

        return_error(str(ex))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
