from splunklib.binding import HTTPError

import demistomock as demisto
from CommonServerPython import *
import splunklib.client as client
import splunklib.results as results
import json
from datetime import timedelta, datetime
import urllib2
import ssl
from StringIO import StringIO
import requests
import urllib3
import io
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define utf8 as default encoding
reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=maybe-no-member
params = demisto.params()
SPLUNK_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
VERIFY_CERTIFICATE = not bool(params.get('unsecure'))
FETCH_LIMIT = int(params.get('fetch_limit', 50))
FETCH_LIMIT = max(min(200, FETCH_LIMIT), 1)
PROBLEMATIC_CHARACTERS = ['.', '(', ')', '[', ']']
REPLACE_WITH = '_'
REPLACE_FLAG = params.get('replaceKeys', False)
FETCH_TIME = demisto.params().get('fetch_time')
TIME_UNIT_TO_MINUTES = {'minute': 1, 'hour': 60, 'day': 24 * 60, 'week': 7 * 24 * 60, 'month': 30 * 24 * 60,
                        'year': 365 * 24 * 60}


class ResponseReaderWrapper(io.RawIOBase):
    """ This class was supplied as a solution for a bug in Splunk causing the search to run slowly.
    """

    def __init__(self, responseReader):
        self.responseReader = responseReader

    def readable(self):
        return True

    def close(self):
        self.responseReader.close()

    def read(self, n):
        return self.responseReader.read(n)

    def readinto(self, b):
        sz = len(b)
        data = self.responseReader.read(sz)
        for idx, ch in enumerate(data):
            b[idx] = ch

        return len(data)


def get_current_splunk_time(splunk_service):
    t = datetime.utcnow() - timedelta(days=3)
    time = t.strftime(SPLUNK_TIME_FORMAT)
    kwargs_oneshot = {'count': 1, 'earliest_time': time}
    searchquery_oneshot = '| gentimes start=-1 | eval clock = strftime(time(), "%Y-%m-%dT%H:%M:%S")' \
                          ' | sort 1 -_time | table clock'

    oneshotsearch_results = splunk_service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)

    reader = results.ResultsReader(oneshotsearch_results)
    for item in reader:
        if isinstance(item, results.Message):
            return item.message["clock"]
        if isinstance(item, dict):
            return item["clock"]
    raise ValueError('Error: Could not fetch Splunk time')


def rawToDict(raw):
    result = {}  # type: Dict[str, str]
    if 'message' in raw:
        raw = raw.replace('"', '').strip('{').strip('}')
        key_val_arr = raw.split(",")
        for key_val in key_val_arr:
            single_key_val = key_val.split(":")
            if len(single_key_val) > 1:
                val = single_key_val[1]
                key = single_key_val[0].strip()

                if key in result.keys():
                    result[key] = result[key] + "," + val
                else:
                    result[key] = val

    else:
        raw_response = re.split('(?<=\S),', raw)  # split by any non-whitespace character
        for key_val in raw_response:
            key_value = key_val.replace('"', '').strip()
            if '=' in key_value:
                key_and_val = key_value.split('=', 1)
                result[key_and_val[0]] = key_and_val[1]

    if REPLACE_FLAG:
        result = replace_keys(result)
    return result


# Converts to an str
def convert_to_str(obj):
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    return str(obj)


def updateNotableEvents(sessionKey, baseurl, comment, status=None, urgency=None, owner=None, eventIDs=None,
                        searchID=None):
    """
    Update some notable events.

    Arguments:
    sessionKey -- The session key to use
    comment -- A description of the change or some information about the notable events
    status -- A status (only required if you are changing the status of the event)
    urgency -- An urgency (only required if you are changing the urgency of the event)
    owner -- A nowner (only required if reassigning the event)
    eventIDs -- A list of notable event IDs (must be provided if a search ID is not provided)
    searchID -- An ID of a search. All of the events associated with this search will be modified
     unless a list of eventIDs are provided that limit the scope to a sub-set of the results.
    """

    # Make sure that the session ID was provided
    if sessionKey is None:
        raise Exception("A session key was not provided")

    # Make sure that rule IDs and/or a search ID is provided
    if eventIDs is None and searchID is None:
        raise Exception("Either eventIDs of a searchID must be provided (or both)")

    # These the arguments to the REST handler
    args = {}
    args['comment'] = comment

    if status is not None:
        args['status'] = status

    if urgency is not None:
        args['urgency'] = urgency

    if owner is not None:
        args['newOwner'] = owner

    # Provide the list of event IDs that you want to change:
    if eventIDs is not None:
        args['ruleUIDs'] = eventIDs

    # If you want to manipulate the notable events returned by a search then include the search ID
    if searchID is not None:
        args['searchID'] = searchID

    auth_header = {'Authorization': 'Splunk %s' % sessionKey}

    args['output_mode'] = 'json'

    mod_notables = requests.post(baseurl + 'services/notable_update', data=args, headers=auth_header,
                                 verify=VERIFY_CERTIFICATE)

    return mod_notables.json()


def severity_to_level(severity):
    if severity == 'informational':
        return 0.5
    elif severity == 'critical':
        return 4
    elif severity == 'high':
        return 3
    elif severity == 'medium':
        return 2
    else:
        return 1


def notable_to_incident(event):
    incident = {}  # type: Dict[str,Any]
    rule_title = ''
    rule_name = ''
    if demisto.get(event, 'rule_title'):
        rule_title = event['rule_title']
    if demisto.get(event, 'rule_name'):
        rule_name = event['rule_name']
    incident["name"] = "{} : {}".format(rule_title, rule_name)
    if demisto.get(event, 'urgency'):
        incident["severity"] = severity_to_level(event['urgency'])
    if demisto.get(event, 'rule_description'):
        incident["details"] = event["rule_description"]
    if demisto.get(event, "_time"):
        incident["occurred"] = event["_time"]
    else:
        incident["occurred"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.0+00:00')
    event = replace_keys(event) if REPLACE_FLAG else event
    incident["rawJSON"] = json.dumps(event)
    labels = []
    if demisto.get(demisto.params(), 'parseNotableEventsRaw'):
        isParseNotableEventsRaw = demisto.params()['parseNotableEventsRaw']
        if isParseNotableEventsRaw:
            rawDict = rawToDict(event['_raw'])
            for rawKey in rawDict:
                labels.append({'type': rawKey, 'value': rawDict[rawKey]})
    if demisto.get(event, 'security_domain'):
        labels.append({'type': 'security_domain', 'value': event["security_domain"]})
    incident['labels'] = labels
    return incident


def handler(proxy):
    proxy_handler = urllib2.ProxyHandler({'http': proxy, 'https': proxy})
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)
    return request


def request(url, message):
    method = message['method'].lower()
    data = message.get('body', "") if method == 'post' else None
    headers = dict(message.get('headers', []))
    req = urllib2.Request(url, data, headers)  # guardrails-disable-line
    context = ssl.create_default_context()

    if VERIFY_CERTIFICATE:
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        response = urllib2.urlopen(req, context=context)  # guardrails-disable-line
    except urllib2.HTTPError as response:  # noqa: F841
        pass  # Propagate HTTP errors via the returned response message
    return {
        'status': response.code,  # type: ignore
        'reason': response.msg,  # type: ignore
        'headers': response.info().dict,  # type: ignore
        'body': StringIO(response.read())  # type: ignore
    }


def requests_handler(url, message, **kwargs):
    method = message['method'].lower()
    data = message.get('body', '') if method == 'post' else None
    headers = dict(message.get('headers', []))
    try:
        response = requests.request(
            method,
            url,
            data=data,
            headers=headers,
            verify=VERIFY_CERTIFICATE,
            **kwargs
        )
    except requests.exceptions.HTTPError as e:
        # Propagate HTTP errors via the returned response message
        response = e.response
        demisto.debug('Got exception while using requests handler - {}'.format(str(e)))
    return {
        'status': response.status_code,
        'reason': response.reason,
        'headers': response.headers.items(),
        'body': io.BytesIO(response.content)
    }


def build_search_kwargs(args):
    t = datetime.utcnow() - timedelta(days=7)
    time_str = t.strftime(SPLUNK_TIME_FORMAT)

    kwargs_normalsearch = {
        "earliest_time": time_str,
        "exec_mode": "blocking"  # A blocking search runs synchronously, and returns a job when it's finished.
    }  # type: Dict[str,Any]
    if demisto.get(args, 'earliest_time'):
        kwargs_normalsearch['earliest_time'] = args['earliest_time']
    if demisto.get(args, 'latest_time'):
        kwargs_normalsearch['latest_time'] = args['latest_time']
    if demisto.get(args, 'app'):
        kwargs_normalsearch['app'] = args['app']
    return kwargs_normalsearch


def build_search_query(args):
    query = args['query']
    query = query.encode('utf-8')
    if not query.startswith('search') and not query.startswith('Search') and not query.startswith('|'):
        query = 'search ' + query
    return query


def create_entry_context(args, parsed_search_results, dbot_scores):
    ec = {}

    if args.get('update_context', "true") == "true":
        ec['Splunk.Result'] = parsed_search_results
        if len(dbot_scores) > 0:
            ec['DBotScore'] = dbot_scores
    return ec


def build_search_human_readable(args, parsed_search_results):
    headers = ""
    if parsed_search_results and len(parsed_search_results) > 0:
        if not isinstance(parsed_search_results[0], dict):
            headers = "results"
        else:
            search_for_table_args = re.search(' table (?P<table>.*)(\|)?', args.get('query', ''))
            if search_for_table_args:
                table_args = search_for_table_args.group('table')
                table_args = table_args if '|' not in table_args else table_args.split(' |')[0]
                chosen_fields = [field for field in re.split(' |,', table_args) if field]

                headers = update_headers_from_field_names(parsed_search_results, chosen_fields)

    human_readable = tableToMarkdown("Splunk Search results for query: {}".format(args['query']),
                                     parsed_search_results, headers)
    return human_readable


def update_headers_from_field_names(search_result, chosen_fields):
    headers = []
    search_result_keys = search_result[0].keys()
    for field in chosen_fields:
        if field[-1] == '*':
            temp_field = field.replace('*', '.*')
            for key in search_result_keys:
                if re.search(temp_field, key):
                    headers.append(key)

        elif field in search_result_keys:
            headers.append(field)

    return headers


def get_current_results_batch(search_job, batch_size, results_offset):
    current_batch_kwargs = {
        "count": batch_size,
        "offset": results_offset
    }

    results_batch = search_job.results(**current_batch_kwargs)
    return results_batch


def parse_batch_of_results(current_batch_of_results, max_results_to_add, app):
    parsed_batch_results = []
    batch_dbot_scores = []
    results_reader = results.ResultsReader(io.BufferedReader(ResponseReaderWrapper(current_batch_of_results)))
    for item in results_reader:
        if isinstance(item, results.Message):
            if "Error in" in item.message:
                raise ValueError(item.message)
            parsed_batch_results.append(convert_to_str(item.message))

        elif isinstance(item, dict):
            if demisto.get(item, 'host'):
                batch_dbot_scores.append({'Indicator': item['host'], 'Type': 'hostname',
                                          'Vendor': 'Splunk', 'Score': 0, 'isTypedIndicator': True})
            if app:
                item['app'] = app
            # Normal events are returned as dicts
            parsed_batch_results.append(item)

        if len(parsed_batch_results) >= max_results_to_add:
            break
    return parsed_batch_results, batch_dbot_scores


def splunk_search_command(service):
    args = demisto.args()

    query = build_search_query(args)
    search_kwargs = build_search_kwargs(args)
    search_job = service.jobs.create(query, **search_kwargs)  # type: ignore
    num_of_results_from_query = search_job["resultCount"]

    results_limit = float(demisto.args().get("event_limit", 100))
    if results_limit == 0.0:
        # In Splunk, a result limit of 0 means no limit.
        results_limit = float("inf")
    batch_size = int(demisto.args().get("batch_limit", 25000))

    results_offset = 0
    total_parsed_results = []  # type: List[Dict[str,Any]]
    dbot_scores = []  # type: List[Dict[str,Any]]

    while len(total_parsed_results) < int(num_of_results_from_query) and len(total_parsed_results) < results_limit:
        current_batch_of_results = get_current_results_batch(search_job, batch_size, results_offset)
        max_results_to_add = results_limit - len(total_parsed_results)
        parsed_batch_results, batch_dbot_scores = parse_batch_of_results(current_batch_of_results, max_results_to_add,
                                                                         search_kwargs.get('app', ''))
        total_parsed_results.extend(parsed_batch_results)
        dbot_scores.extend(batch_dbot_scores)

        results_offset += batch_size

    entry_context = create_entry_context(args, total_parsed_results, dbot_scores)
    human_readable = build_search_human_readable(args, total_parsed_results)

    demisto.results({
        "Type": 1,
        "Contents": total_parsed_results,
        "ContentsFormat": "json",
        "EntryContext": entry_context,
        "HumanReadable": human_readable
    })


def splunk_job_create_command(service):
    query = demisto.args()['query']
    app = demisto.args().get('app', '')
    if not query.startswith('search'):
        query = 'search ' + query
    search_kwargs = {
        "exec_mode": "normal",
        "app": app
    }
    search_job = service.jobs.create(query, **search_kwargs)  # type: ignore

    entry_context = {
        'Splunk.Job': search_job.sid
    }
    demisto.results({
        "Type": 1,
        "ContentsFormat": formats['text'],
        "Contents": "Splunk Job created with SID: " + search_job.sid,
        "EntryContext": entry_context
    })


def splunk_results_command(service):
    res = []
    sid = demisto.args().get('sid', '')
    try:
        job = service.job(sid)
    except HTTPError as error:
        if error.message == 'HTTP 404 Not Found -- Unknown sid.':
            demisto.results("Found no job for sid: {}".format(sid))
        else:
            return_error(error.message, error)
    else:
        for result in results.ResultsReader(job.results()):
            if isinstance(result, results.Message):
                demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(result.message)})
            elif isinstance(result, dict):
                # Normal events are returned as dicts
                res.append(result)

        demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(res)})


def fetch_incidents(service):
    last_run = demisto.getLastRun() and demisto.getLastRun()['time']
    search_offset = demisto.getLastRun().get('offset', 0)

    incidents = []
    current_time_for_fetch = datetime.utcnow()
    if demisto.get(demisto.params(), 'timezone'):
        timezone = demisto.params()['timezone']
        current_time_for_fetch = current_time_for_fetch + timedelta(minutes=int(timezone))

    now = current_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
    if demisto.get(demisto.params(), 'useSplunkTime'):
        now = get_current_splunk_time(service)
        current_time_in_splunk = datetime.strptime(now, SPLUNK_TIME_FORMAT)
        current_time_for_fetch = current_time_in_splunk

    if len(last_run) == 0:
        fetch_time_in_minutes = parse_time_to_minutes()
        start_time_for_fetch = current_time_for_fetch - timedelta(minutes=fetch_time_in_minutes)
        last_run = start_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)

    earliest_fetch_time_fieldname = demisto.params().get("earliest_fetch_time_fieldname", "index_earliest")
    latest_fetch_time_fieldname = demisto.params().get("latest_fetch_time_fieldname", "index_latest")

    kwargs_oneshot = {earliest_fetch_time_fieldname: last_run,
                      latest_fetch_time_fieldname: now, "count": FETCH_LIMIT, 'offset': search_offset}

    searchquery_oneshot = demisto.params()['fetchQuery']

    if demisto.get(demisto.params(), 'extractFields'):
        extractFields = demisto.params()['extractFields']
        extra_raw_arr = extractFields.split(',')
        for field in extra_raw_arr:
            field_trimmed = field.strip()
            searchquery_oneshot = searchquery_oneshot + ' | eval ' + field_trimmed + '=' + field_trimmed

    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)  # type: ignore
    reader = results.ResultsReader(oneshotsearch_results)
    for item in reader:
        inc = notable_to_incident(item)
        incidents.append(inc)

    demisto.incidents(incidents)
    if len(incidents) < FETCH_LIMIT:
        demisto.setLastRun({'time': now, 'offset': 0})
    else:
        demisto.setLastRun({'time': last_run, 'offset': search_offset + FETCH_LIMIT})


def parse_time_to_minutes():
    """
    Calculate how much time to fetch back in minutes
    Returns (int): Time to fetch back in minutes
    """
    number_of_times, time_unit = FETCH_TIME.split(' ')
    if str(number_of_times).isdigit():
        number_of_times = int(number_of_times)
    else:
        return_error("Error: Invalid fetch time, need to be a positive integer with the time unit afterwards"
                     " e.g '2 months, 4 days'.")
    # If the user input contains a plural of a time unit, for example 'hours', we remove the 's' as it doesn't
    # impact the minutes in that time unit
    if time_unit[-1] == 's':
        time_unit = time_unit[:-1]
    time_unit_value_in_minutes = TIME_UNIT_TO_MINUTES.get(time_unit.lower())
    if time_unit_value_in_minutes:
        return number_of_times * time_unit_value_in_minutes

    return_error('Error: Invalid time unit.')


def splunk_get_indexes_command(service):
    indexes = service.indexes  # type: ignore
    indexesNames = []
    for index in indexes:
        index_json = {'name': index.name, 'count': index["totalEventCount"]}
        indexesNames.append(index_json)
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(indexesNames),
                     'HumanReadable': tableToMarkdown("Splunk Indexes names", indexesNames, '')})


def splunk_submit_event_command(service):
    try:
        index = service.indexes[demisto.args()['index']]  # type: ignore
    except KeyError:
        demisto.results({'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
                         'Contents': "Found no Splunk index: " + demisto.args()['index']})

    else:
        data = demisto.args()['data']
        data_formatted = data.encode('utf8')
        r = index.submit(data_formatted, sourcetype=demisto.args()['sourcetype'], host=demisto.args()['host'])
        demisto.results('Event was created in Splunk index: ' + r.name)


def splunk_submit_event_hec(hec_token, baseurl, event, fields, host, index, source_type, source, time_):

    if hec_token is None:
        raise Exception('The HEC Token was not provided')

    args = assign_params(
        event=event,
        host=host,
        fields={'fields': fields} if fields else None,
        index=index,
        sourcetype=source_type,
        source=source,
        time=time_
    )

    headers = {
        'Authorization': 'Splunk {}'.format(hec_token),
        'Content-Type': 'application/json'
    }

    response = requests.post(baseurl + '/services/collector/event', data=json.dumps(args), headers=headers,
                             verify=VERIFY_CERTIFICATE)
    return response


def splunk_submit_event_hec_command():

    hec_token = demisto.params().get('hec_token')
    baseurl = demisto.params().get('hec_url')
    if baseurl is None:
        raise Exception('The HEC URL was not provided.')

    event = demisto.args().get('event')
    host = demisto.args().get('host')
    fields = demisto.args().get('fields')
    index = demisto.args().get('index')
    source_type = demisto.args().get('source_type')
    source = demisto.args().get('source')
    time_ = demisto.args().get('time')

    response_info = splunk_submit_event_hec(hec_token, baseurl, event, fields, host, index, source_type, source, time_)

    if 'Success' not in response_info.text:
        return_error('Could not send event to Splunk ' + response_info.text.encode('utf8'))
    else:
        demisto.results('The event was sent successfully to Splunk.')


def splunk_edit_notable_event_command(proxy):
    if not proxy:
        os.environ["HTTPS_PROXY"] = ""
        os.environ["HTTP_PROXY"] = ""
        os.environ["https_proxy"] = ""
        os.environ["http_proxy"] = ""
    baseurl = 'https://' + demisto.params()['host'] + ':' + demisto.params()['port'] + '/'
    username = demisto.params()['authentication']['identifier']
    password = demisto.params()['authentication']['password']
    auth_req = requests.post(baseurl + 'services/auth/login',
                             data={'username': username, 'password': password, 'output_mode': 'json'},
                             verify=VERIFY_CERTIFICATE)

    sessionKey = auth_req.json()['sessionKey']
    eventIDs = None
    if demisto.get(demisto.args(), 'eventIDs'):
        eventIDsStr = demisto.args()['eventIDs']
        eventIDs = eventIDsStr.split(",")
    status = None
    if demisto.get(demisto.args(), 'status'):
        status = int(demisto.args()['status'])
    response_info = updateNotableEvents(sessionKey=sessionKey, baseurl=baseurl,
                                        comment=demisto.get(demisto.args(), 'comment'), status=status,
                                        urgency=demisto.get(demisto.args(), 'urgency'),
                                        owner=demisto.get(demisto.args(), 'owner'), eventIDs=eventIDs)
    if 'success' not in response_info or not response_info['success']:
        demisto.results({'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
                         'Contents': "Could not update notable "
                                     "events: " + demisto.args()['eventIDs'] + ' : ' + str(response_info)})

    demisto.results('Splunk ES Notable events: ' + response_info['message'])


def splunk_job_status(service):
    sid = demisto.args().get('sid')
    try:
        job = service.job(sid)
    except HTTPError as error:
        if error.message == 'HTTP 404 Not Found -- Unknown sid.':
            demisto.results("Not found job for SID: {}".format(sid))
        else:
            return_error(error.message, error)
    else:
        status = job.state.content.get('dispatchState')
        entry_context = {
            'SID': sid,
            'Status': status
        }
        context = {'Splunk.JobStatus(val.SID && val.SID === obj.SID)': entry_context}
        human_readable = tableToMarkdown('Splunk Job Status', entry_context)
        demisto.results({
            "Type": entryTypes['note'],
            "Contents": entry_context,
            "ContentsFormat": formats["json"],
            "EntryContext": context,
            "HumanReadable": human_readable
        })


def splunk_parse_raw_command():
    raw = demisto.args().get('raw', '')
    rawDict = rawToDict(raw)
    ec = {}
    ec['Splunk.Raw.Parsed'] = rawDict
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(rawDict), "EntryContext": ec})


def test_module(service):
    if demisto.params().get('isFetch'):
        t = datetime.utcnow() - timedelta(hours=1)
        time = t.strftime(SPLUNK_TIME_FORMAT)
        kwargs_oneshot = {'count': 1, 'earliest_time': time}
        searchquery_oneshot = demisto.params()['fetchQuery']
        try:
            service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)  # type: ignore
        except HTTPError as error:
            return_error(str(error))


def replace_keys(data):
    if not isinstance(data, dict):
        return data
    for key in list(data.keys()):
        value = data.pop(key)
        for character in PROBLEMATIC_CHARACTERS:
            key = key.replace(character, REPLACE_WITH)

        data[key] = value
    return data


def main():
    service = None
    proxy = demisto.params().get('proxy')
    use_requests_handler = demisto.params().get('use_requests_handler')

    connection_args = {
        'host': demisto.params()['host'],
        'port': demisto.params()['port'],
        'app': demisto.params().get('app'),
        'username': demisto.params()['authentication']['identifier'],
        'password': demisto.params()['authentication']['password'],
        'verify': VERIFY_CERTIFICATE
    }

    if use_requests_handler:
        handle_proxy()
        connection_args['handler'] = requests_handler

    elif proxy:
        connection_args['handler'] = handler(proxy)

    try:
        service = client.connect(**connection_args)
    except urllib2.URLError as e:
        if e.reason.errno == 1 and sys.version_info < (2, 6, 3):  # type: ignore
            pass
        else:
            raise

    if service is None:
        demisto.error("Could not connect to SplunkPy")

    # The command demisto.command() holds the command sent from the user.
    if demisto.command() == 'test-module':
        test_module(service)
        demisto.results('ok')
    if demisto.command() == 'splunk-search':
        splunk_search_command(service)
    if demisto.command() == 'splunk-job-create':
        splunk_job_create_command(service)
    if demisto.command() == 'splunk-results':
        splunk_results_command(service)
    if demisto.command() == 'fetch-incidents':
        fetch_incidents(service)
    if demisto.command() == 'splunk-get-indexes':
        splunk_get_indexes_command(service)
    if demisto.command() == 'splunk-submit-event':
        splunk_submit_event_command(service)
    if demisto.command() == 'splunk-notable-event-edit':
        splunk_edit_notable_event_command(proxy)
    if demisto.command() == 'splunk-parse-raw':
        splunk_parse_raw_command()
    if demisto.command() == 'splunk-submit-event-hec':
        splunk_submit_event_hec_command()
    if demisto.command() == 'splunk-job-status':
        splunk_job_status(service)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
