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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define utf8 as default encoding
reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=maybe-no-member

SPLUNK_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
VERIFY_CERTIFICATE = not bool(demisto.params().get('unsecure'))
FETCH_LIMIT = int(demisto.params().get('fetch_limit', 50))
FETCH_LIMIT = max(min(50, FETCH_LIMIT), 1)


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
    raw = raw.strip("}")
    raw = raw.strip("{")
    key_val_arr = raw.split(",")

    for key_val in key_val_arr:
        single_key_val = key_val.split("=")
        if len(single_key_val) > 1:
            val = single_key_val[1]
            val = val.strip("\\")
            val = val.strip("\"")
            val = val.strip("\\")
            key = single_key_val[0].strip()

            alreadyThere = False
            for dictkey, dictvalue in result.items():
                if dictkey == key:
                    alreadyThere = True
                    result[dictkey] = dictvalue + "," + val

            if not alreadyThere:
                result[key] = val

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
        return False

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
    incident["occurred"] = event["_time"]
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


def request(url, message, **kwargs):
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
    except urllib2.HTTPError as response:
        pass  # Propagate HTTP errors via the returned response message
    return {
        'status': response.code,  # type: ignore
        'reason': response.msg,  # type: ignore
        'headers': response.info().dict,  # type: ignore
        'body': StringIO(response.read())  # type: ignore
    }


service = None
proxy = demisto.params()['proxy']
if proxy:
    try:
        service = client.connect(
            handler=handler(proxy),
            host=demisto.params()['host'],
            port=demisto.params()['port'],
            app=demisto.params().get('app'),
            username=demisto.params()['authentication']['identifier'],
            password=demisto.params()['authentication']['password'],
            verify=VERIFY_CERTIFICATE)
    except urllib2.URLError as e:
        if e.reason.errno == 1 and sys.version_info < (2, 6, 3):  # type: ignore
            pass
        else:
            raise
else:
    service = client.connect(
        host=demisto.params()['host'],
        port=demisto.params()['port'],
        app=demisto.params().get('app'),
        username=demisto.params()['authentication']['identifier'],
        password=demisto.params()['authentication']['password'],
        verify=VERIFY_CERTIFICATE)

if service is None:
    demisto.error("Could not connect to SplunkPy")
    sys.exit(0)

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # for app in service.apps:
    #    print app.name
    if len(service.jobs) >= 0:
        demisto.results('ok')
    sys.exit(0)
if demisto.command() == 'splunk-search':
    t = datetime.utcnow() - timedelta(days=7)
    time_str = t.strftime(SPLUNK_TIME_FORMAT)
    kwargs_oneshot = {"earliest_time": time_str}  # type: Dict[str,Any]
    if demisto.get(demisto.args(), 'earliest_time'):
        kwargs_oneshot['earliest_time'] = demisto.args()['earliest_time']
    if demisto.get(demisto.args(), 'latest_time'):
        kwargs_oneshot['latest_time'] = demisto.args()['latest_time']
    if demisto.get(demisto.args(), 'event_limit'):
        kwargs_oneshot['count'] = int(demisto.args()['event_limit'])
    searchquery_oneshot = demisto.args()['query']
    searchquery_oneshot = searchquery_oneshot.encode('utf-8')
    if not searchquery_oneshot.startswith('search') and not searchquery_oneshot.startswith('Search')\
            and not searchquery_oneshot.startswith('|'):
        searchquery_oneshot = 'search ' + searchquery_oneshot
    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)

    reader = results.ResultsReader(oneshotsearch_results)
    res = []
    dbot_scores = []  # type: List[Dict[str,Any]]
    for item in reader:
        if isinstance(item, results.Message):
            if "Error in" in item.message:
                raise ValueError(item.message)
            res.append(convert_to_str(item.message))

        elif isinstance(item, dict):
            if demisto.get(item, 'host'):
                dbot_scores.append({'Indicator': item['host'], 'Type': 'hostname',
                                    'Vendor': 'Splunk', 'Score': 0, 'isTypedIndicator': True})
            # Normal events are returned as dicts
            res.append(item)
    ec = {}
    ec['Splunk.Result'] = res
    if len(dbot_scores) > 0:
        ec['DBotScore'] = dbot_scores

    headers = ""
    if (res and len(res) > 0):
        if not isinstance(res[0], dict):
            headers = "results"

    human_readable = tableToMarkdown("Splunk Search results \n\n Results for query: {}".format(demisto.args()['query']),
                                     res, headers)

    demisto.results({
        "Type": 1,
        "Contents": res,
        "ContentsFormat": "json",
        "EntryContext": ec,
        "HumanReadable": human_readable
    })

    sys.exit(0)
if demisto.command() == 'splunk-job-create':
    searchquery_normal = demisto.args()['query']
    if not searchquery_normal.startswith('search'):
        searchquery_normal = 'search ' + searchquery_normal
    kwargs_normalsearch = {"exec_mode": "normal"}
    job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)

    ec = {}
    ec['Splunk.Job'] = job.sid
    demisto.results({"Type": 1, "ContentsFormat": formats['text'],
                     "Contents": "Splunk Job created with SID: " + job.sid, "EntryContext": ec})
    sys.exit(0)
if demisto.command() == 'splunk-results':
    jobs = service.jobs
    found = False
    res = []
    for job in jobs:
        if job.sid == demisto.args()['sid']:
            rr = results.ResultsReader(job.results())
            for result in rr:
                if isinstance(result, results.Message):
                    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(result.message)})
                elif isinstance(result, dict):
                    # Normal events are returned as dicts
                    res.append(result)
            found = True
    if not found:
        demisto.results("Found no job for sid: " + demisto.args()['sid'])
    if found:
        demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(res)})
    sys.exit(0)
if demisto.command() == 'fetch-incidents':
    lastRun = demisto.getLastRun() and demisto.getLastRun()['time']
    search_offset = demisto.getLastRun().get('offset', 0)

    incidents = []
    t = datetime.utcnow()
    if demisto.get(demisto.params(), 'timezone'):
        timezone = demisto.params()['timezone']
        t = t + timedelta(minutes=int(timezone))

    now = t.strftime(SPLUNK_TIME_FORMAT)
    if demisto.get(demisto.params(), 'useSplunkTime'):
        now = get_current_splunk_time(service)
        t = datetime.strptime(now, SPLUNK_TIME_FORMAT)
    if len(lastRun) == 0:
        t = t - timedelta(minutes=10)
        lastRun = t.strftime(SPLUNK_TIME_FORMAT)

    earliest_fetch_time_fieldname = demisto.params().get("earliest_fetch_time_fieldname", "index_earliest")
    latest_fetch_time_fieldname = demisto.params().get("latest_fetch_time_fieldname", "index_latest")

    kwargs_oneshot = {earliest_fetch_time_fieldname: lastRun,
                      latest_fetch_time_fieldname: now, "count": FETCH_LIMIT, 'offset': search_offset}

    searchquery_oneshot = demisto.params()['fetchQuery']

    if demisto.get(demisto.params(), 'extractFields'):
        extractFields = demisto.params()['extractFields']
        extra_raw_arr = extractFields.split(',')
        for field in extra_raw_arr:
            field_trimmed = field.strip()
            searchquery_oneshot = searchquery_oneshot + ' | eval ' + field_trimmed + '=' + field_trimmed

    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
    reader = results.ResultsReader(oneshotsearch_results)
    for item in reader:
        inc = notable_to_incident(item)
        incidents.append(inc)

    demisto.incidents(incidents)
    if len(incidents) < FETCH_LIMIT:
        demisto.setLastRun({'time': now, 'offset': 0})
    else:
        demisto.setLastRun({'time': lastRun, 'offset': search_offset + FETCH_LIMIT})
    sys.exit(0)

if demisto.command() == 'splunk-get-indexes':
    indexes = service.indexes
    indexesNames = []
    for index in indexes:
        index_json = {'name': index.name, 'count': index["totalEventCount"]}
        indexesNames.append(index_json)
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(indexesNames),
                     'HumanReadable': tableToMarkdown("Splunk Indexes names", indexesNames, '')})
    sys.exit(0)

if demisto.command() == 'splunk-submit-event':
    try:
        index = service.indexes[demisto.args()['index']]
    except KeyError:
        demisto.results({'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
                         'Contents': "Found no Splunk index: " + demisto.args()['index']})
        sys.exit(0)
    else:
        data = demisto.args()['data']
        data_formatted = data.encode('utf8')
        r = index.submit(data_formatted, sourcetype=demisto.args()['sourcetype'], host=demisto.args()['host'])
        demisto.results('Event was created in Splunk index: ' + r.name)
    sys.exit(0)

if demisto.command() == 'splunk-notable-event-edit':
    if not proxy:
        os.environ["HTTPS_PROXY"] = ""
        os.environ["HTTP_PROXY"] = ""
        os.environ["https_proxy"] = ""
        os.environ["http_proxy"] = ""
    baseurl = 'https://' + demisto.params()['host'] + ':' + demisto.params()['port'] + '/'
    username = demisto.params()['authentication']['identifier']
    password = demisto.params()['authentication']['password']
    auth_req = requests.post(baseurl + 'services/auth/login',
                             data={'username': username, 'password': password, 'output_mode': 'json'}, verify=VERIFY_CERTIFICATE)

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
        sys.exit(0)
    demisto.results('Splunk ES Notable events: ' + response_info['message'])
    sys.exit(0)
if demisto.command() == 'splunk-parse-raw':
    raw = demisto.args()['raw']
    rawDict = rawToDict(raw)
    ec = {}
    ec['Splunk.Raw.Parsed'] = rawDict
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(rawDict), "EntryContext": ec})
    sys.exit(0)
