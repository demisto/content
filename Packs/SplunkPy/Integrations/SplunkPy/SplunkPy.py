from splunklib.binding import HTTPError, namespace

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
FETCH_LIMIT = int(params.get('fetch_limit')) if params.get('fetch_limit') else 50
FETCH_LIMIT = max(min(200, FETCH_LIMIT), 1)
PROBLEMATIC_CHARACTERS = ['.', '(', ')', '[', ']']
REPLACE_WITH = '_'
REPLACE_FLAG = params.get('replaceKeys', False)
FETCH_TIME = demisto.params().get('fetch_time')
PROXIES = handle_proxy()
TIME_UNIT_TO_MINUTES = {'minute': 1, 'hour': 60, 'day': 24 * 60, 'week': 7 * 24 * 60, 'month': 30 * 24 * 60,
                        'year': 365 * 24 * 60}
ENABLED_ENRICHMENTS = params.get('enabled_enrichments', [])

# ===== Enrichment Mechanism Constants =====
DRILLDOWN_ENRICHMENT = 'Drilldown'
ASSET_ENRICHMENT = 'Asset'
IDENTITY_ENRICHMENT = 'Identity'
SUBMITTED_NOTABLES = 'submitted_notables'
EVENT_ID = 'event_id'
JOB_CREATION_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
LAST_RUN_OVER_FETCH = 'last_run_over_fetch'
LAST_RUN_REGULAR_FETCH = 'last_run_regular_fetch'
NUM_FETCHED_NOTABLES = 'num_fetched_notables'
NOT_YET_SUBMITTED_NOTABLES = 'not_yet_submitted_notables'
INFO_MIN_TIME = "info_min_time"
INFO_MAX_TIME = "info_max_time"
INCIDENTS = 'incidents'
DUMMY = 'dummy'
NOTABLE = 'notable'
ENRICHMENTS = 'enrichments'
MAX_HANDLE_NOTABLES = 20
MAX_SUBMIT_NOTABLES = 30
CACHE = 'cache'
STATUS = 'status'
DATA = 'data'
TYPE = 'type'
ID = 'id'
CREATION_TIME = 'creation_time'

DRILLDOWN_REGEX = r'([^\s\$]+)=(\$[^\$]+\$)|(\$[^\$]+\$)'

ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS = {
    DRILLDOWN_ENRICHMENT: 'successful_drilldown_enrichment',
    ASSET_ENRICHMENT: 'successful_asset_enrichment',
    IDENTITY_ENRICHMENT: 'successful_identity_enrichment'
}


class Enrichment:
    """ A class to represent an Enrichment. Each notable has 3 possible enrichments: Drilldown, Asset & Identity

    Attributes:
        type (str): The enrichment type. Possible values are: Drilldown, Asset & Identity.
        id (str): The enrichment's job id in Splunk server.
        data (list): The enrichment's data list (events retrieved from the job's search)
        creation_time (str): The enrichment's creation time in ISO format.
        status (str): The enrichment's status.

    """
    FAILED = 'Enrichment failed'
    IN_PROGRESS = 'Enrichment is in progress'
    SUCCESSFUL = 'Enrichment successfully handled'

    def __init__(self, enrichment_type, status=None, enrichment_id=None, data=None, creation_time=None):
        self.type = enrichment_type
        self.id = enrichment_id
        self.data = data if data else []
        self.creation_time = creation_time if creation_time else datetime.utcnow().isoformat()
        self.status = status if status else Enrichment.IN_PROGRESS

    @property
    def status(self):
        return self.status

    @status.setter
    def status(self, status):
        self.status = status

    @classmethod
    def from_json(cls, enrichment_dict):
        """ Deserialization method.

        Args:
            enrichment_dict (dict): The enrichment dict in JSON format.

        Returns:
            An instance of the Enrichment class constructed from JSON representation.

        """
        return cls(
            enrichment_type=enrichment_dict.get(TYPE),
            data=enrichment_dict.get(DATA),
            status=enrichment_dict.get(STATUS),
            enrichment_id=enrichment_dict.get(ID),
            creation_time=enrichment_dict.get(CREATION_TIME)
        )


class Notable:
    """ A class to represent a notable.

    Attributes:
        data (dict): The notable data.
        id (str): The notable's id.
        enrichments (list): The list of all enrichments that needs to handle.

    """

    def __init__(self, data, enrichments=None, notable_id=None):
        self.data = data
        self.enrichments = enrichments if enrichments else []
        if notable_id:
            self.id = notable_id
        else:
            if EVENT_ID in data:
                self.id = data[EVENT_ID]
            else:
                if ENABLED_ENRICHMENTS:
                    raise Exception('When using the enrichment mechanism, an event_id field is needed, and thus, '
                                    'one must use a fetch query of the following format: search `notable` .......\n'
                                    'Please re-edit the fetchQuery parameter in the integration configuration, reset '
                                    'the fetch mechanism using the splunk-reset-enriching-fetch-mechanism command and '
                                    'run the fetch again.')
                else:
                    self.id = None

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, notable_id):
        self.id = notable_id

    @property
    def data(self):
        return self.data

    @data.setter
    def data(self, data):
        self.data = data

    def to_incident(self):
        for e in self.enrichments:
            self.data[e.type] = e.data
            self.data[ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS[e.type]] = e.status == Enrichment.SUCCESSFUL
        return notable_to_incident(self.data)

    @classmethod
    def from_json(cls, notable_dict):
        """ Deserialization method.

        Args:
            notable_dict: The notable dict in JSON format.

        Returns:
            An instance of the Enrichment class constructed from JSON representation.

        """
        return cls(
            data=notable_dict.get(DATA),
            enrichments=list(map(Enrichment.from_json, notable_dict.get(ENRICHMENTS))),
            notable_id=notable_dict.get(ID)
        )


class Cache:
    """ A class to represent the cache for the enriching fetch mechanism.

    Attributes:
        not_yet_submitted_notables (list): The list of all notables that were fetched but not yet submitted.
        submitted_notables (list): The list of all submitted notables that needs to be handled.
        last_run_regular_fetch (dict): The last run object to set in case of regular fetch (num_incidents < FETCH_LIMIT)
        last_run_over_fetch (dict): The last run object to set in case of over fetch (num_incidents >= FETCH_LIMIT)
        num_fetched_notables (int): The number of fetched notables from Splunk.

    """

    def __init__(self, not_yet_submitted_notables=None, submitted_notables=None, last_run_regular_fetch=None,
                 last_run_over_fetch=None, num_fetched_notables=0):
        self.not_yet_submitted_notables = not_yet_submitted_notables if not_yet_submitted_notables else []
        self.submitted_notables = submitted_notables if submitted_notables else []
        self.last_run_regular_fetch = last_run_regular_fetch if last_run_regular_fetch else {}
        self.last_run_over_fetch = last_run_over_fetch if last_run_over_fetch else {}
        self.num_fetched_notables = num_fetched_notables

    @property
    def not_yet_submitted_notables(self):
        return self.not_yet_submitted_notables

    @not_yet_submitted_notables.setter
    def not_yet_submitted_notables(self, not_yet_enriched_notables):
        self.not_yet_submitted_notables = not_yet_enriched_notables

    @property
    def submitted_notables(self):
        return self.submitted_notables

    @submitted_notables.setter
    def submitted_notables(self, submitted_notables):
        self.submitted_notables = submitted_notables

    @property
    def last_run_regular_fetch(self):
        return self.last_run_regular_fetch

    @last_run_regular_fetch.setter
    def last_run_regular_fetch(self, last_run_regular_fetch):
        self.last_run_regular_fetch = last_run_regular_fetch

    @property
    def last_run_over_fetch(self):
        return self.last_run_over_fetch

    @last_run_over_fetch.setter
    def last_run_over_fetch(self, last_run_over_fetch):
        self.last_run_over_fetch = last_run_over_fetch

    @property
    def num_fetched_notables(self):
        return self.num_fetched_notables

    @num_fetched_notables.setter
    def num_fetched_notables(self, num_fetched_notables):
        self.num_fetched_notables = num_fetched_notables

    @classmethod
    def from_json(cls, cache_dict):
        """ Deserialization method.

        Args:
            cache_dict: The cache dict in JSON format.

        Returns:
            An instance of the Cache class constructed from JSON representation.

        """
        return cls(
            not_yet_submitted_notables=list(map(Notable.from_json, cache_dict.get(NOT_YET_SUBMITTED_NOTABLES, []))),
            submitted_notables=list(map(Notable.from_json, cache_dict.get(SUBMITTED_NOTABLES, []))),
            last_run_regular_fetch=cache_dict.get(LAST_RUN_REGULAR_FETCH, {}),
            last_run_over_fetch=cache_dict.get(LAST_RUN_OVER_FETCH, {}),
            num_fetched_notables=cache_dict.get(NUM_FETCHED_NOTABLES, 0)
        )

    @classmethod
    def load_from_integration_context(cls, integration_context):
        return Cache.from_json(json.loads(integration_context.get(CACHE, "{}")))

    def dump_to_integration_context(self, integration_context):
        integration_context[CACHE] = json.dumps(self, default=lambda obj: obj.__dict__)
        set_integration_context(integration_context)


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
    try:
        result = json.loads(raw)
    except ValueError:
        if 'message' in raw:
            raw = raw.replace('"', '').strip('{').strip('}')
            key_val_arr = raw.split(",")
            for key_val in key_val_arr:
                single_key_val = key_val.split(":", 1)
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
    for key, val in event.items():
        # if notable event raw fields were sent in double quotes (e.g. "DNS Destination") and the field does not exist
        # in the event, then splunk returns the field with the key as value (e.g. ("DNS Destination", "DNS Destination")
        # so we go over the fields, and check if the key equals the value and set the value to be empty string
        if key == val:
            demisto.debug('Found notable event raw field [{}] with key that equals the value - replacing the value '
                          'with empty string'.format(key))
            event[key] = ''
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


def fetch_notables(service, cache_object=None, enrich_notables=False):
    demisto.debug("Fetching new notables")
    last_run = demisto.getLastRun()
    last_run = last_run and 'time' in last_run and last_run['time']
    search_offset = demisto.getLastRun().get('offset', 0)

    incidents = []
    current_time_for_fetch = datetime.utcnow()
    dem_params = demisto.params()
    if demisto.get(dem_params, 'timezone'):
        timezone = dem_params['timezone']
        current_time_for_fetch = current_time_for_fetch + timedelta(minutes=int(timezone))

    now = current_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
    if demisto.get(dem_params, 'useSplunkTime'):
        now = get_current_splunk_time(service)
        current_time_in_splunk = datetime.strptime(now, SPLUNK_TIME_FORMAT)
        current_time_for_fetch = current_time_in_splunk

    if not last_run:
        fetch_time_in_minutes = parse_time_to_minutes()
        start_time_for_fetch = current_time_for_fetch - timedelta(minutes=fetch_time_in_minutes)
        last_run = start_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)

    earliest_fetch_time_fieldname = dem_params.get("earliest_fetch_time_fieldname", "earliest_time")
    latest_fetch_time_fieldname = dem_params.get("latest_fetch_time_fieldname", "latest_time")

    kwargs_oneshot = {earliest_fetch_time_fieldname: last_run,
                      latest_fetch_time_fieldname: now, "count": FETCH_LIMIT, 'offset': search_offset}

    searchquery_oneshot = dem_params['fetchQuery']

    if demisto.get(dem_params, 'extractFields'):
        extractFields = dem_params['extractFields']
        extra_raw_arr = extractFields.split(',')
        for field in extra_raw_arr:
            field_trimmed = field.strip()
            searchquery_oneshot = searchquery_oneshot + ' | eval ' + field_trimmed + '=' + field_trimmed

    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)  # type: ignore
    reader = results.ResultsReader(oneshotsearch_results)

    last_run_regular_fetch = {'time': now, 'offset': 0}
    last_run_over_fetch = {'time': last_run, 'offset': search_offset + FETCH_LIMIT}

    if not enrich_notables:
        demisto.info("Creating incidents from fetched notables without enrichment")
        for item in reader:
            notable = Notable(data=item)
            incidents.append(notable.to_incident())

        demisto.incidents(incidents)
        if len(incidents) < FETCH_LIMIT:
            demisto.setLastRun(last_run_regular_fetch)
        else:
            demisto.setLastRun(last_run_over_fetch)
    else:
        handle_enriched_fetch(reader, last_run_regular_fetch, last_run_over_fetch, cache_object)


def handle_enriched_fetch(reader, last_run_regular_fetch, last_run_over_fetch, cache_object):
    """ Maintains all data for the enriching fetch mechanism

    Args:
        reader: The Splunk results reader
        last_run_regular_fetch: The last run object in regular case (len(incident) < FETCH_LIMIT)
        last_run_over_fetch: The last run object in over fetch case (len(incident) >= FETCH_LIMIT)
        cache_object (Cache): The enrichment mechanism cache object

    """

    last_run = demisto.getLastRun()
    if DUMMY not in last_run:
        # we add dummy data to the last run to differentiate between the fetch-incidents triggered to the
        # fetch-incidents running as part of "Pull from instance" in Classification & Mapping
        last_run.update({DUMMY: DUMMY})
        demisto.setLastRun(last_run)

    for item in reader:
        cache_object.not_yet_submitted_notables.append(Notable(data=item))
        cache_object.num_fetched_notables += 1

    # maintaining last run metadata to be set when we finish handling all notables
    cache_object.last_run_regular_fetch = last_run_regular_fetch
    cache_object.last_run_over_fetch = last_run_over_fetch
    demisto.info("Fetched {} notables.".format(cache_object.num_fetched_notables))


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
    limit = int(demisto.args().get('limit', '100'))
    try:
        job = service.job(sid)
    except HTTPError as error:
        if error.message == 'HTTP 404 Not Found -- Unknown sid.':
            demisto.results("Found no job for sid: {}".format(sid))
        else:
            return_error(error.message, error)
    else:
        for result in results.ResultsReader(job.results(count=limit)):
            if isinstance(result, results.Message):
                demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(result.message)})
            elif isinstance(result, dict):
                # Normal events are returned as dicts
                res.append(result)

        demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(res)})


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

    parsed_fields = None
    if fields:
        try:
            parsed_fields = json.loads(fields)
        except Exception:
            parsed_fields = {'fields': fields}

    args = assign_params(
        event=event,
        host=host,
        fields=parsed_fields,
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

    demisto.results('Splunk ES Notable events: ' + response_info.get('message'))


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
    params = demisto.params()
    if params.get('isFetch'):
        t = datetime.utcnow() - timedelta(hours=1)
        time = t.strftime(SPLUNK_TIME_FORMAT)
        kwargs = {'count': 1, 'earliest_time': time}
        query = params['fetchQuery']
        try:
            for item in results.ResultsReader(service.jobs.oneshot(query, **kwargs)):  # type: ignore
                if params.get('enabled_enrichments', []):
                    if 'event_id' not in item:
                        return_error('When using the enrichment mechanism, an event_id field is needed, and thus, '
                                     'one must use a fetch query of the following format: search `notable` .......\n'
                                     'Please re-edit the fetchQuery parameter in the integration configuration, reset '
                                     'the fetch mechanism using the splunk-reset-enriching-fetch-mechanism command and '
                                     'run the fetch again.')
        except HTTPError as error:
            return_error(str(error))
    if params.get('hec_url'):
        headers = {
            'Content-Type': 'application/json'
        }
        try:
            requests.get(params.get('hec_url') + '/services/collector/health', headers=headers,
                         verify=VERIFY_CERTIFICATE)
        except Exception as e:
            return_error("Could not connect to HEC server. Make sure URL and token are correct.", e)


def replace_keys(data):
    if not isinstance(data, dict):
        return data
    for key in list(data.keys()):
        value = data.pop(key)
        for character in PROBLEMATIC_CHARACTERS:
            key = key.replace(character, REPLACE_WITH)

        data[key] = value
    return data


def kv_store_collection_create(service):
    service.kvstore.create(demisto.args()['kv_store_name'])
    return_outputs("KV store collection {} created successfully".format(service.namespace['app']), {}, {})


def kv_store_collection_config(service):
    args = demisto.args()
    app = service.namespace['app']
    kv_store_collection_name = args['kv_store_collection_name']
    kv_store_fields = args['kv_store_fields'].split(',')
    for key_val in kv_store_fields:
        try:
            _key, val = key_val.split('=', 1)
        except ValueError:
            return_error('error when trying to parse {} you possibly forgot to add the field type.'.format(key_val))
        else:
            if _key.startswith('index.'):
                service.kvstore[kv_store_collection_name].update_index(_key.replace('index.', ''), val)
            else:
                service.kvstore[kv_store_collection_name].update_field(_key.replace('field.', ''), val)
    return_outputs("KV store collection {} configured successfully".format(app), {}, {})


def kv_store_collection_add_entries(service):
    args = demisto.args()
    kv_store_data = args.get('kv_store_data', '').encode('utf-8')
    kv_store_collection_name = args['kv_store_collection_name']
    indicator_path = args.get('indicator_path')
    service.kvstore[kv_store_collection_name].data.insert(kv_store_data)
    timeline = None
    if indicator_path:
        indicator = extract_indicator(indicator_path, [json.loads(kv_store_data)])
        timeline = {
            'Value': indicator,
            'Message': 'Indicator added to {} store in Splunk'.format(kv_store_collection_name),
            'Category': 'Integration Update'
        }
    return_outputs("Data added to {}".format(kv_store_collection_name), timeline=timeline)


def kv_store_collections_list(service):
    app_name = service.namespace['app']
    names = list(map(lambda x: x.name, service.kvstore.iter()))
    human_readable = "list of collection names {}\n| name |\n| --- |\n|{}|".format(app_name, '|\n|'.join(names))
    entry_context = {"Splunk.CollectionList": names}
    return_outputs(human_readable, entry_context, entry_context)


def kv_store_collection_data_delete(service):
    args = demisto.args()
    kv_store_collection_name = args['kv_store_collection_name'].split(',')
    for store in kv_store_collection_name:
        service.kvstore[store].data.delete()
    return_outputs('The values of the {} were deleted successfully'.format(args['kv_store_collection_name']), {}, {})


def kv_store_collection_delete(service):
    kv_store_names = demisto.args()['kv_store_name']
    for store in kv_store_names.split(','):
        service.kvstore[store].delete()
    return_outputs('The following KV store {} were deleted successfully'.format(kv_store_names), {}, {})


def build_kv_store_query(kv_store, args):
    if 'key' in args and 'value' in args:
        _type = get_key_type(kv_store, args['key'])
        args['value'] = _type(args['value']) if _type else args['value']
        return json.dumps({args['key']: args['value']})
    elif 'limit' in args:
        return {'limit': args['limit']}
    else:
        return args.get('query', '{}')


def kv_store_collection_data(service):
    args = demisto.args()
    stores = args['kv_store_collection_name'].split(',')

    for i, store_res in enumerate(get_store_data(service)):
        store = service.kvstore[stores[i]]

        if store_res:
            human_readable = tableToMarkdown(name="list of collection values {}".format(store.name),
                                             t=store_res)
            return_outputs(human_readable, {'Splunk.KVstoreData': {store.name: store_res}}, store_res)
        else:

            return_outputs(get_kv_store_config(store), {}, {})


def kv_store_collection_delete_entry(service):
    args = demisto.args()
    store_name = args['kv_store_collection_name']
    indicator_path = args.get('indicator_path')
    store = service.kvstore[store_name]
    query = build_kv_store_query(store, args)
    store_res = next(get_store_data(service))
    if indicator_path:
        indicators = extract_indicator(indicator_path, store_res)
    else:
        indicators = []
    store.data.delete(query=query)
    timeline = {
        'Value': ','.join(indicators),
        'Message': 'Indicator deleted from {} store in Splunk'.format(store_name),
        'Category': 'Integration Update'
    }
    return_outputs('The values of the {} were deleted successfully'.format(store_name), timeline=timeline)


def check_error(service, args):
    app = args.get('app_name')
    store_name = args.get('kv_store_collection_name')
    if app not in service.apps:
        raise DemistoException('app not found')
    elif store_name and store_name not in service.kvstore:
        raise DemistoException('KV Store not found')


def get_key_type(kv_store, _key):
    keys_and_types = get_keys_and_types(kv_store)
    types = {
        'number': float,
        'string': str,
        'cidr': str,
        'boolean': bool,
        'time': str
    }
    index = 'index.{}'.format(_key)
    field = 'field.{}'.format(_key)
    val_type = keys_and_types.get(field) or keys_and_types.get(index)
    return types.get(val_type)


def get_keys_and_types(kv_store):
    keys = kv_store.content()
    for key_name in keys.keys():
        if not (key_name.startswith('field.') or key_name.startswith('index.')):
            del keys[key_name]
    return keys


def get_kv_store_config(kv_store):
    keys = get_keys_and_types(kv_store)
    readable = ['#### configuration for {} store'.format(kv_store.name),
                '| field name | type |',
                '| --- | --- |']
    for _key, val in keys.items():
        readable.append('| {} | {} |'.format(_key, val))
    return '\n'.join(readable)


def extract_indicator(indicator_path, _dict_objects):
    indicators = []
    indicator_paths = indicator_path.split('.')
    for indicator_obj in _dict_objects:
        indicator = ''
        for path in indicator_paths:
            indicator = indicator_obj.get(path, {})
        indicators.append(str(indicator))
    return indicators


def get_store_data(service):
    args = demisto.args()
    stores = args['kv_store_collection_name'].split(',')

    for store in stores:
        store = service.kvstore[store]
        query = build_kv_store_query(store, args)
        if 'limit' not in query:
            query = {'query': query}
        yield store.data.query(**query)


def create_mapping_dict(total_parsed_results, type_field):
    """
    Create a {'field_name': 'fields_properties'} dict to be used as mapping schemas.
    Args:
        total_parsed_results: list. the results from the splunk search query
        type_field: str. the field that represents the type of the event or alert.

    Returns:

    """
    types_map = {}
    for result in total_parsed_results:
        raw_json = json.loads(result.get('rawJSON', "{}"))
        event_type_name = raw_json.get(type_field, '')
        if event_type_name:
            types_map[event_type_name] = raw_json

    return types_map


def get_mapping_fields_command(service):
    # Create the query to get unique objects
    # The logic is identical to the 'fetch_incidents' command
    type_field = demisto.params().get('type_field', 'source')
    total_parsed_results = []
    search_offset = demisto.getLastRun().get('offset', 0)

    current_time_for_fetch = datetime.utcnow()
    dem_params = demisto.params()
    if demisto.get(dem_params, 'timezone'):
        timezone = dem_params['timezone']
        current_time_for_fetch = current_time_for_fetch + timedelta(minutes=int(timezone))

    now = current_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
    if demisto.get(dem_params, 'useSplunkTime'):
        now = get_current_splunk_time(service)
        current_time_in_splunk = datetime.strptime(now, SPLUNK_TIME_FORMAT)
        current_time_for_fetch = current_time_in_splunk

    fetch_time_in_minutes = parse_time_to_minutes()
    start_time_for_fetch = current_time_for_fetch - timedelta(minutes=fetch_time_in_minutes)
    last_run = start_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)

    earliest_fetch_time_fieldname = dem_params.get("earliest_fetch_time_fieldname", "earliest_time")
    latest_fetch_time_fieldname = dem_params.get("latest_fetch_time_fieldname", "latest_time")

    kwargs_oneshot = {earliest_fetch_time_fieldname: last_run,
                      latest_fetch_time_fieldname: now, "count": FETCH_LIMIT, 'offset': search_offset}

    searchquery_oneshot = dem_params['fetchQuery']

    if demisto.get(dem_params, 'extractFields'):
        extractFields = dem_params['extractFields']
        extra_raw_arr = extractFields.split(',')
        for field in extra_raw_arr:
            field_trimmed = field.strip()
            searchquery_oneshot = searchquery_oneshot + ' | eval ' + field_trimmed + '=' + field_trimmed

    searchquery_oneshot = searchquery_oneshot + ' | dedup ' + type_field
    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)  # type: ignore
    reader = results.ResultsReader(oneshotsearch_results)
    for item in reader:
        inc = notable_to_incident(item)
        total_parsed_results.append(inc)

    types_map = create_mapping_dict(total_parsed_results, type_field)
    demisto.results(types_map)


def get_cim_mapping_field_command():
    notable = {'rule_name': '', '': '', 'rule_title': '', 'security_domain': '', 'index': '', 'rule_description': '',
               'risk_score': '', 'host': '', 'host_risk_object_type': '', 'dest_risk_object_type': '',
               'dest_risk_score': '', 'splunk_server': '', '_sourcetype': '', '_indextime': '', '_time': '',
               'src_risk_object_type': '', 'src_risk_score': '', '_raw': '', 'urgency': '', 'owner': '',
               'info_min_time': '', 'info_max_time': '', 'comment': '', 'reviewer': '', 'rule_id': '', 'action': '',
               'app': '', 'authentication_method': '', 'authentication_service': '', 'bugtraq': '', 'bytes': '',
               'bytes_in': '', 'bytes_out': '', 'category': '', 'cert': '', 'change': '', 'change_type': '',
               'command': '', 'comments': '', 'cookie': '', 'creation_time': '', 'cve': '', 'cvss': '', 'date': '',
               'description': '', 'dest': '', 'dest_bunit': '', 'dest_category': '', 'dest_dns': '',
               'dest_interface': '', 'dest_ip': '', 'dest_ip_range': '', 'dest_mac': '', 'dest_nt_domain': '',
               'dest_nt_host': '', 'dest_port': '', 'dest_priority': '', 'dest_translated_ip': '',
               'dest_translated_port': '', 'dest_type': '', 'dest_zone': '', 'direction': '', 'dlp_type': '', 'dns': '',
               'duration': '', 'dvc': '', 'dvc_bunit': '', 'dvc_category': '', 'dvc_ip': '', 'dvc_mac': '',
               'dvc_priority': '', 'dvc_zone': '', 'file_hash': '', 'file_name': '', 'file_path': '', 'file_size': '',
               'http_content_type': '', 'http_method': '', 'http_referrer': '', 'http_referrer_domain': '',
               'http_user_agent': '', 'icmp_code': '', 'icmp_type': '', 'id': '', 'ids_type': '', 'incident': '',
               'ip': '', 'mac': '', 'message_id': '', 'message_info': '', 'message_priority': '', 'message_type': '',
               'mitre_technique_id': '', 'msft': '', 'mskb': '', 'name': '', 'orig_dest': '', 'orig_recipient': '',
               'orig_src': '', 'os': '', 'packets': '', 'packets_in': '', 'packets_out': '', 'parent_process': '',
               'parent_process_id': '', 'parent_process_name': '', 'parent_process_path': '', 'password': '',
               'payload': '', 'payload_type': '', 'priority': '', 'problem': '', 'process': '', 'process_hash': '',
               'process_id': '', 'process_name': '', 'process_path': '', 'product_version': '', 'protocol': '',
               'protocol_version': '', 'query': '', 'query_count': '', 'query_type': '', 'reason': '', 'recipient': '',
               'recipient_count': '', 'recipient_domain': '', 'recipient_status': '', 'record_type': '',
               'registry_hive': '', 'registry_key_name': '', 'registry_path': '', 'registry_value_data': '',
               'registry_value_name': '', 'registry_value_text': '', 'registry_value_type': '', 'request_sent_time': '',
               'request_payload': '', 'request_payload_type': '', 'response_code': '', 'response_payload_type': '',
               'response_received_time': '', 'response_time': '', 'result': '', 'return_addr': '', 'rule': '',
               'rule_action': '', 'sender': '', 'service': '', 'service_hash': '', 'service_id': '', 'service_name': '',
               'service_path': '', 'session_id': '', 'sessions': '', 'severity': '', 'severity_id': '', 'sid': '',
               'signature': '', 'signature_id': '', 'signature_version': '', 'site': '', 'size': '', 'source': '',
               'sourcetype': '', 'src': '', 'src_bunit': '', 'src_category': '', 'src_dns': '', 'src_interface': '',
               'src_ip': '', 'src_ip_range': '', 'src_mac': '', 'src_nt_domain': '', 'src_nt_host': '', 'src_port': '',
               'src_priority': '', 'src_translated_ip': '', 'src_translated_port': '', 'src_type': '', 'src_user': '',
               'src_user_bunit': '', 'src_user_category': '', 'src_user_domain': '', 'src_user_id': '',
               'src_user_priority': '', 'src_user_role': '', 'src_user_type': '', 'src_zone': '', 'state': '',
               'status': '', 'status_code': '', 'status_description': '', 'subject': '', 'tag': '', 'ticket_id': '',
               'time': '', 'time_submitted': '', 'transport': '', 'transport_dest_port': '', 'type': '', 'uri': '',
               'uri_path': '', 'uri_query': '', 'url': '', 'url_domain': '', 'url_length': '', 'user': '',
               'user_agent': '', 'user_bunit': '', 'user_category': '', 'user_id': '', 'user_priority': '',
               'user_role': '', 'user_type': '', 'vendor_account': '', 'vendor_product': '', 'vlan': '', 'xdelay': '',
               'xref': ''}

    drilldown = {
        'Drilldown': {'action': '', 'app': '', 'authentication_method': '', 'authentication_service': '', 'bugtraq': '',
                      'bytes': '', 'bytes_in': '', 'bytes_out': '', 'category': '', 'cert': '', 'change': '',
                      'change_type': '', 'command': '', 'comments': '', 'cookie': '', 'creation_time': '', 'cve': '',
                      'cvss': '', 'date': '', 'description': '', 'dest': '', 'dest_bunit': '', 'dest_category': '',
                      'dest_dns': '', 'dest_interface': '', 'dest_ip': '', 'dest_ip_range': '', 'dest_mac': '',
                      'dest_nt_domain': '', 'dest_nt_host': '', 'dest_port': '', 'dest_priority': '',
                      'dest_translated_ip': '', 'dest_translated_port': '', 'dest_type': '', 'dest_zone': '',
                      'direction': '', 'dlp_type': '', 'dns': '', 'duration': '', 'dvc': '', 'dvc_bunit': '',
                      'dvc_category': '', 'dvc_ip': '', 'dvc_mac': '', 'dvc_priority': '', 'dvc_zone': '',
                      'file_hash': '', 'file_name': '', 'file_path': '', 'file_size': '', 'http_content_type': '',
                      'http_method': '', 'http_referrer': '', 'http_referrer_domain': '', 'http_user_agent': '',
                      'icmp_code': '', 'icmp_type': '', 'id': '', 'ids_type': '', 'incident': '', 'ip': '', 'mac': '',
                      'message_id': '', 'message_info': '', 'message_priority': '', 'message_type': '',
                      'mitre_technique_id': '', 'msft': '', 'mskb': '', 'name': '', 'orig_dest': '',
                      'orig_recipient': '', 'orig_src': '', 'os': '', 'packets': '', 'packets_in': '',
                      'packets_out': '', 'parent_process': '', 'parent_process_id': '', 'parent_process_name': '',
                      'parent_process_path': '', 'password': '', 'payload': '', 'payload_type': '', 'priority': '',
                      'problem': '', 'process': '', 'process_hash': '', 'process_id': '', 'process_name': '',
                      'process_path': '', 'product_version': '', 'protocol': '', 'protocol_version': '', 'query': '',
                      'query_count': '', 'query_type': '', 'reason': '', 'recipient': '', 'recipient_count': '',
                      'recipient_domain': '', 'recipient_status': '', 'record_type': '', 'registry_hive': '',
                      'registry_key_name': '', 'registry_path': '', 'registry_value_data': '',
                      'registry_value_name': '', 'registry_value_text': '', 'registry_value_type': '',
                      'request_payload': '', 'request_payload_type': '', 'request_sent_time': '', 'response_code': '',
                      'response_payload_type': '', 'response_received_time': '', 'response_time': '', 'result': '',
                      'return_addr': '', 'rule': '', 'rule_action': '', 'sender': '', 'service': '', 'service_hash': '',
                      'service_id': '', 'service_name': '', 'service_path': '', 'session_id': '', 'sessions': '',
                      'severity': '', 'severity_id': '', 'sid': '', 'signature': '', 'signature_id': '',
                      'signature_version': '', 'site': '', 'size': '', 'source': '', 'sourcetype': '', 'src': '',
                      'src_bunit': '', 'src_category': '', 'src_dns': '', 'src_interface': '', 'src_ip': '',
                      'src_ip_range': '', 'src_mac': '', 'src_nt_domain': '', 'src_nt_host': '', 'src_port': '',
                      'src_priority': '', 'src_translated_ip': '', 'src_translated_port': '', 'src_type': '',
                      'src_user': '', 'src_user_bunit': '', 'src_user_category': '', 'src_user_domain': '',
                      'src_user_id': '', 'src_user_priority': '', 'src_user_role': '', 'src_user_type': '',
                      'src_zone': '', 'state': '', 'status': '', 'status_code': '', 'subject': '', 'tag': '',
                      'ticket_id': '', 'time': '', 'time_submitted': '', 'transport': '', 'transport_dest_port': '',
                      'type': '', 'uri': '', 'uri_path': '', 'uri_query': '', 'url': '', 'url_domain': '',
                      'url_length': '', 'user': '', 'user_agent': '', 'user_bunit': '', 'user_category': '',
                      'user_id': '', 'user_priority': '', 'user_role': '', 'user_type': '', 'vendor_account': '',
                      'vendor_product': '', 'vlan': '', 'xdelay': '', 'xref': ''}
    }

    asset = {
        'Asset': {'asset': '', 'asset_id': '', 'asset_tag': '', 'bunit': '', 'category': '', 'city': '', 'country': '',
                  'dns': '', 'ip': '', 'is_expected': '', 'lat': '', 'long': '', 'mac': '', 'nt_host': '', 'owner': '',
                  'pci_domain': '', 'priority': '', 'requires_av': ''}
    }

    identity = {
        'Identity': {'bunit': '', 'category': '', 'email': '', 'endDate': '', 'first': '', 'identity': '',
                     'identity_tag': '', 'last': '', 'managedBy': '', 'nick': '', 'phone': '', 'prefix': '',
                     'priority': '', 'startDate': '', 'suffix': '', 'watchlist': '', 'work_city': '', 'work_lat': '',
                     'work_long': ''}
    }

    fields = {
        'Notable Data': notable,
        'Drilldown Data': drilldown,
        'Asset Data': asset,
        'Identity Data': identity
    }

    demisto.results(fields)


def submit_notables(service, incidents, num_enrichment_events, cache_object):
    """ Submits fetched notables to Splunk for an enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        incidents (list): The incident to be submitted at the end of the run.
        num_enrichment_events (int): The maximal number of events to return per enrichment type.
        cache_object (Cache): The enrichment mechanism cache object

    """
    failed_notables, submitted_notables = [], []
    notables = cache_object.not_yet_submitted_notables
    if notables:
        demisto.info('Enriching {} fetched notables'.format(len(notables[:MAX_SUBMIT_NOTABLES])))

    for notable in notables[:MAX_SUBMIT_NOTABLES]:
        task_status = submit_notable(service, notable, num_enrichment_events)
        if task_status:
            cache_object.submitted_notables.append(notable)
            submitted_notables.append(notable)
            demisto.info('Submitted enrichment request to Splunk for notable {}'.format(notable.id))
        else:
            incidents.append(notable.to_incident())
            failed_notables.append(notable)
            demisto.info('Created incident from notable {} as enrichment submission failed'.format(notable.id))

    cache_object.not_yet_submitted_notables = [n for n in notables if n not in submitted_notables + failed_notables]

    if submitted_notables:
        demisto.info('Submitted {} notables successfully.'.format(len(submitted_notables)))

    if cache_object.not_yet_submitted_notables:
        demisto.info('{} notables left to submit.'.format(len(cache_object.not_yet_submitted_notables)))

    if failed_notables:
        demisto.info('The following {} notables failed the enrichment process: {}, creating incidents without '
                     'enrichment.'.format(len(failed_notables), [notable.id for notable in failed_notables]))


def submit_notable(service, notable, num_enrichment_events):
    """ Submits fetched notable to Splunk for an Enrichment. Three enrichments possible: Drilldown, Asset & Identity.
     If all enrichment type executions were unsuccessful, creates a regular incident, Otherwise updates the
     integration context for the next fetch to handle the submitted notable.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable (Notable): The notable.
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns:
        task_status (bool): True if any of the enrichment's succeeded to be submitted to Splunk, False otherwise

    """
    if DRILLDOWN_ENRICHMENT in ENABLED_ENRICHMENTS:
        job = drilldown_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(create_enrichment_from_job(DRILLDOWN_ENRICHMENT, job))
    if ASSET_ENRICHMENT in ENABLED_ENRICHMENTS:
        job = asset_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(create_enrichment_from_job(ASSET_ENRICHMENT, job))
    if IDENTITY_ENRICHMENT in ENABLED_ENRICHMENTS:
        job = identity_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(create_enrichment_from_job(IDENTITY_ENRICHMENT, job))

    return any(enrichment.status == Enrichment.IN_PROGRESS for enrichment in notable.enrichments)


def create_enrichment_from_job(enrichment_type, job):
    """ Creates an Enrichment object from Splunk Job object

    Args:
        enrichment_type (str): The enrichment type
        job (splunklib.client.Job): The corresponding Splunk Job

    Returns:
        The created enrichment (Enrichment)

    """
    if job:
        return Enrichment(enrichment_type, enrichment_id=job["sid"])
    else:
        return Enrichment(enrichment_type, status=Enrichment.FAILED)


def get_fields_query_part(notable_data, prefix, fields, raw_dict=None):
    """ Given the fields to search for in the notables and the prefix, creates the query part for splunk search.
    For example: if fields are ["user"], and the value of the "user" fields in the notable is ["u1", "u2"], and the
    prefix is "identity", the function returns: (identity="u1" OR identity="u2")

    Args:
        notable_data (dict): The notable.
        prefix (str): The prefix to attach to each value returned in the query.
        fields (list): The fields to search in the notable for.
        raw_dict (dict): The raw dict

    Returns: The query part

    """
    if not raw_dict:
        raw_dict = rawToDict(notable_data.get('_raw', ''))
    raw_list = []  # type: list
    for field in fields:
        raw_list += argToList(notable_data.get(field, "")) + argToList(raw_dict.get(field, ""))
        raw_list += argToList(notable_data.get(field, "")) + argToList(raw_dict.get(field, ""))
    raw_list = ['{}="{}"'.format(prefix, item.strip('"')) for item in raw_list]

    if not raw_list:
        return ""
    elif len(raw_list) == 1:
        return raw_list[0]
    else:
        return "({})".format(" OR ".join(raw_list))


def drilldown_enrichment(service, notable_data, num_enrichment_events):
    """ Performs a drilldown enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object.
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job

    """
    job = None
    search = notable_data.get("drilldown_search", "")

    if search:
        raw_dict = rawToDict(notable_data.get("_raw", ""))
        search = build_drilldown_search(notable_data, search, raw_dict)
        status, earliest_offset, latest_offset = get_drilldown_timeframe(notable_data, raw_dict)
        if status:
            search += " earliest={} latest={}".format(earliest_offset, latest_offset)
            kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
            query = build_search_query({"query": search})
            demisto.debug("Drilldown query for notable {}: {}".format(notable_data[EVENT_ID], query))
            try:
                job = service.jobs.create(query, **kwargs)
            except Exception as e:
                err = str(e)
                demisto.error("Caught an exception in drilldown_enrichment function. Additional Info: {}".format(err))
                raise e
        else:
            demisto.error('Failed getting the drilldown timeframe for notable {}'.format(notable_data[EVENT_ID]))
    else:
        demisto.error("drill-down was not configured for notable {}".format(notable_data[EVENT_ID]))

    return job


def build_drilldown_search(notable_data, search, raw_dict):
    """ Replaces all needed fields in a drilldown search query

    Args:
        notable_data (dict): The notable data
        search (str): The drilldown search query
        raw_dict (dict): The raw dict

    Returns (str): A searchable drilldown search query

    """
    searchable_search = []
    start = 0

    for match in re.finditer(DRILLDOWN_REGEX, search):
        groups = match.groups()
        prefix = groups[0]
        raw_field = (groups[1] or groups[2]).strip('$')
        field, replacement = get_notable_field_and_value(raw_field, notable_data, raw_dict)
        if prefix:
            replacement = get_fields_query_part(notable_data, prefix, [field], raw_dict)
        end = match.start()
        searchable_search.append(search[start:end])
        searchable_search.append(str(replacement))
        start = match.end()
    searchable_search.append(search[start:])  # Handling the tail of the query

    return ''.join(searchable_search)


def get_notable_field_and_value(raw_field, notable_data, raw=None):
    """ Gets the value by the name of the raw_field. We don't search for equivalence because raw field
    can be "threat_match_field|s" while the field is "threat_match_field".

    Args:
        raw_field (str): The raw field
        notable_data (dict): The notable data
        raw (dict): The raw dict

    Returns: The value in the notable which is associated with raw_field

    """
    if not raw:
        raw = rawToDict(notable_data.get('_raw', ''))
    for field in notable_data:
        if field in raw_field:
            return field, notable_data[field]
    for field in raw:
        if field in raw_field:
            return field, raw[field]
    raise Exception('Failed building drilldown search query. field {} was not found in the notable.'.format(raw_field))


def get_drilldown_timeframe(notable_data, raw):
    """ Sets the drilldown search timeframe data.

    Args:
        notable_data (dict): The notable
        raw (dict): The raw dict

    Returns:
        task_status: True if the timeframe was retrieved successfully, False otherwise.
        earliest_offset: The earliest time to query from.
        latest_offset: The latest time to query to.

    """
    task_status = True
    earliest_offset = notable_data.get("drilldown_earliest", "")
    latest_offset = notable_data.get("drilldown_latest", "")
    info_min_time = raw.get(INFO_MIN_TIME, "")
    info_max_time = raw.get(INFO_MAX_TIME, "")

    if not earliest_offset or earliest_offset == "${}$".format(INFO_MIN_TIME):
        if info_min_time:
            earliest_offset = info_min_time
        else:
            demisto.info("Failed retrieving info min time")
            task_status = False
    if not latest_offset or latest_offset == "${}$".format(INFO_MAX_TIME):
        if info_max_time:
            latest_offset = info_max_time
        else:
            demisto.info("Failed retrieving info max time")
            task_status = False

    return task_status, earliest_offset, latest_offset


def identity_enrichment(service, notable_data, num_enrichment_events):
    """ Performs an identity enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job

    """
    job = None
    error_msg = "Failed submitting identity enrichment request to Splunk for notable {}".format(notable_data[EVENT_ID])
    users = get_fields_query_part(notable_data=notable_data, prefix="identity", fields=["user", "src_user"])

    if users:
        kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
        query = '| inputlookup identity_lookup_expanded where {}'.format(users)
        demisto.debug("Identity query for notable {}: {}".format(notable_data[EVENT_ID], query))
        try:
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error("Caught an exception in drilldown_enrichment function. Additional Info: {}".format(str(e)))
            raise e
    else:
        demisto.error('No users were found in notable. {}'.format(error_msg))

    return job


def asset_enrichment(service, notable_data, num_enrichment_events):
    """ Performs an asset enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job

    """
    job = None
    error_msg = "Failed submitting asset enrichment request to Splunk for notable {}".format(notable_data[EVENT_ID])
    assets = get_fields_query_part(
        notable_data=notable_data, prefix="asset", fields=["src", "dest", "src_ip", "dst_ip"]
    )

    if assets:
        kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
        query = '| inputlookup append=T asset_lookup_by_str where {} | inputlookup append=t asset_lookup_by_cidr ' \
                'where {} | rename _key as asset_id | stats values(*) as * by asset_id'.format(assets, assets)
        demisto.debug("Asset query for notable {}: {}".format(notable_data[EVENT_ID], query))
        try:
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error("Caught an exception in asset_enrichment function. Additional Info: {}".format(str(e)))
            raise e
    else:
        demisto.error('No assets were found in notable. {}'.format(error_msg))

    return job


def handle_submitted_notables(service, enrichment_timeout, incidents, cache_object):
    """ Handles submitted notables. For each submitted notable, tries to retrieve its results, if results aren't ready,
     it moves to the next submitted notable.

    Args:
        service (splunklib.client.Service): Splunk service object.
        enrichment_timeout (int): The timeout for the enrichment process.
        incidents (list): The incident to be submitted at the end of the run.
        cache_object (Cache): The enrichment mechanism cache object

    Returns (bool): True if we finished handling all open enrichments, False otherwise

    """
    done_handling = False
    handled_notables = []
    notables = cache_object.submitted_notables
    demisto.info("Trying to handle {} open enrichments".format(len(notables[:MAX_HANDLE_NOTABLES])))

    for notable in notables[:MAX_HANDLE_NOTABLES]:
        task_status = handle_submitted_notable(service, notable, enrichment_timeout)
        if task_status:
            incidents.append(notable.to_incident())
            handled_notables.append(notable)

    cache_object.submitted_notables = [n for n in notables if n not in handled_notables]

    if handled_notables:
        demisto.info("Handled {} notables.".format(len(handled_notables)))

    if cache_object.submitted_notables:
        demisto.info("{} notables left to handle.".format(len(cache_object.submitted_notables)))
    else:
        done_handling = True

    return done_handling


def store_incidents_for_mapping(incidents, integration_context):
    """ Stores ready incidents in integration context to allow the mapping to pull the incidents from the instance.
    We store at most 20 incidents.

    Args:
        incidents (list): The incidents
        integration_context (dict): The integration context

    """
    if incidents:
        integration_context[INCIDENTS] = incidents[:20]


def handle_last_run(cache_object):
    """ Handles the last run by the same logic as in regular fetch (no enrichment)

    Args:
        cache_object (Cache): The enrichment mechanism cache object

    """

    # first fetch check
    if all([
        cache_object.last_run_over_fetch,
        cache_object.last_run_regular_fetch,
        cache_object.num_fetched_notables
    ]):
        last_run = demisto.getLastRun()
        if cache_object.num_fetched_notables < FETCH_LIMIT:
            last_run.update(cache_object.last_run_regular_fetch)
        else:
            last_run.update(cache_object.last_run_over_fetch)
        demisto.setLastRun(last_run)


def handle_submitted_notable(service, notable, enrichment_timeout):
    """ Handles submitted notable. If enrichment process timeout has reached, creates an incident.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable (Notable): The notable
        enrichment_timeout (int): The timeout for the enrichment process

    Returns:
        notable_status (str): The status of the notable

    """
    task_status = False

    if not is_enrichment_process_exceeding_timeout(notable, enrichment_timeout):
        demisto.info("Trying to handle open enrichment {}".format(notable.id))
        for enrichment in notable.enrichments:
            if enrichment.status == Enrichment.IN_PROGRESS:
                job = client.Job(service=service, sid=enrichment.id)
                if job.is_ready():
                    demisto.debug('Handling open {} enrichment for notable {}'.format(enrichment.type, notable.id))
                    for item in results.ResultsReader(job.results()):
                        enrichment.data.append(item)
                    enrichment.status = Enrichment.SUCCESSFUL

        if all(enrichment.status in (Enrichment.SUCCESSFUL, Enrichment.FAILED) for enrichment in notable.enrichments):
            task_status = True
            demisto.info("Handled open enrichment for notable {}.".format(notable.id))
        else:
            demisto.info("Did not finish handling open enrichment for notable {}".format(notable.id))

    else:
        task_status = True
        demisto.info("Open enrichment {} has exceeded the enrichment timeout of {}. Submitting the notable without "
                     "the enrichment.".format(notable.id, enrichment_timeout))

    return task_status


def is_enrichment_process_exceeding_timeout(notable, enrichment_timeout):
    """ Checks whether an enrichment process has exceeded timeout or not

    Args:
        notable (Notable): The enrichment
        enrichment_timeout (int): The timeout for the enrichment process

    Returns (bool): True if the enrichment process exceeded the given timeout, False otherwise

    """
    enrichments = [enrichment for enrichment in notable.enrichments if enrichment.status == Enrichment.IN_PROGRESS]
    if enrichments:
        earliest_enrichment_datetime = min(
            datetime.strptime(enrichment.creation_time, JOB_CREATION_TIME_FORMAT)
            for enrichment in enrichments
        )
        return datetime.utcnow() - earliest_enrichment_datetime > timedelta(minutes=enrichment_timeout)
    return False


def reset_enriching_fetch_mechanism():
    """ Resets all the fields regarding the enriching fetch mechanism & the last run object """

    integration_context = get_integration_context()
    for field in (INCIDENTS, CACHE):
        if field in integration_context:
            del integration_context[field]
    set_integration_context(integration_context)
    demisto.setLastRun({})
    demisto.results("Enriching fetch mechanism was reset successfully.")


def fetch_incidents(service, enrichment_timeout, num_enrichment_events):
    if ENABLED_ENRICHMENTS:
        integration_context = get_integration_context()
        if not demisto.getLastRun() and integration_context:
            # In "Pull from instance" in Classification & Mapping the last run object is empty, integration context
            # will not be empty because of the enrichment mechanism. In regular enriched fetch, we use dummy data
            # in the last run object to avoid entering this case
            fetch_incidents_for_mapping(integration_context)
        else:
            run_enrichment_mechanism(service, enrichment_timeout, integration_context, num_enrichment_events)
    else:
        fetch_notables(service=service, enrich_notables=False)


def run_enrichment_mechanism(service, enrichment_timeout, integration_context, num_enrichment_events):
    """ Execute the enriching fetch mechanism
    1. We first handle submitted notables that have not been handled in the last fetch run
    2. If we finished handling and submitting all fetched notables, we fetch new notables
    3. After we finish to fetch new notables or if we have left notables that have not been submitted, we submit
       them for an enrichment to Splunk
    4. Finally and in case of an Exception, we store the current cache object state in the integration context

    Args:
        service (splunklib.client.Service): Splunk service object.
        enrichment_timeout (int): The timeout for the enrichment process.
        integration_context (dict): The integration context
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    """
    incidents = []  # type: list
    cache_object = Cache.load_from_integration_context(integration_context)

    try:
        done_handling = handle_submitted_notables(service, enrichment_timeout, incidents, cache_object)
        done_submitting = is_done_submitting(cache_object)
        if done_handling and done_submitting:
            handle_last_run(cache_object)
            fetch_notables(service=service, cache_object=cache_object, enrich_notables=True)
        submit_notables(service, incidents, num_enrichment_events, cache_object)

    except Exception as e:
        err = 'Caught an exception while executing the enriching fetch mechanism. Additional Info: {}'.format(str(e))
        demisto.error(err)
        raise e

    finally:
        store_incidents_for_mapping(incidents, integration_context)
        cache_object.dump_to_integration_context(integration_context)
        demisto.incidents(incidents)


def is_done_submitting(cache_object):
    """ Indicates whether we've finished to submit all fetched notables to enrichment or not

    Args:
        cache_object (Cache): The enrichment mechanism cache object

    Returns (bool): True if we finished, False otherwise

    """
    return not cache_object.not_yet_submitted_notables


def fetch_incidents_for_mapping(integration_context):
    """ Gets the stored incidents to the "Pull from instance" in Classification & Mapping (In case of enriched fetch)

    Args:
        integration_context (dict): The integration context

    """
    incidents = integration_context.get(INCIDENTS, [])
    demisto.info('Retrieving {} incidents for "Pull from instance" in Classification & Mapping.'.format(len(incidents)))
    demisto.incidents(incidents)


def main():
    if demisto.command() == 'splunk-parse-raw':
        splunk_parse_raw_command()
        sys.exit(0)
    service = None
    proxy = demisto.params().get('proxy')
    use_requests_handler = demisto.params().get('use_requests_handler')

    connection_args = {
        'host': demisto.params()['host'],
        'port': demisto.params()['port'],
        'app': demisto.params().get('app', '-'),
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
    if demisto.command() == 'splunk-reset-enriching-fetch-mechanism':
        reset_enriching_fetch_mechanism()
    if demisto.command() == 'splunk-search':
        splunk_search_command(service)
    if demisto.command() == 'splunk-job-create':
        splunk_job_create_command(service)
    if demisto.command() == 'splunk-results':
        splunk_results_command(service)
    if demisto.command() == 'fetch-incidents':
        params = demisto.params()
        enrichment_timeout = arg_to_number(str(params.get('enrichment_timeout')))
        num_enrichment_events = arg_to_number(str(params.get('num_enrichment_events')))
        fetch_incidents(service, enrichment_timeout, num_enrichment_events)
    if demisto.command() == 'splunk-get-indexes':
        splunk_get_indexes_command(service)
    if demisto.command() == 'splunk-submit-event':
        splunk_submit_event_command(service)
    if demisto.command() == 'splunk-notable-event-edit':
        splunk_edit_notable_event_command(proxy)
    if demisto.command() == 'splunk-submit-event-hec':
        splunk_submit_event_hec_command()
    if demisto.command() == 'splunk-job-status':
        splunk_job_status(service)
    if demisto.command().startswith('splunk-kv-') and service is not None:
        args = demisto.args()
        app = args.get('app_name', 'search')
        service.namespace = namespace(app=app, owner='nobody', sharing='app')
        check_error(service, args)

        if demisto.command() == 'splunk-kv-store-collection-create':
            kv_store_collection_create(service)
        elif demisto.command() == 'splunk-kv-store-collection-config':
            kv_store_collection_config(service)
        elif demisto.command() == 'splunk-kv-store-collection-delete':
            kv_store_collection_delete(service)
        elif demisto.command() == 'splunk-kv-store-collections-list':
            kv_store_collections_list(service)
        elif demisto.command() == 'splunk-kv-store-collection-add-entries':
            kv_store_collection_add_entries(service)
        elif demisto.command() in ['splunk-kv-store-collection-data-list',
                                   'splunk-kv-store-collection-search-entry']:
            kv_store_collection_data(service)
        elif demisto.command() == 'splunk-kv-store-collection-data-delete':
            kv_store_collection_data_delete(service)
        elif demisto.command() == 'splunk-kv-store-collection-delete-entry':
            kv_store_collection_delete_entry(service)
    if demisto.command() == 'get-mapping-fields':
        if argToBoolean(demisto.params().get('use_cim', False)):
            get_cim_mapping_field_command()
        else:
            get_mapping_fields_command(service)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
