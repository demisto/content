import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import io
import json
import re
from datetime import datetime, timedelta
import dateparser
import pytz
import requests

from splunklib import client
from splunklib import results
from splunklib.data import Record
from splunklib.binding import AuthenticationError, HTTPError, namespace


OUTPUT_MODE_JSON = 'json'  # type of response from splunk-sdk query (json/csv/xml)
# Define utf8 as default encoding
params = demisto.params()
SPLUNK_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
VERIFY_CERTIFICATE = not bool(params.get('unsecure'))
FETCH_LIMIT = int(params.get('fetch_limit')) if params.get('fetch_limit') else 50
FETCH_LIMIT = max(min(200, FETCH_LIMIT), 1)
MIRROR_LIMIT = 1000
PROBLEMATIC_CHARACTERS = ['.', '(', ')', '[', ']']
REPLACE_WITH = '_'
REPLACE_FLAG = params.get('replaceKeys', False)
FETCH_TIME = params.get('fetch_time')
PROXIES = handle_proxy()
TIME_UNIT_TO_MINUTES = {'minute': 1, 'hour': 60, 'day': 24 * 60, 'week': 7 * 24 * 60, 'month': 30 * 24 * 60,
                        'year': 365 * 24 * 60}
DEFAULT_DISPOSITIONS = {
    'True Positive - Suspicious Activity': 'disposition:1',
    'Benign Positive - Suspicious But Expected': 'disposition:2',
    'False Positive - Incorrect Analytic Logic': 'disposition:3',
    'False Positive - Inaccurate Data': 'disposition:4',
    'Other': 'disposition:5',
    'Undetermined': 'disposition:6'
}

# =========== Mirroring Mechanism Globals ===========
MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}
OUTGOING_MIRRORED_FIELDS = ['comment', 'status', 'owner', 'urgency', 'reviewer', 'disposition']

# =========== Enrichment Mechanism Globals ===========
ENABLED_ENRICHMENTS = params.get('enabled_enrichments', [])

DRILLDOWN_ENRICHMENT = 'Drilldown'
ASSET_ENRICHMENT = 'Asset'
IDENTITY_ENRICHMENT = 'Identity'
SUBMITTED_NOTABLES = 'submitted_notables'
EVENT_ID = 'event_id'
JOB_CREATION_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
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
INCIDENT_CREATED = 'incident_created'

DRILLDOWN_REGEX = r'([^\s\$]+)=(\$[^\$]+\$)|(\$[^\$]+\$)'

ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS = {
    DRILLDOWN_ENRICHMENT: 'successful_drilldown_enrichment',
    ASSET_ENRICHMENT: 'successful_asset_enrichment',
    IDENTITY_ENRICHMENT: 'successful_identity_enrichment'
}
COMMENT_MIRRORED_FROM_XSOAR = 'Mirrored from Cortex XSOAR'

# =========== Not Missing Events Mechanism Globals ===========
CUSTOM_ID = 'custom_id'
OCCURRED = 'occurred'
INDEX_TIME = 'index_time'
TIME_IS_MISSING = 'time_is_missing'


# =========== Enrich User Mechanism ============
class UserMappingObject:
    def __init__(
        self, service: client.Service,
        should_map_user: bool,
        table_name: str = 'splunk_xsoar_users',
        xsoar_user_column_name: str = 'xsoar_user',
        splunk_user_column_name: str = 'splunk_user'
    ):
        self.service = service
        self.should_map = should_map_user
        self.table_name = table_name
        self.xsoar_user_column_name = xsoar_user_column_name
        self.splunk_user_column_name = splunk_user_column_name

    def _get_record(self, col: str, value_to_search: str):
        """ Gets the records with the value found in the relevant column. """
        kvstore: client.KVStoreCollection = self.service.kvstore[self.table_name]
        return kvstore.data.query(query=json.dumps({col: value_to_search}))

    def get_xsoar_user_by_splunk(self, splunk_user):

        record = list(self._get_record(self.splunk_user_column_name, splunk_user))

        if not record:

            demisto.error(
                "Could not find xsoar user matching splunk's {splunk_user}. "
                "Consider adding it to the {table_name} lookup.".format(
                    splunk_user=splunk_user, table_name=self.table_name))
            return ''

        # assuming username is unique, so only one record is returned.
        xsoar_user = record[0].get(self.xsoar_user_column_name)

        if not xsoar_user:
            demisto.error(
                "Xsoar user matching splunk's {splunk_user} is empty. Fix the record in {table_name} lookup.".format(
                    splunk_user=splunk_user, table_name=self.table_name))
            return ''

        return xsoar_user

    def get_splunk_user_by_xsoar(self, xsoar_user, map_missing=True):

        record = list(self._get_record(self.xsoar_user_column_name, xsoar_user))

        if not record:
            demisto.error(
                f"Could not find splunk user matching xsoar's {xsoar_user}. Consider adding it to the {self.table_name} lookup.")
            return 'unassigned' if map_missing else None

        # assuming username is unique, so only one record is returned.
        splunk_user = record[0].get(self.splunk_user_column_name)

        if not splunk_user:
            demisto.error(
                f"Splunk user matching Xsoar's {xsoar_user} is empty. Fix the record in {self.table_name} lookup.")
            return 'unassigned' if map_missing else None

        return splunk_user

    def get_splunk_user_by_xsoar_command(self, args):
        xsoar_users = argToList(args.get('xsoar_username'))
        map_missing = argToBoolean(args.get('map_missing', True))

        outputs = []
        for user in xsoar_users:
            splunk_user = self.get_splunk_user_by_xsoar(user, map_missing=map_missing) if user else None
            outputs.append(
                {'XsoarUser': user,
                 'SplunkUser': splunk_user or 'Could not map splunk user, Check logs for more info.'})

        return CommandResults(
            outputs=outputs,
            outputs_prefix='Splunk.UserMapping',
            readable_output=tableToMarkdown('Xsoar-Splunk Username Mapping', outputs,
                                            headers=['XsoarUser', 'SplunkUser'])
        )


# =========== Regular Fetch Mechanism ===========
def splunk_time_to_datetime(incident_ocurred_time):
    incident_time_without_timezone = incident_ocurred_time.split('.')[0]
    return datetime.strptime(incident_time_without_timezone, SPLUNK_TIME_FORMAT)


def get_latest_incident_time(incidents):
    def get_incident_time_datetime(incident):
        incident_time = incident["occurred"]
        incident_time_datetime = splunk_time_to_datetime(incident_time)
        return incident_time_datetime

    latest_incident = max(incidents, key=get_incident_time_datetime)
    return latest_incident["occurred"]


def get_next_start_time(latests_incident_fetched_time, latest_time, were_new_incidents_found=True):
    if not were_new_incidents_found:
        return latest_time
    latest_incident_datetime = splunk_time_to_datetime(latests_incident_fetched_time)
    return latest_incident_datetime.strftime(SPLUNK_TIME_FORMAT)


def create_incident_custom_id(incident):
    incident_raw_data = json.loads(incident["rawJSON"])
    fields_to_add = ['_cd', 'index', '_time', '_indextime', '_raw']
    fields_supplied_by_user = demisto.params().get('unique_id_fields', '')
    fields_supplied_by_user = fields_supplied_by_user or ""
    fields_to_add.extend(fields_supplied_by_user.split(','))

    incident_custom_id = '___'
    for field_name in fields_to_add:
        if field_name in incident_raw_data:
            incident_custom_id += f'{field_name}___{incident_raw_data[field_name]}'
        elif field_name in incident:
            incident_custom_id += f'{field_name}___{incident[field_name]}'

    extensive_log(f'[SplunkPy] ID after all fields were added: {incident_custom_id}')

    unique_id = hashlib.md5(incident_custom_id.encode('utf-8')).hexdigest()  # nosec  # guardrails-disable-line
    extensive_log(f'[SplunkPy] Found incident ID is: {unique_id}')
    return unique_id


def extensive_log(message):
    if demisto.params().get('extensive_logs', False):
        demisto.debug(message)


def remove_old_incident_ids(last_run_fetched_ids, current_epoch_time, occurred_look_behind):
    """Remove all the IDs of all the incidents that were found more than twice the look behind time frame,
    to stop our IDs dict from becoming too large.

    Args:
        last_run_fetched_ids (list): All the event IDs that weren't out of date in the last run + all the new event IDs
        from newly fetched events in this run.
        current_epoch_time (int): The current time in epoch.
        occurred_look_behind (int): The max look behind time (parameter, as defined by the user).

    Returns:
        new_last_run_fetched_ids (list): The updated list of IDs, without old IDs.
    """
    new_last_run_fetched_ids = {}
    for inc_id, addition_time in list(last_run_fetched_ids.items()):
        max_look_behind_in_seconds = occurred_look_behind * 60
        deletion_threshold_in_seconds = max_look_behind_in_seconds * 2
        if current_epoch_time - addition_time < deletion_threshold_in_seconds:
            new_last_run_fetched_ids[inc_id] = addition_time

    return new_last_run_fetched_ids


def enforce_look_behind_time(last_run_time, now, look_behind_time):
    """ Verifies that the start time of the fetch is at X minutes before
    the end time, X being the number of minutes specified in the look_behind parameter.
    The reason this is needed is to ensure that events that have a significant difference
    between their index time and occurrence time in Splunk are still fetched and are not missed.

    Args:
        last_run_time (str): The current start time of the fetch.
        now (str): The current end time of the fetch.
        look_behind_time (int): The minimal difference (in minutes) that should be enforced between
                                the start time and end time.

    Returns:
        last_run (str): The new start time for the fetch.
    """
    last_run_datetime = datetime.strptime(last_run_time, SPLUNK_TIME_FORMAT)
    now_datetime = datetime.strptime(now, SPLUNK_TIME_FORMAT)
    if now_datetime - last_run_datetime < timedelta(minutes=look_behind_time):
        time_before_given_look_behind_datetime = now_datetime - timedelta(minutes=look_behind_time)
        return datetime.strftime(
            time_before_given_look_behind_datetime, SPLUNK_TIME_FORMAT
        )
    return last_run_time


def get_fetch_start_times(params, service, last_run_earliest_time, occurence_time_look_behind):
    current_time_for_fetch = datetime.utcnow()
    if timezone_ := params.get('timezone'):
        current_time_for_fetch = current_time_for_fetch + timedelta(minutes=int(timezone_))

    now = current_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
    if params.get('useSplunkTime'):
        now = get_current_splunk_time(service)
        current_time_in_splunk = datetime.strptime(now, SPLUNK_TIME_FORMAT)
        current_time_for_fetch = current_time_in_splunk

    if not last_run_earliest_time:
        fetch_time_in_minutes = parse_time_to_minutes()
        start_time_for_fetch = current_time_for_fetch - timedelta(minutes=fetch_time_in_minutes)
        last_run_earliest_time = start_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
        extensive_log(f'[SplunkPy] SplunkPy last run is None. Last run earliest time is: {last_run_earliest_time}')

    occured_start_time = enforce_look_behind_time(last_run_earliest_time, now, occurence_time_look_behind)

    return occured_start_time, now


def build_fetch_kwargs(params, occured_start_time, latest_time, search_offset):
    occurred_start_time_fieldname = params.get("earliest_occurrence_time_fieldname", "earliest_time")
    occurred_end_time_fieldname = params.get("latest_occurrence_time_fieldname", "latest_time")

    extensive_log(f'[SplunkPy] occurred_start_time_fieldname: {occurred_start_time_fieldname}')
    extensive_log(f'[SplunkPy] occured_start_time: {occured_start_time}')

    return {
        occurred_start_time_fieldname: occured_start_time,
        occurred_end_time_fieldname: latest_time,
        "count": FETCH_LIMIT,
        'offset': search_offset,
        "output_mode": OUTPUT_MODE_JSON,
    }


def build_fetch_query(params):
    fetch_query = params['fetchQuery']

    if (extract_fields := params.get('extractFields')):
        for field in extract_fields.split(','):
            field_trimmed = field.strip()
            fetch_query = f'{fetch_query} | eval {field_trimmed}={field_trimmed}'

    return fetch_query


def fetch_notables(service: client.Service, mapper: UserMappingObject, comment_tag_to_splunk: str, comment_tag_from_splunk: str,
                   cache_object: "Cache" = None, enrich_notables=False):
    last_run_data = demisto.getLastRun()
    params = demisto.params()
    if not last_run_data:
        extensive_log('[SplunkPy] SplunkPy first run')

    last_run_earliest_time = last_run_data and last_run_data.get('time')
    last_run_latest_time = last_run_data and last_run_data.get('latest_time')
    extensive_log(f'[SplunkPy] SplunkPy last run is:\n {last_run_data}')

    search_offset = last_run_data.get('offset', 0)

    occurred_look_behind = int(params.get('occurrence_look_behind', 15) or 15)
    extensive_log(f'[SplunkPy] occurrence look behind is: {occurred_look_behind}')

    occured_start_time, now = get_fetch_start_times(params, service, last_run_earliest_time, occurred_look_behind)

    # if last_run_latest_time is not None it's mean we are in a batch fetch iteration with offset
    latest_time = last_run_latest_time or now
    kwargs_oneshot = build_fetch_kwargs(params, occured_start_time, latest_time, search_offset)
    fetch_query = build_fetch_query(params)

    demisto.debug(f'[SplunkPy] fetch query = {fetch_query}')
    demisto.debug(f'[SplunkPy] oneshot query args = {kwargs_oneshot}')
    oneshotsearch_results = service.jobs.oneshot(fetch_query, **kwargs_oneshot)
    reader = results.JSONResultsReader(oneshotsearch_results)

    last_run_fetched_ids = last_run_data.get('found_incidents_ids', {})

    incidents = []
    notables = []
    incident_ids_to_add = []
    num_of_dropped = 0
    for item in reader:
        if handle_message(item):
            continue
        extensive_log(f'[SplunkPy] Incident data before parsing to notable: {item}')
        notable_incident = Notable(data=item)
        inc = notable_incident.to_incident(mapper, comment_tag_to_splunk, comment_tag_from_splunk)
        extensive_log(f'[SplunkPy] Incident data after parsing to notable: {inc}')
        incident_id = create_incident_custom_id(inc)

        if incident_id not in last_run_fetched_ids:
            incident_ids_to_add.append(incident_id)
            incidents.append(inc)
            notables.append(notable_incident)
            extensive_log(f'[SplunkPy] - Fetched incident {item.get("event_id", incident_id)} to be created.')
        else:
            num_of_dropped += 1
            extensive_log(f'[SplunkPy] - Dropped incident {item.get("event_id", incident_id)} due to duplication.')

    current_epoch_time = int(time.time())
    extensive_log(f'[SplunkPy] Size of last_run_fetched_ids before adding new IDs: {len(last_run_fetched_ids)}')
    for incident_id in incident_ids_to_add:
        last_run_fetched_ids[incident_id] = current_epoch_time
    extensive_log(f'[SplunkPy] Size of last_run_fetched_ids after adding new IDs: {len(last_run_fetched_ids)}')
    last_run_fetched_ids = remove_old_incident_ids(last_run_fetched_ids, current_epoch_time, occurred_look_behind)
    extensive_log('[SplunkPy] Size of last_run_fetched_ids after '
                  f'removing old IDs: {len(last_run_fetched_ids)}')
    extensive_log(f'[SplunkPy] SplunkPy - incidents fetched on last run = {last_run_fetched_ids}')

    demisto.debug(f'SplunkPy - total number of new incidents found is: {len(incidents)}')
    demisto.debug(f'SplunkPy - total number of dropped incidents is: {num_of_dropped}')

    if not enrich_notables or not cache_object:
        demisto.incidents(incidents)
    else:
        cache_object.not_yet_submitted_notables += notables
        if DUMMY not in last_run_data:
            # we add dummy data to the last run to differentiate between the fetch-incidents triggered to the
            # fetch-incidents running as part of "Pull from instance" in Classification & Mapping, as we don't
            # want to add data to the integration context (which will ruin the logic of the cache object)
            last_run_data.update({DUMMY: DUMMY})

    # we didn't get any new incident or get less then limit
    # so the next run earliest time will be the latest_time from this iteration
    # should also set when num_of_dropped == FETCH_LIMIT
    if not incidents or (len(incidents) + num_of_dropped) < FETCH_LIMIT:
        next_run_earliest_time = latest_time
        new_last_run = {
            'time': next_run_earliest_time,
            'latest_time': None,
            'offset': 0,
            'found_incidents_ids': last_run_fetched_ids
        }

    # we get limit notables from splunk
    # we should fetch the entire queue with offset - so set the offset, time and latest_time for the next run
    else:
        new_last_run = {
            'time': occured_start_time,
            'latest_time': latest_time,
            'offset': search_offset + FETCH_LIMIT,
            'found_incidents_ids': last_run_fetched_ids
        }
    demisto.debug(f'SplunkPy - {new_last_run["time"]=}, {new_last_run["latest_time"]=}, {new_last_run["offset"]=}')

    last_run_data.update(new_last_run)
    demisto.setLastRun(last_run_data)


def fetch_incidents(service: client.Service, mapper: UserMappingObject, comment_tag_to_splunk: str, comment_tag_from_splunk: str):
    if ENABLED_ENRICHMENTS:
        integration_context = get_integration_context()
        if not demisto.getLastRun() and integration_context:
            # In "Pull from instance" in Classification & Mapping the last run object is empty, integration context
            # will not be empty because of the enrichment mechanism. In regular enriched fetch, we use dummy data
            # in the last run object to avoid entering this case
            fetch_incidents_for_mapping(integration_context)
        else:
            run_enrichment_mechanism(service, integration_context, mapper, comment_tag_to_splunk, comment_tag_from_splunk)
    else:
        fetch_notables(service=service, enrich_notables=False, mapper=mapper, comment_tag_to_splunk=comment_tag_to_splunk,
                       comment_tag_from_splunk=comment_tag_from_splunk)


# =========== Regular Fetch Mechanism ===========


# =========== Enriching Fetch Mechanism ===========

class Enrichment:
    """ A class to represent an Enrichment. Each notable has 3 possible enrichments: Drilldown, Asset & Identity

    Attributes:
        type (str): The enrichment type. Possible values are: Drilldown, Asset & Identity.
        id (str): The enrichment's job id in Splunk server.
        data (list): The enrichment's data list (events retrieved from the job's search).
        creation_time (str): The enrichment's creation time in ISO format.
        status (str): The enrichment's status.
    """
    FAILED = 'Enrichment failed'
    EXCEEDED_TIMEOUT = 'Enrichment exceed the given timeout'
    IN_PROGRESS = 'Enrichment is in progress'
    SUCCESSFUL = 'Enrichment successfully handled'
    HANDLED = (EXCEEDED_TIMEOUT, FAILED, SUCCESSFUL)

    def __init__(self, enrichment_type, status=None, enrichment_id=None, data=None, creation_time=None):
        self.type = enrichment_type
        self.id = enrichment_id
        self.data = data or []
        self.creation_time = creation_time if creation_time else datetime.utcnow().isoformat()
        self.status = status or Enrichment.IN_PROGRESS

    @classmethod
    def from_job(cls, enrichment_type, job: client.Job):
        """ Creates an Enrichment object from Splunk Job object

        Args:
            enrichment_type (str): The enrichment type
            job (splunklib.client.Job): The corresponding Splunk Job

        Returns:
            The created enrichment (Enrichment)
        """
        if job:
            return cls(enrichment_type=enrichment_type, enrichment_id=job["sid"])
        else:
            return cls(enrichment_type=enrichment_type, status=Enrichment.FAILED)

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
        incident_created (bool): Whether an incident created or not.
        occurred (str): The occurred time of the notable.
        custom_id (str): The custom ID of the notable (used in the fetch function).
        time_is_missing (bool): Whether the `_time` field has an empty value or not.
        index_time (str): The time the notable have been indexed.
    """

    def __init__(self, data, enrichments=None, notable_id=None, occurred=None, custom_id=None, index_time=None,
                 time_is_missing=None, incident_created=None):
        self.data = data
        self.id = notable_id or self.get_id()
        self.enrichments = enrichments or []
        self.incident_created = incident_created or False
        self.time_is_missing = time_is_missing or False
        self.index_time = index_time or self.data.get('_indextime')
        self.occurred = occurred or self.get_occurred()
        self.custom_id = custom_id or self.create_custom_id()

    def get_id(self):
        if EVENT_ID in self.data:
            return self.data[EVENT_ID]
        if ENABLED_ENRICHMENTS:
            raise Exception('When using the enrichment mechanism, an event_id field is needed, and thus, '
                            'one must use a fetch query of the following format: search `notable` .......\n'
                            'Please re-edit the fetchQuery parameter in the integration configuration, reset '
                            'the fetch mechanism using the splunk-reset-enriching-fetch-mechanism command and '
                            'run the fetch again.')
        else:
            return None

    @staticmethod
    def create_incident(notable_data, occurred, mapper: UserMappingObject, comment_tag_to_splunk: str,
                        comment_tag_from_splunk: str):
        rule_title, rule_name = '', ''
        params = demisto.params()
        if demisto.get(notable_data, 'rule_title'):
            rule_title = notable_data['rule_title']
        if demisto.get(notable_data, 'rule_name'):
            rule_name = notable_data['rule_name']
        incident: dict[str, Any] = {"name": f"{rule_title} : {rule_name}"}
        if demisto.get(notable_data, 'urgency'):
            incident["severity"] = severity_to_level(notable_data['urgency'])
        if demisto.get(notable_data, 'rule_description'):
            incident["details"] = notable_data["rule_description"]
        if (
            notable_data.get("owner")
            and mapper.should_map
            and (owner := mapper.get_xsoar_user_by_splunk(notable_data["owner"]))
        ):
            incident["owner"] = owner

        incident["occurred"] = occurred
        notable_data = parse_notable(notable_data)
        notable_data.update({
            'mirror_instance': demisto.integrationInstance(),
            'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction')),
            'mirror_tags': [comment_tag_from_splunk, comment_tag_to_splunk]
        })
        comment_entries = []
        labels = []
        if params.get('parseNotableEventsRaw'):
            for key, value in rawToDict(notable_data['_raw']).items():
                if not isinstance(value, str):
                    value = convert_to_str(value)
                labels.append({'type': key, 'value': value})
        if demisto.get(notable_data, 'security_domain'):
            labels.append({'type': 'security_domain', 'value': notable_data["security_domain"]})
        if demisto.get(notable_data, 'comment'):
            comments = argToList(notable_data.get('comment', []))
            demisto.debug(f"data to update comment= {comments}")
            for comment in comments:
                # Creating a comment
                comment_entries.append({
                    'Comment': comment})
        labels.append({'type': 'SplunkComments', 'value': str(comment_entries)})
        incident['labels'] = labels
        incident['dbotMirrorId'] = notable_data.get(EVENT_ID)
        notable_data['SplunkComments'] = comment_entries
        incident["rawJSON"] = json.dumps(notable_data)
        incident['SplunkComments'] = comment_entries

        return incident

    def to_incident(self, mapper: UserMappingObject, comment_tag_to_splunk: str, comment_tag_from_splunk: str):
        """ Gathers all data from all notable's enrichments and return an incident """
        self.incident_created = True

        for e in self.enrichments:
            self.data[e.type] = e.data
            self.data[ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS[e.type]] = e.status == Enrichment.SUCCESSFUL

        return self.create_incident(self.data, self.occurred, mapper=mapper, comment_tag_to_splunk=comment_tag_to_splunk,
                                    comment_tag_from_splunk=comment_tag_from_splunk)

    def submitted(self) -> bool:
        """ Returns an indicator on whether any of the notable's enrichments was submitted or not """
        return any(enrichment.status == Enrichment.IN_PROGRESS for enrichment in self.enrichments) and len(
            self.enrichments) == len(ENABLED_ENRICHMENTS)

    def failed_to_submit(self):
        """ Returns an indicator on whether all notable's enrichments were failed to submit or not """
        return all(enrichment.status == Enrichment.FAILED for enrichment in self.enrichments) and len(
            self.enrichments) == len(ENABLED_ENRICHMENTS)

    def handled(self):
        """ Returns an indicator on whether all notable's enrichments were handled or not """
        return all(enrichment.status in Enrichment.HANDLED for enrichment in self.enrichments) or any(
            enrichment.status == Enrichment.EXCEEDED_TIMEOUT for enrichment in self.enrichments)

    def get_submitted_enrichments(self):
        """ Returns indicators on whether each enrichment was submitted/failed or not initiated """
        submitted_drilldown, submitted_asset, submitted_identity = False, False, False

        for enrichment in self.enrichments:
            if enrichment.type == DRILLDOWN_ENRICHMENT:
                submitted_drilldown = True
            elif enrichment.type == ASSET_ENRICHMENT:
                submitted_asset = True
            elif enrichment.type == IDENTITY_ENRICHMENT:
                submitted_identity = True

        return submitted_drilldown, submitted_asset, submitted_identity

    def get_occurred(self):
        """ Returns the occurred time, if not exists in data, returns the current fetch time """
        if '_time' in self.data:
            notable_occurred = self.data['_time']
        else:
            # Use-cases where fetching non-notables from Splunk
            notable_occurred = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.0+00:00')
            self.time_is_missing = True
            demisto.debug(f'\n\n occurred time in else: {notable_occurred} \n\n')

        return notable_occurred

    def create_custom_id(self):
        """ Generates a custom ID for a given notable """
        if self.id:
            return self.id

        notable_raw_data = self.data.get('_raw', '')
        raw_hash = hashlib.md5(notable_raw_data.encode('utf-8')).hexdigest()  # nosec  # guardrails-disable-line

        if self.time_is_missing and self.index_time:
            notable_custom_id = f'{self.index_time}_{raw_hash}'  # index_time stays in epoch to differentiate
            demisto.debug('Creating notable custom id using the index time')
        else:
            notable_custom_id = f'{self.occurred}_{raw_hash}'

        return notable_custom_id

    def is_enrichment_process_exceeding_timeout(self, enrichment_timeout):
        """ Checks whether an enrichment process has exceeded timeout or not

        Args:
            enrichment_timeout (int): The timeout for the enrichment process

        Returns (bool): True if the enrichment process exceeded the given timeout, False otherwise
        """
        now = datetime.utcnow()
        exceeding_timeout = False

        for enrichment in self.enrichments:
            if enrichment.status == Enrichment.IN_PROGRESS:
                creation_time_datetime = datetime.strptime(enrichment.creation_time, JOB_CREATION_TIME_FORMAT)
                if now - creation_time_datetime > timedelta(minutes=enrichment_timeout):
                    exceeding_timeout = True
                    enrichment.status = Enrichment.EXCEEDED_TIMEOUT

        return exceeding_timeout

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
            notable_id=notable_dict.get(ID),
            custom_id=notable_dict.get(CUSTOM_ID),
            occurred=notable_dict.get(OCCURRED),
            time_is_missing=notable_dict.get(TIME_IS_MISSING),
            index_time=notable_dict.get(INDEX_TIME),
            incident_created=notable_dict.get(INCIDENT_CREATED)
        )


class Cache:
    """ A class to represent the cache for the enriching fetch mechanism.

    Attributes:
        not_yet_submitted_notables (list): The list of all notables that were fetched but not yet submitted.
        submitted_notables (list): The list of all submitted notables that needs to be handled.
    """

    def __init__(self, not_yet_submitted_notables=None, submitted_notables=None):
        self.not_yet_submitted_notables = not_yet_submitted_notables or []
        self.submitted_notables = submitted_notables or []

    def done_submitting(self):
        return not self.not_yet_submitted_notables

    def done_handling(self):
        return not self.submitted_notables

    def organize(self):
        """ This function is designated to handle unexpected behaviors in the enrichment mechanism.
         E.g. Connection error, instance disabling, etc...
         It re-organizes the cache object to the correct state of the mechanism when the exception was caught.
         If there are notables that were handled but the mechanism didn't create an incident for them, it returns them.
         This function is called in each "end" of execution of the enrichment mechanism.

        Returns:
            handled_not_created_incident (list): The list of all notables that have been handled but not created an
             incident.
        """
        not_yet_submitted, submitted, handled_not_created_incident = [], [], []

        for notable in self.not_yet_submitted_notables:
            if notable.submitted():
                if notable not in self.submitted_notables:
                    submitted.append(notable)
            elif notable.failed_to_submit():
                if not notable.incident_created:
                    handled_not_created_incident.append(notable)
            else:
                not_yet_submitted.append(notable)

        for notable in self.submitted_notables:
            if notable.handled():
                if not notable.incident_created:
                    handled_not_created_incident.append(notable)
            else:
                submitted.append(notable)

        self.not_yet_submitted_notables = not_yet_submitted
        self.submitted_notables = submitted

        return handled_not_created_incident

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
            submitted_notables=list(map(Notable.from_json, cache_dict.get(SUBMITTED_NOTABLES, [])))
        )

    @classmethod
    def load_from_integration_context(cls, integration_context):
        return Cache.from_json(json.loads(integration_context.get(CACHE, "{}")))

    def dump_to_integration_context(self, integration_context):
        integration_context[CACHE] = json.dumps(self, default=lambda obj: obj.__dict__)
        set_integration_context(integration_context)


def get_fields_query_part(notable_data, prefix, fields, raw_dict=None, add_backslash=False):
    """ Given the fields to search for in the notables and the prefix, creates the query part for splunk search.
    For example: if fields are ["user"], and the value of the "user" fields in the notable is ["u1", "u2"], and the
    prefix is "identity", the function returns: (identity="u1" OR identity="u2")

    Args:
        notable_data (dict): The notable.
        prefix (str): The prefix to attach to each value returned in the query.
        fields (list): The fields to search in the notable for.
        raw_dict (dict): The raw dict
        add_backslash (bool): For users that contains single backslash, we add one more

    Returns: The query part
    """
    if not raw_dict:
        raw_dict = rawToDict(notable_data.get('_raw', ''))
    raw_list: list = []
    for field in fields:
        raw_list += argToList(notable_data.get(field, "")) + argToList(raw_dict.get(field, ""))
    if add_backslash:
        raw_list = [item.replace('\\', '\\\\') for item in raw_list]
    raw_list = [f"""{prefix}="{item.strip('"')}\"""" for item in raw_list]

    if not raw_list:
        return ""
    elif len(raw_list) == 1:
        return raw_list[0]
    else:
        return f'({" OR ".join(raw_list)})'


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
    demisto.error(f'Failed building drilldown search query. field {raw_field} was not found in the notable.')
    return "", ""


def build_drilldown_search(notable_data, search, raw_dict):
    """ Replaces all needed fields in a drilldown search query

    Args:
        notable_data (dict): The notable data
        search (str): The drilldown search query
        raw_dict (dict): The raw dict

    Returns (str): A searchable drilldown search query
    """
    searchable_search: list = []
    start = 0

    for match in re.finditer(DRILLDOWN_REGEX, search):
        groups = match.groups()
        prefix = groups[0]
        raw_field = (groups[1] or groups[2]).strip('$')
        field, replacement = get_notable_field_and_value(raw_field, notable_data, raw_dict)
        if not field and not replacement:
            return ""
        if prefix:
            replacement = get_fields_query_part(notable_data, prefix, [field], raw_dict)
        end = match.start()
        searchable_search.extend((search[start:end], str(replacement)))
        start = match.end()
    searchable_search.append(search[start:])  # Handling the tail of the query

    return ''.join(searchable_search)


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

    if not earliest_offset or earliest_offset == f"${INFO_MIN_TIME}$":
        if info_min_time:
            earliest_offset = info_min_time
        else:
            demisto.debug("Failed retrieving info min time")
            task_status = False
    if not latest_offset or latest_offset == f"${INFO_MAX_TIME}$":
        if info_max_time:
            latest_offset = info_max_time
        else:
            demisto.debug("Failed retrieving info max time")
            task_status = False

    return task_status, earliest_offset, latest_offset


def drilldown_enrichment(service: client.Service, notable_data, num_enrichment_events):
    """ Performs a drilldown enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object.
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job
    """
    job = None
    if search := notable_data.get("drilldown_search", ""):
        raw_dict = rawToDict(notable_data.get("_raw", ""))
        if searchable_query := build_drilldown_search(
            notable_data, search, raw_dict
        ):
            status, earliest_offset, latest_offset = get_drilldown_timeframe(notable_data, raw_dict)
            if status:
                kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
                if latest_offset:
                    kwargs['latest_time'] = latest_offset
                if earliest_offset:
                    kwargs['earliest_time'] = earliest_offset
                query = build_search_query({"query": searchable_query})
                demisto.debug(f"Drilldown query for notable {notable_data[EVENT_ID]}: {query}")
                try:
                    job = service.jobs.create(query, **kwargs)
                except Exception as e:
                    demisto.error(f"Caught an exception in drilldown_enrichment function: {str(e)}")
            else:
                demisto.debug(f'Failed getting the drilldown timeframe for notable {notable_data[EVENT_ID]}')
        else:
            demisto.debug(
                f"Couldn't build search query for notable {notable_data[EVENT_ID]} with the following drilldown search {search}"
            )
    else:
        demisto.debug(f"drill-down was not configured for notable {notable_data[EVENT_ID]}")

    return job


def identity_enrichment(service: client.Service, notable_data, num_enrichment_events) -> client.Job:
    """ Performs an identity enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job
    """
    job = None
    error_msg = f"Failed submitting identity enrichment request to Splunk for notable {notable_data[EVENT_ID]}"
    if users := get_fields_query_part(
        notable_data=notable_data,
        prefix="identity",
        fields=["user", "src_user"],
        add_backslash=True,
    ):
        kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
        query = f'| inputlookup identity_lookup_expanded where {users}'
        demisto.debug(f"Identity query for notable {notable_data[EVENT_ID]}: {query}")
        try:
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error(f"Caught an exception in drilldown_enrichment function: {str(e)}")
    else:
        demisto.debug(f'No users were found in notable. {error_msg}')

    return job


def asset_enrichment(service: client.Service, notable_data, num_enrichment_events) -> client.Job:
    """ Performs an asset enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable_data (dict): The notable data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job
    """
    job = None
    error_msg = f"Failed submitting asset enrichment request to Splunk for notable {notable_data[EVENT_ID]}"
    if assets := get_fields_query_part(
        notable_data=notable_data,
        prefix="asset",
        fields=["src", "dest", "src_ip", "dst_ip"],
    ):
        kwargs = {"count": num_enrichment_events, "exec_mode": "normal"}
        query = f'| inputlookup append=T asset_lookup_by_str where {assets} \
                | inputlookup append=t asset_lookup_by_cidr where {assets} \
                | rename _key as asset_id \
                | stats values(*) as * by asset_id'

        demisto.debug(f"Asset query for notable {notable_data[EVENT_ID]}: {query}")
        try:
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error(f"Caught an exception in asset_enrichment function: {str(e)}")
    else:
        demisto.debug(f'No assets were found in notable. {error_msg}')

    return job


def handle_submitted_notables(service: client.Service, incidents, cache_object: Cache, mapper: UserMappingObject,
                              comment_tag_to_splunk: str,
                              comment_tag_from_splunk: str):
    """ Handles submitted notables. For each submitted notable, tries to retrieve its results, if results aren't ready,
     it moves to the next submitted notable.

    Args:
        service (splunklib.client.Service): Splunk service object.
        incidents (list): The incident to be submitted at the end of the run.
        cache_object (Cache): The enrichment mechanism cache object
    """
    handled_notables = []
    if not (enrichment_timeout := arg_to_number(str(demisto.params().get('enrichment_timeout', '5')))):
        enrichment_timeout = 5
    notables = cache_object.submitted_notables
    total = len(notables)
    demisto.debug(f"Trying to handle {len(notables[:MAX_HANDLE_NOTABLES])}/{total} open enrichments")

    for notable in notables[:MAX_HANDLE_NOTABLES]:
        if handle_submitted_notable(
            service, notable, enrichment_timeout
        ):
            incidents.append(notable.to_incident(mapper, comment_tag_to_splunk, comment_tag_from_splunk))
            handled_notables.append(notable)

    cache_object.submitted_notables = [n for n in notables if n not in handled_notables]

    if handled_notables:
        demisto.debug(f"Handled {len(handled_notables)}/{total} notables.")


def handle_submitted_notable(service: client.Service, notable: Notable, enrichment_timeout: int) -> bool:
    """ Handles submitted notable. If enrichment process timeout has reached, creates an incident.

    Args:
        service (splunklib.client.Service): Splunk service object
        notable (Notable): The notable
        enrichment_timeout (int): The timeout for the enrichment process

    Returns:
        notable_status (str): The status of the notable
    """
    task_status = False

    if not notable.is_enrichment_process_exceeding_timeout(enrichment_timeout):
        demisto.debug(f"Trying to handle open enrichment {notable.id}")
        for enrichment in notable.enrichments:
            if enrichment.status == Enrichment.IN_PROGRESS:
                try:
                    job = client.Job(service=service, sid=enrichment.id)
                    if job.is_done():
                        demisto.debug(f'Handling open {enrichment.type} enrichment for notable {notable.id}')
                        for item in results.JSONResultsReader(job.results(output_mode=OUTPUT_MODE_JSON)):
                            if handle_message(item):
                                continue
                            enrichment.data.append(item)
                        enrichment.status = Enrichment.SUCCESSFUL
                except Exception as e:
                    demisto.error(
                        f"Caught an exception while retrieving {enrichment.type}\
                        enrichment results for notable {notable.id}: {str(e)}"
                    )
                    enrichment.status = Enrichment.FAILED

        if notable.handled():
            task_status = True
            demisto.debug(f"Handled open enrichment for notable {notable.id}.")
        else:
            demisto.debug(f"Did not finish handling open enrichment for notable {notable.id}")

    else:
        task_status = True
        demisto.debug(
            f"Open enrichment {notable.id} has exceeded the enrichment timeout of {enrichment_timeout}.\
            Submitting the notable without the enrichment."
        )

    return task_status


def submit_notables(service: client.Service, incidents: list, cache_object: Cache, mapper: UserMappingObject,
                    comment_tag_to_splunk: str, comment_tag_from_splunk: str):
    """ Submits fetched notables to Splunk for an enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        incidents (list): The incident to be submitted at the end of the run.
        cache_object (Cache): The enrichment mechanism cache object
    """
    failed_notables, submitted_notables = [], []
    num_enrichment_events = arg_to_number(str(demisto.params().get('num_enrichment_events', '20')))
    notables = cache_object.not_yet_submitted_notables
    total = len(notables)
    if notables:
        demisto.debug(f'Enriching {len(notables[:MAX_SUBMIT_NOTABLES])}/{total} fetched notables')

    for notable in notables[:MAX_SUBMIT_NOTABLES]:
        if submit_notable(
            service, notable, num_enrichment_events
        ):
            cache_object.submitted_notables.append(notable)
            submitted_notables.append(notable)
            demisto.debug(f'Submitted enrichment request to Splunk for notable {notable.id}')
        else:
            incidents.append(notable.to_incident(mapper, comment_tag_to_splunk, comment_tag_from_splunk))
            failed_notables.append(notable)
            demisto.debug(f'Created incident from notable {notable.id} as each enrichment submission failed')

    cache_object.not_yet_submitted_notables = [n for n in notables if n not in submitted_notables + failed_notables]

    if submitted_notables:
        demisto.debug(f'Submitted {len(submitted_notables)}/{total} notables successfully.')

    if failed_notables:
        demisto.debug(
            f'The following {len(failed_notables)} notables failed the enrichment process: \
            {[notable.id for notable in failed_notables]}, \
            creating incidents without enrichment.'
        )


def submit_notable(service: client.Service, notable: Notable, num_enrichment_events) -> bool:
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
    submitted_drilldown, submitted_asset, submitted_identity = notable.get_submitted_enrichments()

    if DRILLDOWN_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_drilldown:
        job = drilldown_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(Enrichment.from_job(DRILLDOWN_ENRICHMENT, job))
    if ASSET_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_asset:
        job = asset_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(Enrichment.from_job(ASSET_ENRICHMENT, job))
    if IDENTITY_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_identity:
        job = identity_enrichment(service, notable.data, num_enrichment_events)
        notable.enrichments.append(Enrichment.from_job(IDENTITY_ENRICHMENT, job))

    return notable.submitted()


def run_enrichment_mechanism(service: client.Service, integration_context, mapper: UserMappingObject,
                             comment_tag_to_splunk, comment_tag_from_splunk):
    """ Execute the enriching fetch mechanism
    1. We first handle submitted notables that have not been handled in the last fetch run
    2. If we finished handling and submitting all fetched notables, we fetch new notables
    3. After we finish to fetch new notables or if we have left notables that have not been submitted, we submit
       them for an enrichment to Splunk
    4. Finally and in case of an Exception, we store the current cache object state in the integration context

    Args:
        service (splunklib.client.Service): Splunk service object.
        integration_context (dict): The integration context
    """
    incidents: list = []
    cache_object = Cache.load_from_integration_context(integration_context)

    try:
        handle_submitted_notables(service, incidents, cache_object, mapper, comment_tag_to_splunk, comment_tag_from_splunk)
        if cache_object.done_submitting() and cache_object.done_handling():
            fetch_notables(service=service, cache_object=cache_object, enrich_notables=True, mapper=mapper,
                           comment_tag_to_splunk=comment_tag_to_splunk,
                           comment_tag_from_splunk=comment_tag_from_splunk)
        submit_notables(service, incidents, cache_object, mapper, comment_tag_to_splunk, comment_tag_from_splunk)

    except Exception as e:
        err = f'Caught an exception while executing the enriching fetch mechanism. Additional Info: {str(e)}'
        demisto.error(err)
        # we throw exception only if there is no incident to create
        if not incidents:
            raise e

    finally:
        store_incidents_for_mapping(incidents, integration_context)
        handled_but_not_created_incidents = cache_object.organize()
        cache_object.dump_to_integration_context(integration_context)
        incidents += [notable.to_incident(mapper, comment_tag_to_splunk, comment_tag_from_splunk)
                      for notable in handled_but_not_created_incidents]
        demisto.incidents(incidents)


def store_incidents_for_mapping(incidents, integration_context):
    """ Stores ready incidents in integration context to allow the mapping to pull the incidents from the instance.
    We store at most 20 incidents.

    Args:
        incidents (list): The incidents
        integration_context (dict): The integration context
    """
    if incidents:
        integration_context[INCIDENTS] = incidents[:20]


def fetch_incidents_for_mapping(integration_context):
    """ Gets the stored incidents to the "Pull from instance" in Classification & Mapping (In case of enriched fetch)

    Args:
        integration_context (dict): The integration context
    """
    incidents = integration_context.get(INCIDENTS, [])
    demisto.debug(
        f'Retrieving {len(incidents)} incidents for "Pull from instance" in Classification & Mapping.')
    demisto.incidents(incidents)


def reset_enriching_fetch_mechanism():
    """ Resets all the fields regarding the enriching fetch mechanism & the last run object """

    integration_context = get_integration_context()
    for field in (INCIDENTS, CACHE):
        if field in integration_context:
            del integration_context[field]
    set_integration_context(integration_context)
    demisto.setLastRun({})
    return_results("Enriching fetch mechanism was reset successfully.")


# =========== Enriching Fetch Mechanism ===========


# =========== Mirroring Mechanism ===========

def get_last_update_in_splunk_time(last_update):
    """ Transforms the time to the corresponding time on the Splunk server

    Args:
        last_update (str): The time to be transformed, E.g 2021-02-09T16:41:30.589575+02:00

    Returns (int): The corresponding timestamp on the Splunk server
    """
    last_update_utc_datetime = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
    if not last_update_utc_datetime:
        raise Exception(f'Could not parse the last update time: {last_update}')
    params = demisto.params()

    try:
        splunk_timezone = int(params['timezone'])
    except (KeyError, ValueError, TypeError) as e:
        raise Exception(
            'Cannot mirror incidents when timezone is not configured. Please enter the '
            'timezone of the Splunk server being used in the integration configuration.'
        ) from e

    dt = last_update_utc_datetime + timedelta(minutes=splunk_timezone)
    return (dt - datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds()


def get_comments_data(service: client.Service, notable_id: str, comment_tag_from_splunk: str, last_update_splunk_timestamp):
    """get notable comments data and add new entries if needed
    Args:
        comment_tag_from_splunk (str): _description_
    """
    notes = []
    search = '|`incident_review` ' \
             '| eval last_modified_timestamp=_time ' \
             f'| where rule_id="{notable_id}" ' \
             f'| where last_modified_timestamp>{last_update_splunk_timestamp} ' \
             '| fields - time ' \

    demisto.debug(f'Performing get-comments-data command with query: {search}')

    for item in results.JSONResultsReader(service.jobs.oneshot(search, output_mode=OUTPUT_MODE_JSON)):
        demisto.debug(f'item: {item}')
        if handle_message(item):
            continue
        updated_notable = parse_notable(item, to_dict=True)
        demisto.debug(f'updated_notable: {updated_notable}')
        comment = updated_notable.get('comment', '')
        if comment and COMMENT_MIRRORED_FROM_XSOAR not in comment:
            # Creating a note
            notes.append({
                'Type': EntryType.NOTE,
                'Contents': comment,
                'ContentsFormat': EntryFormat.TEXT,
                'Tags': [comment_tag_from_splunk],  # The list of tags to add to the entry
                'Note': True,
            })
            demisto.debug(f'Update new comment-{comment}')
    demisto.debug(f'notes={notes}')
    return notes


def get_remote_data_command(service: client.Service, args: dict,
                            close_incident: bool, close_end_statuses: bool, close_extra_labels: list[str], mapper,
                            comment_tag_from_splunk: str):
    """ get-remote-data command: Returns an updated notable and error entry (if needed)

    Args:
        service (splunklib.client.Service): Splunk service object
        args (dict): The command arguments
        close_incident (bool): Indicates whether to close the corresponding XSOAR incident if the notable
            has been closed on Splunk's end.
        close_end_statuses (bool): Specifies whether "End Status" statuses on Splunk should be closed when mirroring.
        close_extra_labels (list[str]): A list of additional Splunk status labels to close during mirroring.

    Returns:
        GetRemoteDataResponse: The Response containing the update notable to mirror and the entries
    """
    entries = []
    updated_notable = {}
    remote_args = GetRemoteDataArgs(args)
    last_update_splunk_timestamp = get_last_update_in_splunk_time(remote_args.last_update)
    notable_id = remote_args.remote_incident_id
    search = '|`incident_review` ' \
             '| eval last_modified_timestamp=_time ' \
             f'| where rule_id="{notable_id}" ' \
             f'| where last_modified_timestamp>{last_update_splunk_timestamp} ' \
             '| fields - time ' \
             '| map search=" search `notable_by_id($rule_id$)`"'

    demisto.debug(f'Performing get-remote-data command with query: {search}')

    for item in results.JSONResultsReader(service.jobs.oneshot(search, output_mode=OUTPUT_MODE_JSON)):
        if handle_message(item):
            continue
        updated_notable = parse_notable(item, to_dict=True)
    if updated_notable.get('owner'):
        demisto.debug("owner field was found, changing according to mapping.")
        updated_notable["owner"] = mapper.get_xsoar_user_by_splunk(
            updated_notable.get("owner")) if mapper.should_map else updated_notable.get("owner")
    if close_incident and updated_notable.get('status_label'):
        status_label = updated_notable['status_label']

        if status_label == "Closed" or (status_label in close_extra_labels) \
                or (close_end_statuses and argToBoolean(updated_notable.get('status_end', 'false'))):
            demisto.info(f'Closing incident related to notable {notable_id} with status_label: {status_label}')
            entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeReason': f'Notable event was closed on Splunk with status \"{status_label}\".'
                },
                'ContentsFormat': EntryFormat.JSON
            })

    else:
        demisto.debug('"status_label" key could not be found on the returned data, '
                      f'skipping closure mirror for notable {notable_id}.')
    if updated_notable.get('comment'):
        comment_entries = []
        comments = argToList(updated_notable.get('comment'))
        for comment in comments:
            comment_entries.append({
                'Comment': comment,
            })
        new_notes = get_comments_data(service, notable_id, comment_tag_from_splunk, last_update_splunk_timestamp)
        demisto.debug(f"new_notes: {new_notes}")
        entries.extend(new_notes)
        if comment_entries:
            updated_notable['SplunkComments'] = comment_entries
    demisto.debug(f'Updated notable {notable_id}')
    return_results(GetRemoteDataResponse(mirrored_object=updated_notable, entries=entries))


def get_modified_remote_data_command(service: client.Service, args):
    """ Gets the list of all notables ids that have change since a given time

    Args:
        service (splunklib.client.Service): Splunk service object
        args (dict): The command argumens

    Returns:
        GetModifiedRemoteDataResponse: The response containing the list of ids of notables changed
    """
    modified_notable_ids: list = []
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update_splunk_timestamp = get_last_update_in_splunk_time(remote_args.last_update)
    search = '|`incident_review` ' \
             '| eval last_modified_timestamp=_time ' \
             f'| where last_modified_timestamp>{last_update_splunk_timestamp} ' \
             '| fields rule_id ' \
             '| dedup rule_id'
    demisto.debug(f'Performing get-modified-remote-data command with query: {search}')

    modified_notable_ids.extend(
        item['rule_id']
        for item in results.JSONResultsReader(
            service.jobs.oneshot(
                search, count=MIRROR_LIMIT, output_mode=OUTPUT_MODE_JSON
            )
        )
        if not handle_message(item)
    )
    if len(modified_notable_ids) >= MIRROR_LIMIT:
        demisto.info(f'Warning: More than {MIRROR_LIMIT} notables have been modified since the last update.')
    return_results(GetModifiedRemoteDataResponse(modified_incident_ids=modified_notable_ids))


def update_remote_system_command(args, params, service: client.Service, auth_token, mapper, comment_tag_to_splunk):
    """ Pushes changes in XSOAR incident into the corresponding notable event in Splunk Server.

    Args:
        args (dict): Demisto args
        params (dict): Demisto params
        service (splunklib.client.Service): Splunk service object
        auth_token (str) - The authentication token to use
        comment_tag_to_splunk (str) - tag of comment from xsaor

    Returns:
        notable_id (str): The notable id
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    notable_id = parsed_args.remote_incident_id
    entries = parsed_args.entries
    base_url = 'https://' + params['host'] + ':' + params['port'] + '/'
    demisto.debug(f"mirroring args: entries:{parsed_args.entries} delta:{parsed_args.delta}")
    if parsed_args.incident_changed and delta:
        demisto.debug(
            f'Got the following delta keys {list(delta.keys())} to update incident corresponding to notable {notable_id}'
        )

        changed_data: dict[str, Any] = {field: None for field in OUTGOING_MIRRORED_FIELDS}
        for field in delta:
            if field == 'owner' and params.get('userMapping', False):
                new_owner = mapper.get_splunk_user_by_xsoar(delta["owner"]) if mapper.should_map else None
                if new_owner:
                    changed_data['owner'] = new_owner
                else:
                    demisto.error('New owner was not found while userMapping is enabled.')
            elif field in OUTGOING_MIRRORED_FIELDS:
                changed_data[field] = delta[field]

        # Close notable if relevant
        if parsed_args.inc_status == IncidentStatus.DONE and params.get('close_notable'):
            demisto.debug(f'Closing notable {notable_id}')
            changed_data['status'] = '5'

        if any(changed_data.values()):
            demisto.debug(f'Sending update request to Splunk for notable {notable_id}, data: {changed_data}')
            try:
                session_key = None if auth_token else get_auth_session_key(service)
                response_info = update_notable_events(
                    baseurl=base_url, comment=changed_data['comment'], status=changed_data['status'],
                    urgency=changed_data['urgency'], owner=changed_data['owner'], eventIDs=[notable_id],
                    disposition=changed_data.get('disposition'), auth_token=auth_token, sessionKey=session_key
                )
                if 'success' not in response_info or not response_info['success']:
                    demisto.error(f'Failed updating notable {notable_id}: {str(response_info)}')
                else:
                    demisto.debug(
                        f"update-remote-system for notable {notable_id}: {response_info.get('message')}"
                    )

            except Exception as e:
                demisto.error(
                    f'Error in Splunk outgoing mirror for incident corresponding to notable {notable_id}. Error message: {str(e)}'
                )
        else:
            demisto.debug(f"Didn't find changed data to update incident corresponding to notable {notable_id}")

    else:
        demisto.debug(f'Incident corresponding to notable {notable_id} was not changed.')

    if entries:
        for entry in entries:
            entry_tags = entry.get('tags', [])
            demisto.debug(f'Got the entry tags: {entry_tags}')
            if comment_tag_to_splunk in entry_tags:
                demisto.debug('Add new comment')
                comment_body = f'{entry.get("contents", "")}\n {COMMENT_MIRRORED_FROM_XSOAR}'
                try:
                    session_key = get_auth_session_key(service) if not auth_token else None
                    response_info = update_notable_events(
                        baseurl=base_url, comment=comment_body, auth_token=auth_token, sessionKey=session_key,
                        eventIDs=[notable_id])
                    if 'success' not in response_info or not response_info['success']:
                        demisto.error(f'Failed updating notable {notable_id}: {str(response_info)}')
                    else:
                        demisto.debug('update-remote-system for notable {}: {}'
                                      .format(notable_id, response_info.get('message')))
                except Exception as e:
                    demisto.error('Error in Splunk outgoing mirror for incident corresponding to notable {}. '
                                  'Error message: {}'.format(notable_id, str(e)))
    return notable_id


# =========== Mirroring Mechanism ===========


# =========== Mapping Mechanism ===========

def create_mapping_dict(total_parsed_results, type_field):
    """
    Create a {'field_name': 'fields_properties'} dict to be used as mapping schemas.
    Args:
        total_parsed_results: list. the results from the splunk search query
        type_field: str. the field that represents the type of the event or alert.
    """
    types_map = {}
    for result in total_parsed_results:
        raw_json = json.loads(result.get('rawJSON', "{}"))
        if event_type_name := raw_json.get(type_field, ''):
            types_map[event_type_name] = raw_json

    return types_map


def get_mapping_fields_command(service: client.Service, mapper, params: dict, comment_tag_to_splunk: str,
                               comment_tag_from_splunk: str):
    # Create the query to get unique objects
    # The logic is identical to the 'fetch_incidents' command
    type_field = params.get('type_field', 'source')
    total_parsed_results = []
    search_offset = demisto.getLastRun().get('offset', 0)

    current_time_for_fetch = datetime.utcnow()

    if (timezone_ := params.get('timezone')):
        current_time_for_fetch = current_time_for_fetch + timedelta(minutes=int(timezone_))

    now = current_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)
    if params.get('useSplunkTime'):
        now = get_current_splunk_time(service)
        current_time_in_splunk = datetime.strptime(now, SPLUNK_TIME_FORMAT)
        current_time_for_fetch = current_time_in_splunk

    fetch_time_in_minutes = parse_time_to_minutes()
    start_time_for_fetch = current_time_for_fetch - timedelta(minutes=fetch_time_in_minutes)
    last_run = start_time_for_fetch.strftime(SPLUNK_TIME_FORMAT)

    kwargs_oneshot = {
        'earliest_time': last_run,
        'latest_time': now,
        'count': FETCH_LIMIT,
        'offset': search_offset,
        'output_mode': OUTPUT_MODE_JSON,
    }

    searchquery_oneshot = params['fetchQuery']

    if (extractFields := params.get('extractFields')):
        for field in extractFields.split(','):
            field_trimmed = field.strip()
            searchquery_oneshot = (
                f'{searchquery_oneshot} | eval {field_trimmed}={field_trimmed}'
            )

    searchquery_oneshot = f'{searchquery_oneshot} | dedup {type_field}'
    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
    reader = results.JSONResultsReader(oneshotsearch_results)
    for item in reader:
        if isinstance(item, dict):
            notable = Notable(data=item)
            total_parsed_results.append(notable.to_incident(mapper, comment_tag_to_splunk, comment_tag_from_splunk))
        elif handle_message(item):
            continue

    types_map = create_mapping_dict(total_parsed_results, type_field)
    return types_map


def get_cim_mapping_field_command():
    notable = {
        'rule_name': 'string', 'rule_title': 'string', 'security_domain': 'string', 'index': 'string',
        'rule_description': 'string', 'risk_score': 'string', 'host': 'string',
        'host_risk_object_type': 'string', 'dest_risk_object_type': 'string', 'dest_risk_score': 'string',
        'splunk_server': 'string', '_sourcetype': 'string', '_indextime': 'string', '_time': 'string',
        'src_risk_object_type': 'string', 'src_risk_score': 'string', '_raw': 'string', 'urgency': 'string',
        'owner': 'string', 'info_min_time': 'string', 'info_max_time': 'string', 'comment': 'string',
        'reviewer': 'string', 'rule_id': 'string', 'action': 'string', 'app': 'string',
        'authentication_method': 'string', 'authentication_service': 'string', 'bugtraq': 'string',
        'bytes': 'string', 'bytes_in': 'string', 'bytes_out': 'string', 'category': 'string', 'cert': 'string',
        'change': 'string', 'change_type': 'string', 'command': 'string', 'comments': 'string',
        'cookie': 'string', 'creation_time': 'string', 'cve': 'string', 'cvss': 'string', 'date': 'string',
        'description': 'string', 'dest': 'string', 'dest_bunit': 'string', 'dest_category': 'string',
        'dest_dns': 'string', 'dest_interface': 'string', 'dest_ip': 'string', 'dest_ip_range': 'string',
        'dest_mac': 'string', 'dest_nt_domain': 'string', 'dest_nt_host': 'string', 'dest_port': 'string',
        'dest_priority': 'string', 'dest_translated_ip': 'string', 'dest_translated_port': 'string',
        'dest_type': 'string', 'dest_zone': 'string', 'direction': 'string', 'dlp_type': 'string',
        'dns': 'string', 'duration': 'string', 'dvc': 'string', 'dvc_bunit': 'string', 'dvc_category': 'string',
        'dvc_ip': 'string', 'dvc_mac': 'string', 'dvc_priority': 'string', 'dvc_zone': 'string',
        'file_hash': 'string', 'file_name': 'string', 'file_path': 'string', 'file_size': 'string',
        'http_content_type': 'string', 'http_method': 'string', 'http_referrer': 'string',
        'http_referrer_domain': 'string', 'http_user_agent': 'string', 'icmp_code': 'string',
        'icmp_type': 'string', 'id': 'string', 'ids_type': 'string', 'incident': 'string', 'ip': 'string',
        'mac': 'string', 'message_id': 'string', 'message_info': 'string', 'message_priority': 'string',
        'message_type': 'string', 'mitre_technique_id': 'string', 'msft': 'string', 'mskb': 'string',
        'name': 'string', 'orig_dest': 'string', 'orig_recipient': 'string', 'orig_src': 'string',
        'os': 'string', 'packets': 'string', 'packets_in': 'string', 'packets_out': 'string',
        'parent_process': 'string', 'parent_process_id': 'string', 'parent_process_name': 'string',
        'parent_process_path': 'string', 'password': 'string', 'payload': 'string', 'payload_type': 'string',
        'priority': 'string', 'problem': 'string', 'process': 'string', 'process_hash': 'string',
        'process_id': 'string', 'process_name': 'string', 'process_path': 'string', 'product_version': 'string',
        'protocol': 'string', 'protocol_version': 'string', 'query': 'string', 'query_count': 'string',
        'query_type': 'string', 'reason': 'string', 'recipient': 'string', 'recipient_count': 'string',
        'recipient_domain': 'string', 'recipient_status': 'string', 'record_type': 'string',
        'registry_hive': 'string', 'registry_key_name': 'string', 'registry_path': 'string',
        'registry_value_data': 'string', 'registry_value_name': 'string', 'registry_value_text': 'string',
        'registry_value_type': 'string', 'request_sent_time': 'string', 'request_payload': 'string',
        'request_payload_type': 'string', 'response_code': 'string', 'response_payload_type': 'string',
        'response_received_time': 'string', 'response_time': 'string', 'result': 'string',
        'return_addr': 'string', 'rule': 'string', 'rule_action': 'string', 'sender': 'string',
        'service': 'string', 'service_hash': 'string', 'service_id': 'string', 'service_name': 'string',
        'service_path': 'string', 'session_id': 'string', 'sessions': 'string', 'severity': 'string',
        'severity_id': 'string', 'sid': 'string', 'signature': 'string', 'signature_id': 'string',
        'signature_version': 'string', 'site': 'string', 'size': 'string', 'source': 'string',
        'sourcetype': 'string', 'src': 'string', 'src_bunit': 'string', 'src_category': 'string',
        'src_dns': 'string', 'src_interface': 'string', 'src_ip': 'string', 'src_ip_range': 'string',
        'src_mac': 'string', 'src_nt_domain': 'string', 'src_nt_host': 'string', 'src_port': 'string',
        'src_priority': 'string', 'src_translated_ip': 'string', 'src_translated_port': 'string',
        'src_type': 'string', 'src_user': 'string', 'src_user_bunit': 'string', 'src_user_category': 'string',
        'src_user_domain': 'string', 'src_user_id': 'string', 'src_user_priority': 'string',
        'src_user_role': 'string', 'src_user_type': 'string', 'src_zone': 'string', 'state': 'string',
        'status': 'string', 'status_code': 'string', 'status_description': 'string', 'subject': 'string',
        'tag': 'string', 'ticket_id': 'string', 'time': 'string', 'time_submitted': 'string',
        'transport': 'string', 'transport_dest_port': 'string', 'type': 'string', 'uri': 'string',
        'uri_path': 'string', 'uri_query': 'string', 'url': 'string', 'url_domain': 'string',
        'url_length': 'string', 'user': 'string', 'user_agent': 'string', 'user_bunit': 'string',
        'user_category': 'string', 'user_id': 'string', 'user_priority': 'string', 'user_role': 'string',
        'user_type': 'string', 'vendor_account': 'string', 'vendor_product': 'string', 'vlan': 'string',
        'xdelay': 'string', 'xref': 'string'
    }

    drilldown = {
        'Drilldown': {
            'action': 'string', 'app': 'string', 'authentication_method': 'string',
            'authentication_service': 'string', 'bugtraq': 'string', 'bytes': 'string',
            'bytes_in': 'string', 'bytes_out': 'string', 'category': 'string', 'cert': 'string',
            'change': 'string', 'change_type': 'string', 'command': 'string', 'comments': 'string',
            'cookie': 'string', 'creation_time': 'string', 'cve': 'string', 'cvss': 'string',
            'date': 'string', 'description': 'string', 'dest': 'string', 'dest_bunit': 'string',
            'dest_category': 'string', 'dest_dns': 'string', 'dest_interface': 'string',
            'dest_ip': 'string', 'dest_ip_range': 'string', 'dest_mac': 'string',
            'dest_nt_domain': 'string', 'dest_nt_host': 'string', 'dest_port': 'string',
            'dest_priority': 'string', 'dest_translated_ip': 'string',
            'dest_translated_port': 'string', 'dest_type': 'string', 'dest_zone': 'string',
            'direction': 'string', 'dlp_type': 'string', 'dns': 'string', 'duration': 'string',
            'dvc': 'string', 'dvc_bunit': 'string', 'dvc_category': 'string', 'dvc_ip': 'string',
            'dvc_mac': 'string', 'dvc_priority': 'string', 'dvc_zone': 'string',
            'file_hash': 'string', 'file_name': 'string', 'file_path': 'string',
            'file_size': 'string', 'http_content_type': 'string', 'http_method': 'string',
            'http_referrer': 'string', 'http_referrer_domain': 'string', 'http_user_agent': 'string',
            'icmp_code': 'string', 'icmp_type': 'string', 'id': 'string', 'ids_type': 'string',
            'incident': 'string', 'ip': 'string', 'mac': 'string', 'message_id': 'string',
            'message_info': 'string', 'message_priority': 'string', 'message_type': 'string',
            'mitre_technique_id': 'string', 'msft': 'string', 'mskb': 'string', 'name': 'string',
            'orig_dest': 'string', 'orig_recipient': 'string', 'orig_src': 'string', 'os': 'string',
            'packets': 'string', 'packets_in': 'string', 'packets_out': 'string',
            'parent_process': 'string', 'parent_process_id': 'string',
            'parent_process_name': 'string', 'parent_process_path': 'string', 'password': 'string',
            'payload': 'string', 'payload_type': 'string', 'priority': 'string', 'problem': 'string',
            'process': 'string', 'process_hash': 'string', 'process_id': 'string',
            'process_name': 'string', 'process_path': 'string', 'product_version': 'string',
            'protocol': 'string', 'protocol_version': 'string', 'query': 'string',
            'query_count': 'string', 'query_type': 'string', 'reason': 'string',
            'recipient': 'string', 'recipient_count': 'string', 'recipient_domain': 'string',
            'recipient_status': 'string', 'record_type': 'string', 'registry_hive': 'string',
            'registry_key_name': 'string', 'registry_path': 'string',
            'registry_value_data': 'string', 'registry_value_name': 'string',
            'registry_value_text': 'string', 'registry_value_type': 'string',
            'request_payload': 'string', 'request_payload_type': 'string',
            'request_sent_time': 'string', 'response_code': 'string',
            'response_payload_type': 'string', 'response_received_time': 'string',
            'response_time': 'string', 'result': 'string', 'return_addr': 'string', 'rule': 'string',
            'rule_action': 'string', 'sender': 'string', 'service': 'string',
            'service_hash': 'string', 'service_id': 'string', 'service_name': 'string',
            'service_path': 'string', 'session_id': 'string', 'sessions': 'string',
            'severity': 'string', 'severity_id': 'string', 'sid': 'string', 'signature': 'string',
            'signature_id': 'string', 'signature_version': 'string', 'site': 'string',
            'size': 'string', 'source': 'string', 'sourcetype': 'string', 'src': 'string',
            'src_bunit': 'string', 'src_category': 'string', 'src_dns': 'string',
            'src_interface': 'string', 'src_ip': 'string', 'src_ip_range': 'string',
            'src_mac': 'string', 'src_nt_domain': 'string', 'src_nt_host': 'string',
            'src_port': 'string', 'src_priority': 'string', 'src_translated_ip': 'string',
            'src_translated_port': 'string', 'src_type': 'string', 'src_user': 'string',
            'src_user_bunit': 'string', 'src_user_category': 'string', 'src_user_domain': 'string',
            'src_user_id': 'string', 'src_user_priority': 'string', 'src_user_role': 'string',
            'src_user_type': 'string', 'src_zone': 'string', 'state': 'string', 'status': 'string',
            'status_code': 'string', 'subject': 'string', 'tag': 'string', 'ticket_id': 'string',
            'time': 'string', 'time_submitted': 'string', 'transport': 'string',
            'transport_dest_port': 'string', 'type': 'string', 'uri': 'string', 'uri_path': 'string',
            'uri_query': 'string', 'url': 'string', 'url_domain': 'string', 'url_length': 'string',
            'user': 'string', 'user_agent': 'string', 'user_bunit': 'string',
            'user_category': 'string', 'user_id': 'string', 'user_priority': 'string',
            'user_role': 'string', 'user_type': 'string', 'vendor_account': 'string',
            'vendor_product': 'string', 'vlan': 'string', 'xdelay': 'string', 'xref': 'string'
        }
    }

    asset = {
        'Asset': {
            'asset': 'string', 'asset_id': 'string', 'asset_tag': 'string', 'bunit': 'string',
            'category': 'string', 'city': 'string', 'country': 'string', 'dns': 'string',
            'ip': 'string', 'is_expected': 'string', 'lat': 'string', 'long': 'string', 'mac': 'string',
            'nt_host': 'string', 'owner': 'string', 'pci_domain': 'string', 'priority': 'string',
            'requires_av': 'string'
        }
    }

    identity = {
        'Identity': {
            'bunit': 'string', 'category': 'string', 'email': 'string', 'endDate': 'string', 'first': 'string',
            'identity': 'string', 'identity_tag': 'string', 'last': 'string', 'managedBy': 'string',
            'nick': 'string', 'phone': 'string', 'prefix': 'string', 'priority': 'string',
            'startDate': 'string', 'suffix': 'string', 'watchlist': 'string', 'work_city': 'string',
            'work_lat': 'string', 'work_long': 'string'
        }
    }

    return {
        'Notable Data': notable,
        'Drilldown Data': drilldown,
        'Asset Data': asset,
        'Identity Data': identity
    }


# =========== Mapping Mechanism ===========


# =========== Integration Functions & Classes ===========

class ResponseReaderWrapper(io.RawIOBase):
    """ This class was supplied as a solution for a bug in Splunk causing the search to run slowly."""

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


def get_current_splunk_time(splunk_service: client.Service):
    t = datetime.utcnow() - timedelta(days=3)
    time = t.strftime(SPLUNK_TIME_FORMAT)
    kwargs_oneshot = {'count': 1, 'earliest_time': time, 'output_mode': OUTPUT_MODE_JSON, }
    searchquery_oneshot = '| gentimes start=-1 | eval clock = strftime(time(), "%Y-%m-%dT%H:%M:%S")' \
                          ' | sort 1 -_time | table clock'

    oneshotsearch_results = splunk_service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)

    reader = results.JSONResultsReader(oneshotsearch_results)
    for item in reader:
        if isinstance(item, dict):
            return item["clock"]
        if handle_message(item):
            continue

    raise ValueError('Error: Could not fetch Splunk time')


def quote_group(text):
    """ A function that splits groups of key value pairs.
        Taking into consideration key values pairs with nested quotes.
    """

    def clean(t):
        return t.strip().rstrip(',')

    # Return strings that aren't key-valued, as is.
    if len(text.strip()) < 3 or "=" not in text:
        return [text]

    # Remove prefix & suffix wrapping quotes if present around all the text
    # For example a text could be:
    # "a="123"", we want it to be: a="123"
    text = re.sub(r'^\"([\s\S]+\")\"$', r'\1', text)

    # Some of the texts don't end with a comma so we add it to make sure
    # everything acts the same.
    if not text.rstrip().endswith(","):
        text = text.rstrip()
        text += ","

    # Fix elements that aren't key=value (`111, a="123"` => `a="123"`)
    # (^) - start of text
    # ([^=]+), - everything without equal sign and a comma at the end
    #   ('111,' above)
    text = re.sub(r"(^)([^=]+),", ",", text).lstrip(",")

    # Wrap all key values without a quote (`a=123` => `a="123"`)
    # Key part: ([^\"\,]+?=)
    #   asdf=123, here it will match 'asdf'.
    #
    # Value part: ([^\"]+?)
    #   every string without a quote or doesn't start the text.
    #   For example: asdf=123, here it will match '123'.
    #
    # End value part: (,|\")
    #   we need to decide when to end the value, in our case
    #   with a comma. We also check for quotes for this case:
    #   a="b=nested_value_without_a_wrapping_quote", as we want to
    #   wrap 'nested_value_without_a_wrapping_quote' with quotes.
    text = re.sub(r'([^\"\,]+?=)([^\"]+?)(,|\")', r'\1"\2"\3', text)

    # The basic idea here is to check that every key value ends with a `",`
    # Assuming that there are even number of quotes before
    # (some values can have deep nested quotes).
    quote_counter = 0
    rindex = 0
    lindex = 0
    groups = []
    while rindex < len(text):

        # For every quote we increment the quote counter
        # (to preserve context on the opening/closed quotes)
        if text[rindex] == '"':
            quote_counter += 1

        # A quote group ends when `",` is encountered.
        is_end_keypair = rindex > 1 and text[rindex - 1] + text[rindex] == '",'

        # If the quote_counter isn't even we shouldn't close the group,
        # for example: a="b="1",c="3""                * *
        # I'll space for readability:   a = " b = " 1 " , c ...
        #                               0 1 2 3 4 5 6 7 8 9
        # quote_counter is even:            F     T   F   T
        # On index 7 & 8 we find a potential quote closing, but as you can
        # see it isn't a valid group (because of nesting) we need to check
        # the quote counter for an even number => a closing match.
        is_even_number_of_quotes = quote_counter % 2 == 0

        # We check both conditions to find a group
        if is_end_keypair and is_even_number_of_quotes:
            # Clean the match group and append to groups
            groups.append(clean(text[lindex:rindex]))

            # Incrementing the indexes to start searching for the next group.
            lindex = rindex + 1
            rindex += 1
            quote_counter = 0

        # Continue to walk the string until we find a quote again.
        rindex += 1

    # Sometimes there aren't any quotes in the string so we can just append it
    if not groups:
        groups.append(clean(text))

    return groups


def rawToDict(raw):
    result: dict[str, str] = {}
    try:
        result = json.loads(raw)
    except ValueError:
        if '"message"' in raw:
            raw = raw.replace('"', '').strip('{').strip('}')
            key_val_arr = raw.split(",")
            for key_val in key_val_arr:
                single_key_val = key_val.split(":", 1)
                if len(single_key_val) <= 1:
                    single_key_val = key_val.split("=", 1)
                if len(single_key_val) > 1:
                    val = single_key_val[1]
                    key = single_key_val[0].strip()

                    result[key] = f"{result[key]},{val}" if key in tuple(result.keys()) else val
        else:
            # search for the pattern: `key="value", `
            # (the double quotes are optional)
            # we append `, ` to the end of the string to catch the last value
            groups = quote_group(raw)
            for g in groups:
                key_value = g.replace('"', '').strip()
                if key_value == '':
                    continue

                if '=' in key_value:
                    key_and_val = key_value.split('=', 1)
                    result[key_and_val[0]] = key_and_val[1]

    if REPLACE_FLAG:
        result = replace_keys(result)
    return result


# Converts to an str
def convert_to_str(obj):
    return obj.encode('utf-8') if isinstance(obj, str) else str(obj)


def update_notable_events(baseurl, comment, status=None, urgency=None, owner=None, eventIDs=None,
                          disposition=None, searchID=None, auth_token=None, sessionKey=None):
    """
    Update some notable events.

    Arguments:
    comment -- A description of the change or some information about the notable events
    status -- A status (only required if you are changing the status of the event)
    urgency -- An urgency (only required if you are changing the urgency of the event)
    owner -- A nowner (only required if reassigning the event)
    eventIDs -- A list of notable event IDs (must be provided if a search ID is not provided)
    searchID -- An ID of a search. All of the events associated with this search will be modified
     unless a list of eventIDs are provided that limit the scope to a sub-set of the results.
    auth_token - The authentication token to use
    sessionKey -- The session key to use
    """

    # Make sure that the session ID was provided
    if not sessionKey and not auth_token:
        raise Exception("A session_key/auth_token was not provided")

    # Make sure that rule IDs and/or a search ID is provided
    if eventIDs is None and searchID is None:
        raise Exception("Either eventIDs of a searchID must be provided (or both)")

    # These the arguments to the REST handler
    args = {'comment': comment}

    if status is not None:
        args['status'] = status

    if urgency is not None:
        args['urgency'] = urgency

    if owner is not None:
        args['newOwner'] = owner

    # Provide the list of event IDs that you want to change:
    if eventIDs is not None:
        args['ruleUIDs'] = eventIDs

    if disposition:
        args['disposition'] = disposition

    # If you want to manipulate the notable events returned by a search then include the search ID
    if searchID is not None:
        args['searchID'] = searchID

    auth_header = (
        {"Authorization": f"Bearer {auth_token}"} if auth_token else {"Authorization": sessionKey}
    )

    args['output_mode'] = OUTPUT_MODE_JSON

    mod_notables = requests.post(
        f'{baseurl}services/notable_update',
        data=args,
        headers=auth_header,
        verify=VERIFY_CERTIFICATE,
    )

    return mod_notables.json()


def severity_to_level(severity: str | None) -> int | float:
    match severity:
        case 'informational':
            return 0.5
        case 'critical':
            return 4
        case 'high':
            return 3
        case 'medium':
            return 2
        case _:
            return 1


def parse_notable(notable, to_dict=False):
    """ Parses the notable

    Args:
        notable (OrderedDict): The notable
        to_dict (bool): Whether to cast the notable to dict or not.

    Returns (OrderedDict or dict): The parsed notable
    """
    notable = replace_keys(notable) if REPLACE_FLAG else notable
    for key, val in list(notable.items()):
        # if notable event raw fields were sent in double quotes (e.g. "DNS Destination") and the field does not exist
        # in the event, then splunk returns the field with the key as value (e.g. ("DNS Destination", "DNS Destination")
        # so we go over the fields, and check if the key equals the value and set the value to be empty string
        if key == val:
            demisto.debug(
                f'Found notable event raw field [{key}] with key that equals the value - replacing the value with empty string'
            )
            notable[key] = ''
    return dict(notable) if to_dict else notable


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
        demisto.debug(f'Got exception while using requests handler - {str(e)}')
    return {
        'status': response.status_code,
        'reason': response.reason,
        'headers': list(response.headers.items()),
        'body': io.BytesIO(response.content)
    }


def build_search_kwargs(args, polling=False):
    t = datetime.utcnow() - timedelta(days=7)
    time_str = t.strftime(SPLUNK_TIME_FORMAT)

    kwargs_normalsearch: dict[str, Any] = {
        "earliest_time": time_str,
    }
    if demisto.get(args, 'earliest_time'):
        kwargs_normalsearch['earliest_time'] = args['earliest_time']
    if demisto.get(args, 'latest_time'):
        kwargs_normalsearch['latest_time'] = args['latest_time']
    if demisto.get(args, 'app'):
        kwargs_normalsearch['app'] = args['app']
    if argToBoolean(demisto.get(args, 'fast_mode')):
        kwargs_normalsearch['adhoc_search_level'] = "fast"
    kwargs_normalsearch['exec_mode'] = "normal" if polling else "blocking"
    return kwargs_normalsearch


def build_search_query(args):
    query = args['query']
    if not query.startswith('search') and not query.startswith('Search') and not query.startswith('|'):
        query = f'search {query}'
    return query


def create_entry_context(args: dict, parsed_search_results, dbot_scores, status_res, job_id):
    ec = {}
    number_of_results = len(parsed_search_results)

    if args.get('update_context', "true") == "true":
        ec['Splunk.Result'] = parsed_search_results
        if len(dbot_scores) > 0:
            ec['DBotScore'] = dbot_scores
        if status_res:
            ec['Splunk.JobStatus(val.SID && val.SID === obj.SID)'] = {
                **status_res.outputs, 'TotalResults': number_of_results}
    if job_id and not status_res:
        status = 'DONE' if (number_of_results > 0) else 'NO RESULTS'
        ec['Splunk.JobStatus(val.SID && val.SID === obj.SID)'] = [{'SID': job_id,
                                                                   'TotalResults': number_of_results,
                                                                   'Status': status}]
    return ec


def schedule_polling_command(command: str, args: dict, interval_in_secs: int) -> ScheduledCommand:
    """
    Returns a ScheduledCommand object which contain the needed arguments for schedule the polling command.
    """
    return ScheduledCommand(
        command=command,
        next_run_in_seconds=interval_in_secs,
        args=args,
        timeout_in_seconds=600
    )


def build_search_human_readable(args: dict, parsed_search_results, sid) -> str:
    headers = ""
    if parsed_search_results and len(parsed_search_results) > 0:
        if not isinstance(parsed_search_results[0], dict):
            headers = "results"
        else:
            query = args.get('query', '')
            table_args = re.findall(' table (?P<table>[^|]*)', query)
            rename_args = re.findall(' rename (?P<rename>[^|]*)', query)

            chosen_fields: list = []
            for arg_string in table_args:
                chosen_fields.extend(
                    field.strip('"')
                    for field in re.findall(
                        r'((?:".*?")|(?:[^\s,]+))', arg_string
                    )
                    if field
                )
            rename_dict = {}
            for arg_string in rename_args:
                for field in re.findall(r'((?:".*?")|(?:[^\s,]+))( AS )((?:".*?")|(?:[^\s,]+))', arg_string):
                    if field:
                        rename_dict[field[0].strip('"')] = field[-1].strip('"')

            # replace renamed fields
            chosen_fields = [rename_dict.get(field, field) for field in chosen_fields]

            headers = update_headers_from_field_names(parsed_search_results, chosen_fields)

    query = args['query'].replace('`', r'\`')
    hr_headline = 'Splunk Search results for query:\n'
    if sid:
        hr_headline += f'sid: {str(sid)}'
    return tableToMarkdown(hr_headline, parsed_search_results, headers)


def update_headers_from_field_names(search_result, chosen_fields):

    headers: list = []
    search_result_keys: set = set().union(*(list(d.keys()) for d in search_result))
    for field in chosen_fields:
        if field[-1] == '*':
            temp_field = field.replace('*', '.*')
            headers.extend(key for key in search_result_keys if re.search(temp_field, key))
        elif field in search_result_keys:
            headers.append(field)

    return headers


def get_current_results_batch(search_job: client.Job, batch_size: int, results_offset: int):
    current_batch_kwargs = {
        "count": batch_size,
        "offset": results_offset,
        'output_mode': OUTPUT_MODE_JSON,
    }

    return search_job.results(**current_batch_kwargs)


def parse_batch_of_results(current_batch_of_results, max_results_to_add, app):
    parsed_batch_results = []
    batch_dbot_scores = []
    results_reader = results.JSONResultsReader(io.BufferedReader(ResponseReaderWrapper(current_batch_of_results)))
    for item in results_reader:
        if handle_message(item):
            continue

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


def splunk_search_command(service: client.Service, args: dict) -> CommandResults:
    query = build_search_query(args)
    polling = argToBoolean(args.get("polling", False))
    search_kwargs = build_search_kwargs(args, polling)
    job_sid = args.get("sid")
    search_job = None
    interval_in_secs = int(args.get('interval_in_seconds', 30))
    if not job_sid or not polling:
        # create a new job to search the query.
        search_job = service.jobs.create(query, **search_kwargs)
        job_sid = search_job["sid"]
        args['sid'] = job_sid
    status_cmd_result: CommandResults | None = None
    if polling:
        status_cmd_result = splunk_job_status(service, args)
        assert status_cmd_result  # if polling is true, status_cmd_result should not be None
        status = status_cmd_result.outputs['Status']  # type: ignore[index]
        if status.lower() != 'done':
            # Job is still running, schedule the next run of the command.
            scheduled_command = schedule_polling_command("splunk-search", args, interval_in_secs)
            status_cmd_result.scheduled_command = scheduled_command
            status_cmd_result.readable_output = 'Job is still running, it may take a little while...'
            return status_cmd_result
        else:
            # Get the job by its SID.
            search_job = service.job(job_sid)
    num_of_results_from_query = search_job["resultCount"] if search_job else None

    results_limit = float(args.get("event_limit", 100))
    if results_limit == 0.0:
        # In Splunk, a result limit of 0 means no limit.
        results_limit = float("inf")
    batch_size = int(args.get("batch_limit", 25000))

    results_offset = 0
    total_parsed_results: list[dict[str, Any]] = []
    dbot_scores: list[dict[str, Any]] = []

    while len(total_parsed_results) < int(num_of_results_from_query) and len(total_parsed_results) < results_limit:
        current_batch_of_results = get_current_results_batch(search_job, batch_size, results_offset)
        max_results_to_add = results_limit - len(total_parsed_results)
        parsed_batch_results, batch_dbot_scores = parse_batch_of_results(current_batch_of_results, max_results_to_add,
                                                                         search_kwargs.get('app', ''))
        total_parsed_results.extend(parsed_batch_results)
        dbot_scores.extend(batch_dbot_scores)

        results_offset += batch_size
    entry_context = create_entry_context(args, total_parsed_results, dbot_scores, status_cmd_result, str(job_sid))
    human_readable = build_search_human_readable(args, total_parsed_results, str(job_sid))

    return CommandResults(
        outputs=entry_context,
        raw_response=total_parsed_results,
        readable_output=human_readable
    )


def splunk_job_create_command(service: client.Service, args: dict):
    query = args['query']
    app = args.get('app', '')
    if not query.startswith('search'):
        query = f'search {query}'
    search_kwargs = {
        "exec_mode": "normal",
        "app": app
    }
    search_job = service.jobs.create(query, **search_kwargs)

    return_results(CommandResults(
        outputs_prefix='Splunk',
        readable_output=f"Splunk Job created with SID: {search_job.sid}",
        outputs={'Job': search_job.sid}
    ))


def splunk_results_command(service: client.Service, args: dict):
    res = []
    sid = args.get('sid', '')
    limit = int(args.get('limit', '100'))
    try:
        job = service.job(sid)
    except HTTPError as error:
        msg = error.message if hasattr(error, 'message') else str(error)
        if error.status == 404:
            return f"Found no job for sid: {sid}"
        else:
            return_error(msg, error)
    else:
        for result in results.JSONResultsReader(job.results(count=limit, output_mode=OUTPUT_MODE_JSON)):
            if isinstance(result, results.Message):
                res.append({"Splunk message": json.dumps(result.message)})
            elif isinstance(result, dict):
                # Normal events are returned as dicts
                res.append(result)
        return_results(CommandResults(
            raw_response=json.dumps(res),
            content_format=EntryFormat.JSON,
        ))


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
    if time_unit_value_in_minutes := TIME_UNIT_TO_MINUTES.get(
        time_unit.lower()
    ):
        return number_of_times * time_unit_value_in_minutes

    return_error('Error: Invalid time unit.')
    return None


def splunk_get_indexes_command(service: client.Service):
    indexes = service.indexes
    indexesNames = []
    for index in indexes:
        index_json = {'name': index.name, 'count': index["totalEventCount"]}
        indexesNames.append(index_json)
    return_results(CommandResults(
        content_format=EntryFormat.JSON,
        raw_response=json.dumps(indexesNames),
        readable_output=tableToMarkdown("Splunk Indexes names", indexesNames, '')
    ))


def splunk_submit_event_command(service: client.Service, args: dict):
    try:
        index = service.indexes[args['index']]
    except KeyError:
        return_error(f'Found no Splunk index: {args["index"]}')

    else:
        data = args['data']
        data_formatted = data.encode('utf8')
        r = index.submit(data_formatted, sourcetype=args['sourcetype'], host=args['host'])
        return_results(f'Event was created in Splunk index: {r.name}')


def splunk_submit_event_hec(
    hec_token: str | None,
    baseurl: str,
    event: str | None,
    fields: str | None,
    host: str | None,
    index: str | None,
    source_type: str | None,
    source: str | None,
    time_: str | None
):
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
        'Authorization': f'Splunk {hec_token}',
        'Content-Type': 'application/json'
    }

    return requests.post(
        f'{baseurl}/services/collector/event',
        data=json.dumps(args),
        headers=headers,
        verify=VERIFY_CERTIFICATE,
    )


def splunk_submit_event_hec_command(params: dict, args: dict):
    hec_token = params.get('cred_hec_token', {}).get('password') or params.get('hec_token')
    baseurl = params.get('hec_url')
    if baseurl is None:
        raise Exception('The HEC URL was not provided.')

    event = args.get('event')
    host = args.get('host')
    fields = args.get('fields')
    index = args.get('index')
    source_type = args.get('source_type')
    source = args.get('source')
    time_ = args.get('time')

    response_info = splunk_submit_event_hec(hec_token, baseurl, event, fields, host, index, source_type, source, time_)

    if 'Success' not in response_info.text:
        return_error('Could not send event to Splunk ' + response_info.text.encode('utf8'))
    else:
        return_results('The event was sent successfully to Splunk.')


def splunk_edit_notable_event_command(base_url: str, token: str, auth_token: str | None, args: dict) -> None:
    session_key = None if auth_token else token

    event_ids = None
    if args.get('eventIDs'):
        event_ids_str = args['eventIDs']
        event_ids = event_ids_str.split(",")

    status = int(args['status']) if args.get('status') else None
    # Map the label to the disposition id
    disposition = args.get('disposition', '')
    if disposition and disposition in DEFAULT_DISPOSITIONS:
        disposition = DEFAULT_DISPOSITIONS[disposition]

    response_info = update_notable_events(baseurl=base_url,
                                          comment=args.get('comment'), status=status,
                                          urgency=args.get('urgency'),
                                          owner=args.get('owner'), eventIDs=event_ids,
                                          disposition=disposition,
                                          auth_token=auth_token, sessionKey=session_key)

    if 'success' not in response_info or not response_info['success']:
        return_error(f'Could not update notable events: {args.get("eventIDs", "")}: {str(response_info)}')
    else:
        return_results(f'Splunk ES Notable events: {response_info.get("message")}')


def splunk_job_status(service: client.Service, args: dict) -> CommandResults | None:
    sid = args.get('sid')
    try:
        job = service.job(sid)
    except HTTPError as error:
        if str(error) == 'HTTP 404 Not Found -- Unknown sid.':
            return CommandResults(readable_output=f"Not found job for SID: {sid}")
        else:
            return_error(error)  # pylint: disable=no-member
        return None
    else:
        status = job.state.content.get('dispatchState')
        entry_context = {
            'SID': sid,
            'Status': status
        }
        human_readable = tableToMarkdown('Splunk Job Status', entry_context)
        return CommandResults(
            outputs=entry_context,
            readable_output=human_readable,
            outputs_prefix="Splunk.JobStatus",
            outputs_key_field="SID"
        )


def splunk_parse_raw_command(args: dict):
    raw = args.get('raw', '')
    rawDict = rawToDict(raw)
    return_results(CommandResults(
        outputs_prefix='Splunk.Raw.Parsed',
        raw_response=json.dumps(rawDict),
        outputs=rawDict,
        content_format=EntryFormat.JSON
    ))


def test_module(service: client.Service, params: dict) -> None:
    try:
        # validate connection
        service.info()
    except AuthenticationError:
        return_error('Authentication error, please validate your credentials.')

    # validate fetch
    if params.get('isFetch'):
        t = datetime.utcnow() - timedelta(hours=1)
        time = t.strftime(SPLUNK_TIME_FORMAT)
        kwargs = {'count': 1, 'earliest_time': time, 'output_mode': OUTPUT_MODE_JSON}
        query = params['fetchQuery']
        try:
            if MIRROR_DIRECTION.get(params.get('mirror_direction', '')) and not params.get('timezone'):
                return_error('Cannot mirror incidents when timezone is not configured. Please enter the '
                             'timezone of the Splunk server being used in the integration configuration.')

            for item in results.JSONResultsReader(service.jobs.oneshot(query, **kwargs)):
                if isinstance(item, results.Message):
                    continue

                if EVENT_ID not in item:
                    if MIRROR_DIRECTION.get(params.get('mirror_direction', '')):
                        return_error('Cannot mirror incidents if fetch query does not use the `notable` macro.')
                    if ENABLED_ENRICHMENTS:
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
            requests.get(params.get('hec_url', '') + '/services/collector/health', headers=headers,
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


def kv_store_collection_create(service: client.Service, args: dict) -> CommandResults:
    try:
        service.kvstore.create(args['kv_store_name'])
    except HTTPError as error:
        if error.status == 409 and error.reason == 'Conflict':
            raise DemistoException(
                f"KV store collection {service.namespace['app']} already exists.",
            ) from error
        raise

    return CommandResults(
        readable_output=f"KV store collection {service.namespace['app']} created successfully",
    )


def kv_store_collection_config(service: client.Service, args: dict) -> CommandResults:
    app = service.namespace['app']
    kv_store_collection_name = args['kv_store_collection_name']
    kv_store_fields = args['kv_store_fields'].split(',')
    for key_val in kv_store_fields:
        try:
            _key, val = key_val.split('=', 1)
        except ValueError:
            return_error(f'error when trying to parse {key_val} you possibly forgot to add the field type.')
        else:
            if _key.startswith('index.'):
                service.kvstore[kv_store_collection_name].update_index(_key.replace('index.', ''), val)
            else:
                service.kvstore[kv_store_collection_name].update_field(_key.replace('field.', ''), val)
    return CommandResults(
        readable_output=f"KV store collection {app} configured successfully"
    )


def kv_store_collection_create_transform(service: client.Service, args: dict) -> CommandResults:
    collection_name = args['kv_store_collection_name']
    fields = args.get('supported_fields')
    if not fields:
        kv_store = service.kvstore[collection_name]
        default_keys = get_keys_and_types(kv_store).keys()
        if not default_keys:
            raise DemistoException('Please provide supported_fields or run first splunk-kv-store-collection-config')
        default_keys = (key.replace('field.', '').replace('index.', '') for key in default_keys)
        fields = f"_key,{','.join(default_keys)}"

    transforms = service.confs["transforms"]
    params = {
        "external_type": "kvstore",
        "collection": collection_name,
        "namespace": service.namespace,
        "fields_list": fields
    }
    transforms.create(name=collection_name, **params)
    return CommandResults(
        readable_output=f"KV store collection transforms {collection_name} created successfully"
    )


def batch_kv_upload(kv_data_service_client: client.KVStoreCollectionData, json_data: str) -> dict:
    if json_data.startswith('[') and json_data.endswith(']'):
        record: Record = kv_data_service_client._post(
            'batch_save', headers=client.KVStoreCollectionData.JSON_HEADER, body=json_data.encode('utf-8'))
        return dict(record.items())
    elif json_data.startswith('{') and json_data.endswith('}'):
        return kv_data_service_client.insert(json_data.encode('utf-8'))
    else:
        raise DemistoException('kv_store_data argument should be in json format. '
                               '(e.g. {"key": "value"} or [{"key": "value"}, {"key": "value"}]')


def kv_store_collection_add_entries(service: client.Service, args: dict) -> None:
    kv_store_data = args.get('kv_store_data', '')
    kv_store_collection_name = args['kv_store_collection_name']
    indicator_path = args.get('indicator_path')
    batch_kv_upload(service.kvstore[kv_store_collection_name].data, kv_store_data)
    indicators_timeline = None
    if indicator_path:
        kv_store_data = json.loads(kv_store_data)
        indicators = extract_indicator(indicator_path,
                                       kv_store_data if isinstance(kv_store_data, list) else [kv_store_data])
        indicators_timeline = IndicatorsTimeline(
            indicators=indicators,
            category='Integration Update',
            message=f'Indicator added to {kv_store_collection_name} store in Splunk'
        )
    return_results(CommandResults(
        readable_output=f"Data added to {kv_store_collection_name}",
        indicators_timeline=indicators_timeline
    ))


def kv_store_collections_list(service: client.Service) -> None:
    app_name = service.namespace['app']
    names = [x.name for x in service.kvstore.iter()]
    readable_output = "list of collection names {}\n| name |\n| --- |\n|{}|".format(app_name, '|\n|'.join(names))
    return_results(CommandResults(
        outputs_prefix='Splunk.CollectionList',
        outputs=names,
        readable_output=readable_output,
        raw_response=names
    ))


def kv_store_collection_data_delete(service: client.Service, args: dict) -> None:
    kv_store_collection_name = args['kv_store_collection_name'].split(',')
    for store in kv_store_collection_name:
        service.kvstore[store].data.delete()
    return_results(f"The values of the {args['kv_store_collection_name']} were deleted successfully")


def kv_store_collection_delete(service: client.Service, args: dict) -> CommandResults:
    kv_store_names = args['kv_store_name']
    for store in kv_store_names.split(','):
        service.kvstore[store].delete()
    return CommandResults(readable_output=f'The following KV store {kv_store_names} were deleted successfully.')


def build_kv_store_query(kv_store: client.KVStoreCollection, args: dict):
    if 'key' in args and 'value' in args:
        _type = get_key_type(kv_store, args['key'])
        args['value'] = _type(args['value']) if _type else args['value']
        return json.dumps({args['key']: args['value']})
    elif 'limit' in args:
        return {'limit': args['limit']}
    else:
        return args.get('query', '{}')


def kv_store_collection_data(service: client.Service, args: dict) -> None:
    stores = args['kv_store_collection_name'].split(',')

    for i, store_res in enumerate(get_store_data(service)):
        store = service.kvstore[stores[i]]

        if store_res:
            readable_output = tableToMarkdown(name=f"list of collection values {store.name}",
                                              t=store_res)
            return_results(
                CommandResults(
                    outputs_prefix='Splunk.KVstoreData',
                    outputs={store.name: store_res},
                    readable_output=readable_output,
                    raw_response=store_res
                )
            )
        else:
            return_results(get_kv_store_config(store))


def kv_store_collection_delete_entry(service: client.Service, args: dict) -> None:
    store_name = args['kv_store_collection_name']
    indicator_path = args.get('indicator_path')
    store: client.KVStoreCollection = service.kvstore[store_name]
    query = build_kv_store_query(store, args)
    store_res = next(get_store_data(service))
    indicators = extract_indicator(indicator_path, store_res) if indicator_path else []
    store.data.delete(query=query)
    indicators_timeline = IndicatorsTimeline(
        indicators=indicators,
        category='Integration Update',
        message=f'Indicator deleted from {store_name} store in Splunk'
    ) if indicators else None
    return_results(CommandResults(
        readable_output=f'The values of the {store_name} were deleted successfully',
        indicators_timeline=indicators_timeline
    ))


def check_error(service: client.Service, args: dict) -> None:
    app = args.get('app_name')
    store_name = args.get('kv_store_collection_name')
    if app not in service.apps:
        raise DemistoException('app not found')
    elif store_name and store_name not in service.kvstore:
        raise DemistoException('KV Store not found')


def get_key_type(kv_store: client.KVStoreCollection, _key: str):
    keys_and_types = get_keys_and_types(kv_store)
    types = {
        'number': float,
        'string': str,
        'cidr': str,
        'boolean': bool,
        'time': str
    }
    index = f'index.{_key}'
    field = f'field.{_key}'
    val_type = keys_and_types.get(field) or keys_and_types.get(index) or ''
    return types.get(val_type)


def get_keys_and_types(kv_store: client.KVStoreCollection) -> dict[str, str]:
    keys = kv_store.content()
    for key_name in list(keys.keys()):
        if not (key_name.startswith(("field.", "index."))):
            del keys[key_name]
    return keys


def get_kv_store_config(kv_store: client.KVStoreCollection) -> str:
    keys = get_keys_and_types(kv_store)
    readable = [f'#### configuration for {kv_store.name} store',
                '| field name | type |',
                '| --- | --- |']
    readable.extend(f'| {_key} | {val} |' for _key, val in keys.items())
    return '\n'.join(readable)


def get_auth_session_key(service: client.Service) -> str:
    """
    Get the session key or token for POST request based on whether the Splunk basic auth are true or not
    """
    return service and service.basic and service._auth_headers[0][1] or service.token


def extract_indicator(indicator_path: str, _dict_objects: list[dict]) -> list[str]:
    indicators = []
    indicator_paths = indicator_path.split('.')
    for indicator_obj in _dict_objects:
        indicator = ''
        for path in indicator_paths:
            indicator = indicator_obj.get(path, {})
        indicators.append(str(indicator))
    return indicators


def get_store_data(service: client.Service):
    args = demisto.args()
    stores = args['kv_store_collection_name'].split(',')

    for store in stores:
        kvstore: client.KVStoreCollection = service.kvstore[store]
        query = build_kv_store_query(kvstore, args)
        if isinstance(query, str):
            query = {'query': query}
        yield kvstore.data.query(**query)


def get_connection_args(params: dict) -> dict:
    """
    This function gets the connection arguments: host, port, app, and verify.

    Returns: connection args
    """
    app = params.get('app', '-')
    return {
        'host': params['host'],
        'port': params['port'],
        'app': app or "-",
        'verify': VERIFY_CERTIFICATE,
    }


def handle_message(item: results.Message | dict) -> bool:
    """Checks if the response from JSONResultsReader is a message object.
        The message can be info etc.
        such as: "the test table is empty"

    Args:
        item (results.Message | dict): The item to be checked. It can be either a `results.Message`
            object or a dictionary.

    Returns:
        bool: Returns `True` if the item is an instance of `results.Message`, `False` otherwise.

    """
    if isinstance(item, results.Message):
        demisto.info(f"Splunk-SDK message: {item.message}")
        return True
    return False


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    if command == 'splunk-parse-raw':
        splunk_parse_raw_command(args)
        sys.exit(0)
    service = None
    proxy = argToBoolean(params.get('proxy', False))

    connection_args = get_connection_args(params)

    base_url = 'https://' + params['host'] + ':' + params['port'] + '/'
    auth_token = None
    username = params['authentication']['identifier']
    password = params['authentication']['password']
    if username == '_token':
        connection_args['splunkToken'] = password
        auth_token = password
    else:
        if '@_basic' in username:
            username = username.split('@_basic')[0]
            connection_args['basic'] = True
        connection_args['username'] = username
        connection_args['password'] = password
        connection_args['autologin'] = True

    if proxy:
        handle_proxy()

    comment_tag_to_splunk = params.get('comment_tag_to_splunk', 'FROM XSOAR')
    comment_tag_from_splunk = params.get('comment_tag_from_splunk', 'FROM SPLUNK')
    if comment_tag_to_splunk == comment_tag_from_splunk:
        raise DemistoException('Comment Tag to Splunk and Comment Tag '
                               'from Splunk cannot have the same value.')

    connection_args['handler'] = requests_handler

    if (service := client.connect(**connection_args)) is None:
        demisto.error("Could not connect to SplunkPy")

    mapper = UserMappingObject(service, params.get('userMapping'), params.get('user_map_lookup_name'),
                               params.get('xsoar_user_field'), params.get('splunk_user_field'))

    # The command command holds the command sent from the user.
    if command == 'test-module':
        test_module(service, params)
        return_results('ok')
    elif command == 'splunk-reset-enriching-fetch-mechanism':
        reset_enriching_fetch_mechanism()
    elif command == 'splunk-search':
        return_results(splunk_search_command(service, args))
    elif command == 'splunk-job-create':
        splunk_job_create_command(service, args)
    elif command == 'splunk-results':
        splunk_results_command(service, args)
    elif command == 'splunk-get-indexes':
        splunk_get_indexes_command(service)
    elif command == 'fetch-incidents':
        demisto.info('########### FETCH #############')
        fetch_incidents(service, mapper, comment_tag_to_splunk, comment_tag_from_splunk)
    elif command == 'splunk-submit-event':
        splunk_submit_event_command(service, args)
    elif command == 'splunk-notable-event-edit':
        token = get_auth_session_key(service)
        splunk_edit_notable_event_command(base_url, token, auth_token, args)
    elif command == 'splunk-submit-event-hec':
        splunk_submit_event_hec_command(params, args)
    elif command == 'splunk-job-status':
        return_results(splunk_job_status(service, args))
    elif command.startswith('splunk-kv-') and service is not None:
        app = args.get('app_name', 'search')
        service.namespace = namespace(app=app, owner='nobody', sharing='app')
        check_error(service, args)

        if command == 'splunk-kv-store-collection-create':
            return_results(kv_store_collection_create(service, args))
        elif command == 'splunk-kv-store-collection-config':
            return_results(kv_store_collection_config(service, args))
        elif command == 'splunk-kv-store-collection-create-transform':
            return_results(kv_store_collection_create_transform(service, args))
        elif command == 'splunk-kv-store-collection-delete':
            return_results(kv_store_collection_delete(service, args))
        elif command == 'splunk-kv-store-collections-list':
            kv_store_collections_list(service)
        elif command == 'splunk-kv-store-collection-add-entries':
            kv_store_collection_add_entries(service, args)
        elif command in ['splunk-kv-store-collection-data-list',
                         'splunk-kv-store-collection-search-entry']:
            kv_store_collection_data(service, args)
        elif command == 'splunk-kv-store-collection-data-delete':
            kv_store_collection_data_delete(service, args)
        elif command == 'splunk-kv-store-collection-delete-entry':
            kv_store_collection_delete_entry(service, args)

    elif command == 'get-mapping-fields':
        if argToBoolean(params.get('use_cim', False)):
            return_results(get_cim_mapping_field_command())
        else:
            return_results(get_mapping_fields_command(service, mapper, params, comment_tag_to_splunk, comment_tag_from_splunk))
    elif command == 'get-remote-data':
        demisto.info('########### MIRROR IN #############')
        get_remote_data_command(service=service, args=args,
                                close_incident=params.get('close_incident'),
                                close_end_statuses=params.get('close_end_status_statuses'),
                                close_extra_labels=argToList(params.get('close_extra_labels', '')),
                                mapper=mapper,
                                comment_tag_from_splunk=comment_tag_from_splunk)
    elif command == 'get-modified-remote-data':
        get_modified_remote_data_command(service, args)
    elif command == 'update-remote-system':
        demisto.info('########### MIRROR OUT #############')
        return_results(update_remote_system_command(args, params, service, auth_token, mapper, comment_tag_to_splunk))
    elif command == 'splunk-get-username-by-xsoar-user':
        return_results(mapper.get_splunk_user_by_xsoar_command(args))
    else:
        raise NotImplementedError(f'Command not implemented: {command}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
