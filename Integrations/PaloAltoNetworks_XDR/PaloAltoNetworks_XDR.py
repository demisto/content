import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from datetime import datetime, timezone
import secrets
import string
import hashlib

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']

USE_SSL = not demisto.params().get('insecure', False)
API_KEY = demisto.params().get('apikey')
API_KEY_ID = demisto.params().get('apikey_id')
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
BASE_URL = SERVER + '/public_api/v1'

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

NONCE_LENGTH = 64
API_KEY_LENGTH = 128


def convert_epoch_to_milli(ts):
    if ts is None:
        return None
    if 9 < len(str(ts)) < 13:
        ts = int(ts) * 1000
    return int(ts)


def convert_datetime_to_epoch(the_time=0):
    if the_time is None:
        return None
    else:
        try:
            if isinstance(the_time, datetime):
                return int(the_time.strftime('%s'))
        except Exception as e:
            print(e)
            return 0


def convert_datetime_to_epoch_millis(the_time=0):
    return convert_epoch_to_milli(convert_datetime_to_epoch(the_time=the_time))


def generate_current_epoch_utc():
    return convert_datetime_to_epoch_millis(datetime.now(timezone.utc))


def generate_key():
    return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(API_KEY_LENGTH)])


def create_auth(api_key):
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(NONCE_LENGTH)])
    timestamp = str(generate_current_epoch_utc())  # Get epoch time utc millis
    m = hashlib.sha256()
    m.update((api_key + nonce + timestamp).encode("utf-8"))
    return nonce, timestamp, m.hexdigest()


# nonce, timestamp, auth = create_auth(API_KEY)
nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
auth_key = "%s%s%s" % (API_KEY, nonce, timestamp)
auth_key = auth_key.encode("utf-8")
api_key_hash = hashlib.sha256(auth_key).hexdigest()

HEADERS = {
    "x-xdr-timestamp": timestamp,
    "x-xdr-nonce": nonce,
    "x-xdr-auth-id": str(API_KEY_ID),
    "Authorization": api_key_hash
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    demisto.debug(json.dumps(data, indent=4))

    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        json=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in [200]:
        if 'err_code' in res.text:
            error = res.json().get('reply')
            raise ValueError('Error occurred while doing HTTP request.\nURL: {}\nstatus_code: {}\nerr_code: {}'
                             '\nerr_message: {}\n{}'
                             .format(BASE_URL + url_suffix, res.status_code, error.get('err_code'),
                                     error.get('err_msg'), error.get('err_extra')))

        raise ValueError('Error in API call to Palo Alto Networks XDR [%d] - %s' % (res.status_code, res.reason))

    try:
        return res.json()
    except Exception:
        raise ValueError("Failed to parse HTTP response to JSON. Original response: \n\n{}".format(res.text))


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    last_one_day, _ = parse_date_range(FETCH_TIME, TIME_FORMAT)
    get_incidents(lte_creation_time=last_one_day, limit=1)


def get_incidents_command():
    """
    Gets details about a items using IDs or some other filters
    """
    incident_id_list = argToList(demisto.args().get('incident_id_list'))

    lte_modification_time = demisto.args().get('lte_modification_time')
    gte_modification_time = demisto.args().get('gte_modification_time')
    since_modification_time = demisto.args().get('since_modification_time')

    if since_modification_time and gte_modification_time:
        raise ValueError('Can\'t set both since_modification_time and lte_modification_time')
    elif since_modification_time:
        gte_modification_time, _ = parse_date_range(since_modification_time, TIME_FORMAT)

    lte_creation_time = demisto.args().get('lte_creation_time')
    gte_creation_time = demisto.args().get('gte_creation_time')
    since_creation_time = demisto.args().get('since_creation_time')

    if since_creation_time and gte_creation_time:
        raise ValueError('Can\'t set both since_creation_time and lte_creation_time')
    elif since_creation_time:
        gte_creation_time, _ = parse_date_range(since_creation_time, TIME_FORMAT)

    sort_by_modification_time = demisto.args().get('sort_by_modification_time')
    sort_by_creation_time = demisto.args().get('sort_by_creation_time')

    page = int(demisto.args().get('page', 0))
    limit = int(demisto.args().get('limit', 100))

    # If no filters were given, return a meaningful error message
    if (not lte_modification_time and not gte_modification_time and not since_modification_time
            and not lte_creation_time and not gte_creation_time and not since_creation_time):
        return_error("Specify a query for the incidents.\nFor example:"
                     " !xdr-get-incidents since_creation_time=\"1 year\" sort_by_creation_time=\"desc\" limit=10")

    raw_incidents = get_incidents(
        incident_id_list=incident_id_list,
        lte_modification_time=lte_modification_time,
        gte_modification_time=gte_modification_time,
        lte_creation_time=lte_creation_time,
        gte_creation_time=gte_creation_time,
        sort_by_creation_time=sort_by_creation_time,
        sort_by_modification_time=sort_by_modification_time,
        page_number=page,
        limit=limit
    )

    return_outputs(
        readable_output=tableToMarkdown('Incidents', raw_incidents),
        outputs={
            'PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)': raw_incidents
        },
        raw_response=raw_incidents
    )


def get_incidents(incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                  lte_creation_time=None, gte_creation_time=None, sort_by_modification_time=None,
                  sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
    """
    Filters and returns incidents

    :param incident_id_list: List of incident ids - must be list
    :param lte_modification_time: string of time format "2019-12-31T23:59:00"
    :param gte_modification_time: string of time format "2019-12-31T23:59:00"
    :param lte_creation_time: string of time format "2019-12-31T23:59:00"
    :param gte_creation_time: string of time format "2019-12-31T23:59:00"
    :param sort_by_modification_time: optional - enum (asc,desc)
    :param sort_by_creation_time: optional - enum (asc,desc)
    :param page_number: page number
    :param limit: maximum number of incidents to return per page
    :param gte_creation_time_milliseconds: greater than time in milliseconds
    :return:
    """
    search_from = page_number * limit
    search_to = search_from + limit

    request_data = {
        'search_from': search_from,
        'search_to': search_to
    }

    if sort_by_creation_time and sort_by_modification_time:
        raise ValueError('Should be provide either sort_by_creation_time or '
                         'sort_by_modification_time. Can\'t provide both')
    elif sort_by_creation_time:
        request_data['sort'] = {
            'field': 'creation_time',
            'keyword': sort_by_creation_time
        }
    elif sort_by_modification_time:
        request_data['sort'] = {
            'field': 'modification_time',
            'keyword': sort_by_modification_time
        }

    filters = []
    if incident_id_list is not None and len(incident_id_list) > 0:
        filters.append({
            'field': 'incident_id_list',
            'operator': 'in',
            'value': incident_id_list
        })

    if lte_creation_time:
        filters.append({
            'field': 'creation_time',
            'operator': 'lte',
            'value': date_to_timestamp(lte_creation_time, TIME_FORMAT)
        })

    if gte_creation_time:
        filters.append({
            'field': 'creation_time',
            'operator': 'gte',
            'value': date_to_timestamp(gte_creation_time, TIME_FORMAT)
        })

    if lte_modification_time:
        filters.append({
            'field': 'modification_time',
            'operator': 'lte',
            'value': date_to_timestamp(lte_modification_time, TIME_FORMAT)
        })

    if gte_modification_time:
        filters.append({
            'field': 'modification_time',
            'operator': 'gte',
            'value': date_to_timestamp(gte_modification_time, TIME_FORMAT)
        })

    if gte_creation_time_milliseconds > 0:
        filters.append({
            'field': 'creation_time',
            'operator': 'gte',
            'value': gte_creation_time_milliseconds
        })

    if len(filters) > 0:
        request_data['filters'] = filters

    res = http_request('POST', '/incidents/get_incidents/', data={'request_data': request_data})
    incidents = res.get('reply').get('incidents', [])

    return incidents


def get_incident_extra_data_command():
    incident_id = demisto.args().get('incident_id')
    alerts_limit = int(demisto.args().get('alerts_limit', 1000))

    raw_incident = get_incident_extra_data(incident_id, alerts_limit)

    incident = raw_incident.get('incident')
    incident_id = incident.get('incident_id')
    alerts = raw_incident.get('alerts').get('data')
    file_artifacts = raw_incident.get('file_artifacts').get('data')
    network_artifacts = raw_incident.get('network_artifacts').get('data')

    readable_output = [tableToMarkdown('Incident {}'.format(incident_id), incident)]

    if len(alerts) > 0:
        readable_output.append(tableToMarkdown('Alerts', alerts))
    else:
        readable_output.append(tableToMarkdown('Alerts', []))

    if len(network_artifacts) > 0:
        readable_output.append(tableToMarkdown('Network Artifacts', network_artifacts))
    else:
        readable_output.append(tableToMarkdown('Network Artifacts', []))

    if len(file_artifacts) > 0:
        readable_output.append(tableToMarkdown('File Artifacts', file_artifacts))
    else:
        readable_output.append(tableToMarkdown('File Artifacts', []))

    incident.update({
        'alerts': alerts,
        'file_artifacts': file_artifacts,
        'network_artifacts': network_artifacts
    })
    return_outputs(
        readable_output='\n'.join(readable_output),
        outputs={
            'PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)': incident
        },
        raw_response=raw_incident
    )


def get_incident_extra_data(incident_id, alerts_limit=1000):
    """
    Returns incident by id

    :param incident_id: The id of incident
    :param alerts_limit: Maximum number alerts to get
    :return:
    """
    request_data = {
        'incident_id': incident_id,
        'alerts_limit': alerts_limit
    }

    reply = http_request('POST', '/incidents/get_incident_extra_data/', data={'request_data': request_data})
    incident = reply.get('reply')

    return incident


def update_incident_command():
    incident_id = demisto.args().get('incident_id')
    assigned_user_mail = demisto.args().get('assigned_user_mail')
    assigned_user_pretty_name = demisto.args().get('assigned_user_pretty_name')
    status = demisto.args().get('status')
    severity = demisto.args().get('manual_severity')
    unassign_user = demisto.args().get('unassign_user') == 'true'
    resolve_comment = demisto.args().get('resolve_comment')

    update_incident(
        incident_id=incident_id,
        assigned_user_mail=assigned_user_mail,
        assigned_user_pretty_name=assigned_user_pretty_name,
        unassign_user=unassign_user,
        status=status,
        severity=severity,
        resolve_comment=resolve_comment
    )

    return_outputs('Incident {} has been updated'.format(incident_id), outputs=None)


def update_incident(incident_id, assigned_user_mail, assigned_user_pretty_name, status, severity, resolve_comment,
                    unassign_user):
    update_data = {}

    if unassign_user and (assigned_user_mail or assigned_user_pretty_name):
        raise ValueError("Can't provide both assignee_email/assignee_name and unassign_user")
    elif unassign_user:
        update_data['assigned_user_mail'] = 'none'

    if assigned_user_mail:
        update_data['assigned_user_mail'] = assigned_user_mail

    if assigned_user_pretty_name:
        update_data['assigned_user_pretty_name'] = assigned_user_pretty_name

    if status:
        update_data['status'] = status

    if severity:
        update_data['manual_severity'] = severity

    if resolve_comment:
        update_data['resolve_comment'] = resolve_comment

    request_data = {
        'incident_id': incident_id,
        'update_data': update_data
    }
    demisto.info(json.dumps(request_data, indent=4))
    http_request('POST', '/incidents/update_incident/', data={'request_data': request_data})


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    raw_incidents = get_incidents(gte_creation_time_milliseconds=last_fetch,
                                  limit=50, sort_by_creation_time='asc')

    for raw_incident in raw_incidents:
        incident_id = raw_incident.get('incident_id')
        description = raw_incident.get('description')
        occurred = timestamp_to_datestring(raw_incident['creation_time'], TIME_FORMAT + 'Z')
        incident = {
            'name': '#{} - {}'.format(incident_id, description),
            'occurred': occurred,
            'rawJSON': json.dumps(raw_incident)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if raw_incident['creation_time'] > last_fetch:
            last_fetch = raw_incident['creation_time']

        incidents.append(incident)

    demisto.setLastRun({'time': last_fetch + 1})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    try:
        if demisto.command() == 'test-module':
            test_module()
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()

        elif demisto.command() == 'xdr-get-incidents':
            get_incidents_command()

        elif demisto.command() == 'xdr-get-incident-extra-data':
            get_incident_extra_data_command()

        elif demisto.command() == 'xdr-update-incident':
            update_incident_command()

    # Log exceptions
    except Exception as e:
        if demisto.command() == 'fetch-incidents':
            LOG(str(e))
            raise
        else:
            return_error(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
