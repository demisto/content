import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' IMPORTS '''

import json
import traceback
from datetime import datetime, timedelta

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, verify, proxy, headers, username, apikey):
        self.username = username
        self.apikey = apikey
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def get_incidents(self, ts_from=None, ts_to=None):
        """
        :param ts_from: From Timestamp
        :param ts_to:To Timestamp
        :return: dict containing response from API call
        """
        if not ts_to:
            ts_to = datetime.timestamp(datetime.utcnow())
        if not ts_from:
            ts_from = datetime.timestamp(datetime.utcnow() - timedelta(days=1))
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "ts_from": round(float(ts_from)),
                "ts_to": round(float(ts_to))
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='GET',
            url_suffix='/incidents',
            data=data
        )

    def get_incident_data(self, obj_id, incident_id, date):
        """
        :param obj_id: incident obj id
        :param incident_id: incident_id
        :param date: detection_timestamp
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "incident_obj_id": obj_id,
                "incident_id": incident_id,
                "date": float(date)
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='GET',
            url_suffix='/get_data_from_incident',
            data=data
        )

    def get_incident_states(self, ts_from=None, ts_to=None):
        """
        :param ts_from: From Timestamp
        :param ts_to: To Timestamp
        :return: dict containing response from API call
        """
        if not ts_to:
            ts_to = datetime.timestamp(datetime.utcnow())
        if not ts_from:
            ts_from = datetime.timestamp(datetime.utcnow() - timedelta(days=1))
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "ts_from": round(float(ts_from)),
                "ts_to": round(float(ts_to))
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='GET',
            url_suffix='/incident_states',
            data=data
        )

    def add_incident_comment(self, incident_obj_id, comment):
        """
        :param incident_obj_id: incident obj id
        :param comment: Comments to be added
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "version": "0.1",
                "states": [
                    {
                        "_id": incident_obj_id,
                        "comments": [comment]
                    }
                ]
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='POST',
            url_suffix='/add_incident_comment',
            data=data
        )

    def assign_incidents(self, incident_obj_ids, new_assignee):
        """
        :param incident_obj_ids: incident obj ids in the list format
        :param new_assignee: id of the user
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "version": "0.1",
                "incident_ids": incident_obj_ids,
                "new_assignee": new_assignee
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='POST',
            url_suffix='/assign_incident',
            data=data
        )

    def resolve_incidents(self, incident_obj_ids):
        """
        :param incident_obj_ids: incident obj ids in the list format
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "version": "0.1",
                "incident_ids": incident_obj_ids
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='POST',
            url_suffix='/resolve_incident',
            data=data
        )

    def close_incidents(self, incident_obj_ids):
        """
        :param incident_obj_ids: incident ids in list format
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "version": "0.1",
                "incident_ids": incident_obj_ids
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='POST',
            url_suffix='/close_incident',
            data=data
        )

    def reopen_incidents(self, incident_obj_ids):
        """
        :param incident_obj_ids: incident obj ids in list format
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": {
                "version": "0.1",
                "incident_ids": incident_obj_ids
            }
        }
        data = json.dumps(data)
        return self._http_request(
            method='POST',
            url_suffix='/reopen_incident',
            data=data
        )

    def get_users(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey
        }
        data = json.dumps(data)
        return self._http_request(
            method='GET',
            url_suffix='/get_users',
            data=data
        )

    def get_users_preference(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "type": "user_preference"
        }
        return self._http_request(
            method='POST',
            url_suffix='/getalloweddata',
            data=data
        )

    def get_logpoints(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "type": "loginspects"
        }
        return self._http_request(
            method='POST',
            url_suffix='/getalloweddata',
            data=data
        )

    def get_repos(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "type": "logpoint_repos"
        }
        return self._http_request(
            method='POST',
            url_suffix='/getalloweddata',
            data=data
        )

    def get_devices(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "type": "devices"
        }
        return self._http_request(
            method='POST',
            url_suffix='/getalloweddata',
            data=data
        )

    def get_livesearches(self):
        """
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "type": "livesearches"
        }
        return self._http_request(
            method='POST',
            url_suffix='/getalloweddata',
            data=data
        )

    def get_search_id(self, query, time_range, limit=100, repos=[], timeout=60):
        """
        :param query: LogPoint search query

        :param time_range: Time range: Eg. Last 5 minutes, Last 1 day etc.

        :param limit: Number of search results to fetch

        :param repos: LogPoint repos from where logs should be fetched

        :param timeout: LogPoint search timeout

        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": json.dumps({
                "query": query,
                "time_range": time_range,
                "limit": limit,
                "repos": repos,
                "timeout": timeout
            })
        }
        return self._http_request(
            method='POST',
            url_suffix='/getsearchlogs',
            data=data
        )

    def get_search_results(self, search_id):
        """
        :param search_id: Search id obtained from get_search_id() method
        :return: dict containing response from API call
        """
        data = {
            "username": self.username,
            "secret_key": self.apikey,
            "requestData": json.dumps({
                "search_id": search_id
            })
        }
        return self._http_request(
            method='POST',
            url_suffix='/getsearchlogs',
            data=data
        )


''' HELPER FUNCTIONS '''


def get_demisto_severity(severity):
    """
    Maps LogPoint risk_level into Demisto Severity
    :param severity: LogPoint risk_level
    :return: Demisto Severity level (0 to 4)
    """
    severity = severity.lower()
    if severity == 'low':
        return 1
    elif severity == 'medium':
        return 2
    elif severity == 'high':
        return 3
    elif severity == 'critical':
        return 4
    return 0


''' COMMAND FUNCTIONS '''


def test_module(client, max_fetch):
    if max_fetch:
        try:
            max_fetch = int(max_fetch)
        except ValueError:
            return "Fetch limit does not seem to be valid integer. Suggested: 50 or less, max: 200"
        if max_fetch > 200:
            return "Fetch limit should not be greater than 200."
    ts_from = ts_to = round(datetime.timestamp(datetime.utcnow()))
    try:
        result = client.get_incidents(ts_from, ts_to)
        if not result.get('success'):
            msg = result.get('message')
            if msg == 'Authentication Failed':
                return "LogPoint authentication failed. Please make sure that the API Key is correct."
            else:
                return msg
    except DemistoException as err:
        if '<requests.exceptions.ConnectionError>' in str(err):
            msg = "Could not connect to the LogPoint server. " \
                  "Verify that the server URL parameter is correct " \
                  "and that you have access to the server from your host."
            return msg
        else:
            raise err
    return "ok"


def get_incidents_command(client, args):
    ts_from = args.get('ts_from')
    ts_to = args.get('ts_to')
    limit = args.get('limit') if args.get('limit') else 50
    if limit:
        try:
            limit = int(limit)
        except ValueError:
            raise DemistoException(f"The provided argument '{limit}' for limit is not a valid integer.")
    result = client.get_incidents(ts_from, ts_to)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    incidents = result.get('incidents', [])
    table_header = []
    display_title = 'Incidents'
    if incidents and len(incidents) > 0:
        table_header = list(incidents[0].keys())
        if not ts_from:
            ts_from = incidents[0].get('detection_timestamp')
    if len(incidents) > limit:
        incidents = incidents[:limit]
        last_detection_ts = incidents[-1].get('detection_timestamp')
        display_title = f"Displaying first {limit} incidents between {ts_from} and {last_detection_ts} timestamps." \
                        f"\nPlease narrow down ts_from and ts_to arguments or increase the limit argument to " \
                        f"get more incidents."
    elif len(incidents) <= limit and len(incidents) != 0:
        if not ts_to:
            ts_to = incidents[-1].get('detection_timestamp')
        display_title = f"Displaying all {len(incidents)} incidents between {ts_from} and {ts_to}"
    markdown = tableToMarkdown(display_title, incidents, headers=table_header,
                               headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents',
        outputs_key_field='id',
        outputs=incidents
    )


def get_incident_data_command(client, args):
    incident_obj_id = args.get('incident_obj_id')
    incident_id = args.get('incident_id')
    date = args.get('date')
    result = client.get_incident_data(incident_obj_id, incident_id, date)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    incident_data = result.get('rows', [])
    table_header = []
    if incident_data and len(incident_data) > 0:
        table_header = list(incident_data[0].keys())
    markdown = tableToMarkdown('Incident Data', incident_data, headers=table_header,
                               headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.data',
        outputs_key_field='',
        outputs=incident_data
    )


def get_incident_states_command(client, args):
    ts_from = args.get('ts_from')
    ts_to = args.get('ts_to')
    limit = args.get('limit') if args.get('limit') else 50
    if limit:
        try:
            limit = int(limit)
        except ValueError:
            raise DemistoException(f"The provided argument '{limit}' for limit is not a valid integer.")
    result = client.get_incident_states(ts_from, ts_to)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    incident_states = result.get('states', [])
    table_header = []
    display_title = 'Incident States'
    if incident_states and len(incident_states) > 0:
        table_header = list(incident_states[0].keys())
    if len(incident_states) > limit:
        incident_states = incident_states[:limit]
        display_title = f"Displaying first {limit} incident states data. " \
                        f"\nPlease narrow down ts_from and ts_to arguments or increase the limit argument to " \
                        f"get more."
    elif len(incident_states) <= limit and len(incident_states) != 0:
        display_title = f"Displaying all {len(incident_states)} incident states data."
    markdown = tableToMarkdown(display_title, incident_states, headers=table_header,
                               headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.states',
        outputs_key_field='id',
        outputs=incident_states
    )


def add_incident_comment_command(client, args):
    incident_obj_id = args.get('incident_obj_id')
    comment = args.get('comment')
    result = client.add_incident_comment(incident_obj_id, comment)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    msg = result.get('message', 'Comment added!')
    markdown = "### " + msg
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.comment',
        outputs_key_field='',
        outputs=msg
    )
    return results


def assign_incidents_command(client, args):
    incident_obj_ids = argToList(args.get('incident_obj_ids'))
    new_assignee = args.get('new_assignee')
    result = client.assign_incidents(incident_obj_ids, new_assignee)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    msg = result.get('message')
    markdown = "### " + msg
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.assign',
        outputs_key_field='',
        outputs=msg
    )
    return results


def resolve_incidents_command(client, args):
    incident_obj_ids = argToList(args.get('incident_obj_ids'))
    result = client.resolve_incidents(incident_obj_ids)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    msg = result.get('message')
    markdown = "### " + msg
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.resolve',
        outputs_key_field='',
        outputs=msg
    )


def close_incidents_command(client, args):
    incident_obj_ids = argToList(args.get('incident_obj_ids'))
    result = client.close_incidents(incident_obj_ids)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    msg = result.get('message')
    markdown = "### " + msg
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.close',
        outputs_key_field='',
        outputs=msg
    )


def reopen_incidents_command(client, args):
    incident_obj_ids = argToList(args.get('incident_obj_ids'))
    result = client.reopen_incidents(incident_obj_ids)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    msg = result.get('message')
    markdown = "### " + msg
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.reopen',
        outputs_key_field='',
        outputs=msg
    )


def get_users_command(client):
    result = client.get_users()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    users = result.get('users')
    if users and len(users) > 0:
        table_header = list(users[0].keys())
        markdown = tableToMarkdown('Incident Users', users, headers=table_header,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'No users record found.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.users',
        outputs_key_field='id',
        outputs=users
    )


def get_users_preference_command(client):
    result = client.get_users_preference()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    del result['success']
    if not result or len(result) == 0:
        markdown = 'No users preference found.'
    else:
        table_header = list(result.keys())
        display_title = "User's Preference"
        markdown = tableToMarkdown(display_title, result, headers=table_header,
                                   headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.User.Preference',
        outputs=result
    )


def get_logpoints_command(client):
    result = client.get_logpoints()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    allowed_loginspects = result.get('allowed_loginspects')
    if allowed_loginspects and len(allowed_loginspects) > 0:
        table_header = list(allowed_loginspects[0].keys())
        display_title = "LogPoints"
        markdown = tableToMarkdown(display_title, allowed_loginspects, headers=table_header,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'No LogPoints found.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.LogPoints',
        outputs_key_field='ip',
        outputs=allowed_loginspects
    )


def get_repos_command(client):
    result = client.get_repos()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    allowed_repos = result.get('allowed_repos')
    if allowed_repos and len(allowed_repos) > 0:
        table_header = list(allowed_repos[0].keys())
        display_title = "LogPoint Repos"
        markdown = tableToMarkdown(display_title, allowed_repos, headers=table_header,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'No repos found.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Repos',
        outputs_key_field='repo',
        outputs=allowed_repos
    )


def get_devices_command(client):
    result = client.get_devices()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    display_title = "Devices"
    allowed_devices = result.get('allowed_devices')
    if allowed_devices and len(allowed_devices) > 0:
        device_list = []
        for device in allowed_devices:
            for key, value in device.items():
                device_list.append({
                    'name': value,
                    'address': key,
                })
        table_header = ['name', 'address']
        markdown = tableToMarkdown(display_title, device_list, headers=table_header,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'Devices not found.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Devices',
        outputs=device_list
    )


def get_livesearches_command(client):
    result = client.get_livesearches()
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    livesearches = result.get('livesearches')
    if livesearches and len(livesearches) > 0:
        display_title = "Live Searches"
        markdown = tableToMarkdown(display_title, livesearches, headers=None,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'No Live Searches data found.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.LiveSearches',
        outputs=livesearches
    )


def get_searchid_command(client, args):
    query = args.get('query')
    time_range = args.get('time_range', 'Last 5 minutes')
    limit = args.get('limit', '100')
    repos = argToList(args.get('repos'))
    timeout = args.get('timeout', '60')
    if limit:
        try:
            limit = int(limit)
        except ValueError:
            raise DemistoException(f"The provided argument '{limit}' for limit is not a valid integer.")
    result = client.get_search_id(query, time_range, limit, repos, timeout)
    if not result.get('success'):
        raise DemistoException(result.get('message'))
    search_id = result.get('search_id')
    if search_id:
        del result['success']
        if result.get('searchId'):
            del result['searchId']
        headers = result.keys()
        display_title = f"Search Id: {search_id}"
        markdown = tableToMarkdown(display_title, result, headers=headers,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'Could not get Search Id.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.search_id',
        outputs=search_id
    )


def search_logs_command(client, args):
    search_id = args.get('search_id')
    rows = []
    while True:
        search_result = client.get_search_results(search_id)
        if not search_result.get('success'):
            raise DemistoException(search_result.get('message'))
        rows += search_result.get('rows', [])
        if search_result.get('final'):
            break
    if rows and len(rows) > 0:
        display_title = f"Found {len(rows)} logs"
        markdown = tableToMarkdown(display_title, rows, headers=None,
                                   headerTransform=string_to_table_header)
    else:
        markdown = 'No results found for the given search parameters.'
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.SearchLogs',
        outputs=rows
    )


def fetch_incidents(client, first_fetch, max_fetch):
    """
    This function retrieves new incidents every interval (default is 1 minute).
    """
    now = datetime.timestamp(datetime.utcnow())
    last_run_object = demisto.getLastRun()
    last_run = last_run_object.get('time', None) if last_run_object else None
    if not last_run:
        if first_fetch:
            last_run = float(first_fetch)
        else:
            last_run = datetime.timestamp(datetime.utcnow() - timedelta(days=1))
    result = client.get_incidents(last_run, now)
    if not result.get('success'):
        raise DemistoException(f"ERROR: {result.get('message')}; last_run: {last_run}; now: {now}")
    lp_incidents = result.get('incidents')
    incidents = []
    if len(lp_incidents) > max_fetch:
        next_fetch_time = lp_incidents[max_fetch]['detection_timestamp']
        lp_incidents = lp_incidents[:max_fetch]
    else:
        next_fetch_time = now
    demisto.info(f"Executing LogPoint fetch_incidents between {last_run} and {next_fetch_time} Timestamp.")
    for inc in lp_incidents:
        detection_ts = inc['detection_timestamp']
        dt = datetime.utcfromtimestamp(detection_ts)
        occurred = dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        incidents.append({
            'name': inc.get('name', 'LogPoint - No name'),
            'occurred': occurred,
            'severity': get_demisto_severity(inc.get('risk_level')),
            'rawJSON': json.dumps(inc)
        })
    demisto.setLastRun({'time': next_fetch_time})
    return incidents


''' MAIN FUNCTION '''


def main():
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    handle_proxy()
    params = demisto.params()
    username = params.get('username')
    apikey = params.get('apikey')
    base_url = params.get('url').rstrip('/')
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)
    first_fetch_param = params.get('first_fetch') if params.get('first_fetch') else '1 day'
    first_fetch_dt = dateparser.parse(first_fetch_param, settings={'TIMEZONE': 'UTC'})
    if first_fetch_param and not first_fetch_dt:
        return_error(f"First fetch input '{first_fetch_param}' is invalid. Valid format eg.:1 day")
    assert first_fetch_dt is not None
    first_fetch = first_fetch_dt.timestamp()
    max_fetch = params.get('max_fetch')
    max_fetch = int(params.get('max_fetch')) if (max_fetch and max_fetch.isdigit()) else 50
    max_fetch = max(min(200, max_fetch), 1)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    incident_commands = [
        'test-module',
        'lp-get-incidents',
        'lp-get-incident-data',
        'lp-get-incident-states',
        'lp-add-incident-comment',
        'lp-assign-incidents',
        'lp-resolve-incidents',
        'lp-close-incidents',
        'lp-reopen-incidents',
        'lp-get-users',
        'fetch-incidents'
    ]
    if command in incident_commands:
        headers = {
            'Content-Type': 'application/json'
        }
    else:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            username=username,
            apikey=apikey)
        args = demisto.args()
        if command == 'test-module':
            return_results(test_module(client, params.get('max_fetch')))
        elif command == 'lp-get-incidents':
            return_results(get_incidents_command(client, args))
        elif command == 'lp-get-incident-data':
            return_results(get_incident_data_command(client, args))
        elif command == 'lp-get-incident-states':
            return_results(get_incident_states_command(client, args))
        elif command == 'lp-add-incident-comment':
            return_results(add_incident_comment_command(client, args))
        elif command == 'lp-assign-incidents':
            return_results(assign_incidents_command(client, args))
        elif command == 'lp-resolve-incidents':
            return_results(resolve_incidents_command(client, args))
        elif command == 'lp-close-incidents':
            return_results(close_incidents_command(client, args))
        elif command == 'lp-reopen-incidents':
            return_results(reopen_incidents_command(client, args))
        elif command == 'lp-get-users':
            return_results(get_users_command(client))
        elif command == 'lp-get-users-preference':
            return_results(get_users_preference_command(client))
        elif command == 'lp-get-logpoints':
            return_results(get_logpoints_command(client))
        elif command == 'lp-get-repos':
            return_results(get_repos_command(client))
        elif command == 'lp-get-devices':
            return_results(get_devices_command(client))
        elif command == 'lp-get-livesearches':
            return_results(get_livesearches_command(client))
        elif command == 'lp-get-searchid':
            return_results(get_searchid_command(client, args))
        elif command == 'lp-search-logs':
            return_results(search_logs_command(client, args))
        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client, first_fetch, max_fetch))
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command. Error: {str(err)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
