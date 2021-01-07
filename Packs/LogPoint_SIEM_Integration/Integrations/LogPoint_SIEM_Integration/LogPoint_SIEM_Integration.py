
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import dateparser
import json
import traceback
import requests
from datetime import timedelta, datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


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
        except Exception:
            raise DemistoException("Fetch limit does not seem to be valid integer. Suggested: 50 or less, max: 200")
        if max_fetch > 200:
            raise DemistoException("Fetch limit should not be greater than 200.")
    ts_from = ts_to = round(datetime.timestamp(datetime.utcnow()))
    result = client.get_incidents(ts_from, ts_to)
    if not result.get('success'):
        raise DemistoException(result['message'])
    return "ok"


def get_incidents_command(client, args):
    ts_from = args.get('ts_from')
    ts_to = args.get('ts_to')
    result = client.get_incidents(ts_from, ts_to)
    if not result.get('success'):
        raise DemistoException(result['message'])
    incidents = result.get('incidents', [])
    table_header = []
    if incidents and len(incidents) > 0:
        table_header = list(incidents[0].keys())
    markdown_name = 'Incidents'
    if len(incidents) > 50:
        incidents = incidents[:50]
        last_detection_ts = incidents[-1].get('detection_timestamp')
        markdown_name = f"Displaying first 50 incidents. \
        \n Only first 50 incidents are displayed. Detection time of the 50th incident is: {last_detection_ts}\
        \n Please narrow down your ts_from and ts_to filter to get all the required incidents"
    markdown = tableToMarkdown(markdown_name, incidents, headers=table_header)
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
        raise DemistoException(result['message'])
    incident_data = result.get('rows', [])
    table_header = []
    if incident_data and len(incident_data) > 0:
        table_header = list(incident_data[0].keys())
    markdown = tableToMarkdown('Incident Data', incident_data, headers=table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.data',
        outputs_key_field='',
        outputs=incident_data
    )


def get_incident_states_command(client, args):
    ts_from = args.get('ts_from')
    ts_to = args.get('ts_to')
    result = client.get_incident_states(ts_from, ts_to)
    if not result.get('success'):
        raise DemistoException(result['message'])
    incident_states = result.get('states', [])
    table_header = []
    if incident_states and len(incident_states) > 0:
        table_header = list(incident_states[0].keys())
    markdown_name = 'Incident States'
    if len(incident_states) > 50:
        incident_states = incident_states[:50]
        markdown_name = "Displaying first 50 Incident States\
            \nOnly first 50 incident states are displayed.\
            \nPlease narrow down your ts_from and ts_to filter to get all the required data."
    markdown = tableToMarkdown(markdown_name, incident_states, headers=table_header)
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
        raise DemistoException(result['message'])
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
        raise DemistoException(result['message'])
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
        raise DemistoException(result['message'])
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
        raise DemistoException(result['message'])
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
        raise DemistoException(result['message'])
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
        raise DemistoException(result['message'])
    users = result.get('users')
    table_header = []
    if users and len(users) > 0:
        table_header = list(users[0].keys())
    markdown = tableToMarkdown('Incident Users', users, headers=table_header)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='LogPoint.Incidents.users',
        outputs_key_field='id',
        outputs=users
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
        raise DemistoException(result['message'])
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
        raise DemistoException(f"First fetch input '{first_fetch_param}' is invalid. Valid format eg.:1 day")
    first_fetch = first_fetch_dt.timestamp()
    max_fetch = params.get('max_fetch')
    max_fetch = int(params.get('max_fetch')) if (max_fetch and max_fetch.isdigit()) else 50
    max_fetch = max(min(200, max_fetch), 1)
    headers = {
        'Content-Type': 'application/json'
    }
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            username=username,
            apikey=apikey)
        args = demisto.args()
        if demisto.command() == 'test-module':
            return_results(test_module(client, params.get('max_fetch')))
        elif demisto.command() == 'lp-get-incidents':
            return_results(get_incidents_command(client, args))
        elif demisto.command() == 'lp-get-incident-data':
            return_results(get_incident_data_command(client, args))
        elif demisto.command() == 'lp-get-incident-states':
            return_results(get_incident_states_command(client, args))
        elif demisto.command() == 'lp-add-incident-comment':
            return_results(add_incident_comment_command(client, args))
        elif demisto.command() == 'lp-assign-incidents':
            return_results(assign_incidents_command(client, args))
        elif demisto.command() == 'lp-resolve-incidents':
            return_results(resolve_incidents_command(client, args))
        elif demisto.command() == 'lp-close-incidents':
            return_results(close_incidents_command(client, args))
        elif demisto.command() == 'lp-reopen-incidents':
            return_results(reopen_incidents_command(client, args))
        elif demisto.command() == 'lp-get-users':
            return_results(get_users_command(client))
        elif demisto.command() == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client, first_fetch, max_fetch))
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(err)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
