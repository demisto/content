import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import time
import json
import urllib3
import traceback
from datetime import datetime
from typing import Any, Dict, Tuple, List, Union

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
SEVERITY_MAPPINGS = {
    'informational': IncidentSeverity.LOW,
    'moderate': IncidentSeverity.MEDIUM,
    'high': IncidentSeverity.CRITICAL
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, *args, project_id: str = None, **kwargs):
        """
        Client subclass to handle API calls to the ASI API

        :param project_id: the project_id to scope the API calls to
        """
        super().__init__(*args, **kwargs)
        self.project_id = project_id

    def get_project_issues(self, snapshot: str) -> Dict:
        """
        Gets all the issues triggered for a particular snapshot

        :param snapshot: date string formatted in DATE_FORMAT
        :return: Dict with a data key that is an array of issues
        """
        return self._http_request(
            method='GET',
            url_suffix=f'/rules/{self.project_id}/{snapshot}/issues'
        )

    def get_recent_issues(self, last_run: Union[str, int]) -> Dict:
        """
        Lookup the added issues after a certain date

        :param last_run: can be a timestamp or a snapshot in DATE_FORMAT
        :return: Dict with a data key that is an array of diffs between snapshots
        """
        return self._http_request(
            method='GET',
            url_suffix=f'/rules/history/{self.project_id}/activity?rule_action=added&start={last_run}'
        )


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests that the client can authenticate and pulls issues correctly

    :param client: Client
    :return: 'ok' if everything works otherwise raise an Exception
    """
    try:
        client.get_project_issues('recent')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def _fetch_project_incidents(client: Client) -> List[Dict]:
    """
    Fetches the most recent set of issues for a project to initialize incidents

    :param client: Client
    :return: list of incidents
    """
    issues_resp = client.get_project_issues(
        snapshot='recent'
    )

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    recent_snapshot = issues_resp.get('meta', {}).get('snapshot')
    incident_created_time = 0 if not recent_snapshot else datetime.strptime(recent_snapshot, DATE_FORMAT).timestamp()
    incident_created_time_ms = incident_created_time * 1000

    for issue in issues_resp.get('data', []):
        incident_name = issue['name']

        incident = {
            'name': incident_name,
            'details': issue['description'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(issue),
            'severity': SEVERITY_MAPPINGS[issue['classification']]
        }

        incidents.append(incident)

    return incidents


def _fetch_recent_incidents(client: Client, start_timestamp: int) -> List[Dict]:
    """
    Fetch recent incidents after a certain timestamp

    :param client: Client
    :param start_timestamp: the timestamp to find new issues afterwards (usually the last_fetch)
    :return: list of incidents
    """
    issues_resp = client.get_recent_issues(
        last_run=start_timestamp
    )

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    for diff in issues_resp.get('data', []):
        diff_snapshot = diff.get('snapshot')
        incident_created_time = 0 if not diff_snapshot else datetime.strptime(diff_snapshot, DATE_FORMAT).timestamp()
        incident_created_time_ms = incident_created_time * 1000
        for issue in diff.get('added_rules', []):
            # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
            if start_timestamp:
                if incident_created_time <= start_timestamp:
                    continue

            incident_name = issue['name']
            incident = {
                'name': incident_name,
                'details': issue['description'],
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(issue),
                'severity': SEVERITY_MAPPINGS[issue['classification']]
            }

            incidents.append(incident)

    return incidents


def fetch_incidents(client: Client, last_run: Dict[str, int]) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function retrieves new alerts every interval (default is 24 hours).

    :param client: Client
    :param last_run: dict with one key (last_fetch) that was when the integration last pulled incidents
    :return: the new last_run and a list of incidents
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)

    if not last_fetch:
        incidents = _fetch_project_incidents(client)
    else:
        incidents = _fetch_recent_incidents(client, last_fetch)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': int(time.time())}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    api_key = demisto.params().get('apikey')
    project_id = demisto.params().get('project_id')

    # get the service API url
    base_url = 'https://api.securitytrails.com/v1/asi'
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'APIKEY': api_key
        }
        client = Client(
            base_url=base_url,
            project_id=project_id,
            verify=True,
            headers=headers)

        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'asi-project-issues-fetch':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run={'last_fetch': int(demisto.args().get('issues_start', 0))}
            )
            demisto.incidents(incidents)
        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun()
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
