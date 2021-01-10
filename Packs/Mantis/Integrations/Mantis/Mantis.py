import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json

import dateparser
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TABLE_HEADERS = ['id', 'reporter', 'project', 'category', 'status', 'summary', 'description', 'created_at']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify=True, proxy=False, headers=None):
        super().__init__(base_url, verify=True, proxy=False, headers=headers)

    def get_issue(self, _id: str):
        issue = self._http_request(
            method='GET',
            url_suffix='/issues/' + _id
        )
        return issue

    def get_issues(self, params: dict):
        issues = self._http_request(
            method='GET',
            url_suffix='/issues/',
            params=params

        )
        return issues

    def create_issue(self, args):
        body = args
        resp = self._http_request(
            method='POST',
            url_suffix='/issues/',
            json_data=body
        )
        return resp

    def create_note(self, _id, args):
        body = args
        resp = self._http_request(
            method='POST',
            url_suffix=f'/issues/{_id}/notes',
            json_data=body
        )
        return resp

    def close_issue(self, _id):
        body = {
            "status": {
                "name": "closed"
            }
        }
        resp = self._http_request(
            method='PATCH',
            url_suffix=f'/issues/{_id}',
            json_data=body
        )
        return resp


def test_module(client):
    params = {
        "page_size": 1,
        "page": 1
    }
    result = client.get_issues(params)
    if "issues" in result:
        demisto.results('ok')
    else:
        return_error(result)


def create_output_result(resp):
    output = {}
    if isinstance(resp, dict):
        for key, value in resp.items():
            if isinstance(value, dict) and 'name' in value:
                output[key] = value['name']
            else:
                output[key] = value
    return output


def mantis_get_all_issues_command(client, args):
    """
        Returns list of all  issues for given  args

        Args:
            client (Client): Mantis client.
            args (dict): page filters.

        Returns:
            list of Mantis issues
        """
    if args is not None:
        params = args
        resp = client.get_issues(params=params).get('issues')
        issues = [create_output_result(issue) for issue in resp]
        readable_output = tableToMarkdown("Mantis Issue Details", issues, headers=TABLE_HEADERS)
        results = CommandResults(
            readable_output=readable_output,
            outputs_prefix="Mantis.issue",
            outputs_key_field=TABLE_HEADERS,
            outputs=issues
        )
        return results


def mantis_close_issue_command(client, args):
    _id = args.get("id")
    resp = client.close_issue(_id)
    if 'issues' in resp:
        return f"Issue {_id} has been closed"
    else:
        return_error(resp)


def mantis_get_issue_by_id_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): Mantis client.
        args (dict): all command arguments.

    Returns:
        Mantis
    """
    _id = args.get('id')
    resp = client.get_issue(_id).get('issues')[0]
    issues = create_output_result(resp)
    readable_output = tableToMarkdown("Mantis Issue Details", issues, headers=TABLE_HEADERS)

    results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Mantis.issue",
        outputs_key_field=TABLE_HEADERS,
        outputs=issues
    )
    return_results(results)


def mantis_create_issue_command(client, args):
    """
        Args:
            body with project details

        Returns:
            Mantis  ticket details
        """
    body = {
        "summary": args.get("summary"),
        "description": args.get("description"),
        "category": {
            "name": args.get("category")
        },
        "project": {
            "name": args.get("project")
        }
    }
    resp = client.create_issue(body).get('issue')
    issues = create_output_result(resp)
    readable_output = tableToMarkdown("Mantis issue created", issues, headers=TABLE_HEADERS)

    results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Mantis.issue",
        outputs_key_field=TABLE_HEADERS,
        outputs=issues
    )
    return_results(results)


def matis_create_note_command(client, args):
    _id = args.get('id')
    body = {
        "text": args.get('text'),
        "view_state": {
            "name": args.get('view_state')
        }
    }
    resp = client.create_note(_id, body)
    return 'Note successfully added'


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/rest')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)
    headers = {
        "Authorization": token
    }

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'mantis-get-issue-by-id':
            return_results(mantis_get_issue_by_id_command(client, args))
        elif demisto.command() == 'mantis-get-issues':
            return_results(mantis_get_all_issues_command(client, args))
        elif demisto.command() == 'mantis-create-issue':
            mantis_create_issue_command(client, args)
        elif demisto.command() == 'mantis-add-note':
            matis_create_note_command(client, args)
        elif demisto.command() == 'mantis-close-issue':
            mantis_close_issue_command(client, args)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
