"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *
from requests.auth import HTTPDigestAuth

urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Celonis'
PRODUCT = 'Celonis'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PAGE_SIZE = 200
PAGE_NUMBER = 0
DEFAULT_FETCH_LIMIT = 600
BEARER_PREFIX = 'Bearer '

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        super().__init__(base_url=base_url, verify=verify)
        self.token = None
        self.create_access_token_for_audit()

    def create_access_token_for_audit(self):
        data = {
            "grant_type": "client_credentials",
            "scope": "audit.log:read"
        }
        results = self._http_request(
            method="POST",
            url_suffix="/oauth2/token",
            data=data,
            auth=(self.client_id, self.client_secret)
        )
        self.token = results['access_token']

    def get_audit_logs(self, start_date: str, end_date: str) -> dict:
        params = assign_params(
            pageNumber=PAGE_NUMBER,
            pageSize=PAGE_SIZE,
            startDate=start_date,
            to=end_date
        )
        headers = {
            'Authorization': f'{BEARER_PREFIX}{self.token}',
        }
        results = self._http_request(
            method="GET",
            url_suffix=f"/log/api/external/audit",
            headers=headers,
            params=params
        )
        return results


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    client.create_access_token_for_audit()
    return "ok"


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    if get_events_args:  # handle get_event command
        event_date = get_events_args.get('start_date', '')
        end = get_events_args.get('end_date', '')
    else:  # handle fetch_events case
        last_run = demisto.getLastRun() or {}
        event_date = last_run.get('start_date', '')
        if not event_date:
            event_date = "2025-01-03T15:19:12.180Z"
            # event_date = get_current_time().strftime(DATE_FORMAT)
        end = get_current_time().strftime(DATE_FORMAT)

    current_start_date = event_date
    output: list = []
    while True:
        try:
            response = client.get_audit_logs(event_date, end)
        except Exception as e:
            if e.errorCode == "LIMIT_RATE_EXCEEDED":  # rate limit reached
                demisto.debug(f"Rate limit reached. Returning {len(output)} instead of {fetch_limit} Audit logs.")
                new_last_run = {'start_date': event_date}
                return output, new_last_run
            if e.error == 'Unauthorized':  # need to regenerate the token
                client.create_access_token_for_audit()
                response = client.get_audit_logs(event_date, end)

        events = response.get('context')
        if not events:
            break
        if check_if_limit_more_than_0_and_wait_this_time:
            pass

        for event in events:
            event_date = event.get('timestamp')
            event['_TIME'] = event_date
            output.append(event)

            if event_date != current_start_date:
                current_start_date = event_date

            if len(output) >= fetch_limit:
                new_last_run = {'start_date': event_date}
                return output, new_last_run

    new_last_run = {'start_date': event_date}
    return output, new_last_run


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_FETCH_LIMIT

    output, _ = fetch_events(client, limit, {"start_date": start_date, "end_date": end_date})

    filtered_events = []
    for event in output:
        filtered_event = {'User ID': event.get('userId'),
                          'User Role': event.get('userRole'),
                          'Event': event.get('event'),
                          'Timestamp': event.get('timestamp')
                          }
        filtered_events.append(filtered_event)

    human_readable = tableToMarkdown(name='Celonis Audit Logs Events', t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix='CelonisEventCollector',
    )
    return output, command_results


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        base_url = params.get("url")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        client_id = params.get('credentials', {}).get('identifier')
        client_secret = params.get('credentials', {}).get('password')
        fetch_limit = arg_to_number(params.get('max_events_per_fetch')) or DEFAULT_FETCH_LIMIT

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret
        )
        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            events, new_last_run_dict = fetch_events(client, fetch_limit)
            if events:
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run_dict)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "celonis-get-events":
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get('should_push_events')):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
