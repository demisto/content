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

urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Celonis'
PRODUCT = 'Celonis'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PAGE_SIZE = 200
PAGE_NUMBER = 0
BEARER_PREFIX = 'Bearer '

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None  # TODO
        self.generate_token()

    def generate_token(self):
        results = self._http_request(
            method="POST",
            url_suffix=f"/oauth2/token?grant_type=client_credentials&scope=audit.log:read",
        )
        self.token = results['access_token']

    def get_events(self, start_date: str, end_date: str) -> dict:
        headers = {
            'Authorization': f'{BEARER_PREFIX}{self.token}',
        }
        results = self._http_request(
            method="GET",
            url_suffix=f"/log/api/external/audit?pageNumber={PAGE_NUMBER}&pageSize={PAGE_SIZE}&from={start_date}&to={end_date}",
            headers=headers
        )
        return results



""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    return "ok"


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    output: list = []

    if get_events_args:
        pass
    else:
        last_run = demisto.getLastRun() or {}
        event_date = last_run.get('start_date', '')
        if not event_date:
            event_date = get_current_time().strftime(DATE_FORMAT)
        end = get_current_time().strftime(DATE_FORMAT)

    current_start_date = event_date

    while True:
        events = client.get_events(event_date, end)

        if rate_limit_reached():
            check_if_limit_more_than_0_and_wait_this_time
            # TODO to add logs
            send_message_to_client_and_return_results()
            return
        if got_error_for_token:
            client.regnerate_token
            client.get_events(event_date, end)

        if not events:
            break

        for event in events:
            event['_TIME'] = event.get('date')
            output.append(event)
            event_date = get_and_parse_date(event)

            if event_date != current_start_date:
                current_start_date = event_date

            if len(output) >= fetch_limit:
                new_last_run = {'start_date': event_date}
                return output, new_last_run

    new_last_run = {'start_date': event_date}
    return output, new_last_run


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    pass


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        headers = {

        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )
        if command == "test-module":
            result = test_module(client)
            return result
        elif command == "fetch-events":
            pass
        elif command == "celonis-get-events":
            pass
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
