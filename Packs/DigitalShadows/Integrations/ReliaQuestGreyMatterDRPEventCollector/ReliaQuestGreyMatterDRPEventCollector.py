import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
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
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format

''' CLIENT CLASS '''


class ReilaQuestClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, url: str, account_id: str, username: str, password: str, verify_ssl: bool = False, proxy: bool = False):
        self.url = url
        self.account_id = account_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        super().__init__(base_url=url, verify=verify_ssl, proxy=proxy, auth=(username, password))

    def http_request(self, url_suffix: str, method: str = "GET", headers: dict[str, Any] | None = None, params: dict[str, Any] | None = None):
        return self._http_request(method, url_suffix=url_suffix, headers=headers or {"searchlight-account-id": self.account_id}, params=params)

    def list_triage_item_events(self, event_created_before: str | None = None, event_created_after: str | None = None, limit: int = 1000, events_num_after: int | None = None):
        """
        Args:
                api docs:
                    Return events with an event-num greater than this value
                    Must be greater than or equal to 0.
            event_created_before (str): retrieve events occurred before a specific time, format:  YYYY-MM-DDThh:mm:ssTZD.
            event_created_after (str): retrieve events occurred after a specific time, format:  YYYY-MM-DDThh:mm:ssTZD.
            limit (int): the maximum number of events to retrieve
            events_num_after (int): used for pagination, can be retrieved from the "event-num" value from previous responses.
        """
        params: dict = {"limit": limit}
        if event_created_before:
            params["event-created-before"] = event_created_before
        if event_created_after:
            params["event-created-after"] = event_created_after
        if events_num_after:
            params["events-num-after"] = events_num_after

        return self.http_request("/triage-item-events", params=params)

    def triage_items(self, triage_item_ids: list[str]):
        """
        Args:
            triage_item_ids: a list of triage item IDs.
            from api:
                One or more triage item identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.http_request("/triage-items", params={"id": triage_item_ids})

    def get_alerts_by_ids(self, alert_ids: list[str]):
        """
        List of alerts was created from alert_id fields of /triage-items  response

        Args:
            alert_ids: List of alerts was created from alert_id fields of /triage-items  response
            from api:
                One or more alert identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.http_request("/alerts", params={"id": alert_ids})

    def get_incident_ids(self, incident_ids: list[str]):
        """
        List of alerts was created from incident-id fields of /triage-items response

        Args:
            incident_ids: a list of incident-IDs.
        """
        return self.http_request("/incidents", params={"id": incident_ids})

    def get_asset_ids(self, asset_ids: list[str]):
        """
        Retrieve the Asset Information for the Alert or Incident

        Args:
            asset_ids: a list of asset-IDs.
        """
        return self.http_request("/assets", params={"id": asset_ids})


def test_module(client: ReilaQuestClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.list_triage_item_events(limit=1)
    return "ok"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    url = params.get("url")
    account_id = params.get("account_id")
    max_fetch_events = arg_to_number(params.get("max_fetch_events")) or 200
    events_first_fetch = dateparser.parse(params.get("first_fetch_events"), settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    verify_ssl = not argToBoolean(password.get("insecure", True))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:

        client = ReilaQuestClient(url, account_id=account_id, username=username, password=password, verify_ssl=verify_ssl, proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == "fetch-events":
            pass
        elif command == "fetch-assets":
            pass
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
