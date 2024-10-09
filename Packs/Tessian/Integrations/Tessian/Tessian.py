import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR & Tessian

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def list_events(self, limit: int | None, after_checkpoint: str | None, created_after: str | None) -> dict[str, Any]:
        params = assign_params(limit=limit, after_checkpoint=after_checkpoint, created_after=created_after)

        return self._http_request(
            method='GET',
            url_suffix='/api/v1/events',
            params=params,
            resp_type='json',
            ok_codes=(200,)
        )

    def release_from_quarantine(self, event_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/api/v1/remediation/release_from_quarantine',
            json_data={"event_id": event_id},
            resp_type='json',
            ok_codes=(200,)
        )

    def delete_from_quarantine(self, event_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/api/v1/remediation/delete_from_quarantine',
            json_data={"event_id": event_id},
            resp_type='json',
            ok_codes=(200,)
        )

    def delete_from_inbox(self, event_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/api/v1/remediation/delete_from_inbox',
            json_data={"event_id": event_id},
            resp_type='json',
            ok_codes=(200,)
        )


''' HELPER FUNCTIONS '''


def format_url(url: str) -> str:
    """
    This function strips the url to make sure it's in the expected format.
    We want to be working with a url that looks like this: https://domain.tessian.com
    """

    #  Remove leading http/https, we do this so that we can add the https:// prefix in the return
    if url.startswith('http://'):
        # We should never have insecure portals, but just in case the customer enters their url
        # with http:// for whatever reason, we'll strip it to add a secure prefix
        url = url[7:]
    elif url.startswith('https://'):
        #  Just strip this so that we can ensure it's not there for the rest of the logic.
        url = url[8:]

    # Remove trailing slashes
    if '/' in url:
        #  We will disregard everything after the trailing slash to obtain the portal URL.
        # This should cover customers who enter their api url by mistake.
        url = url.split('/')[0]

    # Add the https:// prefix in the return
    return f"https://{url}"


''' COMMAND FUNCTIONS '''


def list_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = int(args.get('limit', 100))
    after_checkpoint = args.get('after_checkpoint')
    created_after = args.get('created_after')

    results = client.list_events(limit, after_checkpoint, created_after)

    summary_results = [
        {
            "Event ID": event.get("id"),
            "Event Type": event.get("type"),
            "Event Created At": event.get("created_at"),
            "Event Updated At": event.get("updated_at"),
            "Portal Link": event.get("portal_link")
        } for event in results.get("results", [])
    ]

    markdown = '# Tessian Events\n'
    markdown += f'## Checkpoint: {results.get("checkpoint")}\n'
    markdown += f'## Additional Results: {results.get("additional_results")}\n'
    markdown += f'### Number of events returned: {len(results.get("results", []))}\n'
    markdown += tableToMarkdown(
        name="Results",
        t=summary_results,
        headers=['Event ID', 'Event Type', 'Event Created At', 'Event Update At', 'Portal Link'],
    )

    return CommandResults(
        outputs_prefix='Tessian.EventsOutput',
        outputs_key_field='checkpoint',
        outputs=results,
        raw_response=results,
        readable_output=markdown,
    )


def release_from_quarantine_command(client: Client, args: dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')

    if event_id is None:
        raise ValueError('Event ID is required')

    results = client.release_from_quarantine(event_id)
    results["event_id"] = event_id

    markdown = '# Release from Quarantine Action\n'
    markdown += f'## Event ID: {event_id}\n'
    markdown += f'## Number of Release Actions Successfully Initiated: {results.get("number_of_actions_succeeded")}\n'
    failure_count = results.get("number_of_actions_attempted", 0) - results.get("number_of_actions_succeeded", 0)
    markdown += f'## Number of Release Actions Failed: {failure_count}\n'

    if results.get("number_of_actions_attempted") != results.get("number_of_actions_succeeded"):
        failures = [
            {
                "Recipient": failure.get("user_address"),
                "Error": failure.get("error")
            } for failure in results.get("results", []) if failure.get("error") is not None
        ]
        markdown += tableToMarkdown(
            name="Errors",
            t=failures,
            headers=['Recipient', 'Error'],
        )

    return CommandResults(
        outputs_prefix='Tessian.ReleaseFromQuarantineOutput',
        outputs_key_field='event_id',
        outputs=results,
        raw_response=results,
        readable_output=markdown,
    )


def delete_from_quarantine_command(client: Client, args: dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')

    if event_id is None:
        raise ValueError('Event ID is required')

    results = client.delete_from_quarantine(event_id)
    results["event_id"] = event_id

    markdown = '# Delete from Quarantine Action\n'
    markdown += f'## Event ID: {event_id}\n'
    markdown += f'## Number of Delete Actions Successfully Initiated: {results.get("number_of_actions_succeeded")}\n'
    failure_count = results.get("number_of_actions_attempted", 0) - results.get("number_of_actions_succeeded", 0)
    markdown += f'## Number of Delete Actions Failed: {failure_count}\n'

    if results.get("number_of_actions_attempted") != results.get("number_of_actions_succeeded"):
        failures = [
            {
                "Recipient": failure.get("user_address"),
                "Error": failure.get("error")
            } for failure in results.get("results", []) if failure.get("error") is not None
        ]
        markdown += tableToMarkdown(
            name="Errors",
            t=failures,
            headers=['Recipient', 'Error'],
        )

    return CommandResults(
        outputs_prefix='Tessian.DeleteFromQuarantineOutput',
        outputs_key_field='event_id',
        outputs=results,
        raw_response=results,
        readable_output=markdown,
    )


def delete_from_inbox_command(client: Client, args: dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')

    if event_id is None:
        raise ValueError('Event ID is required')

    results = client.delete_from_inbox(event_id)
    results["event_id"] = event_id

    markdown = '# Delete from Inbox Action\n'
    markdown += f'## Event ID: {event_id}\n'
    markdown += f'## Number of Delete Actions Successfully Initiated: {results.get("number_of_actions_succeeded")}\n'
    failure_count = results.get("number_of_actions_attempted", 0) - results.get("number_of_actions_succeeded", 0)
    markdown += f'## Number of Delete Actions Failed: {failure_count}\n'

    if results.get("number_of_actions_attempted") != results.get("number_of_actions_succeeded"):
        failures = [
            {
                "Recipient": failure.get("user_address"),
                "Error": failure.get("error")
            } for failure in results.get("results", []) if failure.get("error") is not None
        ]
        markdown += tableToMarkdown(
            name="Errors",
            t=failures,
            headers=['Recipient', 'Error'],
        )

    return CommandResults(
        outputs_prefix='Tessian.DeleteFromInboxOutput',
        outputs_key_field='event_id',
        outputs=results,
        raw_response=results,
        readable_output=markdown,
    )


def test_module(client: Client) -> str:  #  pragma: no cover
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """

    try:
        response = client.list_events(2, None, None)

        success = demisto.get(response, 'checkpoint')
        if success is None:
            return f'Unexpected result from the service: expected checkpoint to be a string, response={str(response)}'

        return 'ok'
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


''' MAIN FUNCTION '''


def main() -> None:  #  pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get the service API url
    params = demisto.params()
    args = demisto.args()
    base_url = format_url(params.get('url'))
    api_key = params.get('api_key', {}).get('password')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: dict = {}
        headers["Authorization"] = f"API-Token {api_key}"

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'tessian-list-events':
            return_results(list_events_command(client, args))

        elif demisto.command() == 'tessian-release-from-quarantine':
            return_results(release_from_quarantine_command(client, args))

        elif demisto.command() == 'tessian-delete-from-quarantine':
            return_results(delete_from_quarantine_command(client, args))

        elif demisto.command() == 'tessian-delete-from-inbox':
            return_results(delete_from_inbox_command(client, args))
        else:
            raise NotImplementedError(f"Either the command, {demisto.command}, is not supported yet or it does not exist.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
