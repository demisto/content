import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

urllib3.disable_warnings()

VENDOR = "slack"
PRODUCT = "slack"


def arg_to_timestamp(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if datetime_obj := arg_to_datetime(value):
        return int(datetime_obj.timestamp())
    return None


def prepare_query_params(params: dict) -> dict:
    """
    Parses the given inputs into Slack Audit Logs API expected format.
    """
    query_params = {
        'limit': arg_to_number(params.get('limit')) or 1000,
        'oldest': arg_to_timestamp(params.get('oldest')),
        'latest': arg_to_timestamp(params.get('latest')),
        'action': params.get('action'),
        'actor': params.get('actor'),
        'entity': params.get('entity'),
        'cursor': params.get('cursor'),
    }
    return query_params


class Client(BaseClient):
    def get_logs(self, query_params: dict) -> tuple[dict, list, str | None]:
        raw_response = self._http_request(
            method='GET',
            url_suffix='logs',
            params=query_params,
            retries=2,
        )
        events = raw_response.get('entries', [])
        cursor = raw_response.get('response_metadata', {}).get('next_cursor')

        return raw_response, events, cursor

    def handle_pagination_first_batch(self, query_params: dict, last_run: dict) -> tuple[list, str | None]:
        """
        Makes the first logs API call in the current fetch run.
        If `first_id` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events (that weren't collected yet).
        """
        query_params['cursor'] = last_run.pop('cursor', None)
        _, events, cursor = self.get_logs(query_params)
        if last_run.get('first_id'):
            for idx, event in enumerate(events):
                if event.get('id') == last_run['first_id']:
                    events = events[idx:]
                    break
            last_run.pop('first_id', None)  # removing to make sure it won't be used in future runs
        return events, cursor

    def get_logs_with_pagination(self, query_params: dict, last_run: dict) -> list[dict]:
        """
        Aggregates logs using cursor-based pagination, until one of the following occurs:
        1. Encounters an event that was already fetched in a previous run / reaches the end of the pagination.
           In both cases, clears the cursor from the lastRun obj, updates `last_id` to know where
           to stop in the next runs and returns the aggragated logs.

        2. Reaches the user-defined limit (parameter).
           In this case, stores the last used cursor and the id of the next event to collect (`first_id`)
           and returns the events that have been accumulated so far.

        3. Reaches a rate limit.
           In this case, stores the last cursor used in the lastRun obj
           and returns the events that have been accumulated so far.
        """
        aggregated_logs: list[dict] = []

        user_defined_limit = query_params.pop('limit')
        query_params['limit'] = 200  # recommended limit value by Slack
        try:
            events, cursor = self.handle_pagination_first_batch(query_params, last_run)
            while events:
                for event in events:
                    if event.get('id') == last_run.get('last_id'):
                        demisto.debug('Encountered an event that was already fetched - stopping.')
                        cursor = None
                        break

                    if len(aggregated_logs) == user_defined_limit:
                        demisto.debug(f'Reached the user-defined limit ({user_defined_limit}) - stopping.')
                        last_run['first_id'] = event.get('id')
                        cursor = query_params['cursor']
                        break

                    aggregated_logs.append(event)

                else:
                    # Finished iterating through all events in this batch (did not encounter a break statement)
                    if cursor:
                        demisto.debug('Using the cursor from the last API call to execute the next call.')
                        query_params['cursor'] = cursor
                        _, events, cursor = self.get_logs(query_params)
                        continue

                demisto.debug('Finished iterating through all events in this fetch run.')
                break

        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            demisto.debug('Reached API rate limit, storing last used cursor.')
            cursor = query_params['cursor']

        last_run['cursor'] = cursor
        if not cursor and aggregated_logs:
            # we need to know where to stop in the next runs
            last_run['last_id'] = aggregated_logs[0].get('id')

        return aggregated_logs


def test_module_command(client: Client, params: dict) -> str:
    """
    Tests connection to Slack.
    Args:
        clent (Client): the client implementing the API to Slack.
        params (dict): the instance configuration.

    Returns:
        (str) 'ok' if success.
    """
    fetch_events_command(client, params, last_run={})
    return 'ok'


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Gets log events from Slack.
    Args:
        clent (Client): the client implementing the API to Slack.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved from the logs API call.
        (CommandResults) the CommandResults object holding the collected logs information.
    """
    query_params = prepare_query_params(args)
    raw_response, events, cursor = client.get_logs(query_params)
    results = CommandResults(
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            'Slack Audit Logs',
            events,
            metadata=f'Cursor: {cursor}' if cursor else None,
            date_fields=['date_create'],
        ),
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict) -> tuple[list, dict]:
    """
    Collects log events from Slack using pagination.
    Args:
        clent (Client): the client implementing the API to Slack.
        params (dict): the instance configuration.
        last_run (dict): the lastRun object, holding information from the previous run.

    Returns:
        (list) the events retrieved from the logs API call.
        (dict) the updated lastRun object.
    """
    query_params = prepare_query_params(params)
    events = client.get_logs_with_pagination(query_params, last_run)
    return events, last_run


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=params.get('url'),
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
            headers={
                'Accept': 'application/json',
                'Authorization': f'Bearer {params.pop("user_token", {}).get("password")}'
            },
        )

        if command == 'test-module':
            return_results(test_module_command(client, params))

        elif command == 'slack-get-events':
            events, results = get_events_command(client, args)
            return_results(results)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(client, params, last_run)

            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(last_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
