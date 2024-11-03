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
        demisto.debug(f'{query_params=}')
        raw_response = self._http_request(
            method='GET',
            url_suffix='logs',
            params=query_params,
            retries=2,
        )
        demisto.debug(f'{raw_response=}')
        events = raw_response.get('entries', [])
        cursor = raw_response.get('response_metadata', {}).get('next_cursor')

        return raw_response, events, cursor

    def handle_pagination_first_batch(self, query_params: dict, last_run: dict) -> tuple[list, str | None]:
        """
        Makes the first logs API call in the current fetch run.
        If `last_search_stop_point` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events (that weren't collected yet).
        """
        if last_id := last_run.get('last_id'):
            # Maintain compatibility when moving from versions 3.3.0 and lower to 3.4.0 by updating the 'last-run'.
            # This code should only be performed once for each integration instance,
            # when upgrading the pack from version 3.3.0 or lower to 3.4.0 or higher.
            last_run['last_fetched_event'] = {'last_event_id': last_id, 'last_event_time': None}
            last_run.pop('last_id')

        cursor = last_run.pop('cursor', None)
        last_event = last_run.get('last_fetched_event')
        if cursor:
            query_params['cursor'] = cursor
            query_params.pop('oldest')
        elif last_event:
            query_params['oldest'] = last_event.get('last_event_time')
        _, events, cursor = self.get_logs(query_params)

        if last_run.get('last_search_stop_point_event_id'):
            for idx, event in enumerate(events):
                if event.get('id') == last_run['last_search_stop_point_event_id']:
                    events = events[idx:]
                    break
            last_run.pop('last_search_stop_point_event_id', None)  # removing to make sure it won't be used in future runs
        return events, cursor

    def get_logs_with_pagination(self, query_params: dict, last_run: dict) -> list[dict]:
        """
        Aggregates logs using cursor-based pagination, until one of the following occurs:
        1. Encounters an event that was already fetched in a previous run / reaches all the resolutes.
           In both cases, clears the cursor (if exist) from the lastRun obj, updates `event_last_id` and `event_last_time`
           to know where to stop in the next runs and returns the aggragated logs.

        2. Reaches the user-defined limit (parameter).
           In this case, stores the last used cursor and the id of the next event to collect (`last_search_stop_point`)
           and if it is the first run in this search it saves the newest event details as 'newest_event_fetched'
           to be used when the cursor is exhausted and a new search query should be performed.
           and returns the events that have been accumulated so far.

        3. Reaches a rate limit.
           In this case, stores the last cursor used in the lastRun obj
           if it is the first run in this search it saves the newest event details as 'newest_event_fetched'
           and returns the events that have been accumulated so far.
        """
        aggregated_logs: list[dict] = []

        user_defined_limit = query_params.pop('limit')
        query_params['limit'] = 200  # recommended limit value by Slack
        try:
            events, cursor = self.handle_pagination_first_batch(query_params, last_run)
            last_event_id = last_run.get('last_fetched_event', {}).get('last_event_id')
            while events:
                for event in events:
                    if event.get('id') == last_event_id:
                        demisto.debug('Encountered an event that was already fetched - stopping.')
                        cursor = None
                        break

                    if len(aggregated_logs) == user_defined_limit:
                        demisto.debug(f'Reached the user-defined limit ({user_defined_limit}) - stopping.')
                        last_run['last_search_stop_point_event_id'] = event.get('id')
                        cursor = query_params.get('cursor')
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

        if aggregated_logs:
            '''
            If didn't fetch logs, we are not changing the last run
            If fetched logs, There are 4 scenarios
                1. This run we did a new query and finished fetching all the events,
                    so we save the newest event as 'last_fetched_event'.
                2. We did a new query this time and did not finish fetching all the events,
                    so we save the newest event as 'newest_event_fetched'
                    and the 'cursor' (if exists) and last_search_stop_point_event_id for the next run.
                3. We continued to fetch events by 'cursor' and finished fetching them all,
                    saving the 'newest_event_fetched' as 'last_fetched_event'.
                4. We continued to fetch events by 'cursor', and we still haven't finished fetching them all,
                    so we only need to save the 'cursor' (if exists), and last_search_stop_point_event_id.
            '''
            if not last_run.get('newest_event_fetched'):
                newest_event = {'last_event_id': aggregated_logs[0].get('id'),
                                'last_event_time': aggregated_logs[0].get('date_create')}
                if cursor:
                    last_run['newest_event_fetched'] = newest_event
                    last_run['cursor'] = cursor
                elif last_run.get('last_search_stop_point_event_id'):  # if the 'user defined limit' is less than the page size,
                    # then there won't be a curser, but we haven't finished bringing all the events yet
                    last_run['newest_event_fetched'] = newest_event
                else:
                    last_run['last_fetched_event'] = newest_event
            else:
                if cursor:
                    last_run['cursor'] = cursor
                elif not last_run.get('last_search_stop_point_event_id'):
                    last_run['last_fetched_event'] = last_run['newest_event_fetched']
                    last_run.pop('newest_event_fetched')

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
            demisto.debug(f'last run is: {last_run}')

            events, last_run = fetch_events_command(client, params, last_run)

            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(last_run)
            demisto.debug(f'Last run set to: {last_run}')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
