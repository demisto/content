import demistomock as demisto
from CommonServerPython import *

from typing import Tuple

requests.packages.urllib3.disable_warnings()


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
        'limit': arg_to_number(params.get('limit')) or 200,
        'oldest': arg_to_timestamp(params.get('oldest')),
        'latest': arg_to_timestamp(params.get('latest')),
        'action': params.get('action'),
        'actor': params.get('actor'),
        'entity': params.get('entity'),
        'cursor': params.get('cursor'),
    }
    if not 0 < query_params['limit'] <= 1000:  # type: ignore
        raise ValueError('limit argument must be an integer between 1 to 1000.')
    return query_params


class Client(BaseClient):
    def test(self) -> dict:
        query_params = prepare_query_params({
            'limit': '1',
            'oldest': '3 days ago',
            'latest': 'now',
            'action': 'user_login',
        })
        return self.get_logs(query_params)

    def get_logs(self, query_params: dict) -> dict:
        return self._http_request(method='GET', url_suffix='logs', params=query_params)

    def get_logs_with_pagination(self, query_params: dict, last_run: dict) -> List[dict]:
        """
        Aggregates logs using cursor-based pagination, until encounters an event
        that was already fetched in the previous run or reaches the end of the pagination.

        If reaches rate limit, stores the last cursor used in the lastRun object,
        and returns the events that have been accumulated so far.
        """
        aggregated_logs: List[dict] = []
        last_id = last_run.get('last_id')
        try:
            while raw_response := self.get_logs(query_params):
                for event in raw_response.get('entries', []):
                    if event.get('id') == last_id:
                        return aggregated_logs
                    aggregated_logs.append(event)

                if not (cursor := raw_response.get('response_metadata', {}).get('next_cursor')):
                    last_run['cursor'] = None
                    return aggregated_logs
                query_params['cursor'] = cursor

        except DemistoException as e:
            if e.res and e.res.status_code == 429:
                last_run['cursor'] = query_params.get('cursor')
                return aggregated_logs
            raise e

        return aggregated_logs


def test_module_command(client: Client) -> str:
    client.test()
    return 'ok'


def get_events_command(client: Client, args: dict) -> Tuple[list, CommandResults]:
    query_params = prepare_query_params(args)
    raw_response = client.get_logs(query_params)
    events = raw_response.get('entries', [])
    cursor = raw_response.get('response_metadata', {}).get('next_cursor')
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


def fetch_events_command(client: Client, params: dict, last_run: dict) -> Tuple[list, dict]:
    params['cursor'] = last_run.get('cursor')
    query_params = prepare_query_params(params)
    if events := client.get_logs_with_pagination(query_params, last_run):
        last_run['last_id'] = events[0].get('id')
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
            return_results(test_module_command(client))

        else:
            if command == 'slack-get-events':
                events, results = get_events_command(client, args)
                return_results(results)

            else:  # command == 'fetch-events'
                last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(client, params, last_run)
                demisto.setLastRun(last_run)

            if argToBoolean(params.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    params.get('vendor', 'slack'),
                    params.get('product', 'slack')
                )
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
