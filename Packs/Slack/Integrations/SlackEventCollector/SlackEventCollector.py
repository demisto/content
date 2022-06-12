import demistomock as demisto
from CommonServerPython import *

from typing import Tuple

requests.packages.urllib3.disable_warnings()


def arg_to_timestamp(value: Any) -> Optional[int]:
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
    }
    assert isinstance(query_params['limit'], int)
    if not 0 < query_params['limit'] < 10000:
        raise ValueError('limit argument must be an integer between 1 to 9999.')
    return query_params


class Client(BaseClient):
    def test(self) -> list:
        query_params = prepare_query_params({
            'limit': '1',
            'oldest': '3 days ago',
            'latest': 'now',
            'action': 'user_login',
        })
        return self.get_logs(query_params)

    def get_logs(self, query_params: dict, last_run: Optional[dict] = None) -> list:
        res = self._http_request(method='GET', url_suffix='logs', params=query_params)
        events = res.get('entries', [])
        events.reverse()  # results from API are descending (most to least recent)

        return self.remove_duplicates(events, last_run)

    def remove_duplicates(self, events: list, last_run: Optional[dict]) -> list:
        """
        Drops from the API response of the current fetch the events that were already fetched in the previous run.
        Args:
            events (list): The raw events from the API.
            last_run (dict): If exists, contains the `oldest` and `id` values of the most recent event fetched
               in the previous run.

        Returns:
            (list) All the events that occurred *after* the record stored in the lastRun object.
        """
        if last_run and events:
            if events[0].get('date_create') == last_run.get('oldest'):
                for idx, event in enumerate(events):
                    if event.get('id') == last_run.get('last_id'):
                        return events[idx + 1:]
        return events


def test_module_command(client: Client) -> str:
    client.test()
    return 'ok'


def get_events_command(client: Client, args: dict) -> Tuple[list, CommandResults]:
    query_params = prepare_query_params(args)
    events = client.get_logs(query_params)
    results = CommandResults(
        outputs_prefix='SlackEvents',
        outputs_key_field='id',
        outputs=events,
        readable_output=tableToMarkdown('Slack Audit Logs', events, date_fields=['date_create']),
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict) -> Tuple[list, dict]:
    query_params = prepare_query_params(params)
    query_params['oldest'] = last_run.get('oldest') or query_params.get('oldest')

    if events := client.get_logs(query_params, last_run):
        last_run.update({
            'oldest': events[-1].get('date_create'),
            'last_id': events[-1].get('id')
        })
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
