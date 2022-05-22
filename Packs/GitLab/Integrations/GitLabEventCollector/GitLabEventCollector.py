import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from typing import Any, Dict, List, Tuple
from SiemApiModule import *

def dedup_events(events: list, previous_fetched_events: list):
    for seen_event in previous_fetched_events:
        try:
            events.remove(seen_event)
        except ValueError:
            # seen_event not in events
            pass


''' CLIENT CLASS '''


class Client(BaseClient):
    PAGE_SIZE = 100
    def _get_events(self, end_point: str, created_after: str, page: int) -> List[Dict[str, str]]:
        return self._http_request(
            'GET',
            end_point,
            params={
                'created_after': created_after,
                'page': page,
                'per_page': self.PAGE_SIZE,
                'sort': 'asc',
            }
        )

    def _get_events_with_pagination(
        self,
        end_point: str,
        created_after: str,
        previous_fetched_events: list,
        page: int,
        limit: int = 1000,
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], int]:

        events = []

        last_page_events = current_events = self._get_events(end_point, created_after, page)
        events.extend(current_events)
        dedup_events(events, previous_fetched_events)

        while len(events) < limit and len(current_events) == self.PAGE_SIZE:
            page += 1
            last_page_events = current_events
            current_events = self._get_events(end_point, created_after, page)
            events.extend(current_events)

        return events[:limit], last_page_events, page

    def get_audit_events(self, created_after: str, page: int) -> Dict[str, str]:
        return self._get_events('/audit_events', created_after, page)

    def get_group_events(
        self,
        group_id: str,
        created_after: str,
        previous_fetched_events: list,
        limit: int = 1000,
        page: int = 1
    ) -> List[Dict[str, str]]:

        return self._get_events_with_pagination(
            f'/groups/{group_id}',
            created_after,
            previous_fetched_events,
            page,
            limit=limit,
        )

    def get_project_events(
        self,
        project_id: str,
        created_after: str,
        previous_fetched_events: list,
        limit: int = 1000,
        page: int = 1
    ) -> List[Dict[str, str]]:

        return self._get_events_with_pagination(
            f'/projects/{project_id}',
            created_after,
            previous_fetched_events,
            page,
            limit=limit,
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_audit_events(1)
        result = CommandResults(raw_response='ok')
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            result = CommandResults(raw_response='Authorization Error: make sure API Key is correctly set.')
        else:
            raise

    return result


def get_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = int(args.get('limit'))
    event_type = args.get('event_type')

    if event_type == 'Audit':
        events = client.get_audit_events(limit)
    if event_type == 'Group':
        events = client.get_group_events(limit)
    if event_type == 'Project':
        events = client.get_project_events(limit)
    else:
        raise DemistoException(f'Invalid event_type. Expected one of "Audit", "Group", "Project". Recieved: {event_type}.')

    return CommandResults(
        readable_output=tableToMarkdown('Events', events),
        raw_response=events,
    )


def fetch_events(client: Client, last_run: dict, group_ids: list, project_ids: list):
    events = []

    for group_id in group_ids:
        events.extend(client.get_group_events(group_id, last_run['groups'][group_id]['created_after']))

    for project_id in project_ids:
        events.extend(client.get_project_events(project_id, last_run['projects'][group_id]['created_after']))

    return events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    demisto_params = demisto.params() #| demisto.args()
    base_url = urljoin(demisto_params['url'], '/api/v4')
    api_key = demisto_params.get('credentials', {}).get('password')
    group_ids = argToList(demisto_params.get('group_ids'))
    project_ids = argToList(demisto_params.get('project_ids'))
    verify_certificate = not demisto_params.get('insecure', False)
    proxy = demisto_params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    request = IntegrationHTTPRequest(**demisto_params)

    options = IntegrationOptions.parse_obj(demisto_params)

    client =
    try:
        client = Client(
            base_url=base_url,
            headers={
                'PRIVATE-TOKEN': api_key,
            },
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'gitlab-get-events':
            result = get_events_command(client, demisto.args())
            return_results(result)

        elif command == 'fetch-events':
            # limit = int(params.get('limit', '1000'))
            last_run = demisto.getLastRun()
            events = fetch_events(client, last_run, group_ids, project_ids)
            send_events_to_xsiam(events, 'gitlab', 'gitlab')

    except Exception as exc:
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
