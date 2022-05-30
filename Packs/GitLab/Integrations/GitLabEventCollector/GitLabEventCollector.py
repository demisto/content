from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from SiemApiModule import *  # noqa # pylint: disable=unused-wildcard-import


class Client(IntegrationEventsClient):

    def __init__(self, request: IntegrationHTTPRequest, options: IntegrationOptions, last_run: str):  # pragma: no cover
        super().__init__(request=request, options=options)
        self.last_run = last_run
        self.page = 1
        self.event_type = ''

    def set_request_filter(self, after):  # noqa: F841  # pragma: no cover
        base_url = self.request.url.split("?")[0]
        last_run = self.last_run[self.event_type]  # type: ignore
        after_var = 'created_after'
        per_page = '100'
        if demisto.command() == 'test-module':
            per_page = '1'
        if self.event_type == 'events':
            after_var = 'after'
        self.request.url = f'{base_url}?{after_var}={last_run}&per_page={per_page}&page={self.page}'  # type: ignore
        self.page += 1


class GetEvents(IntegrationGetEvents):
    @staticmethod
    def get_last_run(events: list) -> dict:
        groups = [event for event in events if event.get('entity_type') == 'Group']
        groups.sort(key=lambda k: k.get('id'))
        projects = [event for event in events if event.get('entity_type') == 'Project']
        projects.sort(key=lambda k: k.get('id'))
        user_events = [event for event in events if 'entity_type' not in event]
        user_events.sort(key=lambda k: k.get('id'))
        return {'groups': groups[-1]['created_at'], 'projects': projects[-1]['created_at'],
                'events': user_events[-1]['created_at']}

    def _iter_events(self):  # pragma: no cover
        self.client.set_request_filter(None)
        response = self.call()
        events: list = response.json()
        events.sort(key=lambda k: k.get('created_at'))
        if not events:
            return []
        if demisto.command() == 'test-module':
            self.client.options.limit = 1
            yield events

        while True:
            yield events
            self.client.set_request_filter(None)
            response = self.call()
            events = response.json()
            events.sort(key=lambda k: k.get('created_at'))
            if not events:
                break


def reformat_details(events: list) -> list:
    for event in events:
        if 'details' in event:
            for action in ['add', 'change', 'remove']:
                if action in event['details']:
                    event['details']['action'] = f'{action}_{event["details"][action]}'
                    event['details']['action_type'] = action
                    event["details"]['action_category'] = event['details'][action]
                    break
    return events


def main() -> None:  # pragma: no cover
    demisto_params = demisto.params() | demisto.args()
    url = urljoin(demisto_params['url'], '/api/v4/')
    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
    events_collection_management = {
        'groups_ids': argToList(demisto_params.get('group_ids', '')),
        'projects_ids': argToList(demisto_params.get('project_ids', '')),
        'event_types': ['groups', 'projects']
    }
    headers = {'PRIVATE-TOKEN': demisto_params.get('api_key', {}).get('password')}
    verify = not demisto_params.get('insecure', 'True')
    request_object = {
        'method': Method.GET,
        'url': url,
        'headers': headers,
        'verify': verify
    }
    last_run = demisto.getLastRun()
    if ('groups', 'projects', 'events') not in last_run:
        last_run = dateparser.parse(demisto_params['after'].strip()).isoformat()  # type: ignore
        last_run = {
            'groups': last_run,
            'projects': last_run,
            'events': last_run,
        }

    options = IntegrationOptions(**demisto_params)

    request = IntegrationHTTPRequest(**request_object)

    client = Client(request, options, last_run)

    get_events = GetEvents(client, options)

    command = demisto.command()
    try:
        events = []
        for event_type in events_collection_management['event_types']:
            for obj_id in events_collection_management[f'{event_type}_ids']:
                call_url_suffix = f'{event_type}/{obj_id}/audit_events'
                get_events.client.request.url = url + call_url_suffix
                get_events.client.page = 1  # type: ignore
                get_events.client.event_type = event_type  # type: ignore
                events.extend(get_events.run())
        get_events.client.event_type = 'events'  # type: ignore
        get_events.client.request.url = urljoin(url + 'events')
        get_events.client.page = 1  # type: ignore
        events.extend(get_events.run())

        if command == 'test-module':
            return_results('ok')
            return

        events = reformat_details(events)

        if command == 'gitlab-get-events':
            command_results = CommandResults(
                readable_output=tableToMarkdown('gitlab Logs', events, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)
        elif command == 'fetch-events':
            demisto.setLastRun(get_events.get_last_run(events))
            should_push_events = True
        if should_push_events:
            send_events_to_xsiam(events, demisto_params.get('vendor', 'gitlab'),
                                 demisto_params.get('product', 'gitlab'))

    except Exception as exc:
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
