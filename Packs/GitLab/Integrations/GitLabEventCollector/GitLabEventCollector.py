from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from SiemApiModule import *  # noqa # pylint: disable=unused-wildcard-import

VENDOR = "gitlab"
PRODUCT = "gitlab"


class Client(IntegrationEventsClient):

    def __init__(self, request: IntegrationHTTPRequest, options: IntegrationOptions, last_run: str):  # pragma: no cover
        super().__init__(request=request, options=options)
        self.last_run = last_run
        self.page = 1
        self.event_type = ''

    def set_request_filter(self, after: Any) -> None:  # noqa: F841  # pragma: no cover
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
    def prepare_time_for_next(time_var: str) -> str:
        temp_time = datetime.strptime(time_var, "%Y-%m-%dT%H:%M:%S.%fZ")
        temp_time = temp_time + timedelta(milliseconds=1)
        return temp_time.isoformat()

    @staticmethod
    def get_sorted_events_by_type(events: list, search_in: bool = False, entity_type: str = '') -> list:
        filtered_events = [event for event in events if search_in or event.get('entity_type') == entity_type]
        filtered_events.sort(key=lambda k: k.get('id'))
        return filtered_events

    @staticmethod
    def get_last_run(events: list, audit: list, last_run: dict) -> dict:  # type: ignore
        """
        Check if the dockerfile has the latest tag and if there is a new version of it.
        Args:
        events (list): list of the event from the api
        audit (list): list of the instance audit events
        last_run (dict): the dictionary containing the last run times for the event types
        Returns:
        A dictionary with the times for the next run
        """
        groups = GetEvents.get_sorted_events_by_type(events, entity_type='Group')
        projects = GetEvents.get_sorted_events_by_type(events, entity_type='Project')
        audit_events = GetEvents.get_sorted_events_by_type(audit, search_in=True)
        if not groups:
            groups_time = last_run['groups']
        else:
            groups_time = GetEvents.prepare_time_for_next(groups[-1]['created_at'])
        if not projects:
            projects_time = last_run['projects']
        else:
            projects_time = GetEvents.prepare_time_for_next(projects[-1]['created_at'])
        if not audit_events:
            events_time = last_run['events']
        else:
            events_time = GetEvents.prepare_time_for_next(audit_events[-1]['created_at'])
        return {'groups': groups_time, 'projects': projects_time, 'events': events_time}

    def _iter_events(self):  # pragma: no cover
        self.client.set_request_filter(None)
        # If one endpoint fails don't fail everything
        try:
            response = self.call()
        except Exception as exc:
            demisto.info(f'Failed to get a response from the endpoint: {self.client.request.url}.\nError:\n{str(exc)}')
            return []
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
    if 'groups' not in last_run and 'projects' not in last_run and 'events' not in last_run:
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
        get_events.client.request.url = urljoin(url + 'audit_events')
        get_events.client.page = 1  # type: ignore
        audit = (get_events.run())

        if command == 'test-module':
            return_results('ok')
            return

        events = reformat_details(events)

        if command == 'gitlab-get-events':
            command_results = CommandResults(
                readable_output=tableToMarkdown('gitlab Logs', events + audit, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)
        elif command == 'fetch-events':
            should_push_events = True
        if should_push_events:
            send_events_to_xsiam(events + audit, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(get_events.get_last_run(events, audit, last_run))  # type: ignore

    except Exception as exc:
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
