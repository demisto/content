from CommonServerPython import *
from http import HTTPStatus
VENDOR = "okta"
PRODUCT = "okta"
FETCH_LIMIT = 1000


class Client(BaseClient):
    next_run_filter: str
    params = {
        "sortOrder": "ASCENDING",
    }

    def __init__(self, base_url, api_key, verify=True, proxy=False):
        headers = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": f"SSWS {api_key}"
                   }
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def get_events(self, since: int, limit: int = FETCH_LIMIT):
        self.params['since'] = since  # type: ignore
        self.params['limit'] = limit  # type: ignore
        return self._http_request(url_suffix='/api/v1/logs', method='GET', headers=self._headers, params=self.params)  # type: ignore

    def set_next_run_filter(self, after: str):
        self.next_run_filter = after  # type: ignore


def get_events_command(client: Client, total_events_to_fetch, since, last_object_ids: List[str] = None) -> (List[dict], int):  # pragma: no cover
    """
    Function to group the events returned from the api
    """
    stored_events: list = []
    while total_events_to_fetch > 0:
        num_of_events_to_fetch = 1000 if total_events_to_fetch > 1000 else total_events_to_fetch
        try:
            events = client.get_events(since, num_of_events_to_fetch)  # type: ignore
            if events:
                total_events_to_fetch -= len(events)
                if last_object_ids:
                    events = remove_duplicates(events, last_object_ids)  # type: ignore
                last = events[-1]
                client.next_run_filter = last['published']
                stored_events.extend(events)
            else:
                break
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            demisto.debug(msg)
            status_code: HTTPStatus = exc.res.status_code
            if status_code == HTTPStatus.TOO_MANY_REQUESTS:
                return stored_events, int(exc.res.headers['x-rate-limit-reset'])  # type: ignore
            else:
                return stored_events, 0
    return stored_events, 0


def remove_duplicates(events: list, ids: list) -> list:
    """
    Remove object duplicates by the uuid of the object
    """
    return [event for event in events if event['uuid'] not in ids]


def get_last_run(events: List[dict], last_run_after) -> dict:
    """
    Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
    """
    ids = []
    # gets the last event time
    last_time = events[-1].get('published') if events else last_run_after
    for event in reversed(events):
        if event.get('published') != last_time:
            break
        ids.append(event.get('uuid'))
    last_time = datetime.strptime(str(last_time).lower().replace('z', ''), '%Y-%m-%dt%H:%M:%S.%f')
    return {'after': last_time.isoformat(), 'ids': ids}


def main():  # pragma: no cover
    try:
        start_time_epoch = int(time.time())
        demisto_params = demisto.params() | demisto.args()
        events_limit = int(demisto_params.get('limit', 2000))
        should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
        after = dateparser.parse(demisto_params['after'].strip())
        api_key = demisto_params['api_key']['password']
        verify_certificate = not demisto_params.get('insecure', True)
        base_url = demisto_params['url']
        last_run = demisto.getLastRun()
        last_object_ids = last_run.get('ids')
        if 'after' not in last_run:
            last_run_after = after.isoformat()  # type: ignore
        else:
            last_run_after = last_run['after']
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate)
        command = demisto.command()
        if command == 'test-module':
            get_events_command(client, events_limit, since=last_run_after, last_object_ids=last_object_ids)
            demisto.results('ok')

        if command == 'okta-get-events':
            events, continue_fetch = get_events_command(client, events_limit, since=last_run_after, last_object_ids=last_object_ids)
            command_results = CommandResults(
                readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)

            if should_push_events:
                send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)
        elif command == 'fetch-events':
            continue_fetch = True
            while continue_fetch:
                events, continue_fetch = get_events_command(client, events_limit, since=last_run_after, last_object_ids=last_object_ids)
                if continue_fetch:
                    time.sleep(continue_fetch - start_time_epoch)  # TODO calculate sleep time
            send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(get_last_run(events, last_run_after))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
