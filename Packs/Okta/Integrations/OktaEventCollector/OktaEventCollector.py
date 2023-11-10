from CommonServerPython import *
from http import HTTPStatus
from typing import cast
VENDOR = "okta"
PRODUCT = "okta"
FETCH_LIMIT = 1000
FETCH_TIME_LIMIT = 60


class Client(BaseClient):

    def __init__(self, base_url, api_key, verify=True, proxy=False):
        headers = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": f"SSWS {api_key}"
                   }
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def get_events(self, since: int, limit: int = FETCH_LIMIT):
        params = {
            "sortOrder": "ASCENDING",
            "since": since,
            "limit": limit,
        }
        return self._http_request(url_suffix='/api/v1/logs', method='GET', headers=self._headers, params=params)


def get_events_command(client: Client, total_events_to_fetch, since,
                       last_object_ids: List[str] = None) -> tuple[List[dict], int]:  # pragma: no cover
    """
    Fetches events from the okta api until the total_events_to_fetch is reached or no more events are available.
    if 429:TOO_MANY_REQUESTS is returned, will return the stored_events so far and the x-rate-limit-reset
    from the response headers.
    Args:
        client (Client): the okta client
        total_events_to_fetch: the total number of events to fetch
        since: start fetch from this timestamp
        last_object_ids List[str]: list of uuids of the last fetched events.
    Returns:
        tuple[List[dict], int]:
            List[dict]: list of events fetched,
            int: x-rate-limit-reset: time in seconds until API can be called again.
    """
    stored_events: list = []
    num_of_events_to_fetch = FETCH_LIMIT if total_events_to_fetch > FETCH_LIMIT else total_events_to_fetch
    demisto.debug(f"num of events to fetch: {num_of_events_to_fetch} since: {since}")
    while len(stored_events) < total_events_to_fetch:
        demisto.debug(f"stored_events collected: {len(stored_events)}")
        try:
            events = client.get_events(since=since, limit=num_of_events_to_fetch)  # type: ignore
            if events:
                demisto.debug(f'received {len(events)} number of events.')
                since = events[-1]['published']
                if last_object_ids:
                    events = remove_duplicates(events, last_object_ids)  # type: ignore
                if not events:
                    demisto.debug('Events are empty after dedup will break.')
                    break
                stored_events.extend(events)
                if len(events) < num_of_events_to_fetch:
                    demisto.debug(f"Number of events collected is smaller than: {num_of_events_to_fetch} will break.")
                    break
            else:
                demisto.debug('Didnt receive any events from the api.')
                break
        except DemistoException as exc:
            msg = f'something went wrong: {exc}'
            demisto.debug(msg)
            if type(exc.res) is not requests.models.Response:
                raise
            res: requests.models.Response = exc.res
            status_code: int = res.status_code
            if status_code == HTTPStatus.TOO_MANY_REQUESTS.value:
                demisto.debug(f'fetch-events Got 429. okta rate limit headers:\n \
                x-rate-limit-remaining: {res.headers["x-rate-limit-remaining"]}\n \
                    x-rate-limit-reset: {res.headers["x-rate-limit-reset"]}\n')
                return stored_events, int(res.headers['x-rate-limit-reset'])
            return stored_events, 0
        except Exception as exc:
            demisto.error(f'Unexpected error.\n{traceback.format_exc()}')
            if len(stored_events) == 0:
                raise exc
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


def fetch_events(client: Client,
                 start_time_epoch: int,
                 events_limit: int,
                 last_run_after,
                 last_object_ids: List[str] = None) -> List[dict]:  # pragma: no cover
    while True:
        events, epoch_time_to_continue_fetch = get_events_command(client=client,
                                                                  total_events_to_fetch=events_limit,
                                                                  since=last_run_after,
                                                                  last_object_ids=last_object_ids)
        if epoch_time_to_continue_fetch == 0:
            break

        sleep_time = abs(epoch_time_to_continue_fetch - start_time_epoch)
        if sleep_time and sleep_time < FETCH_TIME_LIMIT:
            demisto.debug(f'Will try fetch again in: {sleep_time},\
                as a result of 429 Too Many Requests HTTP status.')
            time.sleep(sleep_time)  # pylint: disable=E9003
        else:
            break
    return events


def main():  # pragma: no cover
    try:
        start_time_epoch = int(time.time())
        demisto_params = demisto.params()
        demisto_args = demisto.args()
        events_limit = int(demisto_params.get('limit', 1000))
        demisto.debug(f'max_events_to_fetch={events_limit}')
        api_key = demisto_params['api_key']['password']
        verify_certificate = not demisto_params.get('insecure', True)
        base_url = demisto_params['url']
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate)
        command = demisto.command()
        demisto.debug(f'Command being called is {command}')
        after: datetime
        if command == 'test-module':
            after = cast(datetime, dateparser.parse('1 hour'))
            get_events_command(client, events_limit, since=after.isoformat())
            demisto.results('ok')

        if command == 'okta-get-events':
            after = cast(datetime, dateparser.parse(demisto_args.get('from_date').strip()))
            events, _ = get_events_command(client, events_limit, since=after.isoformat())
            command_results = CommandResults(
                readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)
            should_push_events = argToBoolean(demisto_args.get('should_push_events', 'false'))
            if should_push_events:
                send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            after = cast(datetime, dateparser.parse(demisto_params['after'].strip()))
            last_run = demisto.getLastRun()
            last_object_ids = last_run.get('ids')
            if 'after' not in last_run:
                last_run_after = after.isoformat()  # type: ignore
            else:
                last_run_after = last_run['after']
            events = fetch_events(client, start_time_epoch, events_limit,
                                  last_run_after=last_run_after, last_object_ids=last_object_ids)
            demisto.debug(f'sending_events_to_xsiam: {len(events)}')
            send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(get_last_run(events, last_run_after))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
