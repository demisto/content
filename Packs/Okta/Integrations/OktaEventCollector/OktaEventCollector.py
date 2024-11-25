from http import HTTPStatus
from typing import cast
from dateutil.parser import parse
from CommonServerPython import *

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

    def get_events(self, since: int, limit: int = FETCH_LIMIT, next_link_url: str = ''):
        if next_link_url:
            return self._http_request(full_url=next_link_url, method='GET', headers=self._headers, resp_type='response')
        else:
            params = {
                "sortOrder": "ASCENDING",
                "since": since,
                "limit": limit,
            }
            return self._http_request(url_suffix='/api/v1/logs', method='GET', headers=self._headers, params=params,
                                      resp_type='response')


def get_events_command(client: Client, total_events_to_fetch, since,
                       last_object_ids: list[str] = [], next_link: str = '') -> tuple[list[dict], int, str]:
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
    should_continue = True
    while len(stored_events) < total_events_to_fetch and should_continue:
        demisto.debug(f"stored_events collected: {len(stored_events)}")
        try:
            if next_link:
                demisto.debug("Running get_events using next_link")
                response = client.get_events(since=since, limit=num_of_events_to_fetch, next_link_url=next_link)  # type: ignore
            else:
                demisto.debug("Running get_events using since")
                response = client.get_events(since=since, limit=num_of_events_to_fetch)  # type: ignore

            if events := json.loads(response.text):
                demisto.debug(f'received {len(events)} number of events.')
                if len(events) < num_of_events_to_fetch:
                    demisto.debug(f"Number of events collected is smaller than: {num_of_events_to_fetch} \
                        will stop after current fetch.")
                    should_continue = False
                since = events[-1]['published']
                if last_object_ids:
                    events = remove_duplicates(events, last_object_ids)  # type: ignore
                    demisto.debug(f'Number of events after dedup {len(events)}')
                if not events:
                    demisto.debug('Events are empty after dedup - will break. Resetting next_link token.')
                    next_link = ''
                    break
                stored_events.extend(events)
            else:
                demisto.debug('Didnt receive any events from the api. Resetting next_link token.')
                next_link = ''
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
                return stored_events, int(res.headers['x-rate-limit-reset']), next_link
            return stored_events, 0, next_link
        except Exception as exc:
            demisto.error(f'Unexpected error.\n{traceback.format_exc()}')
            if len(stored_events) == 0:
                raise exc
            return stored_events, 0, next_link

        if url := response.links.get('next'):
            next_link = url.get('url')
            demisto.debug("next next_link url found and set as current next_link")
        else:
            next_link = ''
            demisto.debug("next_link set to empty value")

    return stored_events, 0, next_link


def remove_duplicates(events: list, ids: list) -> list:
    """
    Remove object duplicates by the uuid of the object
    """
    return [event for event in events if event['uuid'] not in ids]


def get_last_run(events: List[dict], last_run_after, next_link) -> dict:
    """
    Build the last_run dictionary for the next fetch:
        it returns 3 keys:
        - after: the time to query from.
        - ids: a list of ids to prevent duplications.
        - next_link: a string representing the next request link if available, or an empty string if not.
    """
    ids = []
    # gets the last event time
    last_time = events[-1].get('published') if events else last_run_after
    for event in reversed(events):
        if event.get('published') != last_time:
            break
        ids.append(event.get('uuid'))
    try:
        last_time = datetime.strptime(str(last_time).lower().replace('z', ''), '%Y-%m-%dt%H:%M:%S.%f')
    except ValueError:
        last_time = parse(str(last_time).lower().replace('z', ''))
    except Exception as e:  # General exception
        demisto.error(f'Unexpected error parsing published date from event: {e}')
        return {}

    return {'after': last_time.isoformat(), 'ids': ids, 'next_link': next_link}


def fetch_events(client: Client,
                 start_time_epoch: int,
                 events_limit: int,
                 last_run_after,
                 last_object_ids: list[str] = [],
                 next_link: str = '') -> tuple[list[dict], str]:
    while True:
        events, epoch_time_to_continue_fetch, next_link = get_events_command(client=client,
                                                                             total_events_to_fetch=events_limit,
                                                                             since=last_run_after,
                                                                             last_object_ids=last_object_ids,
                                                                             next_link=next_link)
        if epoch_time_to_continue_fetch == 0:
            break

        sleep_time = abs(epoch_time_to_continue_fetch - start_time_epoch)
        if sleep_time and sleep_time < FETCH_TIME_LIMIT:
            demisto.debug(f'Will try fetch again in: {sleep_time},\
                as a result of 429 Too Many Requests HTTP status.')
            time.sleep(sleep_time)  # pylint: disable=E9003
        else:
            break
    return events, next_link


def main():
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

        elif command == 'okta-get-events':
            after = cast(datetime, dateparser.parse(demisto_args.get('from_date').strip()))
            events, _, _ = get_events_command(client, events_limit, since=after.isoformat())
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
            next_link = last_run.get('next_link')
            if 'after' not in last_run:
                last_run_after = after.isoformat()  # type: ignore
            else:
                last_run_after = last_run['after']
            demisto.debug(f'{last_run=}')
            events, next_link = fetch_events(client, start_time_epoch, events_limit,
                                             last_run_after=last_run_after, last_object_ids=last_object_ids, next_link=next_link)
            demisto.debug(f'sending_events_to_xsiam: {len(events)}')
            send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)
            last_run = get_last_run(events, last_run_after, next_link)
            if last_run:
                demisto.setLastRun(get_last_run(events, last_run_after, next_link))
        else:
            return_error('Unrecognized command: ' + demisto.command())

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
