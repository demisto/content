import demistomock as demisto
from CommonServerPython import *

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

VENDOR = 'fireeye'
PRODUCT = 'etp'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%f%zZ'
LOG_LINE = f"{VENDOR}_{PRODUCT}:"
DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_MAX_FETCH = 1000
CALCULATED_MAX_FETCH = 5000
DEFAULT_LIMIT = 10
DEFAULT_URL = 'https://etp.us.fireeye.com'
DATEPARSER_SETTINGS = {
    'RETURN_AS_TIMEZONE_AWARE': True,
    'TIMEZONE': 'UTC',
}

''' Fetch Events Classes'''
LAST_RUN = 'Last Run'


class EventType:
    def __init__(self, name: str, max_fetch: int, api_request_max: int = DEFAULT_MAX_FETCH, **kwargs) -> None:
        self.name = name
        self.client_max_fetch = max_fetch
        self.api_max = api_request_max
        for name, val in kwargs.items():
            self.__setattr__(str(name), val)


EVENT_TYPES = [
    EventType("email_trace", 300, outbound=False, api_request_max=300),
    EventType("activity_log", 500, api_request_max=500),
    EventType("alerts", 200, outbound=False, api_request_max=200)
]
OUTBOUND_EVENT_TYPES = [
    EventType("email_trace_outbound", 300, outbound=True, api_request_max=300),
    EventType("alerts_outbound", 200, outbound=False, api_request_max=200)
]
ALL_EVENTS = EVENT_TYPES + OUTBOUND_EVENT_TYPES

''' CLIENT '''


class Client(BaseClient):  # pragma: no cover
    def __init__(
        self,
        base_url: str,
        verify_certificate: bool,
        proxy: bool,
        api_key: str,
        outbound_traffic: bool,
        hide_sensitive: bool
    ) -> None:
        super().__init__(base_url, verify_certificate, proxy)
        self._headers = {'x-fireeye-api-key': api_key,
                         'Content-Type': 'application/json'}
        self.outbound_traffic = outbound_traffic
        self.hide_sensitive = hide_sensitive

    def get_alerts(self, from_LastModifiedOn: str, size: int, outbound: bool = False) -> dict:
        req_body = assign_params(
            traffic_type='outbound' if outbound else 'inbound',
            fromLastModifiedOn=from_LastModifiedOn,
            size=size
        )
        demisto.debug(f"{LOG_LINE} request sent: {from_LastModifiedOn=},{size=}, {outbound=}, {req_body=} ")
        res = self._http_request(
            method='POST',
            url_suffix='/api/v1/alerts',
            json_data=req_body
        )
        return res

    def get_email_trace(self, from_LastModifiedOn: str, size: int, outbound: bool = False) -> dict:
        req_body = assign_params(
            traffic_type='outbound' if outbound else 'inbound',
            size=size,
            attributes=assign_params(
                lastModifiedDateTime={'value': f'{from_LastModifiedOn}', 'filter': '>='},)
        )
        demisto.debug(f"{LOG_LINE} request sent: {from_LastModifiedOn=},{size=}, {outbound=}, {req_body=} ")

        res = self._http_request(
            method='POST',
            url_suffix='/api/v1/messages/trace',
            json_data=req_body
        )

        return res

    def get_activity_log(self, from_LastModifiedOn: str, size: int) -> dict:

        req_body = assign_params(
            size=size,
            attributes=assign_params(
                time={"from": f'{from_LastModifiedOn}',
                      }
            )
        )

        return self._http_request(
            method='POST',
            url_suffix='/api/v1/users/activitylogs/search',
            json_data=req_body

        )


class LastRun:
    class LastRunEvent:
        def __init__(self, start_time: datetime = None, last_ids: set[str] = None) -> None:
            self.last_ids = last_ids if last_ids else set()
            self.last_run_timestamp = start_time if start_time else datetime.now()

        def to_demisto_last_run(self) -> dict:
            return {'last_fetch_timestamp': self.last_run_timestamp.isoformat(),
                    'last_fetch_last_ids': list(self.last_ids)}

        def set_ids(self, ids: set[str] = set()) -> None:
            self.last_ids = set(ids) if isinstance(ids, list) else ids

    def __init__(self, event_types: list = None,
                 start_time: datetime = None,
                 last_ids: set = None) -> None:
        self.event_types = event_types if event_types else []
        if event_types:
            for event_type in event_types:
                setattr(self, event_type.name, self.LastRunEvent(start_time, last_ids))

    def get_last_run_event(self, event_name: str) -> LastRunEvent:
        return self.__getattribute__(event_name)

    def to_demisto_last_run(self) -> dict:
        if not self.event_types:
            return {}
        data = {
            LAST_RUN: {
                event_type.name: self.__getattribute__(
                    event_type.name).to_demisto_last_run() for event_type in self.event_types
            }
        }
        return data

    def add_event_type(self, event_type: str, start_time: datetime,
                       last_ids: set, event_types: list[EventType]) -> None:
        setattr(self, event_type, self.LastRunEvent(start_time, last_ids))
        event_type_from_str = next(filter(lambda x: x.name == event_type, event_types))
        self.event_types.append(event_type_from_str)


def get_last_run_from_dict(data: dict, event_types: list[EventType]) -> LastRun:

    new_last_run = LastRun()
    demisto.debug(f"{LOG_LINE} - Starting to parse last run from server: {str(data.get(LAST_RUN, 'Missing Last Run key'))}")

    for event_type in data.get(LAST_RUN, {}):
        demisto.debug(f"{LOG_LINE} - Parsing {event_type=}")

        time = datetime.fromisoformat(data[LAST_RUN].get(event_type, {}).get('last_fetch_timestamp'))
        ids = set(data[LAST_RUN].get(event_type, {}).get('last_fetch_last_ids', []))
        demisto.debug(f"{LOG_LINE} - found id and timestamp in data, adding. \n {ids=}, {time=}")

        new_last_run.add_event_type(event_type, time, ids, event_types)

    demisto.debug(f"{LOG_LINE} - last run was loaded successfully.")

    return new_last_run


class EventCollector:

    def __init__(self, client: Client, events_to_run_on: list[EventType] = None) -> None:
        self.client = client
        self.event_types_to_run_on = events_to_run_on if events_to_run_on else []

    def fetch_command(self, demisto_last_run: dict, first_fetch: datetime = None):
        events: list = []

        if not demisto_last_run:  # First fetch
            first_fetch = first_fetch if first_fetch else datetime.now()
            demisto.debug(f"{LOG_LINE} First fetch recognized, setting first_datetime to {first_fetch}")
            next_run = LastRun(self.event_types_to_run_on, start_time=first_fetch)

        else:
            demisto.debug(f"{LOG_LINE} previous fetch recognized. Loading demisto_last_run")

            next_run = get_last_run_from_dict(demisto_last_run, self.event_types_to_run_on)

            #  Getting new events
            demisto.debug(f"{LOG_LINE} Getting new events")

            for event_type in self.event_types_to_run_on:
                demisto.debug(f"{LOG_LINE} getting events of type {event_type.name}")

                next_run, new_events = self.get_events(event_type=event_type,
                                                       last_run=next_run
                                                       )
                events += new_events

        demisto.debug(f"{LOG_LINE} fetched {len(events)} to load. Setting last_run")

        next_run_dict = next_run.to_demisto_last_run()
        demisto.debug(f"{next_run_dict=}")

        return next_run_dict, events

    def get_events_command(self, start_time: datetime):
        events = []
        demisto.debug(f"{LOG_LINE}: running get-command")
        for event_type in self.event_types_to_run_on:
            _, new_events = self.get_events(event_type=event_type,
                                            last_run=LastRun(self.event_types_to_run_on, start_time),
                                            )
            events += new_events

        hr = tableToMarkdown(name='Test Event', t=events)
        return events, CommandResults(readable_output=hr)

    def fetch_alerts(self, event_type: EventType, start_time: datetime,
                     fetched_ids: set = set()) -> tuple[list[dict], datetime]:
        res_count = 0
        res: list[dict] = []
        results_left = True
        iso_start_time = start_time.isoformat()[:-3]  # formating to 3 digit's microseconds
        #  Running as long as we have not reached the amount of event or the time frame requested.
        while results_left and res_count < event_type.client_max_fetch:
            demisto.debug(f"{LOG_LINE} getting alerts: {results_left=}, {res_count=}, {start_time=}")
            current_batch = self.client.get_alerts(
                iso_start_time, min(event_type.api_max, event_type.client_max_fetch - res_count),
                self.client.outbound_traffic)
            demisto.debug(f"{LOG_LINE} got alerts full response: {current_batch=}")
            current_batch_data = current_batch.get("data", []) or []
            demisto.debug(f"{LOG_LINE} got {len(current_batch_data)} alerts from API")
            if current_batch_data:
                dedup_data = list(filter(lambda item: item.get("id") not in fetched_ids, current_batch_data))

                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} alerts from {len(current_batch_data)} found in API for {event_type.name}")
                    res.extend(dedup_data)
                    res_count += len(dedup_data)
                    fetched_ids = fetched_ids.union({item.get("id") for item in dedup_data})
                    # Getting last item's modification date, assuming asc order
                    iso_start_time = current_batch["meta"]["fromLastModifiedOn"]["end"]
                else:
                    results_left = False
            else:
                results_left = False

        return res, datetime.fromisoformat(iso_start_time)

    def fetch_activity_log(self, event_type: EventType, start_time: datetime,
                           fetched_ids: set = set()) -> tuple[list[dict], datetime]:
        res_count = 0
        res = []
        # formatting to iso z format without microsecconds due to api lack of support, api response should be already in format.
        iso_start_time = f"{datetime.strftime(start_time.astimezone(timezone.utc), '%Y-%m-%dT%H:%M:%S%z')}Z"
        results_left = True

        while results_left and res_count < event_type.client_max_fetch:
            demisto.debug(f"{LOG_LINE} getting user activity: {results_left=}, {res_count=}, {start_time=}")

            current_batch = self.client.get_activity_log(iso_start_time,
                                                         min(event_type.api_max, event_type.client_max_fetch - res_count))
            current_batch_data = current_batch.get("data", [])
            if current_batch_data:
                dedup_data = list(filter(lambda item: get_activity_log_id(item) not in fetched_ids, current_batch_data))
                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} alerts from {len(current_batch_data)} found in API for {event_type.name}")
                    res.extend(dedup_data)
                    res_count += len(dedup_data)

                    fetched_ids = fetched_ids.union({get_activity_log_id(item) for item in dedup_data})

                    # Getting last item's modification date, assuming desc order - not official info.
                    iso_start_time = demisto.get(current_batch_data[0], 'attributes.time')
                else:
                    results_left = False
            else:
                results_left = False

        return res, parse_special_iso_format(iso_start_time)

    def fetch_email_trace(self, event_type: EventType, start_time: datetime,
                          fetched_ids: set = set()) -> tuple[list[dict], datetime]:
        res_count = 0
        res = []
        iso_start_time = start_time.isoformat()[:-3]  # formating to 3 digit's microseconds
        results_left = True

        while results_left and res_count < event_type.client_max_fetch:
            demisto.debug(f"{LOG_LINE} getting trace: {results_left=}, {res_count=}, {start_time=}")

            current_batch = self.client.get_email_trace(iso_start_time,
                                                        min(event_type.api_max, event_type.client_max_fetch - res_count),
                                                        self.client.outbound_traffic)
            current_batch_data = current_batch.get("data", []) or []

            if current_batch_data:
                dedup_data = list(filter(lambda item: item.get("id") not in fetched_ids, current_batch_data))
                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} alerts from {len(current_batch_data)} found in API for {event_type.name}")
                    res.extend(dedup_data)
                    res_count += len(dedup_data)

                    fetched_ids = fetched_ids.union({item.get("id") for item in dedup_data})

                    # Getting last item's modification date, assuming asc order
                    iso_start_time = current_batch["meta"]["fromLastModifiedOn"]["end"][:-1]
                else:
                    results_left = False
            else:
                results_left = False

        return res, datetime.fromisoformat(iso_start_time)

    def get_events(self, event_type: EventType, last_run: LastRun) -> tuple[LastRun, list]:
        last_fetched_ids = last_run.get_last_run_event(event_type.name).last_ids
        last_fetch_time: datetime = last_run.get_last_run_event(event_type.name).last_run_timestamp
        # if not last_fetch_time.microsecond:
        demisto.debug(f"{LOG_LINE} {last_fetch_time=}, {last_fetched_ids=}")

        match event_type.name:
            case 'alerts' | 'alerts_outbound':
                events, last_run_time = self.fetch_alerts(event_type=event_type,
                                                          start_time=last_fetch_time,
                                                          fetched_ids=last_fetched_ids)
                last_run_ids: set[str] = {item.get("id", "") for item in filter(lambda item: datetime.fromisoformat(
                    demisto.get(item, "attributes.meta.last_modified_on")) == last_run_time, events)}
                format_alerts(events, self.client.hide_sensitive)

            case 'email_trace' | 'email_trace_outbound':

                events, last_run_time = self.fetch_email_trace(event_type=event_type,
                                                               start_time=last_fetch_time,
                                                               fetched_ids=last_fetched_ids)
                last_run_ids = {item.get("id", "") for item in filter(
                    lambda item: datetime.fromisoformat(
                        demisto.get(item, "attributes.lastModifiedDateTime")) == last_run_time, events)}

                format_email_trace(events, self.client.hide_sensitive)

            case 'activity_log':
                events, last_run_time = self.fetch_activity_log(event_type=event_type,
                                                                start_time=last_fetch_time,
                                                                fetched_ids=last_fetched_ids)
                last_run_ids = set(
                    map(get_activity_log_id, filter(
                        lambda item: parse_special_iso_format(demisto.get(item, "attributes.time")) == last_run_time, events)))

                format_activity_log(events)

            case _:
                raise DemistoException("Event's type format is undefined.")

        demisto.debug(f"{LOG_LINE} Got {len(events)} events to load with type {event_type.name}. Setting last_run")
        last_run.get_last_run_event(event_type.name).set_ids(last_run_ids)
        last_run.get_last_run_event(event_type.name).last_run_timestamp = last_run_time

        return last_run, events


def get_activity_log_id(event: dict) -> str:
    return f"{demisto.get(event, 'attributes.user_action')}-{demisto.get(event, 'attributes.time')}"


def set_events_max(event_names: list[str], new_max: int) -> None:
    events_to_update = list(filter(lambda x: x.name in event_names, ALL_EVENTS))
    for event_type in events_to_update:
        event_type.client_max_fetch = new_max


def parse_special_iso_format(datetime_str: str) -> datetime:
    """
    This API returns invalid date string that 'supports' ISO Z, such as: 2023-08-01T14:15:26+0000Z
    In reality, ISO Z should be able to handle microseconds and contains 'Z' *OR* ±00:00,
    and even that is used wrong (aka ±0000 instead of ±00:00)
    This function takes the not ISO-like string and converts it to datetime.
    It supports both existing and non-existing microseconds.
    """
    tz_index = None
    if datetime_str.endswith('Z') and '+' in datetime_str:
        datetime_str = datetime_str[:-1]
        tz_index = datetime_str.find("+")

    if "." in datetime_str:
        decimal_index = datetime_str.find(".")
        # getting length of milliseconds part, as API only return with 'Z' of both tz and 'Z'.
        end_index = tz_index if tz_index else len(datetime_str) - 1

        if len(datetime_str[decimal_index + 1: end_index]) < 6:
            datetime_str = f"{datetime_str[:decimal_index+1]}000{datetime_str[decimal_index+1:]}"
    try:

        return datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        # Perhaps the datetime has a whole number of seconds with no decimal
        # point. In that case, this will work:
        return datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S%z")


''' FORMAT FUNCTION '''


def format_alerts(events: list[dict], hide_sensitive: bool):
    for event_data in events:
        create_time = datetime.fromisoformat(demisto.get(event_data, 'attributes.meta.last_modified_on'))

        if create_time:
            event_data['_ENTRY_STATUS'] = 'modified' if datetime.fromisoformat(demisto.get(
                event_data, 'attributes.alert.timestamp')) < create_time else 'new'  # handle missing fields?
            event_data['_TIME'] = create_time.isoformat()
        else:
            demisto.info("API response corrupted, no value found in attributes.meta.last_modified_on.")
        event_data['event_type'] = 'alert'

        if hide_sensitive:
            if demisto.get(event_data, 'attributes.email.attachment'):
                event_data["attributes"]["email"]['attachment'] = "hidden data"

            if demisto.get(event_data, 'attributes.email.headers.subject'):
                event_data["attributes"]["email"]['headers']['subject'] = "hidden data"


def format_email_trace(events: list[dict], hide_sensitive: bool):
    for event_data in events:
        create_time = datetime.fromisoformat(demisto.get(event_data, 'attributes.lastModifiedDateTime'))
        if create_time:
            event_data['_ENTRY_STATUS'] = 'modified' if datetime.fromisoformat(demisto.get(
                event_data, 'attributes.acceptedDateTime')) < create_time else 'new'
            event_data['_TIME'] = create_time.isoformat()
        else:
            demisto.info("API response corrupted, no value found in attributes.meta.last_modified_on.")

        event_data['event_type'] = 'trace'

        if hide_sensitive:
            if event_data.get('included'):
                event_data["included"] = "hidden data"

            if demisto.get(event_data, 'attributes.subject'):
                event_data["attributes"]['subject'] = "hidden data"


def format_activity_log(events: list[dict]):
    for event_data in events:
        event_time = demisto.get(event_data, 'attributes.time')
        valid_event_time = f'{event_time[:-3]}:{event_time[-3:-1]}'  # Removing Z letter and adding ":" to get valid iso format
        create_time = datetime.fromisoformat(valid_event_time)
        event_data['_TIME'] = create_time.strftime(DATE_FORMAT) if create_time else None
        event_data['event_type'] = 'activity'


def test_module(client: Client, events_to_run_on: list[EventType]):
    try:
        collector = EventCollector(client, events_to_run_on)
        for event_type in collector.event_types_to_run_on:
            event_type.client_max_fetch = 1
            collector.get_events(event_type=event_type,
                                 last_run=LastRun(events_to_run_on, datetime.now() - timedelta(minutes=1)))
        return 'ok'
    except DemistoException as e:
        if e.res.status_code == 500:
            return 'Request to API failed, Please check your credentials'
        else:
            raise


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('credentials', {}).get('password', '')
    base_url = params.get('url', '').rstrip('/')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    outbound_traffic = argToBoolean(params.get('outbound_traffic', False))
    hide_sensitive = argToBoolean(params.get('hide_sensitive', True))

    last_run = demisto.getLastRun()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:

        # setting the max fetch on each event type
        set_events_max(['alerts', 'alerts_outbound'],
                       arg_to_number(args.get('limit') or params.get('alerts_max_fetch')) or DEFAULT_MAX_FETCH)
        set_events_max(['email_trace', 'email_trace_outbound'],
                       arg_to_number(args.get('limit') or params.get('email_trace_max_fetch')) or DEFAULT_MAX_FETCH)
        set_events_max(['activity_log'],
                       arg_to_number(args.get('limit') or params.get('activity_log_max_fetch')) or DEFAULT_MAX_FETCH)

        client = Client(
            base_url=base_url,
            verify_certificate=verify,
            proxy=proxy,
            api_key=api_key,
            outbound_traffic=outbound_traffic,
            hide_sensitive=hide_sensitive
        )

        events_to_run_on = EVENT_TYPES + OUTBOUND_EVENT_TYPES if outbound_traffic else EVENT_TYPES
        collector = EventCollector(client, events_to_run_on)
        demisto.debug(f"{LOG_LINE} events configured: {[e.name for e in events_to_run_on]}")

        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, collector.event_types_to_run_on)
            return_results(result)

        elif command == 'fireeye-etp-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events', ''))
            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '3 days'),
                required=True
            )
            assert isinstance(first_fetch_time, datetime)

            events, results = collector.get_events_command(start_time=first_fetch_time)
            return_results(results)

            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = collector.fetch_command(
                demisto_last_run=last_run
            )
            demisto.debug(f"{events=}")
            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
