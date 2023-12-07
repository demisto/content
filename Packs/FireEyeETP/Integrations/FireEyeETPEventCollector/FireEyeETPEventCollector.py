import demistomock as demisto
from CommonServerPython import *
import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "fireeye"
PRODUCT = "etp"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
LOG_LINE = f"{VENDOR}_{PRODUCT}:"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 1000
CALCULATED_MAX_FETCH = 5000
DEFAULT_LIMIT = 10
DEFAULT_URL = "https://etp.us.fireeye.com"
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}

""" Fetch Events Classes"""
LAST_RUN = "Last Run"


class EventType:
    def __init__(
        self,
        name: str,
        max_fetch: int,
        api_request_max: int = DEFAULT_MAX_FETCH,
        **kwargs,
    ) -> None:
        self.name = name
        self.client_max_fetch = max_fetch
        self.api_max = api_request_max
        for name, val in kwargs.items():
            self.__setattr__(str(name), val)


EVENT_TYPES = [
    EventType("email_trace", 300, outbound=False, api_request_max=300),
    EventType("activity_log", 500, api_request_max=500),
    EventType("alerts", 200, outbound=False, api_request_max=200),
]
OUTBOUND_EVENT_TYPES = [
    EventType("email_trace_outbound", 300, outbound=True, api_request_max=300),
    EventType("alerts_outbound", 200, outbound=False, api_request_max=200),
]
ALL_EVENTS = EVENT_TYPES + OUTBOUND_EVENT_TYPES

""" CLIENT """


class Client(BaseClient):  # pragma: no cover
    def __init__(
        self,
        base_url: str,
        verify_certificate: bool,
        proxy: bool,
        api_key: str,
        outbound_traffic: bool,
        hide_sensitive: bool,
    ) -> None:
        super().__init__(base_url, verify_certificate, proxy)
        self._headers = {
            "x-fireeye-api-key": api_key,
            "Content-Type": "application/json",
        }
        self.outbound_traffic = outbound_traffic
        self.hide_sensitive = hide_sensitive

    def get_alerts(
        self, from_LastModifiedOn: str, size: int, outbound: bool = False
    ) -> dict:
        req_body = assign_params(
            traffic_type="outbound" if outbound else "inbound",
            fromLastModifiedOn=from_LastModifiedOn,
            size=size,
        )
        demisto.debug(
            f"{LOG_LINE} request sent: {from_LastModifiedOn=},{size=}, {outbound=}, {req_body=} "
        )
        res = self._http_request(
            method="POST", url_suffix="/api/v1/alerts", json_data=req_body
        )
        return res

    def get_email_trace(
        self, from_LastModifiedOn: str, size: int, outbound: bool = False
    ) -> dict:
        req_body = assign_params(
            traffic_type="outbound" if outbound else "inbound",
            size=size,
            attributes=assign_params(
                lastModifiedDateTime={
                    "value": f"{from_LastModifiedOn}",
                    "filter": ">=",
                },
            ),
        )
        demisto.debug(
            f"{LOG_LINE} request sent: {from_LastModifiedOn=},{size=}, {outbound=}, {req_body=} "
        )

        res = self._http_request(
            method="POST", url_suffix="/api/v1/messages/trace", json_data=req_body
        )

        return res

    def get_activity_log(
        self, from_LastModifiedOn: str, size: int, to_LastModifiedOn: str
    ) -> dict:
        time = {"from": from_LastModifiedOn}
        if to_LastModifiedOn:
            time["to"] = to_LastModifiedOn

        req_body = assign_params(
            size=size,
            attributes=assign_params(time=time),
        )

        return self._http_request(
            method="POST",
            url_suffix="/api/v1/users/activitylogs/search",
            json_data=req_body,
        )


class LastRun:
    class LastRunEvent:
        def __init__(
            self, start_time: datetime | None = None, last_ids: set[str] | None = None
        ) -> None:
            self.last_ids = last_ids if last_ids else set()
            self.last_run_timestamp = start_time if start_time else datetime.now()

        def to_demisto_last_run(self) -> dict:
            return {
                "last_fetch_timestamp": self.last_run_timestamp.isoformat(),
                "last_fetch_last_ids": list(self.last_ids),
            }

        def set_ids(self, ids: set[str] = set()) -> None:
            self.last_ids = set(ids) if isinstance(ids, list) else ids

    def __init__(
        self,
        event_types: list | None = None,
        start_time: datetime | None = None,
        last_ids: set | None = None,
    ) -> None:
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
                    event_type.name
                ).to_demisto_last_run()
                for event_type in self.event_types
            }
        }
        return data

    def add_event_type(
        self,
        event_type: str,
        start_time: datetime,
        last_ids: set,
        event_types: list[EventType],
    ) -> None:
        setattr(self, event_type, self.LastRunEvent(start_time, last_ids))
        event_type_from_str = next(filter(lambda x: x.name == event_type, event_types))
        self.event_types.append(event_type_from_str)


def get_last_run_from_dict(data: dict, event_types: list[EventType]) -> LastRun:
    new_last_run = LastRun()
    demisto.debug(
        f"{LOG_LINE} - Starting to parse last run from server: {str(data.get(LAST_RUN, 'Missing Last Run key'))}"
    )

    for event_type in data.get(LAST_RUN, {}):
        demisto.debug(f"{LOG_LINE} - Parsing {event_type=}")

        time = datetime.fromisoformat(
            data[LAST_RUN].get(event_type, {}).get("last_fetch_timestamp")
        )
        ids = set(data[LAST_RUN].get(event_type, {}).get("last_fetch_last_ids", []))
        demisto.debug(
            f"{LOG_LINE} - found id and timestamp in data, adding. \n {ids=}, {time=}"
        )

        new_last_run.add_event_type(event_type, time, ids, event_types)

    demisto.debug(f"{LOG_LINE} - last run was loaded successfully.")

    return new_last_run


class EventCollector:
    def __init__(
        self, client: Client, events_to_run_on: None | list[EventType] = None
    ) -> None:
        self.client = client
        self.event_types_to_run_on = events_to_run_on if events_to_run_on else []

    def fetch_command(
        self, demisto_last_run: dict, first_fetch: None | datetime = None
    ):
        events: list = []

        if not demisto_last_run:  # First fetch
            first_fetch = first_fetch if first_fetch else datetime.now()
            demisto.debug(
                f"{LOG_LINE} First fetch recognized, setting first_datetime to {first_fetch}"
            )
            next_run = LastRun(
                self.event_types_to_run_on, start_time=first_fetch, last_ids=set()
            )

        else:
            demisto.debug(
                f"{LOG_LINE} previous fetch recognized. Loading demisto_last_run"
            )

            next_run = get_last_run_from_dict(
                demisto_last_run, self.event_types_to_run_on
            )

            #  Getting new events
            demisto.debug(f"{LOG_LINE} Getting new events")

            for event_type in self.event_types_to_run_on:
                demisto.debug(f"{LOG_LINE} getting events of type {event_type.name}")
                if event_type.client_max_fetch > 0:
                    next_run, new_events = self.get_events(
                        event_type=event_type, last_run=next_run
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
            if event_type.client_max_fetch > 0:
                _, new_events = self.get_events(
                    event_type=event_type,
                    last_run=LastRun(
                        self.event_types_to_run_on, start_time, last_ids=set()
                    ),
                )
                events += new_events

        hr = tableToMarkdown(name="Test Event", t=events)
        return events, CommandResults(readable_output=hr)

    def fetch_alerts(
        self, event_type: EventType, start_time: datetime, fetched_ids: set = set()
    ) -> tuple[list[dict], datetime]:
        res_count = 0
        res: list[dict] = []
        results_left = True
        iso_start_time = parse_date_for_api_3_digits(start_time)

        #  Running as long as we have not reached the amount of event or the time frame requested.
        while results_left and res_count < event_type.client_max_fetch:
            demisto.debug(
                f"{LOG_LINE} getting alerts: {results_left=}, {res_count=}, {start_time=}"
            )
            current_batch = self.client.get_alerts(
                iso_start_time,
                min(event_type.api_max, event_type.client_max_fetch - res_count),
                self.client.outbound_traffic,
            )
            current_batch_data = current_batch.get("data", []) or []
            demisto.debug(f"{LOG_LINE} got {len(current_batch_data)} alerts from API")
            if current_batch_data:
                dedup_data = list(
                    filter(
                        lambda item: item.get("id") not in fetched_ids,
                        current_batch_data,
                    )
                )

                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} alerts from {len(current_batch_data)} found in API for {event_type.name}"
                    )
                    res.extend(dedup_data)
                    res_count += len(dedup_data)
                    fetched_ids = fetched_ids.union(
                        {item.get("id") for item in dedup_data}
                    )
                    # Getting last item's modification date, assuming asc order
                    iso_start_time = current_batch["meta"]["fromLastModifiedOn"]["end"]
                else:
                    results_left = False
            else:
                results_left = False

        return res, parse_special_iso_format(iso_start_time)

    def fetch_activity_log(
        self, event_type: EventType, start_time: datetime, fetched_ids: set = set()
    ) -> tuple[list[dict], str]:
        res = []

        results_left = True
        iso_end_time = ""
        demisto.debug(f"Converting {start_time=} to string")
        # formatting to iso z format without microseconds due to api lack of support,
        # api response should be already in this format.
        iso_start_time = f"{datetime.strftime(start_time.astimezone(timezone.utc), '%Y-%m-%dT%H:%M:%S%z')}Z"

        while results_left and ((not iso_end_time) or iso_end_time >= iso_start_time):
            demisto.debug(
                f"{LOG_LINE} getting user activity: {results_left=}, {iso_start_time=}, {iso_end_time=}"
            )
            current_batch = self.client.get_activity_log(
                from_LastModifiedOn=iso_start_time,
                size=event_type.api_max,
                to_LastModifiedOn=iso_end_time,
            )
            current_batch_data = current_batch.get("data", [])

            if current_batch_data:
                dedup_data = [
                    item
                    for item in current_batch_data
                    if get_activity_log_id(item) not in fetched_ids
                ]
                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} non duplicates alerts from\
                            {len(current_batch_data)} found in API for {event_type.name}"
                    )
                    res.extend(dedup_data)

                    fetched_ids = fetched_ids.union(
                        {get_activity_log_id(item) for item in dedup_data}
                    )

                    # Last run of pagination, avoiding endless loop if all page has the same time.
                    # We do not have other eay to handle this case.
                    if iso_end_time == iso_start_time:
                        demisto.debug(
                            "Got equal start and end time, this was the last page."
                        )
                        results_left = False

                    # Getting last item's modification date, Assuming Asc order.
                    # We have to format as the response are not have to be in invalid format
                    end_time = parse_special_iso_format(
                        dedup_data[-1]["attributes"]["time"]
                    )
                    iso_end_time = f"{datetime.strftime(end_time.astimezone(timezone.utc), '%Y-%m-%dT%H:%M:%S%z')}Z"

                else:
                    demisto.debug(
                        "Avoiding infinite loop due to multiple alerts in the same time blocking pagination."
                    )
                    results_left = False
            else:
                results_left = False

        # Got all results from API, taking only the last #max_limit.
        if len(res) > event_type.client_max_fetch:
            res = res[-event_type.client_max_fetch:]

        # Getting last_run_time
        next_run = res[0]["attributes"]["time"] if res else iso_start_time

        return res, next_run

    def fetch_email_trace(
        self, event_type: EventType, start_time: datetime, fetched_ids: set = set()
    ) -> tuple[list[dict], datetime]:
        res_count = 0
        res = []

        # getting start time, formatting to 3 digit's microseconds.
        iso_start_time = parse_date_for_api_3_digits(start_time)

        results_left = True

        while results_left and res_count < event_type.client_max_fetch:
            demisto.debug(
                f"{LOG_LINE} getting trace: {results_left=}, {res_count=}, {start_time=}"
            )

            current_batch = self.client.get_email_trace(
                iso_start_time,
                min(event_type.api_max, event_type.client_max_fetch - res_count),
                self.client.outbound_traffic,
            )
            current_batch_data = current_batch.get("data", []) or []

            if current_batch_data:
                dedup_data = list(
                    filter(
                        lambda item: item.get("id") not in fetched_ids,
                        current_batch_data,
                    )
                )
                if dedup_data:
                    demisto.debug(
                        f"Fetching {len(dedup_data)} alerts from {len(current_batch_data)} \
                            found in API for {event_type.name}"
                    )
                    res.extend(dedup_data)
                    res_count += len(dedup_data)

                    fetched_ids = fetched_ids.union(
                        {item.get("id") for item in dedup_data}
                    )

                    # Getting last item's modification date, assuming asc order
                    iso_start_time = current_batch["meta"]["fromLastModifiedOn"]["end"][
                        :-1
                    ]
                else:
                    results_left = False
            else:
                results_left = False

        return res, parse_special_iso_format(iso_start_time)

    def get_events(
        self, event_type: EventType, last_run: LastRun
    ) -> tuple[LastRun, list]:
        last_fetched_ids = last_run.get_last_run_event(event_type.name).last_ids
        last_fetch_time: datetime = last_run.get_last_run_event(
            event_type.name
        ).last_run_timestamp
        # if not last_fetch_time.microsecond:
        demisto.debug(f"{LOG_LINE} {last_fetch_time=}, {last_fetched_ids=}")

        match event_type.name:
            case "alerts" | "alerts_outbound":
                events, last_run_time = self.fetch_alerts(
                    event_type=event_type,
                    start_time=last_fetch_time,
                    fetched_ids=last_fetched_ids,
                )
                last_run_ids: set[str] = {
                    item.get("id", "")
                    for item in filter(
                        lambda item: datetime.fromisoformat(
                            item["attributes"]["meta"]["last_modified_on"]
                        )
                        == last_run_time,
                        events,
                    )
                }
                format_alerts(events, self.client.hide_sensitive)

            case "email_trace" | "email_trace_outbound":
                events, last_run_time = self.fetch_email_trace(
                    event_type=event_type,
                    start_time=last_fetch_time,
                    fetched_ids=last_fetched_ids,
                )
                last_run_ids = {
                    item.get("id", "")
                    for item in filter(
                        lambda item: datetime.fromisoformat(
                            item["attributes"]["lastModifiedDateTime"]
                        )
                        == last_run_time,
                        events,
                    )
                }

                format_email_trace(events, self.client.hide_sensitive)

            case "activity_log":
                events, next_run_time = self.fetch_activity_log(
                    event_type=event_type,
                    start_time=last_fetch_time,
                    fetched_ids=last_fetched_ids,
                )
                last_run_ids = {
                    get_activity_log_id(item)
                    for item in events
                    if demisto.get(item, "attributes.time") == next_run_time
                }

                format_activity_log(events)
                last_run_time = parse_special_iso_format(next_run_time)
            case _:
                raise DemistoException("Event's type format is undefined.")

        demisto.debug(
            f"{LOG_LINE} Got {len(events)} events to load with type {event_type.name}. Setting last_run"
        )
        last_run.get_last_run_event(event_type.name).set_ids(last_run_ids)
        last_run.get_last_run_event(event_type.name).last_run_timestamp = last_run_time

        return last_run, events


def get_activity_log_id(event: dict) -> str:
    return f"{demisto.get(event, 'attributes.user_action')}- \
            {demisto.get(event, 'attributes.user_email_id')}- \
            {demisto.get(event, 'attributes.time')}"


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

    def fix_date_format(datetime_str: str):
        """" Gets a time string according to the API standard, fix it and parse it.

        Args:
            datetime_str (str): A string representing time (Might be ISO, ISO Z).

        Raises:
            DemistoException: _description_

        Returns:
            datetime: A datetime object parsed from the fixed datetime string.
        """
        tz_index = None
        demisto.debug(f"Fixing format of datetime string: {datetime_str}.")
        if datetime_str.endswith("Z") and "+" in datetime_str:
            datetime_str = datetime_str[:-1]
            tz_index = datetime_str.find("+")

        if "." in datetime_str:
            decimal_index = datetime_str.find(".")
            # getting length of milliseconds part, as API only return with 'Z' of both tz and 'Z'.
            end_index = tz_index if tz_index else len(datetime_str) - 1

            if len(datetime_str[decimal_index + 1: end_index]) < 6:
                datetime_str = f"{datetime_str[:decimal_index+1]}000{datetime_str[decimal_index+1:]}"
        date_obj = dateparser.parse(datetime_str, settings={"TIMEZONE": "UTC"})

        if not date_obj:
            demisto.debug(f"Failed to parse date after changes: {datetime_str}")
            raise DemistoException(
                "Failed parsing date. Check logs for more information."
            )
        return date_obj

    try:
        date_obj = dateparser.parse(datetime_str, settings={"TIMEZONE": "UTC"})
        date_obj = date_obj if date_obj else fix_date_format(datetime_str)

        # The API sometimes returns dates without full data, causing the parsing to fail.
        return date_obj

    except Exception as e:
        demisto.debug(f"Failed parsing {datetime_str}. Error={str(e)}.")
        raise e


def parse_date_for_api_3_digits(date_to_parse: datetime) -> str:
    """
    Returns str representation the API can deal with.
    """
    demisto.debug(f"Parsing {date_to_parse=} to API format")
    # getting start time, formatting to 3 digit's microseconds.
    iso_start_time_splitted = date_to_parse.isoformat().split(".")

    # Dealing with 3 digit AND 6 digit microseconds if exists
    # since .123 is .000123 in ISO.
    # If no microseconds found, add .000 instead
    micro_sec = (
        str(int(iso_start_time_splitted[1]))[:3]
        if len(iso_start_time_splitted) == 2
        else "000"
    )
    return f"{iso_start_time_splitted[0]}.{micro_sec}"


""" FORMAT FUNCTION """


def format_alerts(events: list[dict], hide_sensitive: bool):
    for event_data in events:
        create_time = datetime.fromisoformat(
            event_data["attributes"]["meta"].get("last_modified_on")
        )

        if create_time:
            event_data["_ENTRY_STATUS"] = (
                "modified"
                if datetime.fromisoformat(
                    event_data["attributes"]["alert"].get("timestamp")
                )
                < create_time
                else "new"
            )
            event_data["_TIME"] = create_time.isoformat()
        else:
            demisto.info(
                "API response corrupted, no value found in attributes.meta.last_modified_on."
            )
        event_data["event_type"] = "alert"

        if hide_sensitive:
            if demisto.get(event_data, "attributes.email.attachment"):
                event_data["attributes"]["email"]["attachment"] = "hidden data"

            if demisto.get(event_data, "attributes.email.headers.subject"):
                event_data["attributes"]["email"]["headers"]["subject"] = "hidden data"


def format_email_trace(events: list[dict], hide_sensitive: bool):
    for event_data in events:
        create_time = datetime.fromisoformat(
            event_data["attributes"].get("lastModifiedDateTime")
        )
        if create_time:
            event_data["_ENTRY_STATUS"] = (
                "modified"
                if datetime.fromisoformat(
                    event_data["attributes"].get("acceptedDateTime")
                )
                < create_time
                else "new"
            )
            event_data["_TIME"] = create_time.isoformat()
        else:
            demisto.info(
                "API response corrupted, no value found in attributes.meta.last_modified_on."
            )

        event_data["event_type"] = "trace"

        if hide_sensitive:
            if event_data.get("included"):
                event_data["included"] = "hidden data"

            if demisto.get(event_data, "attributes.subject"):
                event_data["attributes"]["subject"] = "hidden data"


def format_activity_log(events: list[dict]):
    for event_data in events:
        event_time = event_data["attributes"]["time"]
        # Removing Z letter and adding ":" to get valid iso format
        valid_event_time = f"{event_time[:-3]}:{event_time[-3:-1]}"
        create_time = datetime.fromisoformat(valid_event_time)
        event_data["_TIME"] = create_time.strftime(DATE_FORMAT) if create_time else None
        event_data["event_type"] = "activity"


def test_module(client: Client, events_to_run_on: list[EventType]):
    try:
        collector = EventCollector(client, events_to_run_on)
        for event_type in collector.event_types_to_run_on:
            event_type.client_max_fetch = 1
            collector.get_events(
                event_type=event_type,
                last_run=LastRun(
                    events_to_run_on,
                    datetime.now() - timedelta(minutes=1),
                    last_ids=set(),
                ),
            )
        return "ok"
    except DemistoException as e:
        if e.res.status_code == 500:  # type: ignore
            return "Request to API failed, Please check your credentials"
        else:
            raise


def _get_max_events_to_fetch(params_max_fetch: str | int, arg_limit: str | int) -> int:
    """Gets the maximum number of events to fetch, supporting limit of 0.

    Checks the configured max fetch specific to the log type, and the limit argument from a command.
    If a limit argument exists, it will override the max_fetch.
    If neither are found, uses the default limit.

    Args:
        params_max_fetch (str): A limit for the log type.
        arg_limit (str): A general limit.

    Returns:
        int: The maximum number of events to fetch.

    Raises:
        ValueError: If the limit is not a valid integer.
    """
    try:
        limit_param = (
            DEFAULT_MAX_FETCH
            if params_max_fetch in ["", None]
            else int(params_max_fetch)
        )

        limit_arg = None if arg_limit in ["", None] else int(arg_limit)
        val = limit_arg if limit_arg is not None else limit_param

        return int(val)

    except ValueError:
        raise ValueError("Please provide a valid integer value for a fetch limit.")


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    api_key = params.get("credentials", {}).get("password", "")
    base_url = params.get("url", "").rstrip("/")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    outbound_traffic = argToBoolean(params.get("outbound_traffic", False))
    hide_sensitive = argToBoolean(params.get("hide_sensitive", True))

    last_run = demisto.getLastRun()

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        # setting the max fetch on each event type
        set_events_max(
            ["alerts", "alerts_outbound"],
            _get_max_events_to_fetch(
                params.get("alerts_max_fetch", DEFAULT_MAX_FETCH), args.get("limit", "")
            ),
        )
        set_events_max(
            ["email_trace", "email_trace_outbound"],
            _get_max_events_to_fetch(
                params.get("email_trace_max_fetch", DEFAULT_MAX_FETCH),
                args.get("limit", ""),
            ),
        )
        set_events_max(
            ["activity_log"],
            _get_max_events_to_fetch(
                params.get("activity_log_max_fetch", DEFAULT_MAX_FETCH),
                args.get("limit", ""),
            ),
        )

        client = Client(
            base_url=base_url,
            verify_certificate=verify,
            proxy=proxy,
            api_key=api_key,
            outbound_traffic=outbound_traffic,
            hide_sensitive=hide_sensitive,
        )

        events_to_run_on = (
            EVENT_TYPES + OUTBOUND_EVENT_TYPES if outbound_traffic else EVENT_TYPES
        )
        collector = EventCollector(client, events_to_run_on)
        demisto.debug(
            f"{LOG_LINE} events configured: {[e.name for e in events_to_run_on]}"
        )

        demisto.debug(f"Command being called is {command}")
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, collector.event_types_to_run_on)
            return_results(result)

        elif command == "fireeye-etp-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events", ""))
            first_fetch_time = arg_to_datetime(
                arg=params.get("first_fetch", "30 days"), required=True
            )
            assert isinstance(first_fetch_time, datetime)

            events, results = collector.get_events_command(start_time=first_fetch_time)
            return_results(results)

            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = collector.fetch_command(demisto_last_run=last_run)
            demisto.debug(f"{events=}")
            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
