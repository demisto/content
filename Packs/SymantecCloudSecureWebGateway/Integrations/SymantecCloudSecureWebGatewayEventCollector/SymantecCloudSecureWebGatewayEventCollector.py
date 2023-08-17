from typing import NamedTuple
import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from requests import Response
from zipfile import ZipFile, BadZipFile
from io import BytesIO
import gzip

disable_warnings()

VENDOR = "symantec"
PRODUCT = "swg"
REGEX_FOR_STATUS = re.compile(r"X-sync-status: (?P<status>.*?)(?=\\r\\n|$)")
REGEX_FOR_TOKEN = re.compile(r"X-sync-token: (?P<token>.*?)(?=\\r\\n|$)")


class LastRun(NamedTuple):
    start_date: str | None = None
    token: str | None = None
    time_of_last_fetched_event: str | None = None
    events_suspected_duplicates: list[str] | None = None


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify, proxy) -> None:
        headers: dict[str, str] = {"X-APIUsername": username, "X-APIPassword": password}
        super().__init__(
            base_url=base_url, verify=verify, proxy=proxy, headers=headers, timeout=180
        )

    def get_logs(self, params: dict[str, Any]):
        return self._http_request(
            method="GET",
            url_suffix="/reportpod/logs/sync",
            params=params,
            resp_type="response",
        )


""" HELPER FUNCTIONS """


def get_start_and_ent_date(
    args: dict[str, str], start_date: str | None
) -> tuple[int, int]:
    now = datetime.now()

    start_date = int(
        start_date
        or date_to_timestamp(
            arg_to_datetime(args.get("since")) or (now - timedelta(minutes=1))
        )
    )

    end_date = date_to_timestamp(date_str_or_dt=now)

    return start_date, end_date


def get_status_and_token_from_res(response: Response) -> tuple[str, str]:
    status = ""
    token = ""
    if status_match := REGEX_FOR_STATUS.search(str(response.content)):
        status = status_match.groupdict().get("status", "")
    if token_match := REGEX_FOR_TOKEN.search(str(response.content)):
        token = token_match.groupdict().get("token", "")

    return status, token


def extract_logs_from_response(response: Response) -> list[bytes]:
    logs: list[bytes] = []
    try:
        with ZipFile(BytesIO(response.content)) as outer_zip:
            for file in outer_zip.infolist():
                if file.filename.lower().endswith(".gz"):
                    try:
                        with outer_zip.open(file) as nested_zip_file, gzip.open(
                            nested_zip_file, "rb"
                        ) as f:
                            logs.extend(f.readlines())
                    except Exception as e:
                        demisto.debug(
                            f"Crashed at the stage of opening the internal files on {file.filename} file, Error: {e}"
                        )
                else:
                    demisto.debug(
                        f"One of the internal files is not of gzip type, file name is {file.filename}"
                    )
    except BadZipFile as e:
        demisto.debug(
            f"The external file type is not of type ZIP, Error: {e}, the response.content is {BytesIO(response.content)}"
        )
        pass
    except Exception as e:
        raise ValueError(f"There is no specific error for the crash, Error: {e}")
    return logs


def is_first_fetch(last_run: dict[str, str | list[str]], args: dict[str, str]) -> bool:
    return ("start_date" not in last_run) and ("since" not in args)


def is_duplicate(
    id_: str,
    cur_time: str,
    time_of_last_fetched_event: str,
    events_suspected_duplicates: list[str],
) -> bool:
    if cur_time > time_of_last_fetched_event:
        return False
    return not (
        cur_time == time_of_last_fetched_event
        and id_ not in events_suspected_duplicates
    )


def organize_of_events(
    logs: list[bytes],
    token_expired: bool,
    time_of_last_fetched_event: str,
    events_suspected_duplicates: list[str],
) -> tuple[list[str], str, list[str]]:
    events: list[str] = []
    max_time = time_of_last_fetched_event
    max_values = events_suspected_duplicates

    for log in logs:
        event = log.decode()
        if event.startswith("#"):
            continue
        parts = event.split(" ")
        id_ = parts[-1]
        cur_time = f"{parts[1]} {parts[2]}"

        if token_expired and not (
            is_duplicate(
                id_,
                cur_time,
                time_of_last_fetched_event,
                events_suspected_duplicates,
            )
        ):
            continue
        if cur_time > max_time:
            max_time = cur_time
            max_values = [id_]
        elif cur_time == max_time:
            max_values.append(id_)
        events.append(event)

    return events, max_time, max_values


""" FETCH EVENTS """


def get_events_command(
    client: Client, args: dict[str, str], last_run_model: LastRun, is_first_fetch: bool
) -> tuple[list[str], LastRun]:
    """
    ...
    """
    logs: list[bytes] = []
    token_expired: bool = False

    start_date, end_date = get_start_and_ent_date(
        args=args, start_date=last_run_model.start_date
    )
    params: dict[str, Union[str, int]] = {
        "startDate": start_date,
        "endDate": end_date,
        "token": last_run_model.token or "none",
    }
    demisto.debug(
        f"start fetch from {start_date} to {end_date} with {last_run_model.token or 'none'}"
    )

    status = "more"
    while status != "done":
        try:
            res = client.get_logs(params=params)
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 410:
                demisto.debug(f"The token has expired: {e}")
                token_expired = True
                params["token"] = "none"
                continue
            elif e.res is not None and e.res.status_code == 423:
                demisto.debug(f"API access is blocked: {e}")
            elif e.res is not None and e.res.status_code == 429:
                demisto.debug(f"Crashed on limit of api calls: {e}")
            raise e

        status, params["token"] = get_status_and_token_from_res(res)
        demisto.debug(f"The status is {status}")
        if is_first_fetch:
            demisto.debug(
                "The current fetch is the first fetch, "
                "the collector ignores all events that return from the api, "
                "and will start collecting them from the next time onwards"
            )
            continue
        logs.extend(extract_logs_from_response(res))

    (
        events,
        time_of_last_fetched_event,
        events_suspected_duplicates,
    ) = organize_of_events(
        logs,
        token_expired,
        last_run_model.time_of_last_fetched_event or "",
        last_run_model.events_suspected_duplicates or [],
    )

    if time_of_last_fetched_event:
        start_date_for_next_fetch = date_to_timestamp(
            date_str_or_dt=time_of_last_fetched_event, date_format="%Y-%m-%d %H:%M:%S"
        )
    else:
        start_date_for_next_fetch = start_date

    new_last_run_model = LastRun(
        start_date=str(start_date_for_next_fetch),
        token=str(params["token"]),
        time_of_last_fetched_event=time_of_last_fetched_event,
        events_suspected_duplicates=events_suspected_duplicates,
    )

    demisto.debug(
        f"End fetch from {start_date} to {end_date} with {len(events)} events,"
        f"{time_of_last_fetched_event=} and {events_suspected_duplicates=}"
    )
    return events, new_last_run_model


def test_module(client: Client):
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "symantec-get-events":
            should_update_last_run = False
            events, _ = get_events_command(client, args, LastRun(**{}), False)
            t = [{"logs": event} for event in events]
            # By default return as an md table
            # when the argument `should_push_events` is set to true
            # will also be returned as events
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", t))
            )
        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            last_run = demisto.getLastRun()
            events, last_run_model = get_events_command(
                client, params, LastRun(**last_run), is_first_fetch(last_run, args)
            )
            last_run = last_run_model._asdict()
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{len(events)} events were pushed to XSIAM")

            if should_update_last_run:
                demisto.setLastRun(last_run)
                demisto.debug(f"set {last_run=}")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Symantec Web Security Service Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
