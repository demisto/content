from typing import NamedTuple
from collections.abc import Generator
import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from requests import Response
from zipfile import ZipFile, BadZipFile
from io import BytesIO
from gzip import GzipFile
import gzip
import pytz
from pathlib import Path
import tempfile
import os

disable_warnings()

VENDOR = "symantec_long_running"
PRODUCT = "swg_test"
FETCH_SLEEP = 30
FETCH_SLEEP_UNTIL_BEGINNING_NEXT_HOUR = 180
REGEX_FOR_STATUS = re.compile(r"X-sync-status: (?P<status>.*?)(?=\\r\\n|$)")
REGEX_FOR_TOKEN = re.compile(r"X-sync-token: (?P<token>.*?)(?=\\r\\n|$)")
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_CHUNK_SIZE_TO_READ = 1024 * 1024 * 150  # 150 MB
MAX_CHUNK_SIZE_TO_WRITE = 200 * (10**6)  # ~200 MB


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
        """
        API call in streaming to fetch events
        """
        return self._http_request(
            method="GET",
            url_suffix="/reportpod/logs/sync",
            params=params,
            resp_type="response",
            stream=True,
        )


""" HELPER FUNCTIONS """


def get_events_and_write_to_file_system(
    client: Client, params: dict, last_run_model: LastRun
) -> Path:
    """
    Writing the events that come from the API to a temporary file.
    Return:
        Path: the file path
    """
    with client.get_logs(params) as res, tempfile.NamedTemporaryFile(
        mode="wb", delete=False
    ) as tmp_file:
        # Sets the integration context with the last_run and tmp file path
        # if the run crashes before the tmp file is removed,
        # the subsequent run will begin by deleting the tmp file.
        set_integration_context(
            {"last_run": last_run_model._asdict(), "tmp_file_path": tmp_file.name}
        )
        demisto.debug(
            f"set the tmp file path to integration context {tmp_file.name}"
        )  # ????
        # Write the chunks from the response to the tmp file
        for chunk in res.iter_content(chunk_size=MAX_CHUNK_SIZE_TO_WRITE):
            tmp_file.write(chunk)

    file_size = get_file_size(Path(tmp_file.name))  # ????
    demisto.debug(f"File size is {file_size}")  # ????

    return Path(tmp_file.name)


def get_current_time_as_timestamp() -> int:
    now = datetime.now().astimezone(pytz.utc)
    return date_to_timestamp(now)


"""??? def is_more_than_half_an_hour_since_last_fetch(last_fetch: int, current_time: int):
    time_difference = datetime.fromtimestamp(current_time) - datetime.fromtimestamp(
        last_fetch
    )
    return time_difference > timedelta(minutes=30)"""


"""?def is_it_first_10_minutes_of_hour():
    # Get current time in UTC
    now = get_current_time_as_timestamp() / 1000
    return datetime.fromtimestamp(now).minute < 10"""


def get_start_and_ent_date(
    args: dict[str, str], start_date: str | None
) -> tuple[int, int]:
    """
    returns `start_date` and `end_date`

    Args:
        args (dict[str, str]): The args when the fetch manually activated by the `symantec-get-events` command
        start_date (str | None): start_date which is stored in the last_run object from the second run onwards

    Returns:
        tuple[int, int]: start_date, end_date
    """
    # set the end_date to the current time
    now = datetime.now().astimezone(pytz.utc)

    # If there is no `start_date` stored in the `last_run` object
    # and no start time in the args, sets the `start_date` to one
    # minute before the current time
    start_date = int(
        start_date
        or date_to_timestamp(
            arg_to_datetime(args.get("since")) or (now - timedelta(minutes=1))
        )
    )

    # convert the end_date to timestamp
    end_date = date_to_timestamp(date_str_or_dt=now)

    return start_date, end_date


def get_status_and_token_from_file_system(file_path: Path) -> tuple[str, str]:
    """
    Extracting the status and the next_token.
    """

    # Getting the file size to read only its end for the `status` and `next_token`
    file_size = get_file_size(file_path)
    read_size = 2000
    if file_size < read_size:  # In case the file is smaller than 2000 bytes
        read_size = file_size

    # Reading end of file
    with file_path.open("rb") as tmp_file:
        tmp_file.seek(file_size - read_size)
        end_file = tmp_file.read()

    # Extracting the `status` and the `next_token` by regex
    status = ""
    token = ""
    if status_match := REGEX_FOR_STATUS.search(str(end_file)):
        status = status_match.groupdict().get("status", "")
    if token_match := REGEX_FOR_TOKEN.search(str(end_file)):
        token = token_match.groupdict().get("token", "")

    return status, token


def get_file_size(file_path: Path) -> int:
    """Get size of file in bytes"""
    return file_path.stat().st_size


''' -- # def extract_logs_from_response2(response: Response) -> list[bytes]:
#     """
#     - Extracts the data from the zip file returned from the API
#       and then extracts the events from the gzip files into a list of events as bytes
#     - When there is no zip file returns an empty list
#     Args:
#         response (Response)
#     Returns:
#         list[bytes]: list of events as bytes
#     """
#     logs: list[bytes] = []
#     demisto.debug(f"size of the zip file: {len(response.content) / (1024 ** 2):.2f} MB")
#     # try:
#     #     # extract the ZIP file
#     #     with ZipFile(BytesIO(response.content)) as outer_zip:
#     #         # iterate all gzip files
#     #         for file in outer_zip.infolist():
#     #             # check if the file is gzip
#     #             if file.filename.lower().endswith(".gz"):
#     #                 try:
#     #                     with outer_zip.open(file) as nested_zip_file, gzip.open(
#     #                         nested_zip_file, "rb"
#     #                     ) as f:
#     #                         logs.extend(f.readlines())
#     #                 except Exception as e:
#     #                     demisto.debug(
#     #                         f"Crashed at the open the internal file {file.filename} file, Error: {e}"
#     #                     )
#     #             else:  # the file is not gzip
#     #                 demisto.debug(
#     #                     f"The {file.filename} file is not of gzip type"
#     #                 )
#     # except BadZipFile as e:
#     #     try:
#     #         # checks whether no events returned
#     #         if response.content.decode().startswith("X-sync"):
#     #             demisto.debug("No events returned from the api")
#     #         else:
#     #             demisto.debug(
#     #                 f"The external file type is not of type ZIP, Error: {e},"
#     #                 "the response.content is {}".format(response.content)
#     #             )
#     #     except Exception:
#     #         demisto.debug(
#     #             f"The external file type is not of type ZIP, Error: {e},"
#     #             "the response.content is {}".format(response.content)
#     #         )
#     # except Exception as e:
#     #     raise ValueError(f"There is no specific error for the crash, Error: {e}")
#     return logs'''


def get_the_last_row_that_incomplete(lines: list[bytes], file_size: int) -> bytes:
    """
    Args:
        lines (list[bytes]): The list of lines read so far.
        file_size (int): The total size of the file being read.

    Returns:
        bytes: The last incomplete line if one exists, empty bytes otherwise.
    """
    if lines and not lines[-1].endswith(b"\n") and file_size > 0:
        return lines[-1]
    return b""


'''def read_file_in_batches(
    f: GzipFile, file_size: int
) -> Generator[list[bytes], None, None]:
    """
    - Reads the gzipped file in batches to avoid loading the entire file into memory.
    - Splits the file data into lines, handling cases where a line spans batch boundaries.
    - Yields lists of lines for each batch.
    """
    remaining_last_line_part: bytes = b""
    while file_size > 0:
        # Get the chunk size for reading from the file,
        # limited to MAX_CHUNK_SIZE_TO_READ or less
        chunk = min(file_size, MAX_CHUNK_SIZE_TO_READ)

        # Subtracting the chunk to be read from the size of the file
        file_size -= chunk

        # Reads a chunk of data from the gzip file.
        try:
            raw_event_parts = f.read(chunk).splitlines()
        except Exception as e:
            demisto.debug(f"Error occurred while reading file: {e}")
            break

        # Concatenates any remaining last line from previous batch
        # to the first line of current batch to handle log lines split across batches
        if remaining_last_line_part:
            raw_event_parts[0] = remaining_last_line_part + raw_event_parts[0]

        # Checks if the last line is incomplete and saves it for concatenating
        # with the next batch. Yields the current batch without the incomplete line.
        # If no incomplete line, resets the remaining line part and yields the batch.
        if remaining_last_line_part := get_the_last_row_that_incomplete(
            raw_event_parts, file_size
        ):
            yield raw_event_parts[:-1]
        else:
            remaining_last_line_part = b""
            yield raw_event_parts'''


def extract_logs_from_zip_file(file_path: Path) -> Generator[list[bytes], None, None]:
    """Extracts logs from the response ZIP file.

    Iterates through the ZIP file, looking for gzipped files.
    Opens each gzipped file and reads it in batches,
    yielding a list of raw log lines for each batch.

    Args:
        file_path: Path to the ZIP file containing gzipped log files.

    Yields:
        list[bytes]: A batch of raw log lines read from a gzipped file.
    """
    demisto.debug(f"The file path: {file_path.name}")
    try:
        # extract the ZIP file
        with ZipFile(file_path, "r") as outer_zip:
            # iterate all gzip files
            for file in outer_zip.infolist():
                # check if the file is gzip
                if file.filename.lower().endswith(".gz"):
                    try:
                        with outer_zip.open(file) as nested_zip_file, gzip.open(
                            nested_zip_file, "rb"
                        ) as f:
                            file_size = get_size_gzip_file(f)
                            remaining_last_line_part: bytes = b""
                            while file_size > 0:
                                # Get the chunk size for reading from the file,
                                # limited to MAX_CHUNK_SIZE_TO_READ or less
                                chunk = min(file_size, MAX_CHUNK_SIZE_TO_READ)

                                # Subtracting the chunk to be read from the size of the file
                                file_size -= chunk

                                # Reads a chunk of data from the gzip file.
                                try:
                                    raw_event_parts = f.read(chunk).splitlines()
                                except Exception as e:
                                    demisto.debug(
                                        f"Error occurred while reading file: {e}"
                                    )
                                    break

                                # Concatenates any remaining last line from previous batch
                                # to the first line of current batch to handle log lines split across batches
                                if remaining_last_line_part:
                                    raw_event_parts[0] = (
                                        remaining_last_line_part + raw_event_parts[0]
                                    )

                                # Checks if the last line is incomplete and saves it for concatenating
                                # with the next batch. Yields the current batch without the incomplete line.
                                # If no incomplete line, resets the remaining line part and yields the batch.
                                if remaining_last_line_part := get_the_last_row_that_incomplete(
                                    raw_event_parts, file_size
                                ):
                                    yield raw_event_parts[:-1]
                                else:
                                    remaining_last_line_part = b""
                                    yield raw_event_parts
                    except Exception as e:
                        demisto.debug(
                            f"Crashed at the open the internal file {file.filename} file, Error: {e}"
                        )
                else:  # the file is not gzip
                    demisto.debug(f"The {file.filename} file is not of gzip type")
    except BadZipFile as e:
        # try:
        #     # checks whether no events returned
        #     if response.content.decode().startswith("X-sync"):
        #         demisto.debug("No events returned from the api")
        #     else:
        #         demisto.debug(
        #             f"The external file type is not of type ZIP, Error: {e},"
        #             # "the response.content is {}".format(response.content)
        #         )
        # except Exception:
        #     demisto.debug(
        #         f"The external file type is not of type ZIP, Error: {e},"
        #         # "the response.content is {}".format(response.content)
        #     )
        demisto.debug(f"The external file type is not of type ZIP, Error: {e}")
        raise ValueError(f"The external file type is not of type ZIP, Error: {e}")
    except Exception as e:
        raise ValueError(f"There is no specific error for the crash, Error: {e}")


def get_size_gzip_file(f: GzipFile) -> int:
    # Get size of gzip file by seeking to end and getting current position
    f.seek(0, os.SEEK_END)
    file_size = f.tell()
    demisto.debug(f"size of gzip file: {file_size / (1024 ** 2):.2f} MB")

    # Return the pointer position to the beginning of the file
    f.seek(0)

    return file_size


def is_first_fetch(last_run: dict[str, str | list[str]], args: dict[str, str]) -> bool:
    """
    Returns True if this fetch is a first fetch,
    Returns False if it is manually run by the `symantec-get-events` command or is a second fetch and later
    """
    return (
        not last_run.get("start_date") if isinstance(last_run, dict) else True
    ) and ("since" not in args)


def is_duplicate(
    id_: str,
    cur_time: str,
    time_of_last_fetched_event: str,
    events_suspected_duplicates: list[str],
) -> bool:
    """
    Checks whether the event already fetched if so returns True otherwise False

    Args:
        id_ (str): id of the event
        cur_time (str): the time of the event
        time_of_last_fetched_event (str): The time of the last event that already fetched
        events_suspected_duplicates (list[str]): The ids of all events from the latest time of the last fetch
    """

    # The event time is later than the late time of the last fetch
    if cur_time > time_of_last_fetched_event:
        return False

    # The time of the event is equal to the late time of the last fetch,
    # checks if its id is there is in the list of events that have already been fetched
    return not (
        cur_time == time_of_last_fetched_event
        and id_ not in events_suspected_duplicates
    )


"""def organize_of_events(
    logs: list[bytes],
    token_expired: bool,
    time_of_last_fetched_event: str,
    events_suspected_duplicates: list[str],
) -> tuple[list[str], str, list[str]]:
    events: list[str] = []
    max_time = time_of_last_fetched_event
    max_values = events_suspected_duplicates

    demisto.debug(f"The len of the events before filter {len(logs)}")
    for log in logs:
        event = log.decode()
        if event.startswith("#"):
            continue
        parts = event.split(" ")
        try:
            id_ = parts[-1]
        except Exception as e:
            demisto.debug(f"Error occurred while splitting event: {e} -> {event}")
        try:
            cur_time = f"{parts[1]} {parts[2]}"
        except Exception as e:
            demisto.debug(f"Error occurred while splitting event 1: {e} -> {event}")

        if token_expired and (
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

    demisto.debug(f"The len of the events after filter {len(events)}")
    return events, max_time, max_values"""


def parse_events(
    logs: list[bytes],
    token_expired: bool,
    time_of_last_fetched_event: str,
    events_suspected_duplicates: list[str],
    new_events_suspected_duplicates: list[str],
) -> tuple[list[str], str]:
    """Parses raw log events into a list of event strings.

    In case the token is expired it filters duplicate events based on timestamp and ID

    Args:
        logs: The raw log events as bytes
        token_expired: Whether the API token has expired
        time_of_last_fetched_event: The timestamp of the last fetched event
        events_suspected_duplicates: List of event IDs suspected as duplicates
        new_events_suspected_duplicates: Output list for new suspected dups

    Returns:
        events: List of parsed event strings
        max_time: Timestamp of latest event
    """
    events: list[str] = []
    max_time = time_of_last_fetched_event

    demisto.debug(f"The len of the events before filter {len(logs)}")
    for log in logs:
        # Decodes the raw log event bytes to a string
        event = log.decode()

        # each line that starts with '#' is a header, skip it
        if event.startswith("#"):
            continue

        parts = event.split(" ")

        # Parses Date and ID from log event.
        try:
            cur_time = f"{parts[1]} {parts[2]}"
            id_ = parts[-1]
        except Exception as e:
            raise ValueError(f"Error occurred while splitting event: {e} -> {event}")

        # In case that token is expired, checks if the event is a duplicate,
        # if so skips the event
        if token_expired and is_duplicate(
            id_=id_,
            cur_time=cur_time,
            time_of_last_fetched_event=time_of_last_fetched_event,
            events_suspected_duplicates=events_suspected_duplicates,
        ):
            continue

        # management the list of ids and the time of the last event
        if cur_time > max_time:
            new_events_suspected_duplicates.clear()
            new_events_suspected_duplicates.append(id_)
            max_time = cur_time
        elif cur_time == max_time:
            new_events_suspected_duplicates.append(id_)

        events.append(event)

    demisto.debug(f"The len of the events after filter {len(events)}")
    return events, max_time


""" FETCH EVENTS """


def get_events_command(
    client: Client,
    args: dict[str, str],
    last_run_model: LastRun,
    is_first_fetch: bool,
) -> LastRun:
    """ """
    time_of_last_fetched_event: str = last_run_model.time_of_last_fetched_event or ""
    events_suspected_duplicates: list[str] = (
        last_run_model.events_suspected_duplicates or []
    )
    new_events_suspected_duplicates: list[str] = []

    # Set the fetch times, where the `end_time` is consistently set to the current time.
    # The `start_time` is determined by the `last_run`,
    # and if it does not exist, it is set to one minute prior.
    start_date, end_date = get_start_and_ent_date(
        args=args, start_date=last_run_model.start_date
    )

    # Set the parameters for the API call
    params: dict[str, Union[str, int]] = {
        "startDate": start_date,
        "endDate": end_date,
        "token": last_run_model.token or "none",
    }

    # Make API call in streaming to fetch events and writing to a temporary file on the disk.
    status = "more"
    while status != "done":
        demisto.debug(f"In the meantime the {time_of_last_fetched_event=}")
        try:
            tmp_file_path = get_events_and_write_to_file_system(
                client, params, last_run_model
            )
        except DemistoException as e:
            try:
                if e.res is not None and e.res.status_code == 410:
                    demisto.debug(f"The token has expired: {e}")
                    token_expired = True
                    params["token"] = "none"
                    continue
                elif e.res is not None and e.res.status_code == 423:
                    demisto.debug(f"API access is blocked: {e}")
                    time.sleep(FETCH_SLEEP)
                    continue
                elif e.res is not None and e.res.status_code == 429:
                    demisto.debug(f"Crashed on limit of api calls: {e}")
                    time.sleep(FETCH_SLEEP)
                    continue
                else:
                    demisto.debug(f"Some ERROR: {e=}")
                    raise e
            except Exception as err:
                demisto.debug(f"Some ERROR: {e=} after the error: {err}")
                raise e
        except Exception as err:
            demisto.debug(f"Some ERROR: {err}")
            raise err
        status, new_token = get_status_and_token_from_file_system(tmp_file_path)

        # If status is "abort", deletes the tmp file
        # and continue the loop to fetch with the same parameters.
        if status == "abort":
            tmp_file_path.unlink()
            continue

        # Insert a new token into the parameters for the next API call
        params["token"] = new_token

        # Checks if this is the first fetch.
        # if so, ignores events returned from the API
        # and continues to the next fetch
        if is_first_fetch:
            demisto.debug(
                "The current fetch is the first fetch, "
                "the collector ignores all events that return from the api, "
                "and will start collecting them from the next time onwards"
            )
            continue

        # Extracts logs from the zip file downloaded from the API, parses the events,
        # sends them to XSIAM in batches if any events exist.
        for part_logs in extract_logs_from_zip_file(tmp_file_path):
            try:
                # Parse the events
                (
                    events,
                    time_of_last_fetched_event,
                ) = parse_events(
                    part_logs,
                    token_expired,
                    time_of_last_fetched_event,
                    events_suspected_duplicates,
                    new_events_suspected_duplicates,
                )

                try:
                    if events:
                        # Send events to XSIAM in batches
                        send_events_to_xsiam(
                            events,
                            VENDOR,
                            PRODUCT,
                            chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT // 2,
                        )
                        demisto.debug(f"len of the events is: {len(events)}")
                except Exception:
                    demisto.debug(
                        f"Failed to send events to XSOAR. Error: {traceback.format_exc()}"
                    )
            except Exception as e:
                demisto.debug(f"Error parsing events: {e}")

        # Removes the tmp file
        tmp_file_path.unlink()

    demisto.debug(f"after end {time_of_last_fetched_event}")
    if time_of_last_fetched_event:
        # Converts the `time_of_last_fetched_event` to a timestamp
        # to use for the start date of the next fetch.
        try:
            start_date_for_next_fetch = date_to_timestamp(
                date_str_or_dt=time_of_last_fetched_event,
                date_format=DATE_FORMAT,
            )
        except Exception:
            # If the conversion fails,
            # defaults to the original start date.
            demisto.debug("time_of_last_fetched_event is not datetime")
            start_date_for_next_fetch = start_date
    else:
        start_date_for_next_fetch = start_date

    # Creates a LastRun object for the next run.
    new_last_run_model = LastRun(
        start_date=str(start_date_for_next_fetch),
        token=str(params["token"]),
        time_of_last_fetched_event=str(time_of_last_fetched_event),
        events_suspected_duplicates=new_events_suspected_duplicates,
    )

    return new_last_run_model


''' --- def get_events_command(
    client: Client, args: dict[str, str], last_run_model: LastRun, is_first_fetch: bool
) -> tuple[list[str], LastRun]:
    """
    ...
    """
    logs: list[bytes] = []
    token_expired: bool = False
    time_of_last_fetched_event = ""
    events_suspected_duplicates: list[str] = []

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
            # demisto.debug("start fetching events - API")
            # res = write_to_file_system(client, params)
            # res = client.get_logs(params=params)
            demisto.debug("end fetching events - API")
        except DemistoException as e:
            try:
                if e.res is not None and e.res.status_code == 410:
                    demisto.debug(f"The token has expired: {e}")
                    token_expired = True
                    params["token"] = "none"
                    continue
                elif e.res is not None and e.res.status_code == 423:
                    demisto.debug(f"API access is blocked: {e}")
                elif e.res is not None and e.res.status_code == 429:
                    demisto.debug(f"Crashed on limit of api calls: {e}")
                else:
                    demisto.debug(f"Some ERROR: {e=}")
                    raise e
            except Exception as err:
                demisto.debug(f"Some ERROR: {e=} after the error: {err}")
                raise e
        except Exception as err:
            demisto.debug(f"Some ERROR: {err}")
            raise err
        file_size = get_file_size(res)
        demisto.debug(f"size of the file system: {file_size / (1024 ** 2):.2f} MB")
        status, params["token"] = get_status_and_token_from_file_system(res)
        # status, params["token"] = get_status_and_token_from_res(res)
        demisto.debug(f"The status is {status}")

        if status == "abort":
            demisto.debug(
                f"the status is {status}, the fetch will start again with the same values"
            )
            if is_first_fetch:
                return [], LastRun(**{})
            logs = []
            if params["token"] == "none":
                token_expired = True
            params["token"] = last_run_model.token or "none"
            continue

        if is_first_fetch:
            demisto.debug(
                "The current fetch is the first fetch, "
                "the collector ignores all events that return from the api, "
                "and will start collecting them from the next time onwards"
            )
            continue
        for part_logs in extract_logs_from_response(res):
            try:
                (
                    events,
                    time_of_last_fetched_event,
                    parts_events_suspected_duplicates,
                ) = organize_of_events(
                    part_logs,
                    token_expired,
                    time_of_last_fetched_event
                    or last_run_model.time_of_last_fetched_event
                    or "",
                    events_suspected_duplicates
                    or last_run_model.events_suspected_duplicates
                    or [],
                )
                try:
                    if events:
                        send_events_to_xsiam(
                            events,
                            VENDOR,
                            PRODUCT,
                            chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT // 2,
                        )
                        demisto.debug(f"len of the events is: {len(events)}")
                except Exception:
                    demisto.debug(
                        f"Failed to send events to XSOAR. Error: {traceback.format_exc()}"
                    )
            except Exception as e:
                demisto.debug(f"Error organizing events: {e}")
        res.unlink()

    demisto.debug(f"{time_of_last_fetched_event=}")
    if time_of_last_fetched_event:
        try:
            start_date_for_next_fetch = date_to_timestamp(
                date_str_or_dt=time_of_last_fetched_event,
                date_format="%Y-%m-%d %H:%M:%S",
            )
        except Exception:
            demisto.debug("time_of_last_fetched_event is not datetime")
            start_date_for_next_fetch = start_date
    else:
        start_date_for_next_fetch = start_date

    new_last_run_model = LastRun(
        start_date=str(start_date_for_next_fetch),
        token=str(params["token"]),
        time_of_last_fetched_event=time_of_last_fetched_event,
        events_suspected_duplicates=events_suspected_duplicates,
        # last_fetch=int(get_current_time_as_timestamp() / 1000)
    )

    # demisto.debug(
    #     f"End fetch from {start_date} to {end_date} with {len(events)} events,"
    #     f"{time_of_last_fetched_event=} and {events_suspected_duplicates=}"
    # )
    return [], new_last_run_model
    # return [], LastRun(
    #     start_date=str(start_date),
    
    #     token=str(params["token"]),
    #     last_fetch=int(get_current_time_as_timestamp() / 1000),
    # )
    # return [], LastRun(start_date=str(start_date), token=str(params["token"]))'''


def test_module(client: Client):
    return "ok"


def delete_tmp_file_from_last_fetch():
    # Deletes the temporary file from the last fetch if it exists
    if tmp_file_path := get_integration_context().get("tmp_file_path"):
        demisto.debug(f"{tmp_file_path=}")  # ????
        tmp_file_path = Path(tmp_file_path)
        try:
            if tmp_file_path.exists():
                demisto.debug(f"there is a {tmp_file_path=}")  # ????
                tmp_file_path.unlink()
                demisto.debug(f"Deleted temporary file: {tmp_file_path}")
        except Exception as err:
            demisto.debug(f"Failed to delete temporary file. Error: {err}")
    demisto.debug("Skipping temporary file deletion")  # ????


def perform_long_running_loop(client: Client, args: dict[str, str]):
    delete_tmp_file_from_last_fetch()

    last_run_obj: LastRun
    while True:
        try:
            integration_context = get_integration_context()
            demisto.debug(f"Starting new fetch with {integration_context=}")
            integration_context = integration_context.get("last_run")
            if integration_context and "last_fetch" in integration_context:
                del integration_context["last_fetch"]
            if date_to_timestamp(datetime.now().astimezone(pytz.utc)) > 1700048580000:
                last_run_obj = (
                    LastRun(**integration_context) if integration_context else LastRun()
                )
            else:
                last_run_obj = LastRun(start_date="1700032320000")
            # first_fetch = is_first_fetch(integration_context, args)
            demisto.debug(f"{last_run_obj._asdict()}")
            last_run_obj = get_events_command(
                client, args, last_run_obj, is_first_fetch=False
            )
            first_fetch = False

            set_integration_context({"last_run": last_run_obj._asdict()})
            integration_context_for_debug = get_integration_context()  # ????
            demisto.debug(f"{integration_context_for_debug=}")  # ????
        except Exception as e:
            demisto.debug(f"Failed to fetch logs from API. Error: {e}")
        time.sleep(FETCH_SLEEP)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

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
        if command == "long-running-execution":
            demisto.debug("Starting long running execution")
            perform_long_running_loop(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Symantec Web Security Service Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
