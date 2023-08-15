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
PRODUCT = "wss"
REGEX_FOR_STATUS = re.compile(r"X-sync-status: (?P<status>.*?)(?=\\r\\n|$)")
REGEX_FOR_TOKEN = re.compile(r"X-sync-token: (?P<token>.*?)(?=\\r\\n|$)")
REGEX_DETECT_LOG = re.compile(r"^(?!#)")


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify, proxy) -> None:
        headers: dict[str, str] = {"X-APIUsername": username, "X-APIPassword": password}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_logs(self, params: dict[str, Any]):
        return self._http_request(
            method="GET",
            url_suffix="/reportpod/logs/sync",
            params=params,
            resp_type="response",
        )


def get_start_and_ent_date(
    args: dict[str, str], last_run: dict[str, str]
) -> tuple[int, int]:
    now = datetime.now()

    start_date = int(
        last_run.get("start_date")
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


def extract_logs_from_response(response: Response) -> list[str]:
    logs: list[str] = []
    file_names: list[str] = []
    try:
        with ZipFile(BytesIO(response.content)) as outer_zip:
            for file in outer_zip.infolist():
                if file.filename.lower().endswith(".gz"):
                    file_names.append(file.filename.lower())
                    with outer_zip.open(file) as nested_zip_file, gzip.open(
                        nested_zip_file, "rb"
                    ) as f:
                        log = f.readlines()
                        for line in log:
                            if REGEX_DETECT_LOG.match(line.decode()):
                                logs.append(line.decode())
    except BadZipFile:
        demisto.debug("No logs were returned from the API")
        pass
    return logs


def get_events_command(
    client: Client, args: dict[str, str], last_run: dict[str, str]
) -> tuple[list[str], dict[str, str]]:

    logs: list[str] = []
    start_date, end_date = get_start_and_ent_date(args=args, last_run=last_run)
    params = {"startDate": start_date, "endDate": end_date, "token": "none"}

    demisto.debug(f"start fetch from {start_date} to {end_date}")

    status = "more"
    token: str | None = None
    while status != "done":
        if token:
            params["token"] = token

        try:
            res = client.get_logs(params=params)
        except Exception as e:
            raise e

        status, token = get_status_and_token_from_res(res)
        logs.extend(extract_logs_from_response(res))

    last_run.update({"start_date": str(end_date + 1)})

    demisto.debug(f"End fetch from {start_date} to {end_date} with {len(logs)} logs")
    return logs, last_run


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
            events, _ = get_events_command(client, args, last_run={})
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
            events, last_run = get_events_command(client, params, last_run=last_run)
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
