import traceback
from datetime import datetime, timezone
from typing import Any

import urllib3
from CommonServerPython import *  # pylint: disable=unused-wildcard-import


urllib3.disable_warnings()

DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
CY_GENERAL_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
CY_UNIQUE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

MAX_INCIDENTS_TO_FETCH = 35
MAX_EVENTS_TO_DISPLAY = 20

SEVERITIES = ["Low", "Medium", "High", "Critical"]
ACCESSED_STATUS = ["penetrated", "accessed", "executed completely", "exfiltrated", "completed"]
ENDPOINT_DICT = {
    "Web Gateway": "browsing",
    "Data Exfiltration": "dlp",
    "Email Gateway": "mail",
    "Endpoint Security": "edr",
    "Web Application Firewall": "waf",
    "Full Kill-Chain Scenarios": "apt",
    "Immediate Threats": "immediate-threats",
    "Phishing Awareness": "phishing",
    "Hopper": "hopper",
}

MIRRORING_FIELDS = [
    "latest",
]

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
}


class Client(BaseClient):
    """
    Client for Cymulate RESTful API.

    Args:
          base_url (str): Cymulate server url.
          token (str): Cymulate access token.
          verify (bool): Whether the request should verify the SSL certificate.
          proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool, **kwargs):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)
        self.headers = {"x-token": token, "accept": "*/*", "Content-Type": "application/json"}

    def list_findings(
        self,
        limit: int,
        start_date: str,
        end_date: str,
        categories: list[str],
        environment_ids: list[str],
        skip: int = 0,
        latest: bool = True,
    ):
        json_data = remove_empty_elements(
            {
                "limit": limit,
                "skip": skip,
                "date": {
                    "startDate": start_date,
                    "endDate": end_date,
                },
                "filters": {
                    "module": categories,
                    "envID": environment_ids,
                    "status": ["Not Prevented"],
                },
                "sort": {"key": "date", "value": -1},
                "latest": latest,
            }
        )
        demisto.debug(f"msfinding/api/v2/search {json_data=}")
        return self._http_request(
            method="POST",
            url_suffix="/msfinding/api/v2/search",
            headers=self.headers,
            json_data=json_data,
        )

    def get_finding(self, id: str):
        return self._http_request(
            method="GET",
            url_suffix=f"/msfinding/api/v2/info/{id}",
            headers=self.headers,
        )


""" HELPER FUNCTIONS """


def get_end_time():
    return datetime.now().strftime(DATE_FORMAT)


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication. Returning 'ok' indicates that the integration
    works like it is supposed to. Connection to the service is successful.

    Args:
        client (Client): Cymulate client.
    """
    test_message = "ok"
    try:
        client.list_findings(
            limit=1,
            start_date=get_end_time(),
            end_date=get_end_time(),
            categories=[],
            environment_ids=[],
        )
    except DemistoException as err:
        if err.res:
            if err.res.status_code == 401:
                test_message = "Authorization Error: make sure API Key is correctly set."
            else:
                test_message = err.res.json()
        else:
            test_message = "Error"
    return test_message


def normalize_to_utc(dt: datetime | None) -> datetime | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fetch_incidents(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    categories: list[str],
    environment_ids: list[str],
    mirror_direction: str,
) -> tuple[list[dict], str]:

    last_run_str = demisto.getLastRun().get("time")
    last_run = arg_to_datetime(last_run_str)
    demisto.debug(f"fetch_incidents: got {last_run_str=} {last_run=}")

    start_time = (last_run or first_fetch).strftime(DATE_FORMAT)
    last_run = arg_to_datetime(start_time)
    end_time = get_end_time()
    demisto.debug(f"fetch_incidents: {start_time=}")
    incidents = []
    findings: list[dict[str, Any]] = []
    context = get_integration_context() or {}

    first_incident_time = normalize_to_utc(arg_to_datetime(context.get("first_incident_time")))

    while True:
        response = client.list_findings(
            limit=max_fetch,
            start_date=start_time,
            end_date=end_time,
            categories=categories,
            environment_ids=environment_ids,
            skip=len(findings),
            latest=True,
        )
        demisto.debug(f"fetch_incidents: request to list findings {len(findings)=} {start_time=} {end_time=}")
        findings_batch = dict_safe_get(response, ["data", "findings"], [])
        findings.extend(findings_batch)

        if len(findings_batch) < max_fetch:
            break

    demisto.debug(f"fetch_incidents: got {len(findings)=}. old {start_time=}, start to parse")

    for finding in findings:
        if not finding["latest"]:
            continue

        date = finding["date"]
        module_display_name = dict_safe_get(finding, ["module", "displayName"])
        finding_name = finding["findingName"]

        finding_date = normalize_to_utc(arg_to_datetime(date))
        if finding_date is None:
            continue

        if not first_incident_time:
            first_incident_time = finding_date
        elif finding_date and finding_date < first_incident_time:
            first_incident_time = finding_date

        mirror_data = {
            "mirror_direction": mirror_direction,
            "mirror_instance": demisto.integrationInstance(),
        }
        finding |= mirror_data

        if last_run is not None and finding_date.replace(tzinfo=None) > last_run.replace(tzinfo=None):
            incident_date = arg_to_datetime(date, required=True)
            utc_date = normalize_to_utc(incident_date)
            if incident_date is not None and utc_date is not None:
                incidents.append(
                    {
                        "name": f"Cymulate Finding - {module_display_name} - {finding_name}",
                        "occurred": utc_date.strftime(XSOAR_DATE_FORMAT),
                        "dbotMirrorId": finding["_id"],
                        "rawJSON": json.dumps(finding),
                        **mirror_data,
                    }
            )
        else:
            finding_id = finding["_id"]
            demisto.debug(f"fetch_incidents: removed duplicate {finding_id=}")

    if first_incident_time:
        first_incident_time_str = first_incident_time.strftime(XSOAR_DATE_FORMAT)
        set_integration_context({"first_incident_time": first_incident_time_str})
        demisto.debug(f"fetch_incidents: {first_incident_time_str=}")

    demisto.debug(f"fetch_incidents: sending {len(incidents)=}. new {end_time=}")
    return incidents, end_time


def get_modified_remote_data_command(
    client: Client,
    args: dict[str, Any],
    categories: list[str],
    environment_ids: list[str],
    max_page_size: int = 100,
):
    """
    Return IDs of Cymulate findings that should be mirrored-in because they are no longer latest.
    We search with latest=False, within [start_time, end_time], and compare each finding's update timestamp
    to XSOAR's last_update (from the MIRROR mechanism).
    """
    demisto.debug("get_modified_remote_data_command")
    remote_args = GetModifiedRemoteDataArgs(args)
    modified_ids: list[str] = []

    context = get_integration_context() or {}
    demisto.debug(f"get_modified_remote_data_command: {context=}")
    start_dt = arg_to_datetime(context.get("first_incident_time"))
    if not start_dt:
        demisto.debug("get_modified_remote_data_command: First incident time not exists, return []")
        return GetModifiedRemoteDataResponse([])
    start_time = start_dt.strftime(DATE_FORMAT)
    end_time = get_end_time()

    demisto.debug(
        f"get_modified_remote_data_command: start_time={start_time}, end_time={end_time}, "
        f"last_update_time={remote_args.last_update!r}"
    )

    findings: list[dict[str, Any]] = []
    skip = 0

    while True:
        response = client.list_findings(
            limit=max_page_size,
            start_date=start_time,
            end_date=end_time,
            categories=categories,
            environment_ids=environment_ids,
            skip=skip,
            latest=False,
        )
        batch = dict_safe_get(response, ["data", "findings"], [])
        findings.extend(batch)
        demisto.debug(f"get_modified_remote_data_command: page got {len(batch)} findings (skip={skip}).")
        if len(batch) < max_page_size:
            break
        skip += max_page_size

    demisto.debug(f"get_modified_remote_data_command: total collected (latest=false)={len(findings)}")
    for f in findings:
        fid = f.get("_id")
        if not fid:
            continue
        ts = arg_to_datetime(f["date"]) if f.get("date") else None
        finding_latest = f["latest"]
        if ts and ts.replace(tzinfo=None) > start_dt.replace(tzinfo=None) and finding_latest == False:
            print("123")
            modified_ids.append(fid)

    demisto.debug(f"get_modified_remote_data_command: returning {len(modified_ids)} modified IDs. {modified_ids=}")
    return GetModifiedRemoteDataResponse(modified_ids)


def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse:
    parsed_args = GetRemoteDataArgs(args)
    remote_id = parsed_args.remote_incident_id
    demisto.debug(f"get_remote_data_command: {remote_id=}.")
    demisto.debug(f"get_remote_data_command: {parsed_args.__dict__=}.")

    try:
        finding = client.get_finding(remote_id).get("data", {})
    except DemistoException as e:
        return GetRemoteDataResponse({}, [])

    if not finding:
        return GetRemoteDataResponse({}, [])

    entries: list[dict[str, Any]] = []

    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Closed from Cymulate (latest=false).",
                "closeNotes": "Some note",
            },
            "ContentsFormat": EntryFormat.JSON,
        }
    )
    finding["id"] = remote_id

    demisto.debug(f"get_remote_data_command: closing {remote_id=} {entries=}.")

    return GetRemoteDataResponse(finding, entries)


def main() -> None:
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()

    api_key = params.get("api_key") or (params.get("credentials") or {}).get("password")
    if not api_key:
        raise Exception("API Token must be provided.")
    base_url = params.get("base_url")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    categories = remove_empty_elements(
        argToList([ENDPOINT_DICT.get(category) for category in params.get("categories", [])]) or []
    )
    environment_ids = argToList(params.get("environment_ids", [])) or []
    try:
        client = Client(
            base_url=base_url,
            token=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "get-remote-data":
            get_remote_data_command(client, args)

        elif command == "get-modified-remote-data":
            get_modified_remote_data_command(
                client=client,
                args=args,
                categories=categories,
                environment_ids=environment_ids,
                max_page_size=arg_to_number(params.get("max_fetch")) or 50,
            )

        elif command == "fetch-incidents":
            first_fetch = arg_to_datetime(params.get("first_fetch"))
            if not first_fetch:
                raise DemistoException("First fetch time must be specified.")

            incidents, last_run = fetch_incidents(
                client=client,
                first_fetch=first_fetch,
                max_fetch=arg_to_number(params.get("max_fetch")) or 50,
                categories=categories,
                environment_ids=environment_ids,
                mirror_direction=MIRROR_DIRECTION_MAPPING.get(params.get("mirror_direction")) or "None",
            )

            demisto.debug(f"fetch: Update last run time to {last_run}.")
            demisto.debug(f"fetch: Fetched {len(incidents)} incidents.")
            demisto.setLastRun({"time": last_run})
            demisto.incidents(incidents)

    except Exception as error:
        demisto.error(traceback.format_exc())

        return_error(f"Failed to execute {command} command.\n\n" f"Full error message:\n{str(error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
