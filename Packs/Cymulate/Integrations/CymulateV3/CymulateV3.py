import traceback
from datetime import datetime, timezone, timedelta

import urllib3
from CommonServerPython import *  # pylint: disable=unused-wildcard-import


urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
DATE_FORMAT_MS = "%Y-%m-%dT%H:%M:%S.%fZ"
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
MAX_INCIDENTS_TO_FETCH = 200

# Fetch category options
FETCH_CATEGORY_ALL = "all"
FETCH_CATEGORY_THREAT_FEED_IOCS = "threat_feed_iocs"
THREAT_FEED_IOC_TAG = "Threat Feed IOC"

FETCH_CATEGORY_MAPPING = {
    "All": FETCH_CATEGORY_ALL,
    "Threat Feed IOCs": FETCH_CATEGORY_THREAT_FEED_IOCS,
}


class Client(BaseClient):
    """
    Client for Cymulate RESTful API - V2 (Assessment-based).
    Uses /v2/assessments/launched endpoints.

    Args:
        base_url (str): Cymulate server url.
        token (str): Cymulate access token.
        verify (bool): Whether the request should verify the SSL certificate.
        proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool, **kwargs):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)
        self.headers = {"x-token": token, "accept": "application/json"}

    def list_assessments(
        self,
        from_date: str,
        to_date: str,
        status: list[str] | None = None,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict:
        """
        GET /v2/assessments/launched
        List completed assessments with date filters.
        """
        params = remove_empty_elements(
            {
                "fromDate": from_date,
                "toDate": to_date,
                "status": status or ["completed"],
                "limit": limit,
                "cursor": cursor,
                "sortBy": "created",
                "sortOrder": "desc",
            }
        )
        demisto.debug(f"/v2/assessments/launched {params=}")
        return self._http_request(
            method="GET",
            url_suffix="/v2/assessments/launched",
            headers=self.headers,
            params=params,
        )

    def get_assessment_findings(
        self,
        assessment_id: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict:
        """
        GET /v2/assessments/launched/{id}/findings
        Get findings for a specific assessment.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "cursor": cursor,
            }
        )
        demisto.debug(f"/v2/assessments/launched/{assessment_id}/findings {params=}")
        return self._http_request(
            method="GET",
            url_suffix=f"/v2/assessments/launched/{assessment_id}/findings",
            headers=self.headers,
            params=params,
        )


""" HELPER FUNCTIONS """


def get_end_time():
    return datetime.now(timezone.utc).strftime(DATE_FORMAT)


def normalize_to_utc(dt: datetime | None) -> datetime | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication."""
    test_message = "ok"
    try:
        to_date = datetime.now(timezone.utc)
        from_date = to_date - timedelta(hours=1)
        client.list_assessments(
            from_date=from_date.strftime(DATE_FORMAT),
            to_date=to_date.strftime(DATE_FORMAT),
            limit=1,
        )
    except DemistoException as err:
        if err.res and err.res.status_code == 401:
            test_message = "Authorization Error: make sure API Key is correctly set."
        elif "401" in str(err):
            test_message = "Authorization Error: make sure API Key is correctly set."
        else:
            if err.res:
                try:
                    test_message = str(err.res.json())
                except Exception:
                    test_message = f"Error: {str(err)}"
            else:
                test_message = f"Error: {str(err)}"
    return test_message


def fetch_incidents(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    fetch_category: str = FETCH_CATEGORY_ALL,
) -> tuple[list[dict], dict]:
    """
    Fetch incidents using V2 assessment-based API.

    Flow:
    1. Get last_assessment_date from last run (or use first_fetch)
    2. Fetch completed assessments from last_assessment_date to now
    3. For each NEW assessment, fetch its findings
    4. Filter findings by status = "Not Prevented"
    5. Optionally filter by Threat Feed IOC tag
    6. Save latest assessment date for next run
    """
    demisto.debug(f"fetch_incidents: {fetch_category=}")
    last_run_data = demisto.getLastRun()
    last_assessment_date_str = last_run_data.get("last_assessment_date")
    last_assessment_date = arg_to_datetime(last_assessment_date_str)
    demisto.debug(f"fetch_incidents: {last_assessment_date_str=}")

    # Determine time range
    start_time = last_assessment_date or first_fetch
    start_time_str = start_time.strftime(DATE_FORMAT)
    end_time_str = get_end_time()
    demisto.debug(f"fetch_incidents: fetching from {start_time_str} to {end_time_str}")

    # Fetch completed assessments with pagination
    assessments: list[dict] = []
    cursor = None
    while True:
        try:
            response = client.list_assessments(
                from_date=start_time_str,
                to_date=end_time_str,
                status=["completed"],
                limit=25,
                cursor=cursor,
            )
        except Exception as e:
            # Handle transient errors (ChunkedEncodingError, IncompleteRead, etc.)
            demisto.debug(f"fetch_incidents: error fetching assessments (treated as transient): {e}")
            if assessments:
                demisto.error(
                    f"fetch_incidents: transient error fetching assessments. "
                    f"Processing {len(assessments)} assessments collected so far."
                )
                break
            raise DemistoException(f"Error fetching assessments. Original error: {e}")

        batch = response.get("data", [])
        assessments.extend(batch)
        cursor = response.get("nextCursor")
        if not cursor or len(batch) == 0:
            break

    demisto.debug(f"fetch_incidents: found {len(assessments)} completed assessments")

    # Process assessments and collect findings
    incidents: list[dict] = []
    latest_assessment_date = last_assessment_date

    for assessment in assessments:
        assessment_id = assessment.get("id")
        assessment_name = assessment.get("name", "Unknown")
        assessment_created_str = assessment.get("createdAt")
        assessment_created = arg_to_datetime(assessment_created_str)

        # Skip already processed assessments (date-based deduplication)
        if last_assessment_date and assessment_created and assessment_created <= last_assessment_date:
            demisto.debug(f"fetch_incidents: skipping old assessment {assessment_id}")
            continue

        demisto.debug(f"fetch_incidents: processing {assessment_name} ({assessment_id})")

        # Update latest assessment date
        if assessment_created and (latest_assessment_date is None or assessment_created > latest_assessment_date):
            latest_assessment_date = assessment_created

        # Skip if assessment_id is missing
        if not assessment_id:
            demisto.debug(f"fetch_incidents: skipping assessment with missing ID: {assessment_name}")
            continue

        # Fetch findings for this assessment with pagination
        findings: list[dict] = []
        findings_cursor = None
        while True:
            try:
                findings_response = client.get_assessment_findings(
                    assessment_id=assessment_id,
                    limit=100,
                    cursor=findings_cursor,
                )
            except Exception as e:
                demisto.debug(f"fetch_incidents: error fetching findings for {assessment_id} " f"(treated as transient): {e}")
                demisto.error(
                    f"fetch_incidents: transient error fetching findings for assessment {assessment_id}. "
                    f"Processing {len(findings)} findings collected so far."
                )
                break

            findings_batch = findings_response.get("findings", [])
            findings.extend(findings_batch)
            findings_cursor = findings_response.get("nextCursor")
            if not findings_cursor or len(findings_batch) == 0:
                break

        demisto.debug(f"fetch_incidents: {assessment_name} has {len(findings)} findings")

        # Create incidents from "Not Prevented" findings
        for finding in findings:
            if finding.get("status") != "Not Prevented":
                continue

            # Apply fetch category filter
            if fetch_category == FETCH_CATEGORY_THREAT_FEED_IOCS:
                tags = finding.get("tags", [])
                if THREAT_FEED_IOC_TAG not in tags:
                    continue

            finding_name = finding.get("findingName", "Unknown")
            finding_date_str = finding.get("date")
            finding_date = normalize_to_utc(arg_to_datetime(finding_date_str))
            if finding_date is None:
                finding_date = normalize_to_utc(assessment_created)

            # Add assessment info to finding
            finding["_assessment_id"] = assessment_id
            finding["_assessment_name"] = assessment_name

            incidents.append(
                {
                    "name": f"Cymulate Finding - {assessment_name} - {finding_name}",
                    "occurred": finding_date.strftime(XSOAR_DATE_FORMAT) if finding_date else end_time_str,
                    "rawJSON": json.dumps(finding),
                }
            )

            if len(incidents) >= max_fetch:
                break

        if len(incidents) >= max_fetch:
            break

    # Prepare last run data
    new_last_run = {
        "last_assessment_date": latest_assessment_date.strftime(DATE_FORMAT_MS) if latest_assessment_date else None,
    }

    demisto.debug(
        f"fetch_incidents: returning {len(incidents)} incidents, "
        f"new last_assessment_date={new_last_run['last_assessment_date']}"
    )
    return incidents, new_last_run


def main() -> None:
    """main function, parses params and runs command functions"""
    params = demisto.params()

    api_key = params.get("api_key") or (params.get("credentials") or {}).get("password")
    if not api_key:
        raise DemistoException("API Token must be provided.")

    base_url = params.get("base_url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            token=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-incidents":
            first_fetch = arg_to_datetime(params.get("first_fetch"))
            if not first_fetch:
                raise DemistoException("First fetch time must be specified.")

            fetch_category = FETCH_CATEGORY_MAPPING.get(params.get("fetch_category"), FETCH_CATEGORY_ALL)

            incidents, last_run = fetch_incidents(
                client=client,
                first_fetch=first_fetch,
                max_fetch=arg_to_number(params.get("max_fetch")) or MAX_INCIDENTS_TO_FETCH,
                fetch_category=fetch_category,
            )

            demisto.debug(f"fetch: Fetched {len(incidents)} incidents.")
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\n\nFull error message:\n{str(error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
