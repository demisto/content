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
        limit: int = 100,
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
                "sortOrder": "asc",
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

    Findings are fetched page-by-page and converted to incidents as they arrive,
    so fetching stops as soon as max_fetch is reached — no unnecessary API calls.

    When max_fetch is hit mid-assessment, cursor-based state is saved in lastRun
    so the next run resumes from exactly where it stopped, preventing both
    duplicate incidents and infinite re-processing of large assessments.

    lastRun keys
    ------------
    last_assessment_date  – createdAt of the last FULLY processed assessment.
    pending_assessment_id – ID of the assessment currently being ingested (set
                            only when stopped mid-assessment due to max_fetch).
    pending_page_cursor   – Cursor that was passed to get_assessment_findings for
                            the page where max_fetch was hit.  An empty string
                            means the first page (cursor=None).
    pending_page_np_skip  – Number of "Not Prevented" findings from that page
                            already ingested; those are skipped on resume.
    """
    demisto.debug(f"fetch_incidents: {fetch_category=}")
    last_run_data = demisto.getLastRun()
    last_assessment_date_str = last_run_data.get("last_assessment_date")
    last_assessment_date = arg_to_datetime(last_assessment_date_str)
    pending_assessment_id = last_run_data.get("pending_assessment_id")
    pending_page_cursor = last_run_data.get("pending_page_cursor")  # "" = first page
    pending_page_np_skip: int = last_run_data.get("pending_page_np_skip") or 0
    demisto.debug(
        f"fetch_incidents: {last_assessment_date_str=} "
        f"{pending_assessment_id=} {pending_page_cursor=} {pending_page_np_skip=}"
    )

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
                limit=100,
                cursor=cursor,
            )
        except Exception as e:
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

    incidents: list[dict] = []
    latest_assessment_date = last_assessment_date
    # Pending state to persist if we pause mid-assessment this run
    new_pending_id: str | None = None
    new_pending_cursor: str | None = None
    new_pending_skip: int = 0

    for assessment in assessments:
        assessment_id = assessment.get("id")
        assessment_name = assessment.get("name", "Unknown")
        assessment_created_str = assessment.get("createdAt")
        assessment_created = arg_to_datetime(assessment_created_str)

        # Skip fully-processed assessments (strict less-than avoids missing the boundary)
        if last_assessment_date and assessment_created and assessment_created < last_assessment_date:
            demisto.debug(f"fetch_incidents: skipping old assessment {assessment_id}")
            continue

        if not assessment_id:
            demisto.debug(f"fetch_incidents: skipping assessment with missing ID: {assessment_name}")
            continue

        demisto.debug(f"fetch_incidents: processing {assessment_name} ({assessment_id})")

        # When resuming a partially-ingested assessment, start from the saved page
        # cursor. "" signals the first page (cursor=None); a non-empty string is an
        # opaque API cursor.  np_skip tells us how many NP findings on that page to
        # skip because they were already ingested last run.
        is_resuming = pending_assessment_id == assessment_id
        if is_resuming:
            page_cursor: str | None = pending_page_cursor if pending_page_cursor else None
            np_skip = pending_page_np_skip
            demisto.debug(f"fetch_incidents: resuming {assessment_id} " f"from page_cursor={page_cursor!r} np_skip={np_skip}")
        else:
            page_cursor = None
            np_skip = 0

        # Fetch findings page-by-page and create incidents as we go
        paused = False
        while True:
            try:
                findings_response = client.get_assessment_findings(
                    assessment_id=assessment_id,
                    limit=100,
                    cursor=page_cursor,
                )
            except Exception as e:
                demisto.debug(f"fetch_incidents: error fetching findings for {assessment_id} " f"(treated as transient): {e}")
                demisto.error(
                    f"fetch_incidents: transient error fetching findings for assessment {assessment_id}. "
                    f"Stopping findings fetch for this assessment."
                )
                break

            findings_batch = findings_response.get("findings", [])
            next_cursor = findings_response.get("nextCursor")

            np_count_this_page = 0
            for idx, finding in enumerate(findings_batch):
                if finding.get("status") != "Not Prevented":
                    continue

                # Apply fetch category filter
                if fetch_category == FETCH_CATEGORY_THREAT_FEED_IOCS and THREAT_FEED_IOC_TAG not in finding.get("tags", []):
                    continue

                # On resume: skip NP findings from this page already ingested last run
                if np_skip > 0:
                    np_skip -= 1
                    continue

                finding_name = finding.get("findingName", "Unknown")
                finding_date_str = finding.get("date")
                finding_date = normalize_to_utc(arg_to_datetime(finding_date_str))
                if finding_date is None:
                    finding_date = normalize_to_utc(assessment_created)

                finding["_assessment_id"] = assessment_id
                finding["_assessment_name"] = assessment_name

                incidents.append(
                    {
                        "name": f"Cymulate Finding - {assessment_name} - {finding_name}",
                        "occurred": finding_date.strftime(XSOAR_DATE_FORMAT) if finding_date else end_time_str,
                        "rawJSON": json.dumps(finding),
                    }
                )
                np_count_this_page += 1

                if len(incidents) >= max_fetch:
                    paused = True
                    new_pending_id = assessment_id
                    # Optimisation: if no eligible NP findings remain after this one
                    # on the current page, point directly at the next page cursor so
                    # the resume run doesn't waste an API call re-fetching a page only
                    # to skip every finding on it.
                    has_more_np = any(
                        f.get("status") == "Not Prevented"
                        and (fetch_category != FETCH_CATEGORY_THREAT_FEED_IOCS or THREAT_FEED_IOC_TAG in f.get("tags", []))
                        for f in findings_batch[idx + 1:]
                    )
                    if not has_more_np and next_cursor:
                        new_pending_cursor = next_cursor
                        new_pending_skip = 0
                    else:
                        # Empty string encodes "first page" (cursor=None)
                        new_pending_cursor = page_cursor if page_cursor is not None else ""
                        new_pending_skip = np_count_this_page
                    break

            if paused:
                break

            if not next_cursor or len(findings_batch) == 0:
                # All pages of this assessment consumed
                break
            page_cursor = next_cursor

        if paused:
            # Stop processing further assessments this run
            break

        # Assessment fully processed — advance watermark and clear any pending state
        if assessment_created and (latest_assessment_date is None or assessment_created > latest_assessment_date):
            latest_assessment_date = assessment_created

    new_last_run: dict = {
        "last_assessment_date": latest_assessment_date.strftime(DATE_FORMAT_MS) if latest_assessment_date else None,
    }
    if new_pending_id:
        new_last_run["pending_assessment_id"] = new_pending_id
        new_last_run["pending_page_cursor"] = new_pending_cursor
        new_last_run["pending_page_np_skip"] = new_pending_skip

    demisto.debug(
        f"fetch_incidents: returning {len(incidents)} incidents, "
        f"new last_assessment_date={new_last_run['last_assessment_date']} "
        f"pending_assessment_id={new_last_run.get('pending_assessment_id')}"
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
