"""Qualys Enterprise TruRisk Management (ETM) integration for Cortex XSOAR / XSIAM."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

API_PREFIX = "/etm/api/rest/v1"
AUTH_URL_SUFFIX = "/auth"

# The Qualys ETM documentation does not publish the JWT lifetime, so this value is a conservative
# refresh heuristic rather than a documented contract. Correctness does not depend on it: any 401
# response invalidates the cached token and triggers a single re-authentication + replay.
TOKEN_TTL_SECONDS = 3600
# Refresh slightly before the heuristic TTL elapses to avoid racing an expiry mid-request.
TOKEN_EXPIRY_MARGIN_SECONDS = 60

INTEGRATION_CONTEXT_TOKEN_KEY = "jwt_token"
INTEGRATION_CONTEXT_EXPIRY_KEY = "jwt_token_expiry"

DEFAULT_LIMIT = 50
DEFAULT_PAGE = 1
# Maximum number of records requested in a single API call when paginating automatically by limit.
MAX_PAGE_SIZE = 100

# Keys under which Qualys returns a human-readable error message. The gateway uses "_errorMessage" /
# "_errorDetail", while the ETM module endpoints use "error" / "message".
ERROR_MESSAGE_KEYS = ("_errorMessage", "_errorDetail", "error", "message", "errorMessage")

# Header titles that pascalToSpace cannot derive correctly on its own.
REPORT_LIST_HEADERS = {"id": "Report ID"}

DEFAULT_POLL_INTERVAL_SECONDS = 10
DEFAULT_POLL_TIMEOUT_SECONDS = 300

COMPLETED_STATUS = "COMPLETED"
# Statuses that indicate the report is still being generated and polling should continue.
IN_PROGRESS_STATUSES = {"REQUESTED", "RUNNING", "IN_PROGRESS", "INPROGRESS", "PENDING", "SUBMITTED", "QUEUED"}
# Substrings that identify a terminal failure, so polling fails fast instead of waiting for the timeout.
FAILURE_STATUS_MARKERS = ("FAIL", "ERROR", "CANCEL", "EXPIRE", "ABORT", "REJECT")

CREDENTIALS_ERROR = "Authorization Error: make sure the username and password are correctly set."
PERMISSIONS_ERROR = (
    "Access denied by Qualys. Verify that the ETM module is enabled on your subscription and that the "
    "user's role has the 'API Access' permission. See the integration documentation for details."
)

""" CLIENT CLASS """


class Client(BaseClient):
    """Client for the Qualys ETM REST API.

    Authenticates with a username/password pair that is exchanged for a JWT, and caches that JWT in the
    integration context so that it is reused across command executions and polling iterations.
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._username = username
        self._password = password

    def _authenticate(self) -> str:
        """Exchange the configured credentials for a JWT.

        Returns:
            The raw JWT string.
        """
        demisto.debug("QualysETM: requesting a new JWT from the authentication endpoint.")
        token = self._http_request(
            method="POST",
            url_suffix=AUTH_URL_SUFFIX,
            data={
                "username": self._username,
                "password": self._password,
                "token": "true",
                "permissions": "true",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            resp_type="text",
            error_handler=self._error_handler,
        )
        if not token:
            raise DemistoException("Authentication failed: the Qualys authentication API returned an empty token.")
        return token.strip()

    def get_token(self, force_refresh: bool = False) -> str:
        """Return a valid JWT, reusing the cached one when it has not reached its heuristic expiry.

        Args:
            force_refresh: When True, ignore the cached token and authenticate again.

        Returns:
            A JWT string to be used as a Bearer token.
        """
        integration_context = get_integration_context() or {}
        cached_token = integration_context.get(INTEGRATION_CONTEXT_TOKEN_KEY)
        expiry = integration_context.get(INTEGRATION_CONTEXT_EXPIRY_KEY, 0)

        if not force_refresh and cached_token and time.time() < (expiry - TOKEN_EXPIRY_MARGIN_SECONDS):
            demisto.debug("QualysETM: reusing the cached JWT.")
            return cached_token

        token = self._authenticate()
        integration_context[INTEGRATION_CONTEXT_TOKEN_KEY] = token
        integration_context[INTEGRATION_CONTEXT_EXPIRY_KEY] = time.time() + TOKEN_TTL_SECONDS
        set_integration_context(integration_context)
        return token

    @staticmethod
    def _error_handler(response: requests.Response) -> None:
        """Translate Qualys HTTP errors into actionable messages."""
        vendor_message = extract_error_message(response)
        details = f"\nQualys response: {vendor_message}" if vendor_message else ""
        if response.status_code == 401:
            raise DemistoException(f"{CREDENTIALS_ERROR}{details}", res=response)
        if response.status_code == 403:
            raise DemistoException(f"{PERMISSIONS_ERROR}{details}", res=response)
        raise DemistoException(
            f"Error in API call [{response.status_code}] - {response.reason}\n{vendor_message or response.text}", res=response
        )

    def etm_request(
        self,
        method: str,
        url_suffix: str,
        json_data: Any = None,
        resp_type: str = "json",
        allow_retry: bool = True,
    ) -> Any:
        """Perform an authenticated request against the ETM API.

        A cached JWT may have expired before its heuristic TTL elapsed, so a 401 response triggers exactly one
        re-authentication and replay of the request.

        Args:
            method: HTTP method.
            url_suffix: Path appended to the ETM API prefix.
            json_data: Optional JSON body.
            resp_type: Expected response type ("json", "content", "text").
            allow_retry: Internal flag preventing more than one retry.

        Returns:
            The parsed response, according to resp_type.
        """
        token = self.get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            return self._http_request(
                method=method,
                url_suffix=f"{API_PREFIX}{url_suffix}",
                json_data=json_data,
                headers=headers,
                resp_type=resp_type,
                error_handler=self._error_handler,
            )
        except DemistoException as error:
            if allow_retry and self._is_unauthorized(error):
                demisto.debug("QualysETM: cached JWT rejected with 401. Re-authenticating and retrying once.")
                self.get_token(force_refresh=True)
                return self.etm_request(method, url_suffix, json_data, resp_type, allow_retry=False)
            raise

    @staticmethod
    def _is_unauthorized(error: DemistoException) -> bool:
        """Return True when the given exception represents an HTTP 401 response."""
        response = getattr(error, "res", None)
        return getattr(response, "status_code", None) == 401

    def list_active_reports(self, offset: int, limit: int) -> Any:
        """List the active reports."""
        return self.etm_request(method="POST", url_suffix="/reports/list", json_data={"offset": offset, "limit": limit})

    def get_report_details(self, report_id: str) -> dict[str, Any]:
        """Return the full details of a single report."""
        return self.etm_request(method="GET", url_suffix=f"/reports/{report_id}")

    def download_report_resource(self, report_id: str, resource_name: str) -> bytes:
        """Download a single named part-file of a report."""
        return self.etm_request(method="GET", url_suffix=f"/reports/{report_id}/resources/{resource_name}", resp_type="content")

    def download_report_archive(self, report_id: str) -> bytes:
        """Download all resources of a report as a ZIP archive."""
        return self.etm_request(method="GET", url_suffix=f"/reports/{report_id}/download", resp_type="content")

    def submit_findings_report(self, body: dict[str, Any]) -> dict[str, Any]:
        """Submit a new findings report request."""
        return self.etm_request(method="POST", url_suffix="/reports/findings", json_data=body)

    def delete_reports(self, report_ids: list[str]) -> Any:
        """Delete the given reports. The API expects a bare JSON array of report IDs as the body."""
        return self.etm_request(method="DELETE", url_suffix="/reports", json_data=report_ids)


""" HELPER FUNCTIONS """


def extract_error_message(response: requests.Response) -> str:
    """Extract the human-readable error message from a Qualys error response.

    Qualys returns errors in more than one format, for example {"_errorMessage": "..."} from the gateway
    and {"error": "..."} from the ETM module endpoints, so every known key is checked.

    Args:
        response: The failed HTTP response.

    Returns:
        The vendor error message, or an empty string when none can be extracted.
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    for key in ERROR_MESSAGE_KEYS:
        value = body.get(key)
        if value and isinstance(value, str):
            return value
    return ""


def extract_records(response: Any) -> list[dict[str, Any]]:
    """Normalize a Qualys ETM list response into a list of records.

    The response shape of the list endpoint is not confirmed against a live tenant, so both a bare JSON
    array and the common envelope shapes are accepted.

    Args:
        response: The raw parsed API response.

    Returns:
        A list of record dictionaries.
    """
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        for key in ("data", "items", "reports", "content", "results", "response"):
            value = response.get(key)
            if isinstance(value, list):
                return value
        return [response]
    return []


def calculate_pagination(args: dict[str, Any]) -> tuple[int, int, str]:
    """Translate the XSOAR pagination arguments into the vendor's offset/limit body parameters.

    When page or page_size is supplied, manual pagination mode is used and the missing counterpart is
    defaulted. Otherwise, limit bounds the total number of results.

    Args:
        args: The command arguments.

    Returns:
        A tuple of (offset, limit, pagination_message).
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))

    if page is not None or page_size is not None:
        # A supplied value of 0 is invalid, but it is falsy, so the defaults are applied only when the
        # argument was not supplied at all.
        page = DEFAULT_PAGE if page is None else page
        page_size = DEFAULT_LIMIT if page_size is None else page_size
        if page < 1:
            raise DemistoException("The 'page' argument must be greater than or equal to 1.")
        if page_size < 1:
            raise DemistoException("The 'page_size' argument must be greater than or equal to 1.")
        pagination_message = f"Current page size: {page_size}\nShowing page {page} out of others that may exist."
        return (page - 1) * page_size, page_size, pagination_message

    limit = arg_to_number(args.get("limit"))
    limit = DEFAULT_LIMIT if limit is None else limit
    if limit < 1:
        raise DemistoException("The 'limit' argument must be greater than or equal to 1.")
    return 0, limit, ""


def is_failure_status(status: str) -> bool:
    """Return True when the given report status represents a terminal failure."""
    normalized = (status or "").upper()
    return any(marker in normalized for marker in FAILURE_STATUS_MARKERS)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validate the credentials and the ETM module entitlement.

    Authentication alone does not prove that the subscription has the ETM module enabled, so a minimal
    report listing call is issued as well. An empty report list is a valid, successful state.
    """
    client.list_active_reports(offset=0, limit=1)
    return "ok"


def fetch_reports_by_limit(client: Client, limit: int) -> list[dict[str, Any]]:
    """Automatically paginate through the active reports until the limit is reached or no more results exist.

    Args:
        client: The Qualys ETM client.
        limit: The total number of reports to retrieve.

    Returns:
        Up to limit report records.
    """
    reports: list[dict[str, Any]] = []
    offset = 0
    while len(reports) < limit:
        batch_size = min(MAX_PAGE_SIZE, limit - len(reports))
        records = extract_records(client.list_active_reports(offset=offset, limit=batch_size))
        reports.extend(records)
        if len(records) < batch_size:
            break
        offset += len(records)
    # The vendor may not honor the requested limit, so the results are truncated client-side as a safety net.
    return reports[:limit]


def active_reports_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the active reports."""
    offset, limit, pagination_message = calculate_pagination(args)
    if pagination_message:
        # Manual pagination mode: retrieve exactly the requested page.
        reports = extract_records(client.list_active_reports(offset=offset, limit=limit))[:limit]
    else:
        reports = fetch_reports_by_limit(client, limit)
    raw_response = reports

    readable_output = tableToMarkdown(
        "Qualys ETM Active Reports",
        reports,
        headers=["id", "name", "status", "created", "expirationDate"],
        headerTransform=lambda header: REPORT_LIST_HEADERS.get(header, pascalToSpace(header)),
        removeNull=True,
        metadata=pagination_message or None,
    )
    return CommandResults(
        outputs_prefix="QualysETM.Report",
        outputs_key_field="id",
        outputs=reports,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def report_get_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Return the full details of a single report."""
    report_id = args["report_id"]
    raw_response = client.get_report_details(report_id)
    return CommandResults(
        outputs_prefix="QualysETM.Report",
        outputs_key_field="id",
        outputs=raw_response,
        readable_output=report_details_to_markdown(raw_response, f"Qualys ETM Report {report_id}"),
        raw_response=raw_response,
    )


def report_details_to_markdown(report: dict[str, Any], title: str) -> str:
    """Build the human readable output of a single report's details."""
    details = {
        "Report ID": report.get("id"),
        "Name": report.get("name"),
        "Description": report.get("description"),
        "Report Format": report.get("reportFormat"),
        "Status": report.get("status"),
        "Asset QQL": report.get("assetQql"),
        "Findings QQL": report.get("findingsQql"),
        "Created": report.get("created"),
        "Created By": demisto.get(report, "createdBy.name"),
        "Updated": report.get("updated"),
        "Expiration Date": report.get("expirationDate"),
        "Resources": ", ".join(report.get("resources") or []) or None,
    }
    return tableToMarkdown(title, details, headers=list(details.keys()), removeNull=True)


def report_download_command(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    """Download a single named part-file of a report to the War Room."""
    report_id = args["report_id"]
    resource_name = args["resource_name"]
    content = client.download_report_resource(report_id, resource_name)
    return fileResult(filename=resource_name, data=content)


def reports_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete one or more reports."""
    report_ids = argToList(args.get("report_ids"))
    if not report_ids:
        raise DemistoException("The 'report_ids' argument must contain at least one report ID.")

    raw_response = client.delete_reports(report_ids)
    # The delete endpoint was not verified against a live tenant, so both a single object and a list are accepted.
    deletion_results = extract_records(raw_response)

    readable_output = tableToMarkdown(
        "Qualys ETM Deleted Reports",
        deletion_results,
        headers=["reportId", "message"],
        headerTransform=lambda header: {"reportId": "Report ID"}.get(header, pascalToSpace(header)),
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="QualysETM.ReportDeletion",
        outputs_key_field="reportId",
        outputs=deletion_results,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def build_report_generate_body(args: dict[str, Any]) -> dict[str, Any]:
    """Build the submit-findings-report request body from the command arguments."""
    body = {
        "name": args.get("name"),
        "description": args.get("description"),
        "reportFormat": args.get("report_format") or "JSON",
        "assetQql": args.get("asset_qql"),
        "findingsQql": args.get("findings_qql"),
    }
    # remove_empty_elements does not strip empty strings, which the API rejects for optional fields.
    return {key: value for key, value in body.items() if value not in (None, "")}


def build_generate_success_result(client: Client, report: dict[str, Any], report_id: str) -> list[Any]:
    """Build the command results of a completed report: the report details plus the downloaded archive."""
    archive = client.download_report_archive(report_id)
    command_results = CommandResults(
        outputs_prefix="QualysETM.Report",
        outputs_key_field="id",
        outputs=report,
        readable_output=report_details_to_markdown(report, f"Qualys ETM Report {report_id}"),
        raw_response=report,
    )
    return [command_results, fileResult(filename=f"report_{report_id}.zip", data=archive)]


def report_generate_command(args: dict[str, Any], client: Client) -> Any:
    """Submit a findings report, poll until it completes, and download it.

    The polling interval and timeout are command arguments, so the polling decorator is applied here at call
    time rather than at import time.

    Args:
        args: The command arguments.
        client: The Qualys ETM API client.

    Returns:
        The command results, or a scheduled command that polls again.
    """
    interval = arg_to_number(args.get("interval_in_seconds")) or DEFAULT_POLL_INTERVAL_SECONDS
    timeout = arg_to_number(args.get("timeout_in_seconds")) or DEFAULT_POLL_TIMEOUT_SECONDS
    polling_command = polling_function(
        name="qualys-etm-report-generate",
        interval=interval,
        timeout=timeout,
        poll_message="Generating the Qualys ETM report",
        requires_polling_arg=False,
    )(run_report_generate_poll)
    return polling_command(args, client)


def run_report_generate_poll(args: dict[str, Any], client: Client) -> PollResult:
    """Run a single iteration of the report generation polling flow.

    On the first invocation the report is submitted and its ID is carried over to the following polling
    iterations. Terminal failure statuses abort the polling immediately rather than waiting for the timeout.
    """
    report_id = args.get("report_id")

    if not report_id:
        submission = client.submit_findings_report(build_report_generate_body(args))
        report_id = submission.get("id")
        if not report_id:
            raise DemistoException(f"The report submission did not return a report ID. Response: {submission}")
        demisto.debug(f"QualysETM: submitted report {report_id}.")
        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run={"report_id": report_id, **args},
        )

    report = client.get_report_details(report_id)
    status = report.get("status") or ""
    demisto.debug(f"QualysETM: report {report_id} status is {status}.")

    if status.upper() == COMPLETED_STATUS:
        return PollResult(response=build_generate_success_result(client, report, report_id), continue_to_poll=False)

    if is_failure_status(status):
        raise DemistoException(f"Generation of report {report_id} ended with status '{status}'.")

    if status.upper() not in IN_PROGRESS_STATUSES:
        demisto.debug(f"QualysETM: unrecognized status '{status}' for report {report_id}. Continuing to poll.")

    return PollResult(
        response=None,
        continue_to_poll=True,
        args_for_next_run={"report_id": report_id, **args},
        partial_result=CommandResults(
            readable_output=f"Waiting for report {report_id} to complete. Current status: {status or 'UNKNOWN'}."
        ),
    )


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials = params.get("credentials") or {}
    base_url = params["url"].rstrip("/")

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            username=credentials.get("identifier", ""),
            password=credentials.get("password", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "qualys-etm-active-reports-list":
            return_results(active_reports_list_command(client, args))
        elif command == "qualys-etm-report-get-details":
            return_results(report_get_details_command(client, args))
        elif command == "qualys-etm-report-download":
            return_results(report_download_command(client, args))
        elif command == "qualys-etm-report-generate":
            return_results(report_generate_command(args, client))
        elif command == "qualys-etm-reports-delete":
            return_results(reports_delete_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as exception:
        return_error(f"Failed to execute {command} command.\nError:\n{exception!s}", error=exception)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
