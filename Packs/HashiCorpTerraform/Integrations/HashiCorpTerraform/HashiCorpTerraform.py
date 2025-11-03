import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import Response
import aiohttp
from http import HTTPStatus
import asyncio
from typing import Any
from collections.abc import Callable
import math
from datetime import datetime, timedelta, UTC

RUN_HR_KEY_TO_RES_KEY = {
    "Run id": "id",
    "Status": "attributes.status",
    "Plan id": "relationships.plan.data.id",
    "Planned at": "attributes.status-timestamps.planned-at",
}
PLAN_HR_KEY_TO_RES_KEY = {
    "Plan id": "id",
    "Status": "attributes.status",
    "Agent Queued at": "attributes.status-timestamps.agent-queued-at",
}
POLICIES_HR_KEY_TO_RES_KEY = {
    "Policy id": "id",
    "Policy name": "attributes.name",
    "Policy description": "attributes.description",
    "Kind": "attributes.kind",
    "Policy Set ids": "relationships.policy-sets.data.id",
    "Organization id": "relationships.organization.data.id",
}
SET_HR_KEY_TO_RES_KEY = {
    "Policy set id": "id",
    "Policy Set name": "attributes.name",
    "Description": "attributes.description",
    "Organization": "relationships.organization.data.id",
    "Policies ids": "relationships.policies.data.id",
    "Workspaces": "relationships.workspaces.data.id",
    "Projects": "relationships.projects.data.id",
}
CHECK_HR_KEY_TO_RES_KEY = {
    "Policy check id": "id",
    "Result": "attributes.result",
    "Status": "attributes.status",
    "Scope ": "attributes.scope",
}

VENDOR = "HashiCorp"
PRODUCT = "Terraform"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

DEFAULT_GET_EVENTS_LIMIT = 10
DEFAULT_FETCH_EVENTS_LIMIT = 10000

DEFAULT_AUDIT_TRAIL_PAGE_SIZE = 1000
DEFAULT_AUDIT_TRAIL_FROM_DATE = datetime.now(tz=UTC) - timedelta(hours=1)
DEFAULT_AUDIT_TRAIL_MAX_RETRIES = 3


class Client(BaseClient):
    """A synchronous client for interacting with the HashiCorp Terraform API; used for basic commands"""

    def __init__(
        self,
        url: str,
        token: str,
        default_organization_name: str | None = None,
        default_workspace_id: str | None = None,
        verify: bool = True,
        proxy: bool = False,
    ):
        self._default_organization_name = default_organization_name
        self._default_workspace_id = default_workspace_id

        headers = {"Authorization": f"Bearer {token}"}
        super().__init__(base_url=url, verify=verify, proxy=proxy, headers=headers)

    def test_connection(self):
        return self._http_request("GET", "account/details")

    def runs_list_request(
        self,
        workspace_id: str | None = None,
        run_id: str | None = None,
        filter_status: str | None = None,
        page_number: str | None = None,
        page_size: str | None = None,
    ) -> dict:
        params = {}
        if not run_id:
            if filter_status:
                params["filter[status]"] = filter_status
            if page_number:
                params["page[number]"] = page_number
            if page_size:
                params["page[size]"] = page_size

            workspace_id = workspace_id or self._default_workspace_id
            if not workspace_id:
                raise DemistoException(
                    "Please provide either, the instance param 'Default Workspace Id' or the command argument 'workspace_id'"
                )
        url_suffix = f"/runs/{run_id}" if run_id else f"/workspaces/{workspace_id}/runs"
        response = self._http_request("GET", url_suffix, params=params)

        return response

    def run_action(self, run_id: str, action: str, comment: str | None = None) -> Response:
        return self._http_request(
            "POST",
            f"runs/{run_id}/actions/{action}",
            json_data={"comment": comment} if comment and action != "force-execute" else None,
            headers=self._headers | {"Content-Type": "application/vnd.api+json"},
            ok_codes=[200, 202, 403, 404, 409],
            resp_type="response",
        )

    def get_plan(self, plan_id: str, json_output: bool) -> Response:
        url_suffix = f'/plans/{plan_id}{"/json-output" if json_output else ""}'
        return self._http_request("GET", url_suffix, resp_type="response")

    def list_policies(
        self,
        organization_name: str | None = None,
        policy_kind: str | None = None,
        policy_name: str | None = None,
        policy_id: str | None = None,
    ) -> dict:
        params = {}
        if not policy_id:
            if policy_kind:
                params["filter[kind]"] = policy_kind
            if policy_name:
                params["search[name]"] = policy_name
            organization_name = organization_name or self._default_organization_name
            if not organization_name:
                raise DemistoException(
                    "Please provide either the instance param '\
                        'Default Organization Name' or the command argument 'organization_name'"
                )

        url_suffix = f"/policies/{policy_id}" if policy_id else f"/organizations/{organization_name}/policies"
        response = self._http_request("GET", url_suffix, params=params)

        return response

    def list_policy_sets(
        self,
        organization_name: str | None,
        policy_set_id: str | None,
        versioned: str | None,
        policy_set_kind: str | None,
        include: str | None,
        policy_set_name: str | None,
        page_number: str | None,
        page_size: str | None,
    ) -> dict:
        params: dict[str, str] = {}
        if not policy_set_id:
            if versioned:
                params["filter[versioned]"] = versioned
            if policy_set_kind:
                params["filter[kind]"] = policy_set_kind
            if include:
                params["include"] = include
            if policy_set_name:
                params["search[name]"] = policy_set_name
            if page_number:
                params["page[number]"] = page_number
            if page_size:
                params["page[size]"] = page_size
            organization_name = organization_name or self._default_organization_name
            if not organization_name:
                raise DemistoException(
                    "Please provide either the instance param 'Default Organization Name'\
                        ' or the command argument 'organization_name'"
                )

        url_suffix = f"/policy-sets/{policy_set_id}" if policy_set_id else f"/organizations/{organization_name}/policy-sets"
        return self._http_request("GET", url_suffix, params=params)

    def list_policy_checks(
        self, run_id: str | None, policy_check_id: str | None, page_number: str | None, page_size: str | None
    ) -> dict:
        """List Terraform policy checks"""
        params = {}
        if page_number:
            params["page[number]"] = page_number
        if page_size:
            params["page[size]"] = page_size

        url_suffix = f"/runs/{run_id}/policy-checks" if run_id else f"/policy-checks/{policy_check_id}"
        return self._http_request("GET", url_suffix, params=params)


class AsyncClient:
    """An asynchronous client for interacting with the HashiCorp Terraform API; used for SIEM event collection"""

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool):
        self.base_url = base_url
        self._headers = {"Authorization": f"Bearer {token}"}
        self._verify = verify
        self._proxy_url = handle_proxy().get("http") if proxy else None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(headers=self._headers, connector=aiohttp.TCPConnector(ssl=self._verify))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            exception_traceback = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
            demisto.error(f"AsyncClient context exited with an exception: {exception_traceback}.")
        else:
            demisto.debug("AsyncClient context exited normally.")

        # Always ensure HTTP client session is closed
        await self._session.close()

    async def get_audit_trails(
        self,
        from_date: str,
        page_number: int,
        page_size: int = DEFAULT_AUDIT_TRAIL_PAGE_SIZE,
        max_retries: int = DEFAULT_AUDIT_TRAIL_MAX_RETRIES,
    ) -> dict[str, Any]:
        """
        Retrieves audit trails from Terraform.

        Args:
            from_date (str): The start date for the audit trails in ISO 8601 format.
            page_number (int): The page number to retrieve.
            page_size (int): The number of items per page. Default is 1000.
            max_retries (int): The maximum number of retries following HTTP 429 errors. Default is 3.

        Returns:
            dict[str, Any]: A dictionary containing the audit trails raw API response.
        """
        params: dict[str, str] = {"since": from_date, "page[number]": str(page_number), "page[size]": str(page_size)}
        url = urljoin(self.base_url, "/organization/audit-trail")

        backoff_factor = 1

        for attempt in range(max_retries):
            try:
                attempt_string = f"attempt {attempt + 1}/{max_retries}"
                demisto.debug(f"Starting request for audit trails ({attempt_string}) using {params=}.")
                async with self._session.get(url=url, params=params, proxy=self._proxy_url) as response:
                    response.raise_for_status()
                    response_json = await response.json()
                    response_data = response_json.get("data", [])
                    oldest_event_time = newest_event_time = None
                    if response_data:
                        # The first event is the newest, and the last event is the oldest
                        newest_event_time = response_data[0]["timestamp"]
                        oldest_event_time = response_data[-1]["timestamp"]
                    demisto.debug(
                        f"Finished request for audit trails using {params=}. "
                        f"Got {len(response_data)} items: {oldest_event_time=}, {newest_event_time=}."
                    )
                    return response_json

            except aiohttp.ClientResponseError as e:
                if e.status == HTTPStatus.TOO_MANY_REQUESTS and attempt < max_retries - 1:
                    delay = int(backoff_factor * (2**attempt))  # double the back off time each time
                    demisto.debug(f"Got rate limit error ({attempt_string}) using {params=}. Backing off for {delay} seconds.")
                    await asyncio.sleep(delay)
                else:
                    demisto.error(f"Request failed with status {e.status}: {e.message}")
                    raise

        raise Exception(f"Failed after {max_retries} attempts to retrieve audit trails using {params=}.")


def deduplicate_and_format_events(
    raw_response: dict[str, Any],
    all_fetched_ids: set[str],
) -> list[dict[str, Any]]:
    """
    Processes events from a raw API response, deduplicates them, and adds the _time field.

    Args:
        raw_response (dict[str, Any]): A dictionary containing the raw API response of the audit trails.
        all_fetched_ids (set[str]): A set of event IDs that have already been fetched.

    Returns:
        list[dict[str, Any]]: A list of new, processed events.
    """
    events = []
    for event in raw_response.get("data", []):
        event_id = event["id"]
        if event_id in all_fetched_ids:
            demisto.debug(f"Skipping duplicate {event_id=}.")
            continue
        all_fetched_ids.add(event_id)
        # `arg_to_datetime` does not return `None` since `timestamp` field exists and has a supported format
        # Added `type: ignore` to silence type checkers and linters
        event["_time"] = arg_to_datetime(event["timestamp"]).strftime(DATE_FORMAT)  # type: ignore [union-attr]
        events.append(event)
    return events


async def get_audit_trail_events(
    client: AsyncClient,
    from_date: str,
    limit: int,
    last_fetched_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Asynchronously fetches audit trail events from Terraform, handling pagination.
    Since the API returns events from newest to oldest, pages are fetched in reverse order to process the oldest events first.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        from_date (str): The start date for the audit trails in ISO 8601 format.
        limit (int): The maximum number of events to retrieve.
        last_fetched_ids (list[str]): A list of IDs of events that have already been fetched.

    Returns:
        list[dict[str, Any]]: A list of new audit trail events, sorted from oldest to newest.
    """
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events = []

    # Get the first page to determine the total number of pages since the API returns events from newest to oldest
    first_page_raw_response = await client.get_audit_trails(from_date=from_date, page_number=1)
    total_pages = first_page_raw_response.get("pagination", {}).get("total_pages", 1)

    # Calculate the number of pages to fetch to meet the limit
    page_size = DEFAULT_AUDIT_TRAIL_PAGE_SIZE
    required_pages = math.ceil(limit / page_size)
    pages_to_fetch = min(total_pages, int(required_pages))

    # Determine the range of pages to fetch (from last to first)
    start_page = total_pages
    stop_page = max(0, total_pages - pages_to_fetch)  # stop page not included!

    if pages_to_fetch > 0:
        # Create tasks to fetch pages concurrently, from oldest to newest
        audit_trail_tasks = [
            client.get_audit_trails(from_date=from_date, page_number=page_number)
            for page_number in range(start_page, stop_page, -1)
        ]

        # Gather responses from all API requests. If one page fails, all will fail to avoid missing events
        raw_responses = await asyncio.gather(*audit_trail_tasks)

        for raw_response in raw_responses:
            new_events = deduplicate_and_format_events(raw_response, all_fetched_ids)
            # Since we are fetching pages in reverse (oldest to newest)
            all_events.extend(new_events)

    # Sort all collected events by timestamp (oldest to newest) and return up to the limit
    all_events.sort(key=lambda event: event["timestamp"])
    return all_events[:limit]


async def get_events_command(client: AsyncClient, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Implements the `terraform-get-events` command. Gets audit trail events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        args (dict[str, Any]): The command arguments.

    Returns:
        tuple[list[dict[str, Any]], CommandResults]: A tuple of the events list and the CommandResults with human-readable output.
    """
    from_date = (arg_to_datetime(args.get("from_date")) or DEFAULT_AUDIT_TRAIL_FROM_DATE).strftime(DATE_FORMAT)
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT

    events = await get_audit_trail_events(client, from_date, limit)

    return events, CommandResults(readable_output=tableToMarkdown(name="Terraform Audit Trail Events", t=events))


async def fetch_events_command(
    client: AsyncClient,
    last_run: dict,
    max_fetch: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Implements `fetch-events` command. Fetches audit trail events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object.
        max_fetch (int): The maximum number of events to fetch.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of the the next run object and a list of fetched events.
    """
    demisto.debug(f"Starting fetching events with {last_run=}.")
    from_date = last_run.get("from_date") or DEFAULT_AUDIT_TRAIL_FROM_DATE.strftime(DATE_FORMAT)
    last_fetched_ids = last_run.get("last_fetched_ids", [])

    all_events = await get_audit_trail_events(
        client=client,
        from_date=from_date,
        limit=max_fetch,
        last_fetched_ids=last_fetched_ids,
    )

    if not all_events:
        demisto.debug(f"No new events found since {last_run=}.")
        return last_run, []

    # Events are sorted by `timestamp` in ascending order inside `get_audit_trail_events`
    newest_event_timestamp = all_events[-1]["timestamp"]
    demisto.debug(f"Got {len(all_events)} deduplicated events with {newest_event_timestamp=}.")

    # Get the IDs of the events that have the newest timestamp
    new_last_fetched_ids = [event["id"] for event in all_events if event["timestamp"] == newest_event_timestamp]

    next_run = {"from_date": newest_event_timestamp, "last_fetched_ids": new_last_fetched_ids}
    demisto.debug(f"Updating {next_run=} after fetching {len(all_events)} events.")

    return next_run, all_events


def runs_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace_id = args.get("workspace_id")
    run_id = args.get("run_id")
    filter_status = args.get("filter_status")
    page_number = args.get("page_number")
    page_size = args.get("page_size")

    res = client.runs_list_request(workspace_id, run_id, filter_status, page_number, page_size)
    # when run_id is provided, it returns a single run instead of a list
    data = [res.get("data", {})] if run_id else res.get("data", [])
    hr_items = [
        {hr_key: demisto.get(run, response_key) for hr_key, response_key in RUN_HR_KEY_TO_RES_KEY.items()} for run in data
    ]
    command_results = CommandResults(
        outputs_prefix="Terraform.Run",
        outputs_key_field="data.id",
        outputs=res,
        readable_output=tableToMarkdown("Terraform Runs", hr_items, removeNull=True),
    )

    return command_results


def run_action_command(client: Client, args: Dict[str, Any]) -> str:
    run_id = args.get("run_id")
    action = args.get("action")
    comment = args.get("comment")

    if not run_id or not action:
        raise DemistoException("run_id and action are required")

    if action == "force-execute" and comment:
        raise DemistoException("comment parameter is invalid for force-execute action")

    res = client.run_action(run_id=run_id, action=action, comment=comment)

    action_msg = f"queued an {action} request for run id {run_id}"
    if res.status_code == 202:
        return f"Successfully {action_msg}"
    else:
        raise DemistoException(f'Error occurred when {action_msg}: {res.json().get("errors",[{}])[0].get("title")}')


def plan_get_command(client: Client, args: Dict[str, Any]) -> CommandResults | dict[str, Any]:
    plan_id = args.get("plan_id")
    json_output = argToBoolean(args.get("json_output", False))

    if not plan_id:
        raise DemistoException("plan_id is required")
    res = client.get_plan(plan_id, json_output)

    if json_output:
        return fileResult(filename=f"{plan_id}.json", data=res.content, file_type=EntryType.ENTRY_INFO_FILE)

    res_json = res.json()
    plan = res_json.get("data", {})
    hr_plan = {hr_key: demisto.get(plan, response_key) for hr_key, response_key in PLAN_HR_KEY_TO_RES_KEY.items()}

    command_results = CommandResults(
        outputs_prefix="Terraform.Plan",
        outputs_key_field="id",
        outputs=plan,
        raw_response=res_json,
        readable_output=tableToMarkdown("Terraform Plan", hr_plan),
    )

    return command_results


def policies_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get("organization_name")
    policy_kind = args.get("policy_kind")
    policy_name = args.get("policy_name")
    policy_id = args.get("policy_id")

    res = client.list_policies(organization_name, policy_kind, policy_name, policy_id)
    # when policy_id is provided, it returns a single policy instead of a list
    data = [res.get("data", {})] if policy_id else res.get("data", [])
    hr_items = [
        {hr_key: demisto.dt(policy, response_key) for hr_key, response_key in POLICIES_HR_KEY_TO_RES_KEY.items()}
        for policy in data
    ]

    command_results = CommandResults(
        outputs_prefix="Terraform.Policy",
        outputs_key_field="id",
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown("Terraform Policies", hr_items, removeNull=True),
    )

    return command_results


def policy_set_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get("organization_name")
    policy_set_id = args.get("policy_set_id")
    versioned = args.get("versioned")
    policy_set_kind = args.get("policy_set_kind")
    include = args.get("include")
    policy_set_name = args.get("policy_set_name")
    page_number = args.get("page_number")
    page_size = args.get("page_size")

    res = client.list_policy_sets(
        organization_name, policy_set_id, versioned, policy_set_kind, include, policy_set_name, page_number, page_size
    )
    # when policy_set_id is provided, it returns a single policy set instead of a list
    data = [res.get("data", {})] if policy_set_id else res.get("data", [])
    hr_items = [
        {hr_key: demisto.dt(policy_set, response_key) for hr_key, response_key in SET_HR_KEY_TO_RES_KEY.items()}
        for policy_set in data
    ]

    return CommandResults(
        outputs_prefix="Terraform.PolicySet",
        outputs_key_field="id",
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown("Terraform Policy Sets", hr_items, removeNull=True),
    )


def policies_checks_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    run_id = args.get("run_id")
    policy_check_id = args.get("policy_check_id")
    page_number = args.get("page_number")
    page_size = args.get("page_size")

    res = client.list_policy_checks(run_id, policy_check_id, page_number, page_size)

    # when policy_check_id is provided, it returns a single check instead of a list
    data = [res.get("data", {})] if policy_check_id else res.get("data", [])
    hr_items = [
        {hr_key: demisto.get(policy_check, response_key) for hr_key, response_key in CHECK_HR_KEY_TO_RES_KEY.items()}
        for policy_check in data
    ]

    return CommandResults(
        outputs_prefix="Terraform.PolicyCheck",
        outputs_key_field="id",
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown("Terraform Policy Checks", hr_items, removeNull=True),
    )


def test_module(client: Client) -> str:
    try:
        client.test_connection()
    except Exception as e:
        if "Unauthorized" in str(e):
            raise DemistoException("Unauthorized: Please be sure you put a valid API Token")
        raise e
    return "ok"


async def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    url = params.get("server_url", "https://app.terraform.io/api/v2").rstrip("/")
    token = params.get("credentials", {}).get("password")
    default_workspace_id = params.get("default_workspace_id")
    default_organization_name = params.get("default_organization_name")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    is_fetch_events = params.get("isFetchEvents", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_EVENTS_LIMIT

    demisto.debug(f"Command being called is {command}")

    sync_commands: dict[str, Callable] = {
        "terraform-runs-list": runs_list_command,
        "terraform-run-action": run_action_command,
        "terraform-plan-get": plan_get_command,
        "terraform-policies-list": policies_list_command,
        "terraform-policy-set-list": policy_set_list_command,
        "terraform-policies-checks-list": policies_checks_list_command,
    }

    async_commands: tuple[str, str] = ("terraform-get-events", "fetch-events")

    try:

        def _initialize_sync_client() -> Client:
            return Client(url, token, default_organization_name, default_workspace_id, verify_certificate, proxy)

        def _initialize_async_client() -> AsyncClient:
            return AsyncClient(base_url=url, token=token, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            client: Client = _initialize_sync_client()
            test_results = test_module(client)
            if is_fetch_events:
                async with _initialize_async_client() as async_client:
                    await fetch_events_command(async_client, last_run={}, max_fetch=1)
            return_results(test_results)

        elif command in sync_commands:
            client = _initialize_sync_client()
            command_results = sync_commands[command](client, args)
            return_results(command_results)

        elif command in async_commands and (is_xsiam() or is_platform()):
            async with _initialize_async_client() as async_client:
                if command == "fetch-events":
                    last_run = demisto.getLastRun()
                    next_run, events = await fetch_events_command(async_client, last_run=last_run, max_fetch=max_fetch)
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                    demisto.setLastRun(next_run)
                elif command == "terraform-get-events":
                    should_push_events = argToBoolean(args.pop("should_push_events", False))
                    events, command_results = await get_events_command(async_client, args)
                    return_results(command_results)
                    if should_push_events:
                        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    asyncio.run(main())
