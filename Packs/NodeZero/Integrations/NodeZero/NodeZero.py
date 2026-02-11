from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from typing import Any, Literal, TypeAlias, TypedDict

import demistomock as demisto
import requests
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

from pydantic import BaseModel
from pydantic_core import ValidationError

urllib3.disable_warnings()

XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NZ_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


MAX_PAGE_SIZE = 100
DEFAULT_MAX_FETCH = 200
DEFAULT_FIRST_FETCH = "7 days"

AUTH_ENDPOINT = "v1/auth"
GRAPHQL_ENDPOINT = "v1/graphql"

HELLO_WORLD_QUERY = "query HelloWorld { hello }"

WEAKNESSES_PAGE_QUERY = """
query WeaknessesPage($page_input: PageInput!) {
  weaknesses_page(page_input: $page_input) {
    weaknesses {
        uuid
        created_at
        vuln_id
        vuln_name
        vuln_short_name
        vuln_category
        vuln_cisa_kev
        vuln_known_ransomware_campaign_use
        ip
        has_proof
        score
        severity
        affected_asset_uuid
        affected_asset_display_name
        attack_paths_count
        op_id
    }
    page_info {
      page_num
      page_size
    }
  }
}
"""


class Credentials(BaseModel):
    password: str


class Params(BaseModel):
    url: str
    credentials: Credentials
    insecure: bool = False
    proxy: bool = False
    max_fetch: int = DEFAULT_MAX_FETCH
    first_fetch: str = DEFAULT_FIRST_FETCH


class Token(BaseModel):
    token: str


class Incident(TypedDict):
    name: str
    occurred: str
    rawJSON: str
    dbotMirrorId: str


class Weakness(BaseModel):
    uuid: str
    created_at: str
    vuln_id: str
    vuln_name: str | None
    vuln_short_name: str | None
    vuln_category: str | None
    vuln_cisa_kev: bool | None
    vuln_known_ransomware_campaign_use: bool | None
    ip: str | None
    has_proof: bool | None
    score: float | None
    severity: str | None
    affected_asset_uuid: str | None
    affected_asset_display_name: str | None
    attack_paths_count: int
    op_id: str | None

    def to_incident(self) -> Incident:
        """Convert a Weakness to an XSOAR Incident."""
        asset_name = self.affected_asset_display_name or "Unknown Asset"
        vuln_name = self.vuln_short_name or self.vuln_name or self.vuln_id
        data = self.model_dump()
        data["incident_type"] = "NodeZero Weakness"
        return Incident(
            name=f"{vuln_name} on {asset_name}",
            occurred=self.created_at if self.created_at.endswith("Z") else f"{self.created_at}Z",
            dbotMirrorId=self.uuid,
            rawJSON=json.dumps(data),
        )


class PageInfo(BaseModel):
    page_num: int
    page_size: int


class WeaknessesPage(BaseModel):
    weaknesses: list[Weakness]
    page_info: PageInfo

    @classmethod
    def from_graphql_response(cls, response: dict) -> "WeaknessesPage":
        data = response.get("data", {}).get("weaknesses_page", {})
        return cls(
            weaknesses=[Weakness.model_validate(w) for w in data.get("weaknesses", [])],
            page_info=PageInfo.model_validate(data.get("page_info", {})),
        )


class LastRun(BaseModel):
    """State persisted between fetch-incidents runs."""

    last_fetch_date: str | None = None  # ISO 8601 format
    last_ids: list[str] = []  # UUIDs of incidents at last_fetch_date timestamp


@dataclass(frozen=True)
class UnauthenticatedError(Exception):
    message: str = "Authentication failed: invalid or expired API key"


@dataclass(frozen=True)
class TokenExpiredError(Exception): ...


@dataclass(frozen=True)
class ResponseValidationError(Exception):
    validation_error: ValidationError


@dataclass(frozen=True)
class ParametersValidationError(Exception):
    validation_error: ValidationError


HTTPError: TypeAlias = requests.HTTPError


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._base_url: str = base_url
        self._verify: bool = verify
        self._api_key: str = api_key
        self._jwt: str | None = None
        self._expiry: int = 0
        self.load_integration_context()

    def load_integration_context(self) -> None:
        context = get_integration_context()
        if context:
            self._jwt = context["jwt"]
            self._expiry = context["expiry"]

    def is_authenticated(self) -> bool:
        return self._jwt is not None and self._expiry > int(time.time())

    def authenticate(self) -> None:
        url = f"{self._base_url}/{AUTH_ENDPOINT}"
        json = {"key": self._api_key}
        now = int(time.time())

        response = self._session.post(url, json=json)
        self._raise_for_status(response)

        content = Token.model_validate_json(response.content)
        self._jwt = content.token
        self._expiry = now + 3600 - 60  # 1 hr minus 60s buffer to prevent race conditions
        _ = set_integration_context({"jwt": self._jwt, "expiry": self._expiry})

    def _graphql_request(self, query: str, variables: dict[str, Any]) -> requests.Response:
        url = f"{self._base_url}/{GRAPHQL_ENDPOINT}"
        headers = {"Authorization": f"Bearer {self._jwt}"}
        json = {"query": query, "variables": variables}
        resp = self._session.post(url, json=json, headers=headers)
        self._raise_for_status(resp)
        return resp

    def _raise_for_status(self, response: requests.Response) -> None:
        if response.status_code == 401:
            raise UnauthenticatedError
        response.raise_for_status()

    def hello_world(self) -> None:
        """Send hello_world request to check availability.

        If no error is raised, the call was successful
        """
        _ = self._graphql_request(HELLO_WORLD_QUERY, {})

    def query_weaknesses_page(
        self,
        page_num: int,
        page_size: int,
        since_date: str,
    ) -> WeaknessesPage:
        """Fetch a page of HIGH/CRITICAL OPEN weaknesses since the given date.

        Args:
            page_num: 1-indexed page number
            page_size: Number of results per page
            since_date: Fetch weaknesses first seen on or after this date (YYYY-MM-DD)

        Returns:
            WeaknessesPage with weaknesses list and page_info
        """
        variables = {
            "page_input": {
                "page_num": page_num,
                "page_size": page_size,
                "filter_by_inputs": [
                    {"field_name": "severity", "values": ["HIGH", "CRITICAL"]},
                    {"field_name": "created_at", "greater_than_or_equal": since_date},
                ],
                "order_by": "created_at",
                "sort_order": "ASC",
            }
        }
        resp = self._graphql_request(WEAKNESSES_PAGE_QUERY, variables)

        try:
            return WeaknessesPage.from_graphql_response(resp.json())
        except ValidationError as e:
            raise ResponseValidationError(e)


def authenticate(client: Client):
    if not client.is_authenticated():
        client.authenticate()


def fetch_all_weaknesses_pages(
    client: Client,
    since_date: str,
    max_fetch: int = DEFAULT_MAX_FETCH,
) -> list[Weakness]:
    """Fetch all HIGH/CRITICAL OPEN weaknesses since the given date, paginating as needed.

    Args:
        client: NodeZero API client
        since_date: Fetch weaknesses first seen on or after this date (YYYY-MM-DD)
        max_fetch: Maximum number of weaknesses to fetch

    Returns:
        List of WeaknessesPages, up to max_fetch items
    """
    all_weaknesses: list[Weakness] = []
    page_num = 1
    page_size = min(MAX_PAGE_SIZE, max_fetch)

    while len(all_weaknesses) < max_fetch:
        page = client.query_weaknesses_page(
            page_num=page_num,
            page_size=page_size,
            since_date=since_date,
        )
        all_weaknesses.extend(page.weaknesses)

        if len(page.weaknesses) < page_size:
            break

        page_num += 1

    return all_weaknesses[:max_fetch]


""" COMMAND FUNCTIONS """


def _test_module(client: Client) -> Literal["ok"]:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    authenticate(client)
    client.hello_world()
    return "ok"


def dedup_by_ids(weaknesses: list[Weakness], ids_to_skip: list[str]) -> list[Weakness]:
    """Filter out weaknesses that were already fetched in a previous run.

    Args:
        weaknesses: List of weaknesses to filter
        ids_to_skip: UUIDs of weaknesses to exclude

    Returns:
        List of weaknesses not in ids_to_skip
    """
    if not ids_to_skip:
        return weaknesses
    skip_set = set(ids_to_skip)
    return [w for w in weaknesses if w.uuid not in skip_set]


def fetch_incidents(
    client: Client,
    max_fetch: int = DEFAULT_MAX_FETCH,
    first_fetch_time: datetime | None = None,
) -> tuple[list[Incident], LastRun]:
    """Fetch HIGH/CRITICAL OPEN weaknesses as incidents.

    On first run, fetches weaknesses from `first_fetch_time`.
    On subsequent runs, fetches weaknesses since the last fetch date.

    Args:
        client: NodeZero API client
        max_fetch: Maximum number of incidents to fetch
        first_fetch_time: Datetime to fetch from on first run

    Returns:
        Tuple of (incidents list, new last_run state)
    """
    authenticate(client)
    last_run = LastRun.model_validate(demisto.getLastRun())

    if last_run.last_fetch_date:
        since_date = last_run.last_fetch_date
    elif first_fetch_time:
        since_date = first_fetch_time.strftime(NZ_DATE_FORMAT)
    else:
        since_date = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(NZ_DATE_FORMAT)

    demisto.debug(f"Fetching weaknesses since {since_date}")

    weaknesses = fetch_all_weaknesses_pages(
        client=client,
        since_date=since_date,
        max_fetch=max_fetch,
    )

    pre_dedup_count = len(weaknesses)
    weaknesses = dedup_by_ids(weaknesses, last_run.last_ids)
    demisto.debug(f"After deduplication: {len(weaknesses)} weaknesses (filtered {pre_dedup_count - len(weaknesses)})")

    if not weaknesses:
        if pre_dedup_count > 0 and last_run.last_fetch_date:
            # All results were duplicates — advance timestamp by 1s to prevent infinite loop
            advanced = datetime.strptime(last_run.last_fetch_date, NZ_DATE_FORMAT) + timedelta(seconds=1)
            next_run = LastRun(last_fetch_date=advanced.strftime(NZ_DATE_FORMAT), last_ids=[])
            demisto.debug(f"All results deduped; advancing fetch date to {next_run.last_fetch_date}")
            return [], next_run
        return [], last_run

    incidents = [w.to_incident() for w in weaknesses]

    latest_timestamp = max(w.created_at for w in weaknesses)
    last_ids = [w.uuid for w in weaknesses if w.created_at == latest_timestamp]

    next_run = LastRun(last_fetch_date=latest_timestamp, last_ids=last_ids)
    demisto.debug(f"Fetched {len(incidents)} incidents, next fetch from {latest_timestamp}")

    return incidents, next_run


def params() -> Params:
    try:
        return Params.model_validate(demisto.params())
    except ValidationError as e:
        raise ParametersValidationError(e)


def main():
    _args = demisto.args()
    command = demisto.command()

    try:
        params = Params.model_validate(demisto.params())
        demisto.debug(f"Command being called is {command}")

        client = Client(
            base_url=params.url,
            api_key=params.credentials.password,
            verify=not params.insecure,
            proxy=params.proxy,
        )

        if command == "test-module":
            return_results(_test_module(client))

        elif command == "fetch-incidents":
            first_fetch_time = arg_to_datetime(
                arg=params.first_fetch,
                arg_name="First fetch time",
                required=True,
            )
            incidents, next_run = fetch_incidents(
                client,
                max_fetch=params.max_fetch,
                first_fetch_time=first_fetch_time,
            )
            demisto.setLastRun(next_run.model_dump())
            demisto.incidents(incidents)  # type: ignore[arg-type]

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
