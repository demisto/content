import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *
import urllib3
import threading
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "SPA"
CLIENT_NAME = "CitrixSPA"
RECORDS_REQUEST_LIMIT = 200  # Max records per API request
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


""" AUTH HANDLER """


class CitrixOAuth2Handler(AuthHandler):
    """Custom OAuth2 handler for Citrix Cloud API.

    Citrix Cloud uses a non-standard authorization header format:
    ``CwsAuth Bearer={access_token}`` instead of the standard ``Bearer <token>``.

    This handler manages the OAuth2 client_credentials flow and token refresh
    for the Citrix Cloud SystemLog API.

    Args:
        token_url: Full URL to the Citrix Cloud token endpoint.
        client_id: OAuth2 client ID from Citrix Cloud Service Principal.
        client_secret: OAuth2 client secret from Citrix Cloud Service Principal.
        customer_id: Citrix Cloud customer/tenant ID.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        customer_id: str,
    ) -> None:
        if not token_url:
            raise ContentClientConfigurationError("CitrixOAuth2Handler requires a non-empty token_url")
        if not client_id:
            raise ContentClientConfigurationError("CitrixOAuth2Handler requires a non-empty client_id")
        if not client_secret:
            raise ContentClientConfigurationError("CitrixOAuth2Handler requires a non-empty client_secret")
        if not customer_id:
            raise ContentClientConfigurationError("CitrixOAuth2Handler requires a non-empty customer_id")

        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._customer_id = customer_id
        self._access_token: str | None = None
        self._lock = threading.Lock()

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        """Add Citrix-specific auth and customer ID headers to each request.

        Args:
            client: The ContentClient instance.
            request: The HTTP request to modify.
        """
        if not self._access_token:
            await self._refresh_token(client)

        request.headers["Authorization"] = f"CwsAuth Bearer={self._access_token}"
        request.headers["Citrix-CustomerId"] = self._customer_id

    async def on_auth_failure(self, client: "ContentClient", response: httpx.Response) -> bool:
        """Handle 401 responses by refreshing the token.

        Args:
            client: The ContentClient instance.
            response: The failed HTTP response.

        Returns:
            True if token was refreshed successfully and request should be retried.
        """
        demisto.info("Citrix access token expired or invalid; refreshing...")
        try:
            await self._refresh_token(client)
            return True
        except ContentClientAuthenticationError:
            return False

    async def _refresh_token(self, client: "ContentClient") -> None:
        """Refresh the OAuth2 access token using client credentials.

        Args:
            client: The ContentClient instance (used for SSL verification settings).

        Raises:
            ContentClientAuthenticationError: If token refresh fails.
        """
        demisto.debug("Refreshing Citrix Cloud access token")

        with self._lock:
            try:
                async with httpx.AsyncClient(verify=client._verify) as http_client:
                    response = await http_client.post(
                        self._token_url,
                        headers={
                            "Accept": "application/json",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        data={
                            "grant_type": "client_credentials",
                            "client_id": self._client_id,
                            "client_secret": self._client_secret,
                        },
                    )
                    response.raise_for_status()
                    token_data = response.json()
                    self._access_token = token_data.get("access_token")

                    if not self._access_token:
                        raise ContentClientAuthenticationError("No access_token in Citrix Cloud token response")

                    demisto.debug("Citrix Cloud access token refreshed successfully")

            except httpx.HTTPStatusError as e:
                raise ContentClientAuthenticationError(
                    f"Token refresh failed with status {e.response.status_code}: {e.response.text}"
                ) from e
            except httpx.TimeoutException as e:
                raise ContentClientAuthenticationError(f"Token refresh timed out: {str(e)}") from e
            except ContentClientAuthenticationError:
                raise
            except Exception as e:
                raise ContentClientAuthenticationError(f"Failed to refresh Citrix Cloud token: {str(e)}") from e


""" CLIENT CLASS """


class Client(ContentClient):
    """Client for the Citrix Cloud SystemLog API focused on SPA events.

    Extends ContentClient with Citrix-specific functionality including
    custom OAuth2 authentication and pagination for SystemLog records.

    Args:
        base_url: The Citrix Cloud API base URL.
        customer_id: Citrix Cloud customer/tenant ID.
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
        verify: Whether to verify SSL certificates.
        proxy: Whether to use system proxy settings.
    """

    def __init__(
        self,
        base_url: str,
        customer_id: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
    ) -> None:
        token_url = f"{base_url}/cctrustoauth2/{customer_id}/tokens/clients"

        auth_handler = CitrixOAuth2Handler(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            customer_id=customer_id,
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name=CLIENT_NAME,
        )

        self.customer_id = customer_id

    def get_records(
        self,
        start_date_time: str | None,
        end_date_time: str | None,
        continuation_token: str | None = None,
        limit: int | None = None,
    ) -> dict:
        """Fetch a single page of SystemLog records from the Citrix Cloud API.

        Args:
            start_date_time: Start datetime filter in ISO format.
            end_date_time: End datetime filter in ISO format.
            continuation_token: Token for fetching the next page of results.
            limit: Maximum number of records to return per request.

        Returns:
            API response dict containing ``items`` and ``continuationToken``.
        """
        params = assign_params(
            Limit=min(limit if limit else RECORDS_REQUEST_LIMIT, RECORDS_REQUEST_LIMIT),
            continuationToken=continuation_token,
            startDateTime=start_date_time,
            endDateTime=end_date_time,
        )

        demisto.info(f"Sending request to get SPA records with {params=}")

        response = self.get(
            url_suffix="/systemlog/records",
            params=params,
            resp_type="json",
        )

        return response

    def get_records_with_pagination(
        self,
        limit: int,
        start_date_time: str | None,
        end_date_time: str | None = None,
        last_record_id: str | None = None,
    ) -> tuple[list[dict], dict | None]:
        """Fetch SystemLog records with automatic pagination and deduplication.

        Iterates through pages using ``continuationToken`` until the requested
        number of records is collected or no more pages are available.

        Args:
            limit: Maximum total number of records to return.
            start_date_time: Start datetime filter in ISO format.
            end_date_time: End datetime filter in ISO format.
            last_record_id: ID of the last fetched record for deduplication.

        Returns:
            Tuple of (records list with ``_time`` field added, last raw API response).
        """
        records: list[dict] = []
        continuation_token = None
        raw_res: dict | None = None

        while len(records) < int(limit):
            raw_res = self.get_records(
                start_date_time=start_date_time,
                end_date_time=end_date_time,
                continuation_token=continuation_token,
                limit=limit,
            )

            items = raw_res.get("items", [])
            items.reverse()

            # Skip items up to and including the last fetched record to avoid duplicates
            if items and last_record_id:
                for idx, item in enumerate(items):
                    if item.get("recordId") == last_record_id:
                        items = items[idx + 1:]
                        break

            records.extend(items)
            continuation_token = raw_res.get("continuationToken")

            if not continuation_token:
                break

        records = records[:limit]

        for record in records:
            record["_time"] = record.get("utcTimestamp")

        return records, raw_res


""" COMMAND FUNCTIONS """


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Execute the citrix-spa-get-events command.

    Retrieves SPA events from the Citrix Cloud SystemLog API and optionally
    pushes them to XSIAM.

    Args:
        client: The Citrix SPA client instance.
        args: Command arguments including limit, date filters, and should_push_events.

    Returns:
        CommandResults with the retrieved events.
    """
    limit = int(args.get("limit", "10"))

    end_date_time = args.get("end_date_time")
    end_date_time = (
        dateparser.parse(end_date_time).strftime(DATE_FORMAT)  # type: ignore[union-attr]
        if end_date_time
        else None
    )

    start_date_time = args.get("start_date_time")
    start_date_time = (
        dateparser.parse(start_date_time).strftime(DATE_FORMAT)  # type: ignore[union-attr]
        if start_date_time
        else None
    )

    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-spa-get-events with {should_push_events=}")

    records, raw_res = client.get_records_with_pagination(
        limit=limit,
        start_date_time=start_date_time,
        end_date_time=end_date_time,
    )

    results = CommandResults(
        outputs_prefix="CitrixSPA.Event",
        outputs_key_field="recordId",
        outputs=records,
        readable_output=tableToMarkdown("Citrix SPA Events", records),
        raw_response=raw_res,
    )

    if should_push_events:
        demisto.debug(f"Sending {len(records)} SPA events to XSIAM")
        send_events_to_xsiam(records, vendor=VENDOR, product=PRODUCT)

    return results


def fetch_events_command(client: Client, max_fetch: int, last_run: dict) -> tuple[list[dict], dict]:
    """Execute the fetch-events command for automated event collection.

    Fetches new events since the last run and updates the checkpoint.

    Args:
        client: The Citrix SPA client instance.
        max_fetch: Maximum number of events to fetch per run.
        last_run: Dictionary containing the last run state (LastRun timestamp, RecordId).

    Returns:
        Tuple of (events list, updated last_run dict).
    """
    start_date_time = last_run.get("LastRun") or datetime.utcnow().strftime(DATE_FORMAT)
    records, _ = client.get_records_with_pagination(
        limit=max_fetch,
        start_date_time=start_date_time,
        last_record_id=last_run.get("RecordId"),
    )

    if records:
        last_run = {
            "LastRun": records[-1]["_time"],
            "RecordId": records[-1]["recordId"],
        }

    return records, last_run


def module_test_command(client: Client, args: dict) -> str:
    """Test the integration connection by fetching a small number of events.

    Args:
        client: The Citrix SPA client instance.
        args: Command arguments (unused but required by interface).

    Returns:
        'ok' if the test succeeds.
    """
    get_events_command(client, {"limit": "1", "should_push_events": "false"})
    return "ok"


""" MAIN FUNCTION """


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=params.get("url", "").rstrip("/"),
            customer_id=params.get("customer_id", ""),
            client_id=params.get("client_id", ""),
            client_secret=params.get("credentials", {}).get("password", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )

        if command == "test-module":
            result = module_test_command(client, args)
            return_results(result)

        elif command == "citrix-spa-get-events":
            results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            max_fetch = int(params.get("max_fetch", "2000"))
            last_run = demisto.getLastRun()
            demisto.debug(f"Last run is: {last_run}")

            events, last_run = fetch_events_command(client, max_fetch, last_run)

            if not events:
                demisto.info("No SPA events found")
            demisto.debug(f"Sending {len(events)} SPA events to XSIAM")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)
            demisto.debug(f"Last run set to: {last_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"{type(e).__name__} in {command}: {str(e)}\nTraceback:\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
