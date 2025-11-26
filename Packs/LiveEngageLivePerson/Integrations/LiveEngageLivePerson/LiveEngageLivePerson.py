import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
from typing import Any
from datetime import datetime, timedelta, UTC

""" CONSTANTS """

INTEGRATION_NAME = "LivePerson"
INTEGRATION_PREFIX = f"[{INTEGRATION_NAME}]"
DEFAULT_MAX_FETCH = 5000
API_PAGE_SIZE = 500  # The max allowed by the API is 500
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # Standard ISO format for last_run

# --- API Endpoints ---
# Domain API is public, unauthenticated
DOMAIN_API_URL = "https://api.liveperson.net/api/account/{account_id}/service/accountConfigReadOnly/baseURI.json?version=1.0"
# Auth API path (prepended with user-provided auth_server_url)
OAUTH_PATH_SUFFIX = "/sentinel/api/v2/account/{account_id}/app/token"
# Event API path (prepended with *discovered* event_base_url)
FETCH_PATH_SUFFIX = "/api/account/{account_id}/configuration/metadata/audit"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class for LivePerson API.
    This client is initialized with the *discovered* Event API domain as its base_url.
    It handles OAuth 2.0 token generation and refresh against a *separate*
    authentication server, all while respecting proxy and SSL settings.
    """

    def __init__(
        self, base_url: str, account_id: str, auth_server_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool
    ):
        """
        Initializes the client.
        :param base_url: The discovered Event API domain (e.g., https://va.ac.liveperson.net)
        :param account_id: The user's LivePerson Account ID.
        :param auth_server_url: The user-provided Auth server (e.g., va.sentinel.liveperson.net)
        :param client_id: OAuth Client ID.
        :param client_secret: OAuth Client Secret.
        :param verify: SSL verification flag.
        :param proxy: Proxy usage flag.
        """
        self.account_id = account_id
        self.auth_url = f"https://{auth_server_url}"
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={"Content-Type": "application/json"})

        demisto.info(f"{INTEGRATION_PREFIX} Client initialized. Event API Base URL: {base_url}")

    @staticmethod
    def _get_event_domain(account_id: str, verify: bool, proxy: bool) -> str:
        """
        [STATIC] Uses the public LivePerson Domain API to find the correct
        base URL for the 'accountConfigReadOnly' service.
        This call is unauthenticated but MUST respect proxy/verify settings.
        We use a temporary BaseClient for this one-off call.

        :param account_id: The user's LivePerson Account ID.
        :param verify: SSL verification flag.
        :param proxy: Proxy usage flag (boolean).
        :return: The full base URL for the event API (e.g., https://va.ac.liveperson.net)
        :raises: DemistoException if the domain cannot be fetched or parsed.
        """
        # Note: DOMAIN_API_URL is a full URL, but BaseClient needs a base and a suffix.
        # "https://api.liveperson.net/api/account/{account_id}/service/accountConfigReadOnly/baseURI.json?version=1.0"
        domain_api_base = "https://api.liveperson.net"
        domain_api_path = f"/api/account/{account_id}/service/accountConfigReadOnly/baseURI.json"
        params = {"version": "1.0"}

        demisto.info(f"{INTEGRATION_PREFIX} Attempting to fetch event domain from: {domain_api_base}{domain_api_path}")

        try:
            # Use a temporary BaseClient. It will correctly handle proxy and verify.
            temp_client = BaseClient(base_url=domain_api_base, verify=verify, proxy=proxy)
            data = temp_client._http_request(
                method="GET", url_suffix=domain_api_path, params=params, resp_type="json", ok_codes=(200,)
            )
        except DemistoException as e:
            # BaseClient wraps HTTPError and RequestException in DemistoException
            msg = f"Failed to fetch event domain. Error: {str(e)}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

        try:
            event_domain = data.get("baseURI")
            if not event_domain:
                msg = f'Event domain API response missing "baseURI" field. Response: {data}'
                demisto.error(f"{INTEGRATION_PREFIX} {msg}")
                raise DemistoException(msg)

            demisto.info(f"{INTEGRATION_PREFIX} Successfully fetched event domain: {event_domain}")
            return f"https://{event_domain}"

        except AttributeError as e:
            # This handles if 'data' is not a dictionary as expected
            msg = f"Failed to parse event domain API response. Expected JSON dict. Response: {data}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

    def _get_access_token(self) -> str:
        """
        [INSTANCE] Generates an OAuth 2.0 access token from the *authentication* server.
        This call is separate from the main base_url but MUST
        respect the client's proxy/verify settings.

        :return: A valid access token string.
        :raises: DemistoException if the token cannot be fetched or parsed.
        """
        token_path = OAUTH_PATH_SUFFIX.format(account_id=self.account_id)
        full_auth_url = urljoin(self.auth_url, token_path)

        data = {"client_id": self.client_id, "client_secret": self.client_secret, "grant_type": "client_credentials"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        demisto.info(f"{INTEGRATION_PREFIX} Attempting to get new OAuth 2.0 token from: {self.auth_url}")

        try:
            token_data = super()._http_request(
                method="POST", full_url=full_auth_url, data=data, headers=headers, resp_type="json", ok_codes=(200,)
            )
        except DemistoException as e:
            # BaseClient will raise DemistoException for HTTP errors or network issues
            msg = f"Failed to get access token. Error: {str(e)}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

        try:
            access_token = token_data.get("access_token")
            if not access_token:
                msg = f'Auth response missing "access_token" field. Response: {token_data}'
                demisto.error(f"{INTEGRATION_PREFIX} {msg}")
                raise DemistoException(msg)

            demisto.info(f"{INTEGRATION_PREFIX} Successfully retrieved new access token.")
            return access_token

        except AttributeError as e:
            msg = f"Failed to parse auth response. Expected JSON dict. Response: {token_data}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

    def _generate_token(self) -> None:
        """
        [INSTANCE] Internal helper to fetch a new token using the client's
        stored configuration and correctly configured proxy/verify settings.
        This updates the client's auth headers.
        """
        access_token = self._get_access_token()
        self._headers["Authorization"] = f"Bearer {access_token}"

    def _http_request(self, *args, **kwargs) -> dict[str, Any]:
        """
        [OVERRIDE] Override BaseClient._http_request to inject
        OAuth 2.0 token generation and automatic refresh logic.
        All calls made through this method go to the *event_base_url*.
        """
        # If this is the first call, headers won't have auth.
        if not self._headers.get("Authorization"):
            demisto.info(f"{INTEGRATION_PREFIX} No active token. Calling _generate_token().")
            self._generate_token()

        try:
            # Make the request using the parent class method
            demisto.debug(f"{INTEGRATION_PREFIX} Making API request to {self._base_url} with args: {args}, kwargs: {kwargs}")
            return super()._http_request(*args, **kwargs)

        except DemistoException as e:
            # If we get a 401/403, our token might be expired.
            # Check the error message from BaseClient
            if "401" in str(e) or "403" in str(e):
                demisto.info(
                    f"{INTEGRATION_PREFIX} Received 401/403 error. Token may be expired. " "Refreshing token and retrying."
                )
                self._generate_token()  # This will set new headers
                return super()._http_request(*args, **kwargs)
            else:
                demisto.error(f"{INTEGRATION_PREFIX} HTTP request failed: {str(e)}")
                raise e

    def fetch_events(self, max_fetch: int, last_run_time: datetime) -> tuple[list[dict[str, Any]], datetime]:
        """
        Fetches new audit trail events from LivePerson in a paginated loop.

        :param max_fetch: The maximum number of events to fetch in this run.
        :param last_run_time: The timestamp of the last event from the previous run.
        :return: A tuple containing (list of events, new last_run_time (datetime)).
        """
        fetch_url_suffix = FETCH_PATH_SUFFIX.format(account_id=self.account_id)
        from_date_str = last_run_time.strftime(DATE_FORMAT)

        all_events: list[dict[str, Any]] = []
        new_max_timestamp = last_run_time
        offset = 0

        demisto.info(f"{INTEGRATION_PREFIX} Starting event fetch. Max: {max_fetch}, From: {from_date_str}")
        demisto.debug(f"{INTEGRATION_PREFIX} API Page Size is set to {API_PAGE_SIZE}")

        while len(all_events) < max_fetch:
            # Calculate how many more events to fetch, up to the API page size.
            events_to_fetch = min(API_PAGE_SIZE, max_fetch - len(all_events))

            # Body based on dev portal (Ref: Kickoff video @ 18:31, 20:01)
            request_body = {
                "fromData": from_date_str,
                "first": events_to_fetch,
                "offset": offset,
                "orderBy": "changeTimestamp:ASC",  # Get oldest first
            }

            demisto.debug(f"{INTEGRATION_PREFIX} Fetching page. Offset: {offset}, Limit: {events_to_fetch}")

            try:
                # This call now goes through our _http_request override
                response = self._http_request(method="POST", url_suffix=fetch_url_suffix, json_data=request_body)

                events = response.get("data", [])
                if not events:
                    demisto.info(f"{INTEGRATION_PREFIX} No more events returned from API. Stopping fetch loop.")
                    break  # No more events to fetch

                demisto.debug(f"{INTEGRATION_PREFIX} Received {len(events)} events in this page.")

                for event in events:
                    # Map the timestamp field
                    timestamp_str = event.get("changeDate")
                    if timestamp_str:
                        event["_time"] = timestamp_str

                        # Update the latest timestamp we've seen
                        try:
                            # Use fromisoformat and handle Z for UTC
                            event_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                            if event_time > new_max_timestamp:
                                new_max_timestamp = event_time
                        except ValueError:
                            # Use info() for warnings
                            demisto.info(
                                f"{INTEGRATION_PREFIX} [Warning] Could not parse timestamp: {timestamp_str}. "
                                "This event may not update the last_run_time."
                            )

                    all_events.append(event)

                # Prepare for the next page
                offset += len(events)

                # If we received fewer events than we asked for, we are on the last page
                if len(events) < events_to_fetch:
                    demisto.info(f"{INTEGRATION_PREFIX} Received fewer events than requested, assuming this is the last page.")
                    break

            except Exception as e:
                # We break the loop but will process any events we already got
                tb = traceback.format_exc()
                demisto.error(
                    f"{INTEGRATION_PREFIX} Error during event fetch loop: {str(e)}. "
                    f"Will process {len(all_events)} events already fetched.\nTraceback:\n{tb}"
                )
                break

        demisto.info(f"{INTEGRATION_PREFIX} Event fetch complete. Total events fetched: {len(all_events)}")
        return all_events, new_max_timestamp


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.
    The domain lookup is tested *before* this in main().
    This function tests:
    1. Auth API token request (via first _http_request)
    2. Event API request (via fetch_events)

    :param client: An initialized Client object.
    :return: 'ok' if successful, else an error string.
    """
    demisto.info(f"{INTEGRATION_PREFIX} Starting test-module.")
    try:
        one_day_ago = datetime.now(UTC) - timedelta(days=1)
        demisto.info(f"{INTEGRATION_PREFIX} test-module: Attempting to fetch 1 event from 1 day ago.")
        client.fetch_events(max_fetch=1, last_run_time=one_day_ago)

        demisto.info(f"{INTEGRATION_PREFIX} test-module PASSED.")
        return "ok"
    except Exception as e:
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} test-module FAILED. Error: {str(e)}\nTraceback:\n{tb}")
        return f"Test failed: {str(e)}\nTraceback:\n{tb}"


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Manual command to fetch events for debugging.
    """
    try:
        limit = arg_to_number(args.get("limit", 50))
        if limit is None or limit <= 0:
            limit = 50  # Default to 50 if invalid
        start_time_str = args.get("start_time", "3 days")
        should_push_events = argToBoolean(args.get("should_push_events", False))

        demisto.info(
            f"{INTEGRATION_PREFIX} Running get-events command. "
            f"Limit: {limit}, Start Time: {start_time_str}, Should Push Events: {should_push_events}"
        )

        start_time, _ = parse_date_range(start_time_str)
        if not start_time:
            raise ValueError("Invalid 'start_time' format. Use phrases like '3 days ago' or '2023-10-25T10:00:00Z'.")

        events, _ = client.fetch_events(max_fetch=limit, last_run_time=start_time)
        demisto.info(f"{INTEGRATION_PREFIX} get-events command fetched {len(events)} events.")

        # Push events to XSIAM if requested
        if should_push_events:
            demisto.info(f"{INTEGRATION_PREFIX} Pushing {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=INTEGRATION_NAME, product="liveperson")

        readable_output = tableToMarkdown(
            f"LivePerson Audit Events (Last {limit})",
            events,
            headers=["changeDate", "accountId", "objectType", "element"],
            headerTransform=string_to_table_header,
        )

        return CommandResults(
            readable_output=readable_output, outputs_prefix="LivePerson.Event", outputs_key_field="changeDate", outputs=events
        )
    except Exception as e:
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} get-events command failed: {str(e)}\nTraceback:\n{tb}")
        raise


def fetch_events_command(client: Client, max_fetch: int) -> list[dict[str, Any]]:
    """
    Fetches events for XSIAM and returns the events.

    :param client: The LivePerson client
    :param max_fetch: Maximum number of events to fetch
    :return: List of events
    """
    last_run = demisto.getLastRun()
    last_run_time_str = last_run.get("last_fetch_time")

    if last_run_time_str:
        last_run_time = datetime.fromisoformat(last_run_time_str)
        demisto.info(f"{INTEGRATION_PREFIX} Found last run time: {last_run_time_str}")
    else:
        # For first fetch, use 1 minute ago to prevent backpressure
        last_run_time = datetime.now(UTC) - timedelta(minutes=1)
        demisto.info(f"{INTEGRATION_PREFIX} No last run time found. Using 1 minute ago: {last_run_time.isoformat()}")

    events, new_max_timestamp = client.fetch_events(max_fetch=max_fetch, last_run_time=last_run_time)

    # Update last run after fetching
    if events:
        update_last_run(last_run_time, new_max_timestamp, events)

    return events


def update_last_run(last_run_time: datetime, new_max_timestamp: datetime, events: list[dict[str, Any]]) -> None:
    """
    Updates the last run time after successful event submission.

    :param last_run_time: The previous last run time
    :param new_max_timestamp: The maximum timestamp from the fetched events
    :param events: The list of events that were fetched
    """
    # Save the new last run time
    if new_max_timestamp > last_run_time:
        # Add 1 second to the last timestamp to avoid fetching the same event again
        new_last_run_time_plus_one = new_max_timestamp + timedelta(seconds=1)
        new_last_run_time_str = new_last_run_time_plus_one.isoformat()
        demisto.setLastRun({"last_fetch_time": new_last_run_time_str})
        demisto.info(
            f"{INTEGRATION_PREFIX} Setting new last run time to {new_last_run_time_str} "
            f"(based on event time {new_max_timestamp.isoformat()})"
        )
    elif new_max_timestamp == last_run_time and events:
        # We fetched events but the timestamp didn't advance (e.g., batch with same timestamp).
        # We must advance the time window by 1s to avoid an infinite loop.
        demisto.info(
            f"{INTEGRATION_PREFIX} [Warning] Fetched {len(events)} events, but latest event timestamp "
            f"{new_max_timestamp.isoformat()} did not advance. Check for duplicate timestamps."
        )
        new_last_run_time_str = (last_run_time + timedelta(seconds=1)).isoformat()
        demisto.setLastRun({"last_fetch_time": new_last_run_time_str})
        demisto.info(f"{INTEGRATION_PREFIX} Setting new last run time to {new_last_run_time_str} to avoid duplicates.")
    else:
        demisto.info(f"{INTEGRATION_PREFIX} No new events found. Last run time not updated.")


""" MAIN FUNCTION """


def main() -> None:
    """
    Main function, parses params and executes the command.
    """
    params = demisto.params()

    auth_url = params.get("auth_server_url")
    account_id = params.get("account_id")
    client_creds = params.get("credentials", {})
    client_id = client_creds.get("identifier")
    client_secret = client_creds.get("password")

    verify_ssl = not params.get("insecure", False)
    proxies = handle_proxy(params.get("proxy", False))

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))

    command = demisto.command()
    demisto.debug(f"{INTEGRATION_PREFIX} Command being run: {command}")

    try:
        # --- Parameter Validation ---
        if not (auth_url and account_id and client_id and client_secret):
            raise DemistoException(
                "Missing required parameters: Authorization Server URL, Account ID, Client ID, or Client Secret."
            )

        if max_fetch is None or max_fetch <= 0:
            raise DemistoException(f"'max_fetch' must be a positive integer. Got: {max_fetch}")

        # --- Dynamic Domain Lookup ---
        # This is the first network call. It validates account_id and proxy/SSL.
        demisto.debug(f"{INTEGRATION_PREFIX} Attempting to discover Event API domain for account {account_id}...")
        event_base_url = Client._get_event_domain(account_id, verify_ssl, proxies)
        demisto.debug(f"{INTEGRATION_PREFIX} Successfully discovered Event API domain: {event_base_url}")

        # --- Client Initialization ---
        client = Client(
            base_url=event_base_url,
            account_id=account_id,
            auth_server_url=auth_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_ssl,
            proxy=params.get("proxy", False),  # BaseClient __init__ expects the bool
        )

        # --- Command Execution ---
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "liveperson-get-events":
            return_results(get_events_command(client, demisto.args()))

        elif command == "fetch-events":
            events = fetch_events_command(client, max_fetch)

            if events:
                demisto.debug(f"{INTEGRATION_PREFIX} Sending {len(events)} events to XSIAM.")
                # send_events_to_xsiam handles event hashing for deduplication
                send_events_to_xsiam(events, vendor=INTEGRATION_NAME, product="liveperson")
                demisto.info(f"{INTEGRATION_PREFIX} Events successfully sent to XSIAM.")
            else:
                demisto.debug(f"{INTEGRATION_PREFIX} No events to send to XSIAM.")

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        # Get the full traceback for debugging
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} Failed to execute {command} command. Error: {str(e)}\nTraceback:\n{tb}")
        return_error(f"Failed to execute {command} command. Error: {str(e)}\nTraceback:\n{tb}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
