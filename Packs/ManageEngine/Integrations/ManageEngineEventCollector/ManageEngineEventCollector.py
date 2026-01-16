import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "manage"
PRODUCT = "engine"
PAGE_LIMIT_DEFAULT = 5000
DEFAULT_MAX_FETCH = 25000

ENDPOINT_TO_ZOHO_ACCOUNTS = {
    "https://endpointcentral.manageengine.com": "https://accounts.zoho.com",
    "https://endpointcentral.manageengine.eu": "https://accounts.zoho.eu",
    "https://endpointcentral.manageengine.in": "https://accounts.zoho.in",
    "https://endpointcentral.manageengine.com.au": "https://accounts.zoho.com.au",
    "https://endpointcentral.manageengine.cn": "https://accounts.zoho.cn",
    "https://endpointcentral.manageengine.jp": "https://accounts.zoho.jp",
    "https://endpointcentral.manageengine.ca": "https://accounts.zohoone.ca",
}


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        client_code: str,
        verify: bool = True,
        proxy: bool = False,
        **kwargs,
    ):
        """
        Args:
            base_url: Base URL of the EndpointCentral instance.
            client_id: Client ID.
            client_secret: Client secret.
            client_code: Authorization code.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_code = client_code

    def get_access_token_request(self, data: dict) -> dict[str, str]:
        """Token http_request wrapper.

        Args:
            data (dict): {"client_id":,
                          "client_secret":
                          "grant_type":"refresh_token"/"authorization_code"
                          "refresh_token"/"code":}

        Returns:
            dict: The response
        """
        return self._http_request(
            method="POST",
            full_url=ENDPOINT_TO_ZOHO_ACCOUNTS[self._base_url] + "/oauth/v2/token",
            data=data,
            resp_type="json",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def get_access_token(self) -> str:
        """
        Obtain or refresh an access token, caching it in the integration context.
        First run will use the code and next run will use the refresh token for creating the access token.

        Raises:
            DemistoException: If neither an authorization code nor refresh token is available.
        """
        ctx = get_integration_context() or {}

        access_token = ctx.get("access_token")
        expire_date_str = ctx.get("expire_date")
        now = datetime.now()
        if access_token and expire_date_str:
            expire_date = datetime.fromisoformat(expire_date_str)
            if now < expire_date:
                demisto.debug(f"Using cached access token. Expires at {expire_date_str}")
                return access_token

        demisto.debug("No valid access token exists.")

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        refresh_token = ctx.get("refresh_token")

        if refresh_token:
            demisto.debug("Refresh token found in context")
            data.update({"grant_type": "refresh_token", "refresh_token": refresh_token})

        elif self.client_code:
            demisto.debug("Refresh token not found in context.")
            data.update({"grant_type": "authorization_code", "code": self.client_code})
        else:
            raise DemistoException(message="Either grant code or refresh token must be provided.")

        demisto.debug("Asking for new tokens")

        response = self.get_access_token_request(data)

        if "error" in response:
            demisto.debug("Error creating token")
            raise DemistoException(response.get("error"))
        access_token = response["access_token"]
        new_ctx = {
            "refresh_token": ctx.get("refresh_token") or response.get("refresh_token"),
            "access_token": access_token,
            "expire_date": (now + timedelta(seconds=int(response.get("expires_in", 0)) - 60)).isoformat(),
        }

        demisto.debug(f"New access token acquired and stored. Expires at {new_ctx['expire_date']}")
        set_integration_context(new_ctx)
        return access_token

    def search_events(self, start_time: str, end_time: str, limit: int) -> List[Dict]:  # noqa: E501
        """
        Paginate through audit logs.
        Logs return in random order from the API.
        API include start_time and end_time.

        Args:
            start_time_ms: UNIX‐ms timestamp to start from.
            end_time_ms: UNIX‐ms timestamp to end at.
            limit: Maximum total events to return.

        Returns:
            List of audit‐log dicts (up to `limit`) sorted by eventTime.
        """
        events: List[Dict] = []
        page = 1
        access_token = self.get_access_token()
        headers = {
            "Authorization": f"Zoho-oauthtoken {access_token}",
            "Accept": "application/auditlogsdata.v1+json",
        }

        params = {"startTime": start_time, "endTime": end_time, "pageLimit": PAGE_LIMIT_DEFAULT}
        demisto.debug(f"Time intervarl: {start_time} to {end_time}.")

        while True:
            params["page"] = str(page)

            response = self._http_request(
                method="GET",
                url_suffix="/emsapi/server/auditLogs",
                headers=headers,
                params=params,
                ok_codes=(200, 204),
                resp_type="json",
            )

            events_page = response.get("messageResponse", [])
            status = response.get("status")
            demisto.debug(f"Successfully fetched {events_page} on page {page}")
            if status != "success":
                demisto.debug(f"API returned status='{status}', stopping pagination.")
                break

            if not events_page:
                demisto.debug("No more events")
                break

            events.extend(events_page)
            page += 1

            if len(events_page) < PAGE_LIMIT_DEFAULT:
                demisto.debug(f"Fetched {len(events_page)} events < PAGE_LIMIT ({PAGE_LIMIT_DEFAULT}) on the last page.")
                break

        events.sort(key=lambda e: int(e["eventTime"]))
        return events[:limit]


def test_module(client: Client) -> str:
    """
    Verifies credentials + connectivity by attempting to fetch a single audit log.
    """
    now_ts = int(time.time() * 1000)
    one_min_ago_ts = now_ts - (60 * 1000)

    try:
        _ = client.search_events(str(one_min_ago_ts), str(now_ts), 1)
        return "Connection is valid."
    except Exception as e:
        msg = str(e).lower()
        if "unauthorized" in msg or "forbidden" in msg:
            return "Authorization Error: check client_id, client_secret, and client_code"
        raise


def get_events(client: Client, args: dict) -> CommandResults:
    """
    manage-engine-get-events command.
    """
    should_push = argToBoolean(args.get("should_push_events", "false"))
    limit = arg_to_number(args.get("limit")) or 10
    start_date_str = args.get("start_date")
    end_date_str = args.get("end_date")

    now_ts = int(time.time() * 1000)

    start_date = date_to_timestamp(start_date_str, DATE_FORMAT) if start_date_str else now_ts
    end_date = date_to_timestamp(end_date_str, DATE_FORMAT) if end_date_str else (now_ts - 60 * 1000)

    events = client.search_events(str(start_date), str(end_date), limit)
    add_time_to_events(events)
    human_readable = tableToMarkdown(
        name="ManageEngine Audit Logs",
        t=events,
    )
    results = CommandResults(
        readable_output=human_readable,
        outputs_prefix="ManageEngine.Event",
        outputs=events,
    )

    if should_push:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    return results


def fetch_events(
    client: Client,
    last_run: dict[str, str],
    max_events_per_fetch: int,
) -> tuple[Dict, List[Dict]]:
    """
    Polling logic for `fetch-events`.

    Args:
        client: client to use.
        last_run: XSOAR lastRun dict, with `last_time` in ms.
        max_events: Max events to pull this cycle.

    Returns:
        next_run: dict with updated `last_time`;
        events: list of new events.
    """

    now_ts = int(time.time() * 1000)
    last_time_ts = (last_run.get("last_time")) or str(now_ts - (60 * 1000))
    demisto.debug(f"Fetching from: {timestamp_to_datestring(last_time_ts)} to {timestamp_to_datestring(now_ts)}")

    events = client.search_events(start_time=last_time_ts, end_time=str(now_ts), limit=max_events_per_fetch)

    add_time_to_events(events)
    demisto.debug(f"Fetched {len(events)} events.")
    max_timestamp = int(events[-1]["eventTime"] if events else now_ts) + 1
    last_run = {"last_time": f"{max_timestamp}"}
    return last_run, events


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            event["_time"] = timestamp_to_datestring(event.get("eventTime"), date_format=DATE_FORMAT)


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()

    server_url = params.get("server_url")
    if server_url not in ENDPOINT_TO_ZOHO_ACCOUNTS:
        return_error("Invalid URL: Make sure it matches one of the options listed in the help section.")
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    client_code = params.get("client_code", {}).get("password")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_events = int(params.get("max_audit_events", DEFAULT_MAX_FETCH))

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=server_url,
            client_id=client_id,
            client_secret=client_secret,
            client_code=client_code,
            verify=verify,
            proxy=proxy,
        )
        if command == "test-module":
            raise Exception("Please use !manage-engine-test instead")
        if command == "manage-engine-test":
            return_results(test_module(client))
        elif command == "manage-engine-get-events":
            return_results(get_events(client, demisto.args()))
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events,
            )

            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
