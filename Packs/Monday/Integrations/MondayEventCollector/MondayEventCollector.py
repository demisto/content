import uuid
import demistomock as demisto # noqa: F401
from CommonServerPython import *
import urllib3

from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "Monday"
PRODUCT = "Monday"

SCOPE = "boards:read"
REDIRECT_URI = "https://localhost"
AUTH_BASE_URL = "https://auth.monday.com/oauth2"

""" CLIENT CLASS """
# TODO: add function comments
# TODO: edit debug logs prints
class ActivityLogsClient(BaseClient):
    def __init__(
        self,
        client_id: str,
        secret: str,
        auth_code: str = "",
        verify: bool = True,
        proxy: bool = False,    # I think proxy is redundant, TODO: check how to use it on Monday. (I read: No, Monday.com does not use or expose a centralized OAuth proxy service like Microsoft’s OProxy.)
        *args, # ???
        **kwargs, # ???
    ):
        demisto.debug("Initializing ActivityLogsClient with:")
        super().__init__(*args, verify=verify, base_url=AUTH_BASE_URL, **kwargs)  # type: ignore[misc]

        self.client_id = client_id
        self.secret = secret
        self.auth_code = auth_code
        self.verify = verify
        self.proxy = proxy
        
        self.scope = SCOPE  # TODO: check if this is relevant and in used
        self.redirect_uri = REDIRECT_URI

    def generate_login_url(self) -> CommandResults:
        if not self.client_id:
            raise DemistoException("Please make sure you entered the Client ID correctly.")
        
        login_url = f'https://auth.monday.com/oauth2/authorize?client_id={self.client_id}'

        result_msg = f"""Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR the permissions.
        You will be automatically redirected to a link with the following structure:
        ```REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=```
        Copy the `AUTH_CODE` (without the `code=` prefix)
        and paste it in your instance configuration under the **Authorization code** parameter.
        """
        return CommandResults(readable_output=result_msg)

    def get_access_token(self):
        """
        Exchange authorization code for access token from Monday.com
        """
        url = "https://auth.monday.com/oauth2/token"
        payload = {
            "client_id": self.client_id,
            "client_secret": self.secret,
            "code": self.auth_code,
            "redirect_uri": self.redirect_uri
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
                 
        try:
            response = self._http_request(method="POST", url_suffix="token", params=payload, ok_codes=(200,), headers=headers)
            access_token = response.get("access_token")
            if not access_token:
                raise DemistoException("Response missing access_token field")
            demisto.debug("get_monday_access_token - Access token received successfully")
            return access_token
        except Exception as e:
            demisto.debug(f"get_monday_access_token - Error retrieving access token: {str(e)}")
            raise DemistoException(f"get_monday_access_token - Error retrieving access token: {str(e)}")

    
    def test_connection(self):
        """
        Test connectivity in the Authorization Code flow mode.
        """
        access_token = self.get_access_token()  # If fails, get_access_token returns an error
        return CommandResults(readable_output=f"✅ Success!\nAccess token: {access_token}")


    # TODO: Should I save the access_token in the integration context? if so, take reference from this implementation
    def reference_get_access_token(self, resource: str = "", scope: str | None = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.
 
        Args:
            resource: The resource identifier for which the generated token will have access to.
            scope: A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get("current_refresh_token", "")
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f"{scope}_access_token" if scope else "access_token"
        valid_until_keyword = f"{scope}_valid_until" if scope else "valid_until"

        access_token = integration_context.get(resource) if self.multi_resource else integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until and self.epoch_seconds() < valid_until:
            return access_token

        if self.auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                expires_in = None
                for resource_str in self.resources:
                    access_token, current_expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
                    expires_in = current_expires_in if expires_in is None else min(expires_in, current_expires_in)  # type: ignore[call-overload]
                if expires_in is None:
                    raise DemistoException("No resource was provided to get access token from")
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update(
            {access_token_keyword: access_token, valid_until_keyword: valid_until, "current_refresh_token": refresh_token}
        )

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)
        demisto.debug("Set integration context successfully.")

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token


def test_module(client: ActivityLogsClient, params: dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get("alert_status", None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(client: ActivityLogsClient, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """Gets events from API

    Args:
        client (Client): The client
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    limit = args.get("limit", 50)
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(
    client: ActivityLogsClient, last_run: dict[str, int], first_fetch_time, alert_status: str | None, max_events_per_fetch: int
) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get("prev_id", None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f"Fetched event with id: {prev_id + 1}.")

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"prev_id": prev_id + 1}
    return next_run, events


""" MAIN FUNCTION """


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
            create_time = arg_to_datetime(arg=event.get("created_time"))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    
    # TODO: move the unnecessary/unused parameters here, to the right function they in use.
    client_id = params.get("client_id", "")
    secret = params.get("secret",  "")
    auth_code = params.get("auth_code", "")
    proxy = bool(params.get("proxy", False))
    verify_certificate = not bool(params.get("insecure", False))
    
    selected_event_types = params.get("selected_event_types", "")
    board_ids = params.get("board_ids", "")
    
    # -------------------------- Activity logs -----------------------------------
    activity_logs_url = params.get("activity_logs_url", "https://api.monday.com")
    max_activity_logs_per_fetch = int(params.get("max_activity_logs_per_fetch", 50000))

    # -------------------------- Audit logs --------------------------------------
    audit_logs_url =  params.get("audit_logs_url", "")
    audit_token = params.get("audit_token", "")
    max_audit_logs_per_fetch = int(params.get("max_audit_logs_per_fetch", 50000))
    # ----------------------------------------------------------------------------
    
    # TODO: move it to the fetch logic
    # How much time before the first fetch to retrieve events
    first_fetch_time = datetime.now().isoformat()

    demisto.debug(f"Command being called is {command}")
    try:
        activity_logs_client = ActivityLogsClient(
            client_id=client_id,
            secret=secret,
            auth_code=auth_code,
            verify=verify_certificate,
            proxy=proxy
            )
        # TODO: implement this command, think about how to handle different client types (activity_logs_client or audit_logs_client)
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(activity_logs_client, params, first_fetch_time)
            return_results(result)
        elif command == "monday-generate-login-url":
            # TODO: think about moving the generate_login_url and other function out from the client class, and send the client object to the function (like test_module)
            return_results(activity_logs_client.generate_login_url())
        elif command == "monday-auth-test":
            return_results(activity_logs_client.test_connection())
            
        # TODO: implement this command
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                max_events_per_fetch=max_activity_logs_per_fetch,
            )

            add_time_to_events(events)
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
