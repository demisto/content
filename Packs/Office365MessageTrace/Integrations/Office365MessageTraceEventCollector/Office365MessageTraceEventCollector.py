import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Office 365 Message Trace Integration for Cortex XSOAR

This integration provides access to the Office 365 Message Trace API to retrieve
email message tracking information from the Office 365 reporting web service.

API Documentation: https://learn.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15)

"""

from typing import Any
import time
import uuid
from datetime import datetime, timedelta, UTC
import dateparser
from urllib.parse import urlencode

try:
    import jwt
except ImportError:
    jwt = None  # Will handle this in the authentication method
import urllib3


# Disable insecure warnings
urllib3.disable_warnings()


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
OFFICE365_LOGIN_URL = "https://login.microsoftonline.com"
OFFICE365_REPORTS_URL = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc"
OFFICE365_RESOURCE = "https://outlook.office365.com"
VENDOR = "microsoft"
PRODUCT = "messagetrace"


class Client(BaseClient):
    """Client class to interact with the Office 365 Message Trace API

    This Client implements OAuth2 authentication with Azure AD and makes calls
    to the Office 365 Reporting web service to retrieve message trace data.
    """

    def __init__(
        self,
        url: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        certificate_thumbprint: str = "",
        private_key: str = "",
        **kwargs,
    ):
        """Initialize the Office 365 Client

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Azure AD application client ID
            client_secret: Azure AD application client secret
            certificate_thumbprint: X.509 certificate thumbprint for cert-based auth
            private_key: Private key for certificate-based authentication
        """
        super().__init__(base_url=url, **kwargs)
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.certificate_thumbprint = certificate_thumbprint
        self.private_key = private_key
        self.access_token: str = ""
        self.token_expires_at: int = 0

    def _get_access_token(self) -> str:
        """Get a valid access token, refreshing if necessary"""
        if self.access_token and self.token_expires_at and time.time() < self.token_expires_at:
            return self.access_token

        return self._request_access_token()

    def _request_access_token(self) -> str:
        """Request a new access token from Azure AD using client credentials"""
        token_url = f"{OFFICE365_LOGIN_URL}/{self.tenant_id}/oauth2/token"

        if self.certificate_thumbprint and self.private_key:
            # Use certificate-based authentication
            client_assertion = self._create_client_assertion(token_url)
            data = {
                "resource": OFFICE365_RESOURCE,
                "client_id": self.client_id,
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
            }
        else:
            # Use client secret authentication
            data = {
                "resource": OFFICE365_RESOURCE,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = self._http_request(method="POST", full_url=token_url, headers=headers, data=urlencode(data))

        demisto.debug(f"res: {response}")
        self.access_token = response.get("access_token", "")
        if not self.access_token:
            raise ValueError("Failed to obtain access token from Azure")
        expires_in = response.get("expires_in", "3600")
        self.token_expires_at = int(time.time()) + int(expires_in) - 60  # Refresh 1 min early

        return self.access_token

    def _create_client_assertion(self, audience: str) -> str:
        """Create a JWT client assertion for certificate-based authentication"""
        if not self.private_key:
            raise ValueError("Private key is required for certificate-based authentication")

        if jwt is None:
            raise ValueError("PyJWT library is required for certificate-based authentication")

        now = int(time.time())
        header = {"alg": "RS256", "x5t": self.certificate_thumbprint}
        payload = {
            "aud": audience,
            "iss": self.client_id,
            "sub": self.client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "exp": now + 600,  # 10 minutes
        }

        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=header)

    def _make_authenticated_request(self, method: str, url_suffix: str, params: dict | None = None) -> dict:
        """Make an authenticated request to the Office 365 API"""
        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        return self._http_request(method=method, url_suffix=url_suffix, headers=headers, params=params)

    def get_message_trace(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        sender_address: str | None = None,
        recipient_address: str | None = None,
        message_trace_id: str | None = None,
        status: str | None = None,
        top: int = 0,
        skip_token: int = 0,
    ) -> dict[str, Any]:
        """Get message trace data from Office 365

        Args:
            start_date: Start date for the search (format: YYYY-MM-DDTHH:MM:SSZ)
            end_date: End date for the search (format: YYYY-MM-DDTHH:MM:SSZ)
            sender_address: Email address of the sender
            recipient_address: Email address of the recipient
            message_trace_id: Specific message trace ID to search for
            status: Message status (e.g., 'Delivered', 'Failed', 'Pending')
            page_size: Number of results to return (max 5000)

        Returns:
            Dictionary containing message trace results
        """
        # Build OData filter
        filters = []

        if start_date and end_date:
            filters.append(f"StartDate eq datetime'{start_date}' and EndDate eq datetime'{end_date}'")
        elif start_date:
            # If only start date provided, search for last 48 hours from start date
            start_dt = datetime.strptime(start_date, DATE_FORMAT)
            end_dt = start_dt + timedelta(hours=48)
            end_date = end_dt.strftime(DATE_FORMAT)
            filters.append(f"StartDate eq datetime'{start_date}' and EndDate eq datetime'{end_date}'")

        if sender_address:
            filters.append(f"SenderAddress eq '{sender_address}'")

        if recipient_address:
            filters.append(f"RecipientAddress eq '{recipient_address}'")

        if message_trace_id:
            filters.append(f"MessageTraceId eq guid'{message_trace_id}'")

        if status:
            filters.append(f"Status eq '{status}'")

        params = {}
        if top:
            params["$top"] = str(top)
        # Build query parameters
        if filters:
            params["$filter"] = " and ".join(filters)
        if skip_token:
            params["$skiptoken"] = str(skip_token)

        return self._make_authenticated_request("GET", "/MessageTrace", params)

    def get_message_trace_detail(
        self, message_trace_id: str, recipient_address: str, sender_address: str, start_date: str, end_date: str
    ) -> dict[str, Any]:
        """Get detailed message trace information for a specific message

        Args:
            message_trace_id: Message trace ID from MessageTrace report
            recipient_address: Recipient email address
            sender_address: Sender email address
            start_date: Start date for the search
            end_date: End date for the search

        Returns:
            Dictionary containing detailed message trace information
        """
        filters = [
            f"MessageTraceId eq guid'{message_trace_id}'",
            f"RecipientAddress eq '{recipient_address}'",
            f"SenderAddress eq '{sender_address}'",
            f"StartDate eq datetime'{start_date}' and EndDate eq datetime'{end_date}'",
        ]

        params = {"$filter": " and ".join(filters), "$format": "json"}

        return self._make_authenticated_request("GET", "/MessageTraceDetail", params)

    def test_connection(self) -> str:
        """Test the connection to Office 365 API"""
        try:
            # Try to get a small message trace to test connectivity
            result = self.get_message_trace(top=1)
            values = result.get("value", [])
            if isinstance(values, list):
                if len(values) == 1:
                    return ""
                elif len(values) == 0:
                    return "Test connection failed: No message trace data found"
                else:
                    return f"Test connection failed: Unexpected number of results, {len(values)} found"
            else:
                return "Test connection failed: Invalid response format"
        except Exception as e:
            failure_msg = f"Test connection failed: {str(e)}"
            demisto.debug(failure_msg)
            return failure_msg


def office365_message_trace_list_paging(
    client: Client,
    start_date: str | None = None,
    end_date: str | None = None,
    sender_address: str | None = None,
    recipient_address: str | None = None,
    message_trace_id: str | None = None,
    status: str | None = None,
    top: int = 0,
    limit: int = 0,
) -> list[dict[str, Any]]:
    """Retrieve message trace data with pagination handling

    Args:
        client: Office 365 client
        start_date: Start date for the search
        end_date: End date for the search
        sender_address: Sender email address
        recipient_address: Recipient email address
        message_trace_id: Message trace ID
        status: Status of the message
        top: Number of results to return
        limit: Maximum number of results to return

    Returns:
        List of message trace data
    """
    results: list[dict[str, Any]] = []
    skip_token = 0
    while True:
        demisto.debug(f"Fetching events, pulled down {len(results)} so far")
        result = client.get_message_trace(
            start_date=start_date,
            end_date=end_date,
            sender_address=sender_address,
            recipient_address=recipient_address,
            message_trace_id=message_trace_id,
            status=status,
            top=top,
            skip_token=skip_token,
        )
        results += result.get("value", [])

        if "odata.nextLink" not in result:
            break

        demisto.debug(f"Found odata.nextLink: {result.get('odata.nextLink', '')}")
        # Paging data was provided, grab the skip token to
        # grab the next page in the next iteration
        next_link = result.get("odata.nextLink", "")
        next_link_pieces = next_link.split("&")
        for piece in next_link_pieces:
            if "skiptoken" in piece:
                demisto.debug(f"skiptoken piece found: {piece}")
                skip_token_pieces = piece.split("=")
                skip_token_str = skip_token_pieces[1]
                if skip_token_str.isnumeric():
                    demisto.debug(f"skiptoken: {skip_token_str}")
                    skip_token = int(skip_token_str)

    # This is outside the loop for now since the fetching
    # gets newer items first which means all items need to be
    # fetched before cutting down to the limit. This allows for
    # cutting down to the oldest entries instead of newest entries
    # and when used in a fetch operation, avoids missing values
    demisto.debug(f"Checking limit {limit} exists")
    if limit:
        demisto.debug(f"Checking limit {limit} is less than results {len(results)}")
        if len(results) >= limit:
            # Drop results down to the limit
            # Results are newest to oldest so grab oldest values up to limit
            # example: limit is 3
            # >>> limit = 3
            # >>> l = [1,2,3,4,5,6,7]
            # >>> total = len(l)
            # >>> start = total - limit
            # >>> l[start:]
            # [5, 6, 7]
            demisto.debug(f"Enforcing limit of {limit}")
            total = len(results)
            demisto.debug(f"{total=}")
            start = total - limit
            demisto.debug(f"{start=}")
            discards = results[:start]
            results = results[start:]

            # Since the next fetch will increment a microsecond
            # grab any straggler values which are next to the most
            # recent value with a matching date in the limited results
            recent_date = results[0].get("Received")
            demisto.debug(f"{recent_date=}")
            for discard in reversed(discards):
                if discard.get("Received") == recent_date:
                    demisto.debug(f"Stragler found: {json.dumps(discard)}")
                    results.insert(0, discard)
                else:
                    break
            demisto.debug(f"Result count to return {len(results)}")

    return results


def parse_message_trace_date_range(date_range: str | None = None, processing_delay: int = 0) -> tuple[str, str]:
    """Parse date range string or return default range (last 48 hours)

    Args:
        date_range: Date range in format "7 days", "24 hours", etc.

    Returns:
        Tuple of (start_date, end_date) in ISO format
    """
    end_date = datetime.now(UTC)
    fallback = timedelta(minutes=5)

    if date_range:
        parsed_date = dateparser.parse(date_range, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
        if not parsed_date:
            raise ValueError(f"Unable to parse date range: {date_range}")
        start_date = parsed_date
    else:
        # Default to fallback
        start_date = end_date - fallback

    max_date = dateparser.parse("10 days ago", settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
    if not max_date:
        raise ValueError("Unable to parse maximum date of 10 days ago")

    if start_date < max_date:
        raise ValueError(f"starting date cannot be more than 10 days in the past: {start_date} < {max_date}")

    start_date -= timedelta(minutes=processing_delay)
    end_date -= timedelta(minutes=processing_delay)
    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)


def format_message_trace_results(data: list[dict[str, Any]], for_dataset: bool = False) -> list[dict[str, Any]]:
    """Format message trace results for XSOAR/XSIAM output

    Args:
        data: Raw API response data

    Returns:
        Formatted list of message trace entries
    """
    results = []
    for entry in data:
        formatted_entry = {
            "MessageTraceId": entry.get("MessageTraceId", ""),
            "Organization": entry.get("Organization", ""),
            "MessageId": entry.get("MessageId", ""),
            "Received": entry.get("Received", ""),
            "SenderAddress": entry.get("SenderAddress", ""),
            "RecipientAddress": entry.get("RecipientAddress", ""),
            "Subject": entry.get("Subject", ""),
            "Status": entry.get("Status", ""),
            "FromIP": entry.get("FromIP", ""),
            "ToIP": entry.get("ToIP", ""),
            "Size": entry.get("Size", 0),
        }

        # If posting to a dataset, rename the Received key to _time
        if for_dataset:
            formatted_entry["_time"] = entry.get("Received")
            formatted_entry.pop("Received")
        results.append(formatted_entry)

    return results


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        if client.test_connection():
            return "ok"
        else:
            return "Test failed: Unable to connect to Office 365 API"
    except Exception as e:
        return f"Test failed: {str(e)}"


def office365_message_trace_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get message trace data from Office 365

    Args:
        client: Office 365 client
        args: Command arguments

    Returns:
        CommandResults with message trace data
    """
    # Parse arguments
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    date_range = args.get("date_range")
    sender_address = args.get("sender_address")
    recipient_address = args.get("recipient_address")
    message_trace_id = args.get("message_trace_id")
    status = args.get("status")
    top = arg_to_number(args.get("top", 0)) or 0

    # Handle date range
    if not start_date and not end_date:
        start_date, end_date = parse_message_trace_date_range(date_range)
    elif start_date and not end_date:
        # If only start date provided, search for 48 hours from start
        start_dt = datetime.strptime(start_date, DATE_FORMAT)
        end_dt = start_dt + timedelta(hours=48)
        end_date = end_dt.strftime(DATE_FORMAT)

    # Call the API
    results = office365_message_trace_list_paging(
        client=client,
        start_date=start_date,
        end_date=end_date,
        sender_address=sender_address,
        recipient_address=recipient_address,
        message_trace_id=message_trace_id,
        status=status,
        top=top,
    )

    formatted_results = format_message_trace_results(results)

    # Create readable output
    readable_output = tableToMarkdown(
        "Office 365 Message Trace Results",
        formatted_results,
        headers=["MessageId", "Received", "SenderAddress", "RecipientAddress", "Subject", "Status"],
        removeNull=True,
    )

    demisto.debug(f"Pulled down {len(results)} traces")

    return CommandResults(
        outputs_prefix="Office365.MessageTrace",
        outputs_key_field="MessageId",
        outputs=formatted_results,
        readable_output=readable_output,
        raw_response=results,
    )


def get_events(client: Client, last_timestamp: str, processing_delay: int) -> tuple[list[dict[str, Any]], str]:
    """Get new events since last_timestamp

    Args:
        client: Office 365 client
        last_timestamp: Last event timestamp
        processing_delay: Office 365 can take up to 24 hours to process message trace events.
                          Specify how many minutes to delay event processing (1440 minutes = 24 hours).
                          Higher values ensure events are fully processed but increase latency.

    Returns:
        A tuple containing the list of new events, the new last timestamp
    """
    new_last_timestamp = ""
    end_date = (datetime.now(UTC) - timedelta(minutes=processing_delay)).isoformat()

    result = office365_message_trace_list_paging(client=client, start_date=last_timestamp, end_date=end_date)

    # Clean up results into a full array of formatted events
    events = format_message_trace_results(result, for_dataset=True)
    demisto.debug(f"Events: {json.dumps(events)}")

    # Grab new last values
    if events:
        new_last_timestamp = events[0].get("_time", "")

    if not new_last_timestamp:
        new_last_timestamp = last_timestamp
    else:
        # Parse old time and add 1 microsecond to avoid including
        # mail pulled down in the next run
        old_time = dateparser.parse(new_last_timestamp + "Z")
        if old_time:
            new_time = old_time + timedelta(microseconds=1)
            new_last_timestamp = new_time.isoformat()

    demisto.debug(f"New last timestamp: {new_last_timestamp}")
    return events, new_last_timestamp


def office365_message_trace_fetch_events_command(client: Client):
    """Fetches events and sends them to XSIAM

    Args:
        client: Office 365 client
    """
    params = demisto.params()
    processing_delay = int(params.get("processing_delay", "1440"))
    first_fetch = params.get("first_fetch", "1 day ago")

    last_run = demisto.getLastRun()
    last_timestamp = last_run.get("last_timestamp", "")
    if not last_timestamp:
        last_timestamp, _ = parse_message_trace_date_range(first_fetch, processing_delay)
    demisto.debug(f"Last timestamp: {last_timestamp}")
    events, new_last_timestamp = get_events(client=client, last_timestamp=last_timestamp, processing_delay=processing_delay)

    demisto.debug(f"Sending {len(events)} events to send_events_to_xsiam")
    send_events_to_xsiam(events, VENDOR, PRODUCT)
    new_last_run = {"last_timestamp": new_last_timestamp}
    demisto.debug(f"New last run: {json.dumps(new_last_run)}")
    demisto.setIntegrationContext({"last_run": new_last_run})
    demisto.setLastRun(new_last_run)


def main():
    """main function, parses params and runs command functions"""

    params = demisto.params()

    # Authentication parameters
    tenant_id = params.get("tenant_id", "")
    client_id = params.get("client_id", "")
    client_secret = params.get("client_secret", {}).get("password", "")
    certificate_thumbprint = params.get("certificate_thumbprint")
    private_key = params.get("private_key")

    # Validate required parameters
    if not tenant_id or not client_id or not client_secret:
        raise ValueError("tenant_id, client_id, and client_secret are required")

    # Connection parameters
    url = params.get("url", OFFICE365_REPORTS_URL)
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            url=url,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        args = demisto.args()

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == "office365-mt-get-events":
            return_results(office365_message_trace_list_command(client, args))
        # elif command == "office365-message-trace-get":
        #     return_results(office365_message_trace_get_command(client, args))
        elif command == "fetch-events":
            office365_message_trace_fetch_events_command(client)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
