import demistomock as demisto  # noqa: F401
from CommonServerPython import *
import urllib3
import datetime as dt
import time
from typing import Any
import jwt  # PyJWT
from urllib.parse import urlparse


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "docusign"
PRODUCT = "docusign"

LOG_PREFIX = "[Docusign]"

# yml parameter names
CUSTOMER_EVENTS_TYPE = "Customer events"
USER_DATA_TYPE = "Audit Users"

# yml default values
DEFAULT_SERVER_DEV_URL = "https://account.docusign.com"
MAX_USER_DATA_PER_FETCH = 1250

# API limits
MAX_USER_DATA_PER_PAGE = 250
# Due to API limitations, a maximum of 2,000 items can be fetched per request. Only one request per minute is recommended.
MAX_CUSTOMER_EVENTS_PER_FETCH = 2000

# scopes
CUSTOMER_EVENTS_SCOPE = ["signature", "impersonation"]
USER_DATA_SCOPE = ["organization_read", "user_read", "signature"]

SCOPES_PER_FETCH_TYPE = {
    CUSTOMER_EVENTS_TYPE: CUSTOMER_EVENTS_SCOPE,
    USER_DATA_TYPE: USER_DATA_SCOPE,
}

SERVER_PROD_URL = "https://account.docusign.com"


class CustomerEventsClient(BaseClient):
    """
    Client for DocuSign Monitor API to fetch customer events.
    Extends BaseClient to support proxy configuration and proper HTTP request handling.
    """

    def __init__(self, server_url: str, proxy: bool = False, verify: bool = True):
        """Initialize the Customer Events Monitor client.

        Args:
            server_url: Base URL for the Docusign Monitor API (developer/production environment URI)
            proxy: Whether to use a proxy for requests
            verify: Whether to verify SSL certificates
        """
        env = get_env_from_server_url(server_url)
        base_url = urljoin(self.get_monitor_base_url(env), "api/v2.0/datasets/monitor/stream")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def get_monitor_base_url(self, env: str) -> str:
        return "https://lens-d.docusign.net" if env == "dev" else "https://lens.docusign.net"

    def get_customer_events_request(self, cursor: str, limit: int, access_token: str) -> dict:
        """Send GET request to fetch a stream of customer events from Docusign Monitor API."""

        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json", "Content-Type": "application/json"}
        params = {"cursor": cursor, "limit": limit}

        demisto.debug(f"{LOG_PREFIX}Requesting customer events\nParams: {params}")
        resp = self._http_request(method="GET", headers=headers, params=params, resp_type="json")
        return resp


class UserDataClient(BaseClient):
    """
    Docusign Audit Users client for fetching audit users from the Docusign Admin API.

    Args:
        account_id: Docusign account ID
        organization_id: Docusign organization ID
        env: Docusign environment (dev/production)
        proxy: Whether to use a proxy for requests
        verify: Whether to verify SSL certificates
    """

    def __init__(self, account_id: str, organization_id: str, env: str, proxy: bool = False, verify: bool = True):
        super().__init__(base_url="", verify=verify, proxy=proxy)
        self.account_id = account_id
        self.organization_id = organization_id
        self.env = env

    def get_admin_base_url(self) -> str:
        return "https://api-d.docusign.net" if self.env == "dev" else "https://api.docusign.net"

    def get_users_request(self, access_token: str, url: str) -> dict:
        """
        Docusign Admin API
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, resp_type="json")
        return resp

    def get_users_first_request(self, access_token: str, request_params: Dict[str, Any]) -> tuple[dict, str]:
        """
        Docusign Admin API
        """
        base = self.get_admin_base_url()
        url = urljoin(base, f"management/v2/organizations/{self.organization_id}/users")

        headers = {"Authorization": f"Bearer {access_token}"}
        request_params["account_id"] = self.account_id
        resp = self._http_request(method="GET", full_url=url, headers=headers, params=request_params, resp_type="json")
        return resp, url

    def get_user_detail(self, base_uri: str, user_id: str, access_token: str) -> Dict[str, Any]:
        """
        eSignature REST API
        """
        url = urljoin(base_uri, f"restapi/v2.1/accounts/{self.account_id}/users/{user_id}")
        resp = self._http_request(
            method="GET", full_url=url, headers={"Authorization": f"Bearer {access_token}"}, resp_type="json"
        )
        return resp


def remove_duplicate_users(fetched_users: list, ids_to_remove: list, time_to_remove: str) -> list:
    """remove users from fetched_users whose id appears in ids_to_remove and whose their _time field equals to time_to_remove"""
    if not fetched_users or not ids_to_remove:
        return fetched_users

    ids_to_remove = set(ids_to_remove)
    filtered_users = []
    for user in fetched_users:
        if not (user.get("id") in ids_to_remove and user.get("_time") == time_to_remove):
            filtered_users.append(user)

    if not filtered_users:
        demisto.debug(f"{LOG_PREFIX}No users remain for this request after removing duplicates.")

    return filtered_users


def get_env_from_server_url(server_url: str) -> str:
    try:
        parsed_url = urlparse(server_url)
        hostname = parsed_url.hostname or ""

        return "dev" if hostname == "account-d.docusign.com" else "prod"
    except Exception:
        demisto.debug(f"{LOG_PREFIX}Failed to parse server URL: {server_url}")
        raise DemistoException(f"Failed to parse server URL: {server_url}")


def _utcnow() -> dt.datetime:
    return dt.datetime.now()


class AuthClient(BaseClient):
    def __init__(
        self, server_url: str, integration_key: str, user_id: str, private_key_pem: str, verify: bool = True, proxy: bool = False
    ) -> None:
        """
        Initialize the Docusign authenticator.

        Args:
            server_url: Base URL for the Docusign API
            integration_key: Docusign Integration Key (OAuth Client ID)
            user_id: Docusign User ID used as the JWT subject
            private_key_pem: RSA private key in PEM format for JWT signing
            verify: Whether to verify SSL certificates
            proxy: Whether to use a proxy for requests
        """
        super().__init__(base_url="", verify=verify, proxy=proxy)
        self.server_url = server_url.rstrip("/")
        self.integration_key = integration_key
        self.user_id = user_id

        self.private_key_pem = self.validate_private_key(private_key_pem)

        self.access_token = self.get_access_token()

    def get_access_token(self) -> str:
        """
        Generate a JWT and exchange it for access token for the Docusign API OAuth flow.

        This function first checks if an access token already exists in the integration context.
        If not found, it exchanges the JWT for an access token using Docusign's OAuth token endpoint.

        Args:
            client (AuthClient): AuthClient instance used for making requests

        Returns:
            str: Access token for Docusign API authentication
        Note:
            The access token is stored in the integration context for reuse in subsequent calls.
        """
        params = demisto.params()
        selected_fetch_types = params.get("event_types", "")
        required_scopes = get_scopes_per_type(selected_fetch_types)

        integration_context = get_integration_context()
        access_token = integration_context.get("access_token", "")
        expired_at = integration_context.get("expired_at", "")
        access_token_scopes = integration_context.get("access_token_scopes", [])
        consent_scopes = integration_context.get("consent_scopes", [])
        demisto.debug(f"{LOG_PREFIX}required scopes: {required_scopes}\nconsent scopes: {consent_scopes}")

        # Step 1: Check if we have enough consent scopes to generate a valid access token according to the selected fetch types
        if not is_required_scopes_set(required_scopes, consent_scopes):
            message = "Please run docusign-generate-consent-url command to generate a new consent URL for your fetch types."
            demisto.debug(message)
            raise DemistoException(message)

        # Step 2: Check if an access token exists and is usable
        if access_token:
            token_is_expired = is_access_token_expired(expired_at)
            has_required_scopes = is_required_scopes_set(required_scopes, access_token_scopes)

            if not token_is_expired and has_required_scopes:
                demisto.debug(f"{LOG_PREFIX}Access token is valid. Using existing access token.")
                return access_token

        # Step 3: Generate a new access token if needed
        demisto.debug(f"{LOG_PREFIX}Generating a new Access token.")
        try:
            access_token, expired_at, scope = self.get_token(consent_scopes)

            integration_context.update({"access_token": access_token, "expired_at": expired_at, "access_token_scopes": scope})
            set_integration_context(integration_context)

            demisto.debug(
                f"{LOG_PREFIX}Access token received successfully and set to integration context."
                f"\naccess_token: {access_token}\nexpired_at: {expired_at}\nscope: {scope}"
            )

            return access_token

        except Exception as e:
            demisto.debug(f"{LOG_PREFIX}Error retrieving access token: {str(e)}")
            raise DemistoException(f"Error retrieving access token: {str(e)}")

    def validate_private_key(self, private_key_pem: str) -> str:
        """Validate the private key format."""

        prefix = "-----BEGIN RSA PRIVATE KEY-----"
        suffix = "-----END RSA PRIVATE KEY-----"

        if not private_key_pem.strip().startswith(prefix):
            demisto.debug(f"{LOG_PREFIX}Private key must start with {prefix}")
            raise DemistoException(f"Private key must start with {prefix}")
        if not private_key_pem.strip().endswith(suffix):
            demisto.debug(f"{LOG_PREFIX}Private key must end with {suffix}")
            raise DemistoException(f"Private key must end with {suffix}")

        demisto.debug(f"{LOG_PREFIX}Private key before strip: {private_key_pem}")
        private_key_pem = private_key_pem.replace(prefix, "").replace(suffix, "")
        private_key_sections = private_key_pem.strip().split(" ")
        striped_private_key = "".join(private_key_sections)
        formatted_private_key = prefix + "\n" + striped_private_key + "\n" + suffix

        demisto.debug(f"{LOG_PREFIX}Private key after strip: {formatted_private_key}")
        return formatted_private_key

    def get_jwt(self, scopes: str) -> str:
        """Generate a JWT for authentication.

        Returns:
            str: Signed JWT token

        """
        demisto.debug(f"{LOG_PREFIX}Generating JWT for authentication.\nprivate_key_pem:\n{self.private_key_pem}")
        now = _utcnow()
        headers = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self.integration_key,
            "sub": self.user_id,
            "aud": self.server_url.replace("https://", "").replace("http://", ""),
            "iat": int(now.timestamp()),
            "exp": int((now + dt.timedelta(hours=1)).timestamp()),
            "scope": scopes,
        }
        token = jwt.encode(payload, self.private_key_pem, algorithm="RS256", headers=headers)
        return token

    def exchange_jwt_to_access_token(self, jwt: str) -> tuple[str, str, str]:
        """Exchange a JWT for an access token."""

        url = urljoin(self.server_url, "/oauth/token")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        resp = self._http_request(method="POST", full_url=url, headers=headers, data=data, resp_type="json")

        access_token = resp.get("access_token")
        expires_in_seconds = resp.get("expires_in")
        scope = resp.get("scope")

        if not access_token or not expires_in_seconds:
            demisto.error(f"{LOG_PREFIX}: Token exchange failed, response missing access_token or expires_in\n{resp}")
            raise DemistoException(f"Token exchange failed, response missing access_token or expires_in\n{resp}")

        expired_at = (_utcnow() + dt.timedelta(seconds=expires_in_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return access_token, expired_at, scope

    def get_user_info(self, access_token: str) -> dict:
        """Fetch user information from /oauth/userinfo endpoint."""

        url = urljoin(self.server_url, "/oauth/userinfo")
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, resp_type="json")
        return resp

    def get_base_uri(self, access_token: str, account_id: str) -> str:
        """Fetch user information including the base_uri for the account.

        Args:
            access_token: Valid access token
            account_id: Account ID to fetch base URI for

        Returns:
            str: Base URI for the user's account
        """

        integration_context = get_integration_context()
        base_uri = integration_context.get("base_uri")
        if base_uri:
            demisto.debug(f"{LOG_PREFIX}: using base_uri from integration context: {base_uri}")
            return base_uri

        demisto.debug(f"{LOG_PREFIX}: fetching base_uri from /oauth/userinfo")
        user_info = self.get_user_info(access_token)

        accounts = user_info.get("accounts", [])
        if not accounts:
            demisto.debug(f"{LOG_PREFIX}: /oauth/userinfo missing accounts.")
            raise DemistoException("Docusign: /oauth/userinfo missing accounts.")

        for account in accounts:
            if account.get("account_id") == account_id:
                base_uri = account.get("base_uri")

                # Set the base_uri for future runs; it remains constant for the account.
                integration_context.update({"base_uri": base_uri})
                set_integration_context(integration_context)
                demisto.debug(f"{LOG_PREFIX}update integration context with base_uri: {base_uri}")

                return base_uri

        demisto.debug(f"{LOG_PREFIX}: /oauth/userinfo missing configuration account id: {account_id}.")
        raise DemistoException(f"/oauth/userinfo missing configuration account id: {account_id}.")

    def get_token(self, scopes: list[str]) -> tuple[str, str, str]:
        """Exchange JWT for access token using Docusign OAuth flow."""
        scope_str = " ".join(scopes)
        jwt_token = self.get_jwt(scope_str)
        access_token, expired_at, scope = self.exchange_jwt_to_access_token(jwt_token)
        return access_token, expired_at, scope


def is_access_token_expired(expired_at: str) -> bool:
    """Check if access token is expired."""

    is_not_expired = expired_at > (_utcnow() + dt.timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if is_not_expired:
        demisto.debug(f"{LOG_PREFIX}using existing Access token from integration context (expires at {expired_at}).")
        return False
    else:
        demisto.debug(f"{LOG_PREFIX}Access token expired.")
        return True


def is_required_scopes_set(required_scopes: list[str], target_scopes: list[str]) -> bool:
    """Check if all required scopes included in target scopes list."""
    return all(scope in target_scopes for scope in required_scopes)


def get_customer_events(last_run: dict, limit: int, client: CustomerEventsClient, access_token: str) -> tuple[list, dict]:
    """Fetch customer events from Docusign Monitor API.

    Args:
        client: Initialized Docusign client
        last_run: Previous fetch state containing cursor
        limit: Maximum number of events to fetch  (API parameter does not currently work)
    Returns:
        tuple: (events, last_run) where events are the fetched events and last_run is the updated state.

    """
    one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
    # note for developer - cursor is returned from the API even if the response is empty
    cursor = last_run.get("cursor") or one_minute_ago
    demisto.debug(f"{LOG_PREFIX}Customer Events: requesting {limit} events with cursor: {cursor}")

    try:
        resp = client.get_customer_events_request(cursor, limit, access_token)

        cursor = resp.get("endCursor")
        total_events = resp.get("data", [])
        demisto.debug(f"Total customer events fetched: {len(total_events)}")

        if not total_events:
            demisto.info(f"{LOG_PREFIX} Customer Events: No data available for cursor: {cursor}")

        last_run["cursor"] = cursor
        return total_events, last_run

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during get customer events. Exception is {e!s}")
        raise DemistoException(f"Exception during get customer events. Exception is {e!s}")


def get_remaining_user_data(last_run: dict, client: UserDataClient, access_token: str, limit: int) -> tuple[list, dict]:
    """
    Fetch only users that were not retrieved in the last page from the previous run
    """
    excess_users_info = last_run.get("excess_users_info", {})
    if not excess_users_info:
        demisto.debug(f"{LOG_PREFIX}No excess users info found in last run.")
        return [], last_run

    offset = excess_users_info.get("offset")
    prev_url = excess_users_info.get("url")

    try:
        response = client.get_users_request(access_token, prev_url)
        fetched_users = response.get("users", [])[offset:]
        last_run["excess_users_info"] = None

        demisto.debug(
            f"{LOG_PREFIX}Fetched {len(fetched_users)} excess users, "
            f"limit changes from {limit} to {limit - len(fetched_users)}"
            f"last_run after fetching remaining users: {last_run}"
        )

        return fetched_users, last_run

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during get remaining audit users. Exception is {e!s}")
        raise DemistoException(f"Exception during get remaining audit users. Exception is {e!s}")


def fetch_audit_user_data(last_run: dict, auth_client: AuthClient, test_mode: bool = False) -> tuple[dict, list]:
    params = demisto.params()
    limit = min(MAX_USER_DATA_PER_FETCH, int(params.get("max_user_events_per_fetch", MAX_USER_DATA_PER_FETCH)))
    users_per_page = min(MAX_USER_DATA_PER_PAGE, limit)
    users = []
    access_token = auth_client.access_token
    try:
        demisto.debug(f"{LOG_PREFIX} last_run before fetching audit users: {last_run}")
        user_data_client = initiate_user_data_client()

        # Handle fetching excess users from last page fetched
        if last_run.get("excess_users_info"):
            excess_users_from_last_page, last_run = get_remaining_user_data(last_run, user_data_client, access_token, limit)
            users.extend(excess_users_from_last_page)
            limit -= len(excess_users_from_last_page)

        # ---------- STEP 1: Fetch users ----------
        fetched_users, last_run = get_user_data(last_run, limit, users_per_page, user_data_client, access_token)
        users.extend(fetched_users)
        # ---------- STEP 2: Fetch user details ----------
        if not test_mode:
            base_uri = auth_client.get_base_uri(access_token, user_data_client.account_id)

            latest_modified_dt = last_run.get("latest_modifiedDate")
            latest_modified_dt = datetime.strptime(latest_modified_dt, "%Y-%m-%dT%H:%M:%SZ") if latest_modified_dt else None

            users, latest_modified = get_user_details(users, base_uri, access_token, user_data_client, latest_modified_dt)

            # Persist the latest modifiedDate users for next fetch
            last_run["latest_modifiedDate"] = latest_modified

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during fetch audit users.\n{e!s}")
        raise DemistoException(f"Exception during fetch audit users.\n{e!s}")

    return last_run, users


def get_user_details(
    users: list, base_uri: str, access_token: str, client: UserDataClient, latest_modified_dt: datetime | None
) -> tuple[list[Any], str | None]:
    """
    eSignature REST API.
    Fetches user details for each user in the list.
    Returns the updated list of users and the latest modifiedDate.
    latest_modified value must be tracked because the response of the Admin API is not sorted by modifiedDate.

    returns:
        tuple[list, str]: The updated list of users and the latest modifiedDate.
        users: The updated list of users after enrichment
        latest_modified_iso: The latest modifiedDate in ISO format.
    """
    start_time = time.perf_counter()

    for user in users:
        user_data = client.get_user_detail(base_uri, user.get("id"), access_token)

        modified_date = user_data.get("userSettings", {}).get("modifiedDate")
        if modified_date:
            try:
                md_dt = datetime.strptime(modified_date, "%m/%d/%Y %I:%M:%S %p")
                user["_time"] = md_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                user["source_log_type"] = "auditusers"

                # fine the latest modifiedDate
                if latest_modified_dt is None or md_dt > latest_modified_dt:
                    latest_modified_dt = md_dt

            except Exception as ex:
                demisto.debug(
                    f"{LOG_PREFIX}Failed to parse modifiedDate. user:{user.get('id')} with modifiedDate:{modified_date}"
                    f"error:{ex!s}"
                )

    latest_modified_iso = latest_modified_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if latest_modified_dt else None

    end_time = time.perf_counter()
    demisto.debug(f"{LOG_PREFIX} get_user_details took {end_time - start_time}s, retrieved modifiedDate from {len(users)} users")

    return users, latest_modified_iso


def get_user_data(
    last_run: dict, limit: int, users_per_page: int, client: UserDataClient, access_token: str
) -> tuple[list, dict]:
    start = time.perf_counter()
    total_events: list = []
    remaining_to_fetch = 0

    try:
        # A next URL exists from the last response, indicating that fetching continues from the previous run.
        if last_run.get("continuing_fetch_info"):
            url = last_run.get("continuing_fetch_info", {}).get("url")
            request_params = {}
            demisto.debug(f"{LOG_PREFIX}Continuing fetch for Audit data from:\n {url}")
        # First request in the current time range.
        else:
            one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
            url = ""
            request_params = {
                "start": 0,
                "take": users_per_page,  # api limit - max 250
                "last_modified_since": last_run.get("latest_modifiedDate") or one_minute_ago,
            }
        demisto.debug(f"{LOG_PREFIX}Starting new fetch range for Audit Users data.\n{request_params=}")

        """
        The loop exits when the first of the following conditions is met:
        1. len(total_events) >= limit
        2. next_url is None
        """
        while len(total_events) < limit:
            remaining_to_fetch = limit - len(total_events)
            demisto.debug(f"{LOG_PREFIX}Starting to fetch new request of users.\n{remaining_to_fetch=}")

            if url:  # when the last page returned a next_url
                resp = client.get_users_request(access_token, url)
            else:
                resp, url = client.get_users_first_request(access_token, request_params)

            next_url = resp.get("paging", {}).get("next", "")
            users = resp.get("users", [])
            total_events.extend(users)
            demisto.debug(f"{LOG_PREFIX}Successfully fetched {len(users)} users events.")

            if not next_url:  # last page reached
                demisto.debug(f"{LOG_PREFIX}No more pages in the current time range.")

                if len(users) > remaining_to_fetch:
                    demisto.debug(f"{LOG_PREFIX} There are more users than remaining to fetch.")
                    last_run["excess_users_info"] = {"offset": remaining_to_fetch, "url": url}
                    demisto.debug(
                        f"{LOG_PREFIX} Setting excess_users_info for next fetch: {last_run['excess_users_info']}\n"
                        f"{LOG_PREFIX} Truncated total fetched users from {len(total_events)} to limit: {limit}"
                    )
                    total_events = total_events[:limit]

                last_run["continuing_fetch_info"] = None
                end_time = time.perf_counter()
                demisto.debug(f"{LOG_PREFIX} get_user_data took {end_time - start}s, fetched {len(total_events)} users")
                return total_events, last_run

            prev_url = url
            url = next_url

        # At this point, the limit has been reached before next_url is None (there are more pages to fetch).
        last_run["continuing_fetch_info"] = {"url": url}
        demisto.debug(
            f"{LOG_PREFIX} limit is reached and there are more pages to fetch"
            f"setting continuing_fetch_info for next fetch: {last_run['continuing_fetch_info']}"
        )

        if len(users) > remaining_to_fetch:
            last_run["excess_users_info"] = {"offset": remaining_to_fetch, "url": prev_url}

            demisto.debug(
                f"{LOG_PREFIX}Limit is reached and only partial users were fetched from the last page scanning.\n"
                f"Setting excess_users_info: {last_run['excess_users_info']}"
            )

        end_time = time.perf_counter()
        demisto.debug(f"{LOG_PREFIX} get_user_data took {end_time - start}s, fetched {len(total_events)} users")
        return total_events[:limit], last_run

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during get audit users events. Exception is {e!s}")
        raise DemistoException(f"Exception during get audit users events. Exception is {e!s}")


def initiate_user_data_client() -> UserDataClient:
    """
    Create a UserDataClient for interacting with the Docusign Admin API to fetch audit users and user details.
    """
    params = demisto.params()
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    account_id = params.get("account_id", "")
    organization_id = params.get("organization_id", "")
    server_url = params.get("url", DEFAULT_SERVER_DEV_URL)
    env = get_env_from_server_url(server_url)

    if not account_id or not organization_id:
        demisto.debug(f"{LOG_PREFIX} initiate_user_data_client function: Account ID or Organization ID is missing.")
        raise DemistoException("initiate_user_data_client function: Account ID or Organization ID is missing.")

    return UserDataClient(account_id=account_id, organization_id=organization_id, env=env, proxy=proxy, verify=verify)


def initiate_customer_events_client() -> CustomerEventsClient:
    """
    Create a CustomerEventsClient for interacting with the Docusign Monitor API to fetch customer events.
    """
    params = demisto.params()
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    server_url = params.get("url", DEFAULT_SERVER_DEV_URL)

    return CustomerEventsClient(server_url=server_url, proxy=proxy, verify=verify)


def initiate_auth_client() -> AuthClient:
    """
    Create an AuthClient for making requests to the Docusign API authentication flow.

    Returns:
        AuthClient: AuthClient instance
    """

    params = demisto.params()
    server_url = params.get("url", DEFAULT_SERVER_DEV_URL)
    integration_key = params.get("integration_key", "")
    user_id = params.get("user_id", "")
    private_key_pem = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if not integration_key or not user_id or not private_key_pem:
        demisto.debug(f"{LOG_PREFIX}initiate_auth_client function: Integration Key, User ID  or  Private Key is missing.")
        raise DemistoException("initiate_auth_client function: Integration Key, User ID  or  Private Key is missing.")

    auth = AuthClient(
        server_url=server_url,
        integration_key=integration_key,
        user_id=user_id,
        private_key_pem=private_key_pem,
        verify=verify,
        proxy=proxy,
    )
    return auth


def fetch_customer_events(last_run: dict, access_token: str) -> tuple[dict, list]:
    """
    Note to developer:
    MAX_CUSTOMER_EVENTS_PER_FETCH is set to 2000 due to API limitation.
    The limit parameter does not work as expected on the API side, so it is not currently supported in the configuration.
    """
    limit = MAX_CUSTOMER_EVENTS_PER_FETCH
    try:
        demisto.debug(f"{LOG_PREFIX} last_run before fetching customer events: {last_run}")
        client = initiate_customer_events_client()
        customer_events, last_run = get_customer_events(last_run, limit, client, access_token)

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during fetch customer events.\n{e!s}")
        raise DemistoException(f"Exception during fetch customer events.\n{e!s}")

    add_fields_to_customer_events(customer_events)
    return last_run, customer_events


def add_fields_to_customer_events(customer_events: list) -> None:
    for event in customer_events:
        event["source_log_type"] = "customerevent"
        t_without_milliseconds = event.get("timestamp").split(".")[0]
        dt = datetime.strptime(t_without_milliseconds, "%Y-%m-%dT%H:%M:%S") if t_without_milliseconds else None
        time_value = dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None
        event["_time"] = time_value


def fetch_events(auth_client: AuthClient) -> tuple[dict, list]:
    """
    Fetch events from Docusign based on configuration. (Customer events and Audit users)

    Returns:
        tuple: (last_run, events) where last_run is the updated state and events are the fetched events.
    """
    total_start = time.perf_counter()
    events = []
    params = demisto.params()

    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {CUSTOMER_EVENTS_TYPE: {}, USER_DATA_TYPE: {}}
        demisto.debug(f"{LOG_PREFIX}Empty last run object, initializing new last run object {last_run}")

    last_run_customer_events = last_run.get(CUSTOMER_EVENTS_TYPE, {})
    last_run_user_data = last_run.get(USER_DATA_TYPE, {})

    selected_fetch_types = params.get("event_types", "")
    demisto.debug(f"{LOG_PREFIX}Selected fetch types: {selected_fetch_types}")

    if CUSTOMER_EVENTS_TYPE in selected_fetch_types:
        start = time.perf_counter()
        demisto.info(f"{LOG_PREFIX}Start fetch customer events, Current customer events last_run:\n{last_run_customer_events}")
        last_run_customer_events, fetched_customer_events = fetch_customer_events(
            last_run_customer_events, auth_client.access_token
        )
        events.extend(fetched_customer_events)

        elapsed = time.perf_counter() - start
        demisto.debug(f"{LOG_PREFIX}finished fetching customer events: {len(fetched_customer_events)} in {elapsed:.3f}s")

    if USER_DATA_TYPE in selected_fetch_types:
        start = time.perf_counter()
        demisto.info(f"{LOG_PREFIX}Start fetch audit users, Current audit users last_run:\n{last_run_user_data}")
        last_run_user_data, fetched_user_data = fetch_audit_user_data(last_run_user_data, auth_client)
        events.extend(fetched_user_data)

        elapsed = time.perf_counter() - start
        demisto.debug(f"{LOG_PREFIX}finished fetching audit users: {len(fetched_user_data)} in {elapsed:.3f}s")

    elapsed = time.perf_counter() - total_start
    demisto.debug(f"{LOG_PREFIX}finished running fetch_events.\n total events: {len(events)} in {elapsed:.3f}s")
    last_run = {CUSTOMER_EVENTS_TYPE: last_run_customer_events, USER_DATA_TYPE: last_run_user_data}
    return last_run, events


def get_scopes_per_type(selected_fetch_types: str) -> list:
    scopes = []
    if CUSTOMER_EVENTS_TYPE in selected_fetch_types:
        scopes += SCOPES_PER_FETCH_TYPE[CUSTOMER_EVENTS_TYPE]
    if USER_DATA_TYPE in selected_fetch_types:
        scopes += SCOPES_PER_FETCH_TYPE[USER_DATA_TYPE]
    return scopes


def generate_consent_url() -> CommandResults:
    """Generate a consent URL for Docusign OAuth flow.

    Returns:
        CommandResults: Results to return to Demisto
    """
    demisto.debug(f"{LOG_PREFIX}Generating consent URL")
    params = demisto.params()

    selected_fetch_types = params.get("event_types", "")
    if not selected_fetch_types:
        demisto.debug(f"{LOG_PREFIX}Please select Event Types before running docusign-generate-consent-url.")
        raise DemistoException("Please select Event Types before running docusign-generate-consent-url.")

    integration_context = get_integration_context()
    required_scopes = get_scopes_per_type(selected_fetch_types)
    consent_scopes = integration_context.get("consent_scopes", [])

    is_all_required_scopes_consent = True
    for scope in required_scopes:
        if scope not in consent_scopes:
            is_all_required_scopes_consent = False
            consent_scopes.append(scope)

    # If all required scopes for the selected types are already set
    if is_all_required_scopes_consent:
        message = "All consent scopes are already set. No need to generate consent URL for those selected types."
        demisto.debug(message)
        return CommandResults(readable_output=message)

    # not all required scopes are set, validate authentication parameters before generating the consent URL
    server_url = params.get("url", DEFAULT_SERVER_DEV_URL).rstrip("/")
    integration_key = params.get("integration_key", "")
    redirect_url = params.get("redirect_url", "")

    if not server_url or not integration_key or not redirect_url:
        message = "Please provide Server URL, Integration Key and Redirect URL before running docusign-generate-consent-url."
        demisto.debug(f"{LOG_PREFIX}{message}")
        raise DemistoException(message)

    # generate the consent URL including the newly required scopes
    scopes = "%20".join(consent_scopes)
    params = f"response_type=code&scope={scopes}&client_id={integration_key}&redirect_uri={redirect_url}"
    consent_url = f"{server_url}/oauth/auth?" + params

    # set the new consent scopes for the next authentication step
    integration_context.update({"consent_scopes": consent_scopes})
    set_integration_context(integration_context)
    demisto.debug(f"{LOG_PREFIX}generated consent URL with the scopes: {consent_scopes}")

    return CommandResults(readable_output=f"### Docusign Consent URL\n[Click here to authorize]({consent_url})")


def validate_configuration_params() -> str:
    params = demisto.params()
    selected_fetch_types = params.get("event_types", "")

    # Validate authentication parameters
    if (
        not params.get("url")
        or not params.get("redirect_url")
        or not params.get("integration_key")
        or not params.get("user_id")
        or not params.get("credentials", {}).get("password", "")
    ):
        return "Please provide Server URL, Integration Key and Redirect URL for authentication flow."

    # Validate parameters for fetching audit users events
    if USER_DATA_TYPE in selected_fetch_types and (not params.get("account_id") or not params.get("organization_id")):
        return f"Please provide Account ID and Organization ID for fetching {USER_DATA_TYPE}."

    return "ok"


def test_module() -> str:
    return validate_configuration_params()


def reset_access_token() -> CommandResults:
    integration_context = get_integration_context()
    integration_context.pop("access_token", None)
    integration_context.pop("expired_at", None)
    integration_context.pop("access_token_scopes", None)
    set_integration_context(integration_context)
    return CommandResults(readable_output="Access token deleted successfully from integration context.")


def main() -> None:  # pragma: no cover
    try:
        command = demisto.command()
        demisto.debug(f"{LOG_PREFIX} Processing command: {command}")

        if command == "test-module":
            return_results(test_module())

        elif command == "fetch-events":
            auth_client = initiate_auth_client()
            last_run, events = fetch_events(auth_client)
            demisto.debug(f"{LOG_PREFIX}Sending {len(events)} events to XSIAM.")
            demisto.info(f"{LOG_PREFIX}Sending {len(events)} events to XSIAM.\n{events}")

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{LOG_PREFIX}Sent events to XSIAM successfully")

            demisto.setLastRun(last_run)
            demisto.debug(f"{LOG_PREFIX}Updated last_run object after fetch: {last_run}")

        elif command == "docusign-generate-consent-url":
            return_results(generate_consent_url())

        elif command == "docusign-reset-access-token":
            return_results(reset_access_token())

    except Exception as e:
        return_error(f"{LOG_PREFIX}Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()
