from __future__ import annotations

import demistomock as demisto  # noqa: F401
from CommonServerPython import *
import urllib3
import datetime as dt
import time
from typing import Any
import jwt  # PyJWT

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "docusign"
PRODUCT = "docusign"

LOG_PREFIX = "[Docusign]"

# yml parameter names
CUSTOMER_EVENTS_TYPE = "Customer events"
USER_DATA_TYPE = "User data"

# yml default values
DEFAULT_SERVER_URL = "https://account-d.docusign.com"
MAX_CUSTOMER_EVENTS_PER_FETCH = 2000
MAX_USER_DATA_PER_FETCH = 1250

# API limits
MAX_USER_DATA_PER_PAGE = 250

# -------------------- Utilities --------------------

def get_env_from_server_url(server_url: str) -> str: # [V] reviewed
    return "dev" if "account-d.docusign.com" in server_url else "prod"

def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _iso_z(dt_obj: dt.datetime) -> str:
    return dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _parse_time_maybe(s: str) -> Optional[dt.datetime]:
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
    ]
    for f in fmts:
        try:
            return dt.datetime.strptime(s, f).replace(tzinfo=dt.timezone.utc)
        except Exception:
            continue
    return None

class AuthClient(BaseClient):
    def __init__(
        self,
        server_url: str,
        integration_key: str,
        user_id: str,
        private_key_pem: str,
        verify: bool = True,
        proxy: bool = False ) -> None:
        """
        Initialize the DocuSign authenticator.
        
        Args:
            server_url: Base URL for the DocuSign API
            integration_key: DocuSign Integration Key (OAuth Client ID)
            user_id: DocuSign User ID for JWT subject
            private_key_pem: RSA private key in PEM format for JWT signing
            verify: Whether to verify SSL certificates
            proxy: Whether to use proxy for requests
        """
        super().__init__(base_url="", verify=verify, proxy=proxy)
        self.server_url = server_url.rstrip("/")
        self.integration_key = integration_key
        self.user_id = user_id
        self.private_key_pem = private_key_pem

    def get_jwt(self) -> str: # [V] reviewed
        """Generate a JWT for authentication.
            
        Returns:
            str: Signed JWT token

        """
        now = _utcnow()
        headers = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self.integration_key,
            "sub": self.user_id,
            "aud": self.server_url.replace("https://", "").replace("http://", ""),
            "iat": int(now.timestamp()),
            "exp": int((now + dt.timedelta(hours=1)).timestamp()),
            "scope": "signature impersonation organization_read user_read",
        }

        token = jwt.encode(payload, self.private_key_pem, algorithm="RS256", headers=headers)
        return token

    def exchange_jwt_to_access_token(self, jwt: str) -> tuple[str, dt.datetime]: # [V] reviewed
        """Exchange JWT for an access token.
        
        Args:
            jwt: Signed JWT
            
        Returns:
            str: Access token

        """
        url = urljoin(self.server_url, "/oauth/token")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        resp = self._http_request(method="POST", full_url=url, headers=headers, data=data, resp_type="json")
        
        access_token = resp.get("access_token")
        expires_in_seconds = resp.get("expires_in")

        if not access_token or not expires_in_seconds:
            demisto.error(f"{LOG_PREFIX}: Token exchange failed, response missing access_token or expires_in\n{resp}")
            raise DemistoException(f"{LOG_PREFIX}: Token exchange failed, response missing access_token or expires_in\n{resp}")
        
        expired_at = _utcnow() + dt.timedelta(seconds=expires_in_seconds)
        return access_token, expired_at

    def get_user_info(self, access_token: str) -> str: # [V] reviewed
        """Fetch user information from /oauth/userinfo endpoint."""

        url = urljoin(self.server_url, "/oauth/userinfo")
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, resp_type="json")
        return resp

    def get_base_uri(self, access_token: str, account_id: str) -> str:
        """Fetch user information including base_uri for the account.

        Args:
            access_token: Valid access token
            account_id: Account ID to fetch base URI for

        Returns:
            str: Base URI for the user's account
        """

        user_info = self.get_user_info(access_token)

        accounts = user_info.get("accounts", [])
        if not accounts:
            demisto.debug(f"{LOG_PREFIX}: /oauth/userinfo missing accounts.")
            raise DemistoException("DocuSign: /oauth/userinfo missing accounts.")

        for account in accounts:
            if account.get("account_id") == account_id:
                return account.get("base_uri")

        demisto.debug(f"{LOG_PREFIX}: /oauth/userinfo missing configuration account id: {account_id}.")
        raise DemistoException(f"{LOG_PREFIX}: /oauth/userinfo missing configuration account id: {account_id}.")

    def get_token(self) -> tuple[str, dt.datetime]: # [V] reviewed
        """Exchange JWT for access token using DocuSign OAuth flow."""
        assertion = self.get_jwt() # NOTE:  design - step 2
        access_token, expired_at = self.exchange_jwt_to_access_token(assertion) # NOTE: design - step 3
        return access_token, expired_at

def is_access_token_expired(expired_at: dt.datetime) -> bool: # [V] reviewed
    """Check if access token is expired."""

    is_not_expired = expired_at > _utcnow() + dt.timedelta(minutes=1)
    if is_not_expired:
        demisto.debug(f"{LOG_PREFIX}using existing Access token from integration context (expires at {expired_at}).")
        return False
    else:
        demisto.debug(f"{LOG_PREFIX}Access token expired.")
        return True

def get_access_token(client: AuthClient) -> str: # [V] reviewed
    """
    Generate JWT and exchange it for access token for DocuSign API OAuth flow.

    This function first checks if an access token already exists in the integration context.
    If not found, it exchanges the JWT for an access token using DocuSign's OAuth token endpoint.

    Args:
        client (AuthClient): AuthClient instance for making requests

    Returns:
        str: Access token for DocuSign API authentication
    Note:
        The access token is stored in the integration context for reuse in subsequent calls.
    """
    integration_context = get_integration_context()
    access_token = integration_context.get("access_token", "")
    expired_at = integration_context.get("expired_at", "")

    if access_token and expired_at and not is_access_token_expired(expired_at):
        return access_token
    
    demisto.debug(f"{LOG_PREFIX}Acquiring a new Access token.")
    try:
        client = initiate_auth_client()
        access_token, expired_at = client.get_token()
        integration_context.update({"access_token": access_token, "expired_at": expired_at})

        set_integration_context(integration_context)
        demisto.debug(f"{LOG_PREFIX}Access token received successfully and set to integration context."
                      f"\naccess_token: {access_token}\nexpired_at: {expired_at}")

        return access_token

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Error retrieving access token: {str(e)}")
        raise DemistoException(f"Error retrieving access token: {str(e)}")

def get_customer_events(last_run: dict, limit: int, client: CustomerEventsClient) -> tuple[list, dict]: # [V] reviewed
    """Fetch customer events from DocuSign Monitor API.
        
    Args:
        client: Initialized DocuSign client
        last_run: Previous fetch state containing cursor
        limit: Maximum number of events to fetch
    Returns:
        tuple: (events, last_run) where last_run is the updated state and events are the fetched events.
    """
    one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
    cursor = last_run.get("cursor") or one_minute_ago
    demisto.debug(f"{LOG_PREFIX}Customer Events: requesting {limit} events with cursor: {cursor}")

    try:
        resp = client.get_customer_events_request(cursor, limit)

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


class CustomerEventsClient(BaseClient):
    """
    DocuSign Monitor API Client for fetching customer events.
    Extends BaseClient to support proxy configuration and proper HTTP request handling.
    """
    
    def __init__(self, server_url: str, proxy: bool = False, verify: bool = True): # [V] reviewed
        """Initialize the Customer Events Monitor client.
        
        Args:
            server_url: Base URL for the DocuSign Monitor API (developer/production environment URI)
            proxy: Whether to use proxy for requests
            verify: Whether to verify SSL certificates
        """
        env = get_env_from_server_url(server_url)
        base_url = urljoin(self.get_monitor_base_url(env), "api/v2.0/datasets/monitor/stream")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def get_monitor_base_url(self, env: str) -> str: # [V] reviewed
        return "https://lens-d.docusign.net" if env == "dev" else "https://lens.docusign.net"

    def get_customer_events_request(self, cursor: str, limit: int) -> dict: # [V] reviewed
        """Send GET request to fetch a stream of customer events from DocuSign Monitor API."""

        auth_client = initiate_auth_client()
        access_token = get_access_token(auth_client)
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json", "Content-Type": "application/json"}
        params = {"cursor": cursor, "limit": limit}
        
        demisto.debug(f"{LOG_PREFIX}Requesting customer events\nParams: {params}")
        resp = self._http_request(method="GET", headers=headers, params=params, resp_type="json")
        return resp

class UserDataClient(BaseClient):
    """
    DocuSign User Data client for fetching user data from DocuSign Admin API.
    
    Args:
        account_id: DocuSign account ID
        organization_id: DocuSign organization ID
        proxy: Whether to use proxy for requests
        verify: Whether to verify SSL certificates
    """

    def __init__(self, account_id: str, organization_id: str, proxy: bool = False, verify: bool = True):
        super().__init__(base_url="", verify=verify, proxy=proxy)
        self.account_id = account_id
        self.organization_id = organization_id

    def get_admin_base_url(self, env: str) -> str:
        return "https://api-d.docusign.net" if env == "dev" else "https://api.docusign.net"

    def get_users_next_request(self, access_token: str, url: str, request_params: dict = {}) -> dict:
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, params=request_params, resp_type="json")
        return resp
        
    def get_users_first_request(self,
        organization_id: str,
        env: str,
        access_token: str,
        request_params: Dict[str, Any]
    ) -> tuple[dict, str]:

        base = self.get_admin_base_url(env)
        url = urljoin(base, f"management/v2/organizations/{organization_id}/users")
        
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, params=request_params, resp_type="json")
        return resp, url

    def esign_user_detail(
        self,
        scopes: str,
        account_base_uri: str,
        account_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Fetch detailed information about a specific eSignature user.
        
        Args:
            scopes: OAuth scopes required for the request
            account_base_uri: Base URI for the DocuSign account
            account_id: DocuSign account ID
            user_id: ID of the user to fetch details for
            
        Returns:
            Dict containing detailed user information
            
        Raises:
            DemistoException: If there's an error fetching user details
        """
        ti = self.auth.get_token(scopes)
        url = f"{account_base_uri}/restapi/v2.1/accounts/{account_id}/users/{user_id}"
        resp = self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"}
        )
        return resp.json()

def fetch_user_data(last_run: dict) -> tuple[dict, list]: # [V] reviewed
    params = demisto.params()
  
    server_url = params.get("url", DEFAULT_SERVER_URL)
    organization_id = params.get("organization_id", "")
    env = get_env_from_server_url(server_url)
    account_id = params.get("account_id", "")

    limit = min(MAX_USER_DATA_PER_FETCH, int(params.get("max_user_events_per_fetch", MAX_USER_DATA_PER_FETCH)))
    events_per_page = min(MAX_USER_DATA_PER_PAGE, limit)
    
    try:
        demisto.debug(f"{LOG_PREFIX} last_run before fetching user data: {last_run}")
        client = initiate_user_data_client()
        user_data_events, last_run = get_user_data_events(
            last_run, limit, events_per_page, client, organization_id, env, account_id)
    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during fetch user data.\n{e!s}")
        raise DemistoException(f"{LOG_PREFIX}Exception during fetch user data.\n{e!s}")
    
    add_fields_to_events(user_data_events, event_type=USER_DATA_TYPE)
    return last_run, user_data_events



def get_user_data_events(last_run: dict, limit: int, events_per_page: int, client: UserDataClient, organization_id: str, env: str, account_id: str) -> tuple[list, dict]:
    total_events = []
    remaining_to_fetch = 0
    latest_modified_date = None
    
    try:
        # next url was existing in the last response, meaning we are continuing a fetch from the last run
        if last_run.get("continuing_fetch_info"):
            url = last_run.get("continuing_fetch_info", {}).get("url")
            request_params = {}
            demisto.debug(f"{LOG_PREFIX}Continuing fetch for Audit data from:\n {url}")

        # First fetch in the current time range.
        else:
            one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
            url = ""
            request_params = {
                "start": 0,
                "take": events_per_page, # api limit - max 250
                "last_modified_since": last_run.get("last_modified_since") or one_minute_ago
            }
            demisto.debug(f"{LOG_PREFIX}Starting new fetch range for Audit Users data.")
        
        auth_client = initiate_auth_client()
        access_token = get_access_token(auth_client)
        base_uri = auth_client.get_base_uri(access_token, account_id)
        
        """
        The first condition that reached will exit the loop:
        1. len(total_events) >= limit
        2. next_url is None
        """
        while len(total_events) < limit:
            remaining = limit - len(total_events)
            demisto.debug(f"{LOG_PREFIX}Starting to fetch new request of users.\nRemaining users to fetch: {remaining}")

            if url:
                resp = client.get_users_next_request(access_token, url)
            else:
                resp, url = client.get_users_first_request(organization_id, env, access_token, request_params)

            users = resp.get("users", [])
            next_url = resp.get("paging", {}).get("next", "")
            
            demisto.debug(f"{LOG_PREFIX}Successfully fetched {len(users)} users events.")
            total_events.extend(users)

            # TODO: implement handle duplication - maybe i can do it once outside the function, after finishinf to fetch all ues in this current run.
            # just save the old latest modified date before calling this function, and remove the duplicates based on it after calling this function.
            #NOTE: I dont know how to handle duplication because there is no id in the first step, and hoe can I Differentiate between fetched event in the second step?

            if not next_url: # last page reached, there are no more logs to fetch.
                demisto.debug(f"{LOG_PREFIX}No more pages in the current time range.")

                if len(users) > remaining_to_fetch:
                    demisto.debug(f"{LOG_PREFIX} There are more users than remaining to fetch.")
                    last_run["excess_logs_info"] = {
                        "offset": remaining_to_fetch,
                        "url": url,
                        "request_params": request_params
                    }
                    demisto.debug(
                        f"{LOG_PREFIX} Setting excess_logs_info for next fetch: {last_run['excess_logs_info']}\n"
                        f"{LOG_PREFIX} Truncated total fetched users from {len(total_events)} to limit: {limit}"
                    )
                    total_events = total_events[:limit]
                    
                # TODO: add the step 2 for this fetch and set latest_modified_date
                last_run["last_modified_since"] = latest_modified_date
                last_run["continuing_fetch_info"] = None

                return total_events, last_run

            prev_url = url
            url = next_url
            
        # At this point, limit is reached before next_url. (it means there are more pages to fetch)
        last_run["continuing_fetch_info"] = {"url": url}
        demisto.debug(
            f"{LOG_PREFIX} limit is reached and there are more pages to fetch"
            f"setting continuing_fetch_info for next fetch: {last_run['continuing_fetch_info']}")

        if len(users) > remaining_to_fetch:
            last_run["excess_logs_info"] = {
                "offset": remaining_to_fetch,
                "url": prev_url,
                "request_params": request_params
            }

            demisto.debug(
                f"{LOG_PREFIX}Limit is reached and only partial users were fetched from the last page scanning.\n"
                f"Setting excess_logs_info: {last_run['excess_logs_info']}"
            )

            total_events = total_events[:limit]
        return total_events, last_run

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during get user data events. Exception is {e!s}")
        raise DemistoException(f"Exception during get user data events. Exception is {e!s}")
            

def get_user_data_events_reference(last_run: dict, limit: int, events_per_page: int, client: UserDataClient) -> tuple[list, dict]:

    params = demisto.params()

    one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
    last_modified_since = last_run.get("last_modified_since") or one_minute_ago
    next_url = last_run.get("audit_next_url", "")

    start = 0 # TODO: implement remaining events logic like monday collector and use the start as offset
    total_events = []

    max_seen_modified_iso = None # TODO: what is this?
    page_count = 0
    
    try:
        auth_client = initiate_auth_client()
        access_token = get_access_token(auth_client)
        base_uri = auth_client.get_base_uri(access_token, params.get("account_id"))
        
        while len(total_events) < limit:
            page_count += 1
            
            remaining = max(0, limit - len(total_events))
            if remaining == 0:
                demisto.debug(f"{LOG_PREFIX} limit reached, stopping")
                break
            take = min(events_per_page, remaining)

            demisto.debug(f"{LOG_PREFIX} Page number {page_count}: requesting {take} events with next_url: {next_url}")
            # Fetch a page of users synchronously
            try:
                resp = client.admin_list_users(
                    scopes="signature impersonation organization_read user_read",
                    base_uri=base_uri,
                    organization_id=demisto.params().get("organization_id", ""),
                    last_modified_since=last_modified_since,
                    next_url=next_url,
                    start=start,
                    take=take,
                )
            except Exception as e:
                demisto.error(f"{LOG_PREFIX} page {page_count} fetch failed: {e}")
                raise

            users = resp.get("users") or []
            next_url = resp.get("paging", {}).get("next") or ""
            if not users:
                demisto.info(f"{LOG_PREFIX} no users on page {page_count}; stopping")
                break
            
            # TODO: stop here - step 2
            # Enrich with eSign details synchronously
            ids = [str(u.get("id") or u.get("user_id") or "") for u in users if u.get("id") or u.get("user_id")]
            details = []
            if ids:
                detail_start = time.time()
                demisto.debug(
                    f"{LOG_PREFIX} page {page_count} enrich {len(ids)} users"
                )
                try:
                    # Fetch user details sequentially (synchronous)
                    for uid in ids:
                        try:
                            detail = client.esign_user_detail(scopes, base_uri, demisto.params().get("account_id", ""), uid)
                            if detail:
                                details.append(detail)
                        except Exception as e:
                            demisto.debug(f"{LOG_PREFIX} failed to enrich user {uid}: {e}")
                            continue
                except Exception as e:
                    demisto.error(f"{LOG_PREFIX} page {page_count} enrich failed: {e}")
                    details = []  # proceed without enrichment
                finally:
                    enr_dt = time.time() - detail_start
                    demisto.debug(
                        f"{LOG_PREFIX} page {page_count} enrich done | {len(details)} items in {enr_dt:.2f}s"
                    )

            by_id = {
                str(d.get("userId") or d.get("user_id") or d.get("id")): d
                for d in details
                if d
            }

            # Process and collect events
            for u in users:
                ev = {"source_log_type": "auditusers", "user": u}

                # timestamps
                mod = u.get("modifiedDate") or u.get("modified_date") or ""
                ev["_time"] = mod or _iso_z(_utcnow())
                dtp = _parse_time_maybe(mod)
                if dtp:
                    ev["_time_iso"] = _iso_z(dtp)
                    # track max modified seen
                    if max_seen_modified_iso is None or _parse_time_maybe(max_seen_modified_iso) < dtp:
                        max_seen_modified_iso = _iso_z(dtp)

                # attach enrichment
                uid = str(u.get("id") or u.get("user_id") or "")
                if uid and uid in by_id:
                    ev["esign_detail"] = by_id[uid]

                total_events.append(ev)

                if limit and len(total_events) >= limit:
                    demisto.debug(f"{LOG_PREFIX} limit {limit} reached")
                    break

            demisto.debug(
                f"{LOG_PREFIX} page {page_count} collected={len(users)} total={len(total_events)}"
            )

            # stop conditions
            if limit and len(total_events) >= limit:
                demisto.info(f"{LOG_PREFIX} reached limit after {page_count} pages")
                break

            if not next_url:
                # no more pages; advance LMS to max seen (fallback to now if none)
                last_modified_since = max_seen_modified_iso or _iso_z(_utcnow())
                demisto.info(f"{LOG_PREFIX} end of pages; lms-> {last_modified_since}")
                break

            # when using server-provided next URLs, server drives paging
            start = None

    except Exception as e:
        demisto.error(f"{LOG_PREFIX} unexpected error after page {page_count}: {e}")
        raise
    
    last_run["last_modified_since"] = last_modified_since
    last_run["audit_next_url"] = next_url

    return total_events, last_run

def initiate_user_data_client() -> UserDataClient:  # [V] reviewed
    """
    Create UserDataClient for making requests to DocuSign Admin API and fetching user data and fetching user details.
    """
    params = demisto.params()
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    account_id = params.get("account_id", "")
    organization_id = params.get("organization_id", "")
    
    if not account_id or not organization_id:
        demisto.debug(f"{LOG_PREFIX} initiate_user_data_client function: Account ID or Organization ID is missing.")
        raise DemistoException(f"{LOG_PREFIX}. initiate_user_data_client function: Account ID or Organization ID is missing.")

    return UserDataClient(account_id=account_id, organization_id=organization_id, proxy=proxy, verify=verify)

def initiate_customer_events_client() -> CustomerEventsClient: # [V] reviewed
    """
    Create CustomerEventsClient for making requests to DocuSign Monitor API and fetching customer events.
    """
    params = demisto.params()
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    server_url = params.get("url", DEFAULT_SERVER_URL)
    
    return CustomerEventsClient(server_url=server_url, proxy=proxy, verify=verify)

def initiate_auth_client() -> AuthClient: # [V] reviewed
    """
    Create AuthClient for making requests to DocuSign API authentication flow.

    Returns:
        AuthClient: AuthClient instance
    """
    
    params = demisto.params()
    server_url = params.get("url", DEFAULT_SERVER_URL)
    integration_key = params.get("integration_key", "")
    user_id = params.get("user_id", "")
    private_key_pem = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    
    if not integration_key or not user_id or not private_key_pem:
        demisto.debug(f"{LOG_PREFIX}initiate_auth_client function: Integration Key, User ID  or  Private Key is missing.")
        raise DemistoException(
            f"{LOG_PREFIX}. initiate_auth_client function: Integration Key, User ID  or  Private Key is missing."
        )
    
    auth = AuthClient(
        server_url=server_url,
        integration_key=integration_key,
        user_id=user_id,
        private_key_pem=private_key_pem,
        verify=verify,
        proxy=proxy,
    )
    return auth

def fetch_customer_events(last_run: dict) -> tuple[dict, list]: # [V] reviewed
    params = demisto.params()
    limit = min(MAX_CUSTOMER_EVENTS_PER_FETCH, int(params.get("max_customer_events_per_fetch", MAX_CUSTOMER_EVENTS_PER_FETCH)))    
    try:
        demisto.debug(f"{LOG_PREFIX} last_run before fetching customer events: {last_run}")
        client = initiate_customer_events_client()
        customer_events, last_run = get_customer_events(last_run, limit, client)

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during fetch customer events.\n{e!s}")
        raise DemistoException(f"{LOG_PREFIX}Exception during fetch customer events.\n{e!s}")
    
    add_fields_to_events(customer_events, event_type=CUSTOMER_EVENTS_TYPE)
    return last_run, customer_events

def add_fields_to_events(events: list, event_type: str) -> None:
    """
    Adds the _time and event_type keys to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The enriched events.
    """
    for event in events:
        if event_type == CUSTOMER_EVENTS_TYPE:
            event["source_log"] = "eventdata"

            t_without_milliseconds = event.get("timestamp").split('.')[0]
            dt = datetime.strptime(t_without_milliseconds, "%Y-%m-%dT%H:%M:%S") if t_without_milliseconds else None
            time_value = dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None
            event["_time"] = time_value

        elif event_type == USER_DATA_TYPE:
            event["event_type"] = event_type
            # TODO: Add _time field to user data events

def fetch_events() -> tuple[dict, list]: # [V] reviewed
    """
    Fetch events from DocuSign based on configuration. (Customer events and User data)
    
    Returns:
        tuple: (last_run, events) where last_run is the updated state and events are the fetched events.
    """
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
        demisto.info(f"{LOG_PREFIX}Start fetch customer events, Current customer events last_run:\n{last_run_customer_events}")
        last_run_customer_events, fetched_customer_events = fetch_customer_events(last_run_customer_events)
        events.extend(fetched_customer_events)
        demisto.debug(f"{LOG_PREFIX}Total fetched customer events: {len(fetched_customer_events)}")

    if USER_DATA_TYPE in selected_fetch_types:
        demisto.info(f"{LOG_PREFIX}Start fetch user data, Current user data last_run:\n{last_run_user_data}")
        last_run_user_data, fetched_user_data = fetch_user_data(last_run_user_data)
        events.extend(fetched_user_data)
        demisto.debug(f"{LOG_PREFIX}Total fetched user data: {len(fetched_user_data)}")
    
    last_run = {CUSTOMER_EVENTS_TYPE: last_run_customer_events, USER_DATA_TYPE: last_run_user_data}
    return last_run, events

def command_generate_consent_url() -> CommandResults: # [V] reviewed
    """Generate a consent URL for DocuSign OAuth flow.

    Returns:
        CommandResults: Results to return to Demisto
    """
    demisto.debug(f"{LOG_PREFIX}Generating consent URL")
    params = demisto.params()
    
    scopes = "signature%20impersonation%20organization_read%20user_read"
    server_url = params.get("url", DEFAULT_SERVER_URL).rstrip("/")
    integration_key = params.get("integration_key", "")
    redirect_url = params.get("redirect_url", "")
    
    if not server_url or not integration_key or not redirect_url:
        demisto.debug(f"{LOG_PREFIX}Please provide Server URL, Integration Key and Redirect URL in the integration parameters before running monday-generate-login-url.")
        raise DemistoException("Please provide Server URL, Integration Key and Redirect URL in the integration parameters before running monday-generate-login-url.")

    consent_url = f"{server_url}/oauth/auth?response_type=code&scope={scopes}&client_id={integration_key}&redirect_uri={redirect_url}"
    md = f"### DocuSign Consent URL\n[Click here to authorize]({consent_url})"
    
    return CommandResults(readable_output=md)


def validate_params(): # [V] reviewed
    params = demisto.params()
    selected_fetch_types = params.get("event_types", "")
    
    # Validate authentication parameters
    if not params.get("url") or not params.get("redirect_url") or not params.get("integration_key") or not params.get("user_id") or not params.get("credentials", {}).get("password", ""):
        raise DemistoException("Please provide Server URL, Integration Key and Redirect URL for authentication flow.")
    
    if USER_DATA_TYPE in selected_fetch_types and (not params.get("account_id") or not params.get("organization_id")):
        raise DemistoException(f"Please provide Account ID and Organization ID for fetching {USER_DATA_TYPE}.")
    
    if CUSTOMER_EVENTS_TYPE in selected_fetch_types and not params.get("url"):
        raise DemistoException(f"Please provide Server URL for fetching {CUSTOMER_EVENTS_TYPE}.")

def test_module() -> str: # [V] reviewed
    validate_params()

    client = initiate_auth_client()
    access_token = get_access_token(client)
    user_info = client.get_user_info(access_token)

    if not access_token or not user_info:
        demisto.debug(f"{LOG_PREFIX} Test module failed during authentication: No access token or userinfo received")
        raise DemistoException("Test module failed during authentication: No access token or userinfo received")
        
    demisto.debug(f"{LOG_PREFIX} Test module completed successfully")
    return "ok"
  
def main() -> None:
    try:
        command = demisto.command()
        demisto.debug(f"{LOG_PREFIX} Processing command: {command}")

        if command == "test-module": # [V] reviewed
            return_results(test_module())

        elif command == "fetch-events": # [V] reviewed
            last_run, events = fetch_events()
            demisto.debug(f"{LOG_PREFIX}Sending {len(events)} events to XSIAM.")
            demisto.info(f"{LOG_PREFIX}Sending {len(events)} events to XSIAM.\n{events}")

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{LOG_PREFIX}Sent events to XSIAM successfully")
            
            demisto.setLastRun(last_run)
            demisto.debug(f"{LOG_PREFIX}Updated last_run object after fetch: {last_run}")
            
        elif command == "docusign-generate-consent-url": # [V] reviewed
            return_results(command_generate_consent_url())
            
    except Exception as e: # [V] reviewed
        return_error(f"{LOG_PREFIX}Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "builtin", "builtins"):
    main()
