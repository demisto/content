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
MAX_CUSTOMER_EVENTS_PER_FETCH = 10000

# API limits
MAX_CUSTOMER_EVENTS_PER_PAGE = 2000

class Constants:
    """Global constants for the DocuSign integration."""
    
    # Integration metadata
    INTEGRATION_NAME = "Docusign"

    
    # Timeouts and limits
    TOKEN_SKEW_SECONDS = 60
    DEFAULT_TIMEOUT = 60.0  # requests timeout in seconds
    DEFAULT_LIMITS = 100
    # Retry configuration
    RETRY_MAX = 5
    RETRY_MAX_SLEEP = 20.0
    
    # API limits
    MAX_CUSTOMER_EVENTS_PER_PAGE = 2000
    MAX_ADMIN_TAKE = 250
    
    # Default values
    DEFAULT_SERVER_URL = "https://account-d.docusign.com"
    MAX_CUSTOMER_EVENTS_PER_FETCH = 10000
    DEFAULT_MAX_USER_DATA_EVENTS = 1250
    
    # Integration context keys
    CTX_KEY = "docusign_ctx"
    CTX_TOKEN_CACHE = "token_cache"  # {access_token, expires_at, env, base_uri}
    CTX_CUSTOMER_CURSOR = "customer_cursor"
    CTX_AUDIT_NEXT_URL = "audit_next_url"
    CTX_AUDIT_LAST_MOD_SINCE = "audit_last_modified_since"
    
    # Event types
    EVENT_TYPE_CUSTOMER = "customer"
    EVENT_TYPE_USER_DATA = "user"
    
    # Log messages
    LOG_PREFIX = "[Docusign]"

# -------------------- Utilities --------------------

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

def _admin_base(env: str) -> str:
    return "https://api-d.docusign.net" if env == "dev" else "https://api.docusign.net"

def user_scopes(want_customer_events: bool, want_user_data: bool) -> str:
    scopes = []
    if want_customer_events:
        scopes += ["signature", "impersonation"]
    if want_user_data:
        scopes += ["organization_read", "user_read"]
    seen = set()
    ordered = [s for s in scopes if not (s in seen or seen.add(s))]
    return " ".join(ordered) if ordered else "signature impersonation"


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

        # Generate the JWT
        token = jwt.encode(payload, self.private_key_pem, algorithm="RS256", headers=headers)
        return token

    def exchange_jwt_to_access_token(self, jwt: str) -> str: # [V] reviewed
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
        if not access_token:
            demisto.error(f"{LOG_PREFIX}: Token exchange failed, response missing access_token\n{resp}")
            raise DemistoException(f"{LOG_PREFIX}: Token exchange failed, response missing access_token\n{resp}")
        
        expires_in = resp.get("expires_in")
        demisto.debug(f"{LOG_PREFIX}: Token exchange successful.\naccess_token: {access_token}\nexpires_in: {expires_in}")
        
        return access_token

    def userinfo(self, token: str) -> dict:
        """Fetch user information including base_uri for the account.
        
        Args:
            token: Valid access token
            
        Returns:
            dict: Base URI for the user's account
            
        Raises:
            DemistoException: If user info is invalid or missing required data
        """
        # TODO: NOTE FOR DEVELOPER: above API call can be used as part of test module
        url = urljoin(self.server_url, "/oauth/userinfo")
        headers = {"Authorization": f"Bearer {token}"}
        resp = self._http_request(method="GET", full_url=url, headers=headers, resp_type="json")

        accounts = resp.get("accounts", [])
        if not accounts:
            demisto.debug(f"{LOG_PREFIX}: /oauth/userinfo missing accounts.")
            raise DemistoException("DocuSign: /oauth/userinfo missing accounts.")
            
        for account in accounts:
            if account.get("is_default"):
                return account.get("base_uri"), account.get("account_id")
        return accounts[0].get("base_uri"), accounts[0].get("account_id")

    def get_token(self) -> str: # [V] reviewed
        """
        Exchange JWT for access token using DocuSign OAuth flow.

        Args:
            scopes: Space-separated OAuth scopes to request
            
        Returns:
            str: Access token for DocuSign API authentication

        """
        assertion = self.get_jwt() # NOTE:  design - step 2
        access_token = self.exchange_jwt_to_access_token(assertion) # NOTE: design - step 3
        return access_token

def get_access_token() -> str: # [V] reviewed
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
    if access_token:
        demisto.debug(f"{LOG_PREFIX}Access token already exists in integration context")
        return access_token

    params = demisto.params()
    integration_key = params.get("integration_key", "")
    user_id = params.get("user_id", "")
    private_key_pem = params.get("credentials", {}).get("password", "")
    
    if not integration_key or not user_id or not private_key_pem:
        demisto.debug(f"{LOG_PREFIX}get_access_token function: Integration Key, User ID  or  Private Key is missing.")
        raise DemistoException(
            f"{LOG_PREFIX}. get_access_token function: Integration Key, User ID  or  Private Key is missing."
        )

    client = initiate_auth_client()

    try:
        access_token = client.get_token() # NOTE: design - step 2+3
        # base_uri = client.userinfo(access_token) # NOTE: design - step 4, TODO: move it to the test-module command

        integration_context.update({"access_token": access_token})
        set_integration_context(integration_context)
        demisto.debug(f"{LOG_PREFIX}Access token received successfully and set to integration context")

        return access_token

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Error retrieving access token: {str(e)}")
        raise DemistoException(f"Error retrieving access token: {str(e)}")

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
        env = self.get_env_from_server_url(server_url)
        base_url = urljoin(self.get_monitor_base_url(env), "api/v2.0/datasets/monitor/stream")
        
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def get_monitor_base_url(self, env: str) -> str: # [V] reviewed
        return "https://lens-d.docusign.net" if env == "dev" else "https://lens.docusign.net"

    def get_env_from_server_url(self, server_url: str) -> str: # [V] reviewed
        return "dev" if "account-d.docusign.com" in server_url else "prod"

    def get_customer_events_request(self, cursor: str, events_per_page: int) -> dict: # [V] reviewed
        """
        Send GET request to fetch a stream of customer events from DocuSign Monitor API.
        
        Args:
            cursor: Pagination cursor for resuming from a specific point
            events_per_page: Maximum number of events to return in the current request(capped at MAX_CUSTOMER_EVENTS_PER_PAGE)
            
        Returns:
            dict: Response from DocuSign Monitor API containing customer events
            
        """
        access_token = get_access_token()
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json", "Content-Type": "application/json"}
        params = {"cursor": cursor, "limit": events_per_page}
        
        demisto.debug(f"{LOG_PREFIX}Requesting customer events\nParams: {params}")

        resp = self._http_request(method="GET", headers=headers, params=params, resp_type="json")
        return resp

    def admin_list_users(self, scopes: str, organization_id: str, account_id: str, start: Optional[int], take: int,
                         last_modified_since: Optional[str], next_url: Optional[str]) -> Dict[str, Any]:
        """List users with admin access from DocuSign.
        
        Args:
            scopes: OAuth scopes required for the request
            organization_id: DocuSign organization ID
            account_id: DocuSign account ID
            start: Starting index for pagination
            take: Number of users to fetch (capped at MAX_ADMIN_TAKE)
            last_modified_since: Filter users modified since this timestamp (ISO 8601)
            next_url: URL for next page of results (for pagination)
            
        Returns:
            Dict containing user data and pagination information
            
        Raises:
            DemistoException: If there's an error fetching user list
        """
        ti = self.auth.get_token(scopes)
        if next_url:
            url = next_url
            params = None
        else:
            base = _admin_base(ti.env)
            url = f"{base}/management/v2/organizations/{organization_id}/users"
            params = {"account_id": account_id, "take": min(take, Constants.MAX_ADMIN_TAKE)}
            if start is not None:
                params["start"] = start
            if last_modified_since:
                params["last_modified_since"] = last_modified_since
        resp = self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"},
            params=params
        )
        return resp.json()

    def esign_user_detail(self, scopes: str, account_base_uri: str, account_id: str, user_id: str) -> Dict[str, Any]:
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


class DocuSignClient(BaseClient):
    """
    Client for DocuSign API using OAuth 2.0 authentication.
    
    """
    
    def __init__(self, auth: 'AuthClient', verify: bool, proxies: Optional[Dict[str, str]]) -> None:
        """Initialize the DocuSign client.
        
        Args:
            auth: Authenticated AuthClient instance
            verify: Whether to verify SSL certificates
            proxies: Optional proxy configuration
        """
        self.auth = auth
        self.http = RetryClient(verify=verify, proxies=proxies, timeout=Constants.DEFAULT_TIMEOUT)

    def get_customer_events_request(
        self,
        scopes: str,
        cursor: Optional[str],
        limit: int
    ) -> Dict[str, Any]:
        """Fetch a stream of monitor events from DocuSign.
        
        Args:
            scopes: OAuth scopes required for the request
            cursor: Pagination cursor for resuming from a specific point
            limit: Maximum number of events to return per page (capped at MAX_CUSTOMER_EVENTS_PER_PAGE)
            
        Returns:
            Dict containing monitor events and pagination information
            
        Raises:
            DemistoException: If there's an error fetching the monitor stream
        """
        ti = self.auth.get_token(scopes)
        base = get_monitor_base_url(ti.env)
        params: Dict[str, Any] = {"limit": min(limit, Constants.MAX_CUSTOMER_EVENTS_PER_PAGE)}
        if cursor:
            params["cursor"] = cursor
        url = f"{base}/api/v2.0/datasets/monitor/stream"
        resp = self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"},
            params=params
        )
        return resp.json()

    def admin_list_users(
        self,
        scopes: str,
        organization_id: str,
        account_id: str,
        start: Optional[int],
        take: int,
        last_modified_since: Optional[str],
        next_url: Optional[str]
    ) -> Dict[str, Any]:
        """List users with admin access from DocuSign.
        
        Args:
            scopes: OAuth scopes required for the request
            organization_id: DocuSign organization ID
            account_id: DocuSign account ID
            start: Starting index for pagination
            take: Number of users to fetch (capped at MAX_ADMIN_TAKE)
            last_modified_since: Filter users modified since this timestamp (ISO 8601)
            next_url: URL for next page of results (for pagination)
            
        Returns:
            Dict containing user data and pagination information
            
        Raises:
            DemistoException: If there's an error fetching user list
        """
        ti = self.auth.get_token(scopes)
        if next_url:
            url = next_url
            params = None
        else:
            base = _admin_base(ti.env)
            url = f"{base}/management/v2/organizations/{organization_id}/users"
            params = {"account_id": account_id, "take": min(take, Constants.MAX_ADMIN_TAKE)}
            if start is not None:
                params["start"] = start
            if last_modified_since:
                params["last_modified_since"] = last_modified_since
        resp = self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"},
            params=params
        )
        return resp.json()

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

    def close(self) -> None:
        """Close all HTTP connections and cleanup resources.
        
        This should be called when the client is no longer needed to ensure
        proper cleanup of connections.
        """
        self.http.close()
        self.auth.http.close()


# -------------------- Configuration --------------------

class Config:
    """Configuration manager for DocuSign integration.
    
    This class handles loading, validating, and providing access to all
    configuration parameters required by the integration.
    """
    
    def __init__(self, params: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the configuration.
        
        Args:
            params: Raw parameters from Demisto (defaults to demisto.params())
        """
        self._params = params or demisto.params()
        self._constants = Constants()
        self._validate_params()
    
    # TODO: why those 3 types are required at the beginning of the running without any relation to the commands?
    def _validate_params(self) -> None:
        """Validate configuration parameters."""
        required_params = [
            "integration_key",
            "user_id",
            "private_key_pem"
        ]
        
        for param in required_params:
            if not self._params.get(param):
                raise ValueError(f"Missing required parameter: {param}")
    
    @property
    def server_url(self) -> str:
        """Get the DocuSign server URL."""
        return self._params.get("url") or self._constants.DEFAULT_SERVER_URL
    
    @property
    def integration_key(self) -> str:
        """Get the DocuSign integration key."""
        return str(self._params.get("integration_key", ""))
    
    @property
    def user_id(self) -> str:
        """Get the DocuSign user ID."""
        return str(self._params.get("user_id", ""))
    
    @property
    def redirect_uri(self) -> str:
        """Get the OAuth redirect URI."""
        return str(self._params.get("redirect_url", ""))
    
    @property
    def private_key_pem(self) -> str:
        """Get the private key in PEM format."""
        return str(self._params.get("private_key_pem", ""))
    
    @property
    def account_id(self) -> str:
        """Get the DocuSign account ID (optional)."""
        return self._params.get("account_id")
    
    @property
    def organization_id(self) -> str:
        """Get the DocuSign organization ID (optional)."""
        return self._params.get("organization_id")
    
    @property
    def verify_ssl(self) -> bool:
        """Whether to verify SSL certificates."""
        return not argToBoolean(self._params.get("insecure", False))
    
    @property
    def use_proxy(self) -> bool:
        """Whether to use a proxy."""
        return argToBoolean(self._params.get("proxy", False))
    
    @property
    def fetch_events(self) -> bool:
        """Whether to fetch events."""
        return argToBoolean(self._params.get("isFetch", False))

    @property
    def fetch_user_data(self) -> bool:
        """Whether to fetch user data."""
        event_types = self._get_event_types()
        return "User data" in event_types
    
    @property
    def max_customer_per_fetch(self) -> int:
        """Maximum number of customer events to fetch per run."""
        return int(self._params.get("max_customer_events_per_fetch",
                                 self._constants.MAX_CUSTOMER_EVENTS_PER_FETCH))
    
    @property
    def max_user_data_per_fetch(self) -> int:
        """Maximum number of user data events to fetch per run."""
        return int(self._params.get("max_user_events_per_fetch",
                                 self._constants.DEFAULT_MAX_USER_DATA_EVENTS))
    
    def _get_event_types(self) -> str:
        """Get the list of event types to fetch."""
        return self._params.get("event_types", "")
    
    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            "server_url": self.server_url,
            "integration_key": self.integration_key,
            "user_id": self.user_id,
            "redirect_uri": self.redirect_uri,
            "account_id": self.account_id,
            "organization_id": self.organization_id,
            "verify_ssl": self.verify_ssl,
            "use_proxy": self.use_proxy,
            "fetch_events": self.fetch_events,
            "fetch_customer_events": self.fetch_customer_events,
            "fetch_user_data": self.fetch_user_data,
            "max_customer_per_fetch": self.max_customer_per_fetch,
            "max_user_data_per_fetch": self.max_user_data_per_fetch
        }

# TODO: I dont familiar with this handle_proxy function, I use proxy in the http BaseClient
def proxies_if_enabled(use_proxy: bool):
    """Get proxy configuration if enabled.
    
    Args:
        use_proxy: Whether to use proxy
        
    Returns:
        Proxy configuration dict or None if not using proxy
    """
    return handle_proxy() if use_proxy else None  # type: ignore[name-defined]

def ensure_ids_for_audit(org_id: Optional[str], account_id: Optional[str]) -> None:
    """Verify that required IDs for audit API are present.
    
    Args:
        org_id: Organization ID
        account_id: Account ID
        
    Raises:
        DemistoException: If either ID is missing
    """
    if not org_id or not account_id:
        raise DemistoException("Admin API (audit users) requires both Organization ID and Account ID.")

# -------------------- Single-shot command helpers --------------------

def get_customer_events_once(
    client: DocuSignClient,
    config: Config,
    cursor: str | None,
    limit: int
) -> tuple[list[dict[str, Any]], str]:
    """Fetch a single page of customer events from DocuSign.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        cursor: Pagination cursor (optional)
        limit: Maximum number of events to return
        
    Returns:
        Tuple of (events, next_cursor)
    """
    demisto.debug(f"{LOG_PREFIX} Fetching customer events page")
    
    # Get required scopes and set default cursor if not provided
    scopes = user_scopes(True, config.fetch_user_data)
    if not cursor:
        cursor = _iso_z(_utcnow())
    
    # Fetch events from DocuSign API
    resp = client.get_customer_events_request(
        scopes=scopes,
        cursor=cursor,
        limit=min(limit, Constants.MAX_CUSTOMER_EVENTS_PER_PAGE)
    )
    
    # Process the response
    data = resp.get("data") or []
    next_cursor = resp.get("endCursor") or cursor
    
    # Format events with required fields
    events: list[dict[str, Any]] = []
    for event in data[:limit]:
        if not isinstance(event, dict):
            continue
            
        # Ensure required fields are present
        event["_time"] = event.get("timestamp") or _iso_z(_utcnow())
        event["source_log_type"] = "eventdata"
        
        events.append(event)
    
    demisto.debug(
        f"{LOG_PREFIX} Fetched {len(events)} events, "
        f"next_cursor={next_cursor[:30]}..." if next_cursor else ""
    )
    
    return events, next_cursor

def get_audit_users_once(
    client: DocuSignClient,
    config: Config,
    start: int | None,
    take: int,
    last_modified_since: str | None,
    next_url: str | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch a single page of audit users from DocuSign.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        start: Starting index for pagination
        take: Number of users to fetch
        last_modified_since: Filter users modified since this timestamp
        next_url: URL for next page of results (for pagination)
        
    Returns:
        Tuple of (events, state_dict)
        
    Raises:
        DemistoException: If required configuration is missing
    """
    # Validate required parameters
    if not config.organization_id or not config.account_id:
        raise DemistoException(
            "Organization ID and Account ID are required for audit users API"
        )
    
    demisto.debug(
        f"{LOG_PREFIX} Fetching audit users: "
        f"org_id={config.organization_id}, account_id={config.account_id}, "
        f"start={start}, take={take}, last_modified_since={last_modified_since}"
    )
    
    # Get authentication token and required scopes
    scopes = user_scopes(False, True)
    ti = client.auth.get_token(scopes)
    base_uri = ti.base_uri or ""
    
    # Fetch users from DocuSign API
    resp = client.admin_list_users(
        scopes=scopes,
        organization_id=config.organization_id or "",
        account_id=config.account_id or "",
        start=start,
        take=min(take, Constants.MAX_ADMIN_TAKE),
        last_modified_since=last_modified_since,
        next_url=next_url
    )
    
    # Process the response
    users = resp.get("users") or resp.get("data") or []
    paging = resp.get("paging") or {}
    next_page_url = paging.get("next") or resp.get("next") or ""
    
    # Format events with required fields
    events: list[dict[str, Any]] = []
    for user in users:
        if not isinstance(user, dict):
            continue
            
        # Create event with user data
        event: dict[str, Any] = {
            "source_log_type": "auditusers",
            "user": user,
            "_time": user.get("modifiedDate", ""),
            "_time_iso": ""
        }
        
        # Parse and format timestamp if available
        mod_date = user.get("modifiedDate")
        if mod_date:
            parsed_time = _parse_time_maybe(mod_date)
            if parsed_time:
                event["_time_iso"] = _iso_z(parsed_time)
        
        events.append(event)
    
    # Prepare state for pagination
    state = {
        Constants.CTX_AUDIT_NEXT_URL: next_page_url,
        Constants.CTX_AUDIT_LAST_MOD_SINCE: last_modified_since or _iso_z(_utcnow()),
        "base_uri": base_uri
    }
    
    demisto.debug(
        f"{LOG_PREFIX} Fetched {len(events)} audit users, "
        f"next_page_url={next_page_url[:50]}..." if next_page_url else ""
    )
    
    return events, state

# [V] reviewed
def get_customer_events(last_run: dict, limit: int, events_per_page: int, client: CustomerEventsClient) -> tuple[list, dict]:
    """Fetch customer events from DocuSign Monitor API.
        
    Args:
        client: Initialized DocuSign client
        last_run: Previous fetch state containing # TODO: containing...?
        limit: Maximum number of events to fetch
        events_per_page: Number of events per page
    Returns:
        tuple: (events, last_run) where last_run is the updated state and events are the fetched events.
    """
    # TODO: change it back before release
    one_minute_ago = '2025-08-25T14:00:13Z'
    # one_minute_ago = timestamp_to_datestring(int(time.time() - 60) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ")
    cursor = last_run.get("cursor") or one_minute_ago
    
    total_logs: list = []
    request_count = 1

    while len(total_logs) < limit:
        remaining_logs = limit - len(total_logs)
        events_per_page = min(events_per_page, remaining_logs)
        
        demisto.debug(f"{LOG_PREFIX} Request number {request_count}: requesting {events_per_page} events with cursor: {cursor}")
        try:
            resp = client.get_customer_events_request(cursor, events_per_page)
        except Exception as e:
            demisto.debug(f"{LOG_PREFIX}Exception during get customer events. Exception is {e!s}")
            raise DemistoException(f"Exception during get customer events. Exception is {e!s}")

        cursor = resp.get("endCursor")
        fetched_events = resp.get("data") or []
        total_logs.extend(fetched_events)
        
        demisto.debug(
            f"{LOG_PREFIX}{len(fetched_events)} events fetched from request number {request_count}\n"
            f"Total customer events fetched: {len(total_logs)}")

        if not fetched_events:
            demisto.info(f"{LOG_PREFIX} No more data available")
            break
        
        request_count += 1

    last_run["cursor"] = cursor
    return total_logs, last_run


def fetch_user_data(
    client: DocuSignClient,
    config: Config,
    ctx: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch user data from DocuSign synchronously.
    
    Fetches admin users and enriches them with user details.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        ctx: Integration context
        
    Returns:
        Tuple of (events, updated_state)
    """

    # Validate inputs
    ensure_ids_for_audit(config.organization_id, config.account_id)
    
    # Initial setup
    scopes = user_scopes(False, True)
    total_limit = max(0, int(getattr(config, "max_user_data_per_fetch", 0) or 0))
    last_modified_since = ctx.get(Constants.CTX_AUDIT_LAST_MOD_SINCE) or _iso_z(_utcnow())
    next_url = ctx.get(Constants.CTX_AUDIT_NEXT_URL) or ""
    start = None if next_url else 0
    page_take_default = int(min(Constants.MAX_ADMIN_TAKE, total_limit)) if total_limit else int(Constants.MAX_ADMIN_TAKE)
    
    collected_events = []
    
    demisto.info(
        f"{LOG_PREFIX} Starting user data fetch - "
        f"limit={total_limit}, last_modified_since={last_modified_since}"
    )
    
    # Get auth token
    try:
        ti = client.auth.get_token(scopes)
        base_uri = ti.base_uri or ""
        demisto.debug(f"{LOG_PREFIX} token ok | base_uri={base_uri!r}")
    except Exception as e:
        demisto.error(f"{LOG_PREFIX} auth failure: {e}")
        raise
    
    # Fetch user data
    page_count = 0
    start_time = time.time()
    max_seen_modified_iso = None
    
    try:
        while len(collected_events) < total_limit if total_limit else True:
            page_count += 1
            page_start_time = time.time()
            
            # Calculate page size
            if total_limit:
                remaining = max(0, total_limit - len(collected_events))
                if remaining == 0:
                    demisto.debug(f"{LOG_PREFIX} limit reached, stopping")
                    break
                take = min(page_take_default, remaining)
            else:
                take = page_take_default
            
            demisto.debug(
                f"{LOG_PREFIX} page {page_count} fetch | start={start} take={take} next_url={bool(next_url)}"
            )

            # Fetch a page of users synchronously
            try:
                resp = client.admin_list_users(
                    scopes=scopes,
                    base_uri=base_uri,
                    organization_id=config.organization_id or "",
                    last_modified_since=last_modified_since,
                    next_url=next_url,
                    start=start,
                    take=take,
                )
            except Exception as e:
                demisto.error(f"{LOG_PREFIX} page {page_count} fetch failed: {e}")
                raise

            page_dt = time.time() - page_start_time
            users = resp.get("users") or []
            next_url = resp.get("paging", {}).get("next") or ""

            demisto.debug(
                f"{LOG_PREFIX} page {page_count} fetched | {len(users)} users in {page_dt:.2f}s next={bool(next_url)}"
            )

            if not users:
                demisto.info(f"{LOG_PREFIX} no users on page {page_count}; stopping")
                break

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
                            detail = client.esign_user_detail(scopes, base_uri, config.account_id or "", uid)
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

                collected_events.append(ev)

                if total_limit and len(collected_events) >= total_limit:
                    demisto.debug(f"{LOG_PREFIX} limit {total_limit} reached")
                    break

            demisto.debug(
                f"{LOG_PREFIX} page {page_count} collected={len(users)} total={len(collected_events)}"
            )

            # stop conditions
            if total_limit and len(collected_events) >= total_limit:
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
    finally:
        total_dt = time.time() - start_time
        demisto.info(
            f"{LOG_PREFIX} user data fetch done | collected={len(collected_events)} pages={page_count} "
            f"total={total_dt:.2f}s next={bool(next_url)} lms={last_modified_since}"
        )
    
    # Return events and updated state
    updated_state = {
        Constants.CTX_AUDIT_NEXT_URL: next_url,
        Constants.CTX_AUDIT_LAST_MOD_SINCE: last_modified_since
    }
    return collected_events, updated_state


def initiate_customer_events_client() -> CustomerEventsClient: # [V] reviewed
    """
    Create MonitorClient for making requests

    Returns:
        MonitorClient: MonitorClient instance
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
    events_per_page = min(MAX_CUSTOMER_EVENTS_PER_PAGE, limit)
    
    try:
        demisto.debug(f"{LOG_PREFIX} last_run before fetching customer events: {last_run}")
        client = initiate_customer_events_client()
        customer_events, last_run = get_customer_events(last_run, limit, events_per_page, client)

    except Exception as e:
        demisto.debug(f"{LOG_PREFIX}Exception during fetch customer events.\n{e!s}")
        raise DemistoException(f"{LOG_PREFIX}Exception during fetch customer events.\n{e!s}")
    
    add_fields_to_events(customer_events, event_type=CUSTOMER_EVENTS_TYPE)
    return last_run, customer_events


# TODO: implement this function
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

def fetch_user_data(
    client: DocuSignClient) -> None:
    """Run fetch operations for both customer events and user data.
    
    Args:
        client: Initialized DocuSign client
    """
    
    
    # Get integration context
    # TODO: what does the integration context contain?
    full_ctx = get_integration_context() or {}
    ctx = full_ctx.get(Constants.CTX_KEY, {})
    if not isinstance(ctx, dict):
        demisto.warning(f"{LOG_PREFIX} Integration context not a dict; resetting")
        ctx = {}

    demisto.debug(
        f"{LOG_PREFIX} Context | customer_cursor={ctx.get(Constants.CTX_CUSTOMER_CURSOR)} "
        f"audit_next={ctx.get(Constants.CTX_AUDIT_NEXT_URL)} "
        f"audit_lms={ctx.get(Constants.CTX_AUDIT_LAST_MOD_SINCE)}"
    )
    
    all_events = []
    state_updates = {}
    params = demisto.params()
    selected_fetch_types = params.get("event_types", "")
        
    if "Customer events" in selected_fetch_types:
        demisto.info(f"{LOG_PREFIX} Starting customer events fetch")
        try:
            customer_events, customer_state = fetch_customer_events(client)
            all_events.extend(customer_events)
            state_updates.update(customer_state)
            demisto.info(f"{LOG_PREFIX} Fetched {len(customer_events)} customer events")
        except Exception as e:
            demisto.error(f"{LOG_PREFIX} Failed to fetch customer events: {e}")
            raise
    
    if "User data" in selected_fetch_types:
        demisto.info(f"{LOG_PREFIX} Starting user data fetch")
        try:
            user_events, user_state = fetch_user_data(client, ctx)
            all_events.extend(user_events)
            state_updates.update(user_state)
            demisto.info(f"{LOG_PREFIX} Fetched {len(user_events)} user events")
        except Exception as e:
            demisto.error(f"{LOG_PREFIX} Failed to fetch user data: {e}")
            raise
    
    # Update integration context with new state
    if state_updates:
        current_ctx = get_integration_context() or {}
        dctx = current_ctx.get(Constants.CTX_KEY, {})
        dctx.update(state_updates)
        current_ctx[Constants.CTX_KEY] = dctx
        set_integration_context(current_ctx)
        demisto.info(f"{LOG_PREFIX} Updated integration context")
        
        
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


def command_test_module(client: DocuSignClient, config: Config) -> str:
    """Test the integration configuration and authentication.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        
    Returns:
        str: 'ok' if test succeeds
        
    Raises:
        DemistoException: If test fails
    """
    demisto.debug(f"{LOG_PREFIX} Testing module configuration")
    
    # Test authentication
    scopes = user_scopes(config.fetch_customer_events, config.fetch_user_data)
    ti = client.auth.get_token(scopes)
    
    if not ti.access_token or not ti.base_uri:
        raise DemistoException("Authentication failed: No access token or base URI received")
        
    demisto.debug(f"{LOG_PREFIX} Test completed successfully")
    return "ok"

def command_get_customer_events(
    client: DocuSignClient,
    config: Config,
    args: dict[str, Any]
) -> CommandResults:
    """
    Fetch customer events from DocuSign.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        args: Command arguments
        
    Returns:
        CommandResults: Results to return to Demisto
    """
    # Parse arguments
    limit = min(
        int(args.get("limit", config.max_customer_per_fetch)),
        Constants.MAX_CUSTOMER_EVENTS_PER_PAGE
    )
    cursor = args.get("cursor")
    
    demisto.debug(
        f"{LOG_PREFIX} Fetching customer events: "
        f"limit={limit}, cursor={cursor}"
    )
    
    # Fetch events
    events, next_cursor = get_customer_events_once(client, config, cursor, limit)
    
    return CommandResults(
        readable_output=(
            f"### Customer Events\n"
            f"Fetched {len(events)} customer events.\n"
            f"**Next cursor**: {next_cursor or 'No more events'}"
        ),
        raw_response={"events": events, "next_cursor": next_cursor},
        outputs_prefix="Docusign.CustomerEvents",
        outputs={
            "Events": events,
            "NextCursor": next_cursor,
            "Count": len(events)
        },
    )

def command_get_audit_users(
    client: DocuSignClient, 
    config: Config, 
    args: dict[str, Any]
) -> CommandResults:
    """Fetch audit user records from DocuSign.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        args: Command arguments
        
    Returns:
        CommandResults: Results to return to Demisto
        
    Raises:
        DemistoException: If required parameters are missing
    """
    # Validate required parameters
    ensure_ids_for_audit(config.organization_id, config.account_id)
    
    # Parse arguments
    start = int(args.get("start", 0)) if not args.get("next") else None
    take = min(
        int(args.get("take", Constants.MAX_ADMIN_TAKE)),
        Constants.MAX_ADMIN_TAKE
    )
    last_modified_since = args.get("last_modified_since") or _iso_z(_utcnow())
    next_url = args.get("next") or None
    
    demisto.debug(
        f"{LOG_PREFIX} Fetching audit users: "
        f"start={start}, take={take}, last_modified_since={last_modified_since}"
    )
    
    # Fetch audit users
    events, state = get_audit_users_once(
        client=client,
        config=config,
        start=start,
        take=take,
        last_modified_since=last_modified_since,
        next_url=next_url
    )
    
    return CommandResults(
        readable_output=(
            f"### Audit Users\n"
            f"Fetched {len(events)} audit user records.\n"
            f"**Next URL**: {state.get(Constants.CTX_AUDIT_NEXT_URL, 'No more records')}"
        ),
        raw_response={"events": events, "state": state},
        outputs_prefix="Docusign.AuditUsers",
        outputs={
            "Events": events,
            "State": state,
            "Count": len(events)
        },
    )

# -------------------- Main --------------------

def main() -> None:
    try:
        command = demisto.command()
        demisto.debug(f"{LOG_PREFIX} Processing command: {command}")

        if command == "test-module":
            res = "TODO: implement this command"
            # client = DocuSignClient(auth, verify, proxy)
            # res = command_test_module(client)
            return_results(res)

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

        # elif command == "docusign-get-customer-events":
        #     client = DocuSignClient(auth, verify, proxy)
        #     res = command_get_customer_events(client, config, args)
        #     return_results(res)
        # elif command == "docusign-get-audit-users":
        #     client = DocuSignClient(auth, verify, proxy)
        #     res = command_get_audit_users(client, config, args)
        #     return_results(res)
            
    except Exception as e: # [V] reviewed
        return_error(f"{LOG_PREFIX}Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()
