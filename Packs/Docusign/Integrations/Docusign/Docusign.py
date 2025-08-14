# -*- coding: utf-8 -*-
"""
DocuSign Event Collector — asyncio + httpx + producer/consumer

Key points
- Uses the standard XSOAR integration entrypoint: main() + demisto.command() router.
- All HTTP via httpx.AsyncClient with connection pooling and exponential backoff.
- JWT (PyJWT RS256) authentication + /oauth/userinfo base_uri discovery; cached in integration context.
- Two producers:
    • Monitor producer (customer events) paginates with endCursor.
    • Admin producer (audit users) paginates with 'next' and enriches users via eSignature API with bounded concurrency.
- N consumers read from an asyncio.Queue, batch, and ship with send_events_to_xsiam (offloaded so the loop never blocks).
- Resilient: retries on 408/429/5xx, honors Retry-After, token skew handling, safe state persistence.

Commands
- test-module
- docusign-generate-consent-url
- docusign-get-customer-events      (single-shot; no pipeline)
- docusign-get-audit-users          (single-shot; no pipeline)
- fetch-events                      (async pipeline; producer–consumer)
"""

from __future__ import annotations

import asyncio
import datetime as dt
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import jwt  # PyJWT
import httpx

import demistomock as demisto  # noqa: F401
from CommonServerPython import (  # noqa: F401
    CommandResults,
    DemistoException,
    return_results,
    return_error,
    argToBoolean,
    send_events_to_xsiam,
    set_to_integration_context_with_retries,
    get_integration_context,
    handle_proxy,
)

# -------------------- Constants --------------------

class Constants:
    """Global constants for the DocuSign integration."""
    
    # Integration metadata
    INTEGRATION_NAME = "Docusign"
    VENDOR = "docusign"
    PRODUCT = "docusign"
    
    # Timeouts and limits
    TOKEN_SKEW_SECONDS = 60
    DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=60.0, write=60.0, connect=10.0)
    DEFAULT_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=100)
    
    # Retry configuration
    RETRY_MAX = 5
    RETRY_BASE_SLEEP = 1.5
    RETRY_MAX_SLEEP = 20.0
    
    # API limits
    MAX_MONITOR_PAGE_LIMIT = 2000
    MAX_ADMIN_TAKE = 250
    DEFAULT_USER_DETAIL_CONCURRENCY = 12
    
    # Default values
    DEFAULT_SERVER_URL = "https://account-d.docusign.com"
    DEFAULT_MAX_CUSTOMER_EVENTS = 10000
    DEFAULT_MAX_USER_DATA_EVENTS = 1250
    DEFAULT_QUEUE_MAXSIZE = 2000
    DEFAULT_CONSUMER_WORKERS = 3
    DEFAULT_SEND_BATCH_SIZE = 1000
    
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
    
    @classmethod
    def get_default_headers(cls) -> Dict[str, str]:
        """Get default HTTP headers for API requests."""
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"{cls.INTEGRATION_NAME}/1.0"
        }

# -------------------- Utilities --------------------

def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _iso_z(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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

def _env_from_server_url(server_url: str) -> str:
    return "dev" if "account-d.docusign.com" in server_url else "prod"

def _oauth_base(server_url: str) -> str:
    return server_url.rstrip("/")

def _monitor_base(env: str) -> str:
    return "https://lens-d.docusign.net" if env == "dev" else "https://lens.docusign.net"

def _admin_base(env: str) -> str:
    return "https://api-d.docusign.net" if env == "dev" else "https://api.docusign.net"

def _user_scopes(want_customer_events: bool, want_user_data: bool) -> str:
    scopes: List[str] = []
    if want_customer_events:
        scopes += ["signature", "impersonation"]
    if want_user_data:
        scopes += ["organization_read", "user_read"]
    seen = set()
    ordered = [s for s in scopes if not (s in seen or seen.add(s))]
    return " ".join(ordered) if ordered else "signature impersonation"

def build_consent_url(server_url: str, client_id: str, redirect_uri: str, scopes: str) -> str:
    base = _oauth_base(server_url)
    scope_enc = scopes.replace(" ", "%20")
    return f"{base}/oauth/auth?response_type=code&scope={scope_enc}&client_id={client_id}&redirect_uri={redirect_uri}"

# -------------------- HTTP with retries (async) --------------------

class AsyncRetryClient:
    """HTTP client with automatic retry and backoff for failed requests.
    
    This client wraps httpx.AsyncClient and adds retry logic for transient failures,
    rate limiting, and server errors. It implements exponential backoff with jitter.
    """
    
    def __init__(
        self,
        *,
        verify: bool,
        proxies: Optional[Dict[str, str]],
        timeout: httpx.Timeout,
        limits: httpx.Limits
    ) -> None:
        """Initialize the retry client.
        
        Args:
            verify: Whether to verify SSL certificates
            proxies: Optional proxy configuration
            timeout: Timeout configuration for requests
            limits: Connection pool limits
        """
        self.client = httpx.AsyncClient(
            verify=verify,
            proxy=proxies,
            timeout=timeout,
            limits=limits,
            follow_redirects=True
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        allow_status: Iterable[int] = ()
    ) -> httpx.Response:
        """Send an HTTP request with automatic retries on failure.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to send the request to
            headers: Optional request headers
            params: Optional query parameters
            data: Optional form data or raw content
            json: Optional JSON-serializable data
            allow_status: Additional status codes to consider successful
            
        Returns:
            httpx.Response: The HTTP response
            
        Raises:
            httpx.HTTPStatusError: For non-retryable HTTP errors
            httpx.RequestError: For network-related errors after retries
            Exception: For other unexpected errors
        """
        attempt = 0
        backoff = RETRY_BASE_SLEEP
        
        while True:
            attempt += 1
            
            try:
                # Make the request
                resp = await self.client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json
                )
                
                # Check if status code indicates success
                if resp.status_code in allow_status or 200 <= resp.status_code < 300:
                    return resp

                # Handle retryable status codes
                if resp.status_code in (408, 429) or 500 <= resp.status_code < 600:
                    if attempt >= RETRY_MAX:
                        resp.raise_for_status()
                        
                    # Calculate backoff with jitter
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        sleep_s = float(retry_after)
                    else:
                        sleep_s = min(backoff * (1 + 0.1 * (random.random() - 0.5)), RETRY_MAX_SLEEP)
                        
                    demisto.debug(
                        f"[Docusign] Retryable HTTP {resp.status_code} {url}; "
                        f"sleep {sleep_s:.2f}s (attempt {attempt}/{RETRY_MAX})"
                    )
                    
                    await asyncio.sleep(sleep_s)
                    backoff = min(backoff * 2, RETRY_MAX_SLEEP)
                    continue

                # For non-retryable errors, raise immediately
                resp.raise_for_status()
                
            except (httpx.ConnectTimeout, httpx.ReadTimeout, 
                   httpx.ConnectError, httpx.RemoteProtocolError) as e:
                # Handle network-related errors with retries
                if attempt >= RETRY_MAX:
                    demisto.error(
                        f"[Docusign] Max retries ({RETRY_MAX}) exceeded for {method} {url}: {e}"
                    )
                    raise
                    
                sleep_s = min(backoff * (1 + 0.1 * (random.random() - 0.5)), RETRY_MAX_SLEEP)
                demisto.debug(
                    f"[Docusign] Network error {type(e).__name__} on {method} {url}; "
                    f"sleep {sleep_s:.2f}s (attempt {attempt}/{RETRY_MAX}): {e}"
                )
                
                await asyncio.sleep(sleep_s)
                backoff = min(backoff * 2, RETRY_MAX_SLEEP)

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release resources.
        
        This should be called when the client is no longer needed to ensure
        proper cleanup of connections.
        """
        try:
            await self.client.aclose()
        except Exception as e:
            demisto.debug(f"[Docusign] Error closing HTTP client: {e}")
            raise

# -------------------- Auth --------------------

@dataclass
class TokenInfo:
    access_token: str
    expires_at: int
    env: str
    base_uri: Optional[str] = None

class DocuSignAuthAsync:
    """Handles authentication with DocuSign using JWT grant flow.
    
    This class manages the OAuth 2.0 JWT Bearer flow for authenticating with DocuSign APIs.
    It handles token acquisition, refresh, and caching in the integration context.
    """
    
    def __init__(
        self,
        server_url: str,
        integration_key: str,
        user_id: str,
        private_key_pem: str,
        verify: bool,
        proxies: Optional[Dict[str, str]]
    ) -> None:
        """Initialize the DocuSign authenticator.
        
        Args:
            server_url: Base URL for the DocuSign API
            integration_key: DocuSign Integration Key (OAuth Client ID)
            user_id: DocuSign User ID for JWT subject
            private_key_pem: RSA private key in PEM format for JWT signing
            verify: Whether to verify SSL certificates
            proxies: Optional proxy configuration for HTTP requests
        """
        self.server_url = _oauth_base(server_url)
        self.env = _env_from_server_url(server_url)
        self.integration_key = integration_key
        self.user_id = user_id
        self.private_key_pem = private_key_pem
        self.http = AsyncRetryClient(verify=verify, proxies=proxies, timeout=DEFAULT_TIMEOUT, limits=DEFAULT_LIMITS)

    def _jwt(self, scopes: str) -> str:
        """Generate a JWT for authentication.
        
        Args:
            scopes: Space-separated OAuth scopes to request
            
        Returns:
            str: Signed JWT token
            
        Raises:
            Exception: If JWT generation fails
        """
        now = _utcnow()
        payload = {
            "iss": self.integration_key,
            "sub": self.user_id,
            "aud": self.server_url.replace("https://", "").replace("http://", ""),
            "iat": int(now.timestamp()),
            "exp": int((now + dt.timedelta(hours=1)).timestamp()),
            "scope": scopes,
        }
        headers = {"alg": "RS256", "typ": "JWT"}
        token = jwt.encode(payload, self.private_key_pem, algorithm="RS256", headers=headers)
        return token if isinstance(token, str) else token.decode("utf-8")

    async def _exchange(self, assertion: str) -> TokenInfo:
        """Exchange JWT assertion for an access token.
        
        Args:
            assertion: Signed JWT assertion
            
        Returns:
            TokenInfo: Access token and metadata
            
        Raises:
            DemistoException: If token exchange fails or returns invalid response
        """
        url = f"{self.server_url}/oauth/token"
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        resp = await self.http.request(
            "POST",
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data
        )
        js = resp.json()
        access_token = js.get("access_token")
        expires_in = int(js.get("expires_in", 3600))
        if not access_token:
            raise DemistoException("DocuSign: Token exchange failed (no access_token).")
        expires_at = int(time.time()) + max(1, expires_in - TOKEN_SKEW_SECONDS)
        return TokenInfo(access_token=access_token, expires_at=expires_at, env=self.env)

    async def _userinfo(self, token: str) -> str:
        """Fetch user information including base_uri for the account.
        
        Args:
            token: Valid access token
            
        Returns:
            str: Base URI for the user's account
            
        Raises:
            DemistoException: If user info is invalid or missing required data
        """
        url = f"{self.server_url}/oauth/userinfo"
        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        js = resp.json()
        
        # Handle case where response is a string instead of dict
        if isinstance(js, str):
            try:
                import json
                js = json.loads(js)
            except (json.JSONDecodeError, TypeError) as e:
                raise DemistoException(f"DocuSign: /oauth/userinfo returned invalid JSON: {js}") from e
        
        if not isinstance(js, dict):
            raise DemistoException(f"DocuSign: /oauth/userinfo returned unexpected response type: {type(js)} - {js}")
            
        accounts = js.get("accounts") or []
        chosen = None
        for acc in accounts:
            if acc.get("is_default"):
                chosen = acc
                break
        if not chosen and accounts:
            chosen = accounts[0]
            
        base_uri = (chosen or {}).get("base_uri")
        if not base_uri:
            raise DemistoException("DocuSign: /oauth/userinfo missing base_uri.")
            
        return base_uri

    async def get_token(self, scopes: str) -> TokenInfo:
        """Get a valid access token, using cached token if available and not expired.
        
        Args:
            scopes: Space-separated OAuth scopes to request
            
        Returns:
            TokenInfo: Access token and metadata
            
        Raises:
            DemistoException: If authentication fails at any step
        """
        ctx = get_integration_context() or {}
        dctx = ctx.get(CTX_KEY, {})
        
        # Ensure dctx is a dictionary, not a string or other type
        if not isinstance(dctx, dict):
            dctx = {}
            
        cache = dctx.get(CTX_TOKEN_CACHE) or {}
        now = int(time.time())

        # Return cached token if valid
        if (cache and 
            cache.get("access_token") and 
            cache.get("expires_at", 0) > now and 
            cache.get("env") == self.env):
                
            ti = TokenInfo(
                access_token=cache["access_token"],
                expires_at=int(cache["expires_at"]),
                env=cache["env"],
                base_uri=cache.get("base_uri") or None,
            )
        else:
            # Get new token
            assertion = self._jwt(scopes)
            ti = await self._exchange(assertion)

        # Ensure we have the base_uri for the token
        if not ti.base_uri:
            ti.base_uri = await self._userinfo(ti.access_token)

        # Update cache
        set_to_integration_context_with_retries({
            CTX_KEY: {
                **dctx,
                CTX_TOKEN_CACHE: {
                    "access_token": ti.access_token,
                    "expires_at": ti.expires_at,
                    "env": ti.env,
                    "base_uri": ti.base_uri or "",
                }
            }
        })
        
        return ti

# -------------------- API Client --------------------

class DocuSignClientAsync:
    """Asynchronous client for interacting with DocuSign APIs.
    
    This client handles authentication, request retries, and connection management
    for the DocuSign Monitor and Admin APIs.
    """
    
    def __init__(self, auth: 'DocuSignAuthAsync', verify: bool, proxies: Optional[Dict[str, str]]) -> None:
        """Initialize the DocuSign client.
        
        Args:
            auth: Authenticated DocuSignAuthAsync instance
            verify: Whether to verify SSL certificates
            proxies: Optional proxy configuration
        """
        self.auth = auth
        self.http = AsyncRetryClient(verify=verify, proxies=proxies, timeout=DEFAULT_TIMEOUT, limits=DEFAULT_LIMITS)

    async def monitor_stream(
        self,
        scopes: str,
        cursor: Optional[str],
        limit: int
    ) -> Dict[str, Any]:
        """Fetch a stream of monitor events from DocuSign.
        
        Args:
            scopes: OAuth scopes required for the request
            cursor: Pagination cursor for resuming from a specific point
            limit: Maximum number of events to return per page (capped at MAX_MONITOR_PAGE_LIMIT)
            
        Returns:
            Dict containing monitor events and pagination information
            
        Raises:
            DemistoException: If there's an error fetching the monitor stream
        """
        ti = await self.auth.get_token(scopes)
        base = _monitor_base(ti.env)
        params: Dict[str, Any] = {"limit": min(limit, MAX_MONITOR_PAGE_LIMIT)}
        if cursor:
            params["cursor"] = cursor
        url = f"{base}/api/v2.0/datasets/monitor/stream"
        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"},
            params=params
        )
        return resp.json()

    async def admin_list_users(
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
        ti = await self.auth.get_token(scopes)
        if next_url:
            url = next_url
            params = None
        else:
            base = _admin_base(ti.env)
            url = f"{base}/management/v2/organizations/{organization_id}/users"
            params = {"account_id": account_id, "take": min(take, MAX_ADMIN_TAKE)}
            if start is not None:
                params["start"] = start
            if last_modified_since:
                params["last_modified_since"] = last_modified_since
        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"},
            params=params
        )
        return resp.json()

    async def esign_user_detail(
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
        ti = await self.auth.get_token(scopes)
        url = f"{account_base_uri}/restapi/v2.1/accounts/{account_id}/users/{user_id}"
        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {ti.access_token}"}
        )
        return resp.json()

    async def aclose(self) -> None:
        """Close all HTTP connections and cleanup resources.
        
        This should be called when the client is no longer needed to ensure
        proper cleanup of connections.
        """
        await self.http.aclose()
        await self.auth.http.aclose()

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
        return str(self._params.get("server_url") or 
                 self._params.get("url") or 
                 self._constants.DEFAULT_SERVER_URL)
    
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
    def account_id(self) -> Optional[str]:
        """Get the DocuSign account ID (optional)."""
        return self._params.get("account_id")
    
    @property
    def organization_id(self) -> Optional[str]:
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
        return (argToBoolean(self._params.get("isFetch", False)) or 
                argToBoolean(self._params.get("fetch_events", False)))
    
    @property
    def fetch_customer_events(self) -> bool:
        """Whether to fetch customer events."""
        event_types = self._get_event_types()
        return (self._constants.EVENT_TYPE_CUSTOMER in "".join(event_types) or 
                "customer events" in event_types)
    
    @property
    def fetch_user_data(self) -> bool:
        """Whether to fetch user data."""
        event_types = self._get_event_types()
        return (self._constants.EVENT_TYPE_USER_DATA in "".join(event_types) or 
                "user data" in event_types)
    
    @property
    def max_customer_per_fetch(self) -> int:
        """Maximum number of customer events to fetch per run."""
        return int(self._params.get("max_customer_events_per_fetch", 
                                 self._constants.DEFAULT_MAX_CUSTOMER_EVENTS))
    
    @property
    def max_user_data_per_fetch(self) -> int:
        """Maximum number of user data events to fetch per run."""
        return int(self._params.get("max_user_data_events_per_fetch",
                                 self._constants.DEFAULT_MAX_USER_DATA_EVENTS))
    
    @property
    def queue_maxsize(self) -> int:
        """Maximum size of the event queue."""
        return int(self._params.get("queue_maxsize", 
                                 self._constants.DEFAULT_QUEUE_MAXSIZE))
    
    @property
    def consumer_workers(self) -> int:
        """Number of consumer worker threads."""
        return int(self._params.get("consumer_workers", 
                                 self._constants.DEFAULT_CONSUMER_WORKERS))
    
    @property
    def send_batch_size(self) -> int:
        """Batch size for sending events."""
        return int(self._params.get("send_batch_size",
                                 self._constants.DEFAULT_SEND_BATCH_SIZE))
    
    @property
    def user_detail_concurrency(self) -> int:
        """Maximum concurrent user detail requests."""
        return int(self._params.get("user_detail_concurrency",
                                 self._constants.DEFAULT_USER_DETAIL_CONCURRENCY))
    
    @property
    def multiple_threads_send(self) -> bool:
        """Whether to use multiple threads for sending events."""
        return argToBoolean(self._params.get("multiple_threads_send", False))
    
    def _get_event_types(self) -> List[str]:
        """Get the list of event types to fetch."""
        event_types = self._params.get("events_types_to_fetch") or []
        if isinstance(event_types, str):
            event_types = [event_types]
        return [s.lower() for s in event_types]
    
    def to_dict(self) -> Dict[str, Any]:
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
            "max_user_data_per_fetch": self.max_user_data_per_fetch,
            "queue_maxsize": self.queue_maxsize,
            "consumer_workers": self.consumer_workers,
            "send_batch_size": self.send_batch_size,
            "user_detail_concurrency": self.user_detail_concurrency,
            "multiple_threads_send": self.multiple_threads_send
        }

def proxies_if_enabled(use_proxy: bool) -> Optional[Dict[str, str]]:
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

async def get_customer_events_once(
    client: DocuSignClientAsync,
    config: Config,
    cursor: Optional[str],
    limit: int
) -> Tuple[List[Dict[str, Any]], str]:
    """Fetch a single page of customer events from DocuSign.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        cursor: Pagination cursor (optional)
        limit: Maximum number of events to return
        
    Returns:
        Tuple of (events, next_cursor)
    """
    demisto.debug(f"{Constants.LOG_PREFIX} Fetching customer events page")
    
    # Get required scopes and set default cursor if not provided
    scopes = _user_scopes(True, config.fetch_user_data)
    if not cursor:
        cursor = _iso_z(_utcnow())
    
    # Fetch events from DocuSign API
    resp = await client.monitor_stream(
        scopes=scopes,
        cursor=cursor,
        limit=min(limit, Constants.MAX_MONITOR_PAGE_LIMIT)
    )
    
    # Process the response
    data = resp.get("data") or []
    next_cursor = resp.get("endCursor") or cursor
    
    # Format events with required fields
    events: List[Dict[str, Any]] = []
    for event in data[:limit]:
        if not isinstance(event, dict):
            continue
            
        # Ensure required fields are present
        event["_time"] = event.get("timestamp") or _iso_z(_utcnow())
        event["source_log_type"] = "eventdata"
        
        events.append(event)
    
    demisto.debug(
        f"{Constants.LOG_PREFIX} Fetched {len(events)} events, "
        f"next_cursor={next_cursor[:30]}..." if next_cursor else ""
    )
    
    return events, next_cursor

async def get_audit_users_once(
    client: DocuSignClientAsync,
    config: Config,
    start: Optional[int],
    take: int,
    last_modified_since: Optional[str],
    next_url: Optional[str]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
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
        f"{Constants.LOG_PREFIX} Fetching audit users: "
        f"org_id={config.organization_id}, account_id={config.account_id}, "
        f"start={start}, take={take}, last_modified_since={last_modified_since}"
    )
    
    # Get authentication token and required scopes
    scopes = _user_scopes(False, True)
    ti = await client.auth.get_token(scopes)
    base_uri = ti.base_uri or ""
    
    # Fetch users from DocuSign API
    resp = await client.admin_list_users(
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
    events: List[Dict[str, Any]] = []
    for user in users:
        if not isinstance(user, dict):
            continue
            
        # Create event with user data
        event: Dict[str, Any] = {
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
        f"{Constants.LOG_PREFIX} Fetched {len(events)} audit users, "
        f"next_page_url={next_page_url[:50]}..." if next_page_url else ""
    )
    
    return events, state

# -------------------- Producer–Consumer Pipeline --------------------

async def _async_send_to_xsiam(events: List[Dict[str, Any]], multiple_threads: bool) -> None:
    loop = asyncio.get_running_loop()
    # Offload blocking call
    await loop.run_in_executor(None, send_events_to_xsiam, events, VENDOR, PRODUCT, None, None, multiple_threads)

async def monitor_producer(
    queue: asyncio.Queue, 
    client: DocuSignClientAsync, 
    config: Config,
    ctx: Dict[str, Any], 
    state: Dict[str, Any]
) -> None:
    """Producer for customer monitor events.
    
    Fetches customer events from DocuSign in pages and adds them to the queue for processing.
    
    Args:
        queue: Queue to add events to
        client: Initialized DocuSign client
        config: Configuration object
        ctx: Integration context
        state: State dictionary to update with cursor position
    """
    # Get required scopes and initialize cursor
    scopes = _user_scopes(True, config.fetch_user_data)
    cursor = ctx.get(Constants.CTX_CUSTOMER_CURSOR) or _iso_z(_utcnow())
    total_limit = max(0, config.max_customer_per_fetch)
    produced = 0
    
    # Log producer start
    demisto.info(
        f"{Constants.LOG_PREFIX} Starting customer events producer - "
        f"cursor: {cursor}, total_limit: {total_limit}, "
        f"queue_maxsize: {config.queue_maxsize}"
    )
    
    page_count = 0
    start_time = time.time()
    
    try:
        # Fetch events in pages until we reach the limit or run out of data
        while produced < total_limit:
            page_count += 1
            page_limit = min(Constants.MAX_MONITOR_PAGE_LIMIT, total_limit - produced)
            page_start_time = time.time()
            
            demisto.debug(
                f"{Constants.LOG_PREFIX} Page {page_count}: "
                f"requesting {page_limit} events with cursor: {cursor}"
            )
            
            try:
                # Fetch a page of events
                resp = await client.monitor_stream(
                    scopes=scopes,
                    cursor=cursor,
                    limit=page_limit
                )
            except Exception as e:
                demisto.error(
                    f"{Constants.LOG_PREFIX} Failed to fetch page {page_count}: {e}"
                )
                raise
                
            # Process the response
            page_duration = time.time() - page_start_time
            data = resp.get("data") or []
            cursor = resp.get("endCursor") or cursor
            
            demisto.debug(
                f"{Constants.LOG_PREFIX} Page {page_count} fetched in {page_duration:.2f}s: "
                f"{len(data)} events, new cursor: {cursor}"
            )
            
            if not data:
                demisto.info(
                    f"{Constants.LOG_PREFIX} No more data available after {page_count} pages"
                )
                break
                
            # Process and queue events
            queue_put_count = 0
            for event in data:
                if not isinstance(event, dict):
                    continue
                    
                # Ensure required fields are present
                event["_time"] = event.get("timestamp") or _iso_z(_utcnow())
                event["source_log_type"] = "eventdata"
                
                try:
                    await queue.put(event)
                    queue_put_count += 1
                    produced += 1
                    
                    if produced >= total_limit:
                        demisto.debug(
                            f"{Constants.LOG_PREFIX} Reached total limit {total_limit}, stopping"
                        )
                        break
                except Exception as e:
                    demisto.error(
                        f"{Constants.LOG_PREFIX} Failed to put event in queue: {e}"
                    )
                    raise
                    
            demisto.debug(
                f"{Constants.LOG_PREFIX} Page {page_count}: queued {queue_put_count} events, "
                f"total produced: {produced}"
            )
            
            # Check if we've reached the end of the data
            if len(data) < page_limit:
                demisto.info(
                    f"{Constants.LOG_PREFIX} Received partial page ({len(data)} < {page_limit}), "
                    "no more data available"
                )
                break
                
    except Exception as e:
        demisto.error(
            f"{Constants.LOG_PREFIX} Error in monitor_producer: {e}"
        )
        raise
    finally:
        # Update state with the final cursor position
        state[Constants.CTX_CUSTOMER_CURSOR] = cursor
        total_duration = time.time() - start_time
        
        demisto.info(
            f"{Constants.LOG_PREFIX} Completed: {produced} events produced across "
            f"{page_count} pages in {total_duration:.2f}s, "
            f"final cursor: {cursor}"
        )

async def _bounded_gather(coros: Iterable, limit: int) -> List[Any]:
    sem = asyncio.Semaphore(limit)
    results: List[Any] = []

    async def _runner(coro):
        async with sem:
            return await coro

    for c in asyncio.as_completed([_runner(c) for c in coros]):
        results.append(await c)
    return results

async def audit_producer(
    queue: asyncio.Queue,
    client: DocuSignClientAsync,
    config: Config,
    ctx: Dict[str, Any],
    state: Dict[str, Any]
) -> None:
    """Producer for audit user data.
    
    Fetches audit users from DocuSign in pages, enriches them with additional data,
    and adds them to the queue for processing.
    
    Args:
        queue: Queue to add events to
        client: Initialized DocuSign client
        config: Configuration object
        ctx: Integration context
        state: State dictionary to update with pagination info
    """
    # Validate required parameters
    ensure_ids_for_audit(config.organization_id, config.account_id)
    
    # Initialize scopes and pagination
    scopes = _user_scopes(False, True)
    total_limit = max(0, config.max_user_data_per_fetch)
    last_modified_since = ctx.get(Constants.CTX_AUDIT_LAST_MOD_SINCE) or _iso_z(_utcnow())
    next_url = ctx.get(Constants.CTX_AUDIT_NEXT_URL) or ""
    start = None if next_url else 0
    take = min(Constants.MAX_ADMIN_TAKE, total_limit) if total_limit else Constants.MAX_ADMIN_TAKE

    # Log producer start
    demisto.info(
        f"{Constants.LOG_PREFIX} Starting user data producer - "
        f"total_limit: {total_limit}, last_modified_since: {last_modified_since}, "
        f"next_url: {next_url}, take: {take}"
    )

    try:
        # Get authentication token and base URI
        ti = await client.auth.get_token(scopes)
        base_uri = ti.base_uri or ""
        demisto.debug(f"{Constants.LOG_PREFIX} Got token, base_uri: {base_uri}")
    except Exception as e:
        demisto.error(f"{Constants.LOG_PREFIX} Failed to get authentication token: {e}")
        raise

    # Initialize counters and timers
    produced = 0
    page_count = 0
    start_time = time.time()
    total_enrichment_time = 0
    
    try:
        # Fetch users in pages until we reach the limit or run out of data
        while True:
            page_count += 1
            page_start_time = time.time()
            
            demisto.debug(
                f"{Constants.LOG_PREFIX} Page {page_count}: fetching users - "
                f"start: {start}, take: {take}, next_url: {next_url}"
            )
            
            try:
                # Fetch a page of users
                resp = await client.admin_list_users(
                    scopes=scopes,
                    organization_id=config.organization_id or "",
                    account_id=config.account_id or "",
                    start=start,
                    take=take,
                    last_modified_since=last_modified_since,
                    next_url=next_url or None
                )
            except Exception as e:
                demisto.error(
                    f"{Constants.LOG_PREFIX} Failed to fetch users on page {page_count}: {e}"
                )
                raise
                
            # Process the response
            page_fetch_duration = time.time() - page_start_time
            users = resp.get("users") or resp.get("data") or []
            paging = resp.get("paging") or {}
            next_url = paging.get("next") or resp.get("next") or ""

            demisto.debug(
                f"{Constants.LOG_PREFIX} Page {page_count}: fetched {len(users)} users in "
                f"{page_fetch_duration:.2f}s, next_url: {next_url}"
            )

        # Enrich details concurrently (bounded)
        ids = [u.get("id") or u.get("user_id") for u in users if (u.get("id") or u.get("user_id"))]
        details: List[Dict[str, Any]] = []
        
        if ids:
            enrichment_start_time = time.time()
            demisto.debug(f"[AUDIT_PRODUCER] Page {page_count}: enriching details for {len(ids)} users with concurrency {params.user_detail_concurrency}")
            
            try:
                coros = [client.esign_user_detail(scopes, base_uri, params.account_id or "", str(uid)) for uid in ids]
                details = await _bounded_gather(coros, params.user_detail_concurrency)
                enrichment_duration = time.time() - enrichment_start_time
                total_enrichment_time += enrichment_duration
                
                demisto.debug(f"[AUDIT_PRODUCER] Page {page_count}: enriched {len(details)} user details in {enrichment_duration:.2f}s")
            except Exception as e:
                demisto.error(f"[AUDIT_PRODUCER] Failed to enrich user details on page {page_count}: {e}")
                # Continue without enrichment rather than failing completely
                details = []
                
        by_id = {str(d.get("userId") or d.get("user_id") or d.get("id")): d for d in details if d}
        demisto.debug(f"[AUDIT_PRODUCER] Page {page_count}: mapped {len(by_id)} enriched user details")

        queue_put_count = 0
        for u in users:
            ev: Dict[str, Any] = {"source_log_type": "auditusers", "user": u}
            mod = u.get("modifiedDate") or ""
            ev["_time"] = mod or _iso_z(_utcnow())
            dtp = _parse_time_maybe(mod)
            if dtp:
                ev["_time_iso"] = _iso_z(dtp)
            uid = str(u.get("id") or u.get("user_id") or "")
            if uid and uid in by_id:
                ev["esign_detail"] = by_id[uid]
                
            try:
                await queue.put(ev)
                queue_put_count += 1
                produced += 1
                
                if total_limit and produced >= total_limit:
                    demisto.debug(f"[AUDIT_PRODUCER] Reached total limit {total_limit}, stopping")
                    break
            except Exception as e:
                demisto.error(f"[AUDIT_PRODUCER] Failed to put user event in queue: {e}")
                raise

        demisto.debug(f"[AUDIT_PRODUCER] Page {page_count}: queued {queue_put_count} user events, total produced: {produced}")

        if total_limit and produced >= total_limit:
            demisto.info(f"[AUDIT_PRODUCER] Reached total limit {total_limit} after {page_count} pages")
            break
        if not next_url:
            last_modified_since = _iso_z(_utcnow())
            demisto.info(f"[AUDIT_PRODUCER] No more pages available, updated last_modified_since: {last_modified_since}")
            break
        start = None  # when next_url provided, server drives paging

    total_duration = time.time() - start_time
    state[CTX_AUDIT_NEXT_URL] = next_url
    state[CTX_AUDIT_LAST_MOD_SINCE] = last_modified_since
    
    demisto.info(f"[AUDIT_PRODUCER] Completed: {produced} user events produced across {page_count} pages in {total_duration:.2f}s (enrichment: {total_enrichment_time:.2f}s), final next_url: {next_url}, last_modified_since: {last_modified_since}")

async def consumer_worker(
    name: str, 
    queue: asyncio.Queue, 
    config: Config
) -> None:
    """Consumer worker that processes events from the queue and sends them to XSIAM.
    
    Args:
        name: Worker name for logging
        queue: Queue to consume events from
        config: Configuration object
    """
    batch: List[Dict[str, Any]] = []
    total_processed = 0
    total_batches_sent = 0
    start_time = time.time()
    
    # Get configuration values
    batch_size = config.send_batch_size
    multiple_threads_send = config.multiple_threads_send
    
    demisto.info(
        f"{Constants.LOG_PREFIX} [{name}] Starting consumer worker - "
        f"batch_size: {batch_size}, multiple_threads_send: {multiple_threads_send}"
    )
    
    try:
        while True:
            try:
                # Get an item from the queue with a timeout
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Check for shutdown condition
                    if queue.empty() and queue._unfinished_tasks == 0:  # type: ignore
                        demisto.debug(f"{Constants.LOG_PREFIX} [{name}] Queue empty and no tasks remaining, shutting down")
                        break
                    continue
                    
                # Check for shutdown signal
                if item is None:
                    demisto.info(f"{Constants.LOG_PREFIX} [{name}] Received shutdown signal")
                    break
                    
                # Add item to batch
                if isinstance(item, dict):
                    batch.append(item)
                    total_processed += 1
                    
                    # Log batch status periodically
                    if total_processed % 10 == 0:
                        demisto.debug(
                            f"{Constants.LOG_PREFIX} [{name}] Added event to batch "
                            f"(batch size: {len(batch)}/{batch_size}, "
                            f"queue size: {queue.qsize()}, "
                            f"total processed: {total_processed})"
                        )
                    
                    # Send batch if we've reached the batch size
                    if len(batch) >= batch_size:
                        await _process_batch(
                            name=name,
                            batch=batch,
                            batch_number=total_batches_sent + 1,
                            multiple_threads_send=multiple_threads_send
                        )
                        total_batches_sent += 1
                        batch = []
                
                # Mark task as done
                queue.task_done()
                
            except Exception as e:
                demisto.error(f"{Constants.LOG_PREFIX} [{name}] Error processing item: {e}")
                # Continue processing next item even if one fails
                continue
                
        # Send any remaining events in the final batch
        if batch:
            await _process_batch(
                name=name,
                batch=batch,
                batch_number=total_batches_sent + 1,
                multiple_threads_send=multiple_threads_send,
                is_final=True
            )
            total_batches_sent += 1
            
    except Exception as e:
        demisto.error(f"{Constants.LOG_PREFIX} [{name}] Fatal error in consumer worker: {e}")
        raise
        
    finally:
        # Log completion metrics
        total_duration = time.time() - start_time
        events_per_sec = total_processed / total_duration if total_duration > 0 else 0
        
        demisto.info(
            f"{Constants.LOG_PREFIX} [{name}] Completed: Processed {total_processed} events "
            f"in {total_batches_sent} batches in {total_duration:.2f}s "
            f"({events_per_sec:.2f} events/sec)"
        )

async def _process_batch(
    name: str,
    batch: List[Dict[str, Any]],
    batch_number: int,
    multiple_threads_send: bool,
    is_final: bool = False
) -> None:
    """Process a batch of events and send them to XSIAM.
    
    Args:
        name: Worker name for logging
        batch: Batch of events to process
        batch_number: Batch number for logging
        multiple_threads_send: Whether to use multiple threads for sending
        is_final: Whether this is the final batch
    """
    batch_start_time = time.time()
    batch_type = "final" if is_final else str(batch_number)
    
    demisto.info(
        f"{Constants.LOG_PREFIX} [{name}] Sending {batch_type} batch of {len(batch)} events"
    )
    
    try:
        await _async_send_to_xsiam(batch, multiple_threads_send)
        batch_duration = time.time() - batch_start_time
        
        demisto.debug(
            f"{Constants.LOG_PREFIX} [{name}] Successfully sent {batch_type} batch "
            f"in {batch_duration:.2f}s ({len(batch) / batch_duration:.2f} events/sec)"
        )
        
    except Exception as e:
        batch_duration = time.time() - batch_start_time
        demisto.error(
            f"{Constants.LOG_PREFIX} [{name}] Failed to send {batch_type} batch "
            f"after {batch_duration:.2f}s: {e}"
        )
        raise

async def run_pipeline(client: DocuSignClientAsync, params: Params) -> None:
    if not params.fetch_events:
        demisto.info("[PIPELINE] Fetch events disabled, skipping pipeline")
        return

    demisto.info("[PIPELINE] Starting producer-consumer pipeline")
    pipeline_start_time = time.time()

    full_ctx = get_integration_context() or {}
    dctx: Dict[str, Any] = full_ctx.get(CTX_KEY, {})
    # Ensure dctx is a dictionary, not a string or other type
    if not isinstance(dctx, dict):
        demisto.warning("[PIPELINE] Integration context data was not a dict, resetting to empty dict")
        dctx = {}
    state_updates: Dict[str, Any] = {}

    demisto.debug(f"[PIPELINE] Loaded integration context - customer_cursor: {dctx.get(CTX_CUSTOMER_CURSOR)}, audit_next_url: {dctx.get(CTX_AUDIT_NEXT_URL)}, audit_last_modified_since: {dctx.get(CTX_AUDIT_LAST_MOD_SINCE)}")

    queue: asyncio.Queue = asyncio.Queue(maxsize=params.queue_maxsize)
    demisto.info(f"[PIPELINE] Created queue with maxsize: {params.queue_maxsize}")
    
    # Create consumer tasks
    consumer_tasks = [
        asyncio.create_task(consumer_worker(f"consumer-{i}", queue, params.send_batch_size, params.multiple_threads_send))
        for i in range(params.consumer_workers)
    ]
    demisto.info(f"[PIPELINE] Started {len(consumer_tasks)} consumer workers with batch_size: {params.send_batch_size}")
    
    producers: List[asyncio.Task] = []

    # Start producers based on configuration
    if params.fetch_customer_events:
        producer_task = asyncio.create_task(monitor_producer(queue, client, params, dctx, state_updates))
        producers.append(producer_task)
        demisto.info("[PIPELINE] Started monitor producer for customer events")
        
    if params.fetch_user_data:
        producer_task = asyncio.create_task(audit_producer(queue, client, params, dctx, state_updates))
        producers.append(producer_task)
        demisto.info("[PIPELINE] Started audit producer for user data")

    if not producers:
        demisto.warning("[PIPELINE] No producers configured, shutting down consumers")
        # signal consumers to stop immediately
        for _ in consumer_tasks:
            await queue.put(None)
        await asyncio.gather(*consumer_tasks)
        return

    demisto.info(f"[PIPELINE] Running {len(producers)} producers and {len(consumer_tasks)} consumers")
    
    try:
        # Wait for all producers to complete
        producer_start_time = time.time()
        await asyncio.gather(*producers)
        producer_duration = time.time() - producer_start_time
        demisto.info(f"[PIPELINE] All producers completed in {producer_duration:.2f}s")
        
        # Check final queue size before shutdown
        queue_size = queue.qsize()
        if queue_size > 0:
            demisto.info(f"[PIPELINE] Queue has {queue_size} events remaining, waiting for consumers to process")
        else:
            demisto.debug("[PIPELINE] Queue is empty, proceeding with consumer shutdown")
            
    except Exception as e:
        demisto.error(f"[PIPELINE] Producer error occurred: {e}")
        raise
    finally:
        # signal consumers to stop
        consumer_shutdown_start = time.time()
        demisto.debug(f"[PIPELINE] Sending shutdown signals to {len(consumer_tasks)} consumers")
        
        for i in range(len(consumer_tasks)):
            await queue.put(None)
            demisto.debug(f"[PIPELINE] Sent shutdown signal to consumer {i}")
            
        # Wait for all consumers to finish
        try:
            await asyncio.gather(*consumer_tasks)
            consumer_shutdown_duration = time.time() - consumer_shutdown_start
            demisto.info(f"[PIPELINE] All consumers shut down gracefully in {consumer_shutdown_duration:.2f}s")
        except Exception as e:
            demisto.error(f"[PIPELINE] Error during consumer shutdown: {e}")
            raise

    # persist state
    context_save_start = time.time()
    try:
        dctx.update(state_updates)
        set_to_integration_context_with_retries({CTX_KEY: dctx})
        context_save_duration = time.time() - context_save_start
        demisto.debug(f"[PIPELINE] Saved integration context in {context_save_duration:.2f}s - updates: {list(state_updates.keys())}")
    except Exception as e:
        demisto.error(f"[PIPELINE] Failed to save integration context: {e}")
        raise
        
    pipeline_duration = time.time() - pipeline_start_time
    demisto.info(f"[PIPELINE] Pipeline completed successfully in {pipeline_duration:.2f}s")

# -------------------- Commands --------------------

def command_generate_consent_url(config: Config) -> CommandResults:
    """Generate a consent URL for DocuSign OAuth flow.
    
    Args:
        config: Configuration object
        
    Returns:
        CommandResults: Results to return to Demisto
    """
    scopes = _user_scopes(config.fetch_customer_events, config.fetch_user_data)
    url = build_consent_url(
        config.server_url,
        config.integration_key,
        config.redirect_uri,
        scopes
    )
    
    # Format markdown output
    md = f"### DocuSign Consent URL\n[Click here to authorize]({url})"
    
    return CommandResults(
        readable_output=md,
        outputs={"ConsentURL": url},
        outputs_prefix="Docusign"
    )

async def command_test_module_async(client: DocuSignClientAsync, config: Config) -> str:
    """Test the integration configuration and authentication.
    
    Args:
        client: Initialized DocuSign client
        config: Configuration object
        
    Returns:
        str: 'ok' if test succeeds
        
    Raises:
        DemistoException: If test fails
    """
    demisto.debug(f"{Constants.LOG_PREFIX} Testing module configuration")
    
    # Test authentication
    scopes = _user_scopes(config.fetch_customer_events, config.fetch_user_data)
    ti = await client.auth.get_token(scopes)
    
    if not ti.access_token or not ti.base_uri:
        raise DemistoException("Authentication failed: No access token or base URI received")
        
    demisto.debug(f"{Constants.LOG_PREFIX} Test completed successfully")
    return "ok"

async def command_get_customer_events_async(
    client: DocuSignClientAsync, 
    config: Config, 
    args: Dict[str, Any]
) -> CommandResults:
    """Fetch customer events from DocuSign.
    
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
        Constants.MAX_MONITOR_PAGE_LIMIT
    )
    cursor = args.get("cursor")
    
    demisto.debug(
        f"{Constants.LOG_PREFIX} Fetching customer events: "
        f"limit={limit}, cursor={cursor}"
    )
    
    # Fetch events
    events, next_cursor = await get_customer_events_once(client, config, cursor, limit)
    
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

async def command_get_audit_users_async(
    client: DocuSignClientAsync, 
    config: Config, 
    args: Dict[str, Any]
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
        f"{Constants.LOG_PREFIX} Fetching audit users: "
        f"start={start}, take={take}, last_modified_since={last_modified_since}"
    )
    
    # Fetch audit users
    events, state = await get_audit_users_once(
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

def run_async(coro):
    # XSOAR executes sync entrypoints; wrap async with asyncio.run
    return asyncio.run(coro)

# -------------------- Main --------------------

def main() -> None:
    """Main entry point for the integration."""
    try:
        # Initialize configuration
        config = Config()
        
        # Set up logging
        demisto.debug(f"{Constants.LOG_PREFIX} Starting with config: {config.to_dict()}")
        
        # Set up HTTP client with proxy if enabled
        proxies = proxies_if_enabled(config.use_proxy)
        
        # Initialize authentication and API client
        auth = DocuSignAuthAsync(
            server_url=config.server_url,
            integration_key=config.integration_key,
            user_id=config.user_id,
            private_key_pem=config.private_key_pem,
            verify=config.verify_ssl,
            proxies=proxies,
        )
        client = DocuSignClientAsync(
            auth=auth,
            verify=config.verify_ssl,
            proxies=proxies
        )
        
        # Get command and arguments
        cmd = demisto.command()
        args = demisto.args()
        
        demisto.debug(f"{Constants.LOG_PREFIX} Processing command: {cmd}")
        
        # Route command to appropriate handler
        if cmd == "test-module":
            res = run_async(command_test_module_async(client, config))
            return_results(res)
            
        elif cmd == "docusign-generate-consent-url":
            return_results(command_generate_consent_url(config))
            
        elif cmd == "docusign-get-customer-events":
            res = run_async(command_get_customer_events_async(client, config, args))
            return_results(res)
            
        elif cmd == "docusign-get-audit-users":
            res = run_async(command_get_audit_users_async(client, config, args))
            return_results(res)
            
        elif cmd == "fetch-events":
            run_async(run_pipeline(client, config))
            
        else:
            raise DemistoException(f"Command '{cmd}' is not implemented.")
            
    except Exception as e:
        error_msg = f"{Constants.LOG_PREFIX} Error in {Constants.INTEGRATION_NAME} integration: {str(e)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)
        
    finally:
        # Ensure resources are properly cleaned up
        try:
            if 'client' in locals():
                run_async(client.aclose())
        except Exception as e:
            demisto.error(f"{Constants.LOG_PREFIX} Error during cleanup: {str(e)}")

if __name__ in ("__main__", "builtin", "builtins"):
    main()
