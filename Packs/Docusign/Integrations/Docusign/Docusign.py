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

INTEGRATION_NAME = "Docusign"
VENDOR = "docusign"
PRODUCT = "docusign"

TOKEN_SKEW_SECONDS = 60
DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=60.0, write=60.0, connect=10.0)
DEFAULT_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=100)

RETRY_MAX = 5
RETRY_BASE_SLEEP = 1.5
RETRY_MAX_SLEEP = 20.0

MAX_MONITOR_PAGE_LIMIT = 2000
MAX_ADMIN_TAKE = 250
DEFAULT_USER_DETAIL_CONCURRENCY = 12

# Integration context keys
CTX_KEY = "docusign_ctx"
CTX_TOKEN_CACHE = "token_cache"                  # {access_token, expires_at, env, base_uri}
CTX_CUSTOMER_CURSOR = "customer_cursor"
CTX_AUDIT_NEXT_URL = "audit_next_url"
CTX_AUDIT_LAST_MOD_SINCE = "audit_last_modified_since"

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
    def __init__(self, *, verify: bool, proxies: Optional[Dict[str, str]], timeout: httpx.Timeout, limits: httpx.Limits):
        self.client = httpx.AsyncClient(verify=verify, proxies=proxies, timeout=timeout, limits=limits)

    async def request(self, method: str, url: str, *,
                      headers: Optional[Dict[str, str]] = None,
                      params: Optional[Dict[str, Any]] = None,
                      data: Any = None, json: Any = None,
                      allow_status: Iterable[int] = ()) -> httpx.Response:
        attempt = 0
        backoff = RETRY_BASE_SLEEP
        while True:
            attempt += 1
            try:
                resp = await self.client.request(method, url, headers=headers, params=params, data=data, json=json)
                if resp.status_code in allow_status or 200 <= resp.status_code < 300:
                    return resp

                if resp.status_code in (408, 429) or 500 <= resp.status_code < 600:
                    if attempt >= RETRY_MAX:
                        resp.raise_for_status()
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        sleep_s = float(retry_after)
                    else:
                        sleep_s = min(backoff, RETRY_MAX_SLEEP)
                    demisto.debug(f"[Docusign] Retryable HTTP {resp.status_code} {url}; sleep {sleep_s}s (attempt {attempt}/{RETRY_MAX})")
                    await asyncio.sleep(sleep_s)
                    backoff *= 2.0
                    continue

                resp.raise_for_status()
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                if attempt >= RETRY_MAX:
                    raise
                sleep_s = min(backoff, RETRY_MAX_SLEEP)
                demisto.debug(f"[Docusign] Network error {type(e).__name__}: {e}; sleep {sleep_s}s (attempt {attempt}/{RETRY_MAX})")
                await asyncio.sleep(sleep_s)
                backoff *= 2.0

    async def aclose(self) -> None:
        await self.client.aclose()

# -------------------- Auth --------------------

@dataclass
class TokenInfo:
    access_token: str
    expires_at: int
    env: str
    base_uri: Optional[str] = None

class DocuSignAuthAsync:
    def __init__(self, server_url: str, integration_key: str, user_id: str, private_key_pem: str,
                 verify: bool, proxies: Optional[Dict[str, str]]):
        self.server_url = _oauth_base(server_url)
        self.env = _env_from_server_url(server_url)
        self.integration_key = integration_key
        self.user_id = user_id
        self.private_key_pem = private_key_pem
        self.http = AsyncRetryClient(verify=verify, proxies=proxies, timeout=DEFAULT_TIMEOUT, limits=DEFAULT_LIMITS)

    def _jwt(self, scopes: str) -> str:
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
        url = f"{self.server_url}/oauth/token"
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        resp = await self.http.request("POST", url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data)
        js = resp.json()
        access_token = js.get("access_token")
        expires_in = int(js.get("expires_in", 3600))
        if not access_token:
            raise DemistoException("DocuSign: Token exchange failed (no access_token).")
        expires_at = int(time.time()) + max(1, expires_in - TOKEN_SKEW_SECONDS)
        return TokenInfo(access_token=access_token, expires_at=expires_at, env=self.env)

    async def _userinfo(self, token: str) -> str:
        url = f"{self.server_url}/oauth/userinfo"
        resp = await self.http.request("GET", url, headers={"Authorization": f"Bearer {token}"})
        js = resp.json()
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
        ctx = get_integration_context() or {}
        dctx = ctx.get(CTX_KEY, {})
        cache = dctx.get(CTX_TOKEN_CACHE) or {}
        now = int(time.time())

        if cache and cache.get("access_token") and cache.get("expires_at", 0) > now and cache.get("env") == self.env:
            ti = TokenInfo(
                access_token=cache["access_token"],
                expires_at=int(cache["expires_at"]),
                env=cache["env"],
                base_uri=cache.get("base_uri") or None,
            )
        else:
            assertion = self._jwt(scopes)
            ti = await self._exchange(assertion)

        if not ti.base_uri:
            ti.base_uri = await self._userinfo(ti.access_token)

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
    def __init__(self, auth: DocuSignAuthAsync, verify: bool, proxies: Optional[Dict[str, str]]):
        self.auth = auth
        self.http = AsyncRetryClient(verify=verify, proxies=proxies, timeout=DEFAULT_TIMEOUT, limits=DEFAULT_LIMITS)

    async def monitor_stream(self, scopes: str, cursor: Optional[str], limit: int) -> Dict[str, Any]:
        ti = await self.auth.get_token(scopes)
        base = _monitor_base(ti.env)
        params: Dict[str, Any] = {"limit": min(limit, MAX_MONITOR_PAGE_LIMIT)}
        if cursor:
            params["cursor"] = cursor
        url = f"{base}/api/v2.0/datasets/monitor/stream"
        resp = await self.http.request("GET", url, headers={"Authorization": f"Bearer {ti.access_token}"}, params=params)
        return resp.json()

    async def admin_list_users(self, scopes: str, organization_id: str, account_id: str,
                               start: Optional[int], take: int, last_modified_since: Optional[str],
                               next_url: Optional[str]) -> Dict[str, Any]:
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
        resp = await self.http.request("GET", url, headers={"Authorization": f"Bearer {ti.access_token}"}, params=params)
        return resp.json()

    async def esign_user_detail(self, scopes: str, account_base_uri: str, account_id: str, user_id: str) -> Dict[str, Any]:
        ti = await self.auth.get_token(scopes)
        url = f"{account_base_uri}/restapi/v2.1/accounts/{account_id}/users/{user_id}"
        resp = await self.http.request("GET", url, headers={"Authorization": f"Bearer {ti.access_token}"})
        return resp.json()

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.auth.http.aclose()

# -------------------- Params --------------------

@dataclass
class Params:
    server_url: str
    integration_key: str
    user_id: str
    redirect_uri: str
    private_key_pem: str
    account_id: Optional[str]
    organization_id: Optional[str]
    verify: bool
    proxy: bool
    fetch_events: bool
    fetch_customer_events: bool
    fetch_user_data: bool
    max_customer_per_fetch: int
    max_user_data_per_fetch: int
    queue_maxsize: int
    consumer_workers: int
    send_batch_size: int
    user_detail_concurrency: int
    multiple_threads_send: bool

def load_params() -> Params:
    p = demisto.params()
    event_types = p.get("events_types_to_fetch") or []
    if isinstance(event_types, str):
        event_types = [event_types]
    event_types = [s.lower() for s in event_types]

    return Params(
        server_url=str(p.get("server_url") or p.get("url") or "https://account-d.docusign.com"),
        integration_key=str(p.get("integration_key") or ""),
        user_id=str(p.get("user_id") or ""),
        redirect_uri=str(p.get("redirect_url") or ""),
        private_key_pem=str(p.get("private_key") or ""),
        account_id=(p.get("account_id") or None),
        organization_id=(p.get("organization_id") or None),
        verify=not argToBoolean(p.get("insecure", False)),
        proxy=argToBoolean(p.get("proxy", False)),
        fetch_events=argToBoolean(p.get("isFetch", p.get("fetch_events", False))),
        fetch_customer_events=("customer" in "".join(event_types)) or ("customer events" in event_types),
        fetch_user_data=("user" in "".join(event_types)) or ("user data" in event_types),
        max_customer_per_fetch=int(p.get("max_customer_events_per_fetch", 10000)),
        max_user_data_per_fetch=int(p.get("max_user_data_events_per_fetch", 1250)),
        queue_maxsize=int(p.get("queue_maxsize", 2000)),
        consumer_workers=int(p.get("consumer_workers", 3)),
        send_batch_size=int(p.get("send_batch_size", 1000)),
        user_detail_concurrency=int(p.get("user_detail_concurrency", DEFAULT_USER_DETAIL_CONCURRENCY)),
        multiple_threads_send=argToBoolean(p.get("multiple_threads_send", False)),
    )

def proxies_if_enabled(use_proxy: bool) -> Optional[Dict[str, str]]:
    return handle_proxy() if use_proxy else None  # type: ignore[name-defined]

def ensure_ids_for_audit(params: Params) -> None:
    if not params.organization_id or not params.account_id:
        raise DemistoException("Admin API (audit users) requires both Organization ID and Account ID.")

# -------------------- Single-shot command helpers --------------------

async def get_customer_events_once(client: DocuSignClientAsync, params: Params, cursor: Optional[str], limit: int) -> Tuple[List[Dict[str, Any]], str]:
    scopes = _user_scopes(True, params.fetch_user_data)
    if not cursor:
        cursor = _iso_z(_utcnow())
    resp = await client.monitor_stream(scopes, cursor, limit)
    data = resp.get("data") or []
    next_cursor = resp.get("endCursor") or cursor
    events: List[Dict[str, Any]] = []
    for ev in data[:limit]:
        ev["_time"] = ev.get("timestamp") or _iso_z(_utcnow())
        ev["source_log_type"] = "eventdata"
        events.append(ev)
    return events, next_cursor

async def get_audit_users_once(client: DocuSignClientAsync, params: Params, start: Optional[int], take: int,
                               last_modified_since: Optional[str], next_url: Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    ensure_ids_for_audit(params)
    scopes = _user_scopes(False, True)
    ti = await client.auth.get_token(scopes)
    base_uri = ti.base_uri or ""
    resp = await client.admin_list_users(scopes, params.organization_id or "", params.account_id or "",
                                         start, take, last_modified_since, next_url)
    users = resp.get("users") or resp.get("data") or []
    paging = resp.get("paging") or {}
    nxt = paging.get("next") or resp.get("next")
    # No enrichment for single-shot; keep it light.
    events: List[Dict[str, Any]] = []
    for u in users:
        ev: Dict[str, Any] = {"source_log_type": "auditusers", "user": u}
        mod = u.get("modifiedDate") or ""
        ev["_time"] = mod
        dtp = _parse_time_maybe(mod)
        if dtp:
            ev["_time_iso"] = _iso_z(dtp)
        events.append(ev)
    state = {CTX_AUDIT_NEXT_URL: nxt or "", CTX_AUDIT_LAST_MOD_SINCE: last_modified_since or _iso_z(_utcnow()), "base_uri": base_uri}
    return events, state

# -------------------- Producer–Consumer Pipeline --------------------

async def _async_send_to_xsiam(events: List[Dict[str, Any]], multiple_threads: bool) -> None:
    loop = asyncio.get_running_loop()
    # Offload blocking call
    await loop.run_in_executor(None, send_events_to_xsiam, events, VENDOR, PRODUCT, None, None, multiple_threads)

async def monitor_producer(queue: asyncio.Queue, client: DocuSignClientAsync, params: Params,
                           ctx: Dict[str, Any], state: Dict[str, Any]) -> None:
    scopes = _user_scopes(True, params.fetch_user_data)
    cursor = ctx.get(CTX_CUSTOMER_CURSOR) or _iso_z(_utcnow())
    total_limit = max(0, params.max_customer_per_fetch)
    produced = 0
    while produced < total_limit:
        page_limit = min(MAX_MONITOR_PAGE_LIMIT, total_limit - produced)
        resp = await client.monitor_stream(scopes, cursor, page_limit)
        data = resp.get("data") or []
        cursor = resp.get("endCursor") or cursor
        if not data:
            break
        for ev in data:
            ev["_time"] = ev.get("timestamp") or _iso_z(_utcnow())
            ev["source_log_type"] = "eventdata"
            await queue.put(ev)
            produced += 1
            if produced >= total_limit:
                break
        if len(data) < page_limit:
            break
    state[CTX_CUSTOMER_CURSOR] = cursor

async def _bounded_gather(coros: Iterable, limit: int) -> List[Any]:
    sem = asyncio.Semaphore(limit)
    results: List[Any] = []

    async def _runner(coro):
        async with sem:
            return await coro

    for c in asyncio.as_completed([_runner(c) for c in coros]):
        results.append(await c)
    return results

async def audit_producer(queue: asyncio.Queue, client: DocuSignClientAsync, params: Params,
                         ctx: Dict[str, Any], state: Dict[str, Any]) -> None:
    ensure_ids_for_audit(params)
    scopes = _user_scopes(False, True)
    total_limit = max(0, params.max_user_data_per_fetch)
    last_modified_since = ctx.get(CTX_AUDIT_LAST_MOD_SINCE) or _iso_z(_utcnow())
    next_url = ctx.get(CTX_AUDIT_NEXT_URL) or ""
    start = None if next_url else 0
    take = min(MAX_ADMIN_TAKE, total_limit) if total_limit else MAX_ADMIN_TAKE

    ti = await client.auth.get_token(scopes)
    base_uri = ti.base_uri or ""

    produced = 0
    while True:
        resp = await client.admin_list_users(scopes, params.organization_id or "", params.account_id or "",
                                             start, take, last_modified_since, next_url or None)
        users = resp.get("users") or resp.get("data") or []
        paging = resp.get("paging") or {}
        next_url = paging.get("next") or resp.get("next") or ""

        # Enrich details concurrently (bounded)
        ids = [u.get("id") or u.get("user_id") for u in users if (u.get("id") or u.get("user_id"))]
        details: List[Dict[str, Any]] = []
        if ids:
            coros = [client.esign_user_detail(scopes, base_uri, params.account_id or "", str(uid)) for uid in ids]
            details = await _bounded_gather(coros, params.user_detail_concurrency)
        by_id = {str(d.get("userId") or d.get("user_id") or d.get("id")): d for d in details if d}

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
            await queue.put(ev)
            produced += 1
            if total_limit and produced >= total_limit:
                break

        if total_limit and produced >= total_limit:
            break
        if not next_url:
            last_modified_since = _iso_z(_utcnow())
            break
        start = None  # when next_url provided, server drives paging

    state[CTX_AUDIT_NEXT_URL] = next_url
    state[CTX_AUDIT_LAST_MOD_SINCE] = last_modified_since

async def consumer_worker(name: str, queue: asyncio.Queue, batch_size: int, multiple_threads_send: bool) -> None:
    batch: List[Dict[str, Any]] = []
    while True:
        item = await queue.get()
        if item is None:
            break
        batch.append(item)
        if len(batch) >= batch_size:
            await _async_send_to_xsiam(batch, multiple_threads_send)
            batch.clear()
    if batch:
        await _async_send_to_xsiam(batch, multiple_threads_send)

async def run_pipeline(client: DocuSignClientAsync, params: Params) -> None:
    if not params.fetch_events:
        return

    full_ctx = get_integration_context() or {}
    dctx: Dict[str, Any] = full_ctx.get(CTX_KEY, {})
    state_updates: Dict[str, Any] = {}

    queue: asyncio.Queue = asyncio.Queue(maxsize=params.queue_maxsize)
    consumer_tasks = [
        asyncio.create_task(consumer_worker(f"consumer-{i}", queue, params.send_batch_size, params.multiple_threads_send))
        for i in range(params.consumer_workers)
    ]
    producers: List[asyncio.Task] = []

    if params.fetch_customer_events:
        producers.append(asyncio.create_task(monitor_producer(queue, client, params, dctx, state_updates)))
    if params.fetch_user_data:
        producers.append(asyncio.create_task(audit_producer(queue, client, params, dctx, state_updates)))

    if not producers:
        return

    await asyncio.gather(*producers)

    # signal consumers to stop
    for _ in consumer_tasks:
        await queue.put(None)
    await asyncio.gather(*consumer_tasks)

    # persist state
    dctx.update(state_updates)
    set_to_integration_context_with_retries({CTX_KEY: dctx})

# -------------------- Commands --------------------

def command_generate_consent_url(params: Params) -> CommandResults:
    scopes = _user_scopes(params.fetch_customer_events, params.fetch_user_data)
    url = build_consent_url(params.server_url, params.integration_key, params.redirect_uri, scopes)
    md = f"### DocuSign Consent URL\n[{url}]({url})"
    return CommandResults(readable_output=md, outputs={"ConsentURL": url}, outputs_prefix="Docusign")

async def command_test_module_async(client: DocuSignClientAsync, params: Params) -> str:
    scopes = _user_scopes(params.fetch_customer_events, params.fetch_user_data)
    ti = await client.auth.get_token(scopes)
    if not ti.access_token or not ti.base_uri:
        raise DemistoException("Authentication failed.")
    return "ok"

async def command_get_customer_events_async(client: DocuSignClientAsync, params: Params, args: Dict[str, Any]) -> CommandResults:
    limit = int(args.get("limit", min(MAX_MONITOR_PAGE_LIMIT, params.max_customer_per_fetch)))
    cursor = args.get("cursor")
    events, next_cursor = await get_customer_events_once(client, params, cursor, limit)
    return CommandResults(
        readable_output=f"Fetched {len(events)} customer events. Next cursor: {next_cursor}",
        raw_response={"events": events, "next_cursor": next_cursor},
        outputs_prefix="Docusign.CustomerEvents",
        outputs={"Events": events, "NextCursor": next_cursor},
    )

async def command_get_audit_users_async(client: DocuSignClientAsync, params: Params, args: Dict[str, Any]) -> CommandResults:
    ensure_ids_for_audit(params)
    start = int(args.get("start", 0)) if not args.get("next") else None
    take = min(int(args.get("take", MAX_ADMIN_TAKE)), MAX_ADMIN_TAKE)
    last_modified_since = args.get("last_modified_since") or _iso_z(_utcnow())
    next_url = args.get("next") or None
    events, state = await get_audit_users_once(client, params, start, take, last_modified_since, next_url)
    return CommandResults(
        readable_output=f"Fetched {len(events)} audit user records. Next: {state.get(CTX_AUDIT_NEXT_URL, '')}",
        raw_response={"events": events, "state": state},
        outputs_prefix="Docusign.AuditUsers",
        outputs={"Events": events, "State": state},
    )

def run_async(coro):
    # XSOAR executes sync entrypoints; wrap async with asyncio.run
    return asyncio.run(coro)

# -------------------- Main --------------------

def main() -> None:
    params = load_params()
    proxies = proxies_if_enabled(params.proxy)
    auth = DocuSignAuthAsync(
        server_url=params.server_url,
        integration_key=params.integration_key,
        user_id=params.user_id,
        private_key_pem=params.private_key_pem,
        verify=params.verify,
        proxies=proxies,
    )
    client = DocuSignClientAsync(auth=auth, verify=params.verify, proxies=proxies)

    try:
        cmd = demisto.command()
        args = demisto.args()

        if cmd == "test-module":
            res = run_async(command_test_module_async(client, params))
            return_results(res)

        elif cmd == "docusign-generate-consent-url":
            return_results(command_generate_consent_url(params))

        elif cmd == "docusign-get-customer-events":
            res = run_async(command_get_customer_events_async(client, params, args))
            return_results(res)

        elif cmd == "docusign-get-audit-users":
            res = run_async(command_get_audit_users_async(client, params, args))
            return_results(res)

        elif cmd == "fetch-events":
            run_async(run_pipeline(client, params))

        else:
            raise DemistoException(f"Command '{cmd}' is not implemented.")

    except Exception as e:
        err = f"[Docusign] Error in {INTEGRATION_NAME} integration: {e}"
        demisto.error(err)
        return_error(err)
    finally:
        # Ensure clients close sockets
        try:
            run_async(client.aclose())
        except Exception:
            pass

if __name__ in ("__main__", "builtin", "builtins"):
    main()
