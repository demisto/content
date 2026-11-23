"""tLab Anti-APT Verdicts integration for Cortex XSOAR.

Pulls finished sandbox analyses out of tLab Anti-APT and turns them into
incidents.

This is the PULL half of a two-sided integration. The Go connector shipped
alongside this pack is the PUSH half, and the two are mutually exclusive by
design: enabling both produces two incidents for every analysis. The incident
they build is defined by docs/verdict-incident-schema.json and must stay
identical on both paths, down to the incident name, because an analyst
comparing a pushed and a pulled incident for the same report should not be
able to tell which half made it.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import json
import re
import traceback
from datetime import datetime, timedelta, UTC
from typing import Any
import base64
import contextlib
import hashlib
import time
import urllib.parse
import dateparser
import requests


# ---------------------------------------------------------------------------
# Shared tLab Anti-APT client. Identical in all four tLab Anti-APT
# integrations (Sandbox, Lookup, Feed, Verdicts): change all four together.
# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Verdict vocabulary
# --------------------------------------------------------------------------
# tlab-server returns TWO different verdict enumerations on the same payload:
#
#   SampleReportShortBean.verdict -> ScoreLevel
#       UNKNOWN(0) SUSPICIOUS(1) MALICIOUS(2) OK(3) CLEAN(4) WHITELIST(5)
#   FileDto.fileVerdict           -> FileVerdict
#       UNKNOWN(0) SUSPICIOUS(1) MALWARE(3) OK(4) WHITELIST(5)   <- 2 unused
#
# MALICIOUS and MALWARE mean the same thing. CLEAN and OK do not: ScoreLevel
# separates "score == 0" (CLEAN) from "0 < score < 50" (OK). Never map by the
# numeric code, because FileVerdict skips 2.

VERDICT_MALWARE = "MALWARE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_OK = "OK"
VERDICT_CLEAN = "CLEAN"
VERDICT_WHITELIST = "WHITELIST"
VERDICT_UNKNOWN = "UNKNOWN"

_VERDICT_ALIASES = {
    "MALWARE": VERDICT_MALWARE,
    "MALICIOUS": VERDICT_MALWARE,
    "SUSPICIOUS": VERDICT_SUSPICIOUS,
    "OK": VERDICT_OK,
    "CLEAN": VERDICT_CLEAN,
    "WHITELIST": VERDICT_WHITELIST,
    "WHITELISTED": VERDICT_WHITELIST,
    "UNKNOWN": VERDICT_UNKNOWN,
}

# Verdicts on which a decision can be made without waiting for COMPLETE.
# UNKNOWN is excluded: it means "keep polling".
ACTIONABLE_VERDICTS = {
    VERDICT_MALWARE,
    VERDICT_SUSPICIOUS,
    VERDICT_OK,
    VERDICT_CLEAN,
    VERDICT_WHITELIST,
}

# Defaults mirror ScoreLevel.fromSampleScore on the server
# (analysisService.minMaliciousScore=85).
DEFAULT_SUSPICIOUS_FROM = 50.0
DEFAULT_MALICIOUS_FROM = 85.0

# Default of the "Late completion lookback (hours)" parameter in the yml files.
DEFAULT_LOOKBACK_HOURS = 24


def score_thresholds(params: dict) -> tuple[float, float]:
    """Read the suspicious and malicious score thresholds from the instance.

    Scores are fractional, so these are parsed as floats: arg_to_number would
    turn 72.5 into 72. An empty value falls back to the server's default.
    """

    def read(key: str, default: float) -> float:
        raw = params.get(key)
        if raw is None or str(raw).strip() == "":
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            raise DemistoException(f"Invalid value for {key}: '{raw}' is not a number.") from None

    return (
        read("score_threshold_suspicious", DEFAULT_SUSPICIOUS_FROM),
        read("score_threshold_malicious", DEFAULT_MALICIOUS_FROM),
    )


def lookback_hours(params: dict) -> int:
    """Read the late completion lookback. Unset means the yml default; 0 disables it."""
    value = arg_to_number(params.get("maturation_lookback_hours"), arg_name="maturation_lookback_hours")
    return DEFAULT_LOOKBACK_HOURS if value is None else max(value, 0)


COMPLETENESS_COMPLETE = "COMPLETE"

REQUEST_STATUS_REJECTED = "REJECTED"


# Only these sort keys exist in SampleReportRepositoryImpl.COMMON_SORTS. An
# unknown key is NOT rejected: the query silently falls back to
# "ORDER BY update_time DESC", which quietly reverses the order a cursor
# depends on. "createTime" looks valid and is the usual trap.
ALLOWED_SORT_FIELDS = {"reportTime", "updateTime", "sampleReportId", "sampleScore", "size"}


def normalize_verdict(raw: Any) -> str:
    """Map either verdict vocabulary onto the canonical one. '' when unknown."""
    if raw is None:
        return ""
    return _VERDICT_ALIASES.get(str(raw).strip().upper(), "")


def score_value(report: dict) -> tuple[float, bool]:
    """Return (score, present).

    ``sampleScore`` defaults to -1.0 in the API, not to 0, and the real
    presence flag is ``sampleScoreExists``. Treating -1 as a score would
    declare an unfinished analysis clean.
    """
    raw = report.get("sampleScore")
    if raw is None:
        return 0.0, False
    exists = report.get("sampleScoreExists")
    if exists is False:
        return 0.0, False
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0, False
    if value < 0:
        return 0.0, False
    return value, True


def score_to_verdict(
    score: float,
    present: bool,
    suspicious_from: float = DEFAULT_SUSPICIOUS_FROM,
    malicious_from: float = DEFAULT_MALICIOUS_FROM,
) -> str:
    """Reproduce ScoreLevel.fromSampleScore.

        no score        -> ''        (UNKNOWN)
        score == 0      -> CLEAN
        0 < score < 50  -> OK
        50 <= score <= 85 -> SUSPICIOUS
        score > 85      -> MALICIOUS (MALWARE here)

    Deliberately not the ``verdictByScore`` helper from tlab-cortex-connector,
    which folds 0 into OK and has no CLEAN. The report list already carries a
    server-computed verdict, so this integration must not become a second
    source of truth; where it has to compute, it computes the same way.
    """
    if not present or score < 0:
        return ""
    if score == 0:
        return VERDICT_CLEAN
    if score < suspicious_from:
        return VERDICT_OK
    if score <= malicious_from:
        return VERDICT_SUSPICIOUS
    return VERDICT_MALWARE


def canonical_verdict(
    report: dict,
    suspicious_from: float = DEFAULT_SUSPICIOUS_FROM,
    malicious_from: float = DEFAULT_MALICIOUS_FROM,
    early_verdict: bool = False,
) -> str:
    """Reduce a report to a single verdict.

    Precedence:
      1. WHITELIST wins — it is an analyst decision and score never overrides it.
      2. At COMPLETE the score is the truth, so recompute from it.
      3. With early_verdict, recompute once STAT and AV have finished.
      4. Otherwise take an actionable stored verdict, FileVerdict first.
      5. Otherwise fall back to the local score computation.
    """
    file_dto = report.get("file") or {}
    file_verdict = normalize_verdict(file_dto.get("fileVerdict"))
    score_level = normalize_verdict(report.get("verdict"))
    score, present = score_value(report)

    if report.get("whitelisted") or VERDICT_WHITELIST in (file_verdict, score_level):
        return VERDICT_WHITELIST

    completeness = report.get("sampleReportCompleteness")
    if completeness == COMPLETENESS_COMPLETE:
        computed = score_to_verdict(score, present, suspicious_from, malicious_from)
        if computed:
            return computed

    if early_verdict and _stat_and_av_done(report):
        computed = score_to_verdict(score, present, suspicious_from, malicious_from)
        if computed:
            return computed

    if file_verdict in ACTIONABLE_VERDICTS:
        return file_verdict
    if score_level in ACTIONABLE_VERDICTS:
        return score_level

    # Computing a verdict from the score locally is allowed only when the server
    # did not report completeness. If it explicitly said EMPTY or
    # PARTIALLY_COMPLETE, the analysis is not terminal yet and the verdict must
    # stay UNKNOWN - otherwise polling would finish on an intermediate score.
    if not completeness:
        computed = score_to_verdict(score, present, suspicious_from, malicious_from)
        if computed:
            return computed
    return VERDICT_UNKNOWN


def _stat_and_av_done(report: dict) -> bool:
    completed = report.get("completedAnalyzes")
    if not isinstance(completed, (list, set, tuple)):
        return False
    names = {str(x).upper() for x in completed}
    return {"STAT_ANALYSIS", "AV_ANALYSIS"}.issubset(names)


# XSOAR severity scale: 0 Unknown, 0.5 Informational, 1 Low, 2 Medium,
# 3 High, 4 Critical.
DEFAULT_SEVERITY_MAP = {
    VERDICT_MALWARE: 3,
    VERDICT_SUSPICIOUS: 2,
    VERDICT_OK: 1,
    VERDICT_CLEAN: 1,
    VERDICT_WHITELIST: 0.5,
    VERDICT_UNKNOWN: 1,
}


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------
# tlab-server has no spring.jackson configuration and no ObjectMapper bean, so
# java.util.Date serializes with the Jackson default: epoch milliseconds. A
# Spring Boot upgrade would flip that to ISO strings, so accept both. Seconds
# are accepted too and told apart by magnitude.
TLAB_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_EPOCH_MILLIS_FLOOR = 100_000_000_000  # ~1973 in milliseconds


def epoch_to_datetime(value: Any) -> datetime | None:
    """Parse epoch millis, epoch seconds or an ISO-8601 string into UTC."""
    if value in (None, "", 0):
        return None
    if isinstance(value, str):
        parsed = dateparser.parse(value, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
        return parsed
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    if number < _EPOCH_MILLIS_FLOOR:
        number *= 1000
    return datetime.fromtimestamp(number / 1000.0, tz=UTC)


def epoch_to_iso(value: Any) -> str | None:
    """Same as epoch_to_datetime but formatted the way XSOAR expects."""
    parsed = epoch_to_datetime(value)
    return parsed.strftime(TLAB_DATE_FORMAT) if parsed else None


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
# RejectionCode values are string constants that double as i18n keys. Note
# "common.file_type_no_allowed" — the typo is in the product, not here.
REJECTION_MESSAGES = {
    "common.whitelisted": "The sample is whitelisted in tLab Anti-APT, so it was not analyzed.",
    "common.already_analyzed": "The sample has already been analyzed; the existing report is returned.",
    "common.limit_reached": "The tLab Anti-APT submission limit has been reached. Retry later.",
    "common.invalid_file_size": "The file size is outside the limits accepted by tLab Anti-APT.",
    "common.invalid_file_name": "The file name is not accepted by tLab Anti-APT.",
    "common.file_type_no_allowed": "This file type is not accepted for analysis.",
    "common.general_io_error": "tLab Anti-APT could not read the submitted content.",
    "common.mainFileContentMissing": "The main file content is missing from the submission.",
    "common.extraFileContentMissing": "An additional file's content is missing from the submission.",
    "common.no_such_report": "No such report in tLab Anti-APT.",
    "common.unknown": "tLab Anti-APT rejected the submission without a specific reason.",
    "url.invalid": "The URL is not valid.",
    "url.protocol_not_allowed": "The URL protocol is not allowed for analysis.",
    "url.download_error": "tLab Anti-APT could not download the URL.",
    "url.download_timeout": "Downloading the URL timed out.",
    "archive.password_required": "The archive is password protected. Pass the password in the archive_password argument.",
    "archive.decryption_not_supported": "This archive encryption is not supported.",
    "archive.unknown_error": "The archive could not be processed.",
    "activation.invalidLicense": "The tLab Anti-APT license does not allow this analysis.",
}

# Rejections that are an outcome rather than a failure: the caller gets a
# result, not an exception.
NON_ERROR_REJECTIONS = {"common.whitelisted", "common.already_analyzed"}


def describe_rejection(code: str, message: str = "") -> str:
    """Human-readable text for a rejection code, never swallowing unknown ones."""
    known = REJECTION_MESSAGES.get(code)
    if known:
        return f"{known} (code: {code})" if not message else f"{known} (code: {code}; {message})"
    tail = f": {message}" if message else ""
    return f"tLab Anti-APT rejected the submission with code {code}{tail}"


class TLabRejection(Exception):
    """A submission the server refused, carrying the raw rejection code."""

    def __init__(self, code: str, message: str = "", payload: dict | None = None):
        self.code = code
        self.payload = payload or {}
        super().__init__(describe_rejection(code, message))


def _raise_auth_error(response: requests.Response) -> None:
    body: dict = {}
    with contextlib.suppress(Exception):
        body = response.json() or {}
    message = body.get("message") or ""
    if not message:
        with contextlib.suppress(Exception):
            message = response.text[:200]
    status = response.status_code
    url = getattr(response, "url", "") or ""

    # tlab-server (Spring) answers with timestamp/error/path; tlab-auth never
    # does. Seeing that shape means the Auth server URL points at the sandbox.
    if "timestamp" in body and "path" in body or "authorizationHeader" in message:
        raise DemistoException(
            f"tLab Anti-APT: {url} is answered by tlab-server, not tlab-auth ({message}). "
            f"Set Auth server URL to the omni-center portal, e.g. https://<tlab-host>:{OMNI_PORTAL_TLS_PORT}/api."
        )

    hint = ""
    if status == 401:
        hint = " Check the login and password of the tLab account."
    elif status == 403:
        hint = " The account may need a password change, or lacks access."
    elif status == 404:
        hint = " Check the Auth server URL: it must point at tlab-auth (…/api)."
    raise DemistoException(f"tLab Anti-APT: tlab-auth ({url}) answered HTTP {status}: {message}.{hint}")


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------
AUTH_TLAB_ACCOUNT = "tLab account (tlab-auth)"
AUTH_SOURCE_KEY = "Source key (Bearer)"
AUTH_SIGN_IN = "Username and password"
AUTH_INTERNAL = "Internal token (localhost only)"

_TOKEN_CACHE_KEY = "tlab_signin_token"
_SESSION_CACHE_KEY = "tlab_auth_session"
_TOKEN_SKEW_SECONDS = 60
# Used when a JWT carries no readable exp claim: short enough that a refresh
# happens well before any sane server-side lifetime runs out.
_FALLBACK_TOKEN_LIFETIME = 900


# The omni-center site that tlab-omni-center-frontend installs into nginx listens
# on 8002 with TLS and proxies /api/ to tlab-auth (127.0.0.1:8033).
OMNI_PORTAL_TLS_PORT = 8002


def read_cache(key: str) -> dict:
    """One entry of the integration context, where tokens are cached between runs."""
    return (demisto.getIntegrationContext() or {}).get(key) or {}


def write_cache(key: str, value: dict) -> None:
    """Store one entry, keeping the rest of the context (fetch cursors live there too)."""
    merge_integration_context(**{key: value})


def default_auth_url(server_url: str) -> str:
    """Derive the tlab-auth base URL from the sandbox URL: the omni-center portal
    on the same host, ``https://<host>:8002/api``.

    It goes through the portal rather than straight to tlab-auth on :8033 so the
    password never travels unencrypted. It is not ``https://<host>/api`` either:
    on a sandbox host that path belongs to the tLab web server, whose nginx sends
    all of ``/api`` to tlab-server, and a login there is answered by tlab-server
    with 401 "No authorizationHeader data".
    """
    host = urllib.parse.urlsplit(server_url or "").hostname or ""
    return f"https://{host}:{OMNI_PORTAL_TLS_PORT}/api" if host else ""


def jwt_expiry(token: str) -> float | None:
    """Read the ``exp`` claim without verifying the signature.

    Only used to decide when to refresh; tlab-server verifies the token itself.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
        return float(exp) if exp else None
    except Exception:  # noqa: BLE001 - an unreadable token just means "refresh early"
        return None


class TLabClient(BaseClient):
    """HTTP client for the tLab Anti-APT API.

    Four authentication modes, not interchangeable:

    ``tLab account (tlab-auth)`` — the default
        Log in to tlab-auth (``POST <auth>/auth/login``) with a tLab account and
        send the JWT as ``Authorization: Bearer <access>``. tlab-server verifies
        it itself or through tlab-auth. The session is cached per instance and
        refreshed through ``POST <auth>/auth/refresh`` before it expires; a
        failed refresh falls back to a fresh login. This is the same flow the
        omni-center portal uses, so it works with every tlab-server that
        accepts portal users.

    ``Source key (Bearer)``
        ``Authorization: Bearer <key>``. The key is issued by the tLab
        omni-center source-key registry for source type CORTEX_XSOAR. This is
        the recommended mode. Rotation has a grace period, so a 401 means the
        key was revoked or the grace window expired.

    ``Username and password``
        ``POST /auth/sign_in`` and then ``Authorization: <token>`` with **no
        scheme prefix** — this is the legacy opaque-token branch on the server.

    ``Internal token (localhost only)``
        ``Authorization: Internal <token>``. Usable only when the caller is on
        the tlab-server host: ``tokenAuth.allowedRemoteAddresses`` defaults to
        127.0.0.1. A remote XSOAR cannot use this mode.
    """

    def __init__(
        self,
        base_url: str,
        auth_mode: str,
        credentials: dict,
        client_name: str = "xsoar",
        verify: bool = True,
        proxy: bool = False,
        auth_url: str = "",
    ):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy)
        self._auth_mode = auth_mode
        self._username = (credentials or {}).get("identifier") or ""
        self._secret = (credentials or {}).get("password") or ""
        self._client_name = client_name or "xsoar"
        self._auth_url = (auth_url or "").strip().rstrip("/") or default_auth_url(base_url)

    # -- authentication -----------------------------------------------------

    def _client_header(self) -> dict:
        """``X-Client`` is parsed as ``<type>;<name>``.

        The type must be one of web|mail|endpoint or the server drops the whole
        header silently. The name lands in the analysis property ``client``.
        """
        return {"X-Client": f"endpoint;{self._client_name}"}

    def _auth_header(self) -> dict:
        if self._auth_mode == AUTH_TLAB_ACCOUNT:
            return {"Authorization": f"Bearer {self._tlab_auth_token()}"}
        if self._auth_mode == AUTH_INTERNAL:
            return {"Authorization": f"Internal {self._secret}"}
        if self._auth_mode == AUTH_SIGN_IN:
            return {"Authorization": self._sign_in_token()}
        return {"Authorization": f"Bearer {self._secret}"}

    def _sign_in_token(self, force: bool = False) -> str:
        """Return a legacy token, reusing the cached one until it nearly expires."""
        cached = read_cache(_TOKEN_CACHE_KEY)
        expires_at = cached.get("expires_at") or 0
        if not force and cached.get("value") and time.time() < expires_at - _TOKEN_SKEW_SECONDS:
            return cached["value"]

        response = self._http_request(
            method="POST",
            url_suffix="/auth/sign_in",
            data={"username": self._username, "password": self._secret},
            headers=self._client_header(),
            resp_type="json",
        )
        if not response.get("successful"):
            raise DemistoException("tLab Anti-APT rejected the username and password.")
        token = (response.get("token") or {}).get("tokenValue")
        if not token:
            raise DemistoException("tLab Anti-APT returned no token for the given credentials.")
        expiration = (response.get("token") or {}).get("expirationTime") or 0
        parsed = epoch_to_datetime(expiration)
        write_cache(
            _TOKEN_CACHE_KEY,
            {"value": token, "expires_at": parsed.timestamp() if parsed else time.time() + 3600},
        )
        return token

    # -- tlab-auth session ---------------------------------------------------

    def _session_owner(self) -> str:
        """Who the cached session belongs to. Changing the auth URL or the login
        in the instance settings must not keep using the old session."""
        return hashlib.sha256(f"{self._auth_url}\n{self._username}".encode()).hexdigest()

    def _tlab_auth_token(self, force_refresh: bool = False) -> str:
        """Return a valid access token, logging in or refreshing as needed."""
        if not self._auth_url:
            raise DemistoException(
                "tLab Anti-APT: set the Auth server URL (tlab-auth), e.g. https://<tlab-host>/api, "
                "or a Server URL with a host name to derive it from."
            )
        session = read_cache(_SESSION_CACHE_KEY)
        if session.get("owner") != self._session_owner():
            session = {}

        if not force_refresh and session.get("access") and time.time() < session.get("expires_at", 0) - _TOKEN_SKEW_SECONDS:
            return session["access"]

        tokens = None
        if session.get("refresh"):
            try:
                tokens = self._auth_post("/auth/refresh", {"refresh_token": session["refresh"]})
            except DemistoException as exc:
                demisto.debug(f"tLab: tlab-auth refresh failed, logging in again: {exc}")
        if tokens is None:
            tokens = self._auth_post("/auth/login", {"login": self._username, "password": self._secret})

        access = tokens.get("access") or ""
        if not access:
            raise DemistoException("tLab Anti-APT: tlab-auth returned no access token.")
        write_cache(
            _SESSION_CACHE_KEY,
            {
                "owner": self._session_owner(),
                "access": access,
                "refresh": tokens.get("refresh") or "",
                "expires_at": jwt_expiry(access) or time.time() + _FALLBACK_TOKEN_LIFETIME,
            },
        )
        return access

    def _auth_post(self, path: str, body: dict) -> dict:
        """POST to tlab-auth. Its errors arrive as ``{"message": ...}``; pass that
        text on, because it is what the operator needs: wrong password, locked
        account, expired password."""
        try:
            return self._http_request(
                method="POST",
                full_url=f"{self._auth_url}{path}",
                json_data=body,
                headers={"Accept": "application/json", **self._client_header()},
                resp_type="json",
                error_handler=_raise_auth_error,
            )
        except DemistoException:
            raise
        except Exception as exc:  # noqa: BLE001 - connection errors, bad JSON
            raise DemistoException(f"tLab Anti-APT: tlab-auth at {self._auth_url} is unreachable: {exc}") from exc

    def _build_headers(self, extra: dict | None = None, with_auth: bool = True) -> dict:
        """Assemble request headers.

        Named ``_build_headers`` rather than ``_headers`` on purpose:
        ``BaseClient.__init__`` assigns ``self._headers``, so a method of
        that name is silently replaced by an attribute (usually None).
        """
        headers = {"Accept": "application/json"}
        headers.update(self._client_header())
        if with_auth:
            headers.update(self._auth_header())
        if extra:
            headers.update(extra)
        return headers

    # -- transport ----------------------------------------------------------

    def request(
        self,
        method: str,
        url_suffix: str,
        params: Any = None,
        data: Any = None,
        files: Any = None,
        headers: dict | None = None,
        resp_type: str = "json",
        with_auth: bool = True,
        timeout: int | None = None,
        retry_on_401: bool = True,
    ) -> Any:
        """One request, translating tLab's failure modes into readable errors."""
        # Headers (and with them any login) are built outside the try: a 401
        # from tlab-auth itself must not trigger the retry below, or a wrong
        # password would be tried twice and count twice towards a lockout.
        request_headers = self._build_headers(headers, with_auth=with_auth)
        try:
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                data=data,
                files=files,
                headers=request_headers,
                resp_type=resp_type,
                timeout=timeout,
                error_handler=self._error_handler,
            )
        except DemistoException as exc:
            # A cached token can expire or be revoked mid-playbook: get a new
            # one once and retry, but never loop.
            if retry_on_401 and self._auth_mode in (AUTH_SIGN_IN, AUTH_TLAB_ACCOUNT) and "401" in str(exc):
                if self._auth_mode == AUTH_SIGN_IN:
                    self._sign_in_token(force=True)
                else:
                    self._tlab_auth_token(force_refresh=True)
                return self.request(
                    method,
                    url_suffix,
                    params=params,
                    data=data,
                    files=files,
                    headers=headers,
                    resp_type=resp_type,
                    with_auth=with_auth,
                    timeout=timeout,
                    retry_on_401=False,
                )
            raise

    def _error_handler(self, response: requests.Response) -> None:
        status = response.status_code
        body = ""
        # Diagnostics must never mask the real error.
        with contextlib.suppress(Exception):
            body = response.text[:500]

        if status == 401:
            hint = (
                "The Internal token is accepted only from 127.0.0.1, so a remote XSOAR cannot use it. "
                "Use a source key (Bearer) instead."
                if self._auth_mode == AUTH_INTERNAL
                else "Check the source key: it may have been revoked or its rotation grace period may have expired."
            )
            raise DemistoException(f"tLab Anti-APT returned 401 Unauthorized. {hint}")
        if status == 403:
            raise DemistoException(
                "tLab Anti-APT returned 403 Forbidden. The token authenticated, but the account lacks access. "
                "Listing reports requires the admin or developer role; the external_service role that an "
                "Internal token grants is refused by that endpoint. "
                f"Response: {body}"
            )
        if status == 404:
            raise DemistoException(f"tLab Anti-APT returned 404 Not Found for the requested object. Response: {body}")
        raise DemistoException(f"tLab Anti-APT returned {status}. Response: {body}")

    # -- reports ------------------------------------------------------------

    def list_sample_reports(
        self,
        page: int = 0,
        size: int = 50,
        sort: str = "sampleReportId,asc",
        min_report_id: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        completeness: list | None = None,
        status: list | None = None,
        file_verdicts: list | None = None,
        score_levels: list | None = None,
        file_types: list | None = None,
        source_ids: list | None = None,
        tags: list | None = None,
        indicators: list | None = None,
        root_only: bool | None = None,
        file_hash_sha256: str | None = None,
        file_hash_sha1: str | None = None,
        min_score: float | None = None,
        file_name: str | None = None,
    ) -> dict:
        """One page of GET /sample_reports.

        The sort key is validated before the request leaves: the server does not
        reject an unknown key, it silently reorders the result set.
        """
        validate_sort(sort)
        params: list[tuple[str, Any]] = [("page", page), ("size", size), ("sort", sort)]
        if min_report_id is not None:
            # The filter is applied as ``sample_report_id >= n``, so a cursor
            # must send "last seen + 1" rather than the last seen id.
            params.append(("minReportId", min_report_id))
        for key, value in (
            ("dateFrom", date_from),
            ("dateTo", date_to),
            ("fileHashSha256", file_hash_sha256),
            ("fileHashSha1", file_hash_sha1),
            ("minScore", min_score),
            ("fileName", file_name),
        ):
            if value not in (None, ""):
                params.append((key, value))
        if root_only is not None:
            params.append(("rootOnly", str(bool(root_only)).lower()))
        # Array filters travel as repeated parameters, which is how Spring binds them.
        for key, values in (
            ("completeness", completeness),
            ("status", status),
            ("fileVerdict", file_verdicts),
            ("scoreLevel", score_levels),
            ("fileType", file_types),
            ("sourceId", source_ids),
            ("tags", tags),
            ("indicators", indicators),
        ):
            for item in values or []:
                params.append((key, item))
        payload = self.request("GET", "/sample_reports", params=params)
        if min_report_id:
            check_min_report_id_applied(payload, min_report_id)
        return payload

    def get_threat_indicators(self, sample_report_id: int) -> dict:
        return self.request("GET", f"/sample_reports/{sample_report_id}/threat_indicators")

    # -- public endpoints (no authentication required) -----------------------

    # -- submission ---------------------------------------------------------

    # -- artifacts ----------------------------------------------------------


def check_min_report_id_applied(payload: Any, min_report_id: int) -> None:
    """Fail loudly when the server dropped the minReportId filter.

    tlab-server binds only a whitelist of filter fields for company admins and
    company users (SampleReportsController.initBinder): minReportId, rootOnly
    and sourceId are silently ignored for them. A cursor then never takes
    effect and every fetch starts again from the first report in history.
    """
    for report in (payload or {}).get("content") or [] if isinstance(payload, dict) else []:
        report_id = arg_to_number(report.get("sampleReportId"))
        if report_id is not None and report_id < min_report_id:
            raise DemistoException(
                f"tLab Anti-APT ignored the minReportId={min_report_id} filter and returned report {report_id}. "
                "The server applies it only for system administrators and service accounts: company admins "
                "and users get the whole history on every fetch. Use an account with the system admin role."
            )


def merge_integration_context(**changes: Any) -> None:
    """Merge into the integration context instead of replacing it.

    The context also holds the cached tlab-auth session; overwriting it would
    force a fresh login on every run. A value of None removes the key.
    """
    context = demisto.getIntegrationContext() or {}
    for key, value in changes.items():
        if value is None:
            context.pop(key, None)
        else:
            context[key] = value
    demisto.setIntegrationContext(context)


def validate_sort(sort: str) -> None:
    """Reject a sort key the server would silently ignore."""
    if not sort:
        return
    field = sort.split(",")[0].strip()
    if field not in ALLOWED_SORT_FIELDS:
        raise DemistoException(
            f"Invalid sort field {field!r}. tLab Anti-APT silently ignores unknown sort keys and falls back "
            f"to 'ORDER BY update_time DESC', which reverses the order a cursor depends on. "
            f"Allowed: {', '.join(sorted(ALLOWED_SORT_FIELDS))}."
        )


# ---------------------------------------------------------------------------
# End of the shared tLab Anti-APT client.
# ---------------------------------------------------------------------------


# XSOAR severities. 0.5 is Informational, which is a real value here rather
# than a rounding accident: a WHITELIST verdict is a finding worth recording
# and worth never alerting on.
SEVERITY_UNKNOWN = 0.0
SEVERITY_INFO = 0.5
SEVERITY_LOW = 1.0
SEVERITY_MEDIUM = 2.0
SEVERITY_HIGH = 3.0
SEVERITY_CRITICAL = 4.0

# Mirrors SEVERITY_MAP in the Go connector's config.go. Both halves must agree,
# so changing one without the other is a defect.
DEFAULT_SEVERITY_MAP = {
    VERDICT_MALWARE: SEVERITY_HIGH,
    VERDICT_SUSPICIOUS: SEVERITY_MEDIUM,
    VERDICT_OK: SEVERITY_LOW,
    VERDICT_CLEAN: SEVERITY_LOW,
    VERDICT_WHITELIST: SEVERITY_INFO,
    VERDICT_UNKNOWN: SEVERITY_LOW,
}

DEFAULT_NAME_TEMPLATE = "tLab Anti-APT {verdict}: {filename}"
DEFAULT_VERDICTS = [VERDICT_MALWARE, VERDICT_SUSPICIOUS]
INCIDENT_TYPE = "tLab Anti-APT Verdict"
DELIVERY_PULL = "PULL"

OUTPUT_VERDICT = "TLabAntiAPT.Verdict"
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")

# The seen set only has to cover the maturation window: a report that left it
# can never be re-read. Pruning at twice the window is slack for clock skew.
SEEN_PRUNE_FACTOR = 2


# --------------------------------------------------------------------------
# Incident shape
# --------------------------------------------------------------------------
def dedupe_key(installation_id: str, report_id: int) -> str:
    """tlab-apt:<installation>:<report id>.

    Deliberately not derived from the file hash: the same file legitimately
    produces new detections, and collapsing those would hide re-infections.
    """
    return f"tlab-apt:{installation_id or ''}:{report_id}"


def render_incident_name(template: str | None, report: dict, verdict: str) -> str:
    """Mirrors RenderIncidentName in the Go connector, fallbacks included."""
    score, present = score_value(report)
    file_dto = report.get("file") or {}
    sha256 = file_dto.get("hashSha256") or ""
    report_id = arg_to_number(report.get("sampleReportId")) or 0

    filename = report.get("uploadedFilename") or ""
    if not filename:
        filename = sha256[:12] if len(sha256) >= 12 else f"sample {report_id}"

    source = report.get("source") or {}
    replacements = {
        "{verdict}": verdict,
        "{filename}": filename,
        "{sha256}": sha256,
        "{score}": f"{score:.2f}" if present else "n/a",
        "{report_id}": str(report_id),
        "{source_type}": source.get("sourceType") or "",
    }
    out = template or DEFAULT_NAME_TEMPLATE
    for key, value in replacements.items():
        out = out.replace(key, value)
    return out.strip()


def severity_for(verdict: str, score: float, present: bool, severity_map: dict, critical_score: int) -> float:
    """Mirrors SeverityForVerdict in the Go connector."""
    severity = severity_map.get(verdict, SEVERITY_LOW)
    if critical_score > 0 and verdict == VERDICT_MALWARE and present and score >= critical_score:
        return SEVERITY_CRITICAL
    return severity


def parse_severity_map(raw: str | list | None) -> dict:
    """Parses "MALWARE:3,SUSPICIOUS:2" the way the Go connector's env var does."""
    items = argToList(raw)
    if not items:
        return dict(DEFAULT_SEVERITY_MAP)
    parsed = dict(DEFAULT_SEVERITY_MAP)
    for item in items:
        name, _, value = str(item).partition(":")
        name = name.strip().upper()
        if name not in DEFAULT_SEVERITY_MAP:
            raise DemistoException(f"Severity map: unknown verdict '{name}'.")
        try:
            severity = float(value)
        except ValueError:
            raise DemistoException(f"Severity map: '{item}' is not VERDICT:severity.") from None
        if severity not in (0, 0.5, 1, 2, 3, 4):
            raise DemistoException(f"Severity map: {severity} is not an XSOAR severity (0, 0.5, 1, 2, 3, 4).")
        parsed[name] = severity
    return parsed


def as_float(value: Any) -> float | None:
    """arg_to_number rejects non-integers, and sandbox scores are fractional."""
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def report_url(base_url: str | None, report_id: int) -> str:
    base = (base_url or "").rstrip("/")
    return f"{base}/reports/{report_id}" if base else ""


def contract_payload(report: dict, params: dict, enrichment: dict | None = None) -> dict:
    """Builds docs/verdict-incident-schema.json.

    The Go connector builds the same object in RawJSON(). Keys are omitted
    rather than set to null when a value is absent, which is what the schema's
    nullable types allow and what keeps the two halves byte-comparable.
    """
    report_id = arg_to_number(report.get("sampleReportId")) or 0
    suspicious_from, malicious_from = score_thresholds(params)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)
    file_dto = report.get("file") or {}
    source = report.get("source") or {}
    classifier = report.get("malwareClassifierResult") or {}
    enrichment = enrichment or {}

    payload = {
        "tlab_dedupe_key": dedupe_key(params.get("installation_id") or "", report_id),
        "tlab_sample_report_id": report_id,
        "tlab_verdict": verdict,
        "tlab_delivery_mode": DELIVERY_PULL,
        "tlab_whitelisted": bool(report.get("whitelisted")),
        "tlab_av_detected": bool(enrichment.get("av_detected")),
        "tlab_multistage": bool(classifier.get("multiStage")),
        "tlab_attack_techniques": enrichment.get("attack_techniques") or [],
        "tlab_threat_indicators": enrichment.get("threat_indicators") or [],
        "tlab_tags": argToList(report.get("tags")) or [],
    }

    optional = {
        "tlab_analysis_request_id": arg_to_number(report.get("analysisRequestId")),
        "tlab_access_code": report.get("accessCode"),
        "tlab_report_type": report.get("sampleReportType"),
        "tlab_completeness": report.get("sampleReportCompleteness"),
        # Both raw enums are kept: an analyst must be able to see what the
        # server actually said, not only our canonicalisation of it.
        "tlab_score_level": report.get("verdict"),
        "tlab_file_verdict": file_dto.get("fileVerdict"),
        "tlab_file_sha256": file_dto.get("hashSha256"),
        "tlab_file_sha1": file_dto.get("hashSha1"),
        "tlab_file_md5": file_dto.get("hashMd5"),
        "tlab_file_name": report.get("uploadedFilename"),
        "tlab_file_size": arg_to_number(file_dto.get("size")),
        "tlab_file_type": file_dto.get("fileType"),
        "tlab_mime_type": file_dto.get("mimeType"),
        "tlab_source_type": source.get("sourceType"),
        "tlab_source_uid": source.get("sourceUid"),
        "tlab_malware_family": classifier.get("primaryType"),
        "tlab_malware_confidence": as_float(classifier.get("confidence")),
        "tlab_dyn_report_id": arg_to_number(report.get("dynReportId")),
        "tlab_stat_report_id": arg_to_number(report.get("statReportId")),
        "tlab_report_url": report_url(params.get("url"), report_id),
        "tlab_create_time": epoch_to_iso(report.get("createTime")),
        "tlab_update_time": epoch_to_iso(report.get("updateTime")),
    }
    for key, value in optional.items():
        if value not in (None, ""):
            payload[key] = value

    # -1.0 is the API's "no score" default and the schema forbids it, so an
    # absent score is an absent key rather than a misleading number.
    if present:
        payload["tlab_score"] = score
    max_score = as_float(report.get("maxSampleReportScore"))
    if max_score is not None and max_score >= 0:
        payload["tlab_max_score"] = max_score
    return payload


# Machine names from x-xsoar-custom-field-names. The mapper shipped with this
# pack does the same translation on the supported path; this table exists for
# the fallback below.
CUSTOM_FIELD_NAMES = {
    "tlab_dedupe_key": "tlabdedupekey",
    "tlab_sample_report_id": "tlabsamplereportid",
    "tlab_access_code": "tlabaccesscode",
    "tlab_verdict": "tlabverdict",
    "tlab_score_level": "tlabscorelevel",
    "tlab_file_verdict": "tlabfileverdict",
    "tlab_score": "tlabscore",
    "tlab_completeness": "tlabcompleteness",
    "tlab_report_type": "tlabreporttype",
    "tlab_file_sha256": "tlabfilesha256",
    "tlab_file_name": "tlabfilename",
    "tlab_file_type": "tlabfiletype",
    "tlab_av_detected": "tlabavdetected",
    "tlab_malware_family": "tlabmalwarefamily",
    "tlab_attack_techniques": "tlabattacktechniques",
    "tlab_source_type": "tlabsourcetype",
    "tlab_report_url": "tlabreporturl",
    "tlab_delivery_mode": "tlabdeliverymode",
}


def custom_fields(payload: dict) -> dict:
    return {machine: payload[key] for key, machine in CUSTOM_FIELD_NAMES.items() if key in payload}


def build_incident(report: dict, params: dict, severity_map: dict, enrichment: dict | None = None) -> dict:
    payload = contract_payload(report, params, enrichment)
    score, present = score_value(report)
    return {
        "name": render_incident_name(params.get("incident_name_template"), report, payload["tlab_verdict"]),
        "occurred": payload.get("tlab_create_time") or epoch_to_iso(report.get("updateTime")),
        "type": params.get("incidentType") or INCIDENT_TYPE,
        "severity": severity_for(
            payload["tlab_verdict"],
            score,
            present,
            severity_map,
            arg_to_number(params.get("severity_critical_score")) or 0,
        ),
        "dbotMirrorId": payload["tlab_dedupe_key"],
        # The mapper shipped with this pack is the supported way to populate
        # the fields. CustomFields is a belt-and-braces fallback for instances
        # configured without one; where the server ignores it, the values are
        # still in rawJSON and in the labels.
        "CustomFields": custom_fields(payload),
        "rawJSON": json.dumps(payload),
    }


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------
def enrich(client: TLabClient, report_id: int) -> dict:
    """Threat indicators, ATT&CK techniques and the AV flag, in one call.

    The sample report list carries no AV result, so detectedByAv has to be
    derived. A MALICIOUS indicator from the AV source is exactly that signal.
    """
    out: dict = {"attack_techniques": [], "threat_indicators": [], "av_detected": False}
    payload = client.get_threat_indicators(report_id)
    techniques: set = set()
    for indicator in payload.get("indicators") or []:
        level = str(indicator.get("level") or "").upper()
        source = str(indicator.get("source") or "").upper()
        if source == "AV" and level == "MALICIOUS":
            out["av_detected"] = True
        if level in ("MALICIOUS", "SUSPICIOUS"):
            out["threat_indicators"].append(
                remove_empty_elements(
                    {
                        "source": indicator.get("source"),
                        "level": level,
                        "title": indicator.get("title") or indicator.get("key") or "",
                        "count": arg_to_number(indicator.get("count")),
                    }
                )
            )
        techniques.update(str(t) for t in (indicator.get("attack") or []) if RE_ATTACK.match(str(t)))
    out["attack_techniques"] = sorted(techniques)
    return out


# --------------------------------------------------------------------------
# Cursor
# --------------------------------------------------------------------------
# Same dual cursor as the feed and the Go connector, for the same reason: the
# server has no updatedSince filter, and analyses complete out of id order, so
# a single cursor is provably lossy in one direction or unfilterable in the
# other. Unlike the feed, duplicates here are not free -- they are duplicate
# incidents -- so the seen set below is load-bearing rather than an
# optimisation.
def discovery_page(client: TLabClient, cursor: int, size: int, params: dict) -> dict:
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="sampleReportId,asc",
        min_report_id=cursor,
        completeness=completeness_filter(params),
        root_only=root_only(params),
    )


def maturation_page(client: TLabClient, lookback_hours: int, size: int, params: dict) -> dict:
    since = datetime.now(UTC) - timedelta(hours=max(1, lookback_hours))
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="updateTime,desc",
        date_from=since.strftime(TLAB_DATE_FORMAT),
        completeness=completeness_filter(params),
        root_only=root_only(params),
    )


def completeness_filter(params: dict) -> list:
    """A PARTIALLY_COMPLETE verdict can still change, and an incident whose
    severity drops after the analyst triaged it is worse than a late one."""
    return ["COMPLETE", "PARTIALLY_COMPLETE"] if param_bool(params, "include_partial") else ["COMPLETE"]


def root_only(params: dict) -> bool:
    """Dropped and embedded files get their own reports. Without this every
    archive turns into a dozen incidents for one delivery."""
    return param_bool(params, "root_reports_only", True)


def param_bool(params: dict, key: str, default: bool = False) -> bool:
    value = params.get(key)
    if value is None or value == "":
        return default
    try:
        return argToBoolean(value)
    except ValueError:
        return default


def next_cursor(reports: list, current: int) -> int:
    highest = current
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        highest = max(highest, report_id + 1)
    return highest


def prune_seen(seen: dict, lookback_hours: int) -> dict:
    """Drop keys for reports that can no longer reappear in the maturation
    window, so last run does not grow without bound."""
    if not seen:
        return {}
    horizon = datetime.now(UTC) - timedelta(hours=max(1, lookback_hours) * SEEN_PRUNE_FACTOR)
    kept = {}
    for key, stamp in seen.items():
        moment = epoch_to_datetime(stamp)
        if moment is None or moment >= horizon:
            kept[key] = stamp
    return kept


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------
def collect_reports(client: TLabClient, params: dict, last_run: dict, preview: bool = False) -> tuple[list, int]:
    # first_report_id is a floor, not just the starting point of the first
    # fetch: XSOAR keeps the cursor across instance edits, so a value set after
    # fetching had started would otherwise be ignored and the backfill from 0
    # would go on. Raising the floor only moves the cursor forward, so it
    # cannot re-create incidents. Going below it takes clearing the parameter.
    floor = arg_to_number(params.get("first_report_id")) or 0
    cursor = arg_to_number(last_run.get("report_cursor"))
    cursor = floor if cursor is None else max(cursor, floor)
    page_size = arg_to_number(params.get("max_fetch")) or 50
    lookback = lookback_hours(params)

    reports: dict[int, dict] = {}
    for report in discovery_page(client, cursor, page_size, params).get("content") or []:
        report_id = arg_to_number(report.get("sampleReportId"))
        if report_id is not None:
            reports[report_id] = report
    advanced = next_cursor(list(reports.values()), cursor)

    if lookback and not preview:
        for report in maturation_page(client, lookback, page_size, params).get("content") or []:
            report_id = arg_to_number(report.get("sampleReportId"))
            # At or above the cursor is discovery's job; taking it here would
            # double the enrichment cost for nothing. Below the floor is what
            # the operator asked not to fetch.
            if report_id is not None and report_id not in reports and floor <= report_id < cursor:
                reports[report_id] = report

    ordered = sorted(reports.values(), key=lambda r: arg_to_number(r.get("sampleReportId")) or 0)
    return ordered, advanced


def build_incidents(client: TLabClient, params: dict, reports: list, seen: dict) -> list:
    verdicts = {v.upper() for v in (argToList(params.get("verdicts")) or DEFAULT_VERDICTS)}
    severity_map = parse_severity_map(params.get("severity_map"))
    enrichment_on = param_bool(params, "enrich_incidents", True)
    installation = params.get("installation_id") or ""
    now = datetime.now(UTC).strftime(TLAB_DATE_FORMAT)

    incidents = []
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        key = dedupe_key(installation, report_id)
        if key in seen:
            continue
        payload_verdict = canonical_verdict(
            report,
            suspicious_from=score_thresholds(params)[0],
            malicious_from=score_thresholds(params)[1],
        )
        if payload_verdict not in verdicts:
            continue

        enrichment = None
        if enrichment_on:
            try:
                enrichment = enrich(client, report_id)
            except Exception as exc:  # noqa: BLE001 - one bad report must not sink the fetch
                demisto.debug(f"[Fetch] Enrichment failed for report {report_id}: {exc}")

        incidents.append(build_incident(report, params, severity_map, enrichment))
        seen[key] = now
    return incidents


# Where tlab-verdicts-reset-cursor leaves its request. XSOAR 6 does not
# reliably keep demisto.setLastRun() called outside fetch-incidents, so the
# command writes to the integration context and the next fetch applies it.
CURSOR_OVERRIDE_KEY = "cursor_override"


def fetch_incidents_command(client: TLabClient, params: dict) -> None:
    last_run = demisto.getLastRun() or {}
    demisto.debug(f"[Fetch] Starting fetch cycle with report_cursor={last_run.get('report_cursor')}")
    override = (demisto.getIntegrationContext() or {}).get(CURSOR_OVERRIDE_KEY)
    if isinstance(override, dict):
        last_run = {key: value for key, value in last_run.items() if key != "report_cursor"}
        if override.get("report_cursor") is not None:
            last_run["report_cursor"] = override["report_cursor"]
    seen = dict(last_run.get("seen") or {})
    lookback = lookback_hours(params)

    reports, cursor = collect_reports(client, params, last_run)
    incidents = build_incidents(client, params, reports, seen)

    demisto.incidents(incidents)
    # Only after the incidents are handed over, so a failure re-fetches the
    # window instead of silently skipping it.
    demisto.setLastRun(
        {
            "report_cursor": cursor,
            "seen": prune_seen(seen, lookback or 24),
            "last_fetch": datetime.now(UTC).strftime(TLAB_DATE_FORMAT),
        }
    )
    if override is not None:
        merge_integration_context(**{CURSOR_OVERRIDE_KEY: None})
    demisto.info(f"[Fetch] Completed fetch cycle: {len(incidents)} incidents from {len(reports)} reports, cursor now {cursor}")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def verdict_context(payload: dict) -> dict:
    """The incident payload with context-style keys: tlab_sample_report_id
    becomes SampleReportId. The payload itself keeps its tlab_* keys, which are
    the contract shared with the PUSH connector and read by the mapper."""
    return {"".join(part.capitalize() for part in key.removeprefix("tlab_").split("_")): value for key, value in payload.items()}


def get_verdicts_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Preview. Creates no incidents and does not move the cursor."""
    limit = arg_to_number(args.get("limit")) or 10
    last_run = {"report_cursor": arg_to_number(args.get("from_report_id"))} if args.get("from_report_id") else {}
    reports, _ = collect_reports(client, params, last_run, preview=True)
    incidents = build_incidents(client, params, reports[:limit], {})

    rows = [
        {
            "Name": incident["name"],
            "Report ID": incident["CustomFields"].get("tlabsamplereportid"),
            "Verdict": incident["CustomFields"].get("tlabverdict"),
            "Score": incident["CustomFields"].get("tlabscore"),
            "Severity": incident["severity"],
            "File": incident["CustomFields"].get("tlabfilename"),
            "Occurred": incident.get("occurred"),
        }
        for incident in incidents
    ]
    raw = [json.loads(incident["rawJSON"]) for incident in incidents]
    outputs = [verdict_context(payload) for payload in raw]
    return CommandResults(
        outputs_prefix=OUTPUT_VERDICT,
        outputs_key_field="DedupeKey",
        outputs=outputs or None,
        raw_response=raw,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT verdicts ({len(rows)})",
            rows,
            headers=["Name", "Report ID", "Verdict", "Score", "Severity", "File", "Occurred"],
            removeNull=True,
        )
        if rows
        else "No verdicts matched the configured filters.",
    )


def reset_cursor_command(args: dict) -> CommandResults:
    report_id = arg_to_number(args.get("from_report_id"))
    merge_integration_context(**{CURSOR_OVERRIDE_KEY: {"report_cursor": report_id}})
    if report_id is None:
        return CommandResults(
            readable_output="Fetch cursor reset. The next fetch starts from the configured first sample report id."
        )
    return CommandResults(
        readable_output=f"Fetch cursor set to sample report {report_id}; the next fetch starts there. "
        "A First sample report id above it still takes precedence."
    )


def test_module_command(client: TLabClient, params: dict) -> str:
    parse_severity_map(params.get("severity_map"))
    for verdict in argToList(params.get("verdicts")) or []:
        if verdict.upper() not in DEFAULT_SEVERITY_MAP:
            raise DemistoException(f"Verdicts: '{verdict}' is not a tLab verdict.")
    if not (params.get("installation_id") or "").strip():
        raise DemistoException(
            "Installation ID is required. It is part of every deduplication key, so leaving it empty "
            "makes incidents from two tLab installations collide."
        )
    client.list_sample_reports(page=0, size=1, sort="sampleReportId,asc")
    return "ok"


def build_client(params: dict) -> TLabClient:
    return TLabClient(
        base_url=params.get("url") or "",
        auth_mode=params.get("auth_mode") or AUTH_TLAB_ACCOUNT,
        credentials=params.get("credentials") or {},
        client_name=params.get("client_name") or "xsoar",
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        auth_url=params.get("auth_url") or "",
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        client = build_client(params)

        if command == "test-module":
            return_results(test_module_command(client, params))
        elif command == "fetch-incidents":
            fetch_incidents_command(client, params)
        elif command == "tlab-get-verdicts":
            return_results(get_verdicts_command(client, args, params))
        elif command == "tlab-verdicts-reset-cursor":
            return_results(reset_cursor_command(args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}", error=exc)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
