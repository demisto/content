"""tLab Anti-APT Feed integration for Cortex XSOAR.

Turns observables seen during sandbox analysis into Threat Intel Management
indicators.

The hard part is not fetching but precision. tLab reports observables as
``{kind, name}`` pairs where ``kind`` is often just ``VALUE``, so the value has
to be typed here. A feed that guesses badly is worse than no feed: it fills TIM
with file names typed as domains and sandbox-internal addresses typed as
infrastructure, and analysts stop trusting the source.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import ipaddress
import re
import base64
import contextlib
import hashlib
import json
import time
import urllib.parse
from collections.abc import Iterator
from typing import Any


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


COMPLETENESS_EMPTY = "EMPTY"
COMPLETENESS_PARTIAL = "PARTIALLY_COMPLETE"
COMPLETENESS_COMPLETE = "COMPLETE"

REQUEST_STATUS_UNKNOWN = "UNKNOWN"
REQUEST_STATUS_WAITING = "WAITING_FOR_PROCESSING"
REQUEST_STATUS_PROCESSING = "PROCESSING"
REQUEST_STATUS_ACCEPTED = "ACCEPTED"
REQUEST_STATUS_REJECTED = "REJECTED"

REPORT_TYPE_MAIN = "MAIN"
REPORT_TYPE_DROPPED = "DROPPED"
REPORT_TYPE_EMBEDDED = "EMBEDDED"
REPORT_TYPE_COMMAND_LINES = "COMMAND_LINES"
REPORT_TYPE_SANITIZED = "SANITIZED"
REPORT_TYPE_DOWNLOADED_FROM_LINK = "DOWNLOADED_FROM_LINK"

# The source type must be sent by the enum NAME: Spring form-binds by name,
# while the same enum is serialized outwards through @JsonValue as a display
# code ("Cortex XSOAR"). The two never round-trip.
SOURCE_TYPE_NAME = "CORTEX_XSOAR"
SOURCE_TYPE_DISPLAY = "Cortex XSOAR"

# Only these sort keys exist in SampleReportRepositoryImpl.COMMON_SORTS. An
# unknown key is NOT rejected: the query silently falls back to
# "ORDER BY update_time DESC", which quietly reverses the order a cursor
# depends on. "createTime" looks valid and is the usual trap.
ALLOWED_SORT_FIELDS = {"reportTime", "updateTime", "sampleReportId", "sampleScore", "size"}


def stored_file_verdict(value: Any) -> str | None:
    """The verdict stored against a file, or None when nobody has set one.

    ``FileDto.fileVerdict`` is not the analysis result: tlab-server writes it
    only through the manual ``POST /files/{sha256|id}/verdict`` routes, and no
    analysis step ever updates it. Its default is UNKNOWN, which next to a
    MALWARE analysis reads as a contradiction, so an unset value is dropped from
    outputs instead of being shown.
    """
    text = str(value or "").strip().upper()
    return None if text in ("", "UNKNOWN") else text


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


def is_terminal(completeness: str, verdict: str) -> bool:
    """Whether polling can stop.

    COMPLETE is always terminal. PARTIALLY_COMPLETE is terminal only when the
    verdict is already actionable — for example when the antivirus fired before
    dynamic analysis finished.
    """
    if completeness == COMPLETENESS_COMPLETE:
        return True
    if completeness == COMPLETENESS_PARTIAL:
        return verdict in ACTIONABLE_VERDICTS
    return False


def verdict_to_dbot_score(verdict: str, unknown_is_benign: bool = False) -> int:
    """Canonical verdict -> DBotScore (0 Unknown, 1 Good, 2 Suspicious, 3 Bad)."""
    if verdict == VERDICT_MALWARE:
        return Common.DBotScore.BAD
    if verdict == VERDICT_SUSPICIOUS:
        return Common.DBotScore.SUSPICIOUS
    if verdict in (VERDICT_OK, VERDICT_CLEAN, VERDICT_WHITELIST):
        return Common.DBotScore.GOOD
    return Common.DBotScore.GOOD if unknown_is_benign else Common.DBotScore.NONE


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


def verdict_to_severity(
    verdict: str,
    score: float = 0.0,
    score_present: bool = False,
    severity_map: dict | None = None,
    escalate_score: float = 0.0,
) -> float:
    """Canonical verdict -> XSOAR severity, with optional escalation."""
    table = severity_map or DEFAULT_SEVERITY_MAP
    # An unmapped verdict must not break the flow: Low is visible in a queue
    # without raising an alarm.
    severity = table.get(verdict, 1)
    if escalate_score and verdict == VERDICT_MALWARE and score_present and score >= escalate_score:
        return 4
    return float(severity)


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
    return datetime.fromtimestamp(number / 1000.0, tz=timezone.utc)


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


def _raise_auth_error(response) -> None:
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
        context = demisto.getIntegrationContext() or {}
        cached = context.get(_TOKEN_CACHE_KEY) or {}
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
        context[_TOKEN_CACHE_KEY] = {
            "value": token,
            "expires_at": parsed.timestamp() if parsed else time.time() + 3600,
        }
        demisto.setIntegrationContext(context)
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
        context = demisto.getIntegrationContext() or {}
        session = context.get(_SESSION_CACHE_KEY) or {}
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
        context[_SESSION_CACHE_KEY] = {
            "owner": self._session_owner(),
            "access": access,
            "refresh": tokens.get("refresh") or "",
            "expires_at": jwt_expiry(access) or time.time() + _FALLBACK_TOKEN_LIFETIME,
        }
        demisto.setIntegrationContext(context)
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
    ):
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

    def _error_handler(self, response) -> None:
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

    def iter_sample_reports(self, page_size: int = 50, max_pages: int = 20, **kwargs) -> Iterator[dict]:
        """Walk pages until a short page, an empty page or max_pages."""
        for page in range(max_pages):
            payload = self.list_sample_reports(page=page, size=page_size, **kwargs)
            content = payload.get("content") or []
            yield from content
            if len(content) < page_size or payload.get("last"):
                return
        demisto.debug(f"tLab: stopped paging at max_pages={max_pages}; more results may exist")

    def get_sample_report(self, sample_report_id: int) -> dict:
        """Full report. Only this endpoint carries dynReportSummary and
        statReportSummary — the public request-status endpoint returns a
        SampleReportShortBean, which has neither."""
        return self.request("GET", f"/sample_reports/{sample_report_id}")

    def get_threat_indicators(self, sample_report_id: int) -> dict:
        return self.request("GET", f"/sample_reports/{sample_report_id}/threat_indicators")

    def get_attack_matrix(self, sample_report_id: int) -> dict:
        return self.request("GET", f"/sample_reports/{sample_report_id}/attack_matrix")

    def get_archive_password(self, sample_report_id: int) -> dict:
        return self.request("GET", f"/sample_reports/{sample_report_id}/archive_password")

    def get_stat_report(self, stat_report_id: int) -> dict:
        return self.request("GET", f"/stat_reports/{stat_report_id}")

    def get_dyn_report(self, dyn_report_id: int) -> dict:
        return self.request("GET", f"/dyn_reports/{dyn_report_id}")

    def get_file_by_hash(self, sha256: str) -> dict:
        return self.request("GET", f"/files/{sha256}")

    def hash_search(self, hash_type: str, hash_part: str) -> Any:
        """Prefix search over stored hashes.

        This is the safe route for an MD5 lookup: ``fileHashMd5`` exists as a
        report filter but is absent from the server's allow-list for the
        company_admin and user roles, so it is silently dropped rather than
        rejected and the query then matches everything.
        """
        return self.request("GET", "/files/hash_search", params={"hashType": hash_type, "hashPart": hash_part})

    def list_indicator_codes(self) -> Any:
        """Catalogue of indicator codes, usable with the report ``indicators`` filter."""
        return self.request("GET", "/report_indicators")

    def whoami(self) -> dict:
        """Identity and role of the token owner — used by test-module."""
        return self.request("GET", "/auth/test")

    def list_sources(self) -> Any:
        return self.request("GET", "/sources")

    def list_env_presets(self, scope: str = "global") -> Any:
        return self.request("GET", f"/ex_env/presets/{scope}")

    # -- public endpoints (no authentication required) -----------------------

    def request_status(self, access_code: str, early_verdict: bool = False) -> dict:
        """Poll a submission. ``/public/**`` needs no credentials at all."""
        params = {"earlyVerdict": "true"} if early_verdict else None
        return self.request("GET", f"/public/request_status/{access_code}", params=params, with_auth=False)

    def request_status_batch(self, access_codes: list) -> Any:
        """Status for many submissions in one call. Body is a bare JSON array."""
        return self._http_request(
            method="POST",
            url_suffix="/public/request_status/batch",
            json_data=access_codes,
            headers={"Accept": "application/json", **self._client_header()},
            resp_type="json",
            error_handler=self._error_handler,
        )

    # -- submission ---------------------------------------------------------

    def submit(
        self,
        analysis_source: str,
        settings: "SubmitSettings",
        file_path: str | None = None,
        file_name: str | None = None,
        url: str | None = None,
        additional_files: list | None = None,
    ) -> dict:
        """POST /analyzes/{file|url}.

        The body is multipart and several keys repeat (``analysisTypes``,
        ``properties[...]``, ``tags[n].name``), so it is built as a list of
        tuples rather than a dict.
        """
        form = settings.to_form()
        if url:
            form.append(("url", url))

        files = None
        handles = []
        try:
            if file_path:
                handle = open(file_path, "rb")  # noqa: SIM115 - closed in finally
                handles.append(handle)
                files = [("analysisFile", (file_name or os.path.basename(file_path), handle))]
                for extra in additional_files or []:
                    extra_handle = open(extra["path"], "rb")  # noqa: SIM115
                    handles.append(extra_handle)
                    files.append(("additionalFiles", (extra["name"], extra_handle)))

            response = self.request(
                "POST",
                f"/analyzes/{analysis_source}",
                data=form,
                files=files,
                timeout=settings.submit_timeout,
            )
        finally:
            for handle in handles:
                handle.close()

        rejection = response.get("rejectionCode")
        status = response.get("analysisRequestStatus")
        if status == REQUEST_STATUS_REJECTED and rejection and rejection not in NON_ERROR_REJECTIONS:
            raise TLabRejection(rejection, response.get("message") or "", response)
        return response

    # -- artifacts ----------------------------------------------------------

    def download(
        self,
        url_suffix: str,
        accept: str,
        max_bytes: int,
        params: Any = None,
        with_auth: bool = True,
        method: str = "GET",
        json_data: Any = None,
        timeout: int | None = None,
    ) -> bytes:
        """Stream a binary artifact, refusing to buffer more than max_bytes.

        ``accept`` is always explicit: DynReportsController has two handlers
        mapped to ``{id}/pcap`` that differ only by ``produces``, so ``*/*``
        resolves in a Spring-version-dependent way.
        """
        response = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            headers=self._build_headers({"Accept": accept}, with_auth=with_auth),
            resp_type="response",
            stream=True,
            timeout=timeout,
            error_handler=self._error_handler,
        )
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if max_bytes and total > max_bytes:
                response.close()
                raise DemistoException(
                    f"The artifact exceeds the configured limit of {max_bytes} bytes. "
                    "Raise the limit in the integration settings or fetch it from the tLab UI."
                )
            chunks.append(chunk)
        return b"".join(chunks)


class SubmitSettings:
    """Form fields of AnalysisSettingsBean.

    Client-side validation exists so that an operator gets a sentence instead of
    a Spring 400 blob.
    """

    MAX_RESEARCH_TIME = 3600
    MAX_PRESET_NAME = 50
    MAX_COMMAND_LINE = 200
    MAX_UAS_SCRIPT = 10000

    def __init__(
        self,
        analysis_types: list | None = None,
        analysis_priority: str = "LOW",
        research_time: int = 120,
        env_preset: str = "",
        user_preset: bool = False,
        enable_network: bool = False,
        create_dump: bool = False,
        enable_acceleration: bool = False,
        enable_antievasion: bool = False,
        use_original_filename: bool = True,
        command_line_args: str = "",
        uas_script: str = "",
        extract_archive: bool = True,
        include_archive_siblings: bool = True,
        archive_password: str = "",
        ignore_whitelist: bool = False,
        static_prefilter: bool = False,
        public_access: bool = False,
        main_filename: str = "",
        tags: list | None = None,
        properties: dict | None = None,
        source_type: str = SOURCE_TYPE_NAME,
        source_uid: str = "",
        submit_timeout: int = 120,
    ):
        # None means "use the default"; an empty list is an operator error.
        self.analysis_types = ["STAT_ANALYSIS", "DYN_ANALYSIS"] if analysis_types is None else list(analysis_types)
        self.analysis_priority = analysis_priority
        self.research_time = int(research_time)
        self.env_preset = env_preset
        self.user_preset = user_preset
        self.enable_network = enable_network
        self.create_dump = create_dump
        self.enable_acceleration = enable_acceleration
        self.enable_antievasion = enable_antievasion
        self.use_original_filename = use_original_filename
        self.command_line_args = command_line_args
        self.uas_script = uas_script
        self.extract_archive = extract_archive
        self.include_archive_siblings = include_archive_siblings
        self.archive_password = archive_password
        self.ignore_whitelist = ignore_whitelist
        self.static_prefilter = static_prefilter
        self.public_access = public_access
        self.main_filename = main_filename
        self.tags = tags or []
        self.properties = properties or {}
        self.source_type = source_type
        self.source_uid = source_uid
        self.submit_timeout = submit_timeout
        self.validate()

    def validate(self) -> None:
        if not self.analysis_types:
            raise DemistoException("At least one analysis type must be selected.")
        if self.research_time > self.MAX_RESEARCH_TIME:
            raise DemistoException(f"research_time must not exceed {self.MAX_RESEARCH_TIME} seconds (tLab Anti-APT limit).")
        if self.research_time <= 0:
            raise DemistoException("research_time must be a positive number of seconds.")
        if len(self.env_preset) > self.MAX_PRESET_NAME:
            raise DemistoException(f"env_preset must not exceed {self.MAX_PRESET_NAME} characters.")
        if len(self.command_line_args) > self.MAX_COMMAND_LINE:
            raise DemistoException(f"command_line_args must not exceed {self.MAX_COMMAND_LINE} characters.")
        if len(self.uas_script) > self.MAX_UAS_SCRIPT:
            raise DemistoException(f"uas_script must not exceed {self.MAX_UAS_SCRIPT} characters.")
        for tag in self.tags:
            if not 2 <= len(str(tag)) <= 150:
                raise DemistoException(f"Each tag must be between 2 and 150 characters: {tag!r}")

    def to_form(self) -> list:
        """Build the multipart body.

        Note that the server mutates the request: AV_ANALYSIS is always added,
        and DYN_ANALYSIS is stripped on a LITE license or the ``mailer`` preset.
        A request asking for dynamic analysis can therefore come back static
        only — commands surface that as RequestedButNotRun.
        """
        form: list[tuple[str, Any]] = []
        for analysis_type in self.analysis_types:
            form.append(("analysisTypes", analysis_type))
        form.append(("analysisPriority", self.analysis_priority))
        form.append(("dynAnalysisSettings.researchTime", str(self.research_time)))
        if self.env_preset:
            form.append(("dynAnalysisSettings.envPresetName", self.env_preset))
        form.extend(
            [
                ("dynAnalysisSettings.userPreset", _bool(self.user_preset)),
                ("dynAnalysisSettings.enableNetwork", _bool(self.enable_network)),
                ("dynAnalysisSettings.createDump", _bool(self.create_dump)),
                ("dynAnalysisSettings.enableAcceleration", _bool(self.enable_acceleration)),
                ("dynAnalysisSettings.enableAntievasion", _bool(self.enable_antievasion)),
                ("dynAnalysisSettings.useOriginalFilename", _bool(self.use_original_filename)),
                ("extractArchive", _bool(self.extract_archive)),
                ("includeArchiveSiblings", _bool(self.include_archive_siblings)),
                ("ignoreWhitelist", _bool(self.ignore_whitelist)),
                ("staticPrefilter", _bool(self.static_prefilter)),
                ("publicAccess", _bool(self.public_access)),
            ]
        )
        if self.command_line_args:
            form.append(("dynAnalysisSettings.commandLineArgs", self.command_line_args))
        if self.uas_script:
            form.append(("dynAnalysisSettings.uasScript", self.uas_script))
        if self.archive_password:
            form.append(("archiveSettings.password", self.archive_password))
        if self.main_filename:
            form.append(("mainFilename", self.main_filename))
        if self.source_type:
            form.append(("source.sourceType", self.source_type))
        if self.source_uid:
            form.append(("source.sourceUid", self.source_uid))
        for index, tag in enumerate(self.tags):
            form.append((f"tags[{index}].name", str(tag)))
        for key, value in self.properties.items():
            form.append((f"properties[{key}]", str(value)))
        return form


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


def _bool(value: Any) -> str:
    return "true" if value else "false"


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


HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def hash_type_of(value: str) -> str:
    """Return md5, sha1 or sha256 for a full hex hash, or '' when it is neither.

    Partial hashes are refused on purpose: the server's hash filters are prefix
    matches, so a short value would quietly match unrelated samples.
    """
    candidate = (value or "").strip().lower()
    if not candidate or any(c not in "0123456789abcdef" for c in candidate):
        return ""
    return HASH_LENGTHS.get(len(candidate), "")


def report_matches_hash(report: dict, hash_type: str, expected: str) -> bool:
    """Verify a report really belongs to the requested hash.

    Two server behaviours make this necessary: the hash filters are prefix
    matches OR'd against the archive's own hash, and filters outside the
    role allow-list are silently ignored rather than rejected. Either one can
    return a report for a different sample.
    """
    file_dto = report.get("file") or {}
    actual = str(file_dto.get({"md5": "hashMd5", "sha1": "hashSha1", "sha256": "hashSha256"}[hash_type]) or "")
    return actual.lower() == (expected or "").lower()


def select_main_report(reports: list) -> dict | None:
    """Pick the report a submission is really about.

    A submission can yield several reports: archive members plus cached linked
    reports. Prefer an explicit MAIN type, then a root report, then the highest
    score, then the lowest id so the choice is stable.
    """
    if not reports:
        return None
    main = [r for r in reports if r.get("sampleReportType") == REPORT_TYPE_MAIN]
    if main:
        return sorted(main, key=lambda r: r.get("sampleReportId") or 0)[0]
    roots = [r for r in reports if not r.get("parentReportId")]
    pool = roots or reports
    return sorted(pool, key=lambda r: (-(r.get("sampleScore") or -1), r.get("sampleReportId") or 0))[0]


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------
def supports_scheduled_commands() -> bool:
    """Scheduled commands need server 6.2.0."""
    try:
        return ScheduledCommand.supports_polling()
    except Exception:  # noqa: BLE001 - older servers raise rather than return False
        return False


def schedule_next_poll(command: str, args: dict, interval: int, timeout: int) -> ScheduledCommand:
    """Build the follow-up run of a polling command."""
    next_args = dict(args)
    next_args["polling"] = True
    return ScheduledCommand(
        command=command,
        next_run_in_seconds=interval,
        args=next_args,
        timeout_in_seconds=timeout,
    )


def blocking_poll(check, interval: int, timeout: int):
    """Fallback for servers below 6.2.0 that cannot schedule commands.

    This holds an engine worker for the duration, which is why callers cap the
    timeout and the documentation steers 6.0 users towards submit plus a
    separate status command.
    """
    deadline = time.time() + timeout
    while True:
        done, result = check()
        if done:
            return result
        if time.time() + interval >= deadline:
            raise DemistoException(
                f"Timed out after {timeout} seconds waiting for the tLab Anti-APT verdict. "
                "The analysis may still be running; query it later with the status command."
            )
        time.sleep(interval)


# ---------------------------------------------------------------------------
# End of the shared tLab Anti-APT client.
# ---------------------------------------------------------------------------


# Vendored from https://data.iana.org/TLD/tlds-alpha-by-domain.txt (version 2026093000).
#
# The list is embedded rather than downloaded because the pack must install in
# air-gapped networks, and a separate data file would not survive the unify step
# that turns this integration into a single YAML.
#
# Without it, domain typing is unusable: "kernel32.dll" and "setup.exe" satisfy
# every naive FQDN grammar, and a feed that emits those as domains poisons TIM.
# Refresh with:
#     curl -sfL https://data.iana.org/TLD/tlds-alpha-by-domain.txt \
#       | grep -v '^#' | tr 'A-Z' 'a-z' | sort | tr '\n' ' '
_TLD_DATA = (
    "aaa aarp abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco "
    "actor ad ads adult ae aeg aero aetna af afl africa ag agakhan agency ai aig airbus airforce airtel "
    "akdn al alibaba alipay allfinanz allstate ally alsace alstom am amazon americanexpress "
    "americanfamily amex amfam amica amsterdam analytics android anquan anz ao aol apartments app apple "
    "aq aquarelle ar arab aramco archi army arpa art arte as asda asia associates at athleta attorney au "
    "auction audi audible audio auspost author auto autos aw aws ax axa az azure ba baby baidu banamex "
    "band bank bar barcelona barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb "
    "bbc bbt bbva bcg bcn bd be beats beauty beer berlin best bestbuy bet bf bg bh bharti bi bible bid "
    "bike bing bingo bio biz bj black blackfriday blockbuster blog bloomberg blue bm bms bmw bn "
    "bnpparibas bo boats boehringer bofa bom bond boo book booking bosch bostik boston bot boutique box "
    "br bradesco bridgestone broadway broker brother brussels bs bt build builders business buy buzz bv "
    "bw by bz bzh ca cab cafe cal call calvinklein cam camera camp canon capetown capital capitalone car "
    "caravan cards care career careers cars casa case cash casino cat catering catholic cba cbn cbre cc "
    "cd center ceo cern cf cfa cfd cg ch chanel channel charity chase chat cheap chintai christmas chrome "
    "church ci cipriani circle cisco citadel citi citic city ck cl claims cleaning click clinic clinique "
    "clothing cloud club clubmed cm cn co coach codes coffee college cologne com commbank community "
    "company compare computer comsec condos construction consulting contact contractors cooking cool coop "
    "corsica country coupon coupons courses cpa cr credit creditcard creditunion cricket crown crs cruise "
    "cruises cu cuisinella cv cw cx cy cymru cyou cz dad dance data date dating datsun day dclk dds de "
    "deal dealer deals degree delivery dell deloitte delta democrat dental dentist desi design dev dhl "
    "diamonds diet digital direct directory discount discover dish diy dj dk dm dnp do docs doctor dog "
    "domains dot download drive dtv dubai dupont durban dvag dvr dz earth eat ec eco edeka edu education "
    "ee eg email emerck energy engineer engineering enterprises epson equipment er ericsson erni es esq "
    "estate et eu eurovision eus events exchange expert exposed express extraspace fage fail fairwinds "
    "faith family fan fans farm farmers fashion fast fedex feedback ferrari ferrero fi fidelity fido film "
    "final finance financial fire firestone firmdale fish fishing fit fitness fj fk flickr flights flir "
    "florist flowers fly fm fo foo food football ford forex forsale forum foundation fox fr free "
    "fresenius frl frogans frontier ftr fujitsu fun fund furniture futbol fyi ga gal gallery gallo gallup "
    "game games gap garden gay gb gbiz gd gdn ge gea gent genting george gf gg ggee gh gi gift gifts "
    "gives giving gl glass gle global globo gm gmail gmbh gmo gmx gn godaddy gold goldpoint golf goodyear "
    "goog google gop got gov gp gq gr grainger graphics gratis green gripe grocery group gs gt gu gucci "
    "guge guide guitars guru gw gy hair hamburg hangout haus hbo hdfc hdfcbank health healthcare help "
    "helsinki here hermes hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday homedepot "
    "homegoods homes homesense honda horse hospital host hosting hot hotels hotmail house how hr hsbc ht "
    "hu hughes hyatt hyundai ibm icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in "
    "inc industries infiniti info ing ink institute insurance insure int international intuit investments "
    "io ipiranga iq ir irish is ismaili ist istanbul it itau itv jaguar java jcb je jeep jetzt jewelry "
    "jio jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos juniper kaufen kddi ke kerryhotels "
    "kerryproperties kfh kg kh ki kia kids kim kindle kitchen kiwi km kn koeln komatsu kosher kp kpmg kpn "
    "kr krd kred kuokgroup kw ky kyoto kz la lacaixa lamborghini lamer land landrover lanxess lasalle lat "
    "latino latrobe law lawyer lb lc lds lease leclerc lefrak legal lego lexus lgbt li lidl life "
    "lifeinsurance lifestyle lighting like lilly limited limo lincoln link live living lk llc llp loan "
    "loans locker locus lol london lotte lotto love lpl lplfinancial lr ls lt ltd ltda lu lundbeck luxe "
    "luxury lv ly ma madrid maif maison makeup man management mango map market marketing markets marriott "
    "marshalls mattel mba mc mckinsey md me med media meet melbourne meme memorial men menu merck "
    "merckmsd mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma mn mo mobi mobile "
    "moda moe moi mom monash money monster mormon mortgage moscow moto motorcycles mov movie mp mq mr ms "
    "msd mt mtn mtr mu museum music mv mw mx my mz na nab nagoya name navy nba nc ne nec net netbank "
    "netflix network neustar new news next nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja "
    "nissan nissay nl no nokia norton now nowruz nowtv np nr nra nrw ntt nu nyc nz obi observer office "
    "okinawa olayan olayangroup ollo om omega one ong onl online ooo open oracle orange org organic "
    "origins osaka otsuka ott ovh pa page panasonic paris pars partners parts party pay pccw pe pet pf "
    "pfizer pg ph pharmacy phd philips phone photo photography photos physio pics pictet pictures pid pin "
    "ping pink pioneer pizza pk pl place play playstation plumbing plus pm pn pnc pohl poker politie porn "
    "post pr praxi press prime pro prod productions prof progressive promo properties property protection "
    "pru prudential ps pt pub pw pwc py qa qpon quebec quest racing radio re read realestate realtor "
    "realty recipes red redumbrella rehab reise reisen reit reliance ren rent rentals repair report "
    "republican rest restaurant review reviews rexroth rich richardli ricoh ril rio rip ro rocks rodeo "
    "rogers room rs rsvp ru rugby ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon "
    "samsclub samsung sandvik sandvikcoromant sanofi sap sarl sas save saxo sb sbi sbs sc scb schaeffler "
    "schmidt scholarships school schule schwarz science scot sd se search seat secure security seek "
    "select sener services seven sew sex sexy sfr sg sh shangrila sharp shell shia shiksha shoes shop "
    "shopping shouji show si silk sina singles site sj sk ski skin sky skype sl sling sm smart smile sn "
    "sncf so soccer social softbank software sohu solar solutions song sony soy spa space sport spot sr "
    "srl ss st stada staples star statebank statefarm stc stcgroup stockholm storage store stream studio "
    "study style su sucks supplies supply support surf surgery suzuki sv swatch swiss sx sy sydney "
    "systems sz tab taipei talk taobao target tatamotors tatar tattoo tax taxi tc tci td tdk team tech "
    "technology tel temasek tennis teva tf tg th thd theater theatre tiaa tickets tienda tips tires tirol "
    "tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray toshiba total tours town "
    "toyota toys tr trade trading training travel travelers travelersinsurance trust trv tt tube tui "
    "tunes tushu tv tvs tw tz ua ubank ubs ug uk unicom university uno uol ups us uy uz va vacations vana "
    "vanguard vc ve vegas ventures verisign versicherung vet vg vi viajes video vig viking villas vin vip "
    "virgin visa vision viva vivo vlaanderen vn vodka volvo vote voting voto voyage vu wales walmart "
    "walter wang wanggou watch watches weather weatherchannel web webcam weber website wed wedding weibo "
    "weir wf whoswho wien wiki williamhill win windows wine winners wme woodside work works world wow ws "
    "wtc wtf xbox xerox xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a xn--2scrj9c xn--30rr7y xn--3bst00m "
    "xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--3pxu8k xn--42c2d9a xn--45br5cyl xn--45brj9c xn--45q11c "
    "xn--4dbrk0ce xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g "
    "xn--6frz82g xn--6qq986b3xl xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg "
    "xn--8y0a063a xn--90a3ac xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd "
    "xn--bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b xn--cckwcxetd xn--cg4bki xn--clchc0ea0b2g2a9gcd "
    "xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf xn--e1a4c xn--eckvdtc9d xn--efvy88h "
    "xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--fiqz9s xn--fjq720a xn--flw351e "
    "xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gecrj9c xn--gk3at1e "
    "xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i "
    "xn--j1aef xn--j1amh xn--j6w193g xn--jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d "
    "xn--kput3i xn--l1acc xn--lgbbat1ad8j xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a "
    "xn--mgbaam7a8h xn--mgbab2bd xn--mgbah1a3hjkrd xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbbh1a "
    "xn--mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo xn--mgbcpq6gpa1a xn--mgberp4a5d4ar xn--mgbgu82a "
    "xn--mgbi4ecexp xn--mgbpl2fh xn--mgbt3dhd xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f xn--mk1bu44c "
    "xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--node xn--nqv7f xn--nqv7fs00ema xn--nyqy26a "
    "xn--o3cw4h xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--pgbs0dh xn--pssy2u xn--q7ce6a xn--q9jyb4c "
    "xn--qcka1pmc xn--qxa6a xn--qxam xn--rhqv96g xn--rovu88b xn--rvc1e0am3e xn--s9brj9c xn--ses554g "
    "xn--t60b56a xn--tckwe xn--tiq49xqyj xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb "
    "xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a xn--xhq521b "
    "xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz yachts "
    "yahoo yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zm zone "
    "zuerich zw"
)
TLD_SET = frozenset(_TLD_DATA.split())

# Suffixes that are simultaneously real TLDs and common file extensions. Only
# these six actually need a decision — every other extension fails the TLD check
# on its own, so listing it here would just be noise.
#
# Each choice is made for SANDBOX observable data specifically:
#   zip, cab  archives dominate; the gTLDs exist but are barely used
#   sh, py    install.sh and script.py against Saint Helena and Paraguay
#   so        lib.so against Somalia
#
# ".com" is deliberately ABSENT. It is the most common TLD in the world, and
# DOS .com executables are a historical rarity; rejecting it would silently
# drop the majority of real C2 domains.
TLD_FILE_EXTENSION_COLLISIONS = frozenset({"cab", "py", "sh", "so", "zip"})

# ThreatEvidenceCollectors truncates observable values at this length, so a
# value of exactly this size is probably cut mid-token and cannot be trusted.
MAX_VALUE_LENGTH = 300

# A sandbox VM's traffic is overwhelmingly RFC1918 plus link-local and
# multicast noise. Emitting that as threat intel is actively harmful.
DEFAULT_EXCLUDED_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "0.0.0.0/8",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

RE_URL = re.compile(r"^[a-z][a-z0-9+.\-]*://\S+$", re.I)
RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
RE_MD5 = re.compile(r"^[0-9a-f]{32}$", re.I)
RE_SHA1 = re.compile(r"^[0-9a-f]{40}$", re.I)
RE_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)
RE_REGISTRY = re.compile(r"^HK(EY_)?(LM|CU|CR|U|CC|LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\/]", re.I)
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")

# Object kinds that are not indicators.
#   FILE    - file NAMES, not hashes. Emitting them as File indicators would
#             poison TIM with values nothing can ever match.
#   PROCESS - process image names such as svchost.exe.
#   SIGNATURE - antivirus signature names, which have no XSOAR indicator type.
NON_INDICATOR_KINDS = {"FILE", "PROCESS", "SIGNATURE"}

# ATT&CK techniques are a Threat Intel *object*, not a member of
# FeedIndicatorType. Using ATTACK_PATTERN_TYPE raises
# AttributeError at runtime; the type name lives under ThreatIntel.
ATTACK_PATTERN_TYPE = ThreatIntel.ObjectsNames.ATTACK_PATTERN

OUTPUT_INDICATOR = "TLabAntiAPT.Indicator"
BATCH_SIZE = 2000


# --------------------------------------------------------------------------
# Typing
# --------------------------------------------------------------------------
def type_value(value: str, excluded_networks: list, allow_private: bool = False) -> str | None:
    """Classify a free-form observable, or return None when it cannot be trusted.

    The cascade is anchored and ordered most-specific first. Anything that does
    not match cleanly is dropped: a wrong indicator costs an analyst more than
    a missing one.
    """
    candidate = (value or "").strip()
    if not candidate:
        return None
    # A value at the server's truncation limit is probably cut mid-token.
    if len(candidate) >= MAX_VALUE_LENGTH:
        return None
    # Whitespace means a sentence or a command line, not an observable — unless
    # the whole thing is a URL, which cannot contain spaces anyway.
    if any(ch.isspace() for ch in candidate) and not RE_URL.match(candidate):
        return None

    ip_type = _ip_type(candidate, excluded_networks, allow_private)
    if ip_type is not None:
        return ip_type or None

    if RE_URL.match(candidate):
        return FeedIndicatorType.URL
    if RE_EMAIL.match(candidate):
        return FeedIndicatorType.Email
    if RE_SHA256.match(candidate):
        return FeedIndicatorType.File
    if RE_SHA1.match(candidate):
        return FeedIndicatorType.File
    if RE_MD5.match(candidate):
        return FeedIndicatorType.File
    if RE_REGISTRY.match(candidate):
        return FeedIndicatorType.Registry
    if _is_domain(candidate):
        return FeedIndicatorType.Domain
    return None


def _ip_type(candidate: str, excluded_networks: list, allow_private: bool) -> str | None:
    """Return the IP indicator type, '' when the address is excluded, or None
    when the value is not an address at all."""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if not allow_private and _is_excluded(address, excluded_networks):
        return ""
    return FeedIndicatorType.IPv6 if address.version == 6 else FeedIndicatorType.IP


def _is_excluded(address: ipaddress.IPv4Address | ipaddress.IPv6Address, excluded_networks: list) -> bool:
    for network in excluded_networks:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            demisto.debug(f"tLab feed: ignoring malformed excluded network {network!r}")
    return False


def _is_domain(candidate: str) -> bool:
    """A hostname is a domain only if its last label is a real TLD and not a
    file extension.

    Both checks are required. Without the TLD list, "kernel32.dll" passes the
    grammar; without the collision list, "payload.zip" and "install.sh" pass too,
    because .zip and .sh are genuine TLDs.
    """
    if "\\" in candidate or not RE_DOMAIN.match(candidate):
        return False
    last_label = candidate.rsplit(".", 1)[-1].lower()
    if last_label in TLD_FILE_EXTENSION_COLLISIONS:
        return False
    return last_label in TLD_SET


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
def sample_file_indicator(report: dict, params: dict, report_url: str = "") -> dict | None:
    """The analyzed sample itself, which anchors every relationship."""
    file_dto = report.get("file") or {}
    sha256 = file_dto.get("hashSha256")
    if not sha256:
        return None
    suspicious_from, malicious_from = score_thresholds(params)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)

    fields = {
        "md5": file_dto.get("hashMd5"),
        "sha1": file_dto.get("hashSha1"),
        "sha256": sha256,
        "size": file_dto.get("size"),
        "filetype": file_dto.get("fileType"),
        "firstseenbysource": epoch_to_iso(report.get("createTime")),
        "lastseenbysource": epoch_to_iso(report.get("updateTime")),
        "tlabsamplereportid": report.get("sampleReportId"),
        "tlabverdict": verdict,
        "tlabreporturl": report_url or None,
    }
    if present:
        fields["tlabscore"] = score
    classifier = report.get("malwareClassifierResult") or {}
    if classifier.get("primaryType"):
        fields["malwarefamily"] = classifier["primaryType"]
    if report.get("uploadedFilename"):
        fields["associatedfilenames"] = [report["uploadedFilename"]]

    return {
        "value": sha256,
        "type": FeedIndicatorType.File,
        "rawJSON": {"service": "tLab Anti-APT", "sample_report_id": report.get("sampleReportId"), "verdict": verdict},
        "score": verdict_to_dbot_score(verdict),
        "fields": remove_empty_elements(fields),
    }


def extract_from_threat_indicators(
    payload: dict, params: dict, min_level: str, excluded_networks: list
) -> tuple[list, list, list]:
    """Mine observables out of the aggregated threat indicator response."""
    levels = _levels_at_or_above(min_level)
    include_filenames = param_bool(params, "include_filenames")
    allow_private = param_bool(params, "include_private_addresses")

    found: dict[tuple, dict] = {}
    signatures: list = []
    filenames: list = []

    for indicator in payload.get("indicators") or []:
        level = str(indicator.get("level") or "").upper()
        if level not in levels:
            continue
        title = indicator.get("title") or indicator.get("key") or ""
        source = indicator.get("source") or ""

        for obj in indicator.get("objects") or []:
            kind = str(obj.get("kind") or "").upper()
            name = obj.get("name") or ""
            if kind in NON_INDICATOR_KINDS:
                if kind == "SIGNATURE" and name:
                    signatures.append(name)
                elif kind == "FILE" and name and include_filenames:
                    filenames.append(name)
                continue
            indicator_type = type_value(name, excluded_networks, allow_private)
            if not indicator_type:
                continue
            key = (indicator_type, name.strip().lower())
            if key in found:
                continue
            found[key] = {
                "value": name.strip(),
                "type": indicator_type,
                "rawJSON": {
                    "service": "tLab Anti-APT",
                    "source": source,
                    "level": level,
                    "title": title,
                    "analysis_type": indicator.get("analysisType"),
                },
                "score": _level_to_score(level),
                "fields": remove_empty_elements(
                    {
                        "tlabverdict": _level_to_verdict(level),
                        "description": title or None,
                    }
                ),
            }

        for technique in indicator.get("attack") or []:
            if not RE_ATTACK.match(str(technique)):
                continue
            key = (ATTACK_PATTERN_TYPE, str(technique).lower())
            found.setdefault(
                key,
                {
                    "value": str(technique),
                    "type": ATTACK_PATTERN_TYPE,
                    "rawJSON": {"service": "tLab Anti-APT", "technique": technique},
                    "fields": {},
                },
            )

    return list(found.values()), signatures, filenames


def extract_attack_patterns(matrix: dict) -> list:
    """ATT&CK techniques from the dedicated endpoint.

    Preferred over the raw ids embedded in threat indicators, because this
    response already resolves revoked techniques and carries names and links.
    """
    out = []
    for technique in matrix.get("techniques") or []:
        technique_id = str(technique.get("id") or "")
        if not RE_ATTACK.match(technique_id):
            continue
        out.append(
            {
                "value": technique_id,
                "type": ATTACK_PATTERN_TYPE,
                "rawJSON": {"service": "tLab Anti-APT", "technique": technique},
                "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
                "fields": remove_empty_elements(
                    {
                        "description": technique.get("description") or technique.get("name"),
                        "publications": [{"link": technique.get("url"), "title": technique.get("name")}]
                        if technique.get("url")
                        else None,
                    }
                ),
            }
        )
    return out


def build_relationships(sample_sha256: str, indicators: list, enabled: bool) -> None:
    """Attach relationships from the sample to everything seen with it.

    Relationships require server 6.2.0, so this degrades to a no-op rather than
    failing the fetch on an older instance.
    """
    if not enabled or not sample_sha256 or not supports_relationships():
        return
    for indicator in indicators:
        name = _relationship_name(indicator["type"])
        if not name:
            continue
        relationship = EntityRelationship(
            name=name,
            entity_a=sample_sha256,
            entity_a_type=FeedIndicatorType.File,
            entity_b=indicator["value"],
            entity_b_type=indicator["type"],
            source_reliability=None,
            brand="tLab Anti-APT",
        )
        indicator.setdefault("relationships", []).append(relationship.to_indicator())


def _relationship_name(indicator_type: str) -> str | None:
    if indicator_type == ATTACK_PATTERN_TYPE:
        return EntityRelationship.Relationships.USES
    if indicator_type in (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.Domain, FeedIndicatorType.URL):
        return EntityRelationship.Relationships.COMMUNICATES_WITH
    if indicator_type == FeedIndicatorType.File:
        return EntityRelationship.Relationships.DROPS
    return EntityRelationship.Relationships.RELATED_TO


def supports_relationships() -> bool:
    try:
        return is_demisto_version_ge("6.2.0")
    except Exception:  # noqa: BLE001 - older servers raise instead of returning False
        return False


_LEVEL_ORDER = ["INFO", "SUSPICIOUS", "MALICIOUS"]


def _levels_at_or_above(minimum: str) -> set:
    minimum = (minimum or "SUSPICIOUS").upper()
    if minimum not in _LEVEL_ORDER:
        minimum = "SUSPICIOUS"
    return set(_LEVEL_ORDER[_LEVEL_ORDER.index(minimum) :])


def _level_to_score(level: str) -> int:
    return {"MALICIOUS": Common.DBotScore.BAD, "SUSPICIOUS": Common.DBotScore.SUSPICIOUS}.get(
        level.upper(), Common.DBotScore.NONE
    )


def _level_to_verdict(level: str) -> str:
    return {"MALICIOUS": VERDICT_MALWARE, "SUSPICIOUS": VERDICT_SUSPICIOUS}.get(level.upper(), VERDICT_UNKNOWN)


# --------------------------------------------------------------------------
# Cursor
# --------------------------------------------------------------------------
# The sandbox has no "updatedSince" filter and completes analyses out of id
# order, so a single cursor cannot be correct:
#
#   an id cursor alone loses reports that finish after a higher id already did
#   an updateTime cursor alone cannot be filtered server-side
#
# So the fetch runs two passes, exactly like the Go push service. Duplicates
# between them are not a problem: TIM merges indicators by value, and feeds are
# expected to re-submit what they already sent.
def discovery_page(client: TLabClient, cursor: int, size: int, params: dict) -> dict:
    """New reports, oldest first, so the cursor can advance monotonically."""
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="sampleReportId,asc",
        min_report_id=cursor,
        completeness=_completeness_filter(params),
        root_only=True,
    )


def maturation_page(client: TLabClient, lookback_hours: int, size: int, params: dict) -> dict:
    """Reports touched recently, to catch analyses that completed late."""
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, lookback_hours))
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="updateTime,desc",
        date_from=since.strftime(TLAB_DATE_FORMAT),
        completeness=_completeness_filter(params),
        root_only=True,
    )


def param_bool(params: dict, key: str, default: bool = False) -> bool:
    """``params.get(key) or default`` silently ignores an explicit false when
    the default is true, so the flag becomes unsettable. Read it explicitly."""
    value = params.get(key)
    if value is None or value == "":
        return default
    try:
        return argToBoolean(value)
    except ValueError:
        return default


def _completeness_filter(params: dict) -> list:
    """Only harvest analyses that are actually finished.

    A PARTIALLY_COMPLETE report still has stages running, and its observables
    are a snapshot that will change. Emitting them produces indicators whose
    verdict contradicts the finished report minutes later.
    """
    return ["COMPLETE"] if not param_bool(params, "include_partial") else ["COMPLETE", "PARTIALLY_COMPLETE"]


def next_cursor(reports: list, current: int) -> int:
    """Advance past the highest id seen; never move backwards."""
    highest = current
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        highest = max(highest, report_id + 1)
    return highest


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------
def collect_from_report(client: TLabClient, report: dict, params: dict, excluded_networks: list) -> list:
    """Every indicator derived from one sample report, with relationships."""
    report_id = arg_to_number(report.get("sampleReportId"))
    if report_id is None:
        return []

    min_level = params.get("min_indicator_level") or "SUSPICIOUS"
    indicators: list = []

    sample = sample_file_indicator(report, params, _report_url(params, report_id))
    if sample:
        indicators.append(sample)

    observables: list = []
    try:
        payload = client.get_threat_indicators(report_id)
        observables, signatures, filenames = extract_from_threat_indicators(payload, params, min_level, excluded_networks)
        if sample and (signatures or filenames):
            _annotate_sample(sample, signatures, filenames)
    except Exception as exc:  # noqa: BLE001 - one bad report must not sink the fetch
        demisto.debug(f"[Fetch] Threat indicators failed for report {report_id}: {exc}")

    if param_bool(params, "fetch_attack_patterns"):
        try:
            observables.extend(extract_attack_patterns(client.get_attack_matrix(report_id)))
        except Exception as exc:  # noqa: BLE001
            demisto.debug(f"[Fetch] Attack matrix failed for report {report_id}: {exc}")

    build_relationships(
        (report.get("file") or {}).get("hashSha256") or "",
        observables,
        param_bool(params, "create_relationships", True),
    )
    indicators.extend(observables)
    return indicators


def _annotate_sample(sample: dict, signatures: list, filenames: list) -> None:
    """Signature and file names have no indicator type, so they enrich the sample."""
    if signatures:
        sample["fields"]["tlabsignatures"] = sorted(set(signatures))
    if filenames:
        existing = sample["fields"].get("associatedfilenames") or []
        sample["fields"]["associatedfilenames"] = sorted(set(existing) | set(filenames))


def _report_url(params: dict, report_id: int) -> str:
    base = (params.get("url") or "").rstrip("/")
    return f"{base}/reports/{report_id}" if base else ""


def decorate(indicators: list, params: dict) -> list:
    """Apply the feed-wide fields XSOAR expects every feed to set."""
    tags = argToList(params.get("feedTags"))
    tlp = params.get("tlp_color")
    for indicator in indicators:
        fields = indicator.setdefault("fields", {})
        if tags:
            fields["tags"] = tags
        if tlp:
            fields["trafficlightprotocol"] = tlp
    return indicators


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def fetch_indicators(client: TLabClient, params: dict, preview: bool = False) -> tuple[list, int]:
    """Both cursor passes, deduplicated by (type, value). Returns the new cursor."""
    context = demisto.getIntegrationContext() or {}
    # first_report_id is a floor: raising it takes effect on the next fetch
    # even after fetching has started, and only ever moves the cursor forward.
    floor = arg_to_number(params.get("first_report_id")) or 0
    cursor = max(arg_to_number(context.get("report_cursor")) or 0, floor)
    page_size = arg_to_number(params.get("max_reports_per_fetch")) or 50
    excluded_networks = argToList(params.get("excluded_networks")) or DEFAULT_EXCLUDED_NETWORKS

    reports: dict[int, dict] = {}
    discovery = discovery_page(client, cursor, page_size, params)
    for report in discovery.get("content") or []:
        report_id = arg_to_number(report.get("sampleReportId"))
        if report_id is not None:
            reports[report_id] = report
    advanced = next_cursor(list(reports.values()), cursor)

    lookback = lookback_hours(params)
    if lookback and not preview:
        for report in maturation_page(client, lookback, page_size, params).get("content") or []:
            report_id = arg_to_number(report.get("sampleReportId"))
            # Only reports the discovery pass already walked past — anything
            # newer it will pick up on its own next run.
            if report_id is not None and report_id not in reports and floor <= report_id < cursor:
                reports[report_id] = report

    collected: dict[tuple, dict] = {}
    for report in sorted(reports.values(), key=lambda r: arg_to_number(r.get("sampleReportId")) or 0):
        for indicator in collect_from_report(client, report, params, excluded_networks):
            key = (indicator["type"], str(indicator["value"]).lower())
            if key in collected:
                _merge(collected[key], indicator)
            else:
                collected[key] = indicator

    return decorate(list(collected.values()), params), advanced


def _merge(existing: dict, incoming: dict) -> None:
    """Keep the worst verdict and union the relationships across reports."""
    if incoming.get("score", 0) > existing.get("score", 0):
        existing["score"] = incoming["score"]
        verdict = incoming.get("fields", {}).get("tlabverdict")
        if verdict:
            existing.setdefault("fields", {})["tlabverdict"] = verdict
    if incoming.get("relationships"):
        existing.setdefault("relationships", []).extend(incoming["relationships"])


def fetch_indicators_command(client: TLabClient, params: dict) -> None:
    previous = (demisto.getIntegrationContext() or {}).get("report_cursor")
    demisto.debug(f"[Fetch] Starting fetch cycle with report_cursor={previous}")
    indicators, cursor = fetch_indicators(client, params)
    for start in range(0, len(indicators), BATCH_SIZE):
        demisto.createIndicators(indicators[start : start + BATCH_SIZE])
    # Only after the batches are accepted, so a failure mid-way re-fetches
    # instead of silently skipping the window.
    merge_integration_context(report_cursor=cursor)
    demisto.info(f"[Fetch] Completed fetch cycle: {len(indicators)} indicators, cursor now {cursor}")


def get_indicators_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Manual preview. Deliberately does not create indicators or move the cursor."""
    limit = arg_to_number(args.get("limit")) or 10
    indicators, _ = fetch_indicators(client, params, preview=True)
    indicators = indicators[:limit]

    rows = [
        {
            "Value": indicator["value"],
            "Type": indicator["type"],
            "Verdict": indicator.get("fields", {}).get("tlabverdict", ""),
            "Source": indicator.get("rawJSON", {}).get("source", ""),
            "Description": indicator.get("fields", {}).get("description", ""),
        }
        for indicator in indicators
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_INDICATOR,
        outputs_key_field="Value",
        outputs=indicators or None,
        raw_response=indicators,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT indicators ({len(rows)})",
            rows,
            headers=["Value", "Type", "Verdict", "Source", "Description"],
            removeNull=True,
        )
        if rows
        else "No indicators found.",
    )


def reset_cursor_command() -> CommandResults:
    merge_integration_context(report_cursor=None)
    return CommandResults(readable_output="Fetch cursor reset. The next fetch starts from the configured first report id.")


def test_module_command(client: TLabClient, params: dict) -> str:
    client.list_sample_reports(page=0, size=1, sort="sampleReportId,asc")
    for network in argToList(params.get("excluded_networks")) or []:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise DemistoException(f"Excluded networks: '{network}' is not a valid CIDR block.") from None
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
        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)
        elif command == "tlab-get-indicators":
            return_results(get_indicators_command(client, args, params))
        elif command == "tlab-feed-reset-cursor":
            return_results(reset_cursor_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
