"""tLab Anti-APT Sandbox integration for Cortex XSOAR.

Submits files and URLs for analysis, waits for a verdict and pulls the
resulting reports and artifacts into the war room.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
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


OUTPUT_ANALYSIS = "TLabAntiAPT.Analysis"
OUTPUT_SUBMISSION = "TLabAntiAPT.Submission"
OUTPUT_REPORT = "TLabAntiAPT.Report"
OUTPUT_THREAT = "TLabAntiAPT.ThreatIndicator"
OUTPUT_ATTACK = "TLabAntiAPT.AttackMatrix"
OUTPUT_PRESET = "TLabAntiAPT.EnvPreset"
OUTPUT_SOURCE = "TLabAntiAPT.Source"

# Polling defaults. The blocking fallback used on servers below 6.2.0 holds an
# engine worker, so it is capped far lower than the scheduled path.
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 1800
BLOCKING_TIMEOUT_CAP = 600


# --------------------------------------------------------------------------
# Output shaping
# --------------------------------------------------------------------------
def analysis_outputs(report: dict, params: dict, access_code: str = "", request_status: str | None = "") -> dict:
    """Normalize a report into the TLabAntiAPT.Analysis context object."""
    file_dto = report.get("file") or {}
    score, score_present = score_value(report)
    verdict = canonical_verdict(
        report,
        suspicious_from=score_thresholds(params)[0],
        malicious_from=score_thresholds(params)[1],
        early_verdict=argToBoolean(params.get("early_verdict") or False),
    )
    classifier = report.get("malwareClassifierResult") or {}

    outputs = {
        "AccessCode": access_code or None,
        "AnalysisRequestId": report.get("analysisRequestId"),
        "AnalysisRequestStatus": request_status or None,
        "SampleReportId": report.get("sampleReportId"),
        "SampleReportType": report.get("sampleReportType"),
        "Completeness": report.get("sampleReportCompleteness"),
        "Score": score if score_present else None,
        "MaxScore": report.get("maxSampleReportScore"),
        # Both raw enumerations are kept: an analyst must be able to see what
        # the server actually said, not only our canonical value.
        "ScoreLevel": report.get("verdict"),
        # Set by hand in tLab; absent while nobody has set it.
        "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
        "Verdict": verdict,
        "DBotScore": verdict_to_dbot_score(verdict),
        "Whitelisted": bool(report.get("whitelisted")),
        "DetectedByAv": bool((report.get("avReportSummary") or {}).get("detected")),
        "UploadedFilename": report.get("uploadedFilename"),
        "CreateTime": epoch_to_iso(report.get("createTime")),
        "UpdateTime": epoch_to_iso(report.get("updateTime")),
        "DynReportId": (report.get("dynReportSummary") or {}).get("dynReportId"),
        "StatReportId": (report.get("statReportSummary") or {}).get("staticAnalysisReportId"),
        "ParentReportId": report.get("parentReportId"),
        "Tags": report.get("tags") or [],
        "ReportUrl": report_url(params, report.get("sampleReportId")),
        "File": {
            "HashSha256": file_dto.get("hashSha256"),
            "HashSha1": file_dto.get("hashSha1"),
            "HashMd5": file_dto.get("hashMd5"),
            "Size": file_dto.get("size"),
            "FileType": file_dto.get("fileType"),
            "MimeType": file_dto.get("mimeType"),
            "InferredExtension": file_dto.get("inferredExtension"),
            "UploadedExtension": file_dto.get("uploadedExtension"),
            "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
            "Signed": file_dto.get("signed"),
        },
    }
    if classifier:
        outputs["MalwareClassifier"] = {
            "PrimaryType": classifier.get("primaryType"),
            "Confidence": classifier.get("confidence"),
            "MultiStage": classifier.get("multiStage"),
            "SecondaryTypes": classifier.get("secondaryTypes") or [],
            "KeyIndicators": classifier.get("keyIndicators") or [],
        }

    source = report.get("source") or {}
    if source:
        outputs["Source"] = {
            "SourceId": source.get("sourceId"),
            # Serialized through @JsonValue, so this is the display code
            # ("Cortex XSOAR"), never the enum name.
            "Type": source.get("sourceType"),
            "Uid": source.get("sourceUid"),
        }

    requested, not_run = requested_but_not_run(report)
    if not_run:
        # The server mutates the request: AV_ANALYSIS is always added and
        # DYN_ANALYSIS is stripped on a LITE license or the mailer preset. A
        # request asking for dynamic analysis can silently come back static
        # only, so the difference is surfaced rather than hidden.
        outputs["RequestedButNotRun"] = sorted(not_run)
    outputs["AnalyzedReportTypes"] = sorted(requested)
    return remove_empty_elements(outputs)


def requested_but_not_run(report: dict) -> tuple[set, set]:
    requested = {str(x).upper() for x in (report.get("analysisTypes") or []) if x}
    completed = {str(x).upper() for x in (report.get("completedAnalyzes") or []) if x}
    return requested, requested - completed


def report_url(params: dict, sample_report_id: Any) -> str | None:
    base = (params.get("report_url_base") or "").rstrip("/")
    if not base or not sample_report_id:
        return None
    return f"{base}/reports/{sample_report_id}"


def build_file_indicator(outputs: dict, reliability: str) -> Common.File | None:
    """Attach a DBotScore so stock enrichment playbooks keep working."""
    file_part = outputs.get("File") or {}
    sha256 = file_part.get("HashSha256")
    if not sha256:
        return None
    dbot = Common.DBotScore(
        indicator=sha256,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=outputs.get("DBotScore", Common.DBotScore.NONE),
        malicious_description=f"tLab Anti-APT verdict: {outputs.get('Verdict')}",
        reliability=reliability,
    )
    return Common.File(
        dbot_score=dbot,
        md5=file_part.get("HashMd5"),
        sha1=file_part.get("HashSha1"),
        sha256=sha256,
        name=outputs.get("UploadedFilename"),
        size=file_part.get("Size"),
        file_type=file_part.get("FileType"),
        extension=file_part.get("InferredExtension"),
    )


def analysis_readable(outputs: dict) -> str:
    row = {
        "Report ID": outputs.get("SampleReportId"),
        "Verdict": outputs.get("Verdict"),
        "Score": outputs.get("Score"),
        "Completeness": outputs.get("Completeness"),
        "File": outputs.get("UploadedFilename"),
        "SHA256": (outputs.get("File") or {}).get("HashSha256"),
        "Malware family": (outputs.get("MalwareClassifier") or {}).get("PrimaryType"),
        "Detected by AV": outputs.get("DetectedByAv"),
    }
    md = tableToMarkdown("tLab Anti-APT analysis", row, removeNull=True)
    if outputs.get("RequestedButNotRun"):
        md += (
            "\n**Note:** the server did not run "
            f"{', '.join(outputs['RequestedButNotRun'])}. This happens on a LITE license or with the "
            "`mailer` preset, where dynamic analysis is removed from the request.\n"
        )
    if outputs.get("ReportUrl"):
        md += f"\n[Open the full report in tLab Anti-APT]({outputs['ReportUrl']})\n"
    return md


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
# tLab stores the uid in sources.source_uid VARCHAR(45). A longer value does
# not fail the submit: the server logs the truncation error and runs the
# analysis without a source, so the limit is enforced here.
SOURCE_UID_MAX_LEN = 45


def source_uid(params: dict) -> str:
    """Return the uid this XSOAR is known by on the tLab side.

    A configured value is sent as is and must fit the column. The default is
    the XSOAR license ID (CUID<64 hex>CUID, 72 characters) cut to the column
    size: its start stays readable against Settings > About > License ID, and
    41 hex digits still tell XSOAR servers apart.
    """
    configured = (params.get("source_uid") or "").strip()
    if configured:
        if len(configured) > SOURCE_UID_MAX_LEN:
            raise DemistoException(
                f"Source UID is {len(configured)} characters long; tLab Anti-APT accepts at most "
                f"{SOURCE_UID_MAX_LEN}. Shorten it or leave it empty to use the XSOAR license ID."
            )
        return configured
    return (demisto.getLicenseID() or "")[:SOURCE_UID_MAX_LEN]


def test_module_command(client: TLabClient, params: dict) -> str:
    """Probe connectivity and the role, because a wrong role fails silently later."""
    source_uid(params)
    try:
        identity = client.whoami()
    except DemistoException as exc:
        raise DemistoException(f"Could not reach the tLab Anti-APT API. {exc}") from exc

    role = str(identity.get("userRole") or "").lower()
    login = identity.get("userLogin") or identity.get("login") or "unknown"
    if role and role not in ("admin", "developer"):
        # Not fatal for this integration: submission and public polling work
        # with a lower role. Artifact endpoints will not. XSOAR accepts only an
        # exact "ok" as a passed test, so the warning goes to the log.
        demisto.info(
            f"tLab Anti-APT: connected as {login} with role '{role}'. Report artifacts (PCAP, memory dump, "
            "dropped files, extra logs) require the admin or developer role and will return 403."
        )
    # XSOAR treats any other string — even "ok - …" — as a failed test.
    return "ok"


def submit_settings_from_args(args: dict, params: dict) -> SubmitSettings:
    analysis_types = argToList(args.get("analysis_types") or params.get("analysis_types")) or None
    properties = {}
    raw_properties = args.get("properties")
    if raw_properties:
        properties = json.loads(raw_properties) if isinstance(raw_properties, str) else dict(raw_properties)
    # Provenance: lets an analyst pivot from a tLab report back to the incident.
    incident = demisto.incident() or {}
    if incident.get("id"):
        properties.setdefault("xsoar_incident_id", str(incident["id"]))

    research_time = arg_to_number(args.get("research_time") or params.get("research_time") or 120)
    return SubmitSettings(
        analysis_types=analysis_types,
        analysis_priority=args.get("analysis_priority") or params.get("analysis_priority") or "LOW",
        research_time=research_time if research_time is not None else 120,
        env_preset=args.get("env_preset") or params.get("env_preset") or "",
        user_preset=argToBoolean(args.get("user_preset") or params.get("user_preset") or False),
        enable_network=argToBoolean(args.get("enable_network") or params.get("enable_network") or False),
        create_dump=argToBoolean(args.get("create_dump") or params.get("create_dump") or False),
        enable_acceleration=argToBoolean(args.get("enable_acceleration") or params.get("enable_acceleration") or False),
        enable_antievasion=argToBoolean(args.get("enable_antievasion") or params.get("enable_antievasion") or False),
        use_original_filename=argToBoolean(args.get("use_original_filename") or params.get("use_original_filename") or True),
        command_line_args=args.get("command_line_args") or "",
        uas_script=args.get("uas_script") or "",
        extract_archive=argToBoolean(args.get("extract_archive") or params.get("extract_archive") or True),
        include_archive_siblings=argToBoolean(
            args.get("include_archive_siblings") or params.get("include_archive_siblings") or True
        ),
        archive_password=args.get("archive_password") or "",
        ignore_whitelist=argToBoolean(args.get("ignore_whitelist") or params.get("ignore_whitelist") or False),
        static_prefilter=argToBoolean(args.get("static_prefilter") or params.get("static_prefilter") or False),
        public_access=argToBoolean(args.get("public_access") or params.get("public_access") or False),
        main_filename=args.get("main_filename") or "",
        tags=argToList(args.get("tags")),
        properties=properties,
        source_type=params.get("source_type") or SOURCE_TYPE_NAME,
        source_uid=source_uid(params),
    )


def submission_outputs(response: dict, submitted: str = "") -> dict:
    rejection = response.get("rejectionCode")
    return remove_empty_elements(
        {
            "AnalysisRequestId": response.get("analysisRequestId"),
            "AnalysisRequestStatus": response.get("analysisRequestStatus"),
            "AccessCode": response.get("accessCode"),
            "RejectionCode": rejection,
            "RejectionReason": describe_rejection(rejection) if rejection else None,
            "Whitelisted": bool(response.get("whitelisted")),
            "Submitted": submitted or None,
        }
    )


def submit_file_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required: it identifies the war room file to submit.")
    file_info = demisto.getFilePath(entry_id)
    file_name = args.get("file_name") or file_info.get("name")

    additional = []
    for extra_id in argToList(args.get("additional_files_entry_ids")):
        extra = demisto.getFilePath(extra_id)
        additional.append({"path": extra["path"], "name": extra["name"]})

    settings = submit_settings_from_args(args, params)
    if not settings.main_filename:
        settings.main_filename = file_name

    response = client.submit("file", settings, file_path=file_info["path"], file_name=file_name, additional_files=additional)
    outputs = submission_outputs(response, submitted=file_name)
    return CommandResults(
        outputs_prefix=OUTPUT_SUBMISSION,
        outputs_key_field="AccessCode",
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown(f"Submitted {file_name} to tLab Anti-APT", outputs, removeNull=True),
    )


def submit_url_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    url = args.get("url")
    if not url:
        raise DemistoException("url is required.")
    settings = submit_settings_from_args(args, params)
    response = client.submit("url", settings, url=url)
    outputs = submission_outputs(response, submitted=url)
    return CommandResults(
        outputs_prefix=OUTPUT_SUBMISSION,
        outputs_key_field="AccessCode",
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown(f"Submitted {url} to tLab Anti-APT", outputs, removeNull=True),
    )


def resolve_status(client: TLabClient, access_code: str, args: dict, params: dict) -> tuple[bool, CommandResults]:
    """Check one submission. Returns (terminal, results)."""
    early = argToBoolean(args.get("early_verdict") or params.get("early_verdict") or False)
    status = client.request_status(access_code, early_verdict=early)
    request_status = status.get("analysisRequestStatus")

    if request_status == REQUEST_STATUS_REJECTED:
        outputs = submission_outputs(status)
        code = status.get("rejectionCode") or ""
        if code in NON_ERROR_REJECTIONS:
            # Whitelisted and already-analyzed are outcomes, not failures: the
            # caller gets a result rather than an exception.
            return True, CommandResults(
                outputs_prefix=OUTPUT_SUBMISSION,
                outputs_key_field="AccessCode",
                outputs=outputs,
                raw_response=status,
                readable_output=f"### tLab Anti-APT\n{describe_rejection(code)}",
            )
        raise TLabRejection(code, status.get("message") or "", status)

    reports = status.get("reports") or []
    main = select_main_report(reports)
    if not main:
        # Reports appear only once the request reaches ACCEPTED.
        return False, CommandResults(
            readable_output=f"Waiting for tLab Anti-APT: request status is {request_status or 'unknown'}."
        )

    verdict = canonical_verdict(
        main,
        suspicious_from=score_thresholds(params)[0],
        malicious_from=score_thresholds(params)[1],
        early_verdict=early,
    )
    terminal = is_terminal(main.get("sampleReportCompleteness") or "", verdict)

    if terminal and argToBoolean(args.get("extended") or False):
        # The public status endpoint returns SampleReportShortBean, which has
        # no dynReportSummary or statReportSummary. Sub-report ids live only on
        # GET /sample_reports/{id}.
        try:
            main = client.get_sample_report(main["sampleReportId"])
        except DemistoException as exc:
            demisto.debug(f"tLab: could not enrich report {main.get('sampleReportId')}: {exc}")

    outputs = analysis_outputs(main, params, access_code=access_code, request_status=request_status)
    siblings = [r for r in reports if r.get("sampleReportId") != main.get("sampleReportId")]
    if siblings:
        outputs["ChildReports"] = [
            {
                "SampleReportId": r.get("sampleReportId"),
                "SampleReportType": r.get("sampleReportType"),
                "UploadedFilename": r.get("uploadedFilename"),
                "Score": r.get("sampleScore"),
                "Completeness": r.get("sampleReportCompleteness"),
            }
            for r in siblings
        ]

    results = CommandResults(
        outputs_prefix=OUTPUT_ANALYSIS,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=status,
        readable_output=analysis_readable(outputs),
        indicator=build_file_indicator(outputs, params.get("reliability") or DBotScoreReliability.B),
    )
    return terminal, results


def poll_status_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Poll a submission to a terminal verdict.

    Scheduled commands need server 6.2.0. Below that the loop runs inline,
    which holds a worker, so the timeout is capped.
    """
    access_code = args.get("access_code")
    if not access_code:
        raise DemistoException("access_code is required.")
    interval = arg_to_number(args.get("interval_in_seconds") or DEFAULT_INTERVAL) or DEFAULT_INTERVAL
    timeout = arg_to_number(args.get("timeout_in_seconds") or DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT

    terminal, results = resolve_status(client, access_code, args, params)
    if terminal:
        return results

    if supports_scheduled_commands():
        results.scheduled_command = schedule_next_poll("tlab-get-submission-status", args, interval, timeout)
        return results

    capped = min(timeout, BLOCKING_TIMEOUT_CAP)
    demisto.debug(f"tLab: server does not support scheduled commands; polling inline for up to {capped}s")

    def check():
        done, res = resolve_status(client, access_code, args, params)
        return done, res

    return blocking_poll(check, interval, capped)


def detonate_command(client: TLabClient, args: dict, params: dict, kind: str) -> CommandResults:
    """Submit and then poll, reusing the standalone status command."""
    if args.get("access_code"):
        # A scheduled re-run lands here with the access code already known.
        return poll_status_command(client, args, params)

    submitted = submit_file_command(client, args, params) if kind == "file" else submit_url_command(client, args, params)
    outputs = submitted.outputs if isinstance(submitted.outputs, dict) else {}
    access_code = outputs.get("AccessCode")
    if not access_code:
        return submitted

    poll_args = dict(args)
    poll_args["access_code"] = access_code
    return poll_status_command(client, poll_args, params)


def get_report_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    report = client.get_sample_report(sample_report_id)
    outputs = analysis_outputs(report, params)
    return CommandResults(
        outputs_prefix=OUTPUT_REPORT,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=report,
        readable_output=analysis_readable(outputs),
        indicator=build_file_indicator(outputs, params.get("reliability") or DBotScoreReliability.B),
    )


def get_threat_indicators_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    level_filter = {x.upper() for x in argToList(args.get("level"))}
    source_filter = {x.upper() for x in argToList(args.get("source"))}
    limit = arg_to_number(args.get("limit") or 100) or 100

    payload = client.get_threat_indicators(sample_report_id)
    rows = []
    for indicator in payload.get("indicators") or []:
        if level_filter and str(indicator.get("level") or "").upper() not in level_filter:
            continue
        if source_filter and str(indicator.get("source") or "").upper() not in source_filter:
            continue
        rows.append(
            {
                "Id": indicator.get("id"),
                "Source": indicator.get("source"),
                "AnalysisType": indicator.get("analysisType"),
                "Key": indicator.get("key"),
                "Level": indicator.get("level"),
                "Title": indicator.get("title"),
                "Count": indicator.get("count"),
                "ObjectsTotal": indicator.get("objectsTotal"),
                "Objects": [{"Kind": obj.get("kind"), "Name": obj.get("name")} for obj in (indicator.get("objects") or [])],
                "Attack": indicator.get("attack") or [],
            }
        )
        if len(rows) >= limit:
            break

    outputs = {"SampleReportId": sample_report_id, "Indicators": rows, "Totals": payload.get("totals") or {}}
    table = [{"Level": r["Level"], "Source": r["Source"], "Title": r["Title"], "Count": r["Count"]} for r in rows]
    return CommandResults(
        outputs_prefix=OUTPUT_THREAT,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT threat indicators for report {sample_report_id}", table, removeNull=True),
    )


def get_attack_matrix_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    payload = client.get_attack_matrix(sample_report_id)
    techniques = [
        {
            "Id": t.get("id"),
            "Name": t.get("name"),
            "Url": t.get("url"),
            "Level": t.get("level"),
            "Tactics": t.get("tactics") or [],
            "PrimarySource": t.get("primarySource"),
            "StaticOnly": t.get("staticOnly"),
        }
        for t in (payload.get("techniques") or [])
    ]
    outputs = {
        "SampleReportId": sample_report_id,
        "CatalogVersion": payload.get("catalogVersion"),
        "Totals": payload.get("totals") or {},
        "Techniques": techniques,
        "Tactics": payload.get("tactics") or [],
    }
    return CommandResults(
        outputs_prefix=OUTPUT_ATTACK,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(
            f"MITRE ATT&CK techniques for report {sample_report_id}",
            [{"Technique": t["Id"], "Name": t["Name"], "Level": t["Level"]} for t in techniques],
            removeNull=True,
        ),
    )


def get_pcap_command(client: TLabClient, args: dict, params: dict) -> Any:
    """Network capture, as bytes or as the analyzer's JSON report.

    DynReportsController maps two handlers to ``{id}/pcap`` differing only by
    ``produces``, so the Accept header decides which one answers.
    """
    dyn_report_id = arg_to_number(args.get("dyn_report_id"))
    if not dyn_report_id:
        raise DemistoException("dyn_report_id is required.")
    fmt = (args.get("format") or "pcap").lower()
    max_bytes = (arg_to_number(params.get("max_artifact_size_mb") or 50) or 50) * 1024 * 1024

    if fmt == "json":
        payload = client.request("GET", f"/dyn_reports/{dyn_report_id}/pcap", headers={"Accept": "application/json"})
        return CommandResults(
            outputs_prefix="TLabAntiAPT.PcapReport",
            outputs_key_field="DynReportId",
            outputs={"DynReportId": dyn_report_id, "Report": payload},
            raw_response=payload,
            readable_output=f"Retrieved the PCAP analysis report for dynamic report {dyn_report_id}.",
        )

    data = client.download(f"/dyn_reports/{dyn_report_id}/pcap", "application/octet-stream", max_bytes=max_bytes)
    return fileResult(f"tlab_{dyn_report_id}.pcap", data, file_type=EntryType.FILE)


def get_report_pdf_command(client: TLabClient, args: dict, params: dict) -> Any:
    """Rendered PDF report.

    This endpoint is a POST, not a GET, and renders synchronously with no
    status endpoint, so it gets its own timeout.
    """
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    timeout = arg_to_number(args.get("timeout") or params.get("pdf_timeout") or 180) or 180
    max_bytes = (arg_to_number(params.get("max_artifact_size_mb") or 50) or 50) * 1024 * 1024

    data = client.download(
        f"/report-pdf/{sample_report_id}",
        "application/pdf",
        max_bytes=max_bytes,
        method="POST",
        json_data={"imgBase64": ""},
        timeout=timeout,
    )
    return fileResult(f"tlab_report_{sample_report_id}.pdf", data, file_type=EntryType.ENTRY_INFO_FILE)


def list_env_presets_command(client: TLabClient, args: dict) -> CommandResults:
    scope = (args.get("scope") or "global").lower()
    payload = client.list_env_presets(scope)
    names = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    rows = [{"Name": p.get("name") if isinstance(p, dict) else p, "Scope": scope} for p in names]
    return CommandResults(
        outputs_prefix=OUTPUT_PRESET,
        outputs_key_field="Name",
        outputs=rows,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT {scope} environment presets", rows, removeNull=True),
    )


def list_sources_command(client: TLabClient) -> CommandResults:
    payload = client.list_sources()
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    table = [
        {"SourceId": s.get("sourceId"), "Type": s.get("sourceType"), "Uid": s.get("sourceUid")}
        for s in rows
        if isinstance(s, dict)
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_SOURCE,
        outputs_key_field="SourceId",
        outputs=table,
        raw_response=payload,
        readable_output=tableToMarkdown("tLab Anti-APT submission sources", table, removeNull=True),
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
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
        elif command == "tlab-submit-file":
            return_results(submit_file_command(client, args, params))
        elif command == "tlab-submit-url":
            return_results(submit_url_command(client, args, params))
        elif command == "tlab-get-submission-status":
            return_results(poll_status_command(client, args, params))
        elif command == "tlab-detonate-file":
            return_results(detonate_command(client, args, params, "file"))
        elif command == "tlab-detonate-url":
            return_results(detonate_command(client, args, params, "url"))
        elif command == "tlab-get-report":
            return_results(get_report_command(client, args, params))
        elif command == "tlab-get-threat-indicators":
            return_results(get_threat_indicators_command(client, args, params))
        elif command == "tlab-get-attack-matrix":
            return_results(get_attack_matrix_command(client, args, params))
        elif command == "tlab-get-pcap":
            return_results(get_pcap_command(client, args, params))
        elif command == "tlab-get-report-pdf":
            return_results(get_report_pdf_command(client, args, params))
        elif command == "tlab-list-env-presets":
            return_results(list_env_presets_command(client, args))
        elif command == "tlab-list-sources":
            return_results(list_sources_command(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except TLabRejection as rejection:
        return_error(str(rejection))
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
