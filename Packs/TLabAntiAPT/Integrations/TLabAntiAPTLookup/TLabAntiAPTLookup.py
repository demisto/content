"""tLab Anti-APT Lookup integration for Cortex XSOAR.

Answers "has tLab Anti-APT already seen this file?" without submitting
anything. Runs with the lowest tLab role, so it can be given a restricted
account while detonation keeps a privileged one.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import traceback
from typing import Any
import base64
import contextlib
import hashlib
import json
import time
import urllib.parse
from datetime import datetime, UTC
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


COMPLETENESS_COMPLETE = "COMPLETE"

REQUEST_STATUS_REJECTED = "REJECTED"


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


def verdict_to_dbot_score(verdict: str, unknown_is_benign: bool = False) -> int:
    """Canonical verdict -> DBotScore (0 Unknown, 1 Good, 2 Suspicious, 3 Bad)."""
    if verdict == VERDICT_MALWARE:
        return Common.DBotScore.BAD
    if verdict == VERDICT_SUSPICIOUS:
        return Common.DBotScore.SUSPICIOUS
    if verdict in (VERDICT_OK, VERDICT_CLEAN, VERDICT_WHITELIST):
        return Common.DBotScore.GOOD
    return Common.DBotScore.GOOD if unknown_is_benign else Common.DBotScore.NONE


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


def source_reliability(params: dict) -> str:
    """The instance's Source Reliability, B when unset."""
    return DBotScoreReliability.get_dbot_score_reliability_from_str(params.get("reliability") or DBotScoreReliability.B)


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


# ---------------------------------------------------------------------------
# End of the shared tLab Anti-APT client.
# ---------------------------------------------------------------------------


OUTPUT_FILE = "TLabAntiAPT.File"
OUTPUT_SCAN = "TLabAntiAPT.ScanResult"
OUTPUT_INFO = "TLabAntiAPT.FileInfo"
OUTPUT_REPORT = "TLabAntiAPT.Report"
OUTPUT_HASH_SEARCH = "TLabAntiAPT.HashSearch"
OUTPUT_INDICATOR_CODE = "TLabAntiAPT.IndicatorCode"

# Report filters the server accepts from every role. Anything outside this set
# is silently discarded for company_admin and user, which turns a narrow query
# into "return everything" with no error.
ROLE_SAFE_FILTERS = {
    "fileType",
    "completeness",
    "status",
    "dateFrom",
    "dateTo",
    "fileHashSha256",
    "fileHashSha1",
    "tags",
    "indicators",
}
ADMIN_ONLY_FILTERS = {"fileVerdict", "scoreLevel", "sourceId", "rootOnly", "minReportId", "minScore", "fileName"}


def lookup_reports_by_hash(client: TLabClient, hash_value: str, hash_type: str, params: dict) -> list:
    """Find reports for one hash, verifying every result actually matches.

    MD5 is resolved through the hash search endpoint rather than the report
    filter: ``fileHashMd5`` is not in the server's role allow-list, so for a
    non-admin account it is dropped and the query matches unrelated samples.
    """
    completeness = argToList(params.get("completeness")) or [COMPLETENESS_COMPLETE]
    limit = arg_to_number(params.get("lookup_limit") or 1) or 1

    if hash_type == "md5":
        resolved = resolve_md5_to_sha256(client, hash_value)
        if not resolved:
            return []
        hash_value, hash_type = resolved, "sha256"

    query: dict[str, Any] = {"file_hash_sha256": hash_value} if hash_type == "sha256" else {"file_hash_sha1": hash_value}
    page = client.list_sample_reports(
        page=0,
        size=max(limit, 10),
        # Newest first: the most recent analysis is the relevant one.
        sort="sampleReportId,desc",
        completeness=completeness,
        status=["ACTIVE"],
        **query,
    )
    reports = page.get("content") or []
    # The hash filters are prefix matches OR'd against the archive hash, so the
    # server can legitimately return a different sample.
    verified = [r for r in reports if report_matches_hash(r, hash_type, hash_value)]
    dropped = len(reports) - len(verified)
    if dropped:
        demisto.debug(f"tLab: discarded {dropped} report(s) whose {hash_type} did not match {hash_value}")
    return verified[:limit]


def resolve_md5_to_sha256(client: TLabClient, md5: str) -> str:
    payload = client.hash_search("md5", md5)
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    for row in rows:
        if str(row.get("hashMd5") or "").lower() == md5.lower():
            return str(row.get("hashSha256") or "")
    return ""


def file_outputs(report: dict, params: dict) -> dict:
    file_dto = report.get("file") or {}
    suspicious_from, malicious_from = score_thresholds(params)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)
    return remove_empty_elements(
        {
            "SampleReportId": report.get("sampleReportId"),
            "HashSha256": file_dto.get("hashSha256"),
            "HashSha1": file_dto.get("hashSha1"),
            "HashMd5": file_dto.get("hashMd5"),
            "Size": file_dto.get("size"),
            "FileType": file_dto.get("fileType"),
            "MimeType": file_dto.get("mimeType"),
            "UploadedFilename": report.get("uploadedFilename"),
            "Verdict": verdict,
            # Both raw enumerations are kept so an analyst can see what the server
            # said, not only the canonical value.
            "ScoreLevel": report.get("verdict"),
            # Set by hand in tLab; absent while nobody has set it.
            "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
            "Score": score if present else None,
            "Completeness": report.get("sampleReportCompleteness"),
            "AnalyzedAt": epoch_to_iso(report.get("createTime")),
            "Found": True,
        }
    )


def build_indicator(outputs: dict, params: dict, requested_hash: str) -> Common.File:
    verdict = outputs.get("Verdict", VERDICT_UNKNOWN)
    score = verdict_to_dbot_score(verdict, unknown_is_benign=argToBoolean(params.get("unknown_is_benign") or False))
    dbot = Common.DBotScore(
        indicator=requested_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=score,
        malicious_description=f"tLab Anti-APT verdict: {verdict}" if score == Common.DBotScore.BAD else None,
        reliability=source_reliability(params),
    )
    return Common.File(
        dbot_score=dbot,
        md5=outputs.get("HashMd5"),
        sha1=outputs.get("HashSha1"),
        sha256=outputs.get("HashSha256"),
        name=outputs.get("UploadedFilename"),
        size=outputs.get("Size"),
        file_type=outputs.get("FileType"),
    )


def not_found_indicator(requested_hash: str, hash_type: str, params: dict) -> Common.File:
    """A hash tLab has never seen gets score 0, not Good.

    "We have no record" is not the same statement as "this is benign", and a
    Good score here would suppress other vendors' findings in the incident.
    """
    dbot = Common.DBotScore(
        indicator=requested_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=Common.DBotScore.NONE,
        reliability=source_reliability(params),
    )
    kwargs = {hash_type: requested_hash}
    return Common.File(dbot_score=dbot, **kwargs)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def test_module_command(client: TLabClient) -> str:
    identity = client.whoami()
    login = identity.get("userLogin") or identity.get("login") or "unknown"
    role = identity.get("userRole") or "unknown"
    demisto.debug(f"tLab Anti-APT: connected as {login} (role: {role})")
    # XSOAR treats any other string — even "ok - …" — as a failed test.
    return "ok"


def file_reputation_command(client: TLabClient, args: dict, params: dict) -> list:
    hashes = argToList(args.get("file"))
    if not hashes:
        raise DemistoException("The file argument is required.")

    results = []
    for raw in hashes:
        value = str(raw).strip().lower()
        hash_type = hash_type_of(value)
        if not hash_type:
            # Partial hashes are refused rather than searched: the server's
            # filters are prefix matches, so a short value would match
            # unrelated samples and produce a confident wrong verdict.
            results.append(
                CommandResults(
                    readable_output=(
                        f"### tLab Anti-APT\nSkipped {raw!r}: expected a full MD5, SHA1 or SHA256 hash. "
                        "Partial hashes are not looked up because the server matches hash filters by prefix."
                    )
                )
            )
            continue

        reports = lookup_reports_by_hash(client, value, hash_type, params)
        if not reports:
            results.append(
                CommandResults(
                    indicator=not_found_indicator(value, hash_type, params),
                    readable_output=f"### tLab Anti-APT\nNo analysis found for {value}.",
                )
            )
            continue

        outputs = file_outputs(reports[0], params)
        results.append(
            CommandResults(
                outputs_prefix=OUTPUT_FILE,
                outputs_key_field="HashSha256",
                outputs=outputs,
                raw_response=reports[0],
                indicator=build_indicator(outputs, params, value),
                readable_output=tableToMarkdown(
                    f"tLab Anti-APT reputation for {value}",
                    {
                        "Verdict": outputs.get("Verdict"),
                        "Score": outputs.get("Score"),
                        "Report ID": outputs.get("SampleReportId"),
                        "File name": outputs.get("UploadedFilename"),
                        "Analyzed at": outputs.get("AnalyzedAt"),
                    },
                    removeNull=True,
                ),
            )
        )
    return results


def scan_result_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    value = str(args.get("hash") or "").strip().lower()
    if not value:
        raise DemistoException("The hash argument is required.")
    hash_type = args.get("hash_type") or hash_type_of(value)
    if hash_type not in ("md5", "sha1", "sha256"):
        raise DemistoException(
            f"Could not determine the hash type of {value!r}. Provide a full MD5, SHA1 or SHA256 hash, "
            "or set hash_type explicitly."
        )

    limit = arg_to_number(args.get("limit") or params.get("lookup_limit") or 1) or 1
    reports = lookup_reports_by_hash(client, value, hash_type, {**params, "lookup_limit": limit})
    rows = [file_outputs(r, params) for r in reports]
    if not rows:
        return CommandResults(
            outputs_prefix=OUTPUT_SCAN,
            outputs_key_field="HashSha256",
            outputs={"Found": False, "Requested": value},
            readable_output=f"### tLab Anti-APT\nNo analysis found for {value}.",
        )
    return CommandResults(
        outputs_prefix=OUTPUT_SCAN,
        outputs_key_field="SampleReportId",
        outputs=rows,
        raw_response=reports,
        readable_output=tableToMarkdown(f"tLab Anti-APT scan results for {value}", rows, removeNull=True),
    )


def file_info_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sha256 = str(args.get("sha256") or "").strip().lower()
    if hash_type_of(sha256) != "sha256":
        raise DemistoException("sha256 must be a full 64-character SHA256 hash.")
    payload = client.get_file_by_hash(sha256)
    outputs = remove_empty_elements(
        {
            "HashSha256": payload.get("hashSha256"),
            "HashSha1": payload.get("hashSha1"),
            "HashMd5": payload.get("hashMd5"),
            "Size": payload.get("size"),
            "FileType": payload.get("fileType"),
            "MimeType": payload.get("mimeType"),
            "InferredExtension": payload.get("inferredExtension"),
            "UploadedExtension": payload.get("uploadedExtension"),
            "SuggestedName": payload.get("suggestedName"),
            # The stored analyst verdict for this file. It is read here, never
            # written: the /verdict routes are POST setters guarded by @PreAuthorize.
            # Absent while nobody has set it.
            "FileVerdict": stored_file_verdict(payload.get("fileVerdict")),
            "Signed": payload.get("signed"),
            "DigitalSignatureCount": payload.get("digitalSignatureCount"),
        }
    )
    return CommandResults(
        outputs_prefix=OUTPUT_INFO,
        outputs_key_field="HashSha256",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT file {sha256}", outputs, removeNull=True),
    )


def search_reports_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sort = args.get("sort") or "sampleReportId,desc"
    # Rejects createTime, which the server ignores silently instead of failing.
    validate_sort(sort)

    used_admin_filters = sorted(
        name
        for name, value in (
            ("fileVerdict", args.get("file_verdict")),
            ("scoreLevel", args.get("score_level")),
            ("sourceId", args.get("source_id")),
            ("rootOnly", args.get("root_only")),
            ("minReportId", args.get("min_report_id")),
            ("minScore", args.get("min_score")),
            ("fileName", args.get("file_name")),
        )
        if value
    )

    limit = arg_to_number(args.get("limit") or 50) or 50
    page = client.list_sample_reports(
        page=arg_to_number(args.get("page") or 0) or 0,
        size=min(limit, 200),
        sort=sort,
        date_from=args.get("date_from"),
        date_to=args.get("date_to"),
        completeness=argToList(args.get("completeness")),
        status=argToList(args.get("status")) or ["ACTIVE"],
        file_verdicts=argToList(args.get("file_verdict")),
        score_levels=argToList(args.get("score_level")),
        file_types=argToList(args.get("file_type")),
        source_ids=argToList(args.get("source_id")),
        tags=argToList(args.get("tags")),
        indicators=argToList(args.get("indicators")),
        root_only=argToBoolean(args["root_only"]) if args.get("root_only") is not None else None,
        min_report_id=arg_to_number(args.get("min_report_id")),
        min_score=arg_to_number(args.get("min_score")),
        file_name=args.get("file_name"),
        file_hash_sha256=args.get("file_hash_sha256"),
        file_hash_sha1=args.get("file_hash_sha1"),
    )
    rows = [file_outputs(r, params) for r in (page.get("content") or [])][:limit]

    readable = tableToMarkdown(f"tLab Anti-APT reports ({page.get('totalElements', len(rows))} total)", rows, removeNull=True)
    if used_admin_filters:
        # The server drops these for company_admin and user without an error,
        # so a narrow query silently becomes "everything".
        readable += (
            "\n**Warning:** the filters "
            f"{', '.join(used_admin_filters)} are only applied for accounts with the admin or developer "
            "role. With a lower role the server discards them without an error, so these results may be "
            "unfiltered. Verify the account role if the result set looks too broad.\n"
        )
    return CommandResults(
        outputs_prefix=OUTPUT_REPORT,
        outputs_key_field="SampleReportId",
        outputs=rows,
        raw_response=page,
        readable_output=readable,
    )


def hash_search_command(client: TLabClient, args: dict) -> CommandResults:
    hash_type = (args.get("hash_type") or "").lower()
    hash_part = str(args.get("hash_part") or "").strip().lower()
    if hash_type not in ("md5", "sha1", "sha256"):
        raise DemistoException("hash_type must be one of md5, sha1 or sha256.")
    if len(hash_part) < 3:
        raise DemistoException("hash_part must be at least 3 characters long.")

    payload = client.hash_search(hash_type, hash_part)
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    outputs = [
        remove_empty_elements(
            {
                "HashValue": row.get(f"hash{hash_type.capitalize()}") or row.get("hashSha256"),
                "HashType": hash_type,
                "FileType": row.get("fileType"),
                "FileVerdict": stored_file_verdict(row.get("fileVerdict")),
            }
        )
        for row in rows
        if isinstance(row, dict)
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_HASH_SEARCH,
        outputs_key_field="HashValue",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT hash search for {hash_type} starting with {hash_part}", outputs, removeNull=True
        ),
    )


def list_indicator_codes_command(client: TLabClient, args: dict) -> CommandResults:
    analysis_type = (args.get("analysis_type") or "").upper()
    payload = client.list_indicator_codes()
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    outputs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if analysis_type and str(row.get("analysisType") or "").upper() != analysis_type:
            continue
        outputs.append(
            {
                "Code": row.get("indicatorCode") or row.get("code"),
                "Name": row.get("name") or row.get("indicatorName"),
                "AnalysisType": row.get("analysisType"),
            }
        )
    return CommandResults(
        outputs_prefix=OUTPUT_INDICATOR_CODE,
        outputs_key_field="Code",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown("tLab Anti-APT indicator codes", outputs, removeNull=True),
    )


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
            return_results(test_module_command(client))
        elif command == "file":
            return_results(file_reputation_command(client, args, params))
        elif command == "tlab-file-scan-result":
            return_results(scan_result_command(client, args, params))
        elif command == "tlab-file-info":
            return_results(file_info_command(client, args, params))
        elif command == "tlab-search-reports":
            return_results(search_reports_command(client, args, params))
        elif command == "tlab-hash-search":
            return_results(hash_search_command(client, args))
        elif command == "tlab-list-indicator-codes":
            return_results(list_indicator_codes_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}", error=exc)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
