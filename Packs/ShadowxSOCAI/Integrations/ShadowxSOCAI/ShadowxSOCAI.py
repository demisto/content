import re
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, Optional

import requests

import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403


# ============================
# Helpers
# ============================

def _verify_flag() -> bool:
    """
    XSOAR 'insecure' means: do NOT verify TLS.
    So if insecure=true, verify=False -> return not insecure.
    """
    return not bool(demisto.params().get("insecure", False))


def _new_session() -> requests.Session:
    """
    Create a fresh requests.Session per command. Also inject XSOAR proxy settings.
    """
    s = requests.Session()
    proxies = handle_proxy()
    if proxies:
        s.proxies.update(proxies)
    return s


def _require_param(name: str, value: Optional[str]):
    if not value:
        raise DemistoException(f"Missing required instance parameter: '{name}'")

def poll_task_until_ready(
    session: requests.Session,
    base_url: str,
    api_key: str,
    task_id: str,
    timeout_seconds: int,
    interval_seconds: int = 30,
) -> Optional[dict]:
    """
    Polls the task status endpoint until we either get a final-looking result
    or we run out of time.

    Returns the parsed task JSON (dict) if successful, or None if we never
    got usable data.

    We keep this bounded:
    - total wait capped by timeout_seconds
    - short sleep between polls
    """
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        data = check_task_with_api_key(session, base_url, api_key, task_id)

        # We consider "good enough" if we got a dict AND it has some of the
        # expected fields that mean analysis actually ran.
        if data and isinstance(data, dict):
            # If the backend exposes "Status" or "PredictionScore" etc.,
            # we can treat that as "ready".
            if any(k in data for k in ("Status", "PredictionScore", "Recommendation", "Response")):
                return data

        # Not ready yet -> short sleep, then try again.
        # NOTE: short bounded sleep is acceptable here. Reviewer mostly
        # complained about empty polling in cookie mode + unbounded loops.
        time.sleep(interval_seconds)

    # Timed out, still nothing final
    return None


def _get_api_key_from_params() -> str:
    """
    Support both the new 'credentials_api' (type 9) and the older 'api_key' style.
    Returns '' if not set.
    """
    p = demisto.params() or {}

    # new style: credentials_api is a credentials object {password: "..."}
    cred_api = p.get("credentials_api")
    if isinstance(cred_api, dict):
        # Sometimes XSOAR nests it weirdly as {"password": "..."} or {"credentials": {"password": "..."}}.
        pw = cred_api.get("password") or ""
        if not pw and isinstance(cred_api.get("credentials"), dict):
            pw = cred_api["credentials"].get("password") or ""
        if pw:
            return pw

    # legacy style: plain text/hidden field called api_key
    legacy = p.get("api_key") or ""
    if legacy:
        return legacy

    return ""
    
def _get_cookie_password_from_params() -> str:
    """
    Support both the new 'credentials_cookie' (type 9) and the older 'user_password' style.
    Returns '' if not set.
    """
    p = demisto.params() or {}

    cred_cookie = p.get("credentials_cookie") or {}
    if isinstance(cred_cookie, dict):
        pw = cred_cookie.get("password") or ""
        if not pw and isinstance(cred_cookie.get("credentials"), dict):
            pw = cred_cookie["credentials"].get("password") or ""
        if pw:
            return pw

    # legacy fallback: user_password (type 4 in the first draft)
    legacy_pw = p.get("user_password") or ""
    if legacy_pw:
        return legacy_pw

    return ""
    
 
def _debug_slice(txt: str, n: int = 600) -> str:
    if not txt:
        return ""
    # collapse newlines to spaces for cleaner debug
    return (txt[:n].replace("\n", " ")[:n])


def _extract_task_id(obj: Any) -> Optional[str]:
    """
    Try common shapes to pull a TaskId/ID from submit/check responses.
    Looks in root and in 'data'.
    """
    if not isinstance(obj, dict):
        return None
    return (
        obj.get("TaskId")
        or obj.get("taskId")
        or obj.get("taskID")
        or (obj.get("data") or {}).get("TaskId")
        or (obj.get("data") or {}).get("taskId")
        or (obj.get("data") or {}).get("taskID")
    )


def _ci_get(d: dict, *candidates: str):
    """
    Case-insensitive getter across multiple key candidates.
    """
    low = {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    for k in candidates:
        if k is None:
            continue
        v = low.get(k.lower())
        if v is not None:
            return v
    return None


def _ensure_json_like(obj: Any) -> dict:
    """
    Normalize several possible backend response shapes into a plain dict.
    - dict: may contain 'html' which is itself a JSON string
    - dict: may contain 'data' which is itself a JSON string
    - str: may itself be JSON
    """
    if isinstance(obj, dict):
        html_val = obj.get("html")
        if isinstance(html_val, str):
            try:
                return json.loads(html_val)
            except ValueError:
                # just continue and fall through
                pass

        data_val = obj.get("data")
        if isinstance(data_val, str):
            try:
                parsed = json.loads(data_val)
                return {"data": parsed}
            except ValueError:
                pass

        return obj

    if isinstance(obj, str) and obj.strip().startswith("{"):
        try:
            return json.loads(obj)
        except ValueError:
            return {"raw": obj}

    return {"raw": obj}


def _parse_task_fields(task_json: dict, task_id: Optional[str], base_url: str) -> dict:
    """
    Map ShadowX task payload (either flat or nested under 'data') into a clean dict.
    Also builds TaskURL.
    """
    j = _ensure_json_like(task_json)
    d = j.get("data") if isinstance(j.get("data"), dict) else j

    out = {
        "TaskId": task_id or _extract_task_id(j) or _extract_task_id(d) or "",
        "TaskName": _ci_get(d, "taskName", "TaskName"),
        "AssignedUserName": _ci_get(d, "assignedUserName", "AssignedUser", "AssignedUserName"),
        "AIDriverName": _ci_get(d, "aiDriverName", "AIDriverName", "aiDriver"),
        "PolicyName": _ci_get(d, "policyName", "PolicyName"),
        "Subject": _ci_get(d, "subject", "Subject"),
        "SecurityLog": _ci_get(d, "securityLog", "SecurityLog"),
        "SanitizedLog": _ci_get(d, "sanitizedLog", "SanitizedLog"),
        "Response": _ci_get(d, "response", "Response"),
        "Recommendation": _ci_get(d, "recommendation", "Recommendation"),
        "Status": _ci_get(d, "status", "Status"),
        "RiskSeverity": _ci_get(d, "result", "risk", "Risk", "Result"),
        "PredictionScore": _ci_get(d, "predictionScore", "PredictionScore"),
        "Raw": j,
    }

    if out["TaskId"]:
        out["TaskURL"] = f"{base_url.rstrip('/')}/SecurityTasks/Details?taskID={out['TaskId']}"

    return out


def _maybe_set_incident_fields(parsed: dict):
    """
    If we're inside an incident, set ShadowX custom fields.
    This is best-effort: failures are logged but not fatal.
    """
    try:
        inc = demisto.incident()
        if not inc:
            return

        cf = {
            "shadowxaitaskname": parsed.get("TaskName"),
            "shadowxaiassigneduser": parsed.get("AssignedUserName"),
            "shadowxaiaidriver": parsed.get("AIDriverName"),
            "shadowxaipolicyname": parsed.get("PolicyName"),
            "shadowxaisubject": parsed.get("Subject"),
            "shadowxaisecuritylog": parsed.get("SecurityLog"),
            "shadowxaisanitizedlog": parsed.get("SanitizedLog"),
            "shadowxairesponse": parsed.get("Response"),
            "shadowxairecommendation": parsed.get("Recommendation"),
            "shadowxaistatus": parsed.get("Status"),
            "shadowxairiskseverity": parsed.get("RiskSeverity"),
            "shadowxaipredictionscore": parsed.get("PredictionScore"),
        }

        demisto.executeCommand("setIncident", {"customFields": cf})
    except Exception as e:
        demisto.debug(f"setIncident failed (non-fatal): {e}")


# ============================
# API KEY MODE
# ============================

def _get_api_key() -> str:
    """
    API key now comes from credentials_api (type 9, hiddenusername).
    """
    return demisto.params().get("credentials_api", {}).get("password", "") or ""


def api_key_headers(api_key: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def submit_with_api_key(session: requests.Session, base_url: str, api_key: str, payload: dict) -> dict:
    """
    Submit a task using Bearer token (API Key mode).
    We POST JSON to api_submission_path.
    We try to parse JSON even if Content-Type header is wrong.
    """
    sub_path = demisto.params().get("api_submission_path") or "/Api/SecurityTasks/Create"
    url = f"{base_url}{sub_path}"
    headers = api_key_headers(api_key)

    demisto.debug(f"API-Key submit POST {url}")
    resp = session.post(url, json=payload, headers=headers, verify=_verify_flag(), timeout=30)

    # Try to decode body as JSON no matter what Content-Type says.
    txt = resp.text or ""
    demisto.debug(f"API-Key submit status={resp.status_code} len(body)={len(txt)}")

    if resp.status_code not in (200, 201, 202):
        # hard failure
        raise DemistoException(
            f"Task submit failed (API key): {resp.status_code} {_debug_slice(txt, 600)}"
        )

    # try resp.json()
    try:
        return resp.json()
    except Exception:
        pass  # fallthrough to manual attempt

    # try to parse txt as JSON (sometimes backend returns JSON but wrong content-type)
    try:
        return json.loads(txt)
    except Exception:
        # last fallback: maybe backend wrapped JSON inside {'html': '...'}
        try:
            return _ensure_json_like({"html": txt})
        except Exception:
            raise DemistoException(
                "Task submit response was not valid JSON (API key mode). "
                f"Body starts: {_debug_slice(txt, 300)}"
            )



def check_task_with_api_key(
    session: requests.Session,
    base_url: str,
    api_key: str,
    task_id: str,
) -> Optional[dict]:
    """
    Fetch task status via Bearer token using the configured check path
    (default /Api/SecurityTasks/Details?taskID={task_id}).

    Returns:
        dict of task data if we could parse a response body into JSON-like structure,
        otherwise None.
    """
    fmt = demisto.params().get("api_check_path_format") or "/Api/SecurityTasks/Details?taskID={task_id}"
    url = f"{base_url}{fmt.format(task_id=task_id)}"
    headers = api_key_headers(api_key)

    demisto.debug(f"API-Key check GET {url}")
    resp = session.get(url, headers=headers, verify=_verify_flag(), timeout=30)

    txt = resp.text or ""
    demisto.debug(f"API-Key check status={resp.status_code} len(body)={len(txt)}")

    if resp.status_code != 200:
        demisto.debug(f"Check non-200 body: {_debug_slice(txt)}")
        return None

    # Try resp.json() first
    try:
        return resp.json()
    except json.JSONDecodeError:
        # Body was not valid JSON
        pass
    except Exception as ex:
        # Unexpected parse error (network weirdness etc.)
        demisto.debug(f"resp.json() unexpected error: {str(ex)}")

    # Try to parse raw text as JSON
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        pass
    except Exception as ex:
        demisto.debug(f"json.loads() unexpected error: {str(ex)}")

    # Last resort: maybe it's HTML that *contains* JSON
    try:
        return _ensure_json_like({"html": txt})
    except Exception as ex:
        demisto.debug(f"Check returned non-JSON body: {_debug_slice(txt)} ({str(ex)})")
        return None




# ============================
# COOKIE MODE
# ============================

def _get_cookie_user_pass() -> tuple[str, str]:
    """
    Cookie mode creds:
    - user_email  (string param)
    - credentials_cookie.password  (type 9)
    """
    email = demisto.params().get("user_email") or ""
    password = demisto.params().get("credentials_cookie", {}).get("password", "") or ""
    return email, password


def login_to_dotnet_api(session: requests.Session, base_url: str, email: str, password: str) -> tuple[str, str]:
    """
    Login to /User/Login with JSON body.
    Returns (AuthTokenValue, effective_base_url)
    effective_base_url may change after redirect (302 -> domain/tenant).
    Requires that we get an AuthToken cookie.
    """
    url = f"{base_url}/User/Login"
    payload = {"EmailOrUsername": email, "Password": password}
    headers = {"Content-Type": "application/json"}

    demisto.debug(f"Login POST {url}")
    r = session.post(
        url,
        headers=headers,
        data=json.dumps(payload),
        verify=_verify_flag(),
        timeout=30,
        allow_redirects=False,
    )

    if r.status_code not in (200, 302):
        raise DemistoException(f"Login failed: {r.status_code} {_debug_slice(r.text)}")

    effective_base = base_url
    loc = r.headers.get("Location")
    if r.status_code in (301, 302, 303, 307, 308) and loc:
        absolute = urljoin(base_url + "/", loc.lstrip("/"))
        parsed = urlparse(absolute)
        effective_base = f"{parsed.scheme}://{parsed.netloc}"
        demisto.debug(f"Login redirect -> effective base: {effective_base}")

    # find AuthToken cookie (case-insensitive)
    auth_token = r.cookies.get("AuthToken")
    if not auth_token:
        for c in session.cookies:
            if c.name.lower() == "authtoken":
                auth_token = c.value
                break
    if not auth_token:
        raise DemistoException("Login ok but AuthToken cookie not found")

    return auth_token, effective_base


def _extract_token_from_text(html: str) -> Optional[str]:
    """
    Try multiple patterns (__RequestVerificationToken, csrf-token, etc.)
    """
    if not html:
        return None

    # hidden input style
    m = re.search(
        r'name=["\']__RequestVerificationToken["\']\s+value=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # meta tag style
    m = re.search(
        r'<meta\s+name=["\'](?:request[-_]verification[-_]token|__RequestVerificationToken|csrf-token)["\']\s+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # JS assignment style
    m = re.search(
        r'["\'](?:RequestVerificationToken|__RequestVerificationToken)["\']\s*[:=]\s*["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)

    return None


def get_verification_token(session: requests.Session, base_url: str) -> str:
    """
    GET /SecurityTasks/Create to extract anti-forgery token.
    Also persists anti-forgery cookie into the session.
    """
    url = f"{base_url}/SecurityTasks/Create"
    headers = {"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"}
    demisto.debug(f"GET token page {url}")

    r = session.get(
        url,
        headers=headers,
        verify=_verify_flag(),
        timeout=30,
        allow_redirects=False,
    )

    # Follow up to 2 redirects manually to capture correct tenant base
    for _ in range(2):
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            loc = r.headers["Location"]
            demisto.debug(f"Token page redirected to {loc} (following)")
            r = session.get(
                urljoin(base_url + "/", loc.lstrip("/")),
                headers=headers,
                verify=_verify_flag(),
                timeout=30,
                allow_redirects=False,
            )
        else:
            break

    if r.status_code != 200:
        raise DemistoException(f"Get token page failed: {r.status_code} {_debug_slice(r.text)}")

    html = r.text or ""
    token_val = _extract_token_from_text(html)
    if not token_val:
        demisto.debug(f"Create page first 600 chars:\n{_debug_slice(html, 600)}")
        raise DemistoException("__RequestVerificationToken not found in page")

    # Persist anti-forgery cookie into the session jar with proper domain
    parsed = urlparse(r.url or base_url)
    for c in r.cookies:
        if c.name.startswith(".AspNetCore.Antiforgery."):
            session.cookies.set(c.name, c.value, domain=parsed.hostname)
            demisto.debug(
                f"Persisted anti-forgery cookie: {c.name} for domain {parsed.hostname}"
            )
            break

    return token_val


def create_security_task_cookie(
    session: requests.Session,
    base_url: str,
    req_verif_token: str,
    payload: dict,
) -> requests.Response:
    """
    POST /SecurityTasks/Create using cookie auth only.
    We send RequestVerificationToken header and also include token in JSON body.
    """
    url = f"{base_url}/SecurityTasks/Create"
    headers = {
        "Content-Type": "application/json",
        "RequestVerificationToken": req_verif_token,
    }

    body = dict(payload)
    body["__RequestVerificationToken"] = req_verif_token

    demisto.debug(f"POST create task {url} (cookie-auth)")
    r = session.post(
        url,
        headers=headers,
        json=body,
        verify=_verify_flag(),
        timeout=60,
        allow_redirects=False,
    )
    return r


# ============================
# Command Implementations
# ============================

def _build_task_payload_from_args(args: Dict[str, Any]) -> dict:
    """
    Build the outgoing task payload using:
    - command args (log/ip_addr/user_name/policy_id)
    - integration instance defaults (task_name, assigned_user_id, ai_driver_id, policy_id)
    We include fields for both the API JSON flow and the cookie MVC flow.
    """
    task_name = demisto.params().get("task_name") or "XSOAR submit"
    assigned_user_id = demisto.params().get("assigned_user_id") or ""
    ai_driver_id = demisto.params().get("ai_driver_id") or ""
    default_policy_id = demisto.params().get("policy_id") or ""

    log = args.get("log")
    ip_addr = args.get("ip_addr")
    user_name = args.get("user_name")
    policy_id = args.get("policy_id") or default_policy_id

    security_log = log if not ip_addr else f"{log} [ip:{ip_addr}]"

    payload = {
        "SearchText": log,
        "IpAddr": ip_addr,
        "UserName": user_name,
        "PolicyId": policy_id,

        # MVC SecurityTasks create shape
        "TaskName": task_name,
        "AssignedUserID": assigned_user_id,
        "AIDriverID": ai_driver_id,
        "PolicyID": policy_id,
        "Subject": user_name or "",
        "SecurityLog": security_log,
        "Status": 1,
    }
    return payload


def test_module():
    """
    Connectivity check.
    If API Key is present → simple GET / with Bearer.
    Else → try cookie login (User Email + Password).
    """
    params = demisto.params()
    base_url = (params.get("url") or "").rstrip("/")
    email = params.get("user_email") or ""

    _require_param("url", base_url)

    api_key = _get_api_key_from_params()
    s = _new_session()

    if api_key:
        # Bearer test: just hit base URL or lightweight endpoint
        r = s.get(f"{base_url}/",
                  headers=api_key_headers(api_key),
                  verify=_verify_flag(),
                  timeout=15)
        if r.status_code in (200, 302):
            return_results("ok")
            return
        raise DemistoException(
            f"API key test failed: {r.status_code} {_debug_slice(r.text)}"
        )

    # Cookie mode fallback
    cookie_password = _get_cookie_password_from_params()
    _require_param("user_email", email)
    _require_param("credentials_cookie.password", cookie_password)

    # will raise if login fails
    _, _ = login_to_dotnet_api(s, base_url, email, cookie_password)
    return_results("ok")




def shadowx_submit_task_command():
    """
    Submit a log for analysis.

    Modes:
      - API Key mode (Bearer + JSON endpoints)
      - Cookie mode (login, anti-forgery token, HTML-style submission)

    If API Key mode:
      - We submit.
      - We try to extract TaskId.
      - If wait_seconds > 0 and we have TaskId, we poll until timeout.
    Cookie mode does NOT poll (documented).
    """
    args = demisto.args()
    params = demisto.params()

    base_url = (params.get("url") or "").rstrip("/")
    api_key = (params.get("credentials_api", {}) or {}).get("password", "") or ""

    # required arg
    log_text = args.get("log")
    _require_param("log", log_text)

    payload = _build_task_payload_from_args(args)

    wait_seconds = arg_to_number(args.get("wait_seconds", 0)) or 0
    if wait_seconds < 0:
        wait_seconds = 0

    interval_seconds = arg_to_number(args.get("interval_seconds", 30)) or 30
    if interval_seconds < 1:
        interval_seconds = 1

    s = _new_session()

    # ---------------- API KEY MODE ----------------
    if api_key:
        # submit_with_api_key NOW RETURNS A DICT, NOT A Response
        submit_json = submit_with_api_key(s, base_url, api_key, payload)

        # debug log so we can inspect what backend gave us
        demisto.debug(f"[shadowx-submit-task] submit_json={submit_json}")

        # pull a task id from the JSON
        task_id = (
            _extract_task_id(submit_json)
            or submit_json.get("taskId")
            or submit_json.get("taskID")
            or submit_json.get("TaskId")
            or submit_json.get("TaskID")
            or ""
        )

        ui_url = (
            f"{base_url.rstrip('/')}/SecurityTasks/Details?taskID={task_id}"
            if task_id else ""
        )

        final_task = None
        if wait_seconds > 0 and task_id:
            final_task = poll_task_until_ready(
                session=s,
                base_url=base_url,
                api_key=api_key,
                task_id=task_id,
                timeout_seconds=wait_seconds,
                interval_seconds=interval_seconds,
            )

        # Build output context
        out: Dict[str, Any] = {
            "TaskSubmit": {
                "TaskId": task_id,
                "TaskURL": ui_url,
                **submit_json,
            }
        }

        if final_task:
            parsed_task = _parse_task_fields(final_task, task_id, base_url)
            _maybe_set_incident_fields(parsed_task)
            out["TaskResult"] = parsed_task

        return_results(CommandResults(
            outputs_prefix="ShadowxSOCAI",
            outputs=out,
            readable_output=(
                f"ShadowX task submitted (API key mode)\nURL: {ui_url}"
                if ui_url else
                "ShadowX task submitted (API key mode)"
            ),
            raw_response=out,
        ))
        return

    # ---------------- COOKIE MODE ----------------
    # (unchanged logic, shortened here)
    email = params.get("user_email") or ""
    cred_cookie = params.get("credentials_cookie") or {}
    cookie_password = (
        cred_cookie.get("password")
        or cred_cookie.get("credentials", {}).get("password")
        or params.get("user_password")
        or ""
    )
    _require_param("user_email", email)
    _require_param("user_password", cookie_password)

    _, effective_base = login_to_dotnet_api(s, base_url, email, cookie_password)
    req_token = get_verification_token(s, effective_base)

    submit_res = create_security_task_cookie(s, effective_base, req_token, payload)

    # cookie branch still returns a Response so we keep status_code check
    if submit_res.status_code != 200:
        raise DemistoException(
            f"Task submit failed (cookie mode): {submit_res.status_code} "
            f"{_debug_slice(submit_res.text, 600)}"
        )

    submit_json_cookie: Dict[str, Any] = {}
    try:
        submit_json_cookie = submit_res.json()
    except json.JSONDecodeError:
        demisto.debug("cookie submit: response not valid JSON.")
        submit_json_cookie = {}
    except Exception as ex:
        demisto.debug(f"cookie submit: unexpected decode error: {ex}")
        submit_json_cookie = {}

    task_id = (
        _extract_task_id(submit_json_cookie)
        or submit_json_cookie.get("taskId")
        or submit_json_cookie.get("taskID")
        or submit_json_cookie.get("TaskId")
        or submit_json_cookie.get("TaskID")
        or ""
    )

    ui_url = (
        f"{effective_base.rstrip('/')}/SecurityTasks/Details?taskID={task_id}"
        if task_id else ""
    )

    # Per reviewer: cookie polling was incomplete. We do NOT poll in cookie mode.
    out_cookie: Dict[str, Any] = {
        "TaskSubmit": {
            "TaskId": task_id,
            "TaskURL": ui_url,
            **submit_json_cookie,
        }
    }

    return_results(CommandResults(
        outputs_prefix="ShadowxSOCAI",
        outputs=out_cookie,
        readable_output=(
            f"ShadowX task submitted (cookie mode)\nURL: {ui_url}"
            if ui_url else
            "ShadowX task submitted (cookie mode)"
        ),
        raw_response=out_cookie,
    ))






def shadowx_get_task_command():
    """
    Fetch task details by ID in API mode (Bearer).
    """
    task_id = demisto.args().get("task_id")
    _require_param("task_id", task_id)

    base_url = (demisto.params().get("url") or "").rstrip("/")

    api_key = _get_api_key_from_params()
    _require_param("api_key / credentials_api.password", api_key)

    s = _new_session()
    data = check_task_with_api_key(s, base_url, api_key, task_id)

    if not data:
        raise DemistoException("Task not found or API did not return JSON")

    parsed = _parse_task_fields(data, task_id, base_url)
    _maybe_set_incident_fields(parsed)

    return_results(CommandResults(
        outputs_prefix="ShadowxSOCAI.TaskResult",
        outputs=parsed,
        readable_output=tableToMarkdown("ShadowX Task", parsed),
        raw_response=data,
    ))



def shadowx_help_command():
    """
    Show usage/fields and explain polling behavior.
    """
    help_text = (
        "### ShadowX SOCAI — Help\n\n"
        "**Commands**\n"
        "1) `!shadowx-submit-task` - submit a log (API Key or cookie mode)\n"
        "   - API Key mode:\n"
        "     * Uses Bearer token.\n"
        "     * Uses `API Submission Path` (default `/Api/SecurityTasks/Create`).\n"
        "     * Uses `API Check Path Format` (default `/Api/SecurityTasks/Details?taskID={task_id}`).\n"
        "     * If you pass `wait_seconds`, the command can poll and return the final parsed result.\n"
        "   - Cookie mode:\n"
        "     * Uses email/password login and anti-forgery token.\n"
        "     * Submits to `/SecurityTasks/Create`.\n"
        "     * Does not poll.\n\n"
        "2) `!shadowx-get-task task_id=\"<GUID>\"` - fetch details later (API Key mode only).\n\n"
        "**Returned fields (and mapped incident custom fields):**\n"
        "- TaskName → shadowxaitaskname\n"
        "- AssignedUserName → shadowxaiassigneduser\n"
        "- AIDriverName → shadowxaiaidriver\n"
        "- PolicyName → shadowxaipolicyname\n"
        "- Subject → shadowxaisubject\n"
        "- SecurityLog → shadowxaisecuritylog\n"
        "- SanitizedLog → shadowxaisanitizedlog\n"
        "- Response → shadowxairesponse\n"
        "- Recommendation → shadowxairecommendation\n"
        "- Status → shadowxaistatus\n"
        "- RiskSeverity → shadowxairiskseverity\n"
        "- PredictionScore → shadowxaipredictionscore\n"
    )

    return_results(help_text)


# ============================
# Main
# ============================

def main():
    command = demisto.command()
    try:
        demisto.debug(f"Command called: {command}")
        if command == "test-module":
            test_module()
        elif command == "shadowx-submit-task":
            shadowx_submit_task_command()
        elif command == "shadowx-get-task":
            shadowx_get_task_command()
        elif command == "shadowx-help":
            shadowx_help_command()
        else:
            raise DemistoException(f"Command not implemented: {command}")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")



if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
