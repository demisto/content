import re
import json
import time
from urllib.parse import urljoin, urlparse
import requests

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# ============================
# Helpers
# ============================


def _verify_flag() -> bool:
    """XSOAR 'insecure' means do NOT verify TLS."""
    return not bool(demisto.params().get('insecure', False))


def _new_session() -> requests.Session:
    """New session per command (re-login each run)."""
    s = requests.Session()
    proxies = handle_proxy()
    if proxies:
        s.proxies.update(proxies)
    return s


def _require_param(name: str, value: Optional[str]):
    if not value:
        return_error(f"Missing required instance parameter: '{name}'")


def _debug_slice(txt: str, n: int = 600) -> str:
    if not txt:
        return ""
    return (txt[:n].replace('\n', ' ')[:n])


def _extract_task_id(obj: Any) -> Optional[str]:
    """Try common shapes to pull a TaskId out of submit/check responses."""
    if not isinstance(obj, dict):
        return None
    return (
        obj.get('TaskId') or obj.get('taskId') or obj.get('taskID')
        or (obj.get('data') or {}).get('TaskId')
        or (obj.get('data') or {}).get('taskId')
        or (obj.get('data') or {}).get('taskID')
    )


def _ci_get(d: dict, *candidates: str):
    """Case-insensitive getter over multiple key candidates."""
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
    Normalize several possible shapes to a pure dict:
    - Dict already JSON -> return as is
    - {'html': '<json string>'} -> parse the string
    - {'data': '<json string>'} -> parse the string into 'data'
    """
    if isinstance(obj, dict):
        # 'html' contains a JSON string (as in your example)
        html = obj.get('html')
        if isinstance(html, str):
            try:
                return json.loads(html)
            except Exception:
                pass
        # 'data' could be a JSON string
        data = obj.get('data')
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                return {'data': parsed}
            except Exception:
                pass
        return obj
    # Text that looks like JSON
    if isinstance(obj, str) and obj.strip().startswith('{'):
        try:
            return json.loads(obj)
        except Exception:
            return {'raw': obj}
    return {'raw': obj}


def _parse_task_fields(task_json: dict, task_id: Optional[str], base_url: str) -> dict:
    """
    Map API/Details payload to a flat dict and also the incident field names you provided.
    Accepts both {"data": {...}} and flat {...} shapes.
    """
    j = _ensure_json_like(task_json)
    d = j.get('data') if isinstance(j.get('data'), dict) else j
    out = {
        'TaskId': task_id or _extract_task_id(j) or _extract_task_id(d) or '',
        'TaskName': _ci_get(d, 'taskName', 'TaskName'),
        'AssignedUserName': _ci_get(d, 'assignedUserName', 'AssignedUser', 'AssignedUserName'),
        'AIDriverName': _ci_get(d, 'aiDriverName', 'AIDriverName', 'aiDriver'),
        'PolicyName': _ci_get(d, 'policyName', 'PolicyName'),
        'Subject': _ci_get(d, 'subject', 'Subject'),
        'SecurityLog': _ci_get(d, 'securityLog', 'SecurityLog'),
        'SanitizedLog': _ci_get(d, 'sanitizedLog', 'SanitizedLog'),
        'Response': _ci_get(d, 'response', 'Response'),
        'Recommendation': _ci_get(d, 'recommendation', 'Recommendation'),
        'Status': _ci_get(d, 'status', 'Status'),
        'RiskSeverity': _ci_get(d, 'result', 'risk', 'Risk', 'Result'),
        'PredictionScore': _ci_get(d, 'predictionScore', 'PredictionScore'),
        'Raw': j
    }
    if out['TaskId']:
        out['TaskURL'] = f"{base_url.rstrip('/')}/SecurityTasks/Details?taskID={out['TaskId']}"
    return out


def _maybe_set_incident_fields(parsed: dict):
    """
    If we're running in an incident context, set your custom fields:
    shadowxaitaskname, shadowxaiassigneduser, shadowxaiaidriver, shadowxaipolicyname,
    shadowxaisubject, shadowxaisecuritylog, shadowxaisanitizedlog, shadowxairesponse,
    shadowxairecommendation, shadowxaistatus, shadowxairiskseverity, shadowxaipredictionscore
    """
    try:
        inc = demisto.incident()
        if not inc:
            return
        cf = {
            "shadowxaitaskname": parsed.get('TaskName'),
            "shadowxaiassigneduser": parsed.get('AssignedUserName'),
            "shadowxaiaidriver": parsed.get('AIDriverName'),
            "shadowxaipolicyname": parsed.get('PolicyName'),
            "shadowxaisubject": parsed.get('Subject'),
            "shadowxaisecuritylog": parsed.get('SecurityLog'),
            "shadowxaisanitizedlog": parsed.get('SanitizedLog'),
            "shadowxairesponse": parsed.get('Response'),
            "shadowxairecommendation": parsed.get('Recommendation'),
            "shadowxaistatus": parsed.get('Status'),
            "shadowxairiskseverity": parsed.get('RiskSeverity'),
            "shadowxaipredictionscore": parsed.get('PredictionScore'),
        }
        demisto.executeCommand("setIncident", {"customFields": cf})
    except Exception as e:
        demisto.debug(f"setIncident failed (non-fatal): {e}")

# ============================
# API KEY (Bearer) MODE
# ============================


def api_key_headers(api_key: str) -> Dict[str, str]:
    return {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }


def submit_with_api_key(session: requests.Session, base_url: str, api_key: str, payload: dict) -> requests.Response:
    """Submit using Bearer token to a configurable API path (default /Api/SecurityTasks/Create)."""
    submission_path = demisto.params().get('api_submission_path') or '/Api/SecurityTasks/Create'
    url = f'{base_url}{submission_path}'
    headers = api_key_headers(api_key)
    demisto.debug(f'API-Key submit POST {url}')
    r = session.post(url, headers=headers, data=json.dumps(payload), verify=_verify_flag(), timeout=60)
    # Fail fast if HTML came back (means you hit MVC route)
    ct = (r.headers.get('Content-Type') or '').lower()
    if 'json' not in ct:
        return_error(f"API key mode expected JSON but got Content-Type '{ct}'. "
                     f"Check 'API Submission Path' — HTML endpoints like /SecurityTasks/Create require cookie mode.")
    return r


def check_task_with_api_key(session: requests.Session, base_url: str, api_key: str, task_id: str) -> Optional[dict]:
    """Poll task status using Bearer token via configurable path format (default /Api/SecurityTasks/Details?taskID={task_id})."""
    fmt = demisto.params().get('api_check_path_format') or '/Api/SecurityTasks/Details?taskID={task_id}'
    url = f'{base_url}{fmt.format(task_id=task_id)}'
    headers = api_key_headers(api_key)
    demisto.debug(f'API-Key check GET {url}')
    r = session.get(url, headers=headers, verify=_verify_flag(), timeout=30)
    if r.status_code == 200:
        # Try JSON first
        try:
            return r.json()
        except Exception:
            # If it sent text/HTML but the body is actually JSON string somewhere (your "html" case)
            txt = r.text or ''
            try:
                return json.loads(txt)
            except Exception:
                demisto.debug(f'Check returned non-JSON body: {_debug_slice(txt)}')
                return None
    demisto.debug(f'Check returned status {r.status_code}: {_debug_slice(r.text)}')
    return None

# ============================
# COOKIE MODE (legacy MVC flow)
# ============================


def login_to_dotnet_api(session: requests.Session, base_url: str, email: str, password: str) -> tuple[str, str]:
    """Login with JSON to /User/Login, expect AuthToken cookie. Accept 200 or 302; returns (auth_token, effective_base_url)."""
    url = f'{base_url}/User/Login'
    payload = {'EmailOrUsername': email, 'Password': password}
    headers = {'Content-Type': 'application/json'}
    demisto.debug(f'Login POST {url}')
    r = session.post(url, headers=headers, data=json.dumps(payload),
                     verify=_verify_flag(), timeout=30, allow_redirects=False)
    if r.status_code not in (200, 302):
        raise DemistoException(f'Login failed: {r.status_code} {_debug_slice(r.text)}')
    effective_base = base_url
    loc = r.headers.get('Location')
    if r.status_code in (301, 302, 303, 307, 308) and loc:
        absolute = urljoin(base_url + '/', loc.lstrip('/'))
        parsed = urlparse(absolute)
        effective_base = f'{parsed.scheme}://{parsed.netloc}'
        demisto.debug(f'Login redirect -> effective base: {effective_base}')
    auth_token = r.cookies.get('AuthToken')
    if not auth_token:
        for c in session.cookies:
            if c.name.lower() == 'authtoken':
                auth_token = c.value
                break
    if not auth_token:
        raise DemistoException('Login ok but AuthToken cookie not found')
    return auth_token, effective_base


def _extract_token_from_text(html: str) -> Optional[str]:
    if not html:
        return None
    m = re.search(r'name=["\']__RequestVerificationToken["\']\s+value=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'<meta\s+name=["\'](?:request[-_]verification[-_]token|__RequestVerificationToken|csrf-token)["\']\s+content=["\']([^"\']+)["\']',
                  html, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'["\'](?:RequestVerificationToken|__RequestVerificationToken)["\']\s*[:=]\s*["\']([^"\']+)["\']',
                  html, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def get_verification_token(session: requests.Session, base_url: str) -> str:
    """Fetch HTML form and extract __RequestVerificationToken; persist anti-forgery cookie in session jar."""
    url = f'{base_url}/SecurityTasks/Create'
    headers = {'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'}
    demisto.debug(f'GET token page {url}')
    r = session.get(url, headers=headers, verify=_verify_flag(), timeout=30, allow_redirects=False)
    for _ in range(2):
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get('Location'):
            loc = r.headers['Location']
            demisto.debug(f'Token page redirected to {loc} (following)')
            r = session.get(urljoin(base_url + '/', loc.lstrip('/')), headers=headers,
                            verify=_verify_flag(), timeout=30, allow_redirects=False)
        else:
            break
    if r.status_code != 200:
        raise DemistoException(f'Get token page failed: {r.status_code} {_debug_slice(r.text)}')
    html = r.text or ''
    token_val = _extract_token_from_text(html)
    if not token_val:
        demisto.debug(f'Create page first 600 chars:\n{_debug_slice(html, 600)}')
        raise DemistoException('__RequestVerificationToken not found in page')
    parsed = urlparse(r.url or base_url)
    for c in r.cookies:
        if c.name.startswith('.AspNetCore.Antiforgery.'):
            session.cookies.set(c.name, c.value, domain=parsed.hostname)
            demisto.debug(f'Persisted anti-forgery cookie: {c.name} for domain {parsed.hostname}')
            break
    return token_val


def create_security_task_cookie(session: requests.Session, base_url: str, req_verif_token: str, payload: dict) -> requests.Response:
    """POST /SecurityTasks/Create using cookie auth only; include RequestVerificationToken header and token in body."""
    url = f'{base_url}/SecurityTasks/Create'
    headers = {'Content-Type': 'application/json', 'RequestVerificationToken': req_verif_token}
    body = dict(payload)
    body['__RequestVerificationToken'] = req_verif_token
    demisto.debug(f'POST create task {url} (cookie-auth)')
    r = session.post(url, headers=headers, json=body, verify=_verify_flag(), timeout=60, allow_redirects=False)
    return r

# ============================
# Command Implementations
# ============================


def _build_task_payload_from_args(args: Dict[str, Any]) -> dict:
    """Build task payload combining instance defaults + command args; include fields for both API shapes."""
    task_name = demisto.params().get('task_name') or 'XSOAR submit'
    assigned_user_id = demisto.params().get('assigned_user_id') or ''
    ai_driver_id = demisto.params().get('ai_driver_id') or ''
    default_policy_id = demisto.params().get('policy_id') or ''

    log = args.get('log')
    ip_addr = args.get('ip_addr')
    user_name = args.get('user_name')
    policy_id = args.get('policy_id') or default_policy_id

    security_log = log if not ip_addr else f'{log} [ip:{ip_addr}]'

    payload = {
        # API/FreeText shapes (lenient)
        "SearchText": log,
        "IpAddr": ip_addr,
        "UserName": user_name,
        "PolicyId": policy_id,
        # SecurityTasks create shape
        "TaskName": task_name,
        "AssignedUserID": assigned_user_id,
        "AIDriverID": ai_driver_id,
        "PolicyID": policy_id,
        "Subject": user_name or "",
        "SecurityLog": security_log,
        "Status": 1
    }
    return payload


def test_module():
    """If API key set → simple GET / with Bearer; else try cookie login."""
    base_url = (demisto.params().get('url') or '').rstrip('/')
    api_key = demisto.params().get('api_key') or ''
    email = demisto.params().get('user_email') or ''
    password = demisto.params().get('user_password') or ''

    _require_param('url', base_url)
    s = _new_session()

    if api_key:
        r = s.get(f'{base_url}/', headers=api_key_headers(api_key), verify=_verify_flag(), timeout=15)
        if r.status_code in (200, 302):
            return_results('ok')
        else:
            return_error(f'API key test failed: {r.status_code} {_debug_slice(r.text)}')
    else:
        _require_param('user_email', email)
        _require_param('user_password', password)
        _, _ = login_to_dotnet_api(s, base_url, email, password)  # raises on failure
        return_results('ok')


def shadowx_submit_task_command():
    args = demisto.args()
    base_url = (demisto.params().get('url') or '').rstrip('/')
    api_key = demisto.params().get('api_key') or ''

    # Required arg
    log = args.get('log')
    if not log:
        return_error("'log' is required.")

    payload = _build_task_payload_from_args(args)
    wait_seconds = int(args.get('wait_seconds', 0))

    s = _new_session()

    if api_key:
        # API mode (Bearer)
        submit_res = submit_with_api_key(s, base_url, api_key, payload)
        if submit_res.status_code != 200:
            return_error(f"Task submit failed (API key): {submit_res.status_code} {_debug_slice(submit_res.text, 600)}")

        submit_json: Dict[str, Any] = {}
        try:
            submit_json = submit_res.json()
        except Exception:
            pass

        task_id = _extract_task_id(submit_json) or ""
        ui_url = f"{base_url.rstrip('/')}/SecurityTasks/Details?taskID={task_id}" if task_id else ""

        # Optional polling (if TaskId exists)
        if wait_seconds > 0 and task_id:
            end = time.time() + wait_seconds
            while time.time() < end:
                time.sleep(3)
                chk = check_task_with_api_key(s, base_url, api_key, str(task_id))
                if chk and str(_ci_get(_ensure_json_like(chk).get('data', chk), 'Status', 'status')).lower() in ('completed', 'done', 'finished'):
                    parsed = _parse_task_fields(chk, task_id, base_url)
                    _maybe_set_incident_fields(parsed)
                    return_results(CommandResults(
                        outputs_prefix='ShadowxSOCAI.TaskResult',
                        outputs=parsed,
                        readable_output=f"ShadowX Task Completed\nURL: {parsed.get('TaskURL', '')}",
                        raw_response=chk
                    ))
                    return

        # Return submit info (include URL if we have it)
        out = submit_json or {"status": "Submitted"}
        if isinstance(out, dict) and ui_url:
            out['TaskURL'] = ui_url
            if task_id and 'TaskId' not in out:
                out['TaskId'] = task_id

        return_results(CommandResults(
            outputs_prefix='ShadowxSOCAI.TaskSubmit',
            outputs=out,
            readable_output=f"ShadowX task submitted (API key mode)\nURL: {ui_url}" if ui_url else 'ShadowX task submitted (API key mode)',
            raw_response=out
        ))
        return

    # Cookie/HTML mode
    email = demisto.params().get('user_email') or ''
    password = demisto.params().get('user_password') or ''
    _require_param('user_email', email)
    _require_param('user_password', password)

    _, effective_base = login_to_dotnet_api(s, base_url, email, password)
    req_token = get_verification_token(s, effective_base)

    submit_res = create_security_task_cookie(s, effective_base, req_token, payload)
    if submit_res.status_code != 200:
        return_error(f"Task submit failed (cookie mode): {submit_res.status_code} {_debug_slice(submit_res.text, 600)}")

    submit_json: Dict[str, Any] = {}
    try:
        submit_json = submit_res.json()
    except Exception:
        pass

    task_id = _extract_task_id(submit_json) or submit_json.get('taskId') or submit_json.get('taskID') or ''
    ui_url = f"{effective_base.rstrip('/')}/SecurityTasks/Details?taskID={task_id}" if task_id else ''

    if wait_seconds > 0 and task_id:
        end = time.time() + wait_seconds
        while time.time() < end:
            time.sleep(1)

    out = submit_json or {"status": "Submitted"}
    if isinstance(out, dict) and ui_url:
        out['TaskURL'] = ui_url
        if task_id and 'TaskId' not in out:
            out['TaskId'] = task_id

    return_results(CommandResults(
        outputs_prefix='ShadowxSOCAI.TaskSubmit',
        outputs=out,
        readable_output=f"ShadowX task submitted (cookie mode)\nURL: {ui_url}" if ui_url else 'ShadowX task submitted (cookie mode)',
        raw_response=out
    ))


def shadowx_get_task_command():
    """Fetch task details by ID in API mode (Bearer)."""
    task_id = demisto.args().get('task_id')
    if not task_id:
        return_error('task_id is required')
    base_url = (demisto.params().get('url') or '').rstrip('/')
    api_key = demisto.params().get('api_key') or ''
    if not api_key:
        return_error('shadowx-get-task requires API Key mode (set API Key in instance).')

    s = _new_session()
    data = check_task_with_api_key(s, base_url, api_key, task_id)
    if not data:
        return_error('Task not found or API did not return JSON')

    parsed = _parse_task_fields(data, task_id, base_url)
    _maybe_set_incident_fields(parsed)

    return_results(CommandResults(
        outputs_prefix='ShadowxSOCAI.TaskResult',
        outputs=parsed,
        readable_output=tableToMarkdown('ShadowX Task', parsed),
        raw_response=data
    ))


def shadowx_help_command():
    demisto.results("""
### ShadowX SOCAI — Help

**Commands**
1) `!shadowx-submit-task` – submit a log (API Key or cookie mode)
   - In API mode, set instance paths:
     - API Submission Path: `/Api/SecurityTasks/Create`
     - API Check Path Format: `/Api/SecurityTasks/Details?taskID={task_id}`
   - Use `wait_seconds` to poll and return parsed results on first run.
2) `!shadowx-get-task task_id="<GUID>"` – fetch details later (API mode)

Returned fields (and Incident custom fields when in an incident):
TaskName → shadowxaitaskname
AssignedUserName → shadowxaiassigneduser
AIDriverName → shadowxaiaidriver
PolicyName → shadowxaipolicyname
Subject → shadowxaisubject
SecurityLog → shadowxaisecuritylog
SanitizedLog → shadowxaisanitizedlog
Response → shadowxairesponse
Recommendation → shadowxairecommendation
Status → shadowxaistatus
RiskSeverity → shadowxairiskseverity
PredictionScore → shadowxaipredictionscore
""")


# ============================
# Main
# ============================

def main():
    try:
        command = demisto.command()
        demisto.debug(f'Command called: {command}')
        if command == 'test-module':
            test_module()
        elif command == 'shadowx-submit-task':
            shadowx_submit_task_command()
        elif command == 'shadowx-get-task':
            shadowx_get_task_command()
        elif command == 'shadowx-help':
            shadowx_help_command()
        else:
            return_error(f'Command not implemented: {command}')
    except Exception as e:
        return_error(f'Unexpected error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
