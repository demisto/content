import json
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403


# ============================
# Constants (hardcoded paths)
# ============================
SUBMIT_PATH = "/Api/SecurityTasks/Create"
CHECK_FMT = "/Api/SecurityTasks/Details?taskID={task_id}"


# ============================
# Helpers
# ============================

def _verify_flag() -> bool:
    # XSOAR "insecure" → do NOT verify TLS.
    return not bool(demisto.params().get("insecure", False))


def _new_session() -> requests.Session:
    s = requests.Session()
    proxies = handle_proxy()
    if proxies:
        s.proxies.update(proxies)
    return s


def _debug_slice(txt: str, n: int = 600) -> str:
    if not txt:
        return ""
    return (txt[:n].replace("\n", " ")[:n])


def _ensure_json_like(obj: Any) -> dict:
    """
    Normalize backend responses into a dict.
    """
    if isinstance(obj, dict):
        # may already be JSON
        return obj
    if isinstance(obj, str) and obj.strip().startswith("{"):
        try:
            return json.loads(obj)
        except json.JSONDecodeError:
            return {"raw": obj}
    return {"raw": obj}


def _extract_task_id(obj: Any) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    d = obj
    data = d.get("data") if isinstance(d.get("data"), dict) else {}
    return (
        d.get("TaskId") or d.get("taskId") or d.get("taskID")
        or data.get("TaskId") or data.get("taskId") or data.get("taskID")
    )


def _ci_get(d: dict, *keys: str):
    low = {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    for k in keys:
        if k is None:
            continue
        v = low.get(k.lower())
        if v is not None:
            return v
    return None


def _parse_task_fields(task_json: dict, task_id: Optional[str], base_url: str) -> dict:
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
# API-Key Flow
# ============================

def _api_key() -> str:
    # credentials_api is type 9 (hiddenusername)
    return demisto.params().get("credentials_api", {}).get("password", "") or ""


def _api_headers(api_key: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def submit_with_api_key(session: requests.Session, base_url: str, api_key: str, payload: dict) -> dict:
    url = f"{base_url}{SUBMIT_PATH}"
    demisto.debug(f"API submit POST {url}")
    resp = session.post(url, json=payload, headers=_api_headers(api_key),
                        verify=_verify_flag(), timeout=30)
    body_text = resp.text or ""
    demisto.debug(f"API submit status={resp.status_code} len(body)={len(body_text)}")

    if resp.status_code not in (200, 201, 202):
        raise DemistoException(f"Task submit failed: {resp.status_code} {_debug_slice(body_text, 600)}")

    # Parse JSON robustly
    try:
        return resp.json()
    except json.JSONDecodeError as e:
        demisto.debug(f"Failed to parse as JSON, trying text. Error: {e}")
        pass

    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        pass

    # Final fallback
    return _ensure_json_like(body_text)


def check_task_with_api_key(session: requests.Session, base_url: str, api_key: str, task_id: str) -> Optional[dict]:
    url = f"{base_url}{CHECK_FMT.format(task_id=task_id)}"
    demisto.debug(f"API check GET {url}")
    resp = session.get(url, headers=_api_headers(api_key), verify=_verify_flag(), timeout=30)

    txt = resp.text or ""
    demisto.debug(f"API check status={resp.status_code} len(body)={len(txt)}")
    if resp.status_code != 200:
        demisto.debug(f"API check non-200 body: {_debug_slice(txt)}")
        return None

    try:
        return resp.json()
    except json.JSONDecodeError as e:
        demisto.debug(f"Failed to parse as JSON, trying text. Error: {e}")
        pass

    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        pass

    return _ensure_json_like(txt)


def poll_task_until_ready(
    session: requests.Session,
    base_url: str,
    api_key: str,
    task_id: str,
    timeout_seconds: int,
    interval_seconds: int = 30,
) -> Optional[dict]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        data = check_task_with_api_key(session, base_url, api_key, task_id)
        if data and isinstance(data, dict):
            if any(k in data for k in ("Status", "PredictionScore", "Recommendation", "Response")):
                return data
        time.sleep(interval_seconds)
    return None


# ============================
# Commands
# ============================

def test_module():
    params = demisto.params()
    base_url = (params.get("url") or "").rstrip("/")
    api_key = _api_key()

    if not base_url:
        raise DemistoException("Missing required instance parameter: 'url'")
    if not api_key:
        raise DemistoException("Missing required instance parameter: 'credentials_api.password'")

    s = _new_session()
    r = s.get(f"{base_url}/", headers=_api_headers(api_key), verify=_verify_flag(), timeout=15)
    if r.status_code in (200, 302):
        return_results("ok")
    else:
        raise DemistoException(f"API key test failed: {r.status_code} {_debug_slice(r.text)}")


def _build_task_payload_from_args(args: Dict[str, Any]) -> dict:
    task_name = demisto.params().get("task_name") or "XSOAR submit"
    assigned_user_id = demisto.params().get("assigned_user_id") or ""
    ai_driver_id = demisto.params().get("ai_driver_id") or ""
    default_policy_id = demisto.params().get("policy_id") or ""
    default_subject = demisto.params().get("subject") or ""

    log = args.get("log")
    ip_addr = args.get("ip_addr")
    # FIX 2: Check for 'subject', 'user_name', OR the instance default
    subject = args.get("subject") or args.get("user_name") or default_subject
    policy_id = args.get("policy_id") or default_policy_id

    if not log:
        raise DemistoException("'log' is required.")

    security_log = log if not ip_addr else f"{log} [ip:{ip_addr}]"

    return {
        "SearchText": log,
        "IpAddr": ip_addr,
        "UserName": subject,
        "PolicyId": policy_id,
        # UI/MVC-compatible fields (ignored by JSON API if not relevant)
        "TaskName": task_name,
        "AssignedUserID": assigned_user_id,
        "AIDriverID": ai_driver_id,
        "PolicyID": policy_id,
        "Subject": subject or "",
        "SecurityLog": security_log,
        "Status": 1,
    }


def shadowx_submit_task_command():
    params = demisto.params()
    base_url = (params.get("url") or "").rstrip("/")
    api_key = _api_key()

    payload = _build_task_payload_from_args(demisto.args())
    wait_seconds = arg_to_number(demisto.args().get("wait_seconds", 0)) or 0
    interval_seconds = arg_to_number(demisto.args().get("interval_seconds", 30)) or 30
    if interval_seconds < 1:
        interval_seconds = 1

    s = _new_session()

    submit_json = submit_with_api_key(s, base_url, api_key, payload)
    demisto.debug(f"[shadowx-submit-task] submit_json={submit_json}")

    task_id = _extract_task_id(submit_json) or ""
    ui_url = f"{base_url.rstrip('/')}/SecurityTasks/Details?taskID={task_id}" if task_id else ""

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
        readable_output=(f"ShadowX task submitted\nURL: {ui_url}" if ui_url else "ShadowX task submitted"),
        raw_response=out,
    ))


def shadowx_get_task_command():
    task_id = demisto.args().get("task_id")
    if not task_id:
        raise DemistoException("'task_id' is required.")

    base_url = (demisto.params().get("url") or "").rstrip("/")
    api_key = _api_key()

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
    return_results(
        "ShadowX SOCAI (API Key mode only)\n\n"
        "- `!shadowx-submit-task log=\"...\" [ip_addr=] [user_name=] [policy_id=] "
        "[wait_seconds=] [interval_seconds=]`\n"
        "- `!shadowx-get-task task_id=\"<GUID>\"`"
    )


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
