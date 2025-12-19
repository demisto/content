import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import requests
from typing import Any, Dict, Optional
from datetime import datetime, timedelta

# ---- Helpers ----


def _return_results(obj: Any):
    try:
        demisto.results(obj)
    except Exception:
        print(json.dumps(obj, ensure_ascii=False, indent=2))


def _return_error(msg: str):
    _return_results({'Type': 4, 'ContentsFormat': 'text', 'Contents': msg})


def _json_entry(title: str, context: Dict[str, Any], contents: Any):
    hr = f"### {title}\n```json\n{json.dumps(contents, ensure_ascii=False, indent=2)}\n```"
    return {'Type': 1, 'ContentsFormat': 'json', 'Contents': contents,
            'HumanReadable': hr, 'EntryContext': context}


def _get_params():
    try:
        return demisto.params()
    except Exception:
        return {}


def _get_args():
    try:
        return demisto.args()
    except Exception:
        return {}


def _get_command():
    try:
        return demisto.command()
    except Exception:
        return 'test-module'

# ---- HTTP client ----


class SimpleClient:
    def __init__(self, base_url: str, verify: bool = True, proxy: bool = False,
                 headers: Optional[Dict[str, str]] = None, timeout: int = 60):
        self.base_url = base_url.rstrip('/')
        self.verify = verify
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update(headers or {})
        self.s.trust_env = bool(proxy)

    def post(self, path: str, headers: Optional[Dict[str, str]] = None,
             json_data: Optional[Any] = None, data: Optional[Any] = None) -> Any:
        url = f"{self.base_url}{path}"
        hdrs = self.s.headers.copy()
        if headers:
            hdrs.update(headers)
        r = self.s.post(url, headers=hdrs, json=json_data, data=data,
                        timeout=self.timeout, verify=self.verify)
        self._raise_for_status(r)
        return self._safe_json(r)

    def get(self, path: str, headers: Optional[Dict[str, str]] = None) -> Any:
        url = f"{self.base_url}{path}"
        hdrs = self.s.headers.copy()
        if headers:
            hdrs.update(headers)
        r = self.s.get(url, headers=hdrs, timeout=self.timeout, verify=self.verify)
        self._raise_for_status(r)
        return self._safe_json(r)

    @staticmethod
    def _safe_json(r: requests.Response) -> Any:
        try:
            return r.json()
        except Exception:
            return r.text

    @staticmethod
    def _raise_for_status(r: requests.Response):
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            try:
                msg = r.json()
            except Exception:
                msg = r.text
            raise RuntimeError(f"HTTP {r.status_code}: {msg}") from e

# ---- Forcepoint endpoints ----


def dlp_generate_refresh_token(client: SimpleClient, username: str, password: str) -> Any:
    headers = {"username": username, "password": password}
    return client.post("/dlp/rest/v1/auth/refresh-token", headers=headers)


def dlp_generate_access_token(client: SimpleClient, refresh_token: str) -> Any:
    headers = {"refresh-token": f"Bearer {refresh_token}"}
    return client.post("/dlp/rest/v1/auth/access-token", headers=headers)


def dlp_get_incidents(auth_client: SimpleClient, payload: Dict[str, Any]) -> Any:
    headers = {"Content-Type": "application/json"}
    return auth_client.post("/dlp/rest/v1/incidents/", headers=headers, json_data=payload)


def dlp_update_incidents(auth_client: SimpleClient, payload: Dict[str, Any]) -> Any:
    headers = {"Content-Type": "application/json"}
    return auth_client.post("/dlp/rest/v1/incidents/update", headers=headers, json_data=payload)


# ---- Token cache ----
TOKENS: Dict[str, Any] = {'refresh': None, 'access': None, 'refresh_issued': None, 'access_issued': None}
ACCESS_TTL_MIN = 15
REFRESH_TTL_MIN = 23 * 60


def _token_valid(issued_iso: Optional[str], ttl_minutes: int) -> bool:
    if not issued_iso:
        return False
    try:
        ts = datetime.fromisoformat(issued_iso)
        return datetime.utcnow() < ts + timedelta(minutes=ttl_minutes)
    except Exception:
        return False


def _get_access_token(base_client: SimpleClient, username: str, password: str) -> str:
    if TOKENS['access'] and _token_valid(TOKENS['access_issued'], ACCESS_TTL_MIN - 2):
        return TOKENS['access']
    if (not TOKENS['refresh']) or (not _token_valid(TOKENS['refresh_issued'], REFRESH_TTL_MIN - 30)):
        resp = dlp_generate_refresh_token(base_client, username, password)
        if isinstance(resp, dict):
            TOKENS['refresh'] = resp.get("refresh_token") or resp.get(
                "refreshToken") or (resp.get("data", {}) or {}).get("refresh_token")
            at_inline = resp.get("access_token") or resp.get("accessToken")
            TOKENS['refresh_issued'] = datetime.utcnow().isoformat()
            if at_inline:
                TOKENS['access'] = at_inline
                TOKENS['access_issued'] = datetime.utcnow().isoformat()
    if (not TOKENS['access']) or (not _token_valid(TOKENS['access_issued'], ACCESS_TTL_MIN - 2)):
        resp2 = dlp_generate_access_token(base_client, TOKENS['refresh'])
        access = None
        if isinstance(resp2, dict):
            access = resp2.get("access_token") or resp2.get("accessToken")
        if not access:
            raise RuntimeError("Failed to obtain access_token from Forcepoint DLP.")
        TOKENS['access'] = access
        TOKENS['access_issued'] = datetime.utcnow().isoformat()
    return TOKENS['access']


def _build_auth_client(base_client: SimpleClient, access_token: str) -> SimpleClient:
    headers = base_client.s.headers.copy()
    headers.update({"Authorization": f"Bearer {access_token}"})
    return SimpleClient(base_url=base_client.base_url, verify=base_client.verify, proxy=base_client.s.trust_env, headers=headers)

# ---- Format helpers ----


def _format_fp_date(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S")


def _validate_ddmmyyyy_hhmmss(value: Optional[str], name: str) -> Optional[str]:
    if not value:
        return None
    try:
        datetime.strptime(value, "%d/%m/%Y %H:%M:%S")
        return None
    except Exception:
        return f'{name} must be "DD/MM/YYYY HH:MM:SS".'


def _severity_to_xsoar(sev: str) -> int:
    u = (sev or "").upper()
    return 3 if u == "HIGH" else 2 if u == "MEDIUM" else 1 if u == "LOW" else 0


def _incident_name(i: Dict[str, Any]) -> str:
    pid = i.get("id") or i.get("incidentId") or ""
    pol = i.get("policy") or i.get("policy_name") or ""
    return f"Forcepoint DLP Incident {pid} {pol}".strip()


def _incident_occurred(i: Dict[str, Any]) -> str:
    for k in ("INSERT_DATE", "insert_date", "timestamp", "occurred", "date"):
        v = i.get(k)
        if isinstance(v, str):
            return v
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ---- Admin helpers ----


def cmd_show_state():
    try:
        state = demisto.getLastRun() or {}
    except Exception:
        state = {}
    _return_results(_json_entry("Forcepoint DLP – Current Fetch State", {}, state))


def cmd_reset_state():
    try:
        demisto.setLastRun({})
        _return_results("state reset ok")
    except Exception as e:
        _return_error(str(e))

# ---- Commands ----


def cmd_test_module(client: SimpleClient, params: Dict[str, Any]):
    username = (params.get("credentials") or {}).get("identifier") or params.get("username")
    password = (params.get("credentials") or {}).get("password") or params.get("password")
    if not username or not password:
        _return_error("Credentials not configured (Local Application admin required).")
        return
    try:
        _get_access_token(client, username, password)
        _return_results("ok")
    except Exception as e:
        msg = str(e)
        if any(x in msg for x in ("403", "Forbidden", "Unauthorized")):
            _return_error("Authorization Error: Ensure Local Application admin & correct credentials.")
        else:
            _return_error(msg)


def cmd_get_incidents(base_client: SimpleClient, params: Dict[str, Any], args: Dict[str, Any]):
    if not args.get("status"):
        args["status"] = "IN_PROGRESS"
    e1 = _validate_ddmmyyyy_hhmmss(args.get("from_date"), "from_date")
    e2 = _validate_ddmmyyyy_hhmmss(args.get("to_date"), "to_date")
    if e1 or e2:
        _return_error(e1 or e2)
        return
    username = (params.get("credentials") or {}).get("identifier") or params.get("username")
    password = (params.get("credentials") or {}).get("password") or params.get("password")
    if not username or not password:
        _return_error("Instance credentials (Local Application admin) required.")
        return
    try:
        at = _get_access_token(base_client, username, password)
        auth_client = _build_auth_client(base_client, at)
        payload: Dict[str, Any] = {"type": args.get("type") or "INCIDENTS"}
        for key in ("from_date", "to_date", "status", "severity", "action", "policies", "sort_by"):
            v = args.get(key)
            if v:
                payload[key] = v
        resp = dlp_get_incidents(auth_client, payload)
        incidents = resp.get("incidents") or resp.get("data") or resp.get("result") or resp
        context = {"ForcepointDLP.Incidents": incidents}
        _return_results(_json_entry("Forcepoint DLP – Incidents (JSON)", context, incidents))
    except Exception as e:
        _return_results(_json_entry("Forcepoint DLP – Incidents Error", {}, {"error": str(e)}))


def cmd_fetch_incidents(base_client: SimpleClient, params: Dict[str, Any]):
    username = (params.get("credentials") or {}).get("identifier") or params.get("username")
    password = (params.get("credentials") or {}).get("password") or params.get("password")
    if not username or not password:
        _return_error("Fetch incidents requires Local Application admin credentials in instance.")
        return

    fetch_status = params.get("fetch_status") or "IN_PROGRESS"
    fetch_from = params.get("fetch_from_date") or ""
    fetch_to = params.get("fetch_to_date") or ""
    interval = params.get("incidentFetchInterval") or "24h"
    now = datetime.utcnow()
    ignore_static = params.get("ignore_static_dates", True)
    watermark_field = (params.get("watermark_field") or "INSERT_DATE").strip()
    dedup_key_field = (params.get("dedup_key_field") or "eventId").strip()
    dedup_cache_size = int(params.get("dedup_cache_size") or 1000)

    # Load state early
    try:
        last_run = demisto.getLastRun() or {}
    except Exception:
        last_run = {}
    last_iso = last_run.get("last_fetch_iso")

    # Build window
    if (fetch_from and fetch_to) and not ignore_static:
        e1 = _validate_ddmmyyyy_hhmmss(fetch_from, "fetch_from_date")
        e2 = _validate_ddmmyyyy_hhmmss(fetch_to, "fetch_to_date")
        if e1 or e2:
            _return_error(e1 or e2)
            return
        from_dt_str = fetch_from
        to_dt_str = fetch_to
    else:
        if last_iso:
            try:
                from_dt = datetime.fromisoformat(last_iso)
            except Exception:
                from_dt = now - timedelta(hours=24)
        else:
            try:
                n = int(interval[:-1])
                unit = interval[-1].lower()
                if unit == 'h':
                    from_dt = now - timedelta(hours=n)
                elif unit == 'd':
                    from_dt = now - timedelta(days=n)
                elif unit == 'm':
                    from_dt = now - timedelta(minutes=n)
                else:
                    from_dt = now - timedelta(hours=24)
            except Exception:
                from_dt = now - timedelta(hours=24)
        from_dt_str = _format_fp_date(from_dt)
        to_dt_str = _format_fp_date(now)

    payload = {"type": "INCIDENTS", "from_date": from_dt_str,
               "to_date": to_dt_str, "status": fetch_status, "sort_by": "INSERT_DATE"}
    max_fetch = int(params.get("max_fetch", 50))

    try:
        at = _get_access_token(base_client, username, password)
        auth_client = _build_auth_client(base_client, at)
        resp = dlp_get_incidents(auth_client, payload)
        incidents_raw = resp.get("incidents") or resp.get("data") or resp.get("result") or []
        if not isinstance(incidents_raw, list):
            incidents_raw = [incidents_raw]

        seen_ids = set(last_run.get("seen_event_ids", []))

        def parse_insert_date(i: Dict[str, Any]) -> datetime:
            v = i.get(watermark_field) or i.get(watermark_field.lower())
            if isinstance(v, str):
                for fmt in ("%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                    try:
                        return datetime.strptime(v, fmt)
                    except Exception:
                        continue
            # fallback to common keys
            for k in ("INSERT_DATE", "insert_date", "timestamp", "occurred", "date"):
                v2 = i.get(k)
                if isinstance(v2, str):
                    for fmt in ("%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                        try:
                            return datetime.strptime(v2, fmt)
                        except Exception:
                            continue
            return datetime.utcnow()

        def get_dedup_id(i: Dict[str, Any]) -> Optional[int]:
            v = i.get(dedup_key_field)
            if v is None:
                # fallback chain
                for key in ("event_id", "eventId", "id", "incidentId"):
                    v = i.get(key)
                    if v is not None:
                        break
            if v is None:
                return None
            try:
                return int(str(v))
            except Exception:
                return None

        last_dt = None
        if last_iso:
            try:
                last_dt = datetime.fromisoformat(last_iso)
            except Exception:
                last_dt = None

        filtered = []
        max_dt = last_dt or datetime.min
        for i in incidents_raw[:max_fetch]:
            eid = get_dedup_id(i)
            ins_dt = parse_insert_date(i)
            if last_dt and ins_dt <= last_dt:
                continue
            if eid is not None and eid in seen_ids:
                continue
            filtered.append(i)
            if eid is not None:
                seen_ids.add(eid)
            if ins_dt > max_dt:
                max_dt = ins_dt

        if len(seen_ids) > dedup_cache_size:
            seen_ids = set(list(seen_ids)[-dedup_cache_size:])

        xsoar_incidents = [{
            "name": _incident_name(i),
            "occurred": _incident_occurred(i),
            "severity": _severity_to_xsoar(i.get("severity")),
            "rawJSON": json.dumps(i, ensure_ascii=False)
        } for i in filtered]

        next_dt = (max_dt if max_dt != datetime.min else datetime.utcnow()) + timedelta(seconds=1)
        next_run = {"last_fetch_iso": next_dt.isoformat(), "seen_event_ids": list(seen_ids)}

        # Always persist state even if no incidents
        try:
            demisto.setLastRun(next_run)
        except Exception:
            pass
        try:
            demisto.incidents(xsoar_incidents)
        except Exception:
            _return_results(_json_entry("Forcepoint DLP – Fetch Incidents (JSON)", {"NextRun": next_run}, xsoar_incidents))
    except Exception as e:
        _return_results(_json_entry("Forcepoint DLP – Fetch Error", {}, {"error": str(e), "payloadSent": payload}))


def cmd_update_incident(base_client: SimpleClient, params: Dict[str, Any], args: Dict[str, Any]):
    raw_event_ids = args.get("event_ids") or args.get("incident_id")
    partition_index = args.get("partition_index")
    status_value = args.get("status")
    severity_value = args.get("severity")
    tag_value = args.get("tag")
    explicit_action_type = args.get("action_type")
    explicit_value = args.get("value")
    comments = args.get("comments")

    action_type, value = None, None
    if explicit_action_type and explicit_value:
        action_type = str(explicit_action_type).upper()
        value = str(explicit_value)
    elif status_value:
        action_type = "STATUS"
        value = str(status_value).upper()
    elif severity_value:
        action_type = "SEVERITY"
        value = str(severity_value).upper()
    elif tag_value:
        action_type = "TAG"
        value = str(tag_value)
    else:
        _return_error("Provide one of: status, severity, tag OR action_type+value.")
        return

    if not raw_event_ids and not (args.get("incident_id") and partition_index):
        _return_error("Provide event_ids (preferred) OR incident_id + partition_index.")
        return

    event_ids = None
    if raw_event_ids:
        try:
            if isinstance(raw_event_ids, (list, tuple)):
                event_ids = [int(str(x)) for x in raw_event_ids]
            else:
                event_ids = [int(x) for x in str(raw_event_ids).split(",")]
        except Exception:
            _return_error("event_ids/incident_id must be integer(s).")
            return

    username = (params.get("credentials") or {}).get("identifier") or params.get("username")
    password = (params.get("credentials") or {}).get("password") or params.get("password")
    if not username or not password:
        _return_error("Instance credentials (Local Application admin) required.")
        return

    try:
        at = _get_access_token(base_client, username, password)
        auth_client = _build_auth_client(base_client, at)
        payload = {"type": "INCIDENTS", "action_type": action_type, "value": value}
        if event_ids:
            payload["event_ids"] = event_ids
        else:
            payload["incident_id"] = int(args.get("incident_id"))
            payload["partition_index"] = int(partition_index)
        if comments:
            payload["comments"] = comments
        resp = dlp_update_incidents(auth_client, payload)
        _return_results(_json_entry("Forcepoint DLP – Update Incident (JSON)", {"ForcepointDLP.UpdateIncident": resp}, resp))
    except Exception as e:
        _return_error(str(e))

# ---- Main ----


def main():
    params = _get_params()
    args = _get_args()
    command = _get_command()
    base_url = params.get("url") or ""
    if not base_url:
        _return_error('Instance param "url" is required, e.g., https://<DLP_Manager_IP>:<port>')
        return
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    client = SimpleClient(base_url=base_url, verify=verify, proxy=proxy)
    try:
        if command == "test-module":
            cmd_test_module(client, params)
        elif command == "forcepoint-dlp-get-incidents":
            cmd_get_incidents(client, params, args)
        elif command == "forcepoint-dlp-update-incident":
            cmd_update_incident(client, params, args)
        elif command == "forcepoint-dlp-reset-state":
            cmd_reset_state()
        elif command == "forcepoint-dlp-show-state":
            cmd_show_state()
        elif command == "fetch-incidents":
            cmd_fetch_incidents(client, params)
        else:
            _return_error(f"Command {command} is not implemented.")
    except Exception as e:
        _return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
