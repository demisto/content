"""Base Integration for Cortex XSOAR (aka Demisto)

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
from typing import Any, Dict, List, Tuple
from datetime import datetime, timedelta, timezone
import json
from dateparser import parse

import demistomock as demisto
from CommonServerPython import *


# ============================================
# CONFIG
# ============================================
ETD_LOG_TYPES = ["message", "audit", "connection"]

VENDOR = "Cisco"
PRODUCT = "ETD"

# ============================================
# CLIENT
# ============================================


class ETDClient(ContentClient):

    def __init__(self, base_url: str, params: dict):
        self.params = params
        super().__init__(
            base_url=base_url,
            headers={},
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False)
        )

    def get_access_token(self) -> str:

        api_key = get_credential(self.params.get("api_key"))
        client_secret = get_credential(self.params.get("client_secret"))

        demisto.debug(f"[DEBUG] BASE URL: {self._base_url}")
        demisto.debug(f"[DEBUG] API KEY TYPE: {type(api_key)}")
        demisto.debug(f"[DEBUG] API KEY LENGTH: {len(api_key) if api_key else 0}")
        demisto.debug(f"[DEBUG] SECRET LENGTH: {len(client_secret) if client_secret else 0}")

        headers = {
            "x-api-key": api_key
        }
        demisto.debug("[DEBUG] Sending token request...")
        res = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers=headers,
            auth=(self.params.get("client_id"), client_secret),
            timeout=30
        )

        token = res.get("accessToken")

        if not token:
            raise DemistoException(f"Token not found: {res}")

        return token

    def request_log_export(self, token: str, start: str, end: str) -> dict:
        headers = {
            "Authorization": f"Bearer {token}",
            "x-api-key": get_credential(self.params.get("api_key")),
            "Content-Type": "application/json",
        }

        body = {
            "timeRange": [start, end],
            "logTypes": ETD_LOG_TYPES,
        }

        return self._http_request(
            method="POST",
            url_suffix="/v1/logs/downloadLinks",
            headers=headers,
            json_data=body,
            timeout=120
        )

    def get_links(self, response: dict) -> List[Tuple[str, str]]:
        data = response.get("data", {})
        links = []

        for lt in ETD_LOG_TYPES:
            chunk = data.get(lt)
            if isinstance(chunk, list):
                links.extend([(lt, link) for link in chunk])

        return links

    def download_logs(self, links: List[Tuple[str, str]]) -> List[dict]:
        events = []

        for log_type, link in links:
            res = self._http_request(
                method="GET",
                full_url=link,
                resp_type="text",
                timeout=120
            )

            for line in res.splitlines():
                if not line.strip():
                    continue

                try:
                    ev = json.loads(line)
                    if not ev.get("logType"):
                        ev["logType"] = log_type
                    events.append(ev)
                except Exception:
                    continue

        return events


# ============================================
# XSIAM INGEST
# ============================================
def ingest_events_to_xsiam(events):

    BATCH_SIZE = 1000

    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]

        send_events_to_xsiam(
            events=batch,
            vendor=VENDOR,
            product=PRODUCT
        )

# ============================================
# HELPERS
# ============================================


def get_credential(param):
    if isinstance(param, dict):
        return param.get("password") or param.get("credentials", {}).get("password")
    return param


def generate_intervals(start_dt, end_dt):
    intervals = []
    current = start_dt

    while current < end_dt:
        next_t = current + timedelta(hours=3)

        # THIS IS THE IMPORTANT LINE
        if next_t > end_dt:
            next_t = end_dt

        intervals.append((current, next_t))
        current = next_t

    return intervals


# ============================================
# FETCH INCIDENTS / INGEST LOGS
# ============================================
def fetch_and_ingest_logs(client: ETDClient, params: dict):

    demisto.debug("ETD fetch-incidents started")

    now = datetime.now(timezone.utc).replace(
        minute=0,
        second=0,
        microsecond=0
    )

    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")

    # ----------------------------------
    # START TIME LOGIC
    # ----------------------------------
    if not last_fetch:

        first_fetch = params.get("first_fetch", "30 days")

        parsed_time = parse(first_fetch)

        if not parsed_time:
            raise DemistoException(
                f"Invalid first fetch value: {first_fetch}"
            )

        start_dt = parsed_time.astimezone(timezone.utc)

        # ETD 30-day workaround
        if first_fetch.strip().lower() == "30 days":
            start_dt += timedelta(hours=1)

    else:

        start_dt = datetime.fromisoformat(
            last_fetch.replace("Z", "+00:00")
        )

    backlog_days = (now - start_dt).days

    # process max 5 days at a time
    if backlog_days >= 6:

        end_dt = start_dt + timedelta(days=5)

        if end_dt > now:
            end_dt = now

    else:

        end_dt = now

    demisto.debug(
        f"Overall Fetch Window: {start_dt} → {end_dt}"
    )

    # ----------------------------------
    # GENERATE INTERVALS
    # ----------------------------------
    intervals = generate_intervals(start_dt, end_dt)

    demisto.debug(f"Total intervals: {len(intervals)}")

    token = client.get_access_token()

    # ----------------------------------
    # TRACK SUCCESSFUL CHECKPOINT
    # ----------------------------------
    latest_successful_fetch = start_dt

    # ----------------------------------
    # PROCESS EACH INTERVAL
    # ----------------------------------
    for start, end in intervals:

        interval_events = []

        start_time = start.strftime("%Y-%m-%dT%H")
        end_time = end.strftime("%Y-%m-%dT%H")

        demisto.debug(
            f"Fetching interval: {start_time} → {end_time}"
        )

        try:

            # ------------------------------
            # REQUEST EXPORT
            # ------------------------------
            resp = client.request_log_export(
                token,
                start_time,
                end_time
            )

            links = client.get_links(resp)

            if not links:

                demisto.debug(
                    f"No logs for interval: {start_time} → {end_time}"
                )

                # No logs still means interval succeeded
                latest_successful_fetch = end
                continue

            # ------------------------------
            # DOWNLOAD LOGS
            # ------------------------------
            interval_events = client.download_logs(links)

            demisto.debug(
                f"Downloaded {len(interval_events)} events"
            )

            # ------------------------------
            # INGEST TO XSIAM
            # ------------------------------
            if interval_events:

                ingest_events_to_xsiam(interval_events)

                demisto.debug(
                    f"Successfully ingested interval "
                    f"{start_time} → {end_time}"
                )

            # ------------------------------
            # UPDATE SUCCESS CHECKPOINT
            # ONLY AFTER SUCCESSFUL INGESTION
            # ------------------------------
            latest_successful_fetch = end

        except Exception as e:

            demisto.error(
                f"Interval failed: "
                f"{start_time} → {end_time} | {str(e)}"
            )
            break

    # ----------------------------------
    # SAVE ONLY SUCCESSFUL CHECKPOINT
    # ----------------------------------
    demisto.setLastRun({
        "last_fetch": latest_successful_fetch.isoformat()
    })

    demisto.debug(
        f"Checkpoint updated to: "
        f"{latest_successful_fetch.isoformat()}"
    )

    demisto.debug("Fetch completed")


# ============================================
# TEST MODULE
# ============================================
def test_module(client: ETDClient):

    try:
        token = client.get_access_token()

        if not token:
            raise DemistoException("Failed to retrieve token")

        return "ok"

    except Exception as e:
        demisto.error(f"[ERROR] Test failed: {str(e)}")
        raise


# ============================================
# MAIN
# ============================================
def main():
    demisto.debug("[DEBUG] MAIN STARTED")

    params = demisto.params()
    command = demisto.command()

    demisto.debug(f"[DEBUG] COMMAND: {command}")
    demisto.debug(f"[DEBUG] PARAM KEYS: {list(params.keys())}")

    client = ETDClient(
        base_url=params.get("etd_base_url"),
        params=params
    )

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "etd-fetch-logs":
            fetch_and_ingest_logs(client, params)
            return_results("ETD logs fetched successfully")
        elif command == "fetch-events":
            fetch_and_ingest_logs(client, params)
            return_results("ok")

    except Exception as e:
        demisto.error(f"[ERROR] MAIN FAILED: {str(e)}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
