import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum
from typing import Optional

import requests
import urllib3
urllib3.disable_warnings()

import time

from datetime import datetime, timedelta
from typing import *


""" CONSTANTS """
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"   # Your API format

class Client:
    def __init__(self, params: dict):
        self.base_url = params.get("base_url", "").rstrip("/")
        self.access_token = params.get("access_token", {}).get("password", "").strip()

        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        demisto.debug(f"Client initialized with base_url: {self.base_url}, access_token: {self.access_token}")

    def http_post(self, endpoint: str, json_body: dict):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        demisto.debug(f"POST Request URL: {url}")
        demisto.debug(f"POST Request Headers: {self.headers}")
        demisto.debug(f"POST Request Body: {json_body}")
        resp = requests.post(
            url,
            headers=self.headers,
            json=json_body,
            verify=False
        )
        demisto.debug(f"Response Status Code: {resp.status_code}")
        try:
            resp.raise_for_status()
            resp_json = resp.json()
            return resp_json
        except Exception as e:
            demisto.debug(f"HTTP request failed: {e}, Response Text: {resp.text}")
            raise

    # ------------------------------
    # IOC LOOKUP
    # ------------------------------
    def ioc_lookup(self, ioc_value: str):
        endpoint = "/y/iocs"
        body = {"ioc": ioc_value}
        return self.http_post(endpoint, body)

    # ------------------------------
    # Fetch multiple IOC records (POST body)
    # ------------------------------
    def fetch_iocs(self, start_dt: str, end_dt: str, page: int = 1, limit: int = 50):
        endpoint = "/y/iocs"
        body = {
            "page": page,
            "limit": limit,
            "startDate": start_dt,
            "endDate": end_dt
        }
        demisto.debug(f"Fetching IOCs with body: {body}")
        return self.http_post(endpoint, body)

def get_time_range(hours_back: int, last_run: dict) -> Tuple[str, str]:
    """
    Determine the gte/lte timestamps for fetch.
    Uses hours only (days no longer supported).
    """
    now = datetime.utcnow()

    # If we have last_fetch → resume from there
    last_fetch = last_run.get("last_fetch")
    if last_fetch:
        gte_dt = datetime.fromisoformat(last_fetch)
    else:
        # First run → go back N hours
        gte_dt = now - timedelta(hours=hours_back)

    lte_dt = now

    demisto.debug(
        f"Calculated fetch time range: gte={gte_dt.isoformat()}Z, lte={lte_dt.isoformat()}Z"
    )

    return gte_dt.isoformat(), lte_dt.isoformat()

def fmt_date(ts):
    if not ts:
        return "None"
    # Convert timestamp (seconds since epoch) to readable UTC
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def epoch_to_iso(ts):
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


class VerdictEnum(str, Enum):
    UNKNOWN = "Unknown"
    NOT_MALICIOUS = "Not-Malicious"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"

class ConfidenceLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

def calculate_verdict(risk_score: Optional[float], confidence_rating: Optional[str]):
    if risk_score is None:
        risk_score = 0
    if confidence_rating is None:
        confidence_rating = "Low"

    # sanitize risk
    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0

    risk_score = max(0, min(100, risk_score))

    # normalize confidence for internal logic ONLY
    c = confidence_rating.lower()
    if c in ["high", "h"]:
        confidence_level = ConfidenceLevel.HIGH
    elif c in ["medium", "med", "m"]:
        confidence_level = ConfidenceLevel.MEDIUM
    else:
        confidence_level = ConfidenceLevel.LOW

    # matrix logic
    if 0 <= risk_score <= 24:
        if confidence_level == ConfidenceLevel.LOW:
            verdict = VerdictEnum.UNKNOWN
        elif confidence_level == ConfidenceLevel.MEDIUM:
            verdict = VerdictEnum.SUSPICIOUS
        else:
            verdict = VerdictEnum.NOT_MALICIOUS

    elif 25 <= risk_score <= 39:
        if confidence_level == ConfidenceLevel.LOW:
            verdict = VerdictEnum.UNKNOWN
        else:
            verdict = VerdictEnum.SUSPICIOUS

    elif 40 <= risk_score <= 60:
        verdict = VerdictEnum.SUSPICIOUS

    elif 61 <= risk_score <= 75:
        if confidence_level == ConfidenceLevel.HIGH:
            verdict = VerdictEnum.MALICIOUS
        else:
            verdict = VerdictEnum.SUSPICIOUS

    else:  # 76–100
        if confidence_level == ConfidenceLevel.LOW:
            verdict = VerdictEnum.SUSPICIOUS
        else:
            verdict = VerdictEnum.MALICIOUS

    # Only return verdict. Do NOT modify confidence rating.
    return verdict.value


# =====================================================
# FETCH IOCs COMMAND
# =====================================================
def fetch_indicators_command(client: Client, params: dict) -> int:
    """
    Fetch indicators in 1-hour chunks, insert per page immediately,
    use retry for HTTP errors, enforce max 24-hour first_fetch.
    """
    # --- first_fetch (hours) validation ---
    first_fetch_hours = int(params.get("first_fetch", 2))  # default 6 hrs

    if first_fetch_hours < 1 :
        first_fetch_hours=1
    if first_fetch_hours > 3:
        first_fetch_hours=3

    limit = int(params.get("max_fetch", 100))

    # honor "recreate"
    should_reset = demisto.args().get("recreate")
    if should_reset:
        demisto.debug("Re-fetch triggered → resetting last_run")
        last_run = {}
    else:
        last_run = demisto.getLastRun() or {}

    # --- compute initial range ---
    gte_str, final_lte_str = get_time_range(first_fetch_hours, last_run)
    gte = datetime.fromisoformat(gte_str)
    final_lte = datetime.fromisoformat(final_lte_str)

    demisto.debug(f"[fetch] initial gte={gte.isoformat()}Z final_lte={final_lte.isoformat()}Z")

    chunk_hours = 1
    total_inserted = 0

    # -------------------------
    # Fetch loop per chunk
    # -------------------------
    while gte < final_lte:
        chunk_lte_dt = min(gte + timedelta(hours=chunk_hours), final_lte)
        chunk_gte_iso = gte.isoformat()
        chunk_lte_iso = chunk_lte_dt.isoformat()

        demisto.debug(f"[fetch] Processing chunk: {chunk_gte_iso} → {chunk_lte_iso}")

        page = 1

        while True:
            demisto.debug(f"[fetch] Requesting page {page} for chunk {chunk_gte_iso} → {chunk_lte_iso}")

            # -------------------------
            # Retry mechanism (max 5 tries)
            # -------------------------
            retry_count = 0
            response = None

            while retry_count < 5:
                try:
                    resp = client.fetch_iocs(
                        start_dt=chunk_gte_iso,
                        end_dt=chunk_lte_iso,
                        page=page,
                        limit=limit
                    )

                    # enforce dict & 200
                    if isinstance(resp, dict) and resp.get("success", True):
                        response = resp
                        break

                    raise ValueError(f"Non-success API response: {resp}")

                except Exception as e:
                    retry_count += 1
                    demisto.debug(f"[fetch] Attempt {retry_count}/5 failed: {e}")

                    if retry_count == 5:
                        demisto.debug("[fetch] Max retries reached → skipping this page.")
                        response = None
                    else:
                        time.sleep(1)

            if not response:
                break

            # Parse IOCs safely
            data = response.get("data", {}) if isinstance(response, dict) else {}
            ioc_list = data.get("iocs", []) if isinstance(data, dict) else []

            if not ioc_list:
                demisto.debug(f"[fetch] No IOCs returned for page {page} (chunk finished).")
                break

            # -------------------------
            # Build indicators
            # -------------------------
            page_indicators = []
            for i in ioc_list:
                verdict = calculate_verdict(
                    i.get("risk_score"),
                    i.get("confidence_rating")
                )

                page_indicators.append({
                    "value": i.get("ioc"),
                    "type": i.get("ioc_type") or "Unknown",
                    "rawJSON": i,
                    "fields": {

                        # confidence auto-managed by XSOAR
                        "confidence": i.get("confidence_rating"),
                        "cybleverdict": verdict,

                        "cybleriskscore": i.get("risk_score"),
                        "cyblefirstseen": epoch_to_iso(i.get("first_seen")),
                        "cyblelastseen": epoch_to_iso(i.get("last_seen")),
                        "cyblebehaviourtags": i.get("behaviour_tags") or [],

                        "cyblesources": i.get("sources") or [],
                        "cybletargetcountries": i.get("target_countries") or [],
                        "cybletargetregions": i.get("target_regions") or [],
                        "cybletargetindustries": i.get("target_industries") or [],
                        "cyblerelatedmalware": i.get("related_malware") or [],
                        "cyblerelatedthreatactors": i.get("related_threat_actors") or []
                    }
                })

            # Insert indicators
            try:
                demisto.createIndicators(page_indicators)
                demisto.debug(f"[fetch] Inserted {len(page_indicators)} indicators (page {page}).")
            except Exception as e:
                demisto.debug(f"[fetch] Failed to createIndicators for page {page}: {e}")
                # decide: continue to next page or break. We'll continue.
            total_inserted += len(page_indicators)
            page += 1

        # save last_run per chunk
        try:
            demisto.setLastRun({"last_fetch": chunk_lte_iso})
            demisto.debug(f"[fetch] Updated last_run → {chunk_lte_iso}")
        except Exception as e:
            demisto.debug(f"[fetch] Failed to setLastRun: {e}")

        gte = chunk_lte_dt

    demisto.debug(f"[fetch] Completed. total_inserted={total_inserted}")
    return total_inserted


# ==========================================================================
# COMMAND: IOC LOOKUP
# ==========================================================================
def cyble_ioc_lookup_command(client: Client, args: dict):
    ioc = args.get("ioc")
    if not ioc:
        return_error("Missing required argument: ioc")

    demisto.debug(f"Running IOC lookup command for IOC: {ioc}")
    response = client.ioc_lookup(ioc)
    demisto.debug(f"IOC lookup API response: {response}")
    data = response.get("data", {})
    iocs = data.get("iocs", [])

    if not iocs:
        return CommandResults(
            readable_output=f"No results found for IOC: {ioc}",
            outputs_prefix="CybleIntel.IOCLookup",
            outputs={}
        )

    item = iocs[0]

    def fmt(v):
        if isinstance(v, list):
            return ", ".join(v)
        return v if v is not None else "None"

    table = {
        "IOC": item.get("ioc"),
        "IOC Type": item.get("ioc_type"),
        "First Seen": fmt_date(item.get("first_seen")),
        "Last Seen": fmt_date(item.get("last_seen")),
        "Risk Score": item.get("risk_score"),
        "Sources": fmt(item.get("sources")),
        "Behaviour Tags": fmt(item.get("behaviour_tags")),
        "Confidence Rating": item.get("confidence_rating"),
        "Target Countries": fmt(item.get("target_countries")),
        "Target Regions": fmt(item.get("target_regions")),
        "Target Industries": fmt(item.get("target_industries")),
        "Related Malware": fmt(item.get("related_malware")),
        "Related Threat Actors": fmt(item.get("related_threat_actors")),
    }

    readable = tableToMarkdown("Cyble IOC Lookup", table)

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CybleIntel.IOCLookup",
        outputs=table
    )


# ==========================================================================
# MAIN
# ==========================================================================
def main():  # pragma: no cover
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()

        client = Client(params)

        if command == "test-module":
            try:
                now = datetime.utcnow()
                start_dt = (now - timedelta(days=1)).strftime(DATETIME_FORMAT)
                end_dt = now.strftime(DATETIME_FORMAT)

                client.fetch_iocs(start_dt=start_dt, end_dt=end_dt, limit=1, page=1)
                return_results("ok")
            except Exception as e:
                return_error(f"Test failed: {e}")

        elif command == "cyble-vision-ioc-lookup":
            return_results(cyble_ioc_lookup_command(client, args))


        elif command == "fetch-indicators":
            inserted = fetch_indicators_command(client, params)
            return_results(f"Inserted {inserted} indicators.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

