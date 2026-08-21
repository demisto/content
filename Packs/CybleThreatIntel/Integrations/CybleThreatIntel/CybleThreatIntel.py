from typing import *
from datetime import datetime, timedelta
import time
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum

import requests
import urllib3

urllib3.disable_warnings()


""" CONSTANTS """
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"  # Your API format
MAX_API_PAGE_LIMIT = 100
CHUNK_MINUTES = 15
# Non-TIM XSOAR licenses hard-cap ingestion at 100 indicators per fetch-indicators run.
# Calling createIndicators again after that logs success in our code but the platform ingests 0
# and advancing the page checkpoint would permanently skip those IOCs.
DEFAULT_MAX_INDICATORS_PER_FETCH = 100
# Stop before the Docker execution limit so setLastRun commits on a normal return.
# 60s covers a slow API round-trip, createIndicators, setLastRun, and script teardown.
TIME_TO_RUN_BUFFER_SECONDS = 60
DEFAULT_EXECUTION_TIMEOUT_SECONDS = 3 * 60
FETCH_RETRY_ATTEMPTS = 5
FETCH_RETRY_SLEEP_SECONDS = 1


class Client:
    def __init__(self, params: dict):
        self.base_url = params.get("base_url", "").rstrip("/")
        self.access_token = params.get("credentials", {}).get("password", "").strip()

        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        demisto.debug(f"Client initialized with base_url: {self.base_url}")

    def http_post(self, endpoint: str, json_body: dict):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        demisto.debug(f"POST Request URL: {url}")
        demisto.debug(f"POST Request Body: {json_body}")
        resp = requests.post(url, headers=self.headers, json=json_body, verify=False)
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
        body = {"page": page, "limit": limit, "startDate": start_dt, "endDate": end_dt}
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

    demisto.debug(f"Calculated fetch time range: gte={gte_dt.isoformat()}Z, lte={lte_dt.isoformat()}Z")

    return gte_dt.isoformat(), lte_dt.isoformat()


def get_execution_timeout_seconds() -> float:
    """Return the Docker execution budget in seconds from the platform, or the default."""
    timeout_nanoseconds = demisto.callingContext.get("context", {}).get("TimeoutDuration")
    if timeout_nanoseconds:
        return timeout_nanoseconds / 1_000_000_000
    return float(DEFAULT_EXECUTION_TIMEOUT_SECONDS)


def should_stop_before_next_page(
    pages_completed: int, last_page_duration_seconds: float, execution_start: datetime
) -> bool:
    """
    Akamai-style guard: always allow the first page, then stop if there is not enough
    budget left to safely complete another page plus TIME_TO_RUN_BUFFER_SECONDS.
    """
    if pages_completed <= 0:
        return False

    elapsed_seconds = (datetime.utcnow() - execution_start).total_seconds()
    remaining_seconds = get_execution_timeout_seconds() - elapsed_seconds - TIME_TO_RUN_BUFFER_SECONDS
    estimated_next_page_seconds = last_page_duration_seconds if last_page_duration_seconds > 0 else elapsed_seconds

    demisto.debug(
        f"[fetch] timeout check: elapsed={elapsed_seconds:.1f}s, remaining={remaining_seconds:.1f}s, "
        f"estimated_next_page={estimated_next_page_seconds:.1f}s"
    )
    return remaining_seconds <= estimated_next_page_seconds


def save_fetch_checkpoint(chunk_gte_iso: str, next_page: int, chunk_lte_iso: str) -> None:
    """Persist in-progress chunk pagination. All values must be strings for setLastRun."""
    demisto.setLastRun(
        {
            "last_fetch": chunk_gte_iso,
            "page": str(next_page),
            "chunk_lte": chunk_lte_iso,
        }
    )
    demisto.debug(f"[fetch] Checkpoint saved: last_fetch={chunk_gte_iso}, page={next_page}, chunk_lte={chunk_lte_iso}")


def save_chunk_completed_checkpoint(chunk_lte_iso: str) -> None:
    """Chunk finished; advance the time cursor and clear pagination state."""
    demisto.setLastRun({"last_fetch": chunk_lte_iso})
    demisto.debug(f"[fetch] Chunk completed, last_fetch advanced to {chunk_lte_iso}")


def parse_resume_state(last_run: dict) -> tuple[int, str | None]:
    """Return the page and chunk end to resume from, if present."""
    raw_page = last_run.get("page")
    if raw_page is None:
        return 1, None

    try:
        resume_page = int(raw_page)
    except (TypeError, ValueError):
        return 1, None

    if resume_page <= 1:
        return 1, None

    return resume_page, last_run.get("chunk_lte")


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


# Cyble Vision returns types like IPv4 / FileHash-MD5; XSOAR TIM expects FeedIndicatorType values (IP / File).
CYBLE_IOC_TYPE_MAP = {
    "ip": FeedIndicatorType.IP,
    "ipv4": FeedIndicatorType.IP,
    "ipv6": FeedIndicatorType.IPv6,
    "cidr": FeedIndicatorType.CIDR,
    "ipv6cidr": FeedIndicatorType.IPv6CIDR,
    "domain": FeedIndicatorType.Domain,
    "hostname": FeedIndicatorType.Domain,
    "fqdn": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "uri": FeedIndicatorType.URL,
    "email": FeedIndicatorType.Email,
    "cve": FeedIndicatorType.CVE,
    "md5": FeedIndicatorType.File,
    "sha1": FeedIndicatorType.File,
    "sha256": FeedIndicatorType.File,
    "sha512": FeedIndicatorType.File,
    "hash": FeedIndicatorType.File,
    "file": FeedIndicatorType.File,
    "filehash-md5": FeedIndicatorType.File,
    "filehash-sha1": FeedIndicatorType.File,
    "filehash-sha256": FeedIndicatorType.File,
    "filehash-sha512": FeedIndicatorType.File,
    "filehash-imphash": FeedIndicatorType.File,
    "filehash-pehash": FeedIndicatorType.File,
    "ssdeep": FeedIndicatorType.SSDeep,
    "mutex": FeedIndicatorType.MUTEX,
    "asn": FeedIndicatorType.AS,
    "as": FeedIndicatorType.AS,
}


def map_cyble_ioc_type(raw_type: Any, value: Any = None) -> str | None:
    """
    Map a Cyble ioc_type to an XSOAR FeedIndicatorType string.
    Returns None when the type cannot be mapped (caller should skip the IOC).
    """
    if raw_type is not None:
        normalized = str(raw_type).strip().lower().replace("_", "-").replace(" ", "")
        mapped = CYBLE_IOC_TYPE_MAP.get(normalized)
        if mapped:
            return mapped
        # Already a valid XSOAR type (e.g. "IP", "Domain")
        if FeedIndicatorType.is_valid_type(str(raw_type).strip()):
            return str(raw_type).strip()

    if value:
        detected = FeedIndicatorType.ip_to_indicator_type(str(value).strip())
        if detected:
            return detected

    return None


def build_indicator_from_ioc(ioc: dict) -> dict | None:
    """Build an XSOAR indicator dict from a Cyble IOC row, or None if it must be skipped."""
    value = ioc.get("ioc")
    if value is None or str(value).strip() == "":
        return None

    indicator_type = map_cyble_ioc_type(ioc.get("ioc_type"), value)
    if not indicator_type:
        return None

    verdict = calculate_verdict(ioc.get("risk_score"), ioc.get("confidence_rating"))
    return {
        "value": str(value).strip(),
        "type": indicator_type,
        "rawJSON": ioc,
        "fields": {
            "confidence": ioc.get("confidence_rating"),
            "cybleverdict": verdict,
            "cybleriskscore": ioc.get("risk_score"),
            "cyblefirstseen": epoch_to_iso(ioc.get("first_seen")),
            "cyblelastseen": epoch_to_iso(ioc.get("last_seen")),
            "cyblebehaviourtags": ioc.get("behaviour_tags") or [],
            "cyblesources": ioc.get("sources") or [],
            "cybletargetcountries": ioc.get("target_countries") or [],
            "cybletargetregions": ioc.get("target_regions") or [],
            "cybletargetindustries": ioc.get("target_industries") or [],
            "cyblerelatedmalware": ioc.get("related_malware") or [],
            "cyblerelatedthreatactors": ioc.get("related_threat_actors") or [],
        },
    }


class VerdictEnum(str, Enum):
    UNKNOWN = "Unknown"
    NOT_MALICIOUS = "Not-Malicious"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


class ConfidenceLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


def calculate_verdict(risk_score: float | None, confidence_rating: str | None):
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
    Fetch indicators in bounded 15-minute chunks with page-level checkpointing.
    Inserts each page immediately, saves last_run after each successful page, and exits
    gracefully before the Docker execution timeout when the remaining budget is low.

    Also respects the per-fetch indicator cap (default 100). Non-TIM XSOAR licenses reject
    any createIndicators calls after the first 100 of a run; we must stop and checkpoint
    instead of advancing pages that were not actually ingested.
    """
    first_fetch_hours = int(params.get("initial_interval", 2))

    if first_fetch_hours < 1:
        first_fetch_hours = 1
    if first_fetch_hours > 3:
        first_fetch_hours = 3

    limit = min(int(params.get("limit", MAX_API_PAGE_LIMIT)), MAX_API_PAGE_LIMIT)
    try:
        max_per_fetch = int(params.get("max_indicators_per_fetch") or DEFAULT_MAX_INDICATORS_PER_FETCH)
    except (TypeError, ValueError):
        max_per_fetch = DEFAULT_MAX_INDICATORS_PER_FETCH
    if max_per_fetch < 1:
        max_per_fetch = DEFAULT_MAX_INDICATORS_PER_FETCH

    should_reset = demisto.args().get("recreate")
    if should_reset:
        demisto.debug("Re-fetch triggered → resetting last_run")
        last_run: Dict[str, Any] = {}
    else:
        last_run = demisto.getLastRun() or {}

    gte_str, final_lte_str = get_time_range(first_fetch_hours, last_run)
    gte = datetime.fromisoformat(gte_str)
    final_lte = datetime.fromisoformat(final_lte_str)

    resume_page, resume_chunk_lte = parse_resume_state(last_run)
    execution_start = datetime.utcnow()
    last_page_duration_seconds = 0.0
    pages_completed = 0
    total_inserted = 0

    demisto.debug(
        f"[fetch] initial gte={gte.isoformat()}Z final_lte={final_lte.isoformat()}Z "
        f"resume_page={resume_page} timeout_budget={get_execution_timeout_seconds()}s "
        f"max_per_fetch={max_per_fetch}"
    )

    while gte < final_lte:
        chunk_lte_dt = min(gte + timedelta(minutes=CHUNK_MINUTES), final_lte)
        if resume_chunk_lte:
            try:
                parsed_chunk_lte = datetime.fromisoformat(resume_chunk_lte)
                if gte <= parsed_chunk_lte <= final_lte:
                    chunk_lte_dt = parsed_chunk_lte
            except ValueError:
                demisto.debug(f"[fetch] Ignoring invalid resume chunk_lte: {resume_chunk_lte}")
            resume_chunk_lte = None

        chunk_gte_iso = gte.isoformat()
        chunk_lte_iso = chunk_lte_dt.isoformat()
        page = resume_page
        resume_page = 1

        demisto.debug(f"[fetch] Processing chunk: {chunk_gte_iso} → {chunk_lte_iso}, starting at page {page}")

        while True:
            if total_inserted >= max_per_fetch:
                demisto.debug(
                    f"[fetch] Reached per-fetch indicator cap ({max_per_fetch}). "
                    f"Exiting cleanly; next run resumes at page {page}. "
                    f"(Non-TIM XSOAR licenses ingest at most 100 indicators per fetch.)"
                )
                return total_inserted

            if should_stop_before_next_page(pages_completed, last_page_duration_seconds, execution_start):
                demisto.debug("[fetch] Approaching Docker timeout; exiting after last successful page.")
                return total_inserted

            demisto.debug(f"[fetch] Requesting page {page} for chunk {chunk_gte_iso} → {chunk_lte_iso}")
            page_start = time.time()
            response = None

            for attempt in range(FETCH_RETRY_ATTEMPTS):
                try:
                    resp = client.fetch_iocs(start_dt=chunk_gte_iso, end_dt=chunk_lte_iso, page=page, limit=limit)
                    if isinstance(resp, dict) and resp.get("success", True):
                        response = resp
                        break
                    raise ValueError(f"Non-success API response: {resp}")
                except Exception as e:
                    demisto.debug(f"[fetch] Attempt {attempt + 1}/{FETCH_RETRY_ATTEMPTS} failed: {e}")
                    if attempt + 1 == FETCH_RETRY_ATTEMPTS:
                        demisto.debug("[fetch] Max retries reached; preserving checkpoint and exiting.")
                        if pages_completed > 0:
                            save_fetch_checkpoint(chunk_gte_iso, page, chunk_lte_iso)
                        return total_inserted
                    time.sleep(FETCH_RETRY_SLEEP_SECONDS)

            data = response.get("data", {}) if isinstance(response, dict) else {}
            ioc_list = data.get("iocs", []) if isinstance(data, dict) else []

            if not ioc_list:
                demisto.debug(f"[fetch] No IOCs returned for page {page}; chunk finished.")
                break

            page_indicators = []
            skipped = 0
            for i in ioc_list:
                indicator = build_indicator_from_ioc(i)
                if indicator:
                    page_indicators.append(indicator)
                else:
                    skipped += 1

            if skipped:
                demisto.debug(
                    f"[fetch] Page {page}: skipped {skipped}/{len(ioc_list)} IOCs "
                    f"(empty value or unmapped ioc_type)"
                )

            remaining_quota = max_per_fetch - total_inserted
            if remaining_quota <= 0:
                demisto.debug(
                    f"[fetch] Per-fetch cap already reached before submitting page {page}; "
                    f"not calling createIndicators. Resume page stays {page}."
                )
                return total_inserted

            if len(page_indicators) > remaining_quota:
                # Avoid partial-page checkpointing: submit only what fits, then resume same page
                # would re-send duplicates. Prefer stopping before this page if it cannot fit fully.
                demisto.debug(
                    f"[fetch] Page {page} has {len(page_indicators)} indicators but only "
                    f"{remaining_quota} remain in this fetch's quota. Exiting without advancing "
                    f"so the full page can be ingested on the next run."
                )
                save_fetch_checkpoint(chunk_gte_iso, page, chunk_lte_iso)
                return total_inserted

            if not page_indicators:
                # API returned rows we cannot store; advance so we do not loop forever on this page.
                demisto.debug(f"[fetch] Page {page}: no mappable indicators; advancing pagination.")
                pages_completed += 1
                last_page_duration_seconds = max(last_page_duration_seconds, time.time() - page_start)
                page += 1
                save_fetch_checkpoint(chunk_gte_iso, page, chunk_lte_iso)
                continue

            try:
                demisto.createIndicators(page_indicators)
                demisto.debug(
                    f"[fetch] Inserted {len(page_indicators)} indicators (page {page})"
                    + (f", skipped {skipped}." if skipped else ".")
                )
            except Exception as e:
                demisto.error(f"[fetch] Failed to createIndicators for page {page}: {e}")
                save_fetch_checkpoint(chunk_gte_iso, page, chunk_lte_iso)
                return total_inserted

            total_inserted += len(page_indicators)
            pages_completed += 1
            last_page_duration_seconds = max(last_page_duration_seconds, time.time() - page_start)
            page += 1
            save_fetch_checkpoint(chunk_gte_iso, page, chunk_lte_iso)

            if total_inserted >= max_per_fetch:
                demisto.debug(
                    f"[fetch] Reached per-fetch indicator cap ({max_per_fetch}). "
                    f"Exiting cleanly; next run resumes at page {page}. "
                    f"(Non-TIM XSOAR licenses ingest at most 100 indicators per fetch.)"
                )
                return total_inserted

            if should_stop_before_next_page(pages_completed, last_page_duration_seconds, execution_start):
                demisto.debug("[fetch] Page budget exhausted; exiting cleanly to commit checkpoint.")
                return total_inserted

        save_chunk_completed_checkpoint(chunk_lte_iso)
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
    ioc_value: str = str(ioc)
    demisto.debug(f"Running IOC lookup command for IOC: {ioc}")
    response = client.ioc_lookup(ioc_value)
    demisto.debug(f"IOC lookup API response: {response}")
    data = response.get("data", {})
    iocs = data.get("iocs", [])

    if not iocs:
        return CommandResults(
            readable_output=f"No results found for IOC: {ioc}", outputs_prefix="CybleIntel.IOCLookup", outputs={}
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

    return CommandResults(readable_output=readable, outputs_prefix="CybleIntel.IOCLookup", outputs=table)


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

        elif command in ["cyble-vision-fetch-taxii", "cyble-vision-get-collection-names"]:
            return_results(f"The command '{command}' is deprecated and no longer supported.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
