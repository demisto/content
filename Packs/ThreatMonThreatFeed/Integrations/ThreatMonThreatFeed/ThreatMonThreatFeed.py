import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import hashlib
import re
import time
import traceback
from collections.abc import Callable
from datetime import datetime, timedelta, UTC
from email.utils import parsedate_to_datetime
from typing import Any

""" CONSTANTS """

DEFAULT_BASE_URL = "https://ioc.threatmonit.io"
TAXII_API_ROOT = "/taxii"
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
FEED_SOURCE_TAG = "ThreatMon"

# Maximum page size honoured by the ThreatMon TAXII server (larger values are silently capped).
PAGE_SIZE = 500
DEFAULT_FIRST_FETCH = "7 days"
DEFAULT_LOOKBACK_MINUTES = 180
DEFAULT_MAX_PAGES_PER_FETCH = 300
# Safety net so a single fetch run never exceeds the platform execution timeout. The crawl
# position is persisted after every page, so the next run resumes exactly where this one stopped.
MAX_FETCH_RUN_SECONDS = 25 * 60
STATE_VERSION = 3
SEEN_CACHE_MARGIN = timedelta(hours=6)
# The TAXII server silently returns an empty result for malformed added_after values, so the
# timestamp format sent to it must always be exactly this one.
TAXII_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Every collection must be crawled: the ThreatMon collections are not subsets of each other
# (for example, most IP indicators are only published in the "IP" collection, and most domain
# indicators only in the "All" collection), so skipping one of them loses indicators.
COLLECTIONS: dict[str, str] = {
    "All Threat Indicators": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
    "IP Address Indicators": "f438912e-d4a2-46cd-9c95-a36d62a07ef9",
    "IP Address Indicators with Ports": "f438912e-d367-43cd-1295-l98d62a07ef9",
    "URL Indicators": "e8832f1d-938e-4033-bafa-90ed74ec305d",
    "Domain Name Indicators": "2d9083b6-7662-467a-852f-df25f739227f",
    "File Hash Indicators": "c51fc32b-7eee-4ac4-9a61-feb151a1c99e",
    "C2 Server Indicators": "3f6872bf-f561-4b6a-9eb3-d6fe71d109a1",
}

# STIX 2.1 TLP marking definitions (TLP 1.0 and TLP 2.0).
TLP_MARKINGS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "WHITE",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "AMBER",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "AMBER+STRICT",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "RED",
}

# A single STIX comparison expression, e.g. ``domain-name:value = 'evil.com'`` or
# ``file:hashes.'SHA-256' = 'abc...'``.
STIX_COMPARISON_RE = re.compile(r"([\w-]+):([\w.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'")
IPV4_WITH_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$")
URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$", re.IGNORECASE)
CRYPTOCURRENCY_ADDRESS_TYPE = "Cryptocurrency Address"


""" CLIENT """


class Client(BaseClient):
    """
    Client for the ThreatMon TAXII 2.1 server.
    """

    def __init__(self, base_url: str, username: str, api_token: str, verify: bool, proxy: bool):
        base_url = base_url.rstrip("/")
        # Accept both the server root and the TAXII API root as the Server URL.
        if not base_url.endswith(TAXII_API_ROOT):
            base_url += TAXII_API_ROOT
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth=(username or "", api_token),
            headers={"Accept": TAXII_MEDIA_TYPE},
        )

    def get_collections(self) -> dict:
        return self._http_request(method="GET", url_suffix="/collections/", retries=3, backoff_factor=5)

    def get_objects_page(
        self, collection_id: str, added_after: str | None, next_cursor: str | None, limit: int = PAGE_SIZE
    ) -> tuple[dict, datetime | None]:
        """
        Fetches one page of STIX objects from a collection.

        Returns the TAXII envelope and the server time (from the HTTP ``Date`` header), which is used
        as the crawl checkpoint instead of the local clock or the object timestamps.
        """
        params: dict[str, Any] = {"limit": limit}
        if added_after:
            params["added_after"] = added_after
        if next_cursor:
            params["next"] = next_cursor

        response = self._http_request(
            method="GET",
            url_suffix=f"/collections/{collection_id}/objects/",
            params=params,
            resp_type="response",
            retries=3,
            backoff_factor=5,
            status_list_to_retry=[429, 500, 502, 503, 504],
            timeout=120,
        )
        try:
            envelope = response.json() or {}
        except ValueError as e:
            raise DemistoException(f"ThreatMon returned a non-JSON response for collection {collection_id}.") from e
        return envelope, parse_http_date(response.headers.get("Date"))


""" HELPERS """


def parse_http_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(UTC)
    except (TypeError, ValueError):
        return None


def to_taxii_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime(TAXII_TIME_FORMAT)


def from_taxii_time(value: str) -> datetime:
    return datetime.strptime(value, TAXII_TIME_FORMAT).replace(tzinfo=UTC)


def parse_stix_time(value: str | None) -> datetime | None:
    """Parses a STIX timestamp such as ``2026-11-03T10:18:16.12169Z``."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def resolve_collections(params: dict) -> list[tuple[str, str]]:
    """
    Returns the (name, id) pairs of the collections to fetch, defaulting to every collection.
    """
    selected = argToList(params.get("collections")) or list(COLLECTIONS)
    result = [(name, COLLECTIONS[name]) for name in selected if name in COLLECTIONS]
    for collection_id in argToList(params.get("collection_ids")):
        if collection_id not in [cid for _, cid in result]:
            result.append((collection_id, collection_id))
    if not result:
        raise DemistoException("No valid ThreatMon collection is selected.")
    return result


def classify_domain_name(value: str) -> tuple[str, str, dict]:
    """
    ThreatMon publishes several kinds of values as ``domain-name`` observables (for example ``1.2.3.4:443``,
    ``wss://host/path`` or Ethereum wallets). Re-classify them by their shape, so they are not ingested
    as invalid Domain indicators.
    """
    ipv4 = IPV4_WITH_PORT_RE.match(value)
    if ipv4:
        address, port = ipv4.groups()
        return FeedIndicatorType.IP, address, ({"port": port} if port else {})
    if value.startswith("[") and "]" in value:
        return FeedIndicatorType.IPv6, value[1:].split("]", 1)[0], {}
    if value.count(":") >= 2 and re.fullmatch(r"[0-9a-fA-F:]+", value):
        return FeedIndicatorType.IPv6, value, {}
    if URL_SCHEME_RE.match(value):
        return FeedIndicatorType.URL, value, {}
    if ETH_ADDRESS_RE.match(value):
        return CRYPTOCURRENCY_ADDRESS_TYPE, value, {}
    return (FeedIndicatorType.DomainGlob if value.startswith("*") else FeedIndicatorType.Domain), value, {}


def classify_observable(object_path: str, property_path: str, value: str) -> tuple[str | None, str, dict]:
    """
    Maps a STIX observable to a Cortex indicator type.

    Returns the indicator type (``None`` if unsupported), the normalized value and extra fields.
    """
    extra: dict[str, Any] = {}
    value = value.strip()

    if object_path == "ipv4-addr":
        match = IPV4_WITH_PORT_RE.match(value)
        if match:
            value, port = match.groups()
            if port:
                extra["port"] = port
        return (FeedIndicatorType.CIDR if "/" in value else FeedIndicatorType.IP), value, extra
    if object_path == "ipv6-addr":
        if value.startswith("[") and "]" in value:
            value = value[1:].split("]", 1)[0]
        return (FeedIndicatorType.IPv6CIDR if "/" in value else FeedIndicatorType.IPv6), value, extra
    if object_path == "domain-name":
        return classify_domain_name(value)
    if object_path == "url":
        return FeedIndicatorType.URL, value, extra
    if object_path == "email-addr":
        return FeedIndicatorType.Email, value, extra
    if object_path == "file" and property_path.startswith("hashes"):
        hash_name = property_path.split(".", 1)[-1].strip("'\"").upper().replace("-", "")
        if hash_name in ("MD5", "SHA1", "SHA256", "SHA512", "SSDEEP"):
            extra[hash_name.lower()] = value
        return FeedIndicatorType.File, value, extra
    return None, value, extra


def build_description(stix_object: dict, collection_name: str) -> str:
    parts = [f"Source: {FEED_SOURCE_TAG} TAXII ({collection_name})"]
    if stix_object.get("labels"):
        parts.append(f"Labels: {', '.join(stix_object['labels'])}")
    if stix_object.get("indicator_types"):
        parts.append(f"Indicator Types: {', '.join(stix_object['indicator_types'])}")
    if stix_object.get("confidence") is not None:
        parts.append(f"Confidence: {stix_object['confidence']}")
    if stix_object.get("valid_from"):
        parts.append(f"Valid From: {stix_object['valid_from']}")
    if stix_object.get("valid_until"):
        parts.append(f"Valid Until: {stix_object['valid_until']}")
    return "\n".join(parts)


def calculate_verdict(feed_reputation: str | None) -> int:
    """Maps the Indicator Reputation parameter to a DBot score."""
    mapping = {"Unknown": 0, "None": 0, "Benign": 1, "Good": 1, "Suspicious": 2, "Malicious": 3, "Bad": 3}
    return mapping.get(feed_reputation or "Bad", 3)


def parse_stix_indicator(
    stix_object: dict, collection_name: str, feed_tags: list[str], tlp_color: str | None, score: int
) -> tuple[list[dict], list[str]]:
    """
    Converts a STIX 2.1 ``indicator`` object into Cortex indicators.

    Returns the indicators and the list of comparison expressions that could not be mapped, so the
    caller can report them instead of silently dropping data.
    """
    pattern = stix_object.get("pattern") or ""
    comparisons = STIX_COMPARISON_RE.findall(pattern)
    if not comparisons:
        return [], [pattern or f"<no pattern: {stix_object.get('id')}>"]

    labels = [label for label in (stix_object.get("labels") or []) if label]
    tags = list(dict.fromkeys(labels + feed_tags))
    marking_tlp = next((TLP_MARKINGS[ref] for ref in (stix_object.get("object_marking_refs") or []) if ref in TLP_MARKINGS), None)
    description = build_description(stix_object, collection_name)

    indicators, unsupported = [], []
    for object_path, property_path, raw_value in comparisons:
        indicator_type, value, extra_fields = classify_observable(object_path, property_path, raw_value.replace("\\'", "'"))
        if not indicator_type or not value:
            unsupported.append(f"{object_path}:{property_path}")
            continue

        fields: dict[str, Any] = {
            "tags": tags,
            "description": description,
            "stixid": stix_object.get("id"),
            "firstseenbysource": stix_object.get("created"),
            "lastseenbysource": stix_object.get("modified") or stix_object.get("created"),
            **extra_fields,
        }
        tlp = tlp_color or marking_tlp
        if tlp:
            fields["trafficlightprotocol"] = tlp

        indicators.append(
            {
                "value": value,
                "type": indicator_type,
                "score": score,
                "service": FEED_SOURCE_TAG,
                "rawJSON": {**stix_object, "threatmon_collection": collection_name},
                "fields": fields,
            }
        )
    return indicators, unsupported


def dedup_key(indicator: dict) -> str:
    """
    Identifies one publication of an indicator. The same value re-published later (new ``created``)
    gets a new key, so it is sent again and its "last seen" is refreshed in Cortex.
    """
    raw = f"{indicator['type']}|{indicator['value']}|{indicator['fields'].get('firstseenbysource')}"
    # 72 bits of a SHA-256 digest, base64 encoded to 12 characters, to keep the integration context small.
    return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()[:9]).decode()


""" STATE """


class SeenCache:
    """
    De-duplication cache of the indicators already sent, grouped by the hour of their ``created`` time so
    old entries can be dropped in bulk. Stored in the integration context as ``{hour: "key1key2..."}``.

    The cache only prevents re-sending: an entry missing from it never causes a loss, at most one more
    update of an indicator that already exists in Cortex.
    """

    KEY_LENGTH = 12

    def __init__(self, stored: dict | None = None):
        self.buckets: dict[int, set[str]] = {}
        for bucket, packed in (stored or {}).items():
            self.buckets[int(bucket)] = {packed[i : i + self.KEY_LENGTH] for i in range(0, len(packed), self.KEY_LENGTH)}
        self.keys: set[str] = set().union(*self.buckets.values()) if self.buckets else set()

    def __contains__(self, key: str) -> bool:
        return key in self.keys

    def __len__(self) -> int:
        return len(self.keys)

    def add(self, key: str, created_ts: int) -> None:
        self.buckets.setdefault(created_ts - created_ts % 3600, set()).add(key)
        self.keys.add(key)

    def prune(self, horizon_ts: int) -> None:
        for bucket in [b for b in self.buckets if b + 3600 <= horizon_ts]:
            self.keys -= self.buckets.pop(bucket)

    def to_state(self) -> dict:
        return {str(bucket): "".join(sorted(keys)) for bucket, keys in self.buckets.items()}


def load_state() -> tuple[dict, SeenCache]:
    state = get_integration_context() or {}
    if state.get("version") != STATE_VERSION:
        state = {"version": STATE_VERSION, "collections": {}}
    state.setdefault("collections", {})
    return state, SeenCache(state.get("seen"))


def save_state(state: dict, seen: SeenCache) -> None:
    state["seen"] = seen.to_state()
    set_integration_context(state)


def seen_horizon_ts(now: datetime, lookback: timedelta) -> int:
    """
    A future crawl starts at (crawl start - look-back), so objects created before this point are not
    re-read by it and do not need to be kept in the de-duplication cache. The extra margin covers crawls
    spanning several runs.
    """
    return int((now - lookback - SEEN_CACHE_MARGIN).timestamp())


def crawl_order(collections: list[tuple[str, str]], state: dict) -> list[tuple[str, str]]:
    """
    Orders the collections so that no collection can starve the others when the page budget is reached:
    unfinished crawls are resumed first, then the collection whose last complete crawl is the oldest.
    """

    def priority(item: tuple[str, str]) -> tuple[int, str]:
        col_state = state["collections"].get(item[1], {})
        return (0 if col_state.get("next") else 1, col_state.get("last_completed_at") or "")

    return sorted(collections, key=priority)


""" COMMANDS """


def crawl(
    client: Client,
    params: dict,
    state: dict,
    seen: SeenCache,
    now: datetime,
    max_pages: int,
    deadline: float,
    sink: Callable[[list[dict]], None],
) -> dict:
    """
    Crawls every selected collection incrementally, sending indicators to ``sink`` page by page.

    A collection that fails (for example, it is no longer readable with the API token) is skipped for this
    run, so it cannot block the other collections. The failure is raised after the other collections are
    crawled, so it is still visible in the fetch status.

    Completeness guarantees:
    * Every collection is paged with the TAXII ``next`` cursor until ``more`` is false.
    * The cursor is persisted after each page, so a run that hits the page/time budget (or fails)
      resumes from the exact same position on the next run.
    * The next crawl starts from (server time when this crawl started - look-back window). The
      server time is used because object timestamps cannot be trusted as a checkpoint (some are
      published ahead of real time), and ``added_after`` is inclusive, so boundaries are covered.
    * Indicators re-read because of the overlap are de-duplicated by ``dedup_key``.
    """
    lookback = timedelta(minutes=arg_to_number(params.get("lookback_minutes")) or DEFAULT_LOOKBACK_MINUTES)
    first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, settings={"TIMEZONE": "UTC"})
    if not first_fetch:
        raise DemistoException("Invalid First Fetch Time parameter.")
    first_fetch = first_fetch.replace(tzinfo=first_fetch.tzinfo or UTC)

    feed_tags = list(dict.fromkeys([FEED_SOURCE_TAG] + argToList(params.get("feedTags"))))
    tlp_color = params.get("tlp_color") or None
    score = calculate_verdict(params.get("feedReputation"))
    seen_horizon = seen_horizon_ts(now, lookback)

    stats: dict[str, Any] = {
        "pages": 0,
        "objects": 0,
        "sent": 0,
        "duplicates": 0,
        "unsupported": 0,
        "completed": [],
        "pending": [],
        "failed": [],
    }
    unsupported_samples: list[str] = []
    errors: list[str] = []

    for collection_name, collection_id in crawl_order(resolve_collections(params), state):
        col_state = state["collections"].setdefault(collection_id, {})
        col_state.setdefault("added_after", to_taxii_time(first_fetch))

        while stats["pages"] < max_pages and time.time() < deadline:
            try:
                envelope, server_time = client.get_objects_page(collection_id, col_state["added_after"], col_state.get("next"))
            except DemistoException as e:
                status = getattr(e.res, "status_code", None) if e.res is not None else None
                if col_state.get("next") and status in (400, 404, 422):
                    # The stored cursor is no longer accepted: restart this crawl from its checkpoint.
                    # Already-sent indicators are skipped by the de-duplication cache.
                    demisto.info(f"ThreatMon: cursor rejected for {collection_name} ({status}), restarting crawl.")
                    col_state["next"] = None
                    continue
                # Skip this collection for this run; its position is kept, so the next run retries it.
                # The error is raised at the end of the run, so it is still reported.
                demisto.info(f"ThreatMon: failed to fetch collection {collection_name}: {e}")
                demisto.debug(traceback.format_exc())
                stats["failed"].append(collection_name)
                errors.append(f"{collection_name}: {e}")
                break
            stats["pages"] += 1
            if not col_state.get("crawl_started_at"):
                col_state["crawl_started_at"] = to_taxii_time(server_time or now)

            page_indicators = []
            for stix_object in envelope.get("objects") or []:
                stats["objects"] += 1
                if stix_object.get("type") != "indicator":
                    continue
                indicators, unsupported = parse_stix_indicator(stix_object, collection_name, feed_tags, tlp_color, score)
                stats["unsupported"] += len(unsupported)
                unsupported_samples.extend(unsupported[: max(0, 5 - len(unsupported_samples))])
                for indicator in indicators:
                    key = dedup_key(indicator)
                    if key in seen:
                        stats["duplicates"] += 1
                        continue
                    created_ts = int((parse_stix_time(indicator["fields"].get("firstseenbysource")) or now).timestamp())
                    if created_ts >= seen_horizon:
                        # Older objects can never be re-read by a later crawl, so they are not cached.
                        seen.add(key, created_ts)
                    page_indicators.append(indicator)

            if page_indicators:
                sink(page_indicators)
                stats["sent"] += len(page_indicators)

            if envelope.get("more") and envelope.get("next"):
                col_state["next"] = envelope["next"]
            else:
                # The crawl of this collection is complete: move the checkpoint forward.
                crawl_started_at = from_taxii_time(col_state["crawl_started_at"])
                new_added_after = max(crawl_started_at - lookback, from_taxii_time(col_state["added_after"]))
                col_state.update(
                    {
                        "added_after": to_taxii_time(new_added_after),
                        "next": None,
                        "crawl_started_at": None,
                        "last_completed_at": col_state["crawl_started_at"],
                    }
                )
                stats["completed"].append(collection_name)

            # Persist after every page: indicators are already sent, so progress is never lost.
            save_state(state, seen)
            if not col_state.get("next"):
                break
        else:
            # The page or time budget was reached: the next run continues this collection.
            stats["pending"].append(collection_name)

    if unsupported_samples:
        demisto.info(f"ThreatMon: {stats['unsupported']} unsupported STIX observables were skipped, e.g. {unsupported_samples}")
    if errors:
        raise DemistoException(f"Failed to fetch {len(errors)} ThreatMon collection(s): {'; '.join(errors)}")
    return stats


def fetch_indicators_command(client: Client, params: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    state, seen = load_state()
    lookback = timedelta(minutes=arg_to_number(params.get("lookback_minutes")) or DEFAULT_LOOKBACK_MINUTES)
    seen.prune(seen_horizon_ts(now, lookback))
    max_pages = arg_to_number(params.get("max_pages_per_fetch")) or DEFAULT_MAX_PAGES_PER_FETCH

    def sink(indicators: list[dict]) -> None:
        for indicators_batch in batch(indicators, batch_size=2000):
            demisto.createIndicators(indicators_batch)

    # The state is not saved if the crawl raises: a page whose indicators were not created must not be
    # marked as processed. The pages completed before the failure were already saved by ``crawl``.
    stats = crawl(client, params, state, seen, now, max_pages, time.time() + MAX_FETCH_RUN_SECONDS, sink)
    save_state(state, seen)
    demisto.debug(f"ThreatMon fetch finished: {stats}")
    return stats


def get_indicators_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Returns a sample of indicators from a collection, without creating them and without touching the
    fetch state. Intended for testing and debugging.
    """
    limit = arg_to_number(args.get("limit")) or 10
    collections = resolve_collections({"collections": args.get("collection") or "All Threat Indicators"})
    collection_name, collection_id = collections[0]
    feed_tags = list(dict.fromkeys([FEED_SOURCE_TAG] + argToList(params.get("feedTags"))))
    score = calculate_verdict(params.get("feedReputation"))

    envelope, _ = client.get_objects_page(collection_id, None, None, limit=min(limit, PAGE_SIZE))
    indicators: list[dict] = []
    for stix_object in envelope.get("objects") or []:
        if stix_object.get("type") == "indicator":
            indicators.extend(parse_stix_indicator(stix_object, collection_name, feed_tags, params.get("tlp_color"), score)[0])
    indicators = indicators[:limit]

    if not indicators:
        return CommandResults(readable_output="### No indicators were found.")

    table = [
        {
            "Value": indicator["value"],
            "Type": indicator["type"],
            "Score": indicator["score"],
            "Tags": ", ".join(indicator["fields"]["tags"]),
            "First Seen By Source": indicator["fields"].get("firstseenbysource"),
        }
        for indicator in indicators
    ]
    return CommandResults(
        readable_output=tableToMarkdown(f"Indicators from {FEED_SOURCE_TAG} ({collection_name})", table, removeNull=True),
        raw_response=[indicator["rawJSON"] for indicator in indicators],
    )


def get_fetch_state_command(params: dict) -> CommandResults:
    state, seen = load_state()
    rows = []
    for collection_name, collection_id in resolve_collections(params):
        col_state = state["collections"].get(collection_id, {})
        rows.append(
            {
                "Collection": collection_name,
                "AddedAfter": col_state.get("added_after"),
                "CrawlInProgress": bool(col_state.get("next")),
                "LastCompletedCrawl": col_state.get("last_completed_at"),
            }
        )
    readable_rows = [{**row, "AddedAfter": row["AddedAfter"] or "Not started"} for row in rows]
    return CommandResults(
        readable_output=tableToMarkdown(
            "ThreatMon fetch state",
            readable_rows,
            headers=["Collection", "AddedAfter", "CrawlInProgress", "LastCompletedCrawl"],
            headerTransform=pascalToSpace,
        )
        + f"\nDe-duplication cache size: {len(seen)}",
        outputs_prefix="ThreatMon.FetchState",
        outputs_key_field="Collection",
        outputs=rows,
    )


def reset_fetch_state_command() -> CommandResults:
    set_integration_context({})
    return CommandResults(
        readable_output="The ThreatMon fetch state was reset. The next fetch starts again from the First Fetch Time."
    )


def get_collections_command(client: Client) -> CommandResults:
    """
    Lists the collections published by the ThreatMon TAXII server, and whether the integration knows them,
    so new server-side collections can be spotted and added to the Additional Collection IDs parameter.
    """
    known_ids = {collection_id: name for name, collection_id in COLLECTIONS.items()}
    rows = [
        {
            "ID": collection.get("id"),
            "Title": collection.get("title"),
            "Description": collection.get("description"),
            "CanRead": collection.get("can_read"),
            "KnownByIntegration": collection.get("id") in known_ids,
        }
        for collection in (client.get_collections().get("collections") or [])
    ]
    return CommandResults(
        readable_output=tableToMarkdown(
            "ThreatMon TAXII collections",
            rows,
            headers=["ID", "Title", "Description", "CanRead", "KnownByIntegration"],
            headerTransform=pascalToSpace,
            removeNull=True,
        ),
        outputs_prefix="ThreatMon.Collection",
        outputs_key_field="ID",
        outputs=rows,
    )


def test_module(client: Client, params: dict) -> str:
    try:
        available = {collection.get("id") for collection in (client.get_collections().get("collections") or [])}
    except DemistoException as e:
        if e.res is not None and getattr(e.res, "status_code", None) in (401, 403):
            return "Authorization error: make sure the API Token is correct."
        raise
    missing = [name for name, collection_id in resolve_collections(params) if collection_id not in available]
    if missing:
        return f"The following collections are not available for this API Token: {', '.join(missing)}"
    try:
        first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH)
    except ValueError:
        first_fetch = None
    if not first_fetch:
        return "Invalid First Fetch Time parameter."
    return "ok"


""" MAIN """


def main():  # pragma: no cover
    params = demisto.params()
    base_url = (params.get("url") or "").strip() or DEFAULT_BASE_URL
    credentials = params.get("credentials") or {}
    api_token = credentials.get("password") or params.get("api_token")
    username = credentials.get("identifier") or ""

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if not api_token:
            raise DemistoException("Missing API Token.")
        client = Client(
            base_url=base_url,
            username=username,
            api_token=api_token,
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
        )

        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)
        elif command == "threatmon-get-indicators":
            return_results(get_indicators_command(client, params, demisto.args()))
        elif command == "threatmon-get-fetch-state":
            return_results(get_fetch_state_command(params))
        elif command == "threatmon-reset-fetch-state":
            return_results(reset_fetch_state_command())
        elif command == "threatmon-get-collections":
            return_results(get_collections_command(client))
        else:
            raise NotImplementedError(f"Unsupported command: {command}")
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
