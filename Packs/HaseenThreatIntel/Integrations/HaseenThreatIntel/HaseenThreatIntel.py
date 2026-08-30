"""IMPORTS"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re
import base64
import json
import hashlib
from datetime import datetime, UTC
from typing import Any

""" CONSTANTS """

INTEGRATION_NAME = "Haseen Threat Intel"

# STIX 2.x SCO/indicator object types mapped to Cortex FeedIndicatorType.
# Mirrors demisto's own StixParser mapping so downstream playbooks/automations
# receive identical indicator shapes.
STIX_2_TYPES_TO_CORTEX_TYPES: dict[str, str] = {
    "mutex": FeedIndicatorType.MUTEX,
    "windows-registry-key": FeedIndicatorType.Registry,
    "user-account": FeedIndicatorType.Account,
    "email-addr": FeedIndicatorType.Email,
    "autonomous-system": FeedIndicatorType.AS,
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
}

# STIX pattern keywords that carry the actual observable value.
HASH_TYPE_MAP: dict[str, str] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA1": "sha1",
    "SHA256": "sha256",
}

# Non-indicator STIX SDOs we also surface as indicator-like objects so that
# relationship links (indicator -> malware -> attack-pattern -> ...) resolve to
# entities that actually exist in the indicators store. Type strings mirror
# ThreatIntel.ObjectsNames (same values CreateIndicatorsFromSTIX/StixParser use).
STIX_SDO_TYPES_TO_CORTEX_TYPES: dict[str, str] = {
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
}

# Canonical Cortex scores for non-indicator SDOs (mirrors ThreatIntel.ObjectsScore).
SDO_TYPE_TO_SCORE: dict[str, int] = {
    "malware": ThreatIntel.ObjectsScore.MALWARE,
    "attack-pattern": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    "threat-actor": ThreatIntel.ObjectsScore.THREAT_ACTOR,
    "intrusion-set": ThreatIntel.ObjectsScore.INTRUSION_SET,
    "campaign": ThreatIntel.ObjectsScore.CAMPAIGN,
    "tool": ThreatIntel.ObjectsScore.TOOL,
    "course-of-action": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
}

# STIX relationship_type values we normalise into XSOAR's relationship
# vocabulary. `indicates` -> `indicated-by` is the canonical STIX 2.1 mapping
# (same special-case StixParser applies); everything else must already be a
# valid EntityRelationship name to be accepted.
STIX_RELATIONSHIP_TYPE_MAP: dict[str, str] = {
    "indicates": "indicated-by",
}

# Pattern operators we understand for value extraction.
INDICATOR_EQUALS_VAL_PATTERN = re.compile(r"(\w+)\s*=\s*'([^']+)'")
URL_IN_VAL_PATTERN = re.compile(r"value\s*IN\s*\(+('.*?')\)")

# STIX 'modified'/'created' timestamps may carry UTC offsets (+03:00) or
# variable precision. Parse to an aware datetime so delta comparisons are safe;
# a string compare only happens to work when every value is a zero-padded 'Z'
# timestamp, which Haseen does not guarantee.
STIX_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_stix_timestamp(value: str | None) -> datetime | None:
    """Parse a STIX timestamp to a timezone-aware datetime, or None."""
    if not value:
        return None
    text = str(value).strip()
    for fmt in STIX_TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            # Normalise naive 'Z' timestamps to UTC-aware.
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


""" HELPER FUNCTIONS """


# Map Haseen x_attributes 'severity' values to a Cortex DbotScore.
SEVERITY_TO_SCORE: dict[str, int] = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _parse_x_attributes(obj: dict[str, Any]) -> tuple[dict[str, Any], int | None]:
    """
    Flatten a STIX object's `x_attributes` list into {name: value} fields.

    Attributes with duplicate names (e.g. two 'Threat Type' entries) are joined
    into a comma-separated string so no intel is lost. 'severity' also drives
    the Cortex indicator score.

    Returns:
        (fields dict, score int or None)
    """
    fields: dict[str, Any] = {}
    score: int | None = None
    x_attributes = obj.get("x_attributes") or []
    for attr in x_attributes:
        if not isinstance(attr, dict):
            continue
        name = (attr.get("name") or "").strip()
        value = attr.get("value")
        if not name or value is None:
            continue
        if name.lower() == "severity":
            score = SEVERITY_TO_SCORE.get(str(value).lower(), 0)
        if name in fields:
            # Accumulate duplicate keys into a comma-separated list.
            existing = fields[name]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[name] = [existing, value]
        else:
            fields[name] = value
    # Normalise any list-valued fields to a comma-joined string.
    for k, v in fields.items():
        if isinstance(v, list):
            fields[k] = ", ".join(str(x) for x in v)
    return fields, score


def extract_value_from_pattern(pattern: str, stix_type: str) -> str | None:
    """
    Extract the observable value from a STIX 2.x indicator pattern.

    Supports the common `[ipv4-addr:value = '1.2.3.4']` shape as well as
    `value IN (...)` lists and file-hash patterns. Falls back to the object's
    `value` property (STIX 2.1 SCOs) elsewhere.

    Args:
        pattern: The STIX indicator pattern string.
        stix_type: The STIX object type (e.g. 'ipv4-addr').

    Returns:
        The extracted value string, or None if not determinable from the pattern.
    """
    if not pattern:
        return None

    # Handle file hashes: [file:hashes.'SHA-256' = 'abc...']
    if stix_type == "file":
        hash_match = re.search(r"hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern)
        if hash_match:
            return hash_match.group(2)

    # Standard `= 'value'` extraction.
    equals_match = INDICATOR_EQUALS_VAL_PATTERN.search(pattern)
    if equals_match:
        return equals_match.group(2)

    # `value IN ('a', 'b')` lists — take the first, or join when URL/domain.
    in_match = re.search(r"value\s*IN\s*\(+('.*?')\)", pattern)
    if in_match:
        values = re.findall(r"'([^']+)'", in_match.group(1))
        if values:
            return values[0]

    return None


def _normalize_relationship_type(relationship_type: str) -> str | None:
    """
    Normalize a STIX relationship_type into XSOAR relationship vocabulary.

    Mirrors StixParser.parse_relationships: `indicates` maps to `indicated-by`,
    any other type must already be a valid EntityRelationship name or it is
    skipped (with a debug log).
    """
    if not relationship_type:
        return None
    relationship_type = STIX_RELATIONSHIP_TYPE_MAP.get(relationship_type, relationship_type)
    if relationship_type not in EntityRelationship.Relationships.RELATIONSHIPS_NAMES:
        return None
    return relationship_type


def _indicator_to_id_map(indicators: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Build a STIX object id -> {value, type} lookup from parsed indicators.

    Each indicator's rawJSON carries the source STIX object `id`, which is what
    `relationship` objects reference via source_ref / target_ref.
    """
    id_map: dict[str, dict[str, Any]] = {}
    for ind in indicators:
        raw = ind.get("rawJSON") or {}
        stix_id = raw.get("id")
        if stix_id:
            id_map.setdefault(stix_id, {"value": ind.get("value"), "type": ind.get("type")})
    return id_map


def _parse_relationships(
    relationships_lst: list[dict[str, Any]],
    id_map: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """
    Build XSOAR EntityRelationship indicator dicts from STIX `relationship`
    objects — the exact output shape StixParser produces, which
    CreateIndicatorsFromSTIX (and the relationship graph) reads back.

    Returns a dict keyed by the A-side (source) indicator value, mapping to the
    list of relationship dicts that attach to it.

    Truly dangling references (either endpoint absent from the bundle window)
    are skipped with a debug log, matching StixParser.parse_relationships.
    """
    by_a_value: dict[str, list[dict[str, Any]]] = {}

    # Haseen's exporter emits each relationship object twice (duplicate STIX
    # ids). Dedup on (source_ref, relationship_type, target_ref) so the graph
    # doesn't render duplicate edges.
    seen: set[tuple[str, str, str]] = set()

    for rel in relationships_lst:
        relationship_type = _normalize_relationship_type(rel.get("relationship_type"))
        if relationship_type is None:
            demisto.debug(f"Invalid/unsupported relationship_type: {rel.get('relationship_type')!r}")
            continue

        a_stixid = rel.get("source_ref", "")
        b_stixid = rel.get("target_ref", "")
        dedup_key = (a_stixid, relationship_type, b_stixid)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        a_obj = id_map.get(a_stixid)
        b_obj = id_map.get(b_stixid)

        if not a_obj or not b_obj:
            # Truly dangling edge: one or both endpoints aren't present in this
            # bundle window and there is no loadable object to resolve them to.
            # Match StixParser.parse_relationships and skip the relationship
            # with a debug log. We deliberately do NOT synthesize a placeholder
            # endpoint here — fabricating a "ghost" SDO (whose only signal is a
            # STIX id stem) creates phantom indicators that (a) collide on XSOAR's
            # (value, type) dedupe key and (b) re-appear as empty-sourceInstances
            # stubs when the real object later shows up. A dangling reference
            # resolves cleanly once its object appears in a future bundle window.
            demisto.debug(f"Cant find {a_stixid=} or {b_stixid=} — skipping relationship (endpoint object not in bundle).")
            continue

        a_value, a_type = a_obj.get("value"), a_obj.get("type")
        b_value, b_type = b_obj.get("value"), b_obj.get("type")
        if not (a_value and a_type and b_value and b_type):
            continue

        entity_relation = EntityRelationship(
            name=relationship_type,
            entity_a=a_value,
            entity_a_type=a_type,
            entity_b=b_value,
            entity_b_type=b_type,
            fields={
                "firstseenbysource": rel.get("created"),
                "lastseenbysource": rel.get("modified"),
            },
        )
        indicator_relationship = entity_relation.to_indicator()
        by_a_value.setdefault(a_value, []).append(indicator_relationship)

    return by_a_value


def parse_stix_bundle(bundle: dict[str, Any], tags: list[str] | None = None) -> list[dict[str, Any]]:
    """
    Parse a STIX 2.x JSON bundle into Cortex indicator dictionaries.

    Args:
        bundle: A parsed STIX 2.x bundle dict (contains an 'objects' list).
        tags: Optional list of feed-level tags (from the `feedTags` integration
            parameter) applied to every emitted indicator, merged with any
            per-object `labels`.

    Returns:
        A list of indicator dicts in Cortex format, each carrying 'value',
        'type', 'score', 'fields', 'rawJSON', the ISO 'modified' timestamp and
        — when the object participates in a STIX relationship — a
        'relationships' list of XSOAR EntityRelationship dicts.
    """
    configured_tags: list[str] = list(tags) if tags else []
    indicators: list[dict[str, Any]] = []
    relationship_objects: list[dict[str, Any]] = []
    objects = bundle.get("objects", [])

    # Pass 1: parse indicator/SCO/SDO objects into indicators.
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        stix_type = obj.get("type", "")

        if stix_type == "relationship":
            relationship_objects.append(obj)
            continue

        value: str | None = None
        cortex_type: str | None = None

        if stix_type == "indicator":
            # STIX indicator SDO: type is derived from the pattern's leading SCO.
            pattern = obj.get("pattern", "")
            pattern_type = pattern.strip().lstrip("[").split(":")[0] if pattern else ""
            cortex_type = STIX_2_TYPES_TO_CORTEX_TYPES.get(pattern_type)
            value = extract_value_from_pattern(pattern, pattern_type)
        elif stix_type in STIX_2_TYPES_TO_CORTEX_TYPES:
            # STIX 2.1 SCO: has a direct 'value' property (ipv4-addr, domain, etc.)
            cortex_type = STIX_2_TYPES_TO_CORTEX_TYPES[stix_type]
            value = obj.get("value")
            # File SCOs carry hashes instead of a single 'value'.
            if stix_type == "file" and not value:
                hashes = obj.get("hashes") or {}
                value = (
                    hashes.get("SHA-256")
                    or hashes.get("SHA-1")
                    or hashes.get("MD5")
                    or hashes.get("sha256")
                    or hashes.get("sha1")
                    or hashes.get("md5")
                )
        elif stix_type in STIX_SDO_TYPES_TO_CORTEX_TYPES:
            # Non-indicator SDO (malware, attack-pattern, threat-actor, ...):
            # surfaced as an indicator so relationship links can resolve to it.
            cortex_type = STIX_SDO_TYPES_TO_CORTEX_TYPES[stix_type]
            value = obj.get("name")
            # Haseen emits threat-actor objects UUID-keyed with no recoverable
            # real name — most carry only the generic attribution marker
            # 'Attributed'. That is a status flag, not an actor identity; emitting
            # it as a Threat Actor would collapse dozens of distinct actors into a
            # single meaningless 'Attributed' entity (XSOAR dedupes by value).
            # Skip these so only real-named actors survive.
            if (
                stix_type == "threat-actor"
                and isinstance(value, str)
                and value.strip().lower() in {"attributed", "unattributed", "unknown", "n/a", ""}
            ):
                demisto.debug(
                    f"{INTEGRATION_NAME}: skipping threat-actor {obj.get('id')} " f"(no real actor name, got {value!r})"
                )
                continue

        if not value or not cortex_type:
            continue

        # Normalize domain-name SCOs that carry URLs.
        if cortex_type == FeedIndicatorType.Domain and isinstance(value, str) and "://" in value:
            cortex_type = FeedIndicatorType.URL

        modified = obj.get("modified") or obj.get("created") or datetime.now(UTC).strftime(DATE_FORMAT)

        custom_fields: dict[str, Any] = {}
        if obj.get("name"):
            custom_fields["name"] = obj["name"]
        if obj.get("description"):
            custom_fields["description"] = obj["description"]
        labels = obj.get("labels")
        merged_tags: list[str] = list(configured_tags)
        if labels:
            merged_tags.extend(labels if isinstance(labels, list) else [labels])
        if merged_tags:
            # De-duplicate while preserving order.
            custom_fields["tags"] = list(dict.fromkeys(merged_tags))

        # Fold x_attributes (severity, Threat Type, Role, Threat Detail, …) into
        # fields and derive the Cortex score from 'severity'.
        x_fields, score = _parse_x_attributes(obj)
        custom_fields.update(x_fields)

        # XSOAR resolves an indicator's true type from rawJSON. For SDOs the raw
        # STIX object's 'type' is lowercase/dashed ("attack-pattern", "malware"),
        # which contradicts the Cortex type ("Attack Pattern", "Malware") and is
        # not a valid indicator type — so persistence silently drops the record.
        # Rewrite rawJSON to be self-consistent (mirrors FeedTAXII / FeedMitreAttack).
        raw_json: dict[str, Any] = dict(obj)
        raw_json["type"] = cortex_type
        raw_json["value"] = value

        indicator: dict[str, Any] = {
            "value": value,
            "type": cortex_type,
            "fields": custom_fields,
            "rawJSON": raw_json,
            "modified": modified,
            "is_sdo": stix_type in STIX_SDO_TYPES_TO_CORTEX_TYPES,
        }

        if score is not None:
            indicator["score"] = score
        elif stix_type in SDO_TYPE_TO_SCORE:
            # SDOs (malware, attack-pattern, ...) get their canonical Cortex
            # score (mirrors ThreatIntel.ObjectsScore) when the feed doesn't
            # supply an explicit severity-based score via x_attributes.
            indicator["score"] = SDO_TYPE_TO_SCORE[stix_type]

        indicators.append(indicator)

    # Pass 2: build id -> {value, type} map and attach relationships. SDOs
    # (malware, attack-pattern, threat-actor, tool, ...) are parsed above as
    # first-class indicators — XSOAR treats any STIX object (SCO *or* SDO, plus
    # user-defined types) as an ingestible indicator, and the relationship graph
    # traverses both directions (e.g. IP ← indicator-of ← malware ← uses ←
    # attack-pattern), so they must be retained as indicator records.
    id_map = _indicator_to_id_map(indicators)
    relationships_by_a = _parse_relationships(relationship_objects, id_map)

    for ind in indicators:
        rels = relationships_by_a.get(ind["value"])
        if rels:
            ind["relationships"] = rels

    return indicators


# Volatile STIX fields that Haseen re-stamps on mass re-exports without a real
# content change. These must be excluded from the change-detection fingerprint,
# otherwise every re-export looks like a new modification.
_VOLATILE_STIX_FIELDS = frozenset(
    {
        "modified",
        "created",
        "revoked",
        "x_publish_timestamp",
        "x_ingest_timestamp",
        "x_last_seen",
        "first_seen",
        "last_seen",
    }
)


def _indicator_fingerprint(ind: dict[str, Any]) -> str:
    """
    Stable content hash of an indicator, ignoring volatile re-stamp fields and
    case-variant naming.

    Haseen re-exports the same SDO (malware/attack-pattern) in case-variant form
    ("XWorm" vs "Xworm") and re-stamps `modified` each export. Strip volatile
    fields and case-fold string values so those two quirks don't masquerade as a
    genuine change; only a real content edit changes the hash.
    """
    raw = ind.get("rawJSON") or {}
    stable = {k: v for k, v in raw.items() if k not in _VOLATILE_STIX_FIELDS}

    def _normalise(val: Any) -> Any:
        if isinstance(val, str):
            return val.casefold()
        if isinstance(val, list):
            return [_normalise(v) for v in val]
        if isinstance(val, dict):
            return {k: _normalise(v) for k, v in sorted(val.items())}
        return val

    payload = {
        "type": ind.get("type"),
        "value": _normalise(ind.get("value")),
        "raw": _normalise(stable),
        "fields": _normalise(ind.get("fields")),
    }
    # canonical JSON with sorted keys for reproducibility
    blob = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def fetch_indicators_command(
    client,
    first_fetch: str,
    limit: int,
    last_run: dict,
    tags: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict]:
    """
    Fetch indicators from the Haseen STIX bundle with id-keyed delta.

    Haseen re-stamps the STIX `modified` field on nearly every object on each
    bundle re-export (cluster stamps like N indicators sharing one export time),
    so `modified` alone is NOT a reliable change signal — a pure
    `modified > cutoff` filter would re-select almost the whole bundle every
    hour. Instead we track which STIX object ids have already been ingested and
    only emit an indicator when its id is new OR its `modified` has advanced
    past the value we last saw for that exact id.

    Args:
        client: Authenticated BaseClient wrapper.
        first_fetch: First-fetch lookback (parse_date_range spec).
        limit: Max indicators to return this run (-1 = unlimited).
        last_run: The previous fetch's last_run dict.
        tags: Optional feed-level tags applied to every fetched indicator.

    Returns:
        (indicators, updated_last_run).
    """
    # last_run carries two things:
    #   "seen": {stix_id -> content fingerprint}  (id-keyed watermark)
    #   "last_modified": high-water mark string (fallback / first-seed backing field)
    #
    # The fingerprint is a hash of the indicator's stable content *with volatile
    # fields stripped and the value case-normalised*. Haseen re-stamps `modified`
    # to a new batch time on mass re-exports WITHOUT changing object content, and
    # also re-exports the same SDO (malware/attack-pattern) multiple times with
    # case-variant names ("XWorm"/"Xworm"). Both quirks would otherwise look like
    # a genuine change every cycle. Hashing case-normalised, volatile-stripped
    # content collapses re-stamps AND case-variant dupes into one identity, so a
    # re-export emits nothing and only a real edit re-emits.
    seen: dict[str, str] = last_run.get("seen") or {}
    last_modified = last_run.get("last_modified") or parse_date_range(first_fetch, date_format=DATE_FORMAT)[0]

    bundle = client.fetch_bundle()

    all_indicators = parse_stix_bundle(bundle, tags=tags)
    demisto.debug(f"{INTEGRATION_NAME}: parsed {len(all_indicators)} indicators from bundle")

    # Fallback cut-off for objects that predate id-tracking (first boot or a
    # last_run that was reset). STIX-string ordered compare is unsafe across
    # '+03:00' offsets, so parse to aware datetimes.
    cutoff = _parse_stix_timestamp(last_modified) or datetime(1970, 1, 1, tzinfo=UTC)

    new_indicators: list[dict[str, Any]] = []
    latest_modified = last_modified
    latest_ts = cutoff
    updated_seen: dict[str, str] = dict(seen)

    for ind in all_indicators:
        raw = ind.get("rawJSON") or {}
        stix_id = raw.get("id")
        mod = ind.get("modified", "")
        mod_ts = _parse_stix_timestamp(mod)

        # Advance the high-water mark over every object (id-keyed or not) so the
        # fallback cut-off only matters on the very first seed.
        if mod_ts is not None and mod_ts > latest_ts:
            latest_ts = mod_ts
            latest_modified = mod

        prev_fp = updated_seen.get(stix_id)
        cur_fp = _indicator_fingerprint(ind)

        if stix_id is None:
            # No STIX id (shouldn't happen for Haseen, but be safe): fall back to
            # the modified cut-off so we never drop a real indicator.
            emit = mod_ts is None or mod_ts > cutoff
        elif prev_fp is None:
            # Never seen this object before -> new -> emit + record fingerprint.
            emit = True
            updated_seen[stix_id] = cur_fp
        elif prev_fp != cur_fp:
            # Same id, changed content -> genuine edit -> emit + update fingerprint.
            emit = True
            updated_seen[stix_id] = cur_fp
        else:
            # Same id, identical content (re-stamp only) -> ignore.
            emit = False

        if emit:
            new_indicators.append(ind)

    # Prune the seen map to ids that still exist in the feed so it can't grow
    # without bound as the feed retires old objects.
    live_ids = {ind.get("rawJSON", {}).get("id") for ind in all_indicators}
    updated_seen = {k: v for k, v in updated_seen.items() if k in live_ids}

    if limit and limit > 0:
        new_indicators = new_indicators[:limit]

    if not new_indicators:
        demisto.debug(f"{INTEGRATION_NAME}: no new/updated indicators since {last_modified}; " f"skipping ingest this cycle.")

    last_run["seen"] = updated_seen
    last_run["last_modified"] = latest_modified
    return new_indicators, last_run


def test_module(client) -> str:
    """
    Validate connectivity and a successful bundle parse.
    """
    bundle = client.fetch_bundle()
    if not isinstance(bundle, dict) or "objects" not in bundle:
        raise DemistoException("Invalid STIX bundle returned by the feed (missing 'objects').")
    demisto.debug(f"{INTEGRATION_NAME}: test-module fetched {len(bundle.get('objects', []))} STIX objects")
    return "ok"


""" CLIENT """


class Client(BaseClient):
    """
    Thin authenticated client for the Haseen STIX 2.x feed endpoint.

    Per the Haseen API Integration Guide, authentication is:
      * A `token` passed as a URL query parameter (?token=<token>) on every
        request, plus
      * OPTIONAL HTTP Basic Auth (email as username, the API token as
        password) for "certain exports".

    The feed is rate-limited to 2 requests/hour per export type (429 on
    exceed, throttled for ~3600s), so fetch_bundle() must be called sparingly.
    """

    def __init__(
        self,
        url: str,
        token: str,
        verify: bool,
        proxy: bool,
        username: str | None = None,
        password: str | None = None,
    ):
        headers = {"Accept": "application/json"}
        if username and password:
            # Optional Basic Auth for exports that require it. The guide maps
            # username -> account email, password -> API token.
            b64 = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {b64}"
        super().__init__(base_url=url, verify=verify, proxy=proxy, headers=headers)
        self._token = token

    def fetch_bundle(self) -> dict[str, Any]:
        """
        Download the STIX 2.x bundle from the configured feed URL.

        The token is appended as a `token` query parameter (not a header), per
        the Haseen guide.

        Returns:
            The parsed bundle dict.
        """
        params = {"token": self._token} if self._token else {}
        res = self._http_request(method="GET", url_suffix="", params=params, timeout=60, resp_type="json")
        # STIX bundles are either a bare bundle (has 'objects') or wrapped.
        if isinstance(res, dict) and "objects" in res:
            return res
        if isinstance(res, list):
            return {"objects": res}
        raise DemistoException(f"Unexpected feed payload shape: {type(res).__name__}")


""" MAIN """


def main():
    params = demisto.params()
    url = params.get("url", "").rstrip("/")
    token = params.get("api_token") or {}
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    first_fetch = params.get("first_fetch", "7 days")
    limit = arg_to_number(params.get("limit", 0)) or 0
    # Optional Basic Auth credentials (email + token) for exports that require
    # them in addition to the token query parameter. Empty when not configured.
    username = (params.get("credentials") or {}).get("identifier", "")
    password = (params.get("credentials") or {}).get("password", "")
    feed_tags_raw = params.get("feedTags", "")
    feed_tags: list[str] = [t.strip() for t in str(feed_tags_raw).split(",") if t.strip()]

    if not url:
        return_error("The 'url' parameter is required.")

    command = demisto.command()
    client = Client(
        url=url,
        token=token,
        verify=verify,
        proxy=proxy,
        username=username or None,
        password=password or None,
    )

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-indicators":
            last_run = get_feed_last_run() or {}
            # The dedupe watermark (`seen`) is a large nested dict. Feed
            # frameworks sometimes drop unknown keys from last_run between
            # invocations, which would reset `seen` to {} every fetch and make
            # the delta logic re-emit the whole feed (the "Pulled 361" loop).
            # Persist `seen` in the integration context instead — it survives
            # container restarts and is not rewritten by the feed framework.
            ctx = demisto.getIntegrationContext() or {}
            saved_seen = ctx.get("haseen_seen")
            if isinstance(saved_seen, dict) and saved_seen:
                # Context is authoritative: prefer it, but fold in any seen ids
                # that only exist in the framework last_run (defensive merge).
                fb_seen = last_run.get("seen")
                if isinstance(fb_seen, dict):
                    merged = dict(saved_seen)
                    merged.update(fb_seen)
                    last_run["seen"] = merged
                else:
                    last_run["seen"] = dict(saved_seen)

            indicators, new_last_run = fetch_indicators_command(client, first_fetch, limit, last_run, tags=feed_tags)

            batch_size = 2000
            for i in range(0, len(indicators), batch_size):
                demisto.createIndicators(indicators[i: i + batch_size])
            set_feed_last_run(new_last_run)
            # Mirror the seen watermark into the integration context so it can
            # never be silently reset by the feed framework.
            ctx["haseen_seen"] = new_last_run.get("seen", {})
            demisto.setIntegrationContext(ctx)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
