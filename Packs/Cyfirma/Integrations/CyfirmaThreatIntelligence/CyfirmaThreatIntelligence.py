"""CYFIRMA Threat Intelligence feed integration for Cortex XSOAR.

Fetches STIX 2.1 indicators, vulnerabilities, threat actors, malware and their relationships
as XSOAR indicators and exposes search commands over the same data.
"""

import re
import traceback
import uuid
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

INTEGRATION_NAME = "CYFIRMA"

LABEL_INDICATOR = "Indicator"
LABEL_VULNERABILITY = "Vulnerability"
LABEL_THREAT_ACTOR = "ThreatActor"
LABEL_MALWARE = "Malware"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_FIRST_FETCH_DAYS = 60
MAX_DAYS_WITHOUT_TAILORING = 2
TA_SEARCH_CHUNK_SIZE = 10
INDICATOR_BATCH_SIZE = 2500

_BASE_PREFIX_PATH = "/api/ex/v3/da"
_TEST_PATH = "/foo/ping"

_ALL_PATHS = "/all"
_TAILORED_PATHS = "/tailored"

_IOC_API_PATHS = "/stix/2.1/indicators"
_VUL_API_PATHS = "/stix/2.1/vulnerabilities"

_TA_SEARCH_API_PATHS = "/stix/2.1/threat-actors/search"
_IOC_SEARCH_API_PATHS = "/stix/2.1/indicators/search"
_MALWARE_SEARCH_API_PATHS = "/stix/2.1/malware/search"
_VUL_SEARCH_API_PATHS = "/stix/2.1/vulnerabilities/search"

_VUL_EXTENSION_ID = "extension-definition--1f9c5b3e-8a2d-4e7b-9c6a-d1f5e3b2a470"
_INDICATOR_EXTENSION_ID = "extension-definition--4e9c7b2d-8a3f-4c1e-9d6b-5f2a8e7c1b40"
_TA_EXTENSION_ID = "extension-definition--a7f3e9d1-2c8b-4b6e-9f5a-1c2d8e7b3a40"
_MALWARE_EXTENSION_ID = "extension-definition--c1a5b0c2-3b6f-4f92-8e7a-9d5e2c4a1b73"

_EXTENSION_IDS = {
    LABEL_INDICATOR: _INDICATOR_EXTENSION_ID,
    LABEL_VULNERABILITY: _VUL_EXTENSION_ID,
    LABEL_THREAT_ACTOR: _TA_EXTENSION_ID,
    LABEL_MALWARE: _MALWARE_EXTENSION_ID,
}

_OUTPUT_PREFIXES = {
    LABEL_INDICATOR: "CYFIRMA.Indicators",
    LABEL_VULNERABILITY: "CYFIRMA.Vulnerability",
    LABEL_THREAT_ACTOR: "CYFIRMA.ThreatActor",
    LABEL_MALWARE: "CYFIRMA.Malware",
}

# search type -> (search path, query-string parameter name)
_SEARCH_CONFIG = {
    LABEL_INDICATOR: (_IOC_SEARCH_API_PATHS, "value"),
    LABEL_THREAT_ACTOR: (_TA_SEARCH_API_PATHS, "values"),
    LABEL_MALWARE: (_MALWARE_SEARCH_API_PATHS, "value"),
    LABEL_VULNERABILITY: (_VUL_SEARCH_API_PATHS, "value"),
}

_CVSS_COMMON_METRICS = [
    "availability_impact",
    "integrity_impact",
    "impact_score",
    "exploitability_score",
    "confidentiality_impact",
]
_CVSS_VERSION_METRICS_2 = ["access_vector", "access_complexity", "authentication"]
_CVSS_VERSION_METRICS_3 = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
]

# Older XSOAR content versions may not define FeedIndicatorType.Location.
# (The original referenced FeedIndicatorType.Location directly in _SDO_TYPES, which could fail at import.)
_LOCATION_TYPE = getattr(FeedIndicatorType, "Location", "Location")

_TI_SCORES = {
    ThreatIntel.ObjectsNames.CAMPAIGN: ThreatIntel.ObjectsScore.CAMPAIGN,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    ThreatIntel.ObjectsNames.REPORT: ThreatIntel.ObjectsScore.REPORT,
    ThreatIntel.ObjectsNames.MALWARE: ThreatIntel.ObjectsScore.MALWARE,
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
    ThreatIntel.ObjectsNames.INTRUSION_SET: ThreatIntel.ObjectsScore.INTRUSION_SET,
    ThreatIntel.ObjectsNames.THREAT_ACTOR: ThreatIntel.ObjectsScore.THREAT_ACTOR,
    ThreatIntel.ObjectsNames.TOOL: ThreatIntel.ObjectsScore.TOOL,
}

# STIX domain objects (SDO) -> XSOAR indicator type. Keys are the *lowercase STIX* type names.
_SDO_TYPES = {
    "vulnerability": FeedIndicatorType.CVE,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "location": _LOCATION_TYPE,
}

# STIX cyber observable object name (first token in an indicator pattern) -> XSOAR type
_OBSERVABLE_TYPES = {
    "domain-name": FeedIndicatorType.Domain,
    "email-addr": FeedIndicatorType.Email,
    "email": FeedIndicatorType.Email,
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    "windows-registry-key": FeedIndicatorType.Registry,
    "host": FeedIndicatorType.Host,
    "cve": FeedIndicatorType.CVE,
}

_PATTERN_HEAD = re.compile(r"\[\s*([a-z0-9-]+):", re.I)
_PATTERN_VALUE = re.compile(r"=\s*'((?:[^'\\]|\\.)*)'")
_HASH_PATTERN = re.compile(r"file:hashes\.(?:'([\w-]+)'|\"([\w-]+)\"|([\w-]+))\s*=\s*'([^']+)'", re.I)

_HASH_FIELDS = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
    "sha-512": "sha512",
    "sha512": "sha512",
    "ssdeep": "ssdeep",
}
_HASH_PREFERENCE = ("sha256", "sha1", "md5", "sha512", "ssdeep")

_STIX_RELATIONSHIP_ALIASES = {"indicates": "indicator-of"}

_VUL_COLUMNS: list[tuple[str, str, str | None | list[str]]] = [
    ("Attack Complexity", "attack_complexity", ""),
    ("Integrity Impact", "integrity_impact", ""),
    ("Impact Score", "impact_score", ""),
    ("CVSS Version", "cvss_version", "0.0"),
    ("CVSS Base Score", "cvss_base_score", "0.0"),
    ("Exploitability Score", "exploitability_score", "0.0"),
    ("Attack Vector", "attack_vector", ""),
    ("Privileges Required", "privileges_required", ""),
    ("Availability Impact", "availability_impact", ""),
    ("User Interaction", "user_interaction", ""),
    ("CVSS Vector", "cvss_vector", None),
    ("Scope", "scope", ""),
    ("Confidentiality Impact", "confidentiality_impact", ""),
    ("Vendors", "vendors", []),
]
_TA_COLUMNS = [
    ("Origin of Country", "origin_of_country"),
    ("Target Countries", "target_countries"),
    ("Motivation", "motivation"),
    ("Target Technologies", "target_technologies"),
    ("Target Industries", "target_industries"),
    ("Associated Malware", "associated_malware"),
    ("Associated Campaigns", "associated_campaigns"),
]
_MALWARE_COLUMNS = [
    ("Target Technologies", "target_technologies"),
    ("Target Industries", "target_industries"),
    ("Target Countries", "target_countries"),
]


""" HELPERS """


def _as_list(value: Any) -> list:
    """Normalize a value to a list.

    Args:
        value: None/empty string (-> empty list), a list (returned as is) or any scalar (wrapped).

    Returns:
        The value as a list.
    """
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def first_of(data: dict, *keys: str, default: Any = None) -> Any:
    """Return the first non-empty value among the given keys.

    Args:
        data: Source dictionary.
        *keys: Candidate keys, checked in order.
        default: Returned when every key is missing or empty (None, "", [], {}).

    Returns:
        The first non-empty value, or ``default``.
    """
    for key in keys:
        if data.get(key) not in (None, "", [], {}):
            return data[key]
    return default


def confidence_to_score(confidence: Any) -> tuple[int, str]:
    """Map a STIX confidence (0-100) to an XSOAR score and verdict.

    Args:
        confidence: Confidence value; None or non-numeric values are treated as 0.

    Returns:
        ``(score, verdict)``: >=80 -> (3, "Malicious"), >=50 -> (2, "Suspicious"), else (1, "Benign").
    """
    try:
        value = int(confidence or 0)
    except (TypeError, ValueError):
        value = 0
    if value >= 80:
        return 3, "Malicious"
    if value >= 50:
        return 2, "Suspicious"
    return 1, "Benign"


def parse_pattern(pattern: str) -> tuple[str, str, dict[str, str]]:
    """Parse a STIX indicator pattern such as ``[ipv4-addr:value = '1.2.3.4']``.

    For file patterns, all hashes are collected and the strongest one
    (sha256 > sha1 > md5 > sha512 > ssdeep) is used as the indicator value.
    IP values containing "/" are reported as CIDR types.

    Args:
        pattern: STIX pattern string.

    Returns:
        ``(xsoar_indicator_type, value, hashes)``; ``("", "", {})`` if the pattern is empty,
        malformed or of an unsupported observable type.
    """
    if not pattern:
        return "", "", {}
    head = _PATTERN_HEAD.match(pattern.strip())
    if not head:
        return "", "", {}

    obj_name = head.group(1).lower()
    ioc_type = _OBSERVABLE_TYPES.get(obj_name, "")
    if not ioc_type:
        return "", "", {}

    hashes: dict[str, str] = {}
    value = ""

    if obj_name == "file":
        for match in _HASH_PATTERN.finditer(pattern):
            algo = (match.group(1) or match.group(2) or match.group(3) or "").lower()
            field = _HASH_FIELDS.get(algo)
            if field:
                hashes.setdefault(field, match.group(4))
        for field in _HASH_PREFERENCE:
            if hashes.get(field):
                value = hashes[field]
                break

    if not value:
        value_match = _PATTERN_VALUE.search(pattern)
        value = value_match.group(1) if value_match else ""

    value = value.replace("\\'", "'").replace("\\\\", "\\")

    if "/" in value:
        if ioc_type == FeedIndicatorType.IP:
            ioc_type = FeedIndicatorType.CIDR
        elif ioc_type == FeedIndicatorType.IPv6:
            ioc_type = FeedIndicatorType.IPv6CIDR

    return ioc_type, value, hashes


def location_value(obj: dict) -> str:
    """Build a display value for a STIX location object.

    Args:
        obj: STIX location object.

    Returns:
        The name, else "city, region, country", else "lat,lon", else an empty string.
    """
    if obj.get("name"):
        return str(obj["name"])
    parts = [str(p) for p in (obj.get("city"), obj.get("region"), obj.get("country")) if p]
    if parts:
        return ", ".join(parts)
    lat, lon = obj.get("latitude"), obj.get("longitude")
    if lat is not None and lon is not None:
        return f"{lat},{lon}"
    return ""


def get_ti_ext_id(data_type: str) -> str:
    """Return the STIX extension-definition ID for a data type (defaults to the indicator one)."""
    return _EXTENSION_IDS.get(data_type, _INDICATOR_EXTENSION_ID)


def _parse_days(value: Any, default: int = DEFAULT_FIRST_FETCH_DAYS) -> int:
    """Extract a number of days from a parameter such as "60", "60 days" or 60.

    Args:
        value: Raw parameter value.
        default: Returned when no number can be found.

    Returns:
        The number of days.
    """
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else default


class Client(BaseClient):
    """HTTP client for the CYFIRMA threat-intelligence API."""

    def _identify_feed_type(self, obj: dict) -> tuple[str, str]:
        """Determine the XSOAR indicator value and type for a STIX object.

        Args:
            obj: A STIX object (indicator, SDO or bare observable).

        Returns:
            ``(value, xsoar_type)``; ``("", "")`` if the object type is unsupported.
        """
        obj_type = str(obj.get("type") or "").lower()

        if obj_type == "indicator":
            ioc_type, value, _ = parse_pattern(obj.get("pattern") or "")
            if ioc_type and value:
                return value, ioc_type
            name = obj.get("name") or ""
            detected = auto_detect_indicator_type(name) if name else None
            return (name, detected) if detected else ("", "")

        if obj_type == "location":
            return location_value(obj), _LOCATION_TYPE

        if obj_type in _SDO_TYPES:
            return str(obj.get("name") or ""), _SDO_TYPES[obj_type]

        if obj_type in _OBSERVABLE_TYPES:  # bare STIX cyber observable
            return (
                str(obj.get("value") or obj.get("name") or ""),
                _OBSERVABLE_TYPES[obj_type],
            )

        return "", ""

    def call_api(self, end_point: str, params: dict | None = None) -> dict:
        """Perform a GET request with retries on transient gateway errors.

        Args:
            end_point: URL suffix appended to the base URL.
            params: Optional query-string parameters.

        Returns:
            Decoded JSON body, or an empty dict when the response has no content.

        Raises:
            DemistoException: On HTTP errors (after retrying 502/503/504 up to 3 times).
        """
        response = self._http_request(
            url_suffix=end_point,
            params=params,
            resp_type="response",
            method="GET",
            retries=3,
            status_list_to_retry=(502, 503, 504),
            raise_on_status=True,
        )
        if response.status_code == 200 and response.content:
            return response.json()
        return {}

    def _build_relationships(self, feed_rel_obj: dict, feed_objs: dict) -> dict:
        """Convert a STIX relationship object into an XSOAR relationship.

        Both entities are resolved with the same logic used to create the indicators
        (so values/types match the created indicators). Fixes in this version:
        the original used the *source's* type for the target, passed raw STIX type names
        (e.g. "threat-actor") instead of XSOAR types, and crashed when a referenced object
        was not part of the feed.

        Args:
            feed_rel_obj: STIX relationship object.
            feed_objs: Mapping of STIX ID -> STIX object for all non-relationship objects.

        Returns:
            The relationship in indicator format, or an empty dict if it can't be built.
        """
        source_obj = feed_objs.get(feed_rel_obj.get("source_ref"))
        target_obj = feed_objs.get(feed_rel_obj.get("target_ref"))
        if not source_obj or not target_obj:
            return {}

        source_value, source_type = self._identify_feed_type(source_obj)
        target_value, target_type = self._identify_feed_type(target_obj)
        if not (source_value and source_type and target_value and target_type):
            return {}

        rel_type = feed_rel_obj.get("relationship_type") or ""
        if source_obj.get("type") == "indicator":
            rel_type = EntityRelationship.Relationships.INDICATOR_OF
        else:
            rel_type = _STIX_RELATIONSHIP_ALIASES.get(rel_type, rel_type)
        if not rel_type:
            return {}

        return EntityRelationship(
            name=rel_type,
            entity_a=source_value,
            entity_a_type=source_type,
            entity_b=target_value,
            entity_b_type=target_type,
        ).to_indicator()

    def _convert_threat_intel_obj(self, obj: dict, tlp_color: str, feed_reputation: str, feed_tags: list) -> dict:
        """Convert a STIX object into an XSOAR indicator dict.

        Args:
            obj: STIX object.
            tlp_color: Traffic Light Protocol color to set.
            feed_reputation: Reputation to set (skipped when empty).
            feed_tags: Tags to add (merged with the object's STIX labels, de-duplicated).

        Returns:
            The indicator dict, or an empty dict if the object type is unsupported.
        """
        value, ti_type = self._identify_feed_type(obj)
        if not (value and ti_type):
            return {}

        obj_type = obj.get("type")
        confidence = obj.get("confidence") or 0
        score, verdict = confidence_to_score(confidence)
        extensions = obj.get("extensions") or {}

        tags = list(dict.fromkeys([*(feed_tags or []), *[str(x) for x in _as_list(obj.get("labels"))]]))

        fields: dict[str, Any] = {
            "firstseenbysource": obj.get("created", ""),
            "lastseenbysource": obj.get("modified", ""),
            "modified": obj.get("modified", ""),
            "confidence": confidence,
            "stixid": obj.get("id"),
            "description": obj.get("description", ""),
            "tags": tags,
            "labels": [],
            "trafficlightprotocol": tlp_color or "",
            "aliases": _as_list(obj.get("aliases")),
        }
        if feed_reputation not in (None, ""):
            fields["reputation"] = feed_reputation

        ti_obj: dict[str, Any] = {
            "value": value,
            "type": ti_type,
            "rawJSON": obj,
            "score": _TI_SCORES.get(ti_type, score),
            "service": INTEGRATION_NAME,
            "fields": fields,
        }

        if obj_type == "indicator":
            ext: dict[str, Any] = extensions.get(_INDICATOR_EXTENSION_ID) or {}

            fields.update(parse_pattern(obj.get("pattern") or "")[2])
            fields["geocountry"] = ext.get("country", "")

            recommended_action = str(first_of(ext, "recommended_action", "recommended_actions", default="MONITOR"))
            if recommended_action.upper() == "BLOCK":
                fields["blocked"] = True

        elif obj_type == "vulnerability":
            ext = extensions.get(_VUL_EXTENSION_ID) or {}
            cvss_version = str(ext.get("cvss_version") or "")

            fields.update(
                {
                    "verdict": verdict,
                    "score": score,
                    "cvedescription": obj.get("description", ""),
                    "cvemodified": obj.get("modified", ""),
                    "cvssscore": ext.get("cvss_base_score", ""),
                    "cvssvector": ext.get("cvss_vector", ""),
                    "cvssversion": cvss_version,
                }
            )

            names = list(_CVSS_COMMON_METRICS)
            if cvss_version.startswith("2"):
                names += _CVSS_VERSION_METRICS_2
            elif cvss_version.startswith("3"):
                names += _CVSS_VERSION_METRICS_3

            metrics = [{"metrics": m.replace("_", " ").capitalize(), "value": ext.get(m)} for m in names]
            for key, label in (
                ("kev", "KEV"),
                ("vendors", "Vendors"),
                ("products", "Products"),
                ("technologies", "Technologies"),
            ):
                if ext.get(key):
                    metrics.append(
                        {
                            "metrics": label,
                            "value": ", ".join(str(v) for v in _as_list(ext[key])),
                        }
                    )
            fields["cvsstable"] = metrics

        elif obj_type == "location":
            ti_obj["score"] = 0
            lat, lon = obj.get("latitude"), obj.get("longitude")
            if lat is not None and lon is not None:
                fields["geolocation"] = f"{lat},{lon}"
            for stix_key, xsoar_key in (
                ("country", "countryname"),
                ("region", "region"),
                ("city", "city"),
            ):
                if obj.get(stix_key):
                    fields[xsoar_key] = obj[stix_key]

        return ti_obj

    def _fetch_all_pages(self, params: dict, path: str, feeds: list) -> None:
        """Page through an endpoint (starting at page 0) until an empty page is returned.

        Args:
            params: Base query parameters; copied, so the caller's dict is not modified.
            path: Endpoint to query.
            feeds: List that the returned STIX objects are appended to.
        """
        request_params = {**params, "page": 0}
        while True:
            response = self.call_api(path, params=request_params)
            objects = (response or {}).get("objects") or []
            if not objects:
                break
            feeds.extend(objects)
            request_params["page"] += 1

    def _fetch_threat_actors_data(self, ta_names: list, feeds: list) -> None:
        """Enrich the feed with objects related to the given threat actors.

        Names are searched in chunks; a failing chunk is logged and skipped. Threat-actor
        objects themselves are not re-added (they are already in the feed); related objects
        and relationships are.

        Args:
            ta_names: Threat actor names to look up.
            feeds: List that the additional STIX objects are appended to.
        """
        for start in range(0, len(ta_names), TA_SEARCH_CHUNK_SIZE):
            chunk = ta_names[start : start + TA_SEARCH_CHUNK_SIZE]
            try:
                ta_res_data = self.call_api(_TA_SEARCH_API_PATHS, params={"values": chunk})
            except Exception as e:
                demisto.error(f"Threat actor enrichment failed for {chunk}: {e}\n{traceback.format_exc()}")
                continue

            feeds.extend(obj for obj in (ta_res_data or {}).get("objects") or [] if obj.get("type") != "threat-actor")

    def get_feeds(
        self,
        first_fetch: int,
        tlp_color: str,
        feed_reputation: str,
        feed_tags: list,
        fetch_tailored_indicators: bool,
        fetch_tailored_vulnerabilities: bool,
    ) -> list:
        """Fetch indicators and vulnerabilities and convert them (and relationships) to XSOAR format.

        Args:
            first_fetch: Look-back window in days.
            tlp_color: TLP color applied to every indicator.
            feed_reputation: Reputation applied to every indicator.
            feed_tags: Tags applied to every indicator.
            fetch_tailored_indicators: Use the tailored (org-specific) indicator endpoint instead of "all".
            fetch_tailored_vulnerabilities: Use the tailored vulnerability endpoint instead of "all".

        Returns:
            List of XSOAR indicator dicts followed by relationship dicts.
        """
        params = {
            "withRelationships": True,
            "lookBackDays": int(first_fetch),
            "delta": True,
        }
        self._headers["X-Request-ID"] = str(uuid.uuid4())  # type: ignore[index]

        ioc_suffix = _TAILORED_PATHS if fetch_tailored_indicators else _ALL_PATHS
        vul_suffix = _TAILORED_PATHS if fetch_tailored_vulnerabilities else _ALL_PATHS

        raw_ti_feeds: list = []
        self._fetch_all_pages(params, f"{_IOC_API_PATHS}{ioc_suffix}", raw_ti_feeds)
        self._fetch_all_pages(params, f"{_VUL_API_PATHS}{vul_suffix}", raw_ti_feeds)

        # dict preserves order and gives O(1) de-duplication
        ta_names = list(dict.fromkeys(f["name"] for f in raw_ti_feeds if f.get("type") == "threat-actor" and f.get("name")))
        self._fetch_threat_actors_data(ta_names=ta_names, feeds=raw_ti_feeds)

        indicators: list = []
        raw_rels: list = []
        raw_feed_ids: dict[str, dict] = {}

        for f_obj in raw_ti_feeds:
            if f_obj.get("type") == "relationship":
                raw_rels.append(f_obj)
                continue
            obj_id = f_obj.get("id")
            if obj_id in raw_feed_ids:
                continue
            raw_feed_ids[obj_id] = f_obj
            ti_obj = self._convert_threat_intel_obj(
                obj=f_obj,
                tlp_color=tlp_color,
                feed_reputation=feed_reputation,
                feed_tags=feed_tags,
            )
            if ti_obj:
                indicators.append(ti_obj)

        relationships = (self._build_relationships(rel, raw_feed_ids) for rel in raw_rels)
        indicators.extend(rel for rel in relationships if rel)
        return indicators


def test_module(
    client: Client,
    fetch_tailored_indicators: bool,
    fetch_tailored_vulnerabilities: bool,
    first_fetch: int,
) -> str:
    """Validate parameters, connectivity, credentials and that the organization is active.

    Args:
        client: Configured API client.
        fetch_tailored_indicators: Whether tailored indicators are enabled.
        fetch_tailored_vulnerabilities: Whether tailored vulnerabilities are enabled.
        first_fetch: Look-back window in days.

    Returns:
        "ok" on success, otherwise a message describing the problem.

    Raises:
        DemistoException: For errors other than authorization failures.
    """
    if (not fetch_tailored_indicators or not fetch_tailored_vulnerabilities) and first_fetch > MAX_DAYS_WITHOUT_TAILORING:
        return (
            "When tailored indicators or tailored vulnerabilities is disabled, the look-back period "
            f"must not be greater than {MAX_DAYS_WITHOUT_TAILORING} days. "
            f"Please set it between 0 and {MAX_DAYS_WITHOUT_TAILORING} days."
        )

    try:
        res = client.call_api(end_point=_TEST_PATH)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise

    if not res or not res.get("isOrgActive", False):
        return "Not Authorized"
    if "isCompanyActive" in res and not res.get("isCompanyActive", False):
        return "Not Authorized"
    return "ok"


def fetch_feeds(
    client: Client,
    first_fetch: int,
    tlp_color: str,
    feed_reputation: str,
    feed_tags: list,
    fetch_tailored_indicators: bool,
    fetch_tailored_vulnerabilities: bool,
) -> None:
    """Command ``fetch-indicators``: fetch feeds and create indicators in batches.

    Args:
        client: Configured API client.
        first_fetch: Look-back window in days.
        tlp_color: TLP color applied to every indicator.
        feed_reputation: Reputation applied to every indicator.
        feed_tags: Tags applied to every indicator.
        fetch_tailored_indicators: Use the tailored indicator endpoint.
        fetch_tailored_vulnerabilities: Use the tailored vulnerability endpoint.

    Raises:
        Exception: Any error is logged (with traceback) and re-raised.
    """
    try:
        indicators = client.get_feeds(
            first_fetch=first_fetch,
            tlp_color=tlp_color,
            feed_reputation=feed_reputation,
            feed_tags=feed_tags,
            fetch_tailored_indicators=fetch_tailored_indicators,
            fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
        )
        for ioc in batch(indicators, batch_size=INDICATOR_BATCH_SIZE):
            demisto.createIndicators(ioc)
    except Exception as e:
        demisto.error(f"Error at fetch_feeds: {e}\nTraceback: {traceback.format_exc()}")
        raise


def _indicator_row_output(ti_data: dict, ext: dict, score: int, confidence: int) -> tuple[dict, dict]:
    """Build the table row and context entry for an indicator search result."""
    ioc_type, value, _ = parse_pattern(ti_data.get("pattern") or "")
    value_type = ioc_type or "Unknown"
    vendors = ext.get("security_vendors", {})
    country = ext.get("country", "")
    threat_actor = first_of(ext, "threat_actors", "threat_actor", default="")

    row = {
        "Value": value,
        "Type": value_type,
        "Score": score,
        "Country": country,
        "Threat Actor": threat_actor,
        "Action": first_of(ext, "recommended_actions", "recommended_action"),
        "Role": ext.get("roles"),
        "Confidence": confidence,
        "Description": ti_data.get("description"),
        "vendors": vendors,
    }
    output = {
        "value": value,
        "type": value_type,
        "score": score,
        "country": country,
        "threat_actor": threat_actor,
        "vendors": vendors,
    }
    return row, output


def _vulnerability_row_output(ti_data: dict, ext: dict, score: int, confidence: int) -> tuple[dict, dict]:
    """Build the table row and context entry for a vulnerability search result."""
    value = ti_data.get("name", "")
    row: dict[str, Any] = {
        "Value": value,
        "Type": "CVE",
        "Score": score,
        "Country": ext.get("country", ""),
        "Confidence": confidence,
        "Description": ti_data.get("description"),
    }
    output: dict[str, Any] = {
        "value": value,
        "type": "CVE",
        "score": score,
        "confidence": confidence,
    }
    for label, key, default in _VUL_COLUMNS:
        row[label] = ext.get(key, default)
        output[key] = ext.get(key, default)
    return row, output


def _simple_row_output(
    ti_data: dict,
    ext: dict,
    score: int,
    confidence: int,
    data_type: str,
    columns: list[tuple[str, str]],
    extra_output_keys: tuple[str, ...] = (),
) -> tuple[dict, dict]:
    """Build the table row and context entry for threat-actor / malware search results.

    Args:
        ti_data: STIX object.
        ext: The object's extension-definition data.
        score: XSOAR score.
        confidence: STIX confidence.
        data_type: LABEL_THREAT_ACTOR or LABEL_MALWARE.
        columns: ``(table label, extension key)`` pairs to include.
        extra_output_keys: Additional extension keys to add to the context entry only.
    """
    value = ti_data.get("name", "")
    row: dict[str, Any] = {
        "Value": value,
        "Type": data_type,
        "Score": score,
        "Confidence": confidence,
        "Description": ti_data.get("description"),
    }
    output: dict[str, Any] = {"value": value, "type": data_type, "score": score}
    for label, key in columns:
        row[label] = ext.get(key, "")
        output[key] = ext.get(key, "")
    for key in extra_output_keys:
        output[key] = ext.get(key, "")
    return row, output


def build_result(data: list[dict], data_type: str, title: str) -> CommandResults:
    """Format STIX search results as a markdown table and context outputs.

    Args:
        data: STIX objects returned by the API.
        data_type: One of LABEL_INDICATOR, LABEL_VULNERABILITY, LABEL_THREAT_ACTOR, LABEL_MALWARE.
        title: Title of the markdown table.

    Returns:
        CommandResults with the table and ``CYFIRMA.*`` context output.

    Raises:
        ValueError: If ``data_type`` is not supported.
    """
    if not data:
        return CommandResults(readable_output="For current request no data found.")
    if data_type not in _OUTPUT_PREFIXES:
        raise ValueError(f"Invalid data type: {data_type}")

    ext_id = get_ti_ext_id(data_type)
    table_data, outputs = [], []

    for ti_data in data:
        ext: dict[str, Any] = (ti_data.get("extensions") or {}).get(ext_id) or {}
        confidence = ti_data.get("confidence") or 0
        score, _ = confidence_to_score(confidence)

        if data_type == LABEL_INDICATOR:
            row, output = _indicator_row_output(ti_data, ext, score, confidence)
        elif data_type == LABEL_VULNERABILITY:
            row, output = _vulnerability_row_output(ti_data, ext, score, confidence)
        elif data_type == LABEL_THREAT_ACTOR:
            row, output = _simple_row_output(ti_data, ext, score, confidence, LABEL_THREAT_ACTOR, _TA_COLUMNS)
        else:
            row, output = _simple_row_output(
                ti_data,
                ext,
                score,
                confidence,
                LABEL_MALWARE,
                _MALWARE_COLUMNS,
                extra_output_keys=("country", "threat_actors"),
            )

        table_data.append(row)
        outputs.append(output)

    return CommandResults(
        readable_output=tableToMarkdown(title, table_data, removeNull=True),
        outputs_prefix=_OUTPUT_PREFIXES[data_type],
        outputs_key_field="value",
        outputs=outputs,
        raw_response=data,
    )


def fetch_feeds_by_type(client: Client, feed_type: str) -> CommandResults:
    """Commands ``cyfirma-ip/domain/url/file-get``: list indicators of one observable type.

    The original returned the raw object list to ``return_results``; it now returns
    formatted CommandResults like the search commands.

    Args:
        client: Configured API client.
        feed_type: Indicator type to query ("ip", "domain", "url" or "file").

    Returns:
        CommandResults built by ``build_result``.

    Raises:
        Exception: Errors are logged (with traceback) and re-raised.
    """
    try:
        response = client.call_api(_IOC_API_PATHS, params={"types": [feed_type]})
        return build_result(
            data=response.get("objects", []),
            data_type=LABEL_INDICATOR,
            title=f"CYFIRMA Indicators - Type: {feed_type}",
        )
    except Exception as e:
        demisto.error(f"Error at fetch_feeds_by_type: {e}\nTraceback: {traceback.format_exc()}")
        raise


def feed_search(client: Client, search_type: str, args: dict) -> CommandResults:
    """Search CYFIRMA data by value for a given object type.

    Args:
        client: Configured API client.
        search_type: LABEL_INDICATOR, LABEL_THREAT_ACTOR, LABEL_MALWARE or LABEL_VULNERABILITY.
        args: Command args; ``value`` (required) is the value to search for.

    Returns:
        CommandResults with the search results, or a "no results" message.

    Raises:
        ValueError: If ``value`` is missing or ``search_type`` is invalid.
    """
    search_value = args.get("value")
    if not search_value:
        raise ValueError("Missing required argument: value")
    if search_type not in _SEARCH_CONFIG:
        raise ValueError(f"Invalid search type: {search_type}")

    path, param_name = _SEARCH_CONFIG[search_type]
    search_response = client.call_api(end_point=path, params={param_name: [search_value]})

    if not search_response or "objects" not in search_response:
        return CommandResults(readable_output="No results found for the given search criteria.")

    return build_result(
        data=search_response.get("objects", []),
        data_type=search_type,
        title=f"Search Results for {search_type} with value: {search_value}",
    )


def main() -> None:
    """Read integration parameters, build the client and dispatch the invoked command."""
    params = demisto.params()
    command = demisto.command()

    api_url = params.get("url", "").rstrip("/")
    api_key = (params.get("api_key") or {}).get("password")
    if not api_url or not api_key:
        return_error("Server URL and API Key are required.")

    verify_cert = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    first_fetch = _parse_days(params.get("first_fetch"))

    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color") or ""
    feed_reputation = params.get("feedReputation") or ""
    fetch_tailored_indicators = argToBoolean(params.get("fetchTailoredIndicators", True))
    fetch_tailored_vulnerabilities = argToBoolean(params.get("fetchTailoredVulnerability", True))

    demisto.info(f"Command being called is {command}")

    type_commands = {
        "cyfirma-ip-get": "ip",
        "cyfirma-domain-get": "domain",
        "cyfirma-url-get": "url",
        "cyfirma-file-get": "file",
    }
    search_commands = {
        "cyfirma-ioc-search-get": LABEL_INDICATOR,
        "cyfirma-threat-actor-search-get": LABEL_THREAT_ACTOR,
        "cyfirma-malware-search-get": LABEL_MALWARE,
        "cyfirma-vulnerability-search-get": LABEL_VULNERABILITY,
    }

    try:
        client = Client(
            base_url=urljoin(api_url, _BASE_PREFIX_PATH),
            verify=verify_cert,
            headers={"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_TI"},
            proxy=proxy,
        )

        if command == "test-module":
            # The original also called demisto.results(), which duplicated the output.
            return_results(
                test_module(
                    client,
                    fetch_tailored_indicators=fetch_tailored_indicators,
                    fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
                    first_fetch=first_fetch,
                )
            )
        elif command == "fetch-indicators":
            fetch_feeds(
                client=client,
                first_fetch=first_fetch,
                tlp_color=tlp_color,
                feed_reputation=feed_reputation,
                feed_tags=feed_tags,
                fetch_tailored_indicators=fetch_tailored_indicators,
                fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
            )
        elif command in type_commands:
            return_results(fetch_feeds_by_type(client, type_commands[command]))
        elif command in search_commands:
            return_results(feed_search(client, search_commands[command], demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
