import uuid
from typing import Any, Dict

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
    "location": FeedIndicatorType.Location,
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
_HASH_PATTERN = re.compile(
    r"file:hashes\.(?:'([\w-]+)'|\"([\w-]+)\"|([\w-]+))\s*=\s*'([^']+)'", re.I
)

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

_NETWORK_TYPES = (
    FeedIndicatorType.IP,
    FeedIndicatorType.IPv6,
    FeedIndicatorType.Domain,
    FeedIndicatorType.URL,
    FeedIndicatorType.Host,
)

_STIX_RELATIONSHIP_ALIASES = {"indicates": "indicator-of"}


""" HELPERS """


def _as_list(value: Any) -> list:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def first_of(data: dict, *keys: str, default: Any = None) -> Any:
    for key in keys:
        if data.get(key) not in (None, "", [], {}):
            return data[key]
    return default


def confidence_to_score(confidence: Any) -> tuple[int, str]:
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
        match = _PATTERN_VALUE.search(pattern)
        value = match.group(1) if match else ""

    value = value.replace("\\'", "'").replace("\\\\", "\\")

    if "/" in value:
        if ioc_type == FeedIndicatorType.IP:
            ioc_type = FeedIndicatorType.CIDR
        elif ioc_type == FeedIndicatorType.IPv6:
            ioc_type = FeedIndicatorType.IPv6CIDR

    return ioc_type, value, hashes


def location_value(obj: dict) -> str:
    if obj.get("name"):
        return str(obj["name"])
    parts = [obj.get("city"), obj.get("region"), obj.get("country")]
    parts = [str(p) for p in parts if p]
    if parts:
        return ", ".join(parts)
    lat, lon = obj.get("latitude"), obj.get("longitude")
    if lat is not None and lon is not None:
        return f"{lat},{lon}"
    return ""


def get_ti_ext_id(data_type: str) -> str:
    return _EXTENSION_IDS.get(data_type, _INDICATOR_EXTENSION_ID)


class Client(BaseClient):

    def _identify_feed_type(self, obj: dict) -> tuple[str, str]:

        obj_type = str(obj.get("type") or "").lower()

        if obj_type == "indicator":
            ioc_type, value, _ = parse_pattern(obj.get("pattern") or "")
            if ioc_type and value:
                return value, ioc_type
            name = obj.get("name") or ""
            detected = auto_detect_indicator_type(name) if name else None
            return (name, detected) if detected else ("", "")

        # if obj_type == "location":
        #     return location_value(obj), _LOCATION_TYPE

        if obj_type in _SDO_TYPES:
            return str(obj.get("name") or ""), _SDO_TYPES[obj_type]

        if obj_type in _OBSERVABLE_TYPES:  # bare STIX cyber observable
            return (
                str(obj.get("value") or obj.get("name") or ""),
                _OBSERVABLE_TYPES[obj_type],
            )

        return "", ""

    def call_api(self, end_point: str, params: dict | None = None):
        """Trigger the HTTP GET request"""
        response = self._http_request(
            url_suffix=end_point,
            params=params,
            resp_type="response",
            method="GET",
            retries=3,
            status_list_to_retry=(502, 503, 504),
            raise_on_status=True,
            headers=self._headers,
        )
        if response.status_code == 200 and response.content:
            return response.json()

        return {}

    def _build_relationships(self, feed_rel_obj: dict, feed_objs: dict) -> dict:
        source_id = feed_rel_obj.get("source_ref")
        target_id = feed_rel_obj.get("target_ref")

        source_obj = feed_objs.get(source_id)
        target_obj = feed_objs.get(target_id)

        feed_rel_type = feed_rel_obj.get("relationship_type")

        source_value = source_obj.get("value") or source_obj.get("name")    # pyright: ignore
        source_type = source_obj.get("type")    # pyright: ignore

        if source_type == "indicator":
            feed_rel_type = EntityRelationship.Relationships.INDICATOR_OF

        target_value = target_obj.get("value") or target_obj.get("name")    # pyright: ignore
        target_type = source_obj.get("type")    # pyright: ignore

        if source_value and source_type and target_value and target_type:
            return EntityRelationship(
                name=feed_rel_type,
                entity_a=source_value,
                entity_a_type=source_type,
                entity_b=target_value,
                entity_b_type=target_type,
            ).to_indicator()

        return {}

    def _fetch_file_hashes_formats(self, stix_pattern_val: str):
        file_hash_values: dict[str, str] = {}

        if not stix_pattern_val or "file:hashes." not in stix_pattern_val:
            return file_hash_values

        for key_, val_ in re.findall(
            r"file:hashes\.'?([\w-]+)'?\s*=\s*'([^']+)'", stix_pattern_val
        ):
            file_hash_values[key_] = val_

        return file_hash_values

    def _convert_threat_intel_obj(
        self, obj: dict, tlp_color: str, feed_reputation: str, feed_tags: list
    ) -> dict:

        value, ti_type = self._identify_feed_type(obj)  # unpack the tuple
        if not (value and ti_type):
            return {}

        ti_obj: dict[str, Any] = {}
        obj_type = obj.get("type")

        confidence: int = obj.get("confidence", 0)
        score, verdict = confidence_to_score(confidence)

        extensions = obj.get("extensions") or {}

        tags = list(
            dict.fromkeys(
                [*(feed_tags or []), *[str(x) for x in _as_list(obj.get("labels"))]]
            )
        )

        fields: dict[str, Any] = {
            "firstseenbysource": obj.get("created", ""),
            "lastseenbysource": obj.get("modified", ""),
            "modified": obj.get("modified", ""),
            "confidence": confidence,
            "stixid": obj.get("id"),
            "description": obj.get("description", ""),
            "tags": tags,
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

            ti_obj["fields"]["geocountry"] = ext.get("country", "")

            recommended_action: str = ext.get("recommended_action", "MONITOR")
            if "BLOCK" == recommended_action.upper():
                ti_obj["fields"]["blocked"] = True

        elif obj_type == "vulnerability":
            ext = extensions.get(_VUL_EXTENSION_ID) or {}

            ti_obj["fields"]["verdict"] = verdict
            ti_obj["fields"]["score"] = score
            ti_obj["fields"]["cvedescription"] = obj.get("description", "")
            ti_obj["fields"]["cvemodified"] = obj.get("modified", "")

            ti_obj["fields"]["cvssscore"] = ext.get("cvss_base_score", "")
            ti_obj["fields"]["cvssvector"] = ext.get("cvss_vector", "")
            ti_obj["fields"]["cvssversion"] = ext.get("cvss_version", "")

            cvss_version = ext.get("cvss_version", "")

            names = list(_CVSS_COMMON_METRICS)

            if cvss_version and cvss_version[0] == "2":
                names += _CVSS_VERSION_METRICS_2
            elif cvss_version and cvss_version[0] == "3":
                names += _CVSS_VERSION_METRICS_3

            metrics = [
                {"metrics": m.replace("_", " ").capitalize(), "value": ext.get(m)}
                for m in names
            ]

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

            ti_obj["fields"]["cvsstable"] = metrics

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

    def _fetch_all_pages(self, params: dict, path: str, feeds: list):
        params["page"] = 0
        while True:
            response = self.call_api(path, params=params)
            objects = (response or {}).get("objects") or []

            if not objects:
                break

            feeds.extend(objects)

            params["page"] += 1

    def _fecth_threat_actors_data(self, ta_names: list, feeds):

        if ta_names:
            for start in range(0, len(ta_names), 10):
                chunk = ta_names[start: start + 10]
                try:
                    ta_res_data = self.call_api(
                        _TA_SEARCH_API_PATHS, params={"values": chunk}
                    )
                except Exception as e:
                    demisto.error(
                        f"Threat actor enrichment failed for {chunk}: {e}\n{traceback.format_exc()}"
                    )
                    continue

                for obj in (ta_res_data or {}).get("objects") or []:
                    if obj.get("type") != "threat-actor":
                        feeds.append(obj)

    def get_feeds(
        self,
        first_fetch: int,
        tlp_color: str,
        feed_reputation: str,
        feed_tags: list,
        fetch_tailored_indicators: bool,
        fetch_tailored_vulnerabilities: bool,
    ) -> list:

        params = {
            "withRelationships": True,
            "lookBackDays": int(first_fetch),
            "delta": True,
        }
        self._headers["X-Request-ID"] = str(uuid.uuid4())   # pyright: ignore

        ioc_suffix_path = _TAILORED_PATHS if fetch_tailored_indicators else _ALL_PATHS
        vul_suffix_path = (
            _TAILORED_PATHS if fetch_tailored_vulnerabilities else _ALL_PATHS
        )

        indicator_path = f"{_IOC_API_PATHS}{ioc_suffix_path}"
        vulnerability_path = f"{_VUL_API_PATHS}{vul_suffix_path}"

        raw_ti_feeds = []

        self._fetch_all_pages(params, indicator_path, raw_ti_feeds)
        self._fetch_all_pages(params, vulnerability_path, raw_ti_feeds)

        ta_names = []
        for f_obj in raw_ti_feeds:
            name = f_obj.get("name")
            if f_obj.get("type") == "threat-actor" and name and name not in ta_names:
                ta_names.append(f_obj.get("name"))

        self._fecth_threat_actors_data(ta_names=ta_names, feeds=raw_ti_feeds)

        return_data = []
        raw_rels = []
        raw_feed_ids = {}

        for f_obj in raw_ti_feeds:
            if f_obj.get("type") == "relationship":
                raw_rels.append(f_obj)
            else:
                if f_obj.get("id") not in raw_feed_ids:
                    raw_feed_ids[f_obj.get("id")] = f_obj
                    ti_obj = self._convert_threat_intel_obj(
                        obj=f_obj,
                        tlp_color=tlp_color,
                        feed_reputation=feed_reputation,
                        feed_tags=feed_tags,
                    )
                    if ti_obj:
                        return_data.append(ti_obj)

        rel_data = []
        for rel in raw_rels:
            relationship = self._build_relationships(
                feed_rel_obj=rel, feed_objs=raw_feed_ids
            )
            if relationship:
                rel_data.append(relationship)

        return_data.extend(rel_data)
        return return_data


def test_module(
    client: Client,
    fetch_tailored_indicators,
    fetch_tailored_vulnerabilities,
    first_fetch,
) -> str:
    try:

        if not fetch_tailored_indicators or not fetch_tailored_vulnerabilities:
            if first_fetch > 2:
                return "If tailored indicator or vulnerablities false, must be not greater that 2 days look back histories data for indicator and vunerablities. Please set it out 0 to 2 days"

        res: dict = client.call_api(end_point=_TEST_PATH)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise e

    if res is None or res == {}:
        return "Not Authorized"

    org_active: bool = res.get("isOrgActive", False)
    if not org_active:
        return "Not Authorized"

    if "isCompanyActive" in res:
        company_active: bool = res.get("isCompanyActive", False)
        if not company_active:
            return "Not Authorized"

    return "ok"


def extract_value(pattern: str) -> str:
    match = re.search(r"'([^']+)'", pattern or "")
    return match.group(1) if match else ""


def get_type(pattern: str) -> str:
    if "ipv4-addr" in pattern:
        return "IP"
    elif "domain-name" in pattern:
        return "Domain"
    elif "url" in pattern:
        return "URL"
    elif "file:hashes" in pattern:
        return "File"
    return "Unknown"


def fetch_feeds(
    client: Client,
    first_fetch: int,
    tlp_color: str,
    feed_reputation: str,
    feed_tags: list,
    fetch_tailored_indicators: bool,
    fetch_tailored_vulnerabilities: bool,
):
    try:
        indicators = client.get_feeds(
            first_fetch=first_fetch,
            tlp_color=tlp_color,
            feed_reputation=feed_reputation,
            feed_tags=feed_tags,
            fetch_tailored_indicators=fetch_tailored_indicators,
            fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
        )
        for ioc in batch(indicators, batch_size=2500):
            demisto.createIndicators(ioc)

    except Exception as e:
        demisto.error(f"Error at fetch_feeds: {e}\nTraceback: {traceback.format_exc()}")
        raise e


def build_result(data: List[Dict], data_type: str, title: str):

    if not data:
        return CommandResults(readable_output="For current request no data found.")
    table_data = []
    outputs = []

    ext_id = get_ti_ext_id(data_type)

    for ti_data in data:

        ext: dict[str, Any] = ti_data.get("extensions", {}).get(ext_id, {})
        confidence = ti_data.get("confidence", 0)
        score = 1
        if confidence >= 80:
            score = 3
        elif confidence >= 50:
            score = 2

        if data_type == LABEL_INDICATOR:
            pattern = ti_data.get("pattern", "")
            value_type = get_type(pattern)
            value = extract_value(pattern)
            vendors = ext.get("security_vendors", {})

            # -------- Human Readable Row --------
            row = {
                "Value": value,
                "Type": value_type,
                "Score": score,
                "Country": ext.get("country", ""),
                "Threat Actor": ext.get("threat_actors", ""),
                "Action": ext.get("recommended_actions"),
                "Role": ext.get("roles"),
                "Confidence": confidence,
                "Description": ti_data.get("description"),
                "vendors": vendors,
            }
            # -------- Context Output --------
            outputs.append(
                {
                    "value": value,
                    "type": value_type,
                    "score": score,
                    "country": ext.get("country", ""),
                    "threat_actor": ext.get("threat_actors", ""),
                    "vendors": vendors,
                }
            )

        elif data_type == LABEL_VULNERABILITY:
            value = ti_data.get("name", "")
            value_type = "CVE"

            row = {
                "Value": value,
                "Type": value_type,
                "Score": score,
                "Country": ext.get("country", ""),
                "Confidence": confidence,
                "Description": ti_data.get("description"),
                "Attack Complexity": ext.get("attack_complexity", ""),
                "Integrity Impact": ext.get("integrity_impact", ""),
                "Impact Score": ext.get("impact_score", ""),
                "CVSS Version": ext.get("cvss_version", "0.0"),
                "CVSS Base Score": ext.get("cvss_base_score", "0.0"),
                "Exploitability Score": ext.get("exploitability_score", "0.0"),
                "Attack Vector": ext.get("attack_vector", ""),
                "Privileges Required": ext.get("privileges_required", ""),
                "Availability Impact": ext.get("availability_impact", ""),
                "User Interaction": ext.get("user_interaction", ""),
                "CVSS Vector": ext.get("cvss_vector"),
                "Scope": ext.get("scope", ""),
                "Confidentiality Impact": ext.get("confidentiality_impact", ""),
                "Vendors": ext.get("vendors", []),
            }

            outputs.append(
                {
                    "value": value,
                    "type": value_type,
                    "score": score,
                    "confidence": confidence,
                    "attack_complexity": ext.get("attack_complexity", ""),
                    "integrity_impact": ext.get("integrity_impact", ""),
                    "impact_score": ext.get("impact_score", ""),
                    "cvss_version": ext.get("cvss_version", "0.0"),
                    "cvss_base_score": ext.get("cvss_base_score", "0.0"),
                    "exploitability_score": ext.get("exploitability_score", "0.0"),
                    "attack_vector": ext.get("attack_vector", ""),
                    "privileges_required": ext.get("privileges_required", ""),
                    "availability_impact": ext.get("availability_impact", ""),
                    "user_interaction": ext.get("user_interaction", ""),
                    "cvss_vector": ext.get("cvss_vector"),
                    "scope": ext.get("scope", ""),
                    "confidentiality_impact": ext.get("confidentiality_impact", ""),
                    "vendors": ext.get("vendors", []),
                }
            )
        elif data_type == LABEL_THREAT_ACTOR:
            value = ti_data.get("name", "")
            row = {
                "Value": value,
                "Type": LABEL_THREAT_ACTOR,
                "Score": score,
                "Confidence": confidence,
                "Description": ti_data.get("description"),
                "Origin of Country": ext.get("origin_of_country", ""),
                "Target Countries": ext.get("target_countries", ""),
                "Motivation": ext.get("motivation", ""),
                "Target Technologies": ext.get("target_technologies", ""),
                "Target Industries": ext.get("target_industries", ""),
                "Associated Malware": ext.get("associated_malware", ""),
                "Associated Campaigns": ext.get("associated_campaigns", ""),
            }
            outputs.append(
                {
                    "value": value,
                    "type": LABEL_THREAT_ACTOR,
                    "score": score,
                    "origin_of_country": ext.get("origin_of_country", ""),
                    "target_countries": ext.get("target_countries", ""),
                    "motivation": ext.get("motivation", ""),
                    "associated_malware": ext.get("associated_malware", ""),
                    "target_technologies": ext.get("target_technologies", ""),
                    "target_industries": ext.get("target_industries", ""),
                    "associated_campaigns": ext.get("associated_campaigns", ""),
                }
            )
        elif data_type == LABEL_MALWARE:
            value = ti_data.get("name", "")
            row = {
                "Value": value,
                "Type": LABEL_MALWARE,
                "Score": score,
                "Confidence": confidence,
                "Description": ti_data.get("description"),
                "Target Technologies": ext.get("target_technologies", ""),
                "Target Industries": ext.get("target_industries", ""),
                "Target Countries": ext.get("target_countries", ""),
            }
            outputs.append(
                {
                    "value": value,
                    "type": LABEL_MALWARE,
                    "score": score,
                    "country": ext.get("country", ""),
                    "threat_actor": ext.get("threat_actors", ""),
                    "target_technologies": ext.get("target_technologies", ""),
                    "target_industries": ext.get("target_industries", ""),
                    "target_countries": ext.get("target_countries", ""),
                }
            )
        else:
            raise ValueError(f"Invalid data type: {data_type}")

        table_data.append(row)

    human_readable = tableToMarkdown(title, table_data, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix=_OUTPUT_PREFIXES.get(data_type, ""),
        outputs_key_field="value",
        outputs=outputs,
        raw_response=data,
    )


def fetch_feeds_by_type(client: Client, feed_type: str):
    try:
        params = {"types": [feed_type]}

        response = client.call_api(_IOC_API_PATHS, params=params)
        return response.get("objects", [])
    except Exception as e:
        demisto.error(
            f"Error at fetch_feeds_by_type: {e}\nTraceback: {traceback.format_exc()}"
        )
        raise e


def feed_search(client: Client, search_type: str, args: dict):
    """Feed search by indicator type based"""
    search_value = args.get("value")
    if not search_value:
        raise ValueError("Missing required argument: value")

    params = {"value": [search_value]}

    if search_type == LABEL_INDICATOR:
        path = f"{_IOC_SEARCH_API_PATHS}"
        title_type = LABEL_INDICATOR
    elif search_type == LABEL_THREAT_ACTOR:
        path = f"{_TA_SEARCH_API_PATHS}"
        params = {"values": [search_value]}
        title_type = LABEL_THREAT_ACTOR
    elif search_type == LABEL_MALWARE:
        path = f"{_MALWARE_SEARCH_API_PATHS}"
        title_type = LABEL_MALWARE
    elif search_type == LABEL_VULNERABILITY:
        path = f"{_VUL_SEARCH_API_PATHS}"
        title_type = LABEL_VULNERABILITY
    else:
        raise ValueError(f"Invalid search type: {search_type}")

    title = f"Search Results for {title_type} with value: {search_value}"

    search_response = client.call_api(end_point=path, params=params)

    if not search_response or "objects" not in search_response:
        return CommandResults(
            readable_output="No results found for the given search criteria."
        )

    return build_result(
        data=search_response.get("objects", []),
        data_type=title_type,
        title=title,
    )


def main():
    params = demisto.params()
    api_url = params.get("url", "").rstrip("/")
    api_key = params.get("api_key", {}).get("password")

    verify_cert = not argToBoolean(params.get("insecure", False))
    first_fetch = int(params.get("first_fetch", "60").strip().replace(" days", ""))
    proxy = argToBoolean(params.get("proxy", False))

    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    feed_reputation = params.get("feedReputation")
    fetch_tailored_indicators = argToBoolean(
        params.get("fetchTailoredIndicators", True)
    )
    fetch_tailored_vulnerabilities = argToBoolean(
        params.get("fetchTailoredVulnerability", True)
    )

    base_url = urljoin(api_url, _BASE_PREFIX_PATH)
    command = demisto.command()
    headers = {"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_TI"}

    demisto.info(f"Command being called is {demisto.command()}")

    try:
        client = Client(
            base_url=base_url, verify=verify_cert, headers=headers, proxy=proxy
        )
        args = demisto.args()

        if command == "test-module":
            result = test_module(
                client,
                fetch_tailored_indicators=fetch_tailored_indicators,
                fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
                first_fetch=first_fetch,
            )
            demisto.results(result)
            return_results(result)
        elif command == "fetch-indicators":
            fetch_feeds(
                client=client,
                first_fetch=first_fetch,
                tlp_color=tlp_color or "",
                feed_reputation=feed_reputation or "",
                feed_tags=feed_tags,
                fetch_tailored_indicators=fetch_tailored_indicators,
                fetch_tailored_vulnerabilities=fetch_tailored_vulnerabilities,
            )
        elif demisto.command() == "cyfirma-ip-get":
            return_results(fetch_feeds_by_type(client, "ip"))
        elif demisto.command() == "cyfirma-domain-get":
            return_results(fetch_feeds_by_type(client, "domain"))
        elif demisto.command() == "cyfirma-url-get":
            return_results(fetch_feeds_by_type(client, "url"))
        elif demisto.command() == "cyfirma-file-get":
            return_results(fetch_feeds_by_type(client, "file"))
        elif demisto.command() == "cyfirma-ioc-search-get":
            return_results(feed_search(client, LABEL_INDICATOR, args))
        elif demisto.command() == "cyfirma-threat-actor-search-get":
            return_results(feed_search(client, LABEL_THREAT_ACTOR, args))
        elif demisto.command() == "cyfirma-malware-search-get":
            return_results(feed_search(client, LABEL_MALWARE, args))
        elif demisto.command() == "cyfirma-vulnerability-search-get":
            return_results(feed_search(client, LABEL_VULNERABILITY, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
