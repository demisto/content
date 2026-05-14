import json
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_SIZE = 20
DEFAULT_BASE_URL = "https://api.darkmon.com/tip/2025.1"

VENDOR = "Darkmon"

DBOT_SCORE_NONE = 0
DBOT_SCORE_GOOD = 1
DBOT_SCORE_SUSPICIOUS = 2
DBOT_SCORE_BAD = 3

DBOT_SCORE_BY_CLASSIFICATION: dict[str, int] = {
    "malicious": DBOT_SCORE_BAD,
    "phishing": DBOT_SCORE_BAD,
    "malware": DBOT_SCORE_BAD,
    "ransomware": DBOT_SCORE_BAD,
    "c2": DBOT_SCORE_BAD,
    "botnet": DBOT_SCORE_BAD,
    "exploit": DBOT_SCORE_BAD,
    "suspicious": DBOT_SCORE_SUSPICIOUS,
    "clean": DBOT_SCORE_GOOD,
    "benign": DBOT_SCORE_GOOD,
    "safe": DBOT_SCORE_GOOD,
    "whitelisted": DBOT_SCORE_GOOD,
}

SENSITIVE_FIELDS_FOR_REDACTION = {"password", "cardNumber", "cvv", "cvvs"}

IOC_FIELD_MAP: dict[str, list[dict[str, str]]] = {
    "domain": [
        {"src": "name", "dst": "domainname", "kind": "scalar"},
        {"src": "classification", "dst": "tags", "kind": "tag"},
    ],
    "file": [
        {"src": "md5", "dst": "md5", "kind": "scalar"},
        {"src": "sha1", "dst": "sha1", "kind": "scalar"},
        {"src": "sha256", "dst": "sha256", "kind": "scalar"},
        {"src": "sha3_384", "dst": "sha3384", "kind": "scalar"},
        {"src": "ssdeep", "dst": "ssdeep", "kind": "scalar"},
        {"src": "size", "dst": "size", "kind": "scalar"},
        {"src": "name", "dst": "name", "kind": "scalar"},
    ],
    "vulnerabilityioc": [
        {"src": "cvssScore", "dst": "cvssscore", "kind": "scalar"},
        {"src": "description", "dst": "description", "kind": "scalar"},
        {"src": "published", "dst": "published", "kind": "scalar"},
        {"src": "severity", "dst": "tags", "kind": "tag"},
    ],
}


def classification_to_dbot_score(classification: str | None) -> int:
    if not classification:
        return DBOT_SCORE_NONE
    return DBOT_SCORE_BY_CLASSIFICATION.get(classification.lower().strip(), DBOT_SCORE_NONE)


def _resolve_reliability() -> str:
    return demisto.params().get("feedReliability") or "F - Reliability cannot be judged"


def _should_redact_secrets() -> bool:
    raw = demisto.params().get("redact_secrets")
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def _redact_rows(
    rows: list[dict[str, Any]], redact: bool, sensitive: set = SENSITIVE_FIELDS_FOR_REDACTION
) -> list[dict[str, Any]]:
    if not redact:
        return rows
    return [{k: ("***" if (k in sensitive and v not in (None, "", [])) else v) for k, v in row.items()} for row in rows]


def _detect_file_hash_field(value: str) -> str:
    v = (value or "").strip().lower()
    if len(v) == 32 and all(c in "0123456789abcdef" for c in v):
        return "MD5"
    if len(v) == 40 and all(c in "0123456789abcdef" for c in v):
        return "SHA1"
    if len(v) == 64 and all(c in "0123456789abcdef" for c in v):
        return "SHA256"
    return "MD5"


def build_dbot_outputs(value: str, indicator_type: str, search_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build DBotScore + Common.<Type> outputs for a reputation enrichment.

    `indicator_type` is the lowercase XSOAR DBotScore type: 'ip', 'url',
    'domain', 'file', 'email'. `search_results` is the list of cell-flattened
    dicts produced by extract_search_result(); the first cell with a
    'classification' key drives the score.
    """
    classification = next(
        (item.get("classification") for item in (search_results or []) if item.get("classification")),
        None,
    )
    score = classification_to_dbot_score(classification)
    reliability = _resolve_reliability()

    dbot = {
        "Indicator": value,
        "Type": indicator_type,
        "Vendor": VENDOR,
        "Score": score,
        "Reliability": reliability,
    }

    common_specs: dict[str, tuple] = {
        "ip": ("Common.IP(val.Address && val.Address == obj.Address)", "Address"),
        "domain": ("Common.Domain(val.Name && val.Name == obj.Name)", "Name"),
        "url": ("Common.URL(val.Data && val.Data == obj.Data)", "Data"),
        "email": ("Common.EMAIL(val.Address && val.Address == obj.Address)", "Address"),
    }

    if indicator_type == "file":
        common_key = (
            "Common.File(val.MD5 && val.MD5 == obj.MD5 || "
            "val.SHA1 && val.SHA1 == obj.SHA1 || "
            "val.SHA256 && val.SHA256 == obj.SHA256)"
        )
        common_obj: dict[str, Any] = {_detect_file_hash_field(value): value}
    else:
        common_key, value_field = common_specs[indicator_type]
        common_obj = {value_field: value}

    if score == DBOT_SCORE_BAD:
        common_obj["Malicious"] = {
            "Vendor": VENDOR,
            "Description": f"Darkmon classified as {classification}",
        }

    return {"DBotScore": dbot, common_key: common_obj}


def _apply_ioc_fields(item: dict, ioc_type: str, indicator_obj: dict) -> None:
    """Table-driven mapping of raw IOC fields onto the indicator's fields dict."""
    for spec in IOC_FIELD_MAP.get(ioc_type, []):
        v = item.get(spec["src"])
        if v in (None, "", []):
            continue
        if spec["kind"] == "tag":
            existing = indicator_obj["fields"].get("tags", [])
            new_tags = v if isinstance(v, list) else [v]
            indicator_obj["fields"]["tags"] = existing + new_tags
        else:
            indicator_obj["fields"][spec["dst"]] = v


def extract_feature_value(item: dict, key: str) -> Any:
    if not item.get("feature"):
        return None

    for feature in item.get("feature", []):
        if feature.get("accessorKey") == key:
            return feature.get("value")
    return None


def extract_search_result(item: dict) -> dict:
    """Flatten a /search response item into a context-friendly dict.

    The /search endpoint returns SearchFeatureDTO objects of the shape:
        {"type": "<TipFeature>", "feature": [{"accessorKey", "displayName", "type", "value"}, ...]}

    This function is fully dynamic - whatever cells the backend sends become keys
    in the returned dict, so new TipFeature types and new columns work without
    code changes. The 'type' field (the TipFeature enum value, e.g. "Domains")
    is preserved at the top level.
    """
    out: dict[str, Any] = {}
    feature_type = item.get("type")
    if feature_type is not None:
        out["type"] = feature_type

    cells = item.get("feature") or []
    if not isinstance(cells, list):
        return out

    for cell in cells:
        if not isinstance(cell, dict):
            continue
        key = cell.get("accessorKey")
        if not key:
            continue
        value = cell.get("value")
        if value is None:
            continue
        out[key] = value

    return out


def extract_features_to_dict(item: dict) -> dict:
    result = {
        "id": item.get("id"),
        "type": item.get("type"),
        "value": item.get("value"),
        "eventId": item.get("eventId"),
        "eventInfo": item.get("eventInfo"),
        "timestamp": item.get("timestamp"),
        "expired": item.get("expired"),
    }

    indicator_type = item.get("type", "")

    if indicator_type == "domain":
        result.update({"name": item.get("name"), "classification": item.get("classification"), "ips": item.get("ips", [])})

    elif indicator_type == "url":
        result.update({"url": item.get("url"), "ips": item.get("ips", [])})

    elif indicator_type == "file":
        result.update(
            {
                "name": item.get("name"),
                "md5": item.get("md5"),
                "sha1": item.get("sha1"),
                "sha256": item.get("sha256"),
                "sha3_384": item.get("sha3_384"),
                "tlsh": item.get("tlsh"),
                "ssdeep": item.get("ssdeep"),
                "size": item.get("size"),
                "mimeType": item.get("mimeType"),
            }
        )

    elif indicator_type == "ip":
        result.update({"ip": item.get("ip")})

    elif indicator_type == "email":
        result.update({"src": item.get("src")})

    elif indicator_type == "tlsssl":
        result.update({"jarm_fingerprint": item.get("jarm_fingerprint")})

    elif indicator_type == "vulnerabilityioc":
        result.update(
            {
                "vulnerabilityId": item.get("vulnerabilityId"),
                "name": item.get("name"),
                "description": item.get("description"),
                "severity": item.get("severity"),
                "exploitation": item.get("exploitation"),
                "cvssScore": item.get("cvssScore"),
                "sourceIdentifier": item.get("sourceIdentifier"),
                "published": item.get("published"),
                "lastModified": item.get("lastModified"),
                "vectorString": item.get("vectorString"),
                "tags": item.get("tags", []),
                "exploitabilityScore": item.get("exploitabilityScore"),
            }
        )

    return {k: v for k, v in result.items() if v is not None}


class Client(BaseClient):
    def __init__(self, base_url, headers, verify=True, proxy=False):
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def validate_api_key(self) -> bool:
        try:
            response = self._http_request(method="GET", url_suffix="/test-api-key", resp_type="text")
            return response == "The API key is valid!"
        except Exception:
            return False

    def global_search(self, query: str, indicator_type: str, page: int = 0, size: int = DEFAULT_SIZE) -> dict:
        allowed_types = [
            "Domain",
            "IP",
            "URL",
            "Hash",
            "CVE",
            "Email",
            "Username",
            "Malware",
            "Source",
            "Keyword",
            "Card",
            "CardNumber",
            "CardHolder",
        ]

        if indicator_type not in allowed_types:
            raise ValueError(f"Invalid indicator type: {indicator_type}. " f"Allowed types: {', '.join(allowed_types)}")
        formatted_query = f'{indicator_type}: "{query}"'

        params = {"page": page, "size": size, "query": formatted_query}

        return self._http_request(method="GET", url_suffix="search", params=params, resp_type="json")

    def get_compromised_data(self, data_type: str, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        endpoint_map = {
            "accounts": "leaks/accounts",
            "bank-cards": "leaks/bank-cards",
            "combo-lists": "leaks/combo-lists",
            "public-breaches": "leaks/public-breaches",
            "employees": "leaks/accounts/employees",
        }

        if data_type not in endpoint_map:
            raise ValueError(
                f"Unsupported compromised data type: {data_type}. " f"Supported types: {', '.join(endpoint_map.keys())}"
            )

        params: dict[str, Any] = {"page": page, "size": size}
        if sort:
            params["sort"] = sort

        return self._http_request(method="GET", url_suffix=endpoint_map[data_type], params=params)

    def get_indicators(self, size: int = DEFAULT_SIZE) -> dict:
        params = {"size": size}
        return self._http_request(method="GET", url_suffix="ioc-feed", params=params)

    def get_vpn(self, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        params: dict[str, Any] = {"page": page, "size": size}
        if sort:
            params["sort"] = sort
        return self._http_request(
            method="GET",
            url_suffix="vpn",
            params=params,
        )

    def get_proxy(self, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        params: dict[str, Any] = {"page": page, "size": size}
        if sort:
            params["sort"] = sort
        return self._http_request(
            method="GET",
            url_suffix="proxy",
            params=params,
        )

    def get_cve(self, page: int = 0, size: int = DEFAULT_SIZE) -> dict:
        params = {"page": page, "size": size}
        return self._http_request(method="GET", url_suffix="vulnerabilities", params=params)

    def get_nrd(self, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        params: dict[str, Any] = {
            "page": page,
            "size": size,
            "filter": json.dumps({"iocClassifications": ["NEWLY_REGISTERED_DOMAIN"]}),
        }
        if sort:
            params["sort"] = sort
        return self._http_request(
            method="GET",
            url_suffix="ioc",
            params=params,
        )

    def get_tbf(self, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        params: dict[str, Any] = {
            "page": page,
            "size": size,
            "filter": json.dumps({"iocClassifications": ["TELNET_BRUTE_FORCE"]}),
        }
        if sort:
            params["sort"] = sort
        return self._http_request(
            method="GET",
            url_suffix="ioc",
            params=params,
        )

    def get_ransomware(self, mentions: bool = False, page: int = 0, size: int = DEFAULT_SIZE, sort: str | None = None) -> dict:
        url_suffix = "/mentions/ransomware" if mentions else "/articles/ransomware"
        params: dict[str, Any] = {"page": page, "size": size}
        if sort:
            params["sort"] = sort
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
        )

    def get_landscape(self, mentions: bool = False, page: int = 0, size: int = DEFAULT_SIZE) -> dict:
        url_suffix = "/mentions/landscape-news" if mentions else "/articles/landscape-news"
        return self._http_request(method="GET", url_suffix=url_suffix, params={"page": page, "size": size})

    def get_board_protection_requests(self, page: int = 0, size: int = DEFAULT_SIZE, term: str | None = None) -> dict:
        params: dict[str, Any] = {"page": page, "size": size}
        if term:
            params["term"] = term
        return self._http_request(
            method="GET",
            url_suffix="board-leak/request",
            params=params,
        )

    def get_board_leaks(
        self, leak_type: str, email: str, page: int = 0, size: int = DEFAULT_SIZE, term: str | None = None
    ) -> dict:
        endpoint_map = {
            "accounts": "board-leak/leaks/accounts",
            "combo-lists": "board-leak/leaks/comboLists",
            "public-breaches": "board-leak/leaks/publicBreaches",
        }
        if leak_type not in endpoint_map:
            raise ValueError(f"Unsupported board leak type: {leak_type}. " f"Supported types: {', '.join(endpoint_map.keys())}")

        params: dict[str, Any] = {"page": page, "size": size, "email": email}
        if term:
            params["term"] = term

        return self._http_request(
            method="GET",
            url_suffix=endpoint_map[leak_type],
            params=params,
        )


def test_module(client: Client) -> str:
    if client.validate_api_key():
        return "ok"
    raise DemistoException("Failed to validate API key. Please check your credentials.")


def generate_feature_tables(content: list) -> str:
    """Render /search results as one markdown table per TipFeature type.

    Fully dynamic: any TipFeature type and any cell list works automatically.
    Column order is taken from the first seen item of each type (matching the
    backend's deliberate ColumnDto order), with any new columns from later items
    appended in first-seen order.
    """
    if not content:
        return "No data found"

    type_groups: dict[str, list[dict[str, Any]]] = {}
    type_header_order: dict[str, list[str]] = {}

    for item in content:
        feature_type = item.get("type", "Unknown")
        type_groups.setdefault(feature_type, [])
        type_header_order.setdefault(feature_type, [])
        seen = type_header_order[feature_type]

        cells = item.get("feature") or []
        if not isinstance(cells, list) or not cells:
            continue

        row: dict[str, Any] = {}
        for cell in cells:
            if not isinstance(cell, dict):
                continue
            accessor_key = cell.get("accessorKey") or ""
            display_name = cell.get("displayName") or pascalToSpace(accessor_key)
            if not display_name:
                continue
            value = cell.get("value")

            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else ""
            elif isinstance(value, dict):
                value = json.dumps(value, default=str)
            elif value is None:
                value = ""

            row[display_name] = value
            if display_name not in seen:
                seen.append(display_name)

        if row:
            type_groups[feature_type].append(row)

    tables_md = []
    for feature_type, rows in type_groups.items():
        if not rows:
            continue
        headers = type_header_order[feature_type]
        table_md = tableToMarkdown(
            f"{feature_type} Information",
            rows,
            headers=headers,
            removeNull=False,
        )
        tables_md.append(table_md)

    return "\n\n".join(tables_md) if tables_md else "No data found"


def generate_ioc_tables(ioc_objects: list) -> str:
    if not ioc_objects:
        return "No indicators found"

    type_groups: dict[str, list[dict[str, Any]]] = {}

    for item in ioc_objects:
        ioc_type = item.get("type", "Unknown")
        if ioc_type not in type_groups:
            type_groups[ioc_type] = []

        row = {}

        row["ID"] = item.get("id")
        row["Value"] = item.get("value")
        row["Event Info"] = item.get("eventInfo")
        row["Timestamp"] = item.get("timestamp")
        row["Expired"] = item.get("expired")

        if ioc_type == "domain":
            row["Name"] = item.get("name")
            row["Classification"] = item.get("classification")
            if item.get("ips"):
                row["IPs"] = ", ".join(item.get("ips", []))

        elif ioc_type == "url":
            row["URL"] = item.get("url")
            if item.get("ips"):
                row["IPs"] = ", ".join(item.get("ips", []))

        elif ioc_type == "file":
            row["Name"] = item.get("name")
            row["MD5"] = item.get("md5")
            row["SHA1"] = item.get("sha1")
            row["SHA256"] = item.get("sha256")
            row["Size"] = item.get("size")
            row["MIME Type"] = item.get("mimeType")

        elif ioc_type == "ip":
            row["IP"] = item.get("ip")

        elif ioc_type == "email":
            row["Source"] = item.get("src")

        elif ioc_type == "tlsssl":
            row["JARM Fingerprint"] = item.get("jarm_fingerprint")

        elif ioc_type == "vulnerabilityioc":
            row["Vulnerability ID"] = item.get("vulnerabilityId")
            row["Name"] = item.get("name")
            row["Description"] = item.get("description")
            row["Severity"] = item.get("severity")
            row["CVSS Score"] = item.get("cvssScore")
            row["Published"] = item.get("published")
            row["Last Modified"] = item.get("lastModified")

        row = {k: v for k, v in row.items() if v is not None}

        if row:
            type_groups[ioc_type].append(row)

    tables_md = []
    for ioc_type, rows in type_groups.items():
        if not rows:
            continue

        all_headers: set[str] = set()
        for row in rows:
            all_headers.update(row.keys())

        headers = sorted(all_headers)

        table_md = tableToMarkdown(f"{ioc_type.upper()} Indicators", rows, headers=headers, removeNull=True)
        tables_md.append(table_md)

    return "\n\n".join(tables_md) if tables_md else "No indicators found"


def dmontip_get_indicators_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE

    result = client.get_indicators(size=size)

    ioc_objects = result.get("iocObjects", [])

    indicators = []
    for item in ioc_objects:
        indicator_data = extract_features_to_dict(item)
        indicators.append(indicator_data)

    outputs = {"Darkmon.Indicator(val.id == obj.id)": indicators}

    readable_output = generate_ioc_tables(ioc_objects)

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_global_search_command(client: Client, args: dict) -> CommandResults:
    query = args.get("query")
    if not query:
        raise ValueError("Query parameter is required")

    indicator_type = args.get("type") or ""
    user_page = arg_to_number(args.get("page", 1)) or 1
    page = max(0, user_page - 1)
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE

    result = client.global_search(query=query, indicator_type=indicator_type, page=page, size=size)

    search_results = result.get("content", [])
    pagination = result.get("page", {})

    transformed_results = [extract_search_result(item) for item in search_results]

    outputs = {"Darkmon.SearchResult": transformed_results, "Darkmon.Pagination": pagination}

    readable_output = generate_feature_tables(search_results)

    if pagination:
        current_page = pagination.get("number", 0) + 1
        total_pages = pagination.get("totalPages", 1)
        total_elements = pagination.get("totalElements", 0)

        pagination_info = f"\n\n**Pagination**: Page {current_page} of {total_pages} ({total_elements} total items)"

        if total_pages > 1:
            pagination_info += "\n\nTo navigate pages, use the 'page' argument:"
            if current_page > 1:
                pagination_info += (
                    f'\n- Previous page: `!dmontip-global-search query="{query}" type="{indicator_type}" page={page}`'
                )
            if current_page < total_pages:
                pagination_info += (
                    f'\n- Next page: `!dmontip-global-search query="{query}" type="{indicator_type}" page={page + 2}`'
                )
            pagination_info += (
                f"\n\nTo change page size: "
                f'`!dmontip-global-search query="{query}" type="{indicator_type}" page={page} size=<number>`'
            )

        readable_output += pagination_info

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_compromised_command(client: Client, args: dict) -> CommandResults:
    data_type = (args.get("type") or "").strip()
    if not data_type:
        raise ValueError("type argument is required (accounts, bank-cards, combo-lists, public-breaches, employees)")

    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 500:
        raise ValueError("size must be between 1 and 500")

    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    default_sort_by_type = {"combo-lists": "firstSeen,desc"}
    sort = (args.get("sort") or "").strip() or default_sort_by_type.get(data_type)

    result = client.get_compromised_data(data_type=data_type, page=api_page, size=size, sort=sort)

    content_items = result.get("content", []) or []
    page_obj = result.get("page") or {}

    singular_map = {
        "accounts": "Account",
        "bank-cards": "BankCard",
        "combo-lists": "ComboList",
        "public-breaches": "PublicBreach",
        "employees": "Employee",
    }
    singular = singular_map.get(data_type, data_type.capitalize())

    outputs: dict[str, Any] = {f"Darkmon.Compromised.{singular}": content_items}
    if page_obj:
        outputs["Darkmon.Compromised.Page"] = page_obj

    priority_columns: dict[str, list[str]] = {
        "accounts": [
            "id",
            "username",
            "password",
            "url",
            "firstSeen",
            "firstSeenDate",
            "firstCompromiseDate",
            "lastCompromiseDate",
            "state",
            "valid",
            "compromiseSourcesCount",
            "countries",
            "sources",
            "stealers",
        ],
        "employees": [
            "id",
            "username",
            "password",
            "url",
            "firstSeen",
            "firstSeenDate",
            "firstCompromiseDate",
            "lastCompromiseDate",
            "state",
            "valid",
            "compromiseSourcesCount",
            "countries",
            "sources",
            "stealers",
        ],
        "combo-lists": ["id", "username", "password", "source", "firstSeen", "messageTime", "firstSeenDate", "state", "valid"],
        "bank-cards": [
            "id",
            "cardNumber",
            "cardHolders",
            "cvvs",
            "expiry",
            "firstSeen",
            "firstSeenDate",
            "state",
            "valid",
            "compromiseSourcesCount",
            "countries",
            "sources",
            "stealers",
            "chatIds",
            "chatNames",
            "chatUsernames",
        ],
        "public-breaches": [
            "id",
            "source",
            "breachTime",
            "name",
            "username",
            "password",
            "emails",
            "phoneNumbers",
            "address",
            "country",
            "gender",
            "birthDate",
            "facebookUsername",
            "githubUsername",
            "linkedinUsername",
            "twitterUsername",
            "firstSeen",
            "firstSeenDate",
            "state",
            "valid",
            "photoUrl",
        ],
    }

    if content_items:
        headers_set: set[str] = set()
        simplified_rows: list[dict[str, Any]] = []
        for item in content_items:
            row: dict[str, Any] = {}
            for k, v in item.items():
                if isinstance(v, dict):
                    continue
                if isinstance(v, list):
                    if all(not isinstance(x, dict | list) for x in v):
                        display_val = ", ".join(str(x) for x in v)
                    else:
                        continue
                else:
                    display_val = v
                row[k] = display_val
            if row:
                headers_set.update(row.keys())
                simplified_rows.append(row)

        priority = priority_columns.get(data_type, [])
        ordered_headers: list[str] = [h for h in priority if h in headers_set]
        ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

        readable_output = tableToMarkdown(
            f"Compromised {singular} Data (type={data_type}, page={user_page}, size={size})",
            _redact_rows(simplified_rows, _should_redact_secrets()),
            headers=ordered_headers,
            removeNull=True,
        )
        if page_obj:
            current_page = (page_obj.get("number", api_page)) + 1
            total_pages = page_obj.get("totalPages")
            total_elements = page_obj.get("totalElements")
            pagination_line = f"Page {current_page}"
            if total_pages is not None:
                pagination_line += f" / {total_pages}"
            if total_elements is not None:
                pagination_line += f" | Total Items: {total_elements}"
            readable_output += f"\n\n{pagination_line}"
    else:
        readable_output = f"No compromised data found for type {data_type}"

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_vpn_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    sort = (args.get("sort") or "").strip() or "firstSeen,desc"

    result = client.get_vpn(page=api_page, size=size, sort=sort)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = ["ip", "port", "name", "firstSeen", "lastUpdated", "id"]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    readable_output = (
        tableToMarkdown(f"VPN Exit Nodes (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True)
        if rows
        else "No VPN data found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.VPN": content}
    if page_obj:
        outputs["Darkmon.VPN.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_proxy_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    sort = (args.get("sort") or "").strip() or "firstSeen,desc"

    result = client.get_proxy(page=api_page, size=size, sort=sort)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = ["ip", "port", "type", "firstSeen", "lastUpdated", "id"]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    readable_output = (
        tableToMarkdown(f"Open Proxies (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True)
        if rows
        else "No proxy data found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.Proxy": content}
    if page_obj:
        outputs["Darkmon.Proxy.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_cve_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    result = client.get_cve(page=api_page, size=size)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = ["name", "cvssScore", "description", "published", "lastModified", "sourceIdentifier", "tags"]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    readable_output = (
        tableToMarkdown(f"Vulnerabilities (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True)
        if rows
        else "No vulnerability data found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.CVE": content}
    if page_obj:
        outputs["Darkmon.CVE.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_nrd_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    sort = (args.get("sort") or "").strip() or "timestamp,desc"

    result = client.get_nrd(page=api_page, size=size, sort=sort)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = ["value", "timestamp"]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    readable_output = (
        tableToMarkdown(
            f"Newly Registered Domains (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True
        )
        if rows
        else "No newly-registered domains found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.NRD": content}
    if page_obj:
        outputs["Darkmon.NRD.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_tbf_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    sort = (args.get("sort") or "").strip() or "timestamp,desc"

    result = client.get_tbf(page=api_page, size=size, sort=sort)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = ["value", "timestamp"]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    readable_output = (
        tableToMarkdown(
            f"Telnet Brute Force IOCs (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True
        )
        if rows
        else "No Telnet Brute Force IOCs found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.TBF": content}
    if page_obj:
        outputs["Darkmon.TBF.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_ransomware_command(client: Client, args: dict) -> CommandResults:
    mentions = (args.get("type") or "").strip().lower() == "mentions"
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    sort = (args.get("sort") or "").strip() or "publishedAt,desc"

    result = client.get_ransomware(mentions=mentions, page=api_page, size=size, sort=sort)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = [
        "id",
        "victimName",
        "victimDomain",
        "threatActor",
        "description",
        "publishedAt",
        "updatedAt",
        "firstSeen",
        "state",
        "valid",
        "matchedKeywordsLength",
        "matchedKeywords",
        "screenShotUrl",
        "articleSourceId",
    ]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    title_type = "Mentions" if mentions else "Articles"
    readable_output = (
        tableToMarkdown(
            f"Ransomware {title_type} (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True
        )
        if rows
        else f"No ransomware {title_type.lower()} found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.Ransomware": content}
    if page_obj:
        outputs["Darkmon.Ransomware.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_landscape_command(client: Client, args: dict) -> CommandResults:
    mentions = (args.get("type") or "").strip().lower() == "mentions"
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    result = client.get_landscape(mentions=mentions, page=api_page, size=size)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = [
        "id",
        "title",
        "link",
        "publicationDate",
        "source",
        "author",
        "firstSeen",
        "firstSeenDate",
        "state",
        "valid",
        "categories",
        "description",
        "matchedKeywords",
        "matchedKeywordsLength",
    ]

    rows: list[dict[str, Any]] = []
    headers_set: set[str] = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if k == "content":
                continue
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    v = ", ".join(str(x) for x in v)
                else:
                    continue
            elif isinstance(v, dict):
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted([h for h in headers_set if h not in priority]))

    title_type = "Mentions" if mentions else "Articles"
    readable_output = (
        tableToMarkdown(f"Landscape {title_type} (page={user_page}, size={size})", rows, headers=ordered_headers, removeNull=True)
        if rows
        else f"No landscape {title_type.lower()} found"
    )

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {"Darkmon.Landscape": content}
    if page_obj:
        outputs["Darkmon.Landscape.Page"] = page_obj

    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=result)


def dmontip_get_boardprotection_command(client: Client, args: dict) -> CommandResults:
    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    term = (args.get("term") or "").strip() or None

    result = client.get_board_protection_requests(page=api_page, size=size, term=term)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    priority = [
        "value",
        "type",
        "state",
        "firstName",
        "middleName",
        "lastName",
        "reason",
        "createdBy",
        "createdAt",
        "updatedAt",
        "tokens",
        "id",
    ]

    rows: list[dict[str, Any]] = []
    headers_set: set = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, dict):
                continue
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    row[k] = ", ".join(str(x) for x in v)
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted(h for h in headers_set if h not in priority))

    if rows:
        readable_output = tableToMarkdown(
            f"Board Protection Requests (page={user_page}, size={size})",
            rows,
            headers=ordered_headers,
            removeNull=True,
        )
    else:
        readable_output = "No board protection requests found"

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {
        "Darkmon.BoardProtection": content,
    }
    if page_obj:
        outputs["Darkmon.BoardProtection.Page"] = page_obj

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result,
    )


def dmontip_get_boardemails_command(client: Client, args: dict) -> CommandResults:
    leak_type = (args.get("type") or "").strip()
    if not leak_type:
        raise ValueError("type argument is required (accounts, combo-lists, public-breaches)")

    email = (args.get("email") or "").strip()
    if not email:
        raise ValueError("email argument is required")

    size = arg_to_number(args.get("size", DEFAULT_SIZE)) or DEFAULT_SIZE
    if size < 1 or size > 100:
        raise ValueError("size must be between 1 and 100")
    user_page = arg_to_number(args.get("page", 1)) or 1
    if user_page < 1:
        raise ValueError("page must be >= 1")
    api_page = user_page - 1

    term = (args.get("term") or "").strip() or None

    result = client.get_board_leaks(leak_type=leak_type, email=email, page=api_page, size=size, term=term)
    content = result.get("content", []) or []
    page_obj = result.get("page") or {}

    singular_map = {
        "accounts": "Account",
        "combo-lists": "ComboList",
        "public-breaches": "PublicBreach",
    }
    singular = singular_map.get(leak_type, leak_type.capitalize())

    priority_columns: dict[str, list[str]] = {
        "accounts": [
            "email",
            "id",
            "compromiseDate",
            "username",
            "password",
            "url",
            "machineUsername",
            "ip",
            "country",
            "stealer",
            "source",
        ],
        "combo-lists": [
            "email",
            "id",
            "messageTime",
            "username",
            "password",
            "source",
        ],
        "public-breaches": [
            "email",
            "id",
            "breachTime",
            "source",
            "name",
            "username",
            "password",
            "address",
            "country",
            "birthDate",
            "gender",
            "firstSeen",
            "firstSeenDate",
            "facebookUsername",
            "githubUsername",
            "linkedinUsername",
            "twitterUsername",
            "photoUrl",
        ],
    }

    rows: list[dict[str, Any]] = []
    headers_set: set = set()
    for item in content:
        row: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, dict):
                if k == "ip" and "address" in v:
                    row["ip"] = v.get("address")
                continue
            if isinstance(v, list):
                if all(not isinstance(x, dict | list) for x in v):
                    row[k] = ", ".join(str(x) for x in v)
                continue
            row[k] = v
        if row:
            headers_set.update(row.keys())
            rows.append(row)

    priority = priority_columns.get(leak_type, [])
    ordered_headers = [h for h in priority if h in headers_set]
    ordered_headers.extend(sorted(h for h in headers_set if h not in priority))

    if rows:
        readable_output = tableToMarkdown(
            f"Board Leak {singular} (email={email}, page={user_page}, size={size})",
            _redact_rows(rows, _should_redact_secrets()),
            headers=ordered_headers,
            removeNull=True,
        )
    else:
        readable_output = f"No board leak {leak_type} found for email {email}"

    if page_obj:
        current_page = (page_obj.get("number", api_page)) + 1
        total_pages = page_obj.get("totalPages")
        total_elements = page_obj.get("totalElements")
        pagination_line = f"Page {current_page}"
        if total_pages is not None:
            pagination_line += f" / {total_pages}"
        if total_elements is not None:
            pagination_line += f" | Total Items: {total_elements}"
        readable_output += f"\n\n{pagination_line}"

    outputs: dict[str, Any] = {
        f"Darkmon.BoardLeak.{singular}": content,
    }
    if page_obj:
        outputs["Darkmon.BoardLeak.Page"] = page_obj

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result,
    )


_DBOT_TYPE_BY_LABEL = {
    "IP": "ip",
    "URL": "url",
    "Domain": "domain",
    "Email": "email",
    "Hash": "file",
}


def _search_each(client: Client, args: dict, arg_key: str, type_label: str, missing_msg: str) -> list[CommandResults]:
    values = argToList(args.get(arg_key))
    if not values:
        raise ValueError(missing_msg)
    indicator_type = _DBOT_TYPE_BY_LABEL[type_label]

    results: list[CommandResults] = []
    for v in values:
        cr = dmontip_global_search_command(
            client,
            {
                "query": v,
                "type": type_label,
                "page": args.get("page", 1),
                "size": args.get("size", DEFAULT_SIZE),
            },
        )
        outputs_dict: dict[str, Any] = cr.outputs if isinstance(cr.outputs, dict) else {}
        search_items = outputs_dict.get("Darkmon.SearchResult", [])
        cr.outputs = {**outputs_dict, **build_dbot_outputs(v, indicator_type, search_items)}
        results.append(cr)
    return results


def dmontip_search_ip_command(client: Client, args: dict) -> list[CommandResults]:
    return _search_each(client, args, "ip", "IP", "IP parameter is required")


def dmontip_search_url_command(client: Client, args: dict) -> list[CommandResults]:
    return _search_each(client, args, "url", "URL", "URL parameter is required")


def dmontip_search_domain_command(client: Client, args: dict) -> list[CommandResults]:
    return _search_each(client, args, "domain", "Domain", "Domain parameter is required")


def dmontip_search_email_command(client: Client, args: dict) -> list[CommandResults]:
    return _search_each(client, args, "email", "Email", "Email parameter is required")


def dmontip_search_file_command(client: Client, args: dict) -> list[CommandResults]:
    return _search_each(client, args, "hash", "Hash", "File hash parameter is required")


FEED_INDICATOR_TYPE_MAP: dict[str, Any] = {
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "ip": FeedIndicatorType.IP,
    "file": FeedIndicatorType.File,
    "email": FeedIndicatorType.Email,
    "vulnerabilityioc": FeedIndicatorType.CVE,
    "tlsssl": "TLSSSL",
}


def fetch_indicators_command(client: Client, params: dict) -> list[dict]:
    tlp_color = params.get("tlp_color")
    feed_tags = argToList(params.get("feedTags", ""))
    limit = arg_to_number(params.get("limit", DEFAULT_SIZE)) or DEFAULT_SIZE

    result = client.get_indicators(size=limit)
    ioc_objects = result.get("iocObjects", []) or []

    indicators: list[dict[str, Any]] = []
    for item in ioc_objects:
        ioc_type = item.get("type") or ""
        value = item.get("value")
        if not value:
            continue

        indicator_type = FEED_INDICATOR_TYPE_MAP.get(ioc_type, ioc_type)

        raw_data = {"value": value, "type": indicator_type, **item}
        indicator_obj: dict[str, Any] = {
            "value": value,
            "type": indicator_type,
            "service": VENDOR,
            "rawJSON": raw_data,
            "fields": {},
        }

        # Common fields applicable to every IOC type
        if event_info := item.get("eventInfo"):
            indicator_obj["fields"]["description"] = event_info
        if ts := item.get("timestamp"):
            indicator_obj["fields"]["firstseenbysource"] = ts
            indicator_obj["fields"]["lastseenbysource"] = ts

        # Type-specific fields driven by IOC_FIELD_MAP - declarative, future-proof
        _apply_ioc_fields(item, ioc_type, indicator_obj)

        if feed_tags:
            existing = indicator_obj["fields"].get("tags", [])
            indicator_obj["fields"]["tags"] = existing + feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("X-API-KEY", {}).get("password")
    if not api_key:
        raise DemistoException("API key is required")

    base_url = (params.get("base_url") or DEFAULT_BASE_URL).rstrip("/")

    headers = {
        "X-API-KEY": api_key,
        "Accept": "application/json",
    }

    client = Client(
        base_url=base_url,
        headers=headers,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )

    try:
        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for batch_indicators in batch(indicators, batch_size=2000):
                demisto.createIndicators(batch_indicators)

        elif command == "dmontip-get-indicators":
            return_results(dmontip_get_indicators_command(client, args))

        elif command == "dmontip-global-search":
            return_results(dmontip_global_search_command(client, args))

        elif command == "dmontip-get-compromised":
            return_results(dmontip_get_compromised_command(client, args))

        elif command == "dmontip-get-vpn":
            return_results(dmontip_get_vpn_command(client, args))

        elif command == "dmontip-get-proxy":
            return_results(dmontip_get_proxy_command(client, args))

        elif command == "dmontip-get-cve":
            return_results(dmontip_get_cve_command(client, args))

        elif command == "dmontip-get-nrd":
            return_results(dmontip_get_nrd_command(client, args))

        elif command == "dmontip-get-tbf":
            return_results(dmontip_get_tbf_command(client, args))

        elif command == "dmontip-get-ransomware":
            return_results(dmontip_get_ransomware_command(client, args))

        elif command == "dmontip-get-landscape":
            return_results(dmontip_get_landscape_command(client, args))

        elif command == "dmontip-get-boardprotection":
            return_results(dmontip_get_boardprotection_command(client, args))

        elif command == "dmontip-get-boardemails":
            return_results(dmontip_get_boardemails_command(client, args))

        elif command == "ip":
            return_results(dmontip_search_ip_command(client, args))

        elif command == "url":
            return_results(dmontip_search_url_command(client, args))

        elif command == "domain":
            return_results(dmontip_search_domain_command(client, args))

        elif command == "email":
            return_results(dmontip_search_email_command(client, args))

        elif command == "file":
            return_results(dmontip_search_file_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
