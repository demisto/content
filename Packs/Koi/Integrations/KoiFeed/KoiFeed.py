import re
import traceback
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa

INTEGRATION_NAME = "KOI Feed"
MAX_PAGE_SIZE = 500
MAX_PAGES = 200
INDICATOR_TYPE = "Koi Software Item"

SHA1_RE = re.compile(r'^[A-Fa-f0-9]{40}$')
SHA256_RE = re.compile(r'^[A-Fa-f0-9]{64}$')

DBOT_SCORE_TO_REPUTATION = {
    Common.DBotScore.NONE: "None",
    Common.DBotScore.GOOD: "Good",
    Common.DBotScore.SUSPICIOUS: "Suspicious",
    Common.DBotScore.BAD: "Bad",
}


def koi_risk_to_dbot_score(risk_score: float | None, risk_level: str | None) -> int:
    if risk_score is None and risk_level is None:
        return Common.DBotScore.NONE
    if risk_level and risk_level.lower() == "pending":
        return Common.DBotScore.NONE
    if risk_score is not None:
        if risk_score <= 3:
            return Common.DBotScore.GOOD
        if risk_score <= 6:
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.BAD
    level_map = {"low": Common.DBotScore.GOOD, "medium": Common.DBotScore.SUSPICIOUS,
                 "high": Common.DBotScore.BAD, "critical": Common.DBotScore.BAD}
    return level_map.get(risk_level.lower() if risk_level else "", Common.DBotScore.NONE)


class Client(ContentClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

    def get_inventory(self, page: int = 1, page_size: int = MAX_PAGE_SIZE,
                      marketplace: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "page_size": min(page_size, MAX_PAGE_SIZE)}
        if marketplace:
            params["marketplace"] = marketplace
        return self._http_request(method="GET", url_suffix="/api/external/v2/inventory", params=params)

    def test_connection(self) -> str:
        self.get_inventory(page=1, page_size=1)
        return "ok"


def _build_relationships(item: dict[str, Any], indicator_value: str, reliability: str) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    item_id = item.get("item_id", "")

    if SHA1_RE.match(item_id) or SHA256_RE.match(item_id):
        relationships.append(EntityRelationship(
            entity_a=indicator_value,
            entity_a_type=INDICATOR_TYPE,
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_b=item_id,
            entity_b_type=FeedIndicatorType.File,
            reverse_name=EntityRelationship.Relationships.RELATED_TO,
            source_reliability=reliability,
            brand=INTEGRATION_NAME,
        ).to_indicator())

    findings = item.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, str) and finding.upper().startswith("CVE-"):
                relationships.append(EntityRelationship(
                    entity_a=indicator_value,
                    entity_a_type=INDICATOR_TYPE,
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_b=finding,
                    entity_b_type=FeedIndicatorType.CVE,
                    reverse_name=EntityRelationship.Relationships.RELATED_TO,
                    source_reliability=reliability,
                    brand=INTEGRATION_NAME,
                ).to_indicator())

    return relationships


def _build_indicator_from_item(item: dict[str, Any], tags: list[str], tlp_color: str | None,
                               create_relationships: bool = False, reliability: str = "") -> dict[str, Any]:
    item_id = item.get("item_id", "")
    marketplace = item.get("marketplace", "")
    version = item.get("version", "")
    display_name = item.get("item_display_name", item_id)
    risk_score = item.get("risk")
    risk_level = item.get("risk_level")

    dbot_score = koi_risk_to_dbot_score(risk_score, risk_level)

    value = display_name
    if version and version not in display_name:
        value = f"{display_name} ({version})"

    fields: dict[str, Any] = {
        "koiitemid": item_id,
        "koimarketplace": marketplace,
        "koiversion": version,
        "koidisplayname": display_name,
        "koirisk": risk_score,
        "koirisklevel": risk_level,
        "koipublisher": item.get("publisher_name"),
        "koiendpointcount": item.get("endpoint_count"),
        "koifindings": ", ".join(str(f) for f in item.get("findings", []) if f),
        "koiplatforms": ", ".join(str(p) for p in item.get("platforms", []) if p),
        "koistatus": item.get("status"),
        "koiinstallscount": item.get("installs_count"),
        "koifirstseen": item.get("first_seen"),
        "koilastseen": item.get("last_seen"),
        "koishortdescription": item.get("short_description"),
        "dbotreputation": DBOT_SCORE_TO_REPUTATION.get(dbot_score, "None"),
    }
    if tags:
        fields["tags"] = tags
    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color

    indicator: dict[str, Any] = {
        "value": value,
        "type": INDICATOR_TYPE,
        "rawJSON": item,
        "score": dbot_score,
        "fields": fields,
    }

    if create_relationships:
        rels = _build_relationships(item, value, reliability)
        if rels:
            indicator["relationships"] = rels

    return indicator


def _build_cve_indicators_from_item(item: dict[str, Any], tags: list[str], tlp_color: str | None) -> list[dict[str, Any]]:
    cves = []
    findings = item.get("findings", [])
    if not isinstance(findings, list):
        return cves

    for finding in findings:
        if isinstance(finding, str) and finding.upper().startswith("CVE-"):
            cve_id = finding.upper()
            fields: dict[str, Any] = {
                "sourceintegration": INTEGRATION_NAME,
                "koiitemid": item.get("item_id"),
                "koimarketplace": item.get("marketplace"),
            }
            if tags:
                fields["tags"] = tags
            if tlp_color:
                fields["trafficlightprotocol"] = tlp_color
            cves.append({
                "value": cve_id,
                "type": FeedIndicatorType.CVE,
                "rawJSON": item,
                "fields": fields,
                "score": Common.DBotScore.SUSPICIOUS,
            })
    return cves


def fetch_indicators_command(client: Client, params: dict[str, Any]) -> None:
    tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    marketplaces = argToList(params.get("feedMarketplaces"))
    min_risk_score = arg_to_number(params.get("feedMinRiskScore")) or 0
    create_relationships = argToBoolean(params.get("createRelationships", True))
    reliability = params.get("feedReliability", "B - Usually reliable")

    demisto.debug(f"[Feed] Starting indicator fetch. marketplaces={marketplaces}, min_risk={min_risk_score}")

    marketplace_list = marketplaces if marketplaces else [None]

    total_created = 0
    for mp in marketplace_list:
        for page in range(1, MAX_PAGES + 1):
            response = client.get_inventory(page=page, page_size=MAX_PAGE_SIZE, marketplace=mp)
            items = response.get("items", [])
            if not items:
                break

            indicators: list[dict[str, Any]] = []
            for item in items:
                risk = item.get("risk")
                if risk is not None and risk < min_risk_score:
                    continue

                indicators.append(_build_indicator_from_item(item, tags, tlp_color, create_relationships, reliability))
                indicators.extend(_build_cve_indicators_from_item(item, tags, tlp_color))

            if indicators:
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)
                total_created += len(indicators)

            demisto.debug(f"[Feed] marketplace={mp}, page={page}, items={len(items)}, indicators={len(indicators)}")

            if len(items) < MAX_PAGE_SIZE:
                break

    demisto.debug(f"[Feed] Finished. Total indicators created: {total_created}")


def get_indicators_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or 50
    marketplace = args.get("marketplace")
    min_risk_score = arg_to_number(args.get("min_risk_score")) or 0
    tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    create_relationships = argToBoolean(params.get("createRelationships", True))
    reliability = params.get("feedReliability", "B - Usually reliable")

    all_indicators: list[dict[str, Any]] = []
    page = 1
    while len(all_indicators) < limit:
        response = client.get_inventory(page=page, page_size=min(limit, MAX_PAGE_SIZE), marketplace=marketplace)
        items = response.get("items", [])
        if not items:
            break

        for item in items:
            if len(all_indicators) >= limit:
                break
            risk = item.get("risk")
            if risk is not None and risk < min_risk_score:
                continue
            all_indicators.append(_build_indicator_from_item(item, tags, tlp_color, create_relationships, reliability))

        if len(items) < min(limit, MAX_PAGE_SIZE):
            break
        page += 1

    display_rows = []
    for ind in all_indicators:
        fields = ind.get("fields", {})
        display_rows.append({
            "Value": ind["value"],
            "Type": ind["type"],
            "Display Name": fields.get("koidisplayname"),
            "Risk Score": fields.get("koirisk"),
            "Risk Level": fields.get("koirisklevel"),
            "Marketplace": fields.get("koimarketplace"),
            "Publisher": fields.get("koipublisher"),
            "Reputation": fields.get("dbotreputation"),
            "Endpoints": fields.get("koiendpointcount"),
        })

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Indicators",
        display_rows,
        headers=["Value", "Type", "Display Name", "Risk Score", "Risk Level",
                 "Marketplace", "Publisher", "Reputation", "Endpoints"],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="KoiFeed.Indicator",
        outputs_key_field="value",
        outputs=all_indicators,
        raw_response=all_indicators,
    )


def main() -> None:
    demisto.debug(f"{INTEGRATION_NAME} started")
    command = demisto.command()

    try:
        params = demisto.params()
        base_url = params.get("url", "https://api.prod.koi.security/").rstrip("/")
        api_key = params.get("api_key", {})
        if isinstance(api_key, dict):
            api_key = api_key.get("password", "")
        verify = not argToBoolean(params.get("insecure", False))
        proxy = argToBoolean(params.get("proxy", False))

        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            result = client.test_connection()
            return_results(result)
        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)
        elif command == "koi-feed-get-indicators":
            result = get_indicators_command(client, demisto.args(), params)
            return_results(result)
        else:
            raise DemistoException(f"Command '{command}' is not implemented")

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
