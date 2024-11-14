import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

import json
import urllib3
import traceback
import enum

# Disable insecure warnings
urllib3.disable_warnings()

DEBUG_MODE = False

# Minimum supported version is:  1.38
MIN_MAJOR_VERSION = 1
MIN_MINOR_VERSION = 43
FULL_INCIDENTS_SECONDS = 60 if DEBUG_MODE else 86400
ONE_WEEK_IN_SECONDS = 1 if DEBUG_MODE else 604800

DEFAULT_TIME_ID = "timeAgo_days_7"
PREVIOUS_DEFAULT_TIME_ID = "timeAgo_days_7"
XM_CYBER_INCIDENT_TYPE_SCORE = "XM Cyber Security Score"
XM_CYBER_INCIDENT_TYPE_TECHNIQUE = "XM Cyber Technique"
XM_CYBER_INCIDENT_TYPE_ASSET = "XM Cyber Critical Asset"
XM_CYBER_INCIDENT_TYPE_CHOKE_POINT = "XM Cyber Choke Point"
TOP_ENTITIES = 3
PAGE_SIZE = 50
MAX_PAGES = 10
SENSOR_TYPE = "Sensor"

XmEventType = Dict[str, Any]
""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with XM Cyber API"""

    def get(self, url_suffix: str, params: Optional[Dict[str, Any]] = None):
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def post(self, url_suffix: str, params: Optional[Dict[str, Any]] = None):
        return self._http_request(
            method="POST", url_suffix=url_suffix, data=json.dumps(params)
        )

    def _paginated(
        self,
        method: str,
        url_suffix: str,
        params: Dict[str, Any],
        page_size: int,
        max_pages: int,
        log: bool,
    ):
        page, total_pages = 1, 1
        data = []
        params["pageSize"] = page_size
        while page <= total_pages and page <= max_pages:
            if log:
                writeLog(f"in {url_suffix} while loop {page} {total_pages}")

            params["page"] = page
            res = None
            if method == "GET":
                res = self.get(url_suffix, params)
            else:
                res = self.post(url_suffix, params)

            data.extend(res["data"])
            total_pages = res["paging"]["totalPages"]
            page += 1

        return data

    def get_paginated(
        self,
        url_suffix: str,
        params: Optional[Dict[str, Any]] = None,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
        log: bool = True,
    ):
        params = params or {}
        return self._paginated("GET", url_suffix, params, page_size, max_pages, log)

    def post_paginated(
        self,
        url_suffix: str,
        params: Optional[Dict[str, Any]] = None,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
        log: bool = True,
    ):
        params = params or {}
        return self._paginated("POST", url_suffix, params, page_size, max_pages, log)

    def get_base_url(self):
        return self._base_url


class URLS:
    Version = "/version"
    Entities = "/systemReport/entities"
    Risk_Score = "/systemReport/riskScoreV2"
    Top_Assets_At_Risk = "/systemReport/topAssetsAtRiskV2"
    Top_Choke_Points = "/systemReport/topChokePointsV2"
    Techniques = "/systemReport/techniques"
    Critical_Assets_At_Risk = "/systemReport/entities/{entity_id}/assetsAtRisk"
    Affected_Entities = "/systemReport/entities/{entity_id}/affectedEntities"
    Entity_Report = "/#/scenarioHub/entityReport"


class EVENT_NAME:
    EventPrefix = "XM Cyber "
    RiskScore = "security score"
    AssetAtRisk = "critical asset at risk"
    ChokePoint = "choke point"
    TopTechnique = "technique impact"


class SEVERITY:
    Unknown = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4


class XM:
    is_fetch_incidents = False
    ignore_trend = DEBUG_MODE
    date_created = None  # For tests

    def __init__(self, client: Client):
        self.client = client

    def get_version(self):
        return self.client.get(URLS.Version)

    def risk_score(self, time_id: str = DEFAULT_TIME_ID, resolution: int = 1):
        """
        The function returns risk score data for the given timeId
        return dict:
            trend - trend from previous time id
            current_grade - current risk score grade (A-F)
            current_score - current risk score (0-100)
        """
        risk_score_response = self.client.get(
            URLS.Risk_Score, {"timeId": time_id, "resolution": resolution}
        )

        risk_score_stats = risk_score_response["data"]["stats"]

        return {
            "trend": risk_score_stats["trend"],
            "current_grade": risk_score_stats["grade"],
            "current_score": risk_score_stats["score"],
        }

    def get_entities(self, time_id: int, only_assets: bool) -> Dict[str, Any]:
        """
        This general function returns data regarding the entities at a specific timeId
        Params:
          only_assets - return only assets
        return:
          list of entities
        """
        filterObj = {}
        if only_assets:
            filterObj["asset"] = True

        query = {"timeId": time_id, "filter": filterObj}
        return self.client.post_paginated(URLS.Entities, query)

    def _top_entities(self, url, time_id, amount_of_results) -> List[Dict[str, Any]]:
        response = self.client.get(
            url, {"timeId": time_id, "amountOfResults": amount_of_results}
        )

        return response["data"]["entities"]

    def top_assets_at_risk(
        self, time_id: str = DEFAULT_TIME_ID, amount_of_results: int = TOP_ENTITIES
    ) -> List[Dict[str, Any]]:
        return self._top_entities(URLS.Top_Assets_At_Risk, time_id, amount_of_results)

    def top_choke_points(
        self, time_id: str = DEFAULT_TIME_ID, amount_of_results: int = TOP_ENTITIES
    ) -> List[Dict[str, Any]]:
        return self._top_entities(URLS.Top_Choke_Points, time_id, amount_of_results)

    def get_affected_assets(
        self,
        entity_id: str,
        time_id: str = DEFAULT_TIME_ID,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
    ) -> List[Dict[str, Any]]:
        return self.client.get_paginated(
            URLS.Critical_Assets_At_Risk.format(entity_id=entity_id),
            {"timeId": time_id, "sort": "attackComplexity"},
            page_size,
            max_pages,
        )

    def get_affected_entities(
        self,
        entity_id: str,
        time_id: str = DEFAULT_TIME_ID,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
    ) -> List[Dict[str, Any]]:
        return self.client.get_paginated(
            URLS.Affected_Entities.format(entity_id=entity_id),
            {"timeId": time_id, "sort": "attackComplexity"},
            page_size,
            max_pages,
        )

    def search_entities(
        self, field_name_to_value: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Union[str, Dict[str, Any]]] = dict()
        for field_name, value in field_name_to_value.items():
            if field_name == "name":
                params["search"] = f'{{"$regex":"/{value}/i"}}'
            else:
                params.setdefault("filter", {}).update({field_name: value})  # type: ignore

        if params.get("filter"):
            params["filter"] = json.dumps(params["filter"])

        return self.client.get_paginated(URLS.Entities, params)

    def get_techniques(
        self,
        time_id: str,
        page_size: int,
        max_pages: int,
    ) -> List[Dict[str, Any]]:
        return self.client.get_paginated(
            URLS.Techniques, {"timeId": time_id}, page_size, max_pages
        )

    def get_technique_remediation(
        self, technique: str, time_id: str = DEFAULT_TIME_ID
    ) -> List[Dict[str, Any]]:
        return self.client.get(
            f"{URLS.Techniques}/{technique}/remediation", {"timeId": time_id}
        )

    def get_base_url(self) -> str:
        return self.client.get_base_url()

    def _get_base_url_without_api(self):
        base_url = self.get_base_url()
        return base_url.rstrip("/api")

    def get_entity_report_url(
        self, entity_id: str, time_id: str = DEFAULT_TIME_ID
    ) -> str:
        return f"{self._get_base_url_without_api()}/#/report/entity/{entity_id}?timeId={time_id}"

    def get_dashboard_url(self) -> str:
        return f"{self._get_base_url_without_api()}/#/dashboard"

    def get_technique_url(self, technique: str, time_id: str = DEFAULT_TIME_ID) -> str:
        return f"{self._get_base_url_without_api()}/#/report/technique/{technique}?timeId={time_id}"

    def get_link_for_report(self, event_type: str, data: Dict[str, Any]) -> str:
        if event_type == EVENT_NAME.AssetAtRisk or event_type == EVENT_NAME.ChokePoint:
            return self.get_entity_report_url(data["entityId"])

        if event_type == EVENT_NAME.TopTechnique:
            return self.get_technique_url(data["technique"])

        if event_type == EVENT_NAME.RiskScore:
            return self.get_dashboard_url()

        return ""

    def get_incident_type(self, event_type: str) -> str:
        if event_type == EVENT_NAME.TopTechnique:
            return XM_CYBER_INCIDENT_TYPE_TECHNIQUE
        if event_type == EVENT_NAME.AssetAtRisk:
            return XM_CYBER_INCIDENT_TYPE_ASSET
        if event_type == EVENT_NAME.ChokePoint:
            return XM_CYBER_INCIDENT_TYPE_CHOKE_POINT
        return XM_CYBER_INCIDENT_TYPE_SCORE

    def create_xm_event(
        self,
        name: str,
        additional_data_to_title: str,
        data: Dict[str, Any],
        date: Optional[datetime] = None,
    ) -> XmEventType:
        if self.date_created is not None:
            date = self.date_created
        if date is None:
            date = datetime.now()

        data["name"] = f"{EVENT_NAME.EventPrefix}{name} - {additional_data_to_title}"
        data["create_time"] = timestamp_to_datestring(date.timestamp() * 1000)
        data["type"] = self.get_incident_type(name)
        data["severity"] = SEVERITY.Low
        data["linkToReport"] = self.get_link_for_report(name, data)

        return data

    def _create_event_for_risk_score(
        self, xm_events: List[XmEventType], run_data: Dict[str, str]
    ):
        risk_score = self.risk_score()
        trend = risk_score["trend"]
        if self.ignore_trend or (trend is not None and trend != "" and trend < 0):
            score = risk_score["current_score"]
            name = f"risk_score_{score}"
            if should_create_xm_event(name, run_data):
                xm_events.append(
                    self.create_xm_event(
                        EVENT_NAME.RiskScore, risk_score["current_score"], risk_score
                    )
                )

    def _create_events_from_top_dashboard(
        self,
        xm_events: List[XmEventType],
        top_fetched_events: List[Dict[str, Any]],
        event_name: str,
        trend_negative: bool,
        run_data: Dict[str, str],
    ):
        for event in top_fetched_events:
            trend = event["trend"]
            if trend is None or trend == "":
                trend = 0
            else:
                trend = int(trend)

            if (
                self.ignore_trend
                or (trend_negative and trend < 0)
                or (not trend_negative and trend > 0)
            ):
                displayName = event["displayName"]
                name = f"{event_name}_{displayName}_{trend}"
                if should_create_xm_event(name, run_data):
                    xm_events.append(
                        self.create_xm_event(event_name, displayName, event)
                    )

    def _get_technique_best_practices_and_remediation(
        self, technique: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        advices = []
        remediations = self.get_technique_remediation(technique["technique"])
        for remediation in remediations:
            advices.append(
                {
                    "type": remediation["adviceTypeDisplayName"],
                    "text": remediation["displayName"],
                }
            )

        return advices

    def _create_events_from_top_techniques(
        self,
        xm_events: List[XmEventType],
        current_techniques: List[Dict[str, Any]],
        previous_techniques: List[Dict[str, Any]],
        run_data: Dict[str, str],
    ):
        for current_tech in current_techniques:
            previous_tech = None
            for previous_tech_iteratee in previous_techniques:
                if current_tech["technique"] == previous_tech_iteratee["technique"]:
                    previous_tech = previous_tech_iteratee
                    break

            criticalAssets = int(current_tech["criticalAssets"])
            if (
                self.ignore_trend
                or previous_tech is None
                or criticalAssets > int(previous_tech["criticalAssets"])
            ):
                current_tech[
                    "advices"
                ] = self._get_technique_best_practices_and_remediation(current_tech)
                critical_asset_trend = 0
                if previous_tech is not None:
                    critical_asset_trend = criticalAssets - int(
                        previous_tech["criticalAssets"]
                    )
                current_tech["criticalAssets_trend"] = critical_asset_trend

                display_name = current_tech["displayName"]
                name = f"{display_name}_{criticalAssets}"
                if should_create_xm_event(name, run_data):
                    xm_events.append(
                        self.create_xm_event(
                            EVENT_NAME.TopTechnique, display_name, current_tech
                        )
                    )

    def get_fetch_incidents_events(self, run_data: Dict[str, Any]):
        cortex_events: List = []

        writeLog("risk score")
        # risk score
        self._create_event_for_risk_score(cortex_events, run_data)

        writeLog("assets at risk")
        # top assets at risk

        self._create_events_from_top_dashboard(
            cortex_events,
            self.top_assets_at_risk(),
            EVENT_NAME.AssetAtRisk,
            True,
            run_data,
        )

        writeLog("choke point")
        # top choke points
        self._create_events_from_top_dashboard(
            cortex_events,
            self.top_choke_points(),
            EVENT_NAME.ChokePoint,
            False,
            run_data,
        )

        writeLog("top techniques")
        # top techniques
        current_techniques = self.get_techniques(DEFAULT_TIME_ID, TOP_ENTITIES, 1)
        previous_techniques = self.get_techniques(
            PREVIOUS_DEFAULT_TIME_ID, TOP_ENTITIES, 1
        )
        self._create_events_from_top_techniques(
            cortex_events, current_techniques, previous_techniques, run_data
        )

        return cortex_events


""" HELPER FUNCTIONS """


class LogLevel(enum.Enum):
    Debug = (0,)
    Info = (1,)
    Error = (2,)


def should_create_xm_event(name, run_data):
    if name not in run_data:
        run_data[name] = datetime.now().isoformat()
        return True
    return False


def is_seconds_diff_passed(date_in_iso, diff_in_seconds):
    now = datetime.now()
    start_time = datetime.fromisoformat(date_in_iso)
    diff = dates_diff_seconds(now, start_time)
    return diff > diff_in_seconds


def writeLog(msg, logLevel=LogLevel.Info):
    if logLevel == LogLevel.Debug:
        demisto.debug(msg)
    elif logLevel == LogLevel.Info or logLevel == LogLevel.Error:
        demisto.info(msg)


def create_client():
    params = demisto.params()
    api_key = params.get("apikey")
    base_url = urljoin(params["url"], "/api")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    headers = {"X-Api-Key": api_key, "Content-Type": "application/json; charset=utf-8"}
    return Client(
        base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
    )


def dates_diff_seconds(date1, date2):
    return (date1 - date2).total_seconds()


def path_to_compromising_technique(path: Any):
    return path[-1]["event"]["displayName"]


def entity_obj_to_data(xm: XM, entity: Dict[str, Any]) -> Dict[str, Any]:
    try:
        is_asset = entity["asset"]
    except KeyError:
        is_asset = False
    techniques = []
    for technique in entity["attackedByTechniques"]:
        techniques.append(
            {"name": technique["displayName"], "count": technique["count"]}
        )
    entity_id = entity["entityId"]
    entity_report = xm.get_entity_report_url(entity_id=entity_id)

    return {
        "id": entity_id,
        "name": entity["name"],
        "affectedEntities": entity["affectedUniqueEntities"]["count"]["value"],
        "averageComplexity": entity["attackComplexity"]["avg"]["value"],
        "averageComplexityLevel": entity["affectedUniqueAssets"]["count"]["level"],
        "criticalAssetsAtRisk": entity["affectedUniqueAssets"]["count"]["value"],
        "criticalAssetsAtRiskLevel": entity["affectedUniqueAssets"]["count"]["level"],
        "isAsset": is_asset,
        "compromisingTechniques": techniques,
        "type": entity["entityTypeDisplayName"],
        "report": entity_report,
        "OS": entity["os"]["name"]
        if entity["entityTypeDisplayName"] == "Sensor"
        else entity["entityTypeDisplayName"],
    }


def pretty_print_entity(entity: Dict[str, Any]):
    entityId = entity["id"]
    displayName = entity["name"]
    entityType = entity["type"]
    entityReport = entity["report"]
    pretty = "\n"
    pretty += "\n| Property | Value |"
    pretty += "\n| -- | -- |"
    pretty += f"\n| Entity Id | {entityId} |"
    pretty += f"\n| Display Name | {displayName} |"
    pretty += f"\n| Entity Type  | {entityType}  |"
    pretty += f"\n| Entity Report | [{displayName}]({entityReport}) |"
    return pretty


""" COMMAND FUNCTIONS """


def affected_critical_assets_list_command(
    xm: XM, args: Dict[str, Any]
) -> CommandResults:
    time_id = args.get("timeId")
    if not time_id:
        time_id = "timeAgo_days_7"
    entity_ids = argToList(args.get("entityId"))
    if len(entity_ids) == 0:
        raise ValueError("Entity ID(s) not specified")
    output = []
    readable_output = ""
    raw_json = {}
    for entity_id in entity_ids:
        affected_assets = xm.get_affected_assets(entity_id, time_id)
        raw_json[entity_id] = affected_assets
        affected_assets_list = []
        for asset in affected_assets:
            affected_assets_list.append(
                {
                    "name": asset["name"],
                    "average": asset["attackComplexity"],
                    "minimum": asset["minAttackComplexity"],
                }
            )
        output.append(
            {"id": entity_id, "criticalAssetsAtRiskList": affected_assets_list}
        )
        pretty = "\n"
        pretty += "\n| Asset Display Name | Average Complexity | Minimum Complexity"
        pretty += "\n| -- | -- | -- |"
        for i in range(0, min(len(affected_assets_list), 5)):
            pretty += "\n| {name} | {average} | {minimum}  |".format(
                **affected_assets_list[i]
            )
        readable_output += f"found {len(affected_assets)} affected critical assets from {entity_id}. Top 5:\n{pretty}\n"
    return CommandResults(
        outputs_prefix="XMCyber.Entity",
        outputs_key_field="id",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_json,
    )


def affected_entities_list_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get("timeId")
    if not time_id:
        time_id = "timeAgo_days_7"
    entity_ids = argToList(args.get("entityId"))
    if len(entity_ids) == 0:
        raise ValueError("Entity ID(s) not specified")
    output = []
    readable_output = ""
    raw_json = {}
    for entity_id in entity_ids:
        affected_entities = xm.get_affected_entities(entity_id, time_id)
        raw_json[entity_id] = affected_entities
        affected_entities_list = []
        for entity in affected_entities:
            affected_entities_list.append(
                {
                    "entityId": entity.get("entityId", ""),
                    "entityType": entity.get("entityData", {}).get(
                        "entityTypeDisplayName", ""
                    ),
                    "name": entity.get("name", ""),
                    "technique": entity.get("methodsArray", [{}])[0].get(
                        "methodName", ""
                    )
                    if entity.get("methodsArray")
                    else "",
                }
            )
        output.append({"id": entity_id, "entitiesAtRiskList": affected_entities_list})
        pretty = "\n"
        pretty += "\n| Display Name | Technique"
        pretty += "\n| -- | -- |"
        for i in range(0, min(len(affected_entities_list), 5)):
            pretty += "\n| {name} | {technique} |".format(**affected_entities_list[i])
        readable_output += f"found {len(affected_entities)} affected entities from {entity_id}. Top 5:\n{pretty}\n"
    return CommandResults(
        outputs_prefix="XMCyber.Entity",
        outputs_key_field="id",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_json,
    )


def _fetch_incidents_internal(
    xm: XM, args: Dict[str, Any], run_data: Dict[str, Any]
) -> List:
    events = []
    should_run = True

    if xm.is_fetch_incidents:
        if len(run_data) > 0 and not is_seconds_diff_passed(
            run_data["start_time"], FULL_INCIDENTS_SECONDS
        ):
            should_run = False

    if should_run or DEBUG_MODE:
        events = xm.get_fetch_incidents_events(run_data)

    writeLog(f"Found {len(events)} events")
    return events


# Fetch incidents
# This function runs every 3 seconds. In each run, we check if 24 hours passed since the last ran. If not, we just exit
# Otherwise, we fetch 4 type of XM's incidents (Security score, Assets at risk, Choke points and techniques)
# Each incident can be created only one time in each week (in order to avoid spamming the incidents page)
def fetch_incidents_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    run_data = demisto.getLastRun()
    keys_to_delete = []
    # Clean the dict key with old values
    for key in run_data.keys():
        if key == "start_time" or key == "lastRun":
            continue
        if is_seconds_diff_passed(run_data[key], ONE_WEEK_IN_SECONDS):
            keys_to_delete.append(key)

    for key_to_delete in keys_to_delete:
        del run_data[key_to_delete]

    events = _fetch_incidents_internal(xm, args, run_data)

    if xm.is_fetch_incidents:
        incidents = []
        for event in events:
            incident = {
                "name": event["name"],
                "occurred": event["create_time"],
                "rawJson": json.dumps(event),
                "type": event["type"],
                "rawType": event["type"],
                "severity": event["severity"],
            }
            incidents.append(incident)

        writeLog(f"Finish incidents: {len(incidents)}")
        if len(incidents) > 0:
            run_data["start_time"] = datetime.now().isoformat()
            demisto.setLastRun(run_data)

        demisto.incidents(incidents)

    return CommandResults(
        outputs_prefix="XMCyber", outputs_key_field="entityId", outputs=events
    )


def get_version_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    return CommandResults(
        outputs_prefix="XMCyber.Version",
        outputs_key_field="entityId",
        outputs=xm.get_version(),
    )


def is_xm_version_supported_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    version = xm.get_version()
    system_version = version["system"]
    system_version_splitted = system_version.split(".")
    major = int(system_version_splitted[0])
    minor = int(system_version_splitted[1])
    result = {"valid": major >= (MIN_MAJOR_VERSION + 1) or minor >= MIN_MINOR_VERSION}
    return CommandResults(
        outputs_prefix="XMCyber.IsVersion", outputs_key_field="entityId", outputs=result
    )


def update_command_results(
    xm: XM,
    command_results: List[CommandResults],
    xm_data_list: List[Dict[str, Any]],
    readable_output,
    entity: Dict[str, Any],
):
    id_ = entity.get("entityId")
    try:
        ip = entity.get("ipv4Str", "")
        domain = (
            entity.get("customProperties", {})
            .get("domainWorkgroup", {})
            .get("data", "")
        )
        os = entity.get("os", {}).get("type", "")
        os_version = entity.get("os", {}).get("name", "")
        hostname = entity.get("displayName", "")
        endpoint_standard_context = Common.Endpoint(
            id_,
            ip_address=ip,
            domain=domain,
            os=os,
            os_version=os_version,
            hostname=hostname,
        )
    except (TypeError, AttributeError, KeyError):
        endpoint_standard_context = Common.Endpoint(id_)
    command_results.append(
        CommandResults(
            indicator=endpoint_standard_context,
            readable_output=f"Fetched Endpoint {id_} info",
            raw_response=entity,
        )
    )
    entity_data = entity_obj_to_data(xm, entity)
    readable_output += pretty_print_entity(entity_data)
    xm_data_list.append(entity_data)
    return readable_output


def _enrich_from_field(
    xm: XM, field_name: str, field_values: List[str]
) -> List[CommandResults]:
    # Context standard for IP class
    command_results: List[CommandResults] = []
    xm_data_list: List[Dict[str, Any]] = []
    readable_output = ""

    for value in field_values:
        entities = xm.search_entities(field_name_to_value={field_name: value})
        if len(entities) > 0:
            readable_output = (
                f"**Matched the following entities for {field_name} {value}**"
            )
        else:
            readable_output = f"**No entity matches {field_name} {value}"
        for entity in entities:
            readable_output = update_command_results(
                xm, command_results, xm_data_list, readable_output, entity
            )

    # add general hr and output to the begining of result
    command_results.insert(
        0,
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="XMCyber.Entity",
            outputs_key_field="id",
            outputs=xm_data_list,
            raw_response=entities,
        ),
    )

    return command_results


def _enrich_from_multiple_fields(xm: XM, field_name_to_value: Dict[str, Any]):
    command_results: List[CommandResults] = []
    xm_data_list: List[Dict[str, Any]] = []
    entities = xm.search_entities(field_name_to_value=field_name_to_value)
    if len(entities) > 0:
        readable_output = (
            f"**Matched the following entities for {field_name_to_value}**"
        )
        for entity in entities:
            readable_output = update_command_results(
                xm, command_results, xm_data_list, readable_output, entity
            )
    else:
        readable_output = f"**No entity matches {field_name_to_value}**"

    command_results.insert(
        0,
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="XMCyber.Entity",
            outputs_key_field="id",
            outputs=xm_data_list,
            raw_response=entities,
        ),
    )

    return command_results


def enrich_from_entity_id(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    entity_ids = argToList(args.get("entityId"))
    if len(entity_ids) == 0:
        raise ValueError("EntityId(s) not specified")

    return _enrich_from_field(xm=xm, field_name="entityId", field_values=entity_ids)


def enrich_entity_from_fields(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    field_names = argToList(args.get("fields"))
    field_values = argToList(args.get("values"))
    if not field_names or not field_values or len(field_names) != len(field_values):
        raise ValueError("Invalid input")

    return _enrich_from_multiple_fields(
        xm=xm, field_name_to_value=dict(zip(field_names, field_values))
    )


def enrich_from_hostname(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    hostnames = argToList(args.get("hostname"))
    if len(hostnames) == 0:
        raise ValueError("Hostname(s) not specified")

    return _enrich_from_field(xm=xm, field_name="name", field_values=hostnames)


def enrich_from_ip(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    ips = argToList(args.get("ip"))
    if len(ips) == 0:
        raise ValueError("IP(s) not specified")

    return _enrich_from_field(xm=xm, field_name="ipv4Str", field_values=ips)


def test_module_command_internal(xm: XM, args: Dict[str, Any]) -> CommandResults:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        version = xm.get_version()
        system_version = version["system"]
        s_version = system_version.split(".")
        major = int(s_version[0])
        minor = int(s_version[1])
        if major < 1 or (major == MIN_MAJOR_VERSION and minor < MIN_MINOR_VERSION):
            raise Exception(
                f"Instance version not compatible. {system_version} (found) < {MIN_MAJOR_VERSION}.{MIN_MINOR_VERSION} (required)."
            )

    except DemistoException as e:
        if "Forbidden" in str(e):
            raise Exception(
                "Authorization Error: make sure API Key is correct and has Security Analyst role"
            )
        else:
            raise e
    except Exception as e:
        raise Exception(f"Verification Error: could not load XM Cyber version.\n{e}")
    return CommandResults(
        outputs_prefix="ok", outputs_key_field="ok", outputs="ok", readable_output="ok"
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    command = demisto.command()
    args = demisto.args()
    demisto.info(f"Command running: {demisto.command()}")

    try:
        client = create_client()
        xm = XM(client)

        # commands dict
        # key - command key
        # value - command execution function that get two params:
        #         1) XM object
        #         2) args dict
        #         return value - CommandResults
        commandsDict = {
            "test-module": test_module_command_internal,  # This is the call made when pressing the integration Test button.
            "xmcyber-f-incidents": fetch_incidents_command,  # for debugging of fetch incidents
            # XM Cyber Command list
            # xmcyber-command-name: function_command
            "xmcyber-version-get": get_version_command,
            "xmcyber-version-supported": is_xm_version_supported_command,
            "xmcyber-affected-critical-assets-list": affected_critical_assets_list_command,
            "xmcyber-affected-entities-list": affected_entities_list_command,
            # Common commands
            "xmcyber-enrich-from-ip": enrich_from_ip,
            "xmcyber-enrich-from-hostname": enrich_from_hostname,
            "xmcyber-enrich-from-entityId": enrich_from_entity_id,
            "xmcyber-enrich-from-fields": enrich_entity_from_fields,
        }

        if command == "fetch-incidents":
            xm.is_fetch_incidents = True
            fetch_incidents_command(xm, args)
        elif command in commandsDict:
            return_results(commandsDict[command](xm, args))
        else:
            raise Exception("Unsupported command: " + command)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}\n"
            f"Traceback:\n{traceback.format_exc()}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
