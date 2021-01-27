import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, List
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
MIN_MINOR_VERSION = 38
FULL_INCIDENTS_SECONDS = 60 if DEBUG_MODE else 86400
ONE_WEEK_IN_SECONDS = 1 if DEBUG_MODE else 604800

DEFAULT_TIME_ID = 'timeAgo_days_7'
PREVIOUS_DEFAULT_TIME_ID = 'timeAgo_days_7'
XM_CYBER_INCIDENT_TYPE_SCORE = 'XM Cyber Security Score'
XM_CYBER_INCIDENT_TYPE_TECHNIQUE = 'XM Cyber Technique'
XM_CYBER_INCIDENT_TYPE_ASSET = 'XM Cyber Critical Asset'
XM_CYBER_INCIDENT_TYPE_CHOKE_POINT = 'XM Cyber Choke Point'
TOP_ENTITIES = 3
PAGE_SIZE = 50
MAX_PAGES = 10
SENSOR_TYPE = "Sensor"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with XM Cyber API"""

    def get(self, url_suffix, params=None):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )

    def post(self, url_suffix, params=None):
        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            data=json.dumps(params)
        )

    def _paginated(self, method, url_suffix, params, page_size, max_pages, log):
        page, total_pages = 1, 1
        data = []
        params["pageSize"] = page_size
        while page <= total_pages and page <= max_pages:
            if log:
                writeLog(f'in {url_suffix} while loop {page} {total_pages}')

            params["page"] = page
            res = None
            if method == 'GET':
                res = self.get(url_suffix, params)
            else:
                res = self.post(url_suffix, params)

            data.extend(res['data'])
            total_pages = res['paging']['totalPages']
            page += 1

        return data

    def get_paginated(self, url_suffix, params={}, page_size=PAGE_SIZE, max_pages=MAX_PAGES, log=True):
        return self._paginated("GET", url_suffix, params, page_size, max_pages, log)

    def post_paginated(self, url_suffix, params={}, page_size=PAGE_SIZE, max_pages=MAX_PAGES, log=True):
        return self._paginated("POST", url_suffix, params, page_size, max_pages, log)

    def get_base_url(self):
        return self._base_url


class URLS:
    Version = '/version'
    Entities = '/systemReport/entities'
    Risk_Score = '/systemReport/riskScoreV2'
    Top_Assets_At_Risk = '/systemReport/topAssetsAtRiskV2'
    Top_Choke_Points = '/systemReport/topChokePointsV2'
    Inbound = '/systemReport/entity/inbound'
    Outbound = '/systemReport/entity/outbound'
    System_Report = '/systemReport/entity'
    Techniques = '/systemReport/techniques'
    Assets_At_Risk = '/systemReport/assetsAtRiskByEntity'
    Entities_At_Risk = '/systemReport/affectedEntitiesByEntity'
    Entity_Report = '/#/scenarioHub/entityReport'


class EVENT_NAME:
    EventPrefix = 'XM '
    RiskScore = 'Security score'
    AssetAtRisk = 'Asset at risk'
    ChokePoint = 'Choke point'
    TopTechnique = 'Top technique'


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

    # The function return risk score data for the given timeId
    # return dict:
    #   trend - trend from previous time id
    #   current_grade - current risk score grade (A-F)
    #   current_score - current risk score (0-100)

    def risk_score(self, time_id=DEFAULT_TIME_ID, resolution=1):
        risk_score_response = self.client.get(URLS.Risk_Score, {
            'timeId': time_id,
            'resolution': resolution
        })

        risk_score_stats = risk_score_response["data"]["stats"]

        return {
            "trend": risk_score_stats["trend"],
            "current_grade": risk_score_stats["grade"],
            "current_score": risk_score_stats["score"]
        }

    # This general function return data regarding the entities at a specific timeId
    # Params:
    #   only_assets - return only assets
    # return:
    #   list of entities
    def get_entities(self, time_id, only_assets):
        filterObj = {}
        if only_assets:
            filterObj['asset'] = True

        query = {
            'timeId': time_id,
            'filter': filterObj
        }
        return self.client.post_paginated(URLS.Entities, query)

    def _top_entities(self, url, time_id, amount_of_results):
        response = self.client.get(url, {
            'timeId': time_id,
            'amountOfResults': amount_of_results
        })

        return response["data"]["entities"]

    def top_assets_at_risk(self, time_id=DEFAULT_TIME_ID, amount_of_results=TOP_ENTITIES):
        return self._top_entities(URLS.Top_Assets_At_Risk, time_id, amount_of_results)

    def top_choke_points(self, time_id=DEFAULT_TIME_ID, amount_of_results=TOP_ENTITIES):
        return self._top_entities(URLS.Top_Choke_Points, time_id, amount_of_results)

    def get_inbound_paths(self, entity_id: str, time_id: str):
        return self.client.get(URLS.Inbound, {
            'entityId': entity_id,
            'timeId': time_id
        })

    def get_outbound_paths(self, entity_id: str, time_id):
        return self.client.get(URLS.Outbound, {
            'entityId': entity_id,
            'timeId': time_id
        })

    def get_affected_assets(self, entity_id: str, time_id=DEFAULT_TIME_ID, page_size=PAGE_SIZE, max_pages=MAX_PAGES):
        return self.client.get_paginated(URLS.Assets_At_Risk, {
            'entityId': entity_id,
            'timeId': time_id,
            'sort': 'attackComplexity'
        }, page_size, max_pages)

    def get_affected_entities(self, entity_id: str, time_id=DEFAULT_TIME_ID, page_size=PAGE_SIZE, max_pages=MAX_PAGES):
        return self.client.get_paginated(URLS.Entities_At_Risk, {
            'entityId': entity_id,
            'timeId': time_id,
            'sort': 'attackComplexity'
        }, page_size, max_pages)

    def search_entities(self, search_string):
        return self.client.get_paginated(URLS.Entities, {
            'search': f'/^{search_string}$/i'
        })

    def get_techniques(self, time_id=DEFAULT_TIME_ID, page_size=None, max_pages=None):
        return self.client.get_paginated(URLS.Techniques, {
            'timeId': time_id
        }, page_size, max_pages)

    def get_technique_remediation(self, technique, time_id=DEFAULT_TIME_ID):
        return self.client.get(f"{URLS.Techniques}/{technique}/remediation", {
            'timeId': time_id
        })

    def get_entity_report(self, entity_id: str, time_id: str):
        return self.client.get(URLS.System_Report, {
            'entityId': entity_id,
            'timeId': time_id
        })

    def get_base_url(self):
        return self.client.get_base_url()

    def _get_base_url_without_api(self):
        best_url = self.get_base_url()
        return best_url.replace('/api', '')

    def get_entity_report_url(self, entityId, timeId=DEFAULT_TIME_ID):
        return f"{self._get_base_url_without_api()}/systemReport/entity?entityId={entityId}&timeId={timeId}"

    def get_dashboard_url(self):
        return f"{self._get_base_url_without_api()}/#/dashboard"

    def get_technique_url(self, technique, timeId=DEFAULT_TIME_ID):
        return f"{self._get_base_url_without_api()}/#/scenarioHub/systemReport/attackTechniques/{technique}?timeId={timeId}"

    def get_link_for_report(self, event_type, data):
        if event_type == EVENT_NAME.AssetAtRisk or event_type == EVENT_NAME.ChokePoint:
            return self.get_entity_report_url(data["entityId"])

        if event_type == EVENT_NAME.TopTechnique:
            return self.get_technique_url(data["technique"])

        if event_type == EVENT_NAME.RiskScore:
            return self.get_dashboard_url()

        return ''

    def get_incident_type(self, event_type):
        if event_type == EVENT_NAME.TopTechnique:
            return XM_CYBER_INCIDENT_TYPE_TECHNIQUE
        if event_type == EVENT_NAME.AssetAtRisk:
            return XM_CYBER_INCIDENT_TYPE_ASSET
        if event_type == EVENT_NAME.ChokePoint:
            return XM_CYBER_INCIDENT_TYPE_CHOKE_POINT
        return XM_CYBER_INCIDENT_TYPE_SCORE

    def create_xm_event(self, name, additional_data_to_title, data, date=None):
        if self.date_created is not None:
            date = self.date_created
        if date is None:
            date = datetime.now()

        data["name"] = f'{EVENT_NAME.EventPrefix}{name} - {additional_data_to_title}'
        data["create_time"] = timestamp_to_datestring(date.timestamp() * 1000)
        data["type"] = self.get_incident_type(name)
        data["severity"] = SEVERITY.Low
        data["linkToReport"] = self.get_link_for_report(name, data)

        return data

    def _create_event_for_risk_score(self, events, run_data):
        risk_score = self.risk_score()
        trend = risk_score["trend"]
        if self.ignore_trend or (trend is not None and trend != '' and trend < 0):
            score = risk_score["current_score"]
            name = f"risk_score_{score}"
            if should_create_xm_event(name, run_data):
                events.append(self.create_xm_event(EVENT_NAME.RiskScore, risk_score["current_score"], risk_score))

    def _create_events_from_top_dashboard(self, events_array, top_list, event_name, trend_negative, run_data):
        for top in top_list:
            trend = top["trend"]
            if trend is None or trend == '':
                trend = 0
            else:
                trend = int(trend)

            if self.ignore_trend or (trend_negative and trend < 0) or (not trend_negative and trend > 0):
                displayName = top["displayName"]
                name = f"{event_name}_{displayName}_{trend}"
                if should_create_xm_event(name, run_data):
                    events_array.append(self.create_xm_event(event_name, displayName, top))

    def _get_technique_best_practices_and_remediation(self, technique):
        advices = []
        remediationArr = self.get_technique_remediation(technique["technique"])
        for remediation in remediationArr:
            advices.append({
                'type': remediation["adviceTypeDisplayName"],
                'text': remediation["displayName"]
            })

        return advices

    def _create_events_from_top_techniques(self, events_array, current_techniques, previous_techniques, run_data):
        for current_tech in current_techniques:
            previous_tech = None
            for previous_tech_iteratee in previous_techniques:
                if current_tech["technique"] == previous_tech_iteratee["technique"]:
                    previous_tech = previous_tech_iteratee
                    break

            criticalAssets = int(current_tech["criticalAssets"])
            if self.ignore_trend or previous_tech is None or criticalAssets > int(previous_tech["criticalAssets"]):
                current_tech["advices"] = self._get_technique_best_practices_and_remediation(current_tech)
                critical_asset_trend = 0
                if previous_tech is not None:
                    critical_asset_trend = criticalAssets - int(previous_tech["criticalAssets"])
                current_tech["criticalAssets_trend"] = critical_asset_trend

                display_name = current_tech["displayName"]
                name = f"{display_name}_{criticalAssets}"
                if should_create_xm_event(name, run_data):
                    events_array.append(self.create_xm_event(EVENT_NAME.TopTechnique, display_name, current_tech))

    def get_fetch_incidents_events(self, run_data: Dict[str, Any]):
        events: List = []

        writeLog("risk score")
        # risk score
        self._create_event_for_risk_score(events, run_data)

        writeLog("assets at risk")
        # top assets at risk
        self._create_events_from_top_dashboard(events, self.top_assets_at_risk(), EVENT_NAME.AssetAtRisk, True, run_data)

        writeLog("choke point")
        # top choke points
        self._create_events_from_top_dashboard(events, self.top_choke_points(), EVENT_NAME.ChokePoint, False, run_data)

        writeLog("top techniques")
        # top techniques
        current_techniques = self.get_techniques(DEFAULT_TIME_ID, TOP_ENTITIES, 1)
        previous_techniques = self.get_techniques(PREVIOUS_DEFAULT_TIME_ID, TOP_ENTITIES, 1)
        self._create_events_from_top_techniques(events, current_techniques, previous_techniques, run_data)

        return events


''' HELPER FUNCTIONS '''


class LogLevel(enum.Enum):
    Debug = 0,
    Info = 1,
    Error = 2,


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
        demisto.info(f'NNNNNN2 {msg}')


def create_client():
    api_key = demisto.params().get('apikey')

    base_url = urljoin(demisto.params()['url'], '/api')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {
        'X-Api-Key': api_key,
        'Content-Type': 'application/json; charset=utf-8'
    }

    return Client(
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        proxy=proxy)


def dates_diff_seconds(date1, date2):
    return (date1 - date2).total_seconds()


def path_to_compromising_technique(path: Any):
    return path[-1]['event']['displayName']


def entity_obj_to_data(xm: XM, entity: Any):
    try:
        is_asset = entity['asset']
    except KeyError:
        is_asset = False
    techniques = []
    for technique in entity['attackedByTechniques']:
        techniques.append({
            'name': technique['displayName'],
            'count': technique['count']
        })
    entity_id = entity['entityId']
    instance_url = xm.get_base_url()[0:-4]
    entity_report = urljoin(instance_url, f'{URLS.Entity_Report}/{entity_id}?timeId={DEFAULT_TIME_ID}')
    return {
        'id': entity['entityId'],
        'name': entity['name'],
        'affectedEntities': entity['affectedUniqueEntities']['count']['value'],
        'averageComplexity': entity['attackComplexity']['avg']['value'],
        'averageComplexityLevel': entity['affectedUniqueAssets']['count']['level'],
        'criticalAssetsAtRisk': entity['affectedUniqueAssets']['count']['value'],
        'criticalAssetsAtRiskLevel': entity['affectedUniqueAssets']['count']['level'],
        'isAsset': is_asset,
        'compromisingTechniques': techniques,
        'type': entity['entityTypeDisplayName'],
        'report': entity_report,
        'OS': entity['os']['name'] if entity['entityTypeDisplayName'] == 'Sensor' else entity['entityTypeDisplayName']
    }


def entity_score(entity: Any):
    score = 0
    try:
        reputation = entity['affectedUniqueAssets']['count']['level']
        if reputation == 'none':
            score = Common.DBotScore.GOOD
        else:
            score = Common.DBotScore.BAD
    except (KeyError, AttributeError):
        reputation = 'N/A'
        score = Common.DBotScore.NONE
    return score, reputation


def pretty_print_entity(entity: Any):
    entityId = entity['id']
    displayName = entity['name']
    entityType = entity['type']
    entityReport = entity['report']
    pretty = '\n'
    pretty += '\n| Property | Value |'
    pretty += '\n| -- | -- |'
    pretty += f'\n| Entity Id | {entityId} |'
    pretty += f'\n| Display Name | {displayName} |'
    pretty += f'\n| Entity Type  | {entityType}  |'
    pretty += f'\n| Entity Report | [{displayName}]({entityReport}) |'
    return pretty


''' COMMAND FUNCTIONS '''


def affected_critical_assets_list_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('timeId')
    if not time_id:
        time_id = 'timeAgo_days_7'
    entity_ids = argToList(args.get('entityId'))
    if len(entity_ids) == 0:
        raise ValueError('Entity ID(s) not specified')
    output = []
    readable_output = ''
    raw_json = {}
    for entity_id in entity_ids:
        affected_assets = xm.get_affected_assets(entity_id, time_id)
        raw_json[entity_id] = affected_assets
        affected_assets_list = []
        for asset in affected_assets:
            affected_assets_list.append({
                'name': asset['name'],
                'average': asset['attackComplexity'],
                'minimum': asset['minAttackComplexity']
            })
        output.append({
            'id': entity_id,
            'criticalAssetsAtRiskList': affected_assets_list
        })
        pretty = '\n'
        pretty += '\n| Asset Display Name | Average Complexity | Minimum Complexity'
        pretty += '\n| -- | -- | -- |'
        for i in range(0, min(len(affected_assets_list), 5)):
            pretty += '\n| {name} | {average} | {minimum}  |'.format(**affected_assets_list[i])
        readable_output += f'found {len(affected_assets)} affected critical assets from {entity_id}. Top 5:\n{pretty}\n'
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='id',
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_json
    )


def affected_entities_list_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('timeId')
    if not time_id:
        time_id = 'timeAgo_days_7'
    entity_ids = argToList(args.get('entityId'))
    if len(entity_ids) == 0:
        raise ValueError('Entity ID(s) not specified')
    output = []
    readable_output = ''
    raw_json = {}
    for entity_id in entity_ids:
        affected_entities = xm.get_affected_entities(entity_id, time_id)
        raw_json[entity_id] = affected_entities
        affected_entities_list = []
        for entity in affected_entities:
            affected_entities_list.append({
                # 'entityId': entity['entityId'],
                # 'entityType': entity['entityData']['entityTypeDisplayName'],
                'name': entity['name'],
                'technique': entity['methodsArray'][0]['methodName']
            })
        output.append({
            'id': entity_id,
            'entitiesAtRiskList': affected_entities_list
        })
        pretty = '\n'
        pretty += '\n| Display Name | Technique'
        pretty += '\n| -- | -- |'
        for i in range(0, min(len(affected_entities_list), 5)):
            pretty += '\n| {name} | {technique} |'.format(**affected_entities_list[i])
        readable_output += f'found {len(affected_entities)} affected entities from {entity_id}. Top 5:\n{pretty}\n'
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='id',
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_json
    )


def _fetch_incidents_internal(xm: XM, args: Dict[str, Any], run_data: Dict[str, Any]) -> List:
    events = []
    should_run = True

    if xm.is_fetch_incidents:
        if len(run_data) > 0 and not is_seconds_diff_passed(run_data["start_time"], FULL_INCIDENTS_SECONDS):
            should_run = False

    if should_run or DEBUG_MODE:
        events = xm.get_fetch_incidents_events(run_data)

    writeLog(f'Found {len(events)} events')
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
                'name': event['name'],
                'occurred': event['create_time'],
                'rawJson': json.dumps(event),
                'type': event['type'],
                'rawType': event['type'],
                'severity': event["severity"]
            }
            incidents.append(incident)

        writeLog(f'Finish incidents: {len(incidents)}')
        if len(incidents) > 0:
            run_data['start_time'] = datetime.now().isoformat()
            demisto.setLastRun(run_data)

        demisto.incidents(incidents)

    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='entityId',
        outputs=events
    )


def get_version_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    return CommandResults(
        outputs_prefix='XMCyber.Version',
        outputs_key_field='entityId',
        outputs=xm.get_version()
    )


def is_xm_version_supported_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    version = xm.get_version()
    system_version = version["system"]
    system_version_splitted = system_version.split('.')
    major = int(system_version_splitted[0])
    minor = int(system_version_splitted[1])
    result = {'valid': major >= (MIN_MAJOR_VERSION + 1) or minor >= MIN_MINOR_VERSION}
    return CommandResults(
        outputs_prefix='XMCyber.IsVersion',
        outputs_key_field="entityId",
        outputs=result
    )


def ip_command(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    # Context standard for IP class
    command_results: List[CommandResults] = []
    xm_data_list = []  #: List[Dict[str, Any]] = []
    readable_output = ''
    entity_ids: List[Any] = []

    for ip in ips:
        try:
            entity_ids = xm.search_entities(ip['Address'])
        except (AttributeError, TypeError):
            entity_ids = xm.search_entities(ip)
        if len(entity_ids) > 0:
            readable_output = f'**Resolved the following entities for IP {ip}**\n'
        else:
            readable_output = f'**No entity with the IP {ip}'
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name='XMCyber',
                score=Common.DBotScore.NONE,
                malicious_description='No entity found with this IP'
            )
            ip_standard_context = Common.IP(
                ip=ip,
                dbot_score=dbot_score
            )
            command_results.append(CommandResults(
                indicator=ip_standard_context,
                readable_output=f'No entity found for {ip}'
            ))
        for entity in entity_ids:
            score, reputation = entity_score(entity)
            entity_data = entity_obj_to_data(xm, entity)
            criticalAssetsAtRisk = entity_data['criticalAssetsAtRisk']
            if score == Common.DBotScore.BAD:
                readable_output += f'**Bad dbot score given because {ip} risks {criticalAssetsAtRisk} ("{reputation}")\
                    critical assets**\n'
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name='XMCyber',
                score=score,
                malicious_description=f'{ip} is reported to risk {criticalAssetsAtRisk} ("{reputation}") critical assets'
            )
            readable_output += pretty_print_entity(entity_data)
            xm_data_list.append(entity_data)
            ip_standard_context = Common.IP(
                ip=ip,
                dbot_score=dbot_score
            )
            command_results.append(CommandResults(
                indicator=ip_standard_context,
                readable_output=f'Fetched IP {ip} info',
                raw_response=entity_data
            ))

            # TODO return also endpoint
            if entity_data['type'] == SENSOR_TYPE:
                endpoint_standard_context = Common.Endpoint(
                    entity_data['id'],
                    ip_address=ip,
                    hostname=entity_data['name'],
                    os=entity_data['OS']
                )
                command_results.append(CommandResults(
                    indicator=endpoint_standard_context,
                    readable_output=f'Fetched Endpoint for {ip} info',
                    raw_response=entity_data
                ))

    # add general hr and output to the beginning of result
    command_results.insert(0, CommandResults(
        readable_output=readable_output,
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='id',
        outputs=xm_data_list,
        raw_response=entity_ids
    ))

    return command_results


def hostname_command(xm: XM, args: Dict[str, Any]) -> List[CommandResults]:
    hostnames = argToList(args.get('hostname'))
    if len(hostnames) == 0:
        raise ValueError('Endpoint(s) not specified')

    # Context standard for IP class
    command_results: List[CommandResults] = []
    xm_data_list: List[Dict[str, Any]] = []

    for hostname in hostnames:
        res = xm.search_entities(hostname)
        if len(res) > 0:
            readable_output = f'**Matched the following entities for hostname {hostname}**'
        else:
            readable_output = f'**No entity matches hostname {hostname}'
        for entity in res:
            ID = entity['entityId']
            try:
                ip = entity['ipv4Str']
                domain = entity['customProperties']['domainWorkgroup']['data']
                OS = entity['os']['type']
                os_version = entity['os']['name']
                endpoint_standard_context = Common.Endpoint(ID,
                                                            hostname=hostname,
                                                            ip_address=ip,
                                                            domain=domain,
                                                            os=OS,
                                                            os_version=os_version
                                                            )
            except (TypeError, AttributeError, KeyError):
                endpoint_standard_context = Common.Endpoint(ID, hostname=hostname)
            command_results.append(CommandResults(
                indicator=endpoint_standard_context,
                readable_output=f'Fetched Endpoint {hostname} info',
                raw_response=entity
            ))
            entity_data = entity_obj_to_data(xm, entity)
            readable_output += pretty_print_entity(entity_data)
            xm_data_list.append(entity_data)

    # add general hr and output to the begining of result
    command_results.insert(0, CommandResults(
        readable_output=readable_output,
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='id',
        outputs=xm_data_list,
    ))

    return command_results


def test_module_command_internal(xm: XM, args: Dict[str, Any]) -> CommandResults:
    #     """Tests API connectivity and authentication'

    #     Returning 'ok' indicates that the integration works like it is supposed to.
    #     Connection to the service is successful.
    #     Raises exceptions if something goes wrong.

    #     :type client: ``Client``

    #     :return: 'ok' if test passed, anything else will fail the test.
    #     :rtype: ``str``
    #     """

    try:
        version = xm.get_version()
        system_version = version['system']
        s_version = system_version.split('.')
        major = int(s_version[0])
        minor = int(s_version[1])
        if major < 1 or (major == 1 and minor < 37):
            raise Exception(f'Instance version not compatible. {system_version} (found) < 1.37 (required).')

    except DemistoException as e:
        if 'Forbidden' in str(e):
            raise Exception('Authorization Error: make sure API Key is correct and has Security Analyst role')
        else:
            raise e
    except Exception as e:
        raise Exception(f'Verification Error: could not load XM Cyber version.\n{e}')
    return CommandResults(
        outputs_prefix='ok',
        outputs_key_field='ok',
        outputs='ok',
        readable_output='ok'
    )


''' MAIN FUNCTION '''


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
    demisto.info(f'Command running: {demisto.command()}')

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
            "ip": ip_command,
            "xmcyber-hostname": hostname_command
        }

        if command == 'fetch-incidents':
            xm.is_fetch_incidents = True
            fetch_incidents_command(xm, args)
        elif command in commandsDict:
            return_results(commandsDict[command](xm, args))
        else:
            raise Exception("Unsupported command: " + command)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}\n'
                     f'Traceback:\n{traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
