import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, List, Optional, Union

import json
import urllib3
import dateparser
import traceback
import enum

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

# Minimum supported version is:  1.38
MIN_MAJOR_VERSION = 1
MIN_MINOR_VERSION = 38

BREACHPOINT_LABEL = 'Demisto Breachpoint'
CRITICAL_ASSET_LABEL = 'Demisto Critical Asset'
DEFAULT_TIME_ID = 'timeAgo_days_7'
TOP_ENTITIES = 5
PAGE_SIZE = 50
MAX_PAGES = 10

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


class XM:

    def __init__(self, client: Client):
        self.client = client

    def get_version(self):
        return self.client.get(URLS.Version)

    # The function return risk score data for the given timeId
    # return dict:
    #   trend - trend from previous time id
    #   current_grade - current risk score grade (A-F)
    #   current_score - current risk score (0-100)

    def risk_score(self, time_id, resolution):
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

    def top_assets_at_risk(self, time_id, amount_of_results=TOP_ENTITIES):
        return self._top_entities(URLS.Top_Assets_At_Risk, time_id, amount_of_results)

    def top_choke_points(self, time_id, amount_of_results=TOP_ENTITIES):
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

    def get_entities_by_label(self, label: str):
        # is this the right API?
        # /discoveryRules/matchingSensors/getMatchingSensors
        raise NotImplementedError(label)

    def unlabel_entities(self, entities: List[str], label: str):
        # api does not exist
        raise NotImplementedError(entities, label)

    def label_entities(self, entities: List[str], label: str):
        # api does not exist
        raise NotImplementedError(entities, label)

    def search_entities(self, search_string):
        return self.client.get_paginated(URLS.Entities, {
            'search': f'/{search_string}/i'
        })

    def get_top_techniques(self, time_id):
        return self.client.get_paginated(URLS.Techniques, {
            'timeId': time_id
        })

    def lookup_entities_by_ip(self, ips):
        raise NotImplementedError(ips)

    def get_entity_report(self, entity_id: str, time_id: str):
        return self.client.get(URLS.System_Report, {
            'entityId': entity_id,
            'timeId': time_id
        })


''' HELPER FUNCTIONS '''


class LogLevel(enum.Enum):
    Debug = 0,
    Info = 1,
    Error = 2,


def writeLog(msg, logLevel=LogLevel.Info):
    if logLevel == LogLevel.Debug:
        demisto.debug(msg)
    elif logLevel == LogLevel.Info or logLevel == LogLevel.Error:
        demisto.info(msg)


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


''' COMMAND FUNCTIONS '''


def asset_attack_path_list_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = DEFAULT_TIME_ID
    critical_assets = xm.get_entities(time_id, True)
    attack_paths = []
    for critical_asset in critical_assets:
        paths = xm.get_inbound_paths(critical_asset['entityId'], time_id)
        for path in paths:
            attack_paths.append(path)
    readable_output = 'loaded list of {0} asset attack paths'.format(len(attack_paths))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        readable_output=readable_output
    )


def techniques_list_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    techniques = xm.get_top_techniques(time_id)
    readable_output = f'loaded list of {len(techniques)} top techniques'
    return CommandResults(
        outputs_prefix='XMCyber.Technique',
        outputs_key_field='technique',
        outputs=techniques,
        readable_output=readable_output
    )


def breachpoint_update_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = xm.lookup_entities_by_ip(ips)
    xm.label_entities(entities, BREACHPOINT_LABEL)
    labeled_entities = xm.get_entities_by_label(BREACHPOINT_LABEL)
    readable_output = 'The {0} has been updated, there are {1} labeled entities'.format(
        BREACHPOINT_LABEL, len(labeled_entities))
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='entityId',
        outputs=labeled_entities,
        readable_output=readable_output
    )


def critical_asset_add_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = xm.lookup_entities_by_ip(ips)
    xm.label_entities(entities, CRITICAL_ASSET_LABEL)
    labeled_entities = xm.get_entities_by_label(CRITICAL_ASSET_LABEL)
    readable_output = f'The {CRITICAL_ASSET_LABEL} has been updated, there are {len(labeled_entities)} labeled entities'
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='entityId',
        outputs=labeled_entities,
        readable_output=readable_output
    )


def attack_paths_to_entity_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = xm.lookup_entities_by_ip(ips[0])
    attack_paths = []
    for entity in entities:
        paths = xm.get_inbound_paths(entity['agentId'], time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'found {0} attack paths to {1} entities'.format(len(attack_paths), len(entities))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        readable_output=readable_output,

    )


def attack_complexity_to_ip_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    try:
        address = ips[0]['Address']
    except (AttributeError, TypeError):
        address = ips[0]
    entities = xm.lookup_entities_by_ip(address)
    if len(entities) == 0:
        outputs = {
            'EntityIpAddress': address,
            'AverageAttackComplexity': -1,
            'EntityId': 'N/A'
        }
        readable_output = f'Could not find entity with the IP {address}'
    else:
        entity_id = entities[0]['agentId']
        report = xm.get_entity_report(entity_id, time_id)
        attack_complexity = report['attackComplexity']
        average = attack_complexity['avg']['value']
        level = attack_complexity['avg']['level']
        entity_name = entities[0]['name']
        readable_output = f'Entity {entity_name} has average {average} which is {level}'
        outputs = {
            'EntityIpAddress': address,
            'AverageAttackComplexity': average,
            'EntityId': entity_id
        }
    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='EntityId',
        outputs=outputs,
        readable_output=readable_output,
    )


def attack_paths_from_entity_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = xm.lookup_entities_by_ip(ips)
    attack_paths = []
    for entity in entities:
        paths = xm.get_outbound_paths(entity, time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'found {0} attack paths from {1} entities'.format(len(attack_paths), len(entities))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        readable_output=readable_output
    )


def entity_get_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    names = argToList(args.get('name'))
    entities = []
    outputs = []

    demisto.info(f'ips {ips}')
    for ip in ips:
        demisto.info(f'ip {ip}')
        try:
            entities.extend(xm.search_entities(ip['Address']))
        except AttributeError:
            entities.extend(xm.search_entities(ip))
    for name in names:
        entities.extend(xm.search_entities(name))
    if len(entities) == 0:
        readable_output = f'No entities match the properties IPs "{ips}", Names "{names}"'
    else:
        readable_output = '**Found the following entities**'
        for entity in entities:
            name = entity['name']
            try:
                is_asset = entity['asset']
            except KeyError:
                is_asset = False
            affected_assets = entity['affectedUniqueAssets']['count']
            readable_output += f'\n- {name}'
            outputs.append({
                'entity_id': entity['entityId'],
                'name': name,
                'is_asset': is_asset,
                'is_choke_point': affected_assets['level'] != 'none',
                'affected_assets': {
                    'value': affected_assets['value'],
                    'level': affected_assets['level']
                }
            })
    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='entity_id',
        outputs=outputs,
        readable_output=readable_output
    )


def risk_score_trend_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    timeId = 'timeAgo_days_7'
    resolution = 1
    risk_score = xm.risk_score(timeId, resolution)

    return CommandResults(
        outputs_prefix='XMCyber.RiskScore',
        outputs_key_field='score',
        outputs=risk_score
    )


def fetch_incidents_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    demisto.info('Running fetch incidents')
    demisto.debug('@@@@@@@@@@@@@@@@@@@@')
    outputs = [{'entity_id': 'markTest'}]
    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='entity_id',
        outputs=outputs
    )


def test_module_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
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
            raise Exception('Authorization Error: make sure API Key is correctly set')
        else:
            raise e
    except Exception as e:
        raise Exception(f'Verification Error: could not load XM Cyber version.\n{e}')
    return CommandResults(
        outputs_prefix='XMCyber.TestModule',
        outputs_key_field='status',
        outputs={'status': 'ok'}
    )


def get_assets_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    # Not in used - if will be used, need to update yml file
    outputs = xm.get_entities(DEFAULT_TIME_ID, True)
    return CommandResults(
        outputs_prefix='XMCyber.RiskScore',
        outputs_key_field='id',
        outputs=outputs
    )


def top_assets_at_risk_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    outputs = xm.top_assets_at_risk(DEFAULT_TIME_ID)
    return CommandResults(
        outputs_prefix='XMCyber.TopAssetsAtRisk',
        outputs_key_field='id',
        outputs=outputs
    )


def top_choke_points_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    outputs = xm.top_choke_points(DEFAULT_TIME_ID)
    return CommandResults(
        outputs_prefix='XMCyber.TopChokePoints',
        outputs_key_field='entityId',
        outputs=outputs
    )


def get_version_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    return CommandResults(
        outputs_prefix='XMCyber.Version',
        outputs_key_field='system',
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
        outputs_key_field="valid",
        outputs=result
    )


def ip_command(xm: XM, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    
    # Context standard for IP class
    ip_standard_list: List[Common.IP] = []
    ip_data_list: List[Dict[str, Any]] = []

    for ip in ips:
        res: List[Any]
        try:
            res = xm.search_entities(ip['Address'])
        except (AttributeError, TypeError):
            res = xm.search_entities(ip)
        if len(res) > 0:
            readable_output = f'**Resolved the following entities for IP {ip}**'
        else:
            readable_output = f'**No entity with the IP {ip}'
        for entity in res:
            name = entity['name']
            try:
                is_asset = entity['asset']
            except KeyError:
                is_asset = False
            affected_assets = entity['affectedUniqueAssets']['count']
            readable_output += f'\n- {name}'
            score = 0
            reputation = affected_assets['level']
            if reputation == 'none':
                score = Common.DBotScore.GOOD  # unknown
            else:
                score = Common.DBotScore.BAD  # bad

            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name='XMCyber',
                score=score,
                malicious_description=f'XM Cyber affected assets {reputation}'
            )

            ip_standard_context = Common.IP(
                ip=ip,
                dbot_score=dbot_score
            )

            ip_standard_list.append(ip_standard_context)

            ip_data_list = {
                'entity_id': entity['entityId'],
                'name': name,
                'is_asset': is_asset,
                'is_choke_point': affected_assets['level'] != 'none',
                'affected_assets': {
                    'value': affected_assets['value'],
                    'level': affected_assets['level']
                }
            }
    
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='XMCyber.IP',
        outputs_key_field='ip',
        outputs=ip_data_list,
        indicators=ip_standard_list
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
            "test-module": test_module_command,  # This is the call made when pressing the integration Test button.
            "fetch-incidents": fetch_incidents_command,
            # Command list
            # xmcyber-command-name: function_command
            "xmcyber-get-version": get_version_command,
            "xmcyber-risk-score-trend": risk_score_trend_command,
            "xmcyber-assets": get_assets_command,
            "xmcyber-top-assets-at-risk": top_assets_at_risk_command,
            "xmcyber-top-choke-points": top_choke_points_command,
            "xmcyber-is-version-supported": is_xm_version_supported_command,
            "xmcyber-asset-attack-path-list": asset_attack_path_list_command,
            "xmcyber-breachpoint-update": breachpoint_update_command,
            "xmcyber-critical-asset-add": critical_asset_add_command,
            "xmcyber-attack-paths-to-entity": attack_paths_to_entity_command,
            "xmcyber-attack-complexity-to-ip": attack_complexity_to_ip_command,
            "xmcyber-techniques-list": techniques_list_command,
            "xmcyber-attack-paths-from-entity": attack_paths_from_entity_command,
            "xmcyber-entity-get": entity_get_command,
            "ip": ip_command
        }

        if command in commandsDict:
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
