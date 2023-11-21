""" IMPORTS """
from ast import literal_eval
from CommonServerPython import *
# disable insecure warnings
import urllib3
urllib3.disable_warnings()
""""" MAPPERS """
CATEGORY_MAPPER: Dict[str, List[int]] = {
    'Network Access': [1, 2, 3, 4, 19, 20, 21, 22],
    'Network Inspection': [7, 10, 11, 12, 18],
    'Endpoint': [8, 9, 13, 14, 17],
    'Email': [15, 24],
    'Web': [5, 6],
    'Data Leak': [16]
}

SAFEBREACH_TO_DEMISTO_MAPPER = {
    'SHA256': 'SHA256',
    'Port': 'Port',
    'Protocol': 'Protocol',
    'FQDN/IP': 'Data',
    'Command': 'Command',
    'URI': 'URI'
}

INDICATOR_TYPE_MAPPER: Any = {
    'FQDN/IP': FeedIndicatorType.Domain,
    'SHA256': FeedIndicatorType.File,
    'Domain': FeedIndicatorType.Domain,
    'Port': 'SafeBreach Port',
    'Protocol': 'SafeBreach Protocol',
    'Process': 'SafeBreach Process',
    'Registry': 'SafeBreach Registry',
    'Command': 'SafeBreach Command',
    'URI': FeedIndicatorType.URL,
    'IP': FeedIndicatorType.IP,
}

# mapper from SB data type to demisto data type that given when the integration was configured.
INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER = {
    'SHA256': 'Hash',
    'Port': 'Port',
    'FQDN/IP': 'Domain',
    'Command': 'Command',
    'Protocol': 'Protocol',
    'URI': 'URI'
}

INSIGHT_DATA_TYPE_MAPPER = {
    1: 'Port',
    2: 'Protocol',
    3: 'Port',
    4: 'Port',
    5: 'Domain',
    6: 'URI',
    7: 'Hash',
    9: 'Hash',
    10: 'Protocol',
    14: 'Command',
    15: 'Hash',
    17: 'CVE',  # Not Supported Yet.
    18: 'CVE',  # Not Supported Yet.
    19: 'Port',
    20: 'Protocol',
    21: 'Port',
    22: 'Port',
    24: 'Hash',
}
SAFEBREACH_TYPES = [
    'Protocol', 'FQDN/IP', 'Port',
    'URI', 'SHA256', 'Attack', 'Proxies',
    'Impersonated User', 'Commands', 'Drop Path', 'Registry Path',
    'Outbound', 'Inbound', 'Server Header', 'Client Header'
]

DEMISTO_INDICATOR_REPUTATION = {
    'None': 0,
    'Good': 1,
    'Suspicious': 2,
    'Bad': 3
}
IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"


class Client:
    def __init__(self, base_url, account_id, api_key, proxies, verify, tags: Optional[list] = None,
                 tlp_color: Optional[str] = None):
        self.base_url = base_url
        self.account_id = account_id
        self.api_key = api_key
        self.verify = verify
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        self.proxies = proxies

    def http_request(self, method, endpoint_url, url_suffix, body=None):
        full_url = urljoin(self.base_url, f'{endpoint_url}/v1/accounts/' + f'{self.account_id}{url_suffix}')
        return requests.request(
            method,
            full_url,
            json=body,
            headers={'Accept': 'application/json', 'x-apitoken': self.api_key},
            verify=self.verify,
            proxies=self.proxies
        )

    def rerun_at_safebreach(self, rerun_data):
        return self.http_request('POST', endpoint_url='/api/orch', url_suffix='/queue', body=rerun_data)

    def get_remediation_data(self, insight_id):
        return self.http_request('GET', endpoint_url='/api/data',
                                 url_suffix=f'/insights/{insight_id}/remediation')

    def get_insights(self):
        return self.http_request(method='GET', endpoint_url='/api/data', url_suffix='/insights?type=actionBased')

    def get_nodes(self):
        return self.http_request('GET', endpoint_url='api/config',
                                 url_suffix='/nodes?details=true&deleted=true&assets=true')

    def get_simulation(self, simulation_id):
        return self.http_request(method='GET', endpoint_url='api/data', url_suffix=f'/executions/{simulation_id}')

    def get_test_status(self, test_id):
        return self.http_request('GET', endpoint_url='/api/data', url_suffix=f'/testsummaries/{test_id}')

    def test_connection(self):
        return self.http_request('GET', endpoint_url='/api/siem', url_suffix='/config/')


''' Helper functions '''


def is_ip(value):
    if isinstance(value, int):
        value = str(value)
    return re.match(IP_REGEX, value)


def fix_url(url):
    if url and url.endswith('/'):
        return url[0:-1]
    return url


def contains(list_a, list_b):
    return list(set(list_a) & set(list_b))


def unescape_string(string):
    try:
        return string.encode('utf-8').decode('unicode_escape')
    except Exception as e:
        demisto.debug(f"Failed to unescape_string: ' {e}")
        return string


def generate_readable_output(data):
    output = []
    types = list(set(map(lambda i: i['type'], data)))
    for type in types:
        same_type = list({x['value'] for x in data if x['type'] == type})
        output.append({f'{type} ({len(same_type)})': ', '.join(map(str, same_type))})
    return output


def extract_data(data) -> List[Dict[str, Any]]:
    output: list = []
    list_of_seen_items = []

    parent_key = list(data.keys())[0]
    first_level_data = list(data[parent_key].keys())
    list_of_seen_items.extend(first_level_data)
    if parent_key != 'Attack':
        output.extend(list(map(lambda o: {'type': parent_key, "value": o}, first_level_data)))

    for indicator in data[parent_key]:
        if contains(SAFEBREACH_TYPES, list(data[parent_key][indicator].keys())):
            for inner_type in data[parent_key][indicator]:
                formated_inner_type = inner_type.replace(' ', '')
                for item in data[parent_key][indicator][inner_type]:
                    if item == 'N/A':
                        continue
                    if isinstance(item, str):
                        item = unescape_string(item)
                    if item not in list_of_seen_items:
                        list_of_seen_items.append(item)
                        output.append({'type': formated_inner_type, "value": item})
    return output


def get_dbot_type(data_type, value):
    if data_type.lower() in ['sha1', 'md5', 'sha256']:
        return 'file'
    if data_type in ['Domain', 'FQDN/IP', 'URI']:
        if is_ip(value):
            return 'ip'
        return 'url'
    return data_type


def get_demisto_context_path(data_type):
    mapper = {
        'SHA256s': 'File(val.SHA256 == obj.SHA256)',
        'SHA256': 'File(val.SHA256 == obj.SHA256)',
        'FQDNs/IPs': 'URL(val.Data == obj.Data)',
        'FQDN/IP': 'URL(val.Data == obj.Data)',
        'IP': 'URL(val.Data == obj.Data)',
        'Domain': 'URL(val.Data == obj.Data)',
        'Commands': 'Process(val.CommandLine == obj.CommandLine)',
        'URIs': 'URL(val.URI == obj.URI)',
        'URI': 'URL(val.URI == obj.URI)'
    }
    return mapper.get(data_type)


def get_insights_ids_by_category(insight_category: List[str]) -> Union[List[int], None]:
    output: Any = []
    for category in insight_category:
        if CATEGORY_MAPPER.get(category):
            output.append(CATEGORY_MAPPER.get(category))
    return list(set([y for x in output for y in x]))


def refactor_rerun_data(rerun_data, simulation):
    rerun_name = f'Rerun (Demisto) - #({rerun_data.get("matrix").get("moveIds")[0]}) {simulation.get("moveName")}'
    return {
        "force": True,
        "matrix": {
            "name": rerun_name,
            "moveIds": rerun_data['matrix']['moveIds'],
            "nodeIds": list(set(rerun_data['matrix']['nodeIds'])),
            "simulationId": simulation.get('id')
        }
    }


def fetch_simulation_result(simulation):
    if simulation['status'] == 'SUCCESS':
        return 'Not-Blocked'
    if simulation['status'] == 'FAIL':
        return 'Blocked'
    return 'Failure'


def get_node_details(node_role, simulation):
    id = simulation.get('attackerNodeId') if node_role == 'Attacker' else simulation.get('targetNodeId')
    for item in simulation.get('dataObj').get('data')[0]:
        if id == item['id']:
            return item['details']
    return ""


def get_mitre_details(simulation):
    return [list(map(lambda tech: tech['value'], simulation.get('MITRE_Technique') or [])),
            list(map(lambda group: group['value'], simulation.get('Threat_Actor') or [])),
            list(map(lambda soft: soft['value'], simulation.get('MITRE_Software') or []))]


def get_node_display_name(node_role, simulation):
    node_name = simulation.get(f'{node_role}NodeName')
    internal_ip = simulation.get(f'{node_role}InternalIp')
    external_ip = simulation.get(f'{node_role}ExternalIp')
    return f"{node_name} ({internal_ip},{external_ip})"


def get_category_and_data_type_filters(args, predefine_insight_category, predefine_insight_data_type):
    insight_category = args.get('insightCategory') or predefine_insight_category
    insight_data_type = args.get('insightDataType') or predefine_insight_data_type
    # The User can provide the arguments as the following: insightCategory=`Web,Network Inspection`
    if isinstance(insight_category, str):
        insight_category = insight_category.split(',')
    if isinstance(insight_data_type, str):
        insight_data_type = insight_data_type.split(',')

    # if the user provide invalid category or data type raise an ValueError.
    if not contains(insight_category,
                    ['Network Access', 'Network Inspection', 'Endpoint', 'Email', 'Web', 'Data Leak']):
        raise ValueError(f'Category {insight_category} is not a valid category')
    if not contains(insight_data_type, ['Hash', 'Domain', 'URI', 'Command', 'Port', 'Protocol']):
        raise ValueError(f'Data type {insight_data_type} is not a valid data type')
    return insight_category, insight_data_type


def get_node_ids_from_insight(insight):
    node_ids = []
    for target in insight.get('targets'):
        node_ids.append(target.get('targetNodeId'))
        for attacker in target['attackers']:
            node_ids.append(attacker.get('attackerNodeId'))

    return list(set(node_ids))


def extract_affected_targets(client, insight):
    all_nodes = {item['id']: item for item in client.get_nodes().json()['data']}
    return list(map(lambda t: {'name': all_nodes[t['targetNodeId']]['name'],
                               'ip': all_nodes[t['targetNodeId']]['externalIp'],
                               'count': t['breakdown']['count']}, insight['targets']))


def get_splunk_remedation_query(response):
    try:
        query = [vendor['searchQuery'] for vendor in response.json()['mitigationVendors'] if
                 vendor['id'] == 'splunk']
        return "".join(query)
    except Exception as e:
        demisto.error(e)
        return ""


def extract_safebreach_error(response):
    errors = response.json().get('error') and response.json().get('error').get('errors')
    if not errors:
        return f'Failed to extract error!\n{response.json().get("error")}'
    return ','.join(list(map(lambda e: e.get('data').get('message'), errors)))


''' Commands '''


def get_indicators_command(client: Client, insight_category: list, insight_data_type: list, tlp_color: Optional[str],
                           args: dict) -> List[Dict]:
    """Create indicators.

            Arguments:
                client {Client} -- Client derives from BaseClient.
                insight_category {List[String]}  -- List of SafeBreach insight category - using as filter.
                insight_data_type {List[String]}  -- List of data types - using as filter.
                tlp_color {str}: Traffic Light Protocol color.
            Keyword Arguments:

            Returns:
                List[Dict] -- List of insights from SafeBreach
            """
    limit: int = int(args.get('limit') or demisto.params().get('indicatorLimit', 1000))
    indicators: List[Dict] = []
    count: int = 0
    # These variable be filled directly from the integration configuration or as arguments.
    insight_category, insight_data_type = get_category_and_data_type_filters(args, insight_category,
                                                                             insight_data_type)
    # Convert category into insight id
    insights_ids: Any = get_insights_ids_by_category(insight_category)
    raw_insights: Any = client.get_insights().json()

    # Filter insight by category
    insights: Any = [item for item in raw_insights if int(item.get('ruleId')) in insights_ids]
    for insight in insights:
        # Fetch remediation data for each insight
        processed_data: List[Dict[str, Any]] = get_remediation_data_command(client,
                                                                            {'insightId': insight.get('ruleId')}, False)
        for item in processed_data:
            # if the data type is not in the filter data types continue,
            if INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER.get(item['type']) not in insight_data_type:
                continue
            if not INDICATOR_TYPE_MAPPER.get(str(item['type'])) or item["value"] == 'N/A':
                continue
            if isinstance(item['type'], int):
                demisto.info('Data type is int', item['type'], insight['ruleId'])

            is_behaveioral = item['type'] not in ['Domain', 'FQDN/IP', 'SHA256', 'URI', 'Hash']
            score_behavioral_reputation = DEMISTO_INDICATOR_REPUTATION.get(demisto.params().get('behavioralReputation'))
            score_non_behavioral_reputation = DEMISTO_INDICATOR_REPUTATION.get(
                demisto.params().get('nonBehavioralReputation'))
            raw_json = {
                'value': str(item["value"]),
                'dataType': item['type'],
                'insightId': insight.get('ruleId'),
                'insightTime': insight.get('maxExecutionTime'),
            }
            mapping = {
                'description': 'SafeBreach Insight - {0}'.format(insight['actionBasedTitle']),
                item['type'].lower(): item["value"],
                "safebreachinsightids": str(insight.get('ruleId')),
                "safebreachseverity": insight.get('severity'),
                "safebreachseverityscore": str(insight.get('severityScore')),
                "safebreachisbehavioral": is_behaveioral,
                "safebreachattackids": list(map(str, insight.get('attacks'))),
                'tags': [
                    f"SafeBreachInsightId: {insight.get('ruleId')}",
                ]
            }
            if tlp_color:
                mapping['trafficlightprotocol'] = tlp_color

            mapping['tags'] = list((set(mapping['tags'])).union(set(client.tags)))
            indicator = {
                'value': str(item["value"]),
                'type': INDICATOR_TYPE_MAPPER.get(str(item['type'])),
                'rawJSON': raw_json,
                'fields': mapping,
                'score': score_behavioral_reputation if is_behaveioral else score_non_behavioral_reputation
            }

            if is_ip(item["value"]):
                indicator['type'] = FeedIndicatorType.IP

            count += 1
            if count > limit:
                return indicators
            indicators.append(indicator)
    return indicators


def get_remediation_data_command(client: Client, args: dict, no_output_mode: bool) -> List[Dict[str, Any]]:
    """Get SafeBreach remediation data.

            Arguments:
                client {Client} -- Client derives from BaseClient
                args {dict}  -- function arguments
                no_output_mode {bool} -- if true, this function will insert data to the context,
                                        otherwise, it will just returns the data.

            Keyword Arguments:

            Returns:
                Dict -- Each key is a unique SafeBreach data type.
                        Each value is a list of the data.
            """
    insight_id: Optional[int] = args.get('insightId')
    response = client.get_remediation_data(insight_id)
    insight: Any = get_insights_command(client, {'insightIds': [insight_id]}, False)

    if insight:
        insight = insight[0]

    if response.status_code < 200 or response.status_code >= 300:
        error = extract_safebreach_error(response)
        raise DemistoException(
            f'Failed to fetch remediation data for insight id {insight_id}\nSafeBreach error:{error}')

    sb_remediation_data = response.json().get('remediationData')
    processed_data = extract_data(sb_remediation_data)
    readable_output_list = generate_readable_output(processed_data)
    vendor_remediation_data = list(filter(lambda o: o['value'],
                                          [{'type': "Splunk", "value": get_splunk_remedation_query(response)}]))
    # Demisto Context:
    dbot_score_list = []
    standard_context_dict = {}
    standard_context_list: Any = []
    secondary_standard_context_dict: Any = {}
    secondary_standard_context_list = []
    secondary_path: Any = None

    # SafeBreach Context:
    safebreach_context_list = []
    safebreach_context = {
        "Id": insight_id,
        'RawRemediationData': processed_data,
        'VendorRemediationData': vendor_remediation_data
    }
    safebreach_context_list.append(safebreach_context)

    for item in processed_data:
        if item.get('type', '').startswith('Attack') or len(processed_data) == 0:
            continue

        demisto_standard_path = get_demisto_context_path(item['type'])  # e.g URL(val.Data == obj.Data)
        demisto_data_type = SAFEBREACH_TO_DEMISTO_MAPPER.get(item['type'])  # SHA256,Port,Protocol,Data,Command,URI

        if item['type'] in ['DropPaths', 'URIs', 'URI', 'Command']:
            try:
                item["value"] = item["value"].encode('utf-8').decode('unicode_escape').encode('latin1').decode('utf-8')
            except Exception as e:
                demisto.debug(f"Failed to decode/encode: ' {e}")
                item["value"] = item["value"]
        if demisto_data_type:
            is_behaveioral = item['type'] not in ['Domain', 'FQDN/IP', 'SHA256', 'URI', 'Hash']
            score_behavioral_reputation = DEMISTO_INDICATOR_REPUTATION.get(demisto.params().get('behavioralReputation'))
            score_non_behavioral_reputation = DEMISTO_INDICATOR_REPUTATION.get(
                demisto.params().get('nonBehavioralReputation'))
            dbot_score = {
                "Indicator": item["value"],
                'type': get_dbot_type(item['type'], item["value"]),  # TODO: maybe change it to SB_Indicator?
                "Vendor": "SafeBreach",
                "Score": score_behavioral_reputation if is_behaveioral else score_non_behavioral_reputation
            }
            primary_standard_context = {
                demisto_data_type: item["value"],  # e.g Data : <URL>, SHA256:<SHA256>
                "Malicious": {
                    "Description": f"SafeBreach Insights - ({insight_id}){insight.get('actionBasedTitle')}",
                    "Vendor": "SafeBreach"
                }
            }
            if item['type'] in ['FQDNs/IPs', 'FQDN/IP']:
                if re.match(IP_REGEX, item["value"]):
                    secondary_path = 'IP(val.Address == obj.Address)'
                    secondary_standard_context_dict = {
                        'IP': item["value"],
                        "Malicious": {
                            "Description": f"SafeBreach Insights - ({insight_id}){insight.get('actionBasedTitle')}",
                            "Vendor": "SafeBreach"
                        }
                    }
                else:
                    secondary_path = 'Domain(val.Name == obj.Name)'
                    secondary_standard_context_dict = {
                        'Name': item["value"],
                        "Malicious": {
                            "Description": f"SafeBreach Insights - ({insight_id}){insight.get('actionBasedTitle')}",
                            "Vendor": "SafeBreach"
                        }
                    }
            if demisto_standard_path:
                standard_context_list.append(primary_standard_context)
            secondary_standard_context_list.append(secondary_standard_context_dict)
            dbot_score_list.append(dbot_score)

        if len(standard_context_list) > 0 and demisto_standard_path:
            standard_context_dict[demisto_standard_path] = standard_context_list
            if secondary_path:
                standard_context_dict[secondary_path] = secondary_standard_context_list

    output_context = {
        "DBotScore(val.Indicator == obj.Indicator)": dbot_score_list,
        "SafeBreach.Insight(val.Id == obj.Id)": safebreach_context_list
    }
    merged_context = {**output_context, **standard_context_dict}
    readable_output = tableToMarkdown(name="Remediation Data", t=readable_output_list, removeNull=True)
    if no_output_mode:
        return_outputs(readable_output=readable_output, outputs=merged_context)
    return processed_data


def insight_rerun_command(client: Client, args: dict):
    """Rerun SafeBreach insight.

            Arguments:
                client {Client} -- Client derives from BaseClient
                args {dict}  -- function arguments

            Keyword Arguments:
                insight_id {list<int>} -- The insight id to rerun
            Returns:
                outputs
            """

    raw_insights: Any = client.get_insights().json()
    insight_ids: Any = args.get('insightIds')
    if not insight_ids:
        raise Exception('insightIds was not provided to the command')
    human_readable_list = []
    safebreach_insight_context_list = []
    safebreach_test_context_list = []

    if isinstance(insight_ids, str):
        insight_ids = literal_eval(insight_ids)
    if isinstance(insight_ids, int):
        insight_ids = [insight_ids]
    insight_ids = [int(id) for id in insight_ids]

    # Filter all insight according to given.
    active_insight_ids = list(map(lambda i: i['ruleId'], raw_insights))
    invalid_insight_ids = list(filter(lambda i: i not in active_insight_ids, insight_ids))
    insights = list(filter(lambda insight: insight['ruleId'] in insight_ids, raw_insights))

    # if given id is not in the active id:
    if len(invalid_insight_ids):
        # TODO: check if it can be demisto.log()
        demisto.info(f'Insight ids:{invalid_insight_ids} are invalid.')

    for insight in insights:
        try:
            insight_id = insight.get('ruleId')
            if not insight_ids:
                raise ValueError('Insight IDs are invalid')

            nodes_ids = get_node_ids_from_insight(insight)

            rerun_data = {
                "matrix": {
                    "name": "Insight (XSOAR) - {0}".format(insight['actionBasedTitle']),
                    "moveIds": insight['attacks'],
                    "nodeIds": nodes_ids
                },
                "force": True
            }
            response = client.rerun_at_safebreach(rerun_data)

            if response.status_code < 200 or response.status_code >= 300:
                error = extract_safebreach_error(response)
                raise DemistoException(
                    f'Failed to rerun simulation for insight id {insight_id}\nSafeBreach error:{error}')
            try:
                response = response.json()['data']
            except ValueError:
                raise ValueError('Response body does not contain valid json')

            t = {
                'Insight Id': insight_id,
                'Test Id': response.get('runId'),
                'Name': "Insight (XSOAR) - {0}".format(insight.get('actionBasedTitle')),
                '# Attacks': len(insight.get('attacks'))
            }
            context_object = {
                'Id': insight_id,
                'Rerun': [{'Name': "Insight (XSOAR) - {0}".format(insight.get('actionBasedTitle')),
                           'Id': response.get('runId'),
                           'AttacksCount': len(insight.get('attacks')),
                           'ScheduledTime': datetime.now().isoformat()}]
            }
            test_context_dict = {
                'Id': response.get('runId'),
                'Name': "Insight (XSOAR) - {0}".format(insight.get('actionBasedTitle')),
                'Status': 'Pending',
                'AttacksCount': len(insight.get('attacks')),
                'ScheduledTime': datetime.now().isoformat()
            }
            human_readable_list.append(t)
            safebreach_insight_context_list.append(context_object)
            safebreach_test_context_list.append(test_context_dict)
        except Exception as e:
            traceback.print_exc()
            return_error('Failed to rerun insight', e)
    safebreach_context = {
        'SafeBreach.Insight(val.Id == obj.Id)': safebreach_insight_context_list,
        'SafeBreach.Test(val.Id == obj.Id)': safebreach_test_context_list,
    }
    readable_output = tableToMarkdown(name='Rerun SafeBreach Insight', t=human_readable_list, removeNull=True)
    return_outputs(readable_output=readable_output, outputs=safebreach_context)


def get_insights_command(client: Client, args: Dict, no_output_mode: bool) -> List:
    """Get SafeBreach insights.

        Arguments:
            client {Client} -- Client derives from BaseClient
            args {dict}  -- function arguments

        Keyword Arguments:

        Returns:
            List[Dict] -- List of insights from SafeBreach
        """
    insight_ids = args.get('insightIds')
    insights: Any
    if isinstance(insight_ids, str):
        insight_ids = literal_eval(insight_ids)
    if isinstance(insight_ids, int):
        insight_ids = [insight_ids]
    response: Any = client.get_insights()

    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError('Failed to fetch SafeBreach insights', response)

    try:
        insights = sorted(response.json(), key=lambda i: i.get('ruleId'))
    except TypeError:
        demisto.info('Failed to sort SafeBreach insights, skip')

    if insight_ids and len(insight_ids) > 0:
        # Verify that insight_ids holds List[int]
        if isinstance(insight_ids, list):
            insight_ids = list(map(int, insight_ids))
        insights = [item for item in insights if int(item.get('ruleId')) in insight_ids]
    insight_output = []
    insight_readable = []
    headers = []

    for insight in insights:
        affected_targets = extract_affected_targets(client, insight)
        context_insight = {
            'Name': insight['actionBasedTitle'],
            'Id': insight['ruleId'],
            'DataType': INSIGHT_DATA_TYPE_MAPPER.get(insight['ruleId']) or 'Other',
            'Category': insight.get('category'),
            'LatestSimulation': insight.get('maxExecutionTime'),
            'EarliestSimulation': insight.get('minExecutionTime'),
            'SimulationsCount': insight.get('context').get('simulationsCount'),
            'RiskImpact': float("{0:.2f}".format(insight.get('impact'))),
            'AffectedTargetsCount': len(insight.get('targets')),
            'SeverityScore': insight.get('severityScore'),
            'Severity': insight.get('severity'),
            'RemediationDataCount': insight.get("mitigationPoints").get('value'),
            'RemediationDataType': insight.get("mitigationPoints").get('key'),
            'ThreatGroups': insight.get('threatActors'),
            'NetworkDirection': insight.get('direction'),
            'AttacksCount': len(insight.get('attacks')),
            'AttackIds': insight.get('attacks'),
            'AffectedTargets': affected_targets,
            'RemediationAction': insight.get('action'),
            'ResultLink': f"{fix_url(demisto.params().get('url'))}/#/executions?query={insight.get('criteria')}"
        }
        t = {
            'Id': context_insight['Id'],
            'Name': context_insight['Name'],
            'Category': context_insight['Category'],
            'Risk Impact': context_insight['RiskImpact'],
            'Severity': context_insight['Severity'],
            'Affected Targets': context_insight['AffectedTargetsCount'],
            'Data Type': context_insight['DataType'],
        }
        headers = list(t.keys())
        insight_output.append(context_insight)
        insight_readable.append(t)
    readable_output = tableToMarkdown(name='SafeBreach Insights', t=insight_readable, headers=headers,
                                      removeNull=True)
    outputs = {
        'SafeBreach.Insight(val.Id == obj.Id)': insight_output
    }
    if no_output_mode:
        return_outputs(
            readable_output,
            outputs,
            insight_output
        )
    return insights


def get_test_status_command(client: Client, args: Dict):
    """Get status of a SafeBreach test for tracking progress of a run.

            Arguments:
                client {Client} -- Client derives from BaseClient
                args {dict}  -- function's arguments

            Keyword Arguments:
                    testId : float
            Returns:
               None
            """
    test_ids = argToList(args.get('testId'))
    for test_id in test_ids:
        tries = 0
        response: Any
        while tries < 3:
            response = client.get_test_status(test_id)
            if response.status_code == 200:
                break
            tries += 1

        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f'Failed to get status of test: {test_id}')
        try:
            response = response.json()
        except ValueError:
            raise ValueError('Response body does not contain valid json')
        t = {
            'Test Id': response.get('id'),
            'Name': response.get('matrixName'),
            'Status': response.get('status'),
            'Start Time': response.get('startTime'),
            'End Time': response.get('endTime'),
            'Total Simulation Number': response.get('blocked', 0) + response.get('notBlocked', 0)
        }
        readable_output = tableToMarkdown(name='Test Status', t=t, headers=list(t.keys()), removeNull=True)
        safebreach_context = {
            "SafeBreach.Test(val.Id == obj.Id)": {
                'Id': response.get('id'),
                'Name': response.get('matrixName'),
                'Status': response.get('status'),
                'StartTime': response.get('startTime'),
                'EndTime': response.get('endTime'),
                'TotalSimulationNumber': response.get('blocked', 0) + response.get('notBlocked', 0)
            }
        }
        return_outputs(readable_output=readable_output, outputs=safebreach_context)


def get_safebreach_simulation_command(client: Client, args: Dict):
    """Get SafeBreach simulation.

            Arguments:
                client {Client} -- Client derives from BaseClient
                args {dict}  -- function arguments

            Keyword Arguments:
                simulationId {str} -- simulation id.

            Returns:
                None
            """
    simulation_id = args.get('simulationId')

    if not simulation_id:
        raise ValueError('No simulation ID')

    response = client.get_simulation(simulation_id)
    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError('Failed to fetch SafeBreach simulation')
    try:
        simulation = response.json()
    except ValueError:
        raise ValueError('Response body does not contain valid json')
    mitre_techniques, mitre_groups, mitre_software = get_mitre_details(simulation)
    final_status = simulation.get('finalStatus')
    if final_status is not None:
        final_status = final_status.capitalize()

    detected_action = simulation.get('siemDetectionStatus')
    if detected_action is not None:
        detected_action = detected_action.capitalize()
    try:
        simulation_context = {
            'Id': simulation.get('id'),
            'FinalStatus': final_status,
            'Result': fetch_simulation_result(simulation),
            'DetectedAction': detected_action,
            'SimulationRunId': simulation.get('jobId'),
            'Time': simulation.get('executionTime'),
            'LastChangeTime': simulation.get('lastStatusChangeDate'),
            'Labels': simulation.get('labels'),
            "Parameters": simulation.get('parameters'),
            'Attack': {
                'Id': simulation.get('moveId'),
                'Name': simulation.get('moveName'),
                'Description': simulation.get('moveDesc'),
                'Phase': simulation.get('packageName'),
                'Type': list(map(lambda attack_type: attack_type['value'], simulation.get('Attack_Type'))),
                'SecurityControl': list(map(lambda item: item['value'], simulation.get('Security_Controls'))),
                'IndicatorBased': 'True' if simulation.get('IoC_Based')[0]['value'] == 1 else 'False'
            },
            'Attacker': {
                'Name': simulation.get('attackerNodeName'),
                'OS': simulation.get('attackerOSType'),
                'InternalIp': simulation.get('attackerInternalIp'),
                'ExternalIp': simulation.get('attackerExternalIp'),
                'SimulationDetails': get_node_details('Attacker', simulation),
            },
            'Target': {
                'Name': simulation.get('targetNodeName'),
                'OS': simulation.get('targetOSType'),
                'InternalIp': simulation.get('targetInternalIp'),
                'ExternalIp': simulation.get('targetExternalIp'),
                'SimulationDetails': get_node_details('Target', simulation),
            },
            'Network': {
                'Direction': simulation.get('direction'),
                'SourceIp': simulation.get('sourceIp'),
                'DestinationIp': simulation.get('destinationIp'),
                'SourcePort': simulation.get('sourcePort'),
                'DestinationPort': simulation.get('serverPort'),
                'Protocol': simulation.get('attackProtocol'),
                'Proxy': simulation.get('parameters').get('PROXY') and simulation['parameters']['PROXY'][0][
                    'displayName'],
            },
            'Classifications': {
                'MITRETechniques': mitre_techniques,
                'MITREGroups': mitre_groups,
                'MITRESoftware': mitre_software
            }
        }
        t = {
            'Id': simulation_id,
            'Name': f'(#{simulation.get("moveId")}) {simulation.get("moveName")}',
            'Status': simulation.get('status').capitalize(),
            'Result': simulation.get('status').capitalize(),
            'Detected Action': simulation.get('status').capitalize(),
            'Attacker': get_node_display_name('attacker', simulation),
            'Target': get_node_display_name('target', simulation),
        }

        human_readable = tableToMarkdown(name='SafeBreach Simulation', t=t, headers=list(t.keys()), removeNull=True)
        outputs = {
            'SafeBreach.Simulation(val.Id == obj.Id)': simulation_context

        }
        return_outputs(readable_output=human_readable, outputs=outputs)
    except Exception:
        traceback.print_exc()


def rerun_simulation_command(client: Client, args: dict):
    """Rerun a specific SafeBreach simulation in your environment.

            Arguments:
                client {Client} -- Client derives from BaseClient
                args {dict}  -- function arguments

            Keyword Arguments:
                simulationId {str} -- The id of the simulation to rerun.

            Returns:
                None
            """
    rerun_data = {}
    simulation_id = args.get('simulationId')
    if not simulation_id:
        raise ValueError("No simulation ID has been provided")
    try:
        response = client.get_simulation(simulation_id)
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f'Cant Find Simualtion id :{simulation_id}')
        simulation = response.json()
        rerun_data = simulation.get('rerun')
        if not rerun_data:
            raise ValueError(f'Cant Find Rerun Data for simulation is:{simulation_id}')

        rerun_data = refactor_rerun_data(rerun_data, simulation)
        response = client.rerun_at_safebreach(rerun_data).json()['data']

        t = {
            'Simulation Id': simulation_id,
            'Test Id': response['runId'],
            'Name': rerun_data['matrix']['name'],
        }
        safebreach_context = {
            "Id": simulation_id,
            "Rerun": {
                'Id': response['runId'],
                'Name': rerun_data['matrix']['name'],
                'ScheduledTime': datetime.now().isoformat()
            }
        }
        test_context_dict = {
            'Id': response['runId'],
            'Name': rerun_data['matrix']['name'],
            'Status': 'PENDING',
            'AttacksCount': len(rerun_data['matrix']['moveIds'])
        }

        human_readable = tableToMarkdown(name='SafeBreach Rerun Simualtion', t=t, headers=list(t.keys()),
                                         removeNull=True)
        safebreach_context = {
            'SafeBreach.Simulation(val.Id == obj.Id)': safebreach_context,
            'SafeBreach.Test(val.Id == obj.Id)': test_context_dict,
        }
        return_outputs(readable_output=human_readable, outputs=safebreach_context)
    except Exception as e:
        traceback.print_exc()
        return_error('Error in rerun_simulation', e)


def safebreach_test_module(client: Client) -> str:
    """A simple test module
       Arguments:
           url {String} -- SafeBreach Management URL.
       Returns:
           str -- "ok" if succeeded, else raises a error.
       """
    response = client.test_connection()
    if response.status_code == 200:
        return 'ok'
    else:
        massage = response.reason.lower()
        if response.status_code == 401:
            massage = 'API Key is invalid, try again'
        elif response.status_code == 404:
            massage = 'URL is invalid, try again'
        elif response.status_code < 200 or response.status_code >= 300:
            massage = 'Test connection failed'
        raise Exception(f'{massage}')


def main():
    command = demisto.command()
    params = demisto.params()
    account_id = params.get('accountId')
    api_key = params.get('apiKey')
    url = fix_url(params.get('url'))
    insight_category_filter = params.get('insightCategory')
    insight_data_type_filter = params.get('insightDataType')
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    verify_certificate = not params.get('insecure', False)

    proxies = handle_proxy()
    try:
        client = Client(base_url=url, account_id=account_id, api_key=api_key, proxies=proxies,
                        verify=verify_certificate, tags=tags)

        if command == 'safebreach-get-insights':
            get_insights_command(client, demisto.args(), True)
        elif command == 'safebreach-rerun-insight':
            insight_rerun_command(client, demisto.args())
        elif command == 'safebreach-get-remediation-data':
            get_remediation_data_command(client, demisto.args(), True)
        elif command == 'safebreach-get-test-status':
            get_test_status_command(client, demisto.args())
        elif command == 'safebreach-get-simulation':
            get_safebreach_simulation_command(client, demisto.args())
        elif command == 'safebreach-rerun-simulation':
            rerun_simulation_command(client, demisto.args())
        elif command == 'fetch-indicators':
            indicators = get_indicators_command(client, insight_category_filter, insight_data_type_filter,
                                                tlp_color, demisto.args())
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
            demisto.results('ok')
        elif command == 'safebreach-get-indicators':
            indicators = get_indicators_command(client, insight_category_filter, insight_data_type_filter,
                                                tlp_color, demisto.args())
            entry_result = camelize(indicators)
            hr = tableToMarkdown('Indicators:', entry_result)
            return_outputs(hr, {}, entry_result)

        elif command == 'test-module':
            results = safebreach_test_module(client)
            return_outputs(results)
        else:
            return_error(f'Command: {command} is not supported.')

    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__main__', "__builtin__", "builtins"]:
    main()
