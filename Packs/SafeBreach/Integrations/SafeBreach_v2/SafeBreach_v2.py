""" IMPORTS """
import traceback
from ast import literal_eval
from typing import List, Dict, AnyStr, Optional, Any, Union
from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()
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
    'SHA256s': 'SHA256',
    'SHA256': 'SHA256',
    'Ports': 'Port',
    'Port': 'Port',
    'Protocols': 'Protocol',
    'FQDNs/IPs': 'Data',
    'FQDN/IP': 'Data',
    'Commands': 'Command',
    'URIs': 'URI',
    'URI': 'URI'
}

INDICATOR_TYPE_MAPPER = {
    'FQDNs/IPs': FeedIndicatorType.Domain,
    'FQDN/IP': FeedIndicatorType.Domain,
    'SHA256': FeedIndicatorType.File,
    'SHA256s': FeedIndicatorType.File,
    'Domain': FeedIndicatorType.Domain,
    'URI': FeedIndicatorType.URL,
    'IP': FeedIndicatorType.IP,
}

# mapper from SB data type to demisto data type that given when the integration was configured.
INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER = {
    'SHA256': 'Hash',
    'SHA256s': 'Hash',
    'Ports': 'Port',
    'Protocols': 'Protocol',
    'FQDNs/IPs': 'Domain',
    'FQDN/IP': 'Domain',
    'Commands': 'Command',
    'URIs': 'URI',
    'URI': 'URI'
}

INSIGHT_DATA_TYPE_MAPPER = {
    14: 'Command',
    5: 'Domain',
    # 17: 'CVE', # Not Supported Yet.
    # 18: 'CVE', # Not Supported Yet.
    24: 'Hash',
    15: 'Hash',
    6: 'URI',
    7: 'Hash',
    9: 'Hash'
}
SAFEBREACH_TYPES = ['Ports', 'Protocols', 'FQDNs/IPs',
                    'FQDN/IP',
                    'URI', 'SHA256', 'SHA256s', 'Attacks', 'Proxies',
                    'Impersonated Users', 'Commands', 'Drop Paths',
                    'Outbound', 'Inbound', 'Server Headers', 'Client Headers']

IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"


class Client:
    def __init__(self, base_url, account_id, api_key, proxies, verify):
        self.base_url = base_url
        self.account_id = account_id
        self.api_key = api_key
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, endpoint_url, url_suffix, body=None):
        full_url = urljoin(self.base_url, endpoint_url + '/v1/accounts/' + str(self.account_id) + url_suffix)
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
                                 url_suffix='/insights/{0}/remediation'.format(insight_id))

    def get_insights(self):
        return self.http_request(method='GET', endpoint_url='/api/data', url_suffix='/insights?type=actionBased')

    def get_simulation(self, simulation_id):
        return self.http_request(method='GET', endpoint_url='api/data', url_suffix=f"/executions/{simulation_id}")

    def get_test_status(self, test_id):
        return self.http_request('GET', endpoint_url='/api/data', url_suffix=f'/matrixsummaries/{test_id}')

    def test_connection(self):
        return self.http_request('GET', endpoint_url='/api/orch', url_suffix='status')


''' Helper functions '''


def is_ip(value):
    if isinstance(value, int):
        value = str(value)
    return re.match(IP_REGEX, value)


def fix_url(url):
    if url.endswith('/'):
        return url[0:-1]
    return url


def find_element(lst, insight_id):
    if isinstance(insight_id, str):
        insight_id = int(insight_id)
    for item in lst:
        if item['ruleId'] == insight_id:
            return item
    return None


def contains(list_a, list_b):
    return list(set(list_a) & set(list_b))


def unescape_string(string):
    return string.encode('utf-8').decode('unicode_escape')


def extract_data(data):
    parent_key = list(data.keys())[0]
    output = {}
    first_level_data = list(data[parent_key].keys())
    output[parent_key] = first_level_data
    for indicator in data[parent_key]:
        if contains(SAFEBREACH_TYPES, list(data[parent_key][indicator].keys())):
            for inner_type in data[parent_key][indicator]:
                formated_inner_type = inner_type.replace(' ', '')
                for item in data[parent_key][indicator][inner_type]:
                    if isinstance(item, str):
                        item = unescape_string(item)
                    if not output.get(formated_inner_type):
                        output[formated_inner_type] = []
                    if item not in output[formated_inner_type]:
                        output[formated_inner_type].append(item)
    return output


def get_dbot_type(data_type, value):
    if data_type.lower() in ['sha1', 'md5', 'sha256s', 'sha256']:
        return 'file'
    if data_type in ['Domain', 'URIs', 'FQDNs/IPs', 'FQDN/IP', 'URI']:
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


''' Commands '''


def get_indicators_command(client: Client, insight_category: list, insight_data_type: list, args: dict) -> List[Dict]:
    """Create indicators.

            Arguments:
                client {Client} -- Client derives from BaseClient.
                insight_category {List[String]}  -- List of SafeBreach insight category - using as filter.
                insight_data_type {List[String]}  -- List of data types - using as filter.

            Keyword Arguments:

            Returns:
                List[Dict] -- List of insights from SafeBreach
            """
    limit: int = int(args.get('limit') or demisto.params().get('indicatorLimit'))
    insights_ids: Any = []
    indicators: List[Dict] = []
    count: int = 0
    safebreach_to_demisto_type_mapper = {
        'SHA256': 'SHA256',
        'SHA256s': 'SHA256',
        'Ports': 'Port',
        'Protocols': 'Protocol',
        'FQDNs/IPs': 'Domain',
        'FQDN/IP': 'Domain',
        'Domain': 'Domain',
        'Commands': 'Command',
        'URIs': 'URI',
        'URI': 'URI'
    }

    # These variable be filled directly from the integration configuration or as arguments.
    insight_category, insight_data_type = get_category_and_data_type_filters(args, insight_category, insight_data_type)
    # Convert category into insight id
    insights_ids = get_insights_ids_by_category(insight_category)
    raw_insights: Any = client.get_insights().json()

    # Filter insight by category
    insights: Any = list([item for item in raw_insights if int(item.get('ruleId')) in insights_ids])
    for insight in insights:
        # Fetch remediation data for each insight
        processed_data = get_remediation_data_command(client, {'insightId': insight.get('ruleId')}, False)
        for data_type in processed_data:
            # if the data type is not in the filter data types continue,
            if INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER.get(data_type) not in insight_data_type:
                continue
            demisto_indicator_type: Any = safebreach_to_demisto_type_mapper.get(data_type)
            for value in processed_data[data_type]:
                if not INDICATOR_TYPE_MAPPER.get(str(demisto_indicator_type)):
                    continue
                raw_json = {'value': value,
                            'dataType': data_type,
                            'insightId': insight.get('ruleId'),
                            'insightTime': insight.get('maxExecutionTime')}
                mapping = {
                    'description': 'SafeBreach Insight - {0}'.format(insight['actionBasedTitle']),
                    demisto_indicator_type.lower(): value,
                    'tags': [
                        f"SafeBreachInsightId: {insight.get('ruleId')}"
                    ]
                }

                indicator = {
                    'value': value,
                    'type': INDICATOR_TYPE_MAPPER.get(str(demisto_indicator_type)),
                    'rawJSON': raw_json,
                    'fields': mapping,
                    'score': 3
                }

                if is_ip(value):
                    indicator['type'] = FeedIndicatorType.IP

                count += 1
                if count > limit:
                    return indicators
                indicators.append(indicator)
    return indicators


def get_remediation_data_command(client: Client, args: dict, no_output_mode: bool) -> Dict[str, List[AnyStr]]:
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
        raise DemistoException(f'Failed to fetch remediation data for insight id {insight_id}')

    remediation_data = response.json().get('remediationData')
    processed_data = extract_data(remediation_data)
    # Demisto Context:
    dbot_score_list = []
    standard_context_dict = {}
    readable_output_list = []
    primary_standard_context = {}
    secondary_standard_context_dict: Any = {}
    secondary_standard_context_list = []
    secondary_path = ''

    # SafeBreach Context:
    safebreach_context_list = []
    safebreach_context = {}

    for data_type in processed_data:
        if data_type.startswith('Attack') or len(processed_data[data_type]) == 0:
            continue
        if data_type == 'Drop Paths':
            data_type = 'DropPaths'
        standard_context_list: Any = []

        t = {
            f'{data_type} ({len(processed_data[data_type])})': processed_data[data_type]
        }
        readable_output_list.append(t)

        safebreach_context = {
            "Id": insight_id,
            data_type: processed_data[data_type]
        }
        safebreach_context_list.append(safebreach_context)

        demisto_standard_path = get_demisto_context_path(data_type)  # e.g URL(val.Data == obj.Data)
        demisto_data_type = SAFEBREACH_TO_DEMISTO_MAPPER.get(data_type)  # SHA256,Port,Protocol,Data,Command,URI
        for value in processed_data[data_type]:
            if data_type in ['DropPaths', 'URIs', 'URI']:
                value = value.encode('utf-8').decode('unicode_escape').encode('latin1').decode('utf-8')
            if demisto_data_type:
                dbot_score = {
                    "Indicator": value,
                    "Type": get_dbot_type(data_type, value),
                    "Vendor": "SafeBreach",
                    "Score": 3
                }
                primary_standard_context = {
                    demisto_data_type: value,  # e.g Data : <URL>, SHA256:<SHA256>
                    "Malicious": {
                        "Description": f"SafeBreach Insights - ({insight_id}){insight.get('actionBasedTitle')}",
                        "Vendor": "SafeBreach"
                    }
                }
                if data_type in ['FQDNs/IPs', 'FQDN/IP']:
                    if re.match(IP_REGEX, value):
                        secondary_path = 'IP(val.Address == obj.Address)'
                        secondary_standard_context_dict = {
                            'IP': value,
                            "Malicious": {
                                "Description": f"SafeBreach Insights - ({insight_id}){insight.get('actionBasedTitle')}",
                                "Vendor": "SafeBreach"
                            }
                        }
                    else:
                        secondary_path = 'Domain(val.Name == obj.Name)'
                        secondary_standard_context_dict = {
                            'Name': value,
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
                insight_id {int} -- The insight id to rerun
            Returns:
                outputs
            """
    insights = client.get_insights().json()
    insight_id = args.get('insightId')
    insight = find_element(insights, insight_id)

    if not insight:
        raise ValueError('Insight ID is invalid')

    nodes_ids = get_node_ids_from_insight(insight)

    rerun_data = {
        "matrix": {
            "name": "Insight (Demisto) - {0}".format(insight['actionBasedTitle']),
            "moveIds": insight['attacks'],
            "nodeIds": nodes_ids
        },
        "force": True
    }
    response = client.rerun_at_safebreach(rerun_data)

    if response.status_code < 200 or response.status_code >= 300:
        raise DemistoException('Failed to rerun simulation for insight id {}'.format(insight_id))
    try:
        response = response.json()['data']
    except ValueError:
        raise ValueError('Response body does not contain valid json')
    try:
        t = {
            'Insight Id': insight_id,
            'Test Id': response.get('runId'),
            'Name': "Insight (Demisto) - {0}".format(insight.get('actionBasedTitle')),
            '# Attacks': len(insight.get('attacks'))
        }
        context_object = {
            'Id': insight_id,
            'Rerun': [{'Name': "Insight (Demisto) - {0}".format(insight.get('actionBasedTitle')),
                       'Id': response.get('runId'),
                       'AttacksCount': len(insight.get('attacks')),
                       'ScheduledTime': datetime.now().isoformat()}]
        }
        test_context_dict = {
            'Id': response.get('runId'),
            'Name': "Insight (Demisto) - {0}".format(insight.get('actionBasedTitle')),
            'Status': 'Pending',
            'AttacksCount': len(insight.get('attacks')),
            'ScheduledTime': datetime.now().isoformat()
        }
        readable_output = tableToMarkdown(name='Rerun SafeBreach Insight', t=t, removeNull=True)
        safebreach_context = {
            'SafeBreach.Insight(val.Id == obj.Id)': context_object,
            'SafeBreach.Test(val.Id == obj.Id)': test_context_dict,
        }
        return_outputs(readable_output=readable_output, outputs=safebreach_context, raw_response=context_object)
    except Exception as e:
        traceback.print_exc()
        DemistoException('Failed to rerun insight', e)


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
        insights = list([item for item in insights if int(item.get('ruleId')) in insight_ids])
    insight_output = []
    insight_readable = []
    headers = []

    for insight in insights:
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

        if response.status_code < 200 or response.status_code >= 300 or not response.json():
            raise ValueError(f'Failed to get status of test: {test_id}')
        try:
            response = response.json()
        except ValueError:
            raise ValueError('Response body does not contain valid json')
        t = {
            'Test Id': response['id'],
            'Name': response['matrixName'],
            'Status': response['status'],
            'Start Time': response['startTime'],
            'End Time': response['endTime'],
            'Total Simulation Number': response['blocked'] + response['notBlocked'] + response['internalFail']
        }
        readable_output = tableToMarkdown(name='Test Status', t=t, headers=list(t.keys()), removeNull=True)
        safebreach_context = {
            "SafeBreach.Test(val.Id == obj.Id)": {
                'Id': response['id'],
                'Name': response['matrixName'],
                'Status': response['status'],
                'StartTime': response['startTime'],
                'EndTime': response['endTime'],
                'TotalSimulationNumber': response['blocked'] + response['notBlocked']
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
    try:
        simulation_context = {
            'Id': simulation['id'],
            'FinalStatus': simulation['siemDetectionSummary'].lower().capitalize(),
            'Result': fetch_simulation_result(simulation),
            'DetectedAction': simulation.get('siemDetectionStatus').lower().capitalize(),
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
            'Status': simulation.get('siemDetectionSummary').lower().capitalize(),
            'Result': simulation.get('status').lower().capitalize(),
            'Detected Action': simulation.get('siemDetectionStatus').lower().capitalize(),
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


def safebreach_test_module(url: str, api_key: str) -> str:
    """A simple test module
       Arguments:
           url {String} -- SafeBreach Management URL.
       Returns:
           str -- "ok" if succeeded, else raises a error.
       """
    full_url = url + '/api/orch/v1/status'
    response = requests.request(
        'GET',
        full_url,
        headers={'Accept': 'application/json', 'x-apitoken': api_key}
    )
    if response.status_code < 200 or response.status_code >= 300:
        raise DemistoException('Test connection failed')
    return 'ok'


def main():
    command = demisto.command()
    params = demisto.params()
    account_id = params.get('accountId')
    api_key = params.get('apiKey')
    url = fix_url(params.get('url'))
    insight_category_filter = params.get('insightCategory')
    insight_data_type_filter = params.get('insightDataType')
    verify_certificate = not params.get('insecure', False)
    proxies = handle_proxy()
    try:
        client = Client(base_url=url, account_id=account_id, api_key=api_key, proxies=proxies,
                        verify=verify_certificate)

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
                                                demisto.args())
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
            demisto.results('ok')
        elif command == 'safebreach-get-indicators':
            indicators = get_indicators_command(client, insight_category_filter, insight_data_type_filter,
                                                demisto.args())
            entry_result = camelize(indicators)
            hr = tableToMarkdown('Indicators:', entry_result)
            return_outputs(hr, {}, entry_result)

        elif command == 'test-module':
            results = safebreach_test_module(url, api_key)
            return_outputs(results)
        else:
            return_error(f'Command: {command} is not supported.')

    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ["__builtin__", "builtins"]:
    main()
