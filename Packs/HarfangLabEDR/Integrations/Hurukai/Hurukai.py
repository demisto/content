import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json
import urllib3
import time
import traceback


from enum import Enum
from typing import Any, Dict
from datetime import datetime, timedelta, timezone
import dateutil.parser

# Disable insecure warnings
urllib3.disable_warnings()

"""Helper function"""

TACTICS = {
    'reconnaissance': 'Reconnaissance',
    'resource_development': 'Resource Development',
    'initial_access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege_escalation': 'Privilege Escalation',
    'defense_evasion': 'Defense Evasion',
    'credential_access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral_movement': 'Lateral Movement',
    'collection': 'Collection',
    'command_and_control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact'
}

SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

MAX_NUMBER_OF_ALERTS_PER_CALL = 25

HFL_SECURITY_EVENT_INCOMING_ARGS = ['status']
HFL_THREAT_INCOMING_ARGS = [
    'status',
    'security_event_count_by_level.critical',
    'security_event_count_by_level.high',
    'security_event_count_by_level.medium',
    'security_event_count_by_level.low',
    'mitre_tactics',
    'agents.agent_hostname',
    'last_seen',
    'rules.rule_name',
    'top_agents.agent_hostname',
    'top_impacted_users.user_name',
    'top_rules.rule_name',
    'impacted_users.full_name',
    'note.content'
]

SECURITY_EVENT_STATUS = {'new', 'probable_false_positive', 'false_positive', 'investigating', 'closed'}

STATUS_HFL_TO_XSOAR = {
    'new': 'New',
    'probable_false_positive': 'Closed',
    'false_positive': 'Closed',
    'investigating': 'In Progress',
    'closed': 'Closed'
}

STATUS_XSOAR_TO_HFL = {
    'New': 'new',
    'Reopened': 'investigating',
    'In Progress': 'investigating',
    'Closed': 'closed'
}

HFL_THREAT_OUTGOING_ARGS = {'status': f'Updated threat status, one of {"/".join(STATUS_HFL_TO_XSOAR.keys())}'}

HFL_SECURITY_EVENT_OUTGOING_ARGS = {
    'status': f'Updated security event status, one of {"/".join(STATUS_HFL_TO_XSOAR.keys())}'}

MIRROR_DIRECTION_DICT = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}


class IncidentType(Enum):
    SEC_EVENT = 'sec'
    THREAT = 'thr'


def _construct_request_parameters(args: dict, keys: list, params={}):
    """A helper function to add the keys arguments to the dict parameters"""

    parameters = {}
    if params is not None:
        for p in params:
            parameters[p] = params[p]

    for (arg_field, filter_field) in keys:
        value = args.get(arg_field, None)
        if value is not None:
            parameters[filter_field] = value

    return parameters


def _construct_output(results: list, keys: list):
    """A helper function to converts all results to a dict list with only the keys arguments"""

    output = []

    for col in results:
        row = {}
        for (label, data_keys) in keys:
            value = col
            if isinstance(data_keys, list):
                for key in data_keys:
                    value = value.get(key, None)
                    if value is None:
                        break
            else:
                value = value.get(data_keys, None)

            row[label] = value
        output.append(row)

    return output


class Client(BaseClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _http_request(self, *args, **kwargs):

        if kwargs.get('method', None) == 'GET' and len(kwargs.get('params', {})) > 0:
            params = kwargs.pop('params')
            suffix = kwargs.pop('url_suffix')

            suffix += '?{}'.format('&'.join([f'{k}={v}'
                                   for (k, v) in params.items()]))
            kwargs['url_suffix'] = suffix

        return super()._http_request(*args, **kwargs)

    def test_api(self):
        return self._http_request(
            method='GET',
            url_suffix='/api/version'
        )

    def get_api_token(self):
        data = assign_params(is_expirable=True)

        return self._http_request(
            method='POST',
            url_suffix='/api/user/api_token/',
            json_data=data
        )

    def get_endpoint_info(self, agent_id=None):
        if agent_id:
            return self._http_request(
                method='GET',
                url_suffix=f'/api/data/endpoint/Agent/{agent_id}/',
            )
        return None

    def api_call(self, api_method='GET', api_endpoint='/api/version', params={}, json_data={}):

        return self._http_request(
            method=api_method,
            url_suffix=api_endpoint,
            params=params,
            json_data=json_data
        )

    def endpoint_search(self, hostname=None, offset=0, threat_id=None, fields=None):

        fields_str = None
        if fields:
            fields_str = ','.join(fields)
        data = assign_params(hostname=hostname, offset=offset, threat_id=threat_id, fields=fields_str, limit=10000)

        return self._http_request(
            method='GET',
            url_suffix='/api/data/endpoint/Agent/',
            params=data
        )

    def user_search(self, threat_id=None, fields=None):

        fields_str = None
        if fields:
            fields_str = ','.join(fields)
        data = assign_params(offset=0, threat_id=threat_id, fields=fields_str, limit=10000)

        return self._http_request(
            method='GET',
            url_suffix='/api/data/host_properties/local_users/windows/',
            params=data
        )

    def data_hash_search(self, filehash=None):
        data = {}
        if filehash:
            data['values'] = filehash
            data['type'] = "hash"

        return self._http_request(
            method='GET',
            url_suffix='/api/data/search/Search/explorer_with_list/',
            params=data
        )

    def invest_running_process(self, filehash=None):
        data = {}
        if filehash:
            data['binaryinfo.binaryinfo.sha256'] = filehash

        return self._http_request(
            method='GET',
            url_suffix='/api/data/investigation/hunting/Process/',
            params=data
        )

    def invest_runned_process(self, filehash=None):
        data = {}
        if filehash:
            data['hashes.sha256'] = filehash

        return self._http_request(
            method='GET',
            url_suffix='/api/data/telemetry/Processes/',
            params=data
        )

    def job_create(self, agent_id, action, parameters=None):
        data = {
            'targets': {'agents': [agent_id]},
            'actions': [
                {
                    'value': action,
                    'params': parameters,
                }
            ]
        }

        demisto.debug(str(data))

        return self._http_request(
            method='POST',
            url_suffix='/api/data/Job/',
            json_data=data
        )

    def jobinstance_list(self, data=None):
        kwargs = {
            'method': 'GET',
            'url_suffix': '/api/data/JobInstance/',
        }

        if data is not None:
            kwargs['params'] = data

        return self._http_request(**kwargs)

    # EndPoint / Récupération de tous les processus d'une machine donnée avec le job fini
    def getProcess_list(self, job_id=None):
        url_suffix = f'/api/data/investigation/hunting/Process/?offset=0&job_id={job_id}&ordering=-name'

        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def job_info(self, job_id):
        return self._http_request(
            method='GET',
            url_suffix=f'/api/data/Job/{job_id}',
        )

    def job_data(self, job_id, job_type, ordering=None):
        job_types = {
            'pipe': '/api/data/investigation/hunting/Pipe/',
            'driver': '/api/data/investigation/hunting/Driver/',
            'prefetch': '/api/data/investigation/hunting/Prefetch/',
            'scheduledtask': '/api/data/investigation/hunting/ScheduledTaskXML/',
            'runkey': '/api/data/investigation/hunting/RunKey/',
            'service': '/api/data/investigation/hunting/Service/',
            'process': '/api/data/investigation/hunting/Process/',
            'startup': '/api/data/investigation/hunting/Startup/',
            'persistence': '/api/data/investigation/hunting/PersistanceFile/',
            'wmi': '/api/data/investigation/hunting/Wmi/',
            'networkshare': '/api/data/investigation/hunting/NetworkShare/',
            'session': '/api/data/investigation/hunting/Session/',
            'artifact': '/api/data/investigation/artefact/Artefact/',
            'ioc': '/api/data/investigation/ioc/IOC/',
        }
        url_suffix = f'{job_types[job_type]}?limit=10000&job_id={job_id}'
        if ordering is not None:
            url_suffix += f'&ordering={ordering}'

        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def telemetry_data(self, telemetry_type, params=None):
        telemetry_urls = {
            'processes': '/api/data/telemetry/Processes/',
            'binary': '/api/data/telemetry/Binary/',
            'network': '/api/data/telemetry/Network/',
            'eventlog': '/api/data/telemetry/FullEventLog/',
            'dns': '/api/data/telemetry/DNSResolution/',
            'windows_authentications': '/api/data/telemetry/authentication/AuthenticationWindows/',
            'linux_authentications': '/api/data/telemetry/authentication/AuthenticationLinux/',
            'macos_authentications': '/api/data/telemetry/authentication/AuthenticationMacos/'
        }

        kwargs = {
            'method': 'GET',
            'url_suffix': telemetry_urls[telemetry_type],
        }

        if params is not None:
            kwargs['params'] = params

        return self._http_request(**kwargs)

    def isolate_endpoint(self, agentid):
        return self._http_request(
            method='POST',
            url_suffix=f'/api/data/endpoint/Agent/{agentid}/isolate/',
        )

    def get_process_graph(self, process_uuid):
        return self._http_request(
            method='GET',
            url_suffix=f'/api/data/telemetry/Processes/{process_uuid}/graph/',
        )

    def search_whitelist(self, keyword, provided_by_hlab):
        return self._http_request(
            method='GET',
            url_suffix=f'/api/data/threat_intelligence/WhitelistRule/?'
                       f'offset=0&limit=100&search={keyword}&'
                       f'ordering=-last_update&provided_by_hlab={provided_by_hlab}',
        )

    def add_whitelist(self, comment, sigma_rule_id, target, field, case_insensitive, operator, value):

        data = {
            'comment': comment,
            'sigma_rule_id': sigma_rule_id,
            'target': target,
            'criteria': [
                {
                    'case_insensitive': case_insensitive,
                    'field': field,
                    'operator': operator,
                    'value': value
                }
            ]
        }

        return self._http_request(
            method='POST',
            url_suffix='/api/data/threat_intelligence/WhitelistRule/',
            json_data=data
        )

    def add_criterion_to_whitelist(self, id, field, case_insensitive, operator, value):

        data = self.get_whitelist(id)
        data['criteria'].append({
            'case_insensitive': case_insensitive,
            'field': field,
            'operator': operator,
            'value': value
        })

        return self._http_request(
            method='PUT',
            url_suffix=f'/api/data/threat_intelligence/WhitelistRule/{id}/',
            json_data=data
        )

    def get_whitelist(self, id):

        return self._http_request(
            method='GET',
            url_suffix=f'/api/data/threat_intelligence/WhitelistRule/{id}/'
        )

    def delete_whitelist(self, id):

        return self._http_request(
            method='DELETE',
            url_suffix=f'/api/data/threat_intelligence/WhitelistRule/{id}/',
            return_empty_response=True
        )

    def deisolate_endpoint(self, agentid):
        return self._http_request(
            method='POST',
            url_suffix=f'/api/data/endpoint/Agent/{agentid}/deisolate/',
        )

    def change_security_event_status(self, eventid, status):
        data = {}  # type: Dict[str,Any]

        if isinstance(eventid, list):
            data['ids'] = eventid
        else:
            data['ids'] = [eventid]

        if status.lower() == 'new':
            data['new_status'] = 'new'
        elif status.lower() == 'investigating':
            data['new_status'] = 'investigating'
        elif status.lower() == 'false positive':
            data['new_status'] = 'false_positive'
        elif status.lower() == 'closed':
            data['new_status'] = 'closed'

        return self._http_request(
            method='POST',
            url_suffix='/api/data/alert/alert/Alert/tag/',
            json_data=data
        )

    def change_threat_status(self, threat_id, status):
        data = {}  # type: Dict[str,Any]

        if isinstance(threat_id, list):
            data['id'] = threat_id
        else:
            data['id'] = [threat_id]

        if status.lower() == 'new':
            data['new_status'] = 'new'
        elif status.lower() == 'investigating':
            data['new_status'] = 'investigating'
        elif status.lower() == 'false positive':
            data['new_status'] = 'false_positive'
        elif status.lower() == 'closed':
            data['new_status'] = 'closed'

        data['tag_security_events'] = True
        data['update_by_query'] = True

        return self._http_request(
            method='PATCH',
            url_suffix='/api/data/alert/alert/Threat/status/',
            json_data=data
        )

    def update_threat_description(self, threat_id, content):

        threat = self._http_request(
            method='GET',
            url_suffix=f'/api/data/alert/alert/Threat/{threat_id}/'
        )

        return self._http_request(
            method='PATCH',
            url_suffix=f'/api/data/alert/alert/Threat/{threat_id}/note/',
            json_data={
                'title': threat['slug'],
                'content': content
            }
        )

    def list_policies(self, policy_name=None):
        data = {}

        if policy_name:
            data['search'] = policy_name

        return self._http_request(
            method='GET',
            url_suffix='/api/data/endpoint/Policy/',
            params=data
        )

    def list_sources(self, source_type='ioc', source_name=None):
        data = {}

        if source_name:
            data['search'] = source_name

        if source_type == 'yara':
            url_suffix = '/api/data/threat_intelligence/YaraSource/'
        elif source_type == 'sigma':
            url_suffix = '/api/data/threat_intelligence/SigmaSource/'
        elif source_type == 'ioc':
            url_suffix = '/api/data/threat_intelligence/IOCSource/'

        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=data
        )

    def search_ioc(self, ioc_value, source_id):
        data = {
            'source_id': source_id,
            'search': ioc_value
        }

        return self._http_request(
            method='GET',
            url_suffix='/api/data/threat_intelligence/IOCRule/',
            params=data
        )

    def add_ioc_to_source(self, ioc_value, ioc_type, ioc_comment, ioc_status, source_id):

        testing_status = None

        if ioc_status == 'testing':
            testing_status = 'in_progress'

        data = {
            'type': ioc_type,
            'value': ioc_value,
            'comment': ioc_comment,
            'source_id': source_id,
            'hl_status': ioc_status,
            'hl_local_testing_status': testing_status
        }

        return self._http_request(
            method='POST',
            url_suffix='/api/data/threat_intelligence/IOCRule/',
            json_data=data
        )

    def delete_ioc(self, ioc_id):
        return self._http_request(
            method='DELETE',
            url_suffix=f'/api/data/threat_intelligence/IOCRule/{ioc_id}/',
            return_empty_response=True
        )

    def assign_policy_to_agent(self, policyid, agentid):
        data = {
            'agent_ids': [agentid]
        }

        return self._http_request(
            method='POST',
            url_suffix=f'/api/data/endpoint/Policy/{policyid}/add_agents/',
            json_data=data
        )


def assign_policy_to_agent(client, args):
    context = {}
    policy_name = args.get('policy', None)

    results = client.list_policies(policy_name)
    policyid = None
    for policy in results['results']:
        if args['policy'] == policy['name']:
            policyid = policy['id']
            break
    if policyid:
        client.assign_policy_to_agent(policyid, args['agentid'])
        context['Message'] = f'Policy {policy_name} successfully assigned to agent {args["agentid"]}'
    else:
        context['Message'] = f'Unknown policy {policy_name}'

    return CommandResults(
        readable_output=context['Message'],
        outputs=context
    )


def test_module(client, args):
    result = client.test_api()
    if 'version' in result:
        return 'ok'
    else:
        return 'nok'


def fetch_incidents(client, args):
    last_run = demisto.getLastRun()

    if not last_run:
        last_run = [{}, {}]

    if not isinstance(last_run, list):
        last_run = [last_run, {}]

    current_fetch_info_sec_events: dict = last_run[0]
    current_fetch_info_threats: dict = last_run[1]

    max_fetch = args.get('max_fetch', None)
    fetch_types = args.get('fetch_types', [])

    if 'first_fetch' in args and args['first_fetch']:
        days = int(args['first_fetch'])
    else:
        days = 0
    first_fetch_time = int(datetime.timestamp(
        datetime.utcnow() - timedelta(days=days)) * 1000000)

    alert_status = args.get('alert_status', None)
    if alert_status == 'ACTIVE':
        status = ['new', 'probable_false_positive', 'investigating']
    elif alert_status == 'CLOSED':
        status = ['closed', 'false_positive']
    else:
        status = None

    incidents = []

    if 'Threats' in fetch_types:
        already_fetched_previous = []
        already_fetched_current = []

        last_fetch = None
        if current_fetch_info_threats:
            last_fetch = current_fetch_info_threats.get('last_fetch', None)
            already_fetched_previous = current_fetch_info_threats.get('already_fetched', [])

        if last_fetch is None:
            # if missing, use what provided via first_fetch_time
            last_fetch = first_fetch_time
        else:
            # otherwise use the stored last fetch
            last_fetch = int(last_fetch)

        latest_created_time_us = int(last_fetch)
        cursor = datetime.fromtimestamp(latest_created_time_us
                                        / 1000000).replace(tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        threats = get_threats(client,
                              min_created_timestamp=cursor,
                              threat_status=status,
                              min_severity=args.get('min_severity', SEVERITIES[0])
                              )

        for threat in threats:

            incident_created_time_us = int(datetime.timestamp(
                dateutil.parser.isoparse(threat.get('first_seen', '0'))) * 1000000)

            # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
            if incident_created_time_us <= latest_created_time_us:
                continue

            alert_id = threat.get('id', None)
            threat['incident_link'] = f'{client._base_url}/threat/{alert_id}/summary'

            threat['mirror_direction'] = MIRROR_DIRECTION_DICT.get(args.get('mirror_direction'))
            threat['mirror_instance'] = demisto.integrationInstance()
            threat['mirror_tags'] = ['comments', 'work_notes']
            threat['incident_type'] = 'Hurukai threat'

            if alert_id not in already_fetched_previous:
                incident = {
                    'name': threat.get('slug', None),
                    'occurred': threat.get('first_seen', None),
                    'severity': SEVERITIES.index(threat.get('level', '').capitalize()) + 1,
                    'rawJSON': json.dumps(threat)
                }
                incidents.append(incident)
                already_fetched_current.append(alert_id)

            if incident_created_time_us > latest_created_time_us:
                latest_created_time_us = incident_created_time_us

            if max_fetch and len(incidents) >= max_fetch:
                break

        current_fetch_info_threats = {'last_fetch': latest_created_time_us,
                                      'already_fetched': already_fetched_current}

    if 'Security Events' in fetch_types:

        already_fetched_previous = []
        already_fetched_current = []

        last_fetch = None
        if current_fetch_info_sec_events:
            last_fetch = current_fetch_info_sec_events.get('last_fetch', None)
            already_fetched_previous = current_fetch_info_sec_events.get('already_fetched', [])

        if last_fetch is None:
            # if missing, use what provided via first_fetch_time
            last_fetch = first_fetch_time
        else:
            # otherwise use the stored last fetch
            last_fetch = int(last_fetch)

        latest_created_time_us = int(last_fetch)
        cursor = datetime.fromtimestamp(latest_created_time_us
                                        / 1000000).replace(tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        sec_events = get_security_events(client,
                                         min_created_timestamp=cursor,
                                         alert_status=status,
                                         alert_type=args.get('alert_type'),
                                         min_severity=args.get('min_severity', SEVERITIES[0])
                                         )

        for sec_event in sec_events:

            incident_created_time_us = int(datetime.timestamp(
                dateutil.parser.isoparse(sec_event.get('alert_time', '0'))) * 1000000)

            # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
            if incident_created_time_us <= latest_created_time_us:
                continue

            alert_id = sec_event.get('id', None)
            sec_event['incident_link'] = f'{client._base_url}/security-event/{alert_id}/summary'

            sec_event['mirror_direction'] = MIRROR_DIRECTION_DICT.get(args.get('mirror_direction'))
            sec_event['mirror_instance'] = demisto.integrationInstance()
            sec_event['incident_type'] = 'Hurukai alert'

            if alert_id not in already_fetched_previous:
                incident = {
                    'name': sec_event.get('rule_name', None),
                    'occurred': sec_event.get('alert_time', None),
                    'severity': SEVERITIES.index(sec_event.get('level', '').capitalize()) + 1,
                    'rawJSON': json.dumps(sec_event)
                }
                incidents.append(incident)
                already_fetched_current.append(alert_id)

            if incident_created_time_us > latest_created_time_us:
                latest_created_time_us = incident_created_time_us

            if max_fetch and len(incidents) >= max_fetch:
                break

        current_fetch_info_sec_events = {'last_fetch': latest_created_time_us,
                                         'already_fetched': already_fetched_current}

    last_run = [current_fetch_info_sec_events, current_fetch_info_threats]
    demisto.setLastRun(last_run)
    demisto.incidents(incidents)

    return last_run, incidents


def get_endpoint_info(client, args):
    agent_id = args.get('agent_id', None)

    agent = client.get_endpoint_info(agent_id)

    readable_output = tableToMarkdown(
        f'Endpoint information for agent_id : {agent_id}', agent, removeNull=True)

    outputs = {
        'Harfanglab.Agent(val.agentid == obj.agentid)': agent
    }

    return_outputs(
        readable_output,
        outputs,
        agent
    )
    return agent


def api_call(client, args):
    api_method = args.get('api_method', 'GET').upper()
    api_endpoint = args.get('api_endpoint', '/api/version')
    params = args.get('parameters', None)
    json_data = args.get('data')
    if json_data:
        json_data = json.loads(json_data)

    parameters = {}
    if params:
        tokens = params.split('&')
        for tok in tokens:
            res = tok.split('=')
            if len(res) == 2:
                parameters[res[0]] = urllib.parse.quote_plus(res[1])

    result = client.api_call(api_method, api_endpoint, parameters, json_data)

    return CommandResults(
        outputs_prefix='Harfanglab.API',
        outputs=result
    )


def endpoint_search(client, args):
    hostname = args.get('hostname', None)

    data = client.endpoint_search(hostname)

    readable_output = tableToMarkdown(
        f'Endpoint information for Hostname : {hostname}', data['results'], removeNull=True)

    outputs = {
        'Harfanglab.Agent(val.agentid == obj.agentid)': data['results']
    }

    return_outputs(
        readable_output,
        outputs,
        data
    )
    return data


def get_frequent_users(client, args):
    authentications = {}
    output = []

    limit = int(args.get('limit'))
    del args['limit']

    for class_name in ['TelemetryWindowsAuthentication', 'TelemetryLinuxAuthentication',
                       'TelemetryMacosAuthentication']:

        if class_name == 'TelemetryWindowsAuthentication':
            args['logon_type'] = 2

        klass = globals()[class_name]
        instance = klass()

        data = instance.get_telemetry(client, args)

        if len(data['results']) > 0:
            for authentication in data['results']:
                username = authentication['target_username']
                if username not in authentications:
                    authentications[username] = 0
                authentications[username] += 1

            sorted_authentications = dict(sorted(authentications.items(), key=lambda item: item[1], reverse=True))

            for username in sorted_authentications:
                output.append({
                    'Username': username,
                    'Authentication attempts': sorted_authentications[username]
                })
                if limit and len(output) >= limit:
                    break

            readable_output = tableToMarkdown(f'Top {args.get("limit")} authentications', output, headers=[
                'Username', 'Authentication attempts'], removeNull=True)

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix='Harfanglab.Authentications.Users',
                outputs=output
            )


def job_create(client, args, parameters=None, can_use_previous_job=True):
    action = args.get('action', None)
    agent_id = args.get('agent_id', None)

    if action is None or agent_id is None:
        return False, None

    if can_use_previous_job:
        previous_job_id = find_previous_job(client, action, agent_id)
        if previous_job_id is not None:
            return True, previous_job_id

    data = client.job_create(agent_id, action, parameters)

    job_id = data[0]['id']
    return True, job_id


"""
    Returns a job status (context dict)
"""


def get_job_status(client, job_id):
    info = client.job_info(job_id)

    status = "running"

    if info['instance'] == info['done']:
        status = "finished"
    elif info['error'] > 0:
        status = "error"
    elif info['canceled'] > 0:
        status = "canceled"
    elif info['waiting'] > 0:
        status = "waiting"
    elif info['running'] > 0:
        status = "running"
    elif info['injecting'] > 0:
        status = "injecting"

    # Creation time formating
    time_info = info['creationtime'].split('.')
    time_info = time_info[0].replace('T', ' ').replace('Z', ' ')

    context = {
        'ID': job_id,
        'Status': status,
        'Creation date': time_info
    }
    return context


def job_info(client, args):
    # ret vals : starting, running, finished
    job_ids = argToList(str(args.get('ids', None)))

    context = []
    for job_id in job_ids:
        context.append(get_job_status(client, job_id))

    readable_output = tableToMarkdown('Jobs Info', context, headers=[
        'ID', 'Status', 'Creation date'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Job.Info',
        outputs_key_field='ID',
        outputs=context
    )


def find_previous_job(client, action, agent_id):
    starttime = (datetime.now(timezone.utc)
                 - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M')
    args = {
        'agent_id': agent_id,
        'action': action,
        'state': 2,
        'ordering': '-starttime',
        'starttime__gte': starttime
    }
    data = client.jobinstance_list(args)
    job_id = None
    if data['count'] > 0:
        job_id = data['results'][0]['job_id']

    return job_id


def common_result():
    # temporary, data need to reach ES
    time.sleep(10)


def common_job(job_id, job_type):
    context = {
        'ID': job_id,
        'Action': job_type
    }

    return CommandResults(
        readable_output=f'Job {job_id} started',
        outputs_prefix='Harfanglab.Job',
        outputs_key_field='ID',
        outputs=context

    )


def job_pipelist(client, args):
    args['action'] = 'getPipeList'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_pipelist(client, args):
    job_id = args.get('job_id', None)

    common_result()

    data = client.job_data(job_id, 'pipe', ordering='name')
    pipes = [x['name'] for x in data['results']]
    readable_output = tableToMarkdown(
        'Pipe List', pipes, headers=['name'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Pipe',
        outputs_key_field='name',
        outputs=pipes
    )


def job_prefetchlist(client, args):
    args['action'] = 'getPrefetch'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_prefetchlist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'prefetch', ordering='-last_executed')
    prefetchs = []
    for x in data['results']:
        executable_name = x['executable_name']
        last_executed = ''
        if len(x['last_executed']) > 0:
            last_executed = x['last_executed'][0]
        prefetchs.append({
            'executable name': executable_name,
            'last executed': last_executed
        })

    readable_output = tableToMarkdown('Prefetch List', prefetchs, headers=[
        'executable name', 'last executed'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Prefetch',
        outputs_key_field='name',
        outputs=prefetchs
    )


def job_runkeylist(client, args):
    args['action'] = 'getHives'
    parameters = {
        'bSystemHives': True,
        'bUsersHives': True,
        'bWantSlowPlugins': False
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_runkeylist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'runkey', ordering='-last_executed')
    output = []
    for x in data['results']:
        output.append({
            'name': x['name'],
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5', ''),
        })

    readable_output = tableToMarkdown('RunKey List', output, headers=[
        'name', 'fullpath', 'signed', 'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.RunKey',
        outputs_key_field='name',
        outputs=output
    )


def job_scheduledtasklist(client, args):
    args['action'] = 'getScheduledTasks'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_scheduledtasklist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'scheduledtask', ordering='short_name')
    output = []
    for x in data['results']:
        output.append({
            'name': x['short_name'],
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
        })

    readable_output = tableToMarkdown('Scheduled Task List', output, headers=[
        'name', 'fullpath', 'signed', 'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.ScheduledTask',
        outputs_key_field='name',
        outputs=output
    )


def job_linux_persistence_list(client, args):
    args['action'] = 'persistanceScanner'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_linux_persistence_list(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'persistence', ordering='short_name')
    output = []
    for x in data['results']:
        output.append({
            'type': x.get('persistance_type', None),
            'filename': x.get('binaryinfo', {}).get('filename', None),
            'fullpath': x.get('binaryinfo', {}).get('fullpath', None),
        })

    readable_output = tableToMarkdown('Linux persistence list', output, headers=[
        'type', 'filename', 'fullpath'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Persistence',
        outputs_key_field='filename',
        outputs=output
    )


def job_driverlist(client, args):
    args['action'] = 'getLoadedDriverList'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_driverlist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'driver', ordering='short_name')
    output = []
    for x in data['results']:
        output.append({
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
        })

    readable_output = tableToMarkdown('Driver List', output, headers=[
        'fullpath', 'signed', 'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Driver',
        outputs_key_field='md5',
        outputs=output
    )


def job_servicelist(client, args):
    args['action'] = 'getHives'
    parameters = {
        'bSystemHives': True,
        'bUsersHives': True,
        'bWantSlowPlugins': False
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_servicelist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'service', ordering='service_name')
    output = []
    for x in data['results']:
        output.append({
            'name': x['service_name'],
            'image path': x.get('image_path', None),
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
        })

    readable_output = tableToMarkdown('Service List', output, headers=[
        'name', 'image_path', 'fullpath', 'signed', 'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Service',
        outputs_key_field='md5',
        outputs=output
    )


def job_startuplist(client, args):
    args['action'] = 'getStartupFileList'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_startuplist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'startup', ordering='filename')
    output = []
    for x in data['results']:
        output.append({
            'startup_name': x['filename'],
            'startup_fullpath': x.get('fullpathfilename', x.get('fullpathname')),
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
        })

    readable_output = tableToMarkdown('Startup List', output, headers=[
        'startup_name',
        'startup_fullpath',
        'fullpath',
        'signed',
        'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Startup',
        outputs_key_field='md5',
        outputs=output
    )


def job_wmilist(client, args):
    args['action'] = 'getWMI'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_wmilist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'wmi', ordering='filename')
    output = []
    for x in data['results']:
        output.append({
            'filter to consumer type': x['filtertoconsumertype'],
            'event filter name': x['eventfiltername'],
            'event consumer name': x['eventconsumername'],
            'event filter': x['eventfilter'],
            'consumer data': x['consumerdata'],
        })

    readable_output = tableToMarkdown('WMI List', output, headers=[
        'filter to consumer type',
        'event filter name',
        'event consumer name',
        'event filter',
        'consumer data'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Wmi',
        outputs=output
    )


def job_processlist(client, args):
    args['action'] = 'getProcessList'
    parameters = {
        'getConnectionsList': False,
        'getHandlesList': False,
        'getSignaturesInfo': True
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_processlist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'process', ordering='name')
    output = []
    for x in data['results']:
        output.append({
            'name': x['name'],
            'session': x.get('session', None),
            'username': x.get('username', None),
            'integrity': x.get('integrity_level', None),
            'pid': x['pid'],
            'ppid': x['ppid'],
            'cmdline': x['cmdline'],
            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
        })

    readable_output = tableToMarkdown('Process List', output, headers=[
        'name',
        'session',
        'username',
        'integrity',
        'pid',
        'ppid',
        'cmdline',
        'fullpath',
        'signed',
        'md5'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Process',
        outputs_key_field='md5',
        outputs=output
    )


def job_networkconnectionlist(client, args):
    args['action'] = 'getProcessList'
    parameters = {
        'getConnectionsList': True,
        'getHandlesList': False,
        'getSignaturesInfo': True
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_networkconnectionlist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'process', ordering='name')
    output = []
    for x in data['results']:
        if 'connections' in x:
            fullpath = x.get('binaryinfo', {}).get('fullpath', '')
            signed = x.get('binaryinfo', {}).get(
                'binaryinfo', {}).get('signed', False)
            md5 = x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5')

            for connection in x['connections']:
                output.append({
                    'state': connection['connection_state'],
                    'protocol': connection['protocol'],
                    'version': connection['ip_version'],
                    'src_addr': connection['src_addr'],
                    'src_port': connection['src_port'],
                    'dst_addr': connection.get('dst_addr', None),
                    'dst_port': connection.get('dst_port', None),
                    'fullpath': fullpath,
                    'signed': signed,
                    'md5': md5,
                })

    readable_output = tableToMarkdown('Network Connection List',
                                      output,
                                      headers=[
                                          'state',
                                          'protocol',
                                          'version',
                                          'src_addr',
                                          'src_port',
                                          'dst_addr',
                                          'dst_port',
                                          'fullpath',
                                          'signed',
                                          'md5'],
                                      removeNull=True
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.NetworkConnection',
        outputs_key_field='md5',
        outputs=output
    )


def job_networksharelist(client, args):
    args['action'] = 'getNetworkShare'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_networksharelist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'networkshare', ordering='name')
    output = []
    for x in data['results']:
        output.append({
            'Name': x.get('name', ''),
            'Caption': x.get('caption', ''),
            'Description': x.get('description', ''),
            'Path': x.get('path', ''),
            'Status': x.get('status', ''),
            'Share type val': x.get('sharetypeval', ''),
            'Share type': x.get('sharetype', ''),
            'Hostname': x.get('agent', {}).get('hostname', '')
        })

    readable_output = tableToMarkdown('Network Share List',
                                      output,
                                      headers=[
                                          'Name',
                                          'Caption',
                                          'Description',
                                          'Path',
                                          'Status',
                                          'Share type val',
                                          'Share type',
                                          'Hostname'],
                                      removeNull=True
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.NetworkShare',
        outputs_key_field='Name',
        outputs=output
    )


def job_sessionlist(client, args):
    args['action'] = 'getSessions'
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_sessionlist(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'session', ordering='name')
    output = []
    for x in data['results']:
        output.append({
            'Logon Id': x.get('logonid', ''),
            'Authentication package': x.get('authenticationpackage', ''),
            'Logon type': x.get('logontype', ''),
            'Logon type str': x.get('logontypestr', ''),
            'Session start time': x.get('sessionstarttime', ''),
            'Hostname': x.get('agent', {}).get('hostname', '')
        })

    readable_output = tableToMarkdown('Session List',
                                      output,
                                      headers=[
                                          'Logon Id',
                                          'Authentication package',
                                          'Logon type',
                                          'Logon type str',
                                          'Session start time',
                                          'Hostname'
                                      ],
                                      removeNull=True
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Session',
        outputs_key_field='Logon Id',
        outputs=output
    )


def job_ioc(client, args):
    args['action'] = 'IOCScan'

    search_in_path = args.get('search_in_path', None)
    filename = args.get('filename', None)
    filepath = args.get('filepath', None)
    filepath_regex = args.get('filepath_regex', None)
    registry = args.get('registry', None)
    filehash = args.get('hash', None)
    filehash_size = args.get('hash_filesize', None)
    filesize = args.get('filesize', None)

    # filepath_regex = args.get('filepath_regex', None)
    # registry = args.get('registry', None)

    job_parameters = {'values': []}  # type: Dict[str,List[Dict[str,Any]]]
    good = False

    size = None

    if filesize:
        size = arg_to_number(filesize)
    elif filehash_size:
        size = arg_to_number(filehash_size)

    if filename is not None:
        job_parameters['values'].append({
            'global': False,
            'size': size,
            'type': 'filename',
            'value': filename
        })
        good = True
    if filepath is not None:
        job_parameters['values'].append({
            'global': False,
            'type': 'filepath',
            'value': filepath
        })
        good = True
    if filehash is not None:
        job_parameters['values'].append({
            'global': False,
            'size': size,
            'type': 'hash',
            'value': filehash
        })
        good = True
    if registry is not None:
        job_parameters['values'].append({
            'global': False,
            'type': 'registry',
            'value': registry
        })
        good = True
    if filepath_regex is not None:
        job_parameters['values'].append({
            'global': False,
            'type': 'regex',
            'value': filepath_regex
        })
        good = True

    if good and search_in_path is not None:
        job_parameters['values'].append({
            'global': True,
            'type': 'path',
            'value': search_in_path
        })

    if not good:
        return False

    ret, job_id = job_create(
        client, args, job_parameters, can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_ioc(client, args):
    job_id = args.get('job_id', None)
    common_result()

    data = client.job_data(job_id, 'ioc', ordering='name')
    output = []
    for x in data['results']:
        output.append({
            'type': x['hit_type'],
            'search_value': x['search_value'],

            'fullpath': x.get('binaryinfo', {}).get('fullpath', ''),
            'signed': x.get('binaryinfo', {}).get('binaryinfo', {}).get('signed', False),
            'md5': x.get('binaryinfo', {}).get('binaryinfo', {}).get('md5'),
            'registry_path': x.get('found_registry_path'),
            'registry_key': x.get('found_registry_key'),
            'registry_value': x.get('found_registry_value'),
        })

    readable_output = tableToMarkdown('IOC Found List',
                                      output,
                                      headers=[
                                          'type',
                                          'search_value',
                                          'fullpath',
                                          'signed',
                                          'md5',
                                          'registry_path',
                                          'registry_key',
                                          'registry_value'
                                      ],
                                      removeNull=True
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.IOC',
        outputs_key_field='md5',
        outputs=output
    )


def global_job_artifact(client, args, parameters, artifact_type):
    args['action'] = 'collectRAWEvidences'
    ret, job_id = job_create(client, args, parameters,
                             can_use_previous_job=False)

    if not ret:
        return False

    return common_job(job_id, args['action'])


def global_result_artifact(client, args, artifact_type):
    job_id = args.get('job_id', None)
    common_result()

    result = {}
    info = get_job_status(client, job_id)
    result = info

    if info['Status'] != 'finished':
        return CommandResults(
            readable_output=f'Job results not available (Job status: {info["Status"]})',
            outputs_prefix='Harfanglab.Artifact'
        )

    base_url = client._base_url
    data = client.job_data(job_id, 'artifact')
    api_token = None
    token = client.get_api_token()
    if 'api_token' in token:
        api_token = token['api_token']

    output = []
    for i in range(len(data['results'])):
        result = data['results'][i]
        if api_token is not None:
            result['download_link'] = f'{base_url}/api/data/investigation/artefact/Artefact/{result["id"]}/download/'
            result['download_link'] += f'?hl_expiring_key={api_token}'
        else:
            result['download_link'] = 'N/A'

        output.append({
            'hostname': result['agent']['hostname'],
            'msg': result['msg'],
            'size': result['size'],
            'download link': result['download_link']
        })

    readable_output = tableToMarkdown(f'{artifact_type} download list', output, headers=[
        'hostname', 'msg', 'size', 'download link'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Artifact',
        outputs=output
    )


def job_artifact_mft(client, args):
    parameters = {'hives': False, 'evt': False, 'mft': True,
                  'prefetch': False, 'usn': False, 'logs': False, 'fs': False}
    return global_job_artifact(client, args, parameters, 'MFT')


def result_artifact_mft(client, args):
    return global_result_artifact(client, args, 'MFT')


def job_artifact_evtx(client, args):
    parameters = {'hives': False, 'evt': True, 'mft': False,
                  'prefetch': False, 'usn': False, 'logs': False, 'fs': False}
    return global_job_artifact(client, args, parameters, 'EVTX')


def result_artifact_evtx(client, args):
    return global_result_artifact(client, args, 'EVTX')


def job_artifact_logs(client, args):
    parameters = {'hives': False, 'evt': False, 'mft': False,
                  'prefetch': False, 'usn': False, 'logs': True, 'fs': False}
    return global_job_artifact(client, args, parameters, 'LOGS')


def result_artifact_logs(client, args):
    return global_result_artifact(client, args, 'LOGS')


def job_artifact_fs(client, args):
    parameters = {'hives': False, 'evt': False, 'mft': False,
                  'prefetch': False, 'usn': False, 'logs': False, 'fs': True}
    return global_job_artifact(client, args, parameters, 'FS')


def result_artifact_fs(client, args):
    return global_result_artifact(client, args, 'FS')


def job_artifact_hives(client, args):
    parameters = {'hives': True, 'evt': False, 'mft': False,
                  'prefetch': False, 'usn': False, 'logs': False, 'fs': False}
    return global_job_artifact(client, args, parameters, 'HIVES')


def result_artifact_hives(client, args):
    return global_result_artifact(client, args, 'HIVES')


def job_artifact_all(client, args):
    parameters = {'hives': True, 'evt': True, 'mft': True,
                  'prefetch': True, 'usn': True, 'logs': True, 'fs': True}
    return global_job_artifact(client, args, parameters, 'ALL')


def result_artifact_all(client, args):
    return global_result_artifact(client, args, 'ALL')


def job_artifact_downloadfile(client, args):
    args['action'] = 'downloadFile'
    filename = args.get('filename', None)
    parameters = {'filename': filename}

    ret, job_id = job_create(client, args, parameters,
                             can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_artifact_downloadfile(client, args):
    job_id = args.get('job_id', None)
    common_result()

    base_url = client._base_url
    data = client.job_data(job_id, 'artifact', ordering='name')

    api_token = None
    token = client.get_api_token()
    if 'api_token' in token:
        api_token = token['api_token']

    output = []
    for x in data['results']:

        if api_token is not None:
            link = f'{base_url}/api/data/investigation/artefact/Artefact/{x["id"]}/download/?hl_expiring_key={api_token}'
        else:
            link = 'N/A'

        output.append({
            'hostname': x['agent']['hostname'],
            'msg': x['msg'],
            'size': x['size'],
            'download link': link
        })

    readable_output = tableToMarkdown('file download list', output, headers=[
        'hostname', 'msg', 'size', 'download link'], removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.DownloadFile',
        outputs=output
    )


def job_artifact_ramdump(client, args):
    args['action'] = 'memoryDumper'

    ret, job_id = job_create(client, args, can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args['action'])


def result_artifact_ramdump(client, args):
    job_id = args.get('job_id', None)
    common_result()

    base_url = client._base_url
    data = client.job_data(job_id, 'artifact', ordering='name')

    api_token = None
    token = client.get_api_token()
    if 'api_token' in token:
        api_token = token['api_token']

    output = []
    for x in data['results']:
        link = f'{base_url}/api/data/investigation/artefact/Artefact/{x["id"]}/download/'
        link += f'?hl_expiring_key={api_token}'
        output.append({
            'hostname': x['agent']['hostname'],
            'msg': x['msg'],
            'size': x['size'],
            'download link': link
        })

    readable_output = tableToMarkdown('Ramdump list', output, headers=['hostname', 'msg', 'size', 'download link'],
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Ramdump',
        outputs=output
    )


def get_process_graph(client, args):
    process_uuid = args.get('process_uuid', None)

    data = client.get_process_graph(process_uuid)

    return CommandResults(
        outputs_prefix='Harfanglab.ProcessGraph',
        outputs_key_field='current_process_id',
        outputs=data
    )


def search_whitelist(client, args):
    keyword = args.get('keyword', None)
    provided_by_hlab = args.get('provided_by_hlab', False)

    data = client.search_whitelist(keyword, provided_by_hlab)

    for wl in data['results']:
        criteria = []
        for c in wl['criteria']:
            criteria.append(f'{c["field"]} {c["operator"]} {c["value"]}')
        wl['criteria_str'] = ', '.join(criteria)

    readable_output = tableToMarkdown(
        f'Whitelists found for keyword: {keyword}',
        data['results'],
        headers=['comment', 'creation_date', 'last_update', 'target', 'criteria_str', 'sigma_rule_name'],
        removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Harfanglab.Whitelists',
        outputs=data['results']
    )


def add_whitelist(client, args):
    comment = args.get('comment', None)
    sigma_rule_id = args.get('sigma_rule_id', "")
    target = args.get('target', "all")
    field = args.get('field', None)
    case_insensitive = args.get('case_insensitive', True)
    operator = args.get('operator', 'eq')
    value = args.get('value', None)

    message = None
    data = None

    if target not in ['all', 'sigma', 'yara', 'hlai', 'vt', 'ransom', 'orion', 'glimps', 'cape', 'driver']:
        message = 'Invalid target. ' \
                  'Target must be "all", "sigma", ' \
                  '"yara", "hlai", "vt", "ransom", ' \
                  '"orion", "glimps", "cape" or "driver"'
    elif operator not in ['eq', 'regex', 'contains']:
        message = 'Invalid operator. Operator must be "eq", "regex", or "contains"'
    else:
        data = client.add_whitelist(comment, sigma_rule_id, target, field, case_insensitive, operator, value)
        message = 'Successfully added whitelist'

    return CommandResults(
        readable_output=message,
        outputs_prefix='Harfanglab.Whitelists',
        outputs=data
    )


def add_criterion_to_whitelist(client, args):
    id = args.get('id', None)
    field = args.get('field', None)
    case_insensitive = args.get('case_insensitive', True)
    operator = args.get('operator', 'eq')
    value = args.get('value', None)

    message = None
    data = None

    if operator not in ['eq', 'regex', 'contains']:
        message = 'Invalid operator. Operator must be "eq", "regex", or "contains"'
    else:

        data = client.add_criterion_to_whitelist(id, field, case_insensitive, operator, value)
        message = 'Successfully added criterion to whitelist'

    return CommandResults(
        readable_output=message,
        outputs_prefix='Harfanglab.Whitelists',
        outputs=data
    )


def delete_whitelist(client, args):
    id = args.get('id', None)

    client.delete_whitelist(id)

    return CommandResults(
        readable_output='Successfully deleted whitelist'
    )


def hunt_search_hash(client, args):
    filehash = args.get('hash', None)
    common_result()

    results = []

    if isinstance(filehash, list):
        for i in filehash:
            args['hash'] = i
            hunt_search_hash(client, args)
        return None
    else:
        data = client.data_hash_search(filehash=filehash)
        prefetchs = []
        curr_running = False
        prev_runned = False

        if len(data['data']) == 0:
            currently_running = str(curr_running) + " (0 are running)"
            previously_executed = str(prev_runned) + " (0 were previously executed)"
            prefetchs.append({
                'process associated to hash currently running': currently_running,
                'process associated to hash was previously executed': previously_executed
            })

            outputs = {
                'hash': filehash,
                'curr_running': 0,
                'prev_runned': 0
            }
            results.append(CommandResults(
                outputs_prefix='Harfanglab.Hash',
                outputs_key_field='hash',
                outputs=outputs,
                readable_output=tableToMarkdown(
                    'Hash search results', outputs, removeNull=True)
            ))

        for x in data['data']:
            if x['processCount'] > 0:
                curr_running = True
            if x['telemetryProcessCount'] > 0:
                prev_runned = True
            currently_running = str(
                curr_running) + " (" + str(x['processCount']) + " are running)"
            previously_executed = str(
                prev_runned) + " (" + str(x['telemetryProcessCount']) + " were previously executed)"
            prefetchs.append({
                'process associated to hash currently running': currently_running,
                'process associated to hash was previously executed': previously_executed
            })

            outputs = {
                'hash': x['title'],
                'curr_running': x['processCount'],
                'prev_runned': x['telemetryProcessCount']
            }
            results.append(CommandResults(
                outputs_prefix='Harfanglab.Hash',
                outputs_key_field='hash',
                outputs=outputs,
                readable_output=tableToMarkdown(
                    'Hash search results', outputs, removeNull=True)
            ))

        return_results(results)

        return outputs


def hunt_search_running_process_hash(client, args):
    filehash = args.get('hash', None)
    common_result()

    if isinstance(filehash, list):
        for i in filehash:
            args['hash'] = i
            hunt_search_running_process_hash(client, args)
        return None
    else:
        data = client.invest_running_process(filehash=filehash)
        prefetchs = []
        for x in data['results']:
            prefetchs.append({
                "Hostname": x['agent']['hostname'],
                "Domain": x['agent'].get('domainname', ''),
                "Username": x['username'],
                "OS": x['agent']['osproducttype'],
                "OS Version": x['agent']['osversion'],
                "Binary Path": x['binaryinfo']['fullpath'],
                "Hash": filehash,
                "Create timestamp": x['create_time'],
                "Is maybe hollow": x['maybe_hollow']
            })

        readable_output = tableToMarkdown('War room overview', prefetchs, headers=[
            "Hostname",
            "Domain",
            "Username",
            "OS",
            "OS Version",
            "Binary Path",
            "Hash",
            "Create timestamp",
            "Is maybe hollow"], removeNull=True)

        return CommandResults(
            outputs_prefix='Harfanglab.HuntRunningProcessSearch',
            outputs_key_field='hash',
            outputs=prefetchs,
            readable_output=readable_output
        )


def hunt_search_runned_process_hash(client, args):
    filehash = args.get('hash', None)
    common_result()

    if isinstance(filehash, list):
        for i in filehash:
            args['hash'] = i
            hunt_search_runned_process_hash(client, args)
        return None
    else:
        data = client.invest_runned_process(filehash=filehash)
        prefetchs = []
        for x in data['results']:
            prefetchs.append({
                "Hostname": x['agent']['hostname'],
                "Domain": x['agent'].get('domainname', ''),
                "Username": x['username'],
                "OS": x['agent']['osproducttype'],
                "OS Version": x['agent']['osversion'],
                "Binary Path": x['image_name'],
                "Hash": filehash,
                "Create timestamp": x.get('pe_timestamp', '')
            })

        readable_output = tableToMarkdown('War room overview',
                                          prefetchs,
                                          headers=[
                                              "Hostname",
                                              "Domain",
                                              "Username",
                                              "OS",
                                              "Binary Path",
                                              "Create timestamp"
                                          ],
                                          removeNull=True)

        return CommandResults(
            outputs_prefix='Harfanglab.HuntRunnedProcessSearch',
            outputs_key_field='hash',
            outputs=prefetchs,
            readable_output=readable_output
        )


def isolate_endpoint(client, args) -> CommandResults:
    agentid = args.get('agent_id', None)
    data = client.isolate_endpoint(agentid)

    context = {'Status': False, 'Message': ''}  # type: Dict[str,Any]

    if agentid in data['requested']:
        context['Status'] = True
        context['Message'] = 'Agent isolation successfully requested'

    if agentid in data['policy_not_allowed']:
        context['Status'] = False
        context['Message'] = 'Agent isolation request failed (not allowed by the agent policy)'

    return CommandResults(
        outputs_prefix='Harfanglab.Isolation',
        outputs=context,
        readable_output=context['Message']
    )


def deisolate_endpoint(client, args) -> CommandResults:
    agentid = args.get('agent_id', None)
    data = client.deisolate_endpoint(agentid)

    context = {'Status': False, 'Message': ''}  # type: Dict[str,Any]

    if agentid in data['requested']:
        context['Status'] = True
        context['Message'] = 'Agent deisolation successfully requested'

    return CommandResults(
        outputs_prefix='Harfanglab.Unisolation',
        outputs=context,
        readable_output=context['Message']
    )


def change_security_event_status(client, args) -> CommandResults:
    eventid = args.get('security_event_id', None)
    status = args.get('status', None)

    client.change_security_event_status(eventid, status)

    context = {}
    context['Message'] = f'Status for security event {eventid} changed to {status}'

    return CommandResults(
        outputs=context,
        readable_output=context['Message']
    )


def add_ioc_to_source(client, args):
    ioc_value = args.get('ioc_value', None)
    ioc_type = args.get('ioc_type', None)
    ioc_comment = args.get('ioc_comment', '')
    ioc_status = args.get('ioc_status', '')
    source_name = args.get('source_name', None)

    results = client.list_sources(source_type='ioc', source_name=source_name)

    source_id = None

    for source in results['results']:
        if source['name'] == source_name:
            source_id = source['id']

    results = client.search_ioc(ioc_value, source_id)

    context = {}
    if results['count'] > 0:
        context['Message'] = f'IOC {ioc_value} already exists in source {source_name}'
    else:
        client.add_ioc_to_source(
            ioc_value, ioc_type, ioc_comment, ioc_status, source_id)
        context[
            'Message'] = f'IOC {ioc_value} of type {ioc_type} added to source {source_name} with {ioc_status} status'

    return CommandResults(
        outputs=context,
        readable_output=context['Message']
    )


def delete_ioc_from_source(client, args):
    ioc_value = args.get('ioc_value', None)
    source_name = args.get('source_name', None)

    results = client.list_sources(source_type='ioc', source_name=source_name)

    source_id = None

    for source in results['results']:
        if source['name'] == source_name:
            source_id = source['id']

    results = client.search_ioc(ioc_value=ioc_value, source_id=source_id)

    context = {}
    if results['count'] > 0:
        ioc_id = results['results'][0]['id']
        client.delete_ioc(ioc_id)
        context['Message'] = f'IOC {ioc_value} removed from source {source_name}'
    else:
        context['Message'] = f'IOC {ioc_value} does not exist in source {source_name}'

    return CommandResults(
        outputs=context,
        readable_output=context['Message']
    )


class Telemetry:

    def __init__(self):
        self.params = {}

        # Keys is an array of tuple with (args field, filter field)
        self.keys = [
            ('to_date', '@event_create_date__lte'),
            ('from_date', '@event_create_date__gte'),
            ('hostname', 'agent.hostname'),
            ('limit', 'limit'),
        ]

        # Output keys is an array of tuple with (output name `label`, data field)
        self.output_keys = []

        self.title = ''
        self.telemetry_type = ''

    def _add_hash_parameters(self, binary_hash=None):
        if binary_hash is not None:
            if len(binary_hash) == 64:
                hash_type = "sha256"
            elif len(binary_hash) == 40:
                hash_type = "sha1"
            elif len(binary_hash) == 32:
                hash_type = "md5"

            self.params[f'hashes.{hash_type}'] = binary_hash

    def _construct_output(self, results, client=None):
        # Global helper to construct output list
        return _construct_output(results, self.output_keys)

    def get_telemetry(self, client, args):
        self.params = _construct_request_parameters(
            args, self.keys, params=self.params)

        # Execute request with params
        return client.telemetry_data(self.telemetry_type, self.params)

    def telemetry(self, client, args):

        data = self.get_telemetry(client, args)
        output = self._construct_output(data['results'], client)

        # Determines headers for readable output
        headers = list(output[0].keys()) if len(
            output) > 0 else []
        readable_output = tableToMarkdown(
            self.title, output, headers=headers, removeNull=True)

        return CommandResults(
            outputs_prefix=f'Harfanglab.Telemetry{self.telemetry_type}',
            outputs=output,
            readable_output=readable_output
        )


class TelemetryProcesses(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('process_name', 'process_name'),
            ('image_name', 'image_name'),
        ]
        self.output_keys = [
            ('process_unique_id', 'process_unique_id'),
            ('create date', '@event_create_date'),
            ('hostname', ['agent', 'hostname']),
            ('process name', 'process_name'),
            ('image name', 'image_name'),
            ('commandline', 'commandline'),
            ('integrity level', 'integrity_level'),
            ('parent image', 'parent_image'),
            ('parent commandline', 'parent_commandline'),
            ('username', 'username'),
            ('signed', 'signed'),
            ('signer', ['signature_info', 'signer_info', 'display_name']),
            ('sha256', ['hashes', 'sha256']),
        ]

        self.title = 'Processes list'
        self.telemetry_type = 'processes'

    def telemetry(self, client, args):
        binary_hash = args.get('hash', None)
        self._add_hash_parameters(binary_hash)
        return super().telemetry(client, args)


class TelemetryDNSResolution(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('requested_name', 'requested_name'),
            ('query_type', 'query_type'),
        ]
        self.output_keys = [
            ('create date', '@event_create_date'),
            ('hostname', ['agent', 'hostname']),
            ('agentid', ['agent', 'agentid']),
            ('process image path', 'process_image_path'),
            ('pid', 'pid'),
            ('process unique id', 'process_unique_id'),
            ('requested name', 'requested_name'),
            ('query type', 'query_type'),
            ('IP addresses', 'ip_addresses'),
            ('tenant', 'tenant')
        ]

        self.title = 'DNS Resolutions'
        self.telemetry_type = 'dns'

    def telemetry(self, client, args):
        return super().telemetry(client, args)


class TelemetryWindowsAuthentication(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('source_address', 'source_address'),
            ('success', 'success'),
            ('source_username', 'source_username'),
            ('target_username', 'target_username'),
            ('logon_title', 'windows.logon_title'),
            ('logon_type', 'windows.logon_type'),
        ]
        self.output_keys = [
            ('timestamp', '@timestamp'),
            ('hostname', ['agent', 'hostname']),
            ('agentid', ['agent', 'agentid']),
            ('source address', 'source_address'),
            ('source username', 'source_username'),
            ('target username', 'target_username'),
            ('success', 'success'),
            ('event id', ['windows', 'event_id']),
            ('event title', ['windows', 'event_title']),
            ('logon process name', ['windows', 'logon_process_name']),
            ('logon title', ['windows', 'logon_title']),
            ('logon type', ['windows', 'logon_type']),
            ('process name', 'process_name')
        ]

        self.title = 'Windows Authentications'
        self.telemetry_type = 'windows_authentications'


class TelemetryLinuxAuthentication(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('source_address', 'source_address'),
            ('success', 'success'),
            ('source_username', 'source_username'),
            ('target_username', 'target_username'),
        ]
        self.output_keys = [
            ('timestamp', '@timestamp'),
            ('hostname', ['agent', 'hostname']),
            ('agentid', ['agent', 'agentid']),
            ('source address', 'source_address'),
            ('source username', 'source_username'),
            ('target username', 'target_username'),
            ('success', 'success'),
            ('tty', ['linux', 'tty']),
            ('target uid', ['linux', 'target_uid']),
            ('target group', ['linux', 'target_group']),
            ('target gid', ['linux', 'target_gid']),
            ('process name', 'process_name'),
            ('pid', 'pid')

        ]

        self.title = 'Linux Authentications'
        self.telemetry_type = 'linux_authentications'


class TelemetryMacosAuthentication(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('source_address', 'source_address'),
            ('success', 'success'),
            ('source_username', 'source_username'),
            ('target_username', 'target_username'),
        ]
        self.output_keys = [
            ('timestamp', '@timestamp'),
            ('hostname', ['agent', 'hostname']),
            ('agentid', ['agent', 'agentid']),
            ('source address', 'source_address'),
            ('source username', 'source_username'),
            ('target username', 'target_username'),
            ('success', 'success'),
            ('tty', ['linux', 'tty']),
            ('target uid', ['linux', 'target_uid']),
            ('target group', ['linux', 'target_group']),
            ('target gid', ['linux', 'target_gid']),
            ('process name', 'process_name'),
            ('pid', 'pid')

        ]

        self.title = 'Macos Authentications'
        self.telemetry_type = 'macos_authentications'


class TelemetryNetwork(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('source_address', 'saddr'),
            ('source_port', 'sport'),
            ('destination_address', 'daddr'),
            ('destination_port', 'dport'),
        ]
        self.output_keys = [
            ('create date', '@event_create_date'),
            ('hostname', ['agent', 'hostname']),
            ('image name', 'image_name'),
            ('username', 'username'),
            ('source address', 'saddr'),
            ('source port', 'sport'),
            ('destination addr', 'daddr'),
            ('destination port', 'dport'),
            ('direction', 'direction')
        ]

        self.title = 'Network list'
        self.telemetry_type = 'network'


class TelemetryEventLog(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('event_id', 'event_id'),
        ]
        self.output_keys = [
            ('create date', '@event_create_date'),
            ('hostname', ['agent', 'hostname']),
            ('event id', 'event_id'),
            ('source name', 'source_name'),
            ('log name', 'log_name'),
            ('keywords', 'keywords'),
            ('event data', 'event_data'),
            ('level', 'level')
        ]

        self.title = 'Event Log list'
        self.telemetry_type = 'eventlog'


class TelemetryBinary(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys = [
            ('name', 'names'),
            ('path', 'fullpaths'),
            ('filesize_min', 'filesize__gte'),
            ('filesize_max', 'filesize__lte'),
            ('exact_filesize', 'filesize'),
        ]
        self.output_keys += [
            ('process name', 'process_name'),
            ('image name', 'image_name'),
            ('commandline', 'commandline'),
            ('integrity level', 'integrity_level'),
            ('parent image', 'parent_image'),
            ('parent commandline', 'parent_commandline'),
            ('username', 'username'),
            ('signed', 'signed'),
            ('signer', ['signature_info', 'signer_info', 'display_name']),
            ('sha256', ['hashes', 'sha256']),
        ]

        self.title = 'Binary list'
        self.telemetry_type = 'binary'

    def _construct_output(self, results, client):
        """Download with an API token is not supported yet"""
        api_token = client.get_api_token().get('api_token')

        output = []
        for x in results:
            for i in range(0, len(x['names'])):
                name = x['names'][i]
                path = x['paths'][i] if len(x['paths']) > i else None

                link = None
                if x['downloaded'] == 0:
                    link = f'{client._base_url}/api/data/telemetry/Binary/download/{x["hashes"]["sha256"]}/'
                    if api_token:
                        link += f'?hl_expiring_key={api_token}'

                output.append({
                    'name': name,
                    'path': path,
                    'size': x['size'],
                    'signed': x.get('signed', ''),
                    'signer': x.get('signature_info', {}).get('signer_info', {}).get('display_name', None),
                    'sha256': x['hashes'].get('sha256', None),
                    'download link': link,
                })

        return output

    def telemetry(self, client, args):
        binary_hash = args.get('hash', None)
        self._add_hash_parameters(binary_hash)
        return super().telemetry(client, args)


def get_function_from_command_name(command):
    commands = {
        'harfanglab-get-endpoint-info': get_endpoint_info,
        'harfanglab-endpoint-search': endpoint_search,
        'harfanglab-job-info': job_info,

        'harfanglab-job-pipelist': job_pipelist,
        'harfanglab-result-pipelist': result_pipelist,

        'harfanglab-job-prefetchlist': job_prefetchlist,
        'harfanglab-result-prefetchlist': result_prefetchlist,

        'harfanglab-job-runkeylist': job_runkeylist,
        'harfanglab-result-runkeylist': result_runkeylist,

        'harfanglab-job-scheduledtasklist': job_scheduledtasklist,
        'harfanglab-result-scheduledtasklist': result_scheduledtasklist,

        'harfanglab-job-driverlist': job_driverlist,
        'harfanglab-result-driverlist': result_driverlist,

        'harfanglab-job-servicelist': job_servicelist,
        'harfanglab-result-servicelist': result_servicelist,

        'harfanglab-job-processlist': job_processlist,
        'harfanglab-result-processlist': result_processlist,

        'harfanglab-job-networkconnectionlist': job_networkconnectionlist,
        'harfanglab-result-networkconnectionlist': result_networkconnectionlist,

        'harfanglab-job-networksharelist': job_networksharelist,
        'harfanglab-result-networksharelist': result_networksharelist,

        'harfanglab-job-sessionlist': job_sessionlist,
        'harfanglab-result-sessionlist': result_sessionlist,

        'harfanglab-job-persistencelist': job_linux_persistence_list,
        'harfanglab-result-persistencelist': result_linux_persistence_list,

        'harfanglab-job-ioc': job_ioc,
        'harfanglab-result-ioc': result_ioc,

        'harfanglab-job-startuplist': job_startuplist,
        'harfanglab-result-startuplist': result_startuplist,

        'harfanglab-job-wmilist': job_wmilist,
        'harfanglab-result-wmilist': result_wmilist,

        'harfanglab-job-artifact-mft': job_artifact_mft,
        'harfanglab-result-artifact-mft': result_artifact_mft,

        'harfanglab-job-artifact-hives': job_artifact_hives,
        'harfanglab-result-artifact-hives': result_artifact_hives,

        'harfanglab-job-artifact-evtx': job_artifact_evtx,
        'harfanglab-result-artifact-evtx': result_artifact_evtx,

        'harfanglab-job-artifact-logs': job_artifact_logs,
        'harfanglab-result-artifact-logs': result_artifact_logs,

        'harfanglab-job-artifact-filesystem': job_artifact_fs,
        'harfanglab-result-artifact-filesystem': result_artifact_fs,

        'harfanglab-job-artifact-all': job_artifact_all,
        'harfanglab-result-artifact-all': result_artifact_all,

        'harfanglab-job-artifact-downloadfile': job_artifact_downloadfile,
        'harfanglab-result-artifact-downloadfile': result_artifact_downloadfile,

        'harfanglab-job-artifact-ramdump': job_artifact_ramdump,
        'harfanglab-result-artifact-ramdump': result_artifact_ramdump,

        'harfanglab-telemetry-processes': TelemetryProcesses().telemetry,
        'harfanglab-telemetry-network': TelemetryNetwork().telemetry,
        'harfanglab-telemetry-eventlog': TelemetryEventLog().telemetry,
        'harfanglab-telemetry-binary': TelemetryBinary().telemetry,
        'harfanglab-telemetry-dns': TelemetryDNSResolution().telemetry,
        'harfanglab-telemetry-authentication-windows': TelemetryWindowsAuthentication().telemetry,
        'harfanglab-telemetry-authentication-linux': TelemetryLinuxAuthentication().telemetry,
        'harfanglab-telemetry-authentication-macos': TelemetryMacosAuthentication().telemetry,
        'harfanglab-telemetry-authentication-users': get_frequent_users,
        'harfanglab-telemetry-process-graph': get_process_graph,

        'harfanglab-hunt-search-hash': hunt_search_hash,
        'harfanglab-hunt-search-running-process-hash': hunt_search_running_process_hash,
        'harfanglab-hunt-search-runned-process-hash': hunt_search_runned_process_hash,

        'harfanglab-isolate-endpoint': isolate_endpoint,
        'harfanglab-deisolate-endpoint': deisolate_endpoint,

        'harfanglab-change-security-event-status': change_security_event_status,

        'harfanglab-assign-policy-to-agent': assign_policy_to_agent,
        'harfanglab-add-ioc-to-source': add_ioc_to_source,
        'harfanglab-delete-ioc-from-source': delete_ioc_from_source,

        'harfanglab-whitelist-search': search_whitelist,
        'harfanglab-whitelist-add': add_whitelist,
        'harfanglab-whitelist-add-criterion': add_criterion_to_whitelist,
        'harfanglab-whitelist-delete': delete_whitelist,

        'harfanglab-api-call': api_call,

        'fetch-incidents': fetch_incidents,
        'get-modified-remote-data': get_modified_remote_data,
        'get-remote-data': get_remote_data,
        'update-remote-system': update_remote_system,
        'get-mapping-fields': get_mapping_fields,
        'test-module': test_module
    }

    return commands.get(command)


def get_security_events(client, security_event_ids=None, min_created_timestamp=None, min_updated_timestamp=None,
                        alert_status=None, alert_type=None, min_severity=SEVERITIES[0], max_fetch=None, fields=None,
                        limit=MAX_NUMBER_OF_ALERTS_PER_CALL, ordering='alert_time', threat_id=None):
    security_events = []

    agents: Dict[str, Any] = {}

    if security_event_ids:
        for sec_evt_id in security_event_ids:
            results = client._http_request(
                method='GET',
                url_suffix=f'/api/data/alert/alert/Alert/{sec_evt_id}/details/'
            )

            alert = results['alert']

            # Retrieve additional endpoint information
            groups = []
            agent = None
            agentid = alert.get('agent', {}).get('agentid', None)
            if agentid:
                if agentid in agents:
                    agent = agents[agentid]
                else:
                    try:
                        agent = client.get_endpoint_info(agentid)
                    except Exception:
                        agent = None
                    agents[agentid] = agent

                if agent:
                    for g in agent.get('groups', []):
                        groups.append(g['name'])
                    alert['agent']['policy_name'] = agent.get('policy', {}).get('name')
                    alert['agent']['groups'] = groups

            security_events.append(alert)

        return security_events

    args = {
        'ordering': ordering,
        'level': ','.join(SEVERITIES[SEVERITIES.index(min_severity):]).lower(),
        'limit': limit,
        'offset': 0
    }  # type: Dict[str,Any]

    if alert_status == 'ACTIVE':
        args['status'] = ','.join(['new', 'probable_false_positive', 'investigating'])
    elif alert_status == 'CLOSED':
        args['status'] = ','.join(['closed', 'false_positive'])

    if alert_type:
        args['alert_type'] = alert_type

    if min_created_timestamp:
        args['alert_time__gte'] = min_created_timestamp

    if min_updated_timestamp:
        if not fields:
            fields = []
        if 'last_update' not in fields:
            fields.append('last_update')

    if fields:
        args['fields'] = ','.join(fields)

    if threat_id:
        args['threat_key'] = threat_id

    if min_updated_timestamp:
        args['last_update__gte'] = min_updated_timestamp

    demisto.debug(f'Args for fetch_security_events: {args}')

    while True:

        results = client._http_request(
            method='GET',
            url_suffix='/api/data/alert/alert/Alert/',
            params=args
        )

        demisto.debug(f'Got {len(results["results"])} security events')

        for alert in results['results']:

            alert_id = alert.get('id', None)
            alert['incident_link'] = f'{client._base_url}/security-event/{alert_id}/summary'

            # Retrieve additional endpoint information
            groups = []
            agent = None
            agentid = alert.get('agent', {}).get('agentid', None)
            if agentid:
                if agentid in agents:
                    agent = agents[agentid]
                else:
                    try:
                        agent = client.get_endpoint_info(agentid)
                    except Exception:
                        agent = None
                    agents[agentid] = agent

                if agent:
                    for g in agent.get('groups', []):
                        groups.append(g['name'])
                    alert['agent']['policy_name'] = agent.get('policy', {}).get('name')
                    alert['agent']['groups'] = groups

            security_events.append(alert)

            if max_fetch and len(security_events) >= max_fetch:
                break

        demisto.debug(f'Got eventually {len(security_events)} security events')

        args['offset'] += len(results['results'])
        if results['count'] == 0 or not results['next'] or (max_fetch and len(security_events) >= max_fetch):
            break

    return security_events


def enrich_threat(client, threat):
    if not client or not threat or 'id' not in threat:
        return

    threat_id = threat.get('id')

    if not threat_id:
        return

    # Get agents
    results = client.endpoint_search(threat_id=threat_id,
                                     fields=['id', 'hostname', 'domainname', 'osproducttype', 'ostype'])
    threat['agents'] = results['results']

    # Get users
    results = client.user_search(threat_id=threat_id)
    threat['impacted_users'] = results['results']

    # Get rules
    args = assign_params(threat_id=threat_id, fields='rule_level,rule_name,security_event_count')
    results = client._http_request(
        method='GET',
        url_suffix='/api/data/alert/alert/Threat/rules/',
        params=args
    )
    threat['rules'] = results['results']


def get_threats(client, threat_ids=None, min_created_timestamp=None, min_updated_timestamp=None, threat_status=None,
                min_severity=SEVERITIES[0], max_fetch=None, fields=None, limit=MAX_NUMBER_OF_ALERTS_PER_CALL,
                ordering='last_seen'):
    threats = []

    if not threat_ids:
        threat_ids = []
        args = {
            'ordering': ordering,
            'level': ','.join(SEVERITIES[SEVERITIES.index(min_severity):]).lower(),
            'limit': limit,
            'offset': 0
        }  # type: Dict[str,Any]

        if threat_status == 'ACTIVE':
            args['status'] = ','.join(['new', 'investigating'])
        elif threat_status == 'CLOSED':
            args['status'] = ','.join(['closed', 'false_positive'])

        if min_created_timestamp:
            args['from'] = min_created_timestamp

        if min_updated_timestamp:
            args['last_update__gte'] = min_updated_timestamp

        args['fields'] = 'id'

        demisto.debug(f'Args for get_threats: {args}')

        while True:
            results = client._http_request(
                method='GET',
                url_suffix='/api/data/alert/alert/Threat/',
                params=args
            )
            demisto.debug(f'Got {len(results["results"])} threats')

            for threat in results['results']:
                threat_ids.append(threat['id'])

                if max_fetch and len(threat_ids) >= max_fetch:
                    break

            args['offset'] += len(results['results'])
            if results['count'] == 0 or not results['next'] or (max_fetch and len(threat_ids) >= max_fetch):
                break

    for threat_id in threat_ids:
        threat = client._http_request(
            method='GET',
            url_suffix=f'/api/data/alert/alert/Threat/{threat_id}/'
        )
        enrich_threat(client, threat)

        threat_id = threat.get('id', None)
        threat['incident_link'] = f'{client._base_url}/threat/{threat_id}/summary'

        threats.append(threat)

    return threats


def get_modified_remote_data(client, args):
    """
    Gets the modified remote security events and threat IDs.
    Args:
        args:
            last_update: the last time we retrieved modified security events and threats.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved security events and threat IDs.
    """
    demisto.debug('In get_modified_remote_data')
    remote_args = GetModifiedRemoteDataArgs(args)

    last_update_utc = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    assert last_update_utc is not None, f"could not parse{remote_args.last_update}"
    last_update_timestamp = last_update_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    demisto.debug(f'Remote arguments last_update in UTC is {last_update_timestamp}')

    modified_ids_to_mirror = list()

    # Fetch the latest security events and retrieve those whose last update fields is more recent than the last update timestamp
    sec_events = get_security_events(client,
                                     min_updated_timestamp=last_update_timestamp,
                                     alert_type=args.get('alert_type'),
                                     min_severity=args.get('min_severity', SEVERITIES[0]),
                                     fields=['id', 'last_update'],
                                     limit=10000,
                                     ordering='-alert_time')

    for sec_event in sec_events:
        modified_ids_to_mirror.append(f'{IncidentType.SEC_EVENT.value}:{sec_event["id"]}')

    threats = get_threats(client,
                          min_updated_timestamp=last_update_timestamp,
                          min_severity=args.get('min_severity', SEVERITIES[0]),
                          fields=['id'],
                          limit=10000,
                          ordering='-last_seen')

    for threat in threats:
        modified_ids_to_mirror.append(f'{IncidentType.THREAT.value}:{threat["id"]}')

    demisto.debug(f'All ids to mirror in are: {modified_ids_to_mirror}')
    return GetModifiedRemoteDataResponse(modified_ids_to_mirror)


def find_incident_type(remote_incident_id: str):
    if remote_incident_id[0:3] == IncidentType.SEC_EVENT.value:
        return IncidentType.SEC_EVENT
    if remote_incident_id[0:3] == IncidentType.THREAT.value:
        return IncidentType.THREAT


def set_updated_object(updated_object: Dict[str, Any], mirrored_data: Dict[str, Any], mirroring_fields: List[str]):
    """
    Sets the updated object (in place) for the security event or threat we want to mirror in, from the mirrored data, according to
    the mirroring fields. In the mirrored data, the mirroring fields might be nested in a dict or in a dict inside a list (if so,
    their name will have a dot in it).
    Note that the fields that we mirror right now may have only one dot in them, so we only deal with this case.

    :param updated_object: The dictionary to set its values, so it will hold the fields we want to mirror in, with their values.
    :param mirrored_data: The data of the security event or threat we want to mirror in.
    :param mirroring_fields: The mirroring fields that we want to mirror in, given according to whether we want to mirror a
        security event or a threat.
    """
    for field in mirroring_fields:
        if mirrored_data.get(field):
            updated_object[field] = mirrored_data.get(field)

        # if the field is not in mirrored_data, it might be a nested field - that has a . in its name
        elif '.' in field:
            field_name_parts = field.split('.')
            nested_mirrored_data = mirrored_data.get(field_name_parts[0])

            if isinstance(nested_mirrored_data, list):
                # if it is a list, it should hold a dictionary in it because it is a json structure
                for nested_field in nested_mirrored_data:
                    if nested_field.get(field_name_parts[1]):
                        updated_object[field] = nested_field.get(field_name_parts[1])
                        # finding the field in the first time it is satisfying
                        break
            elif isinstance(nested_mirrored_data, dict):
                if nested_mirrored_data.get(field_name_parts[1]):
                    updated_object[field_name_parts[0]] = {}
                    updated_object[field_name_parts[0]][field_name_parts[1]] = nested_mirrored_data.get(
                        field_name_parts[1])


def get_remote_secevent_data(client, remote_incident_id: str):
    """
    Called every time get-remote-data command runs on a security event.
    Gets the relevant security event entity from the remote system (HarfangLab EDR). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_security_events(
        client, security_event_ids=[remote_incident_id])
    mirrored_data = mirrored_data_list[0]

    if 'status' in mirrored_data:
        mirrored_data['status'] = STATUS_HFL_TO_XSOAR.get(mirrored_data.get('status'))

    updated_object: Dict[str, Any] = {'incident_type': 'Hurukai alert'}
    set_updated_object(updated_object, mirrored_data, HFL_SECURITY_EVENT_INCOMING_ARGS)
    return mirrored_data, updated_object


def get_remote_threat_data(client, remote_incident_id: str):
    """
    Called every time get-remote-data command runs on a threat.
    Gets the relevant threat entity from the remote system (HarfangLab EDR). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_threats(
        client, threat_ids=[remote_incident_id])
    mirrored_data = mirrored_data_list[0]

    if 'status' in mirrored_data:
        mirrored_data['status'] = STATUS_HFL_TO_XSOAR.get(mirrored_data.get('status'))

    updated_object: Dict[str, Any] = {'incident_type': 'Hurukai threat'}
    set_updated_object(updated_object, mirrored_data, HFL_THREAT_INCOMING_ARGS)
    return mirrored_data, updated_object


def close_in_xsoar(entries: List, remote_incident_id: str, incident_type_name: str):
    demisto.debug(f'{incident_type_name} is closed: {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentClose': True,
            'closeReason': f'{incident_type_name} was closed on HarfangLab EDR'
        },
        'ContentsFormat': EntryFormat.JSON
    })


def reopen_in_xsoar(entries: List, remote_incident_id: str, incident_type_name: str):
    demisto.debug(f'{incident_type_name} is reopened: {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    })


def set_xsoar_security_events_entries(updated_object: Dict[str, Any], entries: List, remote_incident_id: str):
    if demisto.params().get('close_incident'):
        if updated_object.get('status') == 'Closed':
            close_in_xsoar(entries, remote_incident_id, 'Hurukai alert')
        elif updated_object.get('status') in (set(STATUS_XSOAR_TO_HFL.keys()) - {'Closed'}):
            reopen_in_xsoar(entries, remote_incident_id, 'Hurukai alert')


def set_xsoar_threats_entries(updated_object: Dict[str, Any], entries: List, remote_incident_id: str):
    if demisto.params().get('close_incident'):
        if updated_object.get('status') == 'Closed':
            close_in_xsoar(entries, remote_incident_id, 'Hurukai threat')
        elif updated_object.get('status') in (set(STATUS_XSOAR_TO_HFL.keys()) - {'Closed'}):
            reopen_in_xsoar(entries, remote_incident_id, 'Hurukai threat')


def get_remote_data(client, args):
    """
    get-remote-data command: Returns an updated remote security event or threat.
    Args:
        args:
            id: security event or threat id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the security event or threat data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id

    mirrored_data = {}
    entries: List = []
    updated_object = None

    try:
        demisto.debug(f'Performing get-remote-data command with incident or detection id: {remote_incident_id} '
                      f'and last_update: {remote_args.last_update}')
        incident_type = find_incident_type(remote_incident_id)
        if incident_type == IncidentType.SEC_EVENT:
            mirrored_data, updated_object = get_remote_secevent_data(client, remote_incident_id[4:])
            if updated_object:
                demisto.debug(f'Update security event {remote_incident_id} with fields: {updated_object}')
                set_xsoar_security_events_entries(updated_object, entries, remote_incident_id)  # sets in place

        elif incident_type == IncidentType.THREAT:
            mirrored_data, updated_object = get_remote_threat_data(client, remote_incident_id[4:])
            if updated_object:
                demisto.debug(f'Update threat {remote_incident_id} with fields: {updated_object}')
                set_xsoar_threats_entries(updated_object, entries, remote_incident_id)  # sets in place
        else:
            # this is here as prints can disrupt mirroring
            raise Exception(f'Executed get-remote-data command with undefined id: {remote_incident_id}')

        if not updated_object:
            demisto.debug(f'No delta was found for detection {remote_incident_id}.')

        demisto.debug(f'Updated object {updated_object}')

        return GetRemoteDataResponse(mirrored_object=updated_object, entries=entries)

    except Exception as e:
        demisto.debug(f"Error in HarfangLab EDR incoming mirror for security event or threat: {remote_incident_id}\n"
                      f"Error message: {str(e)}")

        if not mirrored_data:
            mirrored_data = {'id': remote_incident_id}
        mirrored_data['in_mirror_error'] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def close_in_hfl(delta: Dict[str, Any]) -> bool:
    """
    Closing in the remote system should happen only when both:
        1. The user asked for it
        2. One of the closing fields appears in the delta

    The second is mandatory so we will not send a closing request at all of the mirroring requests that happen after closing an
    incident (in case where the incident is updated so there is a delta, but it is not the status that was changed).
    """
    closing_fields = {'closeReason', 'closingUserId', 'closeNotes'}
    return demisto.params().get('close_in_hfl') and any(field in delta for field in closing_fields)


def update_security_event_request(client, ids: List[str], status: str) -> str:
    if status not in SECURITY_EVENT_STATUS:
        raise DemistoException(f'HarfangLab EDR Error: '
                               f'Status given is {status} and it is not in {SECURITY_EVENT_STATUS}')

    for eventid in ids:
        client.change_security_event_status(eventid, status)
    return 'OK'


def update_threat_request(client, ids: List[str], status: str) -> str:
    if status not in SECURITY_EVENT_STATUS:
        raise DemistoException(f'HarfangLab EDR Error: '
                               f'Status given is {status} and it is not in {SECURITY_EVENT_STATUS}')

    for threatid in ids:
        client.change_threat_status(threatid, status)
    return 'OK'


def update_remote_security_event(client, delta, inc_status: IncidentStatus, detection_id: str) -> str:

    if inc_status == IncidentStatus.DONE and close_in_hfl(delta):
        demisto.debug(f'Closing security event with remote ID {detection_id} in remote system.')
        return str(update_security_event_request(client, [detection_id[4:]], 'closed'))

    # status field in HarfangLab EDR is mapped to State field in XSOAR
    elif inc_status == IncidentStatus.PENDING:
        demisto.debug(
            f'Security Event with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_security_event_request(client, [detection_id[4:]], 'new'))

    elif inc_status == IncidentStatus.ACTIVE:
        demisto.debug(
            f'Security Event with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_security_event_request(client, [detection_id[4:]], 'investigating'))

    return ''


def update_remote_threat(client, delta, inc_status: IncidentStatus, detection_id: str) -> str:
    demisto.debug(
        f'Delta {delta}')

    if 'details' in delta:
        client.update_threat_description(detection_id[4:], delta['details'])

    if inc_status == IncidentStatus.DONE and close_in_hfl(delta):
        demisto.debug(f'Closing security event with remote ID {detection_id} in remote system.')
        return str(update_threat_request(client, [detection_id[4:]], 'closed'))

    # status field in HarfangLab EDR is mapped to State field in XSOAR
    elif inc_status == IncidentStatus.PENDING:
        demisto.debug(
            f'Threat with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_threat_request(client, [detection_id[4:]], 'new'))

    elif inc_status == IncidentStatus.ACTIVE:
        demisto.debug(
            f'Threat with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_threat_request(client, [detection_id[4:]], 'investigating'))

    return ''


def update_remote_system(client, args):
    """
    Mirrors out local changes to the remote system.
    Args:
        args: A dictionary containing the data regarding a modified incident, including: data, entries, incident_changed,
         remote_incident_id, inc_status, delta

    Returns:
        The remote incident id that was modified. This is important when the incident is newly created remotely.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    entries = parsed_args.entries
    remote_incident_id = parsed_args.remote_incident_id

    if delta:
        demisto.debug(f'Got the following delta keys {list(delta.keys())}.')
        demisto.debug(f'Got the following entries {entries}.')

    try:
        incident_type = find_incident_type(remote_incident_id)
        if parsed_args.incident_changed and delta:
            if incident_type == IncidentType.SEC_EVENT:
                demisto.debug(f'Updating remote security event {remote_incident_id}')
                result = update_remote_security_event(client, delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Security event updated successfully. Result: {result}')

            elif incident_type == IncidentType.THREAT:
                demisto.debug(f'Updating remote threat {remote_incident_id}')
                result = update_remote_threat(client, delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Threat updated successfully. Result: {result}')
            else:
                raise Exception(f'Executed update-remote-system command with undefined id: {remote_incident_id}')

        else:
            pass
            # demisto.debug(f"Skipping updating remote security event or threat {remote_incident_id} as it didn't change.")

    except Exception as e:
        demisto.error(f'Error in HarfangLab EDR outgoing mirror for security event or threat {remote_incident_id}. '
                      f'Error message: {str(e)}')

    return remote_incident_id


def get_mapping_fields(client, args) -> GetMappingFieldsResponse:
    """
        Returns the list of fields to map in outgoing mirroring, for incidents and detections.
    """

    demisto.debug('In get_mapping_fields')
    mapping_response = GetMappingFieldsResponse()

    security_event_type_scheme = SchemeTypeMapping(type_name='HarfangLab EDR Security Event')
    for argument, description in HFL_SECURITY_EVENT_OUTGOING_ARGS.items():
        security_event_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(security_event_type_scheme)

    threat_type_scheme = SchemeTypeMapping(type_name='HarfangLab EDR Threat')
    for argument, description in HFL_THREAT_OUTGOING_ARGS.items():
        threat_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(threat_type_scheme)

    return mapping_response


def main():
    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    base_url = demisto.params().get('url').rstrip('/')
    api_key = demisto.params().get('credentials', {}).get('password', '') or demisto.params().get("apikey", '')

    try:
        headers = {
            'Authorization': f'Token {api_key}'
        }

        client = Client(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
        )

        command = demisto.command()
        target_function = get_function_from_command_name(command)

        if target_function is None:
            raise Exception(f'unknown command : {command}')

        args = demisto.args()
        if command == 'fetch-incidents':
            args['first_fetch'] = demisto.params().get('first_fetch', None)
            args['alert_status'] = demisto.params().get('alert_status', None)
            args['alert_type'] = demisto.params().get('alert_type', None)
            args['min_severity'] = demisto.params().get(
                'min_severity', SEVERITIES[0])
            args['max_fetch'] = demisto.params().get('max_fetch', None)
            args['mirror_direction'] = demisto.params().get('mirror_direction', None)
            args['fetch_types'] = demisto.params().get('fetch_types', None)
        return_results(target_function(client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
