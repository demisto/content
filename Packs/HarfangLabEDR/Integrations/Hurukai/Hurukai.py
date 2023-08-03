import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json
import urllib3
import time
import traceback

from typing import Any
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

    def endpoint_search(self, hostname=None, offset=0):

        data = assign_params(hostname=hostname, offset=offset)

        return self._http_request(
            method='GET',
            url_suffix='/api/data/endpoint/Agent/',
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

        if status == 'New':
            data['new_status'] = 'new'
        elif status == 'Investigating':
            data['new_status'] = 'investigating'
        elif status == 'False Positive':
            data['new_status'] = 'false_positive'
        elif status == 'Closed':
            data['new_status'] = 'closed'

        return self._http_request(
            method='POST',
            url_suffix='/api/data/alert/alert/Alert/tag/',
            json_data=data
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
            url_suffix='/api/data/threat_intelligence/IOCIndicator/',
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
            url_suffix='/api/data/threat_intelligence/IOCIndicator/',
            json_data=data
        )

    def delete_ioc(self, ioc_id):
        return self._http_request(
            method='DELETE',
            url_suffix=f'/api/data/threat_intelligence/IOCIndicator/{ioc_id}/',
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

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
    })


def test_module(client, args):
    result = client.test_api()
    if 'version' in result:
        demisto.results('ok')
    else:
        demisto.results('failed to access version endpoint')


def fetch_incidents(client, args):

    last_run = demisto.getLastRun()

    days = int(args['first_fetch']) if 'first_fetch' in args and args['first_fetch'] else 0
    first_fetch_time = int(datetime.timestamp(
        datetime.now() - timedelta(days=days)) * 1000000)
    alert_status = args.get('alert_status', None)
    alert_type = args.get('alert_type', None)
    min_severity = args.get('min_severity', SEVERITIES[0])
    max_results = args.get('max_fetch', None)

    severity = ','.join(SEVERITIES[SEVERITIES.index(min_severity):]).lower()

    already_fetched_previous = []
    already_fetched_current = []

    last_fetch = None
    if last_run:
        last_fetch = last_run.get('last_fetch', None)
        already_fetched_previous = last_run.get('already_fetched', [])

    last_fetch = first_fetch_time if last_fetch is None else int(last_fetch)

    if alert_status == 'ACTIVE':
        status = ['new', 'probable_false_positive', 'investigating']
    elif alert_status == 'CLOSED':
        status = ['closed', 'false_positive']
    else:
        status = None

    args = {
        'ordering': '+alert_time',
        'level': severity,
        'limit': MAX_NUMBER_OF_ALERTS_PER_CALL,
        'offset': 0
    }  # type: Dict[str,Any]

    if status:
        args['status'] = ','.join(status)

    if alert_type:
        args['alert_type'] = alert_type

    latest_created_time_us = 0

    if last_fetch:
        latest_created_time_us = int(last_fetch)
        cursor = datetime.fromtimestamp(latest_created_time_us
                                        / 1000000).replace(tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        args['alert_time__gte'] = cursor

    incidents = []
    total_number_of_alerts = 0

    while True:

        results = client._http_request(
            method='GET',
            url_suffix='/api/data/alert/alert/Alert/',
            params=args
        )

        if 'count' in results and 'results' in results:
            for alert in results['results']:
                incident_created_time_us = int(datetime.timestamp(
                    dateutil.parser.isoparse(alert.get('alert_time', '0'))) * 1000000)

                # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
                if last_fetch and incident_created_time_us <= latest_created_time_us:
                    continue

                tags = alert.get('tags', [])
                tactic = []
                technique_id = []

                for tag in tags:
                    if tag.startswith('attack'):
                        content = tag[7:]
                        if content in TACTICS:
                            tactic.append(TACTICS[content])
                        elif content[0] == 't':
                            technique_id.append(content)

                alert_id = alert.get('id', None)
                alert['incident_link'] = f'{client._base_url}/security-event/{alert_id}/summary'
                incident = {
                    'name': alert.get('rule_name', None),
                    'occurred': alert.get('alert_time', None),
                    'severity': SEVERITIES.index(alert.get('level', '').capitalize()) + 1,
                    'rawJSON': json.dumps(alert)
                }

                if alert_id not in already_fetched_previous:
                    incidents.append(incident)
                    already_fetched_current.append(alert_id)

                if incident_created_time_us > latest_created_time_us:
                    latest_created_time_us = incident_created_time_us

                total_number_of_alerts += 1
                if max_results and total_number_of_alerts >= max_results:
                    break

        args['offset'] += len(results['results'])
        if results['count'] == 0 or not results['next'] or (max_results and total_number_of_alerts >= max_results):
            break

    next_run = {'last_fetch': latest_created_time_us,
                'already_fetched': already_fetched_current}

    demisto.setLastRun(next_run)
    demisto.incidents(incidents)

    return next_run, incidents


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

    ec = {
        'Harfanglab.Job.Info(val.ID && val.ID == obj.ID)': context,
    }
    readable_output = tableToMarkdown('Jobs Info', context, headers=[
                                      'ID', 'Status', 'Creation date'], removeNull=True)

    entry = {
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    }

    demisto.results(entry)
    return context


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

    ec = {
        f'Harfanglab.Job(val.ID && val.ID == {job_id})': context,
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        # 'ReadableContentsFormat': formats['markdown'],
        # 'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return context


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

    ec = {
        'Harfanglab.Pipe(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': pipes,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': pipes,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return pipes


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

    ec = {
        'Harfanglab.Prefetch(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': prefetchs,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': prefetchs,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return prefetchs


def job_runkeylist(client, args):
    args['action'] = 'getHives'
    ret, job_id = job_create(client, args)

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

    ec = {
        'Harfanglab.RunKey(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    ec = {
        'Harfanglab.ScheduledTask(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    ec = {
        'Harfanglab.Persistence(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    ec = {
        'Harfanglab.Driver(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


def job_servicelist(client, args):
    args['action'] = 'getHives'
    ret, job_id = job_create(client, args)

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

    readable_output = tableToMarkdown('Scheduled Task List', output, headers=[
                                      'name', 'image_path', 'fullpath', 'signed', 'md5'], removeNull=True)

    ec = {
        'Harfanglab.Service(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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
            'startup_fullpath': x['fullpathfilename'],
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

    ec = {
        'Harfanglab.Startup(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    ec = {
        'Harfanglab.Wmi(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


def job_processlist(client, args):
    args['action'] = 'getProcessList'
    ret, job_id = job_create(client, args)

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

    ec = {
        'Harfanglab.Process(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


def job_networkconnectionlist(client, args):
    args['action'] = 'getProcessList'
    ret, job_id = job_create(client, args)

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

    readable_output = tableToMarkdown('Network Connection List', output, headers=[
        'state', 'protocol', 'version', 'src_addr', 'src_port', 'dst_addr', 'dst_port', 'fullpath', 'signed', 'md5'],
        removeNull=True
    )

    ec = {
        'Harfanglab.NetworkConnection(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    readable_output = tableToMarkdown('Network Share List', output, headers=[
        'Name', 'Caption', 'Description', 'Path', 'Status', 'Share type val', 'Share type', 'Hostname'], removeNull=True
    )

    ec = {
        'Harfanglab.NetworkShare(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    readable_output = tableToMarkdown('Session List', output, headers=[
        'Logon Id', 'Authentication package', 'Logon type', 'Logon type str', 'Session start time', 'Hostname'], removeNull=True
    )

    ec = {
        'Harfanglab.Session(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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

    readable_output = tableToMarkdown('IOC Found List', output, headers=[
        'type', 'search_value', 'fullpath', 'signed', 'md5', 'registry_path', 'registry_key', 'registry_value'], removeNull=True
    )

    ec = {
        'Harfanglab.IOC(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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
        ec = {
            'Harfanglab.Artifact(val.agent_id && val.agent_id === obj.agent_id)': {
                f'{artifact_type}': {},
                'data': ''
            }
        }
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': {},
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'Job results not available (Job status: {})'.format(info['Status']),
            'EntryContext': ec
        })
        return result

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

    ec = {
        'Harfanglab.Artifact(val.agent_id && val.agent_id === obj.agent_id)': {
            f'{artifact_type}': data['results'],
            'data': data['results'][0]['download_link'] if len(data['results']) > 0 else ''
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    result['Results'] = output
    return result


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

    ec = {
        'Harfanglab.DownloadFile(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })

    return data


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

    ec = {
        'Harfanglab.Ramdump(val.agent_id && val.agent_id === obj.agent_id)': {
            'data': output,
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': ec
    })
    return output


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
            previously_executed = str(prev_runned) + \
                " (0 were previously executed)"
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

        return data


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
        contextData = []
        for x in data['results']:
            prefetchs.append({
                "Hostname": x['agent']['hostname'],
                "Domain": x['agent'].get('domainname', ''),
                "Username": x['username'],
                "OS": x['agent']['osproducttype'] + " " + x['agent']['osversion'],
                "Binary Path": x['binaryinfo']['fullpath'],
                "Create timestamp": x['create_time'],
                "Is maybe hollow": x['maybe_hollow']
            })
            contextData.append({
                'hash': filehash,
                "hostname": x['agent']['hostname'],
                "domain": x['agent'].get('domainname', ''),
                "username": x['username'],
                "os": x['agent']['osproducttype'],
                "os_version": x['agent']['osversion'],
                "path": x['binaryinfo']['fullpath'],
                "create_time": x['create_time'],
                "maybe_hollow": x['maybe_hollow'],
                "binary_info": x['binaryinfo']['binaryinfo']
            })

        readable_output = tableToMarkdown('War room overview', prefetchs, headers=[
                                          "Hostname",
                                          "Domain",
                                          "Username",
                                          "OS",
                                          "Binary Path",
                                          "Create timestamp",
                                          "Is maybe hollow"], removeNull=True)

        ec = {
            'Harfanglab.HuntRunningProcessSearch(val.hash && val.hash === obj.hash)': {
                'data': contextData,
            }
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': prefetchs,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': readable_output,
            'EntryContext': ec
        })
        return data


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
        contextData = []
        for x in data['results']:
            prefetchs.append({
                "Hostname": x['agent']['hostname'],
                "Domain": x['agent'].get('domainname', ''),
                "Username": x['username'],
                "OS": x['agent']['osproducttype'] + " " + x['agent']['osversion'],
                "Binary Path": x['image_name'],
                "Create timestamp": x.get('pe_timestamp', '')
            })
            contextData.append({
                'hash': filehash,
                "hostname": x['agent']['hostname'],
                "domain": x['agent'].get('domainname', ''),
                "username": x['username'],
                "os": x['agent']['osproducttype'],
                "os_version": x['agent']['osversion'],
                "path": x['image_name'],
                "create_time": x.get('pe_timestamp', ''),
                "binary_info": x.get('pe_info', '')
            })

        readable_output = tableToMarkdown('War room overview', prefetchs, headers=[
                                          "Hostname", "Domain", "Username", "OS", "Binary Path", "Create timestamp"],
                                          removeNull=True)

        ec = {
            'Harfanglab.HuntRunnedProcessSearch(val.hash && val.hash === obj.hash)': {
                'data': contextData,
            }
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': prefetchs,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': readable_output,
            'EntryContext': ec
        })
        return data


def isolate_endpoint(client, args) -> dict[str, Any]:
    agentid = args.get('agent_id', None)
    data = client.isolate_endpoint(agentid)

    context = {'Status': False, 'Message': ''}  # type: Dict[str,Any]
    entryType = entryTypes['note']

    if agentid in data['requested']:
        context['Status'] = True
        context['Message'] = 'Agent isolation successfully requested'

    if agentid in data['policy_not_allowed']:
        context['Status'] = False
        context['Message'] = 'Agent isolation request failed (not allowed by the agent policy)'
        entryType = entryTypes['warning']

    demisto.results({
        'Type': entryType,
        'Contents': context,
        'ContentsFormat': formats['json'],
    })

    return context


def deisolate_endpoint(client, args) -> dict[str, Any]:
    agentid = args.get('agent_id', None)
    data = client.deisolate_endpoint(agentid)

    context = {'Status': False, 'Message': ''}  # type: Dict[str,Any]

    if agentid in data['requested']:
        context['Status'] = True
        context['Message'] = 'Agent deisolation successfully requested'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
    })

    return context


def change_security_event_status(client, args):
    eventid = args.get('security_event_id', None)
    status = args.get('status', None)

    client.change_security_event_status(eventid, status)

    context = {}
    context['Message'] = f'Status for security event {eventid} changed to {status}'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
    })

    return context


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
        context['Message'] = f'IOC {ioc_value} of type {ioc_type} added to source {source_name} with {ioc_status} status'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
    })

    return context


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

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
    })

    return context


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

    def telemetry(self, client, args):
        self.params = _construct_request_parameters(
            args, self.keys, params=self.params)

        # Execute request with params
        data = client.telemetry_data(self.telemetry_type, self.params)
        output = self._construct_output(data['results'], client)

        # Determines headers for readable output
        headers = list(output[0].keys()) if len(
            output) > 0 else []
        readable_output = tableToMarkdown(
            self.title, output, headers=headers, removeNull=True)

        ec = {
            f'Harfanglab.Telemetry{self.telemetry_type}(val.agent_id && val.agent_id === obj.agent_id)': {
                self.telemetry_type: output,
            }
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': output,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': readable_output,
            'EntryContext': ec
        })
        return output


class TelemetryProcesses(Telemetry):

    def __init__(self):
        super().__init__()

        self.keys += [
            ('process_name', 'process_name'),
            ('image_name', 'image_name'),
        ]
        self.output_keys = [
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

        'harfanglab-hunt-search-hash': hunt_search_hash,
        'harfanglab-hunt-search-running-process-hash': hunt_search_running_process_hash,
        'harfanglab-hunt-search-runned-process-hash': hunt_search_runned_process_hash,

        'harfanglab-isolate-endpoint': isolate_endpoint,
        'harfanglab-deisolate-endpoint': deisolate_endpoint,

        'harfanglab-change-security-event-status': change_security_event_status,

        'harfanglab-assign-policy-to-agent': assign_policy_to_agent,
        'harfanglab-add-ioc-to-source': add_ioc_to_source,
        'harfanglab-delete-ioc-from-source': delete_ioc_from_source,

        'fetch-incidents': fetch_incidents,
        'test-module': test_module
    }

    return commands.get(command)


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
        target_function(client, args)

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
