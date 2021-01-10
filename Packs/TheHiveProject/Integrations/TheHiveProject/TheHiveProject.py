from typing import Dict

from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

SCHEMA = {
    "_id": "00000000",
    "_parent": None,
    "_routing": "00000000",
    "_type": "case",
    "_version": 41,
    "caseId": 30,
    "createdAt": 1595342673924,
    "createdBy": "admin",
    "customFields": {},
    "description": "description",
    "endDate": 1595346352635,
    "flag": False,
    "id": "00000000",
    "metrics": {},
    "observables": [
        {
            "_id": "00000000",
            "_parent": "00000000",
            "_routing": "00000000",
            "_type": "case_artifact",
            "_version": 1,
            "createdAt": 1595342693106,
            "createdBy": "admin",
            "data": "1.1.1.1",
            "dataType": "ip",
            "id": "00000000",
            "ioc": True,
            "message": "message",
            "reports": {},
            "sighted": True,
            "startDate": 1595342693106,
            "status": "Ok",
            "tags": [
                "asd"
            ],
            "tlp": 1,
            "updatedAt": 1595346351088,
            "updatedBy": "xsoar"
        }
    ],
    "owner": "admin",
    "pap": 1,
    "resolutionStatus": "FalsePositive",
    "severity": 3,
    "startDate": 1595342640000,
    "status": "Resolved",
    "summary": "This was a False positive.",
    "tags": [
        "asd"
    ],
    "tasks": [
        {
            "_id": "00000000",
            "_parent": "00000000",
            "_routing": "00000000",
            "_type": "case_task",
            "_version": 41,
            "createdAt": 1595342675063,
            "createdBy": "admin",
            "description": "description",
            "flag": False,
            "group": "group name",
            "id": "00000000",
            "logs": [],
            "order": 0,
            "status": "Cancel",
            "title": "title",
            "updatedAt": 1595346353652,
            "updatedBy": "xsoar"
        }
    ],
    "title": "New test case",
    "tlp": 1,
    "updatedAt": 1595346352635,
    "updatedBy": "xsoar"
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url=None, verify=False, mirroring=None, headers={}, proxy=None):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)
        self.mirroring = mirroring

    def get_cases(self, limit: int = None):
        instance = demisto.integrationInstance()
        cases = list()
        res = self._http_request('GET', 'case')
        if limit and type(res) == list:
            if len(res) > limit:
                return res[0:limit]
        for case in res:
            case['tasks'] = self.get_tasks(case['id'])
            case['observables'] = self.list_observables(case['id'])
            case['instance'] = instance
            case['mirroring'] = self.mirroring
            cases.append(case)
        return cases

    def get_case(self, case_id: int = None):
        res = self._http_request('GET', f'case/{case_id}', ok_codes=[200, 201, 404], resp_type='response')
        if res.status_code == 404:
            return None
        case = res.json()
        case['tasks'] = self.get_tasks(case_id)
        case['observables'] = self.list_observables(case['id'])
        return case

    def search_cases(self, args: dict = None):
        data = args
        res = self._http_request('POST', f'case/_search', ok_codes=[200, 201, 404], data=data, resp_type='response')
        if res.status_code == 404:
            return None
        else:
            cases = res.json()
            return cases

    def update_case(self, case_id: str = None, updates: dict = None):
        res = self._http_request('PATCH', f'case/{case_id}', ok_codes=[200, 201, 404], data=updates,
                                 resp_type='response')
        if res.status_code != 200:
            return (res.status_code, res.text)
        else:
            case = res.json()
            return case

    def create_case(self, details: dict = None):
        res = self._http_request('POST', 'case', ok_codes=[200, 201, 404], data=details, resp_type='response')
        if res.status_code not in [200, 201]:
            return (res.status_code, res.text)
        else:
            case = res.json()
            return case

    def remove_case(self, case_id: str = None, permanent: bool = False):
        url = f'case/{case_id}/force' if permanent else f'case/{case_id}'
        res = self._http_request('DELETE', url, ok_codes=[200, 201, 204, 404], resp_type='response', timeout=360)
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.status_code

    def get_linked_cases(self, case_id: str = None):
        res = self._http_request(f'GET', 'case/{case_id}/links', ok_codes=[200, 201, 204, 404], resp_type='response')
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.json()

    def merge_cases(self, first_case_id: str = None, second_case_id: str = None):
        res = self._http_request(f'POST', f'case/{first_case_id}/_merge/{second_case_id}',
                                 ok_codes=[200, 201, 204, 404], resp_type='response')
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.json()

    def get_tasks(self, case_id: str = None):
        data = {"id": case_id}
        tasks = list()
        res = self._http_request(f'POST', f'case/task/_search', data=data, ok_codes=[200, 201, 204, 404],
                                 resp_type='response')
        if res.status_code != 200:
            return None
        tasks = [x for x in res.json() if x['_parent'] == case_id]
        for task in tasks:
            logs = self.get_task_logs(task['id'])
            task['logs'] = logs
        return tasks

    def get_task(self, task_id: str = None):
        res = self._http_request('GET', f'case/task/{task_id}', ok_codes=[200], resp_type='response')
        if res.status_code != 200:
            return None
        task = res.json()
        task['logs'] = self.get_task_logs(task_id)
        return task

    def create_task(self, case_id: str = None, data: dict = None):
        res = self._http_request('POST', f'case/{case_id}/task', data=data, ok_codes=[201], resp_type='response')
        if res.status_code != 201:
            return None
        return res.json()

    def get_task_logs(self, task_id: str = None):
        res = self._http_request('GET', f'case/task/{task_id}/log', ok_codes=[200], resp_type='response')
        if res.status_code != 200:
            return []
        logs = list()
        for log in res.json():
            log['has_attachments'] = True if log.get('attachment', None) else False
            logs.append(log)
        return logs

    def get_log(self, log_id: str = None):
        res = self._http_request('GET', f'case/task/log/{log_id}', ok_codes=[200], resp_type='response')
        if res.status_code != 200:
            return None
        return res.json()

    def get_attachment_data(self, filename=None, fileId=None):
        headers = self._headers.update({
            "name": filename
        })
        data = bytes()
        with self._http_request('GET', f'datastore/{fileId}', stream=True, headers=headers, resp_type="response") as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                data += chunk
        return data

    def update_task(self, task_id: str = None, updates: dict = {}):
        res = self._http_request('PATCH', f'case/task/{task_id}', ok_codes=[200, 201], data=updates,
                                 resp_type='response')
        if res.status_code not in [200, 201]:
            return_error(res.text)
        return res.json()

    def search_users(self, search_filter: dict = None):
        users = self._http_request('POST', 'user/_search', ok_codes=[200], data=search_filter)
        return users

    def get_user(self, user_id: str = None):
        res = self._http_request('GET', f'user/{user_id}', ok_codes=[200])
        return res

    def create_user(self, user_data: dict = None):
        res = self._http_request('POST', f'user', data=user_data, ok_codes=[201])
        return res

    def block_user(self, user_id: str = None):
        res = self._http_request('DELETE', f'user/{user_id}', ok_codes=[204], resp_type='response')
        if res.status_code == 204:
            return True
        else:
            return False

    def list_observables(self, case_id: str = None):
        res = self._http_request('POST', f'case/artifact/_search', ok_codes=[200])
        res[:] = [x for x in res if x['_parent'] == case_id] if case_id else res
        return res

    def create_observable(self, case_id: str = None, data: dict = None):
        res = self._http_request('POST', f'case/{case_id}/artifact', ok_codes=[201], data=data)
        return res

    def update_observable(self, artifact_id: str = None, data: dict = None):
        res = self._http_request('PATCH', f'case/artifact/{artifact_id}', ok_codes=[200], data=data)
        return res


''' HELPER FUNCTIONS '''


def output_results(title: str = None, outputs: [dict, list] = None, headers: [str, list] = None,
                   outputs_prefix: str = None, outputs_key_field: [str, list] = None, human_readable: bool = True):
    if title and outputs and headers and human_readable:
        md = tableToMarkdown(title, outputs, headers)
    else:
        md = None
    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=md
    )
    return_results(command_results)


''' COMMAND FUNCTIONS '''


def list_cases_command(client: Client, args: dict = None):
    limit = int(args.get('limit', None)) if args.get('limit', None) else None
    res = client.get_cases(limit=limit)
    res = sorted(res, key=lambda x: x['caseId'])
    output_results(
        title='TheHive Cases:',
        outputs=res,
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id'
    )


def get_case_command(client: Client, args: dict = None):
    case_id = args.get('id')
    case = client.get_case(case_id)
    output_results(
        title=f'TheHive Case ID {case_id}:',
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=case
    )


def search_cases_command(client: Client, args: dict = None):
    arguments = {k: True if v == 'true' else v for k, v in args.items() if v != None}
    arguments = {k: False if v == 'false' else v for k, v in arguments.items()}
    cases = client.search_cases(arguments)
    output_results(
        title='TheHive Cases search:',
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=cases
    )


def update_case_command(client: Client, args: dict = None):
    case_id = args.get('id')

    # Get the case first
    original_case = client.get_case(case_id)
    if not original_case:
        return_error(f'Could not find case ID {case_id}')
    del updates['id']
    for k, v in updates.items():
        v = v.split(",") if k in ['tags'] and "," in v else v
        original_case[k] = v
    res = client.update_case(case_id, updates)
    if type(res) == tuple:
        return_error(f'Error updating case ({res[0]}) - {res[1]}')
    output_results(
        title=f'TheHive Update Case ID {case_id}:',
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=res
    )


def create_case_command(client: Client, args: dict = None):
    res = client.create_case(args)
    if type(res) == tuple:
        return_error(f'Error creating case ({res[0]}) - {res[1]}')
    output_results(
        title='TheHive Create Case:',
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=res
    )


def remove_case_command(client: Client, args: dict = None):
    case_id = args.get('id')
    permanent = args.get('permanent', 'false')
    permanent = True if permanent == 'true' else False

    # See if the case exists
    case = client.get_case(case_id)
    if not case:
        return_error(f'Case ID {case_id} does not exist')
    res = client.remove_case(case_id, permanent)
    if type(res) == tuple:
        return_error(f'Error removing case ID {case_id} ({res[0]}) - {res[1]}')
    message = f'Case ID {case_id} permanently removed successfully' if permanent else f'Case ID {case_id} removed successfully'
    demisto.results(message)


def get_linked_cases_command(client: Client, args: dict = None):
    case_id = args.get('case_id')
    res = client.get_linked_cases(case_id)
    if type(res) == tuple:
        return_error(f'Error getting linked cases ({res[0]}) - {res[1]}')
    output_results(
        title=f'TheHive Linked Cases of {case_id}:',
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=res
    )


def merge_cases_command(client: Client, args: dict = None):
    first_case = args.get('firstCaseID')
    second_case = args.get('secondCaseID')
    res = client.merge_cases(first_case, second_case)
    if type(res) == tuple:
        return_error(f'Error getting linked cases ({res[0]}) - {res[1]}')
    output_results(
        title=f'TheHive Linked Cases of {case_id}:',
        outputs=res,
        headers=['id', 'title', 'description', 'createdAt'],
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
    )


def get_case_tasks_command(client: Client, args: dict = None):
    case_id = args.get('id')
    tasks = client.get_tasks(case_id)
    output_results(
        title=f'TheHive Tasks For Case {case_id}:',
        outputs=tasks,
        headers=['id', 'title', 'createdAt', 'status'],
        outputs_prefix='TheHive.Tasks',
        outputs_key_field='id',
    )


def get_task_command(client: Client, args: dict = None, params: dict = None):
    task_id = args.get('id')
    tasks = client.get_task(task_id)
    output_results(
        title=f'TheHive Task {task_id}:',
        outputs=tasks,
        headers=['id', 'title', 'createdAt', 'createdBy', 'status', '_parent'],
        outputs_prefix='TheHive.Tasks',
        outputs_key_field='id',
    )


def get_attachment_command(client: Client, args: dict = None, params: dict = None):
    log_id = args.get('id')
    log = client.get_log(log_id)
    if log and "attachment" in log:
        attachment = log.get('attachment')
        data = client.get_attachment_data(filename=attachment.get('name', None), fileId=attachment.get('id', None))
        demisto.results(fileResult(attachment['name'], data))
        output_results(
            title=f'TheHive Log Attachments:',
            outputs=attachment,
            headers=['id', 'name', 'hashes', 'size', 'contentType'],
            outputs_prefix='TheHive.Attachments',
            outputs_key_field='id',
        )
    else:
        demisto.results('No attachments in log ID {log_id}')


def update_task_command(client: Client, args: dict = None, params: dict = None):
    task_id = args.get('id')
    data = args
    del data['id']
    task = client.update_task(task_id=task_id, updates=data)
    if type(task) == dict:
        task['id'] = task_id
    output_results(
        title=f'TheHive Update Task {task_id}:',
        outputs=task,
        headers=[x for x in args.keys() if x != 'id'],
        outputs_prefix='TheHive.Tasks',
        outputs_key_field='id',
    )


def search_users_command(client: Client, args: dict = None, params: dict = None):
    users = client.search_users()
    output_results(
        title=f'TheHive Users:',
        outputs=users,
        headers=['id', 'name', 'roles', 'status'],
        outputs_prefix='TheHive.Users',
        outputs_key_field='id',
    )


def get_user_command(client: Client, args: dict = None, params: dict = None):
    user_id = args.get('id')
    user = client.get_user(user_id)
    output_results(
        title=f'TheHive User ID {user_id}:',
        outputs=user,
        headers=['id', 'name', 'roles', 'status'],
        outputs_prefix='TheHive.Users',
        outputs_key_field='id',
    )


def create_local_user_command(client: Client, args: dict = None, params: dict = None):
    data = {
        "login": args.get('login'),
        "name": args.get('name'),
        "roles": args.get('roles').split(",") if "," in args.get('roles') else args.get('roles'),
        "password": args.get('password')
    }
    result = client.create_user(user_data=data)
    output_results(
        title=f'New User {user_id}:',
        outputs=result,
        headers=['id', 'name', 'roles', 'status'],
        outputs_prefix='TheHive.Users',
        outputs_key_field='id',
    )


def block_user_command(client: Client, args: dict = None, params: dict = None):
    user_id = args.get('id')
    if client.block_user(user_id):
        demisto.results(f'User "{user_id}" blocked successfully')
    else:
        demisto.results(f'User "{user_id}" was not blocked successfully')


def list_observables_command(client: Client, args: dict = None, params: dict = None):
    case_id = args.get('id')
    observables = client.list_observables(case_id)
    title = f"Observables for Case {case_id}" if case_id else "Observables:"
    output_results(
        title=title,
        outputs=observables,
        headers=['data', 'dataType', 'message'],
        outputs_prefix='TheHive.Observables',
        outputs_key_field='id',
    )


def create_observable_command(client: Client, args: dict = None, params: dict = None):
    case_id = args.get('id')
    data = {
        "data": args.get('data'),
        "dataType": args.get('dataType'),
        "message": args.get('message'),
        "startDate": args.get('startDate', None),
        "tlp": args.get('tlp', None),
        "ioc": True if args.get('ioc', 'false') == 'true' else False,
        "status": args.get('status', None)
    }
    data = {k: v for k, v in data.items() if v}
    res = client.create_observable(case_id=case_id, data=data)
    output_results(
        title='New Observable:',
        outputs=res,
        headers=['data', 'dataType', 'message'],
        outputs_prefix='TheHive.Observables',
        outputs_key_field='id',
    )


def update_observable_command(client: Client, args: dict = None, params: dict = None):
    artifact_id = args.get('id')
    data = {
        "message": args.get('message'),
        "tlp": args.get('tlp', None),
        "ioc": True if args.get('ioc', 'false') == 'true' else False,
        "status": args.get('status', None)
    }
    data = {k: v for k, v in data.items() if v}
    res = client.update_observable(artifact_id=artifact_id, data=data)
    output_results(
        title='Updated Observable {artifact_id}:',
        outputs=res,
        headers=['data', 'dataType', 'message'],
        outputs_prefix='TheHive.Observables',
        outputs_key_field='id',
    )


def get_mapping_fields_command(client: Client, args: dict = None, params: dict = None) -> Dict[str, Any]:
    instance_name = demisto.integrationInstance()
    mirror_direction = demisto.params().get('mirror')
    mirror_direction = None if mirror_direction == "Disabled" else mirror_direction
    SCHEMA['dbotMirrorDirection'] = mirror_direction
    SCHEMA['dbotMirrorInstance'] = instance_name
    return {"Default Schema": SCHEMA}


def update_remote_system_command(client: Client, args: dict = None, params: dict = None) -> Dict[str, Any]:
    data = args.get('data')
    delta = args.get('delta')
    changes = {k: v for k, v in delta.items() if k in data.keys()}
    entries = args.get('entries')
    incident_changed = args.get('incidentChanged')
    case_id = args.get('remoteId')
    status = args.get('status')
    if incident_changed:
        # Apply the updates
        client.update_case(case_id=case_id, updates=changes)
    return case_id


def get_remote_data_command(client: Client, args: dict = None, params: dict = None) -> List[Dict[str, Any]]:
    case_id = args.get('id')
    last_update = args.get('lastUpdate')
    last_update_timestamp = dateparser.parse(last_update).timestamp()
    entries = list()
    case = client.get_case(case_id)
    if not case:
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': 'Deleted',
                'closeNotes': 'Case no longer exists',
                'casestatus': 'Deleted'
            },
            'ContentsFormat': EntryFormat.JSON
        })
        return [{}] + entries

    # Handle closing the case
    if case['status'] != "Open":
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': case.get('resolutionStatus', ''),
                'closeNotes': case.get('summary', '')
            },
            'ContentsFormat': EntryFormat.JSON
        })
    return [case] + entries


def test_module(client: Client):
    res = client._http_request('GET', 'case', resp_type="response")
    if res.status_code == 200:
        return 'ok'
    else:
        return res.text


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()
    last_timestamp = int(last_run.get('timestamp', 0))
    res = client.get_cases()
    res[:] = [x for x in res if x['createdAt'] > last_timestamp and x['status'] == 'Open']
    res = sorted(res, key=lambda x: x['createdAt'])
    incidents = list()
    instance_name = demisto.integrationInstance()
    mirror_direction = demisto.params().get('mirror')
    mirror_direction = None if mirror_direction == "Disabled" else mirror_direction
    for case in res:
        case['dbotMirrorDirection'] = mirror_direction
        case['dbotMirrorInstance'] = instance_name
        incident = {
            'name': case['title'],
            'occurred': timestamp_to_datestring(case['createdAt']),
            'severity': case['severity'],
            'rawJSON': json.dumps(case)
        }
        incidents.append(incident)
        last_timestamp = case['createdAt'] if case['createdAt'] > last_timestamp else last_timestamp
    demisto.setLastRun({"timestamp": str(last_timestamp)})
    return incidents


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    api_key = params['apiKey']
    url = params.get('url')
    base_url = f'{url}/api'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    mirroring = params.get('mirroring', None).title() if params.get('mirroring', None) else None
    mirroring = None if mirroring == 'Disabled' else mirroring

    command = demisto.command()

    command_map = {
        'thehive-list-cases': list_cases_command,
        'thehive-get-case': get_case_command,
        'thehive-search-cases': search_cases_command,
        'thehive-update-case': update_case_command,
        'thehive-create-case': create_case_command,
        'thehive-remove-case': remove_case_command,
        'thehive-get-linked-cases': get_linked_cases_command,
        'thehive-merge-cases': merge_cases_command,
        'thehive-get-case-tasks': get_case_tasks_command,
        'thehive-get-task': get_task_command,
        'thehive-get-attachment': get_attachment_command,
        'thehive-update-task': update_task_command,
        'thehive-list-users': search_users_command,
        'thehive-get-user': get_user_command,
        'thehive-create-local-user': create_local_user_command,
        'thehive-block-user': block_user_command,
        'thehive-list-observables': list_observables_command,
        'thehive-create-observable': create_observable_command,
        'thehive-update-observable': update_observable_command
    }
    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            mirroring=mirroring
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)

        elif command == 'get-remote-data':
            demisto.results(get_remote_data_command(client, args, params))

        elif command == 'update-remote-system':
            demisto.results(update_remote_system_command(client, args, params))

        elif command == 'get-mapping-fields':
            demisto.results(get_mapping_fields_command(client, args, params))

        elif command in command_map:
            command_map[command](client, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command. \nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
