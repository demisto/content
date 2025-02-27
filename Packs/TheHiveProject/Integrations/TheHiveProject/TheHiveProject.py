import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_LIMIT = 50


class Client(BaseClient):

    def __init__(self, base_url=None, verify=False, mirroring=None, headers={}, proxy=None):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)
        self.mirroring = mirroring
        self.version = self.get_version()

    def get_version(self):
        res = self._http_request('GET', 'status', ok_codes=[200, 201, 404], resp_type='response')
        if "versions" in res.json():
            if "TheHive" in res.json()['versions']:
                return res.json()['versions']['TheHive']
            else:
                return "Unknown"
        return None

    def get_cases(self, limit: int = DEFAULT_LIMIT, start_time: int = 0):
        instance = demisto.integrationInstance()
        cases = []
        query = {
            "query": [
                {
                    "_name": "listCase",
                },
                {
                    "_name": "filter",
                    "_gte": {
                        "_field": "_createdAt",
                        "_value": start_time
                    },
                },
                {
                    "_name": "sort",
                    "_fields": [{"_createdAt": "asc"}]
                },
                {
                    "_name": "page",
                    "from": 0,
                    "to": limit
                },


            ]
        }
        res = self._http_request('POST', 'v1/query',
                                 json_data=query, params={"name": "list-cases"})

        for case in res:
            case["id"] = case["_id"]
            case["caseId"] = case["_id"]
            case["createdAt"] = case["_createdAt"]
            case["type"] = case["_type"]
            case["updatedAt"] = case.get("_updatedAt")
            case['tasks'] = self.get_tasks(case['_id'])
            case['observables'] = self.list_observables(case['_id'])
            case['instance'] = instance
            case['mirroring'] = self.mirroring
            cases.append(case)
        return cases

    def get_case(self, case_id):
        res = self._http_request('GET', f'case/{case_id}', ok_codes=[200, 201, 404], resp_type='response')
        if res.status_code == 404:
            return None
        case = res.json()
        case['tasks'] = self.get_tasks(case_id)
        case['observables'] = self.list_observables(case['id'])
        return case

    def search_cases(self, args: dict = None):
        if self.version[0] == "4":
            res = self._http_request('POST', 'case/_search',
                                     params={"name": "cases"}, ok_codes=[200, 201, 404], json_data=args,
                                     resp_type='response')
        else:
            res = self._http_request('POST', 'case/_search', ok_codes=[200, 201, 404], json_data=args,
                                     resp_type='response')
        if res.status_code == 404:
            return None
        else:
            cases = res.json()
            return cases

    def update_case(self, case_id: str = None, updates: dict = None):
        res = self._http_request('PATCH', f'case/{case_id}', ok_codes=[200, 201, 404], json_data=updates,
                                 resp_type='response')
        if res.status_code != 200:
            return (res.status_code, res.text)
        else:
            case = res.json()
            return case

    def create_case(self, details: dict = None):
        res = self._http_request('POST', 'case', ok_codes=[200, 201, 404], json_data=details, resp_type='response')
        if res.status_code not in [200, 201]:
            return (res.status_code, res.text)
        else:
            case = res.json()
            return case

    def remove_case(self, case_id, permanent=''):
        url = f'case/{case_id}/force' if permanent == 'true' else f'case/{case_id}'
        res = self._http_request('DELETE', url, ok_codes=[200, 201, 204, 404], resp_type='response', timeout=360)
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.status_code

    def get_linked_cases(self, case_id: str = None):
        res = self._http_request('GET', 'case/{case_id}/links', ok_codes=[200, 201, 204, 404], resp_type='response')
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.json()

    def merge_cases(self, first_case_id: str = None, second_case_id: str = None):
        res = self._http_request('POST', f'case/{first_case_id}/_merge/{second_case_id}',
                                 ok_codes=[200, 201, 204, 404], resp_type='response')
        if res.status_code not in [200, 201, 204]:
            return (res.status_code, res.text)
        else:
            return res.json()

    def get_tasks(self, case_id):
        if self.version[0] == "4":
            query = {
                "query": [
                    {
                        "_name": "getCase",
                        "idOrName": case_id
                    },
                    {
                        "_name": "tasks"
                    },
                    {
                        "_name": "sort",
                        "_fields": [
                            {
                                "flag": "desc"
                            },
                            {
                                "order": "asc"
                            },
                            {
                                "startDate": "asc"
                            },
                            {
                                "title": "asc"
                            }
                        ]
                    },
                    {
                        "_name": "page",
                        "from": 0,
                        "to": 15,
                        "extraData": [
                            "shareCount"
                        ]
                    }
                ]
            }
            res = self._http_request(
                'POST', 'v1/query',
                params={"name": "case-tasks"},
                json_data=query,
                ok_codes=[200, 201, 204, 404],
                resp_type='response'
            )
            if res.status_code != 200:
                tasks = []
            else:
                tasks = res.json()
        else:
            data = {"id": case_id}
            res = self._http_request(
                'POST',
                'case/task/_search',
                data=data,
                ok_codes=[200, 201, 204, 404],
                resp_type='response'
            )
            if res.status_code != 200:
                return None
            tasks = list(res.json())
        if tasks:
            for task in tasks:
                if "id" in task:
                    logs = self.get_task_logs(task['id'])
                elif "_id" in task:
                    logs = self.get_task_logs(task['_id'])
                else:
                    logs = []
                task['logs'] = logs
        return tasks

    def get_task(self, task_id: str = None):
        if self.version[0] == "4":
            query = {
                "query": [{
                    "_name": "getTask",
                    "idOrName": task_id
                }, {
                    "_name": "page",
                    "from": 0,
                    "to": 1
                }]
            }
            res = self._http_request(
                'POST',
                'v1/query',
                params={"name": f"get-task-{task_id}"},
                json_data=query,
                ok_codes=[200, 404],
                resp_type='response'
            )
        else:
            res = self._http_request(
                'GET',
                f'case/task/{task_id}',
                ok_codes=[200, 404],
                resp_type='response'
            )
        if res.status_code != 200:
            return None
        if res.json():
            task = res.json()
            task['logs'] = self.get_task_logs(task_id)
        else:
            task = None
        return task

    def create_task(self, case_id: str = None, data: dict = None):
        res = self._http_request(
            'POST',
            f'case/{case_id}/task',
            data=data,
            ok_codes=[201, 200],
            resp_type='response'
        )
        if res.status_code not in [201, 200]:
            return None
        return res.json()

    def get_task_logs(self, task_id: str = None):
        if self.version[0] == "4":
            query = {
                "query": [{
                    "_name": "getTask",
                    "idOrName": task_id
                }, {
                    "_name": "logs"
                }, {
                    "_name": "sort",
                    "_fields": [{
                        "date": "desc"
                    }]
                }, {
                    "_name": "page",
                    "from": 0,
                    "to": 10,
                    "extraData": ["actionCount"]
                }]
            }
            res = self._http_request(
                'POST',
                'v1/query',
                params={"name": "case-task-logs"},
                json_data=query,
                ok_codes=[200, 404],
                resp_type='response'
            )
        else:
            res = self._http_request(
                'GET',
                f'case/task/{task_id}/log',
                ok_codes=[200, 404],
                resp_type='response'
            )
        if res.status_code != 200:
            return []
        else:
            logs = []
            for log in res.json():
                log['has_attachments'] = bool(log.get('attachment', None))
                logs.append(log)
            return logs

    def get_log(self, log_id: str = None):
        if self.version[0] == "4":
            return "Not yet implemented"
        else:
            res = self._http_request(
                'GET',
                f'case/task/log/{log_id}',
                ok_codes=[200, 404],
                resp_type='response'
            )
            if res.status_code != 200:
                return None
            return res.json()

    def get_attachment_data(self, filename: str = None, fileId: str = None):
        headers = self._headers.update({
            "name": filename
        })
        data = b''
        with self._http_request('GET', f'datastore/{fileId}', stream=True, headers=headers, resp_type="response") as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                data += chunk
        return data

    def update_task(self, task_id: str = None, updates: dict = {}):
        res = self._http_request(
            'PATCH',
            f'case/task/{task_id}',
            ok_codes=[200, 201],
            data=updates,
            resp_type='response'
        )
        if res.status_code not in [200, 201]:
            return_error(res.text)
        return res.json()

    def get_users(self):
        users = self._http_request('POST', 'user/_search', ok_codes=[200, 404], data=None, resp_type='response')
        return users.json() if users.status_code != 404 else None

    def get_user(self, user_id: str = None):
        res = self._http_request('GET', f'user/{user_id}', ok_codes=[200, 404], resp_type='response')
        return res.json() if res.status_code != 404 else None

    def create_user(self, user_data: dict):
        if self.version[0] == "4":
            res = self._http_request('POST', 'v1/user', data=user_data, ok_codes=[201, 200])
        else:
            res = self._http_request('POST', 'user', data=user_data, ok_codes=[201, 200])
        return res

    def block_user(self, user_id: str = None):
        res = self._http_request('DELETE', f'user/{user_id}', ok_codes=[204, 404], resp_type='response')
        return res.status_code == 204

    def list_observables(self, case_id: str = None):
        if self.version[0] == "4":
            query4 = {
                "query": [
                    {
                        "_name": "getCase",
                        "idOrName": case_id if case_id else ''
                    },
                    {
                        "_name": "observables"
                    },
                    {
                        "_name": "sort",
                        "_fields": [
                            {
                                "startDate": "desc"
                            }
                        ]
                    },
                    {
                        "_name": "page",
                        "from": 0,
                        "to": 15,
                        "extraData": [
                            "seen",
                            "permissions",
                            "shareCount"
                        ]
                    }
                ]
            }
            res = self._http_request(
                'POST',
                'v1/query',
                ok_codes=[200],
                params={"name": "observables"},
                json_data=query4
            )
        else:
            query = {
                "query": {
                    "_and": [{
                        "_parent": {
                            "_type": "case",
                            "_query": {"_id": case_id}
                        }
                    }, {

                    }]
                }
            }
            res = self._http_request('POST', 'case/artifact/_search', params={'range': 'all'}, ok_codes=[200],
                                     json_data=query)

        return res

    def create_observable(self, case_id: str = None, data: dict = None):
        res = self._http_request('POST', f'case/{case_id}/artifact', ok_codes=[201, 200], data=data)
        return res

    def update_observable(self, artifact_id: str = None, data: dict = None):
        res = self._http_request(
            'PATCH',
            f'case/artifact/{artifact_id}',
            ok_codes=[200, 204, 404],
            data=data,
            resp_type="response")
        return res.json() if res.status_code != 404 else None


''' HELPER FUNCTIONS '''


def output_results(title: str, outputs: Any, headers: list, outputs_prefix: str,
                   outputs_key_field: str, human_readable: bool = True):
    if title and outputs and headers and human_readable:
        md = tableToMarkdown(title, outputs, headers)
    else:
        md = None
    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=md
    )


''' COMMAND FUNCTIONS '''


def list_cases_command(client: Client, args: dict):
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    res = client.get_cases(limit=limit)
    res = sorted(res, key=lambda x: x['caseId'])
    if res:
        for case in res:
            case_date_dt = dateparser.parse(str(case['createdAt']))
            case_update_dt = dateparser.parse(str(case['updatedAt']))
            if case_date_dt:
                case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
            if case_update_dt:
                case['updatedAt'] = case_update_dt.strftime(DATE_FORMAT)
        read = tableToMarkdown('TheHive Cases:', res, ['id', 'title', 'description', 'createdAt'])
    else:
        read = "No cases to be displayed."

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=res,
        readable_output=read,
    )


def get_case_command(client: Client, args: dict):
    case_id = args.get('id')
    case = client.get_case(case_id)
    if case:
        case_date_dt = dateparser.parse(str(case['createdAt']))
        case_update_dt = dateparser.parse(str(case['updatedAt']))
        if case_date_dt:
            case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
        if case_update_dt:
            case['updatedAt'] = case_update_dt.strftime(DATE_FORMAT)

        headers = ['id', 'title', 'description', 'createdAt']
        read = tableToMarkdown(f'TheHive Case ID {case_id}:', case, headers)
    else:
        read = "No case with the given ID."
    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field='id',
        outputs=case,
        readable_output=read,
    )


def search_cases_command(client: Client, args: dict):
    if client.version[0] == "4":
        arguments = args.get('query', None)
    else:
        arguments = {k: True if v == 'true' else v for k, v in args.items() if v is not None}
        arguments = {k: False if v == 'false' else v for k, v in arguments.items() if v is not None}
    try:
        arguments = json.loads(arguments)
    except Exception:
        pass
    cases = client.search_cases(arguments)
    if cases:
        for case in cases:
            case_date_dt = dateparser.parse(str(case['createdAt']))
            if case_date_dt:
                case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
        read = tableToMarkdown('TheHive Cases search:', cases, ['id', 'title', 'description', 'createdAt'])
    else:
        read = "No cases were found."

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=cases,
        readable_output=read,
    )


def update_case_command(client: Client, args: dict):
    case_id = args.get('id')
    args['tags'] = argToList(args.get('tags', []))
    if args.get('severity'):
        args['severity'] = arg_to_number(args.get('severity'))
    # Get the case first
    original_case = client.get_case(case_id)
    if not original_case:
        raise DemistoException(f'Could not find case ID {case_id}.')
    del args['id']
    for k, v in args.items():
        v = v.split(",") if k in ['tags'] and "," in v else v
        original_case[k] = v
    case = client.update_case(case_id, args)
    if type(case) is tuple:
        raise DemistoException(f'Error updating case ({case[0]}) - {case[1]}')
    case_date_dt = dateparser.parse(str(case['createdAt']))
    case_update_dt = dateparser.parse(str(case['updatedAt']))
    if case_date_dt:
        case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
    if case_update_dt:
        case['updatedAt'] = case_update_dt.strftime(DATE_FORMAT)
    read = tableToMarkdown(f'TheHive Update Case ID {case_id}:', case, ['id', 'title', 'description', 'createdAt'])

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=case,
        readable_output=read,
    )


def fix_element(args: dict):
    """
    Fix args to fit API types requirements.

    Args:
        args (dict): args to fix
    """
    types_dict = {
        'title': str,
        'description': str,
        'tlp': arg_to_number,
        'pap': arg_to_number,
        'severity': arg_to_number,
        'flag': argToBoolean,
        'tags': argToList,
        'startDate': dateparser.parse,
        'metrics': argToList,
        'customFields': str,
        'tasks': argToList,
        'template': str,
        'owner': str
    }
    for k, v in args.items():
        args[k] = types_dict.get(k, str)(v)  # type: ignore
        if k == 'tasks':
            args[k] = [fix_element(task) for task in args[k]]


def create_case_command(client: Client, args: dict):
    fix_element(args)
    case = client.create_case(args)
    if type(case) is tuple:
        raise DemistoException(f'Error creating case ({case[0]}) - {case[1]}')

    case_date_dt = dateparser.parse(str(case['createdAt']))
    case_update_dt = dateparser.parse(str(case['updatedAt']))
    if case_date_dt:
        case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
    if case_update_dt:
        case['updatedAt'] = case_update_dt.strftime(DATE_FORMAT)
    read = tableToMarkdown('TheHive newly Created Case:', case, ['id', 'title', 'description', 'createdAt'])

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=case,
        readable_output=read,
    )


def remove_case_command(client: Client, args: dict):
    case_id = args.get('id')
    permanent = args.get('permanent')

    case = client.get_case(case_id)
    if not case:
        raise DemistoException(f'No case found with ID {case_id}')

    res = client.remove_case(case_id, permanent)
    if type(res) is tuple:
        raise DemistoException(f'Error removing case ID {case_id} ({res[0]}) - {res[1]}')

    return f'Case ID {case_id} permanently removed successfully' if permanent == 'true' \
        else f'Case ID {case_id} removed successfully'


def create_task_command(client: Client, args: dict):
    case_id = args.pop('id')
    task = client.create_task(case_id, args)
    if task:
        task_date_dt = dateparser.parse(str(task['createdAt']))
        if task_date_dt:
            task['createdAt'] = task_date_dt.strftime(DATE_FORMAT)
        read = tableToMarkdown("The newly created task", task, ['id', 'title', 'createdAt', 'status'])
    else:
        read = "failed to create a new task"

    return CommandResults(
        outputs_prefix='TheHive.Tasks',
        outputs_key_field="id",
        outputs=task,
        readable_output=read
    )


def get_linked_cases_command(client: Client, args: dict):
    case_id = args.get('case_id')
    res = client.get_linked_cases(case_id)
    if type(res) is tuple:
        raise DemistoException(f'Error getting linked cases ({res[0]}) - {res[1]}')
    if res:
        for case in res:
            case_date_dt = dateparser.parse(str(case['createdAt']))
            if case_date_dt:
                case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
        read = tableToMarkdown('TheHive newly Created Case:', res, ['id', 'title', 'description', 'createdAt'])
    else:
        read = "No linked cases found."

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=res,
        readable_output=read,
    )


def merge_cases_command(client: Client, args: dict):
    first_case = args.get('firstCaseID')
    second_case = args.get('secondCaseID')
    case = client.merge_cases(first_case, second_case)
    if isinstance(case, tuple):
        raise DemistoException(f'Error getting linked cases ({case[0]}) - {case[1]}')

    case_date_dt = dateparser.parse(str(case['createdAt']))
    if case_date_dt:
        case['createdAt'] = case_date_dt.strftime(DATE_FORMAT)
    read = tableToMarkdown(f'TheHive Linked Cases of {first_case}:', case, ['id', 'title', 'description', 'createdAt'])

    return CommandResults(
        outputs_prefix='TheHive.Cases',
        outputs_key_field="id",
        outputs=case,
        readable_output=read,
    )


def get_case_tasks_command(client: Client, args: dict):
    case_id = args.get('id')
    if client.get_case(case_id):
        tasks = client.get_tasks(case_id)
        if tasks:
            for task in tasks:
                task_date_dt = dateparser.parse(str(task['_createdAt']))
                if task_date_dt:
                    task['_createdAt'] = task_date_dt.strftime(DATE_FORMAT)
            read = tableToMarkdown(f'TheHive Tasks For Case {case_id}:', tasks,
                                   ['_id', 'title', '_createdAt', '_createdBy', 'status', 'group'])
        else:
            read = "No tasks found for this case."
    else:
        read = f"No case found with id: {case_id}."
        tasks = None

    return CommandResults(
        outputs_prefix='TheHive.Tasks',
        outputs_key_field="id",
        outputs=tasks,
        readable_output=read,
    )


def get_task_command(client: Client, args: dict):
    task_id = args.get('id')
    task = client.get_task(task_id)
    if task:
        # task = task[0]
        task_date_dt = dateparser.parse(str(task['_createdAt']))
        if task_date_dt:
            task['_createdAt'] = task_date_dt.strftime(DATE_FORMAT)

        read = tableToMarkdown(f'TheHive Task {task_id}:', task,
                               ['_id', 'title', '_createdAt', '_createdBy', 'status', 'group'])
    else:
        read = f"No task found with id: {task_id}."

    return CommandResults(
        outputs_prefix='TheHive.Tasks',
        outputs_key_field="id",
        outputs=task,
        readable_output=read,
    )


def get_attachment_command(client: Client, args: dict):
    attachment_id = args.get('id')
    attachment_name = args.get('name')
    data = client.get_attachment_data(filename=attachment_name, fileId=attachment_id)
    if data:
        return fileResult(attachment_name, data)
    else:
        read = f'No attachments with ID "{attachment_id}" and name "{attachment_name}" found.'

    return CommandResults(
        outputs_prefix='TheHive.Attachments',
        outputs_key_field="id",
        outputs={"name": attachment_name, "id": attachment_id},
        readable_output=read,
    )


def update_task_command(client: Client, args: dict):
    task_id = args.get('id')
    data = args
    del data['id']
    task = client.get_task(task_id)
    if task:
        updated_task = client.update_task(task_id=task_id, updates=data)
        if type(task) is dict:
            task_date_dt = dateparser.parse(str(updated_task['_createdAt']))
            if task_date_dt:
                updated_task['_createdAt'] = task_date_dt.strftime(DATE_FORMAT)
            read = tableToMarkdown(f"Updated task with id: {task_id}", updated_task,
                                   ['_id', 'title', 'createdAt', '_createdBy', 'status', 'group'])
        else:
            read = "failed to update the task."
    else:
        read = f"No task found with id: {task_id}."

    return CommandResults(
        outputs_prefix='TheHive.Tasks',
        outputs_key_field="id",
        outputs=updated_task,
        readable_output=read,
    )


def get_users_list_command(client: Client, args: dict = None):
    users = client.get_users()
    if users:
        read = tableToMarkdown('TheHive Users:', users, ['id', 'name', 'roles', 'status'])
        for user in users:
            user_date_dt = dateparser.parse(str(user['createdAt']))
            if user_date_dt:
                user['createdAt'] = user_date_dt.strftime(DATE_FORMAT)
    else:
        read = "No users found."

    return CommandResults(
        outputs_prefix='TheHive.Users',
        outputs_key_field="id",
        outputs=users,
        readable_output=read,
    )


def get_user_command(client: Client, args: dict):
    user_id = args.get('id')
    user = client.get_user(user_id)
    if user:
        user_date_dt = dateparser.parse(str(user['createdAt']))
        if user_date_dt:
            user['createdAt'] = user_date_dt.strftime(DATE_FORMAT)
        read = tableToMarkdown(f'TheHive User ID {user_id}:', user,
                               ['_id', 'name', 'roles', 'status', 'organisation', 'createdAt'])
    else:
        read = f"No user found with id: {user_id}."

    return CommandResults(
        outputs_prefix='TheHive.Users',
        outputs_key_field="id",
        outputs=user,
        readable_output=read,
    )


def create_local_user_command(client: Client, args: dict):
    user_data = {
        "login": args.get('login'),
        "name": args.get('name'),
        "roles": argToList(args.get('roles', 'read')),
        "password": args.get('password')
    }
    if client.version[0] == "4":
        user_data['profile'] = args.get('profile', "read-only")
        del user_data['roles']
    result = client.create_user(user_data=user_data)
    if result:
        read = tableToMarkdown(f"New User {result.get('id', result.get('_id', None))}:", result,
                               headers=['id', 'login', 'name', 'roles'] if client.version[0] != "4"
                               else ['_id', 'login', 'name', 'profile'])
    else:
        read = "failed to create a user."

    return CommandResults(
        outputs_prefix='TheHive.Users',
        outputs_key_field="id",
        outputs=result,
        readable_output=read,
    )


def block_user_command(client: Client, args: dict):
    user_id = args.get('id')
    if client.block_user(user_id):
        return f'User "{user_id}" blocked successfully'
    else:
        return f'No user found with id: {user_id}'


def list_observables_command(client: Client, args: dict):
    case_id = args.get('id')
    case = client.get_case(case_id)
    if not case:
        raise DemistoException(f"No case found with id: {case_id}.")
    observables = case['observables']
    if observables:
        read = tableToMarkdown(f"Observables for Case {case_id}:", observables,
                               ['data', 'dataType', 'message'])
    else:
        read = f"No observables found for case with id: {case_id}."

    return CommandResults(
        outputs_prefix='TheHive.Observables',
        outputs_key_field="id",
        outputs=observables,
        readable_output=read,
    )


def create_observable_command(client: Client, args: dict):
    case_id = args.get('id')
    case = client.get_case(case_id)
    if not case:
        raise DemistoException(f"No case found with id: {case_id}.")
    else:
        data = {
            "data": args.get('data'),
            "dataType": args.get('dataType'),
            "message": args.get('message'),
            "startDate": args.get('startDate', None),
            "tlp": args.get('tlp', None),
            "ioc": args.get('ioc', 'false') == 'true',
            "status": args.get('status', None)
        }
        data = {k: v for k, v in data.items() if v}
        res = client.create_observable(case_id=case_id, data=data)
        if res:
            read = tableToMarkdown('New Observable:', res, ['id', 'data', 'dataType', 'message'])
        else:
            read = "Could not create a new observable."

    return CommandResults(
        outputs_prefix='TheHive.Observables',
        outputs_key_field="id",
        outputs=res,
        readable_output=read,
    )


def update_observable_command(client: Client, args: dict):
    artifact_id = args.get('id')

    data = {
        "message": args.get('message'),
        "tlp": args.get('tlp', None),
        "ioc": args.get('ioc', 'false') == 'true',
        "status": args.get('status', None)
    }
    data = {k: v for k, v in data.items() if v}
    res = client.update_observable(artifact_id=artifact_id, data=data)

    read = tableToMarkdown('Updated Observable:', res, ['id', 'data', 'dataType', 'message'])if res\
        else f"No observable found with id: {artifact_id}."

    return CommandResults(
        outputs_prefix='TheHive.Observables',
        outputs_key_field="id",
        outputs=res,
        readable_output=read,
    )


def get_mapping_fields_command(client: Client, args: dict) -> Dict[str, Any]:
    instance_name = demisto.integrationInstance()
    schema = client.get_cases(limit=1)
    schema = schema[0] if schema and type(schema) is list else {}
    schema_id = schema.get('id', None)
    schema = client.get_case(schema_id) if schema_id else {"Warning": "No cases to pull schema from."}
    schema['dbotMirrorDirection'] = client.mirroring
    schema['dbotMirrorInstance'] = instance_name
    return {f"Default Schema {client.version}": schema}


def update_remote_system_command(client: Client, args: dict) -> str:
    parsed_args = UpdateRemoteSystemArgs(args)
    changes = {k: v for k, v in parsed_args.delta.items() if k in parsed_args.data}
    demisto.debug(f'Changes from update_remote_system: {changes}')
    # Convert the values: severity, pap and tlp to integer as the api request
    changes = {k: (int(v) if isinstance(v, str) and v.isdigit() else v) for k, v in changes.items()}
    if parsed_args.remote_incident_id:
        # Apply the updates
        client.update_case(case_id=parsed_args.remote_incident_id, updates=changes)
    return parsed_args.remote_incident_id


def get_modified_remote_data_command(client: Client, args: dict):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    last_update_utc = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
    assert last_update_utc is not None, f'could not parse {last_update}'
    last_update_utc = last_update_utc.replace(tzinfo=None)
    last_timestamp = int(last_update_utc.timestamp() * 1000)

    query = {
        "query": {
            "_and": [
                {
                    "_gt": {
                        "updatedAt": last_timestamp
                    }
                }
            ]
        }
    }
    cases = client.search_cases(query)
    incident_ids = [x['id'] for x in cases] if cases else []
    return GetModifiedRemoteDataResponse(incident_ids)


def get_remote_data_command(client: Client, args: dict):
    parsed_args = GetRemoteDataArgs(args)

    parsed_entries = []
    case: dict = client.get_case(parsed_args.remote_incident_id)

    if not case:
        parsed_entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': 'Deleted',
                'closeNotes': 'Case no longer exists',
                'casestatus': 'Deleted'
            },
            'ContentsFormat': EntryFormat.JSON
        })
        case = {'caseId': parsed_args.remote_incident_id}  # can not be empty dict so extract_for_local will be called
    elif case['status'] != "Open":  # Handle closing the case
        parsed_entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': case.get('resolutionStatus', ''),
                'closeNotes': case.get('summary', '')
            },
            'ContentsFormat': EntryFormat.JSON
        })

    return GetRemoteDataResponse(case, parsed_entries)  # mypy: ignore


def get_version_command(client: Client, args: dict):
    version = client.get_version()
    return version


def test_module(client: Client):
    res = client._http_request('GET', 'case', resp_type="response")
    if res.status_code == 200:
        return 'ok'
    else:
        return res.text


def fetch_incidents(client: Client, fetch_closed: bool = False):
    params = demisto.params()
    last_run = demisto.getLastRun()
    last_timestamp = int(last_run.pop('timestamp', 0))
    if last_timestamp:
        # migrate to isoformat
        last_run['time'] = datetime.fromtimestamp(last_timestamp / 1000).strftime(DATE_FORMAT)
    look_back = int(params.get('look_back', 0))
    first_fetch = params.get('first_fetch')

    max_fetch_param = arg_to_number(params.get('max_fetch')) or 50
    max_fetch = last_run.get('limit') or max_fetch_param
    start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=last_run, first_fetch=first_fetch,
                                                                look_back=look_back, date_format=DATE_FORMAT)
    start_fetch_datetime = dateparser.parse(start_fetch_time)
    assert start_fetch_datetime
    start_fetch_time = int(start_fetch_datetime.timestamp() * 1000)
    res = client.get_cases(limit=max_fetch, start_time=start_fetch_time)
    if not fetch_closed:
        res = list(filter(lambda case: case['status'] == 'Open', res))
    demisto.debug(f"number of returned cases from the api:{len(res)}")
    incidents = []
    instance_name = demisto.integrationInstance()
    mirror_direction = demisto.params().get('mirror')
    mirror_direction = None if mirror_direction == "Disabled" else mirror_direction
    for case in res:
        case['dbotMirrorDirection'] = mirror_direction
        case['dbotMirrorInstance'] = instance_name
        incident = {
            'name': f"TheHiveProject - {case['id']}: {case['title']}",
            'occurred': timestamp_to_datestring(case['createdAt'], date_format=DATE_FORMAT),
            'severity': case['severity'],
            'rawJSON': json.dumps(case)
        }
        incidents.append(incident)
        last_timestamp = max(case['createdAt'], last_timestamp)
    incidents = filter_incidents_by_duplicates_and_limit(incidents_res=incidents, last_run=last_run,
                                                         fetch_limit=max_fetch_param, id_field='name')
    last_run = update_last_run_object(last_run=last_run, incidents=incidents, fetch_limit=max_fetch_param,
                                      start_fetch_time=start_fetch_time, end_fetch_time=end_fetch_time, look_back=look_back,
                                      created_time_field='occurred', id_field='name', date_format=DATE_FORMAT)

    demisto.setLastRun(last_run)
    return incidents


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    mirroring = params.get('mirror', 'Disabled').title()
    api_key = params.get('credentials_api_key', {}).get('password') or params.get('apiKey')
    if not api_key:
        raise DemistoException('API Key must be provided.')
    client = Client(
        base_url=urljoin(params.get('url'), '/api'),
        verify=not params.get('insecure', False),
        headers={'Authorization': f'Bearer {api_key}'},
        proxy=params.get('proxy', False),
        mirroring=None if mirroring == 'Disabled' else mirroring,
    )

    command = demisto.command()

    command_map = {
        'thehive-list-cases': list_cases_command,
        'thehive-get-case': get_case_command,
        'thehive-search-cases': search_cases_command,  # deprecated
        'thehive-update-case': update_case_command,
        'thehive-create-case': create_case_command,
        'thehive-get-linked-cases': get_linked_cases_command,  # deprecated
        'thehive-merge-cases': merge_cases_command,
        'thehive-get-case-tasks': get_case_tasks_command,
        'thehive-get-task': get_task_command,
        'thehive-get-attachment': get_attachment_command,  # no create attachment
        'thehive-update-task': update_task_command,
        'thehive-list-users': get_users_list_command,
        'thehive-get-user': get_user_command,
        'thehive-create-local-user': create_local_user_command,
        'thehive-list-observables': list_observables_command,
        'thehive-create-observable': create_observable_command,
        'thehive-update-observable': update_observable_command,
        'get-remote-data': get_remote_data_command,  #
        'get-modified-remote-data': get_modified_remote_data_command,
        'update-remote-system': update_remote_system_command,
        'get-mapping-fields': get_mapping_fields_command,  #
        'thehive-create-task': create_task_command,
        'thehive-remove-case': remove_case_command,
        'thehive-block-user': block_user_command,
        'thehive-get-version': get_version_command,
    }
    demisto.debug(f'Command being called is {command}')
    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(client, demisto.params().get('fetch_closed', True))
            demisto.incidents(incidents)

        elif command in command_map:
            return_results(command_map[command](client, args))  # type: ignore

    except Exception as err:
        return_error(f'Failed to execute {command} command. \nError: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
