import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import Response


RUN_HR_KEY_TO_RES_KEY = {
    'Run id': 'id',
    'Status': 'attributes.status',
    'Plan id': 'relationships.plan.data.id',
    'Planned at': 'attributes.status-timestamps.planned-at'
}
PLAN_HR_KEY_TO_RES_KEY = {
    "Plan id": "id",
    "Status": "attributes.status",
    "Agent Queued at": "attributes.status-timestamps.agent-queued-at"
}
POLICIES_HR_KEY_TO_RES_KEY = {
    'Policy id': 'id',
    'Policy name': 'attributes.name',
    'Policy description': 'attributes.description',
    'Kind': 'attributes.kind',
    'Policy Set ids': 'relationships.policy-sets.data.id',
    'Organization id': 'relationships.organization.data.id'
}
SET_HR_KEY_TO_RES_KEY = {
    'Policy set id': 'id',
    'Policy Set name': 'attributes.name',
    'Description': 'attributes.description',
    'Organization': 'relationships.organization.data.id',
    'Policies ids': 'relationships.policies.data.id',
    'Workspaces': 'relationships.workspaces.data.id',
    'Projects': 'relationships.projects.data.id'
}
CHECK_HR_KEY_TO_RES_KEY = {
    'Policy check id': 'id',
    'Result': 'attributes.result',
    'Status': 'attributes.status',
    'Scope ': 'attributes.scope'
}


class Client(BaseClient):
    def __init__(
            self, url: str, token: str,
            default_organization_name: str | None = None,
            default_workspace_id: str | None = None,
            verify: bool = True, proxy: bool = False):
        self._default_organization_name = default_organization_name
        self._default_workspace_id = default_workspace_id

        headers = {
            'Authorization': f'Bearer {token}'
        }
        super().__init__(base_url=url, verify=verify, proxy=proxy, headers=headers)

    def test_connection(self):
        return self._http_request('GET', 'account/details')

    def runs_list_request(self, workspace_id: str | None = None,
                          run_id: str | None = None, filter_status: str | None = None,
                          page_number: str | None = None, page_size: str | None = None) -> dict:
        params = {}
        if not run_id:
            if filter_status:
                params['filter[status]'] = filter_status
            if page_number:
                params['page[number]'] = page_number
            if page_size:
                params['page[size]'] = page_size

            workspace_id = workspace_id or self._default_workspace_id
            if not workspace_id:
                raise DemistoException(
                    "Please provide either, the instance param 'Default Workspace Id' or the command argument 'workspace_id'"
                )
        url_suffix = f'/runs/{run_id}' if run_id else f'/workspaces/{workspace_id}/runs'
        response = self._http_request('GET', url_suffix, params=params)

        return response

    def run_action(self, run_id: str, action: str, comment: str | None = None) -> Response:

        return self._http_request(
            'POST',
            f'runs/{run_id}/actions/{action}',
            json_data={'comment': comment} if comment and action != 'force-execute' else None,
            headers=self._headers | {'Content-Type': 'application/vnd.api+json'},
            ok_codes=[200, 202, 403, 404, 409],
            resp_type='response')

    def get_plan(self, plan_id: str, json_output: bool) -> Response:
        url_suffix = f'/plans/{plan_id}{"/json-output" if json_output else ""}'
        return self._http_request('GET', url_suffix, resp_type='response')

    def list_policies(self, organization_name: str | None = None, policy_kind: str | None = None,
                      policy_name: str | None = None, policy_id: str | None = None) -> dict:

        params = {}
        if not policy_id:
            if policy_kind:
                params['filter[kind]'] = policy_kind
            if policy_name:
                params['search[name]'] = policy_name
            organization_name = organization_name or self._default_organization_name
            if not organization_name:
                raise DemistoException(
                    "Please provide either the instance param '\
                        'Default Organization Name' or the command argument 'organization_name'")

        url_suffix = f'/policies/{policy_id}' if policy_id else f'/organizations/{organization_name}/policies'
        response = self._http_request('GET', url_suffix, params=params)

        return response

    def list_policy_sets(self, organization_name: str | None, policy_set_id: str | None,
                         versioned: str | None, policy_set_kind: str | None, include: str | None,
                         policy_set_name: str | None, page_number: str | None,
                         page_size: str | None) -> dict:
        params: dict[str, str] = {}
        if not policy_set_id:
            if versioned:
                params['filter[versioned]'] = versioned
            if policy_set_kind:
                params['filter[kind]'] = policy_set_kind
            if include:
                params['include'] = include
            if policy_set_name:
                params['search[name]'] = policy_set_name
            if page_number:
                params['page[number]'] = page_number
            if page_size:
                params['page[size]'] = page_size
            organization_name = organization_name or self._default_organization_name
            if not organization_name:
                raise DemistoException(
                    "Please provide either the instance param 'Default Organization Name'\
                        ' or the command argument 'organization_name'")

        url_suffix = f'/policy-sets/{policy_set_id}' if policy_set_id else f'/organizations/{organization_name}/policy-sets'
        return self._http_request('GET', url_suffix, params=params)

    def list_policy_checks(self, run_id: str | None, policy_check_id: str | None,
                           page_number: str | None, page_size: str | None) -> dict:
        """List Terraform policy checks"""
        params = {}
        if page_number:
            params['page[number]'] = page_number
        if page_size:
            params['page[size]'] = page_size

        url_suffix = f'/runs/{run_id}/policy-checks' if run_id else f'/policy-checks/{policy_check_id}'
        return self._http_request('GET', url_suffix, params=params)


def runs_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace_id = args.get('workspace_id')
    run_id = args.get('run_id')
    filter_status = args.get('filter_status')
    page_number = args.get('page_number')
    page_size = args.get('page_size')

    res = client.runs_list_request(workspace_id, run_id, filter_status, page_number, page_size)
    # when run_id is provided, it returns a single run instead of a list
    data = [res.get('data', {})] if run_id else res.get('data', [])
    hr_items = [
        {hr_key: demisto.get(run, response_key) for hr_key, response_key in RUN_HR_KEY_TO_RES_KEY.items()}
        for run in data
    ]
    command_results = CommandResults(
        outputs_prefix='Terraform.Run',
        outputs_key_field='data.id',
        outputs=res,
        readable_output=tableToMarkdown('Terraform Runs', hr_items, removeNull=True)
    )

    return command_results


def run_action_command(client: Client, args: Dict[str, Any]) -> str:

    run_id = args.get('run_id')
    action = args.get('action')
    comment = args.get('comment')

    if not run_id or not action:
        raise DemistoException("run_id and action are required")

    if action == 'force-execute' and comment:
        raise DemistoException("comment parameter is invalid for force-execute action")

    res = client.run_action(
        run_id=run_id,
        action=action,
        comment=comment
    )

    action_msg = f'queued an {action} request for run id {run_id}'
    if res.status_code == 202:
        return f'Successfully {action_msg}'
    else:
        raise DemistoException(f'Error occurred when {action_msg}: {res.json().get("errors",[{}])[0].get("title")}')


def plan_get_command(client: Client, args: Dict[str, Any]) -> CommandResults | dict[str, Any]:
    plan_id = args.get('plan_id')
    json_output = argToBoolean(args.get('json_output', False))

    if not plan_id:
        raise DemistoException("plan_id is required")
    res = client.get_plan(plan_id, json_output)

    if json_output:
        return fileResult(filename=f'{plan_id}.json',
                          data=res.content,
                          file_type=EntryType.ENTRY_INFO_FILE)

    res_json = res.json()
    plan = res_json.get('data', {})
    hr_plan = {hr_key: demisto.get(plan, response_key) for hr_key, response_key in PLAN_HR_KEY_TO_RES_KEY.items()}

    command_results = CommandResults(
        outputs_prefix='Terraform.Plan',
        outputs_key_field='id',
        outputs=plan,
        raw_response=res_json,
        readable_output=tableToMarkdown('Terraform Plan', hr_plan)
    )

    return command_results


def policies_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    policy_kind = args.get('policy_kind')
    policy_name = args.get('policy_name')
    policy_id = args.get('policy_id')

    res = client.list_policies(organization_name, policy_kind, policy_name, policy_id)
    # when policy_id is provided, it returns a single policy instead of a list
    data = [res.get('data', {})] if policy_id else res.get('data', [])
    hr_items = [
        {hr_key: demisto.dt(policy, response_key) for hr_key, response_key in POLICIES_HR_KEY_TO_RES_KEY.items()}
        for policy in data
    ]

    command_results = CommandResults(
        outputs_prefix='Terraform.Policy',
        outputs_key_field='id',
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown('Terraform Policies', hr_items, removeNull=True)
    )

    return command_results


def policy_set_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    policy_set_id = args.get('policy_set_id')
    versioned = args.get('versioned')
    policy_set_kind = args.get('policy_set_kind')
    include = args.get('include')
    policy_set_name = args.get('policy_set_name')
    page_number = args.get('page_number')
    page_size = args.get('page_size')

    res = client.list_policy_sets(organization_name, policy_set_id, versioned,
                                  policy_set_kind, include, policy_set_name,
                                  page_number, page_size)
    # when policy_set_id is provided, it returns a single policy set instead of a list
    data = [res.get('data', {})] if policy_set_id else res.get('data', [])
    hr_items = [
        {hr_key: demisto.dt(policy_set, response_key) for hr_key, response_key in SET_HR_KEY_TO_RES_KEY.items()}
        for policy_set in data
    ]

    return CommandResults(
        outputs_prefix='Terraform.PolicySet',
        outputs_key_field='id',
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown('Terraform Policy Sets', hr_items, removeNull=True)
    )


def policies_checks_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    run_id = args.get('run_id')
    policy_check_id = args.get('policy_check_id')
    page_number = args.get('page_number')
    page_size = args.get('page_size')

    res = client.list_policy_checks(run_id, policy_check_id, page_number, page_size)

    # when policy_check_id is provided, it returns a single check instead of a list
    data = [res.get('data', {})] if policy_check_id else res.get('data', [])
    hr_items = [
        {hr_key: demisto.get(policy_check, response_key) for hr_key, response_key in CHECK_HR_KEY_TO_RES_KEY.items()}
        for policy_check in data
    ]

    return CommandResults(
        outputs_prefix='Terraform.PolicyCheck',
        outputs_key_field='id',
        outputs=data,
        raw_response=res,
        readable_output=tableToMarkdown('Terraform Policy Checks', hr_items, removeNull=True)
    )


def test_module(client: Client) -> str:
    try:
        client.test_connection()
    except Exception as e:
        if 'Unauthorized' in str(e):
            raise DemistoException('Unauthorized: Please be sure you put a valid API Token')
        raise e
    return 'ok'


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('server_url', 'https://app.terraform.io/api/v2').rstrip('/')
    token = params.get('credentials', {}).get('password')
    default_workspace_id = params.get('default_workspace_id')
    default_organization_name = params.get('default_organization_name')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client: Client = Client(url, token, default_organization_name, default_workspace_id, verify_certificate, proxy)

        commands = {
            'terraform-runs-list': runs_list_command,
            'terraform-run-action': run_action_command,
            'terraform-plan-get': plan_get_command,
            'terraform-policies-list': policies_list_command,
            'terraform-policy-set-list': policy_set_list_command,
            'terraform-policies-checks-list': policies_checks_list_command,
        }

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
