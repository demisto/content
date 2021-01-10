from CommonServerPython import *

import json
import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


class Client(BaseClient):
    def __init__(self, input_url: str, username: str, password: str, verify_certificate: bool, proxy: bool):
        base_url = urljoin(input_url, '/api/v2/')
        headers = {
            "Content-Type": "application/json",
        }
        authentication = (username, password)
        super(Client, self).__init__(base_url=base_url,
                                     verify=verify_certificate,
                                     headers=headers,
                                     auth=authentication,
                                     proxy=proxy)

    def api_request(self, method: str, url_suffix: str, params: dict = None, json_data: dict = None,
                    empty_valid_codes: list = None, return_empty_response: bool = False, ok_codes: list = None) -> dict:
        response = self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data,
                                      empty_valid_codes=empty_valid_codes, return_empty_response=return_empty_response,
                                      ok_codes=ok_codes)
        if not return_empty_response:
            results = response.get('results', [])
            if results:
                for res in results:
                    res.pop('related', None)
                    res.pop('summary_fields', None)
            else:
                response.pop('related', None)
                response.pop('summary_fields', None)
        return response


def output_data(response: dict) -> dict:
    """
    Arrange the returned data and remove irrelevant fields from response
    Args:
        response: raw json api response

    Returns:
        the response without irrelevant fields
    """
    remove_fields = ['ask_diff_mode_on_launch', 'ask_variables_on_launch', 'ask_limit_on_launch',
                     'ask_tags_on_launch', 'ask_skip_tags_on_launch', 'ask_job_type_on_launch',
                     'ask_verbosity_on_launch', 'ask_inventory_on_launch', 'ask_credential_on_launch', 'job_env', 'job',
                     'job_slice_number', 'job_slice_count', 'event_processing_finished', 'diff_mode', 'elapsed',
                     'allow_simultaneous', 'force_handlers', 'forks', 'unified_job_template', 'use_fact_cache',
                     'verbosity', 'has_inventory_sources', 'last_job_host_summary']

    context_data = {}
    for key in response:
        if key not in remove_fields:
            if key in ['created', 'modified']:
                value = parse_date_string(str(response[key]), DATE_FORMAT)
                context_data[key] = str(value)
            else:
                context_data[key] = response[key]
    return context_data


def results_output_data(results: list) -> list:
    context_data = []
    for res in results:
        context_data.append(output_data(res))
    return context_data


def output_content(content, print_output, text_filter, headline):
    """
    Builds the human readable output return from stdout commands according to print_output and text_filter
    Args:
        content: stdout returned from running ad hoc command or job
        print_output: if True human readable is shown to user
        text_filter: if provided than human readable will include only lines in the content that contains this text
        headline: headline of the human readable text

    Returns: human readable text

    """
    output_text = ' '
    if print_output:
        filtered_content = ''
        if text_filter:
            for line in content.split("\n"):
                if re.search(fr'{text_filter.lower()}', line.lower()):
                    filtered_content = '\n'.join([filtered_content, line])
        add_filter_data = f'Filtered text: {text_filter}\n' if text_filter else ''
        output_text = headline + add_filter_data + (filtered_content if filtered_content else content) + '\n'
    return output_text


def get_headers(context_data) -> list:
    """
    Arrange the headers by importance - 'name' and 'id' will appear first
    Args:
        context_data: list or dict containing the context data

    Returns: headers arrange by importance

    """
    if isinstance(context_data, dict):
        context_data = [context_data]
    headers = list(context_data[0].keys())
    if 'name' in headers:
        headers.remove('name')
        headers.insert(0, 'name')
    if 'id' in headers:
        headers.remove('id')
        headers.insert(1, 'id')
    return headers


def inventories_list(client: Client, args: dict) -> CommandResults:
    args['page'] = args.pop('page_number', 1)
    response = client.api_request(method='GET', url_suffix='inventories/', params=args)
    results = response.get('results', [])
    if not results:
        return CommandResults(
            readable_output=f"No results were found for the following arguments {str(args)}",
            raw_response=response
        )
    context_data = results_output_data(results)
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Inventory',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(name='Inventories List', t=context_data, removeNull=True, headers=headers),
        raw_response=results
    )


def hosts_list(client: Client, args: dict) -> CommandResults:
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/hosts/'
    else:
        url_suffix = 'hosts/'
    args = {"id" if k == 'host_id' else k: v for k, v in args.items()}  # Rename key name of host id to match api params
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)
    results = response.get('results', [])
    if not results:
        return CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        )
    context_data = results_output_data(results)
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Host',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(name='Hosts List', t=context_data, removeNull=True, headers=headers),
        raw_response=response)


def create_host(client: Client, args: dict) -> CommandResults:
    inventory_id = args.pop('inventory_id', None)
    url_suffix = f'inventories/{inventory_id}/hosts/'

    body = {'name': args.get('host_name'),
            'description': args.get('description', ''),
            'enabled': bool(args.get('enabled', 'True')),
            }
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body)
    context_data = output_data(response)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Host',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name='Created Host', t=context_data, removeNull=True),
        raw_response=response
    )


def delete_host(client: Client, args: dict) -> CommandResults:
    host_id = args.pop('host_id', None)
    url_suffix = f'hosts/{host_id}/'
    client.api_request(method='DELETE', url_suffix=url_suffix, return_empty_response=True)
    return CommandResults(
        readable_output=f'Removed host id: {host_id}',
        outputs_prefix='AnsibleAWX.Host',
        outputs_key_field='id',
        outputs={"id": host_id, "Deleted": True}  # Update the context data that this host was deleted. If this host
        # do not exist in the context it will show only the id and the deleted variable
    )


def templates_list(client: Client, args: dict) -> CommandResults:
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/job_templates/'
    else:
        url_suffix = 'job_templates/'

    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)
    results = response.get('results', [])

    if not results:
        return CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        )

    context_data = results_output_data(results)
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.JobTemplate',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(name='Job Templates List', t=context_data, headers=headers),
        raw_response=response)


def credentials_list(client: Client, args: dict) -> CommandResults:
    url_suffix = 'credentials/'

    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)

    results = response.get('results', [])
    if not results:
        return CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        )

    context_data = results_output_data(results)
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Credential',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(name='Credentials List', t=context_data, headers=headers),
        raw_response=response)


def job_template_launch(client: Client, args: dict) -> CommandResults:

    job_template_id = args.get('job_template_id', None)
    url_suffix = f'job_templates/{job_template_id}/launch/'

    extra_vars = json.loads(args.get('extra_variables', None)) if args.get('extra_variables', None) else None
    data = {"inventory": args.get("inventory_id", None),
            "credential": int(args.get("credentials_id", 0)) if args.get("credentials_id", None) else None,
            "extra_vars": extra_vars}
    body = {key: data[key] for key in data if data[key]}
    demisto.debug(f"Request body is: {str(body)}")
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body, ok_codes=[201])
    context_data = output_data(response)
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=context_data,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True,
                                        headers=headers),
        raw_response=response
    )


def job_relaunch(client: Client, args: dict):
    job_id = args.get('job_id', None)
    url_suffix = f'jobs/{job_id}/relaunch/'

    data = {"hosts": args.get("relaunch_hosts", "all"),
            "credential": args.get("credentials_id", None)}
    body = {key: data[key] for key in data if data[key]}
    demisto.debug(f"Request body is: {str(body)}")
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body, ok_codes=[201])
    context_data = output_data(response)
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True,
                                        headers=headers),
        raw_response=response
    )


def cancel_job(client: Client, args: dict) -> CommandResults:
    job_id = args.get('job_id', None)
    url_suffix = f'jobs/{job_id}/cancel/'
    client.api_request(method='POST', url_suffix=url_suffix, empty_valid_codes=[202], return_empty_response=True)
    return job_status(client, args)


def job_stdout(client: Client, args: dict) -> CommandResults:
    print_output = True if args.get('print_output', 'True') == 'True' else False
    text_filter = args.get('text_filter', '')
    job_id = args.get('job_id', '')
    url_suffix = f'jobs/{job_id}/stdout/'
    params = {"format": "json"}
    response = client.api_request(method='GET', url_suffix=url_suffix, params=params)
    response['job_id'] = job_id
    output_text = output_content(response.get('content', ''), print_output, text_filter,
                                 f'### Job {job_id} output ### \n\n')
    return CommandResults(
        outputs_prefix='AnsibleAWX.JobStdout',
        outputs_key_field='job_id',
        outputs=response,
        readable_output=output_text,
        raw_response=response
    )


def job_status(client: Client, args: dict) -> CommandResults:
    job_id = args.pop('job_id', None)
    url_suffix = f'jobs/{job_id}/'
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)
    context_data = output_data(response)
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True,
                                        headers=headers),
        raw_response=response
    )


def list_job_events(client: Client, args: dict) -> CommandResults:
    url_suffix = 'job_events/'

    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)

    results = response.get('results', [])
    if not results:
        return CommandResults(
            readable_output=f"No results were found for the following arguments {str(args)}",
            raw_response=response
        )

    context_data = results_output_data(results)
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.JobEvents',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(name='Results', t=context_data, removeNull=True, headers=headers),
        raw_response=response
    )


def create_ad_hoc_command(client: Client, args: dict) -> CommandResults:
    inventory_id = args.get('inventory_id')
    credential_id = args.get('credential_id')
    module_name = args.get('module_name')
    module_args = args.get('module_args')
    body = {"inventory": inventory_id,
            "credential": credential_id,
            "module_name": module_name,
            "module_args": module_args}
    url_suffix = 'ad_hoc_commands/'
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body, ok_codes=[201])
    context_data = output_data(response)
    command_id = context_data.get('id', '')
    command_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=context_data,
                                        removeNull=True, headers=headers),
        raw_response=response
    )


def relaunch_ad_hoc_command(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/relaunch/'
    response = client.api_request(method='POST', url_suffix=url_suffix, ok_codes=[201])
    context_data = output_data(response)
    command_id = context_data.get('id', '')
    command_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=context_data,
                                        removeNull=True, headers=headers),
        raw_response=response
    )


def cancel_ad_hoc_command(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/cancel/'
    try:
        client.api_request(method='POST', url_suffix=url_suffix, empty_valid_codes=[202], return_empty_response=True)
        return ad_hoc_command_status(client, args)
    except DemistoException as e:
        if e.res.status_code == 405:
            response = client.api_request(method='GET', url_suffix=url_suffix)
            error_msg = f"{response}. Error: {e.message}"
            raise DemistoException(error_msg, e)
        raise DemistoException(e)


def ad_hoc_command_stdout(client: Client, args: dict) -> CommandResults:
    print_output = True if args.get('print_output', 'True') == 'True' else False
    text_filter = args.get('text_filter', '')
    command_id = args.get('command_id', None)
    url_suffix = f'ad_hoc_commands/{command_id}/stdout/'
    params = {"format": "json"}
    response = client.api_request(method='GET', url_suffix=url_suffix, params=params)
    response['command_id'] = command_id
    output_text = output_content(response.get('content', ''), print_output, text_filter,
                                 f'### Ad hoc command {command_id} output ### \n\n')
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommandStdout',
        outputs_key_field='job_id',
        outputs=response,
        readable_output=output_text,
        raw_response=response
    )


def ad_hoc_command_status(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/'
    response = client.api_request(method='GET', url_suffix=url_suffix)
    context_data = output_data(response)
    command_id = context_data.get('id', '')
    command_status = context_data.get('status', '')
    headers = get_headers(context_data)
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=context_data,
                                        removeNull=True, headers=headers),
        raw_response=response
    )


def test_module(client: Client) -> str:

    client.api_request(method="GET", url_suffix='inventories/')
    return 'ok'


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    commands = {
        'ansible-tower-inventories-list': inventories_list,
        'ansible-tower-hosts-list': hosts_list,
        'ansible-tower-host-create': create_host,
        'ansible-tower-host-delete': delete_host,
        'ansible-tower-job-templates-list': templates_list,
        'ansible-tower-credentials-list': credentials_list,
        'ansible-tower-job-launch': job_template_launch,
        'ansible-tower-job-relaunch': job_relaunch,
        'ansible-tower-job-cancel': cancel_job,
        'ansible-tower-job-stdout': job_stdout,
        'ansible-tower-job-status': job_status,
        'ansible-tower-job-events-list': list_job_events,
        'ansible-tower-adhoc-command-launch': create_ad_hoc_command,
        'ansible-tower-adhoc-command-relaunch': relaunch_ad_hoc_command,
        'ansible-tower-adhoc-command-cancel': cancel_ad_hoc_command,
        'ansible-tower-adhoc-command-stdout': ad_hoc_command_stdout,
        'ansible-tower-adhoc-command-status': ad_hoc_command_status
    }

    base_url = params.get("url")
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:

        client = Client(
            input_url=base_url,
            username=username,
            password=password,
            verify_certificate=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
