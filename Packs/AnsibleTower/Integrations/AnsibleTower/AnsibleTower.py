from CommonServerPython import *

import json
import urllib3
import traceback
from typing import List

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
                    empty_valid_codes: list = None, return_empty_response: bool = False, ok_codes=None) -> dict:
        return self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data,
                                  empty_valid_codes=empty_valid_codes, return_empty_response=return_empty_response,
                                  ok_codes=ok_codes)


def inventories_list(client: Client, args: dict) -> List[CommandResults]:
    command_results = []
    response = client.api_request(method='GET', url_suffix='inventories/', params=args)
    results = response.get('results', [])
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following arguments {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related', None)  # remove irrelevant fields from output
        res.pop('summary_fields', None)
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.Inventory',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res, removeNull=True),
            raw_response=res
        ))
    return command_results


def hosts_list(client: Client, args: dict) -> List[CommandResults]:
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/hosts/'
    else:
        url_suffix = 'hosts/'

    command_results = []
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)
    results = response.get('results', [])
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related', None)  # remove irrelevant fields from output
        res.pop('summary_fields', None)
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.Host',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res, removeNull=True),
            raw_response=response
        ))
    return command_results


def create_host(client: Client, args: dict) -> CommandResults:
    inventory_id = args.pop('inventory_id', None)
    url_suffix = f'inventories/{inventory_id}/hosts/'

    body = {'name': args.get('host_name'),
            'description': args.get('description', ''),
            'enabled': bool(args.get('enabled', 'True')),
            }
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body)
    response.pop('related', None)  # remove irrelevant fields from output
    response.pop('summary_fields', None)
    return CommandResults(
        outputs_prefix='AnsibleAWX.Host',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name='Created Host', t=response, removeNull=True),
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


def templates_list(client: Client, args: dict) -> List[CommandResults]:
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/job_templates/'
    else:
        url_suffix = 'job_templates/'

    command_results = []
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)

    results = response.get('results', [])
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related', None)  # remove irrelevant fields from output
        res.pop('summary_fields', None)
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.JobTemplate',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res),
            raw_response=response
        ))

    return command_results


def credentials_list(client: Client, args: dict) -> List[CommandResults]:
    url_suffix = 'credentials/'

    command_results = []

    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)

    results = response.get('results', [])
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related', None)  # remove irrelevant fields from output
        res.pop('summary_fields', None)
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.Credential',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res),
            raw_response=response
        ))

    return command_results


def job_template_launch(client: Client, args: dict) -> CommandResults:

    job_template_id = args.get('job_template_id', None)
    url_suffix = f'job_templates/{job_template_id}/launch/'

    extra_vars = json.loads(args.get('extra_variables', None)) if args.get('extra_variables', None) else None
    data = {"inventory": args.get("inventory_id", None),
            "credential": args.get("credentials_id", None),
            "extra_vars": extra_vars}
    body = {key: data[key] for key in data if data[key]}
    demisto.debug(f"Request body is: {str(body)}")
    response = client.api_request(method='POST', url_suffix=url_suffix, json_data=body, ok_codes=[201])
    remove_fields = {'ask_diff_mode_on_launch', 'ask_variables_on_launch', 'ask_limit_on_launch',
                     'ask_tags_on_launch',
                     'ask_skip_tags_on_launch', 'ask_job_type_on_launch', 'ask_verbosity_on_launch',
                     'ask_inventory_on_launch', 'ask_credential_on_launch', 'related', 'summary_fields'}
    context_data = {}
    for key in response:
        if key not in remove_fields:
            context_data[key] = response[key]
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=context_data,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True),
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
    remove_fields = {'ask_diff_mode_on_launch', 'ask_variables_on_launch', 'ask_limit_on_launch', 'ask_tags_on_launch',
                     'ask_skip_tags_on_launch', 'ask_job_type_on_launch', 'ask_verbosity_on_launch',
                     'ask_inventory_on_launch', 'ask_credential_on_launch', 'related', 'summary_fields'}
    context_data = {}
    for key in response:
        if key not in remove_fields:
            context_data[key] = response[key]
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True),
        raw_response=response
    )


def cancel_job(client: Client, args: dict) -> CommandResults:
    job_id = args.get('job_id', None)
    url_suffix = f'jobs/{job_id}/cancel/'
    client.api_request(method='POST', url_suffix=url_suffix, empty_valid_codes=[202], return_empty_response=True)
    return job_status(client, args)


def job_stdout(client: Client, args: dict) -> CommandResults:
    job_id = args.get('job_id', None)
    url_suffix = f'jobs/{job_id}/stdout/'
    params = {"format": "json"}
    response = client.api_request(method='GET', url_suffix=url_suffix, params=params)
    response['job_id'] = job_id
    output_content = f'### Job {job_id} output ### \n\n' + response.pop('content') + '\n' + tableToMarkdown(name='', t=response)
    return CommandResults(
        outputs_prefix='AnsibleAWX.JobStdout',
        outputs_key_field='job_id',
        outputs=response,
        readable_output=output_content,
        raw_response=response
    )


def job_status(client: Client, args: dict) -> CommandResults:
    job_id = args.pop('job_id', None)
    url_suffix = f'jobs/{job_id}/'
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)
    remove_fields = {'ask_diff_mode_on_launch', 'ask_variables_on_launch', 'ask_limit_on_launch', 'ask_tags_on_launch',
                     'ask_skip_tags_on_launch', 'ask_job_type_on_launch', 'ask_verbosity_on_launch',
                     'ask_inventory_on_launch', 'ask_credential_on_launch', 'related', 'summary_fields'}
    context_data = {}
    for key in response:
        if key not in remove_fields:
            context_data[key] = response[key]
    job_id = context_data.get('id', '')
    job_id_status = context_data.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.Job',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Job {job_id} status {job_id_status}', t=context_data, removeNull=True),
        raw_response=response
    )


def list_job_events(client: Client, args: dict) -> List[CommandResults]:
    url_suffix = 'job_events/'

    command_results = []
    response = client.api_request(method='GET', url_suffix=url_suffix, params=args)

    results = response.get('results', [])
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following arguments {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related', None)  # remove irrelevant fields from output
        res.pop('summary_fields', None)
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.JobEvents',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res, removeNull=True),
            raw_response=response
        ))

    return command_results


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
    response.pop('related', None)  # remove irrelevant fields from output
    response.pop('summary_fields', None)
    command_id = response.get('id', '')
    command_status = response.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=response,
                                        removeNull=True),
        raw_response=response
    )


def relaunch_ad_hoc_command(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/relaunch/'
    response = client.api_request(method='POST', url_suffix=url_suffix, ok_codes=[201])
    response.pop('related', None)  # remove irrelevant fields from output
    response.pop('summary_fields', None)
    command_id = response.get('id', '')
    command_status = response.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=response,
                                        removeNull=True),
        raw_response=response
    )


def cancel_ad_hoc_command(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/cancel/'
    try:
        client.api_request(method='POST', url_suffix=url_suffix, empty_valid_codes=[202], return_empty_response=True)
        return ad_hoc_command_status(client, args)
    except Exception as e:
        response = client.api_request(method='GET', url_suffix=url_suffix)
        error_msg = f"{response}. Error: {e.message}"
        raise DemistoException(error_msg, e)


def ad_hoc_command_stdout(client: Client, args: dict) -> CommandResults:
    command_id = args.get('command_id', None)
    url_suffix = f'ad_hoc_commands/{command_id}/stdout/'
    params = {"format": "json"}
    response = client.api_request(method='GET', url_suffix=url_suffix, params=params)
    response['command_id'] = command_id
    output_content = f'### Ad hoc command {command_id} output ### \n\n' + response.pop('content') + '\n' + \
                     tableToMarkdown(name='', t=response)
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommandStdout',
        outputs_key_field='job_id',
        outputs=response,
        readable_output=output_content,
        raw_response=response
    )


def ad_hoc_command_status(client: Client, args: dict) -> CommandResults:
    command_id = args.get("command_id")
    url_suffix = f'ad_hoc_commands/{command_id}/'
    response = client.api_request(method='GET', url_suffix=url_suffix)
    response.pop('related', None)  # remove irrelevant fields from output
    response.pop('summary_fields', None)
    response.pop('job_env', None)
    command_id = response.get('id', '')
    command_status = response.get('status', '')
    return CommandResults(
        outputs_prefix='AnsibleAWX.AdhocCommand',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(name=f'Ad hoc command - {command_id} status - {command_status}', t=response,
                                        removeNull=True),
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

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    username = params.get("username")
    password = params.get("password")

    try:

        client = Client(
            input_url=base_url,
            username=username,
            password=password,
            verify_certificate=verify_certificate,
            proxy=proxy)

        command = demisto.command()

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
