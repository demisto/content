import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

INTEGRATION_CONTEXT_BRAND = 'Core'
INTEGRATION_NAME = 'Cortex Core - IR'

XSOAR_RESOLVED_STATUS_TO_Core = {
    'Other': 'resolved_other',
    'Duplicate': 'resolved_duplicate',
    'False Positive': 'resolved_false_positive',
    'Resolved': 'resolved_true_positive',
}

PREVALENCE_COMMANDS = {
    'core-get-hash-analytics-prevalence': 'hash',
    'core-get-IP-analytics-prevalence': 'ip',
    'core-get-domain-analytics-prevalence': 'domain',
    'core-get-process-analytics-prevalence': 'process',
    'core-get-registry-analytics-prevalence': 'registry',
    'core-get-cmd-analytics-prevalence': 'cmd',
}

TERMINATE_BUILD_NUM = '1398786'
TERMINATE_SERVER_VERSION = '8.8.0'


class Client(CoreClient):

    def test_module(self):
        """
            Performs basic get request to get item samples
        """
        try:
            self.get_endpoints(limit=1)
        except Exception as err:
            if 'API request Unauthorized' in str(err):
                # this error is received from the Core server when the client clock is not in sync to the server
                raise DemistoException(f'{str(err)} please validate that your both '
                                       f'XSOAR and Core server clocks are in sync')
            else:
                raise

    def report_incorrect_wildfire(self, file_hash: str, new_verdict: int, reason: str, email: str) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            "hash": file_hash,
            "new_verdict": new_verdict,
            "reason": reason,
            "email": email,
        }

        reply = demisto._apiCall(method='POST',
                                 name="wfReportIncorrectVerdict",
                                 params=None,
                                 data=json.dumps(request_data))

        return reply

    def get_prevalence(self, request_data: dict):
        reply = self._http_request(method='POST', json_data={'request_data': request_data}, headers=self._headers,
                                   url_suffix='/analytics_apis/')
        return reply

    def get_asset_details(self, asset_id):
        reply = self._http_request(
            method="POST",
            json_data={"asset_id": asset_id},
            headers=self._headers,
            url_suffix="/unified-asset-inventory/get_asset/",
        )
        return reply


def report_incorrect_wildfire_command(client: Client, args) -> CommandResults:
    file_hash = args.get('file_hash')
    reason = args.get('reason')
    email = args.get('email')
    new_verdict = arg_to_int(
        arg=args.get('new_verdict'),
        arg_name='Failed to parse "new_verdict". Must be a number.',
        required=True
    )

    response = client.report_incorrect_wildfire(file_hash, new_verdict, reason, email)
    return CommandResults(
        readable_output=f'Reported incorrect WildFire on {file_hash}',
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.WildFire',
        outputs={"file_hash": file_hash, "new_verdict": new_verdict},
        raw_response=response,
    )


def handle_prevalence_command(client: Client, command: str, args: dict):
    key_names_in_response = {
        'ip': 'ip_address',
        'domain': 'domain_name',
        'process': 'process_name',
        'cmd': 'process_command_line',
        'hash': 'sha256',
        'registry': 'key_name',
    }
    args.pop('integration_context_brand', None)
    args.pop('integration_name', None)
    if command == 'core-get-registry-analytics-prevalence':
        # arg list should in the following structure:
        #   args: [
        #       {"key_name": "some_key1", "value_name": "some_value1"},
        #       {"key_name": "some_key2", "value_name": "some_value2"}
        #       ]

        args_list = []
        keys = argToList(args.get('key_name'))
        values = argToList(args.get('value_name'))
        if len(keys) != len(values):
            raise DemistoException('Number of elements in key_name argument should be equal to the number '
                                   'of elements in value_name argument.')
        for key, value in zip(keys, values):
            args_list.append({'key_name': key, 'value_name': value})
    else:
        args_list = []
        for key, value in args.items():
            values = argToList(value)
            for val in values:
                args_list.append({key: val})

    request_body = {
        'api_id': command,
        'args': args_list
    }
    res = client.get_prevalence(request_body).get('results', [])
    for item in res:  # remove 'args' scope
        name = item.pop('args', {})
        item.update(name)
    command_type = PREVALENCE_COMMANDS[command]
    return CommandResults(
        readable_output=tableToMarkdown(string_to_table_header(f'{command_type} Prevalence'),
                                        [{
                                            key_names_in_response[command_type]: item.get(
                                                key_names_in_response[command_type]),
                                            'Prevalence': item.get('value')
                                        } for item in res],
                                        headerTransform=string_to_table_header),
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.AnalyticsPrevalence.{command_type.title()}',
        outputs=res,
        raw_response=res,
    )


def get_asset_details_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves details of a specific asset by its ID and formats the response.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - asset_id (str): The ID of the asset to retrieve.

    Returns:
        CommandResults: Object containing the formatted asset details,
                        raw response, and outputs for integration context.
    """
    client._base_url = "/api/webapp/data-platform"
    asset_id = args.get("asset_id")
    response = client.get_asset_details(asset_id)
    parsed = response.get("reply") if response else "An empty response was returned."
    return CommandResults(
        readable_output=tableToMarkdown("Asset Details", parsed, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.CoreAsset",
        outputs=parsed,
        raw_response=parsed,
    )


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    LOG(f'Command being called is {command}')
    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME
    headers = {}
    url_suffix = '/xsiam' if command in PREVALENCE_COMMANDS else "/public_api/v1"
    if not FORWARD_USER_RUN_RBAC:
        api_key = demisto.params().get('apikey')
        api_key_id = demisto.params().get('apikey_id')
        url = demisto.params().get('url')

        if not api_key or not api_key_id or not url:
            headers = {
                "HOST": demisto.getLicenseCustomField("Core.ApiHostName"),
                demisto.getLicenseCustomField("Core.ApiHeader"): demisto.getLicenseCustomField("Core.ApiKey"),
                "Content-Type": "application/json"
            }
            url = "http://" + demisto.getLicenseCustomField("Core.ApiHost") + "/api/webapp/"
            add_sensitive_log_strs(demisto.getLicenseCustomField("Core.ApiKey"))
        else:
            headers = {
                "Content-Type": "application/json",
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key
            }
            add_sensitive_log_strs(api_key)
    else:
        url = "/api/webapp/"
    base_url = urljoin(url, url_suffix)
    proxy = demisto.params().get('proxy')
    verify_cert = not demisto.params().get('insecure', False)

    try:
        timeout = int(demisto.params().get('timeout', 120))
    except ValueError as e:
        demisto.debug(f'Failed casting timeout parameter to int, falling back to 120 - {e}')
        timeout = 120
    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers,
        timeout=timeout,
    )

    try:
        if command == 'test-module':
            client.test_module()
            demisto.results('ok')

        elif command == 'core-get-endpoints':
            return_results(get_endpoints_command(client, args))

        elif command == 'core-endpoint-alias-change':
            return_results(endpoint_alias_change_command(client, **args))

        elif command == 'core-isolate-endpoint' or command == 'core-isolate-endpoint-quick-action':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd=command,
                                               command_function=isolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_ISOLATED"],
                                               stop_polling=True))

        elif command == 'core-unisolate-endpoint':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-unisolate-endpoint",
                                               command_function=unisolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_UNISOLATED",
                                                              "CANCELLED",
                                                              "ֿPENDING_ABORT",
                                                              "ABORTED",
                                                              "EXPIRED",
                                                              "COMPLETED_PARTIAL",
                                                              "COMPLETED_SUCCESSFULLY",
                                                              "FAILED",
                                                              "TIMEOUT"],
                                               stop_polling=True))

        elif command == 'core-get-distribution-url':
            return_results(get_distribution_url_command(client, args))

        elif command == 'core-get-create-distribution-status':
            return_outputs(*get_distribution_status_command(client, args))

        elif command == 'core-get-distribution-versions':
            return_outputs(*get_distribution_versions_command(client, args))

        elif command == 'core-create-distribution':
            return_outputs(*create_distribution_command(client, args))

        elif command == 'core-get-audit-management-logs':
            return_outputs(*get_audit_management_logs_command(client, args))

        elif command == 'core-get-audit-agent-reports':
            return_outputs(*get_audit_agent_reports_command(client, args))

        elif command == 'core-blocklist-files':
            return_results(blocklist_files_command(client, args))

        elif command == 'core-allowlist-files':
            return_results(allowlist_files_command(client, args))

        elif command == 'core-quarantine-files' or command == 'core-quarantine-files-quick-action':
            polling_args = {
                **args,
                "endpoint_id": argToList(args.get("endpoint_id_list"))[0]
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd=command,
                                               command_function=quarantine_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-get-quarantine-status':
            return_results(get_quarantine_status_command(client, args))

        elif command == 'core-restore-file' or command == 'core-restore-file-quick-action':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd=command,
                                               command_function=restore_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan' or command == 'core-endpoint-scan-quick-action':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd=command,
                                               command_function=endpoint_scan_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan-abort':
            return_results(endpoint_scan_abort_command(client, args))

        elif command == 'core-delete-endpoints':
            return_outputs(*delete_endpoints_command(client, args))

        elif command == 'core-get-policy':
            return_outputs(*get_policy_command(client, args))

        elif command == 'core-get-endpoint-device-control-violations':
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif command == 'core-retrieve-files' or command == 'core-retrieve-files-quick-action':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd=command,
                                               command_function=retrieve_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-retrieve-file-details':
            return_entry, file_results = retrieve_file_details_command(client, args, False)
            demisto.results(return_entry)
            if file_results:
                demisto.results(file_results)

        elif command == 'core-get-scripts':
            return_outputs(*get_scripts_command(client, args))

        elif command == 'core-get-script-metadata':
            return_outputs(*get_script_metadata_command(client, args))

        elif command == 'core-get-script-code':
            return_outputs(*get_script_code_command(client, args))

        elif command == 'core-action-status-get':
            return_results(action_status_get_command(client, args))

        elif command == 'core-run-script':
            return_results(run_script_command(client, args))

        elif command == 'core-script-run' or command == 'core-script-run-quick-action':
            args = args | {'is_core': True}
            return_results(script_run_polling_command(args, client))

        elif command == 'core-run-snippet-code-script':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-snippet-code-script",
                                               command_function=run_snippet_code_script_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-get-script-execution-status':
            return_results(get_script_execution_status_command(client, args))

        elif command == 'core-get-script-execution-results':
            return_results(get_script_execution_results_command(client, args))

        elif command == 'core-get-script-execution-result-files':
            return_results(get_script_execution_result_files_command(client, args))

        elif command == 'core-run-script-execute-commands':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-execute-commands",
                                               command_function=run_script_execute_commands_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-delete-file':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-delete-file",
                                               command_function=run_script_delete_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-file-exists':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-file-exists",
                                               command_function=run_script_file_exists_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-kill-process':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-kill-process",
                                               command_function=run_script_kill_process_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'endpoint':
            return_results(endpoint_command(client, args))

        elif command == 'core-report-incorrect-wildfire':
            return_results(report_incorrect_wildfire_command(client, args))

        elif command == 'core-remove-blocklist-files':
            return_results(remove_blocklist_files_command(client, args))

        elif command == 'core-remove-allowlist-files':
            return_results(remove_allowlist_files_command(client, args))

        elif command == 'core-add-exclusion':
            return_results(add_exclusion_command(client, args))

        elif command == 'core-delete-exclusion':
            return_results(delete_exclusion_command(client, args))

        elif command == 'core-get-exclusion':
            return_results(get_exclusion_command(client, args))

        elif command == 'core-get-cloud-original-alerts':
            return_results(get_original_alerts_command(client, args))

        elif command == 'core-get-dynamic-analysis':
            return_results(get_dynamic_analysis_command(client, args))

        elif command == 'core-add-endpoint-tag':
            return_results(add_tag_to_endpoints_command(client, args))

        elif command == 'core-remove-endpoint-tag':
            return_results(remove_tag_from_endpoints_command(client, args))

        elif command == 'core-list-users':
            return_results(list_users_command(client, args))

        elif command == 'core-list-risky-users':
            return_results(list_risky_users_or_host_command(client, "user", args))

        elif command == 'core-list-risky-hosts':
            return_results(list_risky_users_or_host_command(client, "host", args))

        elif command == 'core-list-user-groups':
            return_results(list_user_groups_command(client, args))

        elif command == 'core-get-incidents':
            return_outputs(*get_incidents_command(client, args))

        elif command == 'core-terminate-process':
            if not is_demisto_version_ge(version=TERMINATE_SERVER_VERSION,
                                         build_number=TERMINATE_BUILD_NUM):
                raise DemistoException('This command is only available for XSIAM 2.4 and above')
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-terminate-process",
                                               command_function=terminate_process_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"
                                                              ],
                                               values_raise_error=["FAILED",
                                                                   "TIMEOUT",
                                                                   "ABORTED",
                                                                   "CANCELED"]))

        elif command == 'core-terminate-causality' or command == 'core-terminate-causality-quick-action':
            if not is_demisto_version_ge(version=TERMINATE_SERVER_VERSION,
                                         build_number=TERMINATE_BUILD_NUM):
                raise DemistoException("This command is only available for XSIAM 2.4 and above")
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd=command,
                                               command_function=terminate_causality_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"],
                                               values_raise_error=["FAILED",
                                                                   "TIMEOUT",
                                                                   "ABORTED",
                                                                   "CANCELED"]
                                               ))

        elif command == "core-get-asset-details":
            return_results(get_asset_details_command(client, args))

        elif command in PREVALENCE_COMMANDS:
            return_results(handle_prevalence_command(client, command, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
