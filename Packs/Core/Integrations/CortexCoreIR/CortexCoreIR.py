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


class Client(CoreClient):

    def test_module(self):
        """
            Performs basic get request to get item samples
        """
        try:
            self.get_incidents(limit=1)
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

        reply = demisto._apiCall(name="wfReportIncorrectVerdict",
                                 params=None,
                                 data=json.dumps(request_data))

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


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    LOG(f'Command being called is {command}')
    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME
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

    base_url = urljoin(url, '/public_api/v1')
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
        timeout=timeout
    )

    try:
        if command == 'test-module':
            client.test_module()
            demisto.results('ok')

        elif command == 'core-get-endpoints':
            return_results(get_endpoints_command(client, args))

        elif command == 'core-isolate-endpoint':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-isolate-endpoint",
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
            return_outputs(*get_distribution_url_command(client, args))

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

        elif command == 'core-quarantine-files':
            polling_args = {
                **args,
                "endpoint_id": argToList(args.get("endpoint_id_list"))[0]
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-quarantine-files",
                                               command_function=quarantine_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-get-quarantine-status':
            return_results(get_quarantine_status_command(client, args))

        elif command == 'core-restore-file':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-restore-file",
                                               command_function=restore_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-endpoint-scan",
                                               command_function=endpoint_scan_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan-abort':
            return_results(endpoint_scan_abort_command(client, args))

        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args))

        elif command == 'core-delete-endpoints':
            return_outputs(*delete_endpoints_command(client, args))

        elif command == 'core-get-policy':
            return_outputs(*get_policy_command(client, args))

        elif command == 'core-get-endpoint-device-control-violations':
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif command == 'core-retrieve-files':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-retrieve-files",
                                               command_function=retrieve_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-retrieve-file-details':
            return_entry, file_results = retrieve_file_details_command(client, args)
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

        elif command == 'xdr-get-alerts':
            return_results(get_alerts_by_filter_command(client, args))

        elif command == 'core-get-dynamic-analysis':
            return_results(get_dynamic_analysis_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
