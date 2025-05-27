from copy import deepcopy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Core - IR"

XSOAR_RESOLVED_STATUS_TO_Core = {
    "Other": "resolved_other",
    "Duplicate": "resolved_duplicate",
    "False Positive": "resolved_false_positive",
    "Resolved": "resolved_true_positive",
}

PREVALENCE_COMMANDS = {
    "core-get-hash-analytics-prevalence": "hash",
    "core-get-IP-analytics-prevalence": "ip",
    "core-get-domain-analytics-prevalence": "domain",
    "core-get-process-analytics-prevalence": "process",
    "core-get-registry-analytics-prevalence": "registry",
    "core-get-cmd-analytics-prevalence": "cmd",
}

TERMINATE_BUILD_NUM = "1398786"
TERMINATE_SERVER_VERSION = "8.8.0"
COMMAND_DATA_KEYS = ["failed_files", "retention_date", "retrieved_files", "standard_output", "command_output", "execution_status"]
EXECUTE_COMMAND_READABLE_OUTPUT_FIELDS = [
    "endpoint_id",
    "command",
    "command_output",
    "endpoint_ip_address",
    "endpoint_name",
    "endpoint_status",
]


class Client(CoreClient):
    def test_module(self):
        """
        Performs basic get request to get item samples
        """
        try:
            self.get_endpoints(limit=1)
        except Exception as err:
            if "API request Unauthorized" in str(err):
                # this error is received from the Core server when the client clock is not in sync to the server
                raise DemistoException(f"{err!s} please validate that your both XSOAR and Core server clocks are in sync")
            else:
                raise

    def report_incorrect_wildfire(self, file_hash: str, new_verdict: int, reason: str, email: str) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            "hash": file_hash,
            "new_verdict": new_verdict,
            "reason": reason,
            "email": email,
        }

        reply = demisto._apiCall(method="POST", name="wfReportIncorrectVerdict", params=None, data=json.dumps(request_data))

        return reply

    def get_prevalence(self, request_data: dict):
        reply = self._http_request(
            method="POST", json_data={"request_data": request_data}, headers=self._headers, url_suffix="/analytics_apis/"
        )
        return reply

    def get_asset_details(self, asset_id):
        reply = self._http_request(
            method="POST",
            json_data={"asset_id": asset_id},
            headers=self._headers,
            url_suffix="/unified-asset-inventory/get_asset/",
        )
        return reply

    def post_indicator_rule(self, request_data: Union[dict, str], suffix: str):
        reply = self._http_request(
            method="POST", json_data={"request_data": request_data, "validate": True}, headers=self._headers, url_suffix=suffix
        )
        return reply


def report_incorrect_wildfire_command(client: Client, args) -> CommandResults:
    file_hash = args.get("file_hash")
    reason = args.get("reason")
    email = args.get("email")
    new_verdict = arg_to_int(
        arg=args.get("new_verdict"), arg_name='Failed to parse "new_verdict". Must be a number.', required=True
    )

    response = client.report_incorrect_wildfire(file_hash, new_verdict, reason, email)
    return CommandResults(
        readable_output=f"Reported incorrect WildFire on {file_hash}",
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.WildFire",
        outputs={"file_hash": file_hash, "new_verdict": new_verdict},
        raw_response=response,
    )


def handle_prevalence_command(client: Client, command: str, args: dict):
    key_names_in_response = {
        "ip": "ip_address",
        "domain": "domain_name",
        "process": "process_name",
        "cmd": "process_command_line",
        "hash": "sha256",
        "registry": "key_name",
    }
    args.pop("integration_context_brand", None)
    args.pop("integration_name", None)
    if command == "core-get-registry-analytics-prevalence":
        # arg list should in the following structure:
        #   args: [
        #       {"key_name": "some_key1", "value_name": "some_value1"},
        #       {"key_name": "some_key2", "value_name": "some_value2"}
        #       ]

        args_list = []
        keys = argToList(args.get("key_name"))
        values = argToList(args.get("value_name"))
        if len(keys) != len(values):
            raise DemistoException(
                "Number of elements in key_name argument should be equal to the number of elements in value_name argument."
            )
        for key, value in zip(keys, values):
            args_list.append({"key_name": key, "value_name": value})
    else:
        args_list = []
        for key, value in args.items():
            values = argToList(value)
            for val in values:
                args_list.append({key: val})

    request_body = {"api_id": command, "args": args_list}
    res = client.get_prevalence(request_body).get("results", [])
    for item in res:  # remove 'args' scope
        name = item.pop("args", {})
        item.update(name)
    command_type = PREVALENCE_COMMANDS[command]
    return CommandResults(
        readable_output=tableToMarkdown(
            string_to_table_header(f"{command_type} Prevalence"),
            [
                {
                    key_names_in_response[command_type]: item.get(key_names_in_response[command_type]),
                    "Prevalence": item.get("value"),
                }
                for item in res
            ],
            headerTransform=string_to_table_header,
        ),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AnalyticsPrevalence.{command_type.title()}",
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


def parse_expiration_date(expiration: Optional[str]) -> Optional[Union[int, str]]:
    """
     Converts relative expiration strings / numbers to epoch milliseconds or returns 'Never'.

    Args:
        expiration Optional[str]: The input from the command argument

    Returns:
        Optional[int, str]: The valiue that represent the expiration date of the IOC rule:
            None: the rule get a default value.
            str: "Never" - The rule has no expiration date.
            int: epoch milliseconds of the expiration date.
    """

    if not expiration:
        return None
    if expiration == "Never":
        return "Never"

    def convert_datetime_to_epoch_milli(dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def is_relative_time_format(s: str) -> bool:
        """
        Returns True if the input matches a relative time format:
        'N minutes', 'N hours', 'N days', 'N weeks', 'N months', 'N years'
        """
        if not isinstance(s, str):
            return False

        pattern = r"^\s*\d+\s+(minutes|hours|days|weeks|months|years)\s*$"
        return bool(re.match(pattern, s, flags=re.IGNORECASE))

    now_epoch_milli = convert_datetime_to_epoch_milli(get_current_time())
    try:
        datetime_arg = arg_to_datetime(expiration)
    except ValueError:
        return expiration

    if datetime_arg:
        is_relative_time_format_flag = is_relative_time_format(expiration)
        datetime_arg_epoch_milli = convert_datetime_to_epoch_milli(datetime_arg)
        if is_relative_time_format_flag:
            # Using arg_to_datetime that takes relative time and converts it into datetime (if its relative then in the past)
            delta = now_epoch_milli - datetime_arg_epoch_milli
            # the arg_to_datetime returned a time in the past
            return now_epoch_milli + delta
        else:
            return datetime_arg_epoch_milli
    else:
        raise DemistoException("The expiration date cannot be converted to epoch milliseconds.")


def prepare_ioc_to_output(ioc_payload: Union[dict, str], input_format: str) -> dict:
    """
    Prepare the IOC data to output:
        if it's a Dictionary - return it, else converts a single-row CSV IOC definition into a JSON object (Python dict).

    Args:
        ioc_payload Union[dict, str]: the data contained in the IOC payload.
        input_format str: representing what is the input format.

    Returns:
        dict: Parsed JSON-style IOC object.
    """
    if input_format == "JSON":
        return cast(dict, ioc_payload)

    ioc_payload = cast(str, ioc_payload)

    # Split CSV string into lines
    lines = ioc_payload.strip().splitlines()
    header = lines[0].split(",")
    values = lines[1].split(",")

    # Map headers to values, collecting all duplicate fields
    # Create a flat mapping, keeping the last occurrence of each header
    field_map: dict[str, Any] = {}
    for i, key in enumerate(header):
        field_map[key] = values[i]  # always overwrite (keep last)

    if "expiration_date" in field_map:
        int_val_date = int(field_map["expiration_date"])
        field_map["expiration_date"] = int_val_date

    # Extract vendor fields
    vendor_name = field_map.pop("vendor.name", None)
    vendor_reliability = field_map.pop("vendor.reliability", None)
    vendor_reputation = field_map.pop("vendor.reputation", None)

    # Attach vendor only if name exists
    if vendor_name:
        field_map["vendors"] = [{"vendor_name": vendor_name, "reliability": vendor_reliability, "reputation": vendor_reputation}]

    return field_map


def core_execute_command_reformat_readable_output(script_res: list) -> str:
    """
    Reformat the human-readable output of the 'core_execute_command' command
    so that each command appears as a separate row in the table.

    Args:
        script_res (list): The result from the polling command.

    Returns:
        str: Reformatted human-readable output
    """
    reformatted_results = []
    for response in script_res:
        results = response.outputs.get("results")
        for res in results:
            # for each result, get only the data we want to present to the user
            reformatted_result = {}
            for key in EXECUTE_COMMAND_READABLE_OUTPUT_FIELDS:
                reformatted_result[key] = res.get(key)
            # remove the underscore prefix from the command name
            reformatted_result["command"] = reformatted_result["command"].removeprefix("_")
            reformatted_results.append(reformatted_result)
    return tableToMarkdown(
        f'Script Execution Results for Action ID: {script_res[0].outputs["action_id"]}',
        reformatted_results,
        EXECUTE_COMMAND_READABLE_OUTPUT_FIELDS,
        removeNull=True,
        headerTransform=string_to_table_header,
    )


def core_execute_command_reformat_command_data(result: dict) -> dict:
    """
    Create a dictionary containing all relevant command data from the result.

    Args:
        result (dict): Data from the execution of a command on a specific endpoint.

    Returns:
        dict: all relevant command data from the result
    """
    reformatted_command = {"command": result["command"].removeprefix("_")}  # remove the underscore prefix from the command name
    for key in COMMAND_DATA_KEYS:
        reformatted_command[key] = result.get(key)
    return reformatted_command


def core_execute_command_reformat_outputs(script_res: list) -> list:
    """
    Reformats the context outputs so that each endpoint has its own result section, without any duplicated data.

    Args:
        script_res (list): The result from the polling command.

    Returns:
        list: Reformatted context outputs
    """
    new_results: dict[str, Any] = {}
    for response in script_res:
        results = response.outputs.get("results")
        for res in results:
            endpoint_id = res.get("endpoint_id")
            if endpoint_id in new_results:
                # if the endpoint already exists - adding the command data to new_results (the endpoint data already in)
                new_results[endpoint_id]["executed_command"].append(core_execute_command_reformat_command_data(res))
                # the context output include for each result a field with the name of each command, we want to remove it
                command_name = res.get("command")
                new_results[endpoint_id].pop(command_name)
            else:
                # if the endpoint doesn't already exist - adding all the data into new_results[endpoint]
                # relocate all the data related to the command to be under executed_command
                reformatted_res = deepcopy(res)
                reformatted_res["executed_command"] = [core_execute_command_reformat_command_data(res)]
                # remove from reformatted_res all the data we put under executed_command
                command_name = reformatted_res.pop("command")
                reformatted_res.pop(command_name)
                for key in COMMAND_DATA_KEYS:
                    reformatted_res.pop(key)
                new_results[endpoint_id] = reformatted_res
    # reformat new_results from {"endpoint_id_1": {values_1}, "endpoint_id_2": {values_2}}
    # to [{values_1}, {values_2}] (values include the endpoint_id)
    reformatted_results = [new_results[i] for i in new_results]
    return reformatted_results


def core_execute_command_reformat_args(args: dict) -> dict:
    """
    Create new dict with the original args and add
    is_core, script_uid and parameters fields to it before starting the polling.

    Args:
        args (dict): Dictionary containing the arguments for the command.

    Returns:
        dict: reformatted args.
    """
    commands = args.get("command")
    if not commands:
        raise DemistoException("'command' is a required argument.")
    # the value of script_uid is the Unique identifier of execute_commands script.
    reformatted_args = args | {"is_core": True, "script_uid": "a6f7683c8e217d85bd3c398f0d3fb6bf"}
    is_raw_command = argToBoolean(args.get("is_raw_command", False))
    commands_list = [commands] if is_raw_command else argToList(commands, args.get("command_separator", ","))
    if args.get("command_type") == "powershell":
        commands_list = [form_powershell_command(command) for command in commands_list]
    reformatted_args["parameters"] = json.dumps({"commands_list": commands_list})
    return reformatted_args


def core_execute_command_command(client: Client, args: dict) -> PollResult:
    """
    Run executed_command script and reformat it's results.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.

    Returns:
        PollResult: Reformatted script_run_polling_command result.
    """
    reformatted_args = core_execute_command_reformat_args(args)
    script_res = script_run_polling_command(reformatted_args, client, statuses=("PENDING", "IN_PROGRESS", "PENDING_ABORT"))
    # script_res = [CommandResult] if it's the final result (ScriptResult)
    # else if the polling still continue, script_res = CommandResult
    if isinstance(script_res, list):
        script_res[0].readable_output = core_execute_command_reformat_readable_output(script_res)
        script_res[0].outputs["results"] = core_execute_command_reformat_outputs(script_res)
    elif isinstance(script_res, CommandResults):
        # delete ScriptRun from context data
        script_res.outputs = None
    return script_res


def core_add_indicator_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Add Indicator Rule to XSIAM command.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                    - indicator (str): String that identifies the indicator to insert into Cortex. **Required.**
                    - type (str): Type of indicator. One of: 'HASH', 'IP', 'PATH', 'DOMAIN_NAME', 'FILENAME'. **Required.**
                    - severity (str): Indicator severity. One of: 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'. **Required.**
                    - expiration_date (str, optional): Expiration as relative time ('7 days', '30 days', etc.), epoch millis,
                     or "Never". If null, defaults by type.
                    - comment (str, optional): Comment string describing the indicator.
                    - reputation (str, optional): Indicator reputation. One of: 'GOOD', 'BAD', 'SUSPICIOUS', 'UNKNOWN'.
                    - reliability (str, optional): Reliability rating (A-F). A is most reliable, F is least.
                    - class (str, optional): Indicator classification (e.g., "Malware").
                    - vendor_name (str, optional): Name of the vendor reporting the indicator.
                    - vendor_reputation (str, optional): Vendor reputation. Required if vendor_name is provided. One of: 'GOOD',
                        'BAD',
                     'SUSPICIOUS', 'UNKNOWN'.
                    - vendor_reliability (str, optional): Vendor reliability rating (A-F).
                        Required if vendor_reputation is provided.
                    - input_format (str, optional): Input format. One of: 'CSV', 'JSON'. Defaults to 'JSON'.
                    - ioc_object (str, optional): Full IOC object as JSON or CSV string, depending on input_format.

    Returns:
        CommandResults: Object containing the formatted asset details,
                        raw response, and outputs for integration context.
    """
    # Required arguments
    indicator = args["indicator"]
    indicator_type = args["type"]
    severity = args["severity"]
    ioc_object = args.get("ioc_object")

    # Optional arguments
    expiration_date = args.get("expiration_date")
    comment = args.get("comment")
    reputation = args.get("reputation")
    reliability = args.get("reliability")
    indicator_class = args.get("class")
    vendor_name = args.get("vendor_name")
    vendor_reputation = args.get("vendor_reputation")
    vendor_reliability = args.get("vendor_reliability")
    input_format = args.get("input_format", "JSON")  # Default to 'JSON'

    ioc_payload: Union[dict, str]

    # Handle pre-built IOC object
    if ioc_object:
        # Try to detect JSON
        try:
            ioc_payload = json.loads(ioc_object)
            input_format = "JSON"
        except json.JSONDecodeError:
            # Not JSON, check if it looks like CSV (very basic check)
            if "," in ioc_object and ("\\n" in ioc_object or "\n" in ioc_object):
                ioc_object = ioc_object.replace("\\n", "\n")
                ioc_payload = ioc_object  # Leave as raw string
                input_format = "CSV"
            else:
                raise DemistoException("Core Add Indicator Rule Command: Invalid ioc_object"
                                       " must be either valid JSON or CSV string.")
    else:
        if not (indicator and indicator_type and severity):
            raise DemistoException(
                "Core Add Indicator Rule Command: when 'ioc_object' is not provided,"
                " 'indicator', 'type', and 'severity' are required arguments.")
        # Build payload from individual arguments
        ioc_payload = {"indicator": indicator, "type": indicator_type, "severity": severity}
        parsed_expiration_date = parse_expiration_date(expiration_date)
        ioc_payload["expiration_date"] = parsed_expiration_date
        ioc_payload["comment"] = comment
        ioc_payload["reputation"] = reputation
        ioc_payload["reliability"] = reliability
        ioc_payload["class"] = indicator_class

        if vendor_name:
            ioc_payload["vendors"] = [
                {"vendor_name": vendor_name, "reliability": vendor_reliability, "reputation": vendor_reputation}
            ]
        input_format = "JSON"

    # Request According to format
    if input_format == "CSV":
        suffix = "indicators/insert_csv"
    else:
        suffix = "indicators/insert_jsons"

    try:
        response = client.post_indicator_rule(ioc_payload, suffix=suffix)
    except DemistoException as error:
        raise DemistoException(f"Core Add Indicator Rule Command: During post, exception occurred {str(error)}")

    is_success = response["reply"]["success"]

    if not is_success:
        # Something went wrong in the creation of new IOC rule.
        errors_array = []
        for error_obj in response["reply"]["validation_errors"]:
            errors_array.append(error_obj["error"])
        error_string = ", ".join(errors_array)
        raise DemistoException(f"Core Add Indicator Rule Command: post of IOC rule failed: {error_string}")

    ioc_payload_output = prepare_ioc_to_output(ioc_payload, input_format)
    return CommandResults(
        readable_output=f"IOC {ioc_payload_output['indicator']} was successfully added.",
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Indicator",
        outputs=ioc_payload_output,
        raw_response=response,
    )


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    LOG(f"Command being called is {command}")
    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME
    headers = {}
    url_suffix = "/xsiam" if command in PREVALENCE_COMMANDS else "/public_api/v1"
    if not FORWARD_USER_RUN_RBAC:
        api_key = demisto.params().get("apikey")
        api_key_id = demisto.params().get("apikey_id")
        url = demisto.params().get("url")

        if not api_key or not api_key_id or not url:
            headers = {
                "HOST": demisto.getLicenseCustomField("Core.ApiHostName"),
                demisto.getLicenseCustomField("Core.ApiHeader"): demisto.getLicenseCustomField("Core.ApiKey"),
                "Content-Type": "application/json",
            }
            url = "http://" + demisto.getLicenseCustomField("Core.ApiHost") + "/api/webapp/"
            add_sensitive_log_strs(demisto.getLicenseCustomField("Core.ApiKey"))
        else:
            headers = {"Content-Type": "application/json", "x-xdr-auth-id": str(api_key_id), "Authorization": api_key}
            add_sensitive_log_strs(api_key)
    else:
        url = "/api/webapp/"
    base_url = urljoin(url, url_suffix)
    proxy = demisto.params().get("proxy")
    verify_cert = not demisto.params().get("insecure", False)

    try:
        timeout = int(demisto.params().get("timeout", 120))
    except ValueError as e:
        demisto.debug(f"Failed casting timeout parameter to int, falling back to 120 - {e}")
        timeout = 120
    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers,
        timeout=timeout,
    )

    try:
        if command == "test-module":
            client.test_module()
            demisto.results("ok")

        elif command == "core-get-endpoints":
            return_results(get_endpoints_command(client, args))

        elif command == "core-endpoint-alias-change":
            return_results(endpoint_alias_change_command(client, **args))

        elif command == "core-isolate-endpoint" or command == "core-isolate-endpoint-quick-action":
            polling_args = {**args, "endpoint_id_list": args.get("endpoint_id")}
            return_results(
                run_polling_command(
                    client=client,
                    args=polling_args,
                    cmd=command,
                    command_function=isolate_endpoint_command,
                    command_decision_field="action_id",
                    results_function=get_endpoints_command,
                    polling_field="is_isolated",
                    polling_value=["AGENT_ISOLATED"],
                    stop_polling=True,
                )
            )

        elif command == "core-unisolate-endpoint":
            polling_args = {**args, "endpoint_id_list": args.get("endpoint_id")}
            return_results(
                run_polling_command(
                    client=client,
                    args=polling_args,
                    cmd="core-unisolate-endpoint",
                    command_function=unisolate_endpoint_command,
                    command_decision_field="action_id",
                    results_function=get_endpoints_command,
                    polling_field="is_isolated",
                    polling_value=[
                        "AGENT_UNISOLATED",
                        "CANCELLED",
                        "ֿPENDING_ABORT",
                        "ABORTED",
                        "EXPIRED",
                        "COMPLETED_PARTIAL",
                        "COMPLETED_SUCCESSFULLY",
                        "FAILED",
                        "TIMEOUT",
                    ],
                    stop_polling=True,
                )
            )

        elif command == "core-get-distribution-url":
            return_results(get_distribution_url_command(client, args))

        elif command == "core-get-create-distribution-status":
            return_outputs(*get_distribution_status_command(client, args))

        elif command == "core-get-distribution-versions":
            return_outputs(*get_distribution_versions_command(client, args))

        elif command == "core-create-distribution":
            return_outputs(*create_distribution_command(client, args))

        elif command == "core-get-audit-management-logs":
            return_outputs(*get_audit_management_logs_command(client, args))

        elif command == "core-get-audit-agent-reports":
            return_outputs(*get_audit_agent_reports_command(client, args))

        elif command == "core-blocklist-files":
            return_results(blocklist_files_command(client, args))

        elif command == "core-allowlist-files":
            return_results(allowlist_files_command(client, args))

        elif command == "core-quarantine-files" or command == "core-quarantine-files-quick-action":
            polling_args = {**args, "endpoint_id": argToList(args.get("endpoint_id_list"))[0]}
            return_results(
                run_polling_command(
                    client=client,
                    args=polling_args,
                    cmd=command,
                    command_function=quarantine_files_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-get-quarantine-status":
            return_results(get_quarantine_status_command(client, args))

        elif command == "core-restore-file" or command == "core-restore-file-quick-action":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd=command,
                    command_function=restore_file_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-endpoint-scan" or command == "core-endpoint-scan-quick-action":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd=command,
                    command_function=endpoint_scan_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-endpoint-scan-abort":
            return_results(endpoint_scan_abort_command(client, args))

        elif command == "core-delete-endpoints":
            return_outputs(*delete_endpoints_command(client, args))

        elif command == "core-get-policy":
            return_outputs(*get_policy_command(client, args))

        elif command == "core-get-endpoint-device-control-violations":
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif command == "core-retrieve-files" or command == "core-retrieve-files-quick-action":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd=command,
                    command_function=retrieve_files_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-retrieve-file-details":
            return_entry, file_results = retrieve_file_details_command(client, args, False)
            demisto.results(return_entry)
            if file_results:
                demisto.results(file_results)

        elif command == "core-get-scripts":
            return_outputs(*get_scripts_command(client, args))

        elif command == "core-get-script-metadata":
            return_outputs(*get_script_metadata_command(client, args))

        elif command == "core-get-script-code":
            return_outputs(*get_script_code_command(client, args))

        elif command == "core-action-status-get":
            return_results(action_status_get_command(client, args))

        elif command == "core-run-script":
            return_results(run_script_command(client, args))

        elif command == "core-script-run" or command == "core-script-run-quick-action":
            args = args | {"is_core": True}
            return_results(script_run_polling_command(args, client))

        elif command == "core-run-snippet-code-script":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-run-snippet-code-script",
                    command_function=run_snippet_code_script_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-get-script-execution-status":
            return_results(get_script_execution_status_command(client, args))

        elif command == "core-get-script-execution-results":
            return_results(get_script_execution_results_command(client, args))

        elif command == "core-get-script-execution-result-files":
            return_results(get_script_execution_result_files_command(client, args))

        elif command == "core-run-script-execute-commands":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-run-script-execute-commands",
                    command_function=run_script_execute_commands_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-run-script-delete-file":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-run-script-delete-file",
                    command_function=run_script_delete_file_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-run-script-file-exists":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-run-script-file-exists",
                    command_function=run_script_file_exists_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "core-run-script-kill-process":
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-run-script-kill-process",
                    command_function=run_script_kill_process_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                )
            )

        elif command == "endpoint":
            return_results(endpoint_command(client, args))

        elif command == "core-report-incorrect-wildfire":
            return_results(report_incorrect_wildfire_command(client, args))

        elif command == "core-remove-blocklist-files":
            return_results(remove_blocklist_files_command(client, args))

        elif command == "core-remove-allowlist-files":
            return_results(remove_allowlist_files_command(client, args))

        elif command == "core-add-exclusion":
            return_results(add_exclusion_command(client, args))

        elif command == "core-delete-exclusion":
            return_results(delete_exclusion_command(client, args))

        elif command == "core-get-exclusion":
            return_results(get_exclusion_command(client, args))

        elif command == "core-get-cloud-original-alerts":
            return_results(get_original_alerts_command(client, args))

        elif command == "core-get-dynamic-analysis":
            return_results(get_dynamic_analysis_command(client, args))

        elif command == "core-add-endpoint-tag":
            return_results(add_tag_to_endpoints_command(client, args))

        elif command == "core-remove-endpoint-tag":
            return_results(remove_tag_from_endpoints_command(client, args))

        elif command == "core-list-users":
            return_results(list_users_command(client, args))

        elif command == "core-list-risky-users":
            return_results(list_risky_users_or_host_command(client, "user", args))

        elif command == "core-list-risky-hosts":
            return_results(list_risky_users_or_host_command(client, "host", args))

        elif command == "core-list-user-groups":
            return_results(list_user_groups_command(client, args))

        elif command == "core-get-incidents":
            return_outputs(*get_incidents_command(client, args))

        elif command == "core-terminate-process":
            if not is_demisto_version_ge(version=TERMINATE_SERVER_VERSION, build_number=TERMINATE_BUILD_NUM):
                raise DemistoException("This command is only available for XSIAM 2.4 and above")
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd="core-terminate-process",
                    command_function=terminate_process_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                    values_raise_error=["FAILED", "TIMEOUT", "ABORTED", "CANCELED"],
                )
            )

        elif command == "core-terminate-causality" or command == "core-terminate-causality-quick-action":
            if not is_demisto_version_ge(version=TERMINATE_SERVER_VERSION, build_number=TERMINATE_BUILD_NUM):
                raise DemistoException("This command is only available for XSIAM 2.4 and above")
            return_results(
                run_polling_command(
                    client=client,
                    args=args,
                    cmd=command,
                    command_function=terminate_causality_command,
                    command_decision_field="action_id",
                    results_function=action_status_get_command,
                    polling_field="status",
                    polling_value=["PENDING", "IN_PROGRESS", "PENDING_ABORT"],
                    values_raise_error=["FAILED", "TIMEOUT", "ABORTED", "CANCELED"],
                )
            )

        elif command == "core-get-asset-details":
            return_results(get_asset_details_command(client, args))

        elif command == "core-execute-command":
            return_results(core_execute_command_command(client, args))

        elif command == "core-add-indicator-rule":
            return_results(core_add_indicator_rule_command(client, args))

        elif command in PREVALENCE_COMMANDS:
            return_results(handle_prevalence_command(client, command, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
