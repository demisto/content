import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *
from copy import deepcopy

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Core - IR"
AGENTS_TABLE = "AGENTS_TABLE"
MAX_GET_ENDPOINTS_LIMIT = 100

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
PRIVATE_API_COMMANDS = ["core-list-endpoints"]

TERMINATE_BUILD_NUM = "1398786"
TERMINATE_SERVER_VERSION = "8.8.0"
COMMAND_DATA_KEYS = [
    "failed_files",
    "retention_date",
    "retrieved_files",
    "standard_output",
    "command",
    "command_output",
    "execution_status",
]
EXECUTE_COMMAND_READABLE_OUTPUT_FIELDS = [
    "endpoint_id",
    "command",
    "command_output",
    "endpoint_ip_address",
    "endpoint_name",
    "endpoint_status",
]
ERROR_CODE_MAP = {
    -199: "IP_BLOCK_DISABLED_BY_POLICY",
    -198: "INVALID_IP_ADDRESS",
    -197: "IP_ADDRESS_ALREADY_BLOCKED",
    -196: "IP_ADDRESS_WHITELISTED",
    -195: "IP_ADDRESS_NOT_BLOCKED",
    -194: "IP_ADDRESS_NOT_BLOCKED_BUT_WHITELISTED",
    -193: "IP_IS_LOOPBACK",
    -192: "IPV6_BLOCKING_IS_DISABLED",
    -191: "IP_IS_LOCAL_ADDRESS",
}
ENDPOINT_TYPE = {
    "mobile": "AGENT_TYPE_MOBILE",
    "server": "AGENT_TYPE_SERVER",
    "workstation": "AGENT_TYPE_WORKSTATION",
    "containerized": "AGENT_TYPE_CONTAINERIZED",
    "serverless": "AGENT_TYPE_SERVERLESS"
}
ENDPOINT_STATUS = {
    "connected": "STATUS_010_CONNECTED",
    "lost": "STATUS_020_LOST",
    "disconnected": "STATUS_040_DISCONNECTED",
    "uninstalled": "STATUS_050_UNINSTALLED",
    "vdi pending login": "STATUS_060_VDI_PENDING_LOG_ON",
    "forensics offline": "STATUS_070_FORENSICS_OFFLINE"
}
ENDPOINT_PLATFORM = {
    "windows": "AGENT_OS_WINDOWS",
    "mac": "AGENT_OS_MAC",
    "linux": "AGENT_OS_LINUX",
    "android": "AGENT_OS_ANDROID",
    "ios": "AGENT_OS_IOS",
    "serverless": "AGENT_OS_SERVERLESS"
}
ENDPOINT_OPERATIONAL_STATUS = {
    "protected": "PROTECTED",
    "partially protected": "PARTIALLY_PROTECTED",
    "unprotected": "UNPROTECTED"
}
ASSIGNED_PREVENTION_POLICY = {
    "pcastro": "0a80deae95e84a90a26e0586a7a6faef",
    "Caas Default": "236a259c803d491484fc5f6d0c198676",
    "kris": "31987a7fb890406ca70287c1fc582cbf",
    "democloud": "44fa048803db4a8f989125a3887baf68",
    "Linux Default": "705e7aae722f45c5ab2926e2639b295f",
    "Android Default": "874e0fb9979c44459ca8f2dfdb3f03d9",
    "Serverless Function Default": "c68bb058bbf94bbcb78d748191978d3b",
    "macOS Default": "c9fd93fcee42486fb270ae0acbb7e0fb",
    "iOS Default": "dc2e804c147f4549a6118c96a5b0d710",
    "Windows Default": "e1f6b443a1e24b27955af39b4c425556",
    "bcpolicy": "f32766a625db4cc29b5dddbfb721fe58"
}
ENDPOINT_FIELDS = {
    "endpoint_name": "HOST_NAME",
    "endpoint_type": "AGENT_TYPE",
    "endpoint_status": "AGENT_STATUS",
    "platform": "OS_TYPE", 
    "operating_system": "OS_DESC",
    "agent_version": "AGENT_VERSION",
    "agent_eol": "SUPPORTED_VERSION",
    "os_version": "OS_VERSION",
    "ip_address": "IP",
    "domain": "DOMAIN",
    "assigned_prevention_policy": "ACTIVE_POLICY",
    "group_name": "GROUP_ID",
    "tags": "TAGS",
    "endpoint_id": "AGENT_ID",
    "operational_status": "OPERATIONAL_STATUS",
    "cloud_provider": "CLOUD_PROVIDER",
    "cloud_region": "CLOUD_REGION",
}
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

    def create_indicator_rule_request(self, request_data: Union[dict, str], suffix: str):
        reply = self._http_request(
            method="POST", json_data={"request_data": request_data, "validate": True}, headers=self._headers, url_suffix=suffix
        )
        return reply

    def _is_endpoint_connected(self, endpoint_id: str) -> bool:
        """
        Helper method to check if an endpoint is connected
        """
        endpoint_status = self.get_endpoints(endpoint_id_list=[endpoint_id], status="connected")
        return bool(endpoint_status)

    def block_ip_request(self, endpoint_id: str, ip_list: list[str], duration: int) -> list[dict[str, Any]]:
        """
        Block one or more IPs on a given endpoint and collect action IDs.
        If endpoint disconnected/not exists the group id will be None.
        Args:
            endpoint_id (str): ID of the endpoint to apply the block.
            ip_list (list[str]): IP addresses to block.
            duration (int): Block duration in seconds.

        Returns:
            list[dict]: A list of action records, each containing:
                - ip_address (str): The blocked IP.
                - endpoint_id (str): The endpoint where the block was applied.
                - group_id (str): ID of the block action for status polling.
        """
        results = []
        if not self._is_endpoint_connected(endpoint_id):
            demisto.debug(f"Cannot block ip list. Endpoint {endpoint_id} is not connected.")
            return [{"ip_address": ip_address, "group_id": None, "endpoint_id": endpoint_id} for ip_address in ip_list]

        for ip_address in ip_list:
            demisto.debug(f"Blocking ip address: {ip_address}")
            response = self._http_request(
                method="POST",
                headers=self._headers,
                url_suffix="/endpoints/block_ip",
                json_data={
                    "request_data": {
                        "addresses": [ip_address],
                        "endpoint_id": endpoint_id,
                        "direction": "both",
                        "duration": duration,
                    }
                },
            )
            group_id = response.get("reply", {}).get("group_action_id")
            demisto.debug(f"Block request for {ip_address} returned with group_id {group_id}")
            results.append(
                {
                    "ip_address": ip_address,
                    "group_id": group_id,
                    "endpoint_id": endpoint_id,
                }
            )

        return results

    def fetch_block_status(self, group_id: int, endpoint_id: str) -> tuple[str, str]:
        """
        Check for status of blocking ip action.

        Args:
            group_id (int): The group id returned from the block request.
            endpoint_id (str): The ID of the endpoint whose block status is being checked.

        Returns:
            tuple[str, str]:
                - status: The returned status from the api.
                - message: The returned error text.
        """
        if not self._is_endpoint_connected(endpoint_id) or not group_id:
            demisto.debug(f"Cannot fetch status. Endpoint {endpoint_id} is not connected.")
            return "Failure", "Endpoint Disconnected"

        if group_id == "INVALID_IP":
            return "Failure", "INVALID_IP"

        reply = self.action_status_get(group_id)
        status = reply.get("data", {}).get(endpoint_id)
        error_reasons = reply.get("errorReasons", {})
        if status == "FAILED":
            reason = error_reasons.get(endpoint_id, {})
            text = reason.get("errorText")

            if not text and reason.get("errorData"):
                try:
                    payload = json.loads(reason["errorData"])
                    text = payload.get("errorText")
                except (ValueError, TypeError):
                    text = reason["errorData"]

            match = re.search(r"error code\s*(-?\d+)", text or "")
            error_number = int(match.group(1)) if match else 0

            demisto.debug(f"Error number {error_number}")
            return "Failure", ERROR_CODE_MAP.get(error_number) or text or "Unknown error"

        if status == "COMPLETED_SUCCESSFULLY":
            return "Success", ""

        return status or "Unknown", ""

    def get_contributing_event_by_alert_id(self, alert_id: int):
        """_summary_

        Args:
            alert_id (int): _description_

        Returns:
            _type_: _description_
        """
        request_data = {
            "request_data": {
                "alert_id": alert_id,
            }
        }
        try:
            reply = self._http_request(
                method="POST",
                json_data=request_data,
                headers=self._headers,
                url_suffix="/alerts/get_correlation_alert_data/",
            )

            return reply
        except Exception as e:
            if "[404]" in str(e):
                raise DemistoException(f"Got 404 when querying for alert ID {alert_id}, alert not found.")
            else:
                raise e
            
    def get_webapp_data(self, request_data: dict):
        reply = self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
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
        Optional[int, str]: The value that represent the expiration date of the IOC rule:
            None: the rule get a default value.
            str: "Never" - The rule has no expiration date.
            int: epoch milliseconds of the expiration date.
    """
    # Return None - give the indicator the default expiration date value for the indicator type
    if not expiration:
        return None

    if expiration.lower() == "never":
        return "Never"

    try:
        dt = arg_to_datetime(expiration)
    except ValueError:
        return expiration  # Invalid input, pass through

    if dt:
        # check if the input matches a relative time format:
        if bool(re.match(r"^\s*\d+\s+(minutes|hours|days|weeks|months|years)\s*$", expiration, flags=re.IGNORECASE)):
            # Using dt that takes relative time and converts it into datetime (if its relative then in the past)
            now = date_to_timestamp(get_current_time())
            # the dt is a time in the past
            delta = now - date_to_timestamp(dt)
            return now + delta
        else:
            return date_to_timestamp(dt)
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
    if input_format.upper() == "JSON":
        if not isinstance(ioc_payload, dict):
            raise ValueError("Expected a dict for JSON input format.")
        return ioc_payload

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
            if isinstance(reformatted_result["command"], str):
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
    reformatted_command = {}
    for key in COMMAND_DATA_KEYS:
        reformatted_command[key] = result.get(key)
    reformatted_command["command"] = (
        result["command"].removeprefix("_") if isinstance(result.get("command"), str) else None
    )  # remove the underscore prefix from the command name
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
                new_results[endpoint_id].pop(command_name, None)
            else:
                # if the endpoint doesn't already exist - adding all the data into new_results[endpoint]
                # relocate all the data related to the command to be under executed_command
                reformatted_res = deepcopy(res)
                reformatted_res["executed_command"] = [core_execute_command_reformat_command_data(res)]
                # remove from reformatted_res all the data we put under executed_command
                command_name = reformatted_res.pop("command", None)
                reformatted_res.pop(command_name, None)
                for key in COMMAND_DATA_KEYS:
                    reformatted_res.pop(key, None)
                new_results[endpoint_id] = reformatted_res
    # reformat new_results from {"endpoint_id_1": {values_1}, "endpoint_id_2": {values_2}}
    # to [{values_1}, {values_2}] (values include the endpoint_id)
    return list(new_results.values())


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
    indicator = args.get("indicator")
    indicator_type = args.get("type")
    severity = args.get("severity")
    ioc_object = args.get("ioc_object")
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
        if input_format == "CSV":
            ioc_object = ioc_object.replace("\\n", "\n")
            ioc_payload = ioc_object  # Leave as raw string
        else:
            # Try to detect JSON
            try:
                ioc_payload = json.loads(ioc_object)
            except json.JSONDecodeError:
                raise DemistoException("Core Add Indicator Rule Command: The IOC object provided isn't in a valid JSON format.")
    else:
        if not (indicator and indicator_type and severity):
            raise DemistoException(
                "Core Add Indicator Rule Command: when 'ioc_object' is not provided,"
                " 'indicator', 'type', and 'severity' are required arguments."
            )
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
        response = client.create_indicator_rule_request(ioc_payload, suffix=suffix)
    except DemistoException as error:
        raise DemistoException(f"Core Add Indicator Rule Command: During post, exception occurred {str(error)}")

    is_success = response.get("reply", {}).get("success")

    if not is_success:
        # Something went wrong in the creation of new IOC rule.
        errors_array = []
        for error_obj in response["reply"]["validation_errors"]:
            errors_array.append(error_obj["error"])
        error_string = ", ".join(errors_array)
        raise DemistoException(f"Core Add Indicator Rule Command: post of IOC rule failed: {error_string}")

    ioc_payload_output = prepare_ioc_to_output(ioc_payload, input_format)
    return CommandResults(
        readable_output=f"IOC rule for {ioc_payload_output['indicator']} was successfully added.",
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Indicator",
        outputs=ioc_payload_output,
        raw_response=response,
    )


def core_get_contributing_event_command(client: Client, args: Dict) -> CommandResults:
    """Gets the contributing events for specific alert IDs.

    Args:
        client (Client): The Core client
        args (dict): Dictionary containing the arguments for the command.

    Returns:
        CommandResults: Object containing the formatted asset details,
                        raw response, and outputs for integration context.
    """
    alert_ids = argToList(args.get("alert_ids"))
    alerts = []

    for alert_id in alert_ids:
        if alert := client.get_contributing_event_by_alert_id(int(alert_id)).get("reply", {}):
            page_number = max(int(args.get("page_number", 1)), 1) - 1  # Min & default zero (First page)
            page_size = max(int(args.get("page_size", 50)), 0)  # Min zero & default 50
            offset = page_number * page_size
            limit = max(int(args.get("limit", 0)), 0) or offset + page_size

            alert_with_events = {
                "alertID": str(alert_id),
                "events": alert.get("events", [])[offset:limit],
            }
            alerts.append(alert_with_events)

    readable_output = tableToMarkdown(
        "Contributing events", alerts, headerTransform=pascalToSpace, removeNull=True, is_auto_json_transform=True
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.ContributingEvent",
        outputs_key_field="alertID",
        outputs=alerts,
        raw_response=alerts,
    )

def map_endpoint_format(endpoint_list):
    """
    Maps and prepares endpoints data for consistent output formatting.

    Args:
        endpoint_list (list): Raw endpoint list from client response.

    Returns:
        dict: Formatted endpoint results with markdown table and outputs.
    """
    map_output_endpoint_fields = {
        v: k for k, v in ENDPOINT_FIELDS.items()
    }

    map_output_endpoint_type = {
        v: k for k, v in ENDPOINT_TYPE.items()
    }

    map_output_endpoint_status = {
        v: k for k, v in ENDPOINT_STATUS.items()
    }

    map_output_endpoint_platform = {
        v: k for k, v in ENDPOINT_PLATFORM.items()
    }

    map_output_endpoint_operational_status = {
        v: k for k, v in ENDPOINT_OPERATIONAL_STATUS.items()
    }

    map_output_assigned_prevention_policy = {
        v: k for k, v in ASSIGNED_PREVENTION_POLICY.items()
    }

    # A dispatcher for easy lookup:
    nested_mappers = {
        "endpoint_type": map_output_endpoint_type,
        "endpoint_status": map_output_endpoint_status,
        "platform": map_output_endpoint_platform,
        "operational_status": map_output_endpoint_operational_status,
        "assigned_prevention_policy": map_output_assigned_prevention_policy,
    }
    mapped_list = []

    for outputs in endpoint_list:
        mapped_item = {}

        for raw_key, raw_value in outputs.items():

            # Step 1: map backend key → friendly key
            if raw_key not in map_output_endpoint_fields:
                continue

            friendly_key = map_output_endpoint_fields[raw_key]

            # Step 2: map nested values (policy ID, status, etc.)
            if friendly_key in nested_mappers:
                mapper = nested_mappers[friendly_key]
                friendly_value = mapper.get(raw_value, raw_value)
            elif friendly_key == "agent_eol": # agent_eol = not supported_version
                friendly_value = not raw_value
            else:
                friendly_value = raw_value

            mapped_item[friendly_key] = friendly_value

        mapped_list.append(mapped_item)

    return mapped_list
        

def core_list_endpoints_command(client: Client, args: dict):
    page = arg_to_number(args.get("page")) or 0
    limit = arg_to_number(args.get("limit")) or MAX_GET_ENDPOINTS_LIMIT
    page_from = page * limit
    page_to = page * limit + limit
    
    operational_status = [ENDPOINT_OPERATIONAL_STATUS[operational_status] for operational_status in argToList(args.get('operational_status'))]
    endpoint_type = [ENDPOINT_TYPE[endpoint_type] for endpoint_type in argToList(args.get('endpoint_type'))]
    endpoint_status = [ENDPOINT_STATUS[status] for status in argToList(args.get('endpoint_status'))]
    platform = [ENDPOINT_PLATFORM[platform] for platform in argToList(args.get('platform'))]
    assigned_prevention_policy = [ASSIGNED_PREVENTION_POLICY[assigned] for assigned in argToList(args.get('assigned_prevention_policy'))]
    agent_eol = args.get('agent_eol')
    supported_version = not arg_to_bool_or_none(agent_eol) if agent_eol else None
    
    filter_builder = FilterBuilder()
    filter_builder.add_field(ENDPOINT_FIELDS["endpoint_status"], FilterType.EQ, endpoint_status)
    filter_builder.add_field(ENDPOINT_FIELDS["operational_status"], FilterType.EQ, operational_status)
    filter_builder.add_field(ENDPOINT_FIELDS["endpoint_type"], FilterType.EQ, endpoint_type)
    filter_builder.add_field(ENDPOINT_FIELDS["platform"], FilterType.EQ, platform)
    filter_builder.add_field(ENDPOINT_FIELDS["assigned_prevention_policy"], FilterType.EQ, assigned_prevention_policy)
    filter_builder.add_field(ENDPOINT_FIELDS["endpoint_name"], FilterType.EQ, argToList(args.get('endpoint_name')))
    filter_builder.add_field(ENDPOINT_FIELDS["operating_system"], FilterType.CONTAINS, argToList(args.get('operating_system')))
    filter_builder.add_field(ENDPOINT_FIELDS["agent_version"], FilterType.EQ, argToList(args.get('agent_version')))
    filter_builder.add_field(ENDPOINT_FIELDS["os_version"], FilterType.EQ, argToList(args.get('os_version')))
    filter_builder.add_field(ENDPOINT_FIELDS["ip_address"], FilterType.ADVANCED_IP_MATCH_EXACT, argToList(args.get('ip_address')))
    filter_builder.add_field(ENDPOINT_FIELDS["domain"], FilterType.EQ, argToList(args.get('domain')))
    filter_builder.add_field(ENDPOINT_FIELDS["group_name"], FilterType.EQ, argToList(args.get('group_name')))
    filter_builder.add_field(ENDPOINT_FIELDS["tags"], FilterType.EQ, argToList(args.get('tags')))
    filter_builder.add_field(ENDPOINT_FIELDS["endpoint_id"], FilterType.EQ, argToList(args.get('endpoint_id')))
    filter_builder.add_field(ENDPOINT_FIELDS["cloud_provider"], FilterType.EQ, argToList(args.get('cloud_provider')))
    filter_builder.add_field(ENDPOINT_FIELDS["cloud_region"], FilterType.EQ, argToList(args.get('cloud_region')))
    filter_builder.add_field(ENDPOINT_FIELDS["agent_eol"], FilterType.EQ, supported_version)
    
    request_data = build_webapp_request_data(
        table_name=AGENTS_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=page_to,
        sort_field="AGENT_NAME",
        sort_order="ASC",
        start_page=page_from,
    )
    demisto.info(f"{request_data=}")
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])
    demisto.debug(f"Raw endpoint data retrieved from API: {data}")
    data = map_endpoint_format(data)
    demisto.debug(f"Endpoint data after mapping and formatting: {data}")
    
    return CommandResults(
        readable_output=tableToMarkdown("Endpoints", data, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Endpoint",
        outputs_key_field="endpoint_id",
        outputs=data,
        raw_response=data,
    )


def polling_block_ip_status(args, client) -> PollResult:
    """
    Check action status for each endpoint id and ip address.
    Due limitation of the polling each time will check all combinations.
    Will stop polling when all statuses of the requests are Success/Failure.

    Args:
        args (dict):
            ip_list list[str]: IPs to block.
            endpoint_list list[str]: Endpoint IDs.
            duration (int, optional): Block time in seconds (default: 300).
            blocked_list list[str]: Action IDs to poll.
        client (Client): Integration client.
    """
    polling_queue = argToList(args.get("blocked_list", []))
    demisto.debug(f"polling queue length:{len(polling_queue)}")

    results = []
    for polled_action in polling_queue:
        demisto.debug(
            f"Polled action: endpoint={polled_action['endpoint_id']}, "
            f"group={polled_action['group_id']}, address={polled_action['ip_address']}"
        )
        status, message = client.fetch_block_status(polled_action["group_id"], polled_action["endpoint_id"])
        demisto.debug(f"polled action status:{status}, with message:{message}")
        if status == "Success":
            results.append(
                {"ip_address": polled_action["ip_address"], "endpoint_id": polled_action["endpoint_id"], "reason": "Success"}
            )

        elif status == "Failure":
            results.append(
                {
                    "ip_address": polled_action["ip_address"],
                    "endpoint_id": polled_action["endpoint_id"],
                    "reason": f"{status}: {message}",
                }
            )

        else:
            demisto.debug("Polling continue")
            return PollResult(
                response=None,
                partial_result=CommandResults(readable_output="Blocking in progress..."),
                continue_to_poll=True,
                args_for_next_run=args,
            )

    response = CommandResults(
        readable_output=tableToMarkdown(
            name="Results",
            t=results,
        ),
        outputs_prefix="Core.ip_block_results",
        outputs=results,
    )

    return PollResult(response=response, continue_to_poll=False, args_for_next_run=args)


@polling_function("core-block-ip", interval=10, timeout=60, requires_polling_arg=False)
def core_block_ip_command(args: dict, client: Client) -> PollResult:
    """
    Send block IP requests for each IP address on each endpoint.
    Polls status of the requests until all status are Success/Failure or until timeout.

    Args:
        args (dict):
            addresses list[str]: IPs to block.
            endpoint_list list[str]: Endpoint IDs.
            duration (int, optional): Block time in seconds (default: 300).
            blocked_list list[dict]: list of dicts each holds 3 fields: ip_address, group_id, endpoint_id
            for polling status of requests only.
        client (Client): client.

    Returns:
        PollResult: Schedules or returns poll status/result.
    """
    if not args.get("blocked_list"):
        # First call when no block ip request has done
        ip_list = argToList(args.get("addresses", []))
        endpoint_list = argToList(args.get("endpoint_list", []))
        duration = arg_to_number(args.get("duration")) or 300

        if duration <= 0 or duration >= 518400:
            raise DemistoException("Duration must be greater than 0 and less than 518,400 minutes (approx 12 months).")

        is_ip_list_valid(ip_list)

        blocked_list = []

        for endpoint_id in endpoint_list:
            blocked_list.extend(client.block_ip_request(endpoint_id, ip_list, duration))
        args_for_next_run = {"blocked_list": blocked_list, **args}
        return polling_block_ip_status(args_for_next_run, client)
    else:
        # all other calls after the block ip requests sent
        return polling_block_ip_status(args, client)


def is_ip_list_valid(ip_list: list[str]):
    """
    Validates all the ip addresses.
    Return error in case one of the inputs is invalid.
    Args:
        ip_list (list[str]): list of ip address to check.
    """
    for ip_address in ip_list:
        if not is_ip_valid(ip_address) and not is_ipv6_valid(ip_address):
            raise DemistoException(f"ip address {ip_address} is invalid")


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
    if command in PREVALENCE_COMMANDS:
        url_suffix = "/xsiam"
    elif command in PRIVATE_API_COMMANDS:
        url_suffix = ""
    else:
        url_suffix = "/public_api/v1"
        
    if not FORWARD_USER_RUN_RBAC:
        api_key = demisto.params().get("apikey")
        api_key_id = demisto.params().get("apikey_id")
        url = demisto.params().get("url")

        if not all((api_key, api_key_id, url)):
            raise DemistoException("Please provide the following parameters: Server URL, API Key, API Key ID")

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

        elif command == "core-get-contributing-event":
            return_results(core_get_contributing_event_command(client, args))

        elif command == "core-block-ip":
            return_results(core_block_ip_command(args, client))
            
        elif command == "core-list-endpoints":
            return_results(core_list_endpoints_command(client, args))

        elif command in PREVALENCE_COMMANDS:
            return_results(handle_prevalence_command(client, command, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
