import re
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn

import demistomock as demisto
from AWSApiModule import *
from CommonServerPython import *

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_ssm.type_defs import (
        DescribeAutomationExecutionsRequestRequestTypeDef,
        DocumentDescriptionTypeDef,
        GetInventoryRequestRequestTypeDef,
        InventoryResultEntityTypeDef,
        ListAssociationsRequestRequestTypeDef,
        ListCommandsRequestRequestTypeDef,
        ListDocumentsRequestRequestTypeDef,
    )
""" CONSTANTS """

SERVICE_NAME = "ssm"  # Amazon Simple Systems Manager (SSM).
DEFAULT_TIMEOUT = 600  # Default timeout for polling commands.
DEFAULT_INTERVAL_IN_SECONDS = 30  # Interval for polling commands.
TERMINAL_AUTOMATION_STATUSES = {
    "Success": "The automation completed successfully.",
    "TimedOut": "A step or approval wasn't completed before the specified timeout period.",
    "Cancelled": "The automation was stopped by a requester before it completed.",
    "Failed": "The automation didn't complete successfully. This is a terminal state.",
}
TERMINAL_COMMAND_STATUSES = {
    "Success": "The command was received by SSM Agent on all specified or targeted managed nodes and returned\
        an exit code of zero.\
        All command invocations have reached a terminal state, and the value of max-errors wasn't reached.\
        This status doesn't mean the command was successfully processed on all specified or targeted managed nodes.",
    "Failed": "The command wasn't successful on the managed node.",
    "Delivery Timed Out": "The command wasn't delivered to the managed node before the total timeout expired.",
    "Incomplete": "The command was attempted on all managed nodes and one or more of the invocations \
        doesn't have a value of Success. However, not enough invocations failed for the status to be Failed.",
    "Cancelled": "The command was canceled before it was completed.",
    "Canceled": "The command was canceled before it was completed.",  # AWS typo, British English (canceled)
    "Rate Exceeded": "The number of managed nodes targeted by the command exceeded the account quota for pending invocations. \
        The system has canceled the command before executing it on any node.",
    "Access Denied": "The user or role initiating the command doesn't have access to the targeted resource group. AccessDenied \
        doesn't count against the parent command's max-errors limit, \
        but does contribute to whether the parent command status is Success or Failed.",
    "No Instances In Tag": "The tag key-pair value or resource group targeted by the command doesn't match any managed nodes. ",
}


class RegexValidator(NamedTuple):
    name: str
    regex: re.Pattern[str]
    error_template: str


ASSOCIATION_ID_VALIDATOR = RegexValidator(
    name="association_id",
    regex=re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    ),
    error_template="Invalid association id: {association_id}",
)

ASSOCIATION_VERSION_VALIDATOR = RegexValidator(
    name="association_version",
    regex=re.compile(r"([$]LATEST)|([1-9][0-9]*)"),
    error_template="Invalid association version: {association_version}",
)

INSTANCE_ID_VALIDATOR = RegexValidator(
    name="instance_id",
    regex=re.compile(r"(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)"),
    error_template="Invalid instance id: {instance_id}",
)

""" Helper functions """


def update_if_value(
    input_dictionary: dict,
    output_dictionary: Any,
    input_to_output_keys: dict[str, str],
) -> Any:
    """
    Update the output dictionary with values from the input dictionary based on specified key mappings.

    This function iterates through the key-value pairs in the `input_to_output_keys` dictionary, and for each pair,
    it checks if the corresponding key exists in the `input_dictionary`. If the key exists, it copies the value to
    the `output_dictionary` under the specified output key.

    Args:
    ____
        input_dictionary (dict): The input dictionary containing data to be copied.
        output_dictionary (dict): The output dictionary where data will be copied.
        input_to_output_keys (dict): A dictionary mapping input keys to output keys.

    Returns:
    _______
        dict: The updated `output_dictionary` containing copied values based on the mapping.

    Example:
    _______
        >>> input_dict = {'next_token': 'test', 'instance_id': test_id}
        >>> output_dict = {}
        >>> key_mapping = {'next_token': 'NextToken', 'instance_id': 'InstanceId'}
        >>> update_if_value(input_dict, output_dict, key_mapping)
        {'NextToken': 'test', 'InstanceId': test_id}
    """
    for input_key, output_key in input_to_output_keys.items():
        if value := input_dictionary.get(input_key):
            output_dictionary[output_key] = value
    return output_dictionary


def format_parameters_arguments(parameters: str) -> dict[str, Any]:
    """Formats the 'parameters' string into a dictionary.

    Args:
    ----
        parameters (str): A string containing key-value pairs separated by colons and
            values separated by commas.

    Returns:
    -------
        dict[str, Any]: A dictionary where keys are extracted from the input string,
            and values are lists of values associated with each key.

    Example:
    -------
        Use this function to format a parameters string:

        >>> parameters = "key1:value1,value2,key2:value3"
        >>> formatted_parameters = format_parameters_arguments(parameters)
        >>> print(formatted_parameters)
        {'key1': ['value1', 'value2'], 'key2': ['value3']}

    Note:
    ----
        - The input string should follow the format 'key:value1,value2,...'.
        - The function will return an empty dictionary if no valid key-value pairs
          are found in the input string.

    """
    items = parameters.split(",")
    formatted_parameters = {}
    current_key = None

    for item in items:
        parts = item.split(":")

        if len(parts) == 2:
            key, value = parts

            if key != current_key:
                current_key = key
                formatted_parameters[key] = [value]
            else:
                formatted_parameters[key].append(value)
        elif current_key is not None:
            for part in parts:
                if part.strip():
                    formatted_parameters[current_key].append(part)

    return formatted_parameters


def format_document_version(document_version: str) -> str:
    """Formats an AWS Systems Manager (SSM) document version .
    convert the string to the correct format for the API call.

    Args:
    ----
        document_version (str): The document version to format.

    Returns:
    -------
        str: The formatted document version string.
            - If "latest", it returns "$LATEST".
            - If None or any other value, it returns "$DEFAULT".

    Example:
    -------
        >>> version = "latest"
        >>> formatted_version = format_document_version(version)
        >>> print(Formatted version)
        $LATEST
    """
    return {"latest": "$LATEST", "default": "$DEFAULT"}.get(document_version, document_version)


def validate_args(args: dict[str, Any]) -> NoReturn | None:
    """Validates the arguments in the provided dictionary using regular expressions,
    from the constants REGEX_PATTERNS.

    Args:
    ----
        args: A dictionary containing the arguments to be validated.

    Raises:
    ------
        DemistoException: If any of the arguments fail to match their respective regex patterns.

    Example:
    -------
        >>> args = {
        >>>    'instance_id': 'i-0a00aaa000000000a', # valid instance id
        >>>    'association_id': '0000' # invalid association id
        >>> }
        >>> try:
        >>>    validate_args(args)
        >>> except DemistoException as e:  # e equals to "Invalid association id: 0000"
        >>>     print(f"Validation error: {e}")
            Validation error: Invalid association id: 0000
    """
    for validator in (
        ASSOCIATION_ID_VALIDATOR,
        ASSOCIATION_VERSION_VALIDATOR,
        INSTANCE_ID_VALIDATOR,
    ):
        if (arg_value := args.get(validator.name)) and not re.search(
            validator.regex,
            arg_value,
        ):
            raise DemistoException(
                validator.error_template.format(**{validator.name: arg_value}),
            )
    return None


def config_aws_session(args: dict[str, str], aws_client: AWSClient) -> "SSMClient":
    """Configures an AWS session for the Lambda service,
    Used in all the commands.

    Args:
    ----
        args: A dictionary containing the configuration parameters for the session.
                     - 'region' (str): The AWS region.
                     - 'roleArn' (str): The ARN of the IAM role.
                     - 'roleSessionName' (str): The name of the role session.
                     - 'roleSessionDuration' (str): The duration of the role session.

        aws_client: The AWS client used to configure the session.

    Returns:
    -------
        AWS session (ssm client): The configured AWS session.
    """
    return aws_client.aws_session(
        service=SERVICE_NAME,
        region=args.get("region"),
        role_arn=args.get("roleArn"),
        role_session_name=args.get("roleSessionName"),
        role_session_duration=args.get("roleSessionDuration"),
    )


def convert_datetime_to_iso(response) -> dict[str, Any]:
    """Converts datetime objects in a response dictionary to ISO formatted strings.

    Args:
    ----
        response (dict): The response dictionary.

    Returns:
    -------
        dict: The response dictionary with datetime objects converted to ISO formatted strings.

    Example:
    -------
        >>> response = {
        >>>    'timestamp': datetime(2023, 8, 20, 12, 30, 0),
        >>>    'data': {
        >>>        'created_at': datetime(2023, 8, 19, 15, 45, 0)
        >>>    }
        >>> }
        >>> iso_response = convert_datetime_to_iso(response)
        >>> print(iso_response)
            {
            'timestamp': '2023-08-20T12:30:00',
            'data': {
                 'created_at': '2023-08-19T15:45:00'
               }
            }
    """

    def _datetime_to_string(obj: Any) -> str:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)

    return json.loads(json.dumps(response, default=_datetime_to_string))


def next_token_command_result(next_token: str, outputs_prefix: str) -> CommandResults:
    """Creates a CommandResults object with the next token as the output.

    Args:
    ----
        next_token (str): The next token.
        outputs_prefix (str): The prefix for the outputs.

    Returns:
    -------
        CommandResults: A CommandResults object with the next token as the output.

    Example:
    -------
        >>> next_token_command_result("token", "InventoryNextToken")
        in the context output(war room):
        {
            AWS:
                SSM:
                    InventoryNextToken:
                        NextToken: "token"
        }
    """
    return CommandResults(
        outputs={f"AWS.SSM.{outputs_prefix}(val.NextToken)": {"NextToken": next_token}},
        readable_output=f"For more results, use the next token from the context path: AWS.SSM.{outputs_prefix}.NextToken",
    )


def get_automation_execution_status(execution_id: str, ssm_client: "SSMClient") -> str:
    """Retrieves the status of an AWS Systems Manager Automation execution.

    Args:
    ----
        execution_id (str): The unique identifier of the Automation execution.
        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        str: The status of the Automation execution, which can be one of the following values:
           - 'Pending'
           - 'InProgress'
           - 'Waiting'
           - 'Success'
           - 'TimedOut'
           - 'Cancelling'
           - 'Cancelled'
           - 'Failed'
           - 'PendingApproval'
           - 'Approved'
           - 'Rejected'
           - 'Scheduled'
           - 'RunbookInProgress'
           - 'PendingChangeCalendarOverride'
           - 'ChangeCalendarOverrideApproved'
           - 'ChangeCalendarOverrideRejected'
           - 'CompletedWithSuccess'
           - 'CompletedWithFailure',

    """
    return ssm_client.get_automation_execution(AutomationExecutionId=execution_id)["AutomationExecution"]["AutomationExecutionStatus"]


def get_command_status(command_id: str, ssm_client: "SSMClient") -> str:
    """Gets the status of an AWS Systems Manager (SSM) command.

    Args:
    ----
        command_id (str): The unique identifier of the command.
        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        str: The status of the command.
        ## Possible values:
        - Pending
        - InProgress
        - Cancelling
        - Delayed
        - Success
        - Delivery Timed Out
        - Execution Timed Out
        - Failed
        - Canceled or Cancelled (AWS typo, British English)
        - Undeliverable
        - Terminated
        - Access Denied
    """
    return ssm_client.list_commands(CommandId=command_id)["Commands"][0]["Status"]


def parse_automation_execution(automation: dict[str, Any]) -> dict[str, Any]:
    """Parses an automation execution
    and returns a dict contain the parsed automation.
    for the readable_output function.
    """
    return {
        "Automation Execution Id": automation.get("AutomationExecutionId"),
        "Document Name": automation.get("DocumentName"),
        "Document Version": automation.get("DocumentVersion"),
        "Start Time": automation.get("ExecutionStartTime"),
        "End Time": automation.get("ExecutionEndTime"),
        "Automation Execution Status": automation.get("AutomationExecutionStatus"),
        "Mode": automation.get("Mode"),
        "Executed By": automation.get("ExecutedBy"),
    }


""" COMMAND FUNCTIONS """


def add_tags_to_resource_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> CommandResults:
    """Adds tags to a specified resource.
    The response from the API call when success is empty dict.

    Args:
    ----
        ssm_client ("SSMClient"): An instance of the SSM client.
        args (dict): A dictionary containing the command arguments.
                     - 'resource_type' (str): The type of the resource.
                     - 'resource_id' (str): The ID of the resource.
                     - 'tag_key' (str): The key of the tag to add.
                     - 'tag_value' (str): The value of the tag to add.

    Returns:
    -------
        CommandResults: readable output only,
    """
    kwargs = {
        "ResourceType": args["resource_type"],
        "ResourceId": args["resource_id"],
        "Tags": [{"Key": args["tag_key"], "Value": args["tag_value"]}],
    }

    ssm_client.add_tags_to_resource(**kwargs)
    return CommandResults(
        readable_output=f"Tags successfully added to resource {args['resource_id']}.",
    )


def remove_tags_from_resource_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> CommandResults:
    ssm_client.remove_tags_from_resource(
        ResourceType=args["resource_type"],
        ResourceId=args["resource_id"],
        TagKeys=[args["tag_key"]],
    )
    return CommandResults(
        readable_output=f"Tag {args['tag_key']} removed from resource {args['resource_id']} successfully.",
    )


def list_tags_for_resource_command(
    args: dict[str, Any],
    ssm_client: "SSMClient"
):
    # Get tags from resource
    response = ssm_client.list_tags_for_resource(
        ResourceType=args["resource_type"],
        ResourceId=args["resource_id"]
    )

    tags = response["TagList"]

    human_readable = tableToMarkdown(f"Tags for {args['resource_id']}", tags)
    
    command_results = CommandResults(
        outputs_key_field="Key",
        outputs_prefix="AWS.SSM.Tag",
        outputs=tags,
        readable_output=human_readable
    )

    return command_results


def list_inventory_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Fetches inventory information from AWS SSM using the provided SSM client and arguments.

    Args:
    ----
        ssm_client: SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults containing the inventory information.
    """

    def _parse_inventory_entities(
        entities: list["InventoryResultEntityTypeDef"],
    ) -> list[dict]:
        """Parses a list of entities and returns a list of dictionaries containing relevant information.

        Args:
        ----
            entities: A list of entities to parse.

        Returns:
        -------
            list of dict containing relevant information.
        """
        def _parse_inventory(data: dict[str, Any]) -> dict[str, Any]:
            return {
                "Instance Id": data.get("InstanceId"),
                "Computer Name": data.get("ComputerName"),
                "Platform Type": data.get("PlatformType"),
                "Platform Name": data.get("PlatformName"),
                "Agent version": data.get("AgentVersion"),
                "IP address": data.get("IpAddress"),
                "Resource Type": data.get("ResourceType"),
            }
        parsed_entities = []
        for entity in entities:
            entity_content = entity.get("Content", {})
            parsed_entity = {"Id": entity.get("Id")}
            for content in entity_content:
                parsed_entities.append(parsed_entity | _parse_inventory(content))
        return parsed_entities

    kwargs: "GetInventoryRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
        "Filters": [
            {"Key": "AWS:InstanceInformation.InstanceStatus", "Values": ["active"]}
        ]
    }
    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})
    if argToBoolean(args.get("include_inactive_instance")):
        kwargs["Filters"][0]["Values"].extend(["stopped", "terminated", 'ConnectionLost'])

    response = ssm_client.get_inventory(**kwargs)
    command_results = []

    if response_next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(response_next_token, "InventoryNextToken"),
        )

    entities = response.get("Entities", [])
    # Extract the Data field from the object and add it to the main dictionary, Data contain a dict.
    for item in entities:
        item["Data"].update(item["Data"].pop("AWS:InstanceInformation", None))
        item.update(item.pop("Data"))

    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.Inventory",
            outputs=entities,
            outputs_key_field="Id",
            readable_output=tableToMarkdown(
                name="AWS SSM Inventory",
                t=_parse_inventory_entities(entities),
            ),
        ),
    )
    return command_results


def list_inventory_entry_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Lists inventory entries for a specific instance and type name using the provided SSM client and arguments.

    Args:
    ----
        ssm_client: AWS SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.
            - instance_id (str): The ID of the instance.
            - type_name (str): The type name of the inventory.
            - limit (int, optional): Maximum number of entries to retrieve. Defaults to 50.
            - next_token (str, optional): Token to retrieve the next set of entries.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults containing the inventory entries information.
            and the next token if exists.

    Raises:
    ------
        DemistoException: If an invalid instance ID is provided.
    """
    type_name = args["type_name"]
    kwargs = {
        "InstanceId": args["instance_id"],
        "TypeName": f'AWS:{type_name}',
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }

    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})

    response = ssm_client.list_inventory_entries(**kwargs)
    response.pop("ResponseMetadata")
    entries = response.get("Entries", [])

    command_results = []
    if next_token := response.get("NextToken"):
        response.pop("NextToken")
        command_results.append(
            next_token_command_result(next_token, "InventoryEntryNextToken"),
        )
   
    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.InventoryEntry",
            outputs=response,
            outputs_key_field="InstanceId",
            readable_output=tableToMarkdown(
                name="AWS SSM Inventory Entry",
                t=entries,
            ),
        ),
    )

    return command_results


def list_associations_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Lists associations in AWS SSM using the provided SSM client and arguments.

    Args:
    ----
        ssm_client: AWS SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.
            - limit (int, optional): Maximum number of associations to retrieve. Defaults to 50.
            - next_token (str, optional): Token to retrieve the next set of associations.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults containing the association information.
        and the next token if exists in the response.
    """

    def _parse_associations(associations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "Document name": association.get("Name"),
                "Association id": association.get("AssociationId"),
                "Association version": association.get("AssociationVersion"),
                "Last execution date": association.get("LastExecutionDate"),
                "Resource status count": dict_safe_get(
                    association,
                    ["Overview", "AssociationStatusAggregatedCount"],
                ),
                "Status": dict_safe_get(association, ["Overview", "Status"]),
            }
            for association in associations
        ]

    kwargs: "ListAssociationsRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }

    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})

    response = ssm_client.list_associations(**kwargs)
    response = convert_datetime_to_iso(response)
    associations = response.get("Associations", [])
    command_results = []

    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "InventoryNextToken"),
        )

    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.Association",
            outputs=associations,
            outputs_key_field="AssociationId",
            readable_output=tableToMarkdown(
                name="AWS SSM Associations",
                t=_parse_associations(associations),
            ),
        ),
    )

    return command_results


def get_association_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> CommandResults:
    """Retrieves information about an SSM association based on provided parameters.

    Args:
    ----
        ssm_client: The AWS SSM client used to interact with the service.
        args (dict[str, Any]): A dictionary containing the command arguments.

    Returns:
    -------
        CommandResults: A CommandResults object containing information about the retrieved association.

    Raises:
    ------
        DemistoException: If the provided arguments are invalid.
    """

    def _parse_association(association: dict[str, Any]) -> dict[str, Any]:
        return {
            "Document name": association.get("Name"),
            "Document version": association.get("DocumentVersion"),
            "Association name": association.get("AssociationName"),
            "Association id": association.get("AssociationId"),
            "Association version": association.get("AssociationVersion"),
            "Last execution date": association.get("LastExecutionDate"),
            "Resource status count": dict_safe_get(
                association,
                ["Overview", "AssociationStatusAggregatedCount"],
            ),
            "Status": dict_safe_get(association, ["Overview", "Status"]),
            "Create date": association.get("Date"),
            "Schedule expression": association.get("ScheduleExpression"),
        }

    association_id = args.get("association_id")
    association_version = args.get("association_version")
    instance_id = args.get("instance_id")
    document_name = args.get("document_name")

    if not (association_id or (instance_id and document_name)):
        msg = "This command must provide either association id or instance_id and document_name."
        raise DemistoException(msg)

    kwargs = {
        "AssociationId": association_id,
        "AssociationVersion": association_version,
        "InstanceId": instance_id,
        "Name": document_name,
    }
    kwargs = {key: value for key, value in kwargs.items() if value is not None}

    response = ssm_client.describe_association(**kwargs)
    response = convert_datetime_to_iso(response)
    association_description = response.get("AssociationDescription", {})

    return CommandResults(
        outputs=association_description,
        outputs_key_field="AssociationId",
        outputs_prefix="AWS.SSM.Association",
        readable_output=tableToMarkdown(
            name="AWS SSM Association",
            t=_parse_association(association_description),
        ),
    )


def list_versions_association_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Lists the versions of an SSM association based on provided parameters.

    Args:
    ----
        ssm_client: The AWS SSM client used to interact with the service.
            - association_id (required): The ID of the association.
            - limit (optional): The maximum number of versions to return. Defaults to 50.
            - next_token (optional): The token for the next set of results.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults objects, containing information about the association versions.
            if next_token provide in the response, the first CommandResults in the list will contain the next token.
    """

    def _parse_association_versions(
        association_versions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "Version": association_version.get("AssociationVersion"),
                "Name": association_version.get("Name"),
                "Create date": association_version.get("CreatedDate"),
                "Association id": association_version.get("AssociationId"),
                "Document version": association_version.get("DocumentVersion"),
                "Targets": association_version.get("Targets"),
                "Parameters": association_version.get("Parameters"),
                "Schedule expression": association_version.get("ScheduleExpression"),
                "Output location": association_version.get("OutputLocation"),
                "MaxConcurrency": association_version.get("MaxConcurrency"),
                "MaxErrors": association_version.get("MaxErrors"),
            }
            for association_version in association_versions
        ]

    kwargs = {
        "AssociationId": args["association_id"],
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})

    response = ssm_client.list_association_versions(**kwargs)
    response = convert_datetime_to_iso(response)
    association_versions = response.get("AssociationVersions", [])

    command_results: list[CommandResults] = []
    if response_next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(
                response_next_token,
                "AssociationVersionNextToken",
            ),
        )
    command_results.append(
        CommandResults(
            outputs=association_versions,
            outputs_key_field="AssociationId",
            outputs_prefix="AWS.SSM.AssociationVersion",
            readable_output=tableToMarkdown(
                t=_parse_association_versions(association_versions),
                name="Association Versions",
                json_transform_mapping={
                    "Parameters": JsonTransformer(
                        is_nested=True,
                    ),
                    "Targets": JsonTransformer(
                        is_nested=True,
                    ),
                },
            ),
        ),
    )
    return command_results


def list_documents_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:

    """Lists the documents in AWS SSM using the provided SSM client and arguments.

    Args:
    ----
        ssm_client: AWS SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.
            - limit (int, optional): Maximum number of documents to retrieve. Defaults to 50.
            - next_token (str, optional): Token to retrieve the next set of documents.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults containing the documents information.
        and the next token if exists in the response.
    """

    def _parse_documents(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "Name": document.get("Name"),
                "Owner": document.get("Owner"),
                "Document version": document.get("DocumentVersion"),
                "Document type": document.get("DocumentType"),
                "Created date": document.get("CreatedDate"),
                "Platform types": document.get("PlatformTypes"),
            }
            for document in documents
        ]

    kwargs: "ListDocumentsRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if (document_type := args.get("document_type")) and document_type != "all":
        kwargs["DocumentFilterList"] = [{"key": "DocumentType", "value": document_type}]

    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})

    response = ssm_client.list_documents(**kwargs)
    response = convert_datetime_to_iso(response)
    documents = response.get("DocumentIdentifiers", [])

    command_results = []
    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "DocumentNextToken"),
        )

    command_results.append(
        CommandResults(
            outputs=documents,
            outputs_key_field="Name",
            outputs_prefix="AWS.SSM.Document",
            readable_output=tableToMarkdown(
                name="AWS SSM Documents",
                t=_parse_documents(documents),
                headers=[
                    "Name",
                    "Owner",
                    "Document version",
                    "Document type",
                    "Platform types",
                    "Created date",
                ],
            ),
        ),
    )
    return command_results


def get_document_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> CommandResults:
    """Retrieves information about an AWS Systems Manager (SSM) document.

    Args:
    ----
        args (dict[str, Any]): A dictionary containing command arguments.
            - document_name (str, required): The name of the SSM document.
            - document_version (str, optional): The version of the SSM document to retrieve.
            - version_name (str, optional): The name of the version of the SSM document to retrieve.

        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        CommandResults: An object containing the results of the command.
    """

    def _parse_document(document: "DocumentDescriptionTypeDef"):
        return {
            "Name": document.get("Name"),
            "Display Name": document.get("DisplayName"),
            "Document version": document.get("VersionName"),
            "Owner": document.get("Owner"),
            "Description": document.get("Description"),
            "Platform types": document.get("PlatformTypes"),
            "Created date": document.get("CreatedDate"),
            "Status": document.get("Status"),
        }

    kwargs = {"Name": args["document_name"]}
    if document_version := args.get("document_version"):
        kwargs["DocumentVersion"] = format_document_version(document_version)
    kwargs = update_if_value(args, kwargs, {"version_name": "VersionName"})

    response = ssm_client.describe_document(**kwargs)
    response = convert_datetime_to_iso(response)
    document = response["Document"]

    return CommandResults(
        outputs=document,
        outputs_key_field="Name",
        outputs_prefix="AWS.SSM.Document",
        readable_output=tableToMarkdown(
            name="AWS SSM Document",
            t=_parse_document(document),
        ),
    )


def get_automation_execution_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> CommandResults:
    """Retrieves information about an AWS Systems Manager (SSM) automation execution.

    Args:
    ----
        args (dict[str, Any]): A dictionary containing command arguments.
            - execution_id (str): The unique identifier of the automation execution.

        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        CommandResults: An object containing the results of the command.
    """
    automation_execution = ssm_client.get_automation_execution(
        AutomationExecutionId=args["execution_id"],
    )["AutomationExecution"]
    automation_execution = convert_datetime_to_iso(automation_execution)
    return CommandResults(
        outputs_prefix="AWS.SSM.AutomationExecution",
        outputs_key_field="AutomationExecutionId",
        outputs=automation_execution,
        readable_output=tableToMarkdown(
            name="AWS SSM Automation Execution",
            t=parse_automation_execution(automation_execution),
            headers=[
                "Automation Execution Id",
                "Document Name",
                "Document Version",
                "Start Time",
                "End Time",
                "Automation Execution Status",
                "Mode",
                "Executed By",
            ],
        ),
    )


def list_automation_executions_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Lists AWS Systems Manager (SSM) automation executions.

    Args:
    ----
        args (dict): A dictionary containing command arguments.
            - limit (int, optional): The maximum number of results to return (default is 50).
            - next_token (str, optional): A token to continue listing executions from a previous query.

        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        list[CommandResults]: A list of objects containing the results of the command.
        if next_token provide in the response, the first CommandResults in the list will contain the next token.
    """
    kwargs: "DescribeAutomationExecutionsRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken"})

    response = ssm_client.describe_automation_executions(**kwargs)
    response = convert_datetime_to_iso(response)

    command_results: list[CommandResults] = []
    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "AutomationExecutionNextToken"),
        )
    automation_execution_list = response["AutomationExecutionMetadataList"]
    command_results.append(
        CommandResults(
            outputs=automation_execution_list,
            outputs_key_field="AutomationExecutionId",
            outputs_prefix="AWS.SSM.AutomationExecution",
            readable_output=tableToMarkdown(
                name="AWS SSM Automation Executions",
                t=[
                    parse_automation_execution(automation)
                    for automation in automation_execution_list
                ],
                headers=[
                    "Automation Execution Id",
                    "Document Name",
                    "Document Version",
                    "Start Time",
                    "End Time",
                    "Automation Execution Status",
                    "Mode",
                    "Executed By",
                ],
            ),
        ),
    )
    return command_results


@polling_function(
    name="aws-ssm-automation-execution-run",
    interval=arg_to_number(
        demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL_IN_SECONDS),
    ),
    timeout=arg_to_number(demisto.args().get("timeout", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,  # means it will always default to poll
)
def run_automation_execution_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> PollResult:
    """Initiates or polls the status of an AWS Systems Manager (SSM) automation execution.
    Note: The argument "execution_id" is hidden in the yml file, and is used to pass the execution id between polling
    Args:
        args (dict[str, Any]): A dictionary containing command arguments.
            - document_name (str, required): The name of the SSM automation document.
            - execution_id (str, optional): The unique identifier of the automation execution.
                require for polling only.
            - tag_key (str, optional): The key for tagging the automation execution.
            - tag_value (str, optional): The value for tagging the automation execution.
            - parameters (str, optional): JSON-formatted string containing automation parameters.  #TODO change to regex
            - mode (str, optional): The execution mode (default is "Auto").
            - client_token (str, optional): A unique identifier for the automation execution.
            - document_version (str, optional): The version of the SSM document to use.
            - max_concurrency (str, optional): The maximum number of targets to run the automation concurrently.
            - max_error (str, optional): The maximum number of errors allowed before stopping the automation.

        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns
    -------
        PollResult: An object containing the results of the command and whether to continue polling.
    """
    execution_id = args.get("execution_id")

    if not execution_id:  # if this is the first time the function is called
        tag_key = args.get("tag_key")
        tag_value = args.get("tag_value")
        kwargs = {
            "DocumentName": args["document_name"],
            "Mode": args.get("mode", "Auto"),
            **(
                {"Tags": [{"Key": tag_key, "Value": tag_value}]}
                if tag_key and tag_value
                else {}
            ),
        }
        if document_version := args.get("document_version"):
            kwargs["DocumentVersion"] = format_document_version(document_version)
        input_to_output_keys = {
            "client_token": "ClientToken",
            "max_concurrency": "MaxConcurrency",
            "max_error": "MaxErrors",
        }
        kwargs = update_if_value(args, kwargs, input_to_output_keys)
        if parameters := args.get("parameters"):
            kwargs["Parameters"] = format_parameters_arguments(parameters)
        execution_id = ssm_client.start_automation_execution(**kwargs)[
            "AutomationExecutionId"
        ]
        args[
            "execution_id"
        ] = execution_id  # needed for the polling and is `hidden: true` in the yml file.
        return PollResult(
            partial_result=CommandResults(
                readable_output=f"Execution {args['execution_id']} is in progress",
            ),
            response=None,
            continue_to_poll=True,
            args_for_next_run=args,
        )
    status = get_automation_execution_status(execution_id, ssm_client)
    if status in TERMINAL_AUTOMATION_STATUSES:
        return PollResult(  # if execution not in progress, return the status and end the polling loop
            response=CommandResults(
                readable_output=TERMINAL_AUTOMATION_STATUSES[status],
            ),
            continue_to_poll=False,
        )
    return PollResult(
        partial_result=CommandResults(
            readable_output=f"Execution {execution_id} is in progress",
        ),
        response=None,
        continue_to_poll=True,
        args_for_next_run=args,
    )


@polling_function(
    name="aws-ssm-automation-execution-cancel",
    interval=arg_to_number(
        demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL_IN_SECONDS),
    ),
    timeout=arg_to_number(demisto.args().get("timeout", DEFAULT_TIMEOUT)),
    requires_polling_arg=True,
    polling_arg_name="include_polling",
)
def cancel_automation_execution_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> PollResult:
    """Cancels an AWS Systems Manager (SSM) automation execution or monitors its cancellation status.
        Note: the argument `first_run` is hidden: true in the yml file,
            and is used to determine if this is the first time the function.

    Args:
    ----
        args (dict[str, Any]): A dictionary containing command arguments.
            - automation_execution_id (str): The unique identifier of the automation execution to cancel.
            - type (str, optional): The type of cancellation (default is "Cancel").
            - include_polling (bool, optional): Whether to continue polling the cancellation status (default is False).

    Returns:
    -------
        PollResult: An object containing the results of the command and whether to continue polling.
    """
    automation_execution_id = args["automation_execution_id"]
    type_ = args.get("type", "Cancel")
    include_polling = argToBoolean(args.get("include_polling", False))

    if not argToBoolean(args["first_run"]):
        status = get_automation_execution_status(automation_execution_id, ssm_client)
        if status in TERMINAL_AUTOMATION_STATUSES:  # STOP POLLING
            return PollResult(
                response=CommandResults(
                    readable_output=TERMINAL_AUTOMATION_STATUSES[status],
                ),
                continue_to_poll=False,
            )
        else:
            return PollResult(  # CONTINUE POLLING
                partial_result=CommandResults(
                    readable_output=f"Execution {automation_execution_id} is {status}",
                ),
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )

    # Initial command execution
    ssm_client.stop_automation_execution(
        AutomationExecutionId=automation_execution_id,
        Type=type_,
    )
    args["first_run"] = False
    # if polling stops after the first run, this will be the final result in the war room
    # otherwise this will be the partial result
    return PollResult(
        response=CommandResults(
            readable_output="Cancellation command was sent successful.",
        ),
        partial_result=CommandResults(
            readable_output="Cancellation command was sent successful.",
        ),
        continue_to_poll=include_polling,
    )


def list_commands_command(
    args: dict[str, Any],
    ssm_client: "SSMClient",
) -> list[CommandResults]:
    """Lists AWS Systems Manager (SSM) commands.

    Args:
    ----
        args (dict[str, Any]): A dictionary containing command arguments.
            - limit (int, optional): The maximum number of results to return (default is 50).
            - next_token (str, optional): A token to continue listing commands from a previous query.
            - command_id (str, optional): The unique identifier of a specific command to retrieve.

        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        list[CommandResults]: A list of objects containing the results of the command.
        if next_token provide in the response, the first CommandResults in the list will contain the next token.
    """

    def _parse_list_command(commands: list[dict]):
        return [
            {
                "Command Id": command.get("CommandId"),
                "Status": command.get("Status"),
                "Requested date": command.get("RequestedDateTime"),
                "Document name": command.get("DocumentName"),
                "Comment": command.get("Comment"),
                "Target Count": command.get("TargetCount"),
                "Error Count": command.get("ErrorCount"),
                "Delivery Timed Out Count": command.get("DeliveryTimedOutCount"),
                "Completed Count": command.get("CompletedCount"),
            }
            for command in commands
        ]

    kwargs: "ListCommandsRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    kwargs = update_if_value(args, kwargs, {"next_token": "NextToken", "command_id": "CommandId"})

    response = ssm_client.list_commands(**kwargs)
    response = convert_datetime_to_iso(response)

    commands = response.get("Commands", [])
    command_result = []
    if next_token := response.get("NextToken"):
        command_result.append(
            next_token_command_result(next_token, "CommandNextToken"),
        )

    command_result.append(
        CommandResults(
            outputs=commands,
            outputs_key_field="CommandId",
            outputs_prefix="AWS.SSM.Command",
            readable_output=tableToMarkdown(
                name="AWS SSM Commands",
                t=_parse_list_command(commands),
                headers=[
                    "Command Id",
                    "Status",
                    "Requested date",
                    "Document name",
                    "Comment",
                    "Target Count",
                    "Error Count",
                    "Delivery Timed Out Count",
                    "Completed Count",
                ],
            ),
        ),
    )
    return command_result


@polling_function(
    name="aws-ssm-command-run",
    interval=arg_to_number(
        demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL_IN_SECONDS),
    ),
    timeout=arg_to_number(demisto.args().get("timeout", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,  # means it will always be default to poll, poll=true,
)
def run_command_command(args: dict[str, Any], ssm_client: "SSMClient") -> PollResult:
    if command_id := args.get("command_id"):
        status = get_command_status(command_id, ssm_client)
        if status in TERMINAL_COMMAND_STATUSES:
            return PollResult(
                response=CommandResults(
                    readable_output=TERMINAL_COMMAND_STATUSES[status],
                ),
                continue_to_poll=False,
            )
        else:
            return PollResult(
                partial_result=CommandResults(
                    readable_output=f"Command {command_id} is {status}",
                ),
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )

    kwargs = {
        "DocumentName": args["document_name"],
        "InstanceIds": argToList(args["instance_ids"]),
    }
    if document_version := args.get("document_version"):
        kwargs["DocumentVersion"] = format_document_version(document_version)
    input_to_output_keys = {
        "comment": "Comment",
        "output_s3_bucket_name": "OutputS3BucketName",
        "output_s3_key_prefix": "OutputS3KeyPrefix",
        "max_concurrency": "MaxConcurrency",
        "max_errors": "MaxErrors",
    }
    kwargs = update_if_value(args, kwargs, input_to_output_keys)
    if parameters := args.get("parameters"):
        parameters = format_parameters_arguments(parameters)

    command = ssm_client.send_command(**kwargs)
    command = convert_datetime_to_iso(command)["Command"]

    command_id = command["CommandId"]
    args["command_id"] = command_id
    return PollResult(
        response=None,
        continue_to_poll=True,
        args_for_next_run=args,
        partial_result=CommandResults(
            readable_output=f"Command {command_id} was sent successful.",
            outputs=command,
            outputs_prefix="AWS.SSM.Command",
            outputs_key_field="CommandId",
        ),
    )


@polling_function(
    name="aws-ssm-command-cancel",
    interval=arg_to_number(
        demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL_IN_SECONDS),
    ),
    timeout=arg_to_number(demisto.args().get("timeout", DEFAULT_TIMEOUT)),
    requires_polling_arg=True,
    polling_arg_name="include_polling",
)
def cancel_command_command(args: dict[str, Any], ssm_client: "SSMClient") -> PollResult:
    command_id = args["command_id"]
    include_polling = argToBoolean(args.get("include_polling", False))

    if not argToBoolean(args["first_run"]):
        status = get_command_status(command_id, ssm_client)
        if status in TERMINAL_COMMAND_STATUSES:  # STOP POLLING
            return PollResult(
                response=CommandResults(
                    readable_output=TERMINAL_COMMAND_STATUSES[status],
                ),
                continue_to_poll=False,
            )
        else:
            return PollResult(  # CONTINUE POLLING
                partial_result=CommandResults(
                    readable_output=f"Execution {command_id} is {status}",
                ),
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )

    # Initial command execution
    kwargs = {"CommandId": command_id}
    if instance_ids := argToList(args.get("instance_ids")):
        kwargs["InstanceIds"] = argToList(instance_ids)
    ssm_client.cancel_command(**kwargs)
    args["first_run"] = False
    status = get_command_status(command_id, ssm_client)

    return PollResult(
        response=CommandResults(
            readable_output="Cancellation command was sent successful.",
        ),  # if the polling is stop after first run, this will be the final result in the war room
        partial_result=CommandResults(
            readable_output="Cancellation command was sent successful.",
        ),  # if the polling is not stop after first run, this will be the partial result
        continue_to_poll=include_polling,
    )


def test_module(ssm_client: "SSMClient") -> str:
    """Tests the connectivity to AWS Systems Manager (SSM) by listing associations.

    Args:
    ----
        ssm_client (SSMClient): An instance of the AWS Systems Manager (SSM) client.

    Returns:
    -------
        str: A status message indicating the success of the test.
    """
    ssm_client.list_associations(MaxResults=1)
    return "ok"


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    verify_certificate = not params.get("insecure", True)

    aws_access_key_id = dict_safe_get(params, ["credentials", "identifier"])
    aws_secret_access_key = dict_safe_get(params, ["credentials", "password"])
    aws_default_region = params["defaultRegion"]
    aws_role_arn = params.get("roleArn")
    aws_role_session_name = params.get("roleSessionName")
    aws_role_session_duration = params.get("sessionDuration")
    aws_role_policy = (
        None  # added it for using AWSClient class without changing the code
    )
    timeout = params["timeout"]
    retries = params["retries"]

    validate_params(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_access_key_id,
        aws_secret_access_key,
    )
    validate_args(args)

    aws_client = AWSClient(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
    )

    ssm_client = config_aws_session(args, aws_client)

    demisto.debug(f"Command being called is {command}")
    try:
        results: CommandResults | list[CommandResults] | str
        match command:
            case "test-module":
                results = test_module(ssm_client)
            case "aws-ssm-tag-add":
                results = add_tags_to_resource_command(args, ssm_client)
            case "aws-ssm-tag-remove":
                results = remove_tags_from_resource_command(args, ssm_client)
            case "aws-ssm-tag-list":
                results = list_tags_for_resource_command(args, ssm_client)
            case "aws-ssm-inventory-list":
                results = list_inventory_command(args, ssm_client)
            case "aws-ssm-inventory-entry-list":
                results = list_inventory_entry_command(args, ssm_client)
            case "aws-ssm-association-list":
                results = list_associations_command(args, ssm_client)
            case "aws-ssm-association-get":
                results = get_association_command(args, ssm_client)
            case "aws-ssm-association-version-list":
                results = list_versions_association_command(args, ssm_client)
            case "aws-ssm-document-list":
                results = list_documents_command(args, ssm_client)
            case "aws-ssm-document-get":
                results = get_document_command(args, ssm_client)
            case "aws-ssm-automation-execution-list":
                if args.get("execution_id"):
                    results = get_automation_execution_command(args, ssm_client)
                else:
                    results = list_automation_executions_command(args, ssm_client)
            case "aws-ssm-automation-execution-run":
                results = run_automation_execution_command(args, ssm_client)
            case "aws-ssm-automation-execution-cancel":
                results = cancel_automation_execution_command(args, ssm_client)
            case "aws-ssm-command-list":
                results = list_commands_command(args, ssm_client)
            case "aws-ssm-command-run":
                results = run_command_command(args, ssm_client)
            case "aws-ssm-command-cancel":
                results = cancel_command_command(args, ssm_client)
            case _:
                msg = f"Command {command} is not implemented"
                raise NotImplementedError(msg)
        return_results(results)
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
