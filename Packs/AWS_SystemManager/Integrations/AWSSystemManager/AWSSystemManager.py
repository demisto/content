import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AWSApiModule import *
import re


""" CONSTANTS """

SERVICE_NAME = "ssm"  # Amazon Simple Systems Manager (SSM).

REGEX_PATTERNS = {
    "association_id": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                       "Invalid association id: {association_id}"),
    "association_version": (r"([$]LATEST)|([1-9][0-9]*)", "Invalid association version: {association_version}"),
    "instance_id": (r"(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)", "Invalid instance id: {instance_id}"),
    "document_name": (r"^[a-zA-Z0-9_\-.:/]{3,128}$", "Invalid document name: {document_name}")
}

""" Helper functions """


def validate_args(args: dict[str, Any]) -> None:
    for arg_name, (regex_pattern, error_message) in REGEX_PATTERNS.items():
        if (arg_value := args.get(arg_name)) and not re.search(regex_pattern, arg_value):
            raise DemistoException(error_message.format(**{arg_name: arg_value}))


def config_aws_session(args: dict[str, str], aws_client: AWSClient):
    """
    Configures an AWS session for the Lambda service,
    Used in all the commands.

    Args:
        args (dict): A dictionary containing the configuration parameters for the session.
                     - 'region' (str): The AWS region.
                     - 'roleArn' (str): The ARN of the IAM role.
                     - 'roleSessionName' (str): The name of the role session.
                     - 'roleSessionDuration' (str): The duration of the role session.

        aws_client (AWSClient): The AWS client used to configure the session.

    Returns:
        AWS session (boto3 client): The configured AWS session.
    """
    return aws_client.aws_session(
        service=SERVICE_NAME,
        region=args.get("region"),
        role_arn=args.get("roleArn"),
        role_session_name=args.get("roleSessionName"),
        role_session_duration=args.get("roleSessionDuration"),
    )


def convert_datetime_to_iso(response: dict[str, Any]) -> dict[str, Any]:
    """
    Converts datetime objects in a response dictionary to ISO formatted strings.

    Args:
        response (dict): The response dictionary.

    Returns:
        dict: The response dictionary with datetime objects converted to ISO formatted strings.
    """
    def datetime_to_string(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj
    response_str = json.dumps(response, default=datetime_to_string)
    response = json.loads(response_str)
    return response


def next_token_command_result(next_token: str, outputs_prefix: str) -> CommandResults:
    """
    Creates a CommandResults object with the next token as the output.

    Args:
        next_token (str): The next token.
        outputs_prefix (str): The prefix for the outputs.

    Returns:
        CommandResults: A CommandResults object with the next token as the output.
    """
    return CommandResults(
        outputs_prefix=f"AWS.SSM.{outputs_prefix}",
        outputs=next_token,
        readable_output=f"For more results rerun the command with {next_token=}.",
    )


""" COMMAND FUNCTIONS """


def add_tags_to_resource_command(ssm_client, args: dict[str, Any]) -> CommandResults:
    """
    Adds tags to a specified resource.
    The response from the API call when success is empty dict.
    Args:
        ssm_client (SSMClient): An instance of the SSM client.
        args (dict): A dictionary containing the command arguments.
                     - 'resource_type' (str): The type of the resource.
                     - 'resource_id' (str): The ID of the resource.
                     - 'tag_key' (str): The key of the tag to add.
                     - 'tag_value' (str): The value of the tag to add.

    Returns:
        CommandResults: readable output only,
    """
    kwargs = {
        "ResourceType": args["resource_type"],
        "ResourceId": args["resource_id"],
        "Tags": [{"Key": args["tag_key"], "Value": args["tag_value"]}],
    }

    ssm_client.add_tags_to_resource(**kwargs)
    return CommandResults(
        readable_output=f"Tags added to resource {args['resource_id']} successfully.",
    )


def get_inventory_command(ssm_client, args: dict[str, Any]) -> list[CommandResults]:
    """
    Fetches inventory information from AWS SSM using the provided SSM client and arguments.

    Args:
        ssm_client: SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.

    Returns:
        list[CommandResults]: A list of CommandResults containing the inventory information.
    """
    def _parse_inventory_entities(entities: list[dict]) -> list[dict]:
        """
        Parses a list of entities and returns a list of dictionaries containing relevant information.

        Args:
            entities: A list of entities to parse.

        Returns:
            list of dict containing relevant information.
        """
        parsed_entities = []
        for entity in entities:
            entity_content = dict_safe_get(entity, ["Data", "AWS:InstanceInformation", "Content"], [{}])
            parsed_entity = {"Id": entity.get("Id")}
            for content in entity_content:
                parsed_entity.update(
                    {
                        "Instance Id": content.get("InstanceId"),
                        "Computer Name": content.get("ComputerName"),
                        "Platform Type": content.get("PlatformType"),
                        "Platform Name": content.get("PlatformName"),
                        "Agent version": content.get("AgentVersion"),
                        "IP address": content.get("IpAddress"),
                        "Resource Type": content.get("ResourceType"),
                    }
                )
                parsed_entities.append(parsed_entity)
        return parsed_entities

    kwargs = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if next_token := args.get("next_token"):
        kwargs["NextToken"] = next_token

    response = ssm_client.get_inventory(**kwargs)
    command_results = []

    if response_next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(response_next_token, "InventoryNextToken")
        )

    entities = response.get("Entities", [])
    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.Inventory",
            outputs=entities,
            outputs_key_field="Id",
            readable_output=tableToMarkdown(
                name="AWS SSM Inventory",
                t=_parse_inventory_entities(entities),
            ),
        )
    )
    return command_results


def list_inventory_entry_command(ssm_client, args: dict[str, Any]) -> list[CommandResults]:
    """
    Lists inventory entries for a specific instance and type name using the provided SSM client and arguments.

    Args:
        ssm_client: AWS SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.
            - instance_id (str): The ID of the instance.
            - type_name (str): The type name of the inventory.
            - limit (int, optional): Maximum number of entries to retrieve. Defaults to 50.
            - next_token (str, optional): Token to retrieve the next set of entries.

    Returns:
        list[CommandResults]: A list of CommandResults containing the inventory entries information.
            and the next token if exists.

    Raises:
        DemistoException: If an invalid instance ID is provided.
    """
    def _parse_inventory_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Parses a list of inventory entries and returns a list of dictionaries containing relevant information.

        Args:
            entries (list[dict]): A list of inventory entries to parse.

        Returns:
            list[dict]: A list of dictionaries containing relevant information for each inventory entry.
        """

        return [
            {
                "Instance Id": entry.get("InstanceId"),
                "Computer Name": entry.get("ComputerName"),
                "Platform Type": entry.get("PlatformType"),
                "Platform Name": entry.get("PlatformName"),
                "Agent version": entry.get("AgentVersion"),
                "IP address": entry.get("IpAddress"),
                "Resource Type": entry.get("ResourceType"),
            }
            for entry in entries
        ]

    validate_args(args)

    kwargs = {
        "InstanceId": args["instance_id"],
        "TypeName": args["type_name"],
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if next_token := args.get("next_token"):
        kwargs["NextToken"] = next_token

    response: dict = ssm_client.list_inventory_entries(**kwargs)
    response.pop("ResponseMetadata")

    command_results = []
    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "InventoryEntryNextToken")
        )

    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.InventoryEntry",
            outputs=response,
            outputs_key_field="InstanceId",
            readable_output=tableToMarkdown(
                name="AWS SSM Inventory",
                t=_parse_inventory_entries(response.get("Entries", [])),
            ),
        )
    )

    return command_results


def list_associations_command(ssm_client, args: dict[str, Any]) -> list[CommandResults]:
    """
    Lists associations in AWS SSM using the provided SSM client and arguments.

    Args:
        ssm_client: AWS SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.
            - limit (int, optional): Maximum number of associations to retrieve. Defaults to 50.
            - next_token (str, optional): Token to retrieve the next set of associations.

    Returns:
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
                "Resource status count": dict_safe_get(association, ["Overview", "AssociationStatusAggregatedCount"]),
                "Status": dict_safe_get(association, ["Overview", "Status"])
            }
            for association in associations
        ]

    kwargs = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if next_token := args.get("next_token"):
        kwargs["NextToken"] = next_token
    response: dict[str, list] = ssm_client.list_associations(**kwargs)
    response.pop("ResponseMetadata")
    response = convert_datetime_to_iso(response)

    command_results = []

    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "InventoryNextToken")
        )

    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.Association",
            outputs=response,
            outputs_key_field="AssociationId",
            readable_output=tableToMarkdown(
                name="AWS SSM Association",
                t=_parse_associations(response.get("Associations", [])),
            ),
        )
    )

    return command_results


def get_association_command(ssm_client, args: dict[str, Any]) -> CommandResults:
    def _parse_association(association: dict[str, Any]) -> dict[str, Any]:
        return {
            "Document name": association.get("Name"),
            "Document version": association.get("DocumentVersion"),
            "Association name": association.get("AssociationName"),
            "Association id": association.get("AssociationId"),
            "Association version": association.get("AssociationVersion"),
            "Last execution date": association.get("LastExecutionDate"),
            "Resource status count": dict_safe_get(association, ["Overview", "AssociationStatusAggregatedCount"]),
            "Status": dict_safe_get(association, ["Overview", "Status"]),
            "Create date": association.get("Date"),
            "Schedule expression": association.get("ScheduleExpression"),
        }
    association_id = args.get("association_id")
    association_version = args.get("association_version")
    instance_id = args.get("instance_id")
    document_name = args.get("document_name")

    validate_args(args)

    if not bool(association_id or (instance_id and document_name)):
        raise DemistoException("This command  must provide either association id or instance_id and document_name.")

    kwargs = {
        "AssociationId": association_id,
        "AssociationVersion": association_version,
        "InstanceId": instance_id,
        "Name": document_name,
    }
    kwargs = {key: value for key, value in kwargs.items() if value is not None}

    response = ssm_client.describe_association(**kwargs)
    response = convert_datetime_to_iso(response)
    response.pop("ResponseMetadata")

    return CommandResults(
        outputs=response,
        outputs_key_field="AssociationId",
        outputs_prefix="AWS.SSM.Association",
        readable_output=tableToMarkdown(
            name="Association",
            t=_parse_association(response.get("AssociationDescription", {}))
        ),
    )


def test_module(ssm_client) -> str:
    ssm_client.list_associations(MaxResults=1)
    return "ok"


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    verify_certificate = not params.get("insecure", True)

    aws_default_region = params["defaultRegion"]
    aws_role_arn = params.get("roleArn")
    aws_role_session_name = params.get("roleSessionName")
    aws_role_session_duration = params.get("sessionDuration")
    aws_access_key_id = dict_safe_get(params, ["credentials", "identifier"])
    aws_secret_access_key = dict_safe_get(params, ["credentials", "password"])
    aws_role_policy = None  # added it for using AWSClient class without changing the code
    timeout = params["timeout"]
    retries = params["retries"]

    validate_params(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_access_key_id,
        aws_secret_access_key,
    )

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

    ssm_client = config_aws_session(args, aws_client)  # ssm, Simple Systems Manager

    demisto.debug(f"Command being called is {command}")
    try:
        match command:
            case "test-module":
                return_results(test_module(ssm_client))
            case "aws-ssm-tag-add":
                return_results(add_tags_to_resource_command(ssm_client, args))
            case "aws-ssm-inventory-get":
                return_results(get_inventory_command(ssm_client, args))
            case "aws-ssm-inventory-entry-list":
                return_results(list_inventory_entry_command(ssm_client, args))
            case "aws-ssm-association-list":
                return_results(list_associations_command(ssm_client, args))
            case "aws-ssm-association-get":
                return_results(get_association_command(ssm_client, args))
            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
