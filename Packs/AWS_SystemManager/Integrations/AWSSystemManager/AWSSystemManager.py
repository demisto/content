import json
import re
from typing import Any, NoReturn, TYPE_CHECKING

import demistomock as demisto
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: E402

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_ssm.type_defs import (
        GetInventoryRequestRequestTypeDef,
        InventoryResultEntityTypeDef,
        ListAssociationsRequestRequestTypeDef,
        ListDocumentsRequestRequestTypeDef,
        DocumentDescriptionTypeDef
    )

""" CONSTANTS """

SERVICE_NAME = "ssm"  # Amazon Simple Systems Manager (SSM).

REGEX_PATTERNS = {
    "association_id": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                       "Invalid association id: {association_id}"),
    "association_version": (r"([$]LATEST)|([1-9][0-9]*)", "Invalid association version: {association_version}"),
    "instance_id": (r"(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)", "Invalid instance id: {instance_id}"),
    "document_name": (r"^[a-zA-Z0-9_\-.:/]{3,128}$", "Invalid document name: {document_name}"),
}

""" Helper functions """


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
        The following example demonstrates the usage of the function:
        ```
        args = {
            'instance_id': 'i-0a00aaa000000000a', # valid instance id
            'association_id': '0000' # invalid association id
        }
        try:
            validate_args(args)
        except DemistoException as e:  # e equals to "Invalid association id: 0000"
            print(f"Validation error: {e}")
        ```
    """
    for arg_name, (regex_pattern, error_message) in REGEX_PATTERNS.items():
        if (arg_value := args.get(arg_name)) and not re.search(regex_pattern, arg_value):
            raise DemistoException(error_message.format(**{arg_name: arg_value}))
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
        The following example demonstrates how to use the function to convert datetime objects:
        ```
        response = {
            'timestamp': datetime(2023, 8, 20, 12, 30, 0),
            'data': {
                'created_at': datetime(2023, 8, 19, 15, 45, 0)
            }
        }
        iso_response = convert_datetime_to_iso(response)
        print(iso_response)
        #   {
        #   'timestamp': '2023-08-20T12:30:00',
        #   'data': {
        #        'created_at': '2023-08-19T15:45:00'
        #      }
        #   }
        ```
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
    """
    return CommandResults(
        outputs_prefix=f"AWS.SSM.{outputs_prefix}",
        outputs=next_token,
        readable_output=f"For more results rerun the command with {next_token=}.",
    )


""" COMMAND FUNCTIONS """


def add_tags_to_resource_command(ssm_client: "SSMClient", args: dict[str, Any]) -> CommandResults:
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
        readable_output=f"Tags added to resource {args['resource_id']} successfully.",
    )


def get_inventory_command(ssm_client: "SSMClient", args: dict[str, Any]) -> list[CommandResults]:
    """Fetches inventory information from AWS SSM using the provided SSM client and arguments.

    Args:
    ----
        ssm_client: SSM client object for making API requests.
        args (dict): Command arguments containing filters and parameters.

    Returns:
    -------
        list[CommandResults]: A list of CommandResults containing the inventory information.
    """
    def _parse_inventory_entities(entities: list["InventoryResultEntityTypeDef"]) -> list[dict]:
        """Parses a list of entities and returns a list of dictionaries containing relevant information.

        Args:
        ----
            entities: A list of entities to parse.

        Returns:
        -------
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
                    },
                )
                parsed_entities.append(parsed_entity)
        return parsed_entities

    kwargs: "GetInventoryRequestRequestTypeDef" = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if (next_token := args.get("next_token")):
        kwargs["NextToken"] = next_token

    response = ssm_client.get_inventory(**kwargs)
    command_results = []

    if response_next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(response_next_token, "InventoryNextToken"),
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
        ),
    )
    return command_results


def list_inventory_entry_command(ssm_client: "SSMClient", args: dict[str, Any]) -> list[CommandResults]:
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
    def _parse_inventory_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parses a list of inventory entries and returns a list of dictionaries containing relevant information.

        Args:
        ----
            entries (list[dict]): A list of inventory entries to parse.

        Returns:
        -------
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
    kwargs.update({"NextToken": next_token}) if (next_token := args.get("next_token")) else None

    response = ssm_client.list_inventory_entries(**kwargs)
    entries = response.get("Entries", [])

    command_results = []
    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "InventoryEntryNextToken"),
        )

    command_results.append(
        CommandResults(
            outputs_prefix="AWS.SSM.InventoryEntry",
            outputs=entries,
            outputs_key_field="InstanceId",
            readable_output=tableToMarkdown(
                name="AWS SSM Inventory",
                t=_parse_inventory_entries(entries),
            ),
        ),
    )

    return command_results


def list_associations_command(ssm_client: "SSMClient", args: dict[str, Any]) -> list[CommandResults]:
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
                "Resource status count": dict_safe_get(association, ["Overview", "AssociationStatusAggregatedCount"]),
                "Status": dict_safe_get(association, ["Overview", "Status"]),
            }
            for association in associations
        ]

    kwargs: "ListAssociationsRequestRequestTypeDef" = {"MaxResults": arg_to_number(args.get("limit", 50)) or 50}
    kwargs.update({"NextToken": next_token}) if (next_token := args.get("next_token")) else None

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
                name="AWS SSM Association",
                t=_parse_associations(associations),
            ),
        ),
    )

    return command_results


def get_association_command(ssm_client: "SSMClient", args: dict[str, Any]) -> CommandResults:
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
            "Resource status count": dict_safe_get(association, ["Overview", "AssociationStatusAggregatedCount"]),
            "Status": dict_safe_get(association, ["Overview", "Status"]),
            "Create date": association.get("Date"),
            "Schedule expression": association.get("ScheduleExpression"),
        }
    association_id = args.get("association_id")
    association_version = args.get("association_version")
    instance_id = args.get("instance_id")
    document_name = args.get("document_name")

    validate_args(args)  # raises DemistoException if invalid args

    if not bool(association_id or (instance_id and document_name)):
        msg = "This command  must provide either association id or instance_id and document_name."
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
            name="Association",
            t=_parse_association(association_description),
        ),
    )


def list_versions_association_command(ssm_client: "SSMClient", args: dict[str, Any]) -> list[CommandResults]:
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
    def _parse_association_versions(association_versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    validate_args(args)
    kwargs = {"AssociationId": args["association_id"], "MaxResults": arg_to_number(args.get("limit", 50)) or 50}
    kwargs.update({"NextToken": next_token}) if (next_token := args.get("next_token")) else None

    response = ssm_client.list_association_versions(**kwargs)
    response = convert_datetime_to_iso(response)
    association_versions = response.get("AssociationVersions", [])

    command_results: list[CommandResults] = []
    if response_next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(response_next_token, "AssociationVersionNextToken"),
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


def list_documents_command(ssm_client: "SSMClient", args: dict[str, Any]) -> list[CommandResults]:
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
                "Display Name": document.get("DisplayName"),
                "Owner": document.get("Owner"),
                "Document version": document.get("DocumentVersion"),
                "Document type": document.get("DocumentType"),
                "Created date": document.get("CreatedDate"),
                "Tags": document.get("Tags"),
                "Platform types": document.get("PlatformTypes"),
            } for document in documents]
    kwargs: "ListDocumentsRequestRequestTypeDef" = {"MaxResults": arg_to_number(args.get("limit", 50)) or 50}
    if (next_token := args.get("next_token")):
        kwargs["NextToken"] = next_token

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
                name="AWS SSM Document",
                t=_parse_documents(documents),
                json_transform_mapping={
                    "Tags": JsonTransformer(
                        is_nested=True,
                    ),
                },
            ),
        ),
    )
    return command_results


def get_document_command(ssm_client: "SSMClient", args: dict[str, Any]) -> CommandResults:
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
    document_version = args.get("document_version")
    version_name = args.get("version_name")

    kwargs = {"Name": args["document_name"]}
    kwargs.update({"DocumentVersion": document_version}) if document_version else None
    kwargs.update({"VersionName": version_name}) if version_name else None
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
        )
    )


def test_module(ssm_client: "SSMClient") -> str:
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
            case "aws-ssm-association-version-list":
                return_results(list_versions_association_command(ssm_client, args))
            case "aws-ssm-document-list":
                return_results(list_documents_command(ssm_client, args))
            case "aws-ssm-document-get":
                return_results(get_document_command(ssm_client, args))
            case _:
                msg = f"Command {command} is not implemented"
                raise NotImplementedError(msg)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
