import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AWSApiModule import *
import re

# from mypy_boto3_ssm.client import SSMClient, Exceptions


# from mypy_boto3_ssm.type_defs import (
#     AddTagsToResourceRequestRequestTypeDef,
#     GetInventoryRequestRequestTypeDef,
#     InventoryResultEntityTypeDef,
#     ListInventoryEntriesRequestRequestTypeDef,
#     ListAssociationsRequestRequestTypeDef,
# )

""" CONSTANTS """

SERVICE_NAME = "ssm"  # Amazon Simple Systems Manager (SSM).
REGEX_INSTANCE_ID = r"(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)"

""" Helper functions """


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


def add_tags_to_resource_command(aws_client, args: dict[str, Any]) -> CommandResults:
    """
    Adds tags to a specified resource.
    The response from the API call when success is empty dict.
    Args:
        aws_client (SSMClient): An instance of the SSM client.
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

    aws_client.add_tags_to_resource(**kwargs)
    return CommandResults(
        readable_output=f"Tags added to resource {args['resource_id']} successfully.",
    )


def get_inventory_command(aws_client, args: dict[str, Any]) -> list[CommandResults]:
    def _parse_inventory_entities(entities) -> list[dict[str, str]]:
        """
        Parses a list of entities and returns a list of dictionaries containing relevant information.

        Args:
            entities: A list of entities to parse.

        Returns:
            list of dict containing relevant information.
        """
        parsed_entities = []
        for entity in entities:
            entity_content = entity.get("Data", {}).get("AWS:InstanceInformation", {}).get("Content", [{}])
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

    response = aws_client.get_inventory(**kwargs)
    # except InvalidNextToken as e:
    #     raise DemistoException(
    #         f"Invalid next token. If the command has already been run, "
    #         f"the next token exists in the context data in the key AWS.SSM.InventoryNextToken. :{e}."
    #     )

    command_results = []
    if next_token := response.get("NextToken"):
        command_results.append(
            next_token_command_result(next_token, "InventoryNextToken")
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


def list_inventory_entry_command(
    aws_client, args: dict[str, Any]
) -> list[CommandResults]:
    def _parse_inventory_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    if (instance_id := args["instance_id"]) and not re.search(
        REGEX_INSTANCE_ID, instance_id
    ):
        raise DemistoException(f"Invalid instance id: {instance_id}")

    kwargs = {
        "InstanceId": instance_id,
        "TypeName": args["type_name"],
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if next_token := args.get("next_token"):
        kwargs["NextToken"] = next_token

    response: dict = aws_client.list_inventory_entries(**kwargs)
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


def list_associations_command(aws_client, args: dict[str, Any]) -> list[CommandResults]:
    def _parse_associations(associations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "Document name": association.get("Name"),
                "Association id": association.get("AssociationId"),
                "Association version": association.get("AssociationVersion"),
                "Last execution date": str(association.get("LastExecutionDate")),
                "Resource status count": association.get("Overview", {}).get("AssociationStatusAggregatedCount"),
                "Status": association.get("OverView", {}).get("Status"),
            }
            for association in associations
        ]

    kwargs = {
        "MaxResults": arg_to_number(args.get("limit", 50)) or 50,
    }
    if next_token := args.get("next_token"):
        kwargs["NextToken"] = next_token
    response = aws_client.list_associations(**kwargs)

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


def test_module(aws_client) -> str:
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
    aws_access_key_id = params.get("credentials", {}).get("identifier") or params.get(
        "access_key"
    )
    aws_secret_access_key = params.get("credentials", {}).get("password") or params.get(
        "secret_key"
    )
    aws_role_policy = (
        None  # added it for using AWSClient class without changing the code
    )
    timeout = params.get("timeout")
    retries = params.get("retries") or 5

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

    aws_client = config_aws_session(args, aws_client)

    demisto.debug(f"Command being called is {command}")
    try:
        match command:
            case "test-module":
                return_results(test_module(aws_client))
            case "aws-ssm-tag-add":
                return_results(add_tags_to_resource_command(aws_client, args))
            case "aws-ssm-inventory-get":
                return_results(get_inventory_command(aws_client, args))
            case "aws-ssm-inventory-entry-list":
                return_results(list_inventory_entry_command(aws_client, args))
            case "aws-ssm-association-list":
                return_results(list_associations_command(aws_client, args))
            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
