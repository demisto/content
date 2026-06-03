from datetime import UTC
import boto3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from dateparser import parse
from AWSApiModule import *  # noqa: E402
from botocore.client import BaseClient as BotoClient

DEFAULT_RETRIES = 5


def build_client(params: dict) -> AWSClient:
    aws_region = params.get("region")
    aws_role_arn = params.get("role_arn")
    aws_role_session_name = params.get("role_session_name")
    aws_role_session_duration = params.get("session_duration")
    aws_role_policy = None
    aws_access_key_id = params.get("credentials", {}).get("identifier")
    aws_secret_access_key = params.get("credentials", {}).get("password")
    verify_certificate = not params.get("insecure", True)
    timeout = params.get("timeout")
    retries = params.get("retries", DEFAULT_RETRIES)
    sts_endpoint_url = params.get("sts_endpoint_url")
    endpoint_url = params.get("endpoint_url")

    validate_params(aws_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key)

    return AWSClient(
        aws_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
        sts_endpoint_url=sts_endpoint_url,
        endpoint_url=endpoint_url,
    ).aws_session(
        service="ec2",
        region=aws_region,
        role_arn=aws_role_arn,
        role_session_name=aws_role_session_name,
        role_session_duration=aws_role_session_duration,
    )


def test_module(client: BotoClient) -> str:
    pass


def main():  # pragma: no cover
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    try:
        client = build_client(params)
        demisto.debug(f"Command being called is {command}")

        # if command == "test-module":
        #     # This is the call made when pressing the integration test button.
        #     human_readable, outputs, response = test_function(client)
        # elif command == "aws-securityhub-get-findings":
        #     human_readable, outputs, response = get_findings_command(client, args)
        # elif command == "aws-securityhub-get-master-account":
        #     human_readable, outputs, response = get_master_account_command(client, args)
        # elif command == "aws-securityhub-list-members":
        #     human_readable, outputs, response = list_members_command(client, args)
        # elif command == "aws-securityhub-enable-security-hub":
        #     human_readable, outputs, response = enable_security_hub_command(client, args)
        # elif command == "aws-securityhub-disable-security-hub":
        #     human_readable, outputs, response = disable_security_hub_command(client, args)
        # elif command == "aws-securityhub-update-findings":
        #     human_readable, outputs, response = update_findings_command(client, args)
        # elif command == "aws-securityhub-batch-update-findings":
        #     human_readable, outputs, response = batch_update_findings_command(client, args)
        # elif command == "fetch-incidents":
        #     fetch_incidents(
        #         client,
        #         aws_sh_severity,
        #         archive_findings,
        #         additional_filters,
        #         mirror_direction,
        #         finding_type,
        #         workflow_status,
        #         product_name,
        #     )
        #     return
        # elif command == "get-remote-data":
        #     return_results(get_remote_data_command(client, args))
        #     return
        # elif command == "update-remote-system":
        #     return_results(update_remote_system_command(client, args, resolve_findings))
        #     return
        # elif command == "get-mapping-fields":
        #     return_results(get_mapping_fields_command())
        #     return
        # else:
        #     raise NotImplementedError(f"{command} command is not implemented.")

        # return_outputs(human_readable, outputs, response)

    except Exception as e:
        return_error(f"Error has occurred in the AWS securityhub Integration: {type(e)} {e}", error=e)


if __name__ in ["__builtin__", "builtins", "__main__"]:  # pragma: no cover
    main()
