import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Any
import traceback
import json


ROLE_SESSION_NAME = "xsoar-session"


def upgrade_package_on_instance(
    instance_id: str,
    asm_rule_id: str,
    region: str,
    assume_role_arn: str
) -> dict:
    """
    Upgrade a specified package on an AWS EC2 instance using AWS SSM.

    Args:
        instance_id (str): The ID of the instance where the package will be upgraded.
        asm_rule_id (str): The ID of the ASM rule that specifies the package to be upgraded.
        region (str): The AWS region where the instance is located.
        assume_role_arn (str): The AWS IAM role arn that will be assumed.

    Returns:
        dict: A dictionary with the keys 'run_command_flag' indicating if the command
        was run successfully, and 'run_command_output' containing the output of the command or error message.
    """

    output_run_command_dict = {"run_command_flag": True, "run_command_output": ""}

    asm_rule_package_dict = {
        "InsecureOpenSSH": {
            "Linux Ubuntu": r"set -e; apt-get update -y;\
NEEDRESTART_MODE=a apt install tar wget libssl-dev gcc g++ gdb cpp make \
cmake libtool libc6 autoconf automake pkg-config build-essential gettext libz-dev -y;\
wget -c https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.8p1.tar.gz;\
tar -xvf openssh-9.8p1.tar.gz; cd openssh-9.8p1; ./configure; make; make install;\
cd ..; rm openssh-9.8p1.tar.gz; rm -r openssh-9.8p1"
        }
    }

    # Check if Package upgrade is supported for the ASM Rule
    if asm_rule_id not in asm_rule_package_dict and output_run_command_dict.get(
        "run_command_flag"
    ):
        output_run_command_dict["run_command_flag"] = False
        output_run_command_dict["run_command_output"] = (
            "Package upgrade is not supported for the ASM Rule ID."
        )
        return output_run_command_dict

    # Get the instance information
    cmd_args = {"instance_id": instance_id, "type_name": "Instance Information"}
    if len(assume_role_arn) > 0:
        cmd_args.update({"roleArn": assume_role_arn, "roleSessionName": ROLE_SESSION_NAME})
    instance_info = demisto.executeCommand("aws-ssm-inventory-entry-list", cmd_args)

    if "Invalid instance id" in instance_info[0].get(
        "Contents"
    ) and output_run_command_dict.get("run_command_flag"):
        output_run_command_dict["run_command_flag"] = False
        output_run_command_dict["run_command_output"] = "Invalid instance id."
        return output_run_command_dict

    if (
        "Entries" in instance_info[0].get("Contents")
        and len(instance_info[0].get("Contents").get("Entries")) == 0
        and output_run_command_dict.get("run_command_flag")
    ):
        output_run_command_dict["run_command_flag"] = False
        output_run_command_dict["run_command_output"] = "Instance does not exist."
        return output_run_command_dict

    instance_info_dict = {}
    if output_run_command_dict.get("run_command_flag"):
        instance_info_dict = instance_info[0].get("Contents").get("Entries")[0]

        if instance_info_dict.get("InstanceStatus") != "Active":
            output_run_command_dict["run_command_flag"] = False
            output_run_command_dict["run_command_output"] = (
                "Instance status is not Active. Check SSM agent on the instance."
            )
            return output_run_command_dict

    if output_run_command_dict.get("run_command_flag"):
        # Check if Package upgrade is supported for the OS
        os = (
            instance_info_dict.get("PlatformType", "")
            + " "
            + instance_info_dict.get("PlatformName", "")
        )
        if os not in asm_rule_package_dict.get(asm_rule_id, {}).keys():
            output_run_command_dict["run_command_flag"] = False
            output_run_command_dict["run_command_output"] = (
                "Package upgrade is not supported for the OS."
            )
            return output_run_command_dict

    if output_run_command_dict.get("run_command_flag"):
        # Determine Command for the OS
        command = asm_rule_package_dict.get(asm_rule_id, {}).get(
            instance_info_dict.get("PlatformType", "")
            + " "
            + instance_info_dict.get("PlatformName", "")
        )

        parameters = {
            "commands": [command],
            "workingDirectory": [""],
            "executionTimeout": ["3600"],
        }

        cmd_args = {
            "document_name": "AWS-RunShellScript",
            "target_key": "Instance Ids",
            "target_values": instance_id,
            "parameters": json.dumps(parameters),
            "region": region,
        }
        if len(assume_role_arn) > 0:
            cmd_args.update(
                {"roleArn": assume_role_arn, "roleSessionName": ROLE_SESSION_NAME}
            )
        output = demisto.executeCommand("aws-ssm-command-run", cmd_args)
        output_run_command_dict["run_command_output"] = (
            "AWS SSM Command run initiated successfully."
        )
        output_run_command_dict["run_command_id"] = (
            output[0].get("Contents").get("CommandId")
        )

    return output_run_command_dict


def aws_package_upgrade(args: dict[str, Any]) -> CommandResults:
    """
    Initiates an upgrade of a software package on a specified AWS EC2 instance.

    This function takes arguments from a command, passes them to the
    upgrade_package_on_instance function, and returns a CommandResults object
    containing the results of the attempted package upgrade.

    Args:
        args (Dict[str, Any]): A dictionary containing:
            - instance_id (str): The ID of the EC2 instance where the package will be upgraded.
            - asm_rule_id (str): The ID of the ASM rule that specifies the package to be upgraded.
            - version (str): The version of the package to install.
            - region (str, optional): The AWS region where the instance is located. If not specified,
                                      it will default to the region of the running Lambda function or EC2 instance.

    Returns:
        CommandResults: A CommandResults object with the results of the package upgrade operation.

    """
    instance_id = args.get("instance_id")
    asm_rule_id = args.get("asm_rule_id")
    region = args.get("region", None)
    assume_role = args.get("assume_role", None)
    account_id = args.get("account_id", None)

    instance_id = str(instance_id) if instance_id is not None else ""
    asm_rule_id = str(asm_rule_id) if asm_rule_id is not None else ""

    assume_role_arn = ''

    if assume_role and account_id:
        assume_role_arn = "arn:aws:iam::" + str(account_id) + ":role/" + str(assume_role)

    results = upgrade_package_on_instance(
        instance_id, asm_rule_id, region, assume_role_arn
    )
    command_results = CommandResults(
        outputs=results,
        outputs_prefix="awspackageupgrade",
        raw_response=results,
        readable_output=results.get("run_command_output"),
    )
    return command_results


""" MAIN FUNCTION """


def main():
    """
    main function
    """
    try:
        return_results(aws_package_upgrade(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSPackageUpgrade. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
