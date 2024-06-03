import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict
import traceback
import re


role_session_name = "xsoar-session"


def upgrade_package_on_instance(
    instance_id: str,
    asm_rule_id: str,
    version: str,
    region: str,
    assume_role: str,
    role_session_name: str
) -> dict:
    """
    Upgrade a specified package on an AWS EC2 instance using AWS SSM.

    Args:
        instance_id (str): The ID of the instance where the package will be upgraded.
        asm_rule_id (str): The ID of the ASM rule that specifies the package to be upgraded.
        version (str): The version of the package to be installed.
        region (str): The AWS region where the instance is located.
        assume_role (str): The AWS IAM role that will be assumed.
        role_session_name (str): The Session role name.

    Returns:
        dict: A dictionary with the keys 'runcommandflag' indicating if the command
        was run successfully, and 'runcommandoutput' containing the output of the command or error message.
    """

    run_command_flag = True
    run_command_output = ''
    os_version_list = ["Linux Ubuntu"]
    asm_rule_package_dict = {"InsecureOpenSSH": ["Linux Ubuntu"]}
    command_dict = {
        "Linux Ubuntu InsecureOpenSSH": r"set -e; apt-get update -y;\
NEEDRESTART_MODE=a apt install tar wget libssl-dev gcc g++ gdb cpp make \
cmake libtool libc6 autoconf automake pkg-config build-essential gettext libz-dev -y;\
wget -c https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/"
        + version
        + ".tar.gz;\
tar -xvf "
        + version
        + ".tar.gz;\
cd "
        + version
        + "/;\
./configure;\
make; make install;\
cd ..;\
rm "
        + version
        + ".tar.gz;\
rm -r "
        + version
    }

    version_pattern = r"^openssh-\d+\.\d+[a-z]*\d*p\d+$"
    if not re.match(version_pattern, str(version)) and run_command_flag:
        run_command_flag = False
        run_command_output = "Version does not match the expected pattern. Example: openssh-9.7p1."

    # Check if Package upgrade is supported for the ASM Rule
    if asm_rule_id not in asm_rule_package_dict.keys() and run_command_flag:
        run_command_flag = False
        run_command_output = "Package upgrade is not supported for the ASM Rule ID."

    # Get the instance information
    cmd_args = {"instance_id": instance_id, "type_name": "Instance Information"}
    if assume_role:
        cmd_args.update({'roleArn': assume_role, 'roleSessionName': role_session_name})
    instance_info = demisto.executeCommand("aws-ssm-inventory-entry-list", cmd_args)

    if "Invalid instance id" in instance_info[0]["Contents"] and run_command_flag:
        run_command_flag = False
        run_command_output = "Invalid instance id."

    if "Entries" in instance_info[0]["Contents"] and len(instance_info[0]["Contents"]['Entries']) == 0 and run_command_flag:
        run_command_flag = False
        run_command_output = "Instance does not exist."

    instance_info_dict = {}
    if run_command_flag:
        instance_info_dict = instance_info[0].get("Contents").get("Entries")[0]

        if instance_info_dict["InstanceStatus"] != "Active":
            run_command_flag = False
            run_command_output = "Instance status is not Active. Check SSM agent on the instance."

    if run_command_flag:
        # Check if Package upgrade is supported for the OS
        os = instance_info_dict["PlatformType"] + " " + instance_info_dict["PlatformName"]
        if os not in os_version_list:
            run_command_flag = False
            run_command_output = "Package upgrade is not supported for the OS."

    if run_command_flag:
        # Determine Command for the OS
        command = command_dict[os + " " + asm_rule_id]

        parameters = {
            "commands": [command],
            "workingDirectory": [""],
            "executionTimeout": ["3600"],
        }

        cmd_args = {
            "document_name": "AWS-RunShellScript",
            "target_key": "Instance Ids",
            "target_values": instance_id,
            "parameters": parameters,
            "region": region,
        }
        if assume_role:
            cmd_args.update({'roleArn': assume_role, 'roleSessionName': role_session_name})
        output = demisto.executeCommand("aws-ssm-command-run", cmd_args)
        run_command_output = output[0]["Contents"]["CommandId"]

    return {'runcommandflag': run_command_flag, 'runcommandoutput': run_command_output}


def aws_ec2_package_upgrade(args: Dict[str, Any]) -> CommandResults:
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
    version = args.get("version")
    region = args.get("region", None)
    assume_role = args.get("assume_role", None)

    results = upgrade_package_on_instance(instance_id, asm_rule_id, version, region, assume_role, role_session_name)

    command_results = CommandResults(
        outputs=results,
        outputs_prefix='awsec2packageupgrade',
        raw_response=results,
        readable_output=results['runcommandoutput'],
    )
    return command_results


""" MAIN FUNCTION """


def main():
    """
    main function
    """
    try:
        return_results(aws_ec2_package_upgrade(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSEC2PackageUpgrade. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

