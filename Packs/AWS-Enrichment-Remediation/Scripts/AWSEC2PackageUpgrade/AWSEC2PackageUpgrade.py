from typing import Any, Dict
import traceback
import re
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


ROLE_SESSION_NAME = "xsoar-session"


def upgrade_package_on_instance(
    platform_type: str,
    platform_name: str,
    asm_rule_id: str,
    instance_id: str,
    version: str,
    region: str,
) -> str:
    """
    This function upgrades a package on an instance using AWS SSM command run.

    Args:
        platform_type (str): The type of the platform (e.g. Linux).
        platform_name (str): The name of the platform (e.g. Ubuntu).
        asm_rule_id (str): The ID of the ASM rule that specifies the package to upgrade.
        instance_id (str): The ID of the instance on which to upgrade the package.
        version (str): The version of the package that needs to be installed.
        region (str): The AWS region in which the instance is located.

    Returns:
        str: The ID of the command that was run on the instance.

    Raises:
        ValueError: If the package upgrade is not supported for the OS or the ASM rule ID.
    """

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
        + "/;"
    }

    # Check if Package upgrade is supported for the OS
    os = platform_type + " " + platform_name
    if os not in os_version_list:
        raise ValueError("Package upgrade is not supported for the OS.")

    # Check if Package upgrade is supported for the ASM Rule
    if asm_rule_id not in asm_rule_package_dict.keys():
        raise ValueError("Package upgrade is not supported for the ASM Rule ID.")

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
    output = demisto.executeCommand("aws-ssm-command-run", cmd_args)

    return output[0]["Contents"]["CommandId"]


def aws_ec2_package_upgrade(args: Dict[str, Any]) -> CommandResults:
    """
    Upgrades a package on a given EC2 instance if the instance is active
    and runs Ubuntu Linux using AWS SSM.

    Args:
        args (Dict[str, Any]): A dictionary containing the arguments for the function.
        This should contain the following keys:
            - instance_id (str): The ID of the EC2 instance to upgrade.
            - asm_rule_id (str): The ID of the ASM rule that specifies the package to upgrade.
            - version (str): The version of the package that needs to be installed.
            - region (Optional[str]): The AWS region in which the instance is located.

    Returns:
        str: The ID of the command that was executed to upgrade the package.

    Raises:
        ValueError: If the version does not match the expected pattern or if the
        instance ID does not exist or if the instance status is not Active.
    """

    instance_id = args.get("instance_id")
    asm_rule_id = args.get("asm_rule_id")
    version = args.get("version")
    region = args.get("region", None)

    # Check version pattern
    version_pattern = r"^openssh-\d+\.\d+[a-z]*\d*p\d+$"
    if not re.match(version_pattern, str(version)):
        raise ValueError(
            "Version does not match the expected pattern. Example: openssh-9.7p1"
        )

    # Get the instance information
    cmd_args = {"instance_id": instance_id, "type_name": "Instance Information"}
    instance_info = demisto.executeCommand("aws-ssm-inventory-entry-list", cmd_args)
    if "Invalid instance id" in instance_info[0]["Contents"]:
        raise ValueError("Instance ID does not exist.")

    instance_info_dict = instance_info[0].get("Contents").get("Entries")[0]

    if instance_info_dict["InstanceStatus"] == "Active":
        command_id = upgrade_package_on_instance(
            instance_info_dict["PlatformType"],
            instance_info_dict["PlatformName"],
            str(asm_rule_id),
            str(instance_id),
            str(version),
            region,
        )

    else:
        raise ValueError(
            "Instance status is not Active. Check SSM agent on the instance."
        )

    command_results = CommandResults(
        outputs={"AWSCommandID": command_id},
        raw_response={"AWSCommandID": command_id},
        readable_output=command_id,
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
