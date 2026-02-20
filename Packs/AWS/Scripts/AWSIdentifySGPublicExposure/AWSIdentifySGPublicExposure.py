import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback


def ec2_instance_info(
    account_id: str, instance_id: str, public_ip: str, region: str, integration_instance: str
) -> tuple[str, list, str]:
    """
    Finds interface with public_ip and from this creates interface ID/SG mapping

    Args:
        account_id (str): AWS Account ID
        instance_id (str): EC2 Instance ID
        public_ip (str): Public IP address of the EC2 instance
        region (str):  AWS Region where the instance is located
        integration_instance (str): The AWS Integration Instance to use

    Returns:
        tuple: A tuple containing:
            - The identified network interface
            - List of its security groups
            - The AWS integration instance used to retrieve the information
    """
    cmd_args = {
        "instance_ids": instance_id,
        "region": region,
        "account_id": account_id,
        "using": integration_instance if integration_instance else None,
    }

    result = demisto.executeCommand("aws-ec2-instances-describe", cmd_args)

    instance_info = []

    if result and len(result) > 1:
        # If multiple entries were returned, such as when multiple AWS integration instances are configured,
        # Identify the first entry with valid results.
        for entry in result:
            if not isError(entry):
                instance_info = [entry]
                break
        else:
            # If all entries are errors, use the first entry
            instance_info = [result[0]]
    else:
        instance_info = result

    if isError(instance_info) or not instance_info:
        raise DemistoException(
            f"Error retrieving instance network interface details with command 'aws-ec2-instances-describe'.\n"
            f"Error: {json.dumps(instance_info[0]['Contents'])}"
        )

    interfaces = dict_safe_get(instance_info, (0, "Contents", "Reservations", 0, "Instances", 0, "NetworkInterfaces"))
    instance_to_use = dict_safe_get(instance_info, (0, "Metadata", "instance"))

    if interfaces:
        for interface in interfaces:
            if interface.get("Association") and interface.get("Association").get("PublicIp") == public_ip:
                group_list = []
                for sg in interface["Groups"]:
                    group_list.append(sg["GroupId"])
                return interface["NetworkInterfaceId"], group_list, instance_to_use

    # Raise an error if no interface was found with the given public IP
    raise ValueError("Unable to find interface associated with the given public IP address.")


def identify_sgs(args: dict[str, Any]) -> CommandResults:
    """
    Main command that determines what EC2 network interface has a given public IP address and lists its security groups.

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        CommandResults: Demisto CommandResults object containing:
            - EC2InstanceID: The original EC2 instance ID
            - NetworkInterfaceID: The network interface ID
            - PublicIP: The public IP address
            - SecurityGroups: List of associated security group IDs
    """

    account_id = args.get("account_id", "")
    instance_id = args.get("instance_id", "")
    public_ip = args.get("public_ip", "")
    region = args.get("region", "")
    integration_instance = args.get("integration_instance", "")

    ec2_interface, sg_list, instance_to_use = ec2_instance_info(account_id, instance_id, public_ip, region, integration_instance)

    readable_output = (
        f"EC2 instance {instance_id} has public IP {public_ip} on ENI {ec2_interface}: \r\n"
        f"Associated Security Groups: {', '.join(sg_list)}."
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field="EC2InstanceID",
        outputs={
            "EC2InstanceID": instance_id,
            "NetworkInterfaceID": ec2_interface,
            "PublicIP": public_ip,
            "SecurityGroups": sg_list,
            "IntegrationInstance": instance_to_use,
        },
        outputs_prefix="AWSPublicExposure.SGAssociations",
    )


def main():
    try:
        return_results(identify_sgs(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSIdentifySGPublicExposure. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
