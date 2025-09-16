import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback
from typing import Any


demisto.debug("pack name = PAN-OS by Palo Alto Networks, pack version = 2.2.7")


def run_command(args: dict) -> dict:
    """run_command Runs the `pano-os-platform-get-available-software` command using the specified Integration Instance

    Args:
        args (dict): Script arguments

    Raises:
        Exception: Raises exception if the executed command returns an error response

    Returns:
        dict: A tuple of two lists: the command results list and command errors list.
    """
    # Set command args
    allowed_args = ["device_filter_string", "target", "panos_instance_name"]
    command_args = {k: args.get(k) for k in allowed_args if k in args}

    # Rename 'instance_name' key to 'using' to match the command syntax, if one was provided
    if "panos_instance_name" in command_args:
        command_args["using"] = command_args.pop("panos_instance_name")

    # Execute the command
    res = demisto.executeCommand("pan-os-platform-get-available-software", command_args)

    # Check if the command returned an error and raise exception if needed
    if is_error(res):
        raise Exception(f"Error executing pan-os-platform-get-system-info: {get_error(res)}")

    # Return command results
    return res


def get_current_version_and_base_version(versions: list) -> tuple[dict, dict]:
    """get_current_version_and_base_version Identify the currently installed software version and its required
    base version.

    Args:
        versions (list): List of PAN-OS images as returned from `pano-os-platform-get-available-software` command

    Raises:
        Exception: Raises an exception if list is missing an entry indicating the currently installed version

    Returns:
        tuple[dict]: Software image information for the current version and its required base version
    """
    # Identify the software image labeled as currently installed
    for item in versions:
        if item["current"]:
            # Calculate base version of this image
            base_image_parts = item["version"].split(".")
            if base_image_parts[-1] != "0":
                base_image_parts = base_image_parts[0:2]
                base_image_parts.append("0")
                base_image_version = ".".join(base_image_parts)
            else:
                base_image_version = item["version"]

            base_version: dict = next((v for v in versions if v.get("version") == base_image_version), {})
            return item, base_version

    # If no currently installed image was found, raise an error
    raise Exception("Command results did not contain a version labeled as current.")


def parse_version(version: str) -> tuple[int, ...]:
    """parse_version Splits a PAN-OS software version string into parts.

    Args:
        version (str): The PAN-OS version string (e.g. "11.2.1-h2")

    Returns:
        tuple[str]: Parts of the PAN-OS version (major, feature, minor, hotfix)
    """
    # Split the version into main parts and hotfix parts
    parts = version.split(".")
    major = int(parts[0])
    feature = int(parts[1])
    minor_and_hotfix = parts[2].split("-")

    minor = int(minor_and_hotfix[0])

    # Identify if a hotfix version was included
    if len(minor_and_hotfix) == 2:
        # Get the hotfix number without the "h"
        hotfix = int(minor_and_hotfix[1][1:])
    else:
        # No hotfix part identified - set it to 0
        hotfix = 0

    return (major, feature, minor, hotfix)


def is_version_newer(left_image_version: str, right_image_version: str) -> bool:
    """is_version_newer Determine if the right PAN-OS version is newer than the left.

    Args:
        left_image_version (str): PAN-OS software version
        right_image_version (str): PAN-OS software version

    Returns:
        bool: True if right version newer than left, else False
    """
    left_version_parts = parse_version(left_image_version)
    right_version_parts = parse_version(right_image_version)

    for left_part, right_part in zip(left_version_parts, right_version_parts):
        if left_part < right_part:
            return True
        elif left_part > right_part:
            return False

    return False  # Versions are the same


def filter_images(command_result: dict) -> dict:
    """filter_images Filter the command results from `pano-os-platform-get-available-software` to include only
    the currently installed release, it's required base version, and versions that are newer than currently installed.

    Args:
        command_result (dict): command results from `pano-os-platform-get-available-software`

    Returns:
        dict: Command result object with older version entries removed
    """
    # Filter the command results to only include details of images newer than is currently installed on the device
    current_version, base_version = get_current_version_and_base_version(command_result[0]["Contents"]["Summary"])

    # Initialize list of newer images, and include current and base versions for comparison
    newer_images = [current_version, base_version]

    # Store initial command result to be updated with filtered results
    filtered_command_result = command_result

    for version in command_result[0]["Contents"]["Summary"]:
        if is_version_newer(current_version.get("version", ""), version.get("version")):
            newer_images.append(version)

    # Replace versions in command result with filtered list
    filtered_command_result[0]["Contents"]["Summary"] = newer_images

    # Replace versions in entry context with filtered list
    filtered_command_result[0]["EntryContext"]["PANOS.SoftwareVersions"]["Summary"] = newer_images

    return filtered_command_result


def get_available_software(args: dict[str, Any]) -> dict:
    """get_available_software Retrieves available PAN-OS software images and filters the output if specified.

    Args:
        args (Dict[str, Any]): Script arguments

    Returns:
        dict: Command result object
    """
    # Store newer_images_only argument value and remove from args to pass to the command
    newer_images_only = args.pop("newer_images_only", "no")

    # Run PAN-OS command and get results
    command_result = run_command(args)

    if newer_images_only == "yes":
        filtered_command_result = filter_images(command_result)
        return filtered_command_result
    else:
        return command_result


def main():
    args = demisto.args()

    try:
        return_results(get_available_software(args))
    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
