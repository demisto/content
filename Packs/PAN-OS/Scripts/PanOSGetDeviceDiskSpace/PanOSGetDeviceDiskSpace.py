import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback


def show_disk_space_command(args: dict) -> dict:
    """show_disk_space_command Runs the `pan-os` command using the specified Integration Instance

    Args:
        args (dict): Script arguments

    Raises:
        Exception: Raises an exception if the `pan-os` command returned an error entry.

    Returns:
        dict: The output command results object from `pan-os`
    """
    # Set command args
    allowed_args = ["target", "panos_instance_name"]
    command_args = {k: args.get(k) for k in allowed_args if k in args}
    command_args["cmd"] = "<show><system><disk-space></disk-space></system></show>"
    command_args["type"] = "op"

    # Rename 'instance_name' key to 'using' to match the command syntax, if required
    if "panos_instance_name" in command_args:
        command_args["using"] = command_args.pop("panos_instance_name")

    # Execute the command
    res = demisto.executeCommand("pan-os", command_args)

    # Check if the command returned an error and raise exception if needed
    if is_error(res):
        raise Exception(f"Error executing pan-os: {get_error(res)}")

    # Return command results
    return res


def convert_space_units(original_value: str, desired_units: str) -> float:
    """convert_space_units Converts disk space units from `show system disk-space` into the desired unit.

    Disk space values from the `show system disk-space` command end in a single letter denoting the unit:
        T: Terabyte
        M: Megabyte
        G: Gigabyte
        K: Kilobyte

    Args:
        original_value (str): Disk space string including unit letter (e.g. "42G")
        desired_units (str): The unit to convert the original disk space value to (e.g. "M")

    Raises:
        ValueError: Unsupported original unit (not one of ['T', 'G', 'M', 'K'])
        ValueError: Unsupported desired unit (not one of ['T', 'G', 'M', 'K'])

    Returns:
        float: The converted disk space, rounded to one decimal
    """
    # Extract the numerical value and the unit from the input string, as long as it's not 0
    if original_value != "0":
        value = float(original_value[:-1])
        original_unit = original_value[-1]
    else:
        # Input value was 0 so no conversion is needed - return as a number
        return 0

    # Conversion dictionary with all units converted to kilobytes
    conversion_to_kilobytes = {"K": 1, "M": 1024, "G": 1024 * 1024, "T": 1024 * 1024 * 1024}

    # Convert original value to kilobytes first
    if original_unit in conversion_to_kilobytes:
        value_in_kilobytes = value * conversion_to_kilobytes[original_unit]
    else:
        raise ValueError("Unsupported original unit")

    # Conversion dictionary from kilobytes to desired unit
    conversion_from_kilobytes = {"K": 1, "M": 1 / 1024, "G": 1 / (1024 * 1024), "T": 1 / (1024 * 1024 * 1024)}

    # Convert from kilobytes to the desired unit
    if desired_units in conversion_from_kilobytes:
        converted_value = round(value_in_kilobytes * conversion_from_kilobytes[desired_units], 1)
    else:
        raise ValueError("Unsupported desired unit")

    return converted_value


def parse_disk_space_output(disk_space_string: str, desired_units: str) -> list[dict]:
    """parse_disk_space_output Parses string output from `show system disk-space` with all disk space values converted
    to the desired unit and returns it as a dictionary.

    Args:
        disk_space_string (str): The output string from the `show system disk-space` command.
        desired_units (str): The unit to represent disk space values (One of ['T', 'G', 'M', 'K'])

    Returns:
        list[dict]: _description_
    """
    # Split the disk space string into lines
    lines = disk_space_string.split("\n")

    # Initialize list of file system entries
    filesystems = []

    # Iterate over each line except the first one (which contains header information)
    for line in lines[1:]:
        # Split the line into components based on whitespace
        parts = line.split()

        # Ensure the line is not empty and has all necessary parts to form a dictionary
        if len(parts) >= 6:
            # Build a dictionary for the current filesystem
            filesystem_info = {
                "FileSystem": parts[0],
                "Size": convert_space_units(parts[1], desired_units),
                "Used": convert_space_units(parts[2], desired_units),
                "Avail": convert_space_units(parts[3], desired_units),
                "Use%": parts[4],
                "MountedOn": " ".join(parts[5:]),  # Joining in case the mount point has spaces
                "Units": desired_units,
            }

            # Append the dictionary to our list
            filesystems.append(filesystem_info)

    # Return the list of dictionaries
    return filesystems


def get_disk_space(args: dict) -> CommandResults:
    """get_disk_space Runs the `show system disk-space` operational command and formats its output as a list of
    dictionaries.

    Args:
        args (dict): Script arguments.

    Returns:
        CommandResults: CommandResults object containing entries for each file system on the device.
    """
    # Run PAN-OS command and get results
    command_result = show_disk_space_command(args)

    # Get the raw string returned by the PAN-OS command
    disk_space_string = command_result[0]["Contents"]["response"]["result"]

    # Parse the raw string into a list of dictionaries with disk space represented in the desired unit
    parsed_disk_space = parse_disk_space_output(disk_space_string, args.get("disk_space_units", ""))

    # Construct the output representing the disk space on the given device
    device_entry = {"hostid": args.get("target"), "FileSystems": parsed_disk_space}

    # Create markdown table to display in war room
    readable_result = tableToMarkdown(name="System Disk Space", t=parsed_disk_space)

    # Construct CommandResults object
    results = CommandResults(
        outputs_prefix="PANOS.DiskSpace", outputs=device_entry, outputs_key_field="hostid", readable_output=readable_result
    )

    return results


def main():
    args = demisto.args()

    try:
        return_results(get_disk_space(args))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute PAN-OS-GetDeviceDiskSpace. Error: {str(ex)}\n"
            f"Traceback: {fix_traceback_line_numbers(traceback.format_exc())}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
