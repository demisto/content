import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def context_setup(keys: list[str], vals: dict) -> list[dict[str, str]]:
    """Prepares key/value mapping to prepare input into XSOAR context
    :type keys: list[str]
    :type vals: ``dict``
    :param keys: comma separated values used for keys (columns)
    :param vals: dictionary of the value assigned to keys
    :return: list of dictionaries
    """
    res_list = []
    temp = {}
    for i, key in enumerate(keys, start=1):
        if vals[f"val{i}"] == "TIMESTAMP":
            temp[key] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            temp[key] = vals[f"val{i}"]
    res_list.append(temp)

    return res_list


""" COMMAND FUNCTION """


def context_setup_command(args: dict[str, str]) -> CommandResults:
    """
    Main command that takes key/value pairs and formats them in a way that allows input into XSOAR context.

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        CommandResults: human readable message of results of !Set command.
    """
    keys = argToList(args.get("keys", []))
    overwrite = argToBoolean(args.get("overwrite", False))

    context_key = args.get("context_key", None)

    # dictionary or all vals
    vals = {k: v for k, v in args.items() if k.startswith("val")}

    # error is keys and value numbers don't align
    if len(keys) != len(vals):
        raise ValueError("number of keys and values needs to be the same")

    # Call the standalone function and get the raw response
    result = context_setup(keys, vals)
    if overwrite:
        results = demisto.executeCommand("Set", {"key": context_key, "value": result})
    else:
        results = demisto.executeCommand("Set", {"key": context_key, "value": result, "append": "true"})
    return results


""" MAIN FUNCTION """


def main():
    try:
        return_results(context_setup_command(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute ContextSetup. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
