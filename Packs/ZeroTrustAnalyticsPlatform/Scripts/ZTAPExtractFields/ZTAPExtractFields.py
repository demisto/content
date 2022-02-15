from CommonServerPython import *

from typing import Dict, Any, List
import traceback

""" STANDALONE FUNCTION """


def extract_fields(value) -> List:
    """
    Extracts ordered ZTAP fields for use in analytics
    """

    output = []
    for event in value:
        fields = {}
        for field in event["fields"]:
            key = field["key"]
            value = field["value"]
            fields[key] = value
        output.append(fields)

    return output


""" COMMAND FUNCTION """


def extract_fields_command(args: Dict[str, Any]) -> CommandResults:

    value = args.get("value", [])

    if not value:
        raise ValueError("value not specified")

    # Call the standalone function and get the raw response
    result = extract_fields(value)

    return CommandResults(
        outputs_prefix="ZTAPExtractFields",
        outputs_key_field="",
        outputs=result,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(extract_fields_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
