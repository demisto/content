from CommonServerPython import *

from typing import Dict, Any
import traceback
from collections import defaultdict

""" STANDALONE FUNCTION """


def parse_fields(events, full, max_fields, max_value_length) -> str:
    """Parses events from the raw trigger events field
    and returns a section of the events in key/value tables
    in the input (events).
    """

    if not events:
        return "No trigger events found"

    headers = ["Key", "Value", "Order"]

    product_indexes: defaultdict = defaultdict(int)
    output = ""
    for event in events:
        trigger = "(*)" if event["ata_trigger"] else ""
        product = event["product"]
        index = product_indexes[product]
        datetime_created = event["datetime_created"]
        table_name = f"## {trigger} {product} {index} ({datetime_created})\n"

        fields = []
        for index, field in enumerate(event["fields"]):
            if not full and index >= max_fields:
                break

            label = field["label"]
            key = field["key"]
            value = field["value"]
            if not full and len(str(value)) > max_value_length:
                value = str(value)[:max_value_length] + "..."

            fields.append(
                {
                    "Key": f"{label} ({key})",
                    "Value": value,
                    "Order": field["order"],
                }
            )
        output += tableToMarkdown(table_name, fields, headers=headers)

        product_indexes[product] += 1

    return output


""" COMMAND FUNCTION """


def parse_fields_command(args: Dict[str, Any]) -> CommandResults:

    incident = demisto.incident()
    custom_fields = incident.get("CustomFields")
    events = custom_fields.get("ztaptriggers")

    max_fields = args.get("max_fields", 50)
    max_value_length = args.get("max_value_length", 512)
    full = args.get("full", False)

    # Call the standalone function and get the raw response
    result = parse_fields(events, full, max_fields, max_value_length)

    return CommandResults(
        outputs_prefix="ZTAPParseFields",
        outputs_key_field="",
        outputs=[result],
        readable_output=result,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(parse_fields_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
