from CommonServerPython import *

from typing import Dict, Any
import traceback
from collections import defaultdict

""" STANDALONE FUNCTION """


def parse_links(events) -> str:
    """Parses external links the raw trigger events field
    and returns a section containing those links.
    """

    if not events:
        return "No external links found"

    headers = ["Link"]

    product_indexes: defaultdict = defaultdict(int)
    output = ""
    for event in events:
        trigger = "(*) " if event["ata_trigger"] else ""
        product = event["product"]
        index = product_indexes[product]
        table_name = f"{trigger}{product} {index}"

        links = []
        for link in event["links"]:
            if link["type"] == "external":
                tooltip = link["tooltip"]
                url = link["url"]
                markdown_link = f"[{tooltip}]({url})"
                links.append(
                    {
                        "Link": markdown_link,
                    }
                )
        output += tableToMarkdown(table_name, links, headers=headers)

        product_indexes[product] += 1

    return output


""" COMMAND FUNCTION """


def parse_links_command(args: Dict[str, Any]) -> CommandResults:

    incident = demisto.incident()
    custom_fields = incident.get("CustomFields")
    events = custom_fields.get("ztaptriggers")

    # Call the standalone function and get the raw response
    result = parse_links(events)

    return CommandResults(
        outputs_prefix="ZTAPParseLinks",
        outputs_key_field="",
        outputs=[result],
        readable_output=result,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(parse_links_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
