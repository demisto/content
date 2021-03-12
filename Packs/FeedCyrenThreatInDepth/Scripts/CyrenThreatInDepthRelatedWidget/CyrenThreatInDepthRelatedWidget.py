import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def cyren_feed_relationship(args) -> CommandResults:
    indicator = args.get("indicator")
    if not indicator:
        raise ValueError("Please provide 'indicator' argument!")

    result = demisto.executeCommand("CyrenThreatInDepthRenderRelated", dict(indicator=json.dumps(indicator)))
    if is_error(result[0]):
        raise ValueError(f"Failed to render related: {str(get_error(result))}")

    readable = result[0]["HumanReadable"]
    return CommandResults(readable_output=readable)


def main(args):
    try:
        return_results(cyren_feed_relationship(args))
    except Exception as e:
        return_error(f"Failed to execute CyrenThreatInDepthRelatedWidget. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main(demisto.args())
