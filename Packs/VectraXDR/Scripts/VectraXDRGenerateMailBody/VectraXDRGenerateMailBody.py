import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json


""" CONSTANTS """


SPACER = " " * 4


""" STANDALONE FUNCTION """


def generate_mail_body(body_content: dict) -> CommandResults:
    """
    Generate a mail body for Vectra MDR assessment as part of the escalation process.

    Args:
        body_content (list): A list of detection assessment responses.

    Returns:
        CommandResults: The mail body as a string.
    """
    body = "Hi,\nPlease find below the detection assessment response for Vectra MDR escalation process.\n\n"
    detection_body = ""

    for index, (key, val) in enumerate(body_content.items(), start=1):
        detection_id, detection_name = key.split("-", 1)
        index_str = f"{index:>2}"
        detection_body += f"{index_str}.Detection ID: {detection_id}\n"
        detection_body += f"{SPACER}Detection Name: {detection_name}\n"
        detection_body += f"{SPACER}- Assessment Reason: {val.get('0')}\n"
        detection_body += f"{SPACER}- Assessment Note: {val.get('1')}\n\n" if val.get("1") else "\n"

    output = body + detection_body
    return CommandResults(outputs_prefix="VectraXDRMailBody", outputs=output, readable_output=output)


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        content = args.get("body_content")
        body_content = json.loads(content)
        result = generate_mail_body(body_content)
        return_results(result)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute VectraXDRGenerateMailBody. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
