import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    tags = args.get("tags", [])
    field = args.get("field")
    if not field:
        return_error("Argument 'field' not given.")

    try:
        md = demisto.incidents()[0].get("CustomFields")[field]
    except Exception as e:
        return_error(f"Error getting comment content. field={field}, error={e}")
    if not md:
        return_error(f"Note field empty. Have you saved it? field={field}")

    # Argus wants a comment formatted in HTML
    html = demisto.executeCommand("mdToHtml", {"text": md})
    if not html:
        return_error("Invalid input, unable to convert MD to HTML")

    html = html[0].get("Contents", "")

    #  create tagged war room entry
    entry = {
        "Type": entryTypes["note"],
        "Contents": html,
        "ContentsFormat": formats["html"],
        "HumanReadable": html,
        "ReadableContentsFormat": formats["html"],
        "Tags": tags,
        "Note": True,
    }

    # wipe editing field
    demisto.executeCommand("setIncident", {field: ""})

    return_results(entry)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
