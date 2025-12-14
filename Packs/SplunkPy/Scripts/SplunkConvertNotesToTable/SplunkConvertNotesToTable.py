import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")
    splunk_notes = demisto.get(incident, "CustomFields.splunknotes", [])
    parsed_notes = []
    for data in splunk_notes:
        parsed_data = json.loads(data)
        parsed_notes.append(parsed_data)

    # Build markdown output with improved formatting
    markdown_output = f"#### Splunk Notes ({len(parsed_notes)})\n\n"
    markdown_output += "--\n\n"

    for i, note_data in enumerate(parsed_notes, 1):
        note_content = note_data.get("Note", "")
        markdown_output += f"{note_content}\n\n"

        # Add minor separator between notes (not after the last one)
        if i < len(parsed_notes):
            markdown_output += "--\n\n"

    return CommandResults(readable_output=markdown_output)



if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        return_results(main())
    except Exception as e:
        return_error(f"Got an error while parsing Splunk events: {e}", error=e)
