import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_json_to_markdown_table(json_data, sort_by_value=True, descending=True):
    # Check if the input is valid JSON
    if not isinstance(json_data, dict):
        raise ValueError("Input data is not a valid JSON object")

    markdown = "| ***Policy Action*** | ***Opration Executed*** |\n"
    markdown += "| --- | ----- |\n"

    sorted_items = sorted(json_data.items(), key=lambda x: x[1], reverse=descending) if sort_by_value else sorted(
        json_data.items(), key=lambda x: x[0])

    # Loop through the JSON and format it into a table
    for key, value in sorted_items:
        # If value is a dictionary, we will format it as a JSON block
        if isinstance(value, dict):
            value = f"```json\n{json.dumps(value, indent=4)}\n```"
        # If it's a list, we join the list into a string for display
        elif isinstance(value, list):
            value = ', '.join(map(str, value))
        # Replace True with checkmark and False with cross emoji
        elif value is True:
            value = "✅"
        elif value is False:
            value = "❌"
        markdown += f"| {key} | {value} |\n"

    return markdown


def main():
    # Fetch the dynamic context key input from the demisto args
    context_key = 'CrowdStrike'  # Get the context key from arguments
    try:
        context_value = demisto.context().get(context_key, None).get('Detection', None)
        results = []
        for _idx, detection in enumerate(context_value):
            if isinstance(detection, dict) and 'policyactions' in detection:
                results.append(detection)

        if not results:
            return_results("### No policyactions data available.")

        results = results[0].get('policyactions', None)
        MD = convert_json_to_markdown_table(results)
        return_results({
            'Type': entryTypes['note'],
            'Contents': MD,
            'ContentsFormat': formats['markdown']
        })
    except Exception:
        return_results("No Policy Actions were found on CrowdStrike.Detection context key")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
