import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def format_value(value):
    if isinstance(value, dict):
        # If the value is a dictionary, recursively format its contents
        formatted_value = ""
        for key, val in value.items():
            if key != "URL":
                formatted_value += f"<li>{format_value(val)}</li>"
    elif isinstance(value, list):
        # If the value is a list (array), recursively format its elements
        formatted_value = ""
        for item in value:
            formatted_value += f"{format_value(item)}"
    else:
        # If the value is not a dictionary or list, return it as is
        formatted_value = str(value)
    return formatted_value


def generate_html_for_context_keys(context_keys):
    html_content = ""

    # Create the table header once
    table_header = """
    <tr>
        <th style="background-color: #cce5ff; width: 200px">Vendor</th>
        <th style="background-color: #cce5ff; width: 250px">Category</th>
    </tr>
    """

    for context_key in context_keys:
        # Get the value from the Demisto incident context
        context_data = demisto.get(demisto.context(), context_key)
        if context_data is not None:

            # Format the value, including nested dictionaries
            formatted_value = format_value(context_data)

            if context_key == "VirusTotal.URL.attributes.categories":
                context_key = "VirusTotal"
            if context_key == "Panorama.URLFilter":
                context_key = "PANW URL Filtering"

            # Define an HTML template with a table and added color
            # Add the context key and formatted value to the HTML template
            table_row = f"""
            <tr>
                <td style="font-weight: bold;">{context_key}</td>
                <td style="padding-left: 30px">{formatted_value}</td>
            </tr>
            """

            html_content += table_row

    # Wrap the table rows with a table and the shared table header
    full_html_content = f"""<table class="center" style="background-color: #e6f7ff; padding: 5px; border-radius: 2px; width: 100%;">
                {table_header}
                {html_content}
            </table>"""  # noqa: E501
    return full_html_content


def main():
    try:
        # Replace 'SomeContextKey1', 'SomeContextKey2', etc. with the actual context keys you want to use
        context_keys = ['Panorama.URLFilter', 'VirusTotal.URL.attributes.categories']

        # Generate the HTML content for multiple context keys
        html_content = generate_html_for_context_keys(context_keys)

        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html_content,
        })

    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
