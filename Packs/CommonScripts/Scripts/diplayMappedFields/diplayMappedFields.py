import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# List of empty values that we want to filter out.
EMPTY_VALUES = ["{}", "[{}]", "[{}, {}]", "[{}, {}, {}]", "0001-01-01T00:00:00Z", "containmentsla", "remediationsla",
                "detectionsla", "triagesla"]


def extract_keys_with_values(obj, parent_key=''):
    """
    Extracts the keys with values in the JSON object
    """
    items = []
    for k, v in obj.items():
        new_key = f'{parent_key}.{k}' if parent_key else k
        if isinstance(v, dict):
            items.extend(extract_keys_with_values(v, new_key))
        else:
            items.append((new_key, v))
    return items


def escape_pipe(value):
    """
    Escapes pipe characters in the value by replacing them with an HTML entity.
    """
    return value.replace('|', '&#124;')


def format_data_to_rows(items):
    """
    Formats the extracted data into rows and escapes pipes.
    """
    rows = []
    for key, value in items:
        if isinstance(value, list):
            # If the value is a list, join the items with a separator and escape the result
            value = '|'.join(map(str, value))
        rows.append(f'{escape_pipe(key)}|{escape_pipe(str(value))}')
    return rows


def convert_to_html(rows):
    html = ["""<table style="border-collapse:collapse;"><tbody style="font-family:Lato,Assistant,sans-serif;font-weight:600;font-size:12px;text-align:left;padding: 1px 0px 0px;margin:0px 5px 0px 0px;contrast:4.95">"""]  # noqa: E501
    for row in rows:
        html.append("<tr>")
        columns = row.split("|")
        for i, column in enumerate(map(str.strip, columns)):
            if column:
                style = "color:var(--xdr-on-background-secondary)" if i == 0 else "color:var(--xdr-on-background)"
                html.append(f"<td style=\"{style}\">{column}</td>")
        html.append("</tr>")
    html.append("</tbody></table>")
    return "".join(html)


def remove_empty_rows(rows):
    # Filter out the rows that contain empty dictionaries
    return [row for row in rows if not any(empty_value in row for empty_value in EMPTY_VALUES)]


def main():
    # Fetch alert mapped fields
    incident = demisto.incident()
    fields = incident.get('CustomFields', {})
    fields = fields if isinstance(fields, dict) else {}

    # Extract the keys with values
    items = extract_keys_with_values(fields)
    # Format the data into a rows
    rows = format_data_to_rows(items)
    # Remove keys with empty dictionaries
    filtered_rows = remove_empty_rows(rows)
    # Convert the rows to HTML
    html = convert_to_html(filtered_rows)

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
