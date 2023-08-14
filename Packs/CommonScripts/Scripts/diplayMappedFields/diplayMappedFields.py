import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_keys_with_values(obj, parent_key=''):
    """Extracts the keys with values in the JSON object"""
    items = []
    for k, v in obj.items():
        new_key = f'{parent_key}.{k}' if parent_key else k
        if isinstance(v, dict):
            items.extend(extract_keys_with_values(v, new_key))
        else:
            items.append((new_key, v))
    return items


def format_data_to_table(items):
    """Formats the extracted data into a table format"""
    table = '| Field Name | Value |\n'
    for key, value in items:
        table += f'| {key} | {value} |\n'
    return table


def convert_to_html(markdown):
    html = "<table style='border-collapse: collapse;'>"
    lines = markdown.split("\n")
    for line in lines[1:]:
        html += "<tr>"
        columns = line.split("|")
        for i, column in enumerate(columns):
            if column.strip():
                if i != 1:
                    html += f"<td style='font-family: Lato, Assistant, sans-serif; font-weight: 600; \
                    font-size: 12px; text-align: left; color: #404142; \
                    padding: 1px 0px 0px; margin: 0px 5px 0px 0px; contrast: 4.95;'>{column.strip()}</td>"
                else:
                    html += f"<td style='font-family: Lato, Assistant, sans-serif; font-weight: 600; \
                    font-size: 12px; text-align: left; color: #707070; \
                    padding: 1px 0px 0px; margin: 0px 5px 0px 0px; contrast: 4.95;'>{column.strip()}</td>"
        html += "</tr>"
    html += "</table>"
    return html


def remove_empty_rows(table):
    # Split the table into rows
    rows = table.split("\n")

    # Filter out the rows that contain empty dictionaries
    filtered_rows = [row for row in rows if not (
        "{}" in row or "[{}]" in row or "[{}, {}]" in row or "[{}, {}, {}]" in row or "0001-01-01T00:00:00Z" in row or " \
        containmentsla" in row or "remediationsla" in row or "detectionsla" in row or "triagesla" in row)]

    # Join the filtered rows back into a table
    filtered_table = "\n".join(filtered_rows)

    return filtered_table


def main():
    # Fetch alert mapped fields
    incident = demisto.incident()
    fields = incident.get('CustomFields', {})

    # Extract the keys with values
    items = extract_keys_with_values(fields)
    # Format the data into a table
    table = format_data_to_table(items)
    # Remove keys with empty dictionaries
    filtered_markdown = remove_empty_rows(table)
    # Convert the markdown to HTML
    html = convert_to_html(filtered_markdown)

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
