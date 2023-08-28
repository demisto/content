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
    table = '| Key | Value |\n| Indicator Type | Indicator Values |\n'
    grouped_values = {}
    for key, value in items:
        if key not in grouped_values:
            grouped_values[key] = [value]
        else:
            grouped_values[key].append(value)

    for key, values in grouped_values.items():
        value_str = ', '.join(f"[{v}]" for v in values)  # Surround each value with square brackets
        table += f'| {key} | {value_str} |\n'

    return table


def convert_to_html(markdown):
    html = "<table style='border-collapse: collapse;'>"
    lines = markdown.split("\n")
    for line in lines[1:]:
        html += "<tr>"
        columns = line.split("|")
        for i, column in enumerate(columns):
            if column.strip():
                html += f"<td style='font-family: Lato, Assistant, sans-serif; font-weight: 600; \
                font-size: 12px; text-align: left; color: #404142; \
                padding: 6px 10px; border: 1px solid #D3D4D4;'>{column.strip()}</td>"
        html += "</tr>"
    html += "</table>"
    return html


def main():
    # Fetch alert mapped fields
    fields_list = demisto.context().get('CloudIndicators', [])

    # Check if fields_list is a list, if not, convert it to a list
    if not isinstance(fields_list, list):
        fields_list = [fields_list]

    # Extract the keys with values
    items = []
    for fields in fields_list:
        extracted_items = extract_keys_with_values(fields)
        items.extend(extracted_items)

    # Filter out duplicate values
    unique_items = list(set(items))

    # Format the data into a table
    table = format_data_to_table(unique_items)

    # Convert the markdown to HTML
    html = convert_to_html(table)

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
