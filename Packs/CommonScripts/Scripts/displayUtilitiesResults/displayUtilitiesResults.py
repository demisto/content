import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_dict(d, keys):
    for key in keys:
        try:
            d = d[key]
        except (KeyError, TypeError):
            return None
    return d


def get_data_from_context(incident_context, objects):
    result = {}
    found = False
    for var in objects:
        data = get_dict(incident_context[0], ['Contents', 'context', var])
        if data is not None:
            result[var] = data
            found = True
    if not found:
        result = {"Button Results": "No button execution output found"}
    return result


def convert_to_kv_table(data):
    """Converts data to key-value table"""

    def dict_to_kv_string(dict_obj):
        return "<br>".join([f"{key}: {value}" for key, value in dict_obj.items()])

    items = []
    for key, value in data.items():
        if isinstance(value, dict):
            value = dict_to_kv_string(value)
        items.append((key, value))
    return items


def convert_to_kv_list(data):
    """Converts a list of tuples to a list of key-value tuples"""
    kv_list = []
    for t in data:
        if len(t) == 2:
            kv_list.append((t[0], t[1]))
    return kv_list


def format_data_to_table(items):
    """Formats the extracted data into a dynamic width HTML table format"""
    table = "<table style='width: 100%; table-layout: fixed; border-collapse: collapse;'>\n"
    for key, value in items:
        if isinstance(value, dict):
            value = format_data_to_table(convert_to_kv_list(value))
        elif isinstance(value, list):
            if all(isinstance(v, tuple) and len(v) == 2 for v in value):
                value = "<ul>" + "".join(f"<li><b>{v[0]}:</b> {v[1]}</li>" for v in value) + "</ul>"

            else:
                value = "<ul>" + "".join(f"<li>{v}</li>" for v in value) + "</ul>"
        else:
            value = str(value)
        table += "<tr style='border-bottom: 1px solid #ddd;'>\n"
        table += f"<td style='width: 30%; word-wrap: break-word; border-right: none;'><b>{key}</b></td>\n"
        table += f"<td style='word-wrap: break-word; width: 70%; border-left: 1px solid #ddd; padding-left: 10px;'>{value}</td>\n"
        table += "</tr>\n"
    table += "</table>"
    return table


def main():

    incident = demisto.incident()

    incident_context = demisto.executeCommand("getContext", {'id': incident.get("id")})

    objects = ["Base64", "digresults", "EntropyResult", "ResolveShortenedURL", "Endpoint"]

    # Get data from context
    data = get_data_from_context(incident_context, objects)

    # Convert the data to a key-value table
    items = convert_to_kv_table(data)

    fixed_items = convert_to_kv_list(items)

    # Format the data into a dynamic width HTML table
    table = format_data_to_table(fixed_items)

    return_results({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': table,
    })


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
