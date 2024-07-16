import demistomock as demisto
from CommonServerPython import *


def validate_args(parse_all, header, value):
    if parse_all.lower() != 'true' and (not header or not value):
        return_error("Error: If parse_all is false, both header and value must be specified.")


def validate_list_exists(list_data):
    if not list_data or "Item not found" in list_data:
        return_error("Error: The supplied list name was not found.")


def validate_header_exists(headers, header):
    if header not in headers:
        return_error("Error: The supplied header name was not found.")


def list_to_headers_and_lines(list_data: str, list_separator: str):
    list_data = list_data.strip()
    lines_and_headers = [(line.replace("\r", "") if line.endswith("\r") else line).split(list_separator)
                         for line in list_data.split('\n')]
    headers = lines_and_headers[0]
    return headers, lines_and_headers[1:]


def lines_to_context_format(list_lines, headers):
    lines_context = []
    for line in list_lines:
        line_context = {headers[item]: line[item] for item in range(len(line))}
        lines_context.append(line_context)
    return lines_context


def parse_relevant_rows(headers, lines, header, value, context, parse_all=False):
    outputs_key_field = ['list_name', 'parse_all']
    if parse_all:
        lines_context = lines_to_context_format(lines, headers)
    else:
        header_location = headers.index(header)
        specific_lines_to_parse = [line for line in lines if line[header_location] == value]
        lines_context = lines_to_context_format(specific_lines_to_parse, headers)
        outputs_key_field.extend(['header', 'value'])
    if not lines_context:
        return CommandResults(
            readable_output="No results found"
        )
    context["Results"] = lines_context
    human_readable = tableToMarkdown('List Result', lines_context, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='GetListRow',
        outputs_key_field=outputs_key_field,
        outputs=context,
        readable_output=human_readable
    )


def parse_list(parse_all, header, value, list_name, list_separator: str):
    validate_args(parse_all, header, value)
    list_data = demisto.executeCommand("getList", {'listName': list_name})[0]['Contents']
    context = {
        "ListName": list_name,
        "Header": header,
        "Value": value,
        "ParseAll": parse_all
    }
    validate_list_exists(list_data)
    headers, lines = list_to_headers_and_lines(list_data, list_separator)
    if parse_all.lower() == 'true':
        command_results = parse_relevant_rows(headers, lines, header, value, context, parse_all=True)
    else:
        validate_header_exists(headers, header)
        command_results = parse_relevant_rows(headers, lines, header, value, context)
    return command_results


def main():
    args = demisto.args()
    list_name = args['list_name']
    parse_all = args['parse_all']
    header = args.get('header', '')
    value = args.get('value', '')
    list_separator = args.get('list_separator', ',') or ','
    list_separator = list_separator.replace('\\t', '\t')

    return_results(parse_list(parse_all, header, value, list_name, list_separator))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
