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


def list_to_headers_and_lines(list_data):
    lines_and_headers = [line.split(',') for line in list_data.split('\n')]
    headers = lines_and_headers[0]
    return headers, lines_and_headers[1:]


def lines_to_context_format(list_lines, headers):
    lines_context = []
    for line in list_lines:
        line_context = {headers[item]: line[item] for item in range(len(line))}
        lines_context.append(line_context)
    return lines_context


def parse_relevant_rows(headers, lines, header, value, context, parse_all=False):
    if parse_all:
        lines_context = lines_to_context_format(lines, headers)
        output_condition = "getListRow.Result(val.list_name == obj.list_name && val.parse_all == obj.parse_all)"
    else:
        header_location = headers.index(header)
        specific_lines_to_parse = [line for line in lines if line[header_location] == value]
        lines_context = lines_to_context_format(specific_lines_to_parse, headers)
        output_condition = '''GetListRow(val.header && val.list_name == obj.list_name &&
                           val.header == obj.header && val.value == obj.value && val.parse_all == obj.parse_all)'''
    if not lines_context:
        return CommandResults(
            readable_output="No results found"
        )
    context["Results"] = lines_context
    human_readable = tableToMarkdown('List Result', lines_context, headers=headers)
    return CommandResults(
        outputs_prefix=output_condition,
        outputs=context,
        readable_output=human_readable
    )


def parse_list(parse_all, header, value, list_name):
    validate_args(parse_all, header, value)
    list_data = demisto.executeCommand("getList", {'listName': list_name})[0]['Contents']
    context = {
        "ListName": list_name,
        "Header": header,
        "Value": value,
        "ParseAll": parse_all
    }
    validate_list_exists(list_data)
    headers, lines = list_to_headers_and_lines(list_data)
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

    return_results(parse_list(parse_all, header, value, list_name))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
