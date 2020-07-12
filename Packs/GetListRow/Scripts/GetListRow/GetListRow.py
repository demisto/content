import demistomock as demisto
from CommonServerPython import *


def validate_args(parse_all, header, value):
    if parse_all.lower() != 'true' and (not header or not value):
        return_error("Error: If parse_all is false, both header and value must be specified.")


def validate_list_exists(list_result):
    if not list_result or "Item not found" in list_result:
        return_error("Error: The supplied list name not found.")


def validate_header_exists(headers, header):
    if header not in headers:
        return_error("Error: The supplied header name not found.")


def list_to_headers_and_lines(list_result):
    lines_without_headers = [line.split(',') for line in list_result.split('\n')]
    headers = lines_without_headers[0]
    return lines_without_headers[1:], headers


def list_to_context_format(list_lines, headers):
    result = []
    for line in list_lines:
        dict_result = {headers[item]: line[item] for item in range(len(line))}
        result.append(dict_result)
    return result


def parse_relevant_rows(headers, lines, header, value, context, parse_all=False):
    if parse_all:
        result = list_to_context_format(lines, headers)
    else:
        header_location = headers.index(header)
        specific_lines_to_parse = [line for line in lines if line[header_location] == value]
        result = list_to_context_format(specific_lines_to_parse, headers)
    if not result:
        return CommandResults(
            readable_output="No results found"
        )
    context["results"] = result
    markdown = tableToMarkdown('List Result', result, headers=headers)
    return CommandResults(
        outputs_prefix='''getListRow.Result(val.header && val.header == obj.header
                          && val.value == obj.value && val.list_name == obj.list_name)''',
        outputs=context,
        readable_output=markdown
    )


def parse_list(parse_all, header, value, list_name):
    validate_args(parse_all, header, value)
    list_result = demisto.executeCommand("getList", {'listName': list_name})[0]['Contents']
    context = {
        "list_name": list_name,
        "header": header,
        "value": value,
    }
    validate_list_exists(list_result)
    lines, headers = list_to_headers_and_lines(list_result)
    if parse_all.lower() == "true":
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
