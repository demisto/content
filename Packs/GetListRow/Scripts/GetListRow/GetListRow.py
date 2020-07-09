import demistomock as demisto
from CommonServerPython import *


def validate_args(parse_all, header, value):
    if parse_all.lower() != 'true' and (not header or not value):
        return_error("No parse all, and no header and value to know what to parse")


def validate_list_exists(list_result):
    if not list_result or "Item not found" in list_result:
        return_error("Error: The supplied list name not found.")


def validate_header_exists(headers, header):
    if header not in headers:
        return_error("Error: The supplied header name not found.")


def list_to_headers_and_list_lines(list_result):
    list_lines = [line.split(',') for line in list_result.split('\n')]
    headers = list_lines[0]
    return list_lines[1:], headers


def list_lines_to_parse(list_lines, headers):
    all_result = []
    for line in list_lines:
        dict_result = {headers[item]: line[item] for item in range(len(line))}
        all_result.append(dict_result)
    return all_result


def parse_relevant_rows(headers, list_lines, header, value, context_result, parse_all=False):
    if parse_all:
        all_result = list_lines_to_parse(list_lines, headers)
    else:
        header_location = headers.index(header)
        specific_lines_to_parse = [line for line in list_lines if line[header_location] == value]
        all_result = list_lines_to_parse(specific_lines_to_parse, headers)
    if all_result:
        context_result["results"] = all_result
        markdown = tableToMarkdown('List Result', all_result, headers=headers)
        return CommandResults(
            outputs_prefix='''getListRow.Result(val.header && val.header == obj.header
                              && val.value == obj.value && val.list_name == obj.list_name)''',
            outputs=context_result,
            readable_output=markdown
        )
    return CommandResults(
        readable_output="No results found"
    )


def parse_list(parse_all, header, value, list_name):
    validate_args(parse_all, header, value)
    list_result = demisto.executeCommand("getList", {'listName': list_name})[0]['Contents']
    context_result = {
        "list_name": list_name,
        "header": header,
        "value": value,
    }
    validate_list_exists(list_result)
    list_lines, headers = list_to_headers_and_list_lines(list_result)
    if parse_all.lower() == "true":
        command_results = parse_relevant_rows(headers, list_lines, header, value, context_result, parse_all=True)
    else:
        validate_header_exists(headers, header)
        command_results = parse_relevant_rows(headers, list_lines, header, value, context_result)
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
