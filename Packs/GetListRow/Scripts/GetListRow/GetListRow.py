import demistomock as demisto
from CommonServerPython import *


def validate_args(parse_all, header, value):
    if parse_all.lower() != 'true' and (not header or not value):
        return_error("No parse all, and no header and value to know what to parse")


def does_list_exists(list_result):
    if not list_result or "Item not found" in list_result:
        return_error("No list found")


def does_header_exists(list_result, header):
    list_lines = list_result.split('\n')
    headers = list_lines[0].split(',')
    if header not in headers:
        return_error("This header is not in headers list")


def parse_all_rows(list_result, context_result):
    list_lines = list_result.split('\n')
    headers = list_lines[0].split(',')
    all_result = []
    for line in list_lines[1:]:
        current_line = line.split(',')
        dict_result = {}
        for item in range(len(current_line)):
            dict_result[headers[item]] = current_line[item]
        all_result.append(dict_result)
    context_result["results"] = all_result
    markdown = tableToMarkdown('List Result', all_result, headers=headers)
    return CommandResults(
        outputs_prefix='getListRow.Result(val.header == obj.header && val.value == obj.value && val.list_name == obj.list_name)',
        outputs=context_result,
        readable_output=markdown
    )


def parse_rows(list_result, header, value, context_result):
    list_lines = list_result.split('\n')
    headers = list_lines[0].split(',')
    header_location = headers.index(header)
    all_result = []
    for line in list_lines[1:]:
        current_line = line.split(',')
        if current_line[header_location] == value:
            dict_result = {}
            for item in range(len(current_line)):
                dict_result[headers[item]] = current_line[item]
            all_result.append(dict_result)
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
    does_list_exists(list_result)
    if parse_all.lower() == "true":
        command_results = parse_all_rows(list_result, context_result)
    else:
        does_header_exists(list_result, header)
        command_results = parse_rows(list_result, header, value, context_result)
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
