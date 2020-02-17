import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
import xlrd
import csv


def csv_file_to_indicator_list(file_path, col_num, starting_row, auto_detect, default_type, type_col):
    indicator_list = []
    line_index = 0
    with open(file_path) as csv_file:
        file_reader = csv.reader(csv_file)
        for row in file_reader:
            if line_index >= starting_row:
                indicator = row[col_num]

                indicator_type = detect_type(indicator)

                if indicator_type is None:
                    continue

                if type_col:
                    indicator_type = row[int(type_col) - 1]

                elif not auto_detect:
                    indicator_type = default_type

                indicator_list.append({
                    "type": indicator_type,
                    "value": indicator
                })

            line_index = line_index + 1

    return indicator_list


def xls_file_to_indicator_list(file_path, sheet_name, col_num, starting_row, auto_detect, default_type, type_col):
    indicator_list = []

    xl_woorkbook = xlrd.open_workbook(file_path)
    if sheet_name and sheet_name != 'None':
        xl_sheet = xl_woorkbook.sheet_by_name(sheet_name)

    else:
        xl_sheet = xl_woorkbook.sheet_by_index(0)

    for row_index in range(0, xl_sheet.nrows):
        if row_index >= starting_row:
            indicator = xl_sheet.cell(row_index, col_num).value

            indicator_type = detect_type(indicator)

            if indicator_type is None:
                continue

            if not auto_detect:
                indicator_type = default_type

            if type_col:
                indicator_type = xl_sheet.cell(row_index, int(type_col) - 1).value

            indicator_list.append({
                'type': indicator_type,
                'value': indicator
            })

    return indicator_list


def txt_file_to_indicator_list(file_path, auto_detect, default_type):
    with open(file_path, "r") as fp:
        file_data = fp.read()

    indicator_list = []

    only_indicator_list = file_data.split()

    for indicator in only_indicator_list:
        # drop punctuation
        if len(indicator) > 0:
            if indicator[-1] in ".,?:;\\)}]/!\n\t":
                indicator = indicator[:-1]

            if indicator[0] in ".,({[":
                indicator = indicator[0:]

            indicator_type = detect_type(indicator)

            # indicator not recognized
            if indicator_type is None:
                continue

            if not auto_detect:
                indicator_type = default_type

            indicator_list.append({
                'type': indicator_type,
                'value': indicator
            })

    return indicator_list


def detect_type(indicator):
    """Infer the type of the indicator.
    Args:
        indicator(str): The indicator whose type we want to check.
    Returns:
        str. The type of the indicator.
    """
    if re.match(ipv4cidrRegex, indicator):
        return FeedIndicatorType.CIDR

    if re.match(ipv6cidrRegex, indicator):
        return FeedIndicatorType.IPv6CIDR

    if re.match(ipv4Regex, indicator):
        return FeedIndicatorType.IP

    if re.match(ipv6Regex, indicator):
        return FeedIndicatorType.IPv6

    if re.match(sha256Regex, indicator):
        return FeedIndicatorType.SHA256

    if re.match(urlRegex, indicator):
        return FeedIndicatorType.URL

    if re.match(md5Regex, indicator):
        return FeedIndicatorType.MD5

    if re.match(sha1Regex, indicator):
        return FeedIndicatorType.SHA1

    if re.match(emailRegex, indicator):
        return FeedIndicatorType.Account

    if "." in indicator:
        return FeedIndicatorType.Domain

    else:
        return None


def fetch_indicators_from_file(args):
    file = demisto.getFilePath(args.get('entry_id'))
    file_path = file['path']
    file_name = file['name']
    auto_detect = True if args.get('auto_detect') == 'True' else False
    default_type = args.get('default_type')
    limit = args.get("limit")

    # offset - refers to the indicator list itself -
    # lets say you have a list of 500 and you put a limit of 100 on your output -
    # you can get the next 100 by putting an offset of 100.
    offset = int(str(args.get("offset"))) if args.get('offset') else 0

    # the below params are for Excel type files only.
    sheet_name = args.get('sheet_name')
    indicator_col_num = args.get('indicator_column_number')
    indicator_type_col_num = args.get('indicator_type_column_number')

    # starting_row is for excel files -
    # from which row should I start reading the indicators, it is used to avoid table headers.
    starting_row = args.get('starting_row')

    if file_name.endswith('xls') or file_name.endswith('xlsx'):
        indicator_list = xls_file_to_indicator_list(file_path, sheet_name, int(indicator_col_num) - 1,
                                                    int(starting_row) - 1, auto_detect, default_type,
                                                    indicator_type_col_num)

    elif file_name.endswith('csv'):
        indicator_list = csv_file_to_indicator_list(file_path, int(indicator_col_num) - 1, int(starting_row) - 1,
                                                    auto_detect, default_type, indicator_type_col_num)

    else:
        indicator_list = txt_file_to_indicator_list(file_path, auto_detect, default_type)

    indicator_list_len = len(indicator_list)

    if limit:
        limit = int(str(limit))
        indicator_list = indicator_list[offset: limit + offset]

    human_readable = tableToMarkdown("Indicators from {}:".format(file_path), indicator_list,
                                     headers=['value', 'type'], removeNull=True)

    if limit and indicator_list_len > limit:
        human_readable = human_readable + "\nTo bring the next batch of indicators run:\n!FetchIndicatorsFromFile " \
            "limit={} offset={} entry_id={}".format(limit, int(limit) + int(offset), args.get('entry_id'))

        if sheet_name:
            human_readable = human_readable + " sheet_name={}".format(sheet_name)

        if int(indicator_col_num) != 1:
            human_readable = human_readable + " indicator_column_number={}".format(indicator_col_num)

        if indicator_type_col_num:
            human_readable = human_readable + " indicator_type_column_number={}".format(indicator_type_col_num)

    # Create indicators in demisto
    errors = []
    for indicator in indicator_list:
        res = demisto.executeCommand("createNewIndicator", indicator)
        if is_error(res[0]):
            errors.append("Error creating indicator - {}".format(res[0]["Contents"]))

    if errors:
        return_error(json.dumps(errors, indent=4))

    return human_readable, None, indicator_list


def main():
    try:
        return_outputs(*fetch_indicators_from_file(demisto.args()))
    except Exception as ex:
        return_error('Failed to execute Fetch Indicators From File. Error: {}'.format(str(ex)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
