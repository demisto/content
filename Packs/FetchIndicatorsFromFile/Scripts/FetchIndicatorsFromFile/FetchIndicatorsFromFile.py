import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
import xlrd


def xls_file_to_indicator_list(file_path, sheet_name, col_num, starting_row):
    indicator_list = []

    xl_woorkbook = xlrd.open_workbook(file_path)
    if sheet_name and sheet_name != 'None':
        xl_sheet = xl_woorkbook.sheet_by_name(sheet_name)

    else:
        xl_sheet = xl_woorkbook.sheet_by_index(0)

    for row_index in range(0, xl_sheet.nrows):
        if row_index >= starting_row:
            indicator = xl_sheet.cell(row_index, col_num)
            indicator_list.append(indicator.value)

    return indicator_list


def xls_file_to_parsed_indicators(file_path, sheet_name, indicator_col, type_col, starting_row):
    indicator_list = []

    xl_woorkbook = xlrd.open_workbook(file_path)
    if sheet_name and sheet_name != 'None':
        xl_sheet = xl_woorkbook.sheet_by_name(sheet_name)

    else:
        xl_sheet = xl_woorkbook.sheet_by_index(0)

    for row_index in range(0, xl_sheet.nrows):
        if row_index >= starting_row:
            indicator = xl_sheet.cell(row_index, indicator_col).value
            indicator_type = xl_sheet.cell(row_index, type_col).value

            indicator_list.append({
                'Value': indicator,
                'Type': indicator_type
            })

    return indicator_list


def txt_file_to_indicator_list(file_path):
    with open(file_path, "r") as fp:
        file_data = fp.read()

    indicator_list = re.split('\n|,|, ', file_data)
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

    else:
        return FeedIndicatorType.Domain


def fetch_indicators_from_file(args):
    file = demisto.getFilePath(args.get('entry_id'))
    file_path = file['path']
    file_name = file['name']
    auto_detect = True if args.get('auto_detect') == 'True' else False
    default_type = args.get('default_type')
    limit = args.get("limit")
    offset = int(str(args.get("offset"))) if args.get('offset') else 0
    skip_parsing = False
    sheet_name = args.get('sheet_name')
    indicator_col_num = args.get('indicator_column_number')
    type_col_num = args.get('indicator_type_column_number')
    starting_row = args.get('starting_row')

    if file_name.endswith('xls') or file_name.endswith('csv') or file_name.endswith('xlsx'):

        if not type_col_num:
            indicator_list = xls_file_to_indicator_list(file_path, sheet_name,
                                                        int(indicator_col_num) - 1, int(starting_row) - 1)

        else:
            indicator_list = xls_file_to_parsed_indicators(file_path, sheet_name,
                                                           int(indicator_col_num) - 1, int(type_col_num) - 1,
                                                           int(starting_row) - 1)
            skip_parsing = True

    else:
        indicator_list = txt_file_to_indicator_list(file_path)

    if not skip_parsing:

        parsed_indicators = []
        for indicator in indicator_list:
            if auto_detect:
                indicator_type = detect_type(indicator)

            else:
                indicator_type = default_type

            parsed_indicators.append({
                "Type": indicator_type,
                "Value": indicator
            })

    else:
        parsed_indicators = indicator_list

    if limit:
        limit = int(str(limit))
        parsed_indicators = parsed_indicators[offset: limit + offset]

    human_readable = tableToMarkdown("Indicators from {}:".format(file_path), parsed_indicators,
                                     headers=['Value', 'Type'], removeNull=True)

    if limit:
        human_readable = human_readable + "\nTo bring the next batch of indicators run:\n!FetchIndicatorsFromFile " \
            "limit={} offset={} entry_id={}".format(limit, int(limit) + int(offset), args.get('entry_id'))

        if sheet_name:
            human_readable = human_readable + " sheet_name={}".format(sheet_name)

        if int(indicator_col_num) != 1:
            human_readable = human_readable + " indicator_column_number={}".format(indicator_col_num)

        if type_col_num:
            human_readable = human_readable + " indicator_type_column_number={}".format(type_col_num)

    return human_readable, {
        "Indicator(val.Value == obj.Value && val.Type == obj.Type)": parsed_indicators
    }, indicator_list


def main():
    try:
        return_outputs(*fetch_indicators_from_file(demisto.args()))
    except Exception as ex:
        return_error('Failed to execute Fetch Indicators From File. Error: {}'.format(str(ex)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
