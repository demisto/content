import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re


def xls_file_to_indicator_list(file_path, col_num):
    indicator_list = []

    with open(file_path, 'r') as fp:
        file_data = fp.read()
        for row in file_data:
            indicator_list.append(row[col_num])

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
    if file_name.endswith('xls') or file_name.endswith('csv') or file_name.endswith('xlsx'):
        col_num = int(str(args.get('column_number')))
        indicator_list = xls_file_to_indicator_list(file_path, col_num - 1)

    else:
        indicator_list = txt_file_to_indicator_list(file_path)

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

    if limit:
        limit = int(str(limit))
        parsed_indicators = parsed_indicators[offset: limit + offset]

    human_readable = tableToMarkdown(f"Indicators from {file_path}:", parsed_indicators,
                                     headers=['Value', 'Type'], removeNull=True)

    if limit:
        human_readable = human_readable + f"\nTo bring the next batch of indicators run:\n!FetchIndicatorsFromFile " \
            f"limit={limit} offset={int(limit) + int(offset)} entry_id={args.get('entry_id')}"

    return human_readable, {
        f"Indicator(val.Value == obj.Value && val.Type == obj.Type)": parsed_indicators
    }, indicator_list


def main():
    try:
        return_outputs(*fetch_indicators_from_file(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute Fetch Indicators From File. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
