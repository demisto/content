from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def date_to_any_format(date, input_formatter, output_formatter):
    date_obj = datetime.strptime(date.strip(' \t\r\n'), input_formatter)
    return date_obj.strftime(output_formatter)


def main():
    args = demisto.args()
    date_value = args['value']
    input_formatter = args['input_formatter']
    output_formatter = args['output_formatter']
    demisto.results(date_to_any_format(date_value, input_formatter, output_formatter))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
