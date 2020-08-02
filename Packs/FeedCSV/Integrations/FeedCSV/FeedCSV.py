import demistomock as demisto
from CommonServerPython import *


def main():
    params = demisto.params()
    # when auto_detect is not selected
    if params.get('auto_detect_type') is False and not params.get('indicator_type'):
        return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
    # when auto_detect does not exist - for previous integration instances
    if params.get('auto_detect_type') is None and not params.get('indicator_type'):
        return_error('Indicator Type cannot be empty')
    feed_main('CSV', prefix='csv')


from CSVFeedApiModule import *  # noqa: E402


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
