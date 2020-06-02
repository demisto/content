import demistomock as demisto
from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    if not params.get('auto_detect_type'):
        if not params.get('indicator_type'):
            return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
    feed_main('CSV', prefix='csv')


from CSVFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
