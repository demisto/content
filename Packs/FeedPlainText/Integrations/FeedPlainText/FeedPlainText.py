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
    if params.get('indicator_type') == 'Custom':
        custom_indicator_type = params.get('custom_indicator_type')
        if not custom_indicator_type:
            return_error('If custom indicator type has been chosen, an indicator type must be specified.')
        else:
            params.update({'indicator_type': custom_indicator_type})
    feed_main('PlainText', params=params, prefix='plaintext')


from HTTPFeedApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins'):
    main()
