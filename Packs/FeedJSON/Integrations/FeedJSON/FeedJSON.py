import demistomock as demisto
from CommonServerPython import *

from JSONFeedApiModule import *  # noqa: E402


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    params['feed_name_to_config'] = {
        params.get('url'): {
            'url': params.get('url'),
            'extractor': params.get('extractor'),
            'indicator': params.get('indicator', 'indicator'),
            'rawjson_include_indicator_type': params.get('rawjson_include_indicator_type'),
            'remove_ports': params.get('remove_ports', False)
        }
    }
    auto_detect = params.get('auto_detect_type')
    indicator_type = params.get('indicator_type')
    if demisto.command() == 'test-module' and auto_detect and indicator_type:
        # only fail when doing "Test" to avoid breaking an existing feed
        return_error(f'Indicator Type (value: {indicator_type}) should not be set if "Auto detect indicator type" '
                     'is checked. Either use Auto Detect or set manually the Indicator Type.')

    if not auto_detect:
        if not indicator_type:
            return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
        params['feed_name_to_config'].get(params.get('url'))['indicator_type'] = indicator_type

    feed_main(params, 'JSON Feed', 'json')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
