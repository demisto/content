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
        }
    }

    if not params.get('auto_detect_type'):
        if not params.get('indicator_type'):
            return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
        params['feed_name_to_config'].get(params.get('url'))['indicator_type'] = params.get('indicator_type')

    feed_main(params, 'JSON Feed', 'json')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
