from CommonServerPython import *


def main():
    feed_url_to_config = {
        'http://reputation.alienvault.com/reputation.data': {
            'fieldnames': [
                'value', 'reliability', 'risk', 'threat_type', 'geocountry', 'geocity', 'geolocation', 'unknown'
            ],
            'indicator_type': FeedIndicatorType.IP,
            'mapping': {
                'geocountry': 'geocountry',
                'geolocation': 'geolocation'
            }
        }
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['url'] = 'http://reputation.alienvault.com/reputation.data'
    params['feed_url_to_config'] = feed_url_to_config
    params['delimiter'] = '#'

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('AlienVault Reputation Feed', params, 'alienvault')


from CSVFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
