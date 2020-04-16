from CommonServerPython import *


def main():
    feed_url_to_config = {
        'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv': {
            'fieldnames': ['firstseenbysource', 'value', 'port'],
            'indicator_type': FeedIndicatorType.IP,
            'mapping': {
                'firstseenbysource': 'firstseenbysource',
                'port': 'port'
            }
        },
        'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv': {
            'fieldnames': ['firstseenbysource', 'value', 'port'],
            'indicator_type': FeedIndicatorType.IP,
            'mapping': {
                'firstseenbysource': 'firstseenbysource',
                'port': 'port'
            }
        }
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_url_to_config'] = feed_url_to_config
    params['ignore_regex'] = r'^#'
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('SSL Blacklist Feed', params, 'sslbl')


from CSVFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
