from CommonServerPython import *


def main():
    feed_url_to_config = {
        'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv': {
            'fieldnames': ['value', 'description',
                           'date_created',
                           'info'],
            #
            'indicator_type': FeedIndicatorType.IP
        },
        'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv': {
            'fieldnames': ['value', 'description',
                           'date_created',
                           'info'],
            # Firstseen,DstIP,DstPort
            'indicator_type': FeedIndicatorType.IP
        }
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_url_to_config'] = feed_url_to_config
    params['ignore_regex'] = r'^#'
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('SSLBL Feed', params, 'sslbl')


from CSVFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
