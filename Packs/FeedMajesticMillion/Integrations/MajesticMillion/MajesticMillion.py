from CommonServerPython import *


def main():
    # TODO: need to think how to handle value field
    feed_url_to_config = {
        'http://downloads.majestic.com/majestic_million.csv': {
            'fieldnames': ['GlobalRank', 'TldRank', 'Domain', 'TLD', 'RefSubNets', 'RefIPs', 'IDN_Domain', 'IDN_TLD',
                           'PrevGlobalRank', 'PrevTldRank', 'PrevRefSubNets', 'PrevRefIPs'],
            'indicator_type': FeedIndicatorType.Domain,
            'mapping': {
            }
        }
    }
    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_url_to_config'] = feed_url_to_config
    # params['url'] = 'http://downloads.majestic.com/majestic_million.csv'
    params['indicator_type'] = FeedIndicatorType.Domain
    params['ignore_regex'] = r'^#'
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Majestic Million Feed', params, 'majesticmillion')


from CSVFeedApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins'):
    main()
