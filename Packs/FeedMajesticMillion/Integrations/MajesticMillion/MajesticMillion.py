from CommonServerPython import *


def main():
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
    params['value_field'] = 'Domain'
    params['url'] = 'http://downloads.majestic.com/majestic_million.csv'
    params['ignore_regex'] = r'^GlobalRank'  # ignore the first line
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main(feed_name='Majestic Million Feed', params=params, prefix='majesticmillion')


from CSVFeedApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins'):
    main()
