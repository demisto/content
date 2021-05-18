from CommonServerPython import *

MAJESTIC_MILLION_URL = 'http://downloads.majestic.com/majestic_million.csv'


def main():
    try:
        feed_url_to_config = {
            MAJESTIC_MILLION_URL: {
                'fieldnames': ['GlobalRank', 'TldRank', 'Domain', 'TLD', 'RefSubNets', 'RefIPs', 'IDN_Domain',
                               'IDN_TLD',
                               'PrevGlobalRank', 'PrevTldRank', 'PrevRefSubNets', 'PrevRefIPs'],
                'indicator_type': FeedIndicatorType.Domain,
                'mapping': {
                    'domainname': 'Domain',
                    'domainreferringsubnets': 'RefSubNets',
                    'domainreferringips': 'RefIPs',
                    'idndomain': 'IDN_Domain',
                }
            }
        }
        params = {k: v for k, v in demisto.params().items() if v is not None}
        params['feed_url_to_config'] = feed_url_to_config
        params['value_field'] = 'Domain'
        params['url'] = MAJESTIC_MILLION_URL
        params['ignore_regex'] = r'^GlobalRank'  # ignore the first line
        params['delimiter'] = ','
        params['limit'] = int(params.get('limit', 100000))
        if params['limit'] > 1000000:
            params['limit'] = 1000000

        # Main execution of the CSV API Module.
        # This function allows to add to or override this execution.
        feed_main(feed_name='Majestic Million Feed', params=params, prefix='majesticmillion')
    except ValueError:
        return_error('Invalid parameter was given as limit to the number of Domains to fetch.')
    except Exception as err:
        return_error(f'Failed to execute Majestic Million. Error: {str(err)} \n '
                     f'tracback: {traceback.format_exc()}')


from CSVFeedApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins'):
    main()
