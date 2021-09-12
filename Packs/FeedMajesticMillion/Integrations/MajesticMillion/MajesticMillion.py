from CommonServerPython import *


def main():
    try:
        params = {k: v for k, v in demisto.params().items() if v is not None}
        use_https = argToBoolean(params.get('use_https', False)) or False
        protocol = 'https://' if use_https else 'http://'
        majestic_million_url = f'{protocol}downloads.majestic.com/majestic_million.csv'
        feed_url_to_config = {
            majestic_million_url: {
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
        params['feed_url_to_config'] = feed_url_to_config
        params['value_field'] = 'Domain'
        params['url'] = majestic_million_url
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
