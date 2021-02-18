from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    feed_url_to_config = {
        # TODO: Add this service once we have an indicator type of ASN
        'https://www.spamhaus.org/drop/asndrop.txt': {
            'indicator_type': 'ASN',
            'indicator': {
                'regex': r'^AS[0-9]+'
            },
            'fields': [
                {
                    'asndrop_country': {
                        'regex': r'^.*;\W([a-zA-Z]+)\W+',
                        'transform': r'\1'
                    }
                },
                {
                    'asndrop_org': {
                        'regex': r'^.*\|\W+(.*)',
                        'transform': r'\1'
                    }
                }
            ]
        },
        'https://www.spamhaus.org/drop/drop.txt': {
            'indicator_type': FeedIndicatorType.CIDR,
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        },
        'https://www.spamhaus.org/drop/edrop.txt': {
            'indicator_type': FeedIndicatorType.CIDR,
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        }
    }

    params['feed_url_to_config'] = feed_url_to_config

    # Call the main execution of the HTTP API module.
    feed_main('Spamhaus Feed', params, 'spamhaus')


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
