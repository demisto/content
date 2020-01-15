def main():
    # Call the main execution of the HTTP API module.
    # This function also allows to add to or override that execution.
    params = {k: v for k, v in demisto.params().items() if v is not None}

    feed_types = {
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
            'indicator_type': 'IP',
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        },
        'https://www.spamhaus.org/drop/edrop.txt': {
            'indicator_type': 'IP',
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        }
    }

    params['feed_types'] = feed_types
    feed_main('SpamhausFeed', params)


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
