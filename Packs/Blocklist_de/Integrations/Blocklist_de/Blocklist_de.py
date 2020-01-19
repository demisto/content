def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    feed_types = {
        '': {
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
        '': {
            'indicator_type': 'IP',
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        },
        '': {
            'indicator_type': 'IP',
            'indicator': {
                'regex': r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
            }
        }
    }

    params['feed_types'] = feed_types

    # Call the main execution of the HTTP API module.
    feed_main('Blocklist_de Feed', params)


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
