from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    feed_url_to_config = {
        'https://www.cloudflare.com/ips-v4': {
            'indicator_type': FeedIndicatorType.CIDR
        },
        'https://www.cloudflare.com/ips-v6': {
            'indicator_type': FeedIndicatorType.IPv6CIDR
        }
    }

    params['feed_url_to_config'] = feed_url_to_config

    # Call the main execution of the HTTP API module.
    feed_main('Cloudflare Feed', params, 'cloudflare-')


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
