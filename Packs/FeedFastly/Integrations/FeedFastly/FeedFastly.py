import demistomock as demisto
from CommonServerPython import *


from JSONFeedApiModule import *  # noqa: E402


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['indicator'] = 'ip'
    params['url'] = 'https://api.fastly.com/public-ip-list'

    indicator_types = [
        {
            'indicator_type': FeedIndicatorType.CIDR,
            'extractor': 'addresses[].{ip:@}'
        },
        {
            'indicator_type': FeedIndicatorType.IPv6CIDR,
            'extractor': 'ipv6_addresses[].{ip:@}'
        }
    ]

    for item in indicator_types:
        params['indicator_type'] = item['indicator_type']
        params['extractor'] = item['extractor']
        feed_main(params, 'Fastly Feed', 'fastly')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
