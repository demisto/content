import demistomock as demisto
from CommonServerPython import *

from JSONFeedApiModule import *  # noqa: E402

feed_config = {
    'All GCP customer global and regional external IP ranges':
        {'CIDR': {
            'url': 'https://www.gstatic.com/ipranges/cloud.json',
            'extractor': "prefixes[]",
            'indicator': 'ipv4Prefix',
            'indicator_type': FeedIndicatorType.CIDR,
        }, 'IPv6CIDR': {
            'url': 'https://www.gstatic.com/ipranges/cloud.json',
            'extractor': "prefixes[]",
            'indicator': 'ipv6Prefix',
            'indicator_type': FeedIndicatorType.IPv6CIDR,
        }},
    'All available Google IP ranges':
        {'CIDR': {
            'url': 'https://www.gstatic.com/ipranges/goog.json',
            'extractor': "prefixes[]",
            'indicator': 'ipv4Prefix',
            'indicator_type': FeedIndicatorType.CIDR,
        }, 'IPv6CIDR': {
            'url': 'https://www.gstatic.com/ipranges/goog.json',
            'extractor': "prefixes[]",
            'indicator': 'ipv6Prefix',
            'indicator_type': FeedIndicatorType.IPv6CIDR,
        }},
}


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_name_to_config'] = feed_config.get(str(params.get('ip_ranges')))
    feed_main(params, 'Google IP Ranges Feed', 'google-ip-ranges')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
