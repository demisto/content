def test_extractors():
    from AWSFeed import get_feed_config

    sub_feeds = ['AMAZON', 'EC2']

    feed_config = get_feed_config(sub_feeds)

    assert feed_config == {
        'AMAZON': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='AMAZON']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.IP,
            'fields': ['region', 'service']
        },
        'EC2': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='EC2']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.IP,
            'fields': ['region', 'service']
        }
    }
