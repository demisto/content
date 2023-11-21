import demistomock as demisto
from CommonServerPython import *

AVAILABLE_FEEDS = ['AMAZON',
                   'EC2',
                   'ROUTE53',
                   'ROUTE53_HEALTHCHECKS',
                   'CLOUDFRONT',
                   'S3',
                   'AMAZON_APPFLOW',
                   'AMAZON_CONNECT',
                   'API_GATEWAY',
                   'CHIME_MEETINGS',
                   'CHIME_VOICECONNECTOR',
                   'CLOUD9',
                   'CLOUDFRONT_ORIGIN_FACING',
                   'CODEBUILD',
                   'DYNAMODB',
                   'EBS',
                   'EC2_INSTANCE_CONNECT',
                   'GLOBALACCELERATOR',
                   'KINESIS_VIDEO_STREAMS',
                   'ROUTE53_HEALTHCHECKS_PUBLISHING',
                   'ROUTE53_RESOLVER',
                   'WORKSPACES_GATEWAYS',
                   ]


def get_feed_config(services: list, regions: list):
    """
    Creates the configuration for each AWS service.
    Args:
        services: The selected services.
        regions: The selected regions.

    Returns:
        The feed configuration.
    """

    region_path = ''
    if regions and 'All' not in regions:
        region_path = f" && contains({regions}, region)"

    if 'All' in services or not services:
        services = AVAILABLE_FEEDS

    feed_name_to_config = {}

    for feed in services:
        feed_name_to_config[f'{feed}$$CIDR'] = {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': f"prefixes[?service=='{feed}'{region_path}]",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.CIDR,
            'fields': ['region', 'service'],
            'mapping': {
                'region': 'region',
                'service': 'service'
            }
        }

        feed_name_to_config[f'{feed}$$IPv6'] = {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': f"ipv6_prefixes[?service=='{feed}'{region_path}]",
            'indicator': 'ipv6_prefix',
            'indicator_type': FeedIndicatorType.IPv6,
            'fields': ['region', 'service'],
            'mapping': {
                'region': 'region',
                'service': 'service'
            }
        }

    return feed_name_to_config


from JSONFeedApiModule import *  # noqa: E402


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_name_to_config'] = get_feed_config(params.get('services', ['All']),
                                                    argToList(params.get('regions', ['All'])))
    feed_main(params, 'AWS Feed', 'aws')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
