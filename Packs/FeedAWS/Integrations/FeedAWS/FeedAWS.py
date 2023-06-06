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

AVAILABLE_REGIONS = ['af-south-1',
                     'ap-east-1',
                     'ap-east-2',
                     'ap-northeast-1',
                     'ap-northeast-2',
                     'ap-northeast-3',
                     'ap-south-1',
                     'ap-south-2',
                     'ap-southeast-1',
                     'ap-southeast-2',
                     'ap-southeast-3',
                     'ap-southeast-4',
                     'ca-central-1',
                     'cn-north-1',
                     'cn-northwest-1',
                     'eu-central-1',
                     'eu-central-2',
                     'eu-north-1',
                     'eu-south-1',
                     'eu-south-2',
                     'eu-west-1',
                     'eu-west-2',
                     'eu-west-3',
                     'me-south-1',
                     'me-central-1',
                     'sa-east-1',
                     'us-east-1',
                     'us-east-2',
                     'us-gov-east-1',
                     'us-gov-west-1',
                     'us-west-1',
                     'us-west-2',
                     'GLOBAL']


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
