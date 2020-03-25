import demistomock as demisto
from CommonServerPython import *


def get_feed_config(services: list, regions: list):
    """
    Creates the configuration for each AWS service.
    Args:
        services: The selected services.
        regions: The selected regions.

    Returns:
        The feed configuration.
    """
    available_services = {
        'AMAZON',
        'EC2',
        'ROUTE53',
        'ROUTE53_HEALTHCHECKS',
        'CLOUDFRONT',
        'S3'
    }

    region_path = ''
    if regions:
        region_path = f" && contains({regions}, region)"

    feed_name_to_config = {}

    for service in available_services:
        feed_name_to_config[service] = {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': f"prefixes[?service=='{service}'{region_path}]",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.CIDR,
            'fields': ['region', 'service'],
            'mapping': {
                'region': 'region'
            }
        }

    return {service: feed_name_to_config.get(service) for service in services}


from JSONFeedApiModule import *  # noqa: E402


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_name_to_config'] = get_feed_config(params.get('services', ['AMAZON']),
                                                    argToList(params.get('regions', [])))
    feed_main(params, 'AWS Feed', 'aws')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
