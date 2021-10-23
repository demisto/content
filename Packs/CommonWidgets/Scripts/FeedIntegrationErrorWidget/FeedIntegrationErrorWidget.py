from dateparser import parse

import demistomock as demisto
from CommonServerPython import *


def get_feed_integration_errors() -> TableOrListWidget:
    integration_search_res = demisto.internalHttpRequest(
        'POST',
        '/settings/integration/search',
        '{}',
    )

    table = TableOrListWidget()

    if integration_search_res.get('statusCode') == 200:
        integrations = json.loads(integration_search_res.get('body', '{}'))
        instances = integrations.get('instances', [])
        enabled_instances = {instance.get('name') for instance in instances if instance.get('enabled') == 'true'}
        instances_health = integrations.get('health', {})
        for instance in instances_health.values():
            if 'feed' in (brand := instance.get('brand', '')).lower() and \
                (error := instance.get('lastError', '')) and \
                    (instance_name := instance.get('instance')) in enabled_instances:
                if modified := instance.get('modified', ''):
                    modified_dt = parse(modified)
                    modified = modified_dt.strftime('%Y-%m-%d %H:%M:%S%z')
                table.add_row({
                    'Brand': brand,
                    'Instance': instance_name,
                    'Instance Last Modified Time': modified,
                    'Error Information': error,
                })
    else:
        demisto.error(f'Failed running POST query to /settings/integration/search.\n{str(integration_search_res)}')

    return table


def main():
    try:
        return_results(get_feed_integration_errors())
    except Exception as e:
        return_error(f'Failed to execute FeedIntegrationErrorWidget Script. Error: {str(e)}', e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
