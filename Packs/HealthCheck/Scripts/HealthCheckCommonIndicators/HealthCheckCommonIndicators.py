import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

THRESHOLDS = {
    'relatedIndicatorCount': 1000,
}


def build_body(tenant_name):
    query = f"account:{tenant_name}" if tenant_name != "" else ""
    body = {
        'page': 0,
        'size': 10,
        'query': f'{query}',
        'sort': [{
            'field': 'relatedIncCount',
            'asc': False,
        }],
        'period': {
            'by': 'day',
            'fromValue': 90,
        }
    }
    return body


def main(args):
    incident = demisto.incidents()[0]
    tenant_name = incident.get('account')
    account_name = f"acc_{tenant_name}/" if tenant_name != "" else ""
    body = build_body(tenant_name)

    indicator_thresholds = args.get('Thresholds', THRESHOLDS)
    indicator_res = execute_command('demisto-api-post', {
        'uri': f'{account_name}indicators/search',
        'body': body,
    })

    indicators = indicator_res['response']['iocObjects']

    res = []
    for indicator in indicators:
        if indicator.get('relatedIncCount', 0) > indicator_thresholds['relatedIndicatorCount']:
            res.append({
                'category': 'Indicators',
                'severity': 'Low',
                'description': f'The indicator: "{indicator["value"]}" was found {indicator["relatedIncCount"]} times',
                'resolution': 'You may consider adding it to the exclusion list',
            })

    results = CommandResults(
        readable_output='HealthCheckCommonIndicators Done',
        outputs_prefix='HealthCheck.ActionableItems',
        outputs=res)

    return results


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main(demisto.args()))
