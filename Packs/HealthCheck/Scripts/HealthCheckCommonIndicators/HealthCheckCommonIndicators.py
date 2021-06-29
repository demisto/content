import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

THRESHOLDS = {
    'relatedIndicatorCount': 100,
}

BODY = {
    'page': 0,
    'size': 10,
    'query': '',
    'sort': [{
        'field': 'relatedIncCount',
        'asc': False,
    }],
    'period': {
        'by': 'day',
        'fromValue': 90,
    },
}


def main(args):
    incident = demisto.incidents()[0]
    account_name = incident.get('account')
    account_name = f"acc_{account_name}/" if account_name != "" else ""

    thresholds = args.get('Thresholds', THRESHOLDS)
    indicator_res = demisto.executeCommand('demisto-api-post', {
        'uri': f'{account_name}/indicators/search',
        'body': BODY,
    })
    if is_error(indicator_res):
        return_results(indicator_res)
        return_error('Failed to execute demisto-api-post. See additional error details in the above entries.')

    indicators = indicator_res[0]['Contents']['response']['iocObjects']

    res = []
    for indicator in indicators:
        if indicator['relatedIncCount'] > thresholds['relatedIndicatorCount']:
            res.append({
                'category': 'Indicators',
                'severity': 'Low',
                'description': f'The indicator: "{indicator["value"]}" was found {indicator["relatedIncCount"]} times',
                'resolution': 'You may consider adding it to the exclusion list',
            })

    results = CommandResults(
        readable_output='HealthCheckCommonIndicators Done',
        outputs_prefix='actionableitems',
        outputs=res)

    return results


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main(demisto.args()))
