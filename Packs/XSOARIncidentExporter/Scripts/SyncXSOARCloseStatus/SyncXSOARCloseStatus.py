import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

CLOSE_REASON_MAP = {
    'resolved': 'STATUS_030_RESOLVED_THREAT_HANDLED',
    'false positive': 'STATUS_060_RESOLVED_FALSE_POSITIVE',
    'duplicate': 'STATUS_050_RESOLVED_DUPLICATE',
    'other': 'STATUS_080_RESOLVED_OTHER',
}


class XSIAMClient(BaseClient):

    def __init__(self, base_url: str, api_key: str, api_key_id: str, verify: bool):
        headers = {
            'x-xdr-auth-id': api_key_id,
            'Authorization': api_key,
            'Content-Type': 'application/json',
        }
        super().__init__(base_url=base_url, verify=verify, proxy=False, headers=headers)

    def get_alerts(self, search_from: int = 0, search_to: int = 100) -> dict:
        body = {
            'request_data': {
                'filters': [
                    {
                        'field': 'alert_source',
                        'operator': 'in',
                        'value': ['Palo Alto Networks - XSOAR'],
                    },
                    {
                        'field': 'resolution_status',
                        'operator': 'in',
                        'value': ['STATUS_010_NEW', 'STATUS_020_UNDER_INVESTIGATION'],
                    },
                ],
                'search_from': search_from,
                'search_to': search_to,
                'sort': {
                    'field': 'creation_time',
                    'keyword': 'asc',
                },
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='/public_api/v1/alerts/get_alerts_multi_events',
            json_data=body,
        )

    def update_alerts(self, alert_ids: list, resolution_status: str, comment: str) -> dict:
        body = {
            'request_data': {
                'alert_id_list': alert_ids,
                'resolution_status': resolution_status,
                'resolution_comment': comment,
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='/public_api/v1/alerts/update_alerts',
            json_data=body,
        )


def extract_field(description: str, field_name: str) -> str:
    pattern = rf'{re.escape(field_name)}:\s*(.+?)(?:\n|$)'
    match = re.search(pattern, description)
    return match.group(1).strip() if match else ''


def map_close_reason(xsoar_reason: str) -> str:
    if not xsoar_reason:
        return 'STATUS_080_RESOLVED_OTHER'
    return CLOSE_REASON_MAP.get(xsoar_reason.lower(), 'STATUS_080_RESOLVED_OTHER')


def main():
    args = demisto.args()
    xsiam_url = args.get('xsiam_url', '').rstrip('/')
    xsiam_api_key = args.get('xsiam_api_key', '')
    xsiam_api_key_id = args.get('xsiam_api_key_id', '')
    verify = not argToBoolean(args.get('insecure', 'true'))
    max_alerts = arg_to_number(args.get('max_alerts')) or 100

    if not xsiam_url or not xsiam_api_key or not xsiam_api_key_id:
        return_error('xsiam_url, xsiam_api_key, and xsiam_api_key_id are required.')
        return

    client = XSIAMClient(base_url=xsiam_url, api_key=xsiam_api_key,
                          api_key_id=xsiam_api_key_id, verify=verify)

    response = client.get_alerts(search_from=0, search_to=max_alerts)
    alerts = response.get('reply', {}).get('alerts', [])
    total = response.get('reply', {}).get('total_count', 0)

    if not alerts:
        return_results(CommandResults(
            readable_output=f'No open XSOAR-sourced alerts found ({total} total).',
        ))
        return

    to_close: dict[str, list] = {}
    skipped = []

    for alert in alerts:
        alert_id = alert.get('alert_id', '')
        alert_name = alert.get('name', '')
        description = alert.get('description', '')

        if not description:
            events = alert.get('events', [])
            if events:
                description = events[0].get('alert_description', '') if events else ''

        status = extract_field(description, 'Status')
        close_reason = extract_field(description, 'Close Reason')
        close_notes = extract_field(description, 'Close Notes')
        xsoar_id = extract_field(description, 'XSOAR Incident ID')

        if status in ('Done', 'Archive'):
            resolution = map_close_reason(close_reason)
            comment = f'Closed in XSOAR as: {close_reason}'
            if close_notes:
                comment += f' | Notes: {close_notes}'

            key = f'{resolution}||{comment}'
            if key not in to_close:
                to_close[key] = []
            to_close[key].append({
                'alert_id': alert_id,
                'alert_name': alert_name,
                'xsoar_id': xsoar_id,
                'close_reason': close_reason,
                'close_notes': close_notes,
            })
        else:
            skipped.append({
                'alert_id': alert_id,
                'alert_name': alert_name,
                'xsoar_id': xsoar_id,
                'status': status,
            })

    closed_summary = []
    for key, alert_group in to_close.items():
        resolution, comment = key.split('||', 1)
        alert_ids = [int(a['alert_id']) for a in alert_group]
        try:
            client.update_alerts(alert_ids, resolution, comment)
            for a in alert_group:
                a['result'] = 'Closed'
                closed_summary.append(a)
        except Exception as e:
            for a in alert_group:
                a['result'] = f'Failed: {str(e)}'
                closed_summary.append(a)

    output_parts = []
    if closed_summary:
        table = tableToMarkdown(
            f'Closed {len(closed_summary)} XSIAM Alert(s)',
            closed_summary,
            headers=['alert_id', 'alert_name', 'xsoar_id', 'close_reason', 'close_notes', 'result'],
        )
        output_parts.append(table)

    if skipped:
        table = tableToMarkdown(
            f'Skipped {len(skipped)} Open Alert(s)',
            skipped,
            headers=['alert_id', 'alert_name', 'xsoar_id', 'status'],
        )
        output_parts.append(table)

    if not closed_summary and not skipped:
        output_parts.append('No alerts processed.')

    return_results(CommandResults(
        readable_output='\n'.join(output_parts),
        outputs_prefix='XSOARCloseSync',
        outputs={
            'ClosedCount': len(closed_summary),
            'SkippedCount': len(skipped),
            'ClosedAlerts': closed_summary,
        },
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
