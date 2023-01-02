import demistomock as demisto
import urllib3
import time
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from typing import Dict, Tuple

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

def main() -> None:  # pragma: no cover
    # params = demisto.params()
    # client_id: str = params.get('credentials', {}).get('identifier', '')
    # client_secret: str = params.get('credentials', {}).get('password', '')
    # base_url: str = params.get('url', '').rstrip('/')
    # verify_certificate = not params.get('insecure', False)
    max_fetch = params.get('max_fetch', False)
    vendor = params.get('vendor', False)
    product = params.get('product', False)
    # args = demisto.args()
    from uuid import uuid4
    
    if demisto.command() == 'test-module':
        return_results('ok')
    
    try:
        if demisto.command() == 'fetch-events':
            events = []
            for i in range(int(max_fetch)):
                event = {
                    'test_event_id': str(uuid4()),
                    'foo': f'foo{i}',
                    'bar': f'bar{i}',
                }
                events.append(event)
            
            send_events_to_xsiam(
                events=events,
                vendor=vendor,
                product=product
            )
        else:
            return_error('command not exists')
    except Exception as e:
        raise Exception(f'Error in Palo Alto Saas Security Event Collector Integration [{e}]')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
