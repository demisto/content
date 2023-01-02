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
    # proxy = params.get('proxy', False)
    # args = demisto.args()
    from uuid import uuid4
    
    try:
        events = [
            {
                'test_event_id': str(uuid4()),
                'foo': 'foo1',
                'bar': 'bar1'
            },
            {
                'test_event_id': str(uuid4()),
                'foo': 'foo2',
                'bar': 'bar2'
            }
        ]
        send_events_to_xsiam(
            events=events,
            vendor='test-vendor-1',
            product='test-product-1'
        )
    except Exception as e:
        raise Exception(f'Error in Palo Alto Saas Security Event Collector Integration [{e}]')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
