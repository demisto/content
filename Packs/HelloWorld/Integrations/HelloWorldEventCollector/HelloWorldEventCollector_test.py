from datetime import datetime
import uuid
from HelloWorldEventCollector import Client, fetch_events

RESPONSE = [{
    'id': 2,
    'created_time': datetime.now().isoformat(),
    'description': 'This is test description 2',
    'alert_status': 'Status',
    'custom_details': {
        'triggered_by_name': 'Name for id: 2',
        'triggered_by_uuid': str(uuid.uuid4()),
        'type': 'customType',
        'requested_limit': 1,
    }
}]


def test_fetch_detection_events_command():
    """
    Given:
    - fetch events command (fetches detections)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    last_run = {'prev_id': 1}
    next_run, events = fetch_events(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_str,
        alert_status="Status",
        max_events_per_fetch=1,
    )

    assert len(events) == 1
    assert next_run.get('prev_id') == 2
    assert events[0].get('id') == 2
