import demistomock as demisto
from typing import Dict
from Intel471WatcherAlerts import fetch_incidents, Client, FEED_URL, USER_AGENT


def test_fetch_incidents(mocker):
    base_url = FEED_URL
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    headers: Dict = {
        'user-agent': USER_AGENT
    }

    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        auth=(username, password),
        proxy=proxy)

    last_alert_uid: str = demisto.getIntegrationContext().get('last_alert_uid', '')

    latest_alert_uid, next_run, incidents = fetch_incidents(
        client=client,
        max_results=100,
        last_run=0,
        first_fetch_time=0,
        watcher_group_uids=None,
        severity='Medium',
        last_alert_uid=None
    )

    assert len(incidents) > 0
