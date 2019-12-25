import json
from FeedVT import *
import requests_mock


def test_amazon_ip_feed():
    with open('test_data/virustotal_notifications.json') as notifications_json:
        notifications = json.load(notifications_json)

    with requests_mock.Mocker() as m:
        m.get('https://www.virustotal.com/intelligence/hunting/notifications-feed/', json=notifications)

        client = Client(
            url='https://www.virustotal.com/intelligence/hunting/notifications-feed/',
            api_key='',
            insecure=True
        )

        indicators = fetch_indicators_command(client=client)
        assert len(jmespath.search(expression="[].rawJSON.md5", data=indicators)) == 100
