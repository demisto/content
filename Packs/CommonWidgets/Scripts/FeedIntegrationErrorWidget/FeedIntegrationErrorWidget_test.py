import json

import demistomock as demisto
from FeedIntegrationErrorWidget import get_feed_integration_errors


def test_get_feed_integration_errors(mocker):
    '''
    Given:
        - Integration search result which contains the following:
            - Enabled feed integration instance with error
            - Feed integration without error
            - Not enabled feed integration with error
            - Non-feed integration without error
    When:
        - Running the FeedIntegrationErrorWidget script

    Then:
        - Ensure only the feed integration with error is returned
    '''
    feed_brand = 'Test Feed'
    feed_brand_instance_1 = 'Test Feed_instance_1'
    error = 'some error'
    modified = '2021-10-14T10:42:29.341218+03:00'
    res_body = {
        'health': {
            feed_brand_instance_1: {
                'brand': feed_brand,
                'instance': feed_brand_instance_1,
                'lastError': error,
                'modified': modified,
            },
            'Test Feed_instance_2': {
                'brand': feed_brand,
                'instance': 'Test Feed_instance_2',
                'lastError': '',
                'modified': '2021-10-14T10:42:29.341218+03:00',
            },
            'Test Feed_instance_3': {
                'brand': feed_brand,
                'instance': 'Test Feed_instance_3',
                'lastError': error,
                'modified': '2021-10-14T10:42:29.341218+03:00',
            },
            'Test Integration_instance_1': {
                'brand': 'Test Integration',
                'instance': 'Test Integration_instance_1',
                'lastError': '',
                'modified': '2021-10-14T10:42:29.341218+03:00',
            },
        },
        'instances': [
            {
                'name': feed_brand_instance_1,
                'brand': feed_brand,
                'enabled': 'true',
            },
            {
                'name': 'Test Feed_instance_3',
                'brand': feed_brand,
                'enabled': 'false',
            },
        ],
    }
    mocker.patch.object(
        demisto,
        'internalHttpRequest',
        return_value={
            'statusCode': 200,
            'body': json.dumps(res_body)
        }
    )

    res = get_feed_integration_errors()
    table = json.loads(res.to_display())

    assert table['total'] == 1
    assert table['data'] == [{
        'Brand': feed_brand,
        'Instance': feed_brand_instance_1,
        'Instance Last Modified Time': '2021-10-14 10:42:29+0300',
        'Error Information': error,
    }]
