import demistomock as demisto
from ThreatIntelligenceManagementGetIncidentsPerFeed import get_incidents_per_feed
import re

INDICATORS_TO_RETURN = [
    [
        {
            'sourceBrands': [
                'Test1 Feed',
                'Test2 Feed',
                'Test3',
            ]
        },
        {
            'sourceBrands': [
                'Test1 Feed',
                'Test3',
            ]
        }
    ],
    [
        {
            'sourceBrands': [
                'Test1 Feed',
                'Test2 Feed',
                'Test3',
            ]
        },
        {
            'sourceBrands': [
                'Test4',
            ]
        }
    ]
]

INCIDENTS_TO_RETURN = [
    {
        'Contents': {
            'total': 1,
            'data': [
                {
                    'investigationId': 0
                },
                {
                    'investigationId': 1
                }
            ]
        },
        'Type': 1
    }
]


def execute_command(name, args=None):
    if name == 'getIncidents':
        return INCIDENTS_TO_RETURN
    else:
        return None


def search_indicators(fromDate='', toDate='', query='', size=None, page=None, value=None):
    query_list = re.split(r'\W+', query)
    investigation_id = int(query_list[-1])
    source_brands = query_list[1]
    indicators = INDICATORS_TO_RETURN[investigation_id]
    indicators_to_return = [indicator for indicator in indicators if
                            [brand for brand in indicator['sourceBrands'] if source_brands in brand]]
    return {'iocs': indicators_to_return}


def test_get_incidents_per_feed(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'searchIndicators', side_effect=search_indicators)
    from_date = '2020-03-12T00:00:00.000Z'
    actual_results = get_incidents_per_feed(from_date)
    expected_results = {
        'Test1 Feed': 2,
        'Test2 Feed': 2
    }
    assert actual_results == expected_results
