from typing import Dict
import demistomock as demisto

raw_incidents_data = [
    {
        'buckets':
            {
                'investigations-4185': {
                    'keyN': 133,
                    'leafSize': '1.6 MB'
                },
                'investigations-4187': {
                    'keyN': 1301,
                    'leafSize': '4.8 MB'
                },
                'newInsights': {
                    'keyN': 106,
                    'leafSize': '3.3 MB'
                },
                'newInvPlaybooks': {
                    'keyN': 9,
                    'leafSize': '29 MB'
                }
            },
        'dbName': '082020'
    }
]

investigations = {
    'investigations-4185': {
        'keyN': 133,
        'leafSize': '1.6 MB',
        'Date': '082020'
    },
    'investigations-4187': {
        'keyN': 1301,
        'leafSize': '4.8 MB',
        'Date': '082020'
    }
}


def test_get_investigations():
    from GetLargestInvestigations import get_investigations
    inv: Dict = {}
    get_investigations(raw_incidents_data, inv)
    assert inv == investigations


def test_parse_investigations_to_table():
    from GetLargestInvestigations import parse_investigations_to_table
    table = parse_investigations_to_table(investigations)
    assert table.get('total') == 2
    assert table.get('data')[0].get('IncidentID') == '4187'
    assert table.get('data')[0].get('Size') == '4.8 MB'
    assert table.get('data')[1].get('IncidentID') == '4185'
    assert table.get('data')[1].get('Date') == '08-2020'


def test_get_month_database_names(mocker):
    from GetLargestInvestigations import get_month_database_names
    mocker.patch.object(demisto, 'args', return_value={'to': '2020-08-20T14:28:23.382748Z',
                                                       'from': '2020-06-20T14:28:23.382748Z'})
    db_names = get_month_database_names()
    expected_dbs = {'082020', '072020', '062020'}
    assert db_names == expected_dbs
