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
                },
            },
        'dbName': '082020'
    },
    {
        'buckets':
            {
                'investigations-playground': {
                    'keyN': 1301,
                    'leafSize': '4.8 MB',
                    'Date': ''
                }
            },
        'dbName': 'main'
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
    },
    'investigations-playground': {
        'keyN': 1301,
        'leafSize': '4.8 MB',
        'Date': 'main'
    }
}


def test_get_investigations():
    """
    Given:
        raw incidents info from getDBStatistics command.
    When:
        Running get_investigations.
    Then:
        check the resulting incidents are filtered and formatted correctly
    """
    from GetLargestInvestigations import get_investigations
    inv: Dict = {}
    get_investigations(raw_incidents_data, inv)
    assert inv == investigations


def test_get_investigations__on_fail():
    """
    Given:
        a failure message from getDBStatistics command.
    When:
        Running get_investigations.
    Then:
        check the resulting incidents are in a dict.
    """
    from GetLargestInvestigations import get_investigations
    inv: Dict = {}
    get_investigations('Failed getting DB stats with filter [102020], minBytes [1000000]', inv)
    assert inv == {}


def test_parse_investigations_to_table():
    """
    Given:
        A dict of investigations with their info.
    When:
        Running investigations_to_table.
    Then:
        check the result has the correct amount of outputs, that the incident names are in the correct
        order (sorted by size) and that the date is formatted correctly.
    """
    from GetLargestInvestigations import parse_investigations_to_table
    table = parse_investigations_to_table(investigations, True)
    assert table.get('total') == 3
    assert table.get('data')[0].get('IncidentID') == '4187'
    assert table.get('data')[0].get('Size(MB)') == 4.8
    assert table.get('data')[1].get('Date') == ''
    assert table.get('data')[1].get('IncidentID') == 'playground'
    assert table.get('data')[2].get('IncidentID') == '4185'
    assert table.get('data')[2].get('Date') == '08-2020'


def test_get_month_database_names(mocker):
    """
    Given:
        from and to dates
    When:
        Running get_month_database_names.
    Then:
        the result is a set of all the months between from and to
    """
    from GetLargestInvestigations import get_month_database_names
    mocker.patch.object(demisto, 'args', return_value={'to': '2020-08-20T14:28:23.382748Z',
                                                       'from': '2020-06-20T14:28:23.382748Z'})
    db_names = get_month_database_names()
    expected_dbs = {'082020', '072020', '062020'}
    assert db_names == expected_dbs
