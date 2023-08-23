import dateparser
from ThreatConnectV3 import Client, Method, create_or_query, create_context, get_last_run_time, list_groups, fetch_incidents
from freezegun import freeze_time
import pytest
import demistomock as demisto

client = Client('test', 'test', 'test', False)


@freeze_time('2020-04-20')
def test_create_header():
    assert client.create_header('test', Method.GET) == {
        'Authorization': 'TC test:p5a/YiTRs7sNMp/PEDgZxky8lJDRLbza1pi8erjURrU=',
        'Content-Type': 'application/json',
        'Timestamp': '1587340800'}


def test_create_or_query():
    assert create_or_query('1,2,3,4,5', 'test') == 'test="1" OR test="2" OR test="3" OR test="4" OR test="5" '
    assert create_or_query('1,2,3,4,5', 'test', '') == 'test=1 OR test=2 OR test=3 OR test=4 OR test=5 '


@pytest.fixture
def groups_fixture() -> list:
    return [{'dateAdded': '2022-08-04T12:35:33Z'}, {'dateAdded': '2022-09-06T12:35:33Z'},
            {'dateAdded': '2022-03-06T12:35:33Z'}, {'dateAdded': '2022-09-06T12:36:33Z'},
            {'dateAdded': '2022-08-06T11:35:33Z'}]


@pytest.mark.parametrize('last_run, expected_result', [('2022-07-04T12:35:33', '2022-09-06T12:36:33'),
                                                       ('2023-07-04T12:35:33', '2023-07-04T12:35:33')])
def test_get_last_run_time(last_run, expected_result, groups_fixture):
    """
    Given:
        - a response containing groups with last_run time and the previos last run_time.
    When:
        - Checking for the next last_run.
    Then:
        - Validate that the correct last run is set.
    """
    assert get_last_run_time(groups_fixture, last_run) == expected_result


def test_get_last_run_no_groups():
    """
    Given:
        - no grops were found.
    When:
        - checking for the next last_run.
    Then:
        - validate that the last run remains as it was before in the previos round.
    """
    assert get_last_run_time([], '2022-07-04T12:35:33') == '2022-07-04T12:35:33'


def test_fetch_incidents_first_run(mocker):
    """
    Given:
        - getLastRun is empty (first run)
    When:
        - calling fetch_events
    Then:
        - Validate that the last run is set properly
    """
    import ThreatConnectV3
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(dateparser, 'parse', return_value=dateparser.parse('2022-08-04T12:35:33'))
    mocker.patch.object(ThreatConnectV3, 'list_groups', return_value=[])
    assert fetch_incidents(client) == '2022-08-04T12:35:33'


def test_fetch_incidents_not_first_run(mocker, groups_fixture):
    import ThreatConnectV3
    mocker.patch.object(demisto, 'getLastRun', return_value={'last': '2021-08-04T12:35:33'})
    mocker.patch.object(ThreatConnectV3, 'list_groups', return_value=groups_fixture)
    assert fetch_incidents(client, {}) == '2022-09-06T12:36:33'


def test_create_context():  # type: ignore # noqa
    indicators = [{
        "id": 40435508,
        "ownerName": "Technical Blogs and Reports",
        "dateAdded": "2021-12-09T12:57:18Z",
        "webLink": "https://partnerstage.threatconnect.com/auth/indicators/details/url.xhtml?orgid=40435508",
        "type": "URL",
        "lastModified": "2022-07-26T13:51:49Z",
        "rating": 3.00,
        "confidence": 32,
        "source": "https://blog.sucuri.net/2021/12/php-re-infectors-the-malware-that-keeps-on-giving.html",
        "summary": "http://yourwebsite.com/opcache.php",
    }]
    res = ({'TC.Indicator(val.ID && val.ID === obj.ID)': [{'Confidence': 32,
                                                           'CreateDate': '2021-12-09T12:57:18Z',
                                                           'Description': None,
                                                           'ID': 40435508,
                                                           'LastModified': '2022-07-26T13:51:49Z',
                                                           'Name': 'http://yourwebsite.com/opcache.php',
                                                           'Owner': 'Technical Blogs and '
                                                                    'Reports',
                                                           'Rating': 3,
                                                           'Type': 'URL',
                                                           'WebLink': 'https://partnerstage.threatconnect.com/auth'
                                                                      '/indicators/details/url.xhtml?orgid=40435508'}],
            'URL(val.Data && val.Data == obj.Data)': [{'Data': 'http://yourwebsite.com/opcache.php',
                                                       'Malicious': {'Description': '',
                                                                     'Vendor': 'ThreatConnect'}}]},
           [{'Confidence': 32,
             'CreateDate': '2021-12-09T12:57:18Z',
             'Description': None,
             'ID': 40435508,
             'LastModified': '2022-07-26T13:51:49Z',
             'Name': 'http://yourwebsite.com/opcache.php',
             'Owner': 'Technical Blogs and Reports',
             'Rating': 3,
             'Type': 'URL',
             'WebLink': 'https://partnerstage.threatconnect.com/auth/indicators/details/url.xhtml?orgid=40435508'}])
    assert create_context(indicators) == res


def test_list_groups(mocker):
    mock = mocker.patch.object(Client, 'make_request', return_value={})
    client = Client(api_id='test', api_secret='test', base_url='https://test.com')
    list_groups(client, {}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=0&resultLimit=100'
    list_groups(client, {'tag': 'a,b'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=a%2Cbtag%20like%20%22%25a%25%22%20AND%20tag%20like%' \
                                     '20%22%25b%25%22&fields=tags&resultStart=0&resultLimit=100'
    list_groups(client, {'id': 'test'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=%28id%3Dtest%20%29&resultStart=0&resultLimit=100'
    list_groups(client, {'fromDate': '2022.08.08'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=dateAdded%20%3E%20%222022.08.08%22%20&resultStart=' \
                                     '0&resultLimit=100'
    list_groups(client, {'security_label': 'TLP:AMBER'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=securityLabel%20like%20%22%25TLP%3AAMBER%25%22&fields=' \
                                     'securityLabels&resultStart=0&resultLimit=100'
    list_groups(client, {'group_type': 'Incident'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=typeName%20EQ%20%22Incident%22&resultStart=' \
                                     '0&resultLimit=100'
    list_groups(client, {'filter': 'dateAdded > 2022-03-03'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=dateAdded%20%3E%202022-03-03&resultStart=0&resultLimit=100'
    list_groups(client, {'limit': '666'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=0&resultLimit=666'
    list_groups(client, {'page': '777'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=777&resultLimit=100'
    list_groups(client, {'page': '777', 'limit': '666', 'group_type': 'Incident'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=typeName%20EQ%20%22Incident%22&resultStart=777&resultLimit=666'
    list_groups(client, {'security_label': 'TLP:AMBER', 'tag': 'a,b', 'id': 'test'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=%28id%3Dtest%20%29a%2Cb%20AND%20tag%20like%20%22%25a%25' \
                                     '%22%20AND%20tag%20like%20%22%25b%25%22%20AND%20securityLabel%20like%20%22%25TLP' \
                                     '%3AAMBER%25%22&fields=tags&fields=securityLabels&resultStart=0&resultLimit=100'
