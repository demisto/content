from ThreatConnectV3 import Client, Method, create_or_query, create_context, get_last_run_time, list_groups
from freezegun import freeze_time

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


def test_get_last_run_time():
    groups = [{'dateAdded': '2022-08-04T12:35:33Z'}, {'dateAdded': '2022-09-06T12:35:33Z'},
              {'dateAdded': '2022-03-06T12:35:33Z'}, {'dateAdded': '2022-09-06T12:36:33Z'},
              {'dateAdded': '2022-08-06T11:35:33Z'}, ]
    assert get_last_run_time(groups) == '2022-09-06T12:36:33'


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
