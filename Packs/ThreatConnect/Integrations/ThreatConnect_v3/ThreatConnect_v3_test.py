from ThreatConnect_v3 import Client, Method, create_or_query, create_context, get_last_run_time
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
             'ID': 40435508,
             'LastModified': '2022-07-26T13:51:49Z',
             'Name': 'http://yourwebsite.com/opcache.php',
             'Owner': 'Technical Blogs and Reports',
             'Rating': 3,
             'Type': 'URL',
             'WebLink': 'https://partnerstage.threatconnect.com/auth/indicators/details/url.xhtml?orgid=40435508'}])
    assert create_context(indicators) == res
