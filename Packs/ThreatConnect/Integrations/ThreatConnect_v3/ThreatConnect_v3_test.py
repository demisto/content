from ThreatConnect_v3 import Client, Method, create_or_query
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
