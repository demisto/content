import re
from datetime import datetime


def test_get_ioc_filter():
    from FidelisElevateNetwork import get_ioc_filter
    f = get_ioc_filter('192.168.19.1')  # disable-secrets-detection
    assert f.get('simple', {}).get('column') == 'ANY_IP'

    f = get_ioc_filter('c9a31ea148232b201fe7cb7db5c75f5e')
    assert f.get('simple', {}).get('column') == 'MD5'

    f = get_ioc_filter('2F6C57D8CB43AA5C0153CD3A06E4A783B5BB7BC1')
    assert f.get('simple', {}).get('column') == 'SHA1_HASH'

    f = get_ioc_filter('9d88425e266b3a74045186837fbd71de657b47d11efefcf8b3cd185a884b5306')
    assert f.get('simple', {}).get('column') == 'SHA256'

    f = get_ioc_filter('some ioc')
    assert f.get('simple', {}).get('column') == 'ANY_STRING'


def test_to_fidelis_time_format():
    from FidelisElevateNetwork import to_fidelis_time_format
    fidelis_time = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

    dt = datetime.now()
    assert fidelis_time.match(to_fidelis_time_format(dt)) is not None
    assert fidelis_time.match(to_fidelis_time_format('2019-12-01T05:40:10')) is not None
    assert fidelis_time.match(to_fidelis_time_format('2019-12-01T05:40:1')) is not None
    assert fidelis_time.match(to_fidelis_time_format('2019-12-01T05:40:10Z')) is not None
