import pytest

import demistomock as demisto

import re
from datetime import datetime
import json
import io
from FidelisElevateNetwork import main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


def test_fidelis_get_alert(mocker):

    expected_response = util_load_json("./test_data/get_alert.json")
    args = {
        'alert_id': 1,
    }
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='fidelis-get-alert')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('FidelisElevateNetwork.CREDENTIALS', return_value='')
    mocker.patch('FidelisElevateNetwork.login', return_value='123')
    mocker.patch('FidelisElevateNetwork.http_request', return_value=expected_response)
    main()

    res = demisto.results
    assert res.call_args[0][0].get('Contents') == expected_response


def test_fidelis_delete_alert(mocker):
    args = {
        'alert_id': '1',
    }
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='fidelis-delete-alert')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('FidelisElevateNetwork.CREDENTIALS', return_value='')
    mocker.patch('FidelisElevateNetwork.login', return_value='123')
    mocker.patch('FidelisElevateNetwork.http_request', return_value='')
    main()

    res = demisto.results
    assert res.call_args[0][0].get('Contents') == 'Alert (1) deleted successfully!'


def test_fidelis_get_malware_data(mocker):
    args = {
        'alert_id': '1',
    }
    expected_response = util_load_json("./test_data/get_malware_data.json")

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='fidelis-get-malware-data')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('FidelisElevateNetwork.CREDENTIALS', return_value='')
    mocker.patch('FidelisElevateNetwork.login', return_value='123')
    mocker.patch('FidelisElevateNetwork.http_request', return_value=expected_response)
    main()

    res = demisto.results
    assert res.call_args[0][0].get('Contents') == expected_response
