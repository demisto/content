import gzip
import json
from collections import OrderedDict

import pytest

import demistomock
from SecurityIntelligenceServicesFeed import Client, botocore, MESSAGES

ACCESS_KEY = 'access key'
SECRET_KEY = 'secret key'

CLIENT = Client(ACCESS_KEY, SECRET_KEY, False, True)
CLIENT.set_s3_client(region_name='region')


def test_request_list_objects(mocker):
    """
    Test the list objects method of client class.
    """
    with open('./TestData/response_list_object.json') as f:
        expected_response = json.load(f)

    mocker.patch('botocore.client.BaseClient._make_api_call', return_value=expected_response)
    response = CLIENT.request_list_objects(feed_type='bucket')
    assert response == [
        {'Key': 'key', 'LastModified': 'last modified', 'ETag': 'cb4b5d90134c462ec98a1839f430ee2c', 'Size': 68768,
         'StorageClass': 'STANDARD'}]


def test_return_error_based_on_status_code():
    """
    Tests, Handle various status code based on response from s3.
    """
    with pytest.raises(ValueError) as v_error:
        CLIENT.return_error_based_on_status_code(400, '')
    assert str(v_error.value.args[0]) == MESSAGES['BAD_REQUEST_ERROR']

    with pytest.raises(ValueError) as v_error:
        CLIENT.return_error_based_on_status_code(401, '')
    assert str(v_error.value.args[0]) == MESSAGES['AUTHORIZATION_ERROR']

    with pytest.raises(ValueError) as v_error:
        CLIENT.return_error_based_on_status_code(403, '')
    assert str(v_error.value.args[0]) == MESSAGES['AUTHORIZATION_ERROR']

    with pytest.raises(ValueError) as v_error:
        CLIENT.return_error_based_on_status_code(404, '')
    assert str(v_error.value.args[0]) == MESSAGES['NOT_FOUND_ERROR']

    with pytest.raises(ValueError) as v_error:
        CLIENT.return_error_based_on_status_code(500, '')
    assert str(v_error.value.args[0]) == MESSAGES['SERVER_ERROR']


def test_validate_feed_type():
    """
    Tests, Handle scenarios where feed type are valid or invalid.
    """
    from SecurityIntelligenceServicesFeed import validate_feeds
    feed_types = ['domain']
    assert validate_feeds(feed_types) is None

    from SecurityIntelligenceServicesFeed import validate_feeds
    feed_types = ['Feed']
    with pytest.raises(ValueError) as v_error:
        validate_feeds(feed_types)
    assert str(v_error.value.args[0]) == MESSAGES['INVALID_FEED_TYPE_ERROR']

    feed_types = []
    with pytest.raises(ValueError) as v_error:
        validate_feeds(feed_types)
    assert str(v_error.value.args[0]) == MESSAGES['REQUIRED_FEED_TYPE_ERROR']


def test_main_proxy_error(mocker):
    """
    Tests, Handle proxy configuration is blank in XSOAR.
    """
    params = {
        'accessKey': 'accessKey',
        'secretKey': 'secretKey',
        'feedType': ['Domain'],
        'proxy': True
    }
    mocker.patch('SecurityIntelligenceServicesFeed.demisto.params', return_value=params)

    with pytest.raises(ValueError) as e:
        Client(ACCESS_KEY, SECRET_KEY, False, True)

    assert MESSAGES['BLANK_PROXY_ERROR'] + '{\'http\': \'\', \'https\': \'\'}' == str(e.value)


def test_main(mocker):
    """
    Tests, When the various command of execution triggers.
    """
    from SecurityIntelligenceServicesFeed import main, formatEpochDate
    params = {
        'accessKey': 'accessKey',
        'secretKey': 'secretKey',
        'feedType': ['Domain']
    }

    # Test module
    mocker.patch('SecurityIntelligenceServicesFeed.demisto.params', return_value=params)
    mocker.patch('SecurityIntelligenceServicesFeed.demisto.command', return_value='test-module')
    mocker.patch('SecurityIntelligenceServicesFeed.Client.request_list_objects')
    assert main() is None

    # Sis get indicators
    fetch_indicators_response = [{'value': '007blog.icu',
                                  'type': 'Domain',
                                  'rawJSON': OrderedDict([('value', '007blog.icu'),
                                                          ('Timestamp', '1590810346'),
                                                          ('type', 'Domain')]),
                                  'fields': {'threattypes': {'threatcategory': 'Domain'},
                                             'region': 'us-west-1',
                                             'service': 'S3',
                                             'firstseenbysource': formatEpochDate(1590810346),
                                             'timestamp': '1590810346'}}]
    mocker.patch('SecurityIntelligenceServicesFeed.demisto.command', return_value='sis-get-indicators')
    mocker.patch('SecurityIntelligenceServicesFeed.return_results')
    mocker.patch('SecurityIntelligenceServicesFeed.fetch_indicators_command', return_value=fetch_indicators_response)
    assert main() is None

    # Fetch indicators
    mocker.patch('SecurityIntelligenceServicesFeed.demisto.command', return_value='fetch-indicators')
    mocker.patch('SecurityIntelligenceServicesFeed.fetch_indicators_command', return_value=[['test']])
    mocker.patch.object(demistomock, 'createIndicators', create=True)
    assert main() is None


def test_build_iterator(mocker):
    """
    Tests the various scenarios of build iterator.
    """

    mocker.patch('boto3.s3.transfer.S3Transfer.download_file')
    # When is_get_indicators parameter is False.
    import csv
    mocker.patch.object(gzip, 'open', return_value=['007blog.icu\t1590810346',
                                                    '0122312.com\t1590809115',
                                                    '0666639.cn\t1590812070'], create=True)
    assert isinstance(next(CLIENT.build_iterator(feed_type='domain', key='key')), csv.DictReader)

    mocker.patch('boto3.s3.transfer.S3Transfer.download_file')
    mocker.patch.object(gzip, 'open', create=True)
    mocker.patch('os.remove')
    with pytest.raises(StopIteration):
        next(CLIENT.build_iterator(feed_type='Domain', key='key'))

    # With limit parameter.
    with open('./TestData/response_get_object.json') as f:
        expected_response = json.load(f)
    event_stream = [{
        'Records': {
            'Payload': b'\x68\x65\x6C\x6C\x6F\x5C\x74\x31\x32\x33\x31\x32\x5C\x6E'
        },
        'end': {}
    }]
    expected_response['Payload'] = event_stream
    mocker.patch('botocore.client.BaseClient._make_api_call', return_value=expected_response)
    assert isinstance(next(CLIENT.build_iterator(feed_type='Domain', key='key', limit='1', is_get_indicators=True)),
                      csv.DictReader)

    del expected_response['Payload'][0]['Records']
    assert isinstance(next(CLIENT.build_iterator(feed_type='Domain', key='key', limit='1', is_get_indicators=True)),
                      csv.DictReader)


def test_build_iterator_client_error(mocker):
    """
    Tests, Handle error occur during extracting feeds.
    """
    with open('./TestData/response_list_object.json') as f:
        expected_response = json.load(f)
    expected_response['ResponseMetadata']['HTTPStatusCode'] = 400
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.ClientError(expected_response, ''))
    with pytest.raises(ValueError) as v_error:
        next(CLIENT.build_iterator(feed_type='bucket', key='key'))
    assert str(v_error.value.args[0]) == MESSAGES['BAD_REQUEST_ERROR']


def test_build_iterator_proxy_error(mocker):
    """
    Tests, Handle proxy error received while list_objects from build iterator s3.
    """
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.ProxyConnectionError(proxy_url='proxy_url'))
    with pytest.raises(ValueError) as v_error:
        next(CLIENT.build_iterator(feed_type='bucket', key='key'))
    assert str(v_error.value.args[0]) == MESSAGES['PROXY_ERROR'] + 'Failed to connect to proxy URL: "proxy_url"'


def test_build_iterator_http_client_error(mocker):
    """
    When any parameter is invalid and HTTPClientException occurs.
    Tests, Handle HTTPClientException received while list_objects from build iterator s3.
    """
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.HTTPClientError(error=''))
    with pytest.raises(ValueError) as v_error:
        next(CLIENT.build_iterator(feed_type='bucket', key='key'))
    assert str(v_error.value.args[0]) == MESSAGES[
        'HTTP_CLIENT_ERROR'] + 'An HTTP Client raised an unhandled exception: '


def test_build_iterator_error(mocker):
    """
    Tests, Handle any other exception received while list_objects from s3..
    """
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=Exception(''))
    with pytest.raises(ValueError) as v_error:
        next(CLIENT.build_iterator(feed_type='bucket', key='key'))
    assert str(v_error.value.args[0]) == MESSAGES['ERROR']


def test_test_module_client_error(mocker):
    """
    Tests, Handle error occur during extracting feeds.
    """
    from SecurityIntelligenceServicesFeed import test_module
    with open('./TestData/response_list_object.json') as f:
        expected_response = json.load(f)
    expected_response['ResponseMetadata']['HTTPStatusCode'] = 400
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.ClientError(expected_response, ''))
    with pytest.raises(ValueError) as v_error:
        test_module(CLIENT, 'domain')
    assert str(v_error.value.args[0]) == MESSAGES['BAD_REQUEST_ERROR']


def test_test_module_proxy_error(mocker):
    """
    Tests, Handle proxy error received while list_objects from build iterator s3.
    """
    from SecurityIntelligenceServicesFeed import test_module
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.ProxyConnectionError(proxy_url='proxy_url'))
    with pytest.raises(ValueError) as v_error:
        test_module(CLIENT, 'domain')
    assert str(v_error.value.args[0]) == MESSAGES['PROXY_ERROR'] + 'Failed to connect to proxy URL: "proxy_url"'


def test_test_module_http_client_error(mocker):
    """
    When any parameter is invalid and HTTPClientException occurs.
    Tests, Handle HTTPClientException received while list_objects from build iterator s3.
    """
    from SecurityIntelligenceServicesFeed import test_module
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=botocore.exceptions.HTTPClientError(error=''))
    with pytest.raises(ValueError) as v_error:
        test_module(CLIENT, 'domain')
    assert str(v_error.value.args[0]) == MESSAGES[
        'HTTP_CLIENT_ERROR'] + 'An HTTP Client raised an unhandled exception: '


def test_test_module_error(mocker):
    """
    Tests, Handle any other exception received while list_objects from s3..
    """
    from SecurityIntelligenceServicesFeed import test_module
    mocker.patch('botocore.client.BaseClient._make_api_call',
                 side_effect=Exception(''))
    with pytest.raises(ValueError) as v_error:
        test_module(CLIENT, 'domain')
    assert str(v_error.value.args[0]) == MESSAGES['ERROR']


def test_get_last_key_from_integration_context(mocker):
    """
    Tests, Retrieving last key form integration context.
    """
    from SecurityIntelligenceServicesFeed import get_last_key_from_integration_context_dict
    integration_context = [{
        'Domain': 'key'
    }]

    assert get_last_key_from_integration_context_dict('Domain', integration_context=integration_context) == 'key'
    assert get_last_key_from_integration_context_dict('Malware') == ''


def test_set_last_key_to_integration_context(mocker):
    """
    Tests, set last key to integration context.
    """
    from SecurityIntelligenceServicesFeed import set_last_key_to_integration_context_dict
    integration_context = [{
        'Domain': 'key'
    }]

    set_last_key_to_integration_context_dict('Domain', 'key2', integration_context=integration_context)
    assert integration_context[0].get('Domain') == 'key2'
    set_last_key_to_integration_context_dict('Malware', 'key3', integration_context=integration_context)
    assert integration_context[1].get('Malware') == 'key3'


def test_validate_limit():
    """
    Tests, limit parameter value.
    """
    from SecurityIntelligenceServicesFeed import validate_limit
    validate_limit('1')
    with pytest.raises(ValueError) as v_error:
        validate_limit('a')
    assert str(v_error.value.args[0]) == MESSAGES['INVALID_LIMIT_ERROR']

    with pytest.raises(ValueError) as v_error:
        validate_limit('1001')
    assert str(v_error.value.args[0]) == MESSAGES['INVALID_LIMIT_ERROR']


def test_fetch_indicators_command(mocker):
    """
    Tests, The work of fetch indicators command.
    """
    import csv
    from SecurityIntelligenceServicesFeed import fetch_indicators_command, datetime, timezone
    expected_response = [{'value': '007blog.icu',
                          'type': 'Domain',
                          'rawJSON': OrderedDict([('value', '007blog.icu'),
                                                  ('Timestamp', '1590810346'),
                                                  ('type', 'Domain')]),
                          'fields': {'service': 'Passive Total', 'tags': ['s3', 's4'],
                                     'firstseenbysource': datetime.fromtimestamp(1590810346,
                                                                                 timezone.utc).isoformat()}}]

    mocker.patch('SecurityIntelligenceServicesFeed.Client.request_list_objects',
                 return_value=[{'Key': 'key1.gz', 'LastModified': datetime.now(timezone.utc)}])

    mocker.patch('SecurityIntelligenceServicesFeed.Client.build_iterator',
                 return_value=[csv.DictReader(f=['007blog.icu\t1590810346'], fieldnames=['value', 'Timestamp'],
                                              delimiter='\t')])

    assert next(fetch_indicators_command(client=CLIENT, feed_types=['domain'],
                                         first_fetch_interval='1 day', tags=['s3', 's4'])) == expected_response

    # When no latest key found.
    mocker.patch('SecurityIntelligenceServicesFeed.Client.request_list_objects', return_value=[])
    mocker.patch('SecurityIntelligenceServicesFeed.get_last_key_from_integration_context_dict',
                 return_value='key1')
    mocker.patch('SecurityIntelligenceServicesFeed.Client.build_iterator',
                 return_value=[csv.DictReader(f=['007blog.icu\t1590810346'], fieldnames=['value', 'Timestamp'],
                                              delimiter='\t')])
    assert next(fetch_indicators_command(client=CLIENT, feed_types=['domain'],
                                         first_fetch_interval='0 day', limit='1',
                                         tags=['s3', 's4'])) == expected_response


def test_get_indicators_command(mocker):
    """
    Tests, The work of get indicators command.
    """
    import csv
    from SecurityIntelligenceServicesFeed import get_indicators_command, datetime, timezone
    humanreadable = '### Total indicators fetched: 1\n'
    humanreadable += '### Indicators from Security Intelligence Services feed\n'
    humanreadable += '|Value|Type|\n'
    humanreadable += '|---|---|\n'
    humanreadable += '| 007blog.icu | Domain |\n'
    expected_resp = {'Type': 1,
                     'ContentsFormat': 'json',
                     'Contents': [{'value': '007blog.icu',
                                   'type': 'Domain',
                                   'rawJSON': OrderedDict(
                                       [('value', '007blog.icu'),
                                        ('Timestamp', '1590810346'),
                                        ('type', 'Domain')]),
                                   'fields':
                                       {'service': 'Passive Total',
                                        'firstseenbysource': datetime.fromtimestamp(1590810346,
                                                                                    timezone.utc).isoformat()}}],
                     'HumanReadable': humanreadable,
                     'EntryContext': {},
                     'IndicatorTimeline': [],
                     'IgnoreAutoExtract': False}

    mocker.patch('SecurityIntelligenceServicesFeed.Client.request_list_objects',
                 return_value=[{'Key': 'key1.gz', 'LastModified': datetime.now(timezone.utc)}])

    mocker.patch('SecurityIntelligenceServicesFeed.Client.build_iterator',
                 return_value=[csv.DictReader(f=['007blog.icu\t1590810346'], fieldnames=['value', 'Timestamp'],
                                              delimiter='\t',
                                              quoting=csv.QUOTE_NONE)])
    args = {
        'feed_type': 'Domain',
        'limit': 1
    }
    resp = get_indicators_command(CLIENT, args)
    assert resp.to_context() == expected_resp

    # No records
    mocker.patch('SecurityIntelligenceServicesFeed.Client.build_iterator',
                 return_value=csv.DictReader(f='', fieldnames=['value', 'Timestamp'], delimiter='\t'))
    resp = get_indicators_command(CLIENT, args)
    assert resp == MESSAGES['NO_INDICATORS_FOUND']


def test_indicator_field_mapping():
    """
    Tests, indicator field mapping for various feed.
    """
    from SecurityIntelligenceServicesFeed import indicator_field_mapping, datetime, timezone
    expected_res = {'service': 'Passive Total',
                    'firstseenbysource': datetime.fromtimestamp(1590810346, timezone.utc).isoformat(), 'tags': ['s3']}
    assert indicator_field_mapping('domain', {'value': '007blog.icu', 'Timestamp': '1590810346'},
                                   tags=['s3'], tlp_color='') == expected_res

    expected_res = {'service': 'Passive Total', 'siscategory': 'category',
                    'threattypes': [{'threatcategory': 'Phishing'}],
                    'sismatchtype': 'type',
                    'sisexpiration': '2020-06-15T00:25:44+00:00', 'tags': ['s3'],
                    'trafficlightprotocol': 'AMBER'}

    assert indicator_field_mapping('phish', {'value': '007blog.icu', 'type': 'URL', 'MatchType': 'type',
                                             'Category': 'category',
                                             'Expiration': '2020-06-15 00:25:44.0',
                                             }, tags=['s3'], tlp_color='AMBER') == expected_res
    expected_res = {'service': 'Passive Total', 'sismalwaretype': 'category',
                    'threattypes': [{'threatcategory': 'Malware'}],
                    'sismatchtype': 'type',
                    'sisexpiration': '2020-06-15T00:25:44+00:00', 'tags': ['s3']}

    assert indicator_field_mapping('malware',
                                   {'value': '007blog.icu', 'type': 'URL', 'MatchType': 'type',
                                    'MaliciousExpiration': '2020-06-15 00:25:44.0',
                                    'MalwareType': 'category',
                                    'Expiration': '2020-06-15 00:25:44.0',
                                    }, tags=['s3'], tlp_color=None) == expected_res


@pytest.mark.parametrize('first_fetch_interval', ['invalid_str_value', '1day', ' '])
def test_validate_first_fetch_interval_when_invalid_value(first_fetch_interval):
    """
    Tests, when invalid value is provided for first fetch interval, value error should raise.
    """
    from SecurityIntelligenceServicesFeed import validate_first_fetch_interval

    with pytest.raises(ValueError) as e:
        validate_first_fetch_interval(first_fetch_interval)

    assert MESSAGES['INVALID_FIRST_FETCH_INTERVAL_ERROR'] == str(e.value)


@pytest.mark.parametrize('first_fetch_interval', ['2 dfhdj', '2 daysss'])
def test_validate_first_fetch_interval_when_invalid_unit(first_fetch_interval):
    """
    Tests, when invalid unit is provided for first fetch interval, value error should raise.
    """
    from SecurityIntelligenceServicesFeed import validate_first_fetch_interval

    with pytest.raises(ValueError) as e:
        validate_first_fetch_interval(first_fetch_interval)

    assert MESSAGES['INVALID_FIRST_FETCH_UNIT_ERROR'] == str(e.value)
