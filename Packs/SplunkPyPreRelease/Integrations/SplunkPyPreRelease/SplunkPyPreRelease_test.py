from copy import deepcopy
import pytest
from splunklib import client
from splunklib.binding import AuthenticationError

import SplunkPyPreRelease as splunk
import demistomock as demisto
from CommonServerPython import *
from datetime import datetime, timedelta


RETURN_ERROR_TARGET = 'SplunkPyPreRelease.return_error'
SPLUNK_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

DICT_RAW_RESPONSE = '"1528755951, search_name="NG_SIEM_UC25- High number of hits against ' \
                    'unknown website from same subnet", action="allowed", dest="bb.bbb.bb.bbb , cc.ccc.ccc.cc , ' \
                    'xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", distinct_hosts="5", ' \
                    'first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , 06/11/18 17:37:55 , 06/11/18 17:41:28 , ' \
                    '06/11/18 17:42:05 , 06/11/18 17:42:38", info_max_time="+Infinity", info_min_time="0.000", ' \
                    'src="xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", u_category="unknown", ' \
                    'user="xyz\\a1234 , xyz\\b5678 , xyz\\c91011 , xyz\\d121314 , unknown", website="2.2.2.2""'

LIST_RAW = 'Feb 13 09:02:55 1,2020/02/13 09:02:55,001606001116,THREAT,url,' \
           '1,2020/02/13 09:02:55,10.1.1.1,1.2.3.4,0.0.0.0,0.0.0.0,rule1,jordy,,web-browsing,vsys1,trust,untrust,' \
           'ethernet1/2,ethernet1/1,forwardAll,2020/02/13 09:02:55,59460,1,62889,80,0,0,0x208000,tcp,alert,' \
           '"ushship.com/xed/config.bin",(9999),not-resolved,informational,client-to-server,' \
           '0,0x0,1.1.22.22-5.6.7.8,United States,0,text/html'

RAW_WITH_MESSAGE = '{"@timestamp":"2019-10-15T13:30:08.578-04:00","message":"{"TimeStamp":"2019-10-15 13:30:08",' \
                   '"CATEGORY_1":"CONTACT","ASSOCIATEOID":"G2N2TJETBRAAX68V","HOST":' \
                   '"step-up-authentication-api.gslb.es.oneadp.com","SCOPE[4]":"PiSvcsProvider\/payroll","SCOPE[19]":' \
                   '"\/api\/events\/core\/v1\/user-status","CONTEXT":"\/smsstepup","FLOW":"API","X-REAL-IP":' \
                   '"2.2.2.2","PRODUCT_CODE":"WFNPortal","X-FORWARDED-PROTO":"http","ERROR_ID":"4008",' \
                   '"SCOPE[23]":"\/security\/notification-communication-response-value.accept","REQ_URL":' \
                   '"http:\/\/step-up-authentication-api.gslb.es.blabla.com\/smsstepup\/events\/core\/v1\/step-up-' \
                   'user-authorization-request.evaluate","SCOPE[35]":"autopay\/payroll\/v1\/cafeteria-plan-' \
                   'configurations\/{configurationItemID}","SCOPE_MATCHED":"Y","SCOPE[43]":"communication\/n' \
                   'otification-message-template.add","SCOPE[11]":"\/ISIJWSUserSecurity","SCOPE[27]":"autopay\/events' \
                   '\/payroll\/v1\/earning-configuration.add","ORGOID":"G2SY6MR3ATKA232T","SCOPE[8]":"\/' \
                   'ISIJWSAssociatesService","SCOPE[39]":"autopay\/payroll\/v1\/earning-configurations",' \
                   '"SETUP_SELF":"N","SCOPE[47]":"communication\/notification.publish","SCOPE[15]":"' \
                   '\/OrganizationSoftPurge","X-FORWARDED-HOST":"step-up-authentication-api.gslb.es.blabla.com",' \
                   '"ADP-MESSAGEID":"a1d57ed2-1fe6-4800-be7a-26cd89bhello","CNAME":"JRJG INC","CONTENT-LENGTH":' \
                   '"584","SCOPE[31]":"autopay\/events\/payroll\/v1\/earning-configuration.remove","CID":"BSTAR00044"' \
                   ',"ACTOR_UID":"ABinters@BSTAR00044","SECURE_API_MODE":"HTTPS_SECURE","X-REQUEST-ID":' \
                   '"2473a981bef27bc8444e510adc12234a","SCOPE[1]":"AVSSCP\/Docstash\/Download","SCOPE[18]":' \
                   '"\/api\/events\/core\/v1\/product-role.assign","BLOCK_SESSION":"Y","CONSUMER_ID":' \
                   '"ab2e715e-41c4-43d6-bff7-fc2d713hello","SCOPE[34]":"autopay\/payroll\/v1\/cafeteria-plan-' \
                   'configurations","SCOPE[46]":"communication\/notification-message-template.remove","MODULE":' \
                   '"STEPUP_API","SCOPE[9]":"\/ISIJWSClientService","SCOPE[10]":"\/ISIJWSJobsService","SCOPE[22]":' \
                   '"\/api\/person-account-registration","SCOPE[38]":"autopay\/payroll\/v1\/deposit-configurations",' \
                   '"SUBJECT_ORGOID":"G2SY6MR3ATKA232T","SCOPE[5]":"\/Associate","SCOPE[14]":"\/Organization",' \
                   '"SCOPE[26]":"WFNSvcsProvider\/payrollPi","EVENT_ID":"9ea87118-5679-5b0e-a67f-1abd8ccabcde",' \
                   '"SCOPE[30]":"autopay\/events\/payroll\/v1\/earning-configuration.payroll-accumulators.modify",' \
                   '"X-FORWARDED-PORT":"80","SCOPE[42]":"autopay\/payroll\/v1\/worker-employment-records","JTI":' \
                   '"867b6d06-47cf-40ab-8dd7-bd0d57babcde","X-DOMAIN":"secure.api.es.abc.com","SOR_CODE":' \
                   '"WFNPortal","SCOPE[29]":"autopay\/events\/payroll\/v1\/earning-configuration.configuration' \
                   '-tags.modify","SCOPE[2]":"AVSSCP\/Docstash\/Get","OUTPUT_TYPE":"FAIL","ERR_MSG":"BLOCK_SESSION",' \
                   '"TRANS_ID":"3AF-D30-7CTTCQ","SCOPE[45]":"communication\/notification-message-template.read",' \
                   '"USE_HISTORY":"Y","SCHEME":"http","SCOPE[13]":"\/ISIJWSUsersService","SCOPE[21]":"\/api\/person",' \
                   '"SCOPE[33]":"autopay\/events\/payroll\/v1\/worker-insurable-payments.modify","X-FORWARDED-FOR":' \
                   '"8.8.8.8, 10.10.10.10, 1.2.3.4, 5.6.7.8","SCOPE[17]":"\/api\/core\/v1\/organization",' \
                   '"SCOPE[25]":"\/step-up-user-authorization.initiate","SCOPE[6]":"\/Associate\/PIC","SCOPE[37]":' \
                   '"autopay\/payroll\/v1\/cafeteria-plan-configurations\/{configurationItemID}\/' \
                   'payroll-item-configurations\/{payrollItemID}","FLOW_TYPE":"REST","SCOPE[41]":' \
                   '"autopay\/payroll\/v1\/payroll-output","CONSUMERAPPOID":"WFNPortal","RESOURCE":' \
                   '"\/events\/core\/v1\/step-up-user-authorization-request.evaluate","USER-AGENT":' \
                   '"Apache-HttpClient\/4.5.5 (Java\/10.0.1)","SCOPE[3]":"AVSSCP\/Docstash\/List",' \
                   '"SUB_CATEGORY_1":"worker.businessCommunication.email.change","TIME":"9","X-SCHEME":' \
                   '"http","ADP-CONVERSATIONID":"stY46PpweABoT5JX04CZGCeBbX8=","SCOPE[12]":' \
                   '"\/ISIJWSUserSecurityService","SCOPE[24]":"\/step-up-user-authorization-request.evaluate",' \
                   '"SCOPE[32]":"autopay\/events\/payroll\/v1\/retro-pay-request.add","SCOPE[44]":' \
                   '"communication\/notification-message-template.change","ACTION":"POST","SCOPE[7]":' \
                   '"\/AssociateSoftPurge","SCOPE[16]":"\/api\/authentication","X-ORIGINAL-URI":' \
                   '"\/smsstepup\/events\/core\/v1\/step-up-user-authorization-request.evaluate","SCOPE[28]":' \
                   '"autopay\/events\/payroll\/v1\/earning-configuration.change","SCOPE[36]":' \
                   '"autopay\/payroll\/v1\/cafeteria-plan-configurations\/{configurationItemID}\/payroll-item' \
                   '-configurations","SESSION_ID":"f50be909-9e4f-408d-bf77-68499012bc35","SCOPE[20]":' \
                   '"\/api\/events\/core\/v1\/user.provision","SUBJECT_AOID":"G370XX6XYCABCDE",' \
                   '"X-ORIGINAL-FORWARDED-FOR":"1.1.1.1, 3.3.3.3, 4.4.4.4","SCOPE[40]":' \
                   '"autopay\/payroll\/v1\/employer-details"}","TXID":"3AF-D30-ABCDEF","ADP-MessageID":' \
                   '"a1d57ed2-1fe6-4800-be7a-26cd89bf686d","SESSIONID":"stY46PpweFToT5JX04CZGMeCvP8=","ORGOID":' \
                   '"G2SY6MR3ATKA232T","AOID":"G2N2TJETBRAAXAAA","MSGID":"a1d57ed2-1fe6-0000-be7a-26cd89bf686d"}'

SAMPLE_RESPONSE = [{
    '_bkt': 'notable~668~66D21DF4-F4FD-4886-A986-82E72ADCBFE9',
    '_cd': '668:17198',
    '_indextime': '1596545116',
    '_raw': '1596545116, search_name="Endpoint - Recurring Malware Infection - Rule", count="17", '
            'day_count="8", dest="ACME-workstation-012", info_max_time="1596545100.000000000", '
            'info_min_time="1595939700.000000000", info_search_time="1596545113.965466000", '
            'signature="Trojan.Gen.2"',
    '_serial': '50',
    '_si': ['ip-172-31-44-193', 'notable'],
    '_sourcetype': 'stash',
    '_time': '2020-08-04T05:45:16.000-07:00',
    'dest': 'ACME-workstation-012',
    'dest_asset_id': '028877d3c80cb9d87900eb4f9c9601ea993d9b63',
    'dest_asset_tag': ['cardholder', 'pci', 'americas'],
    'dest_bunit': 'americas',
    'dest_category': ['cardholder', 'pci'],
    'dest_city': 'Pleasanton',
    'dest_country': 'USA',
    'dest_ip': '192.168.3.12',
    'dest_is_expected': 'TRUE',
    'dest_lat': '37.694452',
    'dest_long': '-121.894461',
    'dest_nt_host': 'ACME-workstation-012',
    'dest_pci_domain': ['trust', 'cardholder'],
    'dest_priority': 'medium',
    'dest_requires_av': 'TRUE',
    'dest_risk_object_type': 'system',
    'dest_risk_score': '15680',
    'dest_should_timesync': 'TRUE',
    'dest_should_update': 'TRUE',
    'host': 'ip-172-31-44-193',
    'host_risk_object_type': 'system',
    'host_risk_score': '0',
    'index': 'notable',
    'linecount': '1',
    'priorities': 'medium',
    'priority': 'medium',
    'risk_score': '15680',
    'rule_description': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_name': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_title': 'Endpoint - Recurring Malware Infection - Rule',
    'security_domain': 'Endpoint - Recurring Malware Infection - Rule',
    'severity': 'unknown',
    'signature': 'Trojan.Gen.2',
    'source': 'Endpoint - Recurring Malware Infection - Rule',
    'sourcetype': 'stash',
    'splunk_server': 'ip-172-31-44-193',
    'urgency': 'low'
}]

EXPECTED = {
    "action": "allowed",
    "dest": "bb.bbb.bb.bbb , cc.ccc.ccc.cc , xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa",
    "distinct_hosts": '5',
    "first_3_octets": "1.1.1",
    "first_time": "06/11/18 17:34:07 , 06/11/18 17:37:55 , 06/11/18 17:41:28 , 06/11/18 17:42:05 , 06/11/18 17:42:38",
    "info_max_time": "+Infinity",
    "info_min_time": '0.000',
    "search_name": "NG_SIEM_UC25- High number of hits against unknown website from same subnet",
    "src": "xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa",
    "u_category": "unknown",
    "user": "xyz\\a1234 , xyz\\b5678 , xyz\\c91011 , xyz\\d121314 , unknown",
    "website": "2.2.2.2"
}

URL_TESTING_IN = '"url="https://test.com?key=val"'
URL_TESTING_OUT = {'url': 'https://test.com?key=val'}

# checking a case where the last character for each value was cut
RESPONSE = 'NAS-IP-Address=2.2.2.2, NAS-Port=50222, NAS-Identifier=de-wilm-251littl-idf3b-s2, NAS-Port-Type=' \
           'Ethernet, NAS-Port-Id=GigabitEthernet2/0/05'

POSITIVE = {
    "NAS-IP-Address": "2.2.2.2",
    "NAS-Identifier": "de-wilm-251littl-idf3b-s2",
    "NAS-Port": "50222",
    "NAS-Port-Id": "GigabitEthernet2/0/05",
    "NAS-Port-Type": "Ethernet"
}

# testing the ValueError and json sections
RAW_JSON = '{"Test": "success"}'
RAW_STANDARD = '"Test="success"'
RAW_JSON_AND_STANDARD_OUTPUT = {"Test": "success"}


def test_raw_to_dict():
    actual_raw = DICT_RAW_RESPONSE
    response = splunk.rawToDict(actual_raw)
    list_response = splunk.rawToDict(LIST_RAW)
    raw_message = splunk.rawToDict(RAW_WITH_MESSAGE)
    empty = splunk.rawToDict('')
    url_test = splunk.rawToDict(URL_TESTING_IN)
    character_check = splunk.rawToDict(RESPONSE)

    assert EXPECTED == response
    assert {} == list_response
    assert raw_message.get('SCOPE[29]') == 'autopay\/events\/payroll\/v1\/earning-configuration.configuration-tags' \
                                           '.modify'
    assert isinstance(raw_message, dict)
    assert empty == {}
    assert URL_TESTING_OUT == url_test
    assert POSITIVE == character_check
    assert splunk.rawToDict(RAW_JSON) == RAW_JSON_AND_STANDARD_OUTPUT
    assert splunk.rawToDict(RAW_STANDARD) == RAW_JSON_AND_STANDARD_OUTPUT


@pytest.mark.parametrize('text, output', [
    ('', ['']),
    ('"",', ['"",']),
    #   a value shouldn't do anything special
    ('woopwoop', ['woopwoop']),
    #  a normal key value without quotes
    ('abc=123', ['abc="123"']),
    #  add a comma at the end
    ('abc=123,', ['abc="123"']),
    #  a normal key value with quotes
    ('cbd="123"', ['cbd="123"']),
    #  check all wrapped with quotes removed
    ('"abc="123""', ['abc="123"']),
    #   we need to remove 111 at the start.
    ('111, cbd="123"', ['cbd="123"']),
    # Testing with/without quotes and/or spaces:
    ('abc=123,cbd=123', ['abc="123"', 'cbd="123"']),
    ('abc=123,cbd="123"', ['abc="123"', 'cbd="123"']),
    ('abc="123",cbd=123', ['abc="123"', 'cbd="123"']),
    ('abc="123",cbd="123"', ['abc="123"', 'cbd="123"']),
    ('abc=123, cbd=123', ['abc="123"', 'cbd="123"']),
    ('abc=123, cbd="123"', ['abc="123"', 'cbd="123"']),
    ('cbd="123", abc=123', ['abc="123"', 'cbd="123"']),
    ('cbd="123",abc=123', ['abc="123"', 'cbd="123"']),
    # Continue testing quotes with more values:
    ('xyz=321,cbd=123,abc=123', ['xyz="321"', 'abc="123"', 'cbd="123"']),
    ('xyz=321,cbd="123",abc=123', ['xyz="321"', 'abc="123"', 'cbd="123"']),
    ('xyz="321",cbd="123",abc=123', ['xyz="321"', 'abc="123"', 'cbd="123"']),
    ('xyz="321",cbd="123",abc="123"', ['xyz="321"', 'abc="123"', 'cbd="123"']),
    # Testing nested quotes (the main reason for quote_group):
    #   Try to remove the start 111.
    ('111, cbd="a="123""', ['cbd="a="123""']),
    ('cbd="a="123""', ['cbd="a="123""']),
    ('cbd="a="123", b=321"', ['cbd="a="123", b="321""']),
    ('cbd="a=123, b=321"', ['cbd="a="123", b="321""']),
    ('cbd="a=123, b="321""', ['cbd="a="123", b="321""']),
    ('cbd="a="123", b="321""', ['cbd="a="123", b="321""']),
    ('cbd="a=123, b=321"', ['cbd="a="123", b="321""']),
    ('xyz=123, cbd="a="123", b=321"', ['xyz="123"', 'cbd="a="123", b="321""']),
    ('xyz="123", cbd="a="123", b="321""', ['xyz="123"', 'cbd="a="123", b="321""']),
    ('xyz="123", cbd="a="123", b="321"", qqq=2', ['xyz="123"', 'cbd="a="123", b="321""', 'qqq="2"']),
    ('xyz="123", cbd="a="123", b="321"", qqq="2"', ['xyz="123"', 'cbd="a="123", b="321""', 'qqq="2"']),
])
def test_quote_group(text, output):
    assert sorted(splunk.quote_group(text)) == sorted(output)


data_test_replace_keys = [
    ({}, {}),
    ({'test': 'test'}, {'test': 'test'}),
    ({'test.': 'test.'}, {'test_': 'test.'}),
    ({'te.st': 'te.st'}, {'te_st': 'te.st'}),
    ({'te[st': 'te[st'}, {'te_st': 'te[st'}),
    ({'te]st': 'te]st'}, {'te_st': 'te]st'}),
    ({'te)st': 'te)st'}, {'te_st': 'te)st'}),
    ({'te(st': 'te(st'}, {'te_st': 'te(st'}),
    ('', ''),
    (None, None)
]


@pytest.mark.parametrize('dict_in, dict_out', data_test_replace_keys)
def test_replace_keys(dict_in, dict_out):
    out = splunk.replace_keys(deepcopy(dict_in))
    assert out == dict_out, 'replace_keys({}) got: {} instead: {}'.format(dict_in, out, dict_out)


def test_parse_time_to_minutes_no_error():
    splunk.FETCH_TIME = '3 hours'
    res = splunk.parse_time_to_minutes()
    assert res == 180


def test_parse_time_to_minutes_invalid_time_integer(mocker):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    splunk.FETCH_TIME = 'abc hours'
    splunk.parse_time_to_minutes()
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == "Error: Invalid fetch time, need to be a positive integer with the time unit afterwards " \
                      "e.g '2 months, 4 days'."


def test_parse_time_to_minutes_invalid_time_unit(mocker):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    splunk.FETCH_TIME = '3 hoursss'
    splunk.parse_time_to_minutes()
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: Invalid time unit.'


SEARCH_RESULT = [
    {
        "Something": "regular",
        "But": {
            "This": "is"
        },
        "Very": "Unique"
    },
    {
        "Something": "natural",
        "But": {
            "This": "is a very very"
        },
        "Very": "Unique and awesome"
    }
]
REGULAR_ALL_CHOSEN_FIELDS = [
    "Something",
    "But",
    "Very"
]
REGULAR_CHOSEN_FIELDS_SUBSET = [
    "Something",
    "Very"
]
REGEX_CHOSEN_FIELDS_SUBSET = [
    "Some*",
    "Very"
]
NON_EXISTING_FIELDS = [
    "SDFAFSD",
    "ASBLFKDJK"
]


@pytest.mark.parametrize('search_result, chosen_fields, expected_result', [
    (SEARCH_RESULT, REGULAR_ALL_CHOSEN_FIELDS, REGULAR_ALL_CHOSEN_FIELDS),
    (SEARCH_RESULT, REGULAR_CHOSEN_FIELDS_SUBSET, REGULAR_CHOSEN_FIELDS_SUBSET),
    (SEARCH_RESULT, REGEX_CHOSEN_FIELDS_SUBSET, REGULAR_CHOSEN_FIELDS_SUBSET),
    (SEARCH_RESULT, NON_EXISTING_FIELDS, []),
])
def test_commands(search_result, chosen_fields, expected_result):
    from SplunkPyPreRelease import update_headers_from_field_names
    headers = update_headers_from_field_names(search_result, chosen_fields)

    assert expected_result == headers


APPS = ['app']
STORES = ['store']
EMPTY_CASE = {}
STORE_WITHOUT_APP = {"kv_store_collection_name": "test"}
JUST_APP_NAME = {'app_name': 'app'}  # happens in splunk-kv-store-collections-list command
CREATE_COMMAND = {'app_name': 'app', 'kv_store_name': 'not_store'}
CORRECT = {'app_name': 'app', 'kv_store_collection_name': 'store'}
INCORRECT_STORE_NAME = {'app_name': 'app', 'kv_store_collection_name': 'not_store'}
data_test_check_error = [
    (EMPTY_CASE, 'app not found'),
    (STORE_WITHOUT_APP, 'app not found'),
    (JUST_APP_NAME, 'empty'),
    (CREATE_COMMAND, 'empty'),
    (CORRECT, 'empty'),
    (INCORRECT_STORE_NAME, 'KV Store not found'),
]


@pytest.mark.parametrize('args, out_error', data_test_check_error)
def test_check_error(args, out_error):
    class Service:
        def __init__(self):
            self.apps = APPS
            self.kvstore = STORES

    try:
        splunk.check_error(Service(), args)
        raise splunk.DemistoException('empty')
    except splunk.DemistoException as error:
        output = str(error)
    assert output == out_error, 'check_error(service, {})\n\treturns: {}\n\tinstead: {}'.format(args,
                                                                                                output, out_error)


EMPTY_CASE = {}
JUST_KEY = {"key": "key"}
WITH_ALL_PARAMS = {"key": "demisto", "value": "is awesome", "limit": 1, "query": "test"}
STANDARD_KEY_VAL = {"key": "demisto", "value": "is awesome"}
KEY_AND_LIMIT = {"key": "key", "limit": 1}
KEY_AND_QUERY = {"key": "key", "query": 'test_query'}
QUERY = {"query": 'test_query'}
QUERY_AND_VALUE = {"query": 'test_query', "value": "awesome"}
data_test_build_kv_store_query = [
    (EMPTY_CASE, str(EMPTY_CASE)),
    (JUST_KEY, str(EMPTY_CASE)),
    (STANDARD_KEY_VAL, '{"demisto": "is awesome"}'),
    (WITH_ALL_PARAMS, '{"demisto": "is awesome"}'),
    (KEY_AND_LIMIT, {"limit": 1}),
    (KEY_AND_QUERY, 'test_query'),
    (QUERY, 'test_query'),
    (QUERY_AND_VALUE, 'test_query'),
]


@pytest.mark.parametrize('args, expected_query', data_test_build_kv_store_query)
def test_build_kv_store_query(args, expected_query, mocker):
    mocker.patch('SplunkPyPreRelease.get_key_type', return_value=None)
    output = splunk.build_kv_store_query(None, args)
    assert output == expected_query, 'build_kv_store_query({})\n\treturns: {}\n\tinstead: {}'.format(args, output,
                                                                                                     expected_query)


data_test_build_kv_store_query_with_key_val = [
    ({"key": "demisto", "value": "is awesome"}, str, '{"demisto": "is awesome"}'),
    ({"key": "demisto", "value": "1"}, int, '{"demisto": 1}'),
    ({"key": "demisto", "value": "True"}, bool, '{"demisto": true}'),
]


@pytest.mark.parametrize('args, _type, expected_query', data_test_build_kv_store_query_with_key_val)
def test_build_kv_store_query_with_key_val(args, _type, expected_query, mocker):
    mocker.patch('SplunkPyPreRelease.get_key_type', return_value=_type)
    output = splunk.build_kv_store_query(None, args)
    assert output == expected_query, 'build_kv_store_query({})\n\treturns: {}\n\tinstead: {}'.format(args, output,
                                                                                                     expected_query)

    test_test_get_key_type = [
        ({'field.key': 'number'}, float),
        ({'field.key': 'string'}, str),
        ({'field.key': 'cidr'}, str),
        ({'field.key': 'boolean'}, bool),
        ({'field.key': 'empty'}, None),
        ({'field.key': 'time'}, str),
    ]

    @pytest.mark.parametrize('keys_and_types, expected_type', test_test_get_key_type)
    def test_get_key_type(keys_and_types, expected_type, mocker):
        mocker.patch('SplunkPyPreRelease.get_keys_and_types', return_value=keys_and_types)

        output = splunk.get_key_type(None, 'key')
        assert output == expected_type, 'get_key_type(kv_store, key)\n\treturns: {}\n\tinstead: {}'.format(output,
                                                                                                           expected_type)


EMPTY_CASE = {}
WITHOUT_FIELD = {'empty': 'number'}
STRING_FIELD = {'field.test': 'string'}
NUMBER_FIELD = {'field.test': 'number'}
INDEX = {'index.test': 'string'}
MIXED = {'field.test': 'string', 'empty': 'field'}
data_test_get_keys_and_types = [
    (EMPTY_CASE, EMPTY_CASE),
    (WITHOUT_FIELD, EMPTY_CASE),
    (STRING_FIELD, {'field.test': 'string'}),
    (NUMBER_FIELD, {'field.test': 'number'}),
    (INDEX, {'index.test': 'string'}),
    (MIXED, {'field.test': 'string'}),
]


@pytest.mark.parametrize('raw_keys, expected_keys', data_test_get_keys_and_types)
def test_get_keys_and_types(raw_keys, expected_keys):
    class KVMock:
        def __init__(self):
            pass

        def content(self):
            return raw_keys

    output = splunk.get_keys_and_types(KVMock())
    assert output == expected_keys, 'get_keys_and_types(kv_store)\n\treturns: {}\n\tinstead: {}'.format(output,
                                                                                                        expected_keys)


START_OUTPUT = '#### configuration for {} store\n| field name | type |\n| --- | --- |'.format('name')
EMPTY_OUTPUT = ''
STANDARD_CASE = {'field.test': 'number'}
STANDARD_OUTPUT = '\n| field.test | number |'
data_test_get_kv_store_config = [
    ({}, EMPTY_OUTPUT),
    (STANDARD_CASE, STANDARD_OUTPUT)
]


@pytest.mark.parametrize('fields, expected_output', data_test_get_kv_store_config)
def test_get_kv_store_config(fields, expected_output, mocker):
    class Name:
        def __init__(self):
            self.name = 'name'

    mocker.patch('SplunkPyPreRelease.get_keys_and_types', return_value=fields)
    output = splunk.get_kv_store_config(Name())
    expected_output = '{}{}'.format(START_OUTPUT, expected_output)
    assert output == expected_output


SPLUNK_RESULTS = [
    {
        "rawJSON":
            '{"source": "This is the alert type", "field_name1": "field_val1", "field_name2": "field_val2"}',
        "details": "Endpoint - High Or Critical Priority Host With Malware - Rule",
        "labels": [
            {
                "type": "security_domain",
                "value": "Endpoint - High Or Critical Priority Host With Malware - Rule"
            }
        ],
    }
]

EXPECTED_OUTPUT = {
    'This is the alert type': {
        "source": "This is the alert type",
        "field_name1": "field_val1",
        "field_name2": "field_val2"
    }

}


def test_create_mapping_dict():
    mapping_dict = splunk.create_mapping_dict(SPLUNK_RESULTS, type_field='source')
    assert mapping_dict == EXPECTED_OUTPUT


def test_fetch_notables(mocker):
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", 'enabled_enrichments': []}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.ResultsReader', return_value=SAMPLE_RESPONSE)
    splunk.fetch_notables(service, enrich_notables=False)
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                   "Recurring Malware Infection - Rule"


""" ========== Enriching Fetch Mechanism Tests ========== """


@pytest.mark.parametrize('integration_context, output', [
    ({splunk.INCIDENTS: ['incident']}, ['incident']),
    ({splunk.INCIDENTS: []}, []),
    ({}, [])
])
def test_fetch_incidents_for_mapping(integration_context, output, mocker):
    """
    Scenario: When a user configures a mapper using Fetch from Instance when the enrichment mechanism is working,
     we save the ready incidents in the integration context.

    Given:
    - List of ready incidents
    - An empty list of incidents
    - An empty integration context object

    When:
    - fetch_incidents_for_mapping is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'incidents')
    splunk.fetch_incidents_for_mapping(integration_context)
    assert demisto.incidents.call_count == 1
    assert demisto.incidents.call_args[0][0] == output


def test_reset_enriching_fetch_mechanism(mocker):
    """
    Scenario: When a user is willing to reset the enriching fetch mechanism and start over.

    Given:
    - An integration context object with not empty Cache and incidents

    When:
    - reset_enriching_fetch_mechanism is called

    Then:
    - Check that the integration context does not contain this fields
    """
    integration_context = {
        splunk.CACHE: "cache_string",
        splunk.INCIDENTS: ['i1', 'i2'],
        'wow': 'wow'
    }
    mocker.patch('SplunkPyPreRelease.get_integration_context', return_value=integration_context)
    mocker.patch('SplunkPyPreRelease.set_integration_context')
    splunk.reset_enriching_fetch_mechanism()
    assert integration_context == {'wow': 'wow'}


@pytest.mark.parametrize('drilldown_creation_time, asset_creation_time, enrichment_timeout, output', [
    (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), 5, False),
    ((datetime.utcnow() - timedelta(minutes=6)).isoformat(), datetime.utcnow().isoformat(), 5, True)
])
def test_is_enrichment_exceeding_timeout(drilldown_creation_time, asset_creation_time, enrichment_timeout, output):
    """
    Scenario: When one of the notable's enrichments is exceeding the timeout, we want to create an incident we all
     the data gathered so far.

    Given:
    - Two enrichments that none of them exceeds the timeout.
    - An enrichment exceeding the timeout and one that does not exceeds the timeout.

    When:
    - is_enrichment_process_exceeding_timeout is called

    Then:
    - Return the expected result
    """
    splunk.ENABLED_ENRICHMENTS = [splunk.DRILLDOWN_ENRICHMENT, splunk.ASSET_ENRICHMENT]
    notable = splunk.Notable({splunk.EVENT_ID: 'id'})
    notable.enrichments.append(splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, creation_time=drilldown_creation_time))
    notable.enrichments.append(splunk.Enrichment(splunk.ASSET_ENRICHMENT, creation_time=asset_creation_time))
    assert notable.is_enrichment_process_exceeding_timeout(enrichment_timeout) is output


INCIDENT_1 = {'name': 'incident1', 'rawJSON': json.dumps({})}
INCIDENT_2 = {'name': 'incident2', 'rawJSON': json.dumps({})}


@pytest.mark.parametrize('integration_context, incidents, output', [
    ({}, [], []),
    ({}, [INCIDENT_1, INCIDENT_2], [INCIDENT_1, INCIDENT_2])
])
def test_store_incidents_for_mapping(integration_context, incidents, output):
    """
    Scenario: Store ready incidents in integration context, to be retrieved by a user configuring a mapper
     and selecting "Fetch from instance" when the enrichment mechanism is working.

    Given:
    - An empty list of incidents
    - A list of two incidents

    When:
    - store_incidents_for_mapping is called

    Then:
    - Return the expected result
    """
    splunk.store_incidents_for_mapping(incidents, integration_context)
    assert integration_context.get(splunk.INCIDENTS, []) == output


@pytest.mark.parametrize('notable_data, raw, status, earliest, latest', [
    ({}, {}, False, "", ""),
    ({"drilldown_earliest": "${}$".format(splunk.INFO_MIN_TIME),
      "drilldown_latest": "${}$".format(splunk.INFO_MAX_TIME)},
     {splunk.INFO_MIN_TIME: '1', splunk.INFO_MAX_TIME: '2'}, True, '1', '2'),
    ({"drilldown_earliest": '1', "drilldown_latest": '2', }, {}, True, '1', '2')
])
def test_get_drilldown_timeframe(notable_data, raw, status, earliest, latest, mocker):
    """
    Scenario: Trying to get the drilldown's timeframe from the notable's data

    Given:
    - An empty notable's data
    - An notable's data that the info of the timeframe is in the raw field
    - An notable's data that the info is in the data dict

    When:
    - get_drilldown_timeframe is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(demisto, 'info')
    task_status, earliest_offset, latest_offset = splunk.get_drilldown_timeframe(notable_data, raw)
    assert task_status == status
    assert earliest_offset == earliest
    assert latest_offset == latest


@pytest.mark.parametrize('raw_field, notable_data, expected_field, expected_value', [
    ('field|s', {'field': '1'}, 'field', '1'),
    ('field', {'field': '1'}, 'field', '1'),
    ('field|s', {'_raw': 'field=1,value=2'}, 'field', '1'),
    ('x', {'y': '2'}, '', '')
])
def test_get_notable_field_and_value(raw_field, notable_data, expected_field, expected_value, mocker):
    """
    Scenario: When building the drilldown search query, we search for the field in the raw search query
     and search for its real name in the notable's data or in the notable's raw data.
     We also ignore Splunk advanced syntax such as "|s, |h, ..."

    Given:
    - A raw field that has the same name in the notable's data
    - A raw field that has "|s" as a suffix in the raw search query and its value is in the notable's data
    - A raw field that has "|s" as a suffix in the raw search query and its value is in the notable's raw data
    - A raw field that is not is the notable's data or in the notable's raw data

    When:
    - get_notable_field_and_value is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(demisto, 'error')
    field, value = splunk.get_notable_field_and_value(raw_field, notable_data)
    assert field == expected_field
    assert value == expected_value


@pytest.mark.parametrize('notable_data, search, raw, expected_search', [
    ({'a': '1', '_raw': 'c=3'}, 'search a=$a|s$ c=$c$ suffix', {'c': '3'}, 'search a="1" c="3" suffix'),
    ({'a': ['1', '2'], 'b': '3'}, 'search a=$a|s$ b=$b|s$ suffix', {}, 'search (a="1" OR a="2") b="3" suffix'),
    ({'a': '1', '_raw': 'b=3', 'event_id': '123'}, 'search a=$a|s$ c=$c$ suffix', {'b': '3'}, ''),
])
def test_build_drilldown_search(notable_data, search, raw, expected_search, mocker):
    """
    Scenario: When building the drilldown search query, we replace every field in between "$" sign with its
     corresponding query part (key & value).

    Given:
    - A raw search query with fields both in the notable's data and in the notable's raw data
    - A raw search query with fields in the notable's data that has more than one value
    - A raw search query with fields that does not exist in the notable's data or in the notable's raw data

    When:
    - build_drilldown_search is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(demisto, 'error')
    assert splunk.build_drilldown_search(notable_data, search, raw) == expected_search


@pytest.mark.parametrize('notable_data, prefix, fields, query_part', [
    ({'user': ['u1', 'u2']}, 'identity', ['user'], '(identity="u1" OR identity="u2")'),
    ({'_raw': '1233,user=u1'}, 'user', ['user'], 'user="u1"'),
    ({'user': ['u1', 'u2'], '_raw': '1321,src_user=u3'}, 'user', ['user', 'src_user'],
     '(user="u1" OR user="u2" OR user="u3")'),
    ({}, 'prefix', ['field'], '')
])
def test_get_fields_query_part(notable_data, prefix, fields, query_part):
    """
    Scenario: When building an enrichment search query, we search for values in the notable's data / notable's raw data
     and fill them in the raw search query to create a searchable query.

    Given:
    - One field with multiple values, values in the data
    - One field, value is in the raw data
    - Two fields with multiple values, values in both the data and the raw data
    - An empty notable data, field does not exists

    When:
    - get_fields_query_part is called

    Then:
    - Return the expected result
    """
    assert splunk.get_fields_query_part(notable_data, prefix, fields) == query_part


""" ========== Mirroring Mechanism Tests ========== """


@pytest.mark.parametrize('last_update, demisto_params, splunk_time_timestamp', [
    ('2021-02-22T18:39:47.753+00:00', {'timezone': '0'}, 1614019187.753),
    ('2021-02-22T18:39:47.753+02:00', {'timezone': '+120'}, 1614019187.753),
    ('2021-02-22T20:39:47.753+02:00', {'timezone': '0'}, 1614019187.753),
    ('2021-02-09T16:41:30.589575+02:00', {}, '')
])
def test_get_last_update_in_splunk_time(last_update, demisto_params, splunk_time_timestamp, mocker):
    """ Tests the conversion of the Demisto server time into timestamp in Splunk Server time

    Given:
        - The last update time in the Demisto server
        - The timezone in the Splunk Server
    When:
        Converting the time in the Demisto server into timestamp in Splunk Server time
    Then:
        - Conversion is correct
        - An Exception is raised in case that Splunk Server timezone is not specified in Demisto params

    """
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    if demisto_params:
        assert splunk.get_last_update_in_splunk_time(last_update) == splunk_time_timestamp
    else:
        error_msg = 'Cannot mirror incidents when timezone is not configured. Please enter the '
        'timezone of the Splunk server being used in the integration configuration.'
        with pytest.raises(Exception, match=error_msg):
            splunk.get_last_update_in_splunk_time(last_update)


def test_get_remote_data_command(mocker):
    updated_notable = {'status': '1', 'event_id': 'id'}

    class Jobs:
        def __init__(self):
            self.oneshot = lambda x: updated_notable

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00', 'id': 'id'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch('SplunkPyPreRelease.results.ResultsReader', return_value=[updated_notable])
    mocker.patch.object(demisto, 'results')
    splunk.get_remote_data_command(Service(), args, close_incident=False)
    results = demisto.results.call_args[0][0]
    assert demisto.results.call_count == 1
    assert results == [{'status': '1'}]


def test_get_remote_data_command_close_incident(mocker):
    updated_notable = {'status': '5', 'event_id': 'id'}

    class Jobs:
        def __init__(self):
            self.oneshot = lambda x: updated_notable

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00', 'id': 'id'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch('SplunkPyPreRelease.results.ResultsReader', return_value=[updated_notable])
    mocker.patch.object(demisto, 'results')
    splunk.get_remote_data_command(Service(), args, close_incident=True)
    results = demisto.results.call_args[0][0]
    assert demisto.results.call_count == 1
    assert results == [
        {'status': '5'},
        {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': 'Notable event was closed on Splunk.'
            },
            'ContentsFormat': EntryFormat.JSON
        }]


def test_get_modified_remote_data_command(mocker):
    updated_incidet_review = {'rule_id': 'id'}

    class Jobs:
        def __init__(self):
            self.oneshot = lambda x: [updated_incidet_review]

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch('SplunkPyPreRelease.results.ResultsReader', return_value=[updated_incidet_review])
    mocker.patch.object(demisto, 'results')
    splunk.get_modified_remote_data_command(Service(), args)
    results = demisto.results.call_args[0][0]['Contents']
    assert demisto.results.call_count == 1
    assert results == [updated_incidet_review['rule_id']]


@pytest.mark.parametrize('args, params, call_count, success', [
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}}, 3, True),
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}}, 2, False),
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}, 'close_notable': True},
     4, True)
])
def test_update_remote_system(args, params, call_count, success, mocker, requests_mock):

    class Service:
        def __init__(self):
            self.token = 'fake_token'

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    base_url = 'https://' + params['host'] + ':' + params['port'] + '/'
    requests_mock.post(base_url + 'services/auth/login', json={'sessionKey': 'session_key'})
    requests_mock.post(base_url + 'services/notable_update', json={'success': success, 'message': 'wow'})
    if not success:
        mocker.patch.object(demisto, 'error')
    assert splunk.update_remote_system_command(args, params, Service(), None) == args['remoteId']
    assert demisto.debug.call_count == call_count
    if not success:
        assert demisto.error.call_count == 1


NOTABLE = {
    'rule_name': 'string', 'rule_title': 'string', 'security_domain': 'string', 'index': 'string',
    'rule_description': 'string', 'risk_score': 'string', 'host': 'string',
    'host_risk_object_type': 'string', 'dest_risk_object_type': 'string', 'dest_risk_score': 'string',
    'splunk_server': 'string', '_sourcetype': 'string', '_indextime': 'string', '_time': 'string',
    'src_risk_object_type': 'string', 'src_risk_score': 'string', '_raw': 'string', 'urgency': 'string',
    'owner': 'string', 'info_min_time': 'string', 'info_max_time': 'string', 'comment': 'string',
    'reviewer': 'string', 'rule_id': 'string', 'action': 'string', 'app': 'string',
    'authentication_method': 'string', 'authentication_service': 'string', 'bugtraq': 'string',
    'bytes': 'string', 'bytes_in': 'string', 'bytes_out': 'string', 'category': 'string', 'cert': 'string',
    'change': 'string', 'change_type': 'string', 'command': 'string', 'comments': 'string',
    'cookie': 'string', 'creation_time': 'string', 'cve': 'string', 'cvss': 'string', 'date': 'string',
    'description': 'string', 'dest': 'string', 'dest_bunit': 'string', 'dest_category': 'string',
    'dest_dns': 'string', 'dest_interface': 'string', 'dest_ip': 'string', 'dest_ip_range': 'string',
    'dest_mac': 'string', 'dest_nt_domain': 'string', 'dest_nt_host': 'string', 'dest_port': 'string',
    'dest_priority': 'string', 'dest_translated_ip': 'string', 'dest_translated_port': 'string',
    'dest_type': 'string', 'dest_zone': 'string', 'direction': 'string', 'dlp_type': 'string',
    'dns': 'string', 'duration': 'string', 'dvc': 'string', 'dvc_bunit': 'string', 'dvc_category': 'string',
    'dvc_ip': 'string', 'dvc_mac': 'string', 'dvc_priority': 'string', 'dvc_zone': 'string',
    'file_hash': 'string', 'file_name': 'string', 'file_path': 'string', 'file_size': 'string',
    'http_content_type': 'string', 'http_method': 'string', 'http_referrer': 'string',
    'http_referrer_domain': 'string', 'http_user_agent': 'string', 'icmp_code': 'string',
    'icmp_type': 'string', 'id': 'string', 'ids_type': 'string', 'incident': 'string', 'ip': 'string',
    'mac': 'string', 'message_id': 'string', 'message_info': 'string', 'message_priority': 'string',
    'message_type': 'string', 'mitre_technique_id': 'string', 'msft': 'string', 'mskb': 'string',
    'name': 'string', 'orig_dest': 'string', 'orig_recipient': 'string', 'orig_src': 'string',
    'os': 'string', 'packets': 'string', 'packets_in': 'string', 'packets_out': 'string',
    'parent_process': 'string', 'parent_process_id': 'string', 'parent_process_name': 'string',
    'parent_process_path': 'string', 'password': 'string', 'payload': 'string', 'payload_type': 'string',
    'priority': 'string', 'problem': 'string', 'process': 'string', 'process_hash': 'string',
    'process_id': 'string', 'process_name': 'string', 'process_path': 'string', 'product_version': 'string',
    'protocol': 'string', 'protocol_version': 'string', 'query': 'string', 'query_count': 'string',
    'query_type': 'string', 'reason': 'string', 'recipient': 'string', 'recipient_count': 'string',
    'recipient_domain': 'string', 'recipient_status': 'string', 'record_type': 'string',
    'registry_hive': 'string', 'registry_key_name': 'string', 'registry_path': 'string',
    'registry_value_data': 'string', 'registry_value_name': 'string', 'registry_value_text': 'string',
    'registry_value_type': 'string', 'request_sent_time': 'string', 'request_payload': 'string',
    'request_payload_type': 'string', 'response_code': 'string', 'response_payload_type': 'string',
    'response_received_time': 'string', 'response_time': 'string', 'result': 'string',
    'return_addr': 'string', 'rule': 'string', 'rule_action': 'string', 'sender': 'string',
    'service': 'string', 'service_hash': 'string', 'service_id': 'string', 'service_name': 'string',
    'service_path': 'string', 'session_id': 'string', 'sessions': 'string', 'severity': 'string',
    'severity_id': 'string', 'sid': 'string', 'signature': 'string', 'signature_id': 'string',
    'signature_version': 'string', 'site': 'string', 'size': 'string', 'source': 'string',
    'sourcetype': 'string', 'src': 'string', 'src_bunit': 'string', 'src_category': 'string',
    'src_dns': 'string', 'src_interface': 'string', 'src_ip': 'string', 'src_ip_range': 'string',
    'src_mac': 'string', 'src_nt_domain': 'string', 'src_nt_host': 'string', 'src_port': 'string',
    'src_priority': 'string', 'src_translated_ip': 'string', 'src_translated_port': 'string',
    'src_type': 'string', 'src_user': 'string', 'src_user_bunit': 'string', 'src_user_category': 'string',
    'src_user_domain': 'string', 'src_user_id': 'string', 'src_user_priority': 'string',
    'src_user_role': 'string', 'src_user_type': 'string', 'src_zone': 'string', 'state': 'string',
    'status': 'string', 'status_code': 'string', 'status_description': 'string', 'subject': 'string',
    'tag': 'string', 'ticket_id': 'string', 'time': 'string', 'time_submitted': 'string',
    'transport': 'string', 'transport_dest_port': 'string', 'type': 'string', 'uri': 'string',
    'uri_path': 'string', 'uri_query': 'string', 'url': 'string', 'url_domain': 'string',
    'url_length': 'string', 'user': 'string', 'user_agent': 'string', 'user_bunit': 'string',
    'user_category': 'string', 'user_id': 'string', 'user_priority': 'string', 'user_role': 'string',
    'user_type': 'string', 'vendor_account': 'string', 'vendor_product': 'string', 'vlan': 'string',
    'xdelay': 'string', 'xref': 'string'
}

DRILLDOWN = {
    'Drilldown': {
        'action': 'string', 'app': 'string', 'authentication_method': 'string',
        'authentication_service': 'string', 'bugtraq': 'string', 'bytes': 'string',
        'bytes_in': 'string', 'bytes_out': 'string', 'category': 'string', 'cert': 'string',
        'change': 'string', 'change_type': 'string', 'command': 'string', 'comments': 'string',
        'cookie': 'string', 'creation_time': 'string', 'cve': 'string', 'cvss': 'string',
        'date': 'string', 'description': 'string', 'dest': 'string', 'dest_bunit': 'string',
        'dest_category': 'string', 'dest_dns': 'string', 'dest_interface': 'string',
        'dest_ip': 'string', 'dest_ip_range': 'string', 'dest_mac': 'string',
        'dest_nt_domain': 'string', 'dest_nt_host': 'string', 'dest_port': 'string',
        'dest_priority': 'string', 'dest_translated_ip': 'string',
        'dest_translated_port': 'string', 'dest_type': 'string', 'dest_zone': 'string',
        'direction': 'string', 'dlp_type': 'string', 'dns': 'string', 'duration': 'string',
        'dvc': 'string', 'dvc_bunit': 'string', 'dvc_category': 'string', 'dvc_ip': 'string',
        'dvc_mac': 'string', 'dvc_priority': 'string', 'dvc_zone': 'string',
        'file_hash': 'string', 'file_name': 'string', 'file_path': 'string',
        'file_size': 'string', 'http_content_type': 'string', 'http_method': 'string',
        'http_referrer': 'string', 'http_referrer_domain': 'string', 'http_user_agent': 'string',
        'icmp_code': 'string', 'icmp_type': 'string', 'id': 'string', 'ids_type': 'string',
        'incident': 'string', 'ip': 'string', 'mac': 'string', 'message_id': 'string',
        'message_info': 'string', 'message_priority': 'string', 'message_type': 'string',
        'mitre_technique_id': 'string', 'msft': 'string', 'mskb': 'string', 'name': 'string',
        'orig_dest': 'string', 'orig_recipient': 'string', 'orig_src': 'string', 'os': 'string',
        'packets': 'string', 'packets_in': 'string', 'packets_out': 'string',
        'parent_process': 'string', 'parent_process_id': 'string',
        'parent_process_name': 'string', 'parent_process_path': 'string', 'password': 'string',
        'payload': 'string', 'payload_type': 'string', 'priority': 'string', 'problem': 'string',
        'process': 'string', 'process_hash': 'string', 'process_id': 'string',
        'process_name': 'string', 'process_path': 'string', 'product_version': 'string',
        'protocol': 'string', 'protocol_version': 'string', 'query': 'string',
        'query_count': 'string', 'query_type': 'string', 'reason': 'string',
        'recipient': 'string', 'recipient_count': 'string', 'recipient_domain': 'string',
        'recipient_status': 'string', 'record_type': 'string', 'registry_hive': 'string',
        'registry_key_name': 'string', 'registry_path': 'string',
        'registry_value_data': 'string', 'registry_value_name': 'string',
        'registry_value_text': 'string', 'registry_value_type': 'string',
        'request_payload': 'string', 'request_payload_type': 'string',
        'request_sent_time': 'string', 'response_code': 'string',
        'response_payload_type': 'string', 'response_received_time': 'string',
        'response_time': 'string', 'result': 'string', 'return_addr': 'string', 'rule': 'string',
        'rule_action': 'string', 'sender': 'string', 'service': 'string',
        'service_hash': 'string', 'service_id': 'string', 'service_name': 'string',
        'service_path': 'string', 'session_id': 'string', 'sessions': 'string',
        'severity': 'string', 'severity_id': 'string', 'sid': 'string', 'signature': 'string',
        'signature_id': 'string', 'signature_version': 'string', 'site': 'string',
        'size': 'string', 'source': 'string', 'sourcetype': 'string', 'src': 'string',
        'src_bunit': 'string', 'src_category': 'string', 'src_dns': 'string',
        'src_interface': 'string', 'src_ip': 'string', 'src_ip_range': 'string',
        'src_mac': 'string', 'src_nt_domain': 'string', 'src_nt_host': 'string',
        'src_port': 'string', 'src_priority': 'string', 'src_translated_ip': 'string',
        'src_translated_port': 'string', 'src_type': 'string', 'src_user': 'string',
        'src_user_bunit': 'string', 'src_user_category': 'string', 'src_user_domain': 'string',
        'src_user_id': 'string', 'src_user_priority': 'string', 'src_user_role': 'string',
        'src_user_type': 'string', 'src_zone': 'string', 'state': 'string', 'status': 'string',
        'status_code': 'string', 'subject': 'string', 'tag': 'string', 'ticket_id': 'string',
        'time': 'string', 'time_submitted': 'string', 'transport': 'string',
        'transport_dest_port': 'string', 'type': 'string', 'uri': 'string', 'uri_path': 'string',
        'uri_query': 'string', 'url': 'string', 'url_domain': 'string', 'url_length': 'string',
        'user': 'string', 'user_agent': 'string', 'user_bunit': 'string',
        'user_category': 'string', 'user_id': 'string', 'user_priority': 'string',
        'user_role': 'string', 'user_type': 'string', 'vendor_account': 'string',
        'vendor_product': 'string', 'vlan': 'string', 'xdelay': 'string', 'xref': 'string'
    }
}

ASSET = {
    'Asset': {
        'asset': 'string', 'asset_id': 'string', 'asset_tag': 'string', 'bunit': 'string',
        'category': 'string', 'city': 'string', 'country': 'string', 'dns': 'string',
        'ip': 'string', 'is_expected': 'string', 'lat': 'string', 'long': 'string', 'mac': 'string',
        'nt_host': 'string', 'owner': 'string', 'pci_domain': 'string', 'priority': 'string',
        'requires_av': 'string'
    }
}

IDENTITY = {
    'Identity': {
        'bunit': 'string', 'category': 'string', 'email': 'string', 'endDate': 'string', 'first': 'string',
        'identity': 'string', 'identity_tag': 'string', 'last': 'string', 'managedBy': 'string',
        'nick': 'string', 'phone': 'string', 'prefix': 'string', 'priority': 'string',
        'startDate': 'string', 'suffix': 'string', 'watchlist': 'string', 'work_city': 'string',
        'work_lat': 'string', 'work_long': 'string'
    }
}


def test_get_cim_mapping_field_command(mocker):
    """ Scenario: When the mapping is based on Splunk CIM. """
    mocker.patch.object(demisto, 'results')
    splunk.get_cim_mapping_field_command()
    fields = demisto.results.call_args[0][0]
    assert demisto.results.call_count == 1
    assert fields == {
        'Notable Data': NOTABLE,
        'Drilldown Data': DRILLDOWN,
        'Asset Data': ASSET,
        'Identity Data': IDENTITY
    }


def test_build_search_human_readable(mocker):
    """
    Given:
        table headers in query

    When:
        building a human readable table as part of splunk-search

    Then:
        Test headers are calculated correctly:
            * comma-separated, space-separated
            * support commas and spaces inside header values (if surrounded with parenthesis)

    """
    func_patch = mocker.patch('SplunkPyPreRelease.update_headers_from_field_names')
    results = [
        {'ID': 1, 'Header with space': 'h1', 'header3': 1, 'header_without_space': '1234'},
        {'ID': 2, 'Header with space': 'h2', 'header3': 2, 'header_without_space': '1234'},
    ]
    args = {
        'query': 'something | table ID "Header with space" header3 header_without_space '
                 'comma,separated "Single,Header,with,Commas" | something else'
    }
    expected_headers = ['ID', 'Header with space', 'header3', 'header_without_space',
                        'comma', 'separated', 'Single,Header,with,Commas']

    splunk.build_search_human_readable(args, results)
    headers = func_patch.call_args[0][1]
    assert headers == expected_headers


def test_fetch_incidents(mocker):
    splunk.ENABLED_ENRICHMENTS = []
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", 'enabled_enrichments': []}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.ResultsReader', return_value=SAMPLE_RESPONSE)
    splunk.fetch_notables(service)
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                   "Recurring Malware Infection - Rule"


def test_remove_old_incident_ids():
    """
    Given:
    - An array containing an ID of an incident that occurred less than an hour ago,
    one that occurred more than an hour ago, and one that occurred over 2 hours ago.
    When:
    - Running "remove_old_incident_ids" wtih a look_behind of 1 hour
    - Running "remove_old_incident_ids" wtih a look_behind of 2 hours
    Then:
    - When running with look_behind of 30 mins, only the ID of the incident that occurred less than an hour ago remained.
    - When running with look_behind of 1 hour, only the ID of the incident that occurred more than 2 hours ago was removed.
    """
    from SplunkPyPreRelease import remove_old_incident_ids
    cur_time = int(time.time())

    incident_ids_one_hour = {
        "incident_under_one_hour_old": cur_time - 300,
        "incident_over_one_hour_old": cur_time - 4200,
        "incident_over_two_hours_old": cur_time - 7800
    }

    assert "incident_under_one_hour_old" in incident_ids_one_hour
    assert "incident_over_one_hour_old" in incident_ids_one_hour
    assert "incident_over_two_hours_old" in incident_ids_one_hour

    new_incident_ids_one_hour_look_behind = remove_old_incident_ids(incident_ids_one_hour, cur_time, 30)

    assert "incident_under_one_hour_old" in new_incident_ids_one_hour_look_behind
    assert "incident_over_one_hour_old" not in new_incident_ids_one_hour_look_behind
    assert "incident_over_two_hours_old" not in new_incident_ids_one_hour_look_behind

    new_incident_ids_one_hour_look_behind = remove_old_incident_ids(incident_ids_one_hour, cur_time, 60)

    assert "incident_under_one_hour_old" in new_incident_ids_one_hour_look_behind
    assert "incident_over_one_hour_old" in new_incident_ids_one_hour_look_behind
    assert "incident_over_two_hours_old" not in new_incident_ids_one_hour_look_behind


occurred_time = str(int(time.time()) - 300)

first_incident = {
    'rawJSON': '{"_raw": "first incident"}',
    'occurred': occurred_time
}

second_incident = {
    'rawJSON': '{"_raw": "second incident"}',
    'occurred': occurred_time
}


def test_create_incident_custom_id_creates_different_ids():
    """
    Given:
    - Two different incidents
    When:
    - Creating a custom ID for the incidents using "create_incident_custom_id"
    Then:
    - The IDs of the two incidents are unique.
    """
    from SplunkPyPreRelease import create_incident_custom_id
    first_incident_custom_id = create_incident_custom_id(first_incident)
    second_incident_custom_id = create_incident_custom_id(second_incident)
    assert first_incident_custom_id != second_incident_custom_id


incidents_with_minutes_difference = (
    [
        {'occurred': '2020-08-04T05:44:16.000-07:00'},
        {'occurred': '2020-08-04T05:48:17.000-07:00'},
    ],
    '2020-08-04T05:48:17.000-07:00'
)

incidents_with_days_difference = (
    [
        {'occurred': '2020-08-05T05:48:17.000-07:00'},
        {'occurred': '2020-08-04T05:48:17.000-07:00'},
    ],
    '2020-08-05T05:48:17.000-07:00'
)

incidents_with_seconds_difference = (
    [
        {'occurred': '2020-08-04T05:48:18.000-07:00'},
        {'occurred': '2020-08-04T05:48:17.000-07:00'},
    ],
    '2020-08-04T05:48:18.000-07:00'
)

get_latest_incident_time_test_data = [
    incidents_with_minutes_difference,
    incidents_with_days_difference,
    incidents_with_seconds_difference
]


@pytest.mark.parametrize('test_incidents, expected', get_latest_incident_time_test_data)
def test_get_latest_incident_time(test_incidents, expected):
    """
    Given:
    - Two different incidents, one of which occurred later than the other by a few minutes
    - Two different incidents, one of which occurred later than the other by a few seconds
    - Two different incidents, one of which occurred later than the other by a few days
    When:
    - Using "get_latest_incident_time" to get the time of the latest incident.
    Then:
    - The time of the most recent incident is retrieved.
    """
    from SplunkPyPreRelease import get_latest_incident_time

    latest_time = get_latest_incident_time(test_incidents)
    assert latest_time == expected


response_with_early_incident = [{
    '_bkt': 'notable~668~66D21DF4-F4FD-4886-A986-82E72ADCBFE9',
    '_cd': '668:17198',
    '_indextime': '1596545116',
    '_raw': '1596545116, search_name="Endpoint - Recurring Malware Infection - Rule", count="17", '
            'day_count="8", dest="ACME-workstation-012", info_max_time="1596545100.000000000", '
            'info_min_time="1595939700.000000000", info_search_time="1596545113.965466000", '
            'signature="Trojan.Gen.2"',
    '_serial': '50',
    '_si': ['ip-172-31-44-193', 'notable'],
    '_sourcetype': 'stash',
    '_time': '2020-08-04T05:45:16.000-07:00',
    'dest': 'ACME-workstation-012',
    'dest_asset_id': '028877d3c80cb9d87900eb4f9c9601ea993d9b63',
    'dest_asset_tag': ['cardholder', 'pci', 'americas'],
    'dest_bunit': 'americas',
    'dest_category': ['cardholder', 'pci'],
    'dest_city': 'Pleasanton',
    'dest_country': 'USA',
    'dest_ip': '192.168.3.12',
    'dest_is_expected': 'TRUE',
    'dest_lat': '37.694452',
    'dest_long': '-121.894461',
    'dest_nt_host': 'ACME-workstation-012',
    'dest_pci_domain': ['trust', 'cardholder'],
    'dest_priority': 'medium',
    'dest_requires_av': 'TRUE',
    'dest_risk_object_type': 'system',
    'dest_risk_score': '15680',
    'dest_should_timesync': 'TRUE',
    'dest_should_update': 'TRUE',
    'host': 'ip-172-31-44-193',
    'host_risk_object_type': 'system',
    'host_risk_score': '0',
    'index': 'notable',
    'linecount': '1',
    'priorities': 'medium',
    'priority': 'medium',
    'risk_score': '15680',
    'rule_description': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_name': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_title': 'Endpoint - Recurring Malware Infection - Rule',
    'security_domain': 'Endpoint - Recurring Malware Infection - Rule',
    'severity': 'unknown',
    'signature': 'Trojan.Gen.2',
    'source': 'Endpoint - Recurring Malware Infection - Rule',
    'sourcetype': 'stash',
    'splunk_server': 'ip-172-31-44-193',
    'urgency': 'low'
}]

response_with_late_incident = [{
    '_bkt': 'notable~668~66D21DF4-F4FD-4886-A986-82E72ADCBFE9',
    '_cd': '668:17198',
    '_indextime': '1596545116',
    '_raw': '1596545116, search_name="Endpoint - Recurring Malware Infection - Rule", count="17", '
            'day_count="8", dest="ACME-workstation-012", info_max_time="1596545100.000000000", '
            'info_min_time="1595939700.000000000", info_search_time="1596545113.965466000", '
            'signature="Trojan.Gen.2"',
    '_serial': '50',
    '_si': ['ip-172-31-44-193', 'notable'],
    '_sourcetype': 'stash',
    '_time': '2020-08-04T05:45:17.000-07:00',
    'dest': 'ACME-workstation-012',
    'dest_asset_id': '028877d3c80cb9d87900eb4f9c9601ea993d9b63',
    'dest_asset_tag': ['cardholder', 'pci', 'americas'],
    'dest_bunit': 'americas',
    'dest_category': ['cardholder', 'pci'],
    'dest_city': 'Pleasanton',
    'dest_country': 'USA',
    'dest_ip': '192.168.3.12',
    'dest_is_expected': 'TRUE',
    'dest_lat': '37.694452',
    'dest_long': '-121.894461',
    'dest_nt_host': 'ACME-workstation-012',
    'dest_pci_domain': ['trust', 'cardholder'],
    'dest_priority': 'medium',
    'dest_requires_av': 'TRUE',
    'dest_risk_object_type': 'system',
    'dest_risk_score': '15680',
    'dest_should_timesync': 'TRUE',
    'dest_should_update': 'TRUE',
    'host': 'ip-172-31-44-193',
    'host_risk_object_type': 'system',
    'host_risk_score': '0',
    'index': 'notable',
    'linecount': '1',
    'priorities': 'medium',
    'priority': 'medium',
    'risk_score': '15680',
    'rule_description': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_name': 'Endpoint - Recurring Malware Infection - Rule',
    'rule_title': 'Endpoint - Recurring Malware Infection - Rule',
    'security_domain': 'Endpoint - Recurring Malware Infection - Rule',
    'severity': 'unknown',
    'signature': 'Trojan.Gen.2',
    'source': 'Endpoint - Recurring Malware Infection - Rule',
    'sourcetype': 'stash',
    'splunk_server': 'ip-172-31-44-193',
    'urgency': 'low'
}]


def test_fetch_incidents_pre_indexing_scenario(mocker):
    """
    Given:
    - Two different incidents, one of which occurred seconds earlier than the other,
    but was indexed later so was not fetched on the first run.
    When:
    - Running "Fetch Incidents" and the more recent incident returns.
    Then:
    - The next fetch will start from a time that will allow getting the earlier incident as well,
    even though it was indexed later.
    """
    splunk.ENABLED_ENRICHMENTS = []
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", 'enabled_enrichments': []}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)

    mocker.patch('splunklib.results.ResultsReader', return_value=response_with_late_incident)
    splunk.fetch_notables(service)
    next_run = demisto.setLastRun.call_args[0][0]
    next_run_timestamp = datetime.strptime(next_run["time"], SPLUNK_TIME_FORMAT)
    earlier_incident_time = response_with_late_incident[0]["_time"].split('.')[0]
    earlier_incident_time = datetime.strptime(earlier_incident_time, SPLUNK_TIME_FORMAT)
    assert earlier_incident_time >= next_run_timestamp


def test_fetch_incidents_deduping(mocker):
    """
    Given:
    - An incident is returned from SplunkPyPreRelease on two subsequent "Fetch Incidents" runs.
    When:
    - Returning incidents on the second run.
    Then:
    - The incident is not returned again, thus it was effectively deduped.
    """
    splunk.ENABLED_ENRICHMENTS = []
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", 'enabled_enrichments': []}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.ResultsReader', return_value=response_with_late_incident)
    splunk.fetch_notables(service)
    next_run = demisto.setLastRun.call_args[0][0]
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 1

    mocker.patch('demistomock.getLastRun', return_value=next_run)
    splunk.fetch_notables(service)
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 0


def test_fetch_incidents_incident_next_run_calculation(mocker):
    """
    Given:
    - A new incident is found when "Fetch Incidents" runs.
    When:
    - The next run's "last run" values are set.
    Then:
    - The next run's start time will be the the occurrence time of the new incident.
    """
    from SplunkPyPreRelease import splunk_time_to_datetime

    splunk.ENABLED_ENRICHMENTS = []
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", 'enabled_enrichments': []}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.ResultsReader', return_value=response_with_late_incident)
    splunk.fetch_notables(service)
    next_run = demisto.setLastRun.call_args[0][0]
    incidents = demisto.incidents.call_args[0][0]
    incident_found = incidents[0]
    found_incident_time = splunk_time_to_datetime(incident_found['occurred'])
    next_run_time = datetime.strptime(next_run["time"], SPLUNK_TIME_FORMAT)

    assert next_run_time == found_incident_time


@pytest.mark.parametrize(
    argnames='credentials',
    argvalues=[{'username': 'test', 'password': 'test'}, {'splunkToken': 'token', 'password': 'test'}]
)
def test_module_test(mocker, credentials):
    """
    Given:
        - Credentials for connecting Splunk

    When:
        - Run test-module command

    Then:
        - Validate the info method was called
    """

    # prepare
    mocker.patch.object(client.Service, 'info')
    mocker.patch.object(client.Service, 'login')
    service = client.Service(**credentials)
    # run

    splunk.test_module(service)

    # validate
    assert service.info.call_count == 1


@pytest.mark.parametrize(
    argnames='credentials',
    argvalues=[{'username': 'test', 'password': 'test'}, {'splunkToken': 'token', 'password': 'test'}]
)
def test_module__exception_raised(mocker, credentials):
    """
    Given:
        - AuthenticationError was occurred

    When:
        - Run test-module command

    Then:
        - Validate the expected message was returned
    """

    # prepare
    def exception_raiser():
        raise AuthenticationError()

    mocker.patch.object(AuthenticationError, '__init__', return_value=None)
    mocker.patch.object(client.Service, 'info', side_effect=exception_raiser)
    mocker.patch.object(client.Service, 'login')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    service = client.Service(**credentials)
    # run

    splunk.test_module(service)

    # validate
    assert return_error_mock.call_args[0][0] == 'Authentication error, please validate your credentials.'


def test_module_hec_url(mocker):
    """
    Given:
        - hec_url was is in params

    When:
        - Run test-module command

    Then:
        - Validate taht the request.get was called with the expected args
    """

    # prepare

    mocker.patch.object(demisto, 'params', return_value={'hec_url': 'test_hec_url'})
    mocker.patch.object(client.Service, 'info')
    mocker.patch.object(client.Service, 'login')
    mocker.patch.object(requests, 'get')

    service = client.Service(username='test', password='test')
    # run

    splunk.test_module(service)

    # validate
    assert requests.get.call_args[0][0] == 'test_hec_url/services/collector/health'
