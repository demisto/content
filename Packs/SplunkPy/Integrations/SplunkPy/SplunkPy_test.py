from copy import deepcopy
import pytest
import SplunkPy as splunk
import demistomock as demisto

RETURN_ERROR_TARGET = 'SplunkPy.return_error'

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
    from SplunkPy import update_headers_from_field_names
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
    mocker.patch('SplunkPy.get_key_type', return_value=None)
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
    mocker.patch('SplunkPy.get_key_type', return_value=_type)
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
        mocker.patch('SplunkPy.get_keys_and_types', return_value=keys_and_types)

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

    mocker.patch('SplunkPy.get_keys_and_types', return_value=fields)
    output = splunk.get_kv_store_config(Name())
    expected_output = '{}{}'.format(START_OUTPUT, expected_output)
    assert output == expected_output


def test_fetch_incidents(mocker):
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something"}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.ResultsReader', return_value=SAMPLE_RESPONSE)
    splunk.fetch_incidents(service)
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                   "Recurring Malware Infection - Rule"


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


NOTABLE = {'rule_name': '', '': '', 'rule_title': '', 'security_domain': '', 'index': '', 'rule_description': '',
           'risk_score': '', 'host': '', 'host_risk_object_type': '', 'dest_risk_object_type': '',
           'dest_risk_score': '', 'splunk_server': '', '_sourcetype': '', '_indextime': '', '_time': '',
           'src_risk_object_type': '', 'src_risk_score': '', '_raw': '', 'urgency': '', 'owner': '',
           'info_min_time': '', 'info_max_time': '', 'comment': '', 'reviewer': '', 'rule_id': '', 'action': '',
           'app': '', 'authentication_method': '', 'authentication_service': '', 'bugtraq': '', 'bytes': '',
           'bytes_in': '', 'bytes_out': '', 'category': '', 'cert': '', 'change': '', 'change_type': '', 'command': '',
           'comments': '', 'cookie': '', 'creation_time': '', 'cve': '', 'cvss': '', 'date': '', 'description': '',
           'dest': '', 'dest_bunit': '', 'dest_category': '', 'dest_dns': '', 'dest_interface': '', 'dest_ip': '',
           'dest_ip_range': '', 'dest_mac': '', 'dest_nt_domain': '', 'dest_nt_host': '', 'dest_port': '',
           'dest_priority': '', 'dest_translated_ip': '', 'dest_translated_port': '', 'dest_type': '', 'dest_zone': '',
           'direction': '', 'dlp_type': '', 'dns': '', 'duration': '', 'dvc': '', 'dvc_bunit': '', 'dvc_category': '',
           'dvc_ip': '', 'dvc_mac': '', 'dvc_priority': '', 'dvc_zone': '', 'file_hash': '', 'file_name': '',
           'file_path': '', 'file_size': '', 'http_content_type': '', 'http_method': '', 'http_referrer': '',
           'http_referrer_domain': '', 'http_user_agent': '', 'icmp_code': '', 'icmp_type': '', 'id': '',
           'ids_type': '', 'incident': '', 'ip': '', 'mac': '', 'message_id': '', 'message_info': '',
           'message_priority': '', 'message_type': '', 'mitre_technique_id': '', 'msft': '', 'mskb': '', 'name': '',
           'orig_dest': '', 'orig_recipient': '', 'orig_src': '', 'os': '', 'packets': '', 'packets_in': '',
           'packets_out': '', 'parent_process': '', 'parent_process_id': '', 'parent_process_name': '',
           'parent_process_path': '', 'password': '', 'payload': '', 'payload_type': '', 'priority': '', 'problem': '',
           'process': '', 'process_hash': '', 'process_id': '', 'process_name': '', 'process_path': '',
           'product_version': '', 'protocol': '', 'protocol_version': '', 'query': '', 'query_count': '',
           'query_type': '', 'reason': '', 'recipient': '', 'recipient_count': '', 'recipient_domain': '',
           'recipient_status': '', 'record_type': '', 'registry_hive': '', 'registry_key_name': '', 'registry_path': '',
           'registry_value_data': '', 'registry_value_name': '', 'registry_value_text': '', 'registry_value_type': '',
           'request_sent_time': '', 'request_payload': '', 'request_payload_type': '', 'response_code': '',
           'response_payload_type': '', 'response_received_time': '', 'response_time': '', 'result': '',
           'return_addr': '', 'rule': '', 'rule_action': '', 'sender': '', 'service': '', 'service_hash': '',
           'service_id': '', 'service_name': '', 'service_path': '', 'session_id': '', 'sessions': '', 'severity': '',
           'severity_id': '', 'sid': '', 'signature': '', 'signature_id': '', 'signature_version': '', 'site': '',
           'size': '', 'source': '', 'sourcetype': '', 'src': '', 'src_bunit': '', 'src_category': '', 'src_dns': '',
           'src_interface': '', 'src_ip': '', 'src_ip_range': '', 'src_mac': '', 'src_nt_domain': '', 'src_nt_host': '',
           'src_port': '', 'src_priority': '', 'src_translated_ip': '', 'src_translated_port': '', 'src_type': '',
           'src_user': '', 'src_user_bunit': '', 'src_user_category': '', 'src_user_domain': '', 'src_user_id': '',
           'src_user_priority': '', 'src_user_role': '', 'src_user_type': '', 'src_zone': '', 'state': '', 'status': '',
           'status_code': '', 'status_description': '', 'subject': '', 'tag': '', 'ticket_id': '', 'time': '',
           'time_submitted': '', 'transport': '', 'transport_dest_port': '', 'type': '', 'uri': '', 'uri_path': '',
           'uri_query': '', 'url': '', 'url_domain': '', 'url_length': '', 'user': '', 'user_agent': '',
           'user_bunit': '', 'user_category': '', 'user_id': '', 'user_priority': '', 'user_role': '', 'user_type': '',
           'vendor_account': '', 'vendor_product': '', 'vlan': '', 'xdelay': '', 'xref': ''}

DRILLDOWN = {
    'Drilldown': {'action': '', 'app': '', 'authentication_method': '', 'authentication_service': '', 'bugtraq': '',
                  'bytes': '', 'bytes_in': '', 'bytes_out': '', 'category': '', 'cert': '', 'change': '',
                  'change_type': '', 'command': '', 'comments': '', 'cookie': '', 'creation_time': '', 'cve': '',
                  'cvss': '', 'date': '', 'description': '', 'dest': '', 'dest_bunit': '', 'dest_category': '',
                  'dest_dns': '', 'dest_interface': '', 'dest_ip': '', 'dest_ip_range': '', 'dest_mac': '',
                  'dest_nt_domain': '', 'dest_nt_host': '', 'dest_port': '', 'dest_priority': '',
                  'dest_translated_ip': '', 'dest_translated_port': '', 'dest_type': '', 'dest_zone': '',
                  'direction': '', 'dlp_type': '', 'dns': '', 'duration': '', 'dvc': '', 'dvc_bunit': '',
                  'dvc_category': '', 'dvc_ip': '', 'dvc_mac': '', 'dvc_priority': '', 'dvc_zone': '',
                  'file_hash': '', 'file_name': '', 'file_path': '', 'file_size': '', 'http_content_type': '',
                  'http_method': '', 'http_referrer': '', 'http_referrer_domain': '', 'http_user_agent': '',
                  'icmp_code': '', 'icmp_type': '', 'id': '', 'ids_type': '', 'incident': '', 'ip': '', 'mac': '',
                  'message_id': '', 'message_info': '', 'message_priority': '', 'message_type': '',
                  'mitre_technique_id': '', 'msft': '', 'mskb': '', 'name': '', 'orig_dest': '',
                  'orig_recipient': '', 'orig_src': '', 'os': '', 'packets': '', 'packets_in': '',
                  'packets_out': '', 'parent_process': '', 'parent_process_id': '', 'parent_process_name': '',
                  'parent_process_path': '', 'password': '', 'payload': '', 'payload_type': '', 'priority': '',
                  'problem': '', 'process': '', 'process_hash': '', 'process_id': '', 'process_name': '',
                  'process_path': '', 'product_version': '', 'protocol': '', 'protocol_version': '', 'query': '',
                  'query_count': '', 'query_type': '', 'reason': '', 'recipient': '', 'recipient_count': '',
                  'recipient_domain': '', 'recipient_status': '', 'record_type': '', 'registry_hive': '',
                  'registry_key_name': '', 'registry_path': '', 'registry_value_data': '',
                  'registry_value_name': '', 'registry_value_text': '', 'registry_value_type': '',
                  'request_payload': '', 'request_payload_type': '', 'request_sent_time': '', 'response_code': '',
                  'response_payload_type': '', 'response_received_time': '', 'response_time': '', 'result': '',
                  'return_addr': '', 'rule': '', 'rule_action': '', 'sender': '', 'service': '', 'service_hash': '',
                  'service_id': '', 'service_name': '', 'service_path': '', 'session_id': '', 'sessions': '',
                  'severity': '', 'severity_id': '', 'sid': '', 'signature': '', 'signature_id': '',
                  'signature_version': '', 'site': '', 'size': '', 'source': '', 'sourcetype': '', 'src': '',
                  'src_bunit': '', 'src_category': '', 'src_dns': '', 'src_interface': '', 'src_ip': '',
                  'src_ip_range': '', 'src_mac': '', 'src_nt_domain': '', 'src_nt_host': '', 'src_port': '',
                  'src_priority': '', 'src_translated_ip': '', 'src_translated_port': '', 'src_type': '',
                  'src_user': '', 'src_user_bunit': '', 'src_user_category': '', 'src_user_domain': '',
                  'src_user_id': '', 'src_user_priority': '', 'src_user_role': '', 'src_user_type': '',
                  'src_zone': '', 'state': '', 'status': '', 'status_code': '', 'subject': '', 'tag': '',
                  'ticket_id': '', 'time': '', 'time_submitted': '', 'transport': '', 'transport_dest_port': '',
                  'type': '', 'uri': '', 'uri_path': '', 'uri_query': '', 'url': '', 'url_domain': '',
                  'url_length': '', 'user': '', 'user_agent': '', 'user_bunit': '', 'user_category': '',
                  'user_id': '', 'user_priority': '', 'user_role': '', 'user_type': '', 'vendor_account': '',
                  'vendor_product': '', 'vlan': '', 'xdelay': '', 'xref': ''}
}

ASSET = {
    'Asset': {'asset': '', 'asset_id': '', 'asset_tag': '', 'bunit': '', 'category': '', 'city': '', 'country': '',
              'dns': '', 'ip': '', 'is_expected': '', 'lat': '', 'long': '', 'mac': '', 'nt_host': '', 'owner': '',
              'pci_domain': '', 'priority': '', 'requires_av': ''}
}

IDENTITY = {
    'Identity': {'bunit': '', 'category': '', 'email': '', 'endDate': '', 'first': '', 'identity': '',
                 'identity_tag': '', 'last': '', 'managedBy': '', 'nick': '', 'phone': '', 'prefix': '',
                 'priority': '', 'startDate': '', 'suffix': '', 'watchlist': '', 'work_city': '', 'work_lat': '',
                 'work_long': ''}
}


def test_get_cim_mapping_field_command(mocker):
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
