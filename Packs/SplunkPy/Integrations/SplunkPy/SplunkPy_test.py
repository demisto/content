import demistomock as demisto
from CommonServerPython import *

import pytest
from copy import deepcopy
from collections import namedtuple
from datetime import timedelta, datetime

from splunklib.binding import AuthenticationError
from splunklib import client
from splunklib import results
import SplunkPy as splunk
from pytest_mock import MockerFixture
from unittest.mock import MagicMock, patch


RETURN_ERROR_TARGET = 'SplunkPy.return_error'

DICT_RAW_RESPONSE = '"1528755951, url="https://test.url.com", search_name="NG_SIEM_UC25- High number of hits against ' \
                    'unknown website from same subnet", action="allowed", dest="bb.bbb.bb.bbb , cc.ccc.ccc.cc , ' \
                    'xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", distinct_hosts="5", ' \
                    'first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , 06/11/18 17:37:55 , 06/11/18 17:41:28 , ' \
                    '06/11/18 17:42:05 , 06/11/18 17:42:38", info_max_time="+Infinity", info_min_time="0.000", ' \
                    'src="xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", u_category="unknown", ' \
                    'user="xyz\\a1234 , xyz\\b5678 , xyz\\c91011 , xyz\\d121314 , unknown", website="2.2.2.2""'

DICT_RAW_RESPONSE_WITH_MESSAGE_ID = '"1528755951, message-id="1", url="https://test.url.com", ' \
                                    'search_name="NG_SIEM_UC25- High number of hits against ' \
                                    'unknown website from same subnet", action="allowed", dest="bb.bbb.bb.bbb , ' \
                                    'cc.ccc.ccc.cc , xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", ' \
                                    'distinct_hosts="5", ' \
                                    'first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , ' \
                                    '06/11/18 17:37:55 , 06/11/18 17:41:28 , ' \
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

SAMPLE_RESPONSE = [
    results.Message("INFO-TEST", "test message"),
    {
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
        'urgency': 'low',
        'owner': 'unassigned',
        'event_id': '66D21DF4-F4FD-4886-A986-82E72ADCBFE9@@notable@@5aa44496ec8e5cf45c78ab230189a4ca',
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
    "website": "2.2.2.2",
    "url": "https://test.url.com"
}

EXPECTED_WITH_MESSAGE_ID = {
    "message-id": "1",
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
    "website": "2.2.2.2",
    "url": "https://test.url.com"
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


class Jobs:
    def __init__(self, status, service):
        self.oneshot = lambda x, **kwargs: x
        state = namedtuple('state', 'content')
        self.state = state(content={'dispatchState': str(status)})
        self.service = service

    def __getitem__(self, arg):
        return 0

    def create(self, query, **kwargs):
        job = client.Job(sid='123456', service=self.service, **kwargs)
        job.resultCount = 0
        job._state = self.state
        return job


class Service:
    def __init__(self, status):
        self.jobs = Jobs(status, self)
        self.status = status
        self.disable_v2_api = False
        self.namespace = {'app': 'test', 'owner': 'test', 'sharing': 'global'}
        self._abspath = lambda x, **kwargs: x

    def get(self, path_segment, owner=None, app=None, headers=None, sharing=None, **query):
        return {'status': '200', 'body': 'test', 'headers': {'content-type': 'application/json'}, 'reason': 'OK'}

    def job(self, sid):
        return self.jobs


def test_raw_to_dict():
    actual_raw = DICT_RAW_RESPONSE
    response = splunk.rawToDict(actual_raw)
    response_with_message = splunk.rawToDict(DICT_RAW_RESPONSE_WITH_MESSAGE_ID)
    list_response = splunk.rawToDict(LIST_RAW)
    raw_message = splunk.rawToDict(RAW_WITH_MESSAGE)
    empty = splunk.rawToDict('')
    url_test = splunk.rawToDict(URL_TESTING_IN)
    character_check = splunk.rawToDict(RESPONSE)

    assert response == EXPECTED
    assert response_with_message == EXPECTED_WITH_MESSAGE_ID
    assert {} == list_response
    assert raw_message.get('SCOPE[29]') == 'autopay\/events\/payroll\/v1\/earning-configuration.configuration-tags' \
                                           '.modify'
    assert isinstance(raw_message, dict)
    assert empty == {}
    assert url_test == URL_TESTING_OUT
    assert character_check == POSITIVE
    assert splunk.rawToDict(RAW_JSON) == RAW_JSON_AND_STANDARD_OUTPUT
    assert splunk.rawToDict(RAW_STANDARD) == RAW_JSON_AND_STANDARD_OUTPUT

    assert splunk.rawToDict('drilldown_search="key IN ("test1","test2")') == {
        'drilldown_search': 'key IN (test1,test2)'}
    assert splunk.rawToDict('123456, sample_account="sample1", '
                            'sample_account="sample2", sample_account="sample3",'
                            ' distinct_count_ac="5"') == {'sample_account': 'sample1, sample2, sample3',
                                                          'distinct_count_ac': '5'}


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
    assert out == dict_out, f'replace_keys({dict_in}) got: {out} instead: {dict_out}'


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


def test_splunk_submit_event_hec_command(mocker):
    text = "a msg with a failure."

    class MockRes:
        def __init__(self, text):
            self.text = text

    mocker.patch.object(splunk, "splunk_submit_event_hec", return_value=MockRes(text))
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    splunk.splunk_submit_event_hec_command(params={"hec_url": "mock_url"}, args={"entry_id": "some_entry"}, service=Service)
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == f"Could not send event to Splunk {text}"


def check_request_channel(args: dict):
    """
    Check if args contains a request_channel, return the proper text.
    Args:
        args: A dict of args.
    Returns: A MockResRequestChannel with the correct text value.
    """
    if args.get('request_channel'):
        return MockResRequestChannel('{"text":"Success","code":0,"ackId":1}')
    else:
        return MockResRequestChannel('{"text":"Data channel is missing","code":10}')


class MockResRequestChannel:
    def __init__(self, text):
        self.text = text


def test_splunk_submit_event_hec_command_request_channel(mocker):
    """
    Given
    - An args dict that contains a request_channel and a dummy params.
    When
    - Executing splunk_submit_event_hec_command function
    Then
    - The return result object contains the correct message.
    """
    args = {"request_channel": "11111111-1111-1111-1111-111111111111", "entry_id": "some_entry"}
    mocker.patch.object(splunk, "splunk_submit_event_hec", return_value=check_request_channel(args))
    moc = mocker.patch.object(demisto, 'results')
    splunk.splunk_submit_event_hec_command(params={"hec_url": "mock_url"},
                                           args=args, service=Service)
    readable_output = moc.call_args[0][0]
    assert readable_output == "The events were sent successfully to Splunk. AckID: 1"


def test_splunk_submit_event_hec_command_without_request_channel(mocker):
    """
    Given
    - An args dict that doesn't contain a request_channel and a dummy params.
    When
    - Executing splunk_submit_event_hec_command function
    Then
    - The return result object contains the correct message.
    """
    args = {"entry_id": "some_entry"}
    mocker.patch.object(splunk, "splunk_submit_event_hec", return_value=check_request_channel(args))

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    splunk.splunk_submit_event_hec_command(params={"hec_url": "mock_url"},
                                           args=args, service=Service)
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Could not send event to Splunk {"text":"Data channel is missing","code":10}'


def test_parse_time_to_minutes_invalid_time_unit(mocker):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    splunk.FETCH_TIME = '3 hoursss'
    splunk.parse_time_to_minutes()
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: Invalid time unit.'


SEARCH_RESULT = [
    {
        "But": {
            "This": "is"
        },
        "Very": "Unique"
    },
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
    assert (
        output == out_error
    ), f'check_error(service, {args})\n\treturns: {output}\n\tinstead: {out_error}'


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
    assert (
        output == expected_query
    ), f'build_kv_store_query({args})\n\treturns: {output}\n\tinstead: {expected_query}'


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
    assert (
        output == expected_keys
    ), f'get_keys_and_types(kv_store)\n\treturns: {output}\n\tinstead: {expected_keys}'


START_OUTPUT = (
    '#### configuration for name store\n| field name | type |\n| --- | --- |'
)
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
    expected_output = f'{START_OUTPUT}{expected_output}'
    assert output == expected_output


class TestFetchRemovingIrrelevantIncidents:
    notable1 = {'status': '5', 'event_id': '3'}
    notable2 = {'status': '6', 'event_id': '4'}

    # In order to mock the service.jobs.oneshot() call in the fetch_notables function, we need to create
    # the following two classes
    class Jobs:
        def __init__(self):
            self.oneshot = lambda x, **kwargs: TestFetchForLateIndexedEvents.notable1

    class Service:
        def __init__(self):
            self.jobs = TestFetchForLateIndexedEvents.Jobs()

    def test_backwards_compatible(self, mocker: MockerFixture):
        """
        Given
        - Incident IDs that were fetched in the last fetch round with the epoch time of their occurrence

        When
        - Fetching notables

        Then
        - Make sure that the last fetched IDs now hold the start of the fetch window, and not the epoch time
        """
        from SplunkPy import UserMappingObject

        mocker.patch.object(demisto, 'setLastRun')
        mock_last_run = {'time': '2024-02-12T10:00:00', 'latest_time': '2024-02-19T10:00:00',
                         'found_incidents_ids': {'1': 1700497516}}
        mock_params = {'fetchQuery': '`notable` is cool', 'fetch_limit': 2}
        mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
        mocker.patch('demistomock.params', return_value=mock_params)
        mocker.patch('splunklib.results.JSONResultsReader', return_value=[self.notable1,
                                                                          self.notable2])
        service = self.Service()
        set_last_run_mocker = mocker.patch('demistomock.setLastRun')
        mapper = UserMappingObject(service, False)
        splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
        last_fetched_ids = set_last_run_mocker.call_args_list[0][0][0]['found_incidents_ids']
        assert last_fetched_ids == {'1': {'occurred_time': '2024-02-19T10:00:00'},
                                    '3': {'occurred_time': '2024-02-19T10:00:00'},
                                    '4': {'occurred_time': '2024-02-19T10:00:00'}}

    def test_remove_irrelevant_fetched_incident_ids(self, mocker: MockerFixture):
        """
        Given
        - Incident IDs that were fetched in the last fetch round

        When
        - Fetching notables

        Then
        - Make sure that the fetched IDs that are no longer in the fetch window are removed
        """
        from SplunkPy import UserMappingObject

        mocker.patch.object(demisto, 'setLastRun')
        mock_last_run = {'time': '2024-02-12T10:00:00', 'latest_time': '2024-02-19T10:00:00',
                         'found_incidents_ids': {'1': {'occurred_time': '2024-02-12T09:59:59'},
                                                 '2': {'occurred_time': '2024-02-18T10:00:00'}}}
        mock_params = {'fetchQuery': '`notable` is cool', 'fetch_limit': 2}
        mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
        mocker.patch('demistomock.params', return_value=mock_params)
        mocker.patch('splunklib.results.JSONResultsReader', return_value=[self.notable1,
                                                                          self.notable2])
        service = self.Service()
        set_last_run_mocker = mocker.patch('demistomock.setLastRun')
        mapper = UserMappingObject(service, False)
        splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
        last_fetched_ids = set_last_run_mocker.call_args_list[0][0][0]['found_incidents_ids']
        assert last_fetched_ids == {'2': {'occurred_time': '2024-02-18T10:00:00'},
                                    '3': {'occurred_time': '2024-02-19T10:00:00'},
                                    '4': {'occurred_time': '2024-02-19T10:00:00'}}


class TestFetchForLateIndexedEvents:
    notable1 = {'status': '5', 'event_id': 'id_1'}
    notable2 = {'status': '6', 'event_id': 'id_2'}

    # In order to mock the service.jobs.oneshot() call in the fetch_notables function, we need to create
    # the following two classes
    class Jobs:
        def __init__(self):
            self.oneshot = lambda x, **kwargs: TestFetchForLateIndexedEvents.notable1

    class Service:
        def __init__(self):
            self.jobs = TestFetchForLateIndexedEvents.Jobs()

    # If late_indexed_pagination is True, then we exclude the last fetched ids (check by using fetch query),
    # and kwargs_oneshot['offset'] == 0
    def test_fetch_query_and_oneshot_args(self, mocker: MockerFixture):
        """
        Given
        - Mocked incidents api response
        - The key "late_indexed_pagination" in the last run object is set to True
        - Some incident IDs that were fetched in the last fetch round

        When
        - Fetching notables

        Then
        - Make sure that last fetched incident IDs are specified to be excluded from the fetch query
        - Make sure that the offset of the fetch query is set to 0
        """
        from SplunkPy import UserMappingObject
        mocker.patch.object(demisto, 'setLastRun')
        mock_last_run = {'time': '2018-10-24T14:13:20', 'late_indexed_pagination': True,
                         'found_incidents_ids': {'1234': 1700497516, '5678': 1700497516}}
        mock_params = {'fetchQuery': 'something'}
        mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
        mocker.patch('demistomock.params', return_value=mock_params)
        mocker.patch('splunklib.results.JSONResultsReader', return_value=[self.notable1])
        service = self.Service()
        oneshot_mocker = mocker.patch.object(service.jobs, 'oneshot', side_effect=service.jobs.oneshot)
        mapper = UserMappingObject(service, False)
        splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
        assert oneshot_mocker.call_args_list[0][0][0] == 'something | where not event_id in ("1234","5678")'
        assert oneshot_mocker.call_args_list[0][1]['offset'] == 0

    # If (num_of_dropped == FETCH_LIMIT and '`notable`' in fetch_query), then late_indexed_pagination should be set to True
    def test_first_condition_for_late_indexed_pagination(self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch):
        """
        Given
        - Incident IDs that were fetched in the last fetch round
        - Mocked incidents api response, that have IDs as the last fetched IDs (which means that num_of_dropped == FETCH_LIMIT)
        - `notable` is in the fetch query

        When
        - Fetching notables

        Then
        - Make sure that the key "late_indexed_pagination" in last run object is set to True
        """
        from SplunkPy import UserMappingObject
        # MonkeyPatch can be used to patch global variables
        monkeypatch.setattr(splunk, 'FETCH_LIMIT', 2)
        mocker.patch.object(demisto, 'setLastRun')
        mock_last_run = {'time': '2018-10-24T14:13:20',
                         'found_incidents_ids': {'id_1': 1700497516, 'id_2': 1700497516}}
        mock_params = {'fetchQuery': '`notable` is cool', 'fetch_limit': 2}
        mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
        mocker.patch('demistomock.params', return_value=mock_params)
        mocker.patch('splunklib.results.JSONResultsReader', return_value=[self.notable1,
                                                                          self.notable2])
        set_last_run_mocker = mocker.patch('demistomock.setLastRun')
        service = self.Service()
        mapper = UserMappingObject(service, False)
        splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
        assert set_last_run_mocker.call_args_list[0][0][0]['late_indexed_pagination'] is True

    # If (len(incidents) == FETCH_LIMIT and late_indexed_pagination), then late_indexed_pagination should be set to True
    def test_second_condition_for_late_indexed_pagination(self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch):
        """
        Given
        - Incident IDs that were fetched in the last fetch round
        - Mocked incidents api response, where only new incidents are fetched (which means that len(incidents) == FETCH_LIMIT)
        - The key "late_indexed_pagination" in the last run object is set to True

        When
        - Fetching notables

        Then
        - Make sure that the key "late_indexed_pagination" in last run object is set to True
        """
        from SplunkPy import UserMappingObject
        # MonkeyPatch can be used to patch global variables
        monkeypatch.setattr(splunk, 'FETCH_LIMIT', 2)
        mocker.patch.object(demisto, 'setLastRun')
        mock_last_run = {'time': '2018-10-24T14:13:20', 'late_indexed_pagination': True,
                         'found_incidents_ids': {'1234': 1700497516, '5678': 1700497516}}
        mock_params = {'fetchQuery': '`notable` is cool', 'fetch_limit': 2}
        mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
        mocker.patch('demistomock.params', return_value=mock_params)
        mocker.patch('splunklib.results.JSONResultsReader', return_value=[self.notable1,
                                                                          self.notable2])
        set_last_run_mocker = mocker.patch('demistomock.setLastRun')
        service = self.Service()
        mapper = UserMappingObject(service, False)
        splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
        assert set_last_run_mocker.call_args_list[0][0][0]['late_indexed_pagination'] is True


def test_fetch_incidents(mocker):
    """
    Given
    - mocked incidents api response
    - a mapper which should not map the user owner into the incident response

    When
    - executing the fetch incidents flow

    Then
    - make sure the incident response is valid.
    - make sure that the owner is not part of the incident response
    """
    from SplunkPy import UserMappingObject
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something"}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mocker.patch('splunklib.results.JSONResultsReader', return_value=SAMPLE_RESPONSE)
    mapper = UserMappingObject(service, False)
    splunk.fetch_incidents(service, mapper, 'from_xsoar', 'from_splunk')
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                   "Recurring Malware Infection - Rule"
    assert not incidents[0].get('owner')


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
    """
    Given
    - mocked incidents api response
    - a mapper which should not map the user owner into the incident response

    When
    - executing the fetch notables flow

    Then
    - make sure the incident response is valid.
    - make sure that the owner is not part of the incident response
    """
    mocker.patch.object(splunk.client.Job, 'is_done', return_value=True)
    mocker.patch.object(splunk.client.Job, 'results', return_value=None)
    mocker.patch.object(splunk, 'ENABLED_ENRICHMENTS', [splunk.ASSET_ENRICHMENT,
                                                        splunk.DRILLDOWN_ENRICHMENT, splunk.IDENTITY_ENRICHMENT])
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something"}
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    service = Service('DONE')
    mocker.patch('splunklib.results.JSONResultsReader', return_value=SAMPLE_RESPONSE)
    mapper = splunk.UserMappingObject(service, False)
    splunk.fetch_incidents(service, mapper=mapper, comment_tag_to_splunk='comment_tag_to_splunk',
                           comment_tag_from_splunk='comment_tag_from_splunk')
    cache_object = splunk.Cache.load_from_integration_context(get_integration_context())
    assert cache_object.submitted_notables
    notable = cache_object.submitted_notables[0]
    incident_from_cache = notable.to_incident(mapper, 'comment_tag_to_splunk', 'comment_tag_from_splunk')
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 0
    assert incident_from_cache["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                          "Recurring Malware Infection - Rule"
    assert not incident_from_cache.get('owner')

    # now call second time to make sure that the incident fetched
    splunk.fetch_incidents(service, mapper=mapper, comment_tag_to_splunk='comment_tag_to_splunk',
                           comment_tag_from_splunk='comment_tag_from_splunk')
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Endpoint - Recurring Malware Infection - Rule : Endpoint - " \
                                   "Recurring Malware Infection - Rule"
    assert not incidents[0].get('owner')


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
    mocker.patch('SplunkPy.get_integration_context', return_value=integration_context)
    mocker.patch('SplunkPy.set_integration_context')
    splunk.reset_enriching_fetch_mechanism()
    assert integration_context == {'wow': 'wow'}


@pytest.mark.parametrize(
    "drilldown_creation_time, asset_creation_time, enrichment_timeout, output",
    [
        (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), 5, False),
        (
            (datetime.utcnow() - timedelta(minutes=6)).isoformat(),
            datetime.utcnow().isoformat(),
            5,
            True,
        ),
    ],
)
def test_is_enrichment_exceeding_timeout(mocker, drilldown_creation_time, asset_creation_time, enrichment_timeout,
                                         output):
    """
    Scenario: When one of the notable's enrichments is exceeding the timeout, we want to create an incident with all
     the data gathered so far.

    Given:
    - Two enrichments that none of them exceeds the timeout.
    - An enrichment exceeding the timeout and one that does not exceeds the timeout.

    When:
    - is_enrichment_process_exceeding_timeout is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(splunk, 'ENABLED_ENRICHMENTS',
                        return_value=[splunk.DRILLDOWN_ENRICHMENT, splunk.ASSET_ENRICHMENT])
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


@pytest.mark.parametrize('notable_data, raw, earliest, latest', [
    ({}, {}, "", ""),
    ({"drilldown_earliest": f"${splunk.INFO_MIN_TIME}$",
      "drilldown_latest": f"${splunk.INFO_MAX_TIME}$"},
     {splunk.INFO_MIN_TIME: '1', splunk.INFO_MAX_TIME: '2'}, '1', '2'),
    ({"drilldown_earliest": '1', "drilldown_latest": '2', }, {}, '1', '2')
])
def test_get_drilldown_timeframe(notable_data, raw, earliest, latest, mocker):
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
    earliest_offset, latest_offset = splunk.get_drilldown_timeframe(notable_data, raw)
    assert earliest_offset == earliest
    assert latest_offset == latest


@pytest.mark.parametrize('raw_field, notable_data, expected_field, expected_value', [
    ('field|s', {'field': '1'}, 'field', '1'),
    ('field', {'field': '1'}, 'field', '1'),
    ('field|s', {'_raw': 'field=1, value=2'}, 'field', '1'),
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


@pytest.mark.parametrize('notable_data, search, raw, is_query_name, expected_search', [
    ({'a': '1', '_raw': 'c=3'}, 'search a=$a|s$ c=$c$ suffix', {'c': '3'}, False, 'search a="1" c="3" suffix'),
    ({'a': ['1', '2'], 'b': '3'}, 'search a=$a|s$ b=$b|s$ suffix', {}, False, 'search (a="1" OR a="2") b="3" suffix'),
    ({'a': '1', '_raw': 'b=3', 'event_id': '123'}, 'search a=$a|s$ c=$c$ suffix', {'b': '3'}, False, ''),
    ({"signature": "Backdoor.test"}, "View related '$signature$' events for $dest$", {"dest": "ACME-test-005"}, True,
     "View related 'Backdoor.test' events for ACME-test-005"),
    ({}, 'View all wineventlogs involving user="$user$"', {'user': "test"}, True,
     'View all wineventlogs involving user="test"'),
    ({}, 'Test query name', {}, True, 'Test query name'),
    ({'user': 'test\crusher'}, 'index="test" | where user = $user|s$', {}, False,
     'index="test" | where user="test\\\\crusher"'),
    ({'user': 'test\crusher'}, 'index="test" | where user = "$user|s$"', {}, False,
     'index="test" | where user="test\\\\crusher"'),
    ({'countryNameA': '"test\country"', 'countryNameB': '""'},
     'search countryA="$countryNameA|s$" countryB=$countryNameB|s$', {}, False,
     'search countryA="test\country" countryB=""'),
    ({'test': 'test_user'},
     'search countryA=\$this is a test\$', {}, False,
     'search countryA=\$this is a test\$'),
], ids=[
    "search query fields in notables data and raw data",
    "search query fields in notable data more than one value",
    "search query fields don't exist in notable data and raw data",
    "query name fields in notables data and raw data",
    "query name fields in raw data",
    "query name without fields to replace",
    "search query with a user field that contains a backslash",
    "search query with a user field that is surrounded by quotation marks and contains a backslash",
    "search query fields in notable data more than one value, with one empty value",
    "search query with $ as part of the search - no need to replace"

])
def test_build_drilldown_search(notable_data, search, raw, is_query_name, expected_search, mocker):
    """
    Scenario: When building the drilldown search query, we replace every field in between "$" sign with its
     corresponding query part (key & value).

    Given:
    - A raw search query with fields both in the notable's data and in the notable's raw data
    - A raw search query with fields in the notable's data that has more than one value
    - A raw search query with fields that does not exist in the notable's data or in the notable's raw data
    - A raw query name with fields both in the notable's data and in the notable's raw data
    - A raw query name with fields in the notable's raw data
    - A raw query name without any fields to replace.
    - A raw query search with a user field that contains a backslash
    - A raw query search with a user field that is surrounded by quotation marks and contains a backslash


    When:
    - build_drilldown_search is called

    Then:
    - Return the expected result
    """
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'params', return_value={})
    parsed_query = splunk.build_drilldown_search(notable_data, search, raw, is_query_name)
    assert parsed_query == expected_search


@pytest.mark.parametrize('notable_data, prefix, fields, query_part', [
    ({'user': ['u1', 'u2']}, 'identity', ['user'], '(identity="u1" OR identity="u2")'),
    ({'_raw': '1233, user=u1'}, 'user', ['user'], 'user="u1"'),
    ({'user': ['u1', 'u2'], '_raw': '1321, src_user=u3'}, 'user', ['user', 'src_user'],
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


@pytest.mark.parametrize('enrichments, expected_result', [
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1'),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='2'),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='3')], 3),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1'),
      splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='2'),
      splunk.Enrichment(splunk.IDENTITY_ENRICHMENT, enrichment_id='3')], 1),
    ([splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='1'),
      splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='2'),
      splunk.Enrichment(splunk.IDENTITY_ENRICHMENT, enrichment_id='3')], 0)
], ids=[
    "A Notable with 3 drilldown enrichments",
    "A Notable with 1 drilldown enrichment, 1 asset enrichment and 1 identity enrichment",
    "A Notable with 2 asset enrichments and 1 identity enrichment"
])
def test_drilldown_searches_counter(enrichments, expected_result):
    """
     Tests the drilldown searches enrichment counter.

    Given:
    - A Notable with 3 drilldown enrichments.
    - A Notable with 1 drilldown enrichment, 1 asset enrichment and 1 identity enrichment.
    - A Notable with 2 asset enrichments and 1 identity enrichment.

    When:
    - drilldown_searches_counter function is called

    Then:
    - Return the expected result - number of drilldown enrichments.
    """
    notable = splunk.Notable({}, notable_id='id', enrichments=enrichments)
    assert notable.drilldown_searches_counter() == expected_result


@pytest.mark.parametrize('enrichments, expected_data', [
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name1', query_search='query_search1', data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='2', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name2', query_search='query_search2', data=[{'result1': 'c'}, {'result2': 'd'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='3', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name3', query_search='query_search3', data=[{'result1': 'e'}, {'result2': 'f'}])],
     [{'query_name': 'query_name1', 'query_search': 'query_search1', 'query_results': [{'result1': 'a'}, {'result2': 'b'}],
       'enrichment_status': splunk.Enrichment.SUCCESSFUL},
      {'query_name': 'query_name2', 'query_search': 'query_search2', 'query_results': [{'result1': 'c'}, {'result2': 'd'}],
       'enrichment_status': splunk.Enrichment.SUCCESSFUL},
      {'query_name': 'query_name3', 'query_search': 'query_search3', 'query_results': [{'result1': 'e'}, {'result2': 'f'}],
       'enrichment_status': splunk.Enrichment.SUCCESSFUL}]
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name1', query_search='query_search1', data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='2', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name2', query_search='query_search2', data=[{'result1': 'c'}, {'result2': 'd'}])],
     [{'query_name': 'query_name1', 'query_search': 'query_search1', 'query_results': [{'result1': 'a'}, {'result2': 'b'}],
       'enrichment_status': splunk.Enrichment.SUCCESSFUL},
      {'query_name': 'query_name2', 'query_search': 'query_search2', 'query_results': [{'result1': 'c'}, {'result2': 'd'}],
       'enrichment_status': splunk.Enrichment.SUCCESSFUL}]
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name1', query_search='query_search1', data=[{'result1': 'a'}, {'result2': 'b'}])],
     [{'result1': 'a'}, {'result2': 'b'}]
     ),
    ([], None)
], ids=[
    "A Notable with 3 drilldown enrichments, 1 asset enrichment and 1 identity enrichment",
    "A Notable with 2 drilldown enrichment, 1 asset enrichment and 1 identity enrichment",
    "A Notable with 1 drilldown enrichment, 1 asset enrichment and 1 identity enrichment",
    "A Notable without drilldown enrichments, 1 asset enrichments and 1 identity enrichment"
])
def test_to_incident_notable_enrichments_data(enrichments, expected_data):
    """
     Tests the logic of the Notable.to_incident() function, regarding the results data of multiple drilldown enrichments.

    Given:
        1. A Notable with 3 drilldown enrichments, 1 asset enrichment and 1 identity enrichment.
        2. A Notable with 2 drilldown enrichment, 1 asset enrichment and 1 identity enrichment.
        3. A Notable with 1 drilldown enrichment, 1 asset enrichment and 1 identity enrichment.
        4. A Notable without drilldown enrichments, 1 asset enrichments and 1 identity enrichment.

    When:
    - Notable.to_incident() function is called

    Then:
    - Verify that the data of the notable includes the expected enrichements result as follow:
        1. A dictionary with the results of the 3 drilldown searches by query names.
        2. A dictionary with the results of the 2 drilldown searches by query names.
        3. A list of the drilldown searches results (backwards competability).
        4. No 'Drilldown' key in the notables data.

    """
    notable = splunk.Notable({}, notable_id='id', enrichments=enrichments)
    enrichments_to_add = [
        splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='111', status=splunk.Enrichment.SUCCESSFUL,
                          data=[{'result1': 'a'}, {'result2': 'b'}]),
        splunk.Enrichment(splunk.IDENTITY_ENRICHMENT, enrichment_id='222', status=splunk.Enrichment.FAILED,
                          data=[{'result1': 'a'}, {'result2': 'b'}])
    ]
    notable.enrichments.extend(enrichments_to_add)

    service = Service('DONE')
    mapper = splunk.UserMappingObject(service, False)
    notable.to_incident(mapper, 'comment_tag_to_splunk', 'comment_tag_from_splunk')

    assert notable.data.get(splunk.ASSET_ENRICHMENT) == [{'result1': 'a'}, {'result2': 'b'}]
    assert notable.data.get(splunk.IDENTITY_ENRICHMENT) == [{'result1': 'a'}, {'result2': 'b'}]
    assert notable.data.get(splunk.DRILLDOWN_ENRICHMENT) == expected_data


@pytest.mark.parametrize('enrichments, enrichment_type, expected_stauts_result', [
    ([splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.ASSET_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.ASSET_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.ASSET_ENRICHMENT, False
     ),
    ([splunk.Enrichment(splunk.IDENTITY_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.IDENTITY_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.IDENTITY_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.IDENTITY_ENRICHMENT, False
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        query_name='query_name1', query_search='query_search1', data=[{'result1': 'a'}, {'result2': 'b'}])],
     splunk.DRILLDOWN_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        query_name='query_name1', query_search='query_search1', data=[{'result1': 'a'}, {'result2': 'b'}])],
     splunk.DRILLDOWN_ENRICHMENT, False
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.DRILLDOWN_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.DRILLDOWN_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.DRILLDOWN_ENRICHMENT, False
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.DRILLDOWN_ENRICHMENT, True
     ),
    ([splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.SUCCESSFUL,
                        data=[{'result1': 'a'}, {'result2': 'b'}]),
      splunk.Enrichment(splunk.DRILLDOWN_ENRICHMENT, enrichment_id='1', status=splunk.Enrichment.FAILED,
                        data=[{'result1': 'a'}, {'result2': 'b'}])], splunk.DRILLDOWN_ENRICHMENT, True
     )
], ids=[
    "A Notable with 1 successful Asset enrichment",
    "A Notable with 1 failed Asset enrichment",
    "A Notable with 1 successful Identity enrichment",
    "A Notable with 1 failed Identity enrichment",
    "A Notable with 1 successful Drilldown enrichment",
    "A Notable with 1 failed Drilldown enrichment",
    "A Notable with 1 successful Drilldown enrichment and 1 failed drilldown enrichment (the first is successful)",
    "A Notable with 1 successful Drilldown enrichment and 1 failed drilldown enrichment (the second is successful)",
    "A Notable with 2 Drilldown enrichments [failed, failed]",
    "A Notable with 2 Drilldown enrichments [successful, successful]",
    "A Notable with 3 Drilldown enrichments [failed, successful, failed]"
])
def test_to_incident_notable_enrichments_status(enrichments, enrichment_type, expected_stauts_result):
    """
     Tests the logic of the Notable.to_incident() function, regarding the statuses of enrichments.

    Given:
        1. A Notable with 1 successful Asset enrichment.
        2. A Notable with 1 failed Asset enrichment.
        3. A Notable with 1 successful Identity enrichment.
        4. A Notable with 1 failed Identity enrichment.
        5. A Notable with 1 successful Drilldown enrichment.
        6. A Notable with 1 failed Drilldown enrichment.
        7. A Notable with 1 successful Drilldown enrichment and 1 failed drilldown enrichment (the first is successful).
        8. A Notable with 1 successful Drilldown enrichment and 1 failed drilldown enrichment (the second is successful).
        9. A Notable with 2 Drilldown enrichments [failed, failed].
        10. A Notable with 2 Drilldown enrichments [successful, successful].
        11. A Notable with 3 Drilldown enrichments [failed, successful, failed].


    When:
    - Notable.to_incident() function is called

    Then:
    - Verify that the status of the notable enrichments is as follow:
        1. Asset Enrichment status is: successful_asset_enrichment = True.
        2. Asset Enrichment status is: successful_asset_enrichment = False.
        3. Identity Enrichment status is: successful_identity_enrichment = True.
        4. Identity Enrichment status is: successful_identity_enrichment = False.

        # In Drilldown enrichment - if at least one drilldown enrichment is successful the status is Success.
        5. Drilldown Enrichment status is: successful_drilldown_enrichment = True.
        6. Drilldown Enrichment status is: successful_drilldown_enrichment = False.
        7. Drilldown Enrichment status is: successful_drilldown_enrichment = True.
        8. Drilldown Enrichment status is: successful_drilldown_enrichment = True.
        9. Drilldown Enrichment status is: successful_drilldown_enrichment = False.
        10. Drilldown Enrichment status is: successful_drilldown_enrichment = True.
        11. Drilldown Enrichment status is: successful_drilldown_enrichment = True.

    """
    notable = splunk.Notable({}, notable_id='id', enrichments=enrichments)
    service = Service('DONE')
    mapper = splunk.UserMappingObject(service, False)
    notable.to_incident(mapper, 'comment_tag_to_splunk', 'comment_tag_from_splunk')

    assert notable.data[splunk.ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS[enrichment_type]] == expected_stauts_result


def test_parse_drilldown_searches():
    """
    Given:
    - A list of valid Json strings with splunk drilldown searches data.

    When:
    - Running the splunk.parse_drilldown_searches function

    Then:
    - Verify that the search data was parsed into a python dictionary as expected.
    """
    searches = ["{\"name\":\"View related '$signature$' events for $dest$\",\"search\":\"| from datamodel:\\\"Malware\\\"."
                "\\\"Malware_Attacks\\\" | search dest=$dest|s$ signature=$signature|s$\",\"earliest\":17145"
                "63300,\"latest\":1715168700}",
                "{\"name\":\"View related '$category$' events for $signature$\",\"search\":\"| from datamodel:\\\"Malw"
                "are\\\".\\\"Malware_Attacks\\\" \\n|  fields category, dest, signature | search dest=$dest|s$ signature="
                "$signature|s$\",\"earliest\":1714563300,\"latest\":1715168700}"
                ]
    parsed_searches = splunk.parse_drilldown_searches(searches)
    for search in parsed_searches:
        assert isinstance(search, dict)
    assert parsed_searches == [
        {'name': "View related '$signature$' events for $dest$",
         'search': '| from datamodel:"Malware"."Malware_Attacks" | search dest=$dest|s$ signature=$signature|s$',
         'earliest': 1714563300,
         'latest': 1715168700
         },
        {'name': "View related '$category$' events for $signature$",
         'search': '| from datamodel:"Malware"."Malware_Attacks" \n|  fields category, dest, signature | search dest=$dest|s$ '
                   'signature=$signature|s$',
         'earliest': 1714563300,
         'latest': 1715168700
         }
    ]


@pytest.mark.parametrize('notable_data, expected_call_count', [
    ({'event_id': 'test_id', 'drilldown_search': 'test_search', 'drilldown_searches': ['test_search1', 'test_search2']}, 0),
    ({'event_id': 'test_id', 'drilldown_search': '', 'drilldown_searches': ['test_search1', 'test_search2']}, 1),
    ({'event_id': 'test_id', 'drilldown_searches': ['test_search1', 'test_search2']}, 1)
], ids=[
    "A notable data with both 'drilldown_search' and 'drilldown_searches' keys with values",
    "A notable data with both 'drilldown_search' and 'drilldown_searches' keys but 'drilldown_search' has no value",
    "A notable data with 'drilldown_searches' key only"
])
def test_drilldown_enrichment_main_condition(mocker, notable_data, expected_call_count):
    """
    Tests the logic of the first (main) condition in the drilldown_enrichment() function.
    We want to make sure that in a case that the notable data include both 'drilldown_search' and 'drilldown_searches'
    keys (happens when there is only one drilldown search to enrich) the 'drilldown_search' value will be taken to maintain
    backwards cometability. In any other case the value of the 'drilldown_searches' key will be used.

    Given:
        1. A notable data that includes both 'drilldown_search' and 'drilldown_searches' keys with values.
        2. A notable data that includes both 'drilldown_search' and 'drilldown_searches' keys but 'drilldown_search' has no value.
        3. A notable data that includes 'drilldown_searches' key only.

    When:
    - Running the  splunk.drilldown_enrichment function

    Then:
    - Verify that:
        1. The value of the 'drilldown_search' key is taken (to maintain backwards competability), and therefore we don't call the
           parse_drilldown_searches function.
        2. The value of the 'drilldown_searches' key is taken, and therefore we call the parse_drilldown_searches function.
        3. The value of the 'drilldown_searches' key is taken, and therefore we call the parse_drilldown_searches function.

    """
    mock_parse_drilldown_searches = mocker.patch('SplunkPy.parse_drilldown_searches', return_value=[])
    service = Service('DONE')
    splunk.drilldown_enrichment(service, notable_data, 5)
    assert mock_parse_drilldown_searches.call_count == expected_call_count


@pytest.mark.parametrize('notable_data, expected_call_count', [
    ({'event_id': 'test_id', 'drilldown_search': 'test_search', 'drilldown_searches': [{}], '_raw': "{'test':1}"}, 1),
    ({'event_id': 'test_id',
      'drilldown_searches':
          ["{\"name\":\"View related '$signature$' events for $dest$\",\"search\":\"| from datamodel:\\\"Malware\\\".\\\"Malwa"
           "re_Attacks\\\" | search dest=$dest|s$ signature=$signature|s$\",\"earliest\":1714563300,\"latest\":1715168700}",
           "{\"name\":\"View related '$category$' events for $signature$\",\"search\":\"| from datamodel:\\\"Malware\\\".\\\"M"
           "alware_Attacks\\\" \\n|  fields category, dest, signature | search dest=$dest|s$ signature=$signature|s$\",\"ear"
           "liest\":1714563300,\"latest\":1715168700}"
           ]
      },
     0)
], ids=[
    "A notable data with one drilldown search",
    "A notable data with multiple drilldown searches"
])
def test_drilldown_enrichment_get_timeframe(mocker, notable_data, expected_call_count):
    """
    Tests that in a case of one drildown search we extract the search timeframe from the notable data by calling the
    get_drilldown_timeframe() function, and in a case of multiple drilldown searches, we get the timeframe from the drilldown
    search data dictionary without calling the get_drilldown_timeframe() function.

    Given:
        1. A notable data with one drilldown search.
        2. A notable data with multiple drilldown searches.


    When:
    - Running the splunk.get_drilldown_timeframe function.

    Then:
    - Verify that:
        1. The timeframe is determined according to fields in the notable data and raw data by using the
           get_drilldown_timeframe function.
        2. The timeframe is determined according to fields of each drilldown search data dict.

    """
    mock_get_drilldown_timeframe = mocker.patch('SplunkPy.get_drilldown_timeframe', return_value=("", ""))
    mocker.patch('SplunkPy.build_drilldown_search', return_value='')
    service = Service('DONE')
    splunk.drilldown_enrichment(service, notable_data, 5)
    assert mock_get_drilldown_timeframe.call_count == expected_call_count


@pytest.mark.parametrize('notable_data, expected_result', [
    ({'event_id': 'test_id', 'drilldown_name': 'View all login attempts by system $src$',
      'drilldown_search': "| from datamodel:\"Authentication\".\"Authentication\" | search src=$src|s$",
      'drilldown_searches': "{\"name\":\"View all login attempts by system $src$\",\"search\":\"| from datamodel:\\\"Authent"
                            "ication\\\".\\\"Authentication\\\" | search src=$src|s$\",\"earliest\":1715040000,"
                            "\"latest\":1715126400}",
      '_raw': "src=\'test_src\'", "drilldown_latest": "1715126400.000000000", "drilldown_earliest": "1715040000.000000000"},
     [
         ("View all login attempts by system 'test_src'",
          '| from datamodel:"Authentication"."Authentication" | search src="\'test_src\'"')]),

    ({'event_id': 'test_id2', 'drilldown_searches':
        ["{\"name\":\"View all login attempts by system $src$\",\"search\":\"| from datamodel:\\\"Authentication\\\".\\\"Authe"
         "ntication\\\" | search src=$src|s$\",\"earliest\":1715040000,\"latest\":1715126400}",
         "{\"name\":\"View all test involving user=\\\"$user$\\\"\",\"search\":\"index=\\\"test\\\"\\n| where "
         "user = $user|s$\",\"earliest\":1716955500,\"latest\":1716959400}"],
      '_raw': "src=\'test_src\', user='test_user'"},
     [("View all login attempts by system 'test_src'",
       '| from datamodel:"Authentication"."Authentication" | search src="\'test_src\'"'),
      ('View all test involving user="\'test_user\'"',
       'search index="test"\n| where user="\'test_user\'"')]),
    ({'event_id': 'test_id3', 'drilldown_searches':
        ["{\"name\":\"View all login attempts by system $src$\",\"search\":\"| from datamodel:\\\"Authentication\\\".\\\"Authe"
         "ntication\\\" | search src=$src|s$\",\"earliest_offset\":1715040000,\"latest_offset\":1715126400}",
         "{\"name\":\"View all test involving user=\\\"$user$\\\"\",\"search\":\"index=\\\"test\\\"\\n| where "
         "user = $user|s$\",\"earliest_offset\":1716955500,\"latest_offset\":1716959400}"],
      '_raw': "src=\'test_src\', user='test_user'"},
     [("View all login attempts by system 'test_src'",
       '| from datamodel:"Authentication"."Authentication" | search src="\'test_src\'"'),
      ('View all test involving user="\'test_user\'"',
       'search index="test"\n| where user="\'test_user\'"')]),
], ids=[
    "A notable data with one drilldown search enrichment",
    "A notable data with two drilldown searches which contained the earlies in 'earliest' key ",
    "A notable data with two drilldown searches which contained the earlies in 'earliest_offset' key "
])
def test_drilldown_enrichment(notable_data, expected_result):
    """
    Tests the logic of the drilldown_enrichment function.

    Given:
        1. A notable data with one drilldown search enrichment.
        2. A notable data with multiple (two) drilldown searches to enrich.


    When:
    - Running the splunk.drilldown_enrichment function.

    Then:
    - Verify that the returned jobs and queries are as expected.

    """
    from splunklib import client
    service = Service('DONE')
    jobs_and_queries = splunk.drilldown_enrichment(service, notable_data, 5)
    for i in range(len(jobs_and_queries)):
        job_and_queries = jobs_and_queries[i]
        assert job_and_queries[0] == expected_result[i][0]
        assert job_and_queries[1] == expected_result[i][1]
        assert isinstance(job_and_queries[2], client.Job)


@pytest.mark.parametrize('notable_data, debug_log_message', [
    ({'event_id': 'test_id'}, 'drill-down was not properly configured for notable test_id'),

    ({'event_id': 'test_id', 'drilldown_name': 'View all login attempts by system $src$',
      'drilldown_search': "| from datamodel:\"Authentication\".\"Authentication\" | search src=$src|s$",
      '_raw': "src=\'test_src\'", "drilldown_latest": "", "drilldown_earliest": ""},
     'Failed getting the drilldown timeframe for notable test_id'),

    ({'event_id': 'test_id', 'drilldown_name': 'View all login attempts by system $src$',
      'drilldown_search': "| from datamodel:\"Authentication\".\"Authentication\" | search src=$src|s$", '_raw': "",
      "drilldown_latest": "00101", "drilldown_earliest": "00001"},
     "Couldn't build search query for notable test_id with the following drilldown search "),

    ({'event_id': 'test_id',
      'drilldown_searches': [
          "{\"name\":\"View all login attempts by system $src$\",\"search\":\"| from datamodel:\\\"Authentica"
          "tion\\\".\\\"Authentication\\\" | search src=$src|s$\",\"earliest\":\"\",\"latest\":\"\"}",
          "{\"name\":\"View all test involving user=\\\"$user$\\\"\",\"search\":\"index=\\\"test\\\"\\n| where user ="
          "$user|s$\",\"earliest\":\"\",\"latest\":\"\"}"],
      '_raw': "src=\'test_src\', user='test_user'"},
     'Failed getting the drilldown timeframe for notable test_id'),

    ({'event_id': 'test_id',
      'drilldown_searches':
          ["{\"name\":\"View all login attempts by system $src$\",\"search\":\"| from datamodel:\\\"Authentic"
           "ation\\\".\\\"Authentication\\\" | search src=$src|s$\",\"earliest\":\"\",\"latest\":\"\"}",
           "{\"name\":\"View all test involving user=\\\"$user$\\\"\",\"search\":\"index=\\\"test\\\"\\n| where user ="
           "$user|s$\",\"earliest\":\"\",\"latest\":\"\"}"], '_raw': ""},
     "Couldn't build search query for notable test_id with the following drilldown search"),
], ids=[
    "A notable data without drilldown enrichment data",
    "A notable data with a single drilldown enrichment without search timeframe data",
    "A notable data with a single drilldown enrichment with an invalid search query",
    "A notable data with multiple drilldown enrichments without search timeframe data",
    "A notable data with multiple drilldown enrichments with invalid search queries"
])
def test_drilldown_enrichment_no_enrichement_cases(mocker, notable_data, debug_log_message):
    """
    Tests the logic of the drilldown_enrichment function when for some reason the enrichments raw data is invalid.

    Given:
        1. A notable data without drilldown enrichment data.
        2. A notable data with a single drilldown enrichment without search timeframe data.
        3. A notable data with a single drilldown enrichment with an invalid search query.
        4. A notable data with multiple drilldown enrichments without search timeframe data.
        5. A notable data with multiple drilldown enrichments with invalid search queries.

    When:
    - Running the splunk.drilldown_enrichment function.

    Then:
    - Verify that the returned value is a tuple of None values as expected.

    """
    debug_log = mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'error')
    service = Service('DONE')
    jobs_and_queries = splunk.drilldown_enrichment(service, notable_data, 5)
    for i in range(len(jobs_and_queries)):
        assert jobs_and_queries[i] == (None, None, None)
        assert debug_log_message in debug_log.call_args.args[0]


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


@pytest.mark.parametrize(
    "notable_data, func_call_kwargs, expected_closure_data",
    [
        # A Notable with a "Closed" status label
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Closed", "event_id": "id", "status_end": "true"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": False,
                "close_extra_labels": [],
            },
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": 'Notable event was closed on Splunk with status "Closed".',
                },
                "ContentsFormat": EntryFormat.JSON,
            },
        ),
        # A Notable with a "New" status label (shouldn't close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "New", "event_id": "id", "status_end": "false"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": False,
                "close_extra_labels": [],
            },
            None,
        ),
        # A Notable with a custom status label that is on close_extra_labels (should close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Custom", "event_id": "id", "status_end": "false"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": False,
                "close_extra_labels": ["Custom"],
            },
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": 'Notable event was closed on Splunk with status "Custom".',
                },
                "ContentsFormat": EntryFormat.JSON,
            },
        ),
        # A Notable with close_extra_labels that don't include status_label (shouldn't close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Custom", "event_id": "id", "status_end": "false"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": False,
                "close_extra_labels": ["A", "B"],
            },
            None,
        ),
        # A Notable that has status_end as true with close_end_statuses as true (should close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Custom", "event_id": "id", "status_end": "true"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": True,
                "close_extra_labels": [],
            },
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": 'Notable event was closed on Splunk with status "Custom".',
                },
                "ContentsFormat": EntryFormat.JSON,
            },
        ),
        # A Notable that has status_end as true with close_end_statuses as false (shouldn't close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Custom", "event_id": "id", "status_end": "true"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": False,
                "close_extra_labels": [],
            },
            None,
        ),
        # A Notable that is both on close_extra_labels,
        # and has status_end as true with close_end_statuses as true (should close)
        (
            [
                results.Message("INFO-TEST", "test message"),
                {"status_label": "Custom", "event_id": "id", "status_end": "true"},
            ],
            {
                "close_incident": True,
                "close_end_statuses": True,
                "close_extra_labels": ["Custom"],
            },
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": 'Notable event was closed on Splunk with status "Custom".',
                },
                "ContentsFormat": EntryFormat.JSON,
            },
        ),
    ],
)
def test_get_remote_data_command_close_incident(mocker, notable_data: list[results.Message | dict],
                                                func_call_kwargs: dict, expected_closure_data: dict):
    class Jobs:
        def oneshot(self, _, output_mode: str):
            assert output_mode == splunk.OUTPUT_MODE_JSON
            return notable_data

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00', 'id': 'id'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch('SplunkPy.results.JSONResultsReader', return_value=notable_data)
    mocker.patch.object(demisto, 'results')
    service = Service()
    splunk.get_remote_data_command(service, args, mapper=splunk.UserMappingObject(service, False),
                                   comment_tag_from_splunk='comment_tag_from_splunk', **func_call_kwargs)
    results = demisto.results.call_args[0][0]

    expected_results = [notable_data[1]]

    if expected_closure_data:
        expected_results.append(expected_closure_data)

    assert demisto.results.call_count == 1
    assert results == expected_results


def test_get_remote_data_command_with_message(mocker):
    """
    Test for the get_remote_data_command function with a message.

    This test verifies that when the splunk-sdk returns a message, the function correctly logs the message
    using demisto.info().

    Args:
        mocker: The mocker object for patching and mocking.

    Returns:
        None
    """

    class Jobs:
        def oneshot(self, _, output_mode: str):
            assert output_mode == splunk.OUTPUT_MODE_JSON
            return results.Message("INFO-test", "test message")

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    func_call_kwargs = {
        "args": {"lastUpdate": "2021-02-09T16:41:30.589575+02:00", "id": "id"},
        "close_incident": True,
        "close_end_statuses": True,
        "close_extra_labels": ["Custom"],
        "mapper": splunk.UserMappingObject(Service(), False),
    }
    info_mock = mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "params", return_value={"timezone": "0"})
    mocker.patch(
        "SplunkPy.results.JSONResultsReader", return_value=[results.Message("INFO-test", "test message")]
    )
    mocker.patch("SplunkPy.isinstance", return_value=True)

    splunk.get_remote_data_command(Service(), comment_tag_from_splunk='from_splunk', **func_call_kwargs)
    (info_message,) = info_mock.call_args_list[0][0]
    assert info_message == "Splunk-SDK message: test message"


def test_fetch_with_error_in_message(mocker):
    """
    Given - fetch result from Splunk return Error message
    When - fetch incidents
    Then - assert DemistoException is raised
    """

    mock_params = {'fetchQuery': "something", "parseNotableEventsRaw": True}
    mocker.patch('demistomock.getLastRun', return_value={'time': '2018-10-24T14:13:20'})
    mocker.patch('demistomock.params', return_value=mock_params)
    mocker.patch('splunklib.results.JSONResultsReader', return_value=[results.Message("FATAL", "Error")])

    # run
    service = mocker.patch('splunklib.client.connect')
    with pytest.raises(DemistoException) as e:
        splunk.fetch_incidents(service, None, None, None)
    assert 'Failed to fetch incidents, check the provided query in Splunk web search' in e.value.message


@pytest.mark.parametrize("notable_data, func_call_kwargs, expected_closure_data",
                         [({'status_label': 'New', 'event_id': 'id', 'status_end': 'false',
                            'comment': 'new comment from splunk', 'reviewer': 'admin',
                            'review_time': '1612881691.589575'},
                           {'close_incident': True, 'close_end_statuses': False, 'close_extra_labels': []},
                           None,
                           )])
def test_get_remote_data_command_add_comment(mocker, notable_data: dict,
                                             func_call_kwargs: dict, expected_closure_data: dict):
    """
    Test case for get_remote_data_command with comment addition.
    Given:
        - notable data with new comment
    When:
        new comment added in splunk
    Then:
        - ensure the comment added as a new note
        - ensure the event was updated

    """

    class Jobs:
        def oneshot(self, _, output_mode: str):
            assert output_mode == splunk.OUTPUT_MODE_JSON
            return notable_data

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00', 'id': 'id'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch('SplunkPy.results.JSONResultsReader', return_value=[notable_data])
    mocker.patch.object(demisto, 'results')
    service = Service()

    expected_comment_note = {'Type': 1, 'Contents': 'new comment from splunk',
                             'ContentsFormat': 'text', 'Tags': ['from_splunk'], 'Note': True}
    splunk.get_remote_data_command(service, args, mapper=splunk.UserMappingObject(service, False),
                                   comment_tag_from_splunk='from_splunk', **func_call_kwargs)
    results = demisto.results.call_args[0][0][0]
    notable_data.update({'SplunkComments': [{'Comment': 'new comment from splunk'}]})
    note_results = demisto.results.call_args[0][0][1]

    expected_results = [notable_data][0]

    assert demisto.results.call_count == 1
    assert results == expected_results
    assert note_results == expected_comment_note


def test_get_modified_remote_data_command(mocker):
    updated_incidet_review = {'rule_id': 'id'}

    class Jobs:
        def __init__(self):
            self.oneshot = lambda x, count, output_mode: [updated_incidet_review]

    class Service:
        def __init__(self):
            self.jobs = Jobs()

    args = {'lastUpdate': '2021-02-09T16:41:30.589575+02:00'}
    mocker.patch.object(demisto, 'params', return_value={'timezone': '0'})
    mocker.patch.object(demisto, 'debug')
    mocker.patch('SplunkPy.results.JSONResultsReader', return_value=[updated_incidet_review])
    mocker.patch.object(demisto, 'results')
    splunk.get_modified_remote_data_command(Service(), args)
    results = demisto.results.call_args[0][0]['Contents']
    assert demisto.results.call_count == 1
    assert results == [updated_incidet_review['rule_id']]


def test_edit_notable_event__failed_to_update(mocker, requests_mock):
    """
    Given
    - notable event with id ID100

    When
    - updating the event with invalid owner 'dbot'
    - the service should return error string message 'ValueError: Invalid owner value.'

    Then
    - ensure the error message parsed correctly and returned to the user
    """
    test_base_url = 'https://test.url.com:8089/'
    test_token = 'token12345'
    test_args = {
        'eventIDs': 'ID100',
        'owner': 'dbot'
    }
    mocker.patch.object(splunk, 'return_error')

    requests_mock.post(f'{test_base_url}services/notable_update', json='ValueError: Invalid owner value.')

    splunk.splunk_edit_notable_event_command(
        base_url=test_base_url,
        token=test_token,
        auth_token=None,
        args=test_args
    )

    assert splunk.return_error.call_count == 1
    error_message = splunk.return_error.call_args[0][0]
    assert error_message == 'Could not update notable events: ID100: ValueError: Invalid owner value.'


@pytest.mark.parametrize('args, params, call_count, success', [
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}}, 4, True),
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}}, 3, False),
    ({'delta': {'status': '2'}, 'remoteId': '12345', 'status': 2, 'incidentChanged': True},
     {'host': 'ec.com', 'port': '8089', 'authentication': {'identifier': 'i', 'password': 'p'}, 'close_notable': True},
     5, True)
])
def test_update_remote_system(args, params, call_count, success, mocker, requests_mock):
    class Service:
        def __init__(self):
            self.token = 'fake_token'
            self.basic = True
            self._auth_headers = [('Authentication', self.token)]

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    base_url = 'https://' + params['host'] + ':' + params['port'] + '/'
    requests_mock.post(
        f'{base_url}services/auth/login', json={'sessionKey': 'session_key'}
    )
    requests_mock.post(
        f'{base_url}services/notable_update',
        json={'success': success, 'message': 'wow'},
    )
    if not success:
        mocker.patch.object(demisto, 'error')
    service = Service()
    mapper = splunk.UserMappingObject(service, False)
    assert splunk.update_remote_system_command(args, params, service, None, mapper=mapper,
                                               comment_tag_to_splunk='comment_tag_to_splunk') == args['remoteId']
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
    fields = splunk.get_cim_mapping_field_command()
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
            * rename headers
    """
    func_patch = mocker.patch('SplunkPy.update_headers_from_field_names')
    results = [
        {'ID': 1, 'Header with space': 'h1', 'header3': 1, 'header_without_space': '1234',
         'old_header_1': '1', 'old_header_2': '2'},
        {'ID': 2, 'Header with space': 'h2', 'header3': 2, 'header_without_space': '1234',
         'old_header_1': '1', 'old_header_2': '2'},
    ]
    args = {
        'query': 'something | table ID "Header with space" header3 header_without_space '
                 'comma,separated "Single,Header,with,Commas" old_header_1 old_header_2 | something else'
                 ' | rename old_header_1 AS new_header_1 old_header_2 AS new_header_2'
    }
    expected_headers = ['ID', 'Header with space', 'header3', 'header_without_space',
                        'comma', 'separated', 'Single,Header,with,Commas', 'new_header_1', 'new_header_2']

    splunk.build_search_human_readable(args, results, sid='123456')
    headers = func_patch.call_args[0][1]
    assert headers == expected_headers


def test_build_search_human_readable_multi_table_in_query(mocker):
    """
    Given:
        multiple table headers in query

    When:
        building a human readable table as part of splunk-search

    Then:
        Test headers are calculated correctly:
            * all expected header exist without duplications
    """
    args = {
        "query": " table header_1, header_2 | stats state_1, state_2 | table header_1, header_2, header_3, header_4"}
    results = [
        {'header_1': 'val_1', 'header_2': 'val_2', 'header_3': 'val_3', 'header_4': 'val_4'},
    ]
    expected_headers_hr = "|header_1|header_2|header_3|header_4|\n|---|---|---|---|"
    hr = splunk.build_search_human_readable(args, results, sid='123456')
    assert expected_headers_hr in hr


@pytest.mark.parametrize('polling, fast_mode', [(False, True), (True, True)])
def test_build_search_kwargs(polling, fast_mode):
    """
    Given:
        The splunk-search command args.

    When:
        Running the build_search_kwargs to build the search query kwargs.

    Then:
        Ensure the query kwargs as expected.
    """
    args = {'earliest_time': '2021-11-23T10:10:10', 'latest_time': '2021-11-23T10:10:20', 'app': 'test_app',
            'fast_mode': fast_mode, 'polling': polling}
    kwargs_normalsearch = splunk.build_search_kwargs(args, polling)
    for field in args:
        if field == 'polling':
            assert 'exec_mode' in kwargs_normalsearch
            if polling:
                assert kwargs_normalsearch['exec_mode'] == 'normal'
            else:
                assert kwargs_normalsearch['exec_mode'] == 'blocking'
        elif field == 'fast_mode' and fast_mode:
            assert kwargs_normalsearch['adhoc_search_level'] == 'fast'
        else:
            assert field in kwargs_normalsearch


@pytest.mark.parametrize('polling,status', [
    (False, 'DONE'), (True, 'DONE'), (True, 'RUNNING')
])
def test_splunk_search_command(mocker, polling, status):
    """
    Given:
        A search query with args.

    When:
        Running the splunk_search_command with and without polling.

    Then:
        Ensure the result as expected in polling and in regular search.
    """
    mock_args = {
        "query": "query",
        "earliest_time": "2021-11-23T10:10:10",
        "latest_time": "2020-10-20T10:10:20",
        "app": "test_app",
        "fast_mode": "false",
        "polling": polling,
    }

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    search_result = splunk.splunk_search_command(Service(status), mock_args)
    search_result = search_result if isinstance(search_result, CommandResults) else search_result[0]

    if search_result.scheduled_command:
        assert search_result.outputs['Status'] == status
        assert search_result.scheduled_command._args['sid'] == '123456'
    else:
        assert search_result.outputs['Splunk.Result'] == []
        assert search_result.readable_output == '### Splunk Search results for query:\n' \
                                                'sid: 123456\n**No entries.**\n'


@pytest.mark.parametrize('messages,expected_msg', [
    ({'fatal': ['fatal msg']}, 'fatal msg'),
    ({'error': ['error msg']}, 'error msg')
])
def test_err_in_splunk_search(mocker, messages, expected_msg):
    """
    Given:
        A wrong search query.

    When:
        Running the splunk_search_command.

    Then:
        Ensure the result as expected in polling and in regular search.
    """
    mock_args = {
        "query": "wrong search query",
        "earliest_time": "2021-11-23T10:10:10",
        "latest_time": "2020-10-20T10:10:20",
        "fast_mode": "false",
    }
    service = Service(status="FAILED")
    service.jobs.state.content['messages'] = messages
    with pytest.raises(DemistoException) as e:
        splunk.splunk_search_command(service, mock_args)
    assert f'Failed to run the search in Splunk: {expected_msg}' in str(e)


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

    splunk.test_module(service, {})

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
        raise AuthenticationError

    mocker.patch.object(AuthenticationError, '__init__', return_value=None)
    mocker.patch.object(client.Service, 'info', side_effect=exception_raiser)
    mocker.patch.object(client.Service, 'login')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    service = client.Service(**credentials)

    # run
    splunk.test_module(service, {})

    # validate
    assert return_error_mock.call_args[0][0] == 'Authentication error, please validate your credentials.'


def test_module_hec_url(mocker):
    """
    Given:
        - hec_url was is in params

    When:
        - Run test-module command

    Then:
        - Validate that the request.get was called with the expected args
    """
    # prepare
    mocker.patch.object(client.Service, 'info')
    mocker.patch.object(client.Service, 'login')
    mocker.patch.object(requests, 'get')

    service = client.Service(username='test', password='test')

    # run
    splunk.test_module(service, {'hec_url': 'test_hec_url'})

    # validate
    assert requests.get.call_args[0][0] == 'test_hec_url/services/collector/health'


def test_module_message_object(mocker):
    """
    Given:
        - query results with one message item.

    When:
        - Run test-module command.

    Then:
        - Validate the test_module run successfully and the info method was called once.
    """
    # prepare
    message = results.Message("DEBUG", "There's something in that variable...")
    mocker.patch('splunklib.results.JSONResultsReader', return_value=[message])
    service = mocker.patch('splunklib.client.connect', return_value=None)
    # run
    splunk.test_module(service, {'isFetch': True, 'fetchQuery': 'something'})

    # validate
    assert service.info.call_count == 1


def test_labels_with_non_str_values(mocker):
    """
    Given:
        - Raw response with values in _raw that stored as dict or list

    When:
        - Fetch incidents

    Then:
        - Validate the Labels created in the incident are well formatted to avoid server errors on json.Unmarshal
    """
    from SplunkPy import UserMappingObject
    # prepare
    raw = {
        "message": "Authentication of user via Radius",
        "actor_obj": {
            "id": "test",
            "type": "User",
            "alternateId": "test",
            "displayName": "test"
        },
        "actor_list": [{
            "id": "test",
            "type": "User",
            "alternateId": "test",
            "displayName": "test"
        }],
        "actor_tuple": ("id", "test"),
        "num_val": 100,
        "bool_val": False,
        "float_val": 100.0
    }
    mocked_response: list[results.Message | dict] = SAMPLE_RESPONSE.copy()
    mocked_response[1]['_raw'] = json.dumps(raw)
    mock_last_run = {'time': '2018-10-24T14:13:20'}
    mock_params = {'fetchQuery': "something", "parseNotableEventsRaw": True}
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch('demistomock.getLastRun', return_value=mock_last_run)
    mocker.patch('demistomock.params', return_value=mock_params)
    mocker.patch('splunklib.results.JSONResultsReader', return_value=mocked_response)

    # run
    service = mocker.patch('splunklib.client.connect', return_value=None)
    mapper = UserMappingObject(service, False)
    splunk.fetch_incidents(service, mapper, comment_tag_to_splunk='comment_tag_to_splunk',
                           comment_tag_from_splunk='comment_tag_from_splunk')
    incidents = demisto.incidents.call_args[0][0]

    # validate
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    labels = incidents[0]["labels"]
    assert len(labels) >= 7
    assert all(isinstance(label['value'], str) for label in labels)


def test_empty_string_as_app_param_value(mocker):
    """
    Given:
        - A mock to demisto.params that contains an 'app' key with an empty string as its value

    When:
        - Run splunk.get_connection_args() function

    Then:
        - Validate that the value of the 'app' key in connection_args is '-'
    """
    # prepare
    mock_params = {'app': '', 'host': '111', 'port': '111'}

    # run
    connection_args = splunk.get_connection_args(mock_params)

    # validate
    assert connection_args.get('app') == '-'


@pytest.mark.parametrize(argnames='host, expected_host', argvalues=[
    ('8.8.8.8', '8.8.8.8'),
    ('8.8.8.8/', '8.8.8.8'),
    ('https://www.test.com', 'www.test.com'),
    ('https://www.test.com/', 'www.test.com'),
])
def test_host_param(host, expected_host):
    """
    Given:
        - Different host values
    When:
        - Run get_connection_args() function
    Then:
        - Ensure the host is as expected
    """
    params = {'host': host, 'port': '111'}

    actuall_host = splunk.get_connection_args(params)['host']

    assert actuall_host == expected_host


OWNER_MAPPING = [{'xsoar_user': 'test_xsoar', 'splunk_user': 'test_splunk', 'wait': True},
                 {'xsoar_user': 'test_not_full', 'splunk_user': '', 'wait': True},
                 {'xsoar_user': '', 'splunk_user': 'test_not_full', 'wait': True}, ]

MAPPER_CASES_XSOAR_TO_SPLUNK = [
    ('', 'unassigned',
     'Could not find splunk user matching xsoar\'s . Consider adding it to the splunk_xsoar_users lookup.'),
    ('not_in_table', 'unassigned',
     'Could not find splunk user matching xsoar\'s not_in_table. Consider adding it to the splunk_xsoar_users lookup.')

]


@pytest.mark.parametrize('xsoar_name, expected_splunk, expected_msg', MAPPER_CASES_XSOAR_TO_SPLUNK)
def test_owner_mapping_mechanism_xsoar_to_splunk(mocker, xsoar_name, expected_splunk, expected_msg):
    """
    Given:
        - different xsoar values

    When:
        - fetching, or mirroring

    Then:
        - validates the splunk user is correct
    """

    def mocked_get_record(col, value_to_search):
        return filter(lambda x: x[col] == value_to_search, OWNER_MAPPING[:-1])

    service = mocker.patch('splunklib.client.connect', return_value=None)
    mapper = splunk.UserMappingObject(service, True, table_name='splunk_xsoar_users',
                                      xsoar_user_column_name='xsoar_user',
                                      splunk_user_column_name='splunk_user')
    mocker.patch.object(mapper, '_get_record', side_effect=mocked_get_record)
    error_mock = mocker.patch.object(demisto, 'error')
    s_user = mapper.get_splunk_user_by_xsoar(xsoar_name)
    assert s_user == expected_splunk
    if error_mock.called:
        assert error_mock.call_args[0][0] == expected_msg


MAPPER_CASES_SPLUNK_TO_XSOAR = [
    ('test_splunk', 'test_xsoar', None),
    ('test_not_full', '',
     "Xsoar user matching splunk's test_not_full is empty. Fix the record in splunk_xsoar_users lookup."),
    ('unassigned', '',
     "Could not find xsoar user matching splunk's unassigned. Consider adding it to the splunk_xsoar_users lookup."),
    ('not_in_table', '',
     "Could not find xsoar user matching splunk's not_in_table. Consider adding it to the splunk_xsoar_users lookup.")

]


@pytest.mark.parametrize('splunk_name, expected_xsoar, expected_msg', MAPPER_CASES_SPLUNK_TO_XSOAR)
def test_owner_mapping_mechanism_splunk_to_xsoar(mocker, splunk_name, expected_xsoar, expected_msg):
    """
    Given:
        - different xsoar values

    When:
        - fetching, or mirroring

    Then:
        - validates the splunk user is correct
    """

    def mocked_get_record(col, value_to_search):
        return filter(lambda x: x[col] == value_to_search, OWNER_MAPPING)

    service = mocker.patch('splunklib.client.connect', return_value=None)
    mapper = splunk.UserMappingObject(service, True, table_name='splunk_xsoar_users',
                                      xsoar_user_column_name='xsoar_user',
                                      splunk_user_column_name='splunk_user')
    mocker.patch.object(mapper, '_get_record', side_effect=mocked_get_record)
    error_mock = mocker.patch.object(demisto, 'error')
    s_user = mapper.get_xsoar_user_by_splunk(splunk_name)
    assert s_user == expected_xsoar
    if error_mock.called:
        assert error_mock.call_args[0][0] == expected_msg


COMMAND_CASES = [
    ({'xsoar_username': 'test_xsoar'},  # case normal single username was provided
     [{'SplunkUser': 'test_splunk', 'XsoarUser': 'test_xsoar'}]),
    ({'xsoar_username': 'test_xsoar, Non existing'},  # case normal multiple usernames were provided
     [{'SplunkUser': 'test_splunk', 'XsoarUser': 'test_xsoar'},
      {'SplunkUser': 'unassigned', 'XsoarUser': 'Non existing'}]),
    ({'xsoar_username': 'Non Existing,'},  # case normal&empty multiple usernames were provided
     [{'SplunkUser': 'unassigned', 'XsoarUser': 'Non Existing'},
      {'SplunkUser': 'Could not map splunk user, Check logs for more info.', 'XsoarUser': ''}]),
    ({'xsoar_username': ['test_xsoar', 'Non existing']},  # case normal&missing multiple usernames were provided
     [{'SplunkUser': 'test_splunk', 'XsoarUser': 'test_xsoar'},
      {'SplunkUser': 'unassigned', 'XsoarUser': 'Non existing'}]),
    ({'xsoar_username': ['test_xsoar', 'Non existing'], 'map_missing': False},
     # case normal & missing multiple usernames were provided without missing's mapping activated
     [{'SplunkUser': 'test_splunk', 'XsoarUser': 'test_xsoar'},
      {'SplunkUser': 'Could not map splunk user, Check logs for more info.', 'XsoarUser': 'Non existing'}]),
    ({'xsoar_username': 'Non Existing,', 'map_missing': False},  # case missing&empty multiple usernames were provided
     [{'SplunkUser': 'Could not map splunk user, Check logs for more info.', 'XsoarUser': 'Non Existing'},
      {'SplunkUser': 'Could not map splunk user, Check logs for more info.', 'XsoarUser': ''}]
     ),
]


@pytest.mark.parametrize('xsoar_names, expected_outputs', COMMAND_CASES)
def test_get_splunk_user_by_xsoar_command(mocker, xsoar_names, expected_outputs):
    """
    Given: a list of xsoar users
    When: trying to get splunk matching users
    Then: validates correctness of list
    """

    def mocked_get_record(col, value_to_search):
        return filter(lambda x: x[col] == value_to_search, OWNER_MAPPING[:-1])

    service = mocker.patch('splunklib.client.connect', return_value=None)

    mapper = splunk.UserMappingObject(service, True, table_name='splunk_xsoar_users',
                                      xsoar_user_column_name='xsoar_user',
                                      splunk_user_column_name='splunk_user')
    # Ignoring logging pytest error
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(mapper, '_get_record', side_effect=mocked_get_record)
    res = mapper.get_splunk_user_by_xsoar_command(xsoar_names)
    assert res.outputs == expected_outputs


@pytest.mark.parametrize(argnames='username, expected_username, basic_auth', argvalues=[
    ('test_user', 'test_user', False),
    ('test@_basic', 'test', True)])
def test_basic_authentication_param(mocker, username, expected_username, basic_auth):
    """
    Given: - the username contain '@_basic' suffix
    When:  - connecting to Splunk server
    Then:  - validate the connection args was sent as expected

    """
    mocked_params = {
        'host': 'test_host',
        'port': '8089',
        'proxy': 'false',
        'authentication': {
            'identifier': username,
            'password': 'test_password'
        }
    }
    mocker.patch.object(client, 'connect')
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='not_impl_command')

    with pytest.raises(NotImplementedError):
        splunk.main()

    assert client.connect.call_args[1]['username'] == expected_username
    assert ('basic' in client.connect.call_args[1]) == basic_auth


@pytest.mark.parametrize(argnames='host, expected_base_url', argvalues=[
    ('8.8.8.8', 'https://8.8.8.8:8089/'),
    ('https://www.test.com', 'https://www.test.com:8089/'),
    ('http://www.test.com', 'https://http://www.test.com:8089/'),  # we don't want to silently replace http with https
])
def test_base_url(mocker, host, expected_base_url):
    """
    Given: - Different host values
    When:  - Running the splunk-notable-event-edit command
    Then:  - Ensure the base URL is built as expected

    """
    mocked_params = {
        'host': host,
        'port': '8089',
        'proxy': 'false',
        'authentication': {
            'identifier': 'username',
            'password': 'test_password'
        }
    }
    mocker.patch.object(demisto, 'command', return_value='splunk-notable-event-edit')
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(client, 'connect')

    cmd = mocker.patch.object(splunk, 'splunk_edit_notable_event_command')
    splunk.main()

    assert cmd.call_args[0][0] == expected_base_url


@pytest.mark.parametrize(
    'item, expected',
    [
        ({'message': 'Test message'}, False),
        (results.Message('INFO', 'Test message'), True)
    ]
)
def test_handle_message(item: dict | results.Message, expected: bool):
    """
    Tests that passing a results.Message object returns True
    """
    assert splunk.handle_message(item) is expected


def test_single_drilldown_searches(mocker):
    """
    Given: - notable with single string represent dict, in the drilldown_searches key.
    When:  - call to drilldown_enrichment.
    Then:  - validate there is no errors in the process.

    """

    drilldown_searches = json.dumps(
        {
            "name": "test drilldown",
            "search": "| from datamodel: test",
            "earliest": 1719218100,
            "latest": 1719823500
        }
    )
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(splunk, 'build_drilldown_search', return_value=None)

    splunk.drilldown_enrichment(
        service=None,
        notable_data={'drilldown_searches': drilldown_searches, 'event_id': 'test_id'},
        num_enrichment_events=1)

    assert demisto.error.call_count == 0, 'Something was wrong in the drilldown_enrichment process'


@pytest.mark.parametrize(
    'drilldown_data, expected',
    [({'drilldown_search': 'test'}, ['test']),
     ({'drilldown_searches': '{"search_1":"test_1"}'}, [{'search_1': 'test_1'}]),
     ({'drilldown_searches': ['{"search_1":"test_1"}', '{"search_2":"test_2"}']},
      [{'search_1': 'test_1'}, {'search_2': 'test_2'}]),
     ({'drilldown_searches': '[{"search_1":"test_1"}]'},
      [{'search_1': 'test_1'}]),
     ({'drilldown_searches': '[{"search_1":"test_1"}, {"search_2":"test_2"}]'},
      [{'search_1': 'test_1'}, {'search_2': 'test_2'}])
     ]
)
def test_get_drilldown_searches(drilldown_data, expected):
    """
    Given:  -
        1. A notable data with a single 'old' (string value in the 'drilldown_search' key) drilldown enrichment data .
        2. A notable data with a single drilldown enrichments as json string in the 'new' key (drilldown_searches).
        3. A notable data with multiple drilldown enrichments as json string in the 'new' key (drilldown_searches).
        4. A notable data with a single drilldown enrichments as json list string in the 'new' key (drilldown_searches).
        5. A notable data with a multiple drilldown enrichments as json list string in the 'new' key (drilldown_searches).
    When:   - call to get_drilldown_searches.
    Then:   - validate the result are as expected.
    """

    assert splunk.get_drilldown_searches(drilldown_data) == expected


@pytest.mark.parametrize('drilldown_search, expected_res',
                         [('{"name":"test", "query":"|key="the value""}', 'key="the value"'),
                          ('{"name":"test", "query":"|key in (line_1\nline_2)"}', 'key in (line_1,line_2)'),
                          ('{"name":"test", "query":"search a=$a|s$ c=$c$ suffix"}', 'search a=$a|s$ c=$c$ suffix')])
def test_escape_invalid_chars_in_drilldown_json(drilldown_search, expected_res):
    """
    Scenario: When extracting the drilldown search query which are a json string,
    we should escape unescaped JSON special characters.

    Given:
    - A raw search query with text like 'key="a value"'.
    - A raw search query with text like where 'key in (a\nb)' which it should be 'key in (a,b)'.
    - A raw search query with normal json string, should not be changed by this function.

    When:
    - escape_invalid_chars_in_drilldown_json is called

    Then:
    - Return the expected result
    """
    import json

    res = splunk.escape_invalid_chars_in_drilldown_json(drilldown_search)

    assert expected_res in json.loads(res)['query']


# Define minimal classes to simulate the service and index behavior
class Index:
    def __init__(self, name):
        self.name = name


class ServiceIndex:
    def __init__(self, indexes):
        self.indexes = [Index(name) for name in indexes]


@pytest.mark.parametrize(
    "given_indexes, service_indexes, expected",
    [
        # Test case: All indexes exist in the service
        (["index1", "index2"], ["index1", "index2", "index3"], True),

        # Test case: Some indexes do not exist in the service
        (["index1", "index4"], ["index1", "index2", "index3"], False),

        # Test case: Empty input indexes list
        ([], ["index1", "index2", "index3"], True),
    ]
)
def test_validate_indexes(given_indexes, service_indexes, expected):
    """
    Given: A list of indexes' names.
    When: Calling validate_indexes function.
    Then: The function returns `True` if all the given index names exist within the Splunk service instance;
          otherwise, it returns `False`.
    """
    from SplunkPy import validate_indexes
    service = ServiceIndex(service_indexes)
    # Assert that the function returns the expected result
    assert validate_indexes(given_indexes, service) == expected


@pytest.mark.parametrize(
    "fields, expected",
    [
        # Valid JSON input
        ('{"key": "value"}', {"key": "value"}),

        # Valid JSON with multiple key-value pairs
        ('{"key1": "value1", "key2": 2}', {"key1": "value1", "key2": 2}),

        # Invalid JSON input (non-JSON string)
        ("not a json string", {"fields": "not a json string"}),

        # Another invalid JSON input (partially structured JSON)
        ("{'key': 'value'}", {"fields": "{'key': 'value'}"}),
    ]
)
def test_parse_fields(fields, expected):
    """
    Given: A string representing fields, which may be a valid JSON string or a regular string.
    When: The parse_fields function is called with the given string.
    Then: If the string is valid JSON, the function returns a dictionary of the parsed fields. If the string is not valid JSON,
    the function returns a dictionary with a single key-value pair, where the entire input string is the key.
    """
    from SplunkPy import parse_fields
    result = parse_fields(fields)
    assert result == expected


@pytest.mark.parametrize("event, batch_event_data, entry_id, expected_data", [
    ("Somthing happened", None, None, '{"event": "Somthing happened", "fields": {"field1": "value1"}, "index": "main"}'),
    (None, "{'event': 'some event', 'index': 'some index'} {'event': 'some event', 'index': 'some index'}", None,
     "{'event': 'some event', 'index': 'some index'} {'event': 'some event', 'index': 'some index'}"),  # Batch event data
    (None, None, "some entry_id",
     "{'event': 'some event', 'index': 'some index'} {'event': 'some event', 'index': 'some index'}"),
    (None, """{'event': "some event's", 'index': 'some index'} {'event': 'some event', 'index': 'some index'}""", None,
     """{'event': "some event's", 'index': 'some index'} {'event': 'some event', 'index': 'some index'}"""),  # with '
    (None, None, "some entry_id", "{'event': 'some event', 'index': 'some index'} {'event': 'some event', 'index': 'some index'}")
])
@patch("requests.post")
@patch("SplunkPy.get_events_from_file")
@patch("SplunkPy.extract_indexes")
@patch("SplunkPy.validate_indexes")
@patch("SplunkPy.parse_fields")
def test_splunk_submit_event_hec(
    mock_parse_fields,
    mock_validate_indexes,
    mock_extract_indexes,
    mock_get_events_from_file,
    mock_post,
    event,
    batch_event_data,
    entry_id,
    expected_data
):
    """
    Given: Different types of event submission (single event, batch event, entry_id).
    When: Calling splunk_submit_event_hec.
    Then: Ensure a POST request is sent with the correct data and headers.
    """
    from SplunkPy import splunk_submit_event_hec
    # Arrange
    hec_token = "valid_token"
    baseurl = "https://splunk.example.com"
    fields = '{"field1": "value1"}'
    parsed_fields = {"field1": "value1"}

    # Mocks
    mock_parse_fields.return_value = parsed_fields
    mock_validate_indexes.return_value = True

    if event:
        # Single event
        mock_extract_indexes.return_value = ['some index']
    elif batch_event_data:
        # Batch event data
        mock_extract_indexes.return_value = ['some index1', 'some index2']
    elif entry_id:
        # Entry ID
        mock_get_events_from_file.return_value =\
            "{'event': 'some event', 'index': 'some index'} {'event': 'some event', 'index': 'some index'}"
        mock_extract_indexes.return_value = ['some index1', 'some index2']

    # Act
    splunk_submit_event_hec(
        hec_token=hec_token,
        baseurl=baseurl,
        event=event,
        fields=fields,
        host=None,
        index="main",
        source_type=None,
        source=None,
        time_=None,
        request_channel="test_channel",
        batch_event_data=batch_event_data,
        entry_id=entry_id,
        service=MagicMock(),
    )

    mock_post.assert_called_once_with(
        f"{baseurl}/services/collector/event",
        data=expected_data,
        headers={
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json",
            "X-Splunk-Request-Channel": "test_channel",
        },
        verify=True,
    )


def test_splunk_submit_event_hec_command_no_required_arguments():
    """ Given: none of these arguments: 'entry_id', 'event', 'batch_event_data'
        When: Runing splunk-submit-event-hec command
        Then: An exception is thrown
    """
    from SplunkPy import splunk_submit_event_hec_command
    with pytest.raises(DemistoException,
                       match=r"Invalid input: Please specify one of the following arguments: `event`, "
                       r"`batch_event_data`, or `entry_id`."):
        splunk_submit_event_hec_command({'hec_url': 'hec_url'}, None, {})


@pytest.mark.parametrize("events, expected_result", [
    ("{'index': 'index1', 'event': 'Something happend '} {'index': 'index 2', 'event': 'Something's happend'}",
     ['index1', 'index 2']),
    ({'index': 'index1', 'value': '123'}, ['index1']),
    ("{'event': 'value'}", []),
    ('{"index": "index: 3", "event": "Something happend"}, {"index": "index: 3", "event": "Something happend"}',
     ['index: 3', 'index: 3']),
    ("{'key': 'value'}, {'key': 'value'}", []),
    ("""{"index": "index_3", "event": "Something` happend"}, {"index": "index-4", "event": "Something' happend"}""",
     ['index_3', 'index-4']),
])
def test_extract_indexes(events, expected_result):
    from SplunkPy import extract_indexes
    assert extract_indexes(events) == expected_result
