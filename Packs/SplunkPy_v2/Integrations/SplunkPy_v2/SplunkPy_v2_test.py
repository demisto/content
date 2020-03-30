import json
from copy import deepcopy
from typing import List, Dict

import pytest
from freezegun import freeze_time
from SplunkPy_v2 import build_search_query, get_default_earliest_time, build_fetch_fields, set_latest_time, \
    set_first_run, severity_to_level, replace_key_name, replace_keys, raw_to_dict, notable_to_incident


data_test_build_search_query = [
    ('', 'search '),
    ('test', 'search test'),
    ('search', 'search'),
    ('Search', 'Search'),
    ('|', '|'),
    ('test search', 'search test search'),
    ('test Search', 'search test Search'),
    ('test |', 'search test |')
]


@pytest.mark.parametrize('query, expected_query', data_test_build_search_query)
def test_build_search_query(query, expected_query):
    output = build_search_query(query)
    assert output == expected_query, f'build_search_query({query})\n\treturns: {output}\n\tinstead: {expected_query}'


data_test_build_fetch_fields = [
    ('', '', ''),
    ('test', '', 'test'),
    ('', 'test', ' | eval test=test'),
    ('', 'test1, test2', ' | eval test1=test1 | eval test2=test2'),
    ('', 'test1,test2', ' | eval test1=test1 | eval test2=test2'),
    ('test', 'test1,test2', 'test | eval test1=test1 | eval test2=test2')
]


@pytest.mark.parametrize('query, fields_csv, expected_output', data_test_build_fetch_fields)
def test_build_fetch_fields(query, fields_csv, expected_output):
    output = build_fetch_fields(query=query, fields_csv=fields_csv)
    assert output == expected_output, f'build_fetch_fields({query}, {fields_csv})\n\t' \
                                      f'returns: {output}\n\tinstead: {expected_output}'


@freeze_time("2020-03-26T00:00:00")
def test_get_default_earliest_time():
    expected_output = '2020-03-19T00:00:00'
    output = get_default_earliest_time()
    assert output == expected_output, f'get_default_earliest_time()\n\treturns: {output}\n\tinstead: {expected_output}'


data_test_set_latest_time = [
    (None, '2020-03-29T00:00:00'),
    ('', '2020-03-29T00:00:00'),
    ('10', '2020-03-29T00:10:00'),
    ('60', '2020-03-29T01:00:00'),
    ('-10', '2020-03-28T23:50:00'),
    ('-60', '2020-03-28T23:00:00')
]


@pytest.mark.parametrize('time_zone, expected_output', data_test_set_latest_time)
@freeze_time("2020-03-29T00:00:00")
def test_set_latest_time(time_zone, expected_output):
    output = set_latest_time(time_zone=time_zone)
    assert output == expected_output, f'set_latest_time({time_zone})n\treturns: {output}\n\tinstead: {expected_output}'


data_test_set_first_run = [
    ('10', '2020-03-29T00:00:00', '2020-03-28T23:50:00'),
    ('100', '2020-03-29T00:00:00', '2020-03-28T22:20:00'),
    ('', '2020-03-29T00:00:00', '2020-03-29T00:00:00'),
    (None, '2020-03-29T00:00:00', '2020-03-29T00:00:00')
]


@pytest.mark.parametrize('fetch_time, latest_time, expected_output', data_test_set_first_run)
def test_set_first_run(fetch_time, latest_time, expected_output):
    output = set_first_run(fetch_time, latest_time)
    assert output == expected_output, f'build_fetch_fields({fetch_time}, {latest_time})\n\t' \
                                      f'returns: {output}\n\tinstead: {expected_output}'


data_test_severity_to_level = [
    ('', 1),
    ('test', 1),
    ('informational', 0.5),
    ('critical', 4),
    ('high', 3),
    ('medium', 2)
]


@pytest.mark.parametrize('severity, expected_level', data_test_severity_to_level)
def test_severity_to_level(severity, expected_level):
    level = severity_to_level(severity)
    assert level == expected_level, f'severity_to_level({severity})n\treturns: {level}\n\tinstead: {expected_level}'


data_test_replace_key_name = [
    ('test', 'test'),
    ('te.st', 'te_st'),
    ('te(st', 'te_st'),
    ('te)st', 'te_st'),
    ('te[st', 'te_st'),
    ('te]st', 'te_st')
]


@pytest.mark.parametrize('key_in, key_out', data_test_replace_key_name)
def test_replace_key_name(key_in, key_out):
    output = replace_key_name(key_in)
    assert output == key_out, f'replace_key_name({key_in})n\treturns: {output}\n\tinstead: {key_out}'


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
    output = replace_keys(deepcopy(dict_in))
    assert output == dict_out, f'replace_key_name({dict_in})n\treturns: {output}\n\tinstead: {dict_out}'


data_test_raw_to_dict = [
    (
        '"1528755951, search_name="NG_SIEM_UC25- High number of hits against unknown website from same subnet", '
        'action="allowed", dest="bb.bbb.bb.bbb , cc.ccc.ccc.cc , xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , '
        'aa.aa.aaa.aaa", distinct_hosts="5", first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , 06/11/18 17:37:55 '
        ', 06/11/18 17:41:28 , 06/11/18 17:42:05 , 06/11/18 17:42:38", info_max_time="+Infinity", info_min_time="0.000"'
        ', src="xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", u_category="unknown", user="xyz\\a1234 ,'
        ' xyz\\b5678 , xyz\\c91011 , xyz\\d121314 , unknown", website="2.2.2.2""',
        {
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
    ),
    (
        'Feb 13 09:02:55 1,2020/02/13 09:02:55,001606001116,THREAT,url,1,2020/02/13 09:02:55,10.1.1.1,1.2.3.4,0.0.0.0,'
        '0.0.0.0,rule1,jordy,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,forwardAll,2020/02/13 09:02:55,'
        '59460,1,62889,80,0,0,0x208000,tcp,alert,"ushship.com/xed/config.bin",(9999),not-resolved,informational,'
        'client-to-server,0,0x0,1.1.22.22-5.6.7.8,United States,0,text/html',
        {}
    ),
    (
        '{"@timestamp":"2019-10-15T13:30:08.578-04:00","message":"{"TimeStamp":"2019-10-15 13:30:08",'
        '"CATEGORY_1":"CONTACT","ASSOCIATEOID":"G2N2TJETBRAAX68V",'
        '"HOST":"step-up-authentication-api.gslb.es.oneadp.com",'
        '"SCOPE[29]":"autopay\\/events\\/payroll\\/v1\\/earning-configuration.configuration-tags.modify",'
        '"SCOPE[2]":"AVSSCP\\/Docstash\\/Get","OUTPUT_TYPE":"FAIL","ERR_MSG":"BLOCK_SESSION",'
        '"TRANS_ID":"3AF-D30-7CTTCQ"}}',
        {
            '@timestamp': '2019-10-15T13:30:08.578-04:00',
            "TimeStamp": "2019-10-15 13:30:08",
            "ASSOCIATEOID": "G2N2TJETBRAAX68V",
            "CATEGORY_1": "CONTACT",
            "HOST": "step-up-authentication-api.gslb.es.oneadp.com",
            'SCOPE[29]': 'autopay\\/events\\/payroll\\/v1\\/earning-configuration.configuration-tags.modify',
            'SCOPE[2]': 'AVSSCP\\/Docstash\\/Get',
            "OUTPUT_TYPE": "FAIL",
            "ERR_MSG": "BLOCK_SESSION",
            "TRANS_ID": "3AF-D30-7CTTCQ"
        }
    ),
    (
        '', {}
    ),
    (
        '"url="https://test.com?key=val"',
        {'url': 'https://test.com?key=val'}
    ),
    (
        'NAS-IP-Address=2.2.2.2, NAS-Port=50222, NAS-Identifier=de-wilm-251littl-idf3b-s2, NAS-Port-Type=Ethernet, '
        'NAS-Port-Id=GigabitEthernet2/0/05',
        {
            "NAS-IP-Address": "2.2.2.2",
            "NAS-Identifier": "de-wilm-251littl-idf3b-s2",
            "NAS-Port": "50222",
            "NAS-Port-Id": "GigabitEthernet2/0/05",
            "NAS-Port-Type": "Ethernet"
        }
    )
]


@pytest.mark.parametrize('raw_in, dict_out', data_test_raw_to_dict)
def test_raw_to_dict(raw_in, dict_out):
    output = raw_to_dict(raw_in)
    assert output == dict_out, f'raw_to_dict({raw_in})\n\treturns: {output}\n\tinstead: {dict_out}'


data_test_notable_to_incident = [
    (
        {
            "rule_title": 'title',
            "_time": '2020-03-29T00:00:00'
        },
        {
            "name": 'title : ',
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "rule_name": 'rule',
            "_time": '2020-03-29T00:00:00'
        },
        {
            "name": ' : rule',
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "rule_title": 'title',
            "rule_name": 'rule',
            "_time": '2020-03-29T00:00:00'
        },
        {
            "name": 'title : rule',
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "rule_title": 'title',
            "rule_name": 'rule'
        },
        {
            "name": 'title : rule',
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "urgency": 'informational'
        },
        {
            "name": ' : ',
            "severity": 0.5,
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "urgency": 'critical'
        },
        {
            "name": ' : ',
            "severity": 4,
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "rule_description": 'test'
        },
        {
            "name": ' : ',
            "details": 'test',
            "occurred": "2020-03-29T00:00:00"
        }
    ),
    (
        {
            "rule_description": 'test',
            'security_domain': '127.0.0.1'
        },
        {
            "name": ' : ',
            "details": 'test',
            "occurred": "2020-03-29T00:00:00",
            'labels': [{'type': 'security_domain', 'value': '127.0.0.1'}]
        }
    ),
    (
        {},
        {
            "name": ' : ',
            "occurred": "2020-03-29T00:00:00"
        }
    )
]


@pytest.mark.parametrize('event, expected_output', data_test_notable_to_incident)
@freeze_time("2020-03-29T00:00:00")
def test_notable_to_incident(event, expected_output):
    output = notable_to_incident(event)
    output.pop('rawJSON')
    assert output == expected_output, f'notable_to_incident({event})\n\treturns: {output}\n\tinstead: {expected_output}'


data_test_notable_to_incident_with_replace = [
    ({"te.st": 'te.st'}, {'te_st': 'te.st'}),
    ({"test": 'test'}, {'test': 'test'}),
    ({"test[": "test{"}, {"test_": "test{"})
]


@pytest.mark.parametrize('event, expected_output', data_test_notable_to_incident_with_replace)
def test_notable_to_incident_with_replace(event, expected_output):
    output = notable_to_incident(event, replace=True)
    expected_output = {'rawJSON': json.dumps(expected_output)}
    output.pop('occurred')
    output.pop('name')
    assert output == expected_output, f'notable_to_incident({event}, replace=True)\n\t' \
                                      f'returns: {output}\n\tinstead: {expected_output}'


data_test_notable_to_incident_with_parse_notable_events_raw = [
    (
        '"1528755951, search_name="NG_SIEM_UC25- High number of hits against unknown website from same subnet", '
        'action="allowed", dest="bb.bbb.bb.bbb , cc.ccc.ccc.cc , xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , '
        'aa.aa.aaa.aaa", distinct_hosts="5", first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , 06/11/18 17:37:55 '
        ', 06/11/18 17:41:28 , 06/11/18 17:42:05 , 06/11/18 17:42:38", info_max_time="+Infinity", info_min_time="0.000"'
        ', src="xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", u_category="unknown", user="xyz\\a1234 ,'
        ' xyz\\b5678 , xyz\\c91011 , xyz\\d121314 , unknown", website="2.2.2.2""',
        {
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
    ),
    (
        'Feb 13 09:02:55 1,2020/02/13 09:02:55,001606001116,THREAT,url,1,2020/02/13 09:02:55,10.1.1.1,1.2.3.4,0.0.0.0,'
        '0.0.0.0,rule1,jordy,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,forwardAll,2020/02/13 09:02:55,'
        '59460,1,62889,80,0,0,0x208000,tcp,alert,"ushship.com/xed/config.bin",(9999),not-resolved,informational,'
        'client-to-server,0,0x0,1.1.22.22-5.6.7.8,United States,0,text/html',
        None
    ),
    (
        '{"@timestamp":"2019-10-15T13:30:08.578-04:00","message":"{"TimeStamp":"2019-10-15 13:30:08",'
        '"CATEGORY_1":"CONTACT","ASSOCIATEOID":"G2N2TJETBRAAX68V",'
        '"HOST":"step-up-authentication-api.gslb.es.oneadp.com",'
        '"SCOPE[29]":"autopay\\/events\\/payroll\\/v1\\/earning-configuration.configuration-tags.modify",'
        '"SCOPE[2]":"AVSSCP\\/Docstash\\/Get","OUTPUT_TYPE":"FAIL","ERR_MSG":"BLOCK_SESSION",'
        '"TRANS_ID":"3AF-D30-7CTTCQ"}}',
        {
            '@timestamp': '2019-10-15T13:30:08.578-04:00',
            "TimeStamp": "2019-10-15 13:30:08",
            "ASSOCIATEOID": "G2N2TJETBRAAX68V",
            "CATEGORY_1": "CONTACT",
            "HOST": "step-up-authentication-api.gslb.es.oneadp.com",
            'SCOPE[29]': 'autopay\\/events\\/payroll\\/v1\\/earning-configuration.configuration-tags.modify',
            'SCOPE[2]': 'AVSSCP\\/Docstash\\/Get',
            "OUTPUT_TYPE": "FAIL",
            "ERR_MSG": "BLOCK_SESSION",
            "TRANS_ID": "3AF-D30-7CTTCQ"
        }
    ),
    (
        '', None
    ),
    (
        '"url="https://test.com?key=val"',
        {'url': 'https://test.com?key=val'}
    ),
    (
        'NAS-IP-Address=2.2.2.2, NAS-Port=50222, NAS-Identifier=de-wilm-251littl-idf3b-s2, NAS-Port-Type=Ethernet, '
        'NAS-Port-Id=GigabitEthernet2/0/05',
        {
            "NAS-IP-Address": "2.2.2.2",
            "NAS-Identifier": "de-wilm-251littl-idf3b-s2",
            "NAS-Port": "50222",
            "NAS-Port-Id": "GigabitEthernet2/0/05",
            "NAS-Port-Type": "Ethernet"
        }
    )
]


@pytest.mark.parametrize('event, expected_output', data_test_notable_to_incident_with_parse_notable_events_raw)
def test_notable_to_incident_with_parse_notable_events_raw(event, expected_output):
    event = {'_raw': event}
    output = notable_to_incident(event, parse_notable_events_raw=True)
    expected_output_list = []
    if isinstance(expected_output, Dict):
        for _key, val in expected_output.items():
            expected_output_list.append({'type': _key, 'value': val})

        expected_output = expected_output_list
        expected_output.sort(key=lambda x: x.get('type', ''))
    if isinstance(output, Dict):
        output = output.get('labels')
        if isinstance(output, List):
            output.sort(key=lambda x: x.get('type', ''))
    assert output == expected_output, f'notable_to_incident({event}, parse_notable_events_raw=True).get("labels")\n\t' \
                                      f'returns: {output}\n\tinstead: {expected_output}'
