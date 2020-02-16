import unittest
import demistomock as demisto


DICT_RAW_RESPONSE = """{"_bkt": "notable~38~E9578B6E-A5AE-4C35-8FBB-7079E8DE117A", "_cd": "38:3167", 
"_indextime": "1528755958", "_raw": "1528755951, search_name="NG_SIEM_UC25- High number of hits against unknown website 
from same subnet", action="allowed", dest="bb.bbb.bb.bbb , cc.ccc.ccc.cc , xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz 
, aa.aa.aaa.aaa", distinct_hosts="5", first_3_octets="1.1.1", first_time="06/11/18 17:34:07 , 06/11/18 17:37:55 , 
06/11/18 17:41:28 , 06/11/18 17:42:05 , 06/11/18 17:42:38", info_max_time="+Infinity", info_min_time="0.000", 
src="xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", u_category="unknown", user="xyz\\a1234 , xyz\\b5678 
, xyz\\c91011 , xyz\\d121314 , unknown", website="2.2.2.2"", "_serial": "3", "_si": [
"splunk-index-02.eu.merckgroup.com", "notable"], "_sourcetype": "stash", "_time": "2018-06-12T00:25:51.000+02:00", 
"action": "allowed", "dest": "xx.xx.xxx.xx , yyy.yy.yyy.yy , zz.zzz.zz.zzz , aa.aa.aaa.aaa", "distinct_hosts": "5", 
"first_3_octets": "aa.bbb.ccc", "first_time": "06/11/18 17:34:07 , 06/11/18 17:37:55 , 06/11/18 17:41:28 , 
06/11/18 17:42:05 , 06/11/18 17:42:38", "host": "splunk-searchhead-xx.xx.com", "index": "notable", "info_max_time": 
"+Infinity", "info_min_time": "0.000", "linecount": "1", "priority": "unknown", "rule_description": "NG_SIEM_UC25- High 
number of hits against unknown website from same subnet", "rule_name": "NG_SIEM_UC25- High number of hits against 
unknown website from same subnet", "rule_title": "NG_SIEM_UC25- High number of hits against unknown website from same 
subnet", "security_domain": "NG_SIEM_UC25- High number of hits against unknown website from same subnet", "severity": 
"unknown", "source": "NG_SIEM_UC25- High number of hits against unknown website from same subnet", "sourcetype": 
"stash", "splunk_server": "splunk-index-02.eu.merckgroup.com", "src": "10.253.244.208 , 10.253.244.244 , 10.253.244.51 ,
 10.253.244.84 , 10.253.244.96", "u_category": "unknown", "urgency": "low", "user": "xyz\a1234 , xyz\b5678 , xyz\c91011 
 , xyz\d121314 , unknown", "website": "17.253.55.205"}"""

LIST_RAW = 'Feb 13 09:02:55 1,2020/02/13 09:02:55,001606001116,THREAT,url,' \
           '1,2020/02/13 09:02:55,192.168.0.2,8.5.1.44,0.0.0.0,0.0.0.0,rule1,jordy,,web-browsing,vsys1,trust,untrust,' \
           'ethernet1/2,ethernet1/1,forwardAll,2020/02/13 09:02:55,59460,1,62889,80,0,0,0x208000,tcp,alert,' \
           '"ushship.com/xed/config.bin",(9999),not-resolved,informational,client-to-server,' \
           '0,0x0,192.168.0.0-192.168.255.255,United States,0,text/html'


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


class TestRawToDict(unittest.TestCase):
    def test_raw_to_dict(self):
        from SplunkPy import rawToDict
        actual_raw = DICT_RAW_RESPONSE.replace('\n', '')
        response = rawToDict(actual_raw)
        list_response = rawToDict(LIST_RAW)

        self.assertEqual(response, EXPECTED)
        self.assertEqual(list_response, {})

