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
                   '"a1d57ed2-1fe6-4800-be7a-26cd89bf686d","SESSIONID":"stY46PpweFToT5JX04CZGMeHbX8=","ORGOID":' \
                   '"G2SY6MR3ATKA121T","AOID":"G2N2TJETBRAAXAAA","MSGID":"a1d57ed2-1fe6-0000-be7a-26cd89bf686d"}'

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


def test_raw_to_dict():
    from SplunkPy import rawToDict
    actual_raw = DICT_RAW_RESPONSE
    response = rawToDict(actual_raw)
    list_response = rawToDict(LIST_RAW)

    assert EXPECTED == response
    assert {} == list_response
