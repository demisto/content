from PanwIndicatorCreateQueries import generate_ip_queries, generate_hash_queries, generate_domain_queries


def test_generate_ip_queries():
    expected1 = {
        'CortexTrapsIP': "SELECT * from tms.threat where endPointHeader.agentIp='8.8.8.8'"
    }
    expected2 = {
        'CortexTrapsIP': "SELECT * from tms.threat where endPointHeader.agentIp='8.8.8.8' OR "
                         "endPointHeader.agentIp='1.1.1.1'"
    }
    queries1_1 = generate_ip_queries(['8.8.8.8'])
    queries1_2 = generate_ip_queries(['8.8.8.8', '12345'])
    queries2_1 = generate_ip_queries(['8.8.8.8', '1.1.1.1'])
    assert expected1['CortexTrapsIP'] == queries1_1['CortexTrapsIP']
    assert expected1['CortexTrapsIP'] == queries1_2['CortexTrapsIP']
    assert expected2['CortexTrapsIP'] == queries2_1['CortexTrapsIP']


def test_generate_hash_queries():
    expected1 = {
        'CortexTrapsHash': "SELECT * from tms.threat where messageData.files.sha256='ababababababababab'"
    }
    expected2 = {
        'CortexTrapsHash': "SELECT * from tms.threat where messageData.files.sha256='ababababababababab' OR "
                           "messageData.files.sha256='cbcbcbcbcbcbcbcbcb'"
    }
    queries1_1 = generate_hash_queries(['ababababababababab'])
    queries2_1 = generate_hash_queries(['ababababababababab', 'cbcbcbcbcbcbcbcbcb'])
    assert expected1['CortexTrapsHash'] == queries1_1['CortexTrapsHash']
    assert expected2['CortexTrapsHash'] == queries2_1['CortexTrapsHash']


def test_generate_domain_queries():
    expected1 = {
        'CortexThreatDomain': "SELECT * from panw.threat where misc LIKE 'demisto.com'"
    }
    expected2 = {
        'CortexThreatDomain': "SELECT * from panw.threat where misc LIKE 'demisto.com' OR "
                              "misc LIKE 'paloaltonetworks.com'"
    }
    queries1_1 = generate_domain_queries(['demisto.com'])
    queries2_1 = generate_domain_queries(['demisto.com', 'paloaltonetworks.com'])
    assert expected1['CortexThreatDomain'] == queries1_1['CortexThreatDomain']
    assert expected2['CortexThreatDomain'] == queries2_1['CortexThreatDomain']
