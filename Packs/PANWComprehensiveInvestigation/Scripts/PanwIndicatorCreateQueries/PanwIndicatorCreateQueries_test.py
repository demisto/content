from PanwIndicatorCreateQueries import generate_ip_queries, generate_hash_queries, generate_domain_queries


def test_generate_ip_queries():
    """Unit test
    Given
    - generate_ip_queries command
    - command args(single and multiple ips)
    When
    - executing generate_ip_queries command
    Then
    - Validate that the proper query is created
    """
    expected1 = {"CortexTrapsIP": "SELECT * from tms.threat where endPointHeader.agentIp='8.8.8.8'"}
    expected2 = {
        "CortexTrapsIP": "SELECT * from tms.threat where endPointHeader.agentIp='8.8.8.8' OR " "endPointHeader.agentIp='1.1.1.1'"
    }
    queries1_1 = generate_ip_queries(["8.8.8.8"])
    queries1_2 = generate_ip_queries(["8.8.8.8", "12345"])
    queries2_1 = generate_ip_queries(["8.8.8.8", "1.1.1.1"])
    assert expected1["CortexTrapsIP"] == queries1_1["CortexTrapsIP"]
    assert expected1["CortexTrapsIP"] == queries1_2["CortexTrapsIP"]
    assert expected2["CortexTrapsIP"] == queries2_1["CortexTrapsIP"]


def test_generate_hash_queries():
    """Unit test
    Given
    - generate_hash_queries command
    - command args(single and multiple hashes)
    When
    - executing generate_hash_queries command
    Then
    - Validate that the proper query is created
    """
    cortex_traps_single_hash = {"CortexTrapsHash": "SELECT * from tms.threat where messageData.files.sha256='ababababababababab'"}
    queries_single_hash = generate_hash_queries(["ababababababababab"])
    assert queries_single_hash["CortexTrapsHash"] == cortex_traps_single_hash["CortexTrapsHash"]

    cortex_traps_multiple_hash = {
        "CortexTrapsHash": "SELECT * from tms.threat where messageData.files.sha256='ababababababababab' OR "
        "messageData.files.sha256='cbcbcbcbcbcbcbcbcb'"
    }
    auto_focus_hash_query = (
        '{"operator": "any", "children": ['
        '{"field": "alias.hash_lookup", "operator": "contains", "value": "ababababababababab"}, '
        '{"field": "alias.hash_lookup", "operator": "contains", "value": "cbcbcbcbcbcbcbcbcb"}]}'
    )
    queries_multiple_hashes = generate_hash_queries(["ababababababababab", "cbcbcbcbcbcbcbcbcb"])
    assert queries_multiple_hashes["CortexTrapsHash"] == cortex_traps_multiple_hash["CortexTrapsHash"]
    assert queries_multiple_hashes["AutofocusSessionsHash"] == auto_focus_hash_query


def test_generate_domain_queries():
    """Unit test
    Given
    - generate_domain_queries command
    - command args(single and multiple domains)
    When
    - executing generate_domain_queries command
    Then
    - Validate that the proper query is created
    """
    expected1 = {"CortexThreatDomain": "SELECT * from panw.threat where misc LIKE 'demisto.com'"}
    expected2 = {
        "CortexThreatDomain": "SELECT * from panw.threat where misc LIKE 'demisto.com' OR " "misc LIKE 'paloaltonetworks.com'"
    }
    queries1_1 = generate_domain_queries(["demisto.com"])
    queries2_1 = generate_domain_queries(["demisto.com", "paloaltonetworks.com"])
    assert expected1["CortexThreatDomain"] == queries1_1["CortexThreatDomain"]
    assert expected2["CortexThreatDomain"] == queries2_1["CortexThreatDomain"]
