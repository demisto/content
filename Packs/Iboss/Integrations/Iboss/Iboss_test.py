"""
Unit Tests module for the iboss integration.
"""
import datetime
import copy

REPUTATION_RESPONSE_UNREACHABLE_BENIGN_IP = http_data = {
    'activeMalwareSubscription': 1,
    'categories': '0000000000000000000000000000000000000001000000000000000000000000000000000000000'
                  '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000',
    'categorized': 'true', 'googleSafeBrowsingDescription': '', 'googleSafeBrowsingEnabled': 1,
    'googleSafeBrowsingIsSafeUrl': 1, 'googleSafeBrowsingSuccess': 1, 'googleSafeBrowsingSupport': 1,
    'isSafeUrl': 1, 'malwareEngineAnalysisDescription': 'Redirect - Redirects to: https://1.1.1.1/',
    'malwareEngineAnalysisEnabled': 1, 'malwareEngineAnalysisSuccess': 1, 'malwareEngineIsSafeUrl': 1,
    'malwareEngineResultCode': 3, 'message': 'Status: Url Known. Please see categories below.',
    'realtimeCloudLookupDomainIsGrey': 0, 'realtimeCloudLookupEnabled': 1,
    'realtimeCloudLookupIsSafeUrl': 1, 'realtimeCloudLookupRiskDescription': '',
    'realtimeCloudLookupSuccess': 1, 'reputationDatabaseBotnetDetection': 0,
    'reputationDatabaseEnabled': 1, 'reputationDatabaseIsSafeUrl': 1, 'reputationDatabaseLookupSuccess': 1,
    'reputationDatabaseMalwareDetection': 0, 'url': '1.1.1.1',
    'webRequestHeuristicBlockUnreachableSites': '1',
    'webRequestHeuristicDescription': 'Heuristic Engine Detection', 'webRequestHeuristicIsSafeUrl': 0,
    'webRequestHeuristicLevelHighScore': '79', 'webRequestHeuristicLevelLowScore': '10',
    'webRequestHeuristicLevelMediumScore': '60', 'webRequestHeuristicLevelNoneScore': '0',
    'webRequestHeuristicProtectionActionHigh': '0', 'webRequestHeuristicProtectionActionLow': '0',
    'webRequestHeuristicProtectionActionMedium': '0', 'webRequestHeuristicProtectionLevel': '1',
    'webRequestHeuristicSuccess': 1, 'webRequestHeuristicSupport': 1}

REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN = {
    "activeMalwareSubscription": 1,
    "categories": '0000000000000000000000000000000000000001000000000000000000000000000000000000000'
                  '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000',
    "categorized": "true", "googleSafeBrowsingDescription": "", "googleSafeBrowsingEnabled": 1,
    "googleSafeBrowsingIsSafeUrl": 1, "googleSafeBrowsingSuccess": 1, "googleSafeBrowsingSupport": 1,
    "isSafeUrl": 0, "malwareEngineAnalysisDescription": "Unreachable - HTTP Error Code: 503",
    "malwareEngineAnalysisEnabled": 1, "malwareEngineAnalysisSuccess": 1, "malwareEngineIsSafeUrl": 1,
    "malwareEngineResultCode": 2, "message": "Status: Suspicious Url. Please see below.",
    "realtimeCloudLookupDomainIsGrey": 0, "realtimeCloudLookupEnabled": 1,
    "realtimeCloudLookupIsSafeUrl": 1, "realtimeCloudLookupRiskDescription": "",
    "realtimeCloudLookupSuccess": 1, "reputationDatabaseBotnetDetection": 0,
    "reputationDatabaseEnabled": 1, "reputationDatabaseIsSafeUrl": 0, "reputationDatabaseLookupSuccess": 1,
    "reputationDatabaseMalwareDetection": 1, "url": "unreachable.com",
    "webRequestHeuristicBlockUnreachableSites": "1",
    "webRequestHeuristicDescription": "Heuristic Engine Detection", "webRequestHeuristicIsSafeUrl": 0,
    "webRequestHeuristicLevelHighScore": "79", "webRequestHeuristicLevelLowScore": "10",
    "webRequestHeuristicLevelMediumScore": "60", "webRequestHeuristicLevelNoneScore": "0",
    "webRequestHeuristicProtectionActionHigh": "0", "webRequestHeuristicProtectionActionLow": "0",
    "webRequestHeuristicProtectionActionMedium": "0", "webRequestHeuristicProtectionLevel": "1",
    "webRequestHeuristicSuccess": 1, "webRequestHeuristicSupport": 1}

REPUTATION_RESPONSE_UNREACHABLE_SUSPICIOUS_DOMAIN = {
    "activeMalwareSubscription": 1,
    "categories": '0000000000000000000000000000000000000001000000000000000000000000000000000000000'
                  '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                  '000000000000000000000000000000000000',
    "categorized": "true", "googleSafeBrowsingDescription": "", "googleSafeBrowsingEnabled": 1,
    "googleSafeBrowsingIsSafeUrl": 1, "googleSafeBrowsingSuccess": 1, "googleSafeBrowsingSupport": 1,
    "isSafeUrl": 0, "malwareEngineAnalysisDescription": "Unreachable - HTTP Error Code: 503",
    "malwareEngineAnalysisEnabled": 1, "malwareEngineAnalysisSuccess": 1, "malwareEngineIsSafeUrl": 1,
    "malwareEngineResultCode": 2, "message": "Status: Suspicious Url. Please see below.",
    "realtimeCloudLookupDomainIsGrey": 0, "realtimeCloudLookupEnabled": 1,
    "realtimeCloudLookupIsSafeUrl": 1, "realtimeCloudLookupRiskDescription": "",
    "realtimeCloudLookupSuccess": 1, "reputationDatabaseBotnetDetection": 0,
    "reputationDatabaseEnabled": 1, "reputationDatabaseIsSafeUrl": 1, "reputationDatabaseLookupSuccess": 1,
    "reputationDatabaseMalwareDetection": 1, "url": "unreachable.com",
    "webRequestHeuristicBlockUnreachableSites": "1",
    "webRequestHeuristicDescription": "Heuristic Engine Detection", "webRequestHeuristicIsSafeUrl": 0,
    "webRequestHeuristicLevelHighScore": "79", "webRequestHeuristicLevelLowScore": "10",
    "webRequestHeuristicLevelMediumScore": "60", "webRequestHeuristicLevelNoneScore": "0",
    "webRequestHeuristicProtectionActionHigh": "0", "webRequestHeuristicProtectionActionLow": "0",
    "webRequestHeuristicProtectionActionMedium": "0", "webRequestHeuristicProtectionLevel": "1",
    "webRequestHeuristicSuccess": 1, "webRequestHeuristicSupport": 1}


def get_mock_client(mocker):
    from Iboss import Client
    client = Client(username="user", password="123", account_settings_id="123", verify=False, proxy=False)
    dt_future = datetime.datetime.now() + datetime.timedelta(days=7)
    mocker.patch.object(client, '_get_cloud_token', return_value="abc")
    mocker.patch.object(client, "_get_cloud_settings_tokens", return_value=("def", "ghi", str(dt_future)))
    mocker.patch.object(client, "_get_primary_gateway", return_value="pswg.com")
    mocker.patch.object(client, "_get_swg_xsrf_token", return_value="jkl")
    return client


def test_add_entity_to_block_list(requests_mock, mocker):
    """
        Scenario: Add entry to allow list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A add_entity_to_block_list command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import add_entity_to_block_list_command
    client = get_mock_client(mocker)

    requests_mock.put(
        'https://pswg.com/json/controls/blockList?currentPolicyBeingEdited=1',
        json={'message': 'URL added successfully.'})

    args = {
        "entity": "domain1.com,domain2.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "60"
    }

    result = add_entity_to_block_list_command(client, args=args)

    assert len(result) == 2
    assert result[0].outputs.get("message") == "`domain1.com` successfully added to policy 1 block list."
    assert result[1].outputs.get("message") == "`domain2.com` successfully added to policy 1 block list."


def test_add_entity_to_allow_list(requests_mock, mocker):
    """
        Scenario: Add multiple entries to allow list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A add_entity_to_allow_list command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import add_entity_to_allow_list_command

    client = get_mock_client(mocker)
    requests_mock.put(
        'https://pswg.com/json/controls/allowList?currentPolicyBeingEdited=1',
        json={'message': 'URL added successfully.'})

    args = {
        "entity": "domain1.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = add_entity_to_allow_list_command(client, args=args)

    assert len(result) == 1
    assert result[0].outputs.get("message") == "`domain1.com` successfully added to policy 1 allow list."


def test_add_entity_to_policy_layer_list(requests_mock, mocker):
    """
        Scenario: Add multiple entries to policy layer list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A add_entity_to_policy_layer_ist command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import add_entity_to_policy_layer_list_command

    client = get_mock_client(mocker)

    requests_mock.get(
        'https://pswg.com/json/controls/policyLayers/all',
        json={
            'entries': [
                {'customCategoryName': 'Test Policy Layer', 'customCategoryNumber': 1, 'customCategoryId': 1}
            ]}
    )

    requests_mock.put(
        'https://pswg.com/json/controls/policyLayers/urls',
        json={'message': 'URL added successfully.'}
    )

    args = {
        "policy_layer_name": "Test Policy Layer",
        "entity": "domain1.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0",
        "do_dlp_scan": "1",
        "do_malware_scan": "1",
        "upsert": "0",
        "time_url_expires_in_seconds": "0"
    }

    result = add_entity_to_policy_layer_list_command(client, args=args)

    assert len(result.outputs) == 1
    assert result.outputs[0].get("message") == "domain1.com successfully added to policy layer `Test Policy Layer`."


def test_remove_entity_from_policy_layer_list(requests_mock, mocker):
    """
        Scenario: Remove entry from policy layer list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A remove_entity_from_policy_layer_ist command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import remove_entity_from_policy_layer_list_command

    client = get_mock_client(mocker)

    requests_mock.get(
        'https://pswg.com/json/controls/policyLayers/all',
        json={
            'entries': [
                {'customCategoryName': 'Test Policy Layer', 'customCategoryNumber': 1, 'customCategoryId': 1}
            ]}
    )

    requests_mock.delete(
        'https://pswg.com/json/controls/policyLayers/urls',
        json={'message': 'URL removed successfully.'}
    )

    args = {
        "policy_layer_name": "Test Policy Layer",
        "entity": "domain1.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0",
        "do_dlp_scan": "1",
        "do_malware_scan": "1",
        "upsert": "0",
        "time_url_expires_in_seconds": "0"
    }

    result = remove_entity_from_policy_layer_list_command(client, args=args)

    assert len(result.outputs) == 1
    assert result.outputs[0].get("message") == "domain1.com removed from policy layer `Test Policy Layer`."


def test_remove_entity_from_allow_list_no_exist(requests_mock, mocker):
    """
           Scenario: Attempt to remove entry from allow list that is not present on list
           Given:
            - User has provided valid credentials and arguments.
           When:
            - A remove_entity_from_allow_list command is called and but entry is not removed because
                it is not present on list
           Then:
            - Ensure number of items is correct.
            - Ensure a sample value from the API matches what is generated in the context.
       """
    from Iboss import remove_entity_from_allow_list_command

    client = get_mock_client(mocker)
    requests_mock.delete(
        'https://pswg.com/json/controls/allowList?currentPolicyBeingEdited=1',
        json={'message': 'Failed to remove URL.', 'errorCode': 0})

    args = {
        "entity": "noexist.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = remove_entity_from_allow_list_command(client, args=args)

    assert len(result) == 1
    assert result[0].outputs.get("message") == "`noexist.com` not found in policy 1 allow list."


def test_remove_entity_from_block_list(requests_mock, mocker):
    """
           Scenario: Attempt to remove multiple entries from allow list
           Given:
            - User has provided valid credentials and arguments.
           When:
            - A remove_entity_from_block_list command is called and entries
           Then:
            - Ensure number of items is correct.
            - Ensure a sample value from the API matches what is generated in the context.
       """
    from Iboss import remove_entity_from_block_list_command

    client = get_mock_client(mocker)
    requests_mock.delete(
        'https://pswg.com/json/controls/blockList?currentPolicyBeingEdited=1',
        json={'message': 'URL removed successfully.'})

    args = {
        "entity": "domain1.com, domain2.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = remove_entity_from_block_list_command(client, args=args)

    assert len(result) == 2
    assert result[0].outputs.get("message") == "`domain1.com` removed from policy 1 block list."
    assert result[1].outputs.get("message") == "`domain2.com` removed from policy 1 block list."


def test_ip_lookup(requests_mock, mocker):
    """
       Scenario: Attempt to lookup IP reputation (suspicious due to unreachable)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - An `ip command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is suspicious
        - Ensure iboss metadata indicates site unreachable
        - Ensure iboss metadata show redirect
   """
    from Iboss import ip_lookup

    client = get_mock_client(mocker)

    requests_mock.post(
        'https://pswg.com/json/controls/urlLookup',
        json=REPUTATION_RESPONSE_UNREACHABLE_BENIGN_IP)

    results = ip_lookup(client, {"ip": "1.1.1.1"})

    assert len(results) == 1
    assert results[0].indicator.dbot_score.score == 1
    assert results[0].outputs['categories'][0] == 'Technology'
    expected = ""
    assert results[0].indicator.dbot_score.malicious_description == expected


def test_domain_lookup_malicious(requests_mock, mocker):
    """
       Scenario: Attempt to lookup domain reputation (malicious due to reputation)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - A url command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is malicious
        - Ensure Malicious context message exists
        - Ensure reputationDatabaseMalwareDetection == 1
   """
    from Iboss import domain_lookup

    client = get_mock_client(mocker)

    requests_mock.post(
        'https://pswg.com/json/controls/urlLookup',
        json=REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN)

    results = domain_lookup(client, {"domain": "unreachable.com"})

    assert len(results) == 1
    assert results[0].indicator.dbot_score.score == 3
    assert results[0].outputs['categories'][0] == 'Technology'
    expected = "Status: Suspicious Url. Please see below; Unreachable - HTTP Error Code: 503; Heuristic Engine " \
               "Detection"
    assert results[0].indicator.dbot_score.malicious_description == expected


def test_url_lookup(requests_mock, mocker):
    """
       Scenario: Attempt to lookup url reputation (benign due to reputation)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - A url command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is malicious
        - Ensure Malicious context message exists
        - Ensure reputationDatabaseMalwareDetection == 1
   """
    from Iboss import url_lookup

    client = get_mock_client(mocker)

    requests_mock.post(
        'https://pswg.com/json/controls/urlLookup',
        json=REPUTATION_RESPONSE_UNREACHABLE_BENIGN_IP)

    results = url_lookup(client, {"url": "1.1.1.1"})

    assert len(results) == 1
    assert results[0].indicator.dbot_score.score == 1
    assert results[0].outputs['categories'][0] == 'Technology'
    expected = ""
    assert results[0].indicator.dbot_score.malicious_description == expected


def test_domain_lookup_suspicious(requests_mock, mocker):
    """
       Scenario: Attempt to lookup domain reputation (suspicious due to reputation)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - A url command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is malicious
        - Ensure Malicious context message exists
        - Ensure reputationDatabaseMalwareDetection == 1
   """
    from Iboss import domain_lookup

    client = get_mock_client(mocker)

    requests_mock.post(
        'https://pswg.com/json/controls/urlLookup',
        json=REPUTATION_RESPONSE_UNREACHABLE_SUSPICIOUS_DOMAIN)

    results = domain_lookup(client, {"domain": "unreachable.com"})

    assert len(results) == 1
    assert results[0].indicator.dbot_score.score == 2
    assert results[0].outputs['categories'][0] == 'Technology'
    expected = ""
    assert results[0].indicator.dbot_score.malicious_description == expected


def test_reputation_calculate_dbot_score_malicious():
    """
       Scenario: Derive dbot score from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable, malicious domain
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_calculate_dbot_score

    results = reputation_calculate_dbot_score(REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN)
    expected = 3
    assert results == expected


def test_reputation_calculate_dbot_score_suspicious():
    """
       Scenario: Derive dbot score from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable, suspicious domain
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_calculate_dbot_score

    results = reputation_calculate_dbot_score(REPUTATION_RESPONSE_UNREACHABLE_SUSPICIOUS_DOMAIN)
    expected = 2
    assert results == expected


def test_reputation_get_malicious_message_suspicious():
    """
       Scenario: Derive message from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable domain with a suspicious score.
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_get_malicious_message

    results = reputation_get_malicious_message(REPUTATION_RESPONSE_UNREACHABLE_SUSPICIOUS_DOMAIN, 2)
    expected = ''
    assert results == expected


def test_reputation_get_malicious_message_malicious():
    """
       Scenario: Derive message from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable domain with a malicious score.
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_get_malicious_message

    results = reputation_get_malicious_message(REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN, 3)
    expected = 'Status: Suspicious Url. Please see below; Unreachable - HTTP Error Code: 503; Heuristic Engine Detection'
    assert results == expected


def test_reputation_get_engines_suspicious():
    """
       Scenario: Derive message from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable domain with a malicious score.
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_calculate_engines

    results = reputation_calculate_engines(REPUTATION_RESPONSE_UNREACHABLE_SUSPICIOUS_DOMAIN)
    expected = 5, 1
    assert results == expected


def test_reputation_get_engines_malicious():
    """
       Scenario: Derive message from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable domain with a malicious score.
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_calculate_engines

    results = reputation_calculate_engines(REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN)
    expected = 5, 2
    assert results == expected


def test_reputation_get_headers():
    """
       Scenario: Derive headers from iboss domain lookup response
       Given:
        - User has received valid iboss response when looking up an unreachable, malicious domain
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_get_headers

    results = reputation_get_headers(REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN)
    expected = [
        'message', 'categories', 'isSafeUrl', 'malwareEngineAnalysisSuccess', 'malwareEngineAnalysisDescription',
        'reputationDatabaseLookupSuccess', 'reputationDatabaseMalwareDetection', 'reputationDatabaseBotnetDetection',
        'webRequestHeuristicSuccess', 'webRequestHeuristicProtectionLevel', 'webRequestHeuristicDescription',
        'googleSafeBrowsingSuccess', 'googleSafeBrowsingIsSafeUrl', 'googleSafeBrowsingDescription',
        'realtimeCloudLookupSuccess', 'realtimeCloudLookupDomainIsGrey', 'realtimeCloudLookupRiskDescription'
    ]
    assert results == expected


def test_reputation_get_headers_malware_disabled():
    """
       Scenario: Derive headers from iboss domain lookup response (malware engine analysis disabled)
       Given:
        - User has received valid iboss response when looking up an unreachable, malicious domain
       When:
        - A domain lookup is performed
       Then:
        - Ensure message is correct
   """
    from Iboss import reputation_get_headers

    response = copy.deepcopy(REPUTATION_RESPONSE_UNREACHABLE_MALICIOUS_DOMAIN)
    response['malwareEngineAnalysisEnabled'] = 0

    results = reputation_get_headers(response)
    expected = [
        'message', 'categories', 'isSafeUrl',
        'reputationDatabaseLookupSuccess', 'reputationDatabaseMalwareDetection', 'reputationDatabaseBotnetDetection',
        'webRequestHeuristicSuccess', 'webRequestHeuristicProtectionLevel', 'webRequestHeuristicDescription',
        'googleSafeBrowsingSuccess', 'googleSafeBrowsingIsSafeUrl', 'googleSafeBrowsingDescription',
        'realtimeCloudLookupSuccess', 'realtimeCloudLookupDomainIsGrey', 'realtimeCloudLookupRiskDescription'
    ]
    assert results == expected
