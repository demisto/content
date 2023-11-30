import requests
import pytest
import json

import demistomock as demisto

bundle_index = 0
submitted_indicators = 0
mocked_get_token_response = '''{"access_token": "fababfafbh"}'''
iocs_bundle = [{"id": "bundle--716fd67b-ba74-44db-8d4c-2efde05ddbaa",
                "objects": [
                    {"created": "2017-01-20T00:00:00.000Z", "definition": {"tlp": "amber"}, "definition_type": "tlp",
                     "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "type": "marking-definition"},
                    {"created": "2019-12-26T00:00:00Z",
                     "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."},
                     "definition_type": "statement", "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                     "type": "marking-definition"},
                    {"created": "2020-01-09T07:31:16.708Z",
                     "description": "Shell access to this domain is being sold on dark web markets",
                     "id": "indicator--7fc19d6d-2d58-45d6-a410-85554b12aea9",
                     "kill_chain_phases": [
                         {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                     "labels": ["compromised"], "lang": "en",
                     "modified": "2020-01-09T07:31:16.708Z",
                     "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                     "pattern": "[file:hashes.MD5 = '8f8ff6b696859c3afe7936c345b098bd' OR "
                                "file:hashes.'SHA-1' = '9bb88f703e234a89ff523514a5c676ac12ae6225' OR "
                                "file:hashes.'SHA-256' = "
                                "'9cd46027d63c36e53f4347d43554336c2ea050d38be3ff9a608cb94cca6ab74b']",
                     "sixgill_actor": "some_actor", "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_002",
                     "sixgill_feedname": "compromised_sites",
                     "sixgill_postid": "6e407c41fe6591d591cd8bbf0d105f7c15ed8991",
                     "sixgill_posttitle": "Credit Card Debt Help,       somewebsite.com",
                     "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0",
                     "type": "indicator",
                     "valid_from": "2019-12-07T00:57:04Z"},
                    {"created": "2020-01-09T07:31:16.824Z",
                     "description": "Shell access to this domain is being sold on dark web markets",
                     "id": "indicator--67b2378f-cbdd-4263-b1c4-668014d376f2",
                     "kill_chain_phases": [
                         {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                     "labels": ["compromised"], "lang": "ru",
                     "modified": "2020-01-09T07:31:16.824Z",
                     "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                     "pattern": "[ipv4-addr:value = '121.165.45.1']", "sixgill_actor": "some_actor",
                     "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_004",
                     "sixgill_feedname": "compromised_sites",
                     "sixgill_postid": "59f08fbf692f84f15353a5e946d2a1cebab92418",
                     "sixgill_posttitle": "somewebsite.com",
                     "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0",
                     "type": "indicator",
                     "valid_from": "2019-12-06T17:10:04Z"},
                    {"created": "2020-01-09T07:31:16.757Z",
                     "description": "Shell access to this domain is being sold on dark web markets",
                     "id": "indicator--6e8b5f57-3ee2-4c4a-9283-8547754dfa09",
                     "kill_chain_phases": [
                         {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                     "labels": ["url"], "lang": "en",
                     "modified": "2020-01-09T07:31:16.757Z",
                     "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                     "pattern": "[url:value = 'http://somewebsite.rar[.]html']", "sixgill_actor": "some_actor",
                     "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_010",
                     "sixgill_feedname": "compromised_sites",
                     "sixgill_postid": "f46cdfc3332d9a04aa63078d82c1e453fd76ba50",
                     "sixgill_posttitle": "somewebsite.com", "sixgill_severity": 70,
                     "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator",
                     "valid_from": "2019-12-06T23:24:51Z"},
                    {"created": "2020-01-09T07:31:16.834Z",
                     "description": "Shell access to this domain is being sold on dark web markets",
                     "id": "indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d",
                     "kill_chain_phases": [
                         {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                     "labels": ["ip"], "lang": "en",
                     "modified": "2020-01-09T07:31:16.834Z",
                     "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                     "pattern": "[ipv4-addr:value = '31.31.77.83']", "sixgill_actor": "some_actor",
                     "sixgill_confidence": 60, "sixgill_feedid": "darkfeed_005",
                     "sixgill_feedname": "compromised_sites",
                     "sixgill_postid": "c3f266e67f163e1a6181c0789e225baba89212a2",
                     "sixgill_posttitle": "somewebsite.com",
                     "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0",
                     "type": "indicator",
                     "valid_from": "2019-12-06T14:37:16Z"},
                    {"created": "2020-01-09T07:31:16.834Z",
                     "description": "Shell access to this domain is being sold on dark web markets",
                     "id": "indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d",
                     "kill_chain_phases": [
                         {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                     "labels": ["malware hash"], "lang": "en",
                     "modified": "2020-01-09T07:31:16.834Z",
                     "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                             "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                     "pattern": "[file:hashes.MD5 = '2f4e41ea7006099f365942349b05a269' OR "
                                "file:hashes.'SHA-1' = '835e4574e01c12552c2a3b62b942d177c4d7aaca' OR "
                                "file:hashes.'SHA-256' = 'a925164d6c0c479967b3d9870267a03adf65e8145']",
                     "sixgill_actor": "some_actor",
                     "sixgill_confidence": 80, "sixgill_feedid": "darkfeed_002",
                     "sixgill_feedname": "compromised_sites",
                     "sixgill_postid": "c3f266e67f163e1a6181c0789e225baba89212a2",
                     "sixgill_posttitle": "somewebsite.com",
                     "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0",
                     "type": "indicator",
                     "valid_from": "2019-12-06T14:37:16Z"},
                    {"created": "2020-02-09T06:41:41.266Z",
                     "description": "IP address was listed as a proxy",
                     "external_reference": [
                         {
                             "description": "Mitre attack tactics and technique reference",
                             "mitre_attack_tactic": "Adversary OPSEC",
                             "mitre_attack_tactic_id": "TA0021",
                             "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0021/",
                             "mitre_attack_technique": "Proxy/protocol relays",
                             "mitre_attack_technique_id": "T1304",
                             "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1304/",
                             "source_name": "mitre-attack"
                         }
                     ],
                     "id": "indicator--2ed98497-cef4-468c-9cee-4f05292b5142",
                     "labels": [
                         "anonymization",
                     ],
                     "lang": "en",
                     "modified": "2020-02-09T06:41:41.266Z",
                     "object_marking_refs": [
                         "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                         "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                     ],
                     "pattern": "[ipv4-addr:value = '182.253.121.14']",
                     "sixgill_actor": "LunarEclipsed",
                     "sixgill_confidence": 70,
                     "sixgill_feedid": "darkfeed_009",
                     "sixgill_feedname": "proxy_ips",
                     "sixgill_postid": "00f74eea142e746415457d0dd4a4fc747add3a1b",
                     "sixgill_posttitle": "✅ 9.7K HTTP/S PROXY LIST (FRESH) ✅",
                     "sixgill_severity": 40,
                     "sixgill_source": "forum_nulled",
                     "spec_version": "2.0",
                     "type": "indicator",
                     "valid_from": "2020-01-25T21:08:25Z"
                     }
                ],
                "spec_version": "2.0",
                "type": "bundle"},
               {"id": "bundle--716fd67b-ba74-44db-8d4c-2efde05ddbaa",
                "objects": [
                    {"created": "2017-01-20T00:00:00.000Z", "definition": {"tlp": "amber"}, "definition_type": "tlp",
                     "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "type": "marking-definition"},
                    {"created": "2019-12-26T00:00:00Z",
                     "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."},
                     "definition_type": "statement", "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                     "type": "marking-definition"}
                ],
                "spec_version": "2.0",
                "type": "bundle"}
               ]

expected_ioc_output = [{'value': '9cd46027d63c36e53f4347d43554336c2ea050d38be3ff9a608cb94cca6ab74b', 'type': 'File',
                        'rawJSON': {'created': '2020-01-09T07:31:16.708Z',
                                    'description': 'Shell access to this domain is being sold on dark web markets',
                                    'id': 'indicator--7fc19d6d-2d58-45d6-a410-85554b12aea9', 'kill_chain_phases':
                                        [
                                            {'kill_chain_name': 'lockheed-martin-cyber-kill-chain',
                                             'phase_name': 'weaponization'}],
                                    'labels': ['compromised'], 'lang': 'en',
                                    'modified': '2020-01-09T07:31:16.708Z',
                                    'object_marking_refs': ['marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                                            'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                    'pattern': "[file:hashes.MD5 = '8f8ff6b696859c3afe7936c345b098bd' OR "
                                               "file:hashes.'SHA-1' = '9bb88f703e234a89ff523514a5c676ac12ae6225' OR "
                                               "file:hashes.'SHA-256' = "
                                               "'9cd46027d63c36e53f4347d43554336c2ea050d38be3ff9a608cb94cca6ab74b']",
                                    'sixgill_actor': 'some_actor', 'sixgill_confidence': 90,
                                    'sixgill_feedid': 'darkfeed_002', 'sixgill_feedname': 'compromised_sites',
                                    'sixgill_postid': '6e407c41fe6591d591cd8bbf0d105f7c15ed8991',
                                    'sixgill_posttitle': 'Credit Card Debt Help,       somewebsite.com',
                                    'sixgill_severity': 70, 'sixgill_source': 'market_magbo', 'spec_version': '2.0',
                                    'type': 'indicator', 'valid_from': '2019-12-07T00:57:04Z'},
                        'fields': {'actor': 'some_actor',
                                   'tags': ['compromised', 'compromised_sites'],
                                   'firstseenbysource': '2020-01-09T07:31:16.708Z',
                                   'description': 'Description: Shell access to this domain is being sold on dark web '
                                                  'markets\nCreated On: 2020-01-09T07:31:16.708Z\nPost '
                                                  'Title: Credit Card Debt Help,       somewebsite.com\nThreat '
                                                  'Actor Name: some_actor\nSource: market_magbo\nSixgill '
                                                  'Feed ID: darkfeed_002\nSixgill Feed Name: compromised_sites\n'
                                                  'Sixgill Post ID: 6e407c41fe6591d591cd8bbf0d105f7c15ed8991\n'
                                                  'Sixgill Confidence: 90\n'
                                                  'Language: en\n'
                                                  'Indicator ID: indicator--7fc19d6d-2d58-45d6-a410-85554b12aea9\n'
                                                  'External references (e.g. MITRE ATT&CK): None\n',
                                   'sixgillactor': 'some_actor', 'sixgillfeedname': 'compromised_sites',
                                   'sixgillsource': 'market_magbo', 'sixgilllanguage': 'en',
                                   'sixgillposttitle': 'Credit Card Debt Help,       somewebsite.com',
                                   'sixgillfeedid': 'darkfeed_002', "sixgillconfidence": 90,
                                   'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q='
                                                           '_id:6e407c41fe6591d591cd8bbf0d105f7c15ed8991',
                                   'sixgillindicatorid': 'indicator--7fc19d6d-2d58-45d6-a410-85554b12aea9',
                                   'sixgilldescription': 'Shell access to this domain is being sold on '
                                                         'dark web markets',
                                   'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                                   'sixgillmitreattcktactic': None, 'sixgillmitreattcktechnique': None,
                                   'md5': '8f8ff6b696859c3afe7936c345b098bd',
                                   'sha1': '9bb88f703e234a89ff523514a5c676ac12ae6225',
                                   'sha256': '9cd46027d63c36e53f4347d43554336c2ea050d38be3ff9a608cb94cca6ab74b'},
                        'score': 3}, {'value': '121.165.45.1', 'type': 'IP',
                                      'rawJSON': {'created': '2020-01-09T07:31:16.824Z',
                                                  'description': 'Shell access to this domain is being sold on '
                                                                 'dark web markets',
                                                  'id': 'indicator--67b2378f-cbdd-4263-b1c4-668014d376f2',
                                                  'kill_chain_phases': [
                                                      {'kill_chain_name': 'lockheed-martin-cyber-kill-chain',
                                                       'phase_name': 'weaponization'}],
                                                  'labels': ['compromised'], 'lang': 'ru',
                                                  'modified': '2020-01-09T07:31:16.824Z', 'object_marking_refs':
                                                      [
                                                          'marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                                          'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                                  'pattern': "[ipv4-addr:value = '121.165.45.1']",
                                                  'sixgill_actor': 'some_actor', 'sixgill_confidence': 90,
                                                  'sixgill_feedid': 'darkfeed_004',
                                                  'sixgill_feedname': 'compromised_sites',
                                                  'sixgill_postid': '59f08fbf692f84f15353a5e946d2a1cebab92418',
                                                  'sixgill_posttitle': 'somewebsite.com', 'sixgill_severity': 70,
                                                  'sixgill_source': 'market_magbo', 'spec_version': '2.0',
                                                  'type': 'indicator', 'valid_from': '2019-12-06T17:10:04Z'},
                                      'fields': {'actor': 'some_actor',
                                                 'tags': ['compromised', 'compromised_sites'],
                                                 'firstseenbysource': '2020-01-09T07:31:16.824Z',
                                                 'description': 'Description: Shell access to this domain is being '
                                                                'sold on dark web markets\n'
                                                                'Created On: 2020-01-09T07:31:16.824Z\n'
                                                                'Post Title: somewebsite.com\n'
                                                                'Threat Actor Name: some_actor\n'
                                                                'Source: market_magbo\nSixgill Feed ID: darkfeed_004\n'
                                                                'Sixgill Feed Name: compromised_sites\n'
                                                                'Sixgill Post ID: '
                                                                '59f08fbf692f84f15353a5e946d2a1cebab92418\n'
                                                                'Sixgill Confidence: 90\n'
                                                                'Language: ru\n'
                                                                'Indicator ID: '
                                                                'indicator--67b2378f-cbdd-4263-b1c4-668014d376f2\n'
                                                                'External references (e.g. MITRE ATT&CK): None\n',
                                                 'sixgillactor': 'some_actor', 'sixgillfeedname': 'compromised_sites',
                                                 'sixgillsource': 'market_magbo', 'sixgilllanguage': 'ru',
                                                 'sixgillposttitle': 'somewebsite.com', 'sixgillfeedid': 'darkfeed_004',
                                                 'sixgillconfidence': 90,
                                                 'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q='
                                                                         '_id:59f08fbf692f84f15353a5e946d2a1cebab92418',
                                                 'sixgillindicatorid':
                                                     'indicator--67b2378f-cbdd-4263-b1c4-668014d376f2',
                                                 'sixgilldescription': 'Shell access to this domain is being sold '
                                                                       'on dark web markets',
                                                 'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                                                 'sixgillmitreattcktactic': None, 'sixgillmitreattcktechnique': None},
                                      'score': 3}, {'value': 'http://somewebsite.rar.html', 'type': 'URL',
                                                    'rawJSON': {'created': '2020-01-09T07:31:16.757Z',
                                                                'description': 'Shell access to this domain is '
                                                                               'being sold on dark web markets',
                                                                'id': 'indicator--6e8b5f57-3ee2-4c4a-9283-8547754dfa09',
                                                                'kill_chain_phases':
                                                                    [{
                                                                        'kill_chain_name':
                                                                            'lockheed-martin-cyber-kill-chain',
                                                                        'phase_name': 'weaponization'}],
                                                                'labels': ['url'], 'lang': 'en',
                                                                'modified': '2020-01-09T07:31:16.757Z',
                                                                'object_marking_refs': [
                                                                    'marking-definition--'
                                                                    '41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                                                    'marking-definition--'
                                                                    'f88d31f6-486f-44da-b317-01333bde0b82'],
                                                                'pattern': "[url:value = "
                                                                           "'http://somewebsite.rar[.]html']",
                                                                'sixgill_actor': 'some_actor', 'sixgill_confidence': 90,
                                                                'sixgill_feedid': 'darkfeed_010',
                                                                'sixgill_feedname': 'compromised_sites',
                                                                'sixgill_postid':
                                                                    'f46cdfc3332d9a04aa63078d82c1e453fd76ba50',
                                                                'sixgill_posttitle': 'somewebsite.com',
                                                                'sixgill_severity': 70,
                                                                'sixgill_source': 'market_magbo', 'spec_version': '2.0',
                                                                'type': 'indicator',
                                                                'valid_from': '2019-12-06T23:24:51Z'},
                                                    'fields': {'actor': 'some_actor',
                                                               'tags': ['url', 'compromised_sites'],
                                                               'firstseenbysource': '2020-01-09T07:31:16.757Z',
                                                               'description': 'Description: Shell access to this '
                                                                              'domain is being sold on dark '
                                                                              'web markets\n'
                                                                              'Created On: 2020-01-09T07:31:16.757Z\n'
                                                                              'Post Title: somewebsite.com\n'
                                                                              'Threat Actor Name: some_actor\n'
                                                                              'Source: market_magbo\n'
                                                                              'Sixgill Feed ID: darkfeed_010\n'
                                                                              'Sixgill Feed Name: '
                                                                              'compromised_sites\n'
                                                                              'Sixgill Post ID: '
                                                                              'f46cdfc3332d9a04aa63078d82c1e453fd76ba50'
                                                                              '\nSixgill Confidence: 90'
                                                                              '\nLanguage: en\n'
                                                                              'Indicator ID: indicator--'
                                                                              '6e8b5f57-3ee2-4c4a-9283-8547754dfa09\n'
                                                                              'External references '
                                                                              '(e.g. MITRE ATT&CK): None\n',
                                                               'sixgillactor': 'some_actor',
                                                               'sixgillfeedname': 'compromised_sites',
                                                               'sixgillsource': 'market_magbo', 'sixgilllanguage': 'en',
                                                               'sixgillposttitle': 'somewebsite.com',
                                                               'sixgillfeedid': 'darkfeed_010',
                                                               'sixgillconfidence': 90,
                                                               'sixgillpostreference':
                                                                   'https://portal.cybersixgill.com/#/search?q='
                                                                   '_id:f46cdfc3332d9a04aa63078d82c1e453fd76ba50',
                                                               'sixgillindicatorid':
                                                                   'indicator--6e8b5f57-3ee2-4c4a-9283-8547754dfa09',
                                                               'sixgilldescription': 'Shell access to this domain is '
                                                                                     'being sold on dark web markets',
                                                               'sixgillvirustotaldetectionrate': None,
                                                               'sixgillvirustotalurl': None,
                                                               'sixgillmitreattcktactic': None,
                                                               'sixgillmitreattcktechnique': None}, 'score': 3},
                       {'value': '31.31.77.83', 'type': 'IP', 'rawJSON': {'created': '2020-01-09T07:31:16.834Z',
                                                                          'description': 'Shell access to this domain '
                                                                                         'is being sold on '
                                                                                         'dark web markets',
                                                                          'id':
                                                                              'indicator--85d3d87b-76ed-'
                                                                              '4cab-b709-a43dfbdc5d8d',
                                                                          'kill_chain_phases':
                                                                              [{'kill_chain_name':
                                                                                'lockheed-martin-cyber-kill-chain',
                                                                                'phase_name': 'weaponization'}],
                                                                          'labels': ['ip'], 'lang': 'en',
                                                                          'modified': '2020-01-09T07:31:16.834Z',
                                                                          'object_marking_refs': [
                                                                              'marking-definition--'
                                                                              '41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                                                              'marking-definition--'
                                                                              'f88d31f6-486f-44da-b317-01333bde0b82'],
                                                                          'pattern': "[ipv4-addr:value = "
                                                                                     "'31.31.77.83']",
                                                                          'sixgill_actor': 'some_actor',
                                                                          'sixgill_confidence': 60,
                                                                          'sixgill_feedid': 'darkfeed_005',
                                                                          'sixgill_feedname': 'compromised_sites',
                                                                          'sixgill_postid': 'c3f266e67f163e1a6'
                                                                                            '181c0789e225baba89212a2',
                                                                          'sixgill_posttitle': 'somewebsite.com',
                                                                          'sixgill_severity': 70,
                                                                          'sixgill_source': 'market_magbo',
                                                                          'spec_version': '2.0', 'type': 'indicator',
                                                                          'valid_from': '2019-12-06T14:37:16Z'},
                        'fields': {'actor': 'some_actor', 'tags': ['ip', 'compromised_sites'],
                                   'firstseenbysource': '2020-01-09T07:31:16.834Z',
                                   'description': 'Description: Shell access to this domain is being sold on '
                                                  'dark web markets\nCreated On: 2020-01-09T07:31:16.834Z\n'
                                                  'Post Title: somewebsite.com\nThreat Actor Name: some_actor\n'
                                                  'Source: market_magbo\nSixgill Feed ID: darkfeed_005\n'
                                                  'Sixgill Feed Name: compromised_sites\n'
                                                  'Sixgill Post ID: c3f266e67f163e1a6181c0789e225baba89212a2\n'
                                                  'Sixgill Confidence: 60\n'
                                                  'Language: en\nIndicator ID: '
                                                  'indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d\n'
                                                  'External references (e.g. MITRE ATT&CK): None\n',
                                   'sixgillactor': 'some_actor', 'sixgillfeedname': 'compromised_sites',
                                   'sixgillsource': 'market_magbo', 'sixgilllanguage': 'en',
                                   'sixgillposttitle': 'somewebsite.com', 'sixgillfeedid': 'darkfeed_005',
                                   'sixgillconfidence': 60,
                                   'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q='
                                                           '_id:c3f266e67f163e1a6181c0789e225baba89212a2',
                                   'sixgillindicatorid': 'indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d',
                                   'sixgilldescription': 'Shell access to this domain is being sold on '
                                                         'dark web markets',
                                   'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                                   'sixgillmitreattcktactic': None, 'sixgillmitreattcktechnique': None}, 'score': 3},
                       {'value': 'a925164d6c0c479967b3d9870267a03adf65e8145', 'type': 'File',
                        'rawJSON': {'created': '2020-01-09T07:31:16.834Z',
                                    'description': 'Shell access to this domain is being sold on dark web markets',
                                    'id': 'indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d', 'kill_chain_phases': [{
                                        'kill_chain_name': 'lockheed-martin-cyber-kill-chain',
                                        'phase_name': 'weaponization'}],
                                    'labels': ['malware hash'], 'lang': 'en',
                                    'modified': '2020-01-09T07:31:16.834Z',
                                    'object_marking_refs': ['marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                                            'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                    'pattern': "[file:hashes.MD5 = '2f4e41ea7006099f365942349b05a269' OR "
                                               "file:hashes.'SHA-1' = '835e4574e01c12552c2a3b62b942d177c4d7aaca' OR "
                                               "file:hashes.'SHA-256' = 'a925164d6c0c479967b3d9870267a03adf65e8145']",
                                    'sixgill_actor': 'some_actor', 'sixgill_confidence': 80,
                                    'sixgill_feedid': 'darkfeed_002', 'sixgill_feedname': 'compromised_sites',
                                    'sixgill_postid': 'c3f266e67f163e1a6181c0789e225baba89212a2',
                                    'sixgill_posttitle': 'somewebsite.com', 'sixgill_severity': 70,
                                    'sixgill_source': 'market_magbo', 'spec_version': '2.0', 'type': 'indicator',
                                    'valid_from': '2019-12-06T14:37:16Z'},
                        'fields': {'actor': 'some_actor',
                                   'tags': ['malware hash', 'compromised_sites'],
                                   'firstseenbysource': '2020-01-09T07:31:16.834Z',
                                   'description': 'Description: Shell access to this domain is being sold on dark '
                                                  'web markets\nCreated On: 2020-01-09T07:31:16.834Z\n'
                                                  'Post Title: somewebsite.com\nThreat Actor Name: some_actor\n'
                                                  'Source: market_magbo\nSixgill Feed ID: darkfeed_002\n'
                                                  'Sixgill Feed Name: compromised_sites\n'
                                                  'Sixgill Post ID: c3f266e67f163e1a6181c0789e225baba89212a2\n'
                                                  'Sixgill Confidence: 80\n'
                                                  'Language: en\nIndicator ID: '
                                                  'indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d\n'
                                                  'External references (e.g. MITRE ATT&CK): None\n',
                                   'sixgillactor': 'some_actor', 'sixgillfeedname': 'compromised_sites',
                                   'sixgillsource': 'market_magbo', 'sixgilllanguage': 'en',
                                   'sixgillposttitle': 'somewebsite.com', 'sixgillfeedid': 'darkfeed_002',
                                   'sixgillconfidence': 80,
                                   'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q='
                                                           '_id:c3f266e67f163e1a6181c0789e225baba89212a2',
                                   'sixgillindicatorid': 'indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d',
                                   'sixgilldescription': 'Shell access to this domain is being sold on dark'
                                                         ' web markets',
                                   'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                                   'sixgillmitreattcktactic': None, 'sixgillmitreattcktechnique': None,
                                   'md5': '2f4e41ea7006099f365942349b05a269',
                                   'sha1': '835e4574e01c12552c2a3b62b942d177c4d7aaca',
                                   'sha256': 'a925164d6c0c479967b3d9870267a03adf65e8145'}, 'score': 3},
                       {'value': '182.253.121.14', 'type': 'IP',
                        'rawJSON': {'created': '2020-02-09T06:41:41.266Z',
                                    'description': 'IP address was listed '
                                                   'as a proxy',
                                    'external_reference':
                                        [{'description': 'Mitre attack tactics and technique reference',
                                          'mitre_attack_tactic': 'Adversary OPSEC',
                                          'mitre_attack_tactic_id': 'TA0021',
                                          'mitre_attack_tactic_url': 'https://attack.mitre.org/tactics/TA0021/',
                                          'mitre_attack_technique': 'Proxy/protocol relays',
                                          'mitre_attack_technique_id': 'T1304',
                                          'mitre_attack_technique_url': 'https://attack.mitre.org/techniques/T1304/',
                                          'source_name': 'mitre-attack'}],
                                    'id': 'indicator--2ed98497-cef4'
                                          '-468c-9cee-4f05292b5142',
                                    'labels': ['anonymization'],
                                    'lang': 'en',
                                    'modified': '2020-02-09T06:41:41.266Z',
                                    'object_marking_refs': [
                                        'marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4',
                                        'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                    'pattern': "[ipv4-addr:value = '182.253.121.14']",
                                    'sixgill_actor': 'LunarEclipsed',
                                    'sixgill_confidence': 70,
                                    'sixgill_feedid': 'darkfeed_009',
                                    'sixgill_feedname': 'proxy_ips',
                                    'sixgill_postid': '00f74eea142e746415457d0dd4a4fc747add3a1b',
                                    'sixgill_posttitle': '✅ 9.7K HTTP/S PROXY LIST (FRESH) ✅',
                                    'sixgill_severity': 40,
                                    'sixgill_source': 'forum_nulled',
                                    'spec_version': '2.0', 'type': 'indicator',
                                    'valid_from': '2020-01-25T21:08:25Z'},
                        'fields': {'actor': 'LunarEclipsed',
                                   'tags': ['anonymization', 'proxy_ips'],
                                   'firstseenbysource': '2020-02-09T06:41:41.266Z',
                                   'description': "Description: IP address was listed as a proxy\n"
                                                  "Created On: 2020-02-09T06:41:41.266Z\n"
                                                  "Post Title: ✅ 9.7K HTTP/S PROXY LIST (FRESH) ✅\n"
                                                  "Threat Actor Name: LunarEclipsed\nSource: forum_nulled\n"
                                                  "Sixgill Feed ID: darkfeed_009\nSixgill Feed Name: proxy_ips\n"
                                                  "Sixgill Post ID: 00f74eea142e746415457d0dd4a4fc747add3a1b\n"
                                                  'Sixgill Confidence: 70\n'
                                                  "Language: en\nIndicator ID: "
                                                  "indicator--2ed98497-cef4-468c-9cee-4f05292b5142\n"
                                                  "External references (e.g. MITRE ATT&CK): "
                                                  "[{'description': 'Mitre attack tactics and technique reference', "
                                                  "'mitre_attack_tactic': 'Adversary OPSEC', "
                                                  "'mitre_attack_tactic_id': 'TA0021', 'mitre_attack_tactic_url': "
                                                  "'https://attack.mitre.org/tactics/TA0021/', "
                                                  "'mitre_attack_technique': 'Proxy/protocol relays', "
                                                  "'mitre_attack_technique_id': 'T1304', "
                                                  "'mitre_attack_technique_url': "
                                                  "'https://attack.mitre.org/techniques/T1304/', "
                                                  "'source_name': 'mitre-attack'}]\n",
                                   'sixgillactor': 'LunarEclipsed', 'sixgillfeedname': 'proxy_ips',
                                   'sixgillsource': 'forum_nulled', 'sixgilllanguage': 'en',
                                   'sixgillposttitle': '✅ 9.7K HTTP/S PROXY LIST (FRESH) ✅',
                                   'sixgillfeedid': 'darkfeed_009', 'sixgillconfidence': 70,
                                   'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q='
                                                           '_id:00f74eea142e746415457d0dd4a4fc747add3a1b',
                                   'sixgillindicatorid': 'indicator--2ed98497-cef4-468c-9cee-4f05292b5142',
                                   'sixgilldescription': 'IP address was listed as a proxy',
                                   'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                                   'sixgillmitreattcktactic': 'Adversary OPSEC',
                                   'sixgillmitreattcktechnique': 'Proxy/protocol relays',
                                   'feedrelatedindicators': [{'type': 'MITRE ATT&CK', 'value': 'TA0021',
                                                              'description':
                                                                  'https://attack.mitre.org/tactics/TA0021/'}]},
                        'score': 3}]


class MockedResponse:
    def __init__(self, status_code, text, reason=None, url=None, method=None):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.url = url
        self.request = requests.Request('GET')
        self.headers = {}
        self.ok = self.status_code == 200

    def json(self):
        return json.loads(self.text)


def init_params():
    return {
        'client_id': 'WRONG_CLIENT_ID_TEST',
        'client_secret': 'CLIENT_SECRET_TEST',
    }


def mocked_request(*args, **kwargs):
    global bundle_index
    global submitted_indicators

    request = kwargs.get("request", {})
    end_point = request.path_url
    method = request.method

    response_dict = {
        'POST': {
            '/auth/token':
                MockedResponse(200, mocked_get_token_response),
            '/darkfeed/ioc/ack':
                MockedResponse(200, str(submitted_indicators))
        },
        'GET': {
            '/darkfeed/ioc?limit=1000':
                MockedResponse(200, json.dumps(iocs_bundle[bundle_index])),
        },
    }

    response_dict = response_dict.get(method)
    response = response_dict.get(end_point)

    if method == 'GET' and end_point == '/darkfeed/ioc?limit=1000':
        submitted_indicators = len(iocs_bundle[bundle_index].get("objects")) - 2
        bundle_index += 1

    return response


def test_test_module_command_raise_exception(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(400, "error"))

    from Sixgill_Darkfeed import test_module_command

    with pytest.raises(Exception):
        test_module_command()


def test_test_module_command(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(200, "ok"))

    from Sixgill_Darkfeed import test_module_command
    test_module_command()


def test_filter_confidence(mocker):
    from Sixgill_Darkfeed import filter_confidence
    assert True is filter_confidence('all', {"sixgill_confidence": 80})
    assert True is filter_confidence(60, {"sixgill_confidence": 80})
    assert True is filter_confidence(80, {"sixgill_confidence": 80})
    assert False is filter_confidence(80, {"sixgill_confidence": 60})


def test_fetch_indicators_command(mocker):
    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', new=mocked_request)

    from Sixgill_Darkfeed import fetch_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient("client_id",
                               "client_secret",
                               "some_channel",
                               FeedStream.DARKFEED,
                               demisto, 1000)

    output = fetch_indicators_command(client)

    bundle_index = 0
    submitted_indicators = 0

    assert output == expected_ioc_output


def test_get_indicators_command(mocker):
    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', new=mocked_request)

    from Sixgill_Darkfeed import get_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient("client_id",
                               "client_secret",
                               "some_channel",
                               FeedStream.DARKFEED,
                               demisto, 1000)

    output = get_indicators_command(client, {"limit": 10})

    bundle_index = 0
    submitted_indicators = 0

    assert output[2] == expected_ioc_output


@pytest.mark.parametrize('tlp_color', ['', None, 'AMBER'])
def test_feed_tags_and_tlp_color(mocker, tlp_color):
    """
    Given:
    - feedTags parameter
    When:
    - Executing fetch command on feed
    Then:
    - Validate the tags supplied are added to the tags list in addition to the tags that were there before
    """
    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', new=mocked_request)

    from Sixgill_Darkfeed import fetch_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient("client_id",
                               "client_secret",
                               "some_channel",
                               FeedStream.DARKFEED,
                               demisto, 1000)

    output = fetch_indicators_command(client, tags=['tag1', 'tag2'], tlp_color=tlp_color)
    assert all(item in output[0]['fields']['tags'] for item in ['tag1', 'tag2'])
    assert any(item in output[0]['fields']['tags'] for item in ['compromised', 'ip', 'url'])
    if tlp_color:
        assert output[0]['fields']['trafficlightprotocol'] == tlp_color
    else:
        assert not output[0]['fields'].get('trafficlightprotocol')
        bundle_index -= 1
