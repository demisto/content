ATTACK_PATTERN = {
    'response': {
        "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
        "name": "ATTACK_PATTERN 1",
        "type": "attack-pattern",
        "modified": "2020-05-13T22:50:51.258Z",
        "created": "2017-05-31T21:30:44.329Z",
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        "x_mitre_platforms": [
            "Windows"
        ],
        "external_references": [
            {
                "url": "https://attack.mitre.org/techniques/T1047",
                "source_name": "mitre-attack",
                "external_id": "T1047"
            },
            {
                "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
                "source_name": "Wikipedia SMB",
                "url": "https://en.wikipedia.org/wiki/Server_Message_Block"
            },
            {
                "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
                "source_name": "TechNet RPC",
                "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx"
            },
        ],
        "kill_chain_phases": [
            {
                "phase_name": "defense-evasion",
                "kill_chain_name": "mitre-attack"
            },
            {
                "phase_name": "privilege-escalation",
                "kill_chain_name": "mitre-attack"
            }
        ]
    },
    'map_result': {
        'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
        'firstseenbysource': '2017-05-31T21:30:44.329Z',
        'killchainphases': ['Defense Evasion', 'Privilege Escalation'],
        'modified': "2020-05-13T22:50:51.258Z",
        'description': "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        'operatingsystemrefs': ['Windows'],
        'mitreid': 'T1047',
        'publications': [{'link': "https://en.wikipedia.org/wiki/Server_Message_Block",
                          'title': "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
                          'source': 'Wikipedia SMB'},
                         {'link': "https://technet.microsoft.com/en-us/library/cc787851.aspx",
                          'title': 'Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.',
                          "source": 'TechNet RPC'}],
        'tags': ['T1047']
    },
    'indicator': ([{'fields': {'description': 'Adversaries may abuse Windows Management '
                                              'Instrumentation (WMI) to achieve execution.',
                               'firstseenbysource': '2017-05-31T21:30:44.329Z',
                               'killchainphases': ['Defense Evasion', 'Privilege Escalation'],
                               'mitreid': 'T1047',
                               'modified': '2020-05-13T22:50:51.258Z',
                               'operatingsystemrefs': ['Windows'],
                               'publications': [{'link': 'https://en.wikipedia.org/wiki/Server_Message_Block',
                                                 'source': 'Wikipedia SMB',
                                                 'title': 'Wikipedia. (2016, June 12). Server '
                                                          'Message Block. Retrieved June 12, '
                                                          '2016.'},
                                                {'link': 'https://technet.microsoft.com/en-us/library/cc787851.aspx',
                                                 'source': 'TechNet RPC',
                                                 'title': 'Microsoft. (2003, March 28). What Is '
                                                          'RPC?. Retrieved June 12, 2016.'}],
                               'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
                               'tags': ['T1047']},
                    'rawJSON': {'created': '2017-05-31T21:30:44.329Z',
                                'description': 'Adversaries may abuse Windows Management '
                                               'Instrumentation (WMI) to achieve execution.',
                                'external_references': [{'external_id': 'T1047',
                                                         'source_name': 'mitre-attack',
                                                         'url': 'https://attack.mitre.org/techniques/T1047'},
                                                        {'description': 'Wikipedia. (2016, June '
                                                                        '12). Server Message '
                                                                        'Block. Retrieved June '
                                                                        '12, 2016.',
                                                         'source_name': 'Wikipedia SMB',
                                                         'url': 'https://en.wikipedia.org/wiki/Server_Message_Block'},
                                                        {'description': 'Microsoft. (2003, '
                                                                        'March 28). What Is '
                                                                        'RPC?. Retrieved June '
                                                                        '12, 2016.',
                                                         'source_name': 'TechNet RPC',
                                                         'url': 'https://technet.microsoft.com/en-us/library/cc787851.aspx'}],
                                'id': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
                                'kill_chain_phases': [{'kill_chain_name': 'mitre-attack',
                                                       'phase_name': 'defense-evasion'},
                                                      {'kill_chain_name': 'mitre-attack',
                                                       'phase_name': 'privilege-escalation'}],
                                'modified': '2020-05-13T22:50:51.258Z',
                                'name': 'ATTACK_PATTERN 1',
                                'type': 'attack-pattern',
                                'x_mitre_platforms': ['Windows']},
                    'score': 2,
                    'type': 'Attack Pattern',
                    'value': 'ATTACK_PATTERN 1'}],
                  [],
                  {'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055': 'ATTACK_PATTERN 1'},
                  {'T1047': 'ATTACK_PATTERN 1'})
}

STIX_ATTACK_PATTERN = {
    'response': {
        "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
        "name": "ATTACK_PATTERN 1",
        "type": "attack-pattern",
        "modified": "2020-05-13T22:50:51.258Z",
        "created": "2017-05-31T21:30:44.329Z",
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        "x_mitre_platforms": [
            "Windows"
        ],
        "external_references": [
            {
                "url": "https://attack.mitre.org/techniques/T1047",
                "source_name": "mitre-attack",
                "external_id": "T1047"
            },
            {
                "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
                "source_name": "Wikipedia SMB",
                "url": "https://en.wikipedia.org/wiki/Server_Message_Block"
            },
            {
                "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
                "source_name": "TechNet RPC",
                "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx"
            },
        ],
        "kill_chain_phases": [
            {
                "phase_name": "defense-evasion",
                "kill_chain_name": "mitre-attack"
            },
            {
                "phase_name": "privilege-escalation",
                "kill_chain_name": "mitre-attack"
            }
        ]
    },
    'map_result': {
        'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
        'firstseenbysource': '2017-05-31T21:30:44.329Z',
        'stixkillchainphases': ['Defense Evasion', 'Privilege Escalation'],
        'modified': "2020-05-13T22:50:51.258Z",
        'stixdescription': "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        'operatingsystemrefs': ['Windows'],
        'mitreid': 'T1047',
        'publications': [{'link': "https://en.wikipedia.org/wiki/Server_Message_Block",
                          'title': "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
                          'source': 'Wikipedia SMB'},
                         {'link': "https://technet.microsoft.com/en-us/library/cc787851.aspx",
                          'title': 'Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.',
                          "source": 'TechNet RPC'}],
        'tags': ['T1047']
    }
}

COURSE_OF_ACTION = {
    'response': {
        "id": "course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22",
        "name": "COURSE_OF_ACTION 1",
        "type": "course-of-action",
        "description": "Prevent files from having a trailing space after the extension.",
        "modified": "2019-07-25T11:46:32.010Z",
        "external_references": [
            {
                "external_id": "T1151",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/mitigations/T1151"
            }
        ],
        "created": "2018-10-17T00:14:20.652Z"
    },
    'map_result': {'description': 'Prevent files from having a trailing space after the '
                                  'extension.',
                   'firstseenbysource': '2018-10-17T00:14:20.652Z',
                   'mitreid': 'T1151',
                   'modified': '2019-07-25T11:46:32.010Z',
                   'publications': [],
                   'stixid': 'course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22',
                   'tags': ['T1151']},
    'indicator': ([{'fields': {'description': 'Prevent files from having a trailing space after '
                                              'the extension.',
                               'firstseenbysource': '2018-10-17T00:14:20.652Z',
                               'mitreid': 'T1151',
                               'modified': '2019-07-25T11:46:32.010Z',
                               'publications': [],
                               'stixid': 'course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22',
                               'tags': ['T1151']},
                    'rawJSON': {'created': '2018-10-17T00:14:20.652Z',
                                'description': 'Prevent files from having a trailing space '
                                               'after the extension.',
                                'external_references': [{'external_id': 'T1151',
                                                         'source_name': 'mitre-attack',
                                                         'url': 'https://attack.mitre.org/mitigations/T1151'}],
                                'id': 'course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22',
                                'modified': '2019-07-25T11:46:32.010Z',
                                'name': 'COURSE_OF_ACTION 1',
                                'type': 'course-of-action'},
                    'score': 0,
                    'type': 'Course of Action',
                    'value': 'COURSE_OF_ACTION 1'}],
                  [],
                  {'course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22': 'COURSE_OF_ACTION 1'},
                  {})
}

INTRUSION_SET = {
    'response': {
        "external_references": [
            {
                "external_id": "G0066",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/groups/G0066"
            },
            {
                "description": "(Citation: Security Affairs Elderwood Sept 2012)",
                "source_name": "Elderwood"
            },
        ],
        "description": "[Elderwood](https://attack.mitre.org/groups/G0066)",
        "modified": "2021-03-02T22:40:11.097Z",
        "created": "2018-04-18T17:59:24.739Z",
        "aliases": [
            "Elderwood",
            "Elderwood Gang",
            "Beijing Group",
            "Sneaky Panda"
        ],
        "id": "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484",
        "name": "INTRUSION_SET 1",
        "type": "intrusion-set"
    },
    'map_result': {'aliases': ['Elderwood', 'Elderwood Gang', 'Beijing Group', 'Sneaky Panda'],
                   'description': '[Elderwood](https://attack.mitre.org/groups/G0066)',
                   'firstseenbysource': '2018-04-18T17:59:24.739Z',
                   'mitreid': 'G0066',
                   'modified': '2021-03-02T22:40:11.097Z',
                   'publications': [{'link': '',
                                     'source': 'Elderwood',
                                     'title': '(Citation: Security Affairs Elderwood Sept '
                                              '2012)'}],
                   'stixid': 'intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484',
                   'tags': ['G0066']},
    "indicator": ([{'fields': {'aliases': ['Elderwood',
                                           'Elderwood Gang',
                                           'Beijing Group',
                                           'Sneaky Panda'],
                               'description': '[Elderwood](https://attack.mitre.org/groups/G0066)',
                               'firstseenbysource': '2018-04-18T17:59:24.739Z',
                               'mitreid': 'G0066',
                               'modified': '2021-03-02T22:40:11.097Z',
                               'publications': [{'link': '',
                                                 'source': 'Elderwood',
                                                 'title': '(Citation: Security Affairs '
                                                          'Elderwood Sept 2012)'}],
                               'stixid': 'intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484',
                               'tags': ['G0066']},
                    'rawJSON': {'aliases': ['Elderwood',
                                            'Elderwood Gang',
                                            'Beijing Group',
                                            'Sneaky Panda'],
                                'created': '2018-04-18T17:59:24.739Z',
                                'description': '[Elderwood](https://attack.mitre.org/groups/G0066)',
                                'external_references': [{'external_id': 'G0066',
                                                         'source_name': 'mitre-attack',
                                                         'url': 'https://attack.mitre.org/groups/G0066'},
                                                        {'description': '(Citation: Security '
                                                                        'Affairs Elderwood Sept '
                                                                        '2012)',
                                                         'source_name': 'Elderwood'}],
                                'id': 'intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484',
                                'modified': '2021-03-02T22:40:11.097Z',
                                'name': 'INTRUSION_SET 1',
                                'type': 'intrusion-set'},
                    'score': 3,
                    'type': 'Intrusion Set',
                    'value': 'INTRUSION_SET 1'}],
                  [],
                  {'intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484': 'INTRUSION_SET 1'},
                  {})
}

MALWARE = {
    'response': {
        "description": "[Wiarp](https://attack.mitre.org/software/S0206)",
        "external_references": [
            {
                "external_id": "S0206",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/software/S0206"
            },
            {
                "description": "Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018.",
                "source_name": "Symantec Wiarp May 2012",
                "url": "https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "Wiarp"
        ],
        "modified": "2021-01-06T19:32:28.378Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "malware"
        ],
        "id": "malware--039814a0-88de-46c5-a4fb-b293db21880a",
        "name": "MALWARE 1",
        "type": "malware"
    },
    'map_result': {'aliases': ['Wiarp'],
                   'description': '[Wiarp](https://attack.mitre.org/software/S0206)',
                   'firstseenbysource': '2018-04-18T17:59:24.739Z',
                   'mitreid': 'S0206',
                   'modified': '2021-01-06T19:32:28.378Z',
                   'operatingsystemrefs': ['Windows'],
                   'publications': [
                       {'link': 'https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99',
                        'source': 'Symantec Wiarp May 2012',
                        'title': 'Zhou, R. (2012, May 15). Backdoor.Wiarp. '
                                 'Retrieved February 22, 2018.'}],
                   'stixid': 'malware--039814a0-88de-46c5-a4fb-b293db21880a',
                   'tags': ['S0206', 'malware']},
    "indicator": ([{'fields': {'aliases': ['Wiarp'],
                               'description': '[Wiarp](https://attack.mitre.org/software/S0206)',
                               'firstseenbysource': '2018-04-18T17:59:24.739Z',
                               'mitreid': 'S0206',
                               'modified': '2021-01-06T19:32:28.378Z',
                               'operatingsystemrefs': ['Windows'],
                               'publications': [{
                                   'link': 'https://www.symantec.com/security_response/writeup.jsp?'
                                           'docid=2012-051606-1005-99',
                                   'source': 'Symantec Wiarp May 2012',
                                   'title': 'Zhou, R. (2012, May 15). '
                                            'Backdoor.Wiarp. Retrieved February '
                                            '22, 2018.'}],
                               'stixid': 'malware--039814a0-88de-46c5-a4fb-b293db21880a',
                               'tags': ['S0206', 'malware']},
                    'rawJSON': {'created': '2018-04-18T17:59:24.739Z',
                                'description': '[Wiarp](https://attack.mitre.org/software/S0206)',
                                'external_references': [{'external_id': 'S0206',
                                                         'source_name': 'mitre-attack',
                                                         'url': 'https://attack.mitre.org/software/S0206'},
                                                        {'description': 'Zhou, R. (2012, May '
                                                                        '15). Backdoor.Wiarp. '
                                                                        'Retrieved February 22, '
                                                                        '2018.',
                                                         'source_name': 'Symantec Wiarp May '
                                                                        '2012',
                                                         'url': 'https://www.symantec.com/security_response/writeup.jsp'
                                                                '?docid=2012-051606-1005-99'}],
                                'id': 'malware--039814a0-88de-46c5-a4fb-b293db21880a',
                                'labels': ['malware'],
                                'modified': '2021-01-06T19:32:28.378Z',
                                'name': 'MALWARE 1',
                                'type': 'malware',
                                'x_mitre_aliases': ['Wiarp'],
                                'x_mitre_platforms': ['Windows']},
                    'score': 3,
                    'type': 'Malware',
                    'value': 'MALWARE 1'}],
                  [],
                  {'malware--039814a0-88de-46c5-a4fb-b293db21880a': 'MALWARE 1'}, {})
}

STIX_MALWARE = {
    'response': {
        "description": "[Wiarp](https://attack.mitre.org/software/S0206)",
        "external_references": [
            {
                "external_id": "S0206",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/software/S0206"
            },
            {
                "description": "Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018.",
                "source_name": "Symantec Wiarp May 2012",
                "url": "https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "Wiarp"
        ],
        "modified": "2021-01-06T19:32:28.378Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "malware"
        ],
        "id": "malware--039814a0-88de-46c5-a4fb-b293db21880a",
        "name": "MALWARE 1",
        "type": "malware"
    },
    'map_result': {'stixaliases': ['Wiarp'],
                   'stixdescription': '[Wiarp](https://attack.mitre.org/software/S0206)',
                   'firstseenbysource': '2018-04-18T17:59:24.739Z',
                   'mitreid': 'S0206',
                   'modified': '2021-01-06T19:32:28.378Z',
                   'operatingsystemrefs': ['Windows'],
                   'publications': [
                       {'link': 'https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99',
                        'source': 'Symantec Wiarp May 2012',
                        'title': 'Zhou, R. (2012, May 15). Backdoor.Wiarp. '
                                 'Retrieved February 22, 2018.'}],
                   'stixid': 'malware--039814a0-88de-46c5-a4fb-b293db21880a',
                   'tags': ['S0206', 'malware']}
}

TOOL = {
    'response': {
        "name": "TOOL 1",
        "type": "tool",
        "description": "[PowerSploit](https://attack.mitre.org/software/S0194)",
        "external_references": [
            {
                "external_id": "S0194",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/software/S0194"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "PowerSploit"
        ],
        "modified": "2021-02-09T14:00:16.093Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "tool"
        ],
        "id": "tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d"
    },
    'map_result': {'aliases': ['PowerSploit'],
                   'description': '[PowerSploit](https://attack.mitre.org/software/S0194)',
                   'firstseenbysource': '2018-04-18T17:59:24.739Z',
                   'mitreid': 'S0194',
                   'modified': '2021-02-09T14:00:16.093Z',
                   'operatingsystemrefs': ['Windows'],
                   'publications': [],
                   'stixid': 'tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d',
                   'tags': ['S0194', 'tool']},
    "indicator": ([{'fields': {'aliases': ['PowerSploit'],
                               'description': '[PowerSploit](https://attack.mitre.org/software/S0194)',
                               'firstseenbysource': '2018-04-18T17:59:24.739Z',
                               'mitreid': 'S0194',
                               'modified': '2021-02-09T14:00:16.093Z',
                               'operatingsystemrefs': ['Windows'],
                               'publications': [],
                               'stixid': 'tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d',
                               'tags': ['S0194', 'tool']},
                    'rawJSON': {'created': '2018-04-18T17:59:24.739Z',
                                'description': '[PowerSploit](https://attack.mitre.org/software/S0194)',
                                'external_references': [{'external_id': 'S0194',
                                                         'source_name': 'mitre-attack',
                                                         'url': 'https://attack.mitre.org/software/S0194'}],
                                'id': 'tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d',
                                'labels': ['tool'],
                                'modified': '2021-02-09T14:00:16.093Z',
                                'name': 'TOOL 1',
                                'type': 'tool',
                                'x_mitre_aliases': ['PowerSploit'],
                                'x_mitre_platforms': ['Windows']},
                    'score': 2,
                    'type': 'Tool',
                    'value': 'TOOL 1'}],
                  [],
                  {'tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d': 'TOOL 1'}, {})
}

STIX_TOOL = {
    'response': {
        "name": "TOOL 1",
        "type": "tool",
        "description": "[PowerSploit](https://attack.mitre.org/software/S0194)",
        "external_references": [
            {
                "external_id": "S0194",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/software/S0194"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "PowerSploit"
        ],
        "modified": "2021-02-09T14:00:16.093Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "tool"
        ],
        "id": "tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d"
    },
    'map_result': {'stixaliases': ['PowerSploit'],
                   'stixdescription': '[PowerSploit](https://attack.mitre.org/software/S0194)',
                   'firstseenbysource': '2018-04-18T17:59:24.739Z',
                   'mitreid': 'S0194',
                   'modified': '2021-02-09T14:00:16.093Z',
                   'operatingsystemrefs': ['Windows'],
                   'publications': [],
                   'stixid': 'tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d',
                   'tags': ['S0194', 'tool']},
}

ID_TO_NAME = {
    "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0": "entity b",
    "malware--6a21e3a4-5ffe-4581-af9a-6a54c7536f44": "entity a"
}

RELATION = {
    'response': {
        "type": "relationship",
        "description": " [Explosive](https://attack.mitre.org/software/S0569)",
        "source_ref": "malware--6a21e3a4-5ffe-4581-af9a-6a54c7536f44",
        "created": "2021-04-27T01:56:35.810Z",
        "relationship_type": "uses",
        "modified": "2021-04-27T01:56:35.810Z",
        "target_ref": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
    },
    "indicator": [{'entityA': 'entity a',
                   'entityAFamily': 'Indicator',
                   'entityAType': 'Malware',
                   'entityB': 'entity b',
                   'entityBFamily': 'Indicator',
                   'entityBType': 'Attack Pattern',
                   'fields': {'description': ' '
                                             '[Explosive](https://attack.mitre.org/software/S0569)',
                              'firstseenbysource': '2021-04-27T01:56:35.810Z',
                              'lastseenbysource': '2021-04-27T01:56:35.810Z'},
                   'name': 'uses',
                   'reverseName': 'used-by',
                   'type': 'IndicatorToIndicator'}]
}

MALWARE_LIST_WITHOUT_PREFIX = [
    {"type": "Intrusion Set", "value": "RTM", 'fields': {"stixid": "1111"}},
    {"type": "Intrusion Set", "value": "Machete", 'fields': {"stixid": "2222"}},
    {"type": "Intrusion Set", "value": "APT1", 'fields': {"stixid": "3333"}},
    {"type": "Intrusion Set", "value": "ATP12", 'fields': {"stixid": "4444"}},
    {"type": "Malware", "value": "RTM", 'fields': {"stixid": "5555"}},
    {"type": "Malware", "value": "Machete", 'fields': {"stixid": "6666"}},
    {"type": "Malware", "value": "ABK", 'fields': {"stixid": "7777"}},
    {"type": "Malware", "value": "Adups", 'fields': {"stixid": "8888"}},
    {"type": "Malware", "value": "4H RAT", 'fields': {"stixid": "9999"}},
    {"type": "Attack Pattern", "value": "Access Token", 'fields': {"stixid": "0000"}},
    {"type": "Tool", "value": "at", 'fields': {"stixid": "1212"}},
    {"type": "Course of Action", "value": "Account Use Policies", 'fields': {"stixid": "2323"}}
]

MALWARE_LIST_WITH_PREFIX = [
    {"type": "Intrusion Set", "value": "RTM", 'fields': {"stixid": "1111"}},
    {"type": "Intrusion Set", "value": "Machete", 'fields': {"stixid": "2222"}},
    {"type": "Intrusion Set", "value": "APT1", 'fields': {"stixid": "3333"}},
    {"type": "Intrusion Set", "value": "ATP12", 'fields': {"stixid": "4444"}},
    {"type": "Malware", "value": "RTM [Malware]", 'fields': {"stixid": "5555"}},
    {"type": "Malware", "value": "Machete [Malware]", 'fields': {"stixid": "6666"}},
    {"type": "Malware", "value": "ABK", 'fields': {"stixid": "7777"}},
    {"type": "Malware", "value": "Adups", 'fields': {"stixid": "8888"}},
    {"type": "Malware", "value": "4H RAT", 'fields': {"stixid": "9999"}},
    {"type": "Attack Pattern", "value": "Access Token", 'fields': {"stixid": "0000"}},
    {"type": "Tool", "value": "at", 'fields': {"stixid": "1212"}},
    {"type": "Course of Action", "value": "Account Use Policies", 'fields': {"stixid": "2323"}}
]

INDICATORS_LIST = [
    {"type": "Intrusion Set", "value": "RTM", "fields": {"mitreid": "T1111.111", "stixid": "1"}},
    {"type": "Intrusion Set", "value": "Machete", "fields": {"mitreid": "T1111", "stixid": "2"}},
    {"type": "Intrusion Set", "value": "APT1", "fields": {"mitreid": "T1251", "stixid": "3"}},
    {"type": "Intrusion Set", "value": "ATP12", "fields": {"mitreid": "T1259", "stixid": "4"}},
    {"type": "Malware", "value": "RTM [Malware]", "fields": {"mitreid": "T1256", "stixid": "5"}},
    {"type": "Attack Pattern", "value": "Machete 1", "fields": {"mitreid": "T1254", "stixid": "6"}},
    {"type": "Attack Pattern", "value": "ABK", "fields": {"mitreid": "T1789", "stixid": "7"}},
    {"type": "Attack Pattern", "value": "Adups", "fields": {"mitreid": "T1254.001", "stixid": "8"}},
    {"type": "Attack Pattern", "value": "4H RAT", "fields": {"mitreid": "T1254.002", "stixid": "9"}},
    {"type": "Attack Pattern", "value": "Access Token", "fields": {"mitreid": "T1789.001", "stixid": "10"}},
    {"type": "Tool", "value": "at", "fields": {"mitreid": "T7854", "stixid": "11"}},
    {"type": "Course of Action", "value": "Account Use Policies", "fields": {"mitreid": "T1250", "stixid": "12"}}
]

NEW_INDICATORS_LIST = [
    {"type": "Intrusion Set", "value": "RTM", "fields": {"mitreid": "T1111.111", "stixid": "1"}},
    {"type": "Intrusion Set", "value": "Machete", "fields": {"mitreid": "T1111", "stixid": "2"}},
    {"type": "Intrusion Set", "value": "APT1", "fields": {"mitreid": "T1251", "stixid": "3"}},
    {"type": "Intrusion Set", "value": "ATP12", "fields": {"mitreid": "T1259", "stixid": "4"}},
    {"type": "Malware", "value": "RTM [Malware]", "fields": {"mitreid": "T1256", "stixid": "5"}},
    {"type": "Attack Pattern", "value": "Machete 1", "fields": {"mitreid": "T1254", "stixid": "6"}},
    {"type": "Attack Pattern", "value": "ABK", "fields": {"mitreid": "T1789", "stixid": "7"}},
    {"type": "Attack Pattern", "value": "Machete 1: Adups", "fields": {"mitreid": "T1254.001", "stixid": "8"}},
    {"type": "Attack Pattern", "value": "Machete 1: 4H RAT", "fields": {"mitreid": "T1254.002", "stixid": "9"}},
    {"type": "Attack Pattern", "value": "ABK: Access Token", "fields": {"mitreid": "T1789.001", "stixid": "10"}},
    {"type": "Tool", "value": "at", "fields": {"mitreid": "T7854", "stixid": "11"}},
    {"type": "Course of Action", "value": "Account Use Policies", "fields": {"mitreid": "T1250", "stixid": "12"}}
]

MITRE_ID_TO_MITRE_NAME = {
    "T1254": "Machete 1",
    "T1789": "ABK",
    "T1254.001": "Adups",
    "T1254.002": "4H RAT",
    "T1789.001": "Access Token"
}

OLD_ID_TO_NAME = {
    "1": "RTM",
    "2": "Machete",
    "3": "APT1",
    "4": "ATP12",
    "5": "RTM [Malware]",
    "6": "Machete 1",
    "7": "ABK",
    "8": "Machete 1: Adups",
    "9": "Machete 1: 4H RAT",
    "10": "ABK: Access Token",
    "11": "at",
    "12": "Account Use Policies",

}

NEW_ID_TO_NAME = {
    '1': 'RTM',
    '10': 'ABK: Access Token',
    '11': 'at',
    '12': 'Account Use Policies',
    '2': 'Machete',
    '3': 'APT1',
    '4': 'ATP12',
    '5': 'RTM [Malware]',
    '6': 'Machete 1',
    '7': 'ABK',
    '8': 'Machete 1: Adups',
    '9': 'Machete 1: 4H RAT'
}
