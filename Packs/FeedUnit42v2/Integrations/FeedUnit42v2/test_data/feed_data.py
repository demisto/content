INDICATORS_DATA = [
    {"created": "2019-07-30T09:29:07.724Z", "id": "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839",
     "pattern": "[file:hashes.'SHA-256' = 'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839']",
     "type": "indicator", "valid_from": "2019-07-30T09:29:07.724Z"},
    {"created": "2019-01-08T16:40:53.572Z", "id": "indicator--002e6e49-8099-42aa-a379-03c927c860a1",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e",
     "pattern": "[file:hashes.'SHA-256' = 'e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e']",
     "type": "indicator", "valid_from": "2019-01-08T16:40:53.572Z"},
    {"created": "2020-05-05T20:48:16.115Z", "id": "indicator--003b9bb9-947c-458f-94ef-407345018e1a",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z", "name": "1.1.1.1",
     "pattern": "[ipv4-addr:value = '1.1.1.1']", "type": "indicator",
     "valid_from": "2020-05-05T20:48:16.115Z"},
    {"created": "2018-08-03T20:30:58.705Z", "id": "indicator--004b4557-bc08-4373-b467-e8ff3aeafdf8",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "3b1da8ad68a5a545977946cad0f798923117ef6db6693f7297950961458356b3",
     "pattern": "[file:hashes.'SHA-256' = '3b1da8ad68a5a545977946cad0f798923117ef6db6693f7297950961458356b3']",
     "type": "indicator", "valid_from": "2018-08-03T20:30:58.705Z"},
    {"created": "2018-08-03T20:30:58.705Z", "id": "indicator--0079e6fc-f7cf-406a-ab75-aadbb786d1b1",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "nf321ap.linkgetapp.nl/x5/", "pattern": "[url:value = 'nf321ap.linkgetapp.nl/x5/']",
     "type": "indicator", "valid_from": "2018-08-03T20:30:58.705Z"},
    {"created": "2019-01-08T16:40:53.572Z", "id": "indicator--00ee4fd8-e48f-4658-822e-797b597e7c87",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z", "name": "2014.zzux.com",
     "pattern": "[domain-name:value = '2014.zzux.com']", "type": "indicator",
     "valid_from": "2019-01-08T16:40:53.572Z"},
    {"created": "2019-07-23T13:50:52.999Z", "id": "indicator--01008cc5-96e6-41af-a3c7-e4fa9262fbc0",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z", "name": "arubrabank.com",
     "pattern": "[domain-name:value = 'arubrabank.com']", "type": "indicator",
     "valid_from": "2019-07-23T13:50:52.999Z"},
    {"created": "2020-04-28T07:16:08.649Z", "id": "indicator--010bb9ad-5686-485d-97e5-93c2187e56ce",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "0f11fb955df07afc1912312f276c7fa3794ab85cd9f03b197c8bdbefb215fe92",
     "pattern": "[file:hashes.'SHA-256' = '0f11fb955df07afc1912312f276c7fa3794ab85cd9f03b197c8bdbefb215fe92']",
     "type": "indicator", "valid_from": "2020-04-28T07:16:08.649Z"},
    {"created": "2019-05-06T14:12:22.757Z", "id": "indicator--010c5a3e-823b-4267-8411-e38563fc805b",
     "labels": ["malicious-activity"], "modified": "2020-05-12T13:02:30.000000Z",
     "name": "cmstp.exe /s /ns C:\\Users\\ADMINI~W\\AppData\\Local\\Temp\\XKNqbpzl.txt",
     "pattern": "[process:command_line = 'cmstp.exe",
     "type": "indicator", "valid_from": "2019-05-06T14:12:22.757Z"}
]

ATTACK_PATTERN_DATA = [
    {"created": "2018-08-03T19:54:02.821Z", "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
     "description": "Windows Management",
     "external_references": [
         {
             "description": "Ballenthin",
             "source_name": "FireEye WMI 2015",
             "url": "example.com"
         },
         {
             "external_id": "T1047", "source_name": "mitre-attack",
             "url": "https://attack.mitre.org/techniques/T1047"
         },
         {
             "description": "Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.",
             "source_name": "MSDN WMI",
             "url": "https://msdn.microsoft.com/en-us/library/aa394582.aspx"
         },
         {
             "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
             "source_name": "TechNet RPC",
             "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx"
         },
         {
             "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
             "source_name": "Wikipedia SMB",
             "url": "https://en.wikipedia.org/wiki/Server_Message_Block"
         }
     ],
     "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
     "kill_chain_phases": [{"kill_chain_name": "lockheed", "phase_name": "installation"},
                           {"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "modified": "2020-05-12T13:02:30.000000Z", "name": "T1047: Windows Management Instrumentation",
     "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"], "type": "attack-pattern",
     "x_mitre_data_sources": ["Authentication logs", "Netflow/Enclave netflow", "Process command-line parameters",
                              "Process monitoring"], "x_mitre_detection": [
        "Monitor network traffic"],
     "x_mitre_permissions_required": ["Administrator", "User"], "x_mitre_platforms": ["Windows"],
     "x_mitre_remote_support": "true", "x_mitre_system_requirements": ["WMI service"],
     "x_mitre_version": "1.0"}
]

MALWARE_DATA = [
    {"created": "2019-10-11T16:13:15.086Z",
     "description": " Xbash is an all-in-one Linux malware formed botnet and ransomware developed by Iron cybercrime"
                    " group. Xbash was aiming to discover unprotected services, deleting the victim's MySQL, PostgreSQL"
                    " and MongoDB databases and demands a ransom in BitCoins.",
     "id": "malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9", "labels": ["ransomware"],
     "modified": "2020-05-12T13:02:30.000000Z", "name": "XBash", "type": "malware"},
    {"created": "2020-01-16T16:07:12.459Z",
     "description": "CARROTBALL is a simple FTP-based downloader first found embedded in a targeted macro document"
                    " associated with Konni activity as part of the Fractured Statue campaign. Its most common"
                    " observed payload is the Syscon backdoor. ",
     "id": "malware--f6b7cb46-766c-44df-9d4e-14a90d90957b", "labels": ["dropper"],
     "modified": "2020-05-12T13:02:30.000000Z", "name": "CARROTBALL", "type": "malware"},
    {"created": "2019-10-10T17:21:26.557Z",
     "description": " NanocoreRAT is a Trojan that opens a back door and steals information from the compromised"
                    " computer. It also allows a remote attacker to execute various commands on the infected system."
                    " It may achieve persistence on the targeted system by modifying the Registry.",
     "id": "malware--f8deccc7-5da9-4755-8c5a-7e4bea2547b0", "labels": ["remote-access-trojan"],
     "modified": "2020-05-12T13:02:30.000000Z", "name": "NanoCoreRAT", "type": "malware"},
    {"created": "2019-10-10T17:55:12.389Z", "id": "malware--00811855-d9b9-420d-9bd6-8fd63fbd335a",
     "labels": ["backdoor"], "modified": "2020-05-12T13:02:30.000000Z", "name": "Muirim", "type": "malware"},
    {"created": "2019-10-10T17:55:12.389Z", "id": "malware--00811855-d9b9-420d-9bd6-8fd63fbd335b",
     "labels": ["backdoor"], "modified": "2020-05-12T13:02:30.000000Z", "name": "Muirim2", "type": "malware"},
]

RELATIONSHIP_DATA = [
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a6",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "indicator--010bb9ad-5686-485d-97e5-93c2187e56ce",
     "target_ref": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055", "type": "relationship"},
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a8",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be",
     "target_ref": "malware--00811855-d9b9-420d-9bd6-8fd63fbd335a", "type": "relationship"}
]

RELATIONSHIP_OBJECTS = [{'entityA': 'http://91.218.114.31/yyxtqylcto',
                         'entityAFamily': 'Indicator',
                         'entityAType': 'URL',
                         'entityB': 'NTFS File Attributes',
                         'entityBFamily': 'Indicator',
                         'entityBType': 'Attack Pattern',
                         'fields': {'firstseenbysource': '2019-10-11T18:43:46.039Z',
                                    'lastseenbysource': '2020-05-12T13:02:30.000000Z'},
                         'name': 'indicated-by',
                         'reverseName': 'indicator-of',
                         'type': 'IndicatorToIndicator'},
                        {'entityA': '92.63.32.52',
                         'entityAFamily': 'Indicator',
                         'entityAType': 'IP',
                         'entityB': 'Maze',
                         'entityBFamily': 'Indicator',
                         'entityBType': 'Malware',
                         'fields': {'firstseenbysource': '2019-10-11T18:43:46.039Z',
                                    'lastseenbysource': '2020-05-12T13:02:30.000000Z'},
                         'name': 'indicated-by',
                         'reverseName': 'indicator-of',
                         'type': 'IndicatorToIndicator'}]

ID_TO_OBJ_RELATIONS = {
    "indicator--010bb9ad-5686-485d-97e5-93c2187e56ce": {
        "type": "indicator",
        "id": "indicator--01e860b3-67a6-4bf7-a885-c296c4fa5243",
        "name": "http://91.218.114.31/yyxtqylcto",
        "pattern": "[url:value = 'http://91.218.114.31/yyxtqylcto']",
    },
    "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055": {
        "type": "attack-pattern",
        "id": "attack-pattern--f2857333-11d4-45bf-b064-2c28d8525be5",
        "name": "T1564.004: NTFS File Attributes",
    },
    "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be": {
        "type": "indicator",
        "id": "indicator--003b9bb9-947c-458f-94ef-407345018e1a",
        "name": "92.63.32.52",
        "pattern": "[ipv4-addr:value = '92.63.32.52']"
    },
    "malware--00811855-d9b9-420d-9bd6-8fd63fbd335a": {
        "type": "malware",
        "id": "malware--53e619f7-936e-4f40-b518-9d3000102d44",
        "name": "Maze",
    }

}

REPORTS_DATA = [
    {"type": "report", "id": "report--a", "created": "1993-06-17T11:00:00.000Z", "modified": "1993-06-17T11:00:00.000Z",
     "name": "Main Report", "description": "A description of the report", "published": "1994-08-12T11:00:00.000Z",
     "object_refs": ["intrusion-set--a", "report--ab"], "labels": ["intrusion-set"]},
    {
        "type": "report", "id": "report--ab", "created": "1993-06-17T11:00:00.000Z",
        "modified": "1993-06-17T11:00:00.000Z", "name": "Sub Report", "description": "A description of the report",
        "published": "1994-08-12T11:00:00.000Z",
        "object_refs": ["attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
                        "campaign--95c0884b-71e7-40fd-9307-626634425a93",
                        "course-of-action--fd0da09e-a0b2-4018-9476-1a7edd809b59",
                        "identity--c6f27733-7387-4685-946e-3159d72ba15f",
                        "indicator--13a5365a-894f-47a3-9ce4-6cf85718419f",
                        "indicator--f2eb1d6c-df89-49e2-97f8-5c58706e9519",
                        "intrusion-set--98e7093d-a86a-44b5-b7b3-d89ca457ec78",
                        "malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9",
                        "relationship--ff0a724d-2a3d-4ac1-9c7f-6340bded0d6f"],
        "labels": ["campaign"]
    }
]

CAMPAIGN_RESPONSE = [{
    "type": "campaign",
    "id": "campaign--f69de074-6abd-45a1-909f-51ef8fce808a",
    "created": "2020-04-24T13:40:41.386Z",
    "modified": "2020-08-03T14:55:56.362Z",
    "name": "Campaign 1 - [Endor] Maze Ransomware",
    "description": "Since the beginning of the calendar year",
    "first_seen": "2020-04-01T00:00:00.000Z",
    "last_seen": "2020-04-28T15:48:29.713Z"
}]

CAMPAIGN_INDICATOR = [{'fields': {'description': 'Since the beginning of the calendar year',
                                  'firstseenbysource': '2020-04-24T13:40:41.386Z',
                                  'modified': '2020-08-03T14:55:56.362Z',
                                  'reportedby': 'Unit42',
                                  'stixid': 'campaign--f69de074-6abd-45a1-909f-51ef8fce808a',
                                  'tags': []},
                       'rawJSON': {'created': '2020-04-24T13:40:41.386Z',
                                   'description': 'Since the beginning of the calendar year',
                                   'first_seen': '2020-04-01T00:00:00.000Z',
                                   'id': 'campaign--f69de074-6abd-45a1-909f-51ef8fce808a',
                                   'last_seen': '2020-04-28T15:48:29.713Z',
                                   'modified': '2020-08-03T14:55:56.362Z',
                                   'name': 'Campaign 1 - [Endor] Maze Ransomware',
                                   'type': 'campaign'},
                       'score': 3,
                       'type': 'Campaign',
                       'value': 'Campaign 1 - [Endor] Maze Ransomware'}]

REPORTS_INDICATORS = [{'fields': {'description': 'A description of the report',
                                  'firstseenbysource': '1993-06-17T11:00:00.000Z',
                                  'published': '1994-08-12T11:00:00.000Z',
                                  'reportedby': 'Unit42',
                                  'stixid': 'report--a',
                                  'tags': ['intrusion-set']},
                       'rawJSON': {'unit42_created_date': '1993-06-17T11:00:00.000Z',
                                   'unit42_description': 'A description of the report',
                                   'unit42_id': 'report--a',
                                   'unit42_labels': ['intrusion-set'],
                                   'unit42_modified_date': '1993-06-17T11:00:00.000Z',
                                   'unit42_object_refs': ['intrusion-set--a', 'report--ab'],
                                   'unit42_published': '1994-08-12T11:00:00.000Z'},
                       'relationships': [],
                       'score': 3,
                       'type': 'Report',
                       'value': '[Unit42 ATOM] Main Report'}]

INDICATORS_RESULT = {'fields': {'firstseenbysource': '2019-07-30T09:29:07.724Z',
                                'indicatoridentification': 'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be',
                                'modified': '2020-05-12T13:02:30.000000Z',
                                'reportedby': 'Unit42',
                                'tags': ['malicious-activity']},
                     'rawJSON': {'created': '2019-07-30T09:29:07.724Z',
                                 'id': 'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be',
                                 'labels': ['malicious-activity'],
                                 'modified': '2020-05-12T13:02:30.000000Z',
                                 'name': 'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839',
                                 'pattern': "[file:hashes.'SHA-256' = "
                                            "'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839']",
                                 'type': 'indicator',
                                 'valid_from': '2019-07-30T09:29:07.724Z'},
                     'type': 'File',
                     'value': 'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839'}

ID_TO_OBJECT = {
    'indicator--01a5a209-b94c-450b-b7f9-946497d91055': {
        'external_references': '8.8.8.8',
        'description': 'description',
        'name': 'T111: Software Discovery',
        'pattern': "[ipv4-addr:value = '92.63.32.52']"},
    'indicator--fd0da09e-a0b2-4018-9476-1a7edd809b59': {
        'name': 'Deploy XSOAR Playbook',
        'x_panw_coa_bp_description': 'Deploy XSOAR Playbook - Phishing Investigation - Generic V2',
        'x_panw_coa_bp_title': 'Deploy XSOAR Playbook',
        'pattern': "[url:value = 'http://91.218.114.31/yyxtqylcto']"},
    'report--0f86dccd-29bd-46c6-83fd-e79ba040bf0': {
        "type": "report",
        "name": "Maze Ransomware"
    },
    "indicator--010bb9ad-5686-485d-97e5-93c2187e56ce": {
        "type": "indicator",
        "id": "indicator--01e860b3-67a6-4bf7-a885-c296c4fa5243",
        "name": "http://91.218.114.31/yyxtqylcto",
        "pattern": "[url:value = 'http://91.218.114.31/yyxtqylcto']",
    },
    "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055": {
        "type": "attack-pattern",
        "id": "attack-pattern--f2857333-11d4-45bf-b064-2c28d8525be5",
        "name": "T1564.004: NTFS File Attributes",
    },
    "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be": {
        "type": "indicator",
        "id": "indicator--003b9bb9-947c-458f-94ef-407345018e1a",
        "name": "92.63.32.52",
        "pattern": "[ipv4-addr:value = '92.63.32.52']"
    },
    "malware--00811855-d9b9-420d-9bd6-8fd63fbd335a": {
        "type": "malware",
        "id": "malware--53e619f7-936e-4f40-b518-9d3000102d44",
        "name": "Maze",
    }
}

PUBLICATIONS = [{'link': 'example.com', 'source': 'FireEye WMI 2015', 'title': 'Ballenthin'},
                {'link': 'https://msdn.microsoft.com/en-us/library/aa394582.aspx',
                 'source': 'MSDN WMI',
                 'title': 'Microsoft. (n.d.). Windows Management Instrumentation. Retrieved '
                          'April 27, 2016.'},
                {'link': 'https://technet.microsoft.com/en-us/library/cc787851.aspx',
                 'source': 'TechNet RPC',
                 'title': 'Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, '
                          '2016.'},
                {'link': 'https://en.wikipedia.org/wiki/Server_Message_Block',
                 'source': 'Wikipedia SMB',
                 'title': 'Wikipedia. (2016, June 12). Server Message Block. Retrieved June '
                          '12, 2016.'}]

ATTACK_PATTERN_INDICATOR = [{'fields': {'description': 'Windows Management',
                                        'firstseenbysource': '2018-08-03T19:54:02.821Z',
                                        'killchainphases': ['Installation', 'Execution'],
                                        'mitreid': 'T1047',
                                        'modified': '2020-05-12T13:02:30.000Z',
                                        'operatingsystemrefs': ['Windows'],
                                        'publications': [{'link': 'example.com',
                                                          'source': 'FireEye WMI 2015',
                                                          'title': 'Ballenthin'},
                                                         {
                                                             'link': 'https://msdn.microsoft.com/en-us/library/aa394582.aspx',
                                                             'source': 'MSDN WMI',
                                                             'title': 'Microsoft. (n.d.). Windows Management '
                                                                      'Instrumentation. Retrieved April 27, '
                                                                      '2016.'},
                                                         {
                                                             'link': 'https://technet.microsoft.com/en-us/library/cc787851.aspx',
                                                             'source': 'TechNet RPC',
                                                             'title': 'Microsoft. (2003, March 28). What Is '
                                                                      'RPC?. Retrieved June 12, 2016.'},
                                                         {'link': 'https://en.wikipedia.org/wiki/Server_Message_Block',
                                                          'source': 'Wikipedia SMB',
                                                          'title': 'Wikipedia. (2016, June 12). Server '
                                                                   'Message Block. Retrieved June 12, '
                                                                   '2016.'}],
                                        'reportedby': 'Unit42',
                                        'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
                                        'tags': ['T1047']},
                             'type': 'Attack Pattern',
                             "score": 2,
                             'value': 'Windows Management Instrumentation'}]

STIX_ATTACK_PATTERN_INDICATOR = [{'fields': {'stixdescription': 'Windows Management',
                                             'firstseenbysource': '2018-08-03T19:54:02.821Z',
                                             'stixkillchainphases': ['Installation', 'Execution'],
                                             'mitreid': 'T1047',
                                             'modified': '2020-05-12T13:02:30.000Z',
                                             'operatingsystemrefs': ['Windows'],
                                             'publications': [{'link': 'example.com',
                                                               'source': 'FireEye WMI 2015',
                                                               'title': 'Ballenthin'},
                                                              {
                                                                  'link': 'https://msdn.microsoft.com/en-us/library/aa394582.aspx',
                                                                  'source': 'MSDN WMI',
                                                                  'title': 'Microsoft. (n.d.). Windows Management '
                                                                           'Instrumentation. Retrieved April 27, '
                                                                           '2016.'},
                                                              {
                                                                  'link': 'https://technet.microsoft.com/en-us/library/cc787851.aspx',
                                                                  'source': 'TechNet RPC',
                                                                  'title': 'Microsoft. (2003, March 28). What Is '
                                                                           'RPC?. Retrieved June 12, 2016.'},
                                                              {
                                                                  'link': 'https://en.wikipedia.org/wiki/Server_Message_Block',
                                                                  'source': 'Wikipedia SMB',
                                                                  'title': 'Wikipedia. (2016, June 12). Server '
                                                                           'Message Block. Retrieved June 12, '
                                                                           '2016.'}],
                                             'reportedby': 'Unit42',
                                             'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
                                             'tags': ['T1047']},
                                  'type': 'STIX Attack Pattern',
                                  "score": 2,
                                  'value': 'Windows Management Instrumentation'}]

COURSE_OF_ACTION_DATA = [{
    "type": "course-of-action",
    "id": "course-of-action--00d97976-e97e-4878-b530-9f37d7a3e2e5",
    "name": "Deploy XSOAR Playbook - Phishing Investigation - Generic V2",
    "created": "2020-06-23T19:50:31.722Z",
    "modified": "2020-09-04T13:59:35.883Z"
},
    {
        "type": "course-of-action",
        "id": "course-of-action--02d40837-4b7a-4bd1-a3c6-1cb4695e02e2",
        "name": "Ensure that all zones have Zone Protection Profiles with all Reconnaissance Protection settings enabled.",
        "created": "2020-06-23T19:50:31.722Z",
        "modified": "2020-06-26T19:00:21.151Z",
        "description": "Enable all three scan options in a Zone Protection profile.",
        "x_panw_coa_bp_section_number": "6",
        "x_panw_coa_bp_recommendation_number": "6.18",
        "x_panw_coa_bp_title": "Ensure that all zones have Zone Protection Profiles.",
        "x_panw_coa_bp_status": "published",
        "x_panw_coa_bp_scoring_status": "full",
        "x_panw_coa_bp_description": "Enable all three scan options in a Zone Protection profile.",
        "x_panw_coa_bp_rationale_statement": "Port scans and host sweeps are common in the reconnaissance phase.",
        "x_panw_coa_bp_remediation_procedure": "Navigate to `Network > Network Profiles > Zone Protection.",
        "x_panw_coa_bp_audit_procedure": "Navigate to `Network > Network Profiles > Zone Protection.",
        "x_panw_coa_bp_impact_statement": "Not configuring a Network Zone Protection Profile leaves an organization.",
        "x_panw_coa_bp_cis_controls": [
            "TITLE:Boundary Defense CONTROL:v7 12 DESCRIPTION:Boundary."
        ],
        "x_panw_coa_bp_references": [
            "network-network-profiles-zone-protection/reconnaissance-protection."
        ]
    }]

COURSE_OF_ACTION_INDICATORS = [{'fields': {'description': '',
                                           'firstseenbysource': '2020-06-23T19:50:31.722Z',
                                           'modified': '2020-09-04T13:59:35.883Z',
                                           'publications': [],
                                           'reportedby': 'Unit42',
                                           'stixid': 'course-of-action--00d97976-e97e-4878-b530-9f37d7a3e2e5',
                                           'tags': []},
                                'score': 0,
                                'type': 'Course of Action',
                                'value': 'Deploy XSOAR Playbook - Phishing Investigation - Generic V2'},
                               {'fields': {'description': 'Enable all three scan options in a Zone '
                                                          'Protection profile.',
                                           'firstseenbysource': '2020-06-23T19:50:31.722Z',
                                           'modified': '2020-06-26T19:00:21.151Z',
                                           'publications': [],
                                           'reportedby': 'Unit42',
                                           'stixid': 'course-of-action--02d40837-4b7a-4bd1-a3c6-1cb4695e02e2',
                                           'tags': []},
                                'score': 0,
                                'type': 'Course of Action',
                                'value': 'Ensure that all zones have Zone Protection Profiles with all '
                                         'Reconnaissance Protection settings enabled.'}]

DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST = {
    'relationships': [{'entityA': '0f11fb955df07afc1912312f276c7fa3794ab85cd9f03b197c8bdbefb215fe92',
                       'entityAFamily': 'Indicator',
                       'entityAType': 'File',
                       'entityB': 'Windows Management Instrumentation',
                       'entityBFamily': 'Indicator',
                       'entityBType': 'Attack Pattern',
                       'fields': {'firstseenbysource': '2019-10-11T18:43:46.039Z',
                                  'lastseenbysource': '2020-05-12T13:02:30.000000Z'},
                       'name': 'indicated-by',
                       'reverseName': 'indicator-of',
                       'type': 'IndicatorToIndicator'},
                      {'entityA': 'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839',
                       'entityAFamily': 'Indicator',
                       'entityAType': 'File',
                       'entityB': 'Muirim',
                       'entityBFamily': 'Indicator',
                       'entityBType': 'Malware',
                       'fields': {'firstseenbysource': '2019-10-11T18:43:46.039Z',
                                  'lastseenbysource': '2020-05-12T13:02:30.000000Z'},
                       'name': 'indicated-by',
                       'reverseName': 'indicator-of',
                       'type': 'IndicatorToIndicator'}],
    'value': '$$DummyIndicator$$'}

INTRUSION_SET_DATA = [
    {"type": "intrusion-set",
     "id": "intrusion-set--4e3fe19c-cb72-499a-a357-eb44b5717a3a",
     "created": "2020-04-24T13:40:41.386Z",
     "modified": "2020-04-28T14:13:45.924Z",
     "name": "[Endor] Maze Ransomware"}
]
