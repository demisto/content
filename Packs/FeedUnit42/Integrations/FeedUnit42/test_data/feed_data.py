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
    {"created": "2019-05-21T18:21:23.550Z", "id": "intrusion-set--eeef6603-d891-476a-a600-0096b6fe072f",
     "modified": "2020-05-12T13:02:30.000000Z", "name": "Emissary Panda", "type": "intrusion-set"},
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a8",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be",
     "target_ref": "malware--00811855-d9b9-420d-9bd6-8fd63fbd335a", "type": "relationship"},
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a8",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be",
     "target_ref": "malware--00811855-d9b9-420d-9bd6-8fd63fbd335b", "type": "relationship"},
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a8",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9",
     "target_ref": "indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be", "type": "relationship"},
    {"created": "2019-10-11T18:43:46.039Z", "id": "relationship--001323c2-fc4f-4d4a-914c-2d556fc585a7",
     "modified": "2020-05-12T13:02:30.000000Z", "relationship_type": "indicates",
     "source_ref": "malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9",
     "target_ref": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055", "type": "relationship"}
]

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

REPORTS_INDICATORS = [
    [{'fields': {'published': '1994-08-12T11:00:00.000Z',
                 'reportedby': 'Unit42',
                 'stixdescription': 'A description of the report',
                 'stixid': 'report--a',
                 'tags': ['intrusion-set']},
      'rawJSON': {
          'unit42_created_date': '1993-06-17T11:00:00.000Z',
          'unit42_description': 'A description of the report',
          'unit42_id': 'report--a',
          'unit42_labels': ['intrusion-set'],
          'unit42_modified_date': '1993-06-17T11:00:00.000Z',
          'unit42_object_refs': ['intrusion-set--a', 'report--ab'],
          'unit42_published': '1994-08-12T11:00:00.000Z'},
      'type': 'STIX Report',
      'value': 'Main Report'}]
    ,
    [{'fields': {'published': '1994-08-12T11:00:00.000Z',
                 'reportedby': 'Unit42',
                 'stixdescription': 'A description of the report',
                 'stixid': 'report--a',
                 'tags': ['intrusion-set'],
                 'trafficlightprotocol': 'AMBER'},
      'rawJSON': {'unit42_created_date': '1993-06-17T11:00:00.000Z',
                  'unit42_description': 'A description of the report',
                  'unit42_id': 'report--a',
                  'unit42_labels': ['intrusion-set'],
                  'unit42_modified_date': '1993-06-17T11:00:00.000Z',
                  'unit42_object_refs': ['intrusion-set--a', 'report--ab'],
                  'unit42_published': '1994-08-12T11:00:00.000Z'},
      'type': 'STIX Report',
      'value': 'Main Report'}]
]

MATCHED_RELATIONSHIPS = {
    'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055': {
        'indicator--010bb9ad-5686-485d-97e5-93c2187e56ce',
        'malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9'},
    'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be': {
        'malware--00811855-d9b9-420d-9bd6-8fd63fbd335a',
        'malware--00811855-d9b9-420d-9bd6-8fd63fbd335b',
        'malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9'},
    'indicator--010bb9ad-5686-485d-97e5-93c2187e56ce': {
        'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055'},
    'malware--00811855-d9b9-420d-9bd6-8fd63fbd335a': {
        'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be'},
    'malware--00811855-d9b9-420d-9bd6-8fd63fbd335b': {
        'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be'},
    'malware--f351db0d-0667-4ca0-aed8-205bcef1d9a9': {
        'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
        'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be'}
}
