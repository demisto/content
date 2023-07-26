from CommonServerPython import IncidentStatus, EntryType

response_incident = {"incident_id": "inc:afb5d1512a00480f53e9ad91dc3e4b55:1cf23a95678a421db810e11b5db693bd",
                     "cid": "24ab288b109b411aba970e570d1ddf58",
                     "host_ids": [
                                    "afb5d1512a00480f53e9ad91dc3e4b55"
                     ],
                     "hosts": [
                         {"device_id": "afb5d1512a00480f53e9ad91dc3e4b55",
                          "cid": "24ab288b109b411aba970e570d1ddf58",
                          "agent_load_flags": "0",
                          "agent_local_time": "2020-05-06T23:36:34.594Z",
                          "agent_version": "5.28.10902.0",
                          "bios_manufacturer": "Apple Inc.",
                          "bios_version": "1037.100.359.0.0 (iBridge: 17.16.14263.0.0,0)",
                          "config_id_base": "65994753",
                          "config_id_build": "10902",
                          "config_id_platform": "4",
                          "external_ip": "1.1.1.1",
                          "hostname": "SFO-M-Y81WHJ",
                          "first_seen": "2019-05-10T17:20:39Z",
                          "last_seen": "2020-05-17T16:59:42Z",
                          "local_ip": "1.1.1.1",
                          "mac_address": "86-89-ad-65-d0-30",
                          "major_version": "18",
                          "minor_version": "7",
                          "os_version": "Mojave (10.14)",
                          "platform_id": "1",
                          "platform_name": "Mac",
                          "product_type_desc": "Workstation",
                          "status": "normal",
                          "system_manufacturer": "Apple Inc.",
                          "system_product_name": "MacBookPro15,1",
                          "modified_timestamp": "2020-05-17T16:59:56Z"}
                     ],
                     "created": "2020-05-17T17:30:38Z",
                     "start": "2020-05-17T17:30:38Z",
                     "end": "2020-05-17T17:30:38Z",
                     "state": "closed",
                     "status": 20,
                     "name": "Incident on SFO-M-Y81WHJ at 2020-05-17T17:30:38Z",
                     "description": "Objectives in this incident: Keep Access. Techniques: External Remote Services. "
                     "Involved hosts and end users: SFO-M-Y81WHJ.",
                     "tags": [
                                    "Objective/Keep Access"
                     ],
                     "fine_score": 38}

response_detection = {"cid": "20879a8064904ecfbb62c118a6a19411",
                      "created_timestamp": "2021-12-19T13:53:34.708949512Z",
                      "detection_id": "ldt:15dbb9d8f06b89fe9f61eb46e829d986:528715079668",
                      "device": {
                          "device_id": "15dbb9d7f06b45fe0f61eb46e829d986",
                          "cid": "20897a8064904ecfbb62c118a3a19411",
                          "agent_load_flags": "0",
                          "agent_local_time": "2021-12-03T22:06:35.590Z",
                          "agent_version": "6.30.14406.0",
                          "bios_manufacturer": "Google",
                          "bios_version": "Google",
                          "config_id_base": "65994853",
                          "config_id_build": "14706",
                          "config_id_platform": "3",
                          "external_ip": "35.224.136.145",
                          "hostname": "FALCON-CROWDSTR",
                          "first_seen": "2020-02-10T12:40:18Z",
                          "last_seen": "2021-12-19T13:35:53Z",
                          "local_ip": "10.128.0.7",
                          "mac_address": "42-03-0a-80-92-07",
                          "major_version": "10",
                          "minor_version": "0",
                          "os_version": "Windows Server 2019",
                          "platform_id": "0",
                          "platform_name": "Windows",
                          "product_type": "3",
                          "product_type_desc": "Server",
                          "status": "normal",
                          "system_manufacturer": "Google",
                          "system_product_name": "Google Compute Engine",
                          "modified_timestamp": "2021-12-19T13:51:07Z",
                          "instance_id": "5278723726495898635",
                          "service_provider": "GCP",
                          "service_provider_account_id": "578609343865"
                      },
                      "behaviors": [
                          {
                              "device_id": "15dbb9d8f06b45fe9f61eb46e829d986",
                              "timestamp": "2021-12-19T13:53:27Z",
                              "template_instance_id": "382",
                              "behavior_id": "10197",
                              "filename": "choice.exe",
                              "filepath": "\\Device\\HarddiskVolume1\\Windows\\System32\\choice.exe",
                              "alleged_filetype": "exe",
                              "cmdline": "choice  /m crowdstrike_sample_detection",
                              "scenario": "suspicious_activity",
                              "objective": "Falcon Detection Method",
                              "tactic": "Malware",
                              "tactic_id": "CSTA0001",
                              "technique": "Malicious File",
                              "technique_id": "CST0001",
                              "display_name": "SampleTemplateDetection",
                              "description": "For evaluation only - benign, no action needed.",
                              "severity": 30,
                              "confidence": 80,
                              "ioc_type": "",
                              "ioc_value": "",
                              "ioc_source": "",
                              "ioc_description": "",
                              "user_name": "admin",
                              "user_id": "S-1-5-21-3482992587-1103702653-2661900019-1000",
                              "control_graph_id": "ctg:15dbb9d8f06b45fe9f61eb46e829d986:528715219540",
                              "triggering_process_graph_id": "pid:15dbb9d8f06b45fe9f61eb46e829d986:1560553487562",
                              "sha256": "90f352c1fb7b21cc0216b2f0701a236db92b786e4301904d28f4ec4cb81f2a8b",
                              "md5": "463b5477ff96ab86a01ba44bcc02b539",
                              "pattern_disposition": 0,
                          }
                      ],
                      "email_sent": False,
                      "first_behavior": "2021-12-19T13:53:27Z",
                      "last_behavior": "2021-12-19T13:53:27Z",
                      "max_confidence": 80,
                      "max_severity": 30,
                      "max_severity_displayname": "Low",
                      "show_in_ui": True,
                      "status": "new",
                      "hostinfo": {
                          "domain": ""
                      },
                      "seconds_to_triaged": 0,
                      "seconds_to_resolved": 0,
                      "behaviors_processed": [
                          "pid:15dbb9d8f06b45fe9f61eb46e829d986:1560553487562:10194"
                      ],
                      "date_updated": "2021-12-19T13:53:34.708949512Z"}

response_idp_detection = {
    "added_privileges": [
        "AdministratorsRole"
    ],
    "aggregate_id": "aggind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56",
    "cid": "20879a8064904ecfbb62c118a6a19411",
    "comment": "new test comment new test comment2 new test comment2 new test comment2 new test comment2 new test comment new test comment new test comment new test comment new test comment2 new test comment2 new test comment new test comment2 new test comment2 comment",
    "composite_id": "20879a8064904ecfbb62c118a6a19411:ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56",
    "confidence": 20,
    "context_timestamp": "2023-04-20T11:12:03.089Z",
    "crawl_edge_ids": {
        "Sensor": [
                    "XNWu1KJ3f7ck@.W>%?R;<dP:4XWOiGq9#dnSpb\"l0^f#1Kl9'<k^`t9\"ptE?07V_G^*'_EU'/Ch6&[Xsfl<UI$RnhG;AQa[gb#+-\\+J1O?GF\\U^<^9bluf^^X`dYoqOIQpM,@C%pV[2A%9a\"T6O4b1:B1@ps8N",
                    "N6GX$`'=_9i\"H:bRq0rXhf`Vd$[@1Wr?Lr'`EGQh3P42Up,g(aNSe7C38V)J@NV=)Rg/2m^+P>?(%>fETtmdN.<_m*o''\"CCUmBn.;18rN6.!:g%ohR0te,H;Z\\DK\"=MJe1?:_Y=XZj>E=nHY5ge>3^9:'(g:)A'RG0W,kPj.CNpo<Vk/RE^G9E!b'?=G[!!*'!",
                    "XNXPaKHLg+i\"HEWkr@-r>$W@\"o+ta@8q'lE4T!!e@D;nls7!2S0cEcXKeuua2Q+<<8!<pD:k1.5(j-*D`ECSL7qH1t'ZZKh'%UJG'SaS8QVr:\"4jTCn[!Z]eCQhZa>bpJ`SjuN'Y.FcK0JOE\"K_hb8DEP5rc6I]<!!*'!"
        ]
    },
    "crawl_vertex_ids": {
        "Sensor": [
            "idpind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56",
            "uid:20879a8064904ecfbb62c118a6a19411:S-1-5-21-4043902054-3757442694-3243833439-1141",
            "ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56",
            "aggind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56"
        ]
    },
    "crawled_timestamp": "2023-04-20T12:12:10.427005199Z",
    "created_timestamp": "2023-04-20T11:13:10.424647194Z",
    "description": "A user received new privileges",
    "display_name": "Privilege escalation (user)",
    "end_time": "2023-04-20T11:12:03.089Z",
    "falcon_host_link": "https://falcon.crowdstrike.com/identity-protection/detections/20879a8064904ecfbb62c118a6a19411:ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56?cid=20879a8064904ecfbb62c118a6a19411",
    "id": "ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56",
    "name": "IdpEntityPrivilegeEscalationUser",
            "objective": "Gain Access",
            "pattern_id": 51113,
            "platform": "Windows",
            "previous_privileges": "0",
            "privileges": "2177",
            "product": "idp",
            "scenario": "privilege_escalation",
            "seconds_to_resolved": 5869002,
            "seconds_to_triaged": 2250786,
            "severity": 2,
            "show_in_ui": True,
            "source_account_domain": "ENV11.FERRUM-TECHS.LOCAL",
            "source_account_name": "morganf",
            "source_account_object_sid": "S-1-5-21-4043902054-3757442694-3243833439-1141",
            "source_account_sam_account_name": "morganf",
            "source_account_upn": "test@test.com",
            "start_time": "2023-04-20T11:12:03.089Z",
            "status": "closed",
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "tags": [],
            "technique": "Valid Accounts",
            "technique_id": "T1078",
            "timestamp": "2023-04-20T11:12:05.686Z",
            "type": "idp-user-endpoint-app-info",
            "updated_timestamp": "2023-06-27T09:29:52.448779709Z"
}

context_idp_detection = {'name': 'IDP Detection ID: 20879a8064904ecfbb62c118a6a19411:ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56',
                         'occurred': '2023-04-20T11:12:03.089Z', 'last_updated': '2023-06-27T09:29:52.448779709Z', 'rawJSON': '{"added_privileges": ["AdministratorsRole"], "aggregate_id": "aggind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56", "cid": "20879a8064904ecfbb62c118a6a19411", "comment": "new test comment new test comment2 new test comment2 new test comment2 new test comment2 new test comment new test comment new test comment new test comment new test comment2 new test comment2 new test comment new test comment2 new test comment2 comment", "composite_id": "20879a8064904ecfbb62c118a6a19411:ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56", "confidence": 20, "context_timestamp": "2023-04-20T11:12:03.089Z", "crawl_edge_ids": {"Sensor": ["XNWu1KJ3f7ck@.W>%?R;<dP:4XWOiGq9#dnSpb\\"l0^f#1Kl9\'<k^`t9\\"ptE?07V_G^*\'_EU\'/Ch6&[Xsfl<UI$RnhG;AQa[gb#+-\\\\+J1O?GF\\\\U^<^9bluf^^X`dYoqOIQpM,@C%pV[2A%9a\\"T6O4b1:B1@ps8N", "N6GX$`\'=_9i\\"H:bRq0rXhf`Vd$[@1Wr?Lr\'`EGQh3P42Up,g(aNSe7C38V)J@NV=)Rg/2m^+P>?(%>fETtmdN.<_m*o\'\'\\"CCUmBn.;18rN6.!:g%ohR0te,H;Z\\\\DK\\"=MJe1?:_Y=XZj>E=nHY5ge>3^9:\'(g:)A\'RG0W,kPj.CNpo<Vk/RE^G9E!b\'?=G[!!*\'!", "XNXPaKHLg+i\\"HEWkr@-r>$W@\\"o+ta@8q\'lE4T!!e@D;nls7!2S0cEcXKeuua2Q+<<8!<pD:k1.5(j-*D`ECSL7qH1t\'ZZKh\'%UJG\'SaS8QVr:\\"4jTCn[!Z]eCQhZa>bpJ`SjuN\'Y.FcK0JOE\\"K_hb8DEP5rc6I]<!!*\'!"]}, "crawl_vertex_ids": {"Sensor": ["idpind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56", "uid:20879a8064904ecfbb62c118a6a19411:S-1-5-21-4043902054-3757442694-3243833439-1141", "ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56", "aggind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56"]}, "crawled_timestamp": "2023-04-20T12:12:10.427005199Z", "created_timestamp": "2023-04-20T11:13:10.424647194Z", "description": "A user received new privileges", "display_name": "Privilege escalation (user)", "end_time": "2023-04-20T11:12:03.089Z", "falcon_host_link": "https://falcon.crowdstrike.com/identity-protection/detections/20879a8064904ecfbb62c118a6a19411:ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56?cid=20879a8064904ecfbb62c118a6a19411", "id": "ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56", "name": "IdpEntityPrivilegeEscalationUser", "objective": "Gain Access", "pattern_id": 51113, "platform": "Windows", "previous_privileges": "0", "privileges": "2177", "product": "idp", "scenario": "privilege_escalation", "seconds_to_resolved": 5869002, "seconds_to_triaged": 2250786, "severity": 2, "show_in_ui": true, "source_account_domain": "ENV11.FERRUM-TECHS.LOCAL", "source_account_name": "morganf", "source_account_object_sid": "S-1-5-21-4043902054-3757442694-3243833439-1141", "source_account_sam_account_name": "morganf", "source_account_upn": "test@test.com", "start_time": "2023-04-20T11:12:03.089Z", "status": "closed", "tactic": "Privilege Escalation", "tactic_id": "TA0004", "tags": [], "technique": "Valid Accounts", "technique_id": "T1078", "timestamp": "2023-04-20T11:12:05.686Z", "type": "idp-user-endpoint-app-info", "updated_timestamp": "2023-06-27T09:29:52.448779709Z", "mirror_direction": null, "mirror_instance": ""}'}

remote_incident_id = 'inc:afb5d1512a00480f53e9ad91dc3e4b55:1cf23a95678a421db810e11b5db693bd'
remote_detection_id = 'ldt:15dbb9d8f06b89fe9f61eb46e829d986:528715079668'
remote_idp_detection_id = '20879a8064904e:ind:20879a8064904ecfbb62c118a6a19411:26DF54C9-8803-4F97-AD22-A725EE820EA9'

# remote_id, close_incident, incident_status, detection_status, mirrored_object, entries
get_remote_incident = (remote_incident_id,
                       False,
                       30,
                       None,
                       {'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident', 'state': 'closed', 'status': 'In Progress',
                        'tags': ['Objective/Keep Access']},
                       [])
get_remote_incident_update = (remote_incident_id,
                              True,
                              25,
                              None,
                              {'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident', 'state': 'closed',
                               'status': 'Reopened', 'tags': ['Objective/Keep Access']},
                              [{'Contents': {'dbotIncidentReopen': True}, 'ContentsFormat': 'json', 'Type': EntryType.NOTE}])
get_remote_incident_close = (remote_incident_id,
                             True,
                             40,
                             None,
                             {'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident', 'state': 'closed',
                              'status': 'Closed', 'tags': ['Objective/Keep Access']},
                             [{'Contents': {'closeReason': 'Incident was closed on CrowdStrike Falcon',
                                            'dbotIncidentClose': True}, 'ContentsFormat': 'json', 'Type': EntryType.NOTE}])
get_remote_incident_no_close = (remote_incident_id,
                                False,
                                40,
                                None,
                                {'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident', 'state': 'closed',
                                 'status': 'Closed', 'tags': ['Objective/Keep Access']},
                                [])
get_remote_detection = (remote_detection_id,
                        False,
                        None,
                        'in_progress',
                        {'behaviors.objective': 'Falcon Detection Method', 'behaviors.scenario': 'suspicious_activity',
                         'behaviors.tactic': 'Malware', 'behaviors.technique': 'Malicious File',
                         'device.hostname': 'FALCON-CROWDSTR', 'incident_type': 'detection', 'severity': 2,
                         'status': 'in_progress'},
                        [])
get_remote_detection_update = (remote_detection_id,
                               True,
                               None,
                               'reopened',
                               {'behaviors.objective': 'Falcon Detection Method', 'behaviors.scenario': 'suspicious_activity',
                                'behaviors.tactic': 'Malware', 'behaviors.technique': 'Malicious File',
                                'device.hostname': 'FALCON-CROWDSTR', 'incident_type': 'detection', 'severity': 2,
                                'status': 'reopened'},
                               [{'Contents': {'dbotIncidentReopen': True}, 'ContentsFormat': 'json', 'Type': EntryType.NOTE}])
get_remote_detection_close = (remote_detection_id,
                              True,
                              None,
                              'closed',
                              {'behaviors.objective': 'Falcon Detection Method', 'behaviors.scenario': 'suspicious_activity',
                               'behaviors.tactic': 'Malware', 'behaviors.technique': 'Malicious File',
                               'device.hostname': 'FALCON-CROWDSTR', 'incident_type': 'detection', 'severity': 2,
                               'status': 'closed'},
                              [{'Contents': {'closeReason': 'Detection was closed on CrowdStrike Falcon',
                                             'dbotIncidentClose': True}, 'ContentsFormat': 'json', 'Type': EntryType.NOTE}])
get_remote_detection_no_close = (remote_detection_id,
                                 False,
                                 None,
                                 'closed',
                                 {'behaviors.objective': 'Falcon Detection Method', 'behaviors.scenario': 'suspicious_activity',
                                  'behaviors.tactic': 'Malware', 'behaviors.technique': 'Malicious File',
                                  'device.hostname': 'FALCON-CROWDSTR', 'incident_type': 'detection', 'severity': 2,
                                  'status': 'closed'},
                                 [])

get_remote_data_command_args = [get_remote_incident,
                                get_remote_incident_update,
                                get_remote_incident_close,
                                get_remote_incident_no_close,
                                get_remote_detection,
                                get_remote_detection_update,
                                get_remote_detection_close,
                                get_remote_detection_no_close,
                                ]

# updated_object, entry_content, close_incident
incident_closes = ({'status': 'Closed'},
                   'dbotIncidentClose',
                   True)
incident_reopens = ({'status': 'Reopened'},
                    'dbotIncidentReopen',
                    True)
incident_reopens_other_status = ({'status': 'New'},
                                 'dbotIncidentReopen',
                                 True)
incident_not_closed = ({'status': 'In Progress'},
                       None,
                       False)
incident_no_status = ({},
                      None,
                      True)

set_xsoar_incident_entries_args = [incident_closes,
                                   incident_reopens,
                                   incident_reopens_other_status,
                                   incident_not_closed,
                                   incident_no_status,
                                   ]

# updated_object, entry_content, close_incident
detection_closes = ({'status': 'closed'},
                    'dbotIncidentClose',
                    True)
detection_reopens = ({'status': 'reopened'},
                     'dbotIncidentReopen',
                     True)
detection_reopens_other_status = ({'status': 'true_positive'},
                                  'dbotIncidentReopen',
                                  True)
detection_not_closed = ({'status': 'in_progress'},
                        None,
                        False)
detection_no_status = ({},
                       None,
                       True)

set_xsoar_detection_entries_args = [detection_closes,
                                    detection_reopens,
                                    detection_reopens_other_status,
                                    detection_not_closed,
                                    detection_no_status,
                                    ]

# updated_object, mirrored_data, mirroring_fields, output
keeping_updated_object = ({'incident_type': 'incident'},
                          {},
                          [],
                          {'incident_type': 'incident'})
keeping_empty_updated_object = ({}, {}, [], {})
no_nested_fields = ({'incident_type': 'incident'},
                    response_incident,
                    ['state', 'status', 'tags'],
                    {'incident_type': 'incident',
                     'state': 'closed',
                     'status': 20,
                     'tags': ['Objective/Keep Access']})
fields_not_existing = ({},
                       response_incident,
                       ['tactics.', 'techniques', 'objectives'],
                       {})
field_nested_dict_in_list = ({'incident_type': 'incident'},
                             response_incident,
                             ['state', 'hosts.hostname'],
                             {'incident_type': 'incident',
                              'state': 'closed',
                              'hosts.hostname': 'SFO-M-Y81WHJ'})
field_nested_in_dict = ({}, response_detection,
                        ['behaviors.tactic', 'behaviors.scenario', 'behaviors.objective',
                         'behaviors.technique'],
                        {'behaviors.objective': 'Falcon Detection Method', 'behaviors.scenario': 'suspicious_activity',
                         'behaviors.tactic': 'Malware', 'behaviors.technique': 'Malicious File'})
fields_nested_all_options = ({'incident_type': 'detection'},
                             response_detection,
                             ['status', 'severity', 'behaviors.tactic', 'behaviors.scenario', 'behaviors.objective',
                              'behaviors.technique', 'device.hostname'],
                             {'incident_type': 'detection', 'status': 'new', 'behaviors.objective': 'Falcon Detection Method',
                              'behaviors.scenario': 'suspicious_activity', 'behaviors.tactic': 'Malware',
                              'behaviors.technique': 'Malicious File', 'device.hostname': 'FALCON-CROWDSTR'})

set_updated_object_args = [keeping_updated_object,
                           keeping_empty_updated_object,
                           no_nested_fields,
                           fields_not_existing,
                           field_nested_dict_in_list,
                           field_nested_in_dict,
                           fields_nested_all_options,
                           ]

# args, to_mock, call_args, remote_id, prev_tags, close_in_cs_falcon_param
incident_changed_status = ({'data': {'status': 'New'},
                            'entries': [],
                            'incidentChanged': True,
                            'remoteId': remote_incident_id,
                            'status': IncidentStatus.ACTIVE,
                            'delta': {'status': 'New'}},
                           'update_incident_request',
                           [([remote_incident_id], '20', 'update_status')],
                           remote_incident_id,
                           None,
                           False)
incident_changed_tags = ({'data': {'tag': ['newTag']},
                          'entries': [],
                          'incidentChanged': True,
                          'remoteId': remote_incident_id,
                          'status': IncidentStatus.PENDING,
                          'delta': {'tag': ['newTag']}},
                         'update_incident_request',
                         [([remote_incident_id], 'prevTag', 'delete_tag'),
                          ([remote_incident_id], 'newTag', 'add_tag')],
                         remote_incident_id,
                         {'prevTag'},
                         False)
incident_changed_both = ({'data': {'tag': ['newTag'], 'status': 'Reopened'},
                          'entries': [],
                          'incidentChanged': True,
                          'remoteId': remote_incident_id,
                          'status': IncidentStatus.DONE,
                          'delta': {'tag': ['newTag'], 'status': 'Reopened'}},
                         'update_incident_request',
                         [([remote_incident_id], 'prevTag', 'delete_tag'),
                          ([remote_incident_id], 'newTag', 'add_tag'),
                          ([remote_incident_id], '25', 'update_status')],
                         remote_incident_id,
                         {'prevTag'},
                         False)
incident_changed_no_close = ({'data': {'tag': ['newTag'], 'status': 'Reopened'},
                              'entries': [],
                              'incidentChanged': True,
                              'remoteId': remote_incident_id,
                              'status': IncidentStatus.DONE,
                              'delta': {'tag': ['newTag']}},
                             'update_incident_request',
                             [([remote_incident_id], 'newTag', 'add_tag')],
                             remote_incident_id,
                             set(),
                             False)
incident_changed_param_close = ({'data': {'tag': ['newTag'], 'status': 'Reopened'},
                                 'entries': [],
                                 'incidentChanged': True,
                                 'remoteId': remote_incident_id,
                                 'status': IncidentStatus.ACTIVE,
                                 'delta': {'tag': ['newTag']}},
                                'update_incident_request',
                                [([remote_incident_id], 'newTag', 'add_tag')],
                                remote_incident_id,
                                set(),
                                True)
incident_closed = ({'data': {'tag': ['newTag'], 'status': 'Reopened'},
                    'entries': [],
                    'incidentChanged': True,
                    'remoteId': remote_incident_id,
                    'status': IncidentStatus.DONE,
                    'delta': {'closeReason': 'Other'}},
                   'update_incident_request',
                   [([remote_incident_id], '40', 'update_status')],
                   remote_incident_id,
                   set(),
                   True)
detection_changed = ({'data': {'status': 'new'},
                      'entries': [],
                      'incidentChanged': True,
                      'remoteId': remote_detection_id,
                      'status': IncidentStatus.PENDING,
                      'delta': {'status': 'new'}},
                     'update_detection_request',
                     [([remote_detection_id], 'new')],
                     remote_detection_id,
                     None,
                     False)
detection_changed_no_close = ({'data': {'status': 'new'},
                               'entries': [],
                               'incidentChanged': True,
                               'remoteId': remote_detection_id,
                               'status': IncidentStatus.DONE,
                               'delta': {'status': 'new'}},
                              'update_detection_request',
                              [([remote_detection_id], 'new')],
                              remote_detection_id,
                              None,
                              False)
detection_changed_param_close = ({'data': {'status': 'new'},
                                  'entries': [],
                                  'incidentChanged': True,
                                  'remoteId': remote_detection_id,
                                  'status': IncidentStatus.ACTIVE,
                                  'delta': {'status': 'new'}},
                                 'update_detection_request',
                                 [([remote_detection_id], 'new')],
                                 remote_detection_id,
                                 None,
                                 True)
detection_closed = ({'data': {'status': 'new'},
                     'entries': [],
                     'incidentChanged': True,
                     'remoteId': remote_detection_id,
                     'status': IncidentStatus.DONE,
                     'delta': {'closeReason': 'Other'}},
                    'update_detection_request',
                    [([remote_detection_id], 'closed')],
                    remote_detection_id,
                    None,
                    True)

update_remote_system_command_args = [incident_changed_status,
                                     incident_changed_tags,
                                     incident_changed_both,
                                     incident_changed_no_close,
                                     incident_changed_param_close,
                                     incident_closed,
                                     detection_changed,
                                     detection_changed_no_close,
                                     detection_changed_param_close,
                                     detection_closed,
                                     ]

# delta, close_in_cs_falcon_param, to_close
delta_closed = ({'closeReason': 'Other', 'closingUserId': 'admin', 'runStatus': ''},
                True,
                True)
param_no_close = ({'closeReason': 'Other', 'closingUserId': 'admin', 'runStatus': ''},
                  False,
                  False)
delta_not_closed = ({'status': 'new'},
                    True,
                    False)
no_close = ({},
            False,
            False)

close_in_cs_falcon_args = [delta_closed,
                           param_no_close,
                           delta_not_closed,
                           no_close,
                           ]

# delta, inc_status, close_in_cs_falcon, detection_request_status
detection_closed_in_xsoar = ({'closeReason': 'Other'},
                             IncidentStatus.DONE,
                             True,
                             'closed')
detection_status_closed = ({'status': 'closed'},
                           IncidentStatus.ACTIVE,
                           False,
                           'closed')
detection_update_status_true_close_remote = ({'status': 'new'},
                                             IncidentStatus.ACTIVE,
                                             True,
                                             'new')
detection_update_status_false_close_remote = ({'status': 'in_progress'},
                                              IncidentStatus.ACTIVE,
                                              False,
                                              'in_progress')
detection_update_by_status_dont_close = ({'status': 'false_positive'},
                                         IncidentStatus.DONE,
                                         False,
                                         'false_positive')
detection_didnt_change = ({},
                          IncidentStatus.ACTIVE,
                          False,
                          '')

update_remote_detection_args = [detection_closed_in_xsoar,
                                detection_status_closed,
                                detection_update_status_true_close_remote,
                                detection_update_status_false_close_remote,
                                detection_update_by_status_dont_close,
                                detection_didnt_change,
                                ]

# delta, inc_status, close_in_cs_falcon, resolve_incident_status
incident_closed_in_xsoar = ({'closeReason': 'Other'},
                            IncidentStatus.DONE,
                            True,
                            'Closed')
incident_status_closed = ({'status': 'Closed'},
                          IncidentStatus.ACTIVE,
                          False,
                          'Closed')
incident_update_status_true_close_remote = ({'status': 'New'},
                                            IncidentStatus.ACTIVE,
                                            True,
                                            'New')
incident_update_status_false_close_remote = ({'status': 'In Progress'},
                                             IncidentStatus.ACTIVE,
                                             False,
                                             'In Progress')
incident_update_by_status_dont_close = ({'status': 'New'},
                                        IncidentStatus.DONE,
                                        False,
                                        'New')
incident_didnt_change = ({},
                         IncidentStatus.ACTIVE,
                         False,
                         '')

update_remote_incident_status_args = [incident_closed_in_xsoar,
                                      incident_status_closed,
                                      incident_update_status_true_close_remote,
                                      incident_update_status_false_close_remote,
                                      incident_update_by_status_dont_close,
                                      incident_didnt_change,
                                      ]

# tags, action_name
no_tags = (set(),
           'add_tag')
one_tag_add = ({'tag1'},
               'add_tag')
one_tag_delete = ({'Tag2'},
                  'delete_tag')
add_tags = ({'Objective/Keep Access', 'Detected', 'ignored'},
            'add_tag')
delete_tags = ({'Objective/Keep Access', 'detected', 'Ignored'},
               'delete_tag')

remote_incident_handle_tags_args = [no_tags,
                                    one_tag_add,
                                    one_tag_delete,
                                    add_tags,
                                    delete_tags,
                                    ]
