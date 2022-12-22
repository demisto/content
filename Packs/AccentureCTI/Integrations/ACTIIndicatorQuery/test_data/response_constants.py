

URL_RES_JSON = {
    'results': [{'confidence': 50, 'display_text': 'http://www.malware.com/path',
                 'files': [{'confidence': 50, 'display_text': '934a72f37d861097c85dc3c2e16bca3c',
                            'key': '934a72f37d861097c85dc3c2e16bca3c', 'last_seen': '2020-10-07T20:26:30.000Z',
                            'relationship': 'contactsC2At', 'relationship_created_on': '2020-10-07T20:04:51.000Z',
                            'relationship_last_published': '2020-10-07T20:04:51.000Z', 'type': 'file',
                            'uuid': '8498bf4f-53e0-4cc0-aa44-10917eeec78c',
                            'sha1': '842ccc77b6ea22b4ef17ee6278819b4393051103',
                            'sha256': 'd2b7f1f38705374306c3a7775158933e4963c88a05bedad60078e3fb514c444d',
                            'href': '/rest/fundamental/v0/8498bf4f-53e0-4cc0-aa44-10917eeec78c'},
                           {'confidence': 50, 'display_text': '8d648dc2e1c5ebc383b5f62acefc6875',
                            'key': '8d648dc2e1c5ebc383b5f62acefc6875', 'last_seen': '2020-10-06T00:59:33.000Z',
                            'relationship': 'contactsC2At', 'relationship_created_on': '2020-10-05T23:51:53.000Z',
                            'relationship_last_published': '2016-09-10T01:05:09.000Z', 'type': 'file',
                            'uuid': '9fea5b89-2ff8-4881-849c-6bbee6d80320',
                            'sha1': 'd026df22ad7c9773b12d99795d7a15b3a31d83b0',
                            'sha256': '022728d858c0206adca9ee32ba92e190723d6d42207dd1872657030f19bc27b2',
                            'href': '/rest/fundamental/v0/9fea5b89-2ff8-4881-849c-6bbee6d80320'},
                           {'confidence': 50, 'display_text': '218dfd9d968892d7ae7960fb4a85de35',
                            'key': '218dfd9d968892d7ae7960fb4a85de35', 'last_seen': '2020-10-18T15:24:12.000Z',
                            'malware_family': ['JavaScript Downloader'], 'relationship': 'contactsC2At',
                            'relationship_created_on': '2020-10-18T14:49:36.000Z',
                            'relationship_last_published': '2020-10-18T14:49:36.000Z', 'type': 'file',
                            'uuid': 'b96a5814-bf98-4ad9-9980-7632f5c6a20f',
                            'sha1': 'd47c7a84d72b64f6f690a422e004fee4bc892eab',
                            'sha256': 'bc75daf4592c8aace308f72a6393927e2ae174784cbdaba1b6b641b60aa2c84d',
                            'href': '/rest/fundamental/v0/b96a5814-bf98-4ad9-9980-7632f5c6a20f'}],
                 'index_timestamp': '2020-10-26T09:29:54.600Z',
                 'key': 'http://www.malware.com/path',
                 'last_modified': '2020-10-18T15:25:00.000Z',
                 'last_published': '2020-10-05T23:51:53.000Z', 'last_seen': '2020-10-06T00:59:33.000Z',
                 'last_seen_as': ['MALWARE_C2'], 'malware_family': [],
                 'replication_id': 1603034700680000002,
                 'seen_at': [{'confidence': 50,
                              'display_text': 'JavaScript Downloader', 'key': 'JavaScript Downloader',
                              'last_seen': '2020-10-18T15:24:12.000Z', 'relationship': 'seenAt',
                              'relationship_created_on': '2020-10-18T14:49:36.000Z',
                              'relationship_last_published': '2020-10-18T14:49:36.000Z',
                              'type': 'malware_family', 'uuid': 'f1b2bae6-6909-4303-9584-d91e156a13f7',
                              'href': '/rest/fundamental/v0/f1b2bae6-6909-4303-9584-d91e156a13f7'}],
                 'severity': 3,
                 'threat_types': ['Cyber Crime'],
                 'type': 'url',
                 'uuid': '60a2ef03-8650-490b-9542-0f8cc21e5c6d',
                 'arguments': [], 'path': ['nuklyuql']}], 'total_size': 1, 'page': 1, 'page_size': 25, 'more': False}


URL_INTEL_JSON = {'results': [
    {
        'key': 'http://www.malware.com/path',
        'title': 'my intelligence alert',
        'type': 'intelligence_alert',
        'uuid': '60a2ef03-8650-490b-9542-0f8cc21e5c6d'
    },
    {
        'key': 'http://www.malware.com/path',
        'title': 'my intelligence report',
        'type': 'intelligence_report',
        'uuid': '70a2ef03-8650-490b-9542-0f8cc21e5c6d'
    }
],
    'total_size': 2,
    'page': 1,
    'page_size': 25,
    'more': False
}


IP_RES_JSON = {
    'results':
        [{'confidence': 100, 'display_text': '0.0.0.0',
          'files': [{'display_text': 'bf0fea133818387cca7eaef5a52c0aed', 'key': 'bf0fea133818387cca7eaef5a52c0aed',
                     'relationship': 'contactsC2At', 'relationship_created_on': '2018-06-06T13:13:37.000Z',
                     'relationship_last_published': '2018-06-06T13:13:37.000Z', 'type': 'file',
                     'uuid': 'ec1af5a4-afe1-4580-b51b-f6f3c7609c75', 'sha1': '0a30b5b24196e503c4a21dcfd1447b28a39af314',
                     'sha256': 'dd7e69e14c88972ac173132b90b3f4bfb2d1faec15cca256a256dd3a12b6e75d',
                     'href': '/rest/fundamental/v0/ec1af5a4-afe1-4580-b51b-f6f3c7609c75'},
                    {'display_text': '1535acbcae591b0d03ef7518cb56883e', 'key': '1535acbcae591b0d03ef7518cb56883e',
                     'relationship': 'contactsC2At', 'relationship_created_on': '2018-01-04T01:10:32.000Z',
                     'relationship_last_published': '2018-01-04T01:10:32.000Z', 'type': 'file',
                     'uuid': 'ff8cbab2-d81d-4839-9045-d566282ef4b9', 'sha1': '36b5e59a01e7f244d4a3bbb539e57aa468115dc8',
                     'sha256': '6fcf4592f9261d5734fb3b8534f6839ab65f68fd9ff14a9005225135e743226c',
                     'href': '/rest/fundamental/v0/ff8cbab2-d81d-4839-9045-d566282ef4b9'}],
          'index_timestamp': '2020-10-22T08:00:43.518Z',
          'key': '0.0.0.0',
          'last_modified': '2020-10-08T20:55:58.000Z',
          'last_published': '2018-01-04T15:22:25.000Z',
          'last_seen': '2020-10-06T00:59:33.000Z',
          'last_seen_as': ['MALWARE_DOWNLOAD', 'MALWARE_C2'],
          'malware_family': ['Hive'], 'replication_id': 1602190558122000000,
          'threat_campaigns': [{'display_text': 'FBI Flash CU-000141-MW','uuid':'7q2b129s-6421-4e22-a276-22be5f76cba8'}],
          'threat_actors': [{'display_text': 'RastaFarEye','uuid': '7q2b129s-6421-4e22-a276-22be5f76cba8'}],
          'threat_groups': [{'display_text': 'Black Shadow','uuid': '7q2b129s-6421-4e22-a276-22be5f76cba8'}],
          'severity': 4,
          'threat_types': ['Cyber Espionage'],
          'type': 'ip',
          'uuid': 'e5d40481-bea4-4d33-95d2-e029cff28084',
          'ip_int': 3105436253, 'ip_type': '4'}],
    'total_size': 1,
    'page': 1,
    'page_size': 25,
    'more': False}


IP_INTEL_JSON = {'results': [
    {
        'key': '0.0.0.0',
        'title': 'my intelligence alert1',
        'type': 'intelligence_alert',
        'uuid': 'e5d40481-bea4-4d33-95d2-e029cff28084'
    },
    {
        'key': '0.0.0.0',
        'title': 'my intelligence alert2',
        'type': 'intelligence_alert',
        'uuid': 'e5d40481-bea4-4d33-95d2-e029cff28085'
    },
    {
        'key': '0.0.0.0',
        'title': 'my intelligence alert3',
        'type': 'intelligence_alert',
        'uuid': 'e5d40481-bea4-4d33-95d2-e029cff28086'
    },
    {
        'key': '0.0.0.0',
        'title': 'my intelligence report',
        'type': 'intelligence_report',
        'uuid': 'f5d40481-bea4-4d33-95d2-e029cff28084'
    }
],
    'total_size': 2,
    'page': 1,
    'page_size': 25,
    'more': False
}


DOMAIN_RES_JSON = {
    'results': [
        {
            'confidence': 100,
            'display_text': 'mydomain.com',
            'key': 'mydomain.com',
            'last_published': '2021-08-12T19:12:58.000Z',
            'last_seen': '2020-10-06T00:59:33.000Z',
            'last_seen_as': [
                'MALWARE_C2'
            ],
            'malware_family': [],
            'severity': 3,
            'threat_types': [
                'Cyber Espionage',
                'Cyber Crime'
            ],
            'type': 'domain',
            'uuid': '461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
        }
    ],
    'total_size': 1,
    'page': 1,
    'page_size': 25,
    'more': False
}


DOMAIN_INTEL_JSON = {'results': [
    {
        'key': 'mydomain.com',
        'title': 'my intelligence alert',
        'type': 'intelligence_alert',
        'uuid': '461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
    },
    {
        'key': 'mydomain.com',
        'title': 'my intelligence report',
        'type': 'intelligence_report',
        'uuid': '561b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
    }
],
    'total_size': 2,
    'page': 1,
    'page_size': 25,
    'more': False
}


UUID_RES_JSON={
            'confidence': 100,
            'display_text': 'mydomain.com',
            'key': 'mydomain.com',
            'last_published': '2021-08-12T19:12:58.000Z',
            'last_seen': '2020-10-06T00:59:33.000Z',
            'last_seen_as': [
                'MALWARE_C2'
            ],
            'malware_family': ['Hive'],
            'threat_campaigns': [{'display_text': 'FBI Flash CU-000141-MW','uuid':'7q2b129s-6421-4e22-a276-22be5f76cba8'}],
            'threat_actors': [{'display_text': 'RastaFarEye','uuid': '7q2b129s-6421-4e22-a276-22be5f76cba8'}],
            'threat_groups': [{'display_text': 'Black Shadow','uuid': '7q2b129s-6421-4e22-a276-22be5f76cba8'}],
            'severity': 3,
            'threat_types': [
                'Cyber Espionage',
                'Cyber Crime'
            ],
            'type': 'domain',
            'uuid': '461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
        }


RES_JSON_IA = {
    "attack_techniques": [
        {
            "id": "T1047",
            "label": "Windows Management Instrumentation"
        },
        {
            "id": "T1003",
            "label": "Credential Dumping"
        },
        {
            "id": "T1124",
            "label": "System Time Discovery"
        },
        {
            "id": "T1045",
            "label": "Software Packing"
        },
        {
            "id": "T1145",
            "label": "Private Keys"
        },
        {
            "id": "T1046",
            "label": "Network Service Scanning"
        },
        {
            "id": "T1087",
            "label": "Account Discovery"
        },
        {
            "id": "T1165",
            "label": "Startup Items"
        },
        {
            "id": "T1143",
            "label": "Hidden Window"
        },
        {
            "id": "T1022",
            "label": "Data Encrypted"
        },
        {
            "id": "T1063",
            "label": "Security Software Discovery"
        },
        {
            "id": "T1041",
            "label": "Exfiltration Over Command and Control Channel"
        },
        {
            "id": "T1064",
            "label": "Scripting"
        },
        {
            "id": "T1482",
            "label": "Domain Trust Discovery"
        },
        {
            "id": "T1528",
            "label": "Steal Application Access Token"
        },
        {
            "id": "T1007",
            "label": "System Service Discovery"
        },
        {
            "id": "T1107",
            "label": "File Deletion"
        },
        {
            "id": "T1503",
            "label": "Credentials from Web Browsers"
        },
        {
            "id": "T1049",
            "label": "System Network Connections Discovery"
        },
        {
            "id": "T1083",
            "label": "File and Directory Discovery"
        },
        {
            "id": "T1081",
            "label": "Credentials in Files"
        },
        {
            "id": "T1060",
            "label": "Registry Run Keys / Startup Folder"
        },
        {
            "id": "T1082",
            "label": "System Information Discovery"
        },
        {
            "id": "T1179",
            "label": "Hooking"
        },
        {
            "id": "T1135",
            "label": "Network Share Discovery"
        },
        {
            "id": "T1113",
            "label": "Screen Capture"
        },
        {
            "id": "T1059",
            "label": "Command-Line Interface"
        },
        {
            "id": "T1078",
            "label": "Valid Accounts"
        },
        {
            "id": "T1056",
            "label": "Input Capture"
        },
        {
            "id": "T1012",
            "label": "Query Registry"
        },
        {
            "id": "T1035",
            "label": "Service Execution"
        },
        {
            "id": "T1112",
            "label": "Modify Registry"
        },
        {
            "id": "T1057",
            "label": "Process Discovery"
        },
        {
            "id": "T1010",
            "label": "Application Window Discovery"
        },
        {
            "id": "T1055",
            "label": "Process Injection"
        },
        {
            "id": "T1074",
            "label": "Data Staged"
        },
        {
            "id": "T1539",
            "label": "Steal Web Session Cookie"
        },
        {
            "id": "T1518",
            "label": "Software Discovery"
        },
        {
            "id": "T1119",
            "label": "Automated Collection"
        },
        {
            "id": "T1214",
            "label": "Credentials in Registry"
        },
        {
            "id": "T1016",
            "label": "System Network Configuration Discovery"
        },
        {
            "id": "T1050",
            "label": "New Service"
        },
        {
            "id": "T1070",
            "label": "Indicator Removal on Host"
        },
        {
            "id": "T1170",
            "label": "Mshta"
        },
        {
            "id": "T1071",
            "label": "Standard Application Layer Protocol"
        },
        {
            "id": "T1090",
            "label": "Connection Proxy"
        }
    ],
    "created_on": "2021-03-05T21:47:36.000Z",
    "display_text": "Kazuar Revamped: BELUGASTURGEON Significantly Updates Its Espionage Backdoor",
    "dynamic_properties": {},
    "index_timestamp": "2022-02-09T14:18:19.333Z",
    "key": "5ca1bcc4-843f-4a2b-9673-ec294e05a509",
    "last_modified": "2021-07-14T09:17:37.000Z",
    "last_published": "2021-03-05T21:47:36.000Z",
    "attachment_links": ["/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-02-08cropped.png","/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-03-08cropped.png"],
    "links": [
        {
            "created_on": "2017-05-04T17:45:51.000Z",
            "display_text": "Kazuar",
            "key": "Kazuar",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-05T21:47:36.000Z",
            "relationship_last_published": "2021-03-05T21:47:36.000Z",
            "type": "malware_family",
            "uuid": "ef5a7376-0a81-4478-b15d-68369e7196bd",
            "href": "/rest/fundamental/v0/ef5a7376-0a81-4478-b15d-68369e7196bd"
        },
        {
            "created_on": "2020-08-07T20:08:29.000Z",
            "display_text": "Russia-Linked BELUGASTURGEON Uses ComRATv4 to Target Government and Resources Organizations in Europe and Central Asia",
            "key": "033355e6-e57e-4a02-bf3a-c9805d06a259",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-05T21:47:36.000Z",
            "relationship_last_published": "2021-03-05T21:47:36.000Z",
            "type": "intelligence_report",
            "uuid": "9bf2fc44-570d-40ad-b81a-744141ed443e",
            "href": "/rest/document/v0/9bf2fc44-570d-40ad-b81a-744141ed443e"
        }
    ],
    "replication_id": 1626254257462000000,
    "replication_id_ja": 1615483119339000000,
    "sources_external": [
        {
            "datetime": "2017-05-02T23:00:00.000Z",
            "description": "Kazuar: Multiplatform Espionage Backdoor with API Access",
            "name": "Palo Alto Networks",
            "reputation": 4,
            "url": "https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/"
        }
    ],
    "threat_types": [
        "Cyber Espionage"
    ],
    "title": "Kazuar Revamped: BELUGASTURGEON Significantly Updates Its Espionage Backdoor",
    "type": "intelligence_alert",
    "uuid": "a487dfdc-08b4-4909-82ea-2d934c27d901",
    "analysis": "## Key Findings and Judgements\n\n- From analyzing two Kazuar samples, iDefense determined that BELUGASTURGEON has significantly updated the backdoor's codebase when compared to traditional Kazuar samples.\n\n- The updated variant's core functionality supports new commands for espionage campaigns, including keylogging, credential theft, and system enumeration, without requiring additional plugins.\n\n- BELUGASTURGEON operators can now communicate between Kazuar instances  using task forwarding over named pipes without needing Internet connectivity; these enhancements offer functionality similar to that in Carbon and Uroborus.\n\n- Multiple Kazuar infections can now exist on one compromised system but target different users due to updates in Kazuar's mutex generation function.\n\n- HTTP(S) command-and-control (C2) communications now use primary, backup, and last-chance C2 servers to maintain persistence on a compromised device even if some of BELUGASTURGEON's infrastructure is unavailable.\n\n- Because Kazuar can now load from a Windows Registry key into memory, an infection file does not exist on the device and the chance of detection is reduced.\n\n- A comparison of the samples from August 2020 and February 2021 reveal differences in the Kazuar command set and configuration settings. Based on the discovery times of these samples and the changes between them, iDefense assesses the new Kazuar variant is under active development and BELUGASTURGEON will continue to use it for espionage campaigns.\n\n## Overview\n[Kazuar](#/node/malware_family/view/ef5a7376-0a81-4478-b15d-68369e7196bd) is a .NET backdoor the [BELUGASTURGEON (a.k.a. Turla, Snake, Waterbug, Venomous Bear)](#/node/threat_group/view/fb53e479-54e1-4827-abb4-ae1ae1db53e2) threat group has been using in espionage campaigns since at least 2017. [The Kazuar variant that Palo Alto Networks detailed in May 2017](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) has commands typical of many backdoors, such as reading, writing, copying, moving, and deleting files on the compromised system; executing commands from the command line; taking screenshots; and capturing webcam images. The version is extensible using a plugin framework to achieve additional functionality. The remote API allows BELUGASTURGEON operators to direct the backdoor to act as a web server and listen for inbound HTTP requests. iDefense identified this version of Kazuar used in various BELUGASTURGEON activity, including a [2020 campaign against the Cypriot government](#/node/intelligence_alert/view/6cc805d7-cb77-443d-afea-d052916fa602).\n\nSince its discovery in 2017, developers have been enhancing Kazuar. In 2019, security researcher [Juan Andrés Guerrero-Saade identified](https://www.epicturla.com/blog/sysinturla) Kazuar samples branded to look like the Microsoft SysInternals tool [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview). In addition to cosmetic changes, the Kazuar developers moved to a custom packer instead of  obfuscating Kazuar's code with [ConfuserEx](https://yck1509.github.io/ConfuserEx/). \n\nIn the campaign against the Cypriot government, BELUGASTURGEON operators implemented a novel C2 configuration where the Kazuar backdoor receives commands from URLs pointing to internal nodes in the Cypriot government network. [Another Kazuar sample acted as a transfer agent](#/node/malicious_event/view/2c3490cd-c4bb-4aef-b75f-641b76dcff01), proxying commands between the sample with the novel C2 configuration and the C2 server. Despite these developments, the underlying Kazuar codebase, including the backdoor's command set and configuration, remained mostly unchanged.\n## New Kazuar Functionality \nIn February 2021, Defense analyzed two Kazuar samples and noted significant changes in the codebase,  command set, and configuration functionality to warrant classifying the samples as a new variant of the Kazuar backdoor. One sample, shared by an industry partner, was first seen in August 2020; the second sample was uploaded to a third-party malware repository in February 2021. \n\nThe new variant persists on the system by storing the packed Kazuar binary in the Windows Registry and loading itself into memory at runtime without writing an infection file to disk. The variant offers new credential stealing and keylogging functionality, executes payloads in a range of file formats, and enumerates a wide range of system information about the compromised device. \n\nThe backdoor has a built-in command that forwards tasks to other Kazuar instances in a compromised network via named pipes. The ability to communicate among Kazuar instances as well as the overall extended functionality implemented without plugins allows Kazuar to achieve the functionality of some of BELUGASTURGEON's more sophisticated backdoors, such as [Carbon](#/node/malware_family/view/5c48cd58-180b-4d02-b344-5756f3a6fb33) or [Uroborus](#/node/malware_family/view/7c5fc18d-bab8-4928-a716-9b0c5a92a022).\n\nThe new Kazuar variant appears intended for Windows systems as developers have removed the UNIX-related code found in the earlier variant. Other functionality removed includes the remote HTTP API that is replaced with the task forwarding functionality allowing operators to configure Kazuar instances to listen for tasks from other \"remote\" Kazuar instances. \n\nIndications the Kazuar variant is under active development include an Agent Label value, discussed in more detail in the *Configuration Comparison* section, that is likely a version number incremented when there is a new iteration of the backdoor. iDefense also identified changes in the commands and configuration between the sample from August 2020 and February 2021. \n\niDefense analyzed the following samples of the new Kazuar variant:\n\n- **Filename (packed):**  Agent.Protected.exe  \n - **SHA-256 (packed):**  182d5b53a308f8f3904314463f6718fa2705b7438f751581513188d94a9832cd   \n\n - **Filename (unpacked):**  Agent.Original.exe  \n\n     - **SHA-256 (unpacked):**  41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb  \n     - **File Size (unpacked):** 267 KB  \n     - **Agent Label:**  AGN-AB-03  \n     - **First Seen:** August 2020 (identified by industry partner)\n\n* **Filename (packed):**  Relieved.exe  \n\n - **SHA-256 (packed):**  60f47db216a58d60ca04826c1075e05dd8e6e647f11c54db44c4cc2dd6ee73b9  \n\n  - **Filename (unpacked):**  Musky.exe  \n\n     - **SHA-256 (unpacked):**  1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4     \n     - **File Size (unpacked):** 291 KB  \n     - **Agent Label:** AGN-AB-13  \n     - **First Seen:** 15 February 2021 (uploaded to third-party malware repository)  \n\n\nThe following sections examine the differences between the new variant and the traditional Kazuar variant and the areas of active development in the new variant.\n## Codebase Comparisons \niDefense compared the codebase of the  version of Kazuar [detailed by Palo Alto Networks in May 2017](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/), which will be referred to as the “traditional” variant,  and two samples of Kazuar from August 2020 and February 2021, the “new” variant,  and identified the following significant variations.\n#### Installation and Persistence\n\n**Traditional Kazuar Variant**\n\nThe traditional version of Kazuar is written to disk on the compromised machine. To maintain persistence on the machine, BELUGASTURGEON  adds  a Windows shortcut (LNK) file to the Windows startup folder or adds a subkey to one of the following Windows Registry keys:\n\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n- HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\n- HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load\n\nOnce the LNK file or Registry key is configured, the Kazuar binary launches at user logon. Operators can configure the persistence method using the “autorun” command.\n\n**New Kazuar Variant**\n\nRather than write the binary to disk, the new Kazuar variant installs itself directly in the Windows Registry. For the sample with Agent Label AGN-AB-03, BELUGASTURGEON operators created a Registry subkey under `HKLM\\SOFTWARE\\Microsoft\\ActiveSync` with the name \"Jhkr.\" The subkey data contains an obfuscated VBScript that, when deobfuscated, is likely a modified version of the publicly available [VBSMeter](https://github.com/Cn33liz/VBSMeter). (VBSMeter is a Meterpreter stager for C# assemblies embedded in VBScript.)\n\nThe packed Kazuar binary is stored in one of the VBScript parameters. When launched, the VBScript  checks for a compatible version of the .NET framework installed on the compromised machine, Base64-decodes the packed Kazuar binary from the parameter, deserializes it, and invokes the packed binary in memory. The VBScript then writes the TXT log file ~TMP0666.tmp into the user's `%Temp%` directory. The packing algorithm is simple: XOR decode and decompress the encoded payload that is initially stored in an array. \n\nKazuar sample AGN-AB-13 is loaded from the Registry key `HKCU\\SOFTWARE\\Microsoft\\Arrases\\Canoed`. iDefense was unable to obtain the value of the Registry key to confirm the same VBScript loaded the sample into memory but assesses this is likely. \n\nThe same packing algorithm encodes the samples in the Registry key. The packed sample writes any unpacking errors to log file `%Temp%\\~TMP0666.txt`, as shown in Exhibit 1. This logging functionality was not present in the packed AGN-AB-03 sample, only in the VBScript used to load the sample.\n\n![alt text](/rest/files/download/34/05/ab/e72860f9a0223f242f42e8301dded7b91c3ed03c611fe4892218edc845/exhibit1.PNG)  \n_Exhibit 1: Packing Algorithm and Logging Functionality for Packed Kazuar Sample_\n\niDefense has not yet determined how BELUGASTURGEON operators gain initial access to the machine and install the Registry keys containing the new variant of Kazuar.\n\n#### Initialization\n\n\n###### Mutex \n\n**Traditional Kazuar Variant**\n\nWhen launched, the traditional Kazuar version gathers system information and generates a [mutex](https://docs.microsoft.com/en-us/windows/win32/sync/mutex-objects)  that ensures only one instance of Kazuar is running on the compromised machine. The mutex is generated using the following steps:\n\n- Obtain the MD5 hash of a string “[username]=>singleton-instance-mutex”\n- Encrypt this MD5 hash using an XOR algorithm and the volume serial number \n- Generate a GUID from the result  and append it to the string “Global\\\\”\n\nExhibit 2 shows how the traditional Kazuar variant generates the mutex. [According to Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/), if the variant cannot obtain the system’s storage serial number, it uses a default version of 0xFB1C1A. \n\n![alt text](/rest/files/download/4c/0b/15/a539a2cb938e5d10409cc8d119cfd79400a5e03f37badb37de5e24b0ec/Exhibit2.PNG)   \n_Exhibit 2: Traditional Kazuar Variant Mutex Generation_\n\n**New Kazuar Variant**\n\nThe new variant of Kazuar generates its mutex by XOR-encoding the System Universal Unique Identifier (UUID) value with the current process ID (PID), which has been XOR-encoded with two hardcoded values, as shown in Exhibit 3. The resulting mutex no longer has the prefix  “Global\\\\” indicating it is a local mutex and multiple Kazuar infections can co-exist for different users on one compromised device.\n\n![alt text](/rest/files/download/6d/d8/60/c2914f57d474b1af992bb235466556128510fb251f416728a646a3eb67/Exhibit3.PNG)   \n_Exhibit 3: New Kazuar Variant Mutex Generation_\n\n###### Files Written\n\n**Traditional Kazuar Variant**\n\nThe traditional Kazuar variant writes folders that store the files it generates during execution. The variant writes the folders in the %LocalAppData% directory under a path beginning with \"Microsoft\" and selected from a hardcoded list (see Exhibit 4). The filenames are encoded on disk by calculating the FNV-1a hash of the filename string and XOR-encoding the  hash with the volume serial number and the hardcoded constant 0xBADA55, as shown in Exhibit 5.\n\n ![alt text](/rest/files/download/76/e7/5e/5aae52246f80c7a335e9b32222b09d8c417f9bf9dc931a256626cff650/Exhibit4.PNG)   \n_Exhibit 4: Directory Location for Configuration Files, Traditional Kazuar_\n\n![alt text](/rest/files/download/67/8d/04/34b9f163f8295a86bd222a9d798bbfc0930a34d1c4823af74db2b2b5ba/Exhibit5.PNG)   \n_Exhibit 5: Filename Encoding for Traditional Kazuar_\n\nThe traditional version of Kazuar creates the following folder structure: \n\n- **base:** Folder containing the following subfolders:\n   - **sys:** Folder containing configuration settings in the following files:\n        - 'serv'  – Stores the C2 servers. \n        - 'arun' – Stores the autorun method. \n        - 'remo' – Stores the remote type. \n        - 'cont' – Stores the date of last contact with the C2 server. \n        - 'uuid' – Stores the compromised device's System UUID.\n        - 'tran' – Stores the transport type.\n       - 'intv' – Stores the transport interval.\n\n - **log:** Folder containing logs and debug information.\n - **plg:** Folder containing plugins used to extend Kazuar's functionality.\n - **tsk:** Folder tasks for Kazuar to run.\n - **res:** Folder containing results of processed tasks.\n\n**New Kazuar Variant**\n\nLikewise, the new variant of Kazuar writes files to disk during execution under the `%LocalAppData%` directory selecting paths from a hardcoded list beginning with \"Microsoft\"; however, that list is longer in the new version, as shown in Exhibit 6.\n\n![alt text](/rest/files/download/47/2f/cd/d9b75728ce7e443002d93d1e34bb40ae6b11dc7612f2a43f03f842a8ce/Exhibit6.PNG)   \n_Exhibit 6: Directory Location for Configuration Files, New Kazuar_\n\nExhibit 7 shows the filename-encoding function for the new variant of Kazuar. Rather than generating 8-digit hex strings, as done previously, the new version generates 15-digit alphanumeric strings for filenames and folders. Filenames are also appended with a 3-digit file extension. The System UUID is used as a seed and the process involves a series of XOR encodings and a [custom implementation of the FNV-1a hashing algorithm](https://securelist.com/sunburst-backdoor-kazuar/99981/).\n\n![alt text](/rest/files/download/04/30/8d/ba1b97d2f491900af81e852f9076ae8911770c73517a25003a2d30bf16/Exhibit7.PNG)   \n_Exhibit 7: Filename Encoding for New Kazuar_\n\nThe list below contains the file tree of folders and files the new variant creates along with the encoded and decoded filenames. There is still a base folder and folders to contain the log messages and tasks. Kazuar's configuration data is now stored under the \"config\" folder, similar to the \"sys\" folder in the previous variant. (See the *Configuration Comparison* section below for more details.) The \"keys\" file under the \"logs\" folder stores keystrokes captured when the new keylogger is enabled. \n\n```\n%LOCALAPPDATA%\\MICROSOFT\\OFFICE\\VISIO\\ROT3BMLH2ZGRF9X9 (base)\n|\n|_ i4px5nL5PqksWMb.wgw (logs)\n|\n|_ 2YpvIxMopuiQqHsmc   (task)\n|\n|_ i4px5nL5PqksWMb     (logs)\n|          |_ T9j8NFq6Bwtna1B0ej.rub   (keys)\n|       \n|_Tk7Zu3EKOMqtjTnw     (config)\n        |_ 8c9lq3nL3Vv0bGX.apa   (solve_threads)\n        |_ E8rHL1RRAujyu.cea     (keylog_enabled)\n        |_ MTDLUlXsgIf.yni       (transport)\n        |_ O1a1lIxAqUskBdQUf.ebd (amsi_bypass)\n        |_ OiF6UrrFDBhgcwa.qgg   (inject_mode)\n        |_ QQECzNniEHuKHih2f.oli (delegate_enabled)\n        |_ TqTHomCER6vz.zks      (agent_label)\n        |_ tLkhmS2L3cg5.flo      (remote)\n        \n```\n\n###### Execution Paths\n\n**Traditional Kazuar Variant**\n\nUpon launching, the traditional version of Kazuar can take one of four paths of execution, [as described by Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/):\n\n- If launched with the **install** command-line argument, uses .NET Framework’s InstallHelper method to install itself as a service.\n- If started in a non-user interactive environment (i.e., no user interface), installs itself as a service using the .NET ServiceBase Class.\n- If executed with the **single** command-line argument or if running in a Mac or UNIX environment, launches an infinite loop that reads tasks from the **tsk** folder and resolves them until none remain. \n- If no arguments are provided and if running in a Windows environment, saves a DLL and injects it into the explorer.exe process. The DLL executable loads the malware’s executable and runs it within memory of the explorer.exe process. The Kazuar binary code refers to the DLL as \"the shellcode.\"\n\nAs shown in Exhibit 8, the process injection function of the traditional Kazuar variant proceeds as follows:\n- Makes a FindWindow API call to get a handle to the Shell\\_TrayWnd (Windows taskbar) process\n- Calls GetWindowThreadProcessID to get the thread ID of the Shell\\_TrayWnd window\n- Checks if the DLL loader exists in the base folder:\n    - If it does not exist, it writes it (encoded version hardcoded in Kazuar binary)\n- Once DLL loader exists, calls LoadLibrary to load the DLL\n- Calls GetProcAddress to find the address of the DLL loader-exported Install function \n- Calls SetWindowsHookEx to hook the Shell\\_TrayWnd window; the hook runs the \"Install\" function of the DLL loader when the Shell\\_TrayWnd window gets a message in the queue with WH\\_GETMESSAGE on the thread of the target window\n- Calls PostMessage  to post a message in the thread to trigger the hook instantly and load the DLL immediately\n- Sleeps for 0.1 seconds then calls UnhookWindowsHookEx to remove the hook and exit the program; execution is now passed to the injected DLL loader in explorer.exe\n\n ![alt text](/rest/files/download/66/f3/7a/9414dd315d65a3b16ba48441cfcee331075b5729c959991157bd27161c/Exhibit9.PNG)   \n _Exhibit 8: Process Injection of Traditional Kazuar Into explorer.exe Process_\n\n**New Kazuar Variant**\n\nThe new Kazuar variant has four execution paths that depend on the configured **inject_mode** parameter rather than passed as a command-line argument:\n\n- If **inject_mode** is **single**, Kazuar sets a mode variable to \"solver\" if started in user interactive mode or \"system\" if not. Kazuar checks if the current process is mshta.exe (Microsoft HTML application host). If so, Kazuar enumerates all top-level windows on the screen and then hooks and hides the windows. iDefense assesses this is to determine the results of the code run from mshta.exe. \n\n Kazuar then sets up the REMO (remote), KEYL (keylogger), or SOLV (task solving) threads. Also sets the MIND thread that monitors for processes with names containing:\n  - cmdvrt32.dll (Comodo Antivirus) \n  - sbiedll.dll (Sandboxie)\n  - sxin.dll (360 Total Security)\n  - process monitor\n   - wireshark\n   - fiddler\n\n- If **inject_mode** is **remote**, Kazuar repeats the same process as above but only starts the REMO thread to listen for tasks from other Kazuar instances.\n\n- If started in **non-interactive mode**, Kazuar sets up REMO and INJE (injection) threads and then sleeps.\n\n- If none of the above conditions matches, Kazuar checks if it is already running in explorer.exe. If not, it repeats the check to see if it is running the  process mshta.exe and performs the same subsequent activity. Kazuar then injects into explorer.exe using the same method as the traditional Kazuar, described above.\n\nThe new Kazuar variant has three other **inject_mode** values used to inject into transport processes (i.e., used to communicate with the C2 server): \n\n-  If **inject_mode** is **inject**, Kazuar reads the transport processes from the transport configuration file as targets for injection. If there is no transport process present, Kazuar uses the default browser process; if defined, it uses iexplore.exe. \n\n Kazuar checks for the mutex in the target transport process to see if Kazuar is already running. If not, Kazuar opens the transport process using the OpenProcess API call and checks whether it is running under WOW64 with IsWow64Process. \n\n Kazuar then creates a new memory section with RWX protection using NtCreateSection, maps a view of the previously created section to the local Kazuar process with RW protection, and maps the section to the transport process with RX permissions. Kazuar writes the shellcode to the mapped section in the local process and creates a remote thread in the transport process using CreateRemoteThread, pointing the thread to the mapped view to trigger the shellcode.\n\n- If **inject_mode** is **zombify**, Kazuar injects into the user's default browser; if this fails, it injects into svchost.exe. Kazuar uses the [early bird technique](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) to inject itself into the selected process\n\n-  If **inject_mode** is **combined**, Kazuar first attempts to inject using the **inject** process; if this fails, it attempts the **zombify** process.\n\n\n###### AMSI Bypass \n\n**New Kazuar Variant**\n\nBefore selecting an execution path, the new Kazuar variant calls a function that bypasses the [Antimalware Scan Interface (AMSI)](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)—a way for any Windows application to integrate with the installed antimalware product. The AMSI bypass function is shown in Exhibit 9; it was not available in the traditional Kazuar variant.\n\n![alt text](/rest/files/download/e3/46/cb/9adb5488dfda273e37ca6462009bebae7cef14770849d088cc9afc26e1/amsi.PNG)  \n_Exhibit 9: New Kazuar Variant's AMSI Bypass Function_\n\n[ESET previously reported](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/) on BELUGASTURGEON using AMSI bypass functionality in its PowerShell loaders, and [iDefense has previously analyzed](#/node/intelligence_report/view/9bf2fc44-570d-40ad-b81a-744141ed443e) PowerShell scripts containing AMSI bypass functionality to load BELUGASTURGEON's [securlsa.chk](#/node/malware_family/view/e55ad229-6484-4be3-bf3e-568c96a05b82) backdoor.\n\nThe Kazuar function patches the beginning of [AmsiScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) to always return 80070057, which [translates to](https://docs.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) E\\_INVALIDARG (one or more arguments not valid). The previous PowerShell scripts always patched this buffer to return 1 (AMSI\\_RESULT\\_NOT\\_DETECTED). The new return value is the same value used by the open-source .NET exploitation library [SharpSploit](https://github.com/cobbr/SharpSploit/blob/1407108e638cde3e181c27cb269c8427723884b0/SharpSploit/Evasion/Amsi.cs) suggesting Kazuar developers adapted this functionality from open-source tooling.\n\n## Command Set Comparison\n\n**Traditional Kazuar Variant**\n\nThe following commands, [documented by Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) and verified by iDefense, are available in the traditional Kazuar variant: \n\n- **log:** Logs a specified debug message.  \n- **get:** Uploads files from a specified directory. Palo Alto Networks indicated operators can upload files based on their modified, accessed, and created timestamps.  \n- **put:** Writes a payload to the specified file.  \n- **cmd:**  Executes the specified command, writes the output to a temporary file, and uploads the temporary file to the C2 server.    \n- **sleep:** Sleeps for the specified time.  \n- **upgrade:** Changes the current executable’s file extension to .old and writes the newly provided executable in its place.  \n- **scrshot:** Takes a screenshot of the visible screen and saves it to the specified filename or a filename using the format: [year]-[month]-[day]-[hour]-[minute]-[second]-[millisecond].jpg. Then uploads the file to the C2 server.  \n- **camshot:** Creates a Window called “WebCapt” to capture an image from an attached webcam, copies the image to the clipboard, and writes the image to a specified file or a filename using the format: [year]-[month]-[day]-[hour]-[minute]-[second]-[millisecond].jpg. Then uploads the file to the C2 server.  \n- **uuid:** Sets the unique agent identifier by providing a specific GUID.  \n- **interval:** Sets the transport intervals (minimum and maximum time intervals) between C2 communications.  \n- **server:** Sets the C2 servers by providing a list of URLs.  \n- **transport:** Sets the transport processes by providing a list of processes where Kazuar injected its code and executed within.  \n- **autorun:** Sets the autorun type—DISABLED, WINLOGON, POLICIES, HKCURUN, RUNONCE, LOADKEY, or STARTUP—as discussed earlier. Kazuar accept the following strings for this command:  \n    - **remote:** Configures remote API settings by specifying URI prefix and port to listen on. While the port used varied between the analyzed samples, iDefense only observed the HTTP prefix used, which instructs Kazuar to act as an HTTP server. The threat actor can then interact with the compromised system using inbound HTTP requests.  \n    - **info:** Gathers system information referred to as: Agent information, System information, User information, Local groups and members, Installed software, Special folders, Environment variables, Network adapters, Active network connections, Logical drives, Running processes, and Opened windows.  \n- **copy:** Copies the specified file to a specified location. Also allows the C2 infrastructure to supply a flag to overwrite the destination file, if it already exists.  \n- **move:** Moves the specified file to a specified location. Also allows the C2 infrastructure to supply a flag to delete the destination file, if it exists.  \n- **remove:** Deletes a specified file. Allows the C2 infrastructure to supply a flag to securely delete a file by overwriting the file with random data before deleting the file.  \n- **finddir:** Finds a specified directory and lists its files including the created and modified timestamps, the size, and file path for each of the files in the directory.  \n- **kill:** Kills a process by name or by process identifier (PID).  \n- **tasklisk:** Lists running processes. Uses a WMI query of `select * from Win32_Process` for a Windows system but can also run `ps -eo comm,pid,ppid,user,start,tty,args` to obtain running processes from a UNIX system.  \n- **suicide:** Likely uninstalls Kazuar, but it is not implemented in the referenced samples.  \n- **plugin:** Installs plugin by loading a provided Assembly, saving it to a file whose name is the MD5 hash of the Assembly’s name, and calling the Start method.  \n- **plugout:** Removes a plugin based on the Assembly’s name.  \n- **pluglist:** Gets a list of plugins and determines whether they are “working” or “stopped.”  \n- **run:** Runs a specified executable with supplied arguments and saves its output to a temporary file. Then loads the temporary file to the C2 server.  \n\nIn this Kazuar variant, the C2 server sends the tasks as XML-formatted data containing an action identifier or integer; the numeric action ID is  then translated into the corresponding command from the above set.\n\n**New Kazuar Variant**\n\nThe new Kazuar variant replaces these numeric action IDs with strings for the command names. The following commands have similar functionality in the new variant as they did in the traditional variant:\n\n- **info**\n- **scrshot**\n- **run**\n- **move**\n- **get**\n- **log**\n- **put**\n- **sleep**\n- **kill**\n- **copy**\n\nDevelopers added the following commands to the new variant:\n\n- **steal:** Steal passwords, history, or proxy lists from the following services: FileZilla, Chromium, Mozilla, Outlook, WinSCP, Git, or from the system.  \n- **config:** Set and update Kazuar configuration values, as described in the *Configuration Comparison* section below.  \n- **delegate:** Forward command to remote Kazuar instance using a named pipe and store result in delegated .zip file, as described in the *Command-and-Control Communication* section below under named pipe communications.\n- **psh:**  Execute PowerShell command.\n- **regwrite:** Create Registry key.\n- **regdelete:** Delete Registry key.\n- **vbs:** Execute VBS script with cscript.exe.\n- **regquery:** Query Registry key.\n- **find:** Enumerate a directory; replaces **finddir** command in traditional Kazuar.\n- **forensic:** Enumerate Registry autorun keys, the Program Compatibility Assistant, and the Windows Explorer User Assist Registry keys to determine which program(s) has run on the compromised device.\n- **http:** Execute an HTTP request and save the response to file http<3digits>.rsp.\n- **jsc:** Execute a JavaScript file with cscript.exe.\n- **del:** Delete a file; replaces **remove** command in traditional Kazuar.\n- **unattend:** Enumerate the compromised device's [unattend.xml](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs), sysprep.xml, and web.config files to obtain credentials.\n- **schlist:** Enumerate list of scheduled tasks using the [TaskService](https://docs.microsoft.com/en-us/windows/win32/taskschd/taskservice) object.\n- **wmiquery:** Execute a WMI query.\n- **wmicall:** Execute a WMI method.\n\nDevelopers removed several commands from the traditional Kazuar variant while incorporating the functionality into other commands or configuration settings:\n- The **upgrade** and **suicide** commands are replaced by the Registry editing commands (‘regdelete’ and ‘regwrite’)  now that  Kazuar is stored in a Registry key. \n- The values previously configured by the **uuid**, **jnterval**, **server**, and **transport** commands are now configured using the **config** command. \n- The list of running processes previously obtained with **tasklist** is now returned by **info** along with much more system information. \n- The **autorun** command is not required to configure persistence mechanisms now the Kazuar binary is stored in the Registry. \n- The **plugin** command is no longer necessary since much of the prior information-stealing functionality is implemented within the newer Kazuar. \n- The **remote** command (i.e., HTTP API functionality) has been replaced with task delegation. \n\nThe only functionality apparently not replicated in the new variant is the **camshot** command to take web cam snapshots.\n\nThe commands **schlist**, **wmiquery**, and **wmicall** were present in Kazuar sample AGN-AB-13 but not AGN-AB-03, suggesting the command set of the new variant is under development.\n\n## Configuration Comparison\n\n**Traditional Kazuar Variant**\n\nThe values configured in the traditional Kazuar variant's configuration are:\n\n- **Agent identifier:** Unique agent identifier (GUID format).  \n- **Executable path:**  Path of Kazuar binary on disk.  \n- **Storage path:** Base directory containing Kazuar configuration files.\n- **Fake visible name:** Kazuar filename.\n- **Description label:**  Empty in samples analyzed.\n- **Machine seed:** Seed value derived from System Directory.\n- **Parallel tasks:** Number of tasks to run in parallel.\n- **Last contact:** Last contact from C2 server.\n- **Autorun type:**  Persistence method (LNK file or Registry keys, as described in *Installation and Persistence* section).\n- **Transport interval:** Interval between C2 communications.\n- **Command servers:** C2 servers.\n- **Transport processes:** Process to injected into for C2 communications.\n\n**New Kazuar Variant**\n\nThe updated configuration reflects the broader range of functionality implemented in the new Kazuar variant. The values configured in the new variant's configuration are:\n\n- **Agent label:** Unique Agent Label of format `AGN-AB-<2 digits>`, iterated as updates are made to Kazuar.\n- **Agent UUID:** Unique agent identifier (GUID format).  \n- **Local seed:** Seed value derived from System UUID.\n- **Last contact:** Last contact from C2 server.\n- **Transport type:**  Protocol used for C2 communications; set to \"HTTP\" in both analyzed samples.\n- **Transport main interval:**  Interval between C2 communications.\n- **Transport failed interval:** Interval between failed C2 connections before attempting a retry.\n- **Transport proxy:**  C2 communication proxy; specifies URL, port, and variable to specify when proxy is enabled. This value was empty for both samples iDefense analyzed.\n- **Max server fails:** Number of failed attempts before quitting.\n- **Main servers:**  Primary C2 servers.\n- **Reserved servers:** Backup C2 servers.\n- **Agent regkey:** Registry key where packed Kazuar binary is stored.\n- **Storage root:** Base directory containing Kazuar configuration files.\n- **Config path:** Path to Kazuar configuration directory.\n- **Logs path:**: Path to Kazuar logs file.\n- **Keylogger path:** Path to Kazuar keylogger output file.\n- **Logs size:**  Current size of logs file.\n- **Inject mode:** Inject mode to define execution path and injection method (described in *Installation and Persistence* section).\n- **Solving threads:** Number of threads to run in parallel to solve tasks.\n- **Solving tries:** Maximum number of attempts to solve a task.\n- **Sending tries:** Maximum number of attempts to send task result to C2 server.\n- **Keylogger enabled:** Whether keylogger functionality is enabled (boolean).\n- **Task delegation enabled:** Whether task delegation functionality is enabled (boolean).\n- **AMSI bypass enabled:** Whether AMSI bypass functionality is enabled (boolean).\n- **Delegate system pipe:**  Pipe used to delegate tasks in system mode; also see  *Command-and-Control Communication* section.\n- **Delegate solver pipe:** Pipe used to delegate tasks in solver mode.\n- **Delegate sender pipe:** Pipe used to delegate tasks in sender mode.\n\nIndicating the new Kazuar version is under development, the following values are present in the new Kazuar variant sample AGN-AB-13 but not AGN-AB-03:\n- **Agent regkey**\n- **Delegate system pipe** \n- **Delegate solver pipe** \n- **Delegate sender pipe**\n\n## Command-and-Control Communication\n\n**Traditional Kazuar Variant**\n\nThe traditional Kazuar variant uses its C2 channel to send tasks to the backdoor, receive the results, and exfiltrate data. The variant can use multiple protocols, such as HTTP, HTTPS, FTP, or FTPS, as determined by the prefixes of the hardcoded C2 URLs. [iDefense identified one sample](#/node/intelligence_alert/view/6cc805d7-cb77-443d-afea-d052916fa602) that uses the \"file://\" prefix to communicate across internal nodes in a compromised network, likely via SMB using another Kazuar sample as a transfer agent to forward tasks and results between the C2 server and the first Kazuar sample.\n\n**New Kazuar Variant**\n\nThe new Kazuar samples do not support FTP communications; instead, C2 communications are performed over HTTP(S). Exhibit 10 shows the function that defines the C2 servers:\n\n![alt text](/rest/files/download/e2/97/51/d4d171d120ec49db0128d5c6119399eeb12bf245227e82708290fcf6c3/c2.PNG)  \n_Exhibit 10: Defining C2 Servers in New Kazuar Variant_\n\nThe first two URLs in Exhibit 10 are the \"Main servers\" referred to in the sample's configuration; they act as the primary C2 servers. The third URL is the \"Reserved server\" that Kazuar uses as a backup, if it cannot reach the primary C2s. The fourth URL is the \"Last Chance URL\" that Kazuar uses if communication with the primary and backup C2 servers is lost. \n\nFor sample AGN-AB-03, shown in Exhibit 10, a dummy value (\"www.google.com\") is provided; in sample AGN-AB-13, no value is configured for the \"Last Chance URL.\" However, Kazuar operators can set this to any value. iDefense assesses the operators may choose to use a legitimate web service, such as Pastebin, which allows them to maintain persistence if their own C2 infrastructure is unavailable. [BELUGASTURGEON has previously used a Pastebin project](#/node/intelligence_alert/view/92154a2c-f077-4f16-92d5-2349984ad03e) for C2 communications with its Carbon backdoor.\n\nThe C2 servers identified in the two analyzed samples are:\n\n**AGN-AB-13:**\n - Main servers:\n    - `https://www.rezak[.]com/wp-includes/pomo/pomo.php`\n    - `https://www.hetwittezwaantje[.]nl/wp-includes/rest-api/class-wp-rest-client.php`\n - Reserved server:\n    - `https://aetapet[.]com/wp-includes/IXR/class-IXR-response.php`\n\n**AGN-AB-03:**\n - Main servers:\n    - `https://www.actvoi[.]org/wordpress/wp-includes/fonts/icons/`\n    - `https://www.datalinkelv[.]com/wp-includes/js/pomo/`\n    - `https://www.actvoi.org/wordpress/wp-includes/fonts/`\n - Reserved server:\n    - `https://www.downmags[.]org/wp-includes/pomo/wp/`\n\nIn the new version of Kazuar, HTTP requests are authenticated using an .AspNet.Cookies header rather than an AuthToken cookie. Tasks are forwarded to remote Kazuar instances using the task delegation functionality instead of the remote HTTP API. The task delegation functionality uses named pipes to communicate between Kazuar samples. Exhibit 11 shows the function to generate the pipe name used for communications.\n\n![alt text](/rest/files/download/15/51/62/fe277b22a617898a35647dfe6e6b2d4943dfbeb7e4380c01058995d960/pipe.PNG)   \n_Exhibit 11: New Kazuar Variant Task Delegation Named Pipe_\n\nThe pipe names are GUID values derived from the string `pipename-[system/solver/sender]-AgentLabel` where the values for system, solver, or sender are set based on the **inject_mode**, as described in the *Installation and Persistence* section. \n- **sender** corresponds to the Kazuar instance sending the task.\n- **solver** is set for the Kazuar instance receiving tasks. \n- **system** corresponds to a Kazuar instance started in non-interactive mode. \n\nExhibit 12 shows the function used to send tasks to and receive task results from remote Kazuar instances.\n\n![alt text](/rest/files/download/ac/ec/11/ad97d520210ac43da1c7edd6d91fc4cb59f3e8dd459016a0d335bd0686/pipe2.PNG)  \n_Exhibit 12: New Kazuar Variant Task Delegation Functionality_\n\nTo generate a name for the named pipe, Kazuar uses the `pipename-mode AgentLabel`  format described above replacing \"mode\" with system, solver, or sender as described above and connecting the values for CreateNamedPipe with ConnectNamedPipe. Messages sent over the pipe are encrypted and must begin with PING, PONG, TASK, RESULT, or ERROR. The PING prefix acts as a handshake and expects a PONG response, the TASK prefix is used to send tasks, and the RESULT and ERROR prefixes respond with the results of tasks or any errors.\n\n## Outlook\nAlthough BELUGASTURGEON has made high-level updates to the Kazuar backdoor over the years, the samples from August 2019 and February 2020 represent the first significant update to the malware's codebase since its discovery three years ago. The developers removed the requirement for a plugin framework by incorporating functionality that allows for a wide range of espionage activity such as keylogging, credential stealing, and forensics. Storing the sample as a Registry key rather than on disk decreases the risk of detection in comparison to the older variant.\n\nAdding task delegation functionality makes Kazuar a peer of the group's more sophisticated Carbon and Uroborus backdoors. The group's relatively clumsy prior method of chaining together proxy commands from a C2 server to a Kazuar instance on an internal node without network connection meant task files were written to disk on the internal proxy node. The new functionality forwards tasks directly over named pipes, as done in the group's other backdoors.\n\nDifferences between the August 2019 and February 2020 samples—with the addition of commands and updated configuration specifications—clearly indicate Kazuar is under active development and will continue to be used by BELUGASTURGEON in espionage campaigns.",
    "mitigation": "Check logs for the following indicators of compromise:\n- `182d5b53a308f8f3904314463f6718fa2705b7438f751581513188d94a9832cd` (Kazuar packed)\n- `60f47db216a58d60ca04826c1075e05dd8e6e647f11c54db44c4cc2dd6ee73b9` (Kazuar packed)\n-  `41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb` (Kazuar unpacked)\n- `1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4` (Kazuar unpacked)\n- https://www[.]rezak[.]com/wp-includes/pomo/pomo[.]php\n- https://www[.]hetwittezwaantje[.]nl/wp-includes/rest-api/class-wp-rest-client[.]php\n- https://aetapet[.]com/wp-includes/IXR/class-IXR-response[.]php\n- https://www.actvoi[.]org/wordpress/wp-includes/fonts/icons/\n- https://www.datalinkelv[.]com/wp-includes/js/pomo/9https://www.actvoi.org/wordpress/wp-includes/fonts/\n- https://www.downmags[.]org/wp-includes/pomo/wp/\n\nKazuar developers configure the C2 URIs for each sample; instead monitor for the following more generic indicators:\n-\tRepeated connections to WordPress sites not commonly visited by users in the network, particularly when the URI contains `/wp-includes/pomo/`. \n-\tNamed pipes with names matching the format `///pipe//<GUID>` particularly when used by explorer.exe.\n\nThe following YARA rule matches the analyzed Kazuar samples and may be used for detection or hunting purposes only:\n\n```\nrule new_kazuar_unpacked {\n    meta:\n        desc = \"Detects functions used by new Kazuar Variant.\"\n        author = \"iDefense\"\n        hash1 = \"41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb\"\n        hash2 = \"1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4\"\n\n    strings:\n\n    $a1 = \"Agent.Original.exe\" wide ascii\n    $a2 = \"Musky.exe\" wide ascii\n    $b_amsi = { 28 [4] 3A 01 00 00 00 2A 72 [4] 28 [4] 28 [4] 0A 06 7E [4] 28 [4] 39 [4] 2A 06 72 [4] 28 [4] 28 [4] 0B 07 7E [4] 28 [4] 39 [4] 2A 28 [4] 39 [4] 1C 8D [4] 25 D0 [4] 28 [4] 0C 38 [4] 1E 8D [4] 25 D0 [4] 28 [4] 0C 16 0D 08 8E 69 6A 28 }\n    $b_encoding1 = { 020A061F09594576000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??00000038E70000001F412A1F422A1F432A1F442A1F452A1F462A1F472A1F482A1F492A1F4A2A1F4B2A1F4C2A1F4D2A1F4E2A1F4F2A1F502A1F512A1F522A1F532A1F542A1F552A1F562A1F572A1F582A1F592A1F5A2A1F612A1F622A1F632A1F642A1F652A1F662A1F672A1F682A1F692A1F6A2A1F6B2A1F6C2A1F6D2A1F6E2A1F6F2A1F702A1F712A1F722A1F732A1F742A1F752A1F762A1F772A1F782A1F792A1F7A2A1F7E2A1F252A1F3A2A1F2E2A1F202A1F7C2A1F7B2A1F7D2A1F2D2A1F3D2A1F3C2A1F3E2A1F5C2A1F0A2A1F092A1F302A1F312A1F322A1F332A1F342A1F352A1F362A1F372A1F382A1F392A022A}\n    $b_encoding2 = {73[4]0A160B38[4]02076F[4]28[4]0C0608D16f[4]260717580B07026F[4]3f[4]066F[4]2A}\n    $b_pipename = {03 28 [4] 39 07 00 00 00 28 [4] 10 01 02 6F [4] 0A 72 [4] 28 [4] 06 72 [4] 28 [4] 03 28 [4] 0B 28 [4] 07 6F [4] 0C 28 [4] 08 6F [4] 0D 1F 2A 13 04 1F 11 13 05 1F 15 13 06 16 13 08 38 [4] 11 04 11 05 5A 20 [4] 20 [4] 61 5F D2 13 04 11 04 11 06 58 20 [4] 20 [4] 61 5F D2 13 04 09 11 08 8F [4] 25 47 11 04 61 D2 52 11 08 17 58 13 08 11 08 09 8E 69 3F [4] 12 07 09 28 [4] 12 07 72 [4] 28 [4] 28 [4] 6F [4] 2A}\n\n    condition: uint16(0) == 0x5a4d and (1 of ($a*) and 3 of ($b_*)) or (4 of ($b_*)) and filesize < 350KB\n}\n```",
    "severity": 4,
    "abstract": "In February 2021, iDefense analyzed two samples of BELUGASTURGEON's Kazuar backdoor and identified significant codebase differences when compared to older Kazuar samples. Although BELUGASTURGEON has been making high-level changes to Kazuar and using the backdoor in espionage campaigns since at least 2017, the August 2020 and February 2021 samples contain the first significant updates to the malware's codebase since the malware family was identified.\n\nThe updated Kazuar variant introduces commands that support a range of espionage activity, including keylogging, credential stealing, and forensics, without requiring a plugin framework as in prior  Kazuar samples. Using task forwarding, BELUGASTURGEON operators can now communicate with Kazuar instances without using Internet connectivity; this enhanced peer-to-peer (P2P) functionality advances Kazuar to the level of some of BELUGASTURGEON's more sophisticated backdoors.\n\nWhen comparing the two August 2020 and February 2021 Kazuar samples, iDefense identified command set and configuration updates that indicate Kazuar is under active development for future use in BELUGASTURGEON espionage campaigns."
}


RES_JSON_IR = {
    "created_on": "2021-03-26T20:09:55.000Z",
    "display_text": "Russian Responses to Geopolitical Challenges Include Cyber-Threat Activity against Energy Industry Entities",
    "dynamic_properties": {},
    "index_timestamp": "2022-02-22T23:42:04.231Z",
    "key": "749eebc0-8d03-4384-a4c5-5e309735b311",
    "last_modified": "2022-02-08T18:27:58.000Z",
    "last_published": "2021-03-26T20:09:55.000Z",
    "links": [
        {
            "created_on": "2022-01-07T19:02:52.000Z",
            "display_text": "Feared Russian Invasion of Ukraine Could Have Global Impacts in Cyberspace",
            "key": "b4511cfd-3d13-4092-9275-35b058c246ec",
            "relationship": "mentions",
            "relationship_created_on": "2022-01-07T19:02:52.000Z",
            "relationship_last_published": "2022-01-07T19:02:52.000Z",
            "type": "intelligence_alert",
            "uuid": "edcb0ff2-6598-45fb-ae1c-4eb273032f56",
            "href": "/rest/document/v0/edcb0ff2-6598-45fb-ae1c-4eb273032f56"
        },
        {
            "created_on": "2021-01-06T16:53:13.000Z",
            "display_text": "Suspected Russian Breaches of US Government and Critical Infrastructure Align with Russian Strategic Interests",
            "key": "d01c0e25-ed38-4312-b679-8854bf29b5d2",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_report",
            "uuid": "eb77c712-fcfd-48f6-9533-baa18131fb62",
            "href": "/rest/document/v0/eb77c712-fcfd-48f6-9533-baa18131fb62"
        },
        {
            "created_on": "2022-02-22T21:33:12.000Z",
            "display_text": "SITREP: Ukraine Crisis",
            "key": "0ae44727-6fef-4dcb-9928-8eed0c3bcd3e",
            "relationship": "mentions",
            "relationship_created_on": "2022-02-22T23:39:39.000Z",
            "relationship_last_published": "2022-02-22T23:39:39.000Z",
            "type": "intelligence_alert",
            "uuid": "f1862833-80de-4880-a180-11fad373e896",
            "href": "/rest/document/v0/f1862833-80de-4880-a180-11fad373e896"
        },
        {
            "created_on": "2016-07-21T22:42:19.000Z",
            "display_text": "Texaco",
            "key": "Texaco",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "d9e7c8b1-bce2-43fa-a3ae-bc1caa0f0d22",
            "href": "/rest/fundamental/v0/d9e7c8b1-bce2-43fa-a3ae-bc1caa0f0d22"
        },
        {
            "created_on": "2015-08-21T00:00:00.000Z",
            "display_text": "CSX",
            "key": "CSX",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "4c1ea572-f5d7-46b7-870e-e81821f5316c",
            "href": "/rest/fundamental/v0/4c1ea572-f5d7-46b7-870e-e81821f5316c"
        },
        {
            "created_on": "2007-04-12T00:00:00.000Z",
            "display_text": "Turkmenistan",
            "key": "Turkmenistan",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "a130bfe9-390d-4c83-b75e-c1f050e41820",
            "href": "/rest/fundamental/v0/a130bfe9-390d-4c83-b75e-c1f050e41820"
        },
        {
            "created_on": "2003-09-27T00:00:00.000Z",
            "display_text": "Germany",
            "key": "Germany",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "ee03c799-980c-4998-8240-dc400eebe325",
            "href": "/rest/fundamental/v0/ee03c799-980c-4998-8240-dc400eebe325"
        },
        {
            "created_on": "2003-12-15T00:00:00.000Z",
            "display_text": "Denmark",
            "key": "Denmark",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "f77916a1-655f-4424-91c9-124a289c6abd",
            "href": "/rest/fundamental/v0/f77916a1-655f-4424-91c9-124a289c6abd"
        },
        {
            "created_on": "2012-08-13T16:42:49.000Z",
            "display_text": "Iran",
            "key": "Iran",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "516a2391-b1b6-42e2-adce-ad3410cb15f8",
            "href": "/rest/fundamental/v0/516a2391-b1b6-42e2-adce-ad3410cb15f8"
        },
        {
            "created_on": "2016-06-16T16:04:46.000Z",
            "display_text": "Guccifer",
            "key": "Guccifer",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_actor",
            "uuid": "1e01d510-6b3a-47a7-ab95-967105695d1f",
            "href": "/rest/fundamental/v0/1e01d510-6b3a-47a7-ab95-967105695d1f"
        },
        {
            "created_on": "2015-08-03T15:06:38.000Z",
            "display_text": "JACKMACKEREL",
            "key": "JACKMACKEREL",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "24a38270-949f-442a-aac6-53a99ef1ea70",
            "href": "/rest/fundamental/v0/24a38270-949f-442a-aac6-53a99ef1ea70"
        },
        {
            "created_on": "2017-06-16T16:02:30.000Z",
            "display_text": "SANDFISH",
            "key": "SANDFISH",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "40d2cf30-237a-467b-826d-390f12cc27f0",
            "href": "/rest/fundamental/v0/40d2cf30-237a-467b-826d-390f12cc27f0"
        },
        {
            "created_on": "2019-06-17T12:07:03.000Z",
            "display_text": "ZANDER",
            "key": "ZANDER",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "a363a7ca-1d5d-4477-9ce9-e9259cb888e4",
            "href": "/rest/fundamental/v0/a363a7ca-1d5d-4477-9ce9-e9259cb888e4"
        },
        {
            "created_on": "2016-09-13T16:26:36.000Z",
            "display_text": "Fancy Bears Hack Team",
            "key": "Fancy Bears Hack Team",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "ec08d6ad-5c32-44b9-bde3-bdfe9e1c76c5",
            "href": "/rest/fundamental/v0/ec08d6ad-5c32-44b9-bde3-bdfe9e1c76c5"
        },
        {
            "created_on": "2013-03-25T18:40:44.000Z",
            "display_text": "BLACK GHOST KNIFEFISH",
            "key": "BLACK GHOST KNIFEFISH",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "27332f70-302c-491a-85f2-3714218296b8",
            "href": "/rest/fundamental/v0/27332f70-302c-491a-85f2-3714218296b8"
        },
        {
            "created_on": "2018-01-30T19:03:24.000Z",
            "display_text": "GandCrab",
            "key": "GandCrab",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "8f5bc13f-ee79-4ee6-9cf2-d9a6318b5ed4",
            "href": "/rest/fundamental/v0/8f5bc13f-ee79-4ee6-9cf2-d9a6318b5ed4"
        },
        {
            "created_on": "2018-12-04T19:10:02.000Z",
            "display_text": "Defense & Public Safety",
            "key": "Defense & Public Safety",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "vertical",
            "uuid": "b0b0d8bd-1c9f-4062-9c51-f33a79c736af",
            "href": "/rest/fundamental/v0/b0b0d8bd-1c9f-4062-9c51-f33a79c736af"
        },
        {
            "created_on": "2021-02-15T15:38:34.000Z",
            "display_text": "SANDFISH Continues to Exploit Exim Mail Transfer Agents",
            "key": "82319acb-65eb-48b3-bbb3-61b34f53addf",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "55004ca2-e598-460f-bb0c-8ef6f37b7bca",
            "href": "/rest/document/v0/55004ca2-e598-460f-bb0c-8ef6f37b7bca"
        },
        {
            "created_on": "2020-07-24T21:03:43.000Z",
            "display_text": "US Officials Warn of Threats to Critical Infrastructure and Political Entities",
            "key": "c0373503-7624-441a-b59b-b2163fc04ea7",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "575c5eef-0784-46cd-bf67-8e256d0c2fc7",
            "href": "/rest/document/v0/575c5eef-0784-46cd-bf67-8e256d0c2fc7"
        },
        {
            "created_on": "2020-10-28T17:35:45.000Z",
            "display_text": "Russia-Linked BLACK GHOST KNIFEFISH Continues NTLM Harvesting Campaign, 2019 to 2020",
            "key": "580f8d37-f834-4331-ad79-c05fd96e0f78",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "c3ad35ce-1443-4ef2-b3e2-1a3548605528",
            "href": "/rest/document/v0/c3ad35ce-1443-4ef2-b3e2-1a3548605528"
        },
        {
            "created_on": "2017-01-07T16:26:16.000Z",
            "display_text": "Aggressive Defensiveness: Russian Information Operations against the US Political System",
            "key": "48d85d37-8adf-41c2-9bbe-d23b335a3bc3",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "79e6008d-ddd4-472d-b574-5ad1a769e096",
            "href": "/rest/document/v0/79e6008d-ddd4-472d-b574-5ad1a769e096"
        },
        {
            "created_on": "2018-04-17T19:57:28.000Z",
            "display_text": "Joint US-UK Threat Alert Warns of Russian Government Targeting of Network Infrastructure Devices Worldwide",
            "key": "fa7dd2fa-84ca-4066-90fb-04f91b39c07b",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "21ab89f6-1ac1-4cc3-83f6-233a5d7473cf",
            "href": "/rest/document/v0/21ab89f6-1ac1-4cc3-83f6-233a5d7473cf"
        },
        {
            "created_on": "2020-08-19T19:31:42.000Z",
            "display_text": "Roundup of Notable Ransomware Events with a Focus on Energy and Utility Sectors (January 2020 – August 2020)",
            "key": "3129d754-caf2-425f-8684-3b5edc581776",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_report",
            "uuid": "999b6c55-3cb8-4372-affb-bcc9c47dd95b",
            "href": "/rest/document/v0/999b6c55-3cb8-4372-affb-bcc9c47dd95b"
        },
        {
            "created_on": "2021-06-16T18:23:09.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 16 June 2021",
            "key": "b0dcf12f-1107-4ecc-ae1e-b558f26c0198",
            "relationship": "mentions",
            "relationship_created_on": "2021-06-16T18:23:09.000Z",
            "relationship_last_published": "2021-06-16T18:23:09.000Z",
            "type": "intelligence_alert",
            "uuid": "1c808eb6-0bfb-4468-8f16-321b51855c3e",
            "href": "/rest/document/v0/1c808eb6-0bfb-4468-8f16-321b51855c3e"
        },
        {
            "created_on": "2020-08-10T15:46:02.000Z",
            "display_text": "DoppelPaymer",
            "key": "DoppelPaymer",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "7403e958-17b1-4928-b876-7269da5f76b6",
            "href": "/rest/fundamental/v0/7403e958-17b1-4928-b876-7269da5f76b6"
        },
        {
            "created_on": "2006-02-16T00:00:00.000Z",
            "display_text": "Noble",
            "key": "Noble",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "3781e538-9ff4-4c1e-823e-288698c926d3",
            "href": "/rest/fundamental/v0/3781e538-9ff4-4c1e-823e-288698c926d3"
        },
        {
            "created_on": "2016-11-23T15:14:22.000Z",
            "display_text": "Odebrecht",
            "key": "Odebrecht",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "c7bb4db8-d2af-4aff-97b0-b397b0419296",
            "href": "/rest/fundamental/v0/c7bb4db8-d2af-4aff-97b0-b397b0419296"
        },
        {
            "created_on": "2017-01-11T14:52:30.000Z",
            "display_text": "NATO",
            "key": "NATO",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "830eece9-82bd-4cb8-ab2a-123e855377eb",
            "href": "/rest/fundamental/v0/830eece9-82bd-4cb8-ab2a-123e855377eb"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Noble Energy",
            "key": "Noble Energy",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "72937e93-85c9-4c27-8ee7-fc565f7609c8",
            "href": "/rest/fundamental/v0/72937e93-85c9-4c27-8ee7-fc565f7609c8"
        },
        {
            "created_on": "2003-08-01T00:00:00.000Z",
            "display_text": "China",
            "key": "China",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "917ef603-93eb-4830-9dc3-8a4e4828b4c3",
            "href": "/rest/fundamental/v0/917ef603-93eb-4830-9dc3-8a4e4828b4c3"
        },
        {
            "created_on": "2003-08-01T00:00:00.000Z",
            "display_text": "Mexico",
            "key": "Mexico",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "a664e2ae-5c24-454f-a75b-3d24e9d80938",
            "href": "/rest/fundamental/v0/a664e2ae-5c24-454f-a75b-3d24e9d80938"
        },
        {
            "created_on": "2008-05-29T21:29:21.000Z",
            "display_text": "United Kingdom",
            "key": "United Kingdom",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "05d70c8e-c9e1-48a2-a30e-0228996d5df2",
            "href": "/rest/fundamental/v0/05d70c8e-c9e1-48a2-a30e-0228996d5df2"
        },
        {
            "created_on": "2021-03-03T16:08:19.000Z",
            "display_text": "CLOP",
            "key": "CLOP",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "d6f3dc92-0f8e-4a5c-b216-744976b0a5a9",
            "href": "/rest/fundamental/v0/d6f3dc92-0f8e-4a5c-b216-744976b0a5a9"
        },
        {
            "created_on": "2015-07-31T18:42:50.000Z",
            "display_text": "SNAKEMACKEREL",
            "key": "SNAKEMACKEREL",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "065336a6-651d-4f80-b8c2-9347f4486912",
            "href": "/rest/fundamental/v0/065336a6-651d-4f80-b8c2-9347f4486912"
        },
        {
            "created_on": "2016-10-19T17:39:17.000Z",
            "display_text": "BELUGASTURGEON",
            "key": "BELUGASTURGEON",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "fb53e479-54e1-4827-abb4-ae1ae1db53e2",
            "href": "/rest/fundamental/v0/fb53e479-54e1-4827-abb4-ae1ae1db53e2"
        },
        {
            "created_on": "2015-07-31T17:14:39.000Z",
            "display_text": "Federal Security Service of the Russian Federation (Федеральная служба безопасности Российской Федерации)",
            "key": "Federal Security Service of the Russian Federation (Федеральная служба безопасности Российской Федерации)",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "d96f3b14-462b-4ab4-aa04-23c7a2996611",
            "href": "/rest/fundamental/v0/d96f3b14-462b-4ab4-aa04-23c7a2996611"
        },
        {
            "created_on": "2017-01-03T18:16:36.000Z",
            "display_text": "Main Directorate of the General Staff of the Armed Forces of the Russian Federation (GRU)",
            "key": "Main Directorate of the General Staff of the Armed Forces of the Russian Federation (GRU)",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "675cb6f9-ecab-4c3f-a5c2-9d163d707500",
            "href": "/rest/fundamental/v0/675cb6f9-ecab-4c3f-a5c2-9d163d707500"
        },
        {
            "created_on": "2017-06-15T18:06:42.000Z",
            "display_text": "CRASHOVERRIDE",
            "key": "CRASHOVERRIDE",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "88704197-8308-4837-bd44-d2d46bd1ac1d",
            "href": "/rest/fundamental/v0/88704197-8308-4837-bd44-d2d46bd1ac1d"
        },
        {
            "created_on": "2018-01-02T01:07:28.000Z",
            "display_text": "Triton",
            "key": "Triton",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "68ff5563-b940-4d0e-9bc2-535990747f9b",
            "href": "/rest/fundamental/v0/68ff5563-b940-4d0e-9bc2-535990747f9b"
        },
        {
            "created_on": "2015-07-24T16:45:47.000Z",
            "display_text": "Media",
            "key": "Media",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "vertical",
            "uuid": "bb9bdd2d-180e-41d2-b5c8-08a2062998ca",
            "href": "/rest/fundamental/v0/bb9bdd2d-180e-41d2-b5c8-08a2062998ca"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Oil & Gas",
            "key": "Oil & Gas",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "vertical",
            "uuid": "0aa7b554-b07f-42b4-a904-92da408d9be5",
            "href": "/rest/fundamental/v0/0aa7b554-b07f-42b4-a904-92da408d9be5"
        },
        {
            "created_on": "2017-06-28T18:14:43.000Z",
            "display_text": "GreyEnergy",
            "key": "GreyEnergy",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_campaign",
            "uuid": "b0585685-aaac-44b4-b93b-733d30eaeb6e",
            "href": "/rest/fundamental/v0/b0585685-aaac-44b4-b93b-733d30eaeb6e"
        },
        {
            "created_on": "2021-03-23T17:35:09.000Z",
            "display_text": "What Happened to SANDFISH’s GreyEnergy?",
            "key": "882ed9d3-9d7c-4004-9f3c-cf72300eced1",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "f0289fe9-c076-437b-984f-71f17d6f7950",
            "href": "/rest/document/v0/f0289fe9-c076-437b-984f-71f17d6f7950"
        },
        {
            "created_on": "2019-10-22T19:26:22.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for October 22, 2019",
            "key": "08595e22-0390-43ec-968d-c910e5c4d621",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "6f668357-bd6a-4a04-876d-20bd840e0788",
            "href": "/rest/document/v0/6f668357-bd6a-4a04-876d-20bd840e0788"
        },
        {
            "created_on": "2017-06-27T20:55:03.000Z",
            "display_text": "Global Petya Ransomware Outbreak Cripples Major Companies Worldwide",
            "key": "10c18a7a-741f-43ba-b0a9-24fd42684ccf",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "e4cac05c-83a4-40e3-b8b2-190c7c405ee0",
            "href": "/rest/document/v0/e4cac05c-83a4-40e3-b8b2-190c7c405ee0"
        },
        {
            "created_on": "2021-03-10T20:56:12.000Z",
            "display_text": "CLOP Ransomware Operators Leak CGG Data on Name-and-Shame Site on 1 March 2021",
            "key": "a626ee22-fe70-4ca6-a18b-0270fb0229c5",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "c069f7c1-7b22-4713-a1d9-b1ba041602e8",
            "href": "/rest/fundamental/v0/c069f7c1-7b22-4713-a1d9-b1ba041602e8"
        },
        {
            "created_on": "2021-03-10T16:32:46.000Z",
            "display_text": "CLOP Ransomware Operators Leak CSX Documents on Name-and-Shame Site on 2 March 2021",
            "key": "4b0cd263-8e2b-4a0e-b6f8-7d9b7d623d6c",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "0e1a64c4-e283-457b-b615-9863436b0dbd",
            "href": "/rest/fundamental/v0/0e1a64c4-e283-457b-b615-9863436b0dbd"
        },
        {
            "created_on": "2018-11-06T20:59:09.000Z",
            "display_text": "Account GandCrab Burnishes Patriotic Credentials By Showing Sympathy for Syria",
            "key": "3b4e7772-29e4-424a-9b41-3b9d6759c7f6",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "ff63b317-2de3-4ba3-828a-d294eab5b91f",
            "href": "/rest/fundamental/v0/ff63b317-2de3-4ba3-828a-d294eab5b91f"
        },
        {
            "created_on": "2021-03-23T17:41:46.000Z",
            "display_text": "US and Russia Trade Threats, Raising Fears of Further Cyber Threat Activity",
            "key": "762ebeea-4cc1-45c4-af25-67ddcccb8602",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-30T23:18:03.000Z",
            "relationship_last_published": "2021-03-30T23:18:03.000Z",
            "type": "intelligence_alert",
            "uuid": "3ee020e9-c64f-4c3f-8162-73f80ad85863",
            "href": "/rest/document/v0/3ee020e9-c64f-4c3f-8162-73f80ad85863"
        },
        {
            "created_on": "2021-04-21T17:48:14.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 21 April 2021",
            "key": "e348ab03-75d3-46ba-b00c-7a965da65f5d",
            "relationship": "mentions",
            "relationship_created_on": "2021-04-21T17:48:14.000Z",
            "relationship_last_published": "2021-04-21T17:48:14.000Z",
            "type": "intelligence_alert",
            "uuid": "2149d045-5085-419f-a1c8-1b6acb2d9609",
            "href": "/rest/document/v0/2149d045-5085-419f-a1c8-1b6acb2d9609"
        },
        {
            "created_on": "2021-10-08T01:20:03.000Z",
            "display_text": "Arrest of Russian Cybersecurity Firm's Founder Highlights Russia’s Complex and Dangerous Business Environment",
            "key": "fe0c6c41-9a7e-492a-a268-700b0d41ed6b",
            "relationship": "mentions",
            "relationship_created_on": "2021-10-08T01:20:03.000Z",
            "relationship_last_published": "2021-10-08T01:20:03.000Z",
            "type": "intelligence_alert",
            "uuid": "7af3126f-2f88-4941-bf09-3521cb7889b7",
            "href": "/rest/document/v0/7af3126f-2f88-4941-bf09-3521cb7889b7"
        },
        {
            "created_on": "2004-08-17T00:00:00.000Z",
            "display_text": "Turkey",
            "key": "Turkey",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "9da2b237-dfde-4c8e-a0c1-158cbb15aa3f",
            "href": "/rest/fundamental/v0/9da2b237-dfde-4c8e-a0c1-158cbb15aa3f"
        },
        {
            "created_on": "2003-12-15T00:00:00.000Z",
            "display_text": "Norway",
            "key": "Norway",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "0ab9aefb-1ccd-4151-957a-eff18b13b0af",
            "href": "/rest/fundamental/v0/0ab9aefb-1ccd-4151-957a-eff18b13b0af"
        },
        {
            "created_on": "2021-01-12T00:12:11.000Z",
            "display_text": "SolarWinds Supply-Chain Campaign C2 Infrastructure Analysis",
            "key": "2c18e53c-7dae-4edb-a126-6e3c09ed3003",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "7128fb11-2753-4f4d-aa51-2c13731f7dbe",
            "href": "/rest/document/v0/7128fb11-2753-4f4d-aa51-2c13731f7dbe"
        },
        {
            "created_on": "2019-11-20T18:17:09.000Z",
            "display_text": "Ransomware Attack Hit Mexican Oil Company at Sensitive Time",
            "key": "d67e0be4-5b61-4e57-8c17-0bf09ed5b8f3",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "05982e7e-b7d0-4203-a8a9-dd46ea769854",
            "href": "/rest/fundamental/v0/05982e7e-b7d0-4203-a8a9-dd46ea769854"
        },
        {
            "created_on": "2021-02-25T00:14:03.000Z",
            "display_text": "DoppelPaymer Ransomware Reportedly Impacts Kia Motors, February 2021",
            "key": "7d996ac8-262b-46c4-880d-bed6126b66e4",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "d009718a-25f6-491f-95f2-528d0a3d3f63",
            "href": "/rest/fundamental/v0/d009718a-25f6-491f-95f2-528d0a3d3f63"
        },
        {
            "created_on": "2021-04-19T15:20:14.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 19 April 2021",
            "key": "287df877-37b1-4ef1-8ecc-6bbc8c3b82e2",
            "relationship": "mentions",
            "relationship_created_on": "2021-04-19T15:20:14.000Z",
            "relationship_last_published": "2021-04-19T15:20:14.000Z",
            "type": "intelligence_alert",
            "uuid": "09b14293-ce79-4515-9041-de4cefe3cb6b",
            "href": "/rest/document/v0/09b14293-ce79-4515-9041-de4cefe3cb6b"
        },
        {
            "created_on": "2021-06-21T19:07:23.000Z",
            "display_text": "Biden-Putin Summit May Produce a Lull but Is No Magic Bullet against Russian Cyber-Threat Activity",
            "key": "e25f00ee-1b1a-4c35-ae5c-fece153143f6",
            "relationship": "mentions",
            "relationship_created_on": "2021-06-21T19:07:23.000Z",
            "relationship_last_published": "2021-06-21T19:07:23.000Z",
            "type": "intelligence_alert",
            "uuid": "28f24dd5-9c13-4116-8fbd-7e395f6aeee0",
            "href": "/rest/document/v0/28f24dd5-9c13-4116-8fbd-7e395f6aeee0"
        },
        {
            "created_on": "2021-09-16T16:25:36.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 16 September 2021",
            "key": "de33f9be-318e-49b9-acfe-3c8ea3ce91e1",
            "relationship": "mentions",
            "relationship_created_on": "2021-09-16T16:25:36.000Z",
            "relationship_last_published": "2021-09-16T16:25:36.000Z",
            "type": "intelligence_alert",
            "uuid": "69d0098b-9113-4914-a692-5b42d79f88ad",
            "href": "/rest/document/v0/69d0098b-9113-4914-a692-5b42d79f88ad"
        },
        {
            "created_on": "2021-11-05T21:25:11.000Z",
            "display_text": "COP26 Climate Talks Convene amid Ongoing Energy-Related Espionage and Information Campaigns",
            "key": "cd5bbb2d-9a0b-4553-934e-4d8a6b91b556",
            "relationship": "mentions",
            "relationship_created_on": "2021-11-05T21:25:11.000Z",
            "relationship_last_published": "2021-11-05T21:25:11.000Z",
            "type": "intelligence_alert",
            "uuid": "422c1698-1d2f-46c5-b581-3ec7893b9401",
            "href": "/rest/document/v0/422c1698-1d2f-46c5-b581-3ec7893b9401"
        },
        {
            "created_on": "2021-12-02T21:51:25.000Z",
            "display_text": "Cyber Threats to the Energy Sector",
            "key": "2b867306-ddb0-4ab8-be2a-4ac93cb2cb91",
            "relationship": "mentions",
            "relationship_created_on": "2021-12-02T21:51:25.000Z",
            "relationship_last_published": "2021-12-02T21:54:25.000Z",
            "type": "intelligence_report",
            "uuid": "c023236c-e981-45c4-94e4-38426e364a1f",
            "href": "/rest/document/v0/c023236c-e981-45c4-94e4-38426e364a1f"
        },
        {
            "created_on": "2016-01-25T10:37:24.000Z",
            "display_text": "OPEC",
            "key": "OPEC",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "b09a4448-fc15-4540-882b-03cfd3cebf98",
            "href": "/rest/fundamental/v0/b09a4448-fc15-4540-882b-03cfd3cebf98"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Schlumberger",
            "key": "Schlumberger",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "edcf95d2-a28a-4667-930f-9dc103716c23",
            "href": "/rest/fundamental/v0/edcf95d2-a28a-4667-930f-9dc103716c23"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Chevron",
            "key": "Chevron",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "c52f6188-5bf5-4c5d-a83d-6e2eca9cd4b6",
            "href": "/rest/fundamental/v0/c52f6188-5bf5-4c5d-a83d-6e2eca9cd4b6"
        },
        {
            "created_on": "2016-06-30T18:42:30.000Z",
            "display_text": "YouTube",
            "key": "YouTube",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "0249a9ed-d2ac-4a0a-a2f2-85abe57ae4e7",
            "href": "/rest/fundamental/v0/0249a9ed-d2ac-4a0a-a2f2-85abe57ae4e7"
        },
        {
            "created_on": "2012-11-27T15:41:47.000Z",
            "display_text": "Syria",
            "key": "Syria",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "1e25cb18-113a-41c7-ab12-de2976728eae",
            "href": "/rest/fundamental/v0/1e25cb18-113a-41c7-ab12-de2976728eae"
        },
        {
            "created_on": "2006-12-22T00:00:00.000Z",
            "display_text": "Azerbaijan",
            "key": "Azerbaijan",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "c7a27c94-d97a-420a-8858-9288b184c62e",
            "href": "/rest/fundamental/v0/c7a27c94-d97a-420a-8858-9288b184c62e"
        },
        {
            "created_on": "2003-12-15T00:00:00.000Z",
            "display_text": "Netherlands",
            "key": "Netherlands",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "4b4e3c26-44b9-40ce-947d-a399f53f9c7f",
            "href": "/rest/fundamental/v0/4b4e3c26-44b9-40ce-947d-a399f53f9c7f"
        },
        {
            "created_on": "2018-02-20T17:16:22.000Z",
            "display_text": "GandCrab",
            "key": "GandCrab",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "8538b5a4-bc67-4222-9310-0c9118b0af22",
            "href": "/rest/fundamental/v0/8538b5a4-bc67-4222-9310-0c9118b0af22"
        },
        {
            "created_on": "2018-02-12T16:41:05.000Z",
            "display_text": "Foreign Intelligence Service of the Russian Federation (Служба Внешней Разведки Российской Федерации)",
            "key": "Foreign Intelligence Service of the Russian Federation (Служба Внешней Разведки Российской Федерации)",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "threat_group",
            "uuid": "11759430-3417-4772-9723-43bb38fe2280",
            "href": "/rest/fundamental/v0/11759430-3417-4772-9723-43bb38fe2280"
        },
        {
            "created_on": "2018-10-15T13:42:56.000Z",
            "display_text": "Exaramel",
            "key": "Exaramel",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "5cc66934-6ff0-4c37-84eb-4cc62ba28255",
            "href": "/rest/fundamental/v0/5cc66934-6ff0-4c37-84eb-4cc62ba28255"
        },
        {
            "created_on": "2021-03-12T17:13:00.000Z",
            "display_text": "GreyEnergy",
            "key": "GreyEnergy",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "c34f2ace-6438-4920-9167-027907689eaa",
            "href": "/rest/fundamental/v0/c34f2ace-6438-4920-9167-027907689eaa"
        },
        {
            "created_on": "2018-12-04T19:09:56.000Z",
            "display_text": "Industrial",
            "key": "Industrial",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "vertical",
            "uuid": "fb065f1a-2619-47e8-98fa-30415e3edb9f",
            "href": "/rest/fundamental/v0/fb065f1a-2619-47e8-98fa-30415e3edb9f"
        },
        {
            "created_on": "2008-05-20T21:02:50.000Z",
            "display_text": "Western Asia",
            "key": "Western Asia",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "region",
            "uuid": "53b59355-e4e6-40c7-ba89-002cabec9781",
            "href": "/rest/fundamental/v0/53b59355-e4e6-40c7-ba89-002cabec9781"
        },
        {
            "created_on": "2021-02-20T18:56:36.000Z",
            "display_text": "SITREP: Accellion FTA",
            "key": "87fc1b24-2f1a-40b6-8282-2594335a50a3",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "c68c3558-7540-4a74-9af3-5b1d243f852e",
            "href": "/rest/document/v0/c68c3558-7540-4a74-9af3-5b1d243f852e"
        },
        {
            "created_on": "2020-01-20T20:08:16.000Z",
            "display_text": "Putin Power Transfer Plan Marks New Uncertainties in Balance between Globalism and “Sovereignty”",
            "key": "0def1e52-2034-4a7f-b535-aa3b6c143cc1",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "fffd1701-8cd3-4237-b11b-31270d686f61",
            "href": "/rest/document/v0/fffd1701-8cd3-4237-b11b-31270d686f61"
        },
        {
            "created_on": "2020-06-09T07:52:43.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for June 8, 2020",
            "key": "bdb05bba-049d-4056-906f-3349336d52f1",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "6613f584-7728-4bd4-9dd7-103aef9b30ec",
            "href": "/rest/document/v0/6613f584-7728-4bd4-9dd7-103aef9b30ec"
        },
        {
            "created_on": "2018-11-27T16:09:30.000Z",
            "display_text": "Anonymous Yet Familiar: The Use of False Personas by Russian Cyberinformation Operations",
            "key": "e9e43a5a-caa5-458d-9bc4-3c483cf0394d",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_report",
            "uuid": "bd237f19-3b9f-4ea1-8f32-b9edd4667126",
            "href": "/rest/document/v0/bd237f19-3b9f-4ea1-8f32-b9edd4667126"
        },
        {
            "created_on": "2020-09-11T21:01:17.000Z",
            "display_text": "Cyprus at Center of Eastern Mediterranean Gas Dispute",
            "key": "Cyprus at Center of Eastern Mediterranean Gas Dispute",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "global_event",
            "uuid": "d8e7c996-cfc3-4050-8b51-46a1dc517896",
            "href": "/rest/fundamental/v0/d8e7c996-cfc3-4050-8b51-46a1dc517896"
        },
        {
            "created_on": "2021-04-07T22:11:42.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 7 April 2021",
            "key": "aaeb9511-6a7b-4c8f-a882-cfc0d8b4f321",
            "relationship": "mentions",
            "relationship_created_on": "2021-04-07T22:11:42.000Z",
            "relationship_last_published": "2021-04-07T22:11:42.000Z",
            "type": "intelligence_alert",
            "uuid": "ca097435-e5a7-4f11-9704-888617088676",
            "href": "/rest/document/v0/ca097435-e5a7-4f11-9704-888617088676"
        },
        {
            "created_on": "2021-04-19T18:02:29.000Z",
            "display_text": "Amid Russia-Ukraine Hostilities and US Sanctions Pressure, Russian Media Chief Predicts Cyber War",
            "key": "f7fc303e-994f-4802-b4a0-ca2a591673c3",
            "relationship": "mentions",
            "relationship_created_on": "2021-04-19T18:02:29.000Z",
            "relationship_last_published": "2021-04-19T18:02:29.000Z",
            "type": "intelligence_alert",
            "uuid": "31be69cd-647e-4209-828c-33659d288aa3",
            "href": "/rest/document/v0/31be69cd-647e-4209-828c-33659d288aa3"
        },
        {
            "created_on": "2004-07-07T00:00:00.000Z",
            "display_text": "Russian Federation",
            "key": "Russian Federation",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "97807e5c-65d2-4023-ba96-c44cb0c16dc5",
            "href": "/rest/fundamental/v0/97807e5c-65d2-4023-ba96-c44cb0c16dc5"
        },
        {
            "created_on": "2021-11-13T01:22:43.000Z",
            "display_text": "Ransomware Attacks on US Critical Infrastructure Align with Russian Strategy",
            "key": "d6ee5344-fa61-4eb3-81e1-0cec21b731b0",
            "relationship": "mentions",
            "relationship_created_on": "2021-11-13T01:22:43.000Z",
            "relationship_last_published": "2021-11-13T01:22:43.000Z",
            "type": "intelligence_alert",
            "uuid": "a7f69280-dbcc-4426-b3e9-f851f0603e94",
            "href": "/rest/document/v0/a7f69280-dbcc-4426-b3e9-f851f0603e94"
        },
        {
            "created_on": "2007-04-12T00:00:00.000Z",
            "display_text": "Kazakhstan",
            "key": "Kazakhstan",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2022-01-10T21:09:04.000Z",
            "type": "country",
            "uuid": "cb1de5ae-ec20-4ac1-9561-46425fce81b8",
            "href": "/rest/fundamental/v0/cb1de5ae-ec20-4ac1-9561-46425fce81b8"
        },
        {
            "created_on": "2022-02-02T18:54:34.000Z",
            "display_text": "Cyber Threats Target NATO Countries’ Transportation and Energy Infrastructure Amid Tension with Russia",
            "key": "5f56287d-89ad-4f5d-b7e9-2a9267193e0a",
            "relationship": "mentions",
            "relationship_created_on": "2022-02-02T18:54:34.000Z",
            "relationship_last_published": "2022-02-02T18:54:34.000Z",
            "type": "malicious_event",
            "uuid": "ffd3f586-f9f9-4538-b906-45f80a358662",
            "href": "/rest/fundamental/v0/ffd3f586-f9f9-4538-b906-45f80a358662"
        },
        {
            "created_on": "2016-12-29T10:08:23.000Z",
            "display_text": "Syria",
            "key": "Syria",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "50eac797-06e6-48ec-afd3-cc972ec6c3c9",
            "href": "/rest/fundamental/v0/50eac797-06e6-48ec-afd3-cc972ec6c3c9"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "LukOil",
            "key": "LukOil",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "766e636d-2889-4a24-9af3-b3b30b5fce27",
            "href": "/rest/fundamental/v0/766e636d-2889-4a24-9af3-b3b30b5fce27"
        },
        {
            "created_on": "2015-11-09T16:45:06.000Z",
            "display_text": "NASA",
            "key": "NASA",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "243a1daf-21cf-413f-b1c5-83081336f47b",
            "href": "/rest/fundamental/v0/243a1daf-21cf-413f-b1c5-83081336f47b"
        },
        {
            "created_on": "2017-01-23T12:49:36.000Z",
            "display_text": "Total",
            "key": "Total",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "target_organization",
            "uuid": "72ab7eb0-8977-4686-8218-e9231271184e",
            "href": "/rest/fundamental/v0/72ab7eb0-8977-4686-8218-e9231271184e"
        },
        {
            "created_on": "2008-05-07T00:00:00.000Z",
            "display_text": "Cyprus",
            "key": "Cyprus",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "b4934110-edb0-4d29-8d42-b035f627f4af",
            "href": "/rest/fundamental/v0/b4934110-edb0-4d29-8d42-b035f627f4af"
        },
        {
            "created_on": "2005-02-08T00:00:00.000Z",
            "display_text": "Libya",
            "key": "Libya",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "a8aeac54-fc9a-434c-a9ba-1aeebf76721b",
            "href": "/rest/fundamental/v0/a8aeac54-fc9a-434c-a9ba-1aeebf76721b"
        },
        {
            "created_on": "2006-05-23T00:00:00.000Z",
            "display_text": "Armenia",
            "key": "Armenia",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "198ddfe4-1edb-4dec-97aa-72328ed212f1",
            "href": "/rest/fundamental/v0/198ddfe4-1edb-4dec-97aa-72328ed212f1"
        },
        {
            "created_on": "2003-08-06T00:00:00.000Z",
            "display_text": "Ukraine",
            "key": "Ukraine",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "e614cbe1-3a7d-4dfe-8e3d-56cae2165af6",
            "href": "/rest/fundamental/v0/e614cbe1-3a7d-4dfe-8e3d-56cae2165af6"
        },
        {
            "created_on": "2003-10-16T00:00:00.000Z",
            "display_text": "Saudi Arabia",
            "key": "Saudi Arabia",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "country",
            "uuid": "ca8e002d-dbc1-4ffc-a964-202a2d042c40",
            "href": "/rest/fundamental/v0/ca8e002d-dbc1-4ffc-a964-202a2d042c40"
        },
        {
            "created_on": "2020-04-28T14:37:47.000Z",
            "display_text": "CLOP",
            "key": "CLOP",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malware_family",
            "uuid": "dbba5596-7033-49e1-a731-7d54734463c4",
            "href": "/rest/fundamental/v0/dbba5596-7033-49e1-a731-7d54734463c4"
        },
        {
            "created_on": "2018-12-04T19:10:10.000Z",
            "display_text": "Utilities",
            "key": "Utilities",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "vertical",
            "uuid": "e7e29d66-df14-4875-a8fe-98dd80151eee",
            "href": "/rest/fundamental/v0/e7e29d66-df14-4875-a8fe-98dd80151eee"
        },
        {
            "created_on": "2015-07-31T10:35:10.000Z",
            "display_text": "Asia",
            "key": "Asia",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "region",
            "uuid": "e2aa2414-9adb-447e-ae83-32e3d6afee04",
            "href": "/rest/fundamental/v0/e2aa2414-9adb-447e-ae83-32e3d6afee04"
        },
        {
            "created_on": "2015-07-31T17:09:12.000Z",
            "display_text": "NATO",
            "key": "NATO",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "region",
            "uuid": "e0d04538-588a-4304-9974-832b7670bca7",
            "href": "/rest/fundamental/v0/e0d04538-588a-4304-9974-832b7670bca7"
        },
        {
            "created_on": "2019-06-21T22:43:06.000Z",
            "display_text": "Brinkmanship over Iran and Maneuvering over Upcoming G-20 Summit Could Spark Espionage or Disruptive Attacks",
            "key": "051e541d-05e3-40d1-a867-81300e4573dd",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "84c2db1a-6c35-41b6-9f98-ce44840db791",
            "href": "/rest/document/v0/84c2db1a-6c35-41b6-9f98-ce44840db791"
        },
        {
            "created_on": "2020-08-11T20:34:54.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for August 11, 2020",
            "key": "e5fe7a49-0a0b-406a-aa88-d41de43adc89",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "intelligence_alert",
            "uuid": "5a23f8ed-8038-4727-bb4d-5016c57e10f5",
            "href": "/rest/document/v0/5a23f8ed-8038-4727-bb4d-5016c57e10f5"
        },
        {
            "created_on": "2021-03-04T20:00:52.000Z",
            "display_text": "CLOP Ransomware Operators Leak Qualys Documents on Name-and-Shame Site on 3 and 4 March 2021",
            "key": "1e4a812a-dc96-45a7-b2c4-13e866ae8393",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "61e45fd4-b540-4de0-a81d-4cc8af952a60",
            "href": "/rest/fundamental/v0/61e45fd4-b540-4de0-a81d-4cc8af952a60"
        },
        {
            "created_on": "2020-02-29T23:22:36.000Z",
            "display_text": "Alleged DoppelPaymer Actors Seek to Blackmail Mexican Oil Company with Document Leak",
            "key": "847d1ba4-3f84-4b83-943a-944993cbf934",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "238857cc-12f3-4fac-820a-c59dc58c27da",
            "href": "/rest/fundamental/v0/238857cc-12f3-4fac-820a-c59dc58c27da"
        },
        {
            "created_on": "2017-12-21T19:23:58.000Z",
            "display_text": "TRITON ICS Malware Framework Targets Critical Infrastructure",
            "key": "d4e7170a-3485-4668-ad7d-3c2b0b43ea4c",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "2200deae-56e0-4835-b454-8060bd0be50e",
            "href": "/rest/fundamental/v0/2200deae-56e0-4835-b454-8060bd0be50e"
        },
        {
            "created_on": "2018-11-03T11:26:30.000Z",
            "display_text": "US Indictment Reveals SNAKEMACKEREL Targeting of Westinghouse Electric",
            "key": "28aa3b56-6fcb-4e0d-9c91-bcae3b798882",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-26T20:09:55.000Z",
            "relationship_last_published": "2021-03-26T20:09:55.000Z",
            "type": "malicious_event",
            "uuid": "aff26f9b-2f45-483c-996a-e058fc02a84a",
            "href": "/rest/fundamental/v0/aff26f9b-2f45-483c-996a-e058fc02a84a"
        },
        {
            "created_on": "2021-03-31T19:20:13.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 31 March 2021",
            "key": "d0bff8ef-b21a-4a64-8541-2afba89eeafa",
            "relationship": "mentions",
            "relationship_created_on": "2021-03-31T19:20:13.000Z",
            "relationship_last_published": "2021-03-31T19:20:13.000Z",
            "type": "intelligence_alert",
            "uuid": "bb117f7c-c0b6-43ae-9468-463ae58e2853",
            "href": "/rest/document/v0/bb117f7c-c0b6-43ae-9468-463ae58e2853"
        },
        {
            "created_on": "2021-06-02T22:08:57.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 2 June 2021",
            "key": "61641afe-698f-417a-802d-23197d0fe76d",
            "relationship": "mentions",
            "relationship_created_on": "2021-06-02T22:08:57.000Z",
            "relationship_last_published": "2021-06-02T22:08:57.000Z",
            "type": "intelligence_alert",
            "uuid": "5bcf3272-5207-433c-a550-320968c1587a",
            "href": "/rest/document/v0/5bcf3272-5207-433c-a550-320968c1587a"
        }
    ],
    "replication_id": 1644344878539000048,
    "sources_external": [
        {
            "datetime": "2020-12-18T05:00:00.000Z",
            "description": "-\tСергей Нарышкин: О том как статъ настоящим разведчиком (Sergey Naryshkin: On how to become a real spy)  hxxps://aif[.]ru/society/safety/100_let_svr_sergey_naryshkin_o_tom_kak_stat_nastoyashchim_razvedchikom",
            "name": "Argumenty i fakty",
            "reputation": 4
        },
        {
            "datetime": "2021-02-27T05:00:00.000Z",
            "description": "Когда-то император Александр III сказал замечательную по своей емкости фразу: ....hxxps://t[.]me/nstarikovru/20816/",
            "name": "Nikolay Starikov",
            "reputation": 3
        },
        {
            "datetime": "2019-11-01T04:00:00.000Z",
            "description": "Why Chinese farmers have crossed border into Russia's Far East",
            "name": "British Broadcasting Corporation",
            "reputation": 4,
            "url": "https://www.bbc.com/news/world-europe-50185006"
        },
        {
            "datetime": "2021-03-11T05:00:00.000Z",
            "description": "Support for Russia's Ruling Party Drops to Pre-Crimea Low – Poll",
            "name": "Moscow Times",
            "reputation": 4,
            "url": "https://www.themoscowtimes.com/2021/03/11/support-for-russias-ruling-party-drops-to-pre-crimea-low-poll-a73211"
        },
        {
            "datetime": "2021-03-25T04:00:00.000Z",
            "description": "Kremlin’s ‘Vaccine Diplomacy’ in Action: Tools, Strengths, Intermediary Results",
            "name": "Jamestown Foundation",
            "reputation": 4,
            "url": "https://jamestown.org/program/kremlins-vaccine-diplomacy-in-action-tools-strengths-intermediary-results/"
        },
        {
            "datetime": "2018-11-30T05:00:00.000Z",
            "description": "Watch Vladimir Putin and Crown Prince Mohammed bin Salman Embrace at the G-20",
            "name": "Time",
            "reputation": 4,
            "url": "https://time.com/5467935/putin-bin-salman-g20/"
        },
        {
            "datetime": "2021-03-09T05:00:00.000Z",
            "description": "Vilifying Germany; Wooing Germany",
            "name": "EU vs Disinfo",
            "reputation": 4,
            "url": "https://euvsdisinfo.eu/villifying-germany-wooing-germany/"
        },
        {
            "datetime": "2021-03-15T04:00:00.000Z",
            "description": "The Iran-Russia Cyber Agreement and U.S. Strategy in the Middle East",
            "name": "Council on Foreign Relations",
            "reputation": 4,
            "url": "https://www.cfr.org/blog/iran-russia-cyber-agreement-and-us-strategy-middle-east"
        },
        {
            "datetime": "2017-07-08T04:00:00.000Z",
            "description": "Chinese in the Russian Far East: a geopolitical time bomb?",
            "name": "South China Morning Post",
            "reputation": 4,
            "url": "https://www.scmp.com/week-asia/geopolitics/article/2100228/chinese-russian-far-east-geopolitical-time-bomb"
        },
        {
            "datetime": "2021-02-08T05:00:00.000Z",
            "description": "Russia-Iran cooperation poses challenges for US cyber strategy, global norms",
            "name": "C4ISR",
            "reputation": 4,
            "url": "https://www.c4isrnet.com/thought-leadership/2021/02/08/russia-iran-cooperation-poses-challenges-for-us-cyber-strategy-global-norms/"
        },
        {
            "datetime": "2016-05-11T04:00:00.000Z",
            "description": "Putin’s Hydra: Inside Russia’s Intelligence Services",
            "name": "European Council on Foreign Relations",
            "reputation": 4,
            "url": "https://ecfr.eu/wp-content/uploads/ECFR_169_-_PUTINS_HYDRA_INSIDE_THE_RUSSIAN_INTELLIGENCE_SERVICES_1513.pdf"
        },
        {
            "datetime": "2019-10-18T04:00:00.000Z",
            "description": "Cybersecurity Advisory, Turla Group Exploits Iranian APT to Expand Coverage of Victims",
            "name": "National Security Agency, National Cyber Security Centre",
            "reputation": 5,
            "url": "https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF"
        },
        {
            "datetime": "2020-12-12T05:00:00.000Z",
            "description": "Netherlands kicks out two Russian diplomats as Denmark charges Russian citizen with espionage",
            "name": "EuroNews",
            "reputation": 4,
            "url": "https://www.euronews.com/2020/12/09/russian-citizen-charged-with-spying-on-energy-technology-in-denmark"
        },
        {
            "datetime": "2018-10-03T04:00:00.000Z",
            "description": "US v Aleksei Sergeyevich Morenets et al",
            "name": "US Department of Justice",
            "reputation": 5,
            "url": "https://www.justice.gov/opa/page/file/1098481/download"
        },
        {
            "datetime": "2017-09-15T04:00:00.000Z",
            "description": "International Security and Estonia",
            "name": "Estonian Foreign Intelligence Service",
            "reputation": 5,
            "url": "https://www.valisluureamet.ee/pdf/raport-2018-ENG-web.pdf"
        },
        {
            "datetime": "2021-03-04T05:00:00.000Z",
            "description": "China’s 5-year plan includes goals to open Arctic Silk Road",
            "name": "Reuters",
            "reputation": 4,
            "url": "https://reuters.com/article/us-china-parliament-polar-idUSKBN2AX09F"
        },
        {
            "datetime": "2019-05-01T04:00:00.000Z",
            "description": "How Russian Trolls Are Using American Businesses as Their Weapons",
            "name": "Inc",
            "reputation": 4,
            "url": "https://www.inc.com/magazine/201905/tom-foster/russian-trolls-facebook-social-media-attacks-brands-hoax-fake-disinformation.html"
        },
        {
            "datetime": "2021-03-22T04:00:00.000Z",
            "description": "Russia and Europe hxxps://www.levada[.]ru/en/2021/03/22/russia-and-europe/",
            "name": "Levada",
            "reputation": 4
        },
        {
            "datetime": "2014-09-12T04:00:00.000Z",
            "description": "Announcement of Expanded Treasury Sanctions within the Russian Financial Services, Energy and Defense or Related Materiel Sectors",
            "name": "US Treasury",
            "reputation": 5,
            "url": "https://www.treasury.gov/press-center/press-releases/Pages/jl2629.aspx"
        },
        {
            "datetime": "2009-01-01T05:00:00.000Z",
            "description": "Map_of_the_Arctic_region_showing_the_Northeast_Passage,_the_Northern_Sea_Route_and_Northwest_Passage,_and_bathymetry",
            "name": "Arctic Council",
            "reputation": 5,
            "url": "https://commons.wikimedia.org/wiki/File:Map_of_the_Arctic_region_showing_the_Northeast_Passage,_the_Northern_Sea_Route_and_Northwest_Passage,_and_bathymetry.png"
        },
        {
            "datetime": "2021-02-23T05:00:00.000Z",
            "description": "Q4 2020 Doxxing Victim Trends: Industrial Sector Emerges as Primary Ransom “Non-Payor”",
            "name": "Coveware",
            "reputation": 4,
            "url": "https://www.coveware.com/blog/2021/2/18/q4-doxxing-victim-trends-industrial-sector-emerges-as-primary-ransom-non-payor"
        },
        {
            "datetime": "2019-01-18T05:00:00.000Z",
            "description": "Who Are Russia's Main Allies? hxxps://www.rbth[.]com/lifestyle/329861-who-are-russia-allies",
            "name": "Russia Behind the Headlines",
            "reputation": 3
        },
        {
            "datetime": "2021-02-23T05:00:00.000Z",
            "description": "Detailed plans of military spy plane are leaked on the dark web by hackers after Canadian manufacturer Bombardier 'refused to pay ransom'",
            "name": "Daily Mail",
            "reputation": 4,
            "url": "https://www.dailymail.co.uk/news/article-9293153/Bombardier-latest-company-hacked-group-using-ransomware-called-Clop.html"
        },
        {
            "datetime": "2020-12-16T05:00:00.000Z",
            "description": "How Russia Wins the Climate Crisis",
            "name": "New York Times",
            "reputation": 4,
            "url": "https://www.nytimes.com/interactive/2020/12/16/magazine/russia-climate-migration-crisis.html"
        },
        {
            "datetime": "2020-12-07T05:00:00.000Z",
            "description": "Russia Strives for an Oil and Gas Resurgence",
            "name": "Jamestown",
            "reputation": 4,
            "url": "https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/"
        },
        {
            "datetime": "2021-03-19T04:00:00.000Z",
            "description": "Berlin Assassination: New Evidence on Suspected FSB Hitman Passed to German Investigators",
            "name": "Bellingcat",
            "reputation": 4,
            "url": "https://www.bellingcat.com/news/2021/03/19/berlin-assassination-new-evidence-on-suspected-fsb-hitman-passed-to-german-investigators/"
        },
        {
            "datetime": "2020-03-27T04:00:00.000Z",
            "description": "Russia’s Chinese Dream in the Era of COVID-19",
            "name": "Wilson Center",
            "reputation": 4,
            "url": "https://www.wilsoncenter.org/blog-post/russias-chinese-dream-era-covid-19"
        },
        {
            "datetime": "2019-06-20T04:00:00.000Z",
            "description": "Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments",
            "name": "Symantec",
            "reputation": 4,
            "url": "https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments"
        },
        {
            "datetime": "2021-01-12T05:00:00.000Z",
            "description": "What drives crude oil prices?",
            "name": "US Energy Information Administration",
            "reputation": 5,
            "url": "https://www.eia.gov/finance/markets/crudeoil/reports_presentations/crude.pdf"
        },
        {
            "datetime": "2018-04-20T04:00:00.000Z",
            "description": "US-CERT/CISA Alert (TA18-106A): Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices",
            "name": "US Cybersecurity and Infrastructure Security Agency",
            "reputation": 5,
            "url": "https://us-cert.cisa.gov/ncas/alerts/TA18-106A"
        },
        {
            "datetime": "2020-12-17T05:00:00.000Z",
            "description": "Russia: The EU prolongs economic sanctions for another six months",
            "name": "European Union",
            "reputation": 5,
            "url": "https://www.consilium.europa.eu/en/press/press-releases/2020/12/17/russia-the-eu-prolongs-economic-sanctions-for-another-six-months"
        },
        {
            "datetime": "2021-01-15T05:00:00.000Z",
            "description": "Interview: Media Lawyer Says Russia's New Laws 'Are Burying Civil Society",
            "name": "Radio Free Europe/Radio Liberty",
            "reputation": 4,
            "url": "https://www.rferl.org/a/russia-foreign-agents-law-interview-media-lawyer-civil-societ-rfe/31048094.html"
        },
        {
            "datetime": "2021-02-04T05:00:00.000Z",
            "description": "Dissatisfaction With Putin Surges Among Young Russians – Levada Poll",
            "name": "Moscow Times",
            "reputation": 4,
            "url": "https://www.themoscowtimes.com/2021/02/04/dissatisfaction-with-putin-surges-among-young-russians-levada-poll-a72835"
        },
        {
            "datetime": "2021-02-06T05:00:00.000Z",
            "description": "Rising Poverty and Falling Incomes Fuel Russia's Navalny",
            "name": "Financial Times",
            "reputation": 4,
            "url": "https://amp.ft.com/content/24b45679-ed22-4df7-89ab-f3d5fad71c95"
        },
        {
            "datetime": "2020-03-12T04:00:00.000Z",
            "description": "Tracking Turla: New backdoor delivered via Armenian watering holes",
            "name": "ESET",
            "reputation": 4,
            "url": "https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/"
        },
        {
            "datetime": "2018-03-16T04:00:00.000Z",
            "description": "Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors",
            "name": "US Cybersecurity and Infrastructure Security Agency",
            "reputation": 5,
            "url": "https://us-cert.cisa.gov/ncas/alerts/TA18-074A"
        },
        {
            "datetime": "2020-10-23T04:00:00.000Z",
            "description": "Treasury Sanctions Russian Government Research Institution Connected to the Triton Malware",
            "name": "US Treasury Department",
            "reputation": 5,
            "url": "https://home.treasury.gov/news/press-releases/sm1162"
        },
        {
            "datetime": "2021-03-30T04:00:00.000Z",
            "description": "В Минобороны рассказали, как победить США в \"ментальной войне\"  hxxps://ria[.]ru/20210330/ssha-1603481759.html",
            "name": "RIA"
        },
        {
            "datetime": "2019-10-23T04:00:00.000Z",
            "description": "Past and future of integrity based attacks in ics environments",
            "name": "Dragos",
            "reputation": 4,
            "url": "https://www.slideshare.net/JoeSlowik/past-and-future-of-integrity-based-attacks-in-ics-environments"
        },
        {
            "datetime": "2021-03-17T04:00:00.000Z",
            "description": "Biden: Putin will ‘pay a price’ for interfering in 2020 election",
            "name": "Politico",
            "reputation": 4,
            "url": "https://www.politico.com/news/2021/03/17/biden-putin-election-interference-476656"
        },
        {
            "datetime": "2021-01-14T05:00:00.000Z",
            "description": "Who Is Responsible for Mitigating the Effects of Climate Change in Russia?",
            "name": "Center for Strategic and International Studies",
            "reputation": 4,
            "url": "https://www.csis.org/analysis/who-responsible-mitigating-effects-climate-change-Russia"
        },
        {
            "datetime": "2019-10-21T04:00:00.000Z",
            "description": "Joint Advisory: Turla group exploits Iranian APT to expand coverage of victims",
            "name": "UK National Cyber Security Centre (NCSC) and US National Security Agency",
            "reputation": 5,
            "url": "https://www.ncsc.gov.uk/news/turla-group-exploits-iran-apt-to-expand-coverage-of-victims"
        },
        {
            "datetime": "2019-10-21T04:00:00.000Z",
            "description": "Hacking the hackers: Russian group hijacked Iranian spying operation, officials say",
            "name": "Reuters",
            "reputation": 4,
            "url": "https://www.reuters.com/article/us-russia-cyber/hacking-the-hackers-russian-group-hijacked-iranian-spying-operation-officials-say-idUSKBN1X00AK"
        },
        {
            "datetime": "2021-02-15T05:00:00.000Z",
            "description": "Russia Blackmails and Courts Europe",
            "name": "Jamestown",
            "reputation": 4,
            "url": "https://jamestown.org/program/russia-blackmails-and-courts-europe/"
        },
        {
            "datetime": "2021-02-07T05:00:00.000Z",
            "description": "Vladimir Putin’s Russia is destabilising itself from within",
            "name": "Tatyana Stanovaya for the Financial Times",
            "reputation": 4,
            "url": "https://www.ft.com/content/94aeb690-ec2d-472d-adf7-212930c2d394"
        },
        {
            "datetime": "2015-04-16T04:00:00.000Z",
            "description": "Putin agrees with emperor that Russia's only allies are Army and Navy hxxps://tass[.]com/Russia/789866",
            "name": "TASS",
            "reputation": 3
        },
        {
            "datetime": "2020-12-14T05:00:00.000Z",
            "description": "Deepening Leadership Confusion Exacerbates Russia’s Multiple Crises",
            "name": "Jamestown",
            "reputation": 4,
            "url": "https://jamestown.org/program/deepening-leadership-confusion-exacerbates-russias-multiple-crises/"
        },
        {
            "datetime": "2020-11-12T05:00:00.000Z",
            "description": "Overview of United States sanctions on Russian persons (individuals, entities, and vessels).",
            "name": "US Commerce Department",
            "reputation": 5,
            "url": "https://www.trade.gov/country-commercial-guides/russia-sanctions"
        },
        {
            "datetime": "2020-10-19T04:00:00.000Z",
            "description": "Six Russian GRU Officers Charged in Connection with Worldwide Deployment of Destructive Malware and Other Disruptive Actions in Cyberspace",
            "name": "US Department of Justice",
            "reputation": 5,
            "url": "https://www.justice.gov/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and"
        },
        {
            "datetime": "2019-10-21T04:00:00.000Z",
            "name": "UK National Cyber Security Centre (NCSC)",
            "reputation": 5,
            "url": "https://www.ncsc.gov.uk/news/turla-group-behind-cyber-attack"
        },
        {
            "datetime": "2020-02-20T05:00:00.000Z",
            "description": "UK condemns Russia's GRU over Georgia cyber-attacks",
            "name": "UK Government",
            "reputation": 5,
            "url": "https://www.gov.uk/government/news/uk-condemns-russias-gru-over-georgia-cyber-attacks"
        },
        {
            "datetime": "2018-04-05T04:00:00.000Z",
            "description": "Satellite images show huge Russian military buildup in the Arctic",
            "name": "CNN",
            "reputation": 4,
            "url": "https://www.cnn.com/2021/04/05/europe/russia-arctic-nato-military-intl-cmd/index.html"
        },
        {
            "datetime": "2020-12-03T05:00:00.000Z",
            "description": "Russian, Chinese intelligence targeting Norwegian oil secrets: report",
            "name": "Reuters",
            "reputation": 4,
            "url": "https://www.reuters.com/article/us-norway-oil-security/russian-chinese-intelligence-targeting-norwegian-oil-secrets-report-idUSKBN28D2M7"
        }
    ],
    "threat_types": [
        "Cyber Espionage",
        "Cyber Crime"
    ],
    "title": "Russian Responses to Geopolitical Challenges Include Cyber-Threat Activity against Energy Industry Entities",
    "type": "intelligence_report",
    "uuid": "bdc9d16f-6040-4894-8544-9c98986a41fd",
    "analysis": "##Key Findings and Judgements\n\n- The Russian government faces global and domestic challenges intensified by global warming, unrest in neighboring states, the rise of renewable energy, and international sanctions; these challenges aggravate poverty and discontent within Russia.\n\n- Russia’s government pursues its state strategies through a variety of means including cyber-threat operations that involve espionage, disruptive activity, and disinformation.\n- To mitigate the risks of Russian cyber-threats, organizations can implement best practices that are informed by intelligence.\n\n## An Oil and Gas Superpower Faces a Changing World \n\nFluctuating demand for fossil fuels, aggravated during the pandemic, and complicated relationships with the OPEC+ petroleum exporters’ consortium have contributed to unpredictability in the prices of Russia’s main exports—oil and gas. Geopolitical tensions and upheavals have influenced oil price volatility over the decades (Exhibit 1) and will likely continue to do so in the future.\n\n![USEIA on Oil Prices](/rest/files/download/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-02-08cropped.png)  \n_Exhibit 1: Factors Affecting Crude Oil Prices; from the US Energy Information Administration, 12 January 2021_\n\n####Climate Change: Challenges and Opportunities \n\nClimate change brings challenges and opportunities for Russia, including the following: \n\n- **Move from fossil fuels:** Governments and major corporations are vowing to cut carbon dioxide emissions in various ways, such as by developing renewable energy sources and switching to electric cars. These changes could curtail demand for fossil fuels, push down prices, and cut Russian revenues. Russia’s energy strategy for 2035 portrays these shifts as [a major challenge](https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/). \n\n- **Melting permafrost:** Melting permafrost is remaking Russia’s northern landscape as roads and pipelines sink and buckle. An oil tank at metals giant Norilsk Nickel leaked in 2020, causing a devastating oil spill and [costing the company US$2 billion in fines]( https://www.themoscowtimes.com/2021/02/19/nornickel-will-not-appeal-record-2bln-fine-for-arctic-oil-spill-a72980). \n\n- **Arctic shipping and Siberian agriculture:** Climate change is opening opportunities mixed with challenges for Russia. The melting Arctic has created new shipping routes (see Exhibit 2). Russian ships can carry more traffic on the Northern Sea Route, and the country can leverage its advantage in number of icebreakers, but countries are increasingly [competing with Russia](https://news.usni.org/2021/01/05/new-arctic-strategy-calls-for-regular-presence-as-a-way-to-compete-with-russia-china) to use the Arctic for resources, transport, and [military](https://www.cnn.com/2021/04/05/europe/russia-arctic-nato-military-intl-cmd/index.html ) advantage.  \n\n Some analysts suggest [Russia’s agriculture will improve]( https://asiatimes.com/2021/02/could-russia-dominate-world-agriculture/) with the thaw of the Siberian wastelands; however, Russia’s shrinking population would require the country to welcome migrants, most likely from China, to support the expanding agriculture, and many Russians are [suspicious of Chinese encroachment]( https://www.bbc.com/news/world-europe-50185006).  Russia’s government has [not seriously developed its renewable energy]( https://www.csis.org/analysis/climate-change-will-reshape-russia), as China has.\n\n ![Arctic Map](/rest/files/download/0f/6c/6f/91de9ef8d8d38345dc270f8915d9faa496a00b5babe2bff231dd195cd0/ArcticMapUWNews28288859157_5f54b9c446_c.jpg)  \n _Exhibit 2. “Map of the Arctic Region Showing the Northeast Passage, the Northern Sea Route, and Northwest Passage and Bathymetry NOAA.” Arctic Council, 2009. Public Domain_ \n\n##Global Challenges and Domestic Stability \n \nRussia has faced international condemnation and mounting economic sanctions for its human-rights violations, especially after seizing Crimea from Ukraine in 2014 and interfering in US and other elections. These international travails jeopardize Russia's domestic stability, [as summarized]( https://www.ft.com/content/94aeb690-ec2d-472d-adf7-212930c2d394) by respected Russian political commentator Tatyana Stanovaya: \n \n```\nPutin’s original success was rooted in his regime’s ability to deliver steady improvements in living standards while inspiring Russians with exploits on the world stage. Now the regime is ruling largely by scaring people and fostering the impression that Mother Russia is once again a “besieged fortress.” \n```\n\n####Decline in living standards\n\nSanctions have hindered many Russian entities, including oil and gas producers, from expanding their operations. Many of Russia’s neighbors, including Turkmenistan, Azerbaijan, and Kazakhstan, compete with Russia to export oil and gas, and some neighbors, such as Ukraine, are overtly hostile. For years, Russia has sought to protect its energy exports and revenue by using pipelines that bypass Ukraine. Nord-Stream 2, the latest such pipeline, faces US sanctions.\n\nThe COVID-19 pandemic has contributed to a 3.1 percent drop in Russia’s GDP in 2020 and a [8.6 percent fall](https://amp.ft.com/content/24b45679-ed22-4df7-89ab-f3d5fad71c95) in Russian household consumption. Low oil prices, sanctions, and the COVID-19 pandemic have strained the economy and consumer confidence causing the government to impose price controls on sugar and vegetable oil.\n\nEconomic burdens are contributing to public discontent. YouTube videos of the lavish lifestyles of Russia’s top leaders, such as opposition leader Alexey Navalny’s recent video about “Putin’s Palace” in southern Russia, helped [inspire thousands of people](https://www.themoscowtimes.com/2021/02/04/dissatisfaction-with-putin-surges-among-young-russians-levada-poll-a72835) to protest Navalny’s arrest in January 2021. Russia’s ruling party will face a test with the September 2021 parliamentary elections; party support has [dropped to an eight-year low](https://www.themoscowtimes.com/2021/03/11/support-for-russias-ruling-party-drops-to-pre-crimea-low-poll-a73211), according to a February 2021 survey by the independent Levada polling agency. \n\n####Exploits on the world stage \n\nDuring the COVID-19 pandemic, Russia has been using “[vaccine diplomacy]( https://jamestown.org/program/kremlins-vaccine-diplomacy-in-action-tools-strengths-intermediary-results/)” to boost its image on the world stage.  Russia’s role in ending a conflict between Azerbaijan and Armenia had mixed success in promoting its image as a peacemaker. These small triumphs will likely do little, however, to outweigh Russia’s pariah status or boost Russians’ patriotic pride.\n\n#### Besieged fortress \n\nHaving failed to inspire its people with patriotism through improvements in living standards and exploits on the world stage, Putin’s government has chosen to [stifle public protest](https://www.rferl.org/a/russia-foreign-agents-law-interview-media-lawyer-civil-societ-rfe/31048094.html). Laws in 2021 suppress independent journalists and opposition activists, labeling them as agents of foreign powers, and police have arrested thousands of rally participants.  \n\nPutin's regime is attempting to promote patriotism by “fostering the impression that Mother Russia is once again a ‘besieged fortress’,\" as Stanovaya put it. Officials and state media frequently describe the outside world, particularly the US and Europe, as constantly seeking to undermine and humiliate Russia. \n\nIn an interview in late 2020, Russia’s foreign intelligence service chief, Sergey Naryshkin, portrayed international sanctions for Russian human-rights violations as “hybrid wars,” referring to undeclared wars using diplomatic and psychological means. Naryshkin and other officials have repeatedly portrayed protests in Russia and neighboring countries as schemes by foreign powers to weaken Russia.  \n\n####\"Frenemies\"\n\nFacing ostracism and pressure from sanctions, which affect its oil and gas and other industries, Russia is forced to work with counterparts it does not necessarily trust:\n \n- **China:** Russia and China concluded the 30-year, $400 billion “Power of Siberia” gas pipeline deal in May 2014, just after Russia annexed Crimea from Ukraine and incurred international wrath. Although gas started flowing in 2019, [suspicion surrounds this cooperation](https://www.scmp.com/week-asia/geopolitics/article/2100228/chinese-russian-far-east-geopolitical-time-bomb). Some Russian commentators fear being relegated to the position of a junior partner and raw materials supplier to China. Also, many local residents distrust Chinese migrants, and popular culture occasionally resurrects the specter of hordes of Chinese soldiers coming over the border.\n\n- **Saudi Arabia:** Starting in 2016, Russia and Saudi Arabia agreed to limit oil and gas production to maintain high prices, as well as entering other cooperative agreements. At the G-20 summit in late 2018, Putin and Saudi crown prince Mohamad Bin-Salman even famously [exchanged a high-five](https://time.com/5467935/putin-bin-salman-g20/),  as both men faced harsh international criticisms for human-rights violations. \n\n However, Russia targets its “frenemies” as well as its adversaries. The US and UK governments have accused Russia of carrying out intrusions using [Triton](/#/node/malicious_event/view/2200deae-56e0-4835-b454-8060bd0be50e) and [Neuron/Nautilus](/#/node/intelligence_alert/view/6f668357-bd6a-4a04-876d-20bd840e0788) malware against computer networks in Saudi Arabia. These campaigns were likely intended to gain visibility into and leverage over Saudi policies, particularly regarding oil production levels and prices but also involving the Saudi relationship with other players in the Middle East. \n\n- **Turkey:** Turkey and Russia have a long complicated relationship with signs of both cooperation and conflict in areas surrounding oil and gas. Turkey is a member of the NATO military alliance but buys Russian anti-aircraft weapons and works sporadically with Russia. In 2020, Turkey carried out controversial [gas drilling in the eastern Mediterranean](/#/node/global_event/view/d8e7c996-cfc3-4050-8b51-46a1dc517896), occasionally opposed Russia in conflicts in Syria and Libya, and supported Azerbaijan in a [conflict with Armenia](/#/node/global_event/view/8d7758be-40ec-4b6c-b2fc-cd007183640d) that could have endangered regional oil and gas infrastructure.\n\n- **Iran:** Russia’s equally [complex relationship with Iran](/#/node/intelligence_alert/view/84c2db1a-6c35-41b6-9f98-ce44840db791) has encompassed military cooperation in Syria and agreements on information security cooperation.  At the same time, Russian group BELUGASTURGEON stole hacking tools and infrastructure from an Iranian threat group and used them against Saudi targets in a [false flag operation](/#/node/intelligence_alert/view/6f668357-bd6a-4a04-876d-20bd840e0788) that framed Iran.\n\n####Russian Strategies\n\nOne of Russia’s 19th-century emperors famously said, “Russia has just two allies: its army and its navy.” Putin directly quoted that in 2015, half in jest, but the quote remains popular.  This sense of isolation colors Russia’s strategic worldview. (For more detail on Russian motives and strategies, see the report [Making Sense of Russian Cyberthreat Activity](#/node/intelligence_report/view/30e6397e-69cb-48e9-9017-eafb0d761d24).) \n\n\nRussian strategists perceive the country as engaged in a constant battle in the arena of [psychological or information warfare against US and Western powers](/#/node/intelligence_alert/view/79e6008d-ddd4-472d-b574-5ad1a769e096). Russian officials and state media portray foreign culture, TV and movies, and rhetoric about democracy as ill-disguised attempts to humiliate and weaken Russia. This view allows them to rationalize using propaganda, trolls, and disinformation to discredit and divide other countries, as they [did in 2016]( /#/node/intelligence_report/view/1373c4a9-baab-4fc1-a33b-f7b152a5f933), in the [2020 US elections](https://www.dni.gov/files/ODNI/documents/assessments/ICA-declass-16MAR21.pdf), and elsewhere. \n\nThe sense of hostility toward the West coexists with a desire to be part of Europe and the global economy, to be a “normal” country, and to restore the great power status the Soviet Union enjoyed. As part of that love-hate relationship with the West, Russian policy has long [balanced globalism and isolationism]( /#/node/intelligence_alert/view/fffd1701-8cd3-4237-b11b-31270d686f61). Over the years, Russian officials and businesses have sought to preserve Russian positions in global markets and attract global investors, but as the sanctions have tightened, Russia has increasingly emphasized import substitution policies and preparations for working alone. Events in 2020 to 2021 seem to favor isolationism. Independent Russian pollster Levada found in a February 2021 survey that only 29 percent of respondents consider Russia a European country, down from 52 percent in 2008. \n\nThe [increased sanctions](https://www.bellingcat.com/news/2021/03/19/berlin-assassination-new-evidence-on-suspected-fsb-hitman-passed-to-german-investigators/) from the US and EU in 2020 for human-rights concerns have heightened international tensions.  Media reporting suggests US officials are discussing additional sanctions for Russia’s suspected involvement in the [SolarWinds espionage campaign](/#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4). In a 16 March 2021 interview, US President [Joe Biden warned](https://www.politico.com/news/2021/03/17/biden-putin-election-interference-476656) that Putin would “pay a price” for Russian influence operations in the 2020 US election. [He also said, “I do,”](/#/node/intelligence_alert/view/3ee020e9-c64f-4c3f-8162-73f80ad85863) when asked whether he considered Putin a killer,  prompting Russia’s foreign ministry to recall its ambassador from Washington for the first time since 1998.\n\nGiven these priorities and circumstances, iDefense assesses that Putin and strategists strive for: \n-\tA loyal population \n-\tSome restoration of Russia’s Soviet-era influence and prestige\n-\tAn end to sanctions\n\n#### Aspirations in the Energy Sector \n\nThese overall goals and strategies have implications for Russian policies in the energy sector. iDefense assesses that Russian aspirations include: \n- [Preserving Russian markets for oil and gas](https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/) \n- Meeting challenges from rival trends such as liquefied natural gas, shale gas, and renewables\n- Maintaining control over pipelines\n- Gaining visibility into and leverage over decision-making in oil and gas markets and policies worldwide\n- Obtaining foreign energy-related technologies that have both civilian and military uses, as evident in reports from [Norway](https://www.reuters.com/article/us-norway-oil-security/russian-chinese-intelligence-targeting-norwegian-oil-secrets-report-idUSKBN28D2M7), the [Netherlands, and Denmark]( https://www.euronews.com/2020/12/09/russian-citizen-charged-with-spying-on-energy-technology-in-denmark)  \n- Slowing energy sector development in  adversary countries, sometimes by [encouraging environmental activists there](https://www.inc.com/magazine/201905/tom-foster/russian-trolls-facebook-social-media-attacks-brands-hoax-fake-disinformation.html ) \n\nTo pursue these goals, Russian strategists can choose among a variety of options, including diplomatic, economic and soft power; military action; and asymmetric approaches, such as cyber-threat activity and cyber-enabled information operations.\n\n##Cyber-Threat Capabilities\n\nCyber-threat groups that US and other governments have linked to Russia have helped Russia advance its state strategies through espionage, disruptive activity, and disinformation. Russia’s military and security agencies occasionally perform operations using tools, techniques, and personnel drawn from the Russian-speaking cybercriminal underground. \n\n####Energy Backdooring: BLACK GHOST KNIFEFISH\n\nThe US government has linked [BLACK GHOST KNIFEFISH](/#/node/threat_group/view/27332f70-302c-491a-85f2-3714218296b8) (a.k.a. Dragonfly, Berserk Bear, Energetic Bear) to the Russian government. The group is known for targeting energy entities in multiple countries. \n\nIn March 2018, the US Department of Homeland Security’s Cybersecurity and Infrastructure Security Agency, or CISA, [wrote](/#/node/intelligence_alert/view/c79d8446-28a9-4b20-a5bb-d9ac5ff4a6de):\n\n```\nRussian government cyber actors…targeted small commercial facilities’ networks…gained remote access into energy sector networks…conducted network reconnaissance, moved laterally, and collected information pertaining to Industrial Control Systems (ICS)…DHS was able to reconstruct screenshot fragments of a Human Machine Interface (HMI) that the threat actors accessed. (See Exhibit 4.)\n```\n\n![Dragonfly Screenshots](/rest/files/download/27/f6/e2/72a551319a5908267b8a45e616313115f032bc8442bdf38430cc12f1e6/DragonflyScreenshotsFromUSCERTMarch152018cropped.png)  \n_Exhibit 4: Reconstructed HMI Screenshot Fragments, US CISA Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors, 16 March 2018_ \n\n\nAn April 2018 [US and UK government alert warned]( /#/node/intelligence_alert/view/21ab89f6-1ac1-4cc3-83f6-233a5d7473cf) of Russian government-supported cyber-threat operations matching activity that iDefense tracks as BLACK GHOST KNIFEFISH. The activity targeted network infrastructure devices (such as routers, switches, firewalls, and network intrusion detection systems) enabled with the generic routing encapsulation protocol, Cisco Smart Install feature, or simple network management protocol. The threat actors conducted man-in-the-middle attacks for espionage, to steal intellectual property, and potentially to prepare for future disruptive or destructive activity. \n\nSigns of cooperation exist between BLACK GHOST KNIFEFISH and BELUGASTURGEON (a.k.a. Turla), which US and UK officials say is “widely reported to be associated with Russian actors” and which Estonian and Czech authorities have [identified with](https://www.reuters.com/article/us-russia-cyber/hacking-the-hackers-russian-group-hijacked-iranian-spying-operation-officials-say-idUSKBN1X00AK)  Russia’s [Federal Security Service](/#/node/threat_group/view/d96f3b14-462b-4ab4-aa04-23c7a2996611) (FSB). BELUGASTURGEON’s targets are mostly political entities but have included the [Armenian natural resources ministry](https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes), and, as mentioned above, the threat group carried out false flag operations framing Iranian threat actors.\n\n####Military Hackers: SANDFISH and SNAKEMACKEREL\n\nRussia's cyber-threat capabilities include groups the US government has linked to Russia's military intelligence agency, the GRU.\n\nThe US and other governments have attributed numerous destructive operations, including the Ukrainian blackout of 2015 and the Crashoverride series of attacks in 2016, to a group that iDefense tracks as [SANDFISH](/#/node/threat_group/view/40d2cf30-237a-467b-826d-390f12cc27f0) (a.k.a. SANDWORM).\n\nThe Ukrainian blackouts fit Russia's strategic goals of weakening Ukraine. The electricity blackout from the December 2016 Crashoverride operation was merely the [culmination of a two-week series of attacks]( /#/node/intelligence_alert/view/f7c3ae17-869a-4025-9edb-a6e8c4ca7a3e) that also disrupted operations at the State Treasury; the Finance Ministry, Defense Ministry, and other government entities; an Internet provider; and the railways. Ukrainian citizens could not receive pensions or buy rail tickets. The attempt to disrupt Ukrainian everyday life was likely intended to discredit the leadership of its then-president, who was particularly hostile to Russia.\n\nSANDFISH has also targeted oil and gas companies in Ukraine and Azerbaijan [using GreyEnergy malware]( /#/node/intelligence_alert/view/f0289fe9-c076-437b-984f-71f17d6f7950). SANDFISH tools Exaramel and PAS Shell appeared in a campaign that ran from 2017 to 2020 and compromised French IT and web-hosting companies [running Centreon monitoring software]( /#/node/intelligence_alert/view/55004ca2-e598-460f-bb0c-8ef6f37b7bca). French energy giant Total is one of Centreon's customers. \n\nAs for the military hacker group [SNAKEMACKEREL](/#/node/threat_group/view/065336a6-651d-4f80-b8c2-9347f4486912) (a.k.a. APT28, FancyBear), in May 2020, the [US FBI reportedly warned](/#/node/intelligence_alert/view/575c5eef-0784-46cd-bf67-8e256d0c2fc7) that the group had been targeting US government agencies and educational institutions since December 2018. According to a July 2020 report from the news source Wired, a SNAKEMACKEREL IP address from the FBI alert matched one from an earlier report advisory, drawing speculation that SNAKEMACKEREL had targeted an entity in the US energy sector—a departure in targeting for the group. The DOE-named IP address might have represented infrastructure that both SNAKEMACKEREL and SANDFISH used. The threat actors sent spear-phishing emails to  personal and work email accounts and leveraged password-spraying and brute-force tactics to compromise victims’ mail servers, Microsoft Office 365 and email accounts, and VPN servers, according to Wired. \n\nEarlier, in 2014 and 2015, SNAKEMACKEREL operators also conducted a spear-phishing campaign [against Westinghouse Electric Company](/#/node/malicious_event/view/aff26f9b-2f45-483c-996a-e058fc02a84a), according to a US indictment.\n\nIf SNAKEMACKEREL successfully breached a US energy entity or Westinghouse, Russian intelligence might have gained insight into upcoming deals with countries of interest to Russia. Westinghouse supplies uranium to Ukraine and has bid for contracts to build nuclear power plants for Saudi Arabia.\n\nSNAKEMACKEREL and SANDFISH seek deniability by disguising themselves as criminals or hacktivists:\n- During the [PetyaA/NotPetya campaign](/#/node/intelligence_alert/view/e4cac05c-83a4-40e3-b8b2-190c7c405ee0) against Ukraine in 2017 that US officials attributed to SANDFISH, the perpetrators pretended to be criminal ransomware actors. \n- When conducting hack-and-leak operations, these GRU actors often [hid behind pseudo-hacktivist personas](/#/node/intelligence_report/view/bd237f19-3b9f-4ea1-8f32-b9edd4667126), such as Guccifer 2.0 and Fancy Bears Hack Team, to discredit and divide societies in the US and other countries and entities seen as hostile to Russia. \n\n\n####Threatening Industrial Safety Systems: ZANDER\n\nRussia's cyber-threat capabilities may also include a group iDefense calls [ZANDER]( /#/node/threat_group/view/a363a7ca-1d5d-4477-9ce9-e9259cb888e4), which the US government has linked to Russia’s [Central Research Institute for Chemistry and Mechanics](/#/node/threat_group/view/99890a07-ddca-491d-ae7e-ae22a53db690) (TsNIIKhM). \n\nIf successful, the August 2017 Triton malware attack on the operational technology systems of a refinery in Saudi Arabia [could have endangered human lives](https://www.slideshare.net/JoeSlowik/past-and-future-of-integrity-based-attacks-in-ics-environments).  Researchers attributed the activity to TsNIIKHM, an institute subordinate to the Russian defense ministry’s Federal Service for Technical and Export Control. Having sufficient confidence in this attribution, on 23 October 2020, the US Treasury Department added TsNIIKhM to its Specially Designated Nationals sanctions list in connection with the August 2017 Triton attack.\n\nThe Triton attack was likely meant to create a backdoor for potential disruptive activity, gain leverage over a key company in the petroleum sector, and potentially discredit or influence Saudi policies regarding oil production levels and prices as well as Saudi relationships with other Middle Eastern countries. \n\nZANDER has also targeted the electricity sector. Since late 2018, they have been searching for remote login portals and vulnerabilities in the networks of at least 20 targets in electricity generation, transmission, and distribution systems in the US and Asia Pacific, according to E-ISAC and Dragos reports from June 2019. \n\n####JACKMACKEREL\n\nAnother Russian cyber-threat group with impact on the energy sector is [JACKMACKEREL]( /#/node/threat_group/view/24a38270-949f-442a-aac6-53a99ef1ea70) (a.k.a. Cozy Bear, the Dukes, APT 29). The Estonian government has linked this group with both the FSB and the SVR, Russia’s [Foreign Intelligence Service](/#/node/threat_group/view/11759430-3417-4772-9723-43bb38fe2280).\n\nSome analysts attribute the SolarWinds operation of 2020 to JACKMACKEREL. However, iDefense has [compared the malware and infrastructure](/#/node/intelligence_alert/view/7128fb11-2753-4f4d-aa51-2c13731f7dbe) used in the SolarWinds operation with JACKMACKEREL tools and found some important differences. In April 2021, the US government formally attributed the SolarWinds campaign to the SVR, linking the SVR to the APT29 threat group. In the absence of further detail, [Accenture iDefense cannot currently verify this attribution](/#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4) and is tracking this activity as action from the distinct threat group FireEye calls UNC2452.\n\nRegardless of exact attribution of the SolarWinds operation, the SVR is certainly involved with Russian cyber-threat activity and conducts espionage and pressure campaigns to promote Russia’s economic and political interests abroad. \n\n[Past SVR activities include](PUTINS_HYDRA_INSIDE_THE_RUSSIAN_INTELLIGENCE_SERVICES_1513.pdf) pilfering renewable energy technologies, stealing commercial information such as tenders, or coercing cooperation from people who allocate contracts, according to reports analyzing Russian intelligence services. Stealing commercial information and coercing people can help boost Russian competitiveness in winning oil and gas contracts, while stealing technologies can help Russia compete with or weaken companies developing renewable energy.\n\nThe intelligence service responsible for the SolarWinds operation [specifically targeted](/#/node/intelligence_report/view/eb77c712-fcfd-48f6-9533-baa18131fb62) US report entities, including Sandia and Los Alamos national laboratories in New Mexico and Washington, the Office of Secure Transportation at the report, and DOE’s Richland field office, as well as the Federal Energy Regulatory Commission. In addition, researchers have identified Chevron Texaco as one of 23 entities the threat actors targeted for follow-on activity. These breaches could potentially provide valuable information on the resilience of the US electric grid and nuclear power plants as well as providing insight into Chevron Texaco’s business plans and agreements in contested areas such as the eastern Mediterranean. Note that Cyprus contracted with Chevron subsidiary Noble Energy to drill gas in Cyprus-controlled zones.\n\n####Hybrid Ransomware Operations and EvilCorp \n\nIn addition to the straightforward state-sponsored espionage or disruptive activity discussed above, Russian-state threat groups sometimes hide behind the mask of criminal ransomware. An iDefense compendium of ransomware or data leak [events affecting the energy and utility sectors]( /#/node/intelligence_report/view/999b6c55-3cb8-4372-affb-bcc9c47dd95b) includes breaches of NorskHydro, the Norwegian metals and energy company, and of Mexican oil company Pemex. iDefense has grounds to characterize these with low-to-medium confidence as “[hybrid ransomware]( /#/node/intelligence_report/view/034b4162-239d-438e-8e85-490103b83e5d)” operations. Such operations involve cybercriminals and intelligence services cooperating for mutual benefit, or they are intended to disrupt operations or destroy or exfiltrate data rather than only to extort a ransom payment. Most famously, the June 2017 Petya.A/NotPetya attack in Ukraine was a Russian-state operation disguised as criminal ransomware.\n \nRussian-state cyber-threat operations sometimes draw on tools and personnel from the Russian-speaking cybercrime world, as iDefense has extensively documented and as  [American](/#/node/intelligence_alert/view/575c5eef-0784-46cd-bf67-8e256d0c2fc7) and [Canadian](/#/node/intelligence_alert/view/9fe9f478-a5bb-405d-846a-b6baac07c431) governments have noted. \n\nRussian cyber-criminals [have worked with FSB operatives](/#/node/intelligence_alert/view/0f78f6ba-f0aa-4078-b70a-674cd12d2643) and [received protection](/#/node/intelligence_alert/view/6c403e44-c382-4ed6-aabf-23d0d353c0ba) from highly placed people. When caught by Russian law enforcement, they [are often pressured](/#/node/intelligence_alert/view/130d2acb-9778-4b22-96a8-5c47115f2659) to participate in Russian intelligence missions or consider geopolitical factors in future targeting.\n \nFor example, ransomware operator GandCrab promised in October 2018 to provide decryption keys to people in Russia’s war-torn ally Syria but vowed never to release keys to victims in other countries, as “we need to [continue punitive proceedings]( /#/node/malicious_event/view/ff63b317-2de3-4ba3-828a-d294eab5b91f) against certain countries.” Self-proclaimed hacker and onetime government contractor [Pavel Sitnikov](/#/node/threat_actor/view/ca0ed890-16a4-460c-aa44-69c23914c2b0) in December 2020 stated, “ransomware and special services are inseparable.”  \n\nThe EvilCorp group (a.k.a. [HighRollers](/#/node/threat_group/view/8eb76c68-4d9a-4397-8cc6-e779f9ee8b50), TA505, Dridex Group) exemplifies the intersection between criminal and intelligence activity. According to the US Treasury Department, EvilCorp leader [Maksim Yakubets](/#/node/threat_actor/view/df442e94-f0df-4ec1-9d35-57bedf1a9223) has done contract work for the FSB, and investigative journalists report he is married to an active FSB veteran.\n\nEvilCorp played a role in DoppelPaymer and Clop (a.k.a. Cl0p) ransomware operations. On 10 December 2020, the FBI warned the US private sector that [DoppelPaymer actors were targeting critical infrastructure](/#/node/intelligence_alert/view/8c5412b6-f114-47a4-afd1-5e5f0a88d10b) including the 911 emergency service, according to media accounts. The DoppelPaymer actors have breached and leaked information on numerous companies involved in defense or national security as well as public safety work. DoppelPaymer actors leaked data from [numerous aerospace and defense contractors](/#/node/malicious_event/view/238857cc-12f3-4fac-820a-c59dc58c27da) including Schlumberger Technology, Hyundai’s [Kia Motors](/#/node/malicious_event/view/d009718a-25f6-491f-95f2-528d0a3d3f63), [Boyce Technologies ](/#/node/intelligence_alert/view/5a23f8ed-8038-4727-bb4d-5016c57e10f5), and NASA contractor [Digital Management Inc.]( /#/node/intelligence_alert/view/6613f584-7728-4bd4-9dd7-103aef9b30ec)\n\nThe November 2019 DoppelPaymer [ransomware attack on the Mexican national oil company Pemex]( /#/node/malicious_event/view/238857cc-12f3-4fac-820a-c59dc58c27da) appears to have combined financial and  political motivations. EvilCorp had an incentive to retaliate against or discredit Pemex and Mexican President Andrés Manuel López Obrador (a.k.a. AMLO): EvilCorp leader Yakubets’ father-in-law, retired from Russian intelligence, runs a private security company that provided security for Russian company Lukoil. The Mexican government shunned Lukoil and other foreign investors when attempting to build a self-sufficient Mexican oil industry. During the spring 2018 presidential campaign, pro-AMLO Pemex employees rallied holding signs showing feet kicking the logos of companies like Lukoil. Leaked Pemex documents could also provide evidence in [trials of former Pemex officials]( /#/node/malicious_event/view/05982e7e-b7d0-4203-a8a9-dd46ea769854) for their dealings with scandal-plagued Brazilian company Odebrecht.  This provides an example of a Russian-state malicious actor targeting an oil and gas entity for apparent financial profit and to support Russian national interests.\n\nEnergy companies were also victims in cloud provider [Accellion’s File Transfer Appliance software breach]( /#/node/intelligence_alert/view/c68c3558-7540-4a74-9af3-5b1d243f852e). Some victims received extortion emails from actors threatening to publish stolen data on the “CL0P^_- LEAKS\" .onion website. Clop actors have stolen information with national security value, such as specifications for Bombardier’s military spy plane.  Samples of data from [geophysical services company CGG]( /#/node/malicious_event/view/c069f7c1-7b22-4713-a1d9-b1ba041602e8) and [transportation company CSX]( /#/node/malicious_event/view/0e1a64c4-e283-457b-b615-9863436b0dbd) were also leaked on the site. \n\nRansomware negotiator [Coveware’s analysis](https://www.coveware.com/blog/2021/2/18/q4-doxxing-victim-trends-industrial-sector-emerges-as-primary-ransom-non-payor) of leaks of victim data on ransomware operators’ sites in the last quarter of 2020 indicates the Clop group focused on the energy and technology sectors, whereas the industrial sector suffered most leaks on other groups’ sites. Clop’s geographic targeting also overlaps with Russian-state priorities, according to Coveware’s analysis: 43 percent of Clop leaks were from victims in Germany.   Russia [has aimed hostile rhetoric](https://euvsdisinfo.eu/villifying-germany-wooing-germany/) against that country’s leadership for spearheading EU sanctions against Russia.",
    "conclusion": "To protect against state-sponsored or state-directed cyberthreat activity, iDefense suggests that organizations consider: \n\n * Assessing the threat landscape of critical infrastructure and high-value organizations \nto determine the likelihood of nation-state actors targeting them to steal intellectual property or fulfill strategic requirements.\n\n * Understanding the strategic priorities of China, Iran, North Korea, and Russia to identify high-value data targets and at-risk technologies, information, and business operations.\n\n * Strengthening the organization's cyber defenses through network defense operations, network architecture and design, third-party relationships, software and hardware procurement, user training and security culture building, travel and communication policies, employee vetting and insider threat mitigation, and security partnerships including information-sharing communities, government partners, and contracted security and threat intelligence services.\n\n * Evaluating the organization's key mission and business drivers that align to adversarial states’ priorities.\n\n * Reviewing and updating the organization's knowledge of sanctions lists to ensure critical and high-value organizations only interact and engage with approved and relevant individuals and entities.\n\n * Implementing a proactive cybersecurity strategy and legal framework that defines and addresses changing roles and responsibilities for all parties involved in any security incident.\n\n * Implementing the latest patches for Internet-facing servers, systems, databases, and applications.\n\n * Conducting due diligence on third-party contractors.\n\n * Using multi-factor authentication for corporate network access where possible.\n\nTo counter Russian and other cyber-threats, organizations can focus on specific user-level and system-level defense actions and strategies. This can include educating employees to:\n\n- Resist clickbait \n- Resist over-sharing information online and in emails\n- Doubt questionable links or attachments\n- Check for spoofed URLs and email sender addresses (posing as officials, suppliers, or job seekers)\n\nOrganizations may also consider policies to:\n- Disallow emails with embedded macros \n- Audit network and processes for anomalies\n- Practice red/purple teaming\n- Use IP and port allow- and block-listing  \n- Back up data offsite\n- Disable SMBv1 and RDP if possible",
    "report_type": "Report",
    "summary": "The oil and gas sector is central to Russia's revenue stream as well as the Russian government's economic relationships with the rest of the world. President Vladimir Putin’s government has pursued multiple strategies, including cyber-threat activity, in response to the global and domestic challenges Russia faces in a changing world. Russian-state espionage and disinformation operations as well as disruptive or destructive activity that can occur under the guise of criminal activity or hacktivism have historically targeted organizations in the energy industry and will likely continue to do so."
}


expected_output_ia = {
    'DBot': [{'Indicator': 'a487dfdc-08b4-4909-82ea-2d934c27d901', 'Type': 'ACTI Intelligence Alert', 'Vendor': 'ACTI Threat Intelligence Report', 'Score': 2, 'Reliability': 'B - Usually reliable'}],
    'IA': [{'value': 'a487dfdc-08b4-4909-82ea-2d934c27d901', 'created_on': '2021-03-05T21:47:36.000Z', 'display_text': 'Kazuar Revamped: BELUGASTURGEON Significantly Updates Its Espionage Backdoor', 'dynamic_properties': {}, 'index_timestamp': '2022-02-09T14:18:19.333Z', 'last_modified': '2021-07-14T09:17:37.000Z', 'last_published': '2021-03-05T21:47:36.000Z', 'links': [{'created_on': '2017-05-04T17:45:51.000Z', 'display_text': 'Kazuar', 'key': 'Kazuar', 'relationship': 'mentions', 'relationship_created_on': '2021-03-05T21:47:36.000Z', 'relationship_last_published': '2021-03-05T21:47:36.000Z', 'type': 'malware_family', 'uuid': 'ef5a7376-0a81-4478-b15d-68369e7196bd', 'href': '/rest/fundamental/v0/ef5a7376-0a81-4478-b15d-68369e7196bd'}, {'created_on': '2020-08-07T20:08:29.000Z', 'display_text': 'Russia-Linked BELUGASTURGEON Uses ComRATv4 to Target Government and Resources Organizations in Europe and Central Asia', 'key': '033355e6-e57e-4a02-bf3a-c9805d06a259', 'relationship': 'mentions', 'relationship_created_on': '2021-03-05T21:47:36.000Z', 'relationship_last_published': '2021-03-05T21:47:36.000Z', 'type': 'intelligence_report', 'uuid': '9bf2fc44-570d-40ad-b81a-744141ed443e', 'href': '/rest/document/v0/9bf2fc44-570d-40ad-b81a-744141ed443e'}], 'threat_types': '\n- Cyber Espionage', 'title': 'Kazuar Revamped: BELUGASTURGEON Significantly Updates Its Espionage Backdoor', 'type': 'intelligence_alert', 'uuid': 'a487dfdc-08b4-4909-82ea-2d934c27d901', 'analysis': '## Key Findings and Judgements\n\n- From analyzing two Kazuar samples, iDefense determined that BELUGASTURGEON has significantly updated the backdoor\'s codebase when compared to traditional Kazuar samples.\n\n- The updated variant\'s core functionality supports new commands for espionage campaigns, including keylogging, credential theft, and system enumeration, without requiring additional plugins.\n\n- BELUGASTURGEON operators can now communicate between Kazuar instances  using task forwarding over named pipes without needing Internet connectivity; these enhancements offer functionality similar to that in Carbon and Uroborus.\n\n- Multiple Kazuar infections can now exist on one compromised system but target different users due to updates in Kazuar\'s mutex generation function.\n\n- HTTP(S) command-and-control (C2) communications now use primary, backup, and last-chance C2 servers to maintain persistence on a compromised device even if some of BELUGASTURGEON\'s infrastructure is unavailable.\n\n- Because Kazuar can now load from a Windows Registry key into memory, an infection file does not exist on the device and the chance of detection is reduced.\n\n- A comparison of the samples from August 2020 and February 2021 reveal differences in the Kazuar command set and configuration settings. Based on the discovery times of these samples and the changes between them, iDefense assesses the new Kazuar variant is under active development and BELUGASTURGEON will continue to use it for espionage campaigns.\n\n## Overview\n[Kazuar](https://intelgraph.idefense.com/#/node/malware_family/view/ef5a7376-0a81-4478-b15d-68369e7196bd) is a .NET backdoor the [BELUGASTURGEON (a.k.a. Turla, Snake, Waterbug, Venomous Bear)](https://intelgraph.idefense.com/#/node/threat_group/view/fb53e479-54e1-4827-abb4-ae1ae1db53e2) threat group has been using in espionage campaigns since at least 2017. [The Kazuar variant that Palo Alto Networks detailed in May 2017](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) has commands typical of many backdoors, such as reading, writing, copying, moving, and deleting files on the compromised system; executing commands from the command line; taking screenshots; and capturing webcam images. The version is extensible using a plugin framework to achieve additional functionality. The remote API allows BELUGASTURGEON operators to direct the backdoor to act as a web server and listen for inbound HTTP requests. iDefense identified this version of Kazuar used in various BELUGASTURGEON activity, including a [2020 campaign against the Cypriot government](https://intelgraph.idefense.com/#/node/intelligence_alert/view/6cc805d7-cb77-443d-afea-d052916fa602).\n\nSince its discovery in 2017, developers have been enhancing Kazuar. In 2019, security researcher [Juan Andrés Guerrero-Saade identified](https://www.epicturla.com/blog/sysinturla) Kazuar samples branded to look like the Microsoft SysInternals tool [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview). In addition to cosmetic changes, the Kazuar developers moved to a custom packer instead of  obfuscating Kazuar\'s code with [ConfuserEx](https://yck1509.github.io/ConfuserEx/). \n\nIn the campaign against the Cypriot government, BELUGASTURGEON operators implemented a novel C2 configuration where the Kazuar backdoor receives commands from URLs pointing to internal nodes in the Cypriot government network. [Another Kazuar sample acted as a transfer agent](https://intelgraph.idefense.com/#/node/malicious_event/view/2c3490cd-c4bb-4aef-b75f-641b76dcff01), proxying commands between the sample with the novel C2 configuration and the C2 server. Despite these developments, the underlying Kazuar codebase, including the backdoor\'s command set and configuration, remained mostly unchanged.\n## New Kazuar Functionality \nIn February 2021, Defense analyzed two Kazuar samples and noted significant changes in the codebase,  command set, and configuration functionality to warrant classifying the samples as a new variant of the Kazuar backdoor. One sample, shared by an industry partner, was first seen in August 2020; the second sample was uploaded to a third-party malware repository in February 2021. \n\nThe new variant persists on the system by storing the packed Kazuar binary in the Windows Registry and loading itself into memory at runtime without writing an infection file to disk. The variant offers new credential stealing and keylogging functionality, executes payloads in a range of file formats, and enumerates a wide range of system information about the compromised device. \n\nThe backdoor has a built-in command that forwards tasks to other Kazuar instances in a compromised network via named pipes. The ability to communicate among Kazuar instances as well as the overall extended functionality implemented without plugins allows Kazuar to achieve the functionality of some of BELUGASTURGEON\'s more sophisticated backdoors, such as [Carbon](https://intelgraph.idefense.com/#/node/malware_family/view/5c48cd58-180b-4d02-b344-5756f3a6fb33) or [Uroborus](https://intelgraph.idefense.com/#/node/malware_family/view/7c5fc18d-bab8-4928-a716-9b0c5a92a022).\n\nThe new Kazuar variant appears intended for Windows systems as developers have removed the UNIX-related code found in the earlier variant. Other functionality removed includes the remote HTTP API that is replaced with the task forwarding functionality allowing operators to configure Kazuar instances to listen for tasks from other "remote" Kazuar instances. \n\nIndications the Kazuar variant is under active development include an Agent Label value, discussed in more detail in the *Configuration Comparison* section, that is likely a version number incremented when there is a new iteration of the backdoor. iDefense also identified changes in the commands and configuration between the sample from August 2020 and February 2021. \n\niDefense analyzed the following samples of the new Kazuar variant:\n\n- **Filename (packed):**  Agent.Protected.exe  \n - **SHA-256 (packed):**  182d5b53a308f8f3904314463f6718fa2705b7438f751581513188d94a9832cd   \n\n - **Filename (unpacked):**  Agent.Original.exe  \n\n     - **SHA-256 (unpacked):**  41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb  \n     - **File Size (unpacked):** 267 KB  \n     - **Agent Label:**  AGN-AB-03  \n     - **First Seen:** August 2020 (identified by industry partner)\n\n* **Filename (packed):**  Relieved.exe  \n\n - **SHA-256 (packed):**  60f47db216a58d60ca04826c1075e05dd8e6e647f11c54db44c4cc2dd6ee73b9  \n\n  - **Filename (unpacked):**  Musky.exe  \n\n     - **SHA-256 (unpacked):**  1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4     \n     - **File Size (unpacked):** 291 KB  \n     - **Agent Label:** AGN-AB-13  \n     - **First Seen:** 15 February 2021 (uploaded to third-party malware repository)  \n\n\nThe following sections examine the differences between the new variant and the traditional Kazuar variant and the areas of active development in the new variant.\n## Codebase Comparisons \niDefense compared the codebase of the  version of Kazuar [detailed by Palo Alto Networks in May 2017](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/), which will be referred to as the “traditional” variant,  and two samples of Kazuar from August 2020 and February 2021, the “new” variant,  and identified the following significant variations.\n#### Installation and Persistence\n\n**Traditional Kazuar Variant**\n\nThe traditional version of Kazuar is written to disk on the compromised machine. To maintain persistence on the machine, BELUGASTURGEON  adds  a Windows shortcut (LNK) file to the Windows startup folder or adds a subkey to one of the following Windows Registry keys:\n\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n- HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\n- HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load\n\nOnce the LNK file or Registry key is configured, the Kazuar binary launches at user logon. Operators can configure the persistence method using the “autorun” command.\n\n**New Kazuar Variant**\n\nRather than write the binary to disk, the new Kazuar variant installs itself directly in the Windows Registry. For the sample with Agent Label AGN-AB-03, BELUGASTURGEON operators created a Registry subkey under `HKLM\\SOFTWARE\\Microsoft\\ActiveSync` with the name "Jhkr." The subkey data contains an obfuscated VBScript that, when deobfuscated, is likely a modified version of the publicly available [VBSMeter](https://github.com/Cn33liz/VBSMeter). (VBSMeter is a Meterpreter stager for C# assemblies embedded in VBScript.)\n\nThe packed Kazuar binary is stored in one of the VBScript parameters. When launched, the VBScript  checks for a compatible version of the .NET framework installed on the compromised machine, Base64-decodes the packed Kazuar binary from the parameter, deserializes it, and invokes the packed binary in memory. The VBScript then writes the TXT log file ~TMP0666.tmp into the user\'s `%Temp%` directory. The packing algorithm is simple: XOR decode and decompress the encoded payload that is initially stored in an array. \n\nKazuar sample AGN-AB-13 is loaded from the Registry key `HKCU\\SOFTWARE\\Microsoft\\Arrases\\Canoed`. iDefense was unable to obtain the value of the Registry key to confirm the same VBScript loaded the sample into memory but assesses this is likely. \n\nThe same packing algorithm encodes the samples in the Registry key. The packed sample writes any unpacking errors to log file `%Temp%\\~TMP0666.txt`, as shown in Exhibit 1. This logging functionality was not present in the packed AGN-AB-03 sample, only in the VBScript used to load the sample.\n\n![alt text](/rest/files/download/34/05/ab/e72860f9a0223f242f42e8301dded7b91c3ed03c611fe4892218edc845/exhibit1.PNG)  \n_Exhibit 1: Packing Algorithm and Logging Functionality for Packed Kazuar Sample_\n\niDefense has not yet determined how BELUGASTURGEON operators gain initial access to the machine and install the Registry keys containing the new variant of Kazuar.\n\n#### Initialization\n\n\n###### Mutex \n\n**Traditional Kazuar Variant**\n\nWhen launched, the traditional Kazuar version gathers system information and generates a [mutex](https://docs.microsoft.com/en-us/windows/win32/sync/mutex-objects)  that ensures only one instance of Kazuar is running on the compromised machine. The mutex is generated using the following steps:\n\n- Obtain the MD5 hash of a string “[username]=>singleton-instance-mutex”\n- Encrypt this MD5 hash using an XOR algorithm and the volume serial number \n- Generate a GUID from the result  and append it to the string “Global\\\\”\n\nExhibit 2 shows how the traditional Kazuar variant generates the mutex. [According to Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/), if the variant cannot obtain the system’s storage serial number, it uses a default version of 0xFB1C1A. \n\n![alt text](/rest/files/download/4c/0b/15/a539a2cb938e5d10409cc8d119cfd79400a5e03f37badb37de5e24b0ec/Exhibit2.PNG)   \n_Exhibit 2: Traditional Kazuar Variant Mutex Generation_\n\n**New Kazuar Variant**\n\nThe new variant of Kazuar generates its mutex by XOR-encoding the System Universal Unique Identifier (UUID) value with the current process ID (PID), which has been XOR-encoded with two hardcoded values, as shown in Exhibit 3. The resulting mutex no longer has the prefix  “Global\\\\” indicating it is a local mutex and multiple Kazuar infections can co-exist for different users on one compromised device.\n\n![alt text](/rest/files/download/6d/d8/60/c2914f57d474b1af992bb235466556128510fb251f416728a646a3eb67/Exhibit3.PNG)   \n_Exhibit 3: New Kazuar Variant Mutex Generation_\n\n###### Files Written\n\n**Traditional Kazuar Variant**\n\nThe traditional Kazuar variant writes folders that store the files it generates during execution. The variant writes the folders in the %LocalAppData% directory under a path beginning with "Microsoft" and selected from a hardcoded list (see Exhibit 4). The filenames are encoded on disk by calculating the FNV-1a hash of the filename string and XOR-encoding the  hash with the volume serial number and the hardcoded constant 0xBADA55, as shown in Exhibit 5.\n\n ![alt text](/rest/files/download/76/e7/5e/5aae52246f80c7a335e9b32222b09d8c417f9bf9dc931a256626cff650/Exhibit4.PNG)   \n_Exhibit 4: Directory Location for Configuration Files, Traditional Kazuar_\n\n![alt text](/rest/files/download/67/8d/04/34b9f163f8295a86bd222a9d798bbfc0930a34d1c4823af74db2b2b5ba/Exhibit5.PNG)   \n_Exhibit 5: Filename Encoding for Traditional Kazuar_\n\nThe traditional version of Kazuar creates the following folder structure: \n\n- **base:** Folder containing the following subfolders:\n   - **sys:** Folder containing configuration settings in the following files:\n        - \'serv\'  – Stores the C2 servers. \n        - \'arun\' – Stores the autorun method. \n        - \'remo\' – Stores the remote type. \n        - \'cont\' – Stores the date of last contact with the C2 server. \n        - \'uuid\' – Stores the compromised device\'s System UUID.\n        - \'tran\' – Stores the transport type.\n       - \'intv\' – Stores the transport interval.\n\n - **log:** Folder containing logs and debug information.\n - **plg:** Folder containing plugins used to extend Kazuar\'s functionality.\n - **tsk:** Folder tasks for Kazuar to run.\n - **res:** Folder containing results of processed tasks.\n\n**New Kazuar Variant**\n\nLikewise, the new variant of Kazuar writes files to disk during execution under the `%LocalAppData%` directory selecting paths from a hardcoded list beginning with "Microsoft"; however, that list is longer in the new version, as shown in Exhibit 6.\n\n![alt text](/rest/files/download/47/2f/cd/d9b75728ce7e443002d93d1e34bb40ae6b11dc7612f2a43f03f842a8ce/Exhibit6.PNG)   \n_Exhibit 6: Directory Location for Configuration Files, New Kazuar_\n\nExhibit 7 shows the filename-encoding function for the new variant of Kazuar. Rather than generating 8-digit hex strings, as done previously, the new version generates 15-digit alphanumeric strings for filenames and folders. Filenames are also appended with a 3-digit file extension. The System UUID is used as a seed and the process involves a series of XOR encodings and a [custom implementation of the FNV-1a hashing algorithm](https://securelist.com/sunburst-backdoor-kazuar/99981/).\n\n![alt text](/rest/files/download/04/30/8d/ba1b97d2f491900af81e852f9076ae8911770c73517a25003a2d30bf16/Exhibit7.PNG)   \n_Exhibit 7: Filename Encoding for New Kazuar_\n\nThe list below contains the file tree of folders and files the new variant creates along with the encoded and decoded filenames. There is still a base folder and folders to contain the log messages and tasks. Kazuar\'s configuration data is now stored under the "config" folder, similar to the "sys" folder in the previous variant. (See the *Configuration Comparison* section below for more details.) The "keys" file under the "logs" folder stores keystrokes captured when the new keylogger is enabled. \n\n```\n%LOCALAPPDATA%\\MICROSOFT\\OFFICE\\VISIO\\ROT3BMLH2ZGRF9X9 (base)\n|\n|_ i4px5nL5PqksWMb.wgw (logs)\n|\n|_ 2YpvIxMopuiQqHsmc   (task)\n|\n|_ i4px5nL5PqksWMb     (logs)\n|          |_ T9j8NFq6Bwtna1B0ej.rub   (keys)\n|       \n|_Tk7Zu3EKOMqtjTnw     (config)\n        |_ 8c9lq3nL3Vv0bGX.apa   (solve_threads)\n        |_ E8rHL1RRAujyu.cea     (keylog_enabled)\n        |_ MTDLUlXsgIf.yni       (transport)\n        |_ O1a1lIxAqUskBdQUf.ebd (amsi_bypass)\n        |_ OiF6UrrFDBhgcwa.qgg   (inject_mode)\n        |_ QQECzNniEHuKHih2f.oli (delegate_enabled)\n        |_ TqTHomCER6vz.zks      (agent_label)\n        |_ tLkhmS2L3cg5.flo      (remote)\n        \n```\n\n###### Execution Paths\n\n**Traditional Kazuar Variant**\n\nUpon launching, the traditional version of Kazuar can take one of four paths of execution, [as described by Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/):\n\n- If launched with the **install** command-line argument, uses .NET Framework’s InstallHelper method to install itself as a service.\n- If started in a non-user interactive environment (i.e., no user interface), installs itself as a service using the .NET ServiceBase Class.\n- If executed with the **single** command-line argument or if running in a Mac or UNIX environment, launches an infinite loop that reads tasks from the **tsk** folder and resolves them until none remain. \n- If no arguments are provided and if running in a Windows environment, saves a DLL and injects it into the explorer.exe process. The DLL executable loads the malware’s executable and runs it within memory of the explorer.exe process. The Kazuar binary code refers to the DLL as "the shellcode."\n\nAs shown in Exhibit 8, the process injection function of the traditional Kazuar variant proceeds as follows:\n- Makes a FindWindow API call to get a handle to the Shell\\_TrayWnd (Windows taskbar) process\n- Calls GetWindowThreadProcessID to get the thread ID of the Shell\\_TrayWnd window\n- Checks if the DLL loader exists in the base folder:\n    - If it does not exist, it writes it (encoded version hardcoded in Kazuar binary)\n- Once DLL loader exists, calls LoadLibrary to load the DLL\n- Calls GetProcAddress to find the address of the DLL loader-exported Install function \n- Calls SetWindowsHookEx to hook the Shell\\_TrayWnd window; the hook runs the "Install" function of the DLL loader when the Shell\\_TrayWnd window gets a message in the queue with WH\\_GETMESSAGE on the thread of the target window\n- Calls PostMessage  to post a message in the thread to trigger the hook instantly and load the DLL immediately\n- Sleeps for 0.1 seconds then calls UnhookWindowsHookEx to remove the hook and exit the program; execution is now passed to the injected DLL loader in explorer.exe\n\n ![alt text](/rest/files/download/66/f3/7a/9414dd315d65a3b16ba48441cfcee331075b5729c959991157bd27161c/Exhibit9.PNG)   \n _Exhibit 8: Process Injection of Traditional Kazuar Into explorer.exe Process_\n\n**New Kazuar Variant**\n\nThe new Kazuar variant has four execution paths that depend on the configured **inject_mode** parameter rather than passed as a command-line argument:\n\n- If **inject_mode** is **single**, Kazuar sets a mode variable to "solver" if started in user interactive mode or "system" if not. Kazuar checks if the current process is mshta.exe (Microsoft HTML application host). If so, Kazuar enumerates all top-level windows on the screen and then hooks and hides the windows. iDefense assesses this is to determine the results of the code run from mshta.exe. \n\n Kazuar then sets up the REMO (remote), KEYL (keylogger), or SOLV (task solving) threads. Also sets the MIND thread that monitors for processes with names containing:\n  - cmdvrt32.dll (Comodo Antivirus) \n  - sbiedll.dll (Sandboxie)\n  - sxin.dll (360 Total Security)\n  - process monitor\n   - wireshark\n   - fiddler\n\n- If **inject_mode** is **remote**, Kazuar repeats the same process as above but only starts the REMO thread to listen for tasks from other Kazuar instances.\n\n- If started in **non-interactive mode**, Kazuar sets up REMO and INJE (injection) threads and then sleeps.\n\n- If none of the above conditions matches, Kazuar checks if it is already running in explorer.exe. If not, it repeats the check to see if it is running the  process mshta.exe and performs the same subsequent activity. Kazuar then injects into explorer.exe using the same method as the traditional Kazuar, described above.\n\nThe new Kazuar variant has three other **inject_mode** values used to inject into transport processes (i.e., used to communicate with the C2 server): \n\n-  If **inject_mode** is **inject**, Kazuar reads the transport processes from the transport configuration file as targets for injection. If there is no transport process present, Kazuar uses the default browser process; if defined, it uses iexplore.exe. \n\n Kazuar checks for the mutex in the target transport process to see if Kazuar is already running. If not, Kazuar opens the transport process using the OpenProcess API call and checks whether it is running under WOW64 with IsWow64Process. \n\n Kazuar then creates a new memory section with RWX protection using NtCreateSection, maps a view of the previously created section to the local Kazuar process with RW protection, and maps the section to the transport process with RX permissions. Kazuar writes the shellcode to the mapped section in the local process and creates a remote thread in the transport process using CreateRemoteThread, pointing the thread to the mapped view to trigger the shellcode.\n\n- If **inject_mode** is **zombify**, Kazuar injects into the user\'s default browser; if this fails, it injects into svchost.exe. Kazuar uses the [early bird technique](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) to inject itself into the selected process\n\n-  If **inject_mode** is **combined**, Kazuar first attempts to inject using the **inject** process; if this fails, it attempts the **zombify** process.\n\n\n###### AMSI Bypass \n\n**New Kazuar Variant**\n\nBefore selecting an execution path, the new Kazuar variant calls a function that bypasses the [Antimalware Scan Interface (AMSI)](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)—a way for any Windows application to integrate with the installed antimalware product. The AMSI bypass function is shown in Exhibit 9; it was not available in the traditional Kazuar variant.\n\n![alt text](/rest/files/download/e3/46/cb/9adb5488dfda273e37ca6462009bebae7cef14770849d088cc9afc26e1/amsi.PNG)  \n_Exhibit 9: New Kazuar Variant\'s AMSI Bypass Function_\n\n[ESET previously reported](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/) on BELUGASTURGEON using AMSI bypass functionality in its PowerShell loaders, and [iDefense has previously analyzed](https://intelgraph.idefense.com/#/node/intelligence_report/view/9bf2fc44-570d-40ad-b81a-744141ed443e) PowerShell scripts containing AMSI bypass functionality to load BELUGASTURGEON\'s [securlsa.chk](https://intelgraph.idefense.com/#/node/malware_family/view/e55ad229-6484-4be3-bf3e-568c96a05b82) backdoor.\n\nThe Kazuar function patches the beginning of [AmsiScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) to always return 80070057, which [translates to](https://docs.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) E\\_INVALIDARG (one or more arguments not valid). The previous PowerShell scripts always patched this buffer to return 1 (AMSI\\_RESULT\\_NOT\\_DETECTED). The new return value is the same value used by the open-source .NET exploitation library [SharpSploit](https://github.com/cobbr/SharpSploit/blob/1407108e638cde3e181c27cb269c8427723884b0/SharpSploit/Evasion/Amsi.cs) suggesting Kazuar developers adapted this functionality from open-source tooling.\n\n## Command Set Comparison\n\n**Traditional Kazuar Variant**\n\nThe following commands, [documented by Palo Alto Networks](https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) and verified by iDefense, are available in the traditional Kazuar variant: \n\n- **log:** Logs a specified debug message.  \n- **get:** Uploads files from a specified directory. Palo Alto Networks indicated operators can upload files based on their modified, accessed, and created timestamps.  \n- **put:** Writes a payload to the specified file.  \n- **cmd:**  Executes the specified command, writes the output to a temporary file, and uploads the temporary file to the C2 server.    \n- **sleep:** Sleeps for the specified time.  \n- **upgrade:** Changes the current executable’s file extension to .old and writes the newly provided executable in its place.  \n- **scrshot:** Takes a screenshot of the visible screen and saves it to the specified filename or a filename using the format: [year]-[month]-[day]-[hour]-[minute]-[second]-[millisecond].jpg. Then uploads the file to the C2 server.  \n- **camshot:** Creates a Window called “WebCapt” to capture an image from an attached webcam, copies the image to the clipboard, and writes the image to a specified file or a filename using the format: [year]-[month]-[day]-[hour]-[minute]-[second]-[millisecond].jpg. Then uploads the file to the C2 server.  \n- **uuid:** Sets the unique agent identifier by providing a specific GUID.  \n- **interval:** Sets the transport intervals (minimum and maximum time intervals) between C2 communications.  \n- **server:** Sets the C2 servers by providing a list of URLs.  \n- **transport:** Sets the transport processes by providing a list of processes where Kazuar injected its code and executed within.  \n- **autorun:** Sets the autorun type—DISABLED, WINLOGON, POLICIES, HKCURUN, RUNONCE, LOADKEY, or STARTUP—as discussed earlier. Kazuar accept the following strings for this command:  \n    - **remote:** Configures remote API settings by specifying URI prefix and port to listen on. While the port used varied between the analyzed samples, iDefense only observed the HTTP prefix used, which instructs Kazuar to act as an HTTP server. The threat actor can then interact with the compromised system using inbound HTTP requests.  \n    - **info:** Gathers system information referred to as: Agent information, System information, User information, Local groups and members, Installed software, Special folders, Environment variables, Network adapters, Active network connections, Logical drives, Running processes, and Opened windows.  \n- **copy:** Copies the specified file to a specified location. Also allows the C2 infrastructure to supply a flag to overwrite the destination file, if it already exists.  \n- **move:** Moves the specified file to a specified location. Also allows the C2 infrastructure to supply a flag to delete the destination file, if it exists.  \n- **remove:** Deletes a specified file. Allows the C2 infrastructure to supply a flag to securely delete a file by overwriting the file with random data before deleting the file.  \n- **finddir:** Finds a specified directory and lists its files including the created and modified timestamps, the size, and file path for each of the files in the directory.  \n- **kill:** Kills a process by name or by process identifier (PID).  \n- **tasklisk:** Lists running processes. Uses a WMI query of `select * from Win32_Process` for a Windows system but can also run `ps -eo comm,pid,ppid,user,start,tty,args` to obtain running processes from a UNIX system.  \n- **suicide:** Likely uninstalls Kazuar, but it is not implemented in the referenced samples.  \n- **plugin:** Installs plugin by loading a provided Assembly, saving it to a file whose name is the MD5 hash of the Assembly’s name, and calling the Start method.  \n- **plugout:** Removes a plugin based on the Assembly’s name.  \n- **pluglist:** Gets a list of plugins and determines whether they are “working” or “stopped.”  \n- **run:** Runs a specified executable with supplied arguments and saves its output to a temporary file. Then loads the temporary file to the C2 server.  \n\nIn this Kazuar variant, the C2 server sends the tasks as XML-formatted data containing an action identifier or integer; the numeric action ID is  then translated into the corresponding command from the above set.\n\n**New Kazuar Variant**\n\nThe new Kazuar variant replaces these numeric action IDs with strings for the command names. The following commands have similar functionality in the new variant as they did in the traditional variant:\n\n- **info**\n- **scrshot**\n- **run**\n- **move**\n- **get**\n- **log**\n- **put**\n- **sleep**\n- **kill**\n- **copy**\n\nDevelopers added the following commands to the new variant:\n\n- **steal:** Steal passwords, history, or proxy lists from the following services: FileZilla, Chromium, Mozilla, Outlook, WinSCP, Git, or from the system.  \n- **config:** Set and update Kazuar configuration values, as described in the *Configuration Comparison* section below.  \n- **delegate:** Forward command to remote Kazuar instance using a named pipe and store result in delegated .zip file, as described in the *Command-and-Control Communication* section below under named pipe communications.\n- **psh:**  Execute PowerShell command.\n- **regwrite:** Create Registry key.\n- **regdelete:** Delete Registry key.\n- **vbs:** Execute VBS script with cscript.exe.\n- **regquery:** Query Registry key.\n- **find:** Enumerate a directory; replaces **finddir** command in traditional Kazuar.\n- **forensic:** Enumerate Registry autorun keys, the Program Compatibility Assistant, and the Windows Explorer User Assist Registry keys to determine which program(s) has run on the compromised device.\n- **http:** Execute an HTTP request and save the response to file http<3digits>.rsp.\n- **jsc:** Execute a JavaScript file with cscript.exe.\n- **del:** Delete a file; replaces **remove** command in traditional Kazuar.\n- **unattend:** Enumerate the compromised device\'s [unattend.xml](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs), sysprep.xml, and web.config files to obtain credentials.\n- **schlist:** Enumerate list of scheduled tasks using the [TaskService](https://docs.microsoft.com/en-us/windows/win32/taskschd/taskservice) object.\n- **wmiquery:** Execute a WMI query.\n- **wmicall:** Execute a WMI method.\n\nDevelopers removed several commands from the traditional Kazuar variant while incorporating the functionality into other commands or configuration settings:\n- The **upgrade** and **suicide** commands are replaced by the Registry editing commands (‘regdelete’ and ‘regwrite’)  now that  Kazuar is stored in a Registry key. \n- The values previously configured by the **uuid**, **jnterval**, **server**, and **transport** commands are now configured using the **config** command. \n- The list of running processes previously obtained with **tasklist** is now returned by **info** along with much more system information. \n- The **autorun** command is not required to configure persistence mechanisms now the Kazuar binary is stored in the Registry. \n- The **plugin** command is no longer necessary since much of the prior information-stealing functionality is implemented within the newer Kazuar. \n- The **remote** command (i.e., HTTP API functionality) has been replaced with task delegation. \n\nThe only functionality apparently not replicated in the new variant is the **camshot** command to take web cam snapshots.\n\nThe commands **schlist**, **wmiquery**, and **wmicall** were present in Kazuar sample AGN-AB-13 but not AGN-AB-03, suggesting the command set of the new variant is under development.\n\n## Configuration Comparison\n\n**Traditional Kazuar Variant**\n\nThe values configured in the traditional Kazuar variant\'s configuration are:\n\n- **Agent identifier:** Unique agent identifier (GUID format).  \n- **Executable path:**  Path of Kazuar binary on disk.  \n- **Storage path:** Base directory containing Kazuar configuration files.\n- **Fake visible name:** Kazuar filename.\n- **Description label:**  Empty in samples analyzed.\n- **Machine seed:** Seed value derived from System Directory.\n- **Parallel tasks:** Number of tasks to run in parallel.\n- **Last contact:** Last contact from C2 server.\n- **Autorun type:**  Persistence method (LNK file or Registry keys, as described in *Installation and Persistence* section).\n- **Transport interval:** Interval between C2 communications.\n- **Command servers:** C2 servers.\n- **Transport processes:** Process to injected into for C2 communications.\n\n**New Kazuar Variant**\n\nThe updated configuration reflects the broader range of functionality implemented in the new Kazuar variant. The values configured in the new variant\'s configuration are:\n\n- **Agent label:** Unique Agent Label of format `AGN-AB-<2 digits>`, iterated as updates are made to Kazuar.\n- **Agent UUID:** Unique agent identifier (GUID format).  \n- **Local seed:** Seed value derived from System UUID.\n- **Last contact:** Last contact from C2 server.\n- **Transport type:**  Protocol used for C2 communications; set to "HTTP" in both analyzed samples.\n- **Transport main interval:**  Interval between C2 communications.\n- **Transport failed interval:** Interval between failed C2 connections before attempting a retry.\n- **Transport proxy:**  C2 communication proxy; specifies URL, port, and variable to specify when proxy is enabled. This value was empty for both samples iDefense analyzed.\n- **Max server fails:** Number of failed attempts before quitting.\n- **Main servers:**  Primary C2 servers.\n- **Reserved servers:** Backup C2 servers.\n- **Agent regkey:** Registry key where packed Kazuar binary is stored.\n- **Storage root:** Base directory containing Kazuar configuration files.\n- **Config path:** Path to Kazuar configuration directory.\n- **Logs path:**: Path to Kazuar logs file.\n- **Keylogger path:** Path to Kazuar keylogger output file.\n- **Logs size:**  Current size of logs file.\n- **Inject mode:** Inject mode to define execution path and injection method (described in *Installation and Persistence* section).\n- **Solving threads:** Number of threads to run in parallel to solve tasks.\n- **Solving tries:** Maximum number of attempts to solve a task.\n- **Sending tries:** Maximum number of attempts to send task result to C2 server.\n- **Keylogger enabled:** Whether keylogger functionality is enabled (boolean).\n- **Task delegation enabled:** Whether task delegation functionality is enabled (boolean).\n- **AMSI bypass enabled:** Whether AMSI bypass functionality is enabled (boolean).\n- **Delegate system pipe:**  Pipe used to delegate tasks in system mode; also see  *Command-and-Control Communication* section.\n- **Delegate solver pipe:** Pipe used to delegate tasks in solver mode.\n- **Delegate sender pipe:** Pipe used to delegate tasks in sender mode.\n\nIndicating the new Kazuar version is under development, the following values are present in the new Kazuar variant sample AGN-AB-13 but not AGN-AB-03:\n- **Agent regkey**\n- **Delegate system pipe** \n- **Delegate solver pipe** \n- **Delegate sender pipe**\n\n## Command-and-Control Communication\n\n**Traditional Kazuar Variant**\n\nThe traditional Kazuar variant uses its C2 channel to send tasks to the backdoor, receive the results, and exfiltrate data. The variant can use multiple protocols, such as HTTP, HTTPS, FTP, or FTPS, as determined by the prefixes of the hardcoded C2 URLs. [iDefense identified one sample](https://intelgraph.idefense.com/#/node/intelligence_alert/view/6cc805d7-cb77-443d-afea-d052916fa602) that uses the "file://" prefix to communicate across internal nodes in a compromised network, likely via SMB using another Kazuar sample as a transfer agent to forward tasks and results between the C2 server and the first Kazuar sample.\n\n**New Kazuar Variant**\n\nThe new Kazuar samples do not support FTP communications; instead, C2 communications are performed over HTTP(S). Exhibit 10 shows the function that defines the C2 servers:\n\n![alt text](/rest/files/download/e2/97/51/d4d171d120ec49db0128d5c6119399eeb12bf245227e82708290fcf6c3/c2.PNG)  \n_Exhibit 10: Defining C2 Servers in New Kazuar Variant_\n\nThe first two URLs in Exhibit 10 are the "Main servers" referred to in the sample\'s configuration; they act as the primary C2 servers. The third URL is the "Reserved server" that Kazuar uses as a backup, if it cannot reach the primary C2s. The fourth URL is the "Last Chance URL" that Kazuar uses if communication with the primary and backup C2 servers is lost. \n\nFor sample AGN-AB-03, shown in Exhibit 10, a dummy value ("www.google.com") is provided; in sample AGN-AB-13, no value is configured for the "Last Chance URL." However, Kazuar operators can set this to any value. iDefense assesses the operators may choose to use a legitimate web service, such as Pastebin, which allows them to maintain persistence if their own C2 infrastructure is unavailable. [BELUGASTURGEON has previously used a Pastebin project](https://intelgraph.idefense.com/#/node/intelligence_alert/view/92154a2c-f077-4f16-92d5-2349984ad03e) for C2 communications with its Carbon backdoor.\n\nThe C2 servers identified in the two analyzed samples are:\n\n**AGN-AB-13:**\n - Main servers:\n    - `https://www.rezak[.]com/wp-includes/pomo/pomo.php`\n    - `https://www.hetwittezwaantje[.]nl/wp-includes/rest-api/class-wp-rest-client.php`\n - Reserved server:\n    - `https://aetapet[.]com/wp-includes/IXR/class-IXR-response.php`\n\n**AGN-AB-03:**\n - Main servers:\n    - `https://www.actvoi[.]org/wordpress/wp-includes/fonts/icons/`\n    - `https://www.datalinkelv[.]com/wp-includes/js/pomo/`\n    - `https://www.actvoi.org/wordpress/wp-includes/fonts/`\n - Reserved server:\n    - `https://www.downmags[.]org/wp-includes/pomo/wp/`\n\nIn the new version of Kazuar, HTTP requests are authenticated using an .AspNet.Cookies header rather than an AuthToken cookie. Tasks are forwarded to remote Kazuar instances using the task delegation functionality instead of the remote HTTP API. The task delegation functionality uses named pipes to communicate between Kazuar samples. Exhibit 11 shows the function to generate the pipe name used for communications.\n\n![alt text](/rest/files/download/15/51/62/fe277b22a617898a35647dfe6e6b2d4943dfbeb7e4380c01058995d960/pipe.PNG)   \n_Exhibit 11: New Kazuar Variant Task Delegation Named Pipe_\n\nThe pipe names are GUID values derived from the string `pipename-[system/solver/sender]-AgentLabel` where the values for system, solver, or sender are set based on the **inject_mode**, as described in the *Installation and Persistence* section. \n- **sender** corresponds to the Kazuar instance sending the task.\n- **solver** is set for the Kazuar instance receiving tasks. \n- **system** corresponds to a Kazuar instance started in non-interactive mode. \n\nExhibit 12 shows the function used to send tasks to and receive task results from remote Kazuar instances.\n\n![alt text](/rest/files/download/ac/ec/11/ad97d520210ac43da1c7edd6d91fc4cb59f3e8dd459016a0d335bd0686/pipe2.PNG)  \n_Exhibit 12: New Kazuar Variant Task Delegation Functionality_\n\nTo generate a name for the named pipe, Kazuar uses the `pipename-mode AgentLabel`  format described above replacing "mode" with system, solver, or sender as described above and connecting the values for CreateNamedPipe with ConnectNamedPipe. Messages sent over the pipe are encrypted and must begin with PING, PONG, TASK, RESULT, or ERROR. The PING prefix acts as a handshake and expects a PONG response, the TASK prefix is used to send tasks, and the RESULT and ERROR prefixes respond with the results of tasks or any errors.\n\n## Outlook\nAlthough BELUGASTURGEON has made high-level updates to the Kazuar backdoor over the years, the samples from August 2019 and February 2020 represent the first significant update to the malware\'s codebase since its discovery three years ago. The developers removed the requirement for a plugin framework by incorporating functionality that allows for a wide range of espionage activity such as keylogging, credential stealing, and forensics. Storing the sample as a Registry key rather than on disk decreases the risk of detection in comparison to the older variant.\n\nAdding task delegation functionality makes Kazuar a peer of the group\'s more sophisticated Carbon and Uroborus backdoors. The group\'s relatively clumsy prior method of chaining together proxy commands from a C2 server to a Kazuar instance on an internal node without network connection meant task files were written to disk on the internal proxy node. The new functionality forwards tasks directly over named pipes, as done in the group\'s other backdoors.\n\nDifferences between the August 2019 and February 2020 samples—with the addition of commands and updated configuration specifications—clearly indicate Kazuar is under active development and will continue to be used by BELUGASTURGEON in espionage campaigns.', 'sources_external': [{'datetime': '2017-05-02T23:00:00.000Z', 'description': 'Kazuar: Multiplatform Espionage Backdoor with API Access', 'name': 'Palo Alto Networks', 'reputation': 4, 'url': 'https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/'}], 'mitigation': 'Check logs for the following indicators of compromise:\n- `182d5b53a308f8f3904314463f6718fa2705b7438f751581513188d94a9832cd` (Kazuar packed)\n- `60f47db216a58d60ca04826c1075e05dd8e6e647f11c54db44c4cc2dd6ee73b9` (Kazuar packed)\n-  `41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb` (Kazuar unpacked)\n- `1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4` (Kazuar unpacked)\n- https://www[.]rezak[.]com/wp-includes/pomo/pomo[.]php\n- https://www[.]hetwittezwaantje[.]nl/wp-includes/rest-api/class-wp-rest-client[.]php\n- https://aetapet[.]com/wp-includes/IXR/class-IXR-response[.]php\n- https://www.actvoi[.]org/wordpress/wp-includes/fonts/icons/\n- https://www.datalinkelv[.]com/wp-includes/js/pomo/9https://www.actvoi.org/wordpress/wp-includes/fonts/\n- https://www.downmags[.]org/wp-includes/pomo/wp/\n\nKazuar developers configure the C2 URIs for each sample; instead monitor for the following more generic indicators:\n-\tRepeated connections to WordPress sites not commonly visited by users in the network, particularly when the URI contains `/wp-includes/pomo/`. \n-\tNamed pipes with names matching the format `///pipe//<GUID>` particularly when used by explorer.exe.\n\nThe following YARA rule matches the analyzed Kazuar samples and may be used for detection or hunting purposes only:\n\n```\nrule new_kazuar_unpacked {\n    meta:\n        desc = "Detects functions used by new Kazuar Variant."\n        author = "iDefense"\n        hash1 = "41cc68bbe6b21a21040a904f3f573fb6e902ea6dc32766f0e7cce3c7318cf2cb"\n        hash2 = "1cd4d611dee777a2defb2429c456cb4338bcdd6f536c8d7301f631c59e0ab6b4"\n\n    strings:\n\n    $a1 = "Agent.Original.exe" wide ascii\n    $a2 = "Musky.exe" wide ascii\n    $b_amsi = { 28 [4] 3A 01 00 00 00 2A 72 [4] 28 [4] 28 [4] 0A 06 7E [4] 28 [4] 39 [4] 2A 06 72 [4] 28 [4] 28 [4] 0B 07 7E [4] 28 [4] 39 [4] 2A 28 [4] 39 [4] 1C 8D [4] 25 D0 [4] 28 [4] 0C 38 [4] 1E 8D [4] 25 D0 [4] 28 [4] 0C 16 0D 08 8E 69 6A 28 }\n    $b_encoding1 = { 020A061F09594576000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??000000??00000038E70000001F412A1F422A1F432A1F442A1F452A1F462A1F472A1F482A1F492A1F4A2A1F4B2A1F4C2A1F4D2A1F4E2A1F4F2A1F502A1F512A1F522A1F532A1F542A1F552A1F562A1F572A1F582A1F592A1F5A2A1F612A1F622A1F632A1F642A1F652A1F662A1F672A1F682A1F692A1F6A2A1F6B2A1F6C2A1F6D2A1F6E2A1F6F2A1F702A1F712A1F722A1F732A1F742A1F752A1F762A1F772A1F782A1F792A1F7A2A1F7E2A1F252A1F3A2A1F2E2A1F202A1F7C2A1F7B2A1F7D2A1F2D2A1F3D2A1F3C2A1F3E2A1F5C2A1F0A2A1F092A1F302A1F312A1F322A1F332A1F342A1F352A1F362A1F372A1F382A1F392A022A}\n    $b_encoding2 = {73[4]0A160B38[4]02076F[4]28[4]0C0608D16f[4]260717580B07026F[4]3f[4]066F[4]2A}\n    $b_pipename = {03 28 [4] 39 07 00 00 00 28 [4] 10 01 02 6F [4] 0A 72 [4] 28 [4] 06 72 [4] 28 [4] 03 28 [4] 0B 28 [4] 07 6F [4] 0C 28 [4] 08 6F [4] 0D 1F 2A 13 04 1F 11 13 05 1F 15 13 06 16 13 08 38 [4] 11 04 11 05 5A 20 [4] 20 [4] 61 5F D2 13 04 11 04 11 06 58 20 [4] 20 [4] 61 5F D2 13 04 09 11 08 8F [4] 25 47 11 04 61 D2 52 11 08 17 58 13 08 11 08 09 8E 69 3F [4] 12 07 09 28 [4] 12 07 72 [4] 28 [4] 28 [4] 6F [4] 2A}\n\n    condition: uint16(0) == 0x5a4d and (1 of ($a*) and 3 of ($b_*)) or (4 of ($b_*)) and filesize < 350KB\n}\n```', 'severity': 4, 'abstract': "In February 2021, iDefense analyzed two samples of BELUGASTURGEON's Kazuar backdoor and identified significant codebase differences when compared to older Kazuar samples. Although BELUGASTURGEON has been making high-level changes to Kazuar and using the backdoor in espionage campaigns since at least 2017, the August 2020 and February 2021 samples contain the first significant updates to the malware's codebase since the malware family was identified.\n\nThe updated Kazuar variant introduces commands that support a range of espionage activity, including keylogging, credential stealing, and forensics, without requiring a plugin framework as in prior  Kazuar samples. Using task forwarding, BELUGASTURGEON operators can now communicate with Kazuar instances without using Internet connectivity; this enhanced peer-to-peer (P2P) functionality advances Kazuar to the level of some of BELUGASTURGEON's more sophisticated backdoors.\n\nWhen comparing the two August 2020 and February 2021 Kazuar samples, iDefense identified command set and configuration updates that indicate Kazuar is under active development for future use in BELUGASTURGEON espionage campaigns.", 'attachment_links': '\n- https://intelgraph.idefense.com/rest/files/download/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-02-08cropped.png\n- https://intelgraph.idefense.com/rest/files/download/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-03-08cropped.png'}]
}


expected_output_ir = {

    "DBot": [{'Indicator': 'bdc9d16f-6040-4894-8544-9c98986a41fd', 'Type': 'ACTI Intelligence Report', 'Vendor': 'ACTI Threat Intelligence Report', 'Score': 0, 'Reliability': 'B - Usually reliable'}],
    'IR': [{'value': 'bdc9d16f-6040-4894-8544-9c98986a41fd', 'created_on': '2021-03-26T20:09:55.000Z', 'display_text': 'Russian Responses to Geopolitical Challenges Include Cyber-Threat Activity against Energy Industry Entities', 'dynamic_properties': {}, 'index_timestamp': '2022-02-22T23:42:04.231Z', 'last_modified': '2022-02-08T18:27:58.000Z', 'last_published': '2021-03-26T20:09:55.000Z', 'links': [{'created_on': '2022-01-07T19:02:52.000Z', 'display_text': 'Feared Russian Invasion of Ukraine Could Have Global Impacts in Cyberspace', 'key': 'b4511cfd-3d13-4092-9275-35b058c246ec', 'relationship': 'mentions', 'relationship_created_on': '2022-01-07T19:02:52.000Z', 'relationship_last_published': '2022-01-07T19:02:52.000Z', 'type': 'intelligence_alert', 'uuid': 'edcb0ff2-6598-45fb-ae1c-4eb273032f56', 'href': '/rest/document/v0/edcb0ff2-6598-45fb-ae1c-4eb273032f56'}, {'created_on': '2021-01-06T16:53:13.000Z', 'display_text': 'Suspected Russian Breaches of US Government and Critical Infrastructure Align with Russian Strategic Interests', 'key': 'd01c0e25-ed38-4312-b679-8854bf29b5d2', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_report', 'uuid': 'eb77c712-fcfd-48f6-9533-baa18131fb62', 'href': '/rest/document/v0/eb77c712-fcfd-48f6-9533-baa18131fb62'}, {'created_on': '2022-02-22T21:33:12.000Z', 'display_text': 'SITREP: Ukraine Crisis', 'key': '0ae44727-6fef-4dcb-9928-8eed0c3bcd3e', 'relationship': 'mentions', 'relationship_created_on': '2022-02-22T23:39:39.000Z', 'relationship_last_published': '2022-02-22T23:39:39.000Z', 'type': 'intelligence_alert', 'uuid': 'f1862833-80de-4880-a180-11fad373e896', 'href': '/rest/document/v0/f1862833-80de-4880-a180-11fad373e896'}, {'created_on': '2016-07-21T22:42:19.000Z', 'display_text': 'Texaco', 'key': 'Texaco', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': 'd9e7c8b1-bce2-43fa-a3ae-bc1caa0f0d22', 'href': '/rest/fundamental/v0/d9e7c8b1-bce2-43fa-a3ae-bc1caa0f0d22'}, {'created_on': '2015-08-21T00:00:00.000Z', 'display_text': 'CSX', 'key': 'CSX', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '4c1ea572-f5d7-46b7-870e-e81821f5316c', 'href': '/rest/fundamental/v0/4c1ea572-f5d7-46b7-870e-e81821f5316c'}, {'created_on': '2007-04-12T00:00:00.000Z', 'display_text': 'Turkmenistan', 'key': 'Turkmenistan', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'a130bfe9-390d-4c83-b75e-c1f050e41820', 'href': '/rest/fundamental/v0/a130bfe9-390d-4c83-b75e-c1f050e41820'}, {'created_on': '2003-09-27T00:00:00.000Z', 'display_text': 'Germany', 'key': 'Germany', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'ee03c799-980c-4998-8240-dc400eebe325', 'href': '/rest/fundamental/v0/ee03c799-980c-4998-8240-dc400eebe325'}, {'created_on': '2003-12-15T00:00:00.000Z', 'display_text': 'Denmark', 'key': 'Denmark', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'f77916a1-655f-4424-91c9-124a289c6abd', 'href': '/rest/fundamental/v0/f77916a1-655f-4424-91c9-124a289c6abd'}, {'created_on': '2012-08-13T16:42:49.000Z', 'display_text': 'Iran', 'key': 'Iran', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '516a2391-b1b6-42e2-adce-ad3410cb15f8', 'href': '/rest/fundamental/v0/516a2391-b1b6-42e2-adce-ad3410cb15f8'}, {'created_on': '2016-06-16T16:04:46.000Z', 'display_text': 'Guccifer', 'key': 'Guccifer', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_actor', 'uuid': '1e01d510-6b3a-47a7-ab95-967105695d1f', 'href': '/rest/fundamental/v0/1e01d510-6b3a-47a7-ab95-967105695d1f'}, {'created_on': '2015-08-03T15:06:38.000Z', 'display_text': 'JACKMACKEREL', 'key': 'JACKMACKEREL', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '24a38270-949f-442a-aac6-53a99ef1ea70', 'href': '/rest/fundamental/v0/24a38270-949f-442a-aac6-53a99ef1ea70'}, {'created_on': '2017-06-16T16:02:30.000Z', 'display_text': 'SANDFISH', 'key': 'SANDFISH', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '40d2cf30-237a-467b-826d-390f12cc27f0', 'href': '/rest/fundamental/v0/40d2cf30-237a-467b-826d-390f12cc27f0'}, {'created_on': '2019-06-17T12:07:03.000Z', 'display_text': 'ZANDER', 'key': 'ZANDER', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': 'a363a7ca-1d5d-4477-9ce9-e9259cb888e4', 'href': '/rest/fundamental/v0/a363a7ca-1d5d-4477-9ce9-e9259cb888e4'}, {'created_on': '2016-09-13T16:26:36.000Z', 'display_text': 'Fancy Bears Hack Team', 'key': 'Fancy Bears Hack Team', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': 'ec08d6ad-5c32-44b9-bde3-bdfe9e1c76c5', 'href': '/rest/fundamental/v0/ec08d6ad-5c32-44b9-bde3-bdfe9e1c76c5'}, {'created_on': '2013-03-25T18:40:44.000Z', 'display_text': 'BLACK GHOST KNIFEFISH', 'key': 'BLACK GHOST KNIFEFISH', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '27332f70-302c-491a-85f2-3714218296b8', 'href': '/rest/fundamental/v0/27332f70-302c-491a-85f2-3714218296b8'}, {'created_on': '2018-01-30T19:03:24.000Z', 'display_text': 'GandCrab', 'key': 'GandCrab', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': '8f5bc13f-ee79-4ee6-9cf2-d9a6318b5ed4', 'href': '/rest/fundamental/v0/8f5bc13f-ee79-4ee6-9cf2-d9a6318b5ed4'}, {'created_on': '2018-12-04T19:10:02.000Z', 'display_text': 'Defense & Public Safety', 'key': 'Defense & Public Safety', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'vertical', 'uuid': 'b0b0d8bd-1c9f-4062-9c51-f33a79c736af', 'href': '/rest/fundamental/v0/b0b0d8bd-1c9f-4062-9c51-f33a79c736af'}, {'created_on': '2021-02-15T15:38:34.000Z', 'display_text': 'SANDFISH Continues to Exploit Exim Mail Transfer Agents', 'key': '82319acb-65eb-48b3-bbb3-61b34f53addf', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '55004ca2-e598-460f-bb0c-8ef6f37b7bca', 'href': '/rest/document/v0/55004ca2-e598-460f-bb0c-8ef6f37b7bca'}, {'created_on': '2020-07-24T21:03:43.000Z', 'display_text': 'US Officials Warn of Threats to Critical Infrastructure and Political Entities', 'key': 'c0373503-7624-441a-b59b-b2163fc04ea7', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '575c5eef-0784-46cd-bf67-8e256d0c2fc7', 'href': '/rest/document/v0/575c5eef-0784-46cd-bf67-8e256d0c2fc7'}, {'created_on': '2020-10-28T17:35:45.000Z', 'display_text': 'Russia-Linked BLACK GHOST KNIFEFISH Continues NTLM Harvesting Campaign, 2019 to 2020', 'key': '580f8d37-f834-4331-ad79-c05fd96e0f78', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': 'c3ad35ce-1443-4ef2-b3e2-1a3548605528', 'href': '/rest/document/v0/c3ad35ce-1443-4ef2-b3e2-1a3548605528'}, {'created_on': '2017-01-07T16:26:16.000Z', 'display_text': 'Aggressive Defensiveness: Russian Information Operations against the US Political System', 'key': '48d85d37-8adf-41c2-9bbe-d23b335a3bc3', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '79e6008d-ddd4-472d-b574-5ad1a769e096', 'href': '/rest/document/v0/79e6008d-ddd4-472d-b574-5ad1a769e096'}, {'created_on': '2018-04-17T19:57:28.000Z', 'display_text': 'Joint US-UK Threat Alert Warns of Russian Government Targeting of Network Infrastructure Devices Worldwide', 'key': 'fa7dd2fa-84ca-4066-90fb-04f91b39c07b', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '21ab89f6-1ac1-4cc3-83f6-233a5d7473cf', 'href': '/rest/document/v0/21ab89f6-1ac1-4cc3-83f6-233a5d7473cf'}, {'created_on': '2020-08-19T19:31:42.000Z', 'display_text': 'Roundup of Notable Ransomware Events with a Focus on Energy and Utility Sectors (January 2020 – August 2020)', 'key': '3129d754-caf2-425f-8684-3b5edc581776', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_report', 'uuid': '999b6c55-3cb8-4372-affb-bcc9c47dd95b', 'href': '/rest/document/v0/999b6c55-3cb8-4372-affb-bcc9c47dd95b'}, {'created_on': '2021-06-16T18:23:09.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 16 June 2021', 'key': 'b0dcf12f-1107-4ecc-ae1e-b558f26c0198', 'relationship': 'mentions', 'relationship_created_on': '2021-06-16T18:23:09.000Z', 'relationship_last_published': '2021-06-16T18:23:09.000Z', 'type': 'intelligence_alert', 'uuid': '1c808eb6-0bfb-4468-8f16-321b51855c3e', 'href': '/rest/document/v0/1c808eb6-0bfb-4468-8f16-321b51855c3e'}, {'created_on': '2020-08-10T15:46:02.000Z', 'display_text': 'DoppelPaymer', 'key': 'DoppelPaymer', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': '7403e958-17b1-4928-b876-7269da5f76b6', 'href': '/rest/fundamental/v0/7403e958-17b1-4928-b876-7269da5f76b6'}, {'created_on': '2006-02-16T00:00:00.000Z', 'display_text': 'Noble', 'key': 'Noble', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '3781e538-9ff4-4c1e-823e-288698c926d3', 'href': '/rest/fundamental/v0/3781e538-9ff4-4c1e-823e-288698c926d3'}, {'created_on': '2016-11-23T15:14:22.000Z', 'display_text': 'Odebrecht', 'key': 'Odebrecht', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': 'c7bb4db8-d2af-4aff-97b0-b397b0419296', 'href': '/rest/fundamental/v0/c7bb4db8-d2af-4aff-97b0-b397b0419296'}, {'created_on': '2017-01-11T14:52:30.000Z', 'display_text': 'NATO', 'key': 'NATO', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '830eece9-82bd-4cb8-ab2a-123e855377eb', 'href': '/rest/fundamental/v0/830eece9-82bd-4cb8-ab2a-123e855377eb'}, {'created_on': '2018-12-04T19:10:01.000Z', 'display_text': 'Noble Energy', 'key': 'Noble Energy', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '72937e93-85c9-4c27-8ee7-fc565f7609c8', 'href': '/rest/fundamental/v0/72937e93-85c9-4c27-8ee7-fc565f7609c8'}, {'created_on': '2003-08-01T00:00:00.000Z', 'display_text': 'China', 'key': 'China', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '917ef603-93eb-4830-9dc3-8a4e4828b4c3', 'href': '/rest/fundamental/v0/917ef603-93eb-4830-9dc3-8a4e4828b4c3'}, {'created_on': '2003-08-01T00:00:00.000Z', 'display_text': 'Mexico', 'key': 'Mexico', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'a664e2ae-5c24-454f-a75b-3d24e9d80938', 'href': '/rest/fundamental/v0/a664e2ae-5c24-454f-a75b-3d24e9d80938'}, {'created_on': '2008-05-29T21:29:21.000Z', 'display_text': 'United Kingdom', 'key': 'United Kingdom', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '05d70c8e-c9e1-48a2-a30e-0228996d5df2', 'href': '/rest/fundamental/v0/05d70c8e-c9e1-48a2-a30e-0228996d5df2'}, {'created_on': '2021-03-03T16:08:19.000Z', 'display_text': 'CLOP', 'key': 'CLOP', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': 'd6f3dc92-0f8e-4a5c-b216-744976b0a5a9', 'href': '/rest/fundamental/v0/d6f3dc92-0f8e-4a5c-b216-744976b0a5a9'}, {'created_on': '2015-07-31T18:42:50.000Z', 'display_text': 'SNAKEMACKEREL', 'key': 'SNAKEMACKEREL', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '065336a6-651d-4f80-b8c2-9347f4486912', 'href': '/rest/fundamental/v0/065336a6-651d-4f80-b8c2-9347f4486912'}, {'created_on': '2016-10-19T17:39:17.000Z', 'display_text': 'BELUGASTURGEON', 'key': 'BELUGASTURGEON', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': 'fb53e479-54e1-4827-abb4-ae1ae1db53e2', 'href': '/rest/fundamental/v0/fb53e479-54e1-4827-abb4-ae1ae1db53e2'}, {'created_on': '2015-07-31T17:14:39.000Z', 'display_text': 'Federal Security Service of the Russian Federation (Федеральная служба безопасности Российской Федерации)', 'key': 'Federal Security Service of the Russian Federation (Федеральная служба безопасности Российской Федерации)', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': 'd96f3b14-462b-4ab4-aa04-23c7a2996611', 'href': '/rest/fundamental/v0/d96f3b14-462b-4ab4-aa04-23c7a2996611'}, {'created_on': '2017-01-03T18:16:36.000Z', 'display_text': 'Main Directorate of the General Staff of the Armed Forces of the Russian Federation (GRU)', 'key': 'Main Directorate of the General Staff of the Armed Forces of the Russian Federation (GRU)', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '675cb6f9-ecab-4c3f-a5c2-9d163d707500', 'href': '/rest/fundamental/v0/675cb6f9-ecab-4c3f-a5c2-9d163d707500'}, {'created_on': '2017-06-15T18:06:42.000Z', 'display_text': 'CRASHOVERRIDE', 'key': 'CRASHOVERRIDE', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': '88704197-8308-4837-bd44-d2d46bd1ac1d', 'href': '/rest/fundamental/v0/88704197-8308-4837-bd44-d2d46bd1ac1d'}, {'created_on': '2018-01-02T01:07:28.000Z', 'display_text': 'Triton', 'key': 'Triton', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': '68ff5563-b940-4d0e-9bc2-535990747f9b', 'href': '/rest/fundamental/v0/68ff5563-b940-4d0e-9bc2-535990747f9b'}, {'created_on': '2015-07-24T16:45:47.000Z', 'display_text': 'Media', 'key': 'Media', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'vertical', 'uuid': 'bb9bdd2d-180e-41d2-b5c8-08a2062998ca', 'href': '/rest/fundamental/v0/bb9bdd2d-180e-41d2-b5c8-08a2062998ca'}, {'created_on': '2018-12-04T19:10:01.000Z', 'display_text': 'Oil & Gas', 'key': 'Oil & Gas', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'vertical', 'uuid': '0aa7b554-b07f-42b4-a904-92da408d9be5', 'href': '/rest/fundamental/v0/0aa7b554-b07f-42b4-a904-92da408d9be5'}, {'created_on': '2017-06-28T18:14:43.000Z', 'display_text': 'GreyEnergy', 'key': 'GreyEnergy', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_campaign', 'uuid': 'b0585685-aaac-44b4-b93b-733d30eaeb6e', 'href': '/rest/fundamental/v0/b0585685-aaac-44b4-b93b-733d30eaeb6e'}, {'created_on': '2021-03-23T17:35:09.000Z', 'display_text': 'What Happened to SANDFISH’s GreyEnergy?', 'key': '882ed9d3-9d7c-4004-9f3c-cf72300eced1', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': 'f0289fe9-c076-437b-984f-71f17d6f7950', 'href': '/rest/document/v0/f0289fe9-c076-437b-984f-71f17d6f7950'}, {'created_on': '2019-10-22T19:26:22.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for October 22, 2019', 'key': '08595e22-0390-43ec-968d-c910e5c4d621', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '6f668357-bd6a-4a04-876d-20bd840e0788', 'href': '/rest/document/v0/6f668357-bd6a-4a04-876d-20bd840e0788'}, {'created_on': '2017-06-27T20:55:03.000Z', 'display_text': 'Global Petya Ransomware Outbreak Cripples Major Companies Worldwide', 'key': '10c18a7a-741f-43ba-b0a9-24fd42684ccf', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': 'e4cac05c-83a4-40e3-b8b2-190c7c405ee0', 'href': '/rest/document/v0/e4cac05c-83a4-40e3-b8b2-190c7c405ee0'}, {'created_on': '2021-03-10T20:56:12.000Z', 'display_text': 'CLOP Ransomware Operators Leak CGG Data on Name-and-Shame Site on 1 March 2021', 'key': 'a626ee22-fe70-4ca6-a18b-0270fb0229c5', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': 'c069f7c1-7b22-4713-a1d9-b1ba041602e8', 'href': '/rest/fundamental/v0/c069f7c1-7b22-4713-a1d9-b1ba041602e8'}, {'created_on': '2021-03-10T16:32:46.000Z', 'display_text': 'CLOP Ransomware Operators Leak CSX Documents on Name-and-Shame Site on 2 March 2021', 'key': '4b0cd263-8e2b-4a0e-b6f8-7d9b7d623d6c', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': '0e1a64c4-e283-457b-b615-9863436b0dbd', 'href': '/rest/fundamental/v0/0e1a64c4-e283-457b-b615-9863436b0dbd'}, {'created_on': '2018-11-06T20:59:09.000Z', 'display_text': 'Account GandCrab Burnishes Patriotic Credentials By Showing Sympathy for Syria', 'key': '3b4e7772-29e4-424a-9b41-3b9d6759c7f6', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': 'ff63b317-2de3-4ba3-828a-d294eab5b91f', 'href': '/rest/fundamental/v0/ff63b317-2de3-4ba3-828a-d294eab5b91f'}, {'created_on': '2021-03-23T17:41:46.000Z', 'display_text': 'US and Russia Trade Threats, Raising Fears of Further Cyber Threat Activity', 'key': '762ebeea-4cc1-45c4-af25-67ddcccb8602', 'relationship': 'mentions', 'relationship_created_on': '2021-03-30T23:18:03.000Z', 'relationship_last_published': '2021-03-30T23:18:03.000Z', 'type': 'intelligence_alert', 'uuid': '3ee020e9-c64f-4c3f-8162-73f80ad85863', 'href': '/rest/document/v0/3ee020e9-c64f-4c3f-8162-73f80ad85863'}, {'created_on': '2021-04-21T17:48:14.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 21 April 2021', 'key': 'e348ab03-75d3-46ba-b00c-7a965da65f5d', 'relationship': 'mentions', 'relationship_created_on': '2021-04-21T17:48:14.000Z', 'relationship_last_published': '2021-04-21T17:48:14.000Z', 'type': 'intelligence_alert', 'uuid': '2149d045-5085-419f-a1c8-1b6acb2d9609', 'href': '/rest/document/v0/2149d045-5085-419f-a1c8-1b6acb2d9609'}, {'created_on': '2021-10-08T01:20:03.000Z', 'display_text': "Arrest of Russian Cybersecurity Firm's Founder Highlights Russia’s Complex and Dangerous Business Environment", 'key': 'fe0c6c41-9a7e-492a-a268-700b0d41ed6b', 'relationship': 'mentions', 'relationship_created_on': '2021-10-08T01:20:03.000Z', 'relationship_last_published': '2021-10-08T01:20:03.000Z', 'type': 'intelligence_alert', 'uuid': '7af3126f-2f88-4941-bf09-3521cb7889b7', 'href': '/rest/document/v0/7af3126f-2f88-4941-bf09-3521cb7889b7'}, {'created_on': '2004-08-17T00:00:00.000Z', 'display_text': 'Turkey', 'key': 'Turkey', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '9da2b237-dfde-4c8e-a0c1-158cbb15aa3f', 'href': '/rest/fundamental/v0/9da2b237-dfde-4c8e-a0c1-158cbb15aa3f'}, {'created_on': '2003-12-15T00:00:00.000Z', 'display_text': 'Norway', 'key': 'Norway', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '0ab9aefb-1ccd-4151-957a-eff18b13b0af', 'href': '/rest/fundamental/v0/0ab9aefb-1ccd-4151-957a-eff18b13b0af'}, {'created_on': '2021-01-12T00:12:11.000Z', 'display_text': 'SolarWinds Supply-Chain Campaign C2 Infrastructure Analysis', 'key': '2c18e53c-7dae-4edb-a126-6e3c09ed3003', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '7128fb11-2753-4f4d-aa51-2c13731f7dbe', 'href': '/rest/document/v0/7128fb11-2753-4f4d-aa51-2c13731f7dbe'}, {'created_on': '2019-11-20T18:17:09.000Z', 'display_text': 'Ransomware Attack Hit Mexican Oil Company at Sensitive Time', 'key': 'd67e0be4-5b61-4e57-8c17-0bf09ed5b8f3', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': '05982e7e-b7d0-4203-a8a9-dd46ea769854', 'href': '/rest/fundamental/v0/05982e7e-b7d0-4203-a8a9-dd46ea769854'}, {'created_on': '2021-02-25T00:14:03.000Z', 'display_text': 'DoppelPaymer Ransomware Reportedly Impacts Kia Motors, February 2021', 'key': '7d996ac8-262b-46c4-880d-bed6126b66e4', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': 'd009718a-25f6-491f-95f2-528d0a3d3f63', 'href': '/rest/fundamental/v0/d009718a-25f6-491f-95f2-528d0a3d3f63'}, {'created_on': '2021-04-19T15:20:14.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 19 April 2021', 'key': '287df877-37b1-4ef1-8ecc-6bbc8c3b82e2', 'relationship': 'mentions', 'relationship_created_on': '2021-04-19T15:20:14.000Z', 'relationship_last_published': '2021-04-19T15:20:14.000Z', 'type': 'intelligence_alert', 'uuid': '09b14293-ce79-4515-9041-de4cefe3cb6b', 'href': '/rest/document/v0/09b14293-ce79-4515-9041-de4cefe3cb6b'}, {'created_on': '2021-06-21T19:07:23.000Z', 'display_text': 'Biden-Putin Summit May Produce a Lull but Is No Magic Bullet against Russian Cyber-Threat Activity', 'key': 'e25f00ee-1b1a-4c35-ae5c-fece153143f6', 'relationship': 'mentions', 'relationship_created_on': '2021-06-21T19:07:23.000Z', 'relationship_last_published': '2021-06-21T19:07:23.000Z', 'type': 'intelligence_alert', 'uuid': '28f24dd5-9c13-4116-8fbd-7e395f6aeee0', 'href': '/rest/document/v0/28f24dd5-9c13-4116-8fbd-7e395f6aeee0'}, {'created_on': '2021-09-16T16:25:36.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 16 September 2021', 'key': 'de33f9be-318e-49b9-acfe-3c8ea3ce91e1', 'relationship': 'mentions', 'relationship_created_on': '2021-09-16T16:25:36.000Z', 'relationship_last_published': '2021-09-16T16:25:36.000Z', 'type': 'intelligence_alert', 'uuid': '69d0098b-9113-4914-a692-5b42d79f88ad', 'href': '/rest/document/v0/69d0098b-9113-4914-a692-5b42d79f88ad'}, {'created_on': '2021-11-05T21:25:11.000Z', 'display_text': 'COP26 Climate Talks Convene amid Ongoing Energy-Related Espionage and Information Campaigns', 'key': 'cd5bbb2d-9a0b-4553-934e-4d8a6b91b556', 'relationship': 'mentions', 'relationship_created_on': '2021-11-05T21:25:11.000Z', 'relationship_last_published': '2021-11-05T21:25:11.000Z', 'type': 'intelligence_alert', 'uuid': '422c1698-1d2f-46c5-b581-3ec7893b9401', 'href': '/rest/document/v0/422c1698-1d2f-46c5-b581-3ec7893b9401'}, {'created_on': '2021-12-02T21:51:25.000Z', 'display_text': 'Cyber Threats to the Energy Sector', 'key': '2b867306-ddb0-4ab8-be2a-4ac93cb2cb91', 'relationship': 'mentions', 'relationship_created_on': '2021-12-02T21:51:25.000Z', 'relationship_last_published': '2021-12-02T21:54:25.000Z', 'type': 'intelligence_report', 'uuid': 'c023236c-e981-45c4-94e4-38426e364a1f', 'href': '/rest/document/v0/c023236c-e981-45c4-94e4-38426e364a1f'}, {'created_on': '2016-01-25T10:37:24.000Z', 'display_text': 'OPEC', 'key': 'OPEC', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': 'b09a4448-fc15-4540-882b-03cfd3cebf98', 'href': '/rest/fundamental/v0/b09a4448-fc15-4540-882b-03cfd3cebf98'}, {'created_on': '2018-12-04T19:10:01.000Z', 'display_text': 'Schlumberger', 'key': 'Schlumberger', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': 'edcf95d2-a28a-4667-930f-9dc103716c23', 'href': '/rest/fundamental/v0/edcf95d2-a28a-4667-930f-9dc103716c23'}, {'created_on': '2018-12-04T19:10:01.000Z', 'display_text': 'Chevron', 'key': 'Chevron', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': 'c52f6188-5bf5-4c5d-a83d-6e2eca9cd4b6', 'href': '/rest/fundamental/v0/c52f6188-5bf5-4c5d-a83d-6e2eca9cd4b6'}, {'created_on': '2016-06-30T18:42:30.000Z', 'display_text': 'YouTube', 'key': 'YouTube', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '0249a9ed-d2ac-4a0a-a2f2-85abe57ae4e7', 'href': '/rest/fundamental/v0/0249a9ed-d2ac-4a0a-a2f2-85abe57ae4e7'}, {'created_on': '2012-11-27T15:41:47.000Z', 'display_text': 'Syria', 'key': 'Syria', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '1e25cb18-113a-41c7-ab12-de2976728eae', 'href': '/rest/fundamental/v0/1e25cb18-113a-41c7-ab12-de2976728eae'}, {'created_on': '2006-12-22T00:00:00.000Z', 'display_text': 'Azerbaijan', 'key': 'Azerbaijan', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'c7a27c94-d97a-420a-8858-9288b184c62e', 'href': '/rest/fundamental/v0/c7a27c94-d97a-420a-8858-9288b184c62e'}, {'created_on': '2003-12-15T00:00:00.000Z', 'display_text': 'Netherlands', 'key': 'Netherlands', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '4b4e3c26-44b9-40ce-947d-a399f53f9c7f', 'href': '/rest/fundamental/v0/4b4e3c26-44b9-40ce-947d-a399f53f9c7f'}, {'created_on': '2018-02-20T17:16:22.000Z', 'display_text': 'GandCrab', 'key': 'GandCrab', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '8538b5a4-bc67-4222-9310-0c9118b0af22', 'href': '/rest/fundamental/v0/8538b5a4-bc67-4222-9310-0c9118b0af22'}, {'created_on': '2018-02-12T16:41:05.000Z', 'display_text': 'Foreign Intelligence Service of the Russian Federation (Служба Внешней Разведки Российской Федерации)', 'key': 'Foreign Intelligence Service of the Russian Federation (Служба Внешней Разведки Российской Федерации)', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'threat_group', 'uuid': '11759430-3417-4772-9723-43bb38fe2280', 'href': '/rest/fundamental/v0/11759430-3417-4772-9723-43bb38fe2280'}, {'created_on': '2018-10-15T13:42:56.000Z', 'display_text': 'Exaramel', 'key': 'Exaramel', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': '5cc66934-6ff0-4c37-84eb-4cc62ba28255', 'href': '/rest/fundamental/v0/5cc66934-6ff0-4c37-84eb-4cc62ba28255'}, {'created_on': '2021-03-12T17:13:00.000Z', 'display_text': 'GreyEnergy', 'key': 'GreyEnergy', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': 'c34f2ace-6438-4920-9167-027907689eaa', 'href': '/rest/fundamental/v0/c34f2ace-6438-4920-9167-027907689eaa'}, {'created_on': '2018-12-04T19:09:56.000Z', 'display_text': 'Industrial', 'key': 'Industrial', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'vertical', 'uuid': 'fb065f1a-2619-47e8-98fa-30415e3edb9f', 'href': '/rest/fundamental/v0/fb065f1a-2619-47e8-98fa-30415e3edb9f'}, {'created_on': '2008-05-20T21:02:50.000Z', 'display_text': 'Western Asia', 'key': 'Western Asia', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'region', 'uuid': '53b59355-e4e6-40c7-ba89-002cabec9781', 'href': '/rest/fundamental/v0/53b59355-e4e6-40c7-ba89-002cabec9781'}, {'created_on': '2021-02-20T18:56:36.000Z', 'display_text': 'SITREP: Accellion FTA', 'key': '87fc1b24-2f1a-40b6-8282-2594335a50a3', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': 'c68c3558-7540-4a74-9af3-5b1d243f852e', 'href': '/rest/document/v0/c68c3558-7540-4a74-9af3-5b1d243f852e'}, {'created_on': '2020-01-20T20:08:16.000Z', 'display_text': 'Putin Power Transfer Plan Marks New Uncertainties in Balance between Globalism and “Sovereignty”', 'key': '0def1e52-2034-4a7f-b535-aa3b6c143cc1', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': 'fffd1701-8cd3-4237-b11b-31270d686f61', 'href': '/rest/document/v0/fffd1701-8cd3-4237-b11b-31270d686f61'}, {'created_on': '2020-06-09T07:52:43.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for June 8, 2020', 'key': 'bdb05bba-049d-4056-906f-3349336d52f1', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '6613f584-7728-4bd4-9dd7-103aef9b30ec', 'href': '/rest/document/v0/6613f584-7728-4bd4-9dd7-103aef9b30ec'}, {'created_on': '2018-11-27T16:09:30.000Z', 'display_text': 'Anonymous Yet Familiar: The Use of False Personas by Russian Cyberinformation Operations', 'key': 'e9e43a5a-caa5-458d-9bc4-3c483cf0394d', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_report', 'uuid': 'bd237f19-3b9f-4ea1-8f32-b9edd4667126', 'href': '/rest/document/v0/bd237f19-3b9f-4ea1-8f32-b9edd4667126'}, {'created_on': '2020-09-11T21:01:17.000Z', 'display_text': 'Cyprus at Center of Eastern Mediterranean Gas Dispute', 'key': 'Cyprus at Center of Eastern Mediterranean Gas Dispute', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'global_event', 'uuid': 'd8e7c996-cfc3-4050-8b51-46a1dc517896', 'href': '/rest/fundamental/v0/d8e7c996-cfc3-4050-8b51-46a1dc517896'}, {'created_on': '2021-04-07T22:11:42.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 7 April 2021', 'key': 'aaeb9511-6a7b-4c8f-a882-cfc0d8b4f321', 'relationship': 'mentions', 'relationship_created_on': '2021-04-07T22:11:42.000Z', 'relationship_last_published': '2021-04-07T22:11:42.000Z', 'type': 'intelligence_alert', 'uuid': 'ca097435-e5a7-4f11-9704-888617088676', 'href': '/rest/document/v0/ca097435-e5a7-4f11-9704-888617088676'}, {'created_on': '2021-04-19T18:02:29.000Z', 'display_text': 'Amid Russia-Ukraine Hostilities and US Sanctions Pressure, Russian Media Chief Predicts Cyber War', 'key': 'f7fc303e-994f-4802-b4a0-ca2a591673c3', 'relationship': 'mentions', 'relationship_created_on': '2021-04-19T18:02:29.000Z', 'relationship_last_published': '2021-04-19T18:02:29.000Z', 'type': 'intelligence_alert', 'uuid': '31be69cd-647e-4209-828c-33659d288aa3', 'href': '/rest/document/v0/31be69cd-647e-4209-828c-33659d288aa3'}, {'created_on': '2004-07-07T00:00:00.000Z', 'display_text': 'Russian Federation', 'key': 'Russian Federation', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '97807e5c-65d2-4023-ba96-c44cb0c16dc5', 'href': '/rest/fundamental/v0/97807e5c-65d2-4023-ba96-c44cb0c16dc5'}, {'created_on': '2021-11-13T01:22:43.000Z', 'display_text': 'Ransomware Attacks on US Critical Infrastructure Align with Russian Strategy', 'key': 'd6ee5344-fa61-4eb3-81e1-0cec21b731b0', 'relationship': 'mentions', 'relationship_created_on': '2021-11-13T01:22:43.000Z', 'relationship_last_published': '2021-11-13T01:22:43.000Z', 'type': 'intelligence_alert', 'uuid': 'a7f69280-dbcc-4426-b3e9-f851f0603e94', 'href': '/rest/document/v0/a7f69280-dbcc-4426-b3e9-f851f0603e94'}, {'created_on': '2007-04-12T00:00:00.000Z', 'display_text': 'Kazakhstan', 'key': 'Kazakhstan', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2022-01-10T21:09:04.000Z', 'type': 'country', 'uuid': 'cb1de5ae-ec20-4ac1-9561-46425fce81b8', 'href': '/rest/fundamental/v0/cb1de5ae-ec20-4ac1-9561-46425fce81b8'}, {'created_on': '2022-02-02T18:54:34.000Z', 'display_text': 'Cyber Threats Target NATO Countries’ Transportation and Energy Infrastructure Amid Tension with Russia', 'key': '5f56287d-89ad-4f5d-b7e9-2a9267193e0a', 'relationship': 'mentions', 'relationship_created_on': '2022-02-02T18:54:34.000Z', 'relationship_last_published': '2022-02-02T18:54:34.000Z', 'type': 'malicious_event', 'uuid': 'ffd3f586-f9f9-4538-b906-45f80a358662', 'href': '/rest/fundamental/v0/ffd3f586-f9f9-4538-b906-45f80a358662'}, {'created_on': '2016-12-29T10:08:23.000Z', 'display_text': 'Syria', 'key': 'Syria', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '50eac797-06e6-48ec-afd3-cc972ec6c3c9', 'href': '/rest/fundamental/v0/50eac797-06e6-48ec-afd3-cc972ec6c3c9'}, {'created_on': '2018-12-04T19:10:01.000Z', 'display_text': 'LukOil', 'key': 'LukOil', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '766e636d-2889-4a24-9af3-b3b30b5fce27', 'href': '/rest/fundamental/v0/766e636d-2889-4a24-9af3-b3b30b5fce27'}, {'created_on': '2015-11-09T16:45:06.000Z', 'display_text': 'NASA', 'key': 'NASA', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '243a1daf-21cf-413f-b1c5-83081336f47b', 'href': '/rest/fundamental/v0/243a1daf-21cf-413f-b1c5-83081336f47b'}, {'created_on': '2017-01-23T12:49:36.000Z', 'display_text': 'Total', 'key': 'Total', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'target_organization', 'uuid': '72ab7eb0-8977-4686-8218-e9231271184e', 'href': '/rest/fundamental/v0/72ab7eb0-8977-4686-8218-e9231271184e'}, {'created_on': '2008-05-07T00:00:00.000Z', 'display_text': 'Cyprus', 'key': 'Cyprus', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'b4934110-edb0-4d29-8d42-b035f627f4af', 'href': '/rest/fundamental/v0/b4934110-edb0-4d29-8d42-b035f627f4af'}, {'created_on': '2005-02-08T00:00:00.000Z', 'display_text': 'Libya', 'key': 'Libya', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'a8aeac54-fc9a-434c-a9ba-1aeebf76721b', 'href': '/rest/fundamental/v0/a8aeac54-fc9a-434c-a9ba-1aeebf76721b'}, {'created_on': '2006-05-23T00:00:00.000Z', 'display_text': 'Armenia', 'key': 'Armenia', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': '198ddfe4-1edb-4dec-97aa-72328ed212f1', 'href': '/rest/fundamental/v0/198ddfe4-1edb-4dec-97aa-72328ed212f1'}, {'created_on': '2003-08-06T00:00:00.000Z', 'display_text': 'Ukraine', 'key': 'Ukraine', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'e614cbe1-3a7d-4dfe-8e3d-56cae2165af6', 'href': '/rest/fundamental/v0/e614cbe1-3a7d-4dfe-8e3d-56cae2165af6'}, {'created_on': '2003-10-16T00:00:00.000Z', 'display_text': 'Saudi Arabia', 'key': 'Saudi Arabia', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'country', 'uuid': 'ca8e002d-dbc1-4ffc-a964-202a2d042c40', 'href': '/rest/fundamental/v0/ca8e002d-dbc1-4ffc-a964-202a2d042c40'}, {'created_on': '2020-04-28T14:37:47.000Z', 'display_text': 'CLOP', 'key': 'CLOP', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malware_family', 'uuid': 'dbba5596-7033-49e1-a731-7d54734463c4', 'href': '/rest/fundamental/v0/dbba5596-7033-49e1-a731-7d54734463c4'}, {'created_on': '2018-12-04T19:10:10.000Z', 'display_text': 'Utilities', 'key': 'Utilities', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'vertical', 'uuid': 'e7e29d66-df14-4875-a8fe-98dd80151eee', 'href': '/rest/fundamental/v0/e7e29d66-df14-4875-a8fe-98dd80151eee'}, {'created_on': '2015-07-31T10:35:10.000Z', 'display_text': 'Asia', 'key': 'Asia', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'region', 'uuid': 'e2aa2414-9adb-447e-ae83-32e3d6afee04', 'href': '/rest/fundamental/v0/e2aa2414-9adb-447e-ae83-32e3d6afee04'}, {'created_on': '2015-07-31T17:09:12.000Z', 'display_text': 'NATO', 'key': 'NATO', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'region', 'uuid': 'e0d04538-588a-4304-9974-832b7670bca7', 'href': '/rest/fundamental/v0/e0d04538-588a-4304-9974-832b7670bca7'}, {'created_on': '2019-06-21T22:43:06.000Z', 'display_text': 'Brinkmanship over Iran and Maneuvering over Upcoming G-20 Summit Could Spark Espionage or Disruptive Attacks', 'key': '051e541d-05e3-40d1-a867-81300e4573dd', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '84c2db1a-6c35-41b6-9f98-ce44840db791', 'href': '/rest/document/v0/84c2db1a-6c35-41b6-9f98-ce44840db791'}, {'created_on': '2020-08-11T20:34:54.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for August 11, 2020', 'key': 'e5fe7a49-0a0b-406a-aa88-d41de43adc89', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'intelligence_alert', 'uuid': '5a23f8ed-8038-4727-bb4d-5016c57e10f5', 'href': '/rest/document/v0/5a23f8ed-8038-4727-bb4d-5016c57e10f5'}, {'created_on': '2021-03-04T20:00:52.000Z', 'display_text': 'CLOP Ransomware Operators Leak Qualys Documents on Name-and-Shame Site on 3 and 4 March 2021', 'key': '1e4a812a-dc96-45a7-b2c4-13e866ae8393', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': '61e45fd4-b540-4de0-a81d-4cc8af952a60', 'href': '/rest/fundamental/v0/61e45fd4-b540-4de0-a81d-4cc8af952a60'}, {'created_on': '2020-02-29T23:22:36.000Z', 'display_text': 'Alleged DoppelPaymer Actors Seek to Blackmail Mexican Oil Company with Document Leak', 'key': '847d1ba4-3f84-4b83-943a-944993cbf934', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': '238857cc-12f3-4fac-820a-c59dc58c27da', 'href': '/rest/fundamental/v0/238857cc-12f3-4fac-820a-c59dc58c27da'}, {'created_on': '2017-12-21T19:23:58.000Z', 'display_text': 'TRITON ICS Malware Framework Targets Critical Infrastructure', 'key': 'd4e7170a-3485-4668-ad7d-3c2b0b43ea4c', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': '2200deae-56e0-4835-b454-8060bd0be50e', 'href': '/rest/fundamental/v0/2200deae-56e0-4835-b454-8060bd0be50e'}, {'created_on': '2018-11-03T11:26:30.000Z', 'display_text': 'US Indictment Reveals SNAKEMACKEREL Targeting of Westinghouse Electric', 'key': '28aa3b56-6fcb-4e0d-9c91-bcae3b798882', 'relationship': 'mentions', 'relationship_created_on': '2021-03-26T20:09:55.000Z', 'relationship_last_published': '2021-03-26T20:09:55.000Z', 'type': 'malicious_event', 'uuid': 'aff26f9b-2f45-483c-996a-e058fc02a84a', 'href': '/rest/fundamental/v0/aff26f9b-2f45-483c-996a-e058fc02a84a'}, {'created_on': '2021-03-31T19:20:13.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 31 March 2021', 'key': 'd0bff8ef-b21a-4a64-8541-2afba89eeafa', 'relationship': 'mentions', 'relationship_created_on': '2021-03-31T19:20:13.000Z', 'relationship_last_published': '2021-03-31T19:20:13.000Z', 'type': 'intelligence_alert', 'uuid': 'bb117f7c-c0b6-43ae-9468-463ae58e2853', 'href': '/rest/document/v0/bb117f7c-c0b6-43ae-9468-463ae58e2853'}, {'created_on': '2021-06-02T22:08:57.000Z', 'display_text': 'iDefense Global Research Intelligence Digest for 2 June 2021', 'key': '61641afe-698f-417a-802d-23197d0fe76d', 'relationship': 'mentions', 'relationship_created_on': '2021-06-02T22:08:57.000Z', 'relationship_last_published': '2021-06-02T22:08:57.000Z', 'type': 'intelligence_alert', 'uuid': '5bcf3272-5207-433c-a550-320968c1587a', 'href': '/rest/document/v0/5bcf3272-5207-433c-a550-320968c1587a'}], 'threat_types': '\n- Cyber Espionage\n- Cyber Crime', 'title': 'Russian Responses to Geopolitical Challenges Include Cyber-Threat Activity against Energy Industry Entities', 'type': 'intelligence_report', 'uuid': 'bdc9d16f-6040-4894-8544-9c98986a41fd', 'analysis': '## Key Findings and Judgements\n\n- The Russian government faces global and domestic challenges intensified by global warming, unrest in neighboring states, the rise of renewable energy, and international sanctions; these challenges aggravate poverty and discontent within Russia.\n\n- Russia’s government pursues its state strategies through a variety of means including cyber-threat operations that involve espionage, disruptive activity, and disinformation.\n- To mitigate the risks of Russian cyber-threats, organizations can implement best practices that are informed by intelligence.\n\n## An Oil and Gas Superpower Faces a Changing World \n\nFluctuating demand for fossil fuels, aggravated during the pandemic, and complicated relationships with the OPEC+ petroleum exporters’ consortium have contributed to unpredictability in the prices of Russia’s main exports—oil and gas. Geopolitical tensions and upheavals have influenced oil price volatility over the decades (Exhibit 1) and will likely continue to do so in the future.\n\n![USEIA on Oil Prices](/rest/files/download/6a/7f/fb/0f7be51f6fd40e1361a2b22135cab45f12ce755af5d089e8cc5d086afa/USEIAOnOilPrices2021-02-08cropped.png)  \n_Exhibit 1: Factors Affecting Crude Oil Prices; from the US Energy Information Administration, 12 January 2021_\n\n#### Climate Change: Challenges and Opportunities \n\nClimate change brings challenges and opportunities for Russia, including the following: \n\n- **Move from fossil fuels:** Governments and major corporations are vowing to cut carbon dioxide emissions in various ways, such as by developing renewable energy sources and switching to electric cars. These changes could curtail demand for fossil fuels, push down prices, and cut Russian revenues. Russia’s energy strategy for 2035 portrays these shifts as [a major challenge](https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/). \n\n- **Melting permafrost:** Melting permafrost is remaking Russia’s northern landscape as roads and pipelines sink and buckle. An oil tank at metals giant Norilsk Nickel leaked in 2020, causing a devastating oil spill and [costing the company US$2 billion in fines]( https://www.themoscowtimes.com/2021/02/19/nornickel-will-not-appeal-record-2bln-fine-for-arctic-oil-spill-a72980). \n\n- **Arctic shipping and Siberian agriculture:** Climate change is opening opportunities mixed with challenges for Russia. The melting Arctic has created new shipping routes (see Exhibit 2). Russian ships can carry more traffic on the Northern Sea Route, and the country can leverage its advantage in number of icebreakers, but countries are increasingly [competing with Russia](https://news.usni.org/2021/01/05/new-arctic-strategy-calls-for-regular-presence-as-a-way-to-compete-with-russia-china) to use the Arctic for resources, transport, and [military](https://www.cnn.com/2021/04/05/europe/russia-arctic-nato-military-intl-cmd/index.html ) advantage.  \n\n Some analysts suggest [Russia’s agriculture will improve]( https://asiatimes.com/2021/02/could-russia-dominate-world-agriculture/) with the thaw of the Siberian wastelands; however, Russia’s shrinking population would require the country to welcome migrants, most likely from China, to support the expanding agriculture, and many Russians are [suspicious of Chinese encroachment]( https://www.bbc.com/news/world-europe-50185006).  Russia’s government has [not seriously developed its renewable energy]( https://www.csis.org/analysis/climate-change-will-reshape-russia), as China has.\n\n ![Arctic Map](/rest/files/download/0f/6c/6f/91de9ef8d8d38345dc270f8915d9faa496a00b5babe2bff231dd195cd0/ArcticMapUWNews28288859157_5f54b9c446_c.jpg)  \n _Exhibit 2. “Map of the Arctic Region Showing the Northeast Passage, the Northern Sea Route, and Northwest Passage and Bathymetry NOAA.” Arctic Council, 2009. Public Domain_ \n\n## Global Challenges and Domestic Stability \n \nRussia has faced international condemnation and mounting economic sanctions for its human-rights violations, especially after seizing Crimea from Ukraine in 2014 and interfering in US and other elections. These international travails jeopardize Russia\'s domestic stability, [as summarized]( https://www.ft.com/content/94aeb690-ec2d-472d-adf7-212930c2d394) by respected Russian political commentator Tatyana Stanovaya: \n \n```\nPutin’s original success was rooted in his regime’s ability to deliver steady improvements in living standards while inspiring Russians with exploits on the world stage. Now the regime is ruling largely by scaring people and fostering the impression that Mother Russia is once again a “besieged fortress.” \n```\n\n#### Decline in living standards\n\nSanctions have hindered many Russian entities, including oil and gas producers, from expanding their operations. Many of Russia’s neighbors, including Turkmenistan, Azerbaijan, and Kazakhstan, compete with Russia to export oil and gas, and some neighbors, such as Ukraine, are overtly hostile. For years, Russia has sought to protect its energy exports and revenue by using pipelines that bypass Ukraine. Nord-Stream 2, the latest such pipeline, faces US sanctions.\n\nThe COVID-19 pandemic has contributed to a 3.1 percent drop in Russia’s GDP in 2020 and a [8.6 percent fall](https://amp.ft.com/content/24b45679-ed22-4df7-89ab-f3d5fad71c95) in Russian household consumption. Low oil prices, sanctions, and the COVID-19 pandemic have strained the economy and consumer confidence causing the government to impose price controls on sugar and vegetable oil.\n\nEconomic burdens are contributing to public discontent. YouTube videos of the lavish lifestyles of Russia’s top leaders, such as opposition leader Alexey Navalny’s recent video about “Putin’s Palace” in southern Russia, helped [inspire thousands of people](https://www.themoscowtimes.com/2021/02/04/dissatisfaction-with-putin-surges-among-young-russians-levada-poll-a72835) to protest Navalny’s arrest in January 2021. Russia’s ruling party will face a test with the September 2021 parliamentary elections; party support has [dropped to an eight-year low](https://www.themoscowtimes.com/2021/03/11/support-for-russias-ruling-party-drops-to-pre-crimea-low-poll-a73211), according to a February 2021 survey by the independent Levada polling agency. \n\n#### Exploits on the world stage \n\nDuring the COVID-19 pandemic, Russia has been using “[vaccine diplomacy]( https://jamestown.org/program/kremlins-vaccine-diplomacy-in-action-tools-strengths-intermediary-results/)” to boost its image on the world stage.  Russia’s role in ending a conflict between Azerbaijan and Armenia had mixed success in promoting its image as a peacemaker. These small triumphs will likely do little, however, to outweigh Russia’s pariah status or boost Russians’ patriotic pride.\n\n#### Besieged fortress \n\nHaving failed to inspire its people with patriotism through improvements in living standards and exploits on the world stage, Putin’s government has chosen to [stifle public protest](https://www.rferl.org/a/russia-foreign-agents-law-interview-media-lawyer-civil-societ-rfe/31048094.html). Laws in 2021 suppress independent journalists and opposition activists, labeling them as agents of foreign powers, and police have arrested thousands of rally participants.  \n\nPutin\'s regime is attempting to promote patriotism by “fostering the impression that Mother Russia is once again a ‘besieged fortress’," as Stanovaya put it. Officials and state media frequently describe the outside world, particularly the US and Europe, as constantly seeking to undermine and humiliate Russia. \n\nIn an interview in late 2020, Russia’s foreign intelligence service chief, Sergey Naryshkin, portrayed international sanctions for Russian human-rights violations as “hybrid wars,” referring to undeclared wars using diplomatic and psychological means. Naryshkin and other officials have repeatedly portrayed protests in Russia and neighboring countries as schemes by foreign powers to weaken Russia.  \n\n#### "Frenemies"\n\nFacing ostracism and pressure from sanctions, which affect its oil and gas and other industries, Russia is forced to work with counterparts it does not necessarily trust:\n \n- **China:** Russia and China concluded the 30-year, $400 billion “Power of Siberia” gas pipeline deal in May 2014, just after Russia annexed Crimea from Ukraine and incurred international wrath. Although gas started flowing in 2019, [suspicion surrounds this cooperation](https://www.scmp.com/week-asia/geopolitics/article/2100228/chinese-russian-far-east-geopolitical-time-bomb). Some Russian commentators fear being relegated to the position of a junior partner and raw materials supplier to China. Also, many local residents distrust Chinese migrants, and popular culture occasionally resurrects the specter of hordes of Chinese soldiers coming over the border.\n\n- **Saudi Arabia:** Starting in 2016, Russia and Saudi Arabia agreed to limit oil and gas production to maintain high prices, as well as entering other cooperative agreements. At the G-20 summit in late 2018, Putin and Saudi crown prince Mohamad Bin-Salman even famously [exchanged a high-five](https://time.com/5467935/putin-bin-salman-g20/),  as both men faced harsh international criticisms for human-rights violations. \n\n However, Russia targets its “frenemies” as well as its adversaries. The US and UK governments have accused Russia of carrying out intrusions using [Triton](https://intelgraph.idefense.com/#/node/malicious_event/view/2200deae-56e0-4835-b454-8060bd0be50e) and [Neuron/Nautilus](https://intelgraph.idefense.com/#/node/intelligence_alert/view/6f668357-bd6a-4a04-876d-20bd840e0788) malware against computer networks in Saudi Arabia. These campaigns were likely intended to gain visibility into and leverage over Saudi policies, particularly regarding oil production levels and prices but also involving the Saudi relationship with other players in the Middle East. \n\n- **Turkey:** Turkey and Russia have a long complicated relationship with signs of both cooperation and conflict in areas surrounding oil and gas. Turkey is a member of the NATO military alliance but buys Russian anti-aircraft weapons and works sporadically with Russia. In 2020, Turkey carried out controversial [gas drilling in the eastern Mediterranean](https://intelgraph.idefense.com/#/node/global_event/view/d8e7c996-cfc3-4050-8b51-46a1dc517896), occasionally opposed Russia in conflicts in Syria and Libya, and supported Azerbaijan in a [conflict with Armenia](https://intelgraph.idefense.com/#/node/global_event/view/8d7758be-40ec-4b6c-b2fc-cd007183640d) that could have endangered regional oil and gas infrastructure.\n\n- **Iran:** Russia’s equally [complex relationship with Iran](https://intelgraph.idefense.com/#/node/intelligence_alert/view/84c2db1a-6c35-41b6-9f98-ce44840db791) has encompassed military cooperation in Syria and agreements on information security cooperation.  At the same time, Russian group BELUGASTURGEON stole hacking tools and infrastructure from an Iranian threat group and used them against Saudi targets in a [false flag operation](https://intelgraph.idefense.com/#/node/intelligence_alert/view/6f668357-bd6a-4a04-876d-20bd840e0788) that framed Iran.\n\n#### Russian Strategies\n\nOne of Russia’s 19th-century emperors famously said, “Russia has just two allies: its army and its navy.” Putin directly quoted that in 2015, half in jest, but the quote remains popular.  This sense of isolation colors Russia’s strategic worldview. (For more detail on Russian motives and strategies, see the report [Making Sense of Russian Cyberthreat Activity](https://intelgraph.idefense.com/#/node/intelligence_report/view/30e6397e-69cb-48e9-9017-eafb0d761d24).) \n\n\nRussian strategists perceive the country as engaged in a constant battle in the arena of [psychological or information warfare against US and Western powers](https://intelgraph.idefense.com/#/node/intelligence_alert/view/79e6008d-ddd4-472d-b574-5ad1a769e096). Russian officials and state media portray foreign culture, TV and movies, and rhetoric about democracy as ill-disguised attempts to humiliate and weaken Russia. This view allows them to rationalize using propaganda, trolls, and disinformation to discredit and divide other countries, as they [did in 2016]( https://intelgraph.idefense.com/#/node/intelligence_report/view/1373c4a9-baab-4fc1-a33b-f7b152a5f933), in the [2020 US elections](https://www.dni.gov/files/ODNI/documents/assessments/ICA-declass-16MAR21.pdf), and elsewhere. \n\nThe sense of hostility toward the West coexists with a desire to be part of Europe and the global economy, to be a “normal” country, and to restore the great power status the Soviet Union enjoyed. As part of that love-hate relationship with the West, Russian policy has long [balanced globalism and isolationism]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/fffd1701-8cd3-4237-b11b-31270d686f61). Over the years, Russian officials and businesses have sought to preserve Russian positions in global markets and attract global investors, but as the sanctions have tightened, Russia has increasingly emphasized import substitution policies and preparations for working alone. Events in 2020 to 2021 seem to favor isolationism. Independent Russian pollster Levada found in a February 2021 survey that only 29 percent of respondents consider Russia a European country, down from 52 percent in 2008. \n\nThe [increased sanctions](https://www.bellingcat.com/news/2021/03/19/berlin-assassination-new-evidence-on-suspected-fsb-hitman-passed-to-german-investigators/) from the US and EU in 2020 for human-rights concerns have heightened international tensions.  Media reporting suggests US officials are discussing additional sanctions for Russia’s suspected involvement in the [SolarWinds espionage campaign](https://intelgraph.idefense.com/#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4). In a 16 March 2021 interview, US President [Joe Biden warned](https://www.politico.com/news/2021/03/17/biden-putin-election-interference-476656) that Putin would “pay a price” for Russian influence operations in the 2020 US election. [He also said, “I do,”](https://intelgraph.idefense.com/#/node/intelligence_alert/view/3ee020e9-c64f-4c3f-8162-73f80ad85863) when asked whether he considered Putin a killer,  prompting Russia’s foreign ministry to recall its ambassador from Washington for the first time since 1998.\n\nGiven these priorities and circumstances, iDefense assesses that Putin and strategists strive for: \n-\tA loyal population \n-\tSome restoration of Russia’s Soviet-era influence and prestige\n-\tAn end to sanctions\n\n#### Aspirations in the Energy Sector \n\nThese overall goals and strategies have implications for Russian policies in the energy sector. iDefense assesses that Russian aspirations include: \n- [Preserving Russian markets for oil and gas](https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/) \n- Meeting challenges from rival trends such as liquefied natural gas, shale gas, and renewables\n- Maintaining control over pipelines\n- Gaining visibility into and leverage over decision-making in oil and gas markets and policies worldwide\n- Obtaining foreign energy-related technologies that have both civilian and military uses, as evident in reports from [Norway](https://www.reuters.com/article/us-norway-oil-security/russian-chinese-intelligence-targeting-norwegian-oil-secrets-report-idUSKBN28D2M7), the [Netherlands, and Denmark]( https://www.euronews.com/2020/12/09/russian-citizen-charged-with-spying-on-energy-technology-in-denmark)  \n- Slowing energy sector development in  adversary countries, sometimes by [encouraging environmental activists there](https://www.inc.com/magazine/201905/tom-foster/russian-trolls-facebook-social-media-attacks-brands-hoax-fake-disinformation.html ) \n\nTo pursue these goals, Russian strategists can choose among a variety of options, including diplomatic, economic and soft power; military action; and asymmetric approaches, such as cyber-threat activity and cyber-enabled information operations.\n\n## Cyber-Threat Capabilities\n\nCyber-threat groups that US and other governments have linked to Russia have helped Russia advance its state strategies through espionage, disruptive activity, and disinformation. Russia’s military and security agencies occasionally perform operations using tools, techniques, and personnel drawn from the Russian-speaking cybercriminal underground. \n\n#### Energy Backdooring: BLACK GHOST KNIFEFISH\n\nThe US government has linked [BLACK GHOST KNIFEFISH](https://intelgraph.idefense.com/#/node/threat_group/view/27332f70-302c-491a-85f2-3714218296b8) (a.k.a. Dragonfly, Berserk Bear, Energetic Bear) to the Russian government. The group is known for targeting energy entities in multiple countries. \n\nIn March 2018, the US Department of Homeland Security’s Cybersecurity and Infrastructure Security Agency, or CISA, [wrote](https://intelgraph.idefense.com/#/node/intelligence_alert/view/c79d8446-28a9-4b20-a5bb-d9ac5ff4a6de):\n\n```\nRussian government cyber actors…targeted small commercial facilities’ networks…gained remote access into energy sector networks…conducted network reconnaissance, moved laterally, and collected information pertaining to Industrial Control Systems (ICS)…DHS was able to reconstruct screenshot fragments of a Human Machine Interface (HMI) that the threat actors accessed. (See Exhibit 4.)\n```\n\n![Dragonfly Screenshots](/rest/files/download/27/f6/e2/72a551319a5908267b8a45e616313115f032bc8442bdf38430cc12f1e6/DragonflyScreenshotsFromUSCERTMarch152018cropped.png)  \n_Exhibit 4: Reconstructed HMI Screenshot Fragments, US CISA Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors, 16 March 2018_ \n\n\nAn April 2018 [US and UK government alert warned]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/21ab89f6-1ac1-4cc3-83f6-233a5d7473cf) of Russian government-supported cyber-threat operations matching activity that iDefense tracks as BLACK GHOST KNIFEFISH. The activity targeted network infrastructure devices (such as routers, switches, firewalls, and network intrusion detection systems) enabled with the generic routing encapsulation protocol, Cisco Smart Install feature, or simple network management protocol. The threat actors conducted man-in-the-middle attacks for espionage, to steal intellectual property, and potentially to prepare for future disruptive or destructive activity. \n\nSigns of cooperation exist between BLACK GHOST KNIFEFISH and BELUGASTURGEON (a.k.a. Turla), which US and UK officials say is “widely reported to be associated with Russian actors” and which Estonian and Czech authorities have [identified with](https://www.reuters.com/article/us-russia-cyber/hacking-the-hackers-russian-group-hijacked-iranian-spying-operation-officials-say-idUSKBN1X00AK)  Russia’s [Federal Security Service](https://intelgraph.idefense.com/#/node/threat_group/view/d96f3b14-462b-4ab4-aa04-23c7a2996611) (FSB). BELUGASTURGEON’s targets are mostly political entities but have included the [Armenian natural resources ministry](https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes), and, as mentioned above, the threat group carried out false flag operations framing Iranian threat actors.\n\n#### Military Hackers: SANDFISH and SNAKEMACKEREL\n\nRussia\'s cyber-threat capabilities include groups the US government has linked to Russia\'s military intelligence agency, the GRU.\n\nThe US and other governments have attributed numerous destructive operations, including the Ukrainian blackout of 2015 and the Crashoverride series of attacks in 2016, to a group that iDefense tracks as [SANDFISH](https://intelgraph.idefense.com/#/node/threat_group/view/40d2cf30-237a-467b-826d-390f12cc27f0) (a.k.a. SANDWORM).\n\nThe Ukrainian blackouts fit Russia\'s strategic goals of weakening Ukraine. The electricity blackout from the December 2016 Crashoverride operation was merely the [culmination of a two-week series of attacks]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/f7c3ae17-869a-4025-9edb-a6e8c4ca7a3e) that also disrupted operations at the State Treasury; the Finance Ministry, Defense Ministry, and other government entities; an Internet provider; and the railways. Ukrainian citizens could not receive pensions or buy rail tickets. The attempt to disrupt Ukrainian everyday life was likely intended to discredit the leadership of its then-president, who was particularly hostile to Russia.\n\nSANDFISH has also targeted oil and gas companies in Ukraine and Azerbaijan [using GreyEnergy malware]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/f0289fe9-c076-437b-984f-71f17d6f7950). SANDFISH tools Exaramel and PAS Shell appeared in a campaign that ran from 2017 to 2020 and compromised French IT and web-hosting companies [running Centreon monitoring software]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/55004ca2-e598-460f-bb0c-8ef6f37b7bca). French energy giant Total is one of Centreon\'s customers. \n\nAs for the military hacker group [SNAKEMACKEREL](https://intelgraph.idefense.com/#/node/threat_group/view/065336a6-651d-4f80-b8c2-9347f4486912) (a.k.a. APT28, FancyBear), in May 2020, the [US FBI reportedly warned](https://intelgraph.idefense.com/#/node/intelligence_alert/view/575c5eef-0784-46cd-bf67-8e256d0c2fc7) that the group had been targeting US government agencies and educational institutions since December 2018. According to a July 2020 report from the news source Wired, a SNAKEMACKEREL IP address from the FBI alert matched one from an earlier report advisory, drawing speculation that SNAKEMACKEREL had targeted an entity in the US energy sector—a departure in targeting for the group. The DOE-named IP address might have represented infrastructure that both SNAKEMACKEREL and SANDFISH used. The threat actors sent spear-phishing emails to  personal and work email accounts and leveraged password-spraying and brute-force tactics to compromise victims’ mail servers, Microsoft Office 365 and email accounts, and VPN servers, according to Wired. \n\nEarlier, in 2014 and 2015, SNAKEMACKEREL operators also conducted a spear-phishing campaign [against Westinghouse Electric Company](https://intelgraph.idefense.com/#/node/malicious_event/view/aff26f9b-2f45-483c-996a-e058fc02a84a), according to a US indictment.\n\nIf SNAKEMACKEREL successfully breached a US energy entity or Westinghouse, Russian intelligence might have gained insight into upcoming deals with countries of interest to Russia. Westinghouse supplies uranium to Ukraine and has bid for contracts to build nuclear power plants for Saudi Arabia.\n\nSNAKEMACKEREL and SANDFISH seek deniability by disguising themselves as criminals or hacktivists:\n- During the [PetyaA/NotPetya campaign](https://intelgraph.idefense.com/#/node/intelligence_alert/view/e4cac05c-83a4-40e3-b8b2-190c7c405ee0) against Ukraine in 2017 that US officials attributed to SANDFISH, the perpetrators pretended to be criminal ransomware actors. \n- When conducting hack-and-leak operations, these GRU actors often [hid behind pseudo-hacktivist personas](https://intelgraph.idefense.com/#/node/intelligence_report/view/bd237f19-3b9f-4ea1-8f32-b9edd4667126), such as Guccifer 2.0 and Fancy Bears Hack Team, to discredit and divide societies in the US and other countries and entities seen as hostile to Russia. \n\n\n#### Threatening Industrial Safety Systems: ZANDER\n\nRussia\'s cyber-threat capabilities may also include a group iDefense calls [ZANDER]( https://intelgraph.idefense.com/#/node/threat_group/view/a363a7ca-1d5d-4477-9ce9-e9259cb888e4), which the US government has linked to Russia’s [Central Research Institute for Chemistry and Mechanics](https://intelgraph.idefense.com/#/node/threat_group/view/99890a07-ddca-491d-ae7e-ae22a53db690) (TsNIIKhM). \n\nIf successful, the August 2017 Triton malware attack on the operational technology systems of a refinery in Saudi Arabia [could have endangered human lives](https://www.slideshare.net/JoeSlowik/past-and-future-of-integrity-based-attacks-in-ics-environments).  Researchers attributed the activity to TsNIIKHM, an institute subordinate to the Russian defense ministry’s Federal Service for Technical and Export Control. Having sufficient confidence in this attribution, on 23 October 2020, the US Treasury Department added TsNIIKhM to its Specially Designated Nationals sanctions list in connection with the August 2017 Triton attack.\n\nThe Triton attack was likely meant to create a backdoor for potential disruptive activity, gain leverage over a key company in the petroleum sector, and potentially discredit or influence Saudi policies regarding oil production levels and prices as well as Saudi relationships with other Middle Eastern countries. \n\nZANDER has also targeted the electricity sector. Since late 2018, they have been searching for remote login portals and vulnerabilities in the networks of at least 20 targets in electricity generation, transmission, and distribution systems in the US and Asia Pacific, according to E-ISAC and Dragos reports from June 2019. \n\n#### JACKMACKEREL\n\nAnother Russian cyber-threat group with impact on the energy sector is [JACKMACKEREL]( https://intelgraph.idefense.com/#/node/threat_group/view/24a38270-949f-442a-aac6-53a99ef1ea70) (a.k.a. Cozy Bear, the Dukes, APT 29). The Estonian government has linked this group with both the FSB and the SVR, Russia’s [Foreign Intelligence Service](https://intelgraph.idefense.com/#/node/threat_group/view/11759430-3417-4772-9723-43bb38fe2280).\n\nSome analysts attribute the SolarWinds operation of 2020 to JACKMACKEREL. However, iDefense has [compared the malware and infrastructure](https://intelgraph.idefense.com/#/node/intelligence_alert/view/7128fb11-2753-4f4d-aa51-2c13731f7dbe) used in the SolarWinds operation with JACKMACKEREL tools and found some important differences. In April 2021, the US government formally attributed the SolarWinds campaign to the SVR, linking the SVR to the APT29 threat group. In the absence of further detail, [Accenture iDefense cannot currently verify this attribution](https://intelgraph.idefense.com/#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4) and is tracking this activity as action from the distinct threat group FireEye calls UNC2452.\n\nRegardless of exact attribution of the SolarWinds operation, the SVR is certainly involved with Russian cyber-threat activity and conducts espionage and pressure campaigns to promote Russia’s economic and political interests abroad. \n\n[Past SVR activities include](PUTINS_HYDRA_INSIDE_THE_RUSSIAN_INTELLIGENCE_SERVICES_1513.pdf) pilfering renewable energy technologies, stealing commercial information such as tenders, or coercing cooperation from people who allocate contracts, according to reports analyzing Russian intelligence services. Stealing commercial information and coercing people can help boost Russian competitiveness in winning oil and gas contracts, while stealing technologies can help Russia compete with or weaken companies developing renewable energy.\n\nThe intelligence service responsible for the SolarWinds operation [specifically targeted](https://intelgraph.idefense.com/#/node/intelligence_report/view/eb77c712-fcfd-48f6-9533-baa18131fb62) US report entities, including Sandia and Los Alamos national laboratories in New Mexico and Washington, the Office of Secure Transportation at the report, and DOE’s Richland field office, as well as the Federal Energy Regulatory Commission. In addition, researchers have identified Chevron Texaco as one of 23 entities the threat actors targeted for follow-on activity. These breaches could potentially provide valuable information on the resilience of the US electric grid and nuclear power plants as well as providing insight into Chevron Texaco’s business plans and agreements in contested areas such as the eastern Mediterranean. Note that Cyprus contracted with Chevron subsidiary Noble Energy to drill gas in Cyprus-controlled zones.\n\n#### Hybrid Ransomware Operations and EvilCorp \n\nIn addition to the straightforward state-sponsored espionage or disruptive activity discussed above, Russian-state threat groups sometimes hide behind the mask of criminal ransomware. An iDefense compendium of ransomware or data leak [events affecting the energy and utility sectors]( https://intelgraph.idefense.com/#/node/intelligence_report/view/999b6c55-3cb8-4372-affb-bcc9c47dd95b) includes breaches of NorskHydro, the Norwegian metals and energy company, and of Mexican oil company Pemex. iDefense has grounds to characterize these with low-to-medium confidence as “[hybrid ransomware]( https://intelgraph.idefense.com/#/node/intelligence_report/view/034b4162-239d-438e-8e85-490103b83e5d)” operations. Such operations involve cybercriminals and intelligence services cooperating for mutual benefit, or they are intended to disrupt operations or destroy or exfiltrate data rather than only to extort a ransom payment. Most famously, the June 2017 Petya.A/NotPetya attack in Ukraine was a Russian-state operation disguised as criminal ransomware.\n \nRussian-state cyber-threat operations sometimes draw on tools and personnel from the Russian-speaking cybercrime world, as iDefense has extensively documented and as  [American](https://intelgraph.idefense.com/#/node/intelligence_alert/view/575c5eef-0784-46cd-bf67-8e256d0c2fc7) and [Canadian](https://intelgraph.idefense.com/#/node/intelligence_alert/view/9fe9f478-a5bb-405d-846a-b6baac07c431) governments have noted. \n\nRussian cyber-criminals [have worked with FSB operatives](https://intelgraph.idefense.com/#/node/intelligence_alert/view/0f78f6ba-f0aa-4078-b70a-674cd12d2643) and [received protection](https://intelgraph.idefense.com/#/node/intelligence_alert/view/6c403e44-c382-4ed6-aabf-23d0d353c0ba) from highly placed people. When caught by Russian law enforcement, they [are often pressured](https://intelgraph.idefense.com/#/node/intelligence_alert/view/130d2acb-9778-4b22-96a8-5c47115f2659) to participate in Russian intelligence missions or consider geopolitical factors in future targeting.\n \nFor example, ransomware operator GandCrab promised in October 2018 to provide decryption keys to people in Russia’s war-torn ally Syria but vowed never to release keys to victims in other countries, as “we need to [continue punitive proceedings]( https://intelgraph.idefense.com/#/node/malicious_event/view/ff63b317-2de3-4ba3-828a-d294eab5b91f) against certain countries.” Self-proclaimed hacker and onetime government contractor [Pavel Sitnikov](https://intelgraph.idefense.com/#/node/threat_actor/view/ca0ed890-16a4-460c-aa44-69c23914c2b0) in December 2020 stated, “ransomware and special services are inseparable.”  \n\nThe EvilCorp group (a.k.a. [HighRollers](https://intelgraph.idefense.com/#/node/threat_group/view/8eb76c68-4d9a-4397-8cc6-e779f9ee8b50), TA505, Dridex Group) exemplifies the intersection between criminal and intelligence activity. According to the US Treasury Department, EvilCorp leader [Maksim Yakubets](https://intelgraph.idefense.com/#/node/threat_actor/view/df442e94-f0df-4ec1-9d35-57bedf1a9223) has done contract work for the FSB, and investigative journalists report he is married to an active FSB veteran.\n\nEvilCorp played a role in DoppelPaymer and Clop (a.k.a. Cl0p) ransomware operations. On 10 December 2020, the FBI warned the US private sector that [DoppelPaymer actors were targeting critical infrastructure](https://intelgraph.idefense.com/#/node/intelligence_alert/view/8c5412b6-f114-47a4-afd1-5e5f0a88d10b) including the 911 emergency service, according to media accounts. The DoppelPaymer actors have breached and leaked information on numerous companies involved in defense or national security as well as public safety work. DoppelPaymer actors leaked data from [numerous aerospace and defense contractors](https://intelgraph.idefense.com/#/node/malicious_event/view/238857cc-12f3-4fac-820a-c59dc58c27da) including Schlumberger Technology, Hyundai’s [Kia Motors](https://intelgraph.idefense.com/#/node/malicious_event/view/d009718a-25f6-491f-95f2-528d0a3d3f63), [Boyce Technologies ](https://intelgraph.idefense.com/#/node/intelligence_alert/view/5a23f8ed-8038-4727-bb4d-5016c57e10f5), and NASA contractor [Digital Management Inc.]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/6613f584-7728-4bd4-9dd7-103aef9b30ec)\n\nThe November 2019 DoppelPaymer [ransomware attack on the Mexican national oil company Pemex]( https://intelgraph.idefense.com/#/node/malicious_event/view/238857cc-12f3-4fac-820a-c59dc58c27da) appears to have combined financial and  political motivations. EvilCorp had an incentive to retaliate against or discredit Pemex and Mexican President Andrés Manuel López Obrador (a.k.a. AMLO): EvilCorp leader Yakubets’ father-in-law, retired from Russian intelligence, runs a private security company that provided security for Russian company Lukoil. The Mexican government shunned Lukoil and other foreign investors when attempting to build a self-sufficient Mexican oil industry. During the spring 2018 presidential campaign, pro-AMLO Pemex employees rallied holding signs showing feet kicking the logos of companies like Lukoil. Leaked Pemex documents could also provide evidence in [trials of former Pemex officials]( https://intelgraph.idefense.com/#/node/malicious_event/view/05982e7e-b7d0-4203-a8a9-dd46ea769854) for their dealings with scandal-plagued Brazilian company Odebrecht.  This provides an example of a Russian-state malicious actor targeting an oil and gas entity for apparent financial profit and to support Russian national interests.\n\nEnergy companies were also victims in cloud provider [Accellion’s File Transfer Appliance software breach]( https://intelgraph.idefense.com/#/node/intelligence_alert/view/c68c3558-7540-4a74-9af3-5b1d243f852e). Some victims received extortion emails from actors threatening to publish stolen data on the “CL0P^_- LEAKS" .onion website. Clop actors have stolen information with national security value, such as specifications for Bombardier’s military spy plane.  Samples of data from [geophysical services company CGG]( https://intelgraph.idefense.com/#/node/malicious_event/view/c069f7c1-7b22-4713-a1d9-b1ba041602e8) and [transportation company CSX]( https://intelgraph.idefense.com/#/node/malicious_event/view/0e1a64c4-e283-457b-b615-9863436b0dbd) were also leaked on the site. \n\nRansomware negotiator [Coveware’s analysis](https://www.coveware.com/blog/2021/2/18/q4-doxxing-victim-trends-industrial-sector-emerges-as-primary-ransom-non-payor) of leaks of victim data on ransomware operators’ sites in the last quarter of 2020 indicates the Clop group focused on the energy and technology sectors, whereas the industrial sector suffered most leaks on other groups’ sites. Clop’s geographic targeting also overlaps with Russian-state priorities, according to Coveware’s analysis: 43 percent of Clop leaks were from victims in Germany.   Russia [has aimed hostile rhetoric](https://euvsdisinfo.eu/villifying-germany-wooing-germany/) against that country’s leadership for spearheading EU sanctions against Russia.', 'sources_external': [{'datetime': '2020-12-18T05:00:00.000Z', 'description': '-\tСергей Нарышкин: О том как статъ настоящим разведчиком (Sergey Naryshkin: On how to become a real spy)  hxxps://aif[.]ru/society/safety/100_let_svr_sergey_naryshkin_o_tom_kak_stat_nastoyashchim_razvedchikom', 'name': 'Argumenty i fakty', 'reputation': 4}, {'datetime': '2021-02-27T05:00:00.000Z', 'description': 'Когда-то император Александр III сказал замечательную по своей емкости фразу: ....hxxps://t[.]me/nstarikovru/20816/', 'name': 'Nikolay Starikov', 'reputation': 3}, {'datetime': '2019-11-01T04:00:00.000Z', 'description': "Why Chinese farmers have crossed border into Russia's Far East", 'name': 'British Broadcasting Corporation', 'reputation': 4, 'url': 'https://www.bbc.com/news/world-europe-50185006'}, {'datetime': '2021-03-11T05:00:00.000Z', 'description': "Support for Russia's Ruling Party Drops to Pre-Crimea Low – Poll", 'name': 'Moscow Times', 'reputation': 4, 'url': 'https://www.themoscowtimes.com/2021/03/11/support-for-russias-ruling-party-drops-to-pre-crimea-low-poll-a73211'}, {'datetime': '2021-03-25T04:00:00.000Z', 'description': 'Kremlin’s ‘Vaccine Diplomacy’ in Action: Tools, Strengths, Intermediary Results', 'name': 'Jamestown Foundation', 'reputation': 4, 'url': 'https://jamestown.org/program/kremlins-vaccine-diplomacy-in-action-tools-strengths-intermediary-results/'}, {'datetime': '2018-11-30T05:00:00.000Z', 'description': 'Watch Vladimir Putin and Crown Prince Mohammed bin Salman Embrace at the G-20', 'name': 'Time', 'reputation': 4, 'url': 'https://time.com/5467935/putin-bin-salman-g20/'}, {'datetime': '2021-03-09T05:00:00.000Z', 'description': 'Vilifying Germany; Wooing Germany', 'name': 'EU vs Disinfo', 'reputation': 4, 'url': 'https://euvsdisinfo.eu/villifying-germany-wooing-germany/'}, {'datetime': '2021-03-15T04:00:00.000Z', 'description': 'The Iran-Russia Cyber Agreement and U.S. Strategy in the Middle East', 'name': 'Council on Foreign Relations', 'reputation': 4, 'url': 'https://www.cfr.org/blog/iran-russia-cyber-agreement-and-us-strategy-middle-east'}, {'datetime': '2017-07-08T04:00:00.000Z', 'description': 'Chinese in the Russian Far East: a geopolitical time bomb?', 'name': 'South China Morning Post', 'reputation': 4, 'url': 'https://www.scmp.com/week-asia/geopolitics/article/2100228/chinese-russian-far-east-geopolitical-time-bomb'}, {'datetime': '2021-02-08T05:00:00.000Z', 'description': 'Russia-Iran cooperation poses challenges for US cyber strategy, global norms', 'name': 'C4ISR', 'reputation': 4, 'url': 'https://www.c4isrnet.com/thought-leadership/2021/02/08/russia-iran-cooperation-poses-challenges-for-us-cyber-strategy-global-norms/'}, {'datetime': '2016-05-11T04:00:00.000Z', 'description': 'Putin’s Hydra: Inside Russia’s Intelligence Services', 'name': 'European Council on Foreign Relations', 'reputation': 4, 'url': 'https://ecfr.eu/wp-content/uploads/ECFR_169_-_PUTINS_HYDRA_INSIDE_THE_RUSSIAN_INTELLIGENCE_SERVICES_1513.pdf'}, {'datetime': '2019-10-18T04:00:00.000Z', 'description': 'Cybersecurity Advisory, Turla Group Exploits Iranian APT to Expand Coverage of Victims', 'name': 'National Security Agency, National Cyber Security Centre', 'reputation': 5, 'url': 'https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF'}, {'datetime': '2020-12-12T05:00:00.000Z', 'description': 'Netherlands kicks out two Russian diplomats as Denmark charges Russian citizen with espionage', 'name': 'EuroNews', 'reputation': 4, 'url': 'https://www.euronews.com/2020/12/09/russian-citizen-charged-with-spying-on-energy-technology-in-denmark'}, {'datetime': '2018-10-03T04:00:00.000Z', 'description': 'US v Aleksei Sergeyevich Morenets et al', 'name': 'US Department of Justice', 'reputation': 5, 'url': 'https://www.justice.gov/opa/page/file/1098481/download'}, {'datetime': '2017-09-15T04:00:00.000Z', 'description': 'International Security and Estonia', 'name': 'Estonian Foreign Intelligence Service', 'reputation': 5, 'url': 'https://www.valisluureamet.ee/pdf/raport-2018-ENG-web.pdf'}, {'datetime': '2021-03-04T05:00:00.000Z', 'description': 'China’s 5-year plan includes goals to open Arctic Silk Road', 'name': 'Reuters', 'reputation': 4, 'url': 'https://reuters.com/article/us-china-parliament-polar-idUSKBN2AX09F'}, {'datetime': '2019-05-01T04:00:00.000Z', 'description': 'How Russian Trolls Are Using American Businesses as Their Weapons', 'name': 'Inc', 'reputation': 4, 'url': 'https://www.inc.com/magazine/201905/tom-foster/russian-trolls-facebook-social-media-attacks-brands-hoax-fake-disinformation.html'}, {'datetime': '2021-03-22T04:00:00.000Z', 'description': 'Russia and Europe hxxps://www.levada[.]ru/en/2021/03/22/russia-and-europe/', 'name': 'Levada', 'reputation': 4}, {'datetime': '2014-09-12T04:00:00.000Z', 'description': 'Announcement of Expanded Treasury Sanctions within the Russian Financial Services, Energy and Defense or Related Materiel Sectors', 'name': 'US Treasury', 'reputation': 5, 'url': 'https://www.treasury.gov/press-center/press-releases/Pages/jl2629.aspx'}, {'datetime': '2009-01-01T05:00:00.000Z', 'description': 'Map_of_the_Arctic_region_showing_the_Northeast_Passage,_the_Northern_Sea_Route_and_Northwest_Passage,_and_bathymetry', 'name': 'Arctic Council', 'reputation': 5, 'url': 'https://commons.wikimedia.org/wiki/File:Map_of_the_Arctic_region_showing_the_Northeast_Passage,_the_Northern_Sea_Route_and_Northwest_Passage,_and_bathymetry.png'}, {'datetime': '2021-02-23T05:00:00.000Z', 'description': 'Q4 2020 Doxxing Victim Trends: Industrial Sector Emerges as Primary Ransom “Non-Payor”', 'name': 'Coveware', 'reputation': 4, 'url': 'https://www.coveware.com/blog/2021/2/18/q4-doxxing-victim-trends-industrial-sector-emerges-as-primary-ransom-non-payor'}, {'datetime': '2019-01-18T05:00:00.000Z', 'description': "Who Are Russia's Main Allies? hxxps://www.rbth[.]com/lifestyle/329861-who-are-russia-allies", 'name': 'Russia Behind the Headlines', 'reputation': 3}, {'datetime': '2021-02-23T05:00:00.000Z', 'description': "Detailed plans of military spy plane are leaked on the dark web by hackers after Canadian manufacturer Bombardier 'refused to pay ransom'", 'name': 'Daily Mail', 'reputation': 4, 'url': 'https://www.dailymail.co.uk/news/article-9293153/Bombardier-latest-company-hacked-group-using-ransomware-called-Clop.html'}, {'datetime': '2020-12-16T05:00:00.000Z', 'description': 'How Russia Wins the Climate Crisis', 'name': 'New York Times', 'reputation': 4, 'url': 'https://www.nytimes.com/interactive/2020/12/16/magazine/russia-climate-migration-crisis.html'}, {'datetime': '2020-12-07T05:00:00.000Z', 'description': 'Russia Strives for an Oil and Gas Resurgence', 'name': 'Jamestown', 'reputation': 4, 'url': 'https://jamestown.org/program/russia-strives-for-an-oil-and-gas-resurgence/'}, {'datetime': '2021-03-19T04:00:00.000Z', 'description': 'Berlin Assassination: New Evidence on Suspected FSB Hitman Passed to German Investigators', 'name': 'Bellingcat', 'reputation': 4, 'url': 'https://www.bellingcat.com/news/2021/03/19/berlin-assassination-new-evidence-on-suspected-fsb-hitman-passed-to-german-investigators/'}, {'datetime': '2020-03-27T04:00:00.000Z', 'description': 'Russia’s Chinese Dream in the Era of COVID-19', 'name': 'Wilson Center', 'reputation': 4, 'url': 'https://www.wilsoncenter.org/blog-post/russias-chinese-dream-era-covid-19'}, {'datetime': '2019-06-20T04:00:00.000Z', 'description': 'Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments', 'name': 'Symantec', 'reputation': 4, 'url': 'https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments'}, {'datetime': '2021-01-12T05:00:00.000Z', 'description': 'What drives crude oil prices?', 'name': 'US Energy Information Administration', 'reputation': 5, 'url': 'https://www.eia.gov/finance/markets/crudeoil/reports_presentations/crude.pdf'}, {'datetime': '2018-04-20T04:00:00.000Z', 'description': 'US-CERT/CISA Alert (TA18-106A): Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices', 'name': 'US Cybersecurity and Infrastructure Security Agency', 'reputation': 5, 'url': 'https://us-cert.cisa.gov/ncas/alerts/TA18-106A'}, {'datetime': '2020-12-17T05:00:00.000Z', 'description': 'Russia: The EU prolongs economic sanctions for another six months', 'name': 'European Union', 'reputation': 5, 'url': 'https://www.consilium.europa.eu/en/press/press-releases/2020/12/17/russia-the-eu-prolongs-economic-sanctions-for-another-six-months'}, {'datetime': '2021-01-15T05:00:00.000Z', 'description': "Interview: Media Lawyer Says Russia's New Laws 'Are Burying Civil Society", 'name': 'Radio Free Europe/Radio Liberty', 'reputation': 4, 'url': 'https://www.rferl.org/a/russia-foreign-agents-law-interview-media-lawyer-civil-societ-rfe/31048094.html'}, {'datetime': '2021-02-04T05:00:00.000Z', 'description': 'Dissatisfaction With Putin Surges Among Young Russians – Levada Poll', 'name': 'Moscow Times', 'reputation': 4, 'url': 'https://www.themoscowtimes.com/2021/02/04/dissatisfaction-with-putin-surges-among-young-russians-levada-poll-a72835'}, {'datetime': '2021-02-06T05:00:00.000Z', 'description': "Rising Poverty and Falling Incomes Fuel Russia's Navalny", 'name': 'Financial Times', 'reputation': 4, 'url': 'https://amp.ft.com/content/24b45679-ed22-4df7-89ab-f3d5fad71c95'}, {'datetime': '2020-03-12T04:00:00.000Z', 'description': 'Tracking Turla: New backdoor delivered via Armenian watering holes', 'name': 'ESET', 'reputation': 4, 'url': 'https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/'}, {'datetime': '2018-03-16T04:00:00.000Z', 'description': 'Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors', 'name': 'US Cybersecurity and Infrastructure Security Agency', 'reputation': 5, 'url': 'https://us-cert.cisa.gov/ncas/alerts/TA18-074A'}, {'datetime': '2020-10-23T04:00:00.000Z', 'description': 'Treasury Sanctions Russian Government Research Institution Connected to the Triton Malware', 'name': 'US Treasury Department', 'reputation': 5, 'url': 'https://home.treasury.gov/news/press-releases/sm1162'}, {'datetime': '2021-03-30T04:00:00.000Z', 'description': 'В Минобороны рассказали, как победить США в "ментальной войне"  hxxps://ria[.]ru/20210330/ssha-1603481759.html', 'name': 'RIA'}, {'datetime': '2019-10-23T04:00:00.000Z', 'description': 'Past and future of integrity based attacks in ics environments', 'name': 'Dragos', 'reputation': 4, 'url': 'https://www.slideshare.net/JoeSlowik/past-and-future-of-integrity-based-attacks-in-ics-environments'}, {'datetime': '2021-03-17T04:00:00.000Z', 'description': 'Biden: Putin will ‘pay a price’ for interfering in 2020 election', 'name': 'Politico', 'reputation': 4, 'url': 'https://www.politico.com/news/2021/03/17/biden-putin-election-interference-476656'}, {'datetime': '2021-01-14T05:00:00.000Z', 'description': 'Who Is Responsible for Mitigating the Effects of Climate Change in Russia?', 'name': 'Center for Strategic and International Studies', 'reputation': 4, 'url': 'https://www.csis.org/analysis/who-responsible-mitigating-effects-climate-change-Russia'}, {'datetime': '2019-10-21T04:00:00.000Z', 'description': 'Joint Advisory: Turla group exploits Iranian APT to expand coverage of victims', 'name': 'UK National Cyber Security Centre (NCSC) and US National Security Agency', 'reputation': 5, 'url': 'https://www.ncsc.gov.uk/news/turla-group-exploits-iran-apt-to-expand-coverage-of-victims'}, {'datetime': '2019-10-21T04:00:00.000Z', 'description': 'Hacking the hackers: Russian group hijacked Iranian spying operation, officials say', 'name': 'Reuters', 'reputation': 4, 'url': 'https://www.reuters.com/article/us-russia-cyber/hacking-the-hackers-russian-group-hijacked-iranian-spying-operation-officials-say-idUSKBN1X00AK'}, {'datetime': '2021-02-15T05:00:00.000Z', 'description': 'Russia Blackmails and Courts Europe', 'name': 'Jamestown', 'reputation': 4, 'url': 'https://jamestown.org/program/russia-blackmails-and-courts-europe/'}, {'datetime': '2021-02-07T05:00:00.000Z', 'description': 'Vladimir Putin’s Russia is destabilising itself from within', 'name': 'Tatyana Stanovaya for the Financial Times', 'reputation': 4, 'url': 'https://www.ft.com/content/94aeb690-ec2d-472d-adf7-212930c2d394'}, {'datetime': '2015-04-16T04:00:00.000Z', 'description': "Putin agrees with emperor that Russia's only allies are Army and Navy hxxps://tass[.]com/Russia/789866", 'name': 'TASS', 'reputation': 3}, {'datetime': '2020-12-14T05:00:00.000Z', 'description': 'Deepening Leadership Confusion Exacerbates Russia’s Multiple Crises', 'name': 'Jamestown', 'reputation': 4, 'url': 'https://jamestown.org/program/deepening-leadership-confusion-exacerbates-russias-multiple-crises/'}, {'datetime': '2020-11-12T05:00:00.000Z', 'description': 'Overview of United States sanctions on Russian persons (individuals, entities, and vessels).', 'name': 'US Commerce Department', 'reputation': 5, 'url': 'https://www.trade.gov/country-commercial-guides/russia-sanctions'}, {'datetime': '2020-10-19T04:00:00.000Z', 'description': 'Six Russian GRU Officers Charged in Connection with Worldwide Deployment of Destructive Malware and Other Disruptive Actions in Cyberspace', 'name': 'US Department of Justice', 'reputation': 5, 'url': 'https://www.justice.gov/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and'}, {'datetime': '2019-10-21T04:00:00.000Z', 'name': 'UK National Cyber Security Centre (NCSC)', 'reputation': 5, 'url': 'https://www.ncsc.gov.uk/news/turla-group-behind-cyber-attack'}, {'datetime': '2020-02-20T05:00:00.000Z', 'description': "UK condemns Russia's GRU over Georgia cyber-attacks", 'name': 'UK Government', 'reputation': 5, 'url': 'https://www.gov.uk/government/news/uk-condemns-russias-gru-over-georgia-cyber-attacks'}, {'datetime': '2018-04-05T04:00:00.000Z', 'description': 'Satellite images show huge Russian military buildup in the Arctic', 'name': 'CNN', 'reputation': 4, 'url': 'https://www.cnn.com/2021/04/05/europe/russia-arctic-nato-military-intl-cmd/index.html'}, {'datetime': '2020-12-03T05:00:00.000Z', 'description': 'Russian, Chinese intelligence targeting Norwegian oil secrets: report', 'name': 'Reuters', 'reputation': 4, 'url': 'https://www.reuters.com/article/us-norway-oil-security/russian-chinese-intelligence-targeting-norwegian-oil-secrets-report-idUSKBN28D2M7'}], 'conclusion': "To protect against state-sponsored or state-directed cyberthreat activity, iDefense suggests that organizations consider: \n\n * Assessing the threat landscape of critical infrastructure and high-value organizations \nto determine the likelihood of nation-state actors targeting them to steal intellectual property or fulfill strategic requirements.\n\n * Understanding the strategic priorities of China, Iran, North Korea, and Russia to identify high-value data targets and at-risk technologies, information, and business operations.\n\n * Strengthening the organization's cyber defenses through network defense operations, network architecture and design, third-party relationships, software and hardware procurement, user training and security culture building, travel and communication policies, employee vetting and insider threat mitigation, and security partnerships including information-sharing communities, government partners, and contracted security and threat intelligence services.\n\n * Evaluating the organization's key mission and business drivers that align to adversarial states’ priorities.\n\n * Reviewing and updating the organization's knowledge of sanctions lists to ensure critical and high-value organizations only interact and engage with approved and relevant individuals and entities.\n\n * Implementing a proactive cybersecurity strategy and legal framework that defines and addresses changing roles and responsibilities for all parties involved in any security incident.\n\n * Implementing the latest patches for Internet-facing servers, systems, databases, and applications.\n\n * Conducting due diligence on third-party contractors.\n\n * Using multi-factor authentication for corporate network access where possible.\n\nTo counter Russian and other cyber-threats, organizations can focus on specific user-level and system-level defense actions and strategies. This can include educating employees to:\n\n- Resist clickbait \n- Resist over-sharing information online and in emails\n- Doubt questionable links or attachments\n- Check for spoofed URLs and email sender addresses (posing as officials, suppliers, or job seekers)\n\nOrganizations may also consider policies to:\n- Disallow emails with embedded macros \n- Audit network and processes for anomalies\n- Practice red/purple teaming\n- Use IP and port allow- and block-listing  \n- Back up data offsite\n- Disable SMBv1 and RDP if possible", 'summary': "The oil and gas sector is central to Russia's revenue stream as well as the Russian government's economic relationships with the rest of the world. President Vladimir Putin’s government has pursued multiple strategies, including cyber-threat activity, in response to the global and domestic challenges Russia faces in a changing world. Russian-state espionage and disinformation operations as well as disruptive or destructive activity that can occur under the guise of criminal activity or hacktivism have historically targeted organizations in the energy industry and will likely continue to do so."}]

}


MALWARE_FAMILY_RES_JSON = {
    "created_on": "2021-08-27T15:54:07.000Z",
    "display_text": "Hive",
    "dynamic_properties": {},
    "index_timestamp": "2022-04-05T15:00:05.654Z",
    "key": "Hive",
    "last_modified": "2022-04-04T15:52:25.000Z",
    "last_published": "2022-03-20T19:46:58.000Z",
    "links": [
        {
            "created_on": "2022-04-05T14:59:19.000Z",
            "display_text": "Hive Ransomware Group Compromises Railway Transportation Company Rete Ferroviaria Italiana",
            "key": "0193037c-fda0-43fb-9847-c8c64560090d",
            "relationship": "uses",
            "relationship_created_on": "2022-04-05T14:59:19.000Z",
            "relationship_last_published": "2022-04-05T14:59:19.000Z",
            "type": "malicious_event",
            "uuid": "f21741c7-6200-4490-a2bd-c443a50bd3bd",
            "href": "/rest/fundamental/v0/f21741c7-6200-4490-a2bd-c443a50bd3bd"
        },
        {
            "created_on": "2022-03-03T09:05:16.000Z",
            "display_text": "fce6a04dfa8a955fbe626c3f04491444",
            "key": "fce6a04dfa8a955fbe626c3f04491444",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:05:16.000Z",
            "relationship_last_published": "2022-03-03T09:05:16.000Z",
            "type": "file",
            "uuid": "fafd3e32-d75e-4f28-b43e-3627ea406165",
            "href": "/rest/fundamental/v0/fafd3e32-d75e-4f28-b43e-3627ea406165"
        },
        {
            "created_on": "2022-03-03T09:01:17.000Z",
            "display_text": "514b741214951b9d39d66688839a223d",
            "key": "514b741214951b9d39d66688839a223d",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T13:02:00.000Z",
            "relationship_last_published": "2022-03-03T13:02:00.000Z",
            "type": "file",
            "uuid": "e663897a-7ed9-45e2-a9ce-e5ce9380affb",
            "href": "/rest/fundamental/v0/e663897a-7ed9-45e2-a9ce-e5ce9380affb"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "2c358fdf4c85c4352e1d297727b957f0",
            "key": "2c358fdf4c85c4352e1d297727b957f0",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-01T01:08:10.000Z",
            "relationship_last_published": "2022-02-01T01:08:10.000Z",
            "type": "file",
            "uuid": "d569fe23-409d-4c36-b6ec-bca16eb1aefd",
            "href": "/rest/fundamental/v0/d569fe23-409d-4c36-b6ec-bca16eb1aefd"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "095715a96975ef7b9e17d0a39739e0cc",
            "key": "095715a96975ef7b9e17d0a39739e0cc",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-09T03:07:06.000Z",
            "relationship_last_published": "2022-02-09T03:07:06.000Z",
            "type": "file",
            "uuid": "5af5afb1-b893-44f8-b756-a4a8c6149948",
            "href": "/rest/fundamental/v0/5af5afb1-b893-44f8-b756-a4a8c6149948"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "8e26cf1b3222ea0059aeb2aed6115fc5",
            "key": "8e26cf1b3222ea0059aeb2aed6115fc5",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T21:04:44.000Z",
            "relationship_last_published": "2022-03-03T21:04:44.000Z",
            "type": "file",
            "uuid": "1608025e-11a6-4589-86f2-8e1a6b8d3b11",
            "href": "/rest/fundamental/v0/1608025e-11a6-4589-86f2-8e1a6b8d3b11"
        },
        {
            "created_on": "2021-12-06T23:07:05.000Z",
            "display_text": "Cyber Threats to Nonprofit Organizations",
            "key": "81fd35e0-8b99-43ef-a1f8-45cb7bfadb49",
            "relationship": "mentions",
            "relationship_created_on": "2021-12-06T23:07:05.000Z",
            "relationship_last_published": "2021-12-06T23:08:22.000Z",
            "type": "intelligence_report",
            "uuid": "a8676cc1-5386-4492-b39e-b4064e42193d",
            "href": "/rest/document/v0/a8676cc1-5386-4492-b39e-b4064e42193d"
        },
        {
            "created_on": "2022-03-03T09:06:22.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/10795314.exe",
            "key": "http://193.233.48.64:20001/bot/cache/10795314.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:06:22.000Z",
            "relationship_last_published": "2022-03-03T09:06:22.000Z",
            "type": "url",
            "uuid": "81cfeb63-525e-462d-942d-9f1cc32dada9",
            "href": "/rest/fundamental/v0/81cfeb63-525e-462d-942d-9f1cc32dada9"
        },
        {
            "created_on": "2022-03-03T09:05:31.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/36712604.exe",
            "key": "http://193.233.48.64:20001/bot/cache/36712604.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:31.000Z",
            "relationship_last_published": "2022-03-03T09:05:31.000Z",
            "type": "url",
            "uuid": "43a9beac-9a6a-42dd-9385-86ed5f1c735b",
            "href": "/rest/fundamental/v0/43a9beac-9a6a-42dd-9385-86ed5f1c735b"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "http://85.202.169.245/build.exe",
            "key": "http://85.202.169.245/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-28T21:00:56.000Z",
            "relationship_last_published": "2022-01-28T21:00:56.000Z",
            "type": "url",
            "uuid": "06bb16a3-7de6-43b3-a025-27bfbdfb3737",
            "href": "/rest/fundamental/v0/06bb16a3-7de6-43b3-a025-27bfbdfb3737"
        },
        {
            "created_on": "2022-01-12T16:27:02.000Z",
            "display_text": "Makop and Hive Ransomware Downloaded from GitHub Repository",
            "key": "2403d723-9875-479c-b8a5-ff1181284588",
            "relationship": "uses",
            "relationship_created_on": "2022-01-12T16:27:02.000Z",
            "relationship_last_published": "2022-01-12T16:27:02.000Z",
            "type": "malicious_event",
            "uuid": "f5fab130-70d6-4f3e-8ae2-dada98626b51",
            "href": "/rest/fundamental/v0/f5fab130-70d6-4f3e-8ae2-dada98626b51"
        },
        {
            "created_on": "2021-08-25T17:38:11.000Z",
            "display_text": "504bd1695de326bc533fde29b8a69319",
            "key": "504bd1695de326bc533fde29b8a69319",
            "relationship": "belongsTo",
            "relationship_created_on": "2021-09-29T19:19:09.000Z",
            "relationship_last_published": "2021-09-29T19:19:09.000Z",
            "type": "file",
            "uuid": "a7bc5402-1d74-42b1-b6e1-6e43f52bfcc3",
            "href": "/rest/fundamental/v0/a7bc5402-1d74-42b1-b6e1-6e43f52bfcc3"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "de56cde528237db0bafb21e16e5d2660",
            "key": "de56cde528237db0bafb21e16e5d2660",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:02:54.000Z",
            "relationship_last_published": "2022-01-26T18:02:54.000Z",
            "type": "file",
            "uuid": "9f3b8b8f-b776-4cd2-9ba7-887aaf186a6d",
            "href": "/rest/fundamental/v0/9f3b8b8f-b776-4cd2-9ba7-887aaf186a6d"
        },
        {
            "created_on": "2022-03-21T17:01:13.000Z",
            "display_text": "http://file-coin-coin-10.com/files/3146_1647797189_9799.exe",
            "key": "http://file-coin-coin-10.com/files/3146_1647797189_9799.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-21T17:01:13.000Z",
            "relationship_last_published": "2022-03-21T17:01:13.000Z",
            "type": "url",
            "uuid": "ee9e9f7c-a599-4009-96f8-d5ac5beabe55",
            "href": "/rest/fundamental/v0/ee9e9f7c-a599-4009-96f8-d5ac5beabe55"
        },
        {
            "created_on": "2022-03-03T09:06:00.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/32311396.exe",
            "key": "http://193.233.48.64:20001/bot/cache/32311396.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:06:00.000Z",
            "relationship_last_published": "2022-03-03T09:06:00.000Z",
            "type": "url",
            "uuid": "ad48f931-e83f-4312-ad38-5b51744b14e8",
            "href": "/rest/fundamental/v0/ad48f931-e83f-4312-ad38-5b51744b14e8"
        },
        {
            "created_on": "2022-03-03T09:05:12.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/68950155.exe",
            "key": "http://193.233.48.64:20001/bot/cache/68950155.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:12.000Z",
            "relationship_last_published": "2022-03-03T09:05:12.000Z",
            "type": "url",
            "uuid": "97551dc6-e59a-450b-899c-b2d1e11c4dd8",
            "href": "/rest/fundamental/v0/97551dc6-e59a-450b-899c-b2d1e11c4dd8"
        },
        {
            "created_on": "2022-01-30T11:30:44.000Z",
            "display_text": "http://62.197.136.229/build.exe",
            "key": "http://62.197.136.229/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T21:04:44.000Z",
            "relationship_last_published": "2022-03-03T21:04:44.000Z",
            "type": "url",
            "uuid": "8195b155-dd97-4ba4-82ea-897fc9f0e75a",
            "href": "/rest/fundamental/v0/8195b155-dd97-4ba4-82ea-897fc9f0e75a"
        },
        {
            "created_on": "2022-03-03T09:00:56.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/33132493.exe",
            "key": "http://193.233.48.64:20001/bot/cache/33132493.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:00:56.000Z",
            "relationship_last_published": "2022-03-03T09:00:56.000Z",
            "type": "url",
            "uuid": "3a597bdb-5848-4585-9a5e-58453fab2eba",
            "href": "/rest/fundamental/v0/3a597bdb-5848-4585-9a5e-58453fab2eba"
        },
        {
            "created_on": "2022-02-11T03:01:52.000Z",
            "display_text": "http://82.157.108.230:8000/%E4%B8%AA%E4%BA%BA%E7%AE%80%E5%8E%86.pdf%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20.exe",
            "key": "http://82.157.108.230:8000/%E4%B8%AA%E4%BA%BA%E7%AE%80%E5%8E%86.pdf%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-02-11T03:01:52.000Z",
            "relationship_last_published": "2022-02-11T03:01:52.000Z",
            "type": "url",
            "uuid": "0e9a21fd-bce5-48c2-8506-d06e1b497c0b",
            "href": "/rest/fundamental/v0/0e9a21fd-bce5-48c2-8506-d06e1b497c0b"
        },
        {
            "created_on": "2022-03-21T17:01:13.000Z",
            "display_text": "92d0366537308d4b6e0ca530f49adb6d",
            "key": "92d0366537308d4b6e0ca530f49adb6d",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-21T17:01:13.000Z",
            "relationship_last_published": "2022-03-21T17:01:13.000Z",
            "type": "file",
            "uuid": "e1cf3272-6d75-418e-8168-870b8d4367dc",
            "href": "/rest/fundamental/v0/e1cf3272-6d75-418e-8168-870b8d4367dc"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "3e6c6230b55a1cce968197736af2a89b",
            "key": "3e6c6230b55a1cce968197736af2a89b",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-09T09:11:23.000Z",
            "relationship_last_published": "2022-02-09T09:11:23.000Z",
            "type": "file",
            "uuid": "cb95d9f6-1dce-4cc0-9baa-925879fb83f6",
            "href": "/rest/fundamental/v0/cb95d9f6-1dce-4cc0-9baa-925879fb83f6"
        },
        {
            "created_on": "2022-03-03T09:06:00.000Z",
            "display_text": "689d783fdaeeff17f2c3a9471ad716d7",
            "key": "689d783fdaeeff17f2c3a9471ad716d7",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:06:00.000Z",
            "relationship_last_published": "2022-03-03T09:06:00.000Z",
            "type": "file",
            "uuid": "95c555b5-4ac1-4f9a-a0c4-57fd12adc62e",
            "href": "/rest/fundamental/v0/95c555b5-4ac1-4f9a-a0c4-57fd12adc62e"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "e804bf3e7b1395a2a3d348d5e4b0d1f4",
            "key": "e804bf3e7b1395a2a3d348d5e4b0d1f4",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-16T15:04:03.000Z",
            "relationship_last_published": "2022-02-16T15:04:03.000Z",
            "type": "file",
            "uuid": "7a2caf7a-1349-4345-b0d7-1a6ef276757b",
            "href": "/rest/fundamental/v0/7a2caf7a-1349-4345-b0d7-1a6ef276757b"
        },
        {
            "created_on": "2022-03-03T09:05:57.000Z",
            "display_text": "7d4220c9e78fdf518621c113a8649176",
            "key": "7d4220c9e78fdf518621c113a8649176",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:05:57.000Z",
            "relationship_last_published": "2022-03-03T09:05:57.000Z",
            "type": "file",
            "uuid": "25bea5dd-fc28-4b27-ac88-8bd2091310de",
            "href": "/rest/fundamental/v0/25bea5dd-fc28-4b27-ac88-8bd2091310de"
        },
        {
            "created_on": "2022-02-11T03:01:52.000Z",
            "display_text": "79b5eb5b92a2245b42d82a2c106ecf30",
            "key": "79b5eb5b92a2245b42d82a2c106ecf30",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-11T03:01:52.000Z",
            "relationship_last_published": "2022-02-11T03:01:52.000Z",
            "type": "file",
            "uuid": "114705ce-be03-4498-861d-c72ec73f797c",
            "href": "/rest/fundamental/v0/114705ce-be03-4498-861d-c72ec73f797c"
        },
        {
            "created_on": "2021-11-05T18:18:10.000Z",
            "display_text": "Technical Analysis of Hive Ransomware",
            "key": "5684299e-5bdc-4af5-b829-da7a8c95e7f7",
            "relationship": "mentions",
            "relationship_created_on": "2021-11-05T18:18:10.000Z",
            "relationship_last_published": "2021-11-05T18:18:10.000Z",
            "type": "intelligence_alert",
            "uuid": "995e4c09-dd66-420c-8e35-b1edb022e7ee",
            "href": "/rest/document/v0/995e4c09-dd66-420c-8e35-b1edb022e7ee"
        },
        {
            "created_on": "2021-10-13T16:08:00.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 13 October 2021",
            "key": "cabde77f-68ff-45fc-9e84-3f624d8038e5",
            "relationship": "mentions",
            "relationship_created_on": "2021-10-13T16:08:00.000Z",
            "relationship_last_published": "2021-10-13T16:08:00.000Z",
            "type": "intelligence_alert",
            "uuid": "54745848-9166-4387-9fc3-137b3e07022e",
            "href": "/rest/document/v0/54745848-9166-4387-9fc3-137b3e07022e"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "http://185.112.83.96:20001/build_dl",
            "key": "http://185.112.83.96:20001/build_dl",
            "relationship": "seenAt",
            "relationship_created_on": "2022-02-09T03:07:06.000Z",
            "relationship_last_published": "2022-02-09T03:07:06.000Z",
            "type": "url",
            "uuid": "f688be80-466b-4f9e-8914-747b1da441aa",
            "href": "/rest/fundamental/v0/f688be80-466b-4f9e-8914-747b1da441aa"
        },
        {
            "created_on": "2022-03-03T09:05:57.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/49495799.exe",
            "key": "http://193.233.48.64:20001/bot/cache/49495799.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:57.000Z",
            "relationship_last_published": "2022-03-03T09:05:57.000Z",
            "type": "url",
            "uuid": "d9264aff-df75-4d33-8c4b-cef938a4a683",
            "href": "/rest/fundamental/v0/d9264aff-df75-4d33-8c4b-cef938a4a683"
        },
        {
            "created_on": "2022-01-25T03:00:15.000Z",
            "display_text": "http://5.255.100.227/myblog/posts/32.exe",
            "key": "http://5.255.100.227/myblog/posts/32.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-25T03:00:15.000Z",
            "relationship_last_published": "2022-01-25T03:00:15.000Z",
            "type": "url",
            "uuid": "8ec32443-d904-4f4c-b3e3-da6c8538b5be",
            "href": "/rest/fundamental/v0/8ec32443-d904-4f4c-b3e3-da6c8538b5be"
        },
        {
            "created_on": "2022-03-21T18:13:26.000Z",
            "display_text": "http://file-coin-coin-10.com/files/7060_1647109264_3109.exe",
            "key": "http://file-coin-coin-10.com/files/7060_1647109264_3109.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-21T18:13:26.000Z",
            "relationship_last_published": "2022-03-21T18:13:26.000Z",
            "type": "url",
            "uuid": "22a9b797-d2ad-40e5-a4d1-f7db7b693183",
            "href": "/rest/fundamental/v0/22a9b797-d2ad-40e5-a4d1-f7db7b693183"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Healthcare Providers",
            "key": "Healthcare Providers",
            "relationship": "targets",
            "relationship_created_on": "2021-08-27T15:54:07.000Z",
            "relationship_last_published": "2021-08-27T15:54:07.000Z",
            "type": "vertical",
            "uuid": "baa08cb8-89cd-45a3-a302-4a307edc5708",
            "href": "/rest/fundamental/v0/baa08cb8-89cd-45a3-a302-4a307edc5708"
        },
        {
            "created_on": "2022-03-03T09:05:12.000Z",
            "display_text": "56069652e0a95bb25da5cad6ac8e070e",
            "key": "56069652e0a95bb25da5cad6ac8e070e",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:06:22.000Z",
            "relationship_last_published": "2022-03-03T09:06:22.000Z",
            "type": "file",
            "uuid": "d663d2f5-bde5-4685-9d87-0e27c2eb8acd",
            "href": "/rest/fundamental/v0/d663d2f5-bde5-4685-9d87-0e27c2eb8acd"
        },
        {
            "created_on": "2022-01-03T16:38:23.000Z",
            "display_text": "032760a6afd808e9eaf2979b72bcebf4",
            "key": "032760a6afd808e9eaf2979b72bcebf4",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-10T13:38:32.000Z",
            "relationship_last_published": "2022-01-10T15:43:03.000Z",
            "type": "file",
            "uuid": "c279fa1d-712d-46ae-965b-0d5f653a121b",
            "href": "/rest/fundamental/v0/c279fa1d-712d-46ae-965b-0d5f653a121b"
        },
        {
            "created_on": "2021-08-30T16:01:06.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 30 August 2021",
            "key": "c036ec6d-12a5-4672-9173-3c424d473781",
            "relationship": "mentions",
            "relationship_created_on": "2021-08-30T16:01:06.000Z",
            "relationship_last_published": "2021-08-30T16:01:05.000Z",
            "type": "intelligence_alert",
            "uuid": "94af0110-5706-4bc2-aca1-92a2f78c801d",
            "href": "/rest/document/v0/94af0110-5706-4bc2-aca1-92a2f78c801d"
        },
        {
            "created_on": "2022-03-03T09:01:17.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/22092005.exe",
            "key": "http://193.233.48.64:20001/bot/cache/22092005.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:01:17.000Z",
            "relationship_last_published": "2022-03-03T09:01:17.000Z",
            "type": "url",
            "uuid": "f95eb4f0-7ca1-42bb-9bd3-9309f976fb6c",
            "href": "/rest/fundamental/v0/f95eb4f0-7ca1-42bb-9bd3-9309f976fb6c"
        },
        {
            "created_on": "2022-03-03T13:02:00.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/99608309.exe",
            "key": "http://193.233.48.64:20001/bot/cache/99608309.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T13:02:00.000Z",
            "relationship_last_published": "2022-03-03T13:02:00.000Z",
            "type": "url",
            "uuid": "036e0339-c616-4bed-bcab-979e130dbf07",
            "href": "/rest/fundamental/v0/036e0339-c616-4bed-bcab-979e130dbf07"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "addfdc6395f84f4a377423f212e1fa27",
            "key": "addfdc6395f84f4a377423f212e1fa27",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:17:38.000Z",
            "relationship_last_published": "2022-01-26T18:17:38.000Z",
            "type": "file",
            "uuid": "c6a0aa62-7773-46d5-8a5c-82d745c8c5d6",
            "href": "/rest/fundamental/v0/c6a0aa62-7773-46d5-8a5c-82d745c8c5d6"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "78d6b9e2eba0867155d9f3489e4554bc",
            "key": "78d6b9e2eba0867155d9f3489e4554bc",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:17:38.000Z",
            "relationship_last_published": "2022-01-26T18:17:38.000Z",
            "type": "file",
            "uuid": "5cc0fac4-639b-4423-9b0e-af38eec6b434",
            "href": "/rest/fundamental/v0/5cc0fac4-639b-4423-9b0e-af38eec6b434"
        },
        {
            "created_on": "2022-03-21T18:13:26.000Z",
            "display_text": "0df23d0344989230bd0333c37ca598fd",
            "key": "0df23d0344989230bd0333c37ca598fd",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-21T18:13:26.000Z",
            "relationship_last_published": "2022-03-21T18:13:26.000Z",
            "type": "file",
            "uuid": "0c562fff-70bf-4e23-a54c-5f9db177b21c",
            "href": "/rest/fundamental/v0/0c562fff-70bf-4e23-a54c-5f9db177b21c"
        },
        {
            "created_on": "2022-02-22T21:33:12.000Z",
            "display_text": "SITREP: Ukraine Crisis",
            "key": "0ae44727-6fef-4dcb-9928-8eed0c3bcd3e",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-20T19:46:59.000Z",
            "relationship_last_published": "2022-03-20T19:46:58.000Z",
            "type": "intelligence_alert",
            "uuid": "f1862833-80de-4880-a180-11fad373e896",
            "href": "/rest/document/v0/f1862833-80de-4880-a180-11fad373e896"
        },
        {
            "created_on": "2021-08-25T15:38:48.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 25 August 2021",
            "key": "429ca269-8d25-46a3-8b83-5b666a2e7182",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-20T21:40:13.000Z",
            "relationship_last_published": "2022-03-20T21:40:13.000Z",
            "type": "intelligence_alert",
            "uuid": "4b3c7699-ff95-4650-9f24-6dee2be84112",
            "href": "/rest/document/v0/4b3c7699-ff95-4650-9f24-6dee2be84112"
        },
        {
            "created_on": "2022-01-16T15:01:07.000Z",
            "display_text": "http://91.243.59.17/build.exe",
            "key": "http://91.243.59.17/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-16T15:01:07.000Z",
            "relationship_last_published": "2022-01-16T15:01:07.000Z",
            "type": "url",
            "uuid": "85962156-eeba-43d3-8cc5-ee4f0cd2007a",
            "href": "/rest/fundamental/v0/85962156-eeba-43d3-8cc5-ee4f0cd2007a"
        },
        {
            "created_on": "2022-01-10T13:38:32.000Z",
            "display_text": "https://raw.githubusercontent.com/flicker32/tyupo/main/release.txt",
            "key": "https://raw.githubusercontent.com/flicker32/tyupo/main/release.txt",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-10T13:38:32.000Z",
            "relationship_last_published": "2022-01-10T13:38:32.000Z",
            "type": "url",
            "uuid": "45acec3a-faf6-4c25-8c55-4fbe2859b447",
            "href": "/rest/fundamental/v0/45acec3a-faf6-4c25-8c55-4fbe2859b447"
        },
        {
            "created_on": "2022-03-03T09:05:16.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/42663002.exe",
            "key": "http://193.233.48.64:20001/bot/cache/42663002.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:16.000Z",
            "relationship_last_published": "2022-03-03T09:05:16.000Z",
            "type": "url",
            "uuid": "058afbb7-57be-4378-8d49-e36fb60361bc",
            "href": "/rest/fundamental/v0/058afbb7-57be-4378-8d49-e36fb60361bc"
        }
    ],
    "replication_id": 1649087545647000061,
    "sources_external": [
        {
            "datetime": "2021-08-23T04:00:00.000Z",
            "description": "Hive Attacks | Analysis of the Human-Operated Ransomware Targeting Healthcare",
            "name": "SentinelOne",
            "url": "https://labs.sentinelone.com/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/"
        }
    ],
    "type": "malware_family",
    "uuid": "c1b3216e-8b2e-4a9f-b0a9-2e184b7182f7",
    "description": "##Overview\nThe Hive ransomware, written in the Go programming language, first came to the attention of researchers in June 2021. In August 2021, actors used the [Hive ransomware against a healthcare provider in Ohio]( https://labs.sentinelone.com/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/). Hive actors conduct double extortion tactics and maintain a leak site at hxxp://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd[.]onion/ and an instructions and  payment site at  hxxp://hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd[.]onion/, which requires login and password credentials.\n\n##Functionality and Behavior\nA preliminary iDefense analysis of the Hive ransomware revealed the following functionality:\n\n- Once Hive is deployed on the target machine, the operator can issue command-line parameters that perform functions listed in Exhibit 1.\n \n\n   \n *Exhibit 1: Command-Line Parameters*\n\n- When run without command-line parameters, Hive executes its default functionality as listed in Exhibit 2. Some of the functions include deleting itself, stopping default services shown in Exhibit 1, skipping files more than five years old, and deleting shadow copies.\n \n\n   \n *Exhibit 2: Default Execution*\n\n- During its default encryption activities in a test directory, Hive encrypted an executable file and encrypted PPT files but skipped an XLS file. When encrypting executables in an analysis sandbox, the sandbox environment became unstable. Exhibit 3 shows the encrypted and unencrypted files in the test directory. Hive added the file extension `.[key string][alphanumeric string].hive` to files it encrypted.\n \n   \n *Exhibit 3: Default Execution*\n\n- Hive drops its ransom note in directories it examined during encryption activities. Exhibit 4 shows the ransom note.\n  \n   \n *Exhibit 4: Ransom Note*\n\n##Mitigation\n\nTo protect against the Hive ransomware and possible data exfiltration, iDefense suggests:\n* Implementing the appropriate mitigations selected in the left-hand MITRE ATT&CK techniques tab.\n- Training users to identify and safely handle social engineering emails that could be part of a phishing campaign.\n\n- Avoiding opening or downloading suspicious links and attachments in emails from external sources until confirming with the sender using other means that the message and its contents are valid.\n- Securing networks from malware through best practices for patching, configuring firewalls, maintaining up-to-date anti-virus signatures, running regular scans, retaining backups separate from the network on which they reside, and using application whitelists.\n- Preparing and implementing a robust incident response plan in case a data breach or malware incident occurs.\n- Immediately disconnecting compromised systems from the network on which they reside.\n- Refraining from paying ransoms, as doing so provides an incentive to threat actors to continue making demands.\n- Consider developing continuity of operations plans  that account for massive ransomware or wiper attacks that can spread across the entire business.\n- For additional mitigation advice on how to protect against ransomware attacks, see iDefense’s Intelligence Alert titled [“Overview of Ransomware Activity.”](/#/node/intelligence_alert/view/5afaf6fc-30eb-4635-960b-e92df530787f)\n\nFor threat hunting against Hive samples, iDefense suggests looking for the following files:\n* Encrypted files with extension `.[key string][alphanumeric string].hive`\n* Ransom note “HOW\\_TO_DECRYPT.txt in various directories\n* Hive batch files hive.bat or shadow.bat\n* Key files [key string].key, [key string].key.hiv\n* temp[integer]_swamp.hive of unknown use",
    "severity": 3,
    "threat_types": [
        "Cyber Crime"
    ],
    "variety": [
        "Ransomware"
    ],
    "attack_techniques": [
        {
            "id": "T1489",
            "label": "Service Stop"
        },
        {
            "id": "T1007",
            "label": "System Service Discovery"
        },
        {
            "id": "T1192",
            "label": "Spearphishing Link"
        },
        {
            "id": "T1490",
            "label": "Inhibit System Recovery"
        },
        {
            "id": "T1486",
            "label": "Data Encrypted for Impact"
        },
        {
            "id": "T1045",
            "label": "Software Packing"
        },
        {
            "id": "T1059",
            "label": "Command-Line Interface"
        }
    ]
}


THREAT_GROUP_RES_JSON = {
    "created_on": "2022-03-25T15:30:26.000Z",
    "display_text": "Black Shadow",
    "dynamic_properties": {},
    "index_timestamp": "2022-03-30T10:42:13.076Z",
    "key": "Black Shadow",
    "last_modified": "2022-03-30T10:40:07.000Z",
    "last_published": "2022-03-25T15:30:26.000Z",
    "links": [
        {
            "created_on": "2015-08-20T15:32:06.000Z",
            "display_text": "Middle East",
            "key": "Middle East",
            "relationship": "hasLocation",
            "relationship_created_on": "2022-03-30T10:40:07.000Z",
            "relationship_last_published": "2022-03-30T10:40:07.000Z",
            "type": "region",
            "uuid": "fe11c08f-fc7c-49d9-a1c9-7a9fdf7f8b66",
            "href": "/rest/fundamental/v0/fe11c08f-fc7c-49d9-a1c9-7a9fdf7f8b66"
        },
        {
            "created_on": "2012-08-13T16:42:49.000Z",
            "display_text": "Iran",
            "key": "Iran",
            "relationship": "hasLocation",
            "relationship_created_on": "2022-03-30T10:40:07.000Z",
            "relationship_last_published": "2022-03-30T10:40:07.000Z",
            "type": "country",
            "uuid": "516a2391-b1b6-42e2-adce-ad3410cb15f8",
            "href": "/rest/fundamental/v0/516a2391-b1b6-42e2-adce-ad3410cb15f8"
        },
        {
            "created_on": "2022-03-21T11:38:36.000Z",
            "display_text": "Israel Cyber Authority Confirms DDoS Attack against Government Websites",
            "key": "fd686cb9-7ea3-4b6b-b516-cee98448cf56",
            "relationship": "attributedTo",
            "relationship_created_on": "2022-03-30T10:37:05.000Z",
            "relationship_last_published": "2022-03-30T10:37:05.000Z",
            "type": "malicious_event",
            "uuid": "99aa9cc5-c675-4b1b-ad3f-cb6a8b4e94bb",
            "href": "/rest/fundamental/v0/99aa9cc5-c675-4b1b-ad3f-cb6a8b4e94bb"
        },
        {
            "created_on": "2022-03-18T16:00:55.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 18 March 2022",
            "key": "0096c6c8-04c1-411e-bcc1-d3908f3d6c06",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-25T15:30:26.000Z",
            "relationship_last_published": "2022-03-25T15:30:26.000Z",
            "type": "intelligence_alert",
            "uuid": "36f007a0-8d30-475a-9e6b-dbc56cc2cc2f",
            "href": "/rest/document/v0/36f007a0-8d30-475a-9e6b-dbc56cc2cc2f"
        },
        {
            "created_on": "2021-11-02T17:10:52.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 2 November 2021",
            "key": "5b9095cd-7506-44ec-a53d-f495203a3014",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-25T15:30:26.000Z",
            "relationship_last_published": "2022-03-25T15:30:26.000Z",
            "type": "intelligence_alert",
            "uuid": "e308b55e-c482-4f8d-bcff-907d73b920f6",
            "href": "/rest/document/v0/e308b55e-c482-4f8d-bcff-907d73b920f6"
        },
        {
            "created_on": "2022-03-30T01:22:19.000Z",
            "display_text": "Israel Thwarts Cyber Targeting of Zelensky’s Plea for Aid to Israeli Parliament on 20 March 2022",
            "key": "c947807b-d8a7-4c57-8a01-c6ffac6a52f7",
            "relationship": "attributedTo",
            "relationship_created_on": "2022-03-30T10:38:33.000Z",
            "relationship_last_published": "2022-03-30T10:38:32.000Z",
            "type": "malicious_event",
            "uuid": "8111b03e-e557-4055-9d4c-9c30ee7f1929",
            "href": "/rest/fundamental/v0/8111b03e-e557-4055-9d4c-9c30ee7f1929"
        }
    ],
    "replication_id": 1648636807647000041,
    "sources_external": [
        {
            "datetime": "2021-11-06T22:00:00.000Z",
            "description": "Is Iran behind the Black Shadow attacks and does it matter?",
            "name": "Jerusalem Post",
            "reputation": 4,
            "url": "https://www.jpost.com/international/is-iran-behind-the-black-shadow-attacks-and-does-it-matter-684266"
        },
        {
            "datetime": "2021-10-30T21:00:00.000Z",
            "description": "Hackers threaten to out Israeli LGBTQ dating site users",
            "name": "France 24",
            "reputation": 4,
            "url": "https://www.france24.com/en/live-news/20211031-hackers-threaten-to-out-israeli-lgbtq-dating-site-users"
        },
        {
            "datetime": "2020-12-05T22:00:00.000Z",
            "description": "Shirbit hack serves as a wakeup call to every financial company",
            "name": "Calcalist",
            "reputation": 4,
            "url": "https://www.calcalistech.com/ctech/articles/0,7340,L-3879492,00.html"
        }
    ],
    "type": "threat_group",
    "uuid": "b7ee402d-9c02-4908-b2d1-487a1feaf468",
    "description": "##Overview\nFirst seen in December 2020, the Black Shadow threat group is affiliated with Iran, according to\npublic reporting. iDefense assesses with high confidence that the Black Shadow actors are  politically and financially motivated. Politically, the group  targets Israeli infrastructure and companies in various sectors. Their posts on Twitter and Telegram demonstrate anti-Israel themes. The group is also financially motivated based on its demands for ransom payments.\n\n##Key Details\n* **Associated Geography:** Iran\n* **Active Since:** First seen in December 2020\n* **Targeted Industries:** All sectors\n* **Targeted Geographies:** Israel",
    "analysis": "##Victimology\nThe Black Shadow threat group has mainly targeted Israeli organizations and infrastructure.\n\n####Notable Operations\nBlack Shadow is associated with the following incidents:\n* On 13 March 2022, the group announced it had broken into [the Israeli company Rubinstein Software (SMBS).](#/node/intelligence_alert/view/36f007a0-8d30-475a-9e6b-dbc56cc2cc2f)  \n* On 2 November 2021, the group allegedly leaked sensitive [health records of nearly 290,000 patients]( https://www.france24.com/en/live-news/20211031-hackers-threaten-to-out-israeli-lgbtq-dating-site-users) of an Israeli network of Machon Mor medical centers.\n* On 30 October 2021, the threat group [breached the servers of Israeli internet hosting organization CyberServe.](/#/node/intelligence_alert/view/e308b55e-c482-4f8d-bcff-907d73b920f6) \n\n* In March 2021, the threat group claimed it had hacked [Israeli car financing firm K.L.S. Capital](https://www.jpost.com/international/is-iran-behind-the-black-shadow-attacks-and-does-it-matter-684266) and stolen client data\n* On 1 December 2020, the group compromised and leaked the data of [Israeli insurance giant Shirbit.](https://www.calcalistech.com/ctech/articles/0,7340,L-3879492,00.html)",
    "first_seen": "2020-11-30T22:00:00.000Z",
    "motivations": [
        "Ideological",
        "Financial",
        "Disruption"
    ],
    "origin": "Iran",
    "severity": 3,
    "skill_lvl": "Moderate",
    "threat_types": [
        "Hacktivism",
        "Cyber Crime"
    ]
}


THREAT_ACTOR_RES_JSON = {
    "created_on": "2022-03-25T20:00:17.000Z",
    "display_text": "Swift",
    "dynamic_properties": {},
    "index_timestamp": "2022-03-25T20:04:04.943Z",
    "key": "Swift",
    "last_modified": "2022-03-25T20:00:17.000Z",
    "last_published": "2022-03-25T20:00:17.000Z",
    "links": [
        {
            "created_on": "2022-03-25T18:16:08.000Z",
            "display_text": "Swift (breached)",
            "key": "83a4c14d-a45b-4d31-b6bd-b12209bf6db1",
            "relationship": "owns",
            "relationship_created_on": "2022-03-25T20:00:17.000Z",
            "relationship_last_published": "2022-03-25T20:00:17.000Z",
            "type": "account",
            "uuid": "dc1ee94a-d795-4bf5-9604-02ccbd6ee280",
            "href": "/rest/fundamental/v0/dc1ee94a-d795-4bf5-9604-02ccbd6ee280"
        },
        {
            "created_on": "2004-03-09T00:00:00.000Z",
            "display_text": "United States of America",
            "key": "United States of America",
            "relationship": "targets",
            "relationship_created_on": "2022-03-25T20:00:17.000Z",
            "relationship_last_published": "2022-03-25T20:00:17.000Z",
            "type": "country",
            "uuid": "9cd78f1a-14d9-4670-9f1f-2619ad99837e",
            "href": "/rest/fundamental/v0/9cd78f1a-14d9-4670-9f1f-2619ad99837e"
        },
        {
            "created_on": "2018-12-04T19:10:06.000Z",
            "display_text": "Communications",
            "key": "Communications",
            "relationship": "targets",
            "relationship_created_on": "2022-03-25T20:00:17.000Z",
            "relationship_last_published": "2022-03-25T20:00:17.000Z",
            "type": "vertical",
            "uuid": "f9cf26a2-dc25-4f05-8010-97ecf857c069",
            "href": "/rest/fundamental/v0/f9cf26a2-dc25-4f05-8010-97ecf857c069"
        },
        {
            "created_on": "2018-12-04T19:10:04.000Z",
            "display_text": "Financial Service Providers",
            "key": "Financial Service Providers",
            "relationship": "targets",
            "relationship_created_on": "2022-03-25T20:00:17.000Z",
            "relationship_last_published": "2022-03-25T20:00:17.000Z",
            "type": "vertical",
            "uuid": "af260c8a-39bd-4ba3-8b03-7390b444d213",
            "href": "/rest/fundamental/v0/af260c8a-39bd-4ba3-8b03-7390b444d213"
        }
    ],
    "replication_id": 1648238417893000050,
    "type": "threat_actor",
    "uuid": "e1ae906f-9541-404f-a581-f452f046d713",
    "first_seen": "2022-03-18T04:00:00.000Z",
    "severity": 2,
    "threat_types": [
        "Cyber Crime"
    ],
    "description": "First seen in March 2022, Swift specializes in selling compromised databases on the underground site breached[.]co. In March 2022, [Swift advertised for sale](/#/node/malicious_event/view/17517a72-9624-4d13-aa1f-e108f28be5e0) data stolen from a major US mobile carrier and a large US financial services provider for US$75,000 and US$40,000, respectively.",
    "languages": [
        "English"
    ],
    "motivations": [
        "Financial"
    ],
    "skill_lvl": "Moderate"
}


expected_output_malware_family = {
    'malware_family': [{'value': 'c1b3216e-8b2e-4a9f-b0a9-2e184b7182f7', 'Name': 'Hive', 'DbotReputation': 2, 'ThreatTypes': ['Cyber Crime'], 'Type': 'malware_family', 'LastPublished': '2022-03-20T19:46:58.000Z', 'LastModified': '2022-04-04T15:52:25.000Z', 'IndexTimestamp': '2022-04-05T15:00:05.654Z', 'Severity': 3, 'CreatedOn': '2021-08-27T15:54:07.000Z', 'Description': '## Overview\nThe Hive ransomware, written in the Go programming language, first came to the attention of researchers in June 2021. In August 2021, actors used the [Hive ransomware against a healthcare provider in Ohio]( https://labs.sentinelone.com/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/). Hive actors conduct double extortion tactics and maintain a leak site at hxxp://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd[.]onion/ and an instructions and  payment site at  hxxp://hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd[.]onion/, which requires login and password credentials.\n\n## Functionality and Behavior\nA preliminary iDefense analysis of the Hive ransomware revealed the following functionality:\n\n- Once Hive is deployed on the target machine, the operator can issue command-line parameters that perform functions listed in Exhibit 1.\n \n\n   \n *Exhibit 1: Command-Line Parameters*\n\n- When run without command-line parameters, Hive executes its default functionality as listed in Exhibit 2. Some of the functions include deleting itself, stopping default services shown in Exhibit 1, skipping files more than five years old, and deleting shadow copies.\n \n\n   \n *Exhibit 2: Default Execution*\n\n- During its default encryption activities in a test directory, Hive encrypted an executable file and encrypted PPT files but skipped an XLS file. When encrypting executables in an analysis sandbox, the sandbox environment became unstable. Exhibit 3 shows the encrypted and unencrypted files in the test directory. Hive added the file extension `.[key string][alphanumeric string].hive` to files it encrypted.\n \n   \n *Exhibit 3: Default Execution*\n\n- Hive drops its ransom note in directories it examined during encryption activities. Exhibit 4 shows the ransom note.\n  \n   \n *Exhibit 4: Ransom Note*\n\n## Mitigation\n\nTo protect against the Hive ransomware and possible data exfiltration, iDefense suggests:\n* Implementing the appropriate mitigations selected in the left-hand MITRE ATT&CK techniques tab.\n- Training users to identify and safely handle social engineering emails that could be part of a phishing campaign.\n\n- Avoiding opening or downloading suspicious links and attachments in emails from external sources until confirming with the sender using other means that the message and its contents are valid.\n- Securing networks from malware through best practices for patching, configuring firewalls, maintaining up-to-date anti-virus signatures, running regular scans, retaining backups separate from the network on which they reside, and using application whitelists.\n- Preparing and implementing a robust incident response plan in case a data breach or malware incident occurs.\n- Immediately disconnecting compromised systems from the network on which they reside.\n- Refraining from paying ransoms, as doing so provides an incentive to threat actors to continue making demands.\n- Consider developing continuity of operations plans  that account for massive ransomware or wiper attacks that can spread across the entire business.\n- For additional mitigation advice on how to protect against ransomware attacks, see iDefense’s Intelligence Alert titled [“Overview of Ransomware Activity.”](https://intelgraph.idefense.com/#/node/intelligence_alert/view/5afaf6fc-30eb-4635-960b-e92df530787f)\n\nFor threat hunting against Hive samples, iDefense suggests looking for the following files:\n* Encrypted files with extension `.[key string][alphanumeric string].hive`\n* Ransom note “HOW\\_TO_DECRYPT.txt in various directories\n* Hive batch files hive.bat or shadow.bat\n* Key files [key string].key, [key string].key.hiv\n* temp[integer]_swamp.hive of unknown use'}],
    'dbot': [{'Indicator': 'c1b3216e-8b2e-4a9f-b0a9-2e184b7182f7', 'Type': 'ACTI Malware Family', 'Vendor': 'ACTI Indicator Query', 'Score': 2, 'Reliability': 'B - Usually reliable'}]
}

RAW_MALWARE_FAMILY_RES_JSON = {
    "results": [{
    "created_on": "2021-08-27T15:54:07.000Z",
    "display_text": "Hive",
    "dynamic_properties": {},
    "index_timestamp": "2022-04-05T15:00:05.654Z",
    "key": "Hive",
    "last_modified": "2022-04-04T15:52:25.000Z",
    "last_published": "2022-03-20T19:46:58.000Z",
    "links": [
        {
            "created_on": "2022-04-05T14:59:19.000Z",
            "display_text": "Hive Ransomware Group Compromises Railway Transportation Company Rete Ferroviaria Italiana",
            "key": "0193037c-fda0-43fb-9847-c8c64560090d",
            "relationship": "uses",
            "relationship_created_on": "2022-04-05T14:59:19.000Z",
            "relationship_last_published": "2022-04-05T14:59:19.000Z",
            "type": "malicious_event",
            "uuid": "f21741c7-6200-4490-a2bd-c443a50bd3bd",
            "href": "/rest/fundamental/v0/f21741c7-6200-4490-a2bd-c443a50bd3bd"
        },
        {
            "created_on": "2022-03-03T09:05:16.000Z",
            "display_text": "fce6a04dfa8a955fbe626c3f04491444",
            "key": "fce6a04dfa8a955fbe626c3f04491444",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:05:16.000Z",
            "relationship_last_published": "2022-03-03T09:05:16.000Z",
            "type": "file",
            "uuid": "fafd3e32-d75e-4f28-b43e-3627ea406165",
            "href": "/rest/fundamental/v0/fafd3e32-d75e-4f28-b43e-3627ea406165"
        },
        {
            "created_on": "2022-03-03T09:01:17.000Z",
            "display_text": "514b741214951b9d39d66688839a223d",
            "key": "514b741214951b9d39d66688839a223d",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T13:02:00.000Z",
            "relationship_last_published": "2022-03-03T13:02:00.000Z",
            "type": "file",
            "uuid": "e663897a-7ed9-45e2-a9ce-e5ce9380affb",
            "href": "/rest/fundamental/v0/e663897a-7ed9-45e2-a9ce-e5ce9380affb"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "2c358fdf4c85c4352e1d297727b957f0",
            "key": "2c358fdf4c85c4352e1d297727b957f0",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-01T01:08:10.000Z",
            "relationship_last_published": "2022-02-01T01:08:10.000Z",
            "type": "file",
            "uuid": "d569fe23-409d-4c36-b6ec-bca16eb1aefd",
            "href": "/rest/fundamental/v0/d569fe23-409d-4c36-b6ec-bca16eb1aefd"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "095715a96975ef7b9e17d0a39739e0cc",
            "key": "095715a96975ef7b9e17d0a39739e0cc",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-09T03:07:06.000Z",
            "relationship_last_published": "2022-02-09T03:07:06.000Z",
            "type": "file",
            "uuid": "5af5afb1-b893-44f8-b756-a4a8c6149948",
            "href": "/rest/fundamental/v0/5af5afb1-b893-44f8-b756-a4a8c6149948"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "8e26cf1b3222ea0059aeb2aed6115fc5",
            "key": "8e26cf1b3222ea0059aeb2aed6115fc5",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T21:04:44.000Z",
            "relationship_last_published": "2022-03-03T21:04:44.000Z",
            "type": "file",
            "uuid": "1608025e-11a6-4589-86f2-8e1a6b8d3b11",
            "href": "/rest/fundamental/v0/1608025e-11a6-4589-86f2-8e1a6b8d3b11"
        },
        {
            "created_on": "2021-12-06T23:07:05.000Z",
            "display_text": "Cyber Threats to Nonprofit Organizations",
            "key": "81fd35e0-8b99-43ef-a1f8-45cb7bfadb49",
            "relationship": "mentions",
            "relationship_created_on": "2021-12-06T23:07:05.000Z",
            "relationship_last_published": "2021-12-06T23:08:22.000Z",
            "type": "intelligence_report",
            "uuid": "a8676cc1-5386-4492-b39e-b4064e42193d",
            "href": "/rest/document/v0/a8676cc1-5386-4492-b39e-b4064e42193d"
        },
        {
            "created_on": "2022-03-03T09:06:22.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/10795314.exe",
            "key": "http://193.233.48.64:20001/bot/cache/10795314.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:06:22.000Z",
            "relationship_last_published": "2022-03-03T09:06:22.000Z",
            "type": "url",
            "uuid": "81cfeb63-525e-462d-942d-9f1cc32dada9",
            "href": "/rest/fundamental/v0/81cfeb63-525e-462d-942d-9f1cc32dada9"
        },
        {
            "created_on": "2022-03-03T09:05:31.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/36712604.exe",
            "key": "http://193.233.48.64:20001/bot/cache/36712604.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:31.000Z",
            "relationship_last_published": "2022-03-03T09:05:31.000Z",
            "type": "url",
            "uuid": "43a9beac-9a6a-42dd-9385-86ed5f1c735b",
            "href": "/rest/fundamental/v0/43a9beac-9a6a-42dd-9385-86ed5f1c735b"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "http://85.202.169.245/build.exe",
            "key": "http://85.202.169.245/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-28T21:00:56.000Z",
            "relationship_last_published": "2022-01-28T21:00:56.000Z",
            "type": "url",
            "uuid": "06bb16a3-7de6-43b3-a025-27bfbdfb3737",
            "href": "/rest/fundamental/v0/06bb16a3-7de6-43b3-a025-27bfbdfb3737"
        },
        {
            "created_on": "2022-01-12T16:27:02.000Z",
            "display_text": "Makop and Hive Ransomware Downloaded from GitHub Repository",
            "key": "2403d723-9875-479c-b8a5-ff1181284588",
            "relationship": "uses",
            "relationship_created_on": "2022-01-12T16:27:02.000Z",
            "relationship_last_published": "2022-01-12T16:27:02.000Z",
            "type": "malicious_event",
            "uuid": "f5fab130-70d6-4f3e-8ae2-dada98626b51",
            "href": "/rest/fundamental/v0/f5fab130-70d6-4f3e-8ae2-dada98626b51"
        },
        {
            "created_on": "2021-08-25T17:38:11.000Z",
            "display_text": "504bd1695de326bc533fde29b8a69319",
            "key": "504bd1695de326bc533fde29b8a69319",
            "relationship": "belongsTo",
            "relationship_created_on": "2021-09-29T19:19:09.000Z",
            "relationship_last_published": "2021-09-29T19:19:09.000Z",
            "type": "file",
            "uuid": "a7bc5402-1d74-42b1-b6e1-6e43f52bfcc3",
            "href": "/rest/fundamental/v0/a7bc5402-1d74-42b1-b6e1-6e43f52bfcc3"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "de56cde528237db0bafb21e16e5d2660",
            "key": "de56cde528237db0bafb21e16e5d2660",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:02:54.000Z",
            "relationship_last_published": "2022-01-26T18:02:54.000Z",
            "type": "file",
            "uuid": "9f3b8b8f-b776-4cd2-9ba7-887aaf186a6d",
            "href": "/rest/fundamental/v0/9f3b8b8f-b776-4cd2-9ba7-887aaf186a6d"
        },
        {
            "created_on": "2022-03-21T17:01:13.000Z",
            "display_text": "http://file-coin-coin-10.com/files/3146_1647797189_9799.exe",
            "key": "http://file-coin-coin-10.com/files/3146_1647797189_9799.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-21T17:01:13.000Z",
            "relationship_last_published": "2022-03-21T17:01:13.000Z",
            "type": "url",
            "uuid": "ee9e9f7c-a599-4009-96f8-d5ac5beabe55",
            "href": "/rest/fundamental/v0/ee9e9f7c-a599-4009-96f8-d5ac5beabe55"
        },
        {
            "created_on": "2022-03-03T09:06:00.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/32311396.exe",
            "key": "http://193.233.48.64:20001/bot/cache/32311396.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:06:00.000Z",
            "relationship_last_published": "2022-03-03T09:06:00.000Z",
            "type": "url",
            "uuid": "ad48f931-e83f-4312-ad38-5b51744b14e8",
            "href": "/rest/fundamental/v0/ad48f931-e83f-4312-ad38-5b51744b14e8"
        },
        {
            "created_on": "2022-03-03T09:05:12.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/68950155.exe",
            "key": "http://193.233.48.64:20001/bot/cache/68950155.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:12.000Z",
            "relationship_last_published": "2022-03-03T09:05:12.000Z",
            "type": "url",
            "uuid": "97551dc6-e59a-450b-899c-b2d1e11c4dd8",
            "href": "/rest/fundamental/v0/97551dc6-e59a-450b-899c-b2d1e11c4dd8"
        },
        {
            "created_on": "2022-01-30T11:30:44.000Z",
            "display_text": "http://62.197.136.229/build.exe",
            "key": "http://62.197.136.229/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T21:04:44.000Z",
            "relationship_last_published": "2022-03-03T21:04:44.000Z",
            "type": "url",
            "uuid": "8195b155-dd97-4ba4-82ea-897fc9f0e75a",
            "href": "/rest/fundamental/v0/8195b155-dd97-4ba4-82ea-897fc9f0e75a"
        },
        {
            "created_on": "2022-03-03T09:00:56.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/33132493.exe",
            "key": "http://193.233.48.64:20001/bot/cache/33132493.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:00:56.000Z",
            "relationship_last_published": "2022-03-03T09:00:56.000Z",
            "type": "url",
            "uuid": "3a597bdb-5848-4585-9a5e-58453fab2eba",
            "href": "/rest/fundamental/v0/3a597bdb-5848-4585-9a5e-58453fab2eba"
        },
        {
            "created_on": "2022-02-11T03:01:52.000Z",
            "display_text": "http://82.157.108.230:8000/%E4%B8%AA%E4%BA%BA%E7%AE%80%E5%8E%86.pdf%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20.exe",
            "key": "http://82.157.108.230:8000/%E4%B8%AA%E4%BA%BA%E7%AE%80%E5%8E%86.pdf%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-02-11T03:01:52.000Z",
            "relationship_last_published": "2022-02-11T03:01:52.000Z",
            "type": "url",
            "uuid": "0e9a21fd-bce5-48c2-8506-d06e1b497c0b",
            "href": "/rest/fundamental/v0/0e9a21fd-bce5-48c2-8506-d06e1b497c0b"
        },
        {
            "created_on": "2022-03-21T17:01:13.000Z",
            "display_text": "92d0366537308d4b6e0ca530f49adb6d",
            "key": "92d0366537308d4b6e0ca530f49adb6d",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-21T17:01:13.000Z",
            "relationship_last_published": "2022-03-21T17:01:13.000Z",
            "type": "file",
            "uuid": "e1cf3272-6d75-418e-8168-870b8d4367dc",
            "href": "/rest/fundamental/v0/e1cf3272-6d75-418e-8168-870b8d4367dc"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "3e6c6230b55a1cce968197736af2a89b",
            "key": "3e6c6230b55a1cce968197736af2a89b",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-09T09:11:23.000Z",
            "relationship_last_published": "2022-02-09T09:11:23.000Z",
            "type": "file",
            "uuid": "cb95d9f6-1dce-4cc0-9baa-925879fb83f6",
            "href": "/rest/fundamental/v0/cb95d9f6-1dce-4cc0-9baa-925879fb83f6"
        },
        {
            "created_on": "2022-03-03T09:06:00.000Z",
            "display_text": "689d783fdaeeff17f2c3a9471ad716d7",
            "key": "689d783fdaeeff17f2c3a9471ad716d7",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:06:00.000Z",
            "relationship_last_published": "2022-03-03T09:06:00.000Z",
            "type": "file",
            "uuid": "95c555b5-4ac1-4f9a-a0c4-57fd12adc62e",
            "href": "/rest/fundamental/v0/95c555b5-4ac1-4f9a-a0c4-57fd12adc62e"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "e804bf3e7b1395a2a3d348d5e4b0d1f4",
            "key": "e804bf3e7b1395a2a3d348d5e4b0d1f4",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-16T15:04:03.000Z",
            "relationship_last_published": "2022-02-16T15:04:03.000Z",
            "type": "file",
            "uuid": "7a2caf7a-1349-4345-b0d7-1a6ef276757b",
            "href": "/rest/fundamental/v0/7a2caf7a-1349-4345-b0d7-1a6ef276757b"
        },
        {
            "created_on": "2022-03-03T09:05:57.000Z",
            "display_text": "7d4220c9e78fdf518621c113a8649176",
            "key": "7d4220c9e78fdf518621c113a8649176",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:05:57.000Z",
            "relationship_last_published": "2022-03-03T09:05:57.000Z",
            "type": "file",
            "uuid": "25bea5dd-fc28-4b27-ac88-8bd2091310de",
            "href": "/rest/fundamental/v0/25bea5dd-fc28-4b27-ac88-8bd2091310de"
        },
        {
            "created_on": "2022-02-11T03:01:52.000Z",
            "display_text": "79b5eb5b92a2245b42d82a2c106ecf30",
            "key": "79b5eb5b92a2245b42d82a2c106ecf30",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-02-11T03:01:52.000Z",
            "relationship_last_published": "2022-02-11T03:01:52.000Z",
            "type": "file",
            "uuid": "114705ce-be03-4498-861d-c72ec73f797c",
            "href": "/rest/fundamental/v0/114705ce-be03-4498-861d-c72ec73f797c"
        },
        {
            "created_on": "2021-11-05T18:18:10.000Z",
            "display_text": "Technical Analysis of Hive Ransomware",
            "key": "5684299e-5bdc-4af5-b829-da7a8c95e7f7",
            "relationship": "mentions",
            "relationship_created_on": "2021-11-05T18:18:10.000Z",
            "relationship_last_published": "2021-11-05T18:18:10.000Z",
            "type": "intelligence_alert",
            "uuid": "995e4c09-dd66-420c-8e35-b1edb022e7ee",
            "href": "/rest/document/v0/995e4c09-dd66-420c-8e35-b1edb022e7ee"
        },
        {
            "created_on": "2021-10-13T16:08:00.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 13 October 2021",
            "key": "cabde77f-68ff-45fc-9e84-3f624d8038e5",
            "relationship": "mentions",
            "relationship_created_on": "2021-10-13T16:08:00.000Z",
            "relationship_last_published": "2021-10-13T16:08:00.000Z",
            "type": "intelligence_alert",
            "uuid": "54745848-9166-4387-9fc3-137b3e07022e",
            "href": "/rest/document/v0/54745848-9166-4387-9fc3-137b3e07022e"
        },
        {
            "created_on": "2022-01-26T18:02:54.000Z",
            "display_text": "http://185.112.83.96:20001/build_dl",
            "key": "http://185.112.83.96:20001/build_dl",
            "relationship": "seenAt",
            "relationship_created_on": "2022-02-09T03:07:06.000Z",
            "relationship_last_published": "2022-02-09T03:07:06.000Z",
            "type": "url",
            "uuid": "f688be80-466b-4f9e-8914-747b1da441aa",
            "href": "/rest/fundamental/v0/f688be80-466b-4f9e-8914-747b1da441aa"
        },
        {
            "created_on": "2022-03-03T09:05:57.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/49495799.exe",
            "key": "http://193.233.48.64:20001/bot/cache/49495799.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:57.000Z",
            "relationship_last_published": "2022-03-03T09:05:57.000Z",
            "type": "url",
            "uuid": "d9264aff-df75-4d33-8c4b-cef938a4a683",
            "href": "/rest/fundamental/v0/d9264aff-df75-4d33-8c4b-cef938a4a683"
        },
        {
            "created_on": "2022-01-25T03:00:15.000Z",
            "display_text": "http://5.255.100.227/myblog/posts/32.exe",
            "key": "http://5.255.100.227/myblog/posts/32.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-25T03:00:15.000Z",
            "relationship_last_published": "2022-01-25T03:00:15.000Z",
            "type": "url",
            "uuid": "8ec32443-d904-4f4c-b3e3-da6c8538b5be",
            "href": "/rest/fundamental/v0/8ec32443-d904-4f4c-b3e3-da6c8538b5be"
        },
        {
            "created_on": "2022-03-21T18:13:26.000Z",
            "display_text": "http://file-coin-coin-10.com/files/7060_1647109264_3109.exe",
            "key": "http://file-coin-coin-10.com/files/7060_1647109264_3109.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-21T18:13:26.000Z",
            "relationship_last_published": "2022-03-21T18:13:26.000Z",
            "type": "url",
            "uuid": "22a9b797-d2ad-40e5-a4d1-f7db7b693183",
            "href": "/rest/fundamental/v0/22a9b797-d2ad-40e5-a4d1-f7db7b693183"
        },
        {
            "created_on": "2018-12-04T19:10:01.000Z",
            "display_text": "Healthcare Providers",
            "key": "Healthcare Providers",
            "relationship": "targets",
            "relationship_created_on": "2021-08-27T15:54:07.000Z",
            "relationship_last_published": "2021-08-27T15:54:07.000Z",
            "type": "vertical",
            "uuid": "baa08cb8-89cd-45a3-a302-4a307edc5708",
            "href": "/rest/fundamental/v0/baa08cb8-89cd-45a3-a302-4a307edc5708"
        },
        {
            "created_on": "2022-03-03T09:05:12.000Z",
            "display_text": "56069652e0a95bb25da5cad6ac8e070e",
            "key": "56069652e0a95bb25da5cad6ac8e070e",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-03T09:06:22.000Z",
            "relationship_last_published": "2022-03-03T09:06:22.000Z",
            "type": "file",
            "uuid": "d663d2f5-bde5-4685-9d87-0e27c2eb8acd",
            "href": "/rest/fundamental/v0/d663d2f5-bde5-4685-9d87-0e27c2eb8acd"
        },
        {
            "created_on": "2022-01-03T16:38:23.000Z",
            "display_text": "032760a6afd808e9eaf2979b72bcebf4",
            "key": "032760a6afd808e9eaf2979b72bcebf4",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-10T13:38:32.000Z",
            "relationship_last_published": "2022-01-10T15:43:03.000Z",
            "type": "file",
            "uuid": "c279fa1d-712d-46ae-965b-0d5f653a121b",
            "href": "/rest/fundamental/v0/c279fa1d-712d-46ae-965b-0d5f653a121b"
        },
        {
            "created_on": "2021-08-30T16:01:06.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 30 August 2021",
            "key": "c036ec6d-12a5-4672-9173-3c424d473781",
            "relationship": "mentions",
            "relationship_created_on": "2021-08-30T16:01:06.000Z",
            "relationship_last_published": "2021-08-30T16:01:05.000Z",
            "type": "intelligence_alert",
            "uuid": "94af0110-5706-4bc2-aca1-92a2f78c801d",
            "href": "/rest/document/v0/94af0110-5706-4bc2-aca1-92a2f78c801d"
        },
        {
            "created_on": "2022-03-03T09:01:17.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/22092005.exe",
            "key": "http://193.233.48.64:20001/bot/cache/22092005.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:01:17.000Z",
            "relationship_last_published": "2022-03-03T09:01:17.000Z",
            "type": "url",
            "uuid": "f95eb4f0-7ca1-42bb-9bd3-9309f976fb6c",
            "href": "/rest/fundamental/v0/f95eb4f0-7ca1-42bb-9bd3-9309f976fb6c"
        },
        {
            "created_on": "2022-03-03T13:02:00.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/99608309.exe",
            "key": "http://193.233.48.64:20001/bot/cache/99608309.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T13:02:00.000Z",
            "relationship_last_published": "2022-03-03T13:02:00.000Z",
            "type": "url",
            "uuid": "036e0339-c616-4bed-bcab-979e130dbf07",
            "href": "/rest/fundamental/v0/036e0339-c616-4bed-bcab-979e130dbf07"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "addfdc6395f84f4a377423f212e1fa27",
            "key": "addfdc6395f84f4a377423f212e1fa27",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:17:38.000Z",
            "relationship_last_published": "2022-01-26T18:17:38.000Z",
            "type": "file",
            "uuid": "c6a0aa62-7773-46d5-8a5c-82d745c8c5d6",
            "href": "/rest/fundamental/v0/c6a0aa62-7773-46d5-8a5c-82d745c8c5d6"
        },
        {
            "created_on": "2022-01-26T18:17:38.000Z",
            "display_text": "78d6b9e2eba0867155d9f3489e4554bc",
            "key": "78d6b9e2eba0867155d9f3489e4554bc",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-01-26T18:17:38.000Z",
            "relationship_last_published": "2022-01-26T18:17:38.000Z",
            "type": "file",
            "uuid": "5cc0fac4-639b-4423-9b0e-af38eec6b434",
            "href": "/rest/fundamental/v0/5cc0fac4-639b-4423-9b0e-af38eec6b434"
        },
        {
            "created_on": "2022-03-21T18:13:26.000Z",
            "display_text": "0df23d0344989230bd0333c37ca598fd",
            "key": "0df23d0344989230bd0333c37ca598fd",
            "relationship": "belongsTo",
            "relationship_created_on": "2022-03-21T18:13:26.000Z",
            "relationship_last_published": "2022-03-21T18:13:26.000Z",
            "type": "file",
            "uuid": "0c562fff-70bf-4e23-a54c-5f9db177b21c",
            "href": "/rest/fundamental/v0/0c562fff-70bf-4e23-a54c-5f9db177b21c"
        },
        {
            "created_on": "2022-02-22T21:33:12.000Z",
            "display_text": "SITREP: Ukraine Crisis",
            "key": "0ae44727-6fef-4dcb-9928-8eed0c3bcd3e",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-20T19:46:59.000Z",
            "relationship_last_published": "2022-03-20T19:46:58.000Z",
            "type": "intelligence_alert",
            "uuid": "f1862833-80de-4880-a180-11fad373e896",
            "href": "/rest/document/v0/f1862833-80de-4880-a180-11fad373e896"
        },
        {
            "created_on": "2021-08-25T15:38:48.000Z",
            "display_text": "iDefense Global Research Intelligence Digest for 25 August 2021",
            "key": "429ca269-8d25-46a3-8b83-5b666a2e7182",
            "relationship": "mentions",
            "relationship_created_on": "2022-03-20T21:40:13.000Z",
            "relationship_last_published": "2022-03-20T21:40:13.000Z",
            "type": "intelligence_alert",
            "uuid": "4b3c7699-ff95-4650-9f24-6dee2be84112",
            "href": "/rest/document/v0/4b3c7699-ff95-4650-9f24-6dee2be84112"
        },
        {
            "created_on": "2022-01-16T15:01:07.000Z",
            "display_text": "http://91.243.59.17/build.exe",
            "key": "http://91.243.59.17/build.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-16T15:01:07.000Z",
            "relationship_last_published": "2022-01-16T15:01:07.000Z",
            "type": "url",
            "uuid": "85962156-eeba-43d3-8cc5-ee4f0cd2007a",
            "href": "/rest/fundamental/v0/85962156-eeba-43d3-8cc5-ee4f0cd2007a"
        },
        {
            "created_on": "2022-01-10T13:38:32.000Z",
            "display_text": "https://raw.githubusercontent.com/flicker32/tyupo/main/release.txt",
            "key": "https://raw.githubusercontent.com/flicker32/tyupo/main/release.txt",
            "relationship": "seenAt",
            "relationship_created_on": "2022-01-10T13:38:32.000Z",
            "relationship_last_published": "2022-01-10T13:38:32.000Z",
            "type": "url",
            "uuid": "45acec3a-faf6-4c25-8c55-4fbe2859b447",
            "href": "/rest/fundamental/v0/45acec3a-faf6-4c25-8c55-4fbe2859b447"
        },
        {
            "created_on": "2022-03-03T09:05:16.000Z",
            "display_text": "http://193.233.48.64:20001/bot/cache/42663002.exe",
            "key": "http://193.233.48.64:20001/bot/cache/42663002.exe",
            "relationship": "seenAt",
            "relationship_created_on": "2022-03-03T09:05:16.000Z",
            "relationship_last_published": "2022-03-03T09:05:16.000Z",
            "type": "url",
            "uuid": "058afbb7-57be-4378-8d49-e36fb60361bc",
            "href": "/rest/fundamental/v0/058afbb7-57be-4378-8d49-e36fb60361bc"
        }
    ],
    "replication_id": 1649087545647000061,
    "sources_external": [
        {
            "datetime": "2021-08-23T04:00:00.000Z",
            "description": "Hive Attacks | Analysis of the Human-Operated Ransomware Targeting Healthcare",
            "name": "SentinelOne",
            "url": "https://labs.sentinelone.com/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/"
        }
    ],
    "type": "malware_family",
    "uuid": "c1b3216e-8b2e-4a9f-b0a9-2e184b7182f7",
    "description": "##Overview\nThe Hive ransomware, written in the Go programming language, first came to the attention of researchers in June 2021. In August 2021, actors used the [Hive ransomware against a healthcare provider in Ohio]( https://labs.sentinelone.com/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/). Hive actors conduct double extortion tactics and maintain a leak site at hxxp://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd[.]onion/ and an instructions and  payment site at  hxxp://hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd[.]onion/, which requires login and password credentials.\n\n##Functionality and Behavior\nA preliminary iDefense analysis of the Hive ransomware revealed the following functionality:\n\n- Once Hive is deployed on the target machine, the operator can issue command-line parameters that perform functions listed in Exhibit 1.\n \n\n   \n *Exhibit 1: Command-Line Parameters*\n\n- When run without command-line parameters, Hive executes its default functionality as listed in Exhibit 2. Some of the functions include deleting itself, stopping default services shown in Exhibit 1, skipping files more than five years old, and deleting shadow copies.\n \n\n   \n *Exhibit 2: Default Execution*\n\n- During its default encryption activities in a test directory, Hive encrypted an executable file and encrypted PPT files but skipped an XLS file. When encrypting executables in an analysis sandbox, the sandbox environment became unstable. Exhibit 3 shows the encrypted and unencrypted files in the test directory. Hive added the file extension `.[key string][alphanumeric string].hive` to files it encrypted.\n \n   \n *Exhibit 3: Default Execution*\n\n- Hive drops its ransom note in directories it examined during encryption activities. Exhibit 4 shows the ransom note.\n  \n   \n *Exhibit 4: Ransom Note*\n\n##Mitigation\n\nTo protect against the Hive ransomware and possible data exfiltration, iDefense suggests:\n* Implementing the appropriate mitigations selected in the left-hand MITRE ATT&CK techniques tab.\n- Training users to identify and safely handle social engineering emails that could be part of a phishing campaign.\n\n- Avoiding opening or downloading suspicious links and attachments in emails from external sources until confirming with the sender using other means that the message and its contents are valid.\n- Securing networks from malware through best practices for patching, configuring firewalls, maintaining up-to-date anti-virus signatures, running regular scans, retaining backups separate from the network on which they reside, and using application whitelists.\n- Preparing and implementing a robust incident response plan in case a data breach or malware incident occurs.\n- Immediately disconnecting compromised systems from the network on which they reside.\n- Refraining from paying ransoms, as doing so provides an incentive to threat actors to continue making demands.\n- Consider developing continuity of operations plans  that account for massive ransomware or wiper attacks that can spread across the entire business.\n- For additional mitigation advice on how to protect against ransomware attacks, see iDefense’s Intelligence Alert titled [“Overview of Ransomware Activity.”](/#/node/intelligence_alert/view/5afaf6fc-30eb-4635-960b-e92df530787f)\n\nFor threat hunting against Hive samples, iDefense suggests looking for the following files:\n* Encrypted files with extension `.[key string][alphanumeric string].hive`\n* Ransom note “HOW\\_TO_DECRYPT.txt in various directories\n* Hive batch files hive.bat or shadow.bat\n* Key files [key string].key, [key string].key.hiv\n* temp[integer]_swamp.hive of unknown use",
    "severity": 3,
    "threat_types": [
        "Cyber Crime"
    ],
    "variety": [
        "Ransomware"
    ],
    "attack_techniques": [
        {
            "id": "T1489",
            "label": "Service Stop"
        },
        {
            "id": "T1007",
            "label": "System Service Discovery"
        },
        {
            "id": "T1192",
            "label": "Spearphishing Link"
        },
        {
            "id": "T1490",
            "label": "Inhibit System Recovery"
        },
        {
            "id": "T1486",
            "label": "Data Encrypted for Impact"
        },
        {
            "id": "T1045",
            "label": "Software Packing"
        },
        {
            "id": "T1059",
            "label": "Command-Line Interface"
        }
    ]
    }],
    "total_size": 1, 'page': 1, 'page_size': 25, 'more': False
}
