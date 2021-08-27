from CommonServerPython import *

""" IMPORTS """
import demistomock as demisto

""" CONSTANTS """
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
AUTH_URL = "securitymanager/api/authentication/login"
WORKFLOW_URL = "/policyplanner/api/domain/{0}/workflow/version/latest/all"
CREATE_PP_TICKET_URL = "/policyplanner/api/domain/{0}/workflow/{1}/packet"
PCA_URL_SUFFIX = "/orchestration/api/domain/{}/change/device/{}/pca"
RULE_REC_URL = "orchestration/api/domain/{}/change/rulerec"

create_pp_payload = {
    "sources": [
        ""
    ],
    "destinations": [
        ""
    ],
    "action": "",
    "services": [
        ""
    ],
    "requirementType": "RULE",
    "childKey": "add_access",
    "variables": {}
}


def get_rule_rec_request_payload():
    return {
        "apps": [],
        "destinations": [
            ""
        ],
        "services": [
            ""
        ],
        "sources": [
            ""
        ],
        "users": [],
        "requirementType": "RULE",
        "childKey": "add_access",
        "variables": {
            "expiration": "null",
            "review": "null"
        },
        "action": ""
    }


def get_pca_payload():
    return [{
        "action": "MODIFY",
        "changeType": "RULE",
        "deviceId": 121212110,
        "deviceName": "CISCO ASA Context Test",
        "deviceType": "FIREWALL",
        "implementationStatus": "PENDING",
        "location": "BELOW",
        "policyDisplayName": "CSM_nat_inside_pool1",
        "policyName": "CSM_nat_inside_pool1",
        "policyUUID": "0d197124-de8d-4b8f-8deb-f9f8d9a2cd9b",
        "referencedRules": [
            {
                "sources": [
                    {
                        "name": "5.5.5.0/255.255.255.0"
                    }
                ],
                "destinations": [
                    {
                        "name": "6.6.6.0/255.255.255.0"
                    }
                ],
                "services": [
                    {
                        "name": "tcp-https"
                    }
                ],
                "users": [],
                "apps": [],
                "sourceZones": [
                    {
                        "name": "Any"
                    }
                ],
                "destinationZones": [
                    {
                        "name": "Any"
                    }
                ],
                "ruleUUID": "db086da7-d1c8-4e44-ac1e-92ff9e5bd7c8",
                "ruleName": "line 1",
                "ruleNumberStr": 1,
                "schedules": [],
                "ruleAction": "ACCEPT",
                "ruleNumber": 1,
                "log": "false",
                "disabled": "false"
            }
        ],
        "summary": "testnew1",
        "testedRule": {
            "sources": [
                {
                    "name": "10.10.124.45",
                    "object": {
                        "id": 3,
                        "type": "NETWORK",
                        "matchId": "03db0158-80c7-4acc-9db1-b672a185f62b",
                        "device": {
                            "id": 2,
                            "name": "CISCO ASA Context Test",
                            "externalId": "firemon",
                            "description": "Test device",
                            "managementIp": "192.168.100.39",
                            "parents": [],
                            "children": [],
                            "securityConcernIndex": 2.24,
                            "devicePack": {
                                "type": "DEVICE_PACK",
                                "id": 33,
                                "artifactId": "cisco_pix_asa_fwsm_context",
                                "groupId": "com.fm.sm.dp.cisco-asa-context",
                                "version": "9.3.12",
                                "artifacts": [
                                    {
                                        "name": "layout.json",
                                        "checksum": "0eca755199fd3cac6de2d3e60796088f"
                                    },
                                    {
                                        "name": "layout-modify-serviceobj.json",
                                        "checksum": "635143353b123cfa81f55b7b51ebcbce"
                                    },
                                    {
                                        "name": "plugin.jar",
                                        "checksum": "e3904e821938c88f0bce8fe4ab85f9b5"
                                    },
                                    {
                                        "name": "dc.zip",
                                        "checksum": "8d8ce2346933cf09830298b00eca6e04"
                                    },
                                    {
                                        "name": "layout-modify-networkobj.json",
                                        "checksum": "443791a62fa3dbfec5e1f24de9714268"
                                    }
                                ],
                                "buildDate": "2021-02-19T16:14:27+0000",
                                "deviceName": "ASA/FWSM Context",
                                "deviceType": "FIREWALL",
                                "vendor": "Cisco",
                                "collectionConfig": {
                                    "id": 19,
                                    "name": "default",
                                    "changePattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:",
                                    "changeCriterion": [
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-[\\d]+-106100:\\s*access-list",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:.*?Login\\s+permitted\\s+from\\s+(?<hostName>\\S+)/(?:\\S+)\\s+to\\s+(?:\\S+http\\S+)\\s+for\\s+user\\s+(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "Begin configuration: console writing to memory",
                                            "timeoutSeconds": 30,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+\\S+conf(?:igure)?\\st(?:erminal)?\\S+\\s+command",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s+(?:[\\'\\\"])?(?!(?:rancid|opsware))(?<userName>[^\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+(?!.*(?:(?:conf(?:igure)?\\st(?:erminal)?)|(?:(?:startup-config|running-config)\\ss?ftp)|(?:pager\\s)|('(?:disable|enable|login|enable|enable\\s\\d+)'\\scommand)|(?:'dir\\s.*?'\\scommand)|(?:'perfmon\\s.*?'\\scommand)|(?:'more\\s)|(?:'ping)|(?:'traceroute\\s)|(?:'(?:no\\s)?capture\\s)|(?:'packet-tracer\\s)|(?:'changeto\\s)|(?:'session\\s)|(?:'verify\\s)|(?:'show\\s)|(?:'clear\\s)|(?:'exit)|(?:'no\\sterminal\\spager)))",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+Begin configuration:\\s+(?<hostName>\\S+)\\s+",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*?src=(?<hostName>\\S+).*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        }
                                    ],
                                    "usagePattern": "-[\\d+]-(?:106100|302013|302015|106023)|CISCO",
                                    "usageCriterion": [
                                        {
                                            "pattern": ".*?%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d]+-106100:\\s*access-list\\s+(?<policyName>\\S+)\\s+(?<action>permitted|denied|est-allowed)\\s+(?<proto>\\S+)\\s+(?:[^\\/]+)\\/(?<src>\\S+)\\((?<srcPort>\\d+)\\)(?:\\s*\\(\\S+\\))*\\s+->\\s*(?:[^\\/]+)\\/(?<dst>\\S+)\\((?<dstPort>\\d+)\\)\\s+hit-cnt\\s+(?<hitCount>\\d+)\\s+[^\\[]+(?:[\\)])?(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-(?:302013|302015):\\s+Built\\s+(?<direction>inbound|outbound)\\s+(?<proto>TCP|UDP)\\s+connection\\s+\\-?\\d+\\s+for\\s+(?<interface>[^:]*):(?<src>\\S+)\\/(?<altDstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)(?:[\\\\\\S\\)\\(]+)?\\s+to\\s+(?<altInterface>[^:]*):(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>tcp|udp)\\s+src\\s+\\S+:(?<src>\\S+)\\/(?:\\d+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+(?:\\S+\\s+)?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106100).*?proto=(?<proto>\\S+).*?act=(?<action>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?cs1=(?<policyName>\\S+).*?ad\\.interval=\\S+\\s+\\S+\\s+\\[(?<usageId1>\\S+).*?(?<usageId2>0x\\S+)\\].*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106023).*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?ad\\.Access-group=(?<policyName>\\S+).*?ad\\.data=\\s+\\[(?<usageId1>\\S+),\\s+(?<usageId2>\\S+)\\]",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>icmp)\\s+src\\s+\\S+:(?<src>\\S+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+).*?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"\\s*(?:\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:302013|302015).*?Built\\s+(?<direction>inbound|outbound)\\s+\\S+\\s+connection.*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?sourceTranslatedAddress=(?:\\S+).*?dst=(?<dst>\\S+).*?destinationTranslatedAddress=(?:\\S+).*?dpt=(?<dstPort>\\S+).*?destinationTranslatedPort=(?<altDstPort>\\S+).*?deviceInboundInterface=(?<interface>\\S+).*?deviceOutboundInterface=(?<altInterface>\\S+)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        }
                                    ],
                                    "createdDate": "2021-04-26T07:03:53+0000",
                                    "lastModifiedDate": "2021-04-26T07:03:53+0000",
                                    "createdBy": "com.fm.platform.domain.User@79067614",
                                    "lastModifiedBy": "com.fm.platform.domain.User@79067614",
                                    "usageKeys": [],
                                    "activatedForDevicePack": "false"
                                },
                                "behaviorTranslator": "DstNatRoutePolicySrcNatBehavior_NoImplicitDrop",
                                "normalization": "true",
                                "usage": "true",
                                "change": "true",
                                "usageSyslog": "true",
                                "changeSyslog": "true",
                                "active": "false",
                                "supportsDiff": "true",
                                "supportsManualRetrieval": "true",
                                "implicitDrop": "false",
                                "diffDynamicRoutes": "false",
                                "automation": "false",
                                "lookupNoIntfRoutes": "true",
                                "automationCli": "false",
                                "ssh": "true",
                                "sharedNetworks": "false",
                                "sharedServices": "false",
                                "supportedTypes": [
                                    "POLICY_ROUTES",
                                    "USERS"
                                ],
                                "diffIgnorePatterns": [
                                    ".*\\s+up\\s+([0-9]+\\s+(year|day|hour|min|sec)[s]?\\s*)+",
                                    "\\(\\s*[0-9]*\\s*matches\\s*\\)",
                                    "^access-list cached ACL log flows",
                                    "^[^LCS]\\S?\\s+.*\\[[0-9]+\\/[0-9]+\\]\\s+via.*",
                                    "^Cryptochecksum.*",
                                    "\\(\\s*hitcnt=[0-9]*\\s*\\)",
                                    "^Configuration last modified by .*",
                                    "^:.*Written by.*"
                                ],
                                "convertableTo": []
                            },
                            "gpcDirtyDate": "2021-05-04T06:15:36+0000",
                            "gpcComputeDate": "1970-01-01T00:00:00+0000",
                            "gpcImplementDate": "1970-01-01T00:00:00+0000",
                            "state": "ACTIVE",
                            "managedType": "MANAGED",
                            "gpcStatus": "NOT_SUPPORTED",
                            "updateMemberRuleDoc": "false"
                        },
                        "lastChangeConfigRevId": 19,
                        "createDate": "1970-01-01T00:00:00+0000",
                        "lastUpdated": "2021-05-04T06:15:31+0000"
                    },
                    "objectType": "NETWORK",
                    "role": "SOURCE"
                }
            ],
            "destinations": [
                {
                    "name": "137.69.120.171",
                    "object": {
                        "id": 114,
                        "type": "NETWORK",
                        "matchId": "c0eaad4c-cb07-4f2d-adda-97124b4e6089",
                        "device": {
                            "id": 2,
                            "name": "CISCO ASA Context Test",
                            "externalId": "firemon",
                            "description": "Test device",
                            "managementIp": "192.168.100.39",
                            "parents": [],
                            "children": [],
                            "securityConcernIndex": 2.24,
                            "devicePack": {
                                "type": "DEVICE_PACK",
                                "id": 33,
                                "artifactId": "cisco_pix_asa_fwsm_context",
                                "groupId": "com.fm.sm.dp.cisco-asa-context",
                                "version": "9.3.12",
                                "artifacts": [
                                    {
                                        "name": "layout.json",
                                        "checksum": "0eca755199fd3cac6de2d3e60796088f"
                                    },
                                    {
                                        "name": "layout-modify-serviceobj.json",
                                        "checksum": "635143353b123cfa81f55b7b51ebcbce"
                                    },
                                    {
                                        "name": "plugin.jar",
                                        "checksum": "e3904e821938c88f0bce8fe4ab85f9b5"
                                    },
                                    {
                                        "name": "dc.zip",
                                        "checksum": "8d8ce2346933cf09830298b00eca6e04"
                                    },
                                    {
                                        "name": "layout-modify-networkobj.json",
                                        "checksum": "443791a62fa3dbfec5e1f24de9714268"
                                    }
                                ],
                                "buildDate": "2021-02-19T16:14:27+0000",
                                "deviceName": "ASA/FWSM Context",
                                "deviceType": "FIREWALL",
                                "vendor": "Cisco",
                                "collectionConfig": {
                                    "id": 19,
                                    "name": "default",
                                    "changePattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:",
                                    "changeCriterion": [
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-[\\d]+-106100:\\s*access-list",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:.*?Login\\s+permitted\\s+from\\s+(?<hostName>\\S+)/(?:\\S+)\\s+to\\s+(?:\\S+http\\S+)\\s+for\\s+user\\s+(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "Begin configuration: console writing to memory",
                                            "timeoutSeconds": 30,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+\\S+conf(?:igure)?\\st(?:erminal)?\\S+\\s+command",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s+(?:[\\'\\\"])?(?!(?:rancid|opsware))(?<userName>[^\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+(?!.*(?:(?:conf(?:igure)?\\st(?:erminal)?)|(?:(?:startup-config|running-config)\\ss?ftp)|(?:pager\\s)|('(?:disable|enable|login|enable|enable\\s\\d+)'\\scommand)|(?:'dir\\s.*?'\\scommand)|(?:'perfmon\\s.*?'\\scommand)|(?:'more\\s)|(?:'ping)|(?:'traceroute\\s)|(?:'(?:no\\s)?capture\\s)|(?:'packet-tracer\\s)|(?:'changeto\\s)|(?:'session\\s)|(?:'verify\\s)|(?:'show\\s)|(?:'clear\\s)|(?:'exit)|(?:'no\\sterminal\\spager)))",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+Begin configuration:\\s+(?<hostName>\\S+)\\s+",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*?src=(?<hostName>\\S+).*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        }
                                    ],
                                    "usagePattern": "-[\\d+]-(?:106100|302013|302015|106023)|CISCO",
                                    "usageCriterion": [
                                        {
                                            "pattern": ".*?%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d]+-106100:\\s*access-list\\s+(?<policyName>\\S+)\\s+(?<action>permitted|denied|est-allowed)\\s+(?<proto>\\S+)\\s+(?:[^\\/]+)\\/(?<src>\\S+)\\((?<srcPort>\\d+)\\)(?:\\s*\\(\\S+\\))*\\s+->\\s*(?:[^\\/]+)\\/(?<dst>\\S+)\\((?<dstPort>\\d+)\\)\\s+hit-cnt\\s+(?<hitCount>\\d+)\\s+[^\\[]+(?:[\\)])?(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-(?:302013|302015):\\s+Built\\s+(?<direction>inbound|outbound)\\s+(?<proto>TCP|UDP)\\s+connection\\s+\\-?\\d+\\s+for\\s+(?<interface>[^:]*):(?<src>\\S+)\\/(?<altDstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)(?:[\\\\\\S\\)\\(]+)?\\s+to\\s+(?<altInterface>[^:]*):(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>tcp|udp)\\s+src\\s+\\S+:(?<src>\\S+)\\/(?:\\d+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+(?:\\S+\\s+)?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106100).*?proto=(?<proto>\\S+).*?act=(?<action>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?cs1=(?<policyName>\\S+).*?ad\\.interval=\\S+\\s+\\S+\\s+\\[(?<usageId1>\\S+).*?(?<usageId2>0x\\S+)\\].*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106023).*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?ad\\.Access-group=(?<policyName>\\S+).*?ad\\.data=\\s+\\[(?<usageId1>\\S+),\\s+(?<usageId2>\\S+)\\]",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>icmp)\\s+src\\s+\\S+:(?<src>\\S+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+).*?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"\\s*(?:\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:302013|302015).*?Built\\s+(?<direction>inbound|outbound)\\s+\\S+\\s+connection.*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?sourceTranslatedAddress=(?:\\S+).*?dst=(?<dst>\\S+).*?destinationTranslatedAddress=(?:\\S+).*?dpt=(?<dstPort>\\S+).*?destinationTranslatedPort=(?<altDstPort>\\S+).*?deviceInboundInterface=(?<interface>\\S+).*?deviceOutboundInterface=(?<altInterface>\\S+)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        }
                                    ],
                                    "createdDate": "2021-04-26T07:03:53+0000",
                                    "lastModifiedDate": "2021-04-26T07:03:53+0000",
                                    "createdBy": "com.fm.platform.domain.User@7623a310",
                                    "lastModifiedBy": "com.fm.platform.domain.User@7623a310",
                                    "usageKeys": [],
                                    "activatedForDevicePack": "false"
                                },
                                "behaviorTranslator": "DstNatRoutePolicySrcNatBehavior_NoImplicitDrop",
                                "normalization": "true",
                                "usage": "true",
                                "change": "true",
                                "usageSyslog": "true",
                                "changeSyslog": "true",
                                "active": "false",
                                "supportsDiff": "true",
                                "supportsManualRetrieval": "true",
                                "implicitDrop": "false",
                                "diffDynamicRoutes": "false",
                                "automation": "false",
                                "lookupNoIntfRoutes": "true",
                                "automationCli": "false",
                                "ssh": "true",
                                "sharedNetworks": "false",
                                "sharedServices": "false",
                                "supportedTypes": [
                                    "POLICY_ROUTES",
                                    "USERS"
                                ],
                                "diffIgnorePatterns": [
                                    ".*\\s+up\\s+([0-9]+\\s+(year|day|hour|min|sec)[s]?\\s*)+",
                                    "\\(\\s*[0-9]*\\s*matches\\s*\\)",
                                    "^access-list cached ACL log flows",
                                    "^[^LCS]\\S?\\s+.*\\[[0-9]+\\/[0-9]+\\]\\s+via.*",
                                    "^Cryptochecksum.*",
                                    "\\(\\s*hitcnt=[0-9]*\\s*\\)",
                                    "^Configuration last modified by .*",
                                    "^:.*Written by.*"
                                ],
                                "convertableTo": []
                            },
                            "gpcDirtyDate": "2021-05-04T06:15:36+0000",
                            "gpcComputeDate": "1970-01-01T00:00:00+0000",
                            "gpcImplementDate": "1970-01-01T00:00:00+0000",
                            "state": "ACTIVE",
                            "managedType": "MANAGED",
                            "gpcStatus": "NOT_SUPPORTED",
                            "updateMemberRuleDoc": "false"
                        },
                        "lastChangeConfigRevId": 19,
                        "createDate": "1970-01-01T00:00:00+0000",
                        "lastUpdated": "2021-05-04T06:15:31+0000"
                    },
                    "objectType": "NETWORK",
                    "role": "DESTINATION"
                }
            ],
            "services": [
                {
                    "name": "902-TCP",
                    "object": {
                        "id": 258,
                        "type": "SERVICE",
                        "matchId": "835e425c-d5c1-4a01-91d1-a06e464f2639",
                        "device": {
                            "id": 2,
                            "name": "CISCO ASA Context Test",
                            "externalId": "firemon",
                            "description": "Test device",
                            "managementIp": "192.168.100.39",
                            "parents": [],
                            "children": [],
                            "securityConcernIndex": 2.24,
                            "devicePack": {
                                "type": "DEVICE_PACK",
                                "id": 33,
                                "artifactId": "cisco_pix_asa_fwsm_context",
                                "groupId": "com.fm.sm.dp.cisco-asa-context",
                                "version": "9.3.12",
                                "artifacts": [
                                    {
                                        "name": "layout.json",
                                        "checksum": "0eca755199fd3cac6de2d3e60796088f"
                                    },
                                    {
                                        "name": "layout-modify-serviceobj.json",
                                        "checksum": "635143353b123cfa81f55b7b51ebcbce"
                                    },
                                    {
                                        "name": "plugin.jar",
                                        "checksum": "e3904e821938c88f0bce8fe4ab85f9b5"
                                    },
                                    {
                                        "name": "dc.zip",
                                        "checksum": "8d8ce2346933cf09830298b00eca6e04"
                                    },
                                    {
                                        "name": "layout-modify-networkobj.json",
                                        "checksum": "443791a62fa3dbfec5e1f24de9714268"
                                    }
                                ],
                                "buildDate": "2021-02-19T16:14:27+0000",
                                "deviceName": "ASA/FWSM Context",
                                "deviceType": "FIREWALL",
                                "vendor": "Cisco",
                                "collectionConfig": {
                                    "id": 19,
                                    "name": "default",
                                    "changePattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:",
                                    "changeCriterion": [
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-[\\d]+-106100:\\s*access-list",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:.*?Login\\s+permitted\\s+from\\s+(?<hostName>\\S+)/(?:\\S+)\\s+to\\s+(?:\\S+http\\S+)\\s+for\\s+user\\s+(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "Begin configuration: console writing to memory",
                                            "timeoutSeconds": 30,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s(?:[\\'\\\"])?(?<userName>[^\\s\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+\\S+conf(?:igure)?\\st(?:erminal)?\\S+\\s+command",
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+User\\s+(?:[\\'\\\"])?(?!(?:rancid|opsware))(?<userName>[^\\'\\\"]+)(?:[\\'\\\"])?\\s+executed\\s+the\\s+(?!.*(?:(?:conf(?:igure)?\\st(?:erminal)?)|(?:(?:startup-config|running-config)\\ss?ftp)|(?:pager\\s)|('(?:disable|enable|login|enable|enable\\s\\d+)'\\scommand)|(?:'dir\\s.*?'\\scommand)|(?:'perfmon\\s.*?'\\scommand)|(?:'more\\s)|(?:'ping)|(?:'traceroute\\s)|(?:'(?:no\\s)?capture\\s)|(?:'packet-tracer\\s)|(?:'changeto\\s)|(?:'session\\s)|(?:'verify\\s)|(?:'show\\s)|(?:'clear\\s)|(?:'exit)|(?:'no\\sterminal\\spager)))",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "parentUserName": "enable_15",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "%(?:ASA|PIX|FWSM)-\\d-\\d+:\\s+Begin configuration:\\s+(?<hostName>\\S+)\\s+",
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "false"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*?src=(?<hostName>\\S+).*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        },
                                        {
                                            "pattern": "(?:ASA|PIX|FWSM).*?categoryBehavior=/Modify/Configuration.*",
                                            "timeoutSeconds": 60,
                                            "continueMatch": "false",
                                            "retrieveOnMatch": "true"
                                        }
                                    ],
                                    "usagePattern": "-[\\d+]-(?:106100|302013|302015|106023)|CISCO",
                                    "usageCriterion": [
                                        {
                                            "pattern": ".*?%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d]+-106100:\\s*access-list\\s+(?<policyName>\\S+)\\s+(?<action>permitted|denied|est-allowed)\\s+(?<proto>\\S+)\\s+(?:[^\\/]+)\\/(?<src>\\S+)\\((?<srcPort>\\d+)\\)(?:\\s*\\(\\S+\\))*\\s+->\\s*(?:[^\\/]+)\\/(?<dst>\\S+)\\((?<dstPort>\\d+)\\)\\s+hit-cnt\\s+(?<hitCount>\\d+)\\s+[^\\[]+(?:[\\)])?(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-(?:302013|302015):\\s+Built\\s+(?<direction>inbound|outbound)\\s+(?<proto>TCP|UDP)\\s+connection\\s+\\-?\\d+\\s+for\\s+(?<interface>[^:]*):(?<src>\\S+)\\/(?<altDstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)(?:[\\\\\\S\\)\\(]+)?\\s+to\\s+(?<altInterface>[^:]*):(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+\\((?:\\S+)\\/(?:\\d+)\\)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>tcp|udp)\\s+src\\s+\\S+:(?<src>\\S+)\\/(?:\\d+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+)\\/(?<dstPort>\\d+)\\s+(?:\\S+\\s+)?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"(?:\\s*\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106100).*?proto=(?<proto>\\S+).*?act=(?<action>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?cs1=(?<policyName>\\S+).*?ad\\.interval=\\S+\\s+\\S+\\s+\\[(?<usageId1>\\S+).*?(?<usageId2>0x\\S+)\\].*",
                                            "fields": [],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:106023).*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?dst=(?<dst>\\S+).*?dpt=(?<dstPort>\\S+).*?ad\\.Access-group=(?<policyName>\\S+).*?ad\\.data=\\s+\\[(?<usageId1>\\S+),\\s+(?<usageId2>\\S+)\\]",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "%(?:PIX|ASA|FWSM)-(?:\\S+-)?[\\d+]-106023:\\s+Deny\\s+(?<proto>icmp)\\s+src\\s+\\S+:(?<src>\\S+)\\s+(?:\\S+\\s+)?dst\\s+\\S+:(?<dst>\\S+).*?by\\s+access-group\\s+\\\"(?<policyName>\\S+)\\\"\\s*(?:\\[0x(?<usageId1>[a-zA-Z0-9]+),\\s+0x(?<usageId2>[a-zA-Z0-9]+)\\])?\\s*",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Drop"
                                                }
                                            ],
                                            "dynamicFields": []
                                        },
                                        {
                                            "pattern": "CISCO\\|(?:FWSM|PIX|ASA)\\|?\\S+\\|(?:302013|302015).*?Built\\s+(?<direction>inbound|outbound)\\s+\\S+\\s+connection.*?proto=(?<proto>\\S+).*?src=(?<src>\\S+).*?sourceTranslatedAddress=(?:\\S+).*?dst=(?<dst>\\S+).*?destinationTranslatedAddress=(?:\\S+).*?dpt=(?<dstPort>\\S+).*?destinationTranslatedPort=(?<altDstPort>\\S+).*?deviceInboundInterface=(?<interface>\\S+).*?deviceOutboundInterface=(?<altInterface>\\S+)",
                                            "fields": [
                                                {
                                                    "name": "action",
                                                    "value": "Accept"
                                                }
                                            ],
                                            "dynamicFields": []
                                        }
                                    ],
                                    "createdDate": "2021-04-26T07:03:53+0000",
                                    "lastModifiedDate": "2021-04-26T07:03:53+0000",
                                    "createdBy": "com.fm.platform.domain.User@73a0ed11",
                                    "lastModifiedBy": "com.fm.platform.domain.User@73a0ed11",
                                    "usageKeys": [],
                                    "activatedForDevicePack": "false"
                                },
                                "behaviorTranslator": "DstNatRoutePolicySrcNatBehavior_NoImplicitDrop",
                                "normalization": "true",
                                "usage": "true",
                                "change": "true",
                                "usageSyslog": "true",
                                "changeSyslog": "true",
                                "active": "false",
                                "supportsDiff": "true",
                                "supportsManualRetrieval": "true",
                                "implicitDrop": "false",
                                "diffDynamicRoutes": "false",
                                "automation": "false",
                                "lookupNoIntfRoutes": "true",
                                "automationCli": "false",
                                "ssh": "true",
                                "sharedNetworks": "false",
                                "sharedServices": "false",
                                "supportedTypes": [
                                    "POLICY_ROUTES",
                                    "USERS"
                                ],
                                "diffIgnorePatterns": [
                                    ".*\\s+up\\s+([0-9]+\\s+(year|day|hour|min|sec)[s]?\\s*)+",
                                    "\\(\\s*[0-9]*\\s*matches\\s*\\)",
                                    "^access-list cached ACL log flows",
                                    "^[^LCS]\\S?\\s+.*\\[[0-9]+\\/[0-9]+\\]\\s+via.*",
                                    "^Cryptochecksum.*",
                                    "\\(\\s*hitcnt=[0-9]*\\s*\\)",
                                    "^Configuration last modified by .*",
                                    "^:.*Written by.*"
                                ],
                                "convertableTo": []
                            },
                            "gpcDirtyDate": "2021-05-04T06:15:36+0000",
                            "gpcComputeDate": "1970-01-01T00:00:00+0000",
                            "gpcImplementDate": "1970-01-01T00:00:00+0000",
                            "state": "ACTIVE",
                            "managedType": "MANAGED",
                            "gpcStatus": "NOT_SUPPORTED",
                            "updateMemberRuleDoc": "false"
                        },
                        "lastChangeConfigRevId": 19,
                        "createDate": "1970-01-01T00:00:00+0000",
                        "lastUpdated": "2021-05-04T06:15:31+0000"
                    },
                    "objectType": "SERVICE",
                    "role": "SERVICE"
                }
            ],
            "ruleAction": "ACCEPT",
            "log": "true",
            "destinationZones": [],
            "sourceZones": []
        },
        "type": "STRUCTURED",
        "deviceSupportedTypes": [
            "POLICY_ROUTES",
            "USERS"
        ],
        "devicePackGroupId": "com.fm.sm.dp.cisco-asa-context",
        "devicePackArtifactId": "cisco_pix_asa_fwsm_context",
        "requirementType": "RULE"
    }
    ]


def get_create_pp_ticket_payload():
    return {
        "variables": {
            "summary": "Request Test06",
            "businessNeed": "",
            "priority": "LOW",
            "dueDate": "2021-05-29 13:44:58",
            "applicationName": "",
            "customer": "",
            "externalTicketId": "",
            "notes": "",
            "requesterName": "System Administrator",
            "requesterEmail": "",
            "applicationOwner": "",
            "integrationRecord": "",
            "carbonCopy": [
                ""
            ]
        },
        "policyPlanRequirements": []
    }


class Client(BaseClient):
    def authenticate_user(self):
        username = demisto.params().get('credentials').get('identifier')
        password = demisto.params().get('credentials').get('password')

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        api_response = self._http_request(method='POST',
                                          url_suffix=AUTH_URL,
                                          json_data={'username': username, 'password': password},
                                          headers=headers
                                          )
        return api_response

    def get_all_workflow(self, auth_token, domain_id, parameters):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-FM-Auth-Token': auth_token
        }
        workflow_url = WORKFLOW_URL.format(domain_id)
        api_response = self._http_request(method='GET',
                                          url_suffix=workflow_url,
                                          params=parameters,
                                          headers=headers
                                          )
        list_of_workflow = []
        for workflow in api_response.get('results'):
            if workflow['workflow']['pluginArtifactId'] == "access-request":
                workflow_name = workflow['workflow']['name']
                list_of_workflow.append(workflow_name)

        return list_of_workflow

    def get_list_of_workflow(self, auth_token, domain_id, parameters):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-FM-Auth-Token': auth_token
        }
        workflow_url = WORKFLOW_URL.format(domain_id)
        api_response = self._http_request(method='GET',
                                          url_suffix=workflow_url,
                                          params=parameters,
                                          headers=headers
                                          )

        return api_response

    def get_workflow_id_by_workflow_name(self, domain_id, workflow_name, auth_token, parameters):

        list_of_workflow = self.get_list_of_workflow(auth_token, domain_id, parameters)
        count_of_workflow = list_of_workflow.get('total')

        if count_of_workflow > 10:
            parameters = {'includeDisabled': False, 'pageSize': count_of_workflow}
            list_of_workflow = self.get_list_of_workflow(auth_token, domain_id, parameters)

        for workflow in list_of_workflow.get('results'):
            if ((workflow['workflow']['pluginArtifactId'] == "access-request") and
                    (workflow['workflow']['name'] == workflow_name)):
                workflow_id = workflow['workflow']['id']
                return workflow_id

    def create_pp_ticket(self, auth_token, payload):
        parameters = {'includeDisabled': False, 'pageSize': 10}
        workflow_id = self.get_workflow_id_by_workflow_name(payload["domainId"], payload["workflowName"], auth_token,
                                                            parameters)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-FM-Auth-Token': auth_token
        }
        data = get_create_pp_ticket_payload()
        data["variables"]["priority"] = payload["priority"]
        data["variables"]["dueDate"] = payload["due_date"].replace('T', ' ')[:-6]
        list_of_requirements = payload["requirements"]
        for i in range(len(list_of_requirements)):
            req_payload = list_of_requirements[i]
            input_data = create_pp_payload
            input_data["sources"] = list(req_payload["sources"].split(","))
            input_data["destinations"] = list(req_payload["destinations"].split(","))
            input_data["services"] = list(req_payload["services"].split(","))
            input_data["action"] = req_payload["action"]
            data["policyPlanRequirements"].append(dict(input_data))

        create_pp_ticket_url = CREATE_PP_TICKET_URL.format(payload["domainId"], workflow_id)
        api_response = self._http_request(method='POST',
                                          url_suffix=create_pp_ticket_url,
                                          headers=headers,
                                          json_data=data
                                          )
        return api_response

    def validate_pca_change(self, payload_pca, pca_url_suffix, headers):
        api_response = self._http_request(method='POST',
                                          url_suffix=pca_url_suffix,
                                          json_data=payload_pca,
                                          headers=headers,
                                          params=None,
                                          timeout=20)
        return api_response

    def rule_rec_api(self, auth_token, payload):
        """ Calling orchestration rulerec api by passing json data as request body, headers, params and domainId
                which returns you list of rule recommendations for given input as response"""

        parameters = {'deviceGroupId': payload["deviceGroupId"], 'addressMatchingStrategy': 'INTERSECTS',
                      'modifyBehavior': 'MODIFY', 'strategy': None}
        data = get_rule_rec_request_payload()

        data["destinations"] = payload["destinations"]
        data["sources"] = payload["sources"]
        data["services"] = payload["services"]
        data["action"] = payload["action"]
        rule_rec_api_response = self._http_request(
            method='POST',
            url_suffix=RULE_REC_URL.format(payload["domainId"]),
            json_data=data,
            params=parameters,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-FM-Auth-Token': auth_token,
            }
        )
        return rule_rec_api_response

    def rule_rec_output(self, auth_token, payload):
        """ Calling orchestration rulerec api by passing json data as request body, headers, params and domainId
                which returns you list of rule recommendations for given input as response"""

        parameters = {'deviceId': payload["deviceId"], 'addressMatchingStrategy': 'INTERSECTS',
                      'modifyBehavior': 'MODIFY', 'strategy': None}
        data = get_rule_rec_request_payload()

        data["destinations"] = payload["destinations"]
        data["sources"] = payload["sources"]
        data["services"] = payload["services"]
        data["action"] = payload["action"]
        rule_rec_api_response = self._http_request(
            method='POST',
            url_suffix=RULE_REC_URL.format(payload["domainId"]),
            json_data=data,
            params=parameters,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-FM-Auth-Token': auth_token,
            }
        )
        return rule_rec_api_response


def test_module(client):
    """
     Performs basic get request to get item samples
     """
    response = client.authenticate_user()
    if response.get('authorized'):
        demisto.results("ok")
    else:
        demisto.results("Error in API call in FireMonSecurityManager Integrations")


def authenticate_command(client):
    result = client.authenticate_user().get('token')
    return result


def workflow_command(client, args):
    auth_token = authenticate_command(client)
    domain_id = args.get('domain_id')
    parameters = {'includeDisabled': False, 'pageSize': 10}
    result = client.get_all_workflow(auth_token, domain_id, parameters)
    results = ",".join(result)
    return results


def create_pp_ticket_command(client, args):
    auth_token = authenticate_command(client)

    payload = dict(domainId=args.get('domain_id'), workflowName=args.get('workflow_name'),
                   requirements=args.get("requirement"), priority=args.get("priority"),
                   due_date=args.get("due_date"))
    result = client.create_pp_ticket(auth_token, payload)
    return result


def pca_new_command(client, args):
    auth_token = authenticate_command(client)
    payload = dict(sources=list(args.get("sources").split(",")),
                   destinations=list(args.get('destinations').split(",")),
                   services=list(args.get('services').split(",")),
                   action=args.get('action'), domainId=args.get('domain_id'), deviceGroupId=args.get('device_group_id'))
    payload_rule_rec = client.rule_rec_api(auth_token, payload)
    result = {}
    list_of_device_changes = payload_rule_rec['deviceChanges']
    for i in range(len(list_of_device_changes)):
        filtered_rules = []
        list_of_rule_changes = list_of_device_changes[i]["ruleChanges"]
        device_id = list_of_device_changes[i]["deviceId"]
        headers = {'Content-Type': 'application/json',
                   'accept': 'application/json',
                   'X-FM-Auth-Token': auth_token}

        for j in range(len(list_of_rule_changes)):
            if list_of_rule_changes[j]['action'] != 'NONE':
                filtered_rules.append(list_of_rule_changes[j])

        if filtered_rules is None:
            return "No Rules Needs to be changed!"

        result[i] = client.validate_pca_change(filtered_rules,
                                               PCA_URL_SUFFIX.format(args.get('domain_id'), device_id),
                                               headers)
        del result[i]['requestId']
        del result[i]['pcaResult']['startDate']
        del result[i]['pcaResult']['endDate']
        del result[i]['pcaResult']['device']['parents']
        del result[i]['pcaResult']['device']['children']
        del result[i]['pcaResult']['device']['gpcDirtyDate']
        del result[i]['pcaResult']['device']['gpcComputeDate']
        del result[i]['pcaResult']['device']['gpcImplementDate']
        del result[i]['pcaResult']['device']['state']
        del result[i]['pcaResult']['device']['managedType']
        del result[i]['pcaResult']['device']['gpcStatus']
        del result[i]['pcaResult']['device']['updateMemberRuleDoc']
        del result[i]['pcaResult']['device']['devicePack']
        del result[i]['pcaResult']['affectedRules']

    return result


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    headers = {'Accept': 'application', 'Content-Type': 'application/json'}
    verify_certificate = not demisto.params().get('insecure', False)
    base_url = urljoin(demisto.params()['url'])
    proxy = demisto.params().get('proxy', False)
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'user-authentication':
            result = authenticate_command(client)
            demisto.results(result)
        elif demisto.command() == 'get-all-workflow':
            result = workflow_command(client, demisto.args())
            demisto.results(result)
        elif demisto.command() == 'create-pp-ticket':
            result = create_pp_ticket_command(client, demisto.args())
            demisto.results(result)
        elif demisto.command() == 'pca':
            result = pca_new_command(client, demisto.args())
            demisto.results(result)
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()