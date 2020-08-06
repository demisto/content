import f5_v2

MOCK_ADDR = 'https://fakeurl.com'

MOCK_POLICIES_RESPONSE = {
    "kind": "tm:asm:policies:policycollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies?kind=&selfLink=&ver=15.1.0",
    "totalItems": 2,
    "items": [
        {
            "plainTextProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/plain-text-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "enablePassiveMode": False,
            "behavioralEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/behavioral-enforcement?ver=15.1.0"
            },
            "dataGuardReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/data-guard?ver=15.1.0"
            },
            "createdDatetime": "2020-07-29T14:32:21Z",
            "databaseProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/database-protection?ver=15.1.0"
            },
            "cookieSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookie-settings?ver=15.1.0"
            },
            "csrfUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-urls?ver=15.1.0",
                "isSubCollection": True
            },
            "versionLastChange": "Cookie addedwithdem2 [delete] { audit: policy = /Common/Lior-test, username = admin, client IP = 192.168.30.99 }",
            "name": "Common_Lior-test_copy_2",
            "caseInsensitive": False,
            "headerSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/header-settings?ver=15.1.0"
            },
            "sectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sections?ver=15.1.0",
                "isSubCollection": True
            },
            "flowReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/flows?ver=15.1.0",
                "isSubCollection": True
            },
            "loginPageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "description": "Test stuff with the integration",
            "fullPath": "/Common/Common_Lior-test_copy_2",
            "policyBuilderParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-parameter?ver=15.1.0"
            },
            "hasParent": False,
            "threatCampaignReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaigns?ver=15.1.0",
                "isSubCollection": True
            },
            "partition": "Common",
            "managedByBewaf": False,
            "csrfProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-protection?ver=15.1.0"
            },
            "policyAntivirusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/antivirus?ver=15.1.0"
            },
            "kind": "tm:asm:policies:policystate",
            "virtualServers": [

            ],
            "policyBuilderCookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-cookie?ver=15.1.0"
            },
            "ipIntelligenceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/ip-intelligence?ver=15.1.0"
            },
            "protocolIndependent": False,
            "sessionAwarenessSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking?ver=15.1.0"
            },
            "policyBuilderUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-url?ver=15.1.0"
            },
            "policyBuilderServerTechnologiesReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-server-technologies?ver=15.1.0"
            },
            "policyBuilderFiletypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-filetype?ver=15.1.0"
            },
            "signatureSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-sets?ver=15.1.0",
                "isSubCollection": True
            },
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "loginEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-enforcement?ver=15.1.0"
            },
            "openApiFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/open-api-files?ver=15.1.0",
                "isSubCollection": True
            },
            "navigationParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/navigation-parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "gwtProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/gwt-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "webhookReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/webhooks?ver=15.1.0",
                "isSubCollection": True
            },
            "whitelistIpReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/whitelist-ips?ver=15.1.0",
                "isSubCollection": True
            },
            "historyRevisionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/history-revisions?ver=15.1.0",
                "isSubCollection": True
            },
            "policyBuilderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder?ver=15.1.0"
            },
            "responsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/response-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "vulnerabilityAssessmentReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerability-assessment?ver=15.1.0"
            },
            "serverTechnologyReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/server-technologies?ver=15.1.0",
                "isSubCollection": True
            },
            "cookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookies?ver=15.1.0",
                "isSubCollection": True
            },
            "blockingSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/blocking-settings?ver=15.1.0",
                "isSubCollection": True
            },
            "hostNameReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/host-names?ver=15.1.0",
                "isSubCollection": True
            },
            "versionDeviceName": "f5asm.qmasters.co",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA?ver=15.1.0",
            "threatCampaignSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaign-settings?ver"
                        "=15.1.0 "
            },
            "signatureReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signatures?ver=15.1.0",
                "isSubCollection": True
            },
            "policyBuilderRedirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-redirection-protection?ver=15.1.0"
            },
            "filetypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/filetypes?ver=15.1.0",
                "isSubCollection": True
            },
            "id": "RBPmYSOVvS8I3fPkkLGoZA",
            "modifierName": "",
            "manualVirtualServers": [

            ],
            "versionDatetime": "2020-07-29T12:54:41Z",
            "subPath": "/Common",
            "sessionTrackingStatusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking-statuses?ver=15.1.0",
                "isSubCollection": True
            },
            "active": False,
            "auditLogReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/audit-logs?ver=15.1.0",
                "isSubCollection": True
            },
            "disallowedGeolocationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disallowed-geolocations?ver=15.1.0",
                "isSubCollection": True
            },
            "redirectionProtectionDomainReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection-domains?ver=15.1.0",
                "isSubCollection": True
            },
            "type": "security",
            "signatureSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-settings?ver=15.1.0"
            },
            "deceptionResponsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-response-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "websocketUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/websocket-urls?ver=15.1.0",
                "isSubCollection": True
            },
            "xmlProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "methodReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/methods?ver=15.1.0",
                "isSubCollection": True
            },
            "vulnerabilityReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerabilities?ver=15.1.0",
                "isSubCollection": True
            },
            "redirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection?ver=15.1.0"
            },
            "policyBuilderSessionsAndLoginsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-sessions-and-logins?ver=15.1.0"
            },
            "templateReference": {
                "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw?ver=15.1.0",
                "title": "Fundamental"
            },
            "policyBuilderHeaderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-header?ver=15.1.0"
            },
            "creatorName": "admin",
            "urlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/urls?ver=15.1.0",
                "isSubCollection": True
            },
            "headerReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/headers?ver=15.1.0",
                "isSubCollection": True
            },
            "actionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/action-items?ver=15.1.0",
                "isSubCollection": True
            },
            "microserviceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/microservices?ver=15.1.0",
                "isSubCollection": True
            },
            "xmlValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-validation-files?ver=15.1.0",
                "isSubCollection": True
            },
            "lastUpdateMicros": 0,
            "jsonProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "bruteForceAttackPreventionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/brute-force-attack-preventions?ver=15.1.0",
                "isSubCollection": True
            },
            "disabledActionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disabled-action-items?ver=15.1.0",
                "isSubCollection": True
            },
            "jsonValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-validation-files?ver=15.1.0",
                "isSubCollection": True
            },
            "extractionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/extractions?ver=15.1.0",
                "isSubCollection": True
            },
            "characterSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/character-sets?ver=15.1.0",
                "isSubCollection": True
            },
            "suggestionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/suggestions?ver=15.1.0",
                "isSubCollection": True
            },
            "deceptionSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-settings?ver=15.1.0"
            },
            "isModified": False,
            "sensitiveParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sensitive-parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "generalReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/general?ver=15.1.0"
            },
            "versionPolicyName": "/Common/Lior-test",
            "policyBuilderCentralConfigurationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-central-configuration?ver=15.1.0"
            }
        },
        {
            "plainTextProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/plain-text-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "enablePassiveMode": False,
            "behavioralEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/behavioral-enforcement?ver=15.1.0"
            },
            "dataGuardReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/data-guard?ver=15.1.0"
            },
            "createdDatetime": "2020-07-29T14:32:20Z",
            "databaseProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/database-protection?ver=15.1.0"
            },
            "cookieSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/cookie-settings?ver=15.1.0"
            },
            "csrfUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/csrf-urls?ver=15.1.0",
                "isSubCollection": True
            },
            "versionLastChange": " Security Policy /Common/Ben [add]: Parent Policy was set to empty value.\nType was set to Security.\nEncoding Selected was set to true.\nApplication Language was set to utf-8.\nActive was set to false.\nPolicy Name was set to /Common/Ben. { audit: policy = /Common/Ben, component = tsconfd }",
            "name": "Common_Ben_copy_2",
            "caseInsensitive": False,
            "headerSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/header-settings?ver=15.1.0"
            },
            "sectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/sections?ver=15.1.0",
                "isSubCollection": True
            },
            "flowReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/flows?ver=15.1.0",
                "isSubCollection": True
            },
            "loginPageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/login-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "description": "Fundamental Policy",
            "fullPath": "/Common/Common_Ben_copy_2",
            "policyBuilderParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-parameter?ver=15.1.0"
            },
            "hasParent": False,
            "threatCampaignReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/threat-campaigns?ver=15.1.0",
                "isSubCollection": True
            },
            "partition": "Common",
            "managedByBewaf": False,
            "csrfProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/csrf-protection?ver=15.1.0"
            },
            "policyAntivirusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/antivirus?ver=15.1.0"
            },
            "kind": "tm:asm:policies:policystate",
            "virtualServers": [

            ],
            "policyBuilderCookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-cookie?ver=15.1.0"
            },
            "ipIntelligenceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/ip-intelligence?ver=15.1.0"
            },
            "protocolIndependent": False,
            "sessionAwarenessSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/session-tracking?ver=15.1.0"
            },
            "policyBuilderUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-url?ver=15.1.0"
            },
            "policyBuilderServerTechnologiesReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-server-technologies?ver=15.1.0"
            },
            "policyBuilderFiletypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-filetype?ver=15.1.0"
            },
            "signatureSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signature-sets?ver=15.1.0",
                "isSubCollection": True
            },
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "loginEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/login-enforcement?ver=15.1.0"
            },
            "openApiFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/open-api-files?ver=15.1.0",
                "isSubCollection": True
            },
            "navigationParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/navigation-parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "gwtProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/gwt-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "webhookReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/webhooks?ver=15.1.0",
                "isSubCollection": True
            },
            "whitelistIpReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/whitelist-ips?ver=15.1.0",
                "isSubCollection": True
            },
            "historyRevisionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/history-revisions?ver=15.1.0",
                "isSubCollection": True
            },
            "policyBuilderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder?ver=15.1.0"
            },
            "responsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/response-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "vulnerabilityAssessmentReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/vulnerability-assessment?ver=15.1.0"
            },
            "serverTechnologyReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/server-technologies?ver=15.1.0",
                "isSubCollection": True
            },
            "cookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/cookies?ver=15.1.0",
                "isSubCollection": True
            },
            "blockingSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/blocking-settings?ver=15.1.0",
                "isSubCollection": True
            },
            "hostNameReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/host-names?ver=15.1.0",
                "isSubCollection": True
            },
            "versionDeviceName": "f5asm.qmasters.co",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw?ver=15.1.0",
            "threatCampaignSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/threat-campaign-settings?ver=15.1.0"
            },
            "signatureReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signatures?ver=15.1.0",
                "isSubCollection": True
            },
            "policyBuilderRedirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-redirection-protection?ver=15.1.0"
            },
            "filetypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/filetypes?ver=15.1.0",
                "isSubCollection": True
            },
            "id": "Vn68Wl-lpt_XW0fVaYw6Hw",
            "modifierName": "",
            "manualVirtualServers": [

            ],
            "versionDatetime": "2020-07-02T21:09:26Z",
            "subPath": "/Common",
            "sessionTrackingStatusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/session-tracking-statuses?ver=15.1.0",
                "isSubCollection": True
            },
            "active": False,
            "auditLogReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/audit-logs?ver=15.1.0",
                "isSubCollection": True
            },
            "disallowedGeolocationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/disallowed-geolocations?ver=15.1.0",
                "isSubCollection": True
            },
            "redirectionProtectionDomainReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/redirection-protection-domains?ver=15.1.0",
                "isSubCollection": True
            },
            "type": "security",
            "signatureSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signature-settings?ver=15.1.0"
            },
            "deceptionResponsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/deception-response-pages?ver=15.1.0",
                "isSubCollection": True
            },
            "websocketUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/websocket-urls?ver=15.1.0",
                "isSubCollection": True
            },
            "xmlProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/xml-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "methodReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/methods?ver=15.1.0",
                "isSubCollection": True
            },
            "vulnerabilityReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/vulnerabilities?ver=15.1.0",
                "isSubCollection": True
            },
            "redirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/redirection-protection?ver=15.1.0"
            },
            "policyBuilderSessionsAndLoginsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-sessions-and-logins?ver=15.1.0"
            },
            "templateReference": {
                "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw?ver=15.1.0",
                "title": "Fundamental"
            },
            "policyBuilderHeaderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-header?ver=15.1.0"
            },
            "creatorName": "admin",
            "urlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/urls?ver=15.1.0",
                "isSubCollection": True
            },
            "headerReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/headers?ver=15.1.0",
                "isSubCollection": True
            },
            "actionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/action-items?ver=15.1.0",
                "isSubCollection": True
            },
            "microserviceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/microservices?ver=15.1.0",
                "isSubCollection": True
            },
            "xmlValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/xml-validation-files?ver=15.1.0",
                "isSubCollection": True
            },
            "lastUpdateMicros": 0,
            "jsonProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/json-profiles?ver=15.1.0",
                "isSubCollection": True
            },
            "bruteForceAttackPreventionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/brute-force-attack-preventions?ver=15.1.0",
                "isSubCollection": True
            },
            "disabledActionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/disabled-action-items?ver=15.1.0",
                "isSubCollection": True
            },
            "jsonValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/json-validation-files?ver=15.1.0",
                "isSubCollection": True
            },
            "extractionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/extractions?ver=15.1.0",
                "isSubCollection": True
            },
            "characterSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/character-sets?ver=15.1.0",
                "isSubCollection": True
            },
            "suggestionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/suggestions?ver=15.1.0",
                "isSubCollection": True
            },
            "deceptionSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/deception-settings?ver=15.1.0"
            },
            "isModified": False,
            "sensitiveParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/sensitive-parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "generalReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/general?ver=15.1.0"
            },
            "versionPolicyName": "/Common/Ben",
            "policyBuilderCentralConfigurationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-central-configuration?ver=15.1.0"
            }
        },
    ]
}

MOCK_POLICY_RESPONSE = {
    "plainTextProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/plain-text-profiles?ver=15.1.0",
        "isSubCollection": True
    },
    "behavioralEnforcementReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/behavioral-enforcement?ver=15.1.0"
    },
    "dataGuardReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/data-guard?ver=15.1.0"
    },
    "createdDatetime": "2020-07-29T14:32:21Z",
    "databaseProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/database-protection?ver=15.1.0"
    },
    "cookieSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookie-settings?ver=15.1.0"
    },
    "csrfUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-urls?ver=15.1.0",
        "isSubCollection": True
    },
    "versionLastChange": "Cookie addedwithdem2 [delete] { audit: policy = /Common/Lior-test, username = admin, client IP = 192.168.30.99 }",
    "name": "Common_Lior-test_copy_2",
    "caseInsensitive": False,
    "headerSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/header-settings?ver=15.1.0"
    },
    "sectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sections?ver=15.1.0",
        "isSubCollection": True
    },
    "flowReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/flows?ver=15.1.0",
        "isSubCollection": True
    },
    "loginPageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-pages?ver=15.1.0",
        "isSubCollection": True
    },
    "description": "Test stuff with the integration",
    "fullPath": "/Common/Common_Lior-test_copy_2",
    "policyBuilderParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-parameter?ver=15.1.0"
    },
    "threatCampaignReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaigns?ver=15.1.0",
        "isSubCollection": True
    },
    "partition": "Common",
    "managedByBewaf": False,
    "csrfProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-protection?ver=15.1.0"
    },
    "policyAntivirusReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/antivirus?ver=15.1.0"
    },
    "kind": "tm:asm:policies:policystate",
    "policyBuilderCookieReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-cookie?ver=15.1.0"
    },
    "ipIntelligenceReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/ip-intelligence?ver=15.1.0"
    },
    "protocolIndependent": False,
    "sessionAwarenessSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking?ver=15.1.0"
    },
    "policyBuilderUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-url?ver=15.1.0"
    },
    "policyBuilderServerTechnologiesReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-server-technologies?ver=15.1.0"
    },
    "policyBuilderFiletypeReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-filetype?ver=15.1.0"
    },
    "signatureSetReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-sets?ver=15.1.0",
        "isSubCollection": True
    },
    "parameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/parameters?ver=15.1.0",
        "isSubCollection": True
    },
    "applicationLanguage": "utf-8",
    "loginEnforcementReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-enforcement?ver=15.1.0"
    },
    "openApiFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/open-api-files?ver=15.1.0",
        "isSubCollection": True
    },
    "navigationParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/navigation-parameters?ver=15.1.0",
        "isSubCollection": True
    },
    "gwtProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/gwt-profiles?ver=15.1.0",
        "isSubCollection": True
    },
    "webhookReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/webhooks?ver=15.1.0",
        "isSubCollection": True
    },
    "whitelistIpReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/whitelist-ips?ver=15.1.0",
        "isSubCollection": True
    },
    "historyRevisionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/history-revisions?ver=15.1.0",
        "isSubCollection": True
    },
    "policyBuilderReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder?ver=15.1.0"
    },
    "responsePageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/response-pages?ver=15.1.0",
        "isSubCollection": True
    },
    "vulnerabilityAssessmentReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerability-assessment?ver=15.1.0"
    },
    "serverTechnologyReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/server-technologies?ver=15.1.0",
        "isSubCollection": True
    },
    "cookieReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookies?ver=15.1.0",
        "isSubCollection": True
    },
    "blockingSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/blocking-settings?ver=15.1.0",
        "isSubCollection": True
    },
    "hostNameReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/host-names?ver=15.1.0",
        "isSubCollection": True
    },
    "versionDeviceName": "f5asm.qmasters.co",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA?ver=15.1.0",
    "threatCampaignSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaign-settings?ver=15.1.0"
    },
    "signatureReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signatures?ver=15.1.0",
        "isSubCollection": True
    },
    "policyBuilderRedirectionProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-redirection-protection?ver=15.1.0"
    },
    "filetypeReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/filetypes?ver=15.1.0",
        "isSubCollection": True
    },
    "id": "RBPmYSOVvS8I3fPkkLGoZA",
    "modifierName": "",
    "versionDatetime": "2020-07-29T12:54:41Z",
    "subPath": "/Common",
    "sessionTrackingStatusReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking-statuses?ver=15.1.0",
        "isSubCollection": True
    },
    "auditLogReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/audit-logs?ver=15.1.0",
        "isSubCollection": True
    },
    "disallowedGeolocationReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disallowed-geolocations?ver=15.1.0",
        "isSubCollection": True
    },
    "redirectionProtectionDomainReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection-domains?ver=15.1.0",
        "isSubCollection": True
    },
    "signatureSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-settings?ver=15.1.0"
    },
    "deceptionResponsePageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-response-pages?ver=15.1.0",
        "isSubCollection": True
    },
    "websocketUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/websocket-urls?ver=15.1.0",
        "isSubCollection": True
    },
    "xmlProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-profiles?ver=15.1.0",
        "isSubCollection": True
    },
    "methodReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/methods?ver=15.1.0",
        "isSubCollection": True
    },
    "vulnerabilityReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerabilities?ver=15.1.0",
        "isSubCollection": True
    },
    "redirectionProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection?ver=15.1.0"
    },
    "policyBuilderSessionsAndLoginsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-sessions-and-logins?ver=15.1.0"
    },
    "templateReference": {
        "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw?ver=15.1.0",
        "title": "Fundamental"
    },
    "policyBuilderHeaderReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-header?ver=15.1.0"
    },
    "creatorName": "admin",
    "urlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/urls?ver=15.1.0",
        "isSubCollection": True
    },
    "headerReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/headers?ver=15.1.0",
        "isSubCollection": True
    },
    "actionItemReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/action-items?ver=15.1.0",
        "isSubCollection": True
    },
    "microserviceReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/microservices?ver=15.1.0",
        "isSubCollection": True
    },
    "xmlValidationFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-validation-files?ver=15.1.0",
        "isSubCollection": True
    },
    "lastUpdateMicros": 0,
    "jsonProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-profiles?ver=15.1.0",
        "isSubCollection": True
    },
    "bruteForceAttackPreventionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/brute-force-attack-preventions?ver=15.1.0",
        "isSubCollection": True
    },
    "disabledActionItemReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disabled-action-items?ver=15.1.0",
        "isSubCollection": True
    },
    "jsonValidationFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-validation-files?ver=15.1.0",
        "isSubCollection": True
    },
    "extractionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/extractions?ver=15.1.0",
        "isSubCollection": True
    },
    "characterSetReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/character-sets?ver=15.1.0",
        "isSubCollection": True
    },
    "suggestionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/suggestions?ver=15.1.0",
        "isSubCollection": True
    },
    "deceptionSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-settings?ver=15.1.0"
    },
    "isModified": False,
    "sensitiveParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sensitive-parameters?ver=15.1.0",
        "isSubCollection": True
    },
    "generalReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/general?ver=15.1.0"
    },
    "versionPolicyName": "/Common/Lior-test",
    "policyBuilderCentralConfigurationReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-central-configuration?ver=15.1.0"
    }
}

MOCK_METHODS_RESPONSE = {
    "kind": "tm:asm:policies:methods:methodcollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods?ver=15.1.0",
    "totalItems": 3,
    "items": [
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0",
            "name": "HEAD",
            "id": "4V4hb8HGOfeHsSMezfob-A",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "GET"
        },
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0",
            "name": "POST",
            "id": "oCQ57CKdi-DnSwwWAjkjEA",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "POST"
        },
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0",
            "name": "GET",
            "id": "dSgDWpPuac7bHb3bLwv8yA",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "GET"
        }
    ]
}

MOCK_METHOD_RESPONSE = {
    "kind": "tm:asm:policies:methods:methodstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0",
    "name": "HEAD",
    "id": "4V4hb8HGOfeHsSMezfob-A",
    "lastUpdateMicros": 1595858789000000.0,
    "actAsMethod": "GET"
}

MOCK_FILETYPES_RESPONSE = {
    "kind": "tm:asm:policies:filetypes:filetypecollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes?ver=15.1.0",
    "totalItems": 7,
    "items": [
        {
            "queryStringLength": 100,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/jOSxayK1iJSqhsQh6HWd8w?ver=15.1.0",
            "responseCheck": True,
            "id": "jOSxayK1iJSqhsQh6HWd8w",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 100,
            "name": "k",
            "lastUpdateMicros": 1596047467000000.0,
            "allowed": True,
            "performStaging": False,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 100,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/UmE3F3NrBhFPQhJAKqrVsQ?ver=15.1.0",
            "responseCheck": True,
            "id": "UmE3F3NrBhFPQhJAKqrVsQ",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 100,
            "name": "liill",
            "lastUpdateMicros": 1596047434000000.0,
            "allowed": True,
            "performStaging": False,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 150,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/Rt7-hEtwIk-ItPhYLUwVgA?ver=15.1.0",
            "responseCheck": True,
            "id": "Rt7-hEtwIk-ItPhYLUwVgA",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 100,
            "name": "liil",
            "lastUpdateMicros": 1596047968000000.0,
            "allowed": True,
            "performStaging": False,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 100,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0",
            "responseCheck": True,
            "id": "mOgzedRVODecKsTkfDvoHQ",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 100,
            "name": "exe",
            "lastUpdateMicros": 1596046945000000.0,
            "allowed": True,
            "performStaging": False,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 100,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/Uvs2ebB-t02QeE5hLKXLMA?ver=15.1.0",
            "responseCheck": True,
            "id": "Uvs2ebB-t02QeE5hLKXLMA",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 100,
            "name": "exec",
            "lastUpdateMicros": 1596046786000000.0,
            "allowed": True,
            "performStaging": False,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 1000,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/4b_XYjIeQJzuSsC26EGWPA?ver=15.1.0",
            "responseCheck": False,
            "id": "4b_XYjIeQJzuSsC26EGWPA",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 1000,
            "name": "php",
            "lastUpdateMicros": 1595944147000000.0,
            "allowed": True,
            "performStaging": True,
            "type": "explicit",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "urlLength": 100
        },
        {
            "queryStringLength": 1000,
            "lastLearnedNewEntityDatetime": "2020-07-27T14:06:29Z",
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
            "responseCheck": False,
            "id": "M4na42GvebBMnI5wV_YMxg",
            "checkRequestLength": True,
            "checkUrlLength": True,
            "postDataLength": 1000,
            "name": "*",
            "lastUpdateMicros": 1595858789000000.0,
            "allowed": True,
            "performStaging": True,
            "type": "wildcard",
            "requestLength": 5000,
            "checkQueryStringLength": True,
            "wildcardOrder": 1,
            "urlLength": 100
        }
    ]
}

MOCK_FILETYPE_RESPONSE = {
    "queryStringLength": 100,
    "checkPostDataLength": True,
    "kind": "tm:asm:policies:filetypes:filetypestate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/UmE3F3NrBhFPQhJAKqrVsQ?ver=15.1.0",
    "responseCheck": True,
    "id": "UmE3F3NrBhFPQhJAKqrVsQ",
    "checkRequestLength": True,
    "checkUrlLength": True,
    "postDataLength": 100,
    "name": "liill",
    "lastUpdateMicros": 1596047434000000.0,
    "allowed": True,
    "performStaging": False,
    "type": "explicit",
    "requestLength": 5000,
    "checkQueryStringLength": True,
    "urlLength": 100
}

MOCK_HOSTNAMES_RESPONSE = {
    "kind": "tm:asm:policies:host-names:host-namecollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names?ver=15.1.0",
    "totalItems": 4,
    "items": [
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/kmAEvvvYg0o2GmIf_YfRBw?ver=15.1.0",
            "createdBy": "GUI",
            "name": "shouldbefalse",
            "includeSubdomains": False,
            "id": "kmAEvvvYg0o2GmIf_YfRBw",
            "lastUpdateMicros": 1596015158000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/zgVRLeLapyPniyp0aOuBRQ?ver=15.1.0",
            "createdBy": "GUI",
            "name": "shouldbetrue",
            "includeSubdomains": True,
            "id": "zgVRLeLapyPniyp0aOuBRQ",
            "lastUpdateMicros": 1596015136000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/-ZQ04K98JlqNCxjp0aLMjw?ver=15.1.0",
            "createdBy": "GUI",
            "name": "anothertest.net",
            "includeSubdomains": True,
            "id": "-ZQ04K98JlqNCxjp0aLMjw",
            "lastUpdateMicros": 1595931522000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/PSPPdjNO_C4mqEC1UApi7w?ver=15.1.0",
            "createdBy": "GUI",
            "name": "liortest.com",
            "includeSubdomains": False,
            "id": "PSPPdjNO_C4mqEC1UApi7w",
            "lastUpdateMicros": 1595931405000000.0
        }
    ]
}

MOCK_HOSTNAME_RESPONSE = {
    "kind": "tm:asm:policies:host-names:host-namestate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/Kqz46FpEkkzZtA4gKMSmiA?ver=15.1.0",
    "createdBy": "GUI",
    "name": "mockexample.com",
    "includeSubdomains": False,
    "id": "Kqz46FpEkkzZtA4gKMSmiA",
    "lastUpdateMicros": 1596044537000000.0
}

MOCK_BLOCKING_SETTINGS_LIST_RESPONSE = {
    "kind": "tm:asm:policies:blocking-settings:evasions:evasioncollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions?ver=15.1.0",
    "totalItems": 8,
    "items": [
        {
            "lastUpdateMicros": 1595950127000000.0,
            "description": "Bad unescape",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
            },
            "id": "9--k-GSum4jUNSf0sU91Dw",
            "learn": True,
            "enabled": True
        },
        {
            "lastUpdateMicros": 1596018724000000.0,
            "description": "Apache whitespace",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0"
            },
            "id": "Ahu8fuILcRNNU-ICBr1v6w",
            "learn": False,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595937781000000.0,
            "description": "Bare byte decoding",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0"
            },
            "id": "EKfN2XD-E1z097tVwOO1nw",
            "learn": False,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "IIS Unicode codepoints",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0"
            },
            "id": "dtxhHW66r8ZswIeccbXbXA",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595930400000000.0,
            "description": "IIS backslashes",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0"
            },
            "id": "6l0vHEYIIy4H06o9mY5RNQ",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "%u decoding",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0"
            },
            "id": "Y2TT8PSVtqudz407XG4LAQ",
            "learn": True,
            "enabled": False
        },
        {
            "maxDecodingPasses": 3,
            "lastUpdateMicros": 1595858790000000.0,
            "description": "Multiple decoding",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0"
            },
            "id": "x02XsB6uJX5Eqp1brel7rw",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "Directory traversals",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0"
            },
            "id": "qH_2eaLz5x2RgaZ7dUISLA",
            "learn": True,
            "enabled": False
        }
    ]
}

MOCK_BLOCKING_SETTINGS_SINGLE_RESPONSE = {
    "lastUpdateMicros": 1596044721000000.0,
    "description": "Bad unescape",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0",
    "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
    "evasionReference": {
        "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
    },
    "id": "9--k-GSum4jUNSf0sU91Dw",
    "learn": False,
    "enabled": True
}

MOCK_URLS_RESPONSE = {
    "kind": "tm:asm:policies:urls:urlcollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls?ver=15.1.0",
    "totalItems": 7,
    "items": [
        {
            "protocol": "http",
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/t_-2ylPgDTYcBwNSEjsOOA?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "GET",
            "id": "t_-2ylPgDTYcBwNSEjsOOA",
            "mandatoryBody": False,
            "isAllowed": True,
            "flowsToThisUrlCheck": False,
            "name": "/someweirdmethodthingy",
            "lastUpdateMicros": 1595954238000000.0,
            "description": "",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/t_-2ylPgDTYcBwNSEjsOOA/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "type": "explicit",
            "performStaging": False,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ]
        },
        {
            "protocol": "http",
            "flowsToThisUrlCheck": False,
            "isAllowed": False,
            "createdBy": "GUI",
            "name": "/bingbongdingdong",
            "lastUpdateMicros": 1595950984000000.0,
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eB9iX0sb1ASAosn6ENepBA?ver=15.1.0",
            "inClassification": False,
            "method": "*",
            "type": "explicit",
            "id": "eB9iX0sb1ASAosn6ENepBA",
            "mandatoryBody": False
        },
        {
            "protocol": "http",
            "wildcardIncludesSlash": True,
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/DOua8EHU3Cc8sBU35TNfoQ?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "*",
            "id": "DOua8EHU3Cc8sBU35TNfoQ",
            "mandatoryBody": False,
            "isAllowed": True,
            "metacharsOnUrlCheck": False,
            "name": "/wildcard",
            "positionalParameters": [

            ],
            "lastUpdateMicros": 1595948767000000.0,
            "description": "",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/DOua8EHU3Cc8sBU35TNfoQ/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ],
            "type": "wildcard",
            "performStaging": False,
            "wildcardOrder": 1
        },
        {
            "protocol": "https",
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/wrB7PkQ65vOvOaYBsAm5Uw?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "*",
            "id": "wrB7PkQ65vOvOaYBsAm5Uw",
            "mandatoryBody": False,
            "isAllowed": True,
            "flowsToThisUrlCheck": False,
            "name": "/noslash",
            "lastUpdateMicros": 1595947917000000.0,
            "description": "",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/wrB7PkQ65vOvOaYBsAm5Uw/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "type": "explicit",
            "performStaging": False,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ]
        },
        {
            "protocol": "http",
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/SyQB1OuN4pwy9D2B0P42Gw?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "*",
            "id": "SyQB1OuN4pwy9D2B0P42Gw",
            "mandatoryBody": True,
            "isEntryPoint": True,
            "isAllowed": True,
            "flowsToThisUrlCheck": True,
            "name": "/what.php",
            "lastUpdateMicros": 1595953472000000.0,
            "description": "again",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/SyQB1OuN4pwy9D2B0P42Gw/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "type": "explicit",
            "performStaging": True,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ],
            "urlIsReferrer": False
        },
        {
            "protocol": "http",
            "wildcardIncludesSlash": True,
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "*",
            "id": "faiefv884qtHRU3Qva2AbQ",
            "mandatoryBody": False,
            "isAllowed": True,
            "metacharsOnUrlCheck": False,
            "name": "*",
            "positionalParameters": [

            ],
            "lastUpdateMicros": 1595948879000000.0,
            "description": "",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/faiefv884qtHRU3Qva2AbQ/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ],
            "type": "wildcard",
            "performStaging": False,
            "wildcardOrder": 3
        },
        {
            "protocol": "https",
            "wildcardIncludesSlash": True,
            "createdBy": "GUI",
            "dynamicFlows": [

            ],
            "html5CrossOriginRequestsEnforcement": {
                "enforcementMode": "disabled"
            },
            "kind": "tm:asm:policies:urls:urlstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0",
            "inClassification": False,
            "methodsOverrideOnUrlCheck": False,
            "method": "*",
            "id": "N_a3D1S7OKDehYEPb-mgCg",
            "mandatoryBody": False,
            "isAllowed": True,
            "metacharsOnUrlCheck": False,
            "name": "*",
            "positionalParameters": [

            ],
            "lastUpdateMicros": 1595938285000000.0,
            "description": "",
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/N_a3D1S7OKDehYEPb-mgCg/parameters?ver=15.1.0",
                "isSubCollection": True
            },
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "clickjackingProtection": False,
            "urlContentProfiles": [
                {
                    "headerValue": "*",
                    "headerName": "*",
                    "headerOrder": "default",
                    "type": "apply-value-and-content-signatures"
                },
                {
                    "headerValue": "*form*",
                    "headerName": "Content-Type",
                    "headerOrder": "1",
                    "type": "form-data"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                        "name": "Default"
                    },
                    "headerValue": "*xml*",
                    "headerName": "Content-Type",
                    "headerOrder": "3",
                    "type": "xml"
                }
            ],
            "type": "wildcard",
            "performStaging": False,
            "wildcardOrder": 2
        }
    ]
}

MOCK_URL_RESPONSE = {
    "protocol": "https",
    "createdBy": "GUI",
    "dynamicFlows": [

    ],
    "html5CrossOriginRequestsEnforcement": {
        "enforcementMode": "disabled"
    },
    "kind": "tm:asm:policies:urls:urlstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eJxT4ThwaDSqmvcR0hFghQ?ver=15.1.0",
    "inClassification": False,
    "methodsOverrideOnUrlCheck": False,
    "method": "*",
    "id": "eJxT4ThwaDSqmvcR0hFghQ",
    "mandatoryBody": False,
    "isAllowed": True,
    "flowsToThisUrlCheck": False,
    "name": "/mockexample",
    "lastUpdateMicros": 1596044883000000.0,
    "description": "",
    "parameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eJxT4ThwaDSqmvcR0hFghQ/parameters?ver=15.1.0",
        "isSubCollection": True
    },
    "attackSignaturesCheck": True,
    "signatureOverrides": [

    ],
    "clickjackingProtection": False,
    "type": "explicit",
    "performStaging": False,
    "urlContentProfiles": [
        {
            "headerValue": "*",
            "headerName": "*",
            "headerOrder": "default",
            "type": "apply-value-and-content-signatures"
        },
        {
            "headerValue": "*form*",
            "headerName": "Content-Type",
            "headerOrder": "1",
            "type": "form-data"
        },
        {
            "contentProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
                "name": "Default"
            },
            "headerValue": "*json*",
            "headerName": "Content-Type",
            "headerOrder": "2",
            "type": "json"
        },
        {
            "contentProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                "name": "Default"
            },
            "headerValue": "*xml*",
            "headerName": "Content-Type",
            "headerOrder": "3",
            "type": "xml"
        }
    ]
}

MOCK_COOKIES_RESPONSE = {
    "kind": "tm:asm:policies:cookies:cookiecollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies?ver=15.1.0",
    "totalItems": 4,
    "items": [
        {
            "isBase64": False,
            "createdBy": "GUI",
            "accessibleOnlyThroughTheHttpProtocol": False,
            "kind": "tm:asm:policies:cookies:cookiestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0",
            "securedOverHttpsConnection": False,
            "id": "HeC08NE594GztN6H7bTecA",
            "maskValueInLogs": False,
            "name": "yum",
            "insertSameSiteAttribute": "none",
            "lastUpdateMicros": 1596048372000000.0,
            "enforcementType": "allow",
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "performStaging": False,
            "type": "explicit"
        },
        {
            "isBase64": False,
            "createdBy": "GUI",
            "accessibleOnlyThroughTheHttpProtocol": False,
            "kind": "tm:asm:policies:cookies:cookiestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0",
            "securedOverHttpsConnection": False,
            "id": "E1g7FVU2CYuY30F-Rp_MUw",
            "maskValueInLogs": False,
            "name": "yummy",
            "insertSameSiteAttribute": "none",
            "lastUpdateMicros": 1596045814000000.0,
            "enforcementType": "allow",
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "performStaging": False,
            "type": "explicit"
        },
        {
            "isBase64": False,
            "createdBy": "GUI",
            "accessibleOnlyThroughTheHttpProtocol": True,
            "kind": "tm:asm:policies:cookies:cookiestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/Q_h8jkEsc0YYCWdkctKqQw?ver=15.1.0",
            "securedOverHttpsConnection": True,
            "id": "Q_h8jkEsc0YYCWdkctKqQw",
            "maskValueInLogs": True,
            "name": "addedwithdem",
            "insertSameSiteAttribute": "strict",
            "lastUpdateMicros": 1596026066000000.0,
            "enforcementType": "allow",
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "performStaging": True,
            "type": "explicit"
        },
        {
            "isBase64": False,
            "createdBy": "GUI",
            "lastLearnedNewEntityDatetime": "2020-07-27T14:06:29Z",
            "accessibleOnlyThroughTheHttpProtocol": False,
            "kind": "tm:asm:policies:cookies:cookiestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
            "securedOverHttpsConnection": False,
            "id": "M4na42GvebBMnI5wV_YMxg",
            "maskValueInLogs": False,
            "name": "*",
            "insertSameSiteAttribute": "none",
            "lastUpdateMicros": 1595858789000000.0,
            "enforcementType": "allow",
            "attackSignaturesCheck": True,
            "signatureOverrides": [

            ],
            "performStaging": True,
            "type": "wildcard",
            "wildcardOrder": 2
        }
    ]
}

MOCK_COOKIE_RESPONSE = {
    "isBase64": False,
    "createdBy": "GUI",
    "accessibleOnlyThroughTheHttpProtocol": True,
    "kind": "tm:asm:policies:cookies:cookiestate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/Q_h8jkEsc0YYCWdkctKqQw?ver=15.1.0",
    "securedOverHttpsConnection": True,
    "id": "Q_h8jkEsc0YYCWdkctKqQw",
    "maskValueInLogs": True,
    "name": "addedwithdem",
    "insertSameSiteAttribute": "strict",
    "lastUpdateMicros": 1596026066000000.0,
    "enforcementType": "allow",
    "attackSignaturesCheck": True,
    "signatureOverrides": [

    ],
    "performStaging": True,
    "type": "explicit"
}

MOCK_EMPTY_RESPONSE = {"kind": "tm:asm:policies:host-names:host-namecollectionstate",
                       "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names?ver=15.1.0",
                       "totalItems": 0,
                       "items": []
                       }


def test_format_list_policies():
    _, outputs, _ = f5_v2.format_policy_hostnames_command(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policies(MOCK_POLICIES_RESPONSE)
    assert len(outputs['f5.ListPolicies(val.uid && val.uid == obj.uid)']) == 2


def test_format_delete_policy():
    _, outputs, _ = f5_v2.format_delete_policy(MOCK_POLICY_RESPONSE)
    assert len(outputs['f5.delete-policy(val.uid && val.uid == obj.uid)']) == 3


def test_format_list_policy():
    _, outputs, _ = f5_v2.format_list_policy_methods(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_methods(MOCK_METHODS_RESPONSE)
    assert len(outputs['f5.PolicyMethods(val.uid && val.uid == obj.uid)']) == 3


def test_format_policy_methods_command():
    _, outputs, _ = f5_v2.format_policy_methods_command(MOCK_METHOD_RESPONSE)
    assert len(outputs['f5.PolicyMethods(val.uid && val.uid == obj.uid)']) == 5


def test_format_list_policy_file_type():
    _, outputs, _ = f5_v2.format_list_policy_file_type(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_file_type(MOCK_FILETYPES_RESPONSE)
    assert len(outputs['f5.FileTypes(val.uid && val.uid == obj.uid)']) == 7


def test_format_file_type_command():
    _, outputs, _ = f5_v2.format_file_type_command(MOCK_FILETYPE_RESPONSE)
    assert len(outputs['f5.FileType(val.uid && val.uid == obj.uid)']) == 12


def test_format_list_policy_cookies():
    _, outputs, _ = f5_v2.format_list_cookies(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_cookies(MOCK_COOKIES_RESPONSE)
    assert len(outputs['f5.Cookies(val.uid && val.uid == obj.uid)']) == 4


def test_format_cookies_command():
    _, outputs, _ = f5_v2.format_cookies_command(MOCK_COOKIE_RESPONSE, 'policy-cookies')
    assert len(outputs['f5.Cookies(val.uid && val.uid == obj.uid)']) == 8


def test_format_policy_hostnames_command():
    _, outputs, _ = f5_v2.format_policy_hostnames_command(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_policy_hostnames_command(MOCK_HOSTNAMES_RESPONSE)
    assert len(outputs['f5.Hostname(val.uid && val.uid == obj.uid)']) == 4


def test_format_policy_hostname_command():
    _, outputs, _ = f5_v2.format_policy_hostname_command(MOCK_HOSTNAME_RESPONSE)
    assert len(outputs['f5.Hostname(val.uid && val.uid == obj.uid)']) == 6


def test_format_policy_blocking_settings_list_command():
    _, outputs, _ = f5_v2.format_policy_blocking_settings_list_command(
        MOCK_EMPTY_RESPONSE, 'evasions')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_policy_blocking_settings_list_command(
        MOCK_BLOCKING_SETTINGS_LIST_RESPONSE, 'evasions')
    assert len(outputs['f5.BlockingSettings(val.uid && val.uid == obj.uid)']) == 8


def test_format_policy_blocking_settings_single_command():
    _, outputs, _ = f5_v2.format_policy_blocking_settings_single_command(
        MOCK_BLOCKING_SETTINGS_SINGLE_RESPONSE, 'evasions')
    print(outputs['f5.BlockingSettings(val.uid && val.uid == obj.uid)'])
    assert len(outputs['f5.BlockingSettings(val.uid && val.uid == obj.uid)']) == 10


def test_format_policy_urls_command():
    _, outputs, _ = f5_v2.format_list_policy_urls_command(MOCK_EMPTY_RESPONSE)
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_urls_command(MOCK_URLS_RESPONSE)
    assert len(outputs['f5.Url(val.uid && val.uid == obj.uid)']) == 7


def test_format_policy_url_command():
    _, outputs, _ = f5_v2.format_policy_url_command(MOCK_URL_RESPONSE)
    assert len(outputs['f5.Url(val.uid && val.uid == obj.uid)']) == 12


def test_format_date():
    micros = 1596026066000000.0
    assert f5_v2.format_date(micros) == '2020-07-29T15:34:26Z'
    micros = 0
    assert f5_v2.format_date(micros) == '1970-01-01T02:00:00Z'
