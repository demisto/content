import f5_v2


MOCK_ADDR = 'https://fakeurl.com'

MOCK_POLICIES_RESPONSE = {
    "kind": "tm:asm:policies:policycollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies?kind=&selfLink=&ver=15.1.0",
    "totalItems": 2,
    "items": [
        {
            "plainTextProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/plain-text-profiles",
                "isSubCollection": True
            },
            "enablePassiveMode": False,
            "behavioralEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/behavioral-enforcement"
            },
            "dataGuardReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/data-guard"
            },
            "createdDatetime": "2020-07-29T14:32:21Z",
            "databaseProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/database-protection"
            },
            "cookieSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookie-settings"
            },
            "csrfUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-urls",
                "isSubCollection": True
            },
            "versionLastChange": "Cookie addedwithdem2 [delete] { audit: policy = /Common/Test_Policy, "
                                 "username = admin, client IP = 192.168.30.99 }",
            "name": "Test_Policy",
            "caseInsensitive": False,
            "headerSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/header-settings"
            },
            "sectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sections",
                "isSubCollection": True
            },
            "flowReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/flows",
                "isSubCollection": True
            },
            "loginPageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-pages",
                "isSubCollection": True
            },
            "description": "Test stuff with the integration",
            "fullPath": "/Common/Test_Policy",
            "policyBuilderParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-parameter"
            },
            "hasParent": False,
            "threatCampaignReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaigns",
                "isSubCollection": True
            },
            "partition": "Common",
            "managedByBewaf": False,
            "csrfProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-protection"
            },
            "policyAntivirusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/antivirus"
            },
            "kind": "tm:asm:policies:policystate",
            "virtualServers": [

            ],
            "policyBuilderCookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-cookie"
            },
            "ipIntelligenceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/ip-intelligence"
            },
            "protocolIndependent": False,
            "sessionAwarenessSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking"
            },
            "policyBuilderUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-url"
            },
            "policyBuilderServerTechnologiesReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-server-technologies"
            },
            "policyBuilderFiletypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-filetype"
            },
            "signatureSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-sets",
                "isSubCollection": True
            },
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/parameters",
                "isSubCollection": True
            },
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "loginEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-enforcement"
            },
            "openApiFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/open-api-files",
                "isSubCollection": True
            },
            "navigationParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/navigation-parameters",
                "isSubCollection": True
            },
            "gwtProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/gwt-profiles",
                "isSubCollection": True
            },
            "webhookReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/webhooks",
                "isSubCollection": True
            },
            "whitelistIpReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/whitelist-ips",
                "isSubCollection": True
            },
            "historyRevisionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/history-revisions",
                "isSubCollection": True
            },
            "policyBuilderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder"
            },
            "responsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/response-pages",
                "isSubCollection": True
            },
            "vulnerabilityAssessmentReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerability-assessment"
            },
            "serverTechnologyReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/server-technologies",
                "isSubCollection": True
            },
            "cookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookies",
                "isSubCollection": True
            },
            "blockingSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/blocking-settings",
                "isSubCollection": True
            },
            "hostNameReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/host-names",
                "isSubCollection": True
            },
            "versionDeviceName": "f5asm.qmasters.co",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA",
            "threatCampaignSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaign-settings?ver"
                        "=15.1.0 "
            },
            "signatureReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signatures",
                "isSubCollection": True
            },
            "policyBuilderRedirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-redirection-protection"
            },
            "filetypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/filetypes",
                "isSubCollection": True
            },
            "id": "RBPmYSOVvS8I3fPkkLGoZA",
            "modifierName": "",
            "manualVirtualServers": [

            ],
            "versionDatetime": "2020-07-29T12:54:41Z",
            "subPath": "/Common",
            "sessionTrackingStatusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking-statuses",
                "isSubCollection": True
            },
            "active": False,
            "auditLogReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/audit-logs",
                "isSubCollection": True
            },
            "disallowedGeolocationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disallowed-geolocations",
                "isSubCollection": True
            },
            "redirectionProtectionDomainReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection-domains",
                "isSubCollection": True
            },
            "type": "security",
            "signatureSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-settings"
            },
            "deceptionResponsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-response-pages",
                "isSubCollection": True
            },
            "websocketUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/websocket-urls",
                "isSubCollection": True
            },
            "xmlProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-profiles",
                "isSubCollection": True
            },
            "methodReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/methods",
                "isSubCollection": True
            },
            "vulnerabilityReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerabilities",
                "isSubCollection": True
            },
            "redirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection"
            },
            "policyBuilderSessionsAndLoginsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-sessions-and-logins"
            },
            "templateReference": {
                "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw",
                "title": "Fundamental"
            },
            "policyBuilderHeaderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-header"
            },
            "creatorName": "admin",
            "urlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/urls",
                "isSubCollection": True
            },
            "headerReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/headers",
                "isSubCollection": True
            },
            "actionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/action-items",
                "isSubCollection": True
            },
            "microserviceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/microservices",
                "isSubCollection": True
            },
            "xmlValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-validation-files",
                "isSubCollection": True
            },
            "lastUpdateMicros": 0,
            "jsonProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-profiles",
                "isSubCollection": True
            },
            "bruteForceAttackPreventionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/brute-force-attack-preventions",
                "isSubCollection": True
            },
            "disabledActionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disabled-action-items",
                "isSubCollection": True
            },
            "jsonValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-validation-files",
                "isSubCollection": True
            },
            "extractionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/extractions",
                "isSubCollection": True
            },
            "characterSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/character-sets",
                "isSubCollection": True
            },
            "suggestionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/suggestions",
                "isSubCollection": True
            },
            "deceptionSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-settings"
            },
            "isModified": False,
            "sensitiveParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sensitive-parameters",
                "isSubCollection": True
            },
            "generalReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/general"
            },
            "versionPolicyName": "/Common/Test_Policy",
            "policyBuilderCentralConfigurationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-central-configuration"
            }
        },
        {
            "plainTextProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/plain-text-profiles",
                "isSubCollection": True
            },
            "enablePassiveMode": False,
            "behavioralEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/behavioral-enforcement"
            },
            "dataGuardReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/data-guard"
            },
            "createdDatetime": "2020-07-29T14:32:20Z",
            "databaseProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/database-protection"
            },
            "cookieSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/cookie-settings"
            },
            "csrfUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/csrf-urls",
                "isSubCollection": True
            },
            "versionLastChange": " Security Policy /Common/Ben [add]: Parent Policy was set to empty value.\n"
                                 "Type was set to Security.\nEncoding Selected was set to true.\n"
                                 "Application Language was set to utf-8.\nActive was set to false.\n"
                                 "Policy Name was set to /Common/Ben. {audit: policy = /Common/Ben, component = tsconfd}",
            "name": "Common_Ben_copy_2",
            "caseInsensitive": False,
            "headerSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/header-settings"
            },
            "sectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/sections",
                "isSubCollection": True
            },
            "flowReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/flows",
                "isSubCollection": True
            },
            "loginPageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/login-pages",
                "isSubCollection": True
            },
            "description": "Fundamental Policy",
            "fullPath": "/Common/Common_Ben_copy_2",
            "policyBuilderParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-parameter"
            },
            "hasParent": False,
            "threatCampaignReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/threat-campaigns",
                "isSubCollection": True
            },
            "partition": "Common",
            "managedByBewaf": False,
            "csrfProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/csrf-protection"
            },
            "policyAntivirusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/antivirus"
            },
            "kind": "tm:asm:policies:policystate",
            "virtualServers": [

            ],
            "policyBuilderCookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-cookie"
            },
            "ipIntelligenceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/ip-intelligence"
            },
            "protocolIndependent": False,
            "sessionAwarenessSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/session-tracking"
            },
            "policyBuilderUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-url"
            },
            "policyBuilderServerTechnologiesReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-server-technologies"
            },
            "policyBuilderFiletypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-filetype"
            },
            "signatureSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signature-sets",
                "isSubCollection": True
            },
            "parameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/parameters",
                "isSubCollection": True
            },
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "loginEnforcementReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/login-enforcement"
            },
            "openApiFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/open-api-files",
                "isSubCollection": True
            },
            "navigationParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/navigation-parameters",
                "isSubCollection": True
            },
            "gwtProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/gwt-profiles",
                "isSubCollection": True
            },
            "webhookReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/webhooks",
                "isSubCollection": True
            },
            "whitelistIpReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/whitelist-ips",
                "isSubCollection": True
            },
            "historyRevisionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/history-revisions",
                "isSubCollection": True
            },
            "policyBuilderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder"
            },
            "responsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/response-pages",
                "isSubCollection": True
            },
            "vulnerabilityAssessmentReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/vulnerability-assessment"
            },
            "serverTechnologyReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/server-technologies",
                "isSubCollection": True
            },
            "cookieReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/cookies",
                "isSubCollection": True
            },
            "blockingSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/blocking-settings",
                "isSubCollection": True
            },
            "hostNameReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/host-names",
                "isSubCollection": True
            },
            "versionDeviceName": "f5asm.qmasters.co",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw",
            "threatCampaignSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/threat-campaign-settings"
            },
            "signatureReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signatures",
                "isSubCollection": True
            },
            "filetypeReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/filetypes",
                "isSubCollection": True
            },
            "id": "Vn68Wl-lpt_XW0fVaYw6Hw",
            "modifierName": "",
            "manualVirtualServers": [

            ],
            "versionDatetime": "2020-07-02T21:09:26Z",
            "subPath": "/Common",
            "sessionTrackingStatusReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/session-tracking-statuses",
                "isSubCollection": True
            },
            "active": False,
            "auditLogReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/audit-logs",
                "isSubCollection": True
            },
            "disallowedGeolocationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/disallowed-geolocations",
                "isSubCollection": True
            },
            "redirectionProtectionDomainReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/redirection-protection-domains",
                "isSubCollection": True
            },
            "type": "security",
            "signatureSettingReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/signature-settings"
            },
            "deceptionResponsePageReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/deception-response-pages",
                "isSubCollection": True
            },
            "websocketUrlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/websocket-urls",
                "isSubCollection": True
            },
            "xmlProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/xml-profiles",
                "isSubCollection": True
            },
            "methodReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/methods",
                "isSubCollection": True
            },
            "vulnerabilityReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/vulnerabilities",
                "isSubCollection": True
            },
            "redirectionProtectionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/redirection-protection"
            },
            "policyBuilderSessionsAndLoginsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-sessions-and-logins"
            },
            "templateReference": {
                "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw",
                "title": "Fundamental"
            },
            "policyBuilderHeaderReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-header"
            },
            "creatorName": "admin",
            "urlReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/urls",
                "isSubCollection": True
            },
            "headerReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/headers",
                "isSubCollection": True
            },
            "actionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/action-items",
                "isSubCollection": True
            },
            "microserviceReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/microservices",
                "isSubCollection": True
            },
            "xmlValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/xml-validation-files",
                "isSubCollection": True
            },
            "lastUpdateMicros": 0,
            "jsonProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/json-profiles",
                "isSubCollection": True
            },
            "bruteForceAttackPreventionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/brute-force-attack-preventions",
                "isSubCollection": True
            },
            "disabledActionItemReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/disabled-action-items",
                "isSubCollection": True
            },
            "jsonValidationFileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/json-validation-files",
                "isSubCollection": True
            },
            "extractionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/extractions",
                "isSubCollection": True
            },
            "characterSetReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/character-sets",
                "isSubCollection": True
            },
            "suggestionReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/suggestions",
                "isSubCollection": True
            },
            "deceptionSettingsReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/deception-settings"
            },
            "isModified": False,
            "sensitiveParameterReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/sensitive-parameters",
                "isSubCollection": True
            },
            "generalReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/general"
            },
            "versionPolicyName": "/Common/Ben",
            "policyBuilderCentralConfigurationReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/Vn68Wl-lpt_XW0fVaYw6Hw/policy-builder-central-configuration"
            }
        },
    ]
}

MOCK_POLICY_RESPONSE = {
    "plainTextProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/plain-text-profiles",
        "isSubCollection": True
    },
    "behavioralEnforcementReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/behavioral-enforcement"
    },
    "dataGuardReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/data-guard"
    },
    "createdDatetime": "2020-07-29T14:32:21Z",
    "databaseProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/database-protection"
    },
    "cookieSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookie-settings"
    },
    "csrfUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-urls",
        "isSubCollection": True
    },
    "versionLastChange": "Cookie addedwithdem2 [delete] { audit: policy = /Common/Test_Policy,"
                         " username = admin, client IP = 192.168.30.99 }",
    "name": "Test_Policy",
    "caseInsensitive": False,
    "headerSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/header-settings"
    },
    "sectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sections",
        "isSubCollection": True
    },
    "flowReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/flows",
        "isSubCollection": True
    },
    "loginPageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-pages",
        "isSubCollection": True
    },
    "description": "Test stuff with the integration",
    "fullPath": "/Common/Test_Policy",
    "policyBuilderParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-parameter"
    },
    "threatCampaignReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaigns",
        "isSubCollection": True
    },
    "partition": "Common",
    "managedByBewaf": False,
    "csrfProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/csrf-protection"
    },
    "policyAntivirusReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/antivirus"
    },
    "kind": "tm:asm:policies:policystate",
    "policyBuilderCookieReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-cookie"
    },
    "ipIntelligenceReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/ip-intelligence"
    },
    "protocolIndependent": False,
    "sessionAwarenessSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking"
    },
    "policyBuilderUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-url"
    },
    "policyBuilderServerTechnologiesReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-server-technologies"
    },
    "policyBuilderFiletypeReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-filetype"
    },
    "signatureSetReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-sets",
        "isSubCollection": True
    },
    "parameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/parameters",
        "isSubCollection": True
    },
    "applicationLanguage": "utf-8",
    "loginEnforcementReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/login-enforcement"
    },
    "openApiFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/open-api-files",
        "isSubCollection": True
    },
    "navigationParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/navigation-parameters",
        "isSubCollection": True
    },
    "gwtProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/gwt-profiles",
        "isSubCollection": True
    },
    "webhookReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/webhooks",
        "isSubCollection": True
    },
    "whitelistIpReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/whitelist-ips",
        "isSubCollection": True
    },
    "historyRevisionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/history-revisions",
        "isSubCollection": True
    },
    "policyBuilderReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder"
    },
    "responsePageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/response-pages",
        "isSubCollection": True
    },
    "vulnerabilityAssessmentReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerability-assessment"
    },
    "serverTechnologyReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/server-technologies",
        "isSubCollection": True
    },
    "cookieReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/cookies",
        "isSubCollection": True
    },
    "blockingSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/blocking-settings",
        "isSubCollection": True
    },
    "hostNameReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/host-names",
        "isSubCollection": True
    },
    "versionDeviceName": "f5asm.qmasters.co",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA",
    "threatCampaignSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/threat-campaign-settings"
    },
    "signatureReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signatures",
        "isSubCollection": True
    },
    "policyBuilderRedirectionProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-redirection-protection"
    },
    "filetypeReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/filetypes",
        "isSubCollection": True
    },
    "id": "RBPmYSOVvS8I3fPkkLGoZA",
    "modifierName": "",
    "versionDatetime": "2020-07-29T12:54:41Z",
    "subPath": "/Common",
    "sessionTrackingStatusReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/session-tracking-statuses",
        "isSubCollection": True
    },
    "auditLogReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/audit-logs",
        "isSubCollection": True
    },
    "disallowedGeolocationReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disallowed-geolocations",
        "isSubCollection": True
    },
    "redirectionProtectionDomainReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection-domains",
        "isSubCollection": True
    },
    "signatureSettingReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/signature-settings"
    },
    "deceptionResponsePageReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-response-pages",
        "isSubCollection": True
    },
    "websocketUrlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/websocket-urls",
        "isSubCollection": True
    },
    "xmlProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-profiles",
        "isSubCollection": True
    },
    "methodReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/methods",
        "isSubCollection": True
    },
    "vulnerabilityReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/vulnerabilities",
        "isSubCollection": True
    },
    "redirectionProtectionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/redirection-protection"
    },
    "policyBuilderSessionsAndLoginsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-sessions-and-logins"
    },
    "templateReference": {
        "link": "https://localhost/mgmt/tm/asm/policy-templates/KGO8Jk0HA4ipQRG8Bfd_Dw",
        "title": "Fundamental"
    },
    "policyBuilderHeaderReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-header"
    },
    "creatorName": "admin",
    "urlReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/urls",
        "isSubCollection": True
    },
    "headerReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/headers",
        "isSubCollection": True
    },
    "actionItemReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/action-items",
        "isSubCollection": True
    },
    "microserviceReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/microservices",
        "isSubCollection": True
    },
    "xmlValidationFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/xml-validation-files",
        "isSubCollection": True
    },
    "lastUpdateMicros": 0,
    "jsonProfileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-profiles",
        "isSubCollection": True
    },
    "bruteForceAttackPreventionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/brute-force-attack-preventions",
        "isSubCollection": True
    },
    "disabledActionItemReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/disabled-action-items",
        "isSubCollection": True
    },
    "jsonValidationFileReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/json-validation-files",
        "isSubCollection": True
    },
    "extractionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/extractions",
        "isSubCollection": True
    },
    "characterSetReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/character-sets",
        "isSubCollection": True
    },
    "suggestionReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/suggestions",
        "isSubCollection": True
    },
    "deceptionSettingsReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/deception-settings"
    },
    "isModified": False,
    "sensitiveParameterReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/sensitive-parameters",
        "isSubCollection": True
    },
    "generalReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/general"
    },
    "versionPolicyName": "/Common/Test_Policy",
    "policyBuilderCentralConfigurationReference": {
        "link": "https://localhost/mgmt/tm/asm/policies/RBPmYSOVvS8I3fPkkLGoZA/policy-builder-central-configuration"
    }
}

MOCK_METHODS_RESPONSE = {
    "kind": "tm:asm:policies:methods:methodcollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods",
    "totalItems": 3,
    "items": [
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/4V4hb8HGOfeHsSMezfob-A",
            "name": "HEAD",
            "id": "4V4hb8HGOfeHsSMezfob-A",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "GET"
        },
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/oCQ57CKdi-DnSwwWAjkjEA",
            "name": "POST",
            "id": "oCQ57CKdi-DnSwwWAjkjEA",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "POST"
        },
        {
            "kind": "tm:asm:policies:methods:methodstate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/dSgDWpPuac7bHb3bLwv8yA",
            "name": "GET",
            "id": "dSgDWpPuac7bHb3bLwv8yA",
            "lastUpdateMicros": 1595858789000000.0,
            "actAsMethod": "GET"
        }
    ]
}

MOCK_METHOD_RESPONSE = {
    "kind": "tm:asm:policies:methods:methodstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/methods/4V4hb8HGOfeHsSMezfob-A",
    "name": "HEAD",
    "id": "4V4hb8HGOfeHsSMezfob-A",
    "lastUpdateMicros": 1595858789000000.0,
    "actAsMethod": "GET"
}

MOCK_FILETYPES_RESPONSE = {
    "kind": "tm:asm:policies:filetypes:filetypecollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes",
    "totalItems": 7,
    "items": [
        {
            "queryStringLength": 100,
            "checkPostDataLength": True,
            "kind": "tm:asm:policies:filetypes:filetypestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/jOSxayK1iJSqhsQh6HWd8w",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/UmE3F3NrBhFPQhJAKqrVsQ",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/Rt7-hEtwIk-ItPhYLUwVgA",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/mOgzedRVODecKsTkfDvoHQ",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/Uvs2ebB-t02QeE5hLKXLMA",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/4b_XYjIeQJzuSsC26EGWPA",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/M4na42GvebBMnI5wV_YMxg",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/filetypes/UmE3F3NrBhFPQhJAKqrVsQ",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names",
    "totalItems": 4,
    "items": [
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/kmAEvvvYg0o2GmIf_YfRBw",
            "createdBy": "GUI",
            "name": "shouldbefalse",
            "includeSubdomains": False,
            "id": "kmAEvvvYg0o2GmIf_YfRBw",
            "lastUpdateMicros": 1596015158000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/zgVRLeLapyPniyp0aOuBRQ",
            "createdBy": "GUI",
            "name": "shouldbetrue",
            "includeSubdomains": True,
            "id": "zgVRLeLapyPniyp0aOuBRQ",
            "lastUpdateMicros": 1596015136000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/-ZQ04K98JlqNCxjp0aLMjw",
            "createdBy": "GUI",
            "name": "anothertest.net",
            "includeSubdomains": True,
            "id": "-ZQ04K98JlqNCxjp0aLMjw",
            "lastUpdateMicros": 1595931522000000.0
        },
        {
            "kind": "tm:asm:policies:host-names:host-namestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/PSPPdjNO_C4mqEC1UApi7w",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names/Kqz46FpEkkzZtA4gKMSmiA",
    "createdBy": "GUI",
    "name": "mockexample.com",
    "includeSubdomains": False,
    "id": "Kqz46FpEkkzZtA4gKMSmiA",
    "lastUpdateMicros": 1596044537000000.0
}

MOCK_BLOCKING_SETTINGS_LIST_RESPONSE = {
    "kind": "tm:asm:policies:blocking-settings:evasions:evasioncollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions",
    "totalItems": 8,
    "items": [
        {
            "lastUpdateMicros": 1595950127000000.0,
            "description": "Bad unescape",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions"
                        "/9--k-GSum4jUNSf0sU91Dw",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw"
            },
            "id": "9--k-GSum4jUNSf0sU91Dw",
            "learn": True,
            "enabled": True
        },
        {
            "lastUpdateMicros": 1596018724000000.0,
            "description": "Apache whitespace",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/Ahu8fuILcRNNU-ICBr1v6w",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w"
            },
            "id": "Ahu8fuILcRNNU-ICBr1v6w",
            "learn": False,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595937781000000.0,
            "description": "Bare byte decoding",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/EKfN2XD-E1z097tVwOO1nw",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw"
            },
            "id": "EKfN2XD-E1z097tVwOO1nw",
            "learn": False,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "IIS Unicode codepoints",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/dtxhHW66r8ZswIeccbXbXA",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA"
            },
            "id": "dtxhHW66r8ZswIeccbXbXA",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595930400000000.0,
            "description": "IIS backslashes",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/6l0vHEYIIy4H06o9mY5RNQ",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ"
            },
            "id": "6l0vHEYIIy4H06o9mY5RNQ",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "%u decoding",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/Y2TT8PSVtqudz407XG4LAQ",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ"
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/x02XsB6uJX5Eqp1brel7rw",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw"
            },
            "id": "x02XsB6uJX5Eqp1brel7rw",
            "learn": True,
            "enabled": False
        },
        {
            "lastUpdateMicros": 1595858790000000.0,
            "description": "Directory traversals",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings"
                        "/evasions/qH_2eaLz5x2RgaZ7dUISLA",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "evasionReference": {
                "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA"
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/blocking-settings/evasions"
                "/9--k-GSum4jUNSf0sU91Dw",
    "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
    "evasionReference": {
        "link": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw"
    },
    "id": "9--k-GSum4jUNSf0sU91Dw",
    "learn": False,
    "enabled": True
}

MOCK_URLS_RESPONSE = {
    "kind": "tm:asm:policies:urls:urlcollectionstate",
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/t_-2ylPgDTYcBwNSEjsOOA",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/t_-2ylPgDTYcBwNSEjsOOA/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eB9iX0sb1ASAosn6ENepBA",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/DOua8EHU3Cc8sBU35TNfoQ",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/DOua8EHU3Cc8sBU35TNfoQ/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/wrB7PkQ65vOvOaYBsAm5Uw",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/wrB7PkQ65vOvOaYBsAm5Uw/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/SyQB1OuN4pwy9D2B0P42Gw",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/SyQB1OuN4pwy9D2B0P42Gw/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/faiefv884qtHRU3Qva2AbQ",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/faiefv884qtHRU3Qva2AbQ/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/N_a3D1S7OKDehYEPb-mgCg",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/N_a3D1S7OKDehYEPb-mgCg/parameters",
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
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles"
                                "/X8FbXF48VWJ5Tecp5ATd4A",
                        "name": "Default"
                    },
                    "headerValue": "*json*",
                    "headerName": "Content-Type",
                    "headerOrder": "2",
                    "type": "json"
                },
                {
                    "contentProfileReference": {
                        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles"
                                "/jwQd_XYZPfNGYnc3l7P4Pg",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eJxT4ThwaDSqmvcR0hFghQ",
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
        "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/urls/eJxT4ThwaDSqmvcR0hFghQ/parameters",
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
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/json-profiles/X8FbXF48VWJ5Tecp5ATd4A",
                "name": "Default"
            },
            "headerValue": "*json*",
            "headerName": "Content-Type",
            "headerOrder": "2",
            "type": "json"
        },
        {
            "contentProfileReference": {
                "link": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies",
    "totalItems": 4,
    "items": [
        {
            "isBase64": False,
            "createdBy": "GUI",
            "accessibleOnlyThroughTheHttpProtocol": False,
            "kind": "tm:asm:policies:cookies:cookiestate",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/HeC08NE594GztN6H7bTecA",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/E1g7FVU2CYuY30F-Rp_MUw",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/Q_h8jkEsc0YYCWdkctKqQw",
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
            "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/M4na42GvebBMnI5wV_YMxg",
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
    "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/cookies/Q_h8jkEsc0YYCWdkctKqQw",
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
                       "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw/host-names",
                       "totalItems": 0,
                       "items": []
                       }


def test_format_list_policies():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'Hostname')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policies(MOCK_POLICIES_RESPONSE)
    assert len(outputs['f5.ListPolicies(val.uid && val.uid == obj.uid)']) == 2


def test_format_delete_policy():
    _, outputs, _ = f5_v2.format_delete_policy(MOCK_POLICY_RESPONSE)
    outputs = outputs['f5.DeletePolicy(val.uid && val.uid == obj.uid)']

    assert outputs.get('name') == 'Test_Policy'
    assert outputs.get('id') == 'RBPmYSOVvS8I3fPkkLGoZA'
    assert len(outputs) == 3


def test_format_list_policy():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'PolicyMethods')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_METHODS_RESPONSE, 'PolicyMethods')
    assert len(outputs['f5.PolicyMethods(val.uid && val.uid == obj.uid)']) == 3


def test_format_policy_methods_command():
    _, outputs, _ = f5_v2.format_policy_object(MOCK_METHOD_RESPONSE, 'PolicyMethods')
    outputs = outputs['f5.PolicyMethods(val.uid && val.uid == obj.uid)']
    outputs = {key: value for key, value in outputs.items() if value is not None}

    assert outputs.get('name') == 'HEAD'
    assert outputs.get('actAsMethod') == 'GET'
    assert outputs.get('id') == '4V4hb8HGOfeHsSMezfob-A'
    assert len(outputs) == 5


def test_format_list_policy_file_type():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'FileType')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_FILETYPES_RESPONSE, 'FileType')
    outputs = outputs['f5.FileType(val.uid && val.uid == obj.uid)']
    assert len(outputs) == 7


def test_format_file_type_command():
    _, outputs, _ = f5_v2.format_policy_object(MOCK_FILETYPE_RESPONSE, 'FileType')

    outputs = outputs['f5.FileType(val.uid && val.uid == obj.uid)']
    outputs = {key: value for key, value in outputs.items() if value is not None}

    assert outputs.get('name') == 'liill'
    assert outputs.get('id') == 'UmE3F3NrBhFPQhJAKqrVsQ'
    assert len(outputs) == 4


def test_format_list_policy_cookies():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'Cookies')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_COOKIES_RESPONSE, 'Cookies')
    assert len(outputs['f5.Cookies(val.uid && val.uid == obj.uid)']) == 4


def test_format_cookies_command():
    _, outputs, _ = f5_v2.format_policy_object(MOCK_COOKIE_RESPONSE, 'Cookies')
    outputs = outputs['f5.Cookies(val.uid && val.uid == obj.uid)']
    outputs = {key: value for key, value in outputs.items() if value is not None}

    assert outputs.get('name') == 'addedwithdem'
    assert outputs.get('id') == 'Q_h8jkEsc0YYCWdkctKqQw'


def test_format_policy_hostnames_command():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'Hostname')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_HOSTNAMES_RESPONSE, 'Hostname')
    assert len(outputs['f5.Hostname(val.uid && val.uid == obj.uid)']) == 4


def test_format_policy_hostname_command():
    _, outputs, _ = f5_v2.format_policy_object(MOCK_HOSTNAME_RESPONSE, 'Hostname')
    outputs = outputs['f5.Hostname(val.uid && val.uid == obj.uid)']
    outputs = {key: value for key, value in outputs.items() if value is not None}

    assert outputs.get('name') == 'mockexample.com'
    assert outputs.get('id') == 'Kqz46FpEkkzZtA4gKMSmiA'


def test_format_policy_blocking_settings_list_command():
    _, outputs, _ = f5_v2.format_policy_blocking_settings_list_command(
        MOCK_EMPTY_RESPONSE, 'evasions')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_policy_blocking_settings_list_command(
        MOCK_BLOCKING_SETTINGS_LIST_RESPONSE, 'evasions')
    assert len(outputs['f5.BlockingSettings(val.uid && val.uid == obj.uid)']) == 8


def test_format_policy_blocking_settings_single_command():
    _, outputs, _ = f5_v2.format_policy_blocking_settings_update_command(
        MOCK_BLOCKING_SETTINGS_SINGLE_RESPONSE, 'evasions')
    assert len(outputs['f5.BlockingSettings(val.uid && val.uid == obj.uid)']) == 10


def test_format_policy_urls_command():
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_EMPTY_RESPONSE, 'Url')
    assert isinstance(outputs, dict) and outputs == {}
    _, outputs, _ = f5_v2.format_list_policy_functions(MOCK_URLS_RESPONSE, 'Url')
    assert len(outputs['f5.Url(val.uid && val.uid == obj.uid)']) == 7


def test_format_policy_url_command():
    _, outputs, _ = f5_v2.format_policy_object(MOCK_URL_RESPONSE, 'Url')
    outputs = outputs['f5.Url(val.uid && val.uid == obj.uid)']
    outputs = {key: value for key, value in outputs.items() if value is not None}

    assert outputs.get('name') == '/mockexample'
    assert outputs.get('id') == 'eJxT4ThwaDSqmvcR0hFghQ'
