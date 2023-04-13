test_get_alert_details_command_mock_data = {
    "test_case_1": {"args": {"alert_id": "alert_id", "fields_to_include": "All"},
                    "mock_response": {
                    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Security/alerts/$entity",
                    "id": "da637225970530734950_-1768941086", "azureTenantId": "<tenant id>",
                    "azureSubscriptionId": None, "riskScore": None, "tags": [], "activityGroupName": None,
                    "assignedTo": None, "category": "Malware", "closedDateTime": None, "comments": [],
                    "confidence": None, "createdDateTime": "2020-04-16T01:24:13.0578348Z",
                    "description": "V1 alert description",
                    "detectionIds": [], "eventDateTime": "2020-04-16T01:22:39.3222427Z", "feedback": None,
                    "lastModifiedDateTime": "2020-04-19T10:18:39.35Z", "recommendedActions": [], "severity": "medium",
                    "sourceMaterials": ["https://securitycenter.microsoft.com/alert/da637225970530734950_-1768941086"],
                    "status": "newAlert", "title": "An active 'Wintapp' backdoor was detected",
                    "vendorInformation": {"provider": "Microsoft Defender ATP", "providerVersion": None,
                                          "subProvider": "MicrosoftDefenderATP", "vendor": "Microsoft"},
                    "cloudAppStates": [], "fileStates": [
                        {"name": "<file_name>", "path": "<file_path>", "riskScore": None,
                         "fileHash": {"hashType": "sha1", "hashValue": "f809b926576cab647125a3907ef9265bdb130a0a"}}],
                    "hostStates": [
                        {"fqdn": "desktop-s2455r8", "isAzureAdJoined": True, "isAzureAdRegistered": None,
                         "isHybridAzureDomainJoined": None, "netBiosName": None, "os": "Windows10",
                         "privateIpAddress": "127.0.0.1",
                         "publicIpAddress": "127.0.0.1", "riskScore": "High"}], "historyStates": [], "malwareStates": [],
                    "networkConnections": [], "processes": [], "registryKeyStates": [], "triggers": [],
                    "userStates": [], "vulnerabilityStates": []},
                    "expected_hr": "## Microsoft Security Graph Alert Details - alert_id\n### Basic Properties\n"
                    "|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status"
                    "|Title|\n"
                    "|---|---|---|---|---|---|---|---|---|\n"
                    "| <tenant id> | Malware | 2020-04-16T01:24:13.0578348Z | V1 alert description | "
                    "2020-04-16T01:22:39.3222427Z | 2020-04-16T01:22:39.3222427Z | medium | "
                    "newAlert | An active 'Wintapp' backdoor was detected |\n"
                    "### File Security States for Alert\n"
                    "|FileHash|Name|Path|\n"
                    "|---|---|---|\n"
                    "| f809b926576cab647125a3907ef9265bdb130a0a | <file_name> | <file_path> |\n"
                    "### Host Security States for Alert\n"
                    "|Fqdn|OS|PrivateIPAddress|PublicIPAddress|RiskScore|\n"
                    "|---|---|---|---|---|\n"
                    "| desktop-s2455r8 | Windows10 | 127.0.0.1 | 127.0.0.1 | High |\n"
                    "### Vendor Information for Alert\n"
                    "|Provider|SubProvider|Vendor|\n"
                    "|---|---|---|\n"
                    "| Microsoft Defender ATP | MicrosoftDefenderATP | Microsoft |\n"
                    },
    "api_version": 'API V1',
    "expected_ec": {'MsGraph.Alert(val.ID && val.ID === obj.ID)': {'ID': 'da637225970530734950_-1768941086',
                                                                   'Title': "An active 'Wintapp' backdoor was detected",
                                                                   'Category': 'Malware', 'Severity': 'medium',
                                                                   'CreatedDate': '2020-04-16T01:24:13.0578348Z',
                                                                   'EventDate': '2020-04-16T01:22:39.3222427Z',
                                                                   'Status': 'newAlert', 'Vendor': 'Microsoft',
                                                                   'Provider': 'Microsoft Defender ATP'}}
}

#     "test_case_2": {"args": {"alert_id": "alert_id", "fields_to_include": "FileStates"},
#         "mock_response": {
#             "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Security/alerts/$entity",
#             "id": "da637225970530734950_-1768941086", "azureTenantId": "<tenant id>",
#             "azureSubscriptionId": None, "riskScore": None, "tags": [], "activityGroupName": None,
#             "assignedTo": None, "category": "Malware", "closedDateTime": None, "comments": [],
#             "confidence": None, "createdDateTime": "2020-04-16T01:24:13.0578348Z",
#             "description": " V1 alert description",
#             "detectionIds": [], "eventDateTime": "2020-04-16T01:22:39.3222427Z", "feedback": None,
#             "lastModifiedDateTime": "2020-04-19T10:18:39.35Z", "recommendedActions": [], "severity": "medium",
#             "sourceMaterials": ["https://securitycenter.microsoft.com/alert/da637225970530734950_-1768941086"],
#             "status": "newAlert", "title": "An active 'Wintapp' backdoor was detected",
#             "vendorInformation": {"provider": "Microsoft Defender ATP", "providerVersion": None,
#                                   "subProvider": "MicrosoftDefenderATP", "vendor": "Microsoft"},
#             "cloudAppStates": [], "fileStates": [
#                 {"name": "<file_name>", "path": "<file_path>", "riskScore": None,
#                  "fileHash": {"hashType": "sha1", "hashValue": "f809b926576cab647125a3907ef9265bdb130a0a"}}], "hostStates": [
#                 {"fqdn": "desktop-s2455r8", "isAzureAdJoined": true, "isAzureAdRegistered": None,
#                  "isHybridAzureDomainJoined": None, "netBiosName": None, "os": "Windows10", "privateIpAddress": "127.0.0.1",
#                  "publicIpAddress": "127.0.0.1", "riskScore": "High"}], "historyStates": [], "malwareStates": [],
#             "networkConnections": [], "processes": [], "registryKeyStates": [], "triggers": [],
#             "userStates": [], "vulnerabilityStates": []}
#         }
#     },
#     "test_case_3": {"args": {"alert_id": "alert_id", "fields_to_include": "FileStates"},}

# }
