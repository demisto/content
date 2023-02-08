import pytest
from MicrosoftGraphSecurity import MsGraphClient

# msg-get-user data:
RAW_USERS_DATA = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#users', 'value': [
    {'businessPhones': [], 'displayName': 'Graph Test', 'givenName': None, 'jobTitle': 'Test',
     'mail': "Test@demistodev.onmicrosoft.com", 'mobilePhone': None, 'officeLocation': None, 'preferredLanguage': None,
     'surname': None, 'userPrincipalName': '0e3f5d4140cc4448a857e565a4d228e1@demistodev.onmicrosoft.com',
     'id': '5bfe522c-d817-4ea8-b52c-cc959e10e623'},
    {'businessPhones': ['0525399091'], 'displayName': 'Test Graph 2', 'givenName': 'Test',
     'jobTitle': 'Staff Software Developer', 'mail': 'test2@demistodev.onmicrosoft.com', 'mobilePhone': '0525399091',
     'officeLocation': None, 'preferredLanguage': None, 'surname': None,
     'userPrincipalName': 'test2@demistodev.onmicrosoft.com', 'id': '00df702c-cdae-460d-a442-46db6cecca29'}]}
EXPECTED_USER_CONTEXT = {'MsGraph.User(val.ID && val.ID === obj.ID)': [
    {'Name': 'Graph Test', 'Title': 'Test', 'Email': 'Test@demistodev.onmicrosoft.com',
     'ID': '5bfe522c-d817-4ea8-b52c-cc959e10e623'},
    {'Name': 'Test Graph 2', 'Title': 'Staff Software Developer', 'Email': 'test2@demistodev.onmicrosoft.com',
     'ID': '00df702c-cdae-460d-a442-46db6cecca29'}]}
EXPECTED_USER_HUMAN_READABLE = \
    '### Microsoft Graph Users\n|Name|Title|Email|ID|\n|---|---|---|---|\n' \
    '| Graph Test | Test | Test@demistodev.onmicrosoft.com | 5bfe522c-d817-4ea8-b52c-cc959e10e623 |\n' \
    '| Test Graph 2 | Staff Software Developer | test2@demistodev.onmicrosoft.com | ' \
    '00df702c-cdae-460d-a442-46db6cecca29 |\n'

# msg-search-alerts data:
ALERTS_RAW_RESPONSE = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Security/alerts', 'value': [{
    'id': 'da637229984903196572_-755436942', 'azureTenantId': '<azureTenantId>',
    'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
    'assignedTo': None,
    'category': 'None', 'closedDateTime': None, 'comments': [], 'confidence': None,
    'createdDateTime': '2020-04-20T16:54:50.2722072Z', 'description': 'Created for test',
    'detectionIds': [],
    'eventDateTime': '2020-04-20T16:34:28.061101Z', 'feedback': None,
    'lastModifiedDateTime': '2020-04-20T16:54:51.57Z', 'recommendedActions': [],
    'severity': 'medium',
    'sourceMaterials': [
        'https://securitycenter.microsoft.com/alert/da637229984903196572_-755436942'],
    'status': 'newAlert', 'title': 'test alert',
    'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                          'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
    'cloudAppStates': [],
    'fileStates': [],
    'hostStates': [
        {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
         'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
         'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
         'riskScore': 'High'}],
    'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [],
    'registryKeyStates': [],
    'triggers': [], 'userStates': [], 'vulnerabilityStates': []},
    {'id': 'da637218501473413212_-1554891308', 'azureTenantId': '<azureTenantId>',
     'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
     'assignedTo': None,
     'category': 'None', 'closedDateTime': None, 'comments': [], 'confidence': None,
     'createdDateTime': '2020-04-07T09:55:47.3413212Z', 'description': 'Created for test',
     'detectionIds': [],
     'eventDateTime': '2020-04-07T09:37:43.0372259Z', 'feedback': None,
     'lastModifiedDateTime': '2020-04-20T13:54:13.7933333Z', 'recommendedActions': [],
     'severity': 'medium',
     'sourceMaterials': [
         'https://securitycenter.microsoft.com/alert/da637218501473413212_-1554891308'],
     'status': 'newAlert', 'title': 'test alert',
     'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                           'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
     'cloudAppStates': [],
     'fileStates': [],
     'hostStates': [
         {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
          'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
          'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
          'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
     'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
     'userStates': [],
     'vulnerabilityStates': []},
    {'id': 'da637226278996299656_1986871053', 'azureTenantId': '<azureTenantId>',
     'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
     'assignedTo': 'Automation',
     'category': 'None', 'closedDateTime': '2020-04-19T07:09:16.2118771Z',
     'comments': ['testing', 'testing'],
     'confidence': None, 'createdDateTime': '2020-04-16T09:58:19.4253561Z',
     'description': 'Created for test',
     'detectionIds': [], 'eventDateTime': '2020-04-15T15:27:53.8499648Z', 'feedback': None,
     'lastModifiedDateTime': '2020-04-20T12:34:46.29Z', 'recommendedActions': [],
     'severity': 'medium',
     'sourceMaterials': [
         'https://securitycenter.microsoft.com/alert/da637226278996299656_1986871053'],
     'status': 'resolved', 'title': 'test alert',
     'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                           'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
     'cloudAppStates': [],
     'fileStates': [],
     'hostStates': [
         {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
          'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
          'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
          'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
     'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
     'userStates': [],
     'vulnerabilityStates': []}]}
EXPECTED_ALERTS_OUTPUT = {'MsGraph.Alert(val.ID && val.ID === obj.ID)': [
    {'ID': 'da637229984903196572_-755436942', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-20T16:54:50.2722072Z', 'EventDate': '2020-04-20T16:34:28.061101Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637218501473413212_-1554891308', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-07T09:55:47.3413212Z', 'EventDate': '2020-04-07T09:37:43.0372259Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637226278996299656_1986871053', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-16T09:58:19.4253561Z', 'EventDate': '2020-04-15T15:27:53.8499648Z', 'Status': 'resolved',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'}]}

# msg-search-alerts-v2 data:
ALERTS_V2_RAW_RESPONSE = {"value": [{
    "@odata.type": "#microsoft.graph.security.alert",
    "id": "da637551227677560813_-961444813",
    "providerAlertId": "da637551227677560813_-961444813",
    "incidentId": "28282",
    "status": "new",
    "severity": "low",
    "classification": "unknown",
    "determination": "unknown",
    "serviceSource": "microsoftDefenderForEndpoint",
    "detectionSource": "antivirus",
    "detectorId": "e0da400f-affd-43ef-b1d5-afc2eb6f2756",
    "tenantId": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "title": "Suspicious execution of hidden file",
    "description": "A hidden file has been launched. This activity could indicate a compromised host. Attackers often hide"
    " files associated with malicious tools to evade file system inspection and defenses.",
    "recommendedActions": "Collect artifacts and determine scope\n�\tReview the machine timeline for suspicious activities"
    " that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs)"
    " \n�\tLook for the presence of relevant artifacts on other systems. Identify commonalities and differences between "
    "potentially compromised systems.\n�\tSubmit relevant files for deep analysis and review resulting detailed behavioral "
    "information.\n�\tSubmit undetected files to the MMPC malware portal\n\nInitiate containment & mitigation \n�\tContact "
    "the user to verify intent and initiate local remediation actions as needed.\n�\tUpdate AV signatures and run a full scan."
    " The scan might reveal and remove previously-undetected malware components.\n�\tEnsure that the machine has the latest "
    "security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System "
    "versions.\n�\tIf credential theft is suspected, reset all relevant users passwords.\n�\tBlock communication with relevant"
    " URLs or IPs at the organization�s perimeter.",
    "category": "DefenseEvasion",
    "assignedTo": None,
    "alertWebUrl": "https://security.microsoft.com/alerts/da637551227677560813_-961444813?tid=b3c1b5fc-828c-45fa-a1e1-"
    "10d74f6d6e9c",
    "incidentWebUrl": "https://security.microsoft.com/incidents/28282?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "actorDisplayName": None,
    "threatDisplayName": None,
    "threatFamilyName": None,
    "mitreTechniques": [
        "T1564.001"
    ],
    "createdDateTime": "2021-04-27T12:19:27.7211305Z",
    "lastUpdateDateTime": "2021-05-02T14:19:01.3266667Z",
    "resolvedDateTime": None,
    "firstActivityDateTime": "2021-04-26T07:45:50.116Z",
    "lastActivityDateTime": "2021-05-02T07:56:58.222Z",
    "comments": [],
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "firstSeenDateTime": "2020-09-12T07:28:32.4321753Z",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "azureAdDeviceId": None,
            "deviceDnsName": "tempDns",
            "osPlatform": "Windows10",
            "osBuild": 22424,
            "version": "Other",
            "healthStatus": "active",
            "riskScore": "medium",
            "rbacGroupId": 75,
            "rbacGroupName": "UnassignedGroup",
            "onboardingStatus": "onboarded",
            "defenderAvStatus": "unknown",
            "loggedOnUsers": [],
            "roles": [
                "compromised"
            ],
            "tags": [
                "Test Machine"
            ],
            "vmMetadata": {
                "vmId": "ca1b0d41-5a3b-4d95-b48b-f220aed11d78",
                "cloudProvider": "azure",
                "resourceId": "/subscriptions/8700d3a3-3bb7-4fbe-a090-488a1ad04161/resourceGroups/WdatpApi-EUS-STG/providers/"
                "Microsoft.Compute/virtualMachines/NirLaviTests",
                "subscriptionId": "8700d3a3-3bb7-4fbe-a090-488a1ad04161"
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "detectionStatus": "detected",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "roles": [],
            "tags": [],
            "fileDetails": {
                "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                "fileName": "MsSense.exe",
                "filePath": "C:\\Program Files\\temp",
                "fileSize": 6136392,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "processId": 4780,
            "parentProcessId": 668,
            "processCommandLine": "\"MsSense.exe\"",
            "processCreationDateTime": "2021-08-12T12:43:19.0772577Z",
            "parentProcessCreationDateTime": "2021-08-12T07:39:09.0909239Z",
            "detectionStatus": "detected",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "roles": [],
            "tags": [],
            "imageFile": {
                "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                "fileName": "MsSense.exe",
                "filePath": "C:\\Program Files\\temp",
                "fileSize": 6136392,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            },
            "parentProcessImageFile": {
                "sha1": None,
                "sha256": None,
                "fileName": "services.exe",
                "filePath": "C:\\Windows\\System32",
                "fileSize": 731744,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            },
            "userAccount": {
                "accountName": "SYSTEM",
                "domainName": "NT AUTHORITY",
                "userSid": "S-1-5-18",
                "azureAdUserId": None,
                "userPrincipalName": None
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.registryKeyEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "registryKey": "SYSTEM\\CONTROLSET001\\CONTROL\\WMI\\AUTOLOGGER\\SENSEAUDITLOGGER",
            "registryHive": "HKEY_LOCAL_MACHINE",
            "roles": [],
            "tags": [],
        }
    ]
}]}
EXPECTED_ALERTS_V2_OUTPUT = {'MsGraph.Alert(val.ID && val.ID === obj.ID)': [{
    'ID': 'da637551227677560813_-961444813',
    'Title': 'Suspicious execution of hidden file',
    'Category': 'DefenseEvasion',
    'Severity': 'low',
    'CreatedDate': '2021-04-27T12:19:27.7211305Z',
    'FirstActivityDateTime': '2021-04-26T07:45:50.116Z',
    'LastActivityDateTime': '2021-05-02T07:56:58.222Z',
    'Status': 'new',
    'Provider': 'microsoftDefenderForEndpoint'
}]}

# msg-get-alert-details data:
RAW_ALERT_DETAILS = {
    '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Security/alerts/$entity',
    'id': 'da637225970530734950_-1768941086', 'azureTenantId': '<tenant id>',
    'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
    'assignedTo': None, 'category': 'Malware', 'closedDateTime': None, 'comments': [],
    'confidence': None, 'createdDateTime': '2020-04-16T01:24:13.0578348Z',
    'description': 'Backdoors are malicious remote access tools that allow attackers to access and control infected '
                   'machines. Backdoors can also be used to exfiltrate data.\n\nA malware is considered active if it '
                   'is found running on the machine or it already has persistence mechanisms in place. Active malware '
                   'detections are assigned higher severity ratings.\n\nBecause this malware was active, '
                   'take precautionary measures and check for residual signs of infection.',
    'detectionIds': [], 'eventDateTime': '2020-04-16T01:22:39.3222427Z', 'feedback': None,
    'lastModifiedDateTime': '2020-04-19T10:18:39.35Z', 'recommendedActions': [], 'severity': 'medium',
    'sourceMaterials': ['https://securitycenter.microsoft.com/alert/da637225970530734950_-1768941086'],
    'status': 'newAlert', 'title': "An active 'Wintapp' backdoor was detected",
    'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                          'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
    'cloudAppStates': [], 'fileStates': [
        {'name': '<file_name>', 'path': '<file_path>', 'riskScore': None,
         'fileHash': {'hashType': 'sha1', 'hashValue': 'f809b926576cab647125a3907ef9265bdb130a0a'}}], 'hostStates': [
        {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
         'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10', 'privateIpAddress': '127.0.0.1',
         'publicIpAddress': '127.0.0.1', 'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
    'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
    'userStates': [], 'vulnerabilityStates': []}
EXPECTED_ALERT_DETAILS_CONTEXT = {
    'MsGraph.Alert(val.ID && val.ID === obj.ID)': {'ID': 'da637225970530734950_-1768941086',
                                                   'Title': "An active 'Wintapp' backdoor was detected",
                                                   'Category': 'Malware', 'Severity': 'medium',
                                                   'CreatedDate': '2020-04-16T01:24:13.0578348Z',
                                                   'EventDate': '2020-04-16T01:22:39.3222427Z',
                                                   'Status': 'newAlert', 'Vendor': 'Microsoft',
                                                   'Provider': 'Microsoft Defender ATP'}}
EXPECTED_ALERT_DETAILS_HR_ALL = \
    '## Microsoft Security Graph Alert Details - alert_id\n' \
    '### Basic Properties\n' \
    '|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status' \
    '|Title|\n' \
    '|---|---|---|---|---|---|---|---|---|\n' \
    '| <tenant id> | Malware | 2020-04-16T01:24:13.0578348Z | Backdoors are malicious remote ' \
    'access tools that allow attackers to access and control infected machines. Backdoors can ' \
    'also be used to exfiltrate data.<br><br>A malware is considered active if it is found ' \
    'running on the machine or it already has persistence mechanisms in place. Active malware ' \
    'detections are assigned higher severity ratings.<br><br>Because this malware was active, ' \
    'take precautionary measures and check for residual signs of infection. | ' \
    '2020-04-16T01:22:39.3222427Z | 2020-04-16T01:22:39.3222427Z | medium | ' \
    "newAlert | An active 'Wintapp' backdoor was detected |\n" \
    "### File Security States for Alert\n" \
    "|FileHash|Name|Path|\n" \
    "|---|---|---|\n" \
    "| f809b926576cab647125a3907ef9265bdb130a0a | <file_name> | <file_path> |\n" \
    "### Host Security States for Alert\n" \
    "|Fqdn|OS|PrivateIPAddress|PublicIPAddress|RiskScore|\n" \
    "|---|---|---|---|---|\n" \
    "| desktop-s2455r8 | Windows10 | 127.0.0.1 | 127.0.0.1 | High |\n" \
    "### Vendor Information for Alert\n" \
    "|Provider|SubProvider|Vendor|\n" \
    "|---|---|---|\n" \
    "| Microsoft Defender ATP | MicrosoftDefenderATP | Microsoft |\n"
EXPECTED_ALERT_DETAILS_HR_FILE_STATE = \
    '## Microsoft Security Graph Alert Details - alert_id\n' \
    '### Basic Properties\n' \
    '|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status' \
    '|Title|\n' \
    '|---|---|---|---|---|---|---|---|---|\n' \
    '| <tenant id> | Malware | 2020-04-16T01:24:13.0578348Z | Backdoors are malicious remote ' \
    'access tools that allow attackers to access and control infected machines. Backdoors can ' \
    'also be used to exfiltrate data.<br><br>A malware is considered active if it is found ' \
    'running on the machine or it already has persistence mechanisms in place. Active malware ' \
    'detections are assigned higher severity ratings.<br><br>Because this malware was active, ' \
    'take precautionary measures and check for residual signs of infection. | ' \
    '2020-04-16T01:22:39.3222427Z | 2020-04-16T01:22:39.3222427Z | medium | ' \
    "newAlert | An active 'Wintapp' backdoor was detected |\n" \
    "### File Security States for Alert\n" \
    "|FileHash|Name|Path|\n" \
    "|---|---|---|\n" \
    "| f809b926576cab647125a3907ef9265bdb130a0a | <file_name> | <file_path> |\n"

# msg-get-alert-details-v2 data:
RAW_ALERT_DETAILS_V2 = {
    "@odata.type": "#microsoft.graph.security.alert",
    "id": "da637578995287051192_756343937",
    "providerAlertId": "da637578995287051192_756343937",
    "incidentId": "28282",
    "status": "new",
    "severity": "low",
    "classification": "unknown",
    "determination": "unknown",
    "serviceSource": "microsoftDefenderForEndpoint",
    "detectionSource": "antivirus",
    "detectorId": "e0da400f-affd-43ef-b1d5-afc2eb6f2756",
    "tenantId": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "title": "Suspicious execution of hidden file",
    "description": "A hidden file has been launched. This activity could indicate a compromised host. Attackers often hide files"
    " associated with malicious tools to evade file system inspection and defenses.",
    "recommendedActions": "Collect artifacts and determine scope\n�\tReview the machine timeline for suspicious activities that "
    "may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) \n�\t"
    "Look for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially "
    "compromised systems.\n�\tSubmit relevant files for deep analysis and review resulting detailed behavioral information.\n�\t"
    "Submit undetected files to the MMPC malware portal\n\nInitiate containment & mitigation \n�\tContact the user to verify "
    "intent and initiate local remediation actions as needed.\n�\tUpdate AV signatures and run a full scan. The scan might "
    "reveal and remove previously-undetected malware components.\n�\tEnsure that the machine has the latest security updates. In"
    " particular, ensure that you have installed the latest software, web browser, and Operating System versions.\n�\tIf "
    "credential theft is suspected, reset all relevant users passwords.\n�\tBlock communication with relevant URLs or IPs at the"
    " organization�s perimeter.",
    "category": "DefenseEvasion",
    "assignedTo": None,
    "alertWebUrl": "https://security.microsoft.com/alerts/da637578995287051192_756343937?tid=b3c1b5fc-828c-45fa-a1e1-"
    "10d74f6d6e9c",
    "incidentWebUrl": "https://security.microsoft.com/incidents/28282?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "actorDisplayName": None,
    "threatDisplayName": None,
    "threatFamilyName": None,
    "mitreTechniques": [
        "T1564.001"
    ],
    "createdDateTime": "2021-04-27T12:19:27.7211305Z",
    "lastUpdateDateTime": "2021-05-02T14:19:01.3266667Z",
    "resolvedDateTime": None,
    "firstActivityDateTime": "2021-04-26T07:45:50.116Z",
    "lastActivityDateTime": "2021-05-02T07:56:58.222Z",
    "comments": [],
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "firstSeenDateTime": "2020-09-12T07:28:32.4321753Z",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "azureAdDeviceId": None,
            "deviceDnsName": "tempDns",
            "osPlatform": "Windows10",
            "osBuild": 22424,
            "version": "Other",
            "healthStatus": "active",
            "riskScore": "medium",
            "rbacGroupId": 75,
            "rbacGroupName": "UnassignedGroup",
            "onboardingStatus": "onboarded",
            "defenderAvStatus": "unknown",
            "loggedOnUsers": [],
            "roles": [
                "compromised"
            ],
            "tags": [
                "Test Machine"
            ],
            "vmMetadata": {
                "vmId": "ca1b0d41-5a3b-4d95-b48b-f220aed11d78",
                "cloudProvider": "azure",
                "resourceId": "/subscriptions/8700d3a3-3bb7-4fbe-a090-488a1ad04161/resourceGroups/WdatpApi-EUS-STG/providers/"
                "Microsoft.Compute/virtualMachines/NirLaviTests",
                "subscriptionId": "8700d3a3-3bb7-4fbe-a090-488a1ad04161"
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "detectionStatus": "detected",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "roles": [],
            "tags": [],
            "fileDetails": {
                "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                "fileName": "MsSense.exe",
                "filePath": "C:\\Program Files\\temp",
                "fileSize": 6136392,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "processId": 4780,
            "parentProcessId": 668,
            "processCommandLine": "\"MsSense.exe\"",
            "processCreationDateTime": "2021-08-12T12:43:19.0772577Z",
            "parentProcessCreationDateTime": "2021-08-12T07:39:09.0909239Z",
            "detectionStatus": "detected",
            "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
            "roles": [],
            "tags": [],
            "imageFile": {
                "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                "fileName": "MsSense.exe",
                "filePath": "C:\\Program Files\\temp",
                "fileSize": 6136392,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            },
            "parentProcessImageFile": {
                "sha1": None,
                "sha256": None,
                "fileName": "services.exe",
                "filePath": "C:\\Windows\\System32",
                "fileSize": 731744,
                "filePublisher": "Microsoft Corporation",
                "signer": None,
                "issuer": None
            },
            "userAccount": {
                "accountName": "SYSTEM",
                "domainName": "NT AUTHORITY",
                "userSid": "S-1-5-18",
                "azureAdUserId": None,
                "userPrincipalName": None
            }
        },
        {
            "@odata.type": "#microsoft.graph.security.registryKeyEvidence",
            "createdDateTime": "2021-04-27T12:19:27.7211305Z",
            "verdict": "unknown",
            "remediationStatus": "none",
            "remediationStatusDetails": None,
            "registryKey": "SYSTEM\\CONTROLSET001\\CONTROL\\WMI\\AUTOLOGGER\\SENSEAUDITLOGGER",
            "registryHive": "HKEY_LOCAL_MACHINE",
            "roles": [],
            "tags": [],
        }
    ]
}
EXPECTED_ALERT_DETAILS_CONTEXT_V2 = {'MsGraph.Alert(val.ID && val.ID === obj.ID)': {
    'ID': 'da637578995287051192_756343937',
    'Title': 'Suspicious execution of hidden file',
    'Category': 'DefenseEvasion',
    'Severity': 'low',
    'CreatedDate': '2021-04-27T12:19:27.7211305Z',
    'FirstActivityDateTime': '2021-04-26T07:45:50.116Z',
    'LastActivityDateTime': '2021-05-02T07:56:58.222Z',
    'Status': 'new',
    'Provider': 'microsoftDefenderForEndpoint'
}}


client_mocker = MsGraphClient(tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
                              base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed')


def test_get_users_command(mocker):
    from MicrosoftGraphSecurity import get_users_command
    mocker.patch.object(client_mocker, "get_users", return_value=RAW_USERS_DATA)
    hr, ec, _ = get_users_command(client_mocker, {})
    assert hr == EXPECTED_USER_HUMAN_READABLE
    assert ec == EXPECTED_USER_CONTEXT


@pytest.mark.parametrize(
    'args,expected_hr', [
        ({"alert_id": 'alert_id', "fields_to_include": "All"}, EXPECTED_ALERT_DETAILS_HR_ALL),
        ({"alert_id": 'alert_id', "fields_to_include": "FileStates"}, EXPECTED_ALERT_DETAILS_HR_FILE_STATE)

    ])
def test_get_alert_details_command(mocker, args, expected_hr):
    from MicrosoftGraphSecurity import get_alert_details_command
    mocker.patch.object(client_mocker, 'get_alert_details', return_value=RAW_ALERT_DETAILS)
    hr, ec, _ = get_alert_details_command(client_mocker, args)
    assert hr == expected_hr
    assert ec == EXPECTED_ALERT_DETAILS_CONTEXT


def test_get_alert_details_v2_command(mocker):
    from MicrosoftGraphSecurity import get_alert_details_v2_command
    mocker.patch.object(client_mocker, 'get_alert_details', return_value=RAW_ALERT_DETAILS_V2)
    _, ec, _ = get_alert_details_v2_command(client_mocker, {'alert_id': 'alert_id'})
    assert ec == EXPECTED_ALERT_DETAILS_CONTEXT_V2


def test_search_alerts_command(mocker):
    """
    Unit test
    Given
    - search-alerts command
    - command args
    - command raw response
    When
    - mock the Client's search_alerts command.
    Then
    - run the search alerts command using the Client.
    Validate the contents of the output.
    """
    from MicrosoftGraphSecurity import search_alerts_command
    mocker.patch.object(client_mocker, 'search_alerts', return_value=ALERTS_RAW_RESPONSE)
    _, ec, _ = search_alerts_command(client_mocker, {'severity': 'medium'})
    assert ec == EXPECTED_ALERTS_OUTPUT


def test_search_alerts_v2_command(mocker):
    """
    Unit test
    Given
    - search-alerts-v2 command
    - command args
    - command raw response
    When
    - mock the Client's search_alerts command.
    Then
    - run the search alerts command using the Client.
    Validate the contents of the output.
    """
    from MicrosoftGraphSecurity import search_alerts_v2_command
    mocker.patch.object(client_mocker, 'search_alerts', return_value=ALERTS_V2_RAW_RESPONSE)
    _, ec, _ = search_alerts_v2_command(client_mocker, {})
    assert ec == EXPECTED_ALERTS_V2_OUTPUT


def test_fetch_incidents_command(mocker):
    """
    Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's search_alerts command.
    Then
    - run the fetch incidents command using the Client.
    Validate the length of the results and the different fields of the fetched incidents.
    """
    from MicrosoftGraphSecurity import fetch_incidents
    mocker.patch('MicrosoftGraphSecurity.parse_date_range', return_value=("2020-04-19 08:14:21", 'never mind'))
    mocker.patch.object(client_mocker, 'search_alerts', return_value=ALERTS_RAW_RESPONSE)
    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=10, providers='', filter='')
    assert len(incidents) == 3
    assert incidents[0].get('severity') == 2
    assert incidents[2].get('occurred') == '2020-04-20T16:54:50.2722072Z'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=1, providers='', filter='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'test alert - da637218501473413212_-1554891308'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=0, providers='', filter='')
    assert len(incidents) == 0


def mock_request(method, url_suffix, params):
    return params


@pytest.mark.parametrize('filter_query, expected_filter_query', [
    ("Category eq 'Malware' and Severity eq 'High'", "Category eq 'Malware' and Severity eq 'High'"),
    ("Severity eq 'High'", "Severity eq 'High'"),
    ("Category eq 'Malware'", "Category eq 'Malware'")
])
def test_filter_query(filter_query, expected_filter_query, mocker):
    from MicrosoftGraphSecurity import MicrosoftClient
    mocker.patch.object(MicrosoftClient, 'http_request', side_effect=mock_request)

    response = client_mocker.search_alerts(last_modified=None, severity=None, category=None, vendor=None,
                                           time_from=None, time_to=None, filter_query=filter_query)

    assert response.get('$filter') == expected_filter_query


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from MicrosoftGraphSecurity import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={'value': []})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'resource_group': 'test_resource_group',
        'host': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]['Contents']
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
