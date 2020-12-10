

# Pack ID: Active_Directory_Query

### Scripts
script-ADGetUser.yml depends on: {('Active_Directory_Query', True)}  
IAMInitADUser.yml depends on: set()  
SendEmailToManager.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('Active_Directory_Query', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
script-UserEnrichAD.yml depends on: {('Active_Directory_Query', True)}  

### Playbooks
Active_Directory_-_Get_User_Manager_Email.yml depends on: {('Active_Directory_Query', True), ('CommonScripts', True)}  
playbook-Active_Directory_Investigation.yml depends on: {('Active_Directory_Query', True), ('Ransomware', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers
classifier-User_Profile_-_Active_Directory_(Outgoing).json depends on: {('CommonTypes', True)}  
classifier-User_Profile_-_Active_Directory_(Incoming).json depends on: {('CommonTypes', True)}  

### Widgets


# Pack ID: MailSenderNew

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphMail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Gmail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-Gsuite-gmail_5_9_9.json depends on: {('Phishing', True)}  
classifier-Gsuite-gmail.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-Gsuite-gmail.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: EWSMailSender

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Ransomware

### Scripts
RansomwareDataEncryptionStatus.yml depends on: set()  
RansomwareHostWidget.yml depends on: set()  

### Playbooks
playbook-Post_Intrusion_Ransomware_Investigation.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('rasterize', True), ('Ransomware', True), ('Active_Directory_Query', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layoutscontainer-Post_Intrusion_Ransomware.json depends on: {('Ransomware', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Post_Intrusion_Ransomware.json depends on: {('Ransomware', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: CommonScripts

### Scripts
script-AddEvidence.yml depends on: set()  
AddKeyToList.yml depends on: set()  
AfterRelativeDate.yml depends on: set()  
script-AreValuesEqual.yml depends on: set()  
script-AssignAnalystToIncident.yml depends on: set()  
Base64Decode.yml depends on: set()  
script-Base64Encode.yml depends on: set()  
Base64EncodeV2.yml depends on: set()  
script-Base64ListToFile.yml depends on: set()  
BetweenDates.yml depends on: set()  
BetweenHours.yml depends on: set()  
script-BinarySearchPy.yml depends on: set()  
CalculateEntropy.yml depends on: set()  
CalculateTimeDifference.yml depends on: set()  
script-CEFParser.yml depends on: set()  
ChangeContext.yml depends on: {('CommonScripts', True)}  
script-ChangeRemediationSLAOnSevChange.yml depends on: set()  
CheckFieldValue.yml depends on: set()  
script-CheckSenderDomainDistance.yml depends on: set()  
script-checkValue.yml depends on: set()  
script-CloseInvestigationAsDuplicate.yml depends on: set()  
script-commentsToContext.yml depends on: set()  
CompareIncidentsLabels.yml depends on: set()  
CompareLists.yml depends on: set()  
script-ContainsCreditCardInfo.yml depends on: set()  
script-ContextContains.yml depends on: set()  
script-ContextFilter.yml depends on: set()  
script-ContextGetEmails.yml depends on: set()  
script-ContextGetHashes.yml depends on: set()  
script-ContextGetIps.yml depends on: set()  
script-ContextGetPathForString.yml depends on: set()  
script-ContextSearchForString.yml depends on: set()  
ConvertAllExcept.yml depends on: set()  
ConvertDateToUTC.yml depends on: set()  
ConvertFile.yml depends on: set()  
script-ConvertKeysToTableFieldFormat.yml depends on: set()  
script-ConvertTableToHTML.yml depends on: set()  
ConvertToSingleElementArray.yml depends on: set()  
script-ConvertXmlFileToJson.yml depends on: set()  
script-ConvertXmlToJson.yml depends on: set()  
CopyContextToField.yml depends on: set()  
CopyNotesToIncident.yml depends on: set()  
script-CountArraySize.yml depends on: set()  
script-CreateArray.yml depends on: set()  
script-CreateEmailHtmlBody.yml depends on: set()  
CreateIndicatorsFromSTIX.yml depends on: set()  
script-Cut.yml depends on: set()  
DateStringToISOFormat.yml depends on: set()  
script-DBotAverageScore.yml depends on: set()  
script-DBotClosedIncidentsPercentage.yml depends on: set()  
script-DecodeMimeHeader.yml depends on: set()  
script-DeleteConext.yml depends on: set()  
DemistoVersion.yml depends on: set()  
script-DisplayHTML.yml depends on: set()  
DockerHardeningCheck.yml depends on: set()  
script-DomainReputation.yml depends on: {('Pwned', False), ('ThreatConnect', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('DomainTools_Iris', False), ('AwakeSecurity', False), ('TruSTAR', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('Alexa', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  
script-DT.yml depends on: set()  
script-DumpJSON.yml depends on: set()  
script-EmailAskUser.yml depends on: set()  
script-EmailAskUserResponse.yml depends on: set()  
EmailDomainBlacklist.yml depends on: set()  
script-EmailDomainSquattingReputation.yml depends on: set()  
EmailDomainWhitelist.yml depends on: set()  
script-emailFieldTriggered.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
script-EmailReputation.yml depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('ThreatQ', False), ('EclecticIQ', False), ('DeHashed', False), ('Flashpoint', False), ('EmailRepIO', False), ('AwakeSecurity', False), ('Pipl', False), ('illuminate', False)}  
script-EncodeToAscii.yml depends on: set()  
script-ExampleJSScript.yml depends on: set()  
script-Exists.yml depends on: set()  
script-ExportToCSV.yml depends on: set()  
script-ExposeIncidentOwner.yml depends on: set()  
ExtractDomainAndFQDNFromUrlAndEmail.yml depends on: set()  
ExtractDomainFromUrlFormat.yml depends on: set()  
ExtractFQDNFromUrlAndEmail.yml depends on: set()  
script-ExtractHTMLTables.yml depends on: set()  
ExtractIndicatorsFromTextFile.yml depends on: set()  
ExtractIndicatorsFromWordFile.yml depends on: set()  
script-FailedInstances.yml depends on: set()  
FeedRelatedIndicatorsWidget.yml depends on: set()  
script-FileCreateAndUpload.yml depends on: set()  
script-FileReputation.yml depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
FileToBase64List.yml depends on: set()  
FilterByList.yml depends on: set()  
script-findIncidentsWithIndicator.yml depends on: set()  
FindSimilarIncidentsV2.yml depends on: set()  
FirstArrayElement.yml depends on: set()  
FormattedDateToEpoch.yml depends on: set()  
script-generateSummaryReport.yml depends on: set()  
script-GeneratePassword.yml depends on: set()  
script-GenerateRandomString.yml depends on: set()  
GenerateRandomUUID.yml depends on: set()  
script-GenerateSummaryReports.yml depends on: set()  
script-GenericPollingScheduledTask.yml depends on: set()  
GetByIncidentId.yml depends on: set()  
GetDockerImageLatestTag.yml depends on: set()  
GetDomainDNSDetails.yml depends on: set()  
GetDuplicatesMlv2.yml depends on: set()  
GetFieldsByIncidentType.yml depends on: {('DemistoRESTAPI', True)}  
GetIndicatorDBotScore.yml depends on: set()  
GetListRow.yml depends on: set()  
script-GetStringsDistance.yml depends on: set()  
script-GetTime.yml depends on: set()  
GetValuesOfMultipleFIelds.yml depends on: set()  
GreaterCidrNumAddresses.yml depends on: set()  
script-hideFieldsOnNewIncident.yml depends on: set()  
HTMLtoMD.yml depends on: set()  
script-http.yml depends on: set()  
HTTPListRedirects.yml depends on: set()  
IdentifyAttachedEmail.yml depends on: set()  
IfThenElse.yml depends on: set()  
script-IncidentAddSystem.yml depends on: set()  
IncidentFields.yml depends on: {('DemistoRESTAPI', True)}  
IncreaseIncidentSeverity.yml depends on: set()  
script-IndicatorMaliciousRatioCalculation.yml depends on: set()  
script-InRange.yml depends on: set()  
IPNetwork.yml depends on: set()  
script-IPReputation.yml depends on: {('Cofense-Intelligence', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Ipstack', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('PaloAltoNetworks_Threat_Vault', False), ('ipinfo', False), ('AwakeSecurity', False), ('TruSTAR', False), ('Zscaler', False), ('Barracuda', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('isight', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  
script-IPToHost.yml depends on: set()  
IPv4Blacklist.yml depends on: set()  
IPv4Whitelist.yml depends on: set()  
script-IsEmailAddressInternal.yml depends on: set()  
script-isError.yml depends on: set()  
script-IsGreaterThan.yml depends on: set()  
IsInCidrRanges.yml depends on: set()  
script-IsIntegrationAvailable.yml depends on: set()  
IsInternalDomainName.yml depends on: set()  
IsInternalHostName.yml depends on: set()  
script-IsIPInRanges.yml depends on: set()  
script-IsListExist.yml depends on: set()  
script-IsMaliciousIndicatorFound.yml depends on: set()  
IsNotInCidrRanges.yml depends on: set()  
IsRFC1918Address.yml depends on: set()  
script-IsTrue.yml depends on: set()  
IsUrlPartOfDomain.yml depends on: {('CommonScripts', True)}  
script-IsValueInArray.yml depends on: set()  
Jmespath.yml depends on: set()  
script-JoinIfSingleElementOnly.yml depends on: set()  
JSONFileToCSV.yml depends on: set()  
JSONtoCSV.yml depends on: set()  
script-LanguageDetect.yml depends on: set()  
LastArrayElement.yml depends on: set()  
script-LessThanPercentage.yml depends on: set()  
script-LinkIncidentsWithRetry.yml depends on: set()  
script-listExecutedCommands.yml depends on: set()  
script-LoadJSON.yml depends on: set()  
LookupCSV.yml depends on: set()  
LowerCidrNumAddresses.yml depends on: set()  
script-MaliciousRatioReputation.yml depends on: set()  
script-MapValues.yml depends on: set()  
MapValuesTransformer.yml depends on: set()  
script-MarkAsNoteByTag.yml depends on: set()  
script-MarkRelatedIncidents.yml depends on: set()  
script-MatchRegex.yml depends on: set()  
MatchRegexV2.yml depends on: set()  
script-MathUtil.yml depends on: set()  
ModifyDateTime.yml depends on: set()  
script-NotInContextVerification.yml depends on: set()  
NumberOfPhishingAttemptPerUser.yml depends on: set()  
OnionURLReputation.yml depends on: set()  
PadZeros.yml depends on: set()  
ParseCSV.yml depends on: set()  
ParseEmailFiles.yml depends on: set()  
script-ParseExcel.yml depends on: set()  
script-ParseJSON.yml depends on: set()  
script-ParseWordDoc.yml depends on: set()  
PcapHTTPExtractor.yml depends on: set()  
script-PCAPMiner.yml depends on: set()  
script-PDFUnlocker.yml depends on: set()  
Ping.yml depends on: set()  
PopulateCriticalAssets.yml depends on: set()  
script-PortListenCheck.yml depends on: set()  
PositiveDetectionsVSDetectionEngines.yml depends on: set()  
PrettyPrint.yml depends on: set()  
script-Print.yml depends on: set()  
script-PrintContext.yml depends on: set()  
script-PrintErrorEntry.yml depends on: set()  
PrintRaw.yml depends on: set()  
ProductJoin.yml depends on: set()  
ProvidesCommand.yml depends on: {('DemistoRESTAPI', True)}  
script-PublishEntriesToContext.yml depends on: set()  
ReadFile.yml depends on: set()  
ReadPDFFileV2.yml depends on: set()  
RegexExtractAll.yml depends on: set()  
RegexGroups.yml depends on: set()  
script-RemoteExec.yml depends on: set()  
RemoveKeyFromList.yml depends on: set()  
RepopulateFiles.yml depends on: set()  
script-ResolveShortenedURL.yml depends on: set()  
script-ReverseList.yml depends on: set()  
script-RunDockerCommand.yml depends on: set()  
RunPollingCommand.yml depends on: set()  
script-ScheduleCommand.yml depends on: set()  
script-ScheduleGenericPolling.yml depends on: {('CommonScripts', True)}  
script-SCPPullFiles.yml depends on: set()  
SearchIncidentsV2.yml depends on: set()  
script-SendEmailOnSLABreach.yml depends on: set()  
script-SendMessageToOnlineUsers.yml depends on: set()  
script-Set.yml depends on: set()  
SetAndHandleEmpty.yml depends on: {('CommonScripts', True)}  
script-SetByIncidentId.yml depends on: set()  
script-SetDateField.yml depends on: set()  
SetGridField.yml depends on: set()  
SetIfEmpty.yml depends on: set()  
script-SetMultipleValues.yml depends on: set()  
script-SetTime.yml depends on: set()  
ShowLocationOnMap.yml depends on: set()  
script-ShowOnMap.yml depends on: set()  
script-ShowScheduledEntries.yml depends on: set()  
script-Sleep.yml depends on: set()  
script-SSdeepReputation.yml depends on: set()  
script-StixCreator.yml depends on: set()  
script-StopScheduledTask.yml depends on: set()  
StopTimeToAssignOnOwnerChange.yml depends on: set()  
script-StringContainsArray.yml depends on: set()  
script-StringLength.yml depends on: set()  
script-StringReplace.yml depends on: set()  
script-Strings.yml depends on: set()  
StripChar.yml depends on: set()  
SumList.yml depends on: set()  
script-TextFromHTML.yml depends on: set()  
script-ticksToTime.yml depends on: set()  
TimeStampCompare.yml depends on: set()  
script-TimeStampToDate.yml depends on: set()  
script-TopMaliciousRatioIndicators.yml depends on: set()  
script-ToTable.yml depends on: set()  
script-UnEscapeIPs.yml depends on: set()  
script-UnEscapeURLs.yml depends on: set()  
script-UnPackFile.yml depends on: set()  
UnzipFile.yml depends on: set()  
URLDecode.yml depends on: set()  
URLEncode.yml depends on: set()  
script-URLNumberOfAds.yml depends on: set()  
script-URLReputation.yml depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('PassiveTotal', False), ('Flashpoint', False), ('Recorded_Future', False), ('IsItPhishing', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('UrlScan', False), ('TruSTAR', False), ('Zscaler', False), ('PAN-OS', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('PolySwarm', False), ('GoogleSafeBrowsing', False)}  
script-URLSSLVerification.yml depends on: set()  
script-UtilAnyResults.yml depends on: set()  
VerifyIPv6Indicator.yml depends on: set()  
VerifyJSON.yml depends on: set()  
script-WhereFieldEquals_5_4_9.yml depends on: set()  
WhereFieldEquals.yml depends on: set()  
WordTokenizeTest.yml depends on: set()  
ZipFile.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EWS

### Scripts
script-BuildEWSQuery.yml depends on: set()  
GetEWSFolder.yml depends on: set()  

### Playbooks
playbook-Get_Mails_By_Folder_Paths.yml depends on: {('CommonScripts', True), ('EWS', True)}  
playbook-Office_365_Search_and_Delete.yml depends on: {('EWS', True), ('CommonPlaybooks', True)}  
playbook-Process_Email_-_EWS.yml depends on: {('CommonScripts', True), ('EWS', True)}  
playbook-Search_And_Delete_Emails_-_EWS.yml depends on: {('EWS', True), ('Phishing', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-EWS_O365_5_9_9.json depends on: {('Phishing', True)}  
classifier-EWS_v2_5_9_9.json depends on: {('Phishing', True)}  
classifier-EWS_v2.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-EWS_v2.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: MicrosoftGraphListener

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-MicrosoftGraphListener_5_9_9.json depends on: {('Phishing', True)}  
classifier-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incomming-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: GmailSingleUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-gmail-single-user_5_9_9.json depends on: {('Phishing', True)}  
classifier-gmail-single-user.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-gmail-single-user.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: CommonTypes

### Scripts

### Playbooks

### Layouts
layout-indicatorsDetails-Account.json depends on: {('CommonTypes', True), ('Compliance', True)}  
layoutscontainer-Account.json depends on: {('CommonTypes', True), ('Compliance', True)}  
layout-indicatorsDetails-cve.json depends on: {('CommonTypes', True)}  
layoutscontainer-cve.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-domain.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-domain.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-indicatorsDetails-email.json depends on: {('CommonTypes', True), ('Compliance', True)}  
layoutscontainer-email.json depends on: {('CommonTypes', True), ('Compliance', True)}  
layout-indicatorsDetails-Host.json depends on: {('CommonTypes', True)}  
layoutscontainer-Host.json depends on: {('CommonTypes', True)}  
layout-edit-Indicator_Feed.json depends on: {('CommonTypes', True)}  
layoutscontainer-Indicator_Feed.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-ip.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-ip.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-indicatorsDetails-registryKey.json depends on: {('CommonTypes', True)}  
layoutscontainer-registryKey.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-STIX_Attack_Pattern.json depends on: {('CommonTypes', True)}  
layoutscontainer-STIX_Attack_Pattern.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-STIX_Malware.json depends on: {('CommonTypes', True)}  
layoutscontainer-STIX_Malware.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-STIX_Report.json depends on: {('CommonTypes', True)}  
layoutscontainer-STIX_Report.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-STIX_Threat_Actor.json depends on: {('CommonTypes', True)}  
layoutscontainer-STIX_Threat_Actor.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-STIX_Tool.json depends on: {('CommonTypes', True)}  
layoutscontainer-STIX_Tool.json depends on: {('CommonTypes', True)}  
layout-indicatorsDetails-unifiedFile.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-unifiedFile.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-indicatorsDetails-url.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-url.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-edit-Vulnerability.json depends on: {('CommonTypes', True)}  
layout-details-Vulnerability.json depends on: {('CommonTypes', True)}  
layoutscontainer-Vulnerability.json depends on: {('CommonTypes', True)}  

### Incident Fields

### Indicator Types
reputation-cve.json depends on: {('CVESearch', False), ('CVESearch', True), ('RecordedFuture', False), ('VulnDB', False)}  
reputation-domain.json depends on: {('Pwned', False), ('ThreatConnect', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('DomainTools_Iris', False), ('AwakeSecurity', False), ('TruSTAR', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('Alexa', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  
reputation-email.json depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('ThreatQ', False), ('EclecticIQ', False), ('DeHashed', False), ('Flashpoint', False), ('CommonScripts', True), ('EmailRepIO', False), ('AwakeSecurity', False), ('Pipl', False), ('illuminate', False)}  
reputation-hashRepMD5.json depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('CommonScripts', True), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('SplunkPy', True), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
reputation-hashRepSHA1.json depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('CommonScripts', True), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('SplunkPy', True), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
reputation-hashRepSHA256.json depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('CommonScripts', True), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
reputation-ip.json depends on: {('Cofense-Intelligence', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('CommonScripts', True), ('Ipstack', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('PaloAltoNetworks_Threat_Vault', False), ('ipinfo', False), ('AwakeSecurity', False), ('TruSTAR', False), ('Zscaler', False), ('Barracuda', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('isight', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('SplunkPy', True), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  
reputation-Onion_Address.json depends on: {('CommonScripts', True)}  
reputation-file.json depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('CommonScripts', True), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
reputation-url.json depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('PassiveTotal', False), ('Flashpoint', False), ('Recorded_Future', False), ('CommonScripts', True), ('IsItPhishing', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('UrlScan', False), ('TruSTAR', False), ('Zscaler', False), ('PAN-OS', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('ThreatExchange', False), ('APIVoid', False), ('CyberTotal', False), ('SplunkPy', True), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('PolySwarm', False), ('GoogleSafeBrowsing', False)}  

### Integrations

### Incident Types

### Classifiers
classifier-Mail-listener_5_9_9.json depends on: {('Phishing', True)}  
classifier-Mail-listener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-Mail-listener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: MailSenderNew

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphMail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EWSMailSender

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphListener

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-MicrosoftGraphListener_5_9_9.json depends on: {('Phishing', True)}  
classifier-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incomming-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: GmailSingleUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-gmail-single-user_5_9_9.json depends on: {('Phishing', True)}  
classifier-gmail-single-user.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-gmail-single-user.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: Phishing

### Scripts
CheckEmailAuthenticity.yml depends on: set()  
PhishingDedupPreprocessingRule.yml depends on: {('CommonScripts', True)}  

### Playbooks
Calculate_Severity_By_Email_Authenticity.yml depends on: {('CommonScripts', True)}  
Entity_Enrichment_-_Phishing_v2.yml depends on: {('CommonPlaybooks', True)}  
Get_Original_Email_-_EWS.yml depends on: {('CommonScripts', True), ('EWS', True)}  
Get_Original_Email_-_Gmail.yml depends on: {('CommonScripts', True), ('Gmail', True), ('Phishing', True)}  
Phishing_-_Core.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('rasterize', True), ('Phishing', True), ('CommonPlaybooks', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Phishing_Investigation_-_Generic_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('Phishing', True), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Process_Email_-_Core.yml depends on: {('CommonScripts', True), ('Phishing', True)}  
Process_Email_-_Generic.yml depends on: {('CommonScripts', True), ('Phishing', True), ('CommonPlaybooks', True), ('rasterize', True)}  

### Layouts
layout-quickView-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-details-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-mobile-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-edit-Phishing.json depends on: {('Phishing', True)}  
layoutscontainer-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: rasterize

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pwned

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: XMCyber

### Scripts

### Playbooks
Create_Jira_Ticket_XM_Cyber.yml depends on: {('Jira', True)}  
Endpoint_Enrichment_XM_Cyber.yml depends on: {('CommonScripts', True), ('XMCyber', True)}  
IP_Enrichment_XM_Cyber.yml depends on: {('CommonScripts', True), ('XMCyber', True)}  
Scan_and_Isolate_XM_Cyber.yml depends on: {('Rapid7_Nexpose', True), ('XMCyber', True), ('CommonPlaybooks', True)}  

### Layouts
layoutscontainer-XM_Cyber_Layout.json depends on: {('XMCyber', True)}  
layoutscontainer-XM_Cyber_Security_Score.json depends on: {('XMCyber', True)}  
layoutscontainer-XM_Cyber_Technique.json depends on: {('XMCyber', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
XM_Cyber_Choke_Point.json depends on: {('XMCyber', True)}  
XM_Cyber_Critical_Asset.json depends on: {('XMCyber', True)}  

### Classifiers
classifier-XM_Cyber_Incident_Classifier.json depends on: {('XMCyber', True)}  

### Mappers
mapper-XM_Cyber_Entity_from_Crowdstrike.json depends on: {('CommonTypes', True), ('XMCyber', True)}  
mapper-XM_Cyber_Incident.json depends on: {('CommonTypes', True), ('XMCyber', True)}  

### Widgets


# Pack ID: Recorded_Future

### Scripts
script-RecordedFutureDomainRiskList.yml depends on: set()  
script-RecordedFutureHashRiskList.yml depends on: set()  
script-RecordedFutureIPRiskList.yml depends on: set()  
script-RecordedFutureURLRiskList.yml depends on: set()  
script-RecordedFutureVulnerabilityRiskList.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_Enterprise

### Scripts

### Playbooks
playbook-Anomali_Enterprise-Retro_Forensic_Search.yml depends on: {('Anomali_Enterprise', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Lastline

### Scripts

### Playbooks
playbook-Detonate_File_-_Lastline.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_Lastline_v2.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline_v2.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: IsItPhishing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Ipstack

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AbuseDB

### Scripts
script-AbuseIPDBPopulateIndicators.yml depends on: {('AbuseDB', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HelloWorld

### Scripts
HelloWorldScript.yml depends on: set()  

### Playbooks
playbook-Handle_Hello_World_Alert.yml depends on: {('HelloWorld', True)}  
playbook-HelloWorld_Scan.yml depends on: {('HelloWorld', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Hello_World_Alert-V2.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  
layoutscontainer-Hello_World_Alert.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Hello_World_Alert.json depends on: {('HelloWorld', True)}  

### Classifiers
classifier-HelloWorld_5_9_9.json depends on: {('HelloWorld', True)}  
classifier-HelloWorld.json depends on: {('HelloWorld', True)}  

### Mappers
classifier-mapper-incoming-HelloWorld.json depends on: {('HelloWorld', True)}  

### Widgets


# Pack ID: VirusTotal

### Scripts

### Playbooks
playbook-Detonate_File-VirusTotal.yml depends on: {('CommonScripts', True), ('PolySwarm', False), ('VirusTotal', False), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_Threat_Vault

### Scripts

### Playbooks
Threat_Vault_-_Signature_Search.yml depends on: {('PaloAltoNetworks_Threat_Vault', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ipinfo

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: UrlScan

### Scripts
script-urlscan-get-http-transactions.yml depends on: {('UrlScan', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TruSTAR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Palo_Alto_Networks_WildFire

### Scripts

### Playbooks
playbook-Detonate_URL_-_WildFire-v2.1.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_WildFire-v2.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Zscaler

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AutoFocus

### Scripts

### Playbooks
playbook-Autofocus_Query_Samples_and_Sessions.yml depends on: {('AutoFocus', True)}  
playbook-AutoFocusPolling.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Synapse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Shodan

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pulsedive

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeIntel

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Whois

### Scripts

### Playbooks
playbook-TIM_-_Process_Domain_Age_With_Whois.yml depends on: {('CommonScripts', True)}  
playbook-TIM_-_Process_Domain_Registrant_With_Whois.yml depends on: {('CommonScripts', True)}  
playbook-TIM_-_Process_Domains_With_Whois.yml depends on: {('JsonWhoIs', False), ('DomainTools', False), ('Whois', False), ('Whois', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatMiner

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PolySwarm

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: GoogleChronicleBackstory

### Scripts
ChronicleAssetIdentifierScript.yml depends on: set()  
ChronicleDBotScoreWidgetScript.yml depends on: set()  
ChronicleDomainIntelligenceSourcesWidgetScript.yml depends on: set()  
ConvertDomainToURLs.yml depends on: set()  
ExtractDomainFromIOCDomainMatchRes.yml depends on: set()  
ListDeviceEventsScript.yml depends on: {('GoogleChronicleBackstory', True)}  

### Playbooks
playbook-Investigate_On_Bad_Domain_Matches_-_Chronicle.yml depends on: {('Pwned', False), ('MailSenderNew', False), ('MicrosoftGraphMail', False), ('ThreatConnect', False), ('Gmail', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('DomainTools_Iris', False), ('AwakeSecurity', False), ('EWS', False), ('TruSTAR', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('EWSMailSender', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('Alexa', False), ('ThreatExchange', False), ('APIVoid', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CyberTotal', False), ('GoogleChronicleBackstory', True), ('PAN-OS', True), ('JsonWhoIs', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  
playbook-Threat_Hunting_-_Chronicle.yml depends on: {('Pwned', False), ('ThreatConnect', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('CommonPlaybooks', True), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('DomainTools_Iris', False), ('AwakeSecurity', False), ('TruSTAR', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('Alexa', False), ('ThreatExchange', False), ('APIVoid', False), ('PaloAltoNetworks_PAN_OS_EDL_Management', True), ('CyberTotal', False), ('GoogleChronicleBackstory', True), ('JsonWhoIs', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False)}  

### Layouts
layout-mobile-Chronicle_IOC_Domain_Matches.json depends on: {('Phishing', True), ('SANS', True), ('NIST', True), ('CommonTypes', True), ('GoogleChronicleBackstory', True)}  
layout-quickView-Chronicle_IOC_Domain_Matches.json depends on: {('Phishing', True), ('SANS', True), ('NIST', True), ('CommonTypes', True), ('GoogleChronicleBackstory', True)}  
layout-edit-Chronicle_IOC_Domain_Matches.json depends on: {('Phishing', True), ('SANS', True), ('NIST', True), ('CommonTypes', True), ('GoogleChronicleBackstory', True)}  
layout-details-Chronicle_IOC_Domain_Matches.json depends on: {('GoogleChronicleBackstory', True)}  
layout-indicatorsDetails-ChronicleAsset.json depends on: {('CommonTypes', True), ('GoogleChronicleBackstory', True)}  

### Incident Fields

### Indicator Types
reputation-ChronicleAsset.json depends on: {('GoogleChronicleBackstory', True)}  

### Integrations

### Incident Types
incidenttype-Chronicle_IOC_Domain_Matches.json depends on: {('GoogleChronicleBackstory', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: Cofense-Intelligence

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MaxMind_GeoIP2

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatConnect

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PassiveTotal

### Scripts
script-PTEnrich.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalComponentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairChildrenScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairParentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalPDNSScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalSSLScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalTrackersScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalWhoisScript.yml depends on: {('PassiveTotal', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Flashpoint

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SlashNextPhishingIncidentResponse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EmailRepIO

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_Titanium_Cloud

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: illuminate

### Scripts

### Playbooks
playbook-Analyst1_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  
playbook-illuminate_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AlienVault_OTX

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Maltiverse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_A1000

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Zimperium

### Scripts

### Playbooks
playbook-Zimperium_Incident_Enrichment.yml depends on: {('Zimperium', True)}  

### Layouts
layout-details-Zimperium_event.json depends on: {('CrisisManagement', True), ('Zimperium', True), ('CommonTypes', True)}  
layoutscontainer-Zimperium_event.json depends on: {('CrisisManagement', True), ('Zimperium', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Zimperium_event.json depends on: {('Zimperium', True)}  

### Classifiers
classifier-Zimperium_5_9_9.json depends on: {('Zimperium', True)}  
classifier-Zimperium.json depends on: {('Zimperium', True)}  

### Mappers
classifier-mapper-incoming-Zimperium.json depends on: {('Zimperium', True), ('CommonTypes', True)}  

### Widgets


# Pack ID: RecordedFuture

### Scripts

### Playbooks
playbook-Recorded_Future_CVE_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_CVE_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IOC_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Threat_Assessment.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Reputation.yml depends on: {('RecordedFuture', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: URLHaus

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Spamcop

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Expanse

### Scripts
ExpanseParseRawIncident.yml depends on: set()  

### Playbooks
Expanse_Behavior_Severity_Update.yml depends on: {('CommonScripts', True), ('Expanse', True)}  
Expanse_Incident_Playbook.yml depends on: {('Expanse', True)}  

### Layouts
layout-details-Expanse_Appearance-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Appearance.json depends on: {('Expanse', True)}  
layout-details-Expanse_Behavior-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: DeHashed

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools_Iris

### Scripts

### Playbooks
playbook-Indicator_Pivoting-DomainTools_Iris.yml depends on: {('DomainTools_Iris', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AwakeSecurity

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: McAfee-TIE

### Scripts

### Playbooks
playbook-Search_Endpoints_By_Hash_-_TIE.yml depends on: {('epo', True), ('McAfee-TIE', True)}  
playbook-TIE_-_IOC_Hunt.yml depends on: {('CommonScripts', True), ('epo', True), ('McAfee-TIE', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeMalquery

### Scripts

### Playbooks
CrowdStrikeMalquery_-_GenericPolling_-_Multidownload_and_Fetch.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  
CrowdStrikeMalquery_-_GenericPolling_-_Search.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Barracuda

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PAN-OS

### Scripts

### Playbooks
playbook-NetOps_-_Firewall_Version_Content_Upgrade.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-NetOps_-_Firewall_Upgrade.yml depends on: {('PAN-OS', True)}  
playbook-NetSec_-_Palo_Alto_Networks_DUG_-_Tag_User.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_-_Add_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Static_Address_Group.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_URL_-_Custom_URL_Category.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_EDL_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Delete_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-Pan-OS_Commit_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-PAN-OS_DAG_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Log_Forwarding_Setup_And_Maintenance.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Query_Logs_For_Indicators.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-Panorama_Query_Logs.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-FirewallUpgrade.json depends on: {('PAN-OS', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: XForceExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Symantec_Deepsight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PhishTank

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TCPIPUtils

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DemistoRESTAPI

### Scripts
script-DemistoCreateList.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoGetIncidentTasksByState.yml depends on: set()  
script-DemistoLeaveAllInvestigations.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLinkIncidents.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLogsBundle.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoSendInvite.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFile.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFileToIncident.yml depends on: {('DemistoRESTAPI', True)}  
DemistoUploadFileV2.yml depends on: {('DemistoRESTAPI', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: isight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Alexa

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: APIVoid

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pipl

### Scripts
script-CheckSender.yml depends on: {('Pipl', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CyberTotal

### Scripts

### Playbooks
CyberTotal_Auto_Enrichment_-_CyCraft.yml depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('IsItPhishing', False), ('Lastline', False), ('Ipstack', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('Polygon', False), ('PaloAltoNetworks_Threat_Vault', False), ('DomainTools_Iris', False), ('ipinfo', False), ('AwakeSecurity', False), ('UrlScan', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('Zscaler', False), ('Barracuda', False), ('PAN-OS', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('ThreatExchange', False), ('isight', False), ('APIVoid', False), ('Alexa', False), ('CyberTotal', False), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False), ('GoogleSafeBrowsing', False)}  
CyberTotal_Whois_-_CyCraft.yml depends on: {('CyberTotal', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: OpenPhish

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MISP

### Scripts
script-misp_download_sample.yml depends on: set()  
script-misp_upload_sample.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EclecticIQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: iDefense

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_ThreatStream

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatStream.yml depends on: {('CommonScripts', True), ('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatStream.yml depends on: {('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cisco-umbrella

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Polygon

### Scripts

### Playbooks
playbook-Detonate_File_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  
playbook-Detonate_URL_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: GoogleSafeBrowsing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CommonPlaybooks

### Scripts

### Playbooks
playbook-Account_Enrichment_-_Generic_v2.1.yml depends on: {('Active_Directory_Query', True)}  
playbook-Block_File_-_Generic_v2.yml depends on: {('Traps', False), ('Cybereason', False), ('Cylance_Protect', False), ('Carbon_Black_Enterprise_Response', False)}  
playbook-Block_Indicators_-_Generic_v2.yml depends on: {('CommonPlaybooks', False)}  
playbook-Block_IP_-_Generic_v2.yml depends on: {('CheckpointFirewall', True), ('PAN-OS', False), ('Zscaler', True), ('FortiGate', True)}  
playbook-Block_Account_-_Generic.yml depends on: {('PAN-OS', True)}  
playbook-Block_URL_-_Generic.yml depends on: {('PAN-OS', False), ('Zscaler', True)}  
playbook-Calculate_Severity_-_Critical_Assets_v2.yml depends on: {('CommonScripts', True)}  
playbook-Calculate_Severity_-_Generic_v2.yml depends on: {('CommonScripts', True), ('Phishing', False), ('CommonPlaybooks', True)}  
playbook-Calculate_Severity_-_Standard.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-Calculate_Severity_By_Highest_DBotScore.yml depends on: {('CommonScripts', True)}  
playbook-Calculate_Severity_-_3rd-party_integrations.yml depends on: {('CommonScripts', True)}  
playbook-Calculate_Severity_-_Indicators_DBotScore.yml depends on: {('CommonScripts', True)}  
playbook-Convert_file_hash_to_corresponding_hashes.yml depends on: {('Cofense-Intelligence', False), ('ThreatConnect', False), ('Flashpoint', False), ('Recorded_Future', False), ('Lastline', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('ThreatQ', False), ('VirusTotal', False), ('PaloAltoNetworks_Threat_Vault', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('AutoFocus', False), ('Synapse', False), ('isight', False), ('ThreatExchange', False), ('CyberTotal', False), ('MISP', False), ('EclecticIQ', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('ThreatMiner', False), ('PolySwarm', False), ('Polygon', False)}  
playbook-CVE_Enrichment_-_Generic_v2.yml depends on: {('XForceExchange', True), ('VulnDB', True)}  
playbook-DBot_Indicator_Enrichment_-_Generic.yml depends on: {('CommonScripts', True)}  
playbook-Dedup_-_Generic_v2.yml depends on: {('CommonScripts', True)}  
playbook-Detonate_File_-_Generic.yml depends on: {('fireeye', False), ('CuckooSandbox', False), ('ThreatGrid', False), ('HybridAnalysis', False), ('CrowdStrikeFalconSandbox', False), ('Lastline', False), ('McAfee_Advanced_Threat_Defense', False), ('SNDBOX', False), ('JoeSecurity', False), ('Palo_Alto_Networks_WildFire', False), ('ANYRUN', False), ('VMRay', False)}  
playbook-Detonate_URL_-_Generic.yml depends on: {('CuckooSandbox', False), ('ThreatGrid', False), ('CrowdStrikeFalconSandbox', False), ('Lastline', False), ('CrowdStrikeFalconX', False), ('McAfee_Advanced_Threat_Defense', False), ('JoeSecurity', False), ('Polygon', False), ('ANYRUN', False)}  
playbook-Domain_Enrichment_-_Generic_v2.yml depends on: {('VirusTotal-Private_API', True), ('Cisco-umbrella', True)}  
playbook-Email_Address_Enrichment_-_Generic_v2.1.yml depends on: {('Active_Directory_Query', True), ('CommonScripts', True)}  
playbook-Endpoint_Enrichment_-_Generic_v2.1.yml depends on: {('epo', True), ('Cylance_Protect', False), ('CrowdStrikeHost', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('ExtraHop', True), ('Carbon_Black_Enterprise_Response', True)}  
playbook-Entity_Enrichment_-_Generic_v2.yml depends on: {('CommonPlaybooks', True)}  
Entity_Enrichment_-_Generic_v3.yml depends on: {('CommonPlaybooks', True)}  
playbook-Extract_Indicators_From_File_-_Generic_v2_4_5.yml depends on: {('ImageOCR', True), ('CommonScripts', True)}  
playbook-Field_Polling.yml depends on: {('CommonPlaybooks', True)}  
playbook-File_Enrichment_-_Generic_v2.yml depends on: {('VirusTotal-Private_API', False), ('Cylance_Protect', True)}  
playbook-File_Enrichment_-_File_reputation.yml depends on: {('CommonScripts', True)}  
playbook-GenericPolling.yml depends on: {('CommonScripts', True)}  
playbook-Get_File_Sample_By_Hash_-_Generic_v2.yml depends on: {('Cylance_Protect', False), ('Carbon_Black_Enterprise_Response', False)}  
playbook-Get_File_Sample_From_Path_-_Generic.yml depends on: {('D2', False), ('Carbon_Black_Enterprise_Response', False)}  
Get_Original_Email_-_Generic.yml depends on: {('Phishing', False)}  
playbook-IP_Enrichment_-_External_-_Generic_v2.yml depends on: {('Threat_Crowd', True), ('VirusTotal-Private_API', True), ('CommonScripts', True)}  
playbook-IP_Enrichment_-_Generic_v2.yml depends on: {('CommonPlaybooks', True)}  
playbook-IP_Enrichment_-_Internal_-_Generic_v2.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-Isolate_Endpoint_-_Generic.yml depends on: {('Traps', False), ('CortexXDR', True), ('Carbon_Black_Enterprise_Response', True), ('Cybereason', True)}  
playbook-Retrieve_File_from_Endpoint_-_Generic.yml depends on: {('CommonPlaybooks', True)}  
playbook-Search_Endpoints_By_Hash_-_Generic_V2.yml depends on: {('McAfee-TIE', False), ('Cybereason', False), ('CarbonBlackProtect', False), ('CrowdStrikeHost', False), ('Carbon_Black_Enterprise_Response', False)}  
playbook-Search_And_Delete_Emails_-_Generic.yml depends on: {('EWS', False), ('Phishing', True)}  
playbook-Send_Investigation_Summary_Reports.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-Send_Investigation_Summary_Reports_Job.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-URL_Enrichment_-_Generic_v2.yml depends on: {('CommonScripts', True), ('VirusTotal-Private_API', True), ('rasterize', True)}  
playbook-Wait_Until_Datetime.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Malware

### Scripts

### Playbooks
playbook-Endpoint_Malware_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-edit-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-details-Malware-V2.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Malware.json depends on: {('Malware', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: Compliance

### Scripts
BreachConfirmationHTML.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VulnDB

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CVESearch

### Scripts
script-CveLatest.yml depends on: {('CVESearch', False), ('XForceExchange', False)}  
script-CveSearch.yml depends on: {('XForceExchange', True)}  
script-CveReputation.yml depends on: {('CVESearch', False), ('RecordedFuture', False), ('VulnDB', False)}  

### Playbooks
playbook-CVE_Enrichment_-_Generic.yml depends on: {('XForceExchange', True), ('CVESearch', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SplunkPy

### Scripts
script-SplunkPySearch.yml depends on: {('SplunkPy', True)}  

### Playbooks
playbook-Splunk_Indicator_Hunting.yml depends on: {('CommonScripts', True), ('SplunkPy', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-SplunkPy_5_9_9.json depends on: {('AccessInvestigation', True), ('Malware', True)}  
classifier-SplunkPy.json depends on: {('AccessInvestigation', True), ('Malware', True)}  

### Mappers
classifier-mapper-incoming-SplunkPy.json depends on: {('CommonTypes', True), ('AccessInvestigation', True), ('Malware', True)}  

### Widgets


# Pack ID: MailSenderNew

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphMail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EWSMailSender

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphListener

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-MicrosoftGraphListener_5_9_9.json depends on: {('Phishing', True)}  
classifier-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incomming-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: GmailSingleUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-gmail-single-user_5_9_9.json depends on: {('Phishing', True)}  
classifier-gmail-single-user.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-gmail-single-user.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: Phishing

### Scripts
CheckEmailAuthenticity.yml depends on: set()  
PhishingDedupPreprocessingRule.yml depends on: {('CommonScripts', True)}  

### Playbooks
Calculate_Severity_By_Email_Authenticity.yml depends on: {('CommonScripts', True)}  
Entity_Enrichment_-_Phishing_v2.yml depends on: {('CommonPlaybooks', True)}  
Get_Original_Email_-_EWS.yml depends on: {('CommonScripts', True), ('EWS', True)}  
Get_Original_Email_-_Gmail.yml depends on: {('CommonScripts', True), ('Gmail', True), ('Phishing', True)}  
Phishing_-_Core.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('rasterize', True), ('Phishing', True), ('CommonPlaybooks', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Phishing_Investigation_-_Generic_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('Phishing', True), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Process_Email_-_Core.yml depends on: {('CommonScripts', True), ('Phishing', True)}  
Process_Email_-_Generic.yml depends on: {('CommonScripts', True), ('Phishing', True), ('CommonPlaybooks', True), ('rasterize', True)}  

### Layouts
layout-quickView-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-details-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-mobile-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-edit-Phishing.json depends on: {('Phishing', True)}  
layoutscontainer-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: rasterize

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pwned

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Recorded_Future

### Scripts
script-RecordedFutureDomainRiskList.yml depends on: set()  
script-RecordedFutureHashRiskList.yml depends on: set()  
script-RecordedFutureIPRiskList.yml depends on: set()  
script-RecordedFutureURLRiskList.yml depends on: set()  
script-RecordedFutureVulnerabilityRiskList.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_Enterprise

### Scripts

### Playbooks
playbook-Anomali_Enterprise-Retro_Forensic_Search.yml depends on: {('Anomali_Enterprise', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Lastline

### Scripts

### Playbooks
playbook-Detonate_File_-_Lastline.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_Lastline_v2.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline_v2.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: IsItPhishing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Ipstack

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AbuseDB

### Scripts
script-AbuseIPDBPopulateIndicators.yml depends on: {('AbuseDB', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HelloWorld

### Scripts
HelloWorldScript.yml depends on: set()  

### Playbooks
playbook-Handle_Hello_World_Alert.yml depends on: {('HelloWorld', True)}  
playbook-HelloWorld_Scan.yml depends on: {('HelloWorld', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Hello_World_Alert-V2.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  
layoutscontainer-Hello_World_Alert.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Hello_World_Alert.json depends on: {('HelloWorld', True)}  

### Classifiers
classifier-HelloWorld_5_9_9.json depends on: {('HelloWorld', True)}  
classifier-HelloWorld.json depends on: {('HelloWorld', True)}  

### Mappers
classifier-mapper-incoming-HelloWorld.json depends on: {('HelloWorld', True)}  

### Widgets


# Pack ID: VirusTotal

### Scripts

### Playbooks
playbook-Detonate_File-VirusTotal.yml depends on: {('CommonScripts', True), ('PolySwarm', False), ('VirusTotal', False), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_Threat_Vault

### Scripts

### Playbooks
Threat_Vault_-_Signature_Search.yml depends on: {('PaloAltoNetworks_Threat_Vault', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ipinfo

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: UrlScan

### Scripts
script-urlscan-get-http-transactions.yml depends on: {('UrlScan', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TruSTAR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Palo_Alto_Networks_WildFire

### Scripts

### Playbooks
playbook-Detonate_URL_-_WildFire-v2.1.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_WildFire-v2.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Zscaler

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AutoFocus

### Scripts

### Playbooks
playbook-Autofocus_Query_Samples_and_Sessions.yml depends on: {('AutoFocus', True)}  
playbook-AutoFocusPolling.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Synapse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Shodan

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pulsedive

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeIntel

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatMiner

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PolySwarm

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cofense-Intelligence

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MaxMind_GeoIP2

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatConnect

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PassiveTotal

### Scripts
script-PTEnrich.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalComponentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairChildrenScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairParentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalPDNSScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalSSLScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalTrackersScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalWhoisScript.yml depends on: {('PassiveTotal', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Flashpoint

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SlashNextPhishingIncidentResponse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EmailRepIO

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_Titanium_Cloud

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: illuminate

### Scripts

### Playbooks
playbook-Analyst1_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  
playbook-illuminate_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AlienVault_OTX

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Maltiverse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_A1000

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: RecordedFuture

### Scripts

### Playbooks
playbook-Recorded_Future_CVE_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_CVE_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IOC_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Threat_Assessment.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Reputation.yml depends on: {('RecordedFuture', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: URLHaus

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Spamcop

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Expanse

### Scripts
ExpanseParseRawIncident.yml depends on: set()  

### Playbooks
Expanse_Behavior_Severity_Update.yml depends on: {('CommonScripts', True), ('Expanse', True)}  
Expanse_Incident_Playbook.yml depends on: {('Expanse', True)}  

### Layouts
layout-details-Expanse_Appearance-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Appearance.json depends on: {('Expanse', True)}  
layout-details-Expanse_Behavior-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: DeHashed

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools_Iris

### Scripts

### Playbooks
playbook-Indicator_Pivoting-DomainTools_Iris.yml depends on: {('DomainTools_Iris', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AwakeSecurity

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeMalquery

### Scripts

### Playbooks
CrowdStrikeMalquery_-_GenericPolling_-_Multidownload_and_Fetch.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  
CrowdStrikeMalquery_-_GenericPolling_-_Search.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Barracuda

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PAN-OS

### Scripts

### Playbooks
playbook-NetOps_-_Firewall_Version_Content_Upgrade.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-NetOps_-_Firewall_Upgrade.yml depends on: {('PAN-OS', True)}  
playbook-NetSec_-_Palo_Alto_Networks_DUG_-_Tag_User.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_-_Add_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Static_Address_Group.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_URL_-_Custom_URL_Category.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_EDL_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Delete_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-Pan-OS_Commit_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-PAN-OS_DAG_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Log_Forwarding_Setup_And_Maintenance.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Query_Logs_For_Indicators.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-Panorama_Query_Logs.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-FirewallUpgrade.json depends on: {('PAN-OS', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: XForceExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Symantec_Deepsight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PhishTank

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TCPIPUtils

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DemistoRESTAPI

### Scripts
script-DemistoCreateList.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoGetIncidentTasksByState.yml depends on: set()  
script-DemistoLeaveAllInvestigations.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLinkIncidents.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLogsBundle.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoSendInvite.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFile.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFileToIncident.yml depends on: {('DemistoRESTAPI', True)}  
DemistoUploadFileV2.yml depends on: {('DemistoRESTAPI', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: isight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Alexa

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: APIVoid

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pipl

### Scripts
script-CheckSender.yml depends on: {('Pipl', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CyberTotal

### Scripts

### Playbooks
CyberTotal_Auto_Enrichment_-_CyCraft.yml depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('IsItPhishing', False), ('Lastline', False), ('Ipstack', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('Polygon', False), ('PaloAltoNetworks_Threat_Vault', False), ('DomainTools_Iris', False), ('ipinfo', False), ('AwakeSecurity', False), ('UrlScan', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('Zscaler', False), ('Barracuda', False), ('PAN-OS', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('ThreatExchange', False), ('isight', False), ('APIVoid', False), ('Alexa', False), ('CyberTotal', False), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False), ('GoogleSafeBrowsing', False)}  
CyberTotal_Whois_-_CyCraft.yml depends on: {('CyberTotal', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: OpenPhish

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MISP

### Scripts
script-misp_download_sample.yml depends on: set()  
script-misp_upload_sample.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EclecticIQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: iDefense

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_ThreatStream

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatStream.yml depends on: {('CommonScripts', True), ('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatStream.yml depends on: {('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cisco-umbrella

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Polygon

### Scripts

### Playbooks
playbook-Detonate_File_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  
playbook-Detonate_URL_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: GoogleSafeBrowsing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Malware

### Scripts

### Playbooks
playbook-Endpoint_Malware_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-edit-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-details-Malware-V2.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Malware.json depends on: {('Malware', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: Compliance

### Scripts
BreachConfirmationHTML.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VulnDB

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CVESearch

### Scripts
script-CveLatest.yml depends on: {('CVESearch', False), ('XForceExchange', False)}  
script-CveSearch.yml depends on: {('XForceExchange', True)}  
script-CveReputation.yml depends on: {('CVESearch', False), ('RecordedFuture', False), ('VulnDB', False)}  

### Playbooks
playbook-CVE_Enrichment_-_Generic.yml depends on: {('XForceExchange', True), ('CVESearch', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Jira

### Scripts
script-JiraCreaetIssueGeneric.yml depends on: {('Jira', True)}  
script-JIRAPrintIssue.yml depends on: {('Jira', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Rapid7_Nexpose

### Scripts
script-NexposeCreateIncidentsFromAssets.yml depends on: {('Rapid7_Nexpose', True)}  
script-NexposeEmailParser.yml depends on: set()  
script-NexposeEmailParserForVuln.yml depends on: set()  
script-NexposeVulnExtractor.yml depends on: set()  

### Playbooks
playbook-Scan_Nexpose_Assets.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Scan_Nexpose_Site.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Vulnerability_Handling_-_Nexpose.yml depends on: {('Rapid7_Nexpose', True), ('CommonTypes', True), ('CVESearch', True)}  
playbook-Vulnerability_Management_-_Nexpose_(Job).yml depends on: {('Rapid7_Nexpose', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JsonWhoIs

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SANS

### Scripts

### Playbooks
playbook-Brute_Force_Investigation_-_Generic_-_SANS.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Compliance', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('BruteForce', True), ('SANS', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  
playbook-SANS_-_Incident_Handlers_Checklist.yml depends on: {('CommonScripts', True), ('SANS', True)}  

### Layouts
layout-details-SANS-V2.json depends on: {('SANS', True)}  
layoutscontainer-SANS.json depends on: {('SANS', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: NIST

### Scripts

### Playbooks
playbook-NIST_-_Access_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('NIST', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-NIST_-_Handling_an_Incident.yml depends on: {('NIST', True)}  

### Layouts
layout-details-NIST-V2.json depends on: {('NIST', True)}  
layoutscontainer-NIST.json depends on: {('NIST', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-NIST.json depends on: {('NIST', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_PAN_OS_EDL_Management

### Scripts

### Playbooks
playbook-Block_IOCs_from_CSV_-_External_Dynamic_List.yml depends on: {('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_Domain_-_External_Dynamic_List.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_IP_and_URL_-_External_Dynamic_List_v2.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_EDL_Setup_v3.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrisisManagement

### Scripts

### Playbooks
Continuously_Process_Survey_Responses.yml depends on: {('CrisisManagement', True)}  
Employee_Status_Survey.yml depends on: {('CrisisManagement', True), ('CommonScripts', True), ('MicrosoftGraphUser', True)}  
Process_Survey_Response.yml depends on: {('CommonScripts', True)}  

### Layouts
layout-indicatorsDetails-Employee-V2.json depends on: {('CrisisManagement', True), ('CommonTypes', True)}  
layoutscontainer-Employee.json depends on: {('CrisisManagement', True), ('CommonTypes', True)}  
layout-edit-Employee_Health_Check.json depends on: {('CrisisManagement', True), ('CommonTypes', True), ('Phishing', True)}  
layoutscontainer-Employee_Health_Check.json depends on: {('Phishing', True), ('SANS', True), ('NIST', True), ('CrisisManagement', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
Employee_Health_Check.json depends on: {('CrisisManagement', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: epo

### Scripts
script-EPOFindSystem.yml depends on: {('epo', True)}  

### Playbooks
playbook-McAfee_ePO_Endpoint_Compliance_v2.yml depends on: {('epo', True), ('CommonScripts', True), ('ServiceNow', True)}  
playbook-McAfee_ePO_Endpoint_Connectivity_Diagnostics_v2.yml depends on: {('CommonScripts', True), ('ServiceNow', True)}  
playbook-McAfee_ePO_Repository_Compliance_v2.yml depends on: {('epo', True), ('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cylance_Protect

### Scripts

### Playbooks
playbook-Block_File_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Endpoint_Enrichment_-_Cylance_Protect_v2.yml depends on: {('CommonScripts', True), ('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: FortiGate

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CortexXDR

### Scripts
EntryWidgetNumberHostsXDR.yml depends on: set()  
EntryWidgetNumberUsersXDR.yml depends on: set()  
EntryWidgetPieAlertsXDR.yml depends on: set()  
script-XDR_test_helper.yml depends on: set()  
XDRSyncScript_5_9_9.yml depends on: {('CommonScripts', True)}  
XDRSyncScript.yml depends on: {('CommonScripts', True)}  

### Playbooks
Cortex_XDR_-_Isolate_Endpoint.yml depends on: {('CortexXDR', True), ('CommonPlaybooks', True)}  
Cortex_XDR_-_Malware_Investigation.yml depends on: {('CortexXDR', True), ('CommonPlaybooks', True)}  
Cortex_XDR_-_Port_Scan.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CortexXDR', True), ('CommonScripts', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('CommonPlaybooks', False), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  
Cortex_XDR_-_Port_Scan_-_Adjusted.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Cortex_XDR_-_quarantine_file.yml depends on: {('CortexXDR', True), ('CommonPlaybooks', True)}  
Cortex_XDR_Alerts_Handling.yml depends on: {('CortexXDR', True)}  
Cortex_XDR_Incident_Handling.yml depends on: {('CommonScripts', True), ('PANWComprehensiveInvestigation', False), ('CortexXDR', True), ('CommonPlaybooks', True), ('AutoFocus', True)}  
Cortex_XDR_incident_handling_v2.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('CortexXDR', True), ('DemistoRESTAPI', False)}  
Cortex_XDR_incident_handling_v3.yml depends on: {('DemistoRESTAPI', True), ('CommonScripts', True), ('CortexXDR', True), ('CommonPlaybooks', True)}  
PaloAltoNetworks_Cortex_XDR_Incident_Sync.yml depends on: {('CommonScripts', True), ('CortexXDR', True)}  

### Layouts
layout-details-Cortex_XDR_Incident.json depends on: {('CortexXDR', True), ('CommonTypes', True)}  
layoutscontainer-Cortex_XDR_Incident.json depends on: {('CortexXDR', True), ('CommonTypes', True)}  
layout-details-Cortex_XDR_Port_Scan.json depends on: {('CortexXDR', True), ('CommonTypes', True)}  
layoutscontainer-Cortex_XDR_Port_Scan.json depends on: {('CortexXDR', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
Cortex_XDR_Incident_5_9_9.json depends on: {('CortexXDR', True)}  
Cortex_XDR_Incident.json depends on: {('CortexXDR', True)}  
Cortex_XDR_Port_Scan.json depends on: {('CortexXDR', True)}  

### Classifiers
classifier-PaloAltoNetworks_CortexXDR_5_9_9.json depends on: {('CortexXDR', True)}  
classifier-PaloAltoNetworks_CortexXDR.json depends on: {('CortexXDR', True)}  

### Mappers
classifier-mapper-incoming-PaloAltoNetworks_CortexXDR.json depends on: {('CortexXDR', True), ('CommonTypes', True)}  
classifier-mapper-outgoing-PaloAltoNetworks_CortexXDR.json depends on: {('CortexXDR', True)}  

### Widgets


# Pack ID: D2

### Scripts
script-ActiveUsersD2.yml depends on: set()  
script-Autoruns.yml depends on: set()  
script-CommonD2.yml depends on: set()  
script-CopyFileD2.yml depends on: set()  
script-D2ActiveUsers.yml depends on: set()  
script-D2Autoruns.yml depends on: set()  
script-D2Drop.yml depends on: set()  
script-D2Exec.yml depends on: set()  
script-ExecuteCommandD2.yml depends on: set()  
script-D2GetFile.yml depends on: set()  
script-D2GetSystemLog.yml depends on: set()  
script-D2Hardware.yml depends on: set()  
script-D2O365ComplianceSearch.yml depends on: set()  
script-D2O365SearchAndDelete.yml depends on: set()  
script-D2PEDump.yml depends on: set()  
script-D2Processes.yml depends on: set()  
script-D2RegQuery.yml depends on: set()  
script-D2Rekall.yml depends on: set()  
D2Remove.yml depends on: set()  
script-D2Services.yml depends on: set()  
script-D2Users.yml depends on: set()  
script-D2Winpmem.yml depends on: set()  
script-FetchFileD2.yml depends on: set()  
script-O365SearchEmails.yml depends on: {('D2', True)}  
script-RegCollectValues.yml depends on: set()  
script-RegPathReputationBasicLists.yml depends on: set()  
script-RegProbeBasic.yml depends on: set()  
script-StaticAnalyze.yml depends on: {('D2', True)}  

### Playbooks
playbook-D2_-_Endpoint_data_collection.yml depends on: {('CommonScripts', True), ('D2', True)}  
playbook-Get_File_Sample_From_Path_-_D2.yml depends on: {('CommonScripts', True), ('D2', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: McAfee_Advanced_Threat_Defense

### Scripts
script-ATDDetonate.yml depends on: {('McAfee_Advanced_Threat_Defense', True)}  

### Playbooks
playbook-Detonate_File_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_Remote_File_from_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cybereason

### Scripts
script-CybereasonPreProcessing.yml depends on: set()  

### Playbooks
playbook-Block_File_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Isolate_Endpoint_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Search_Endpoints_By_Hash_-_Cybereason.yml depends on: {('Cybereason', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ImageOCR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatGrid

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatGrid.yml depends on: {('CommonScripts', True), ('ThreatGrid', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatGrid.yml depends on: {('ThreatGrid', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HybridAnalysis

### Scripts

### Playbooks
playbook-Detonate_File_-_HybridAnalysis.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  
playbook-Hybrid-analysis_quick-scan.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CheckpointFirewall

### Scripts
CheckPointDownloadBackup.yml depends on: {('CheckpointFirewall', True)}  
CheckpointFWBackupStatus.yml depends on: set()  
CheckpointFWCreateBackup.yml depends on: set()  

### Playbooks
Checkpoint_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Block_URL.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Publish&Install_configuration.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CarbonBlackProtect

### Scripts
script-CBPApproveHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPBanHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPCatalogFindHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindComputer.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindRule.yml depends on: {('CarbonBlackProtect', True)}  

### Playbooks
playbook-Carbon_black_Protection_Rapid_IOC_Hunting.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  
playbook-Search_Endpoints_By_Hash_-_Carbon_Black_Protection.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SNDBOX

### Scripts

### Playbooks
playbook-Detonate_File_-_SNDBOX.yml depends on: {('CommonScripts', True), ('SNDBOX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Carbon_Black_Enterprise_Response

### Scripts
script-CBAlerts.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  
script-CBEvents.yml depends on: set()  
CBFindIP.yml depends on: set()  
CBLiveFetchFiles.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  
CBLiveGetFile.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True), ('Carbon_Black_Enterprise_Response', True)}  
CBLiveGetFile_V2.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True), ('Carbon_Black_Enterprise_Response', True)}  
script-CBSensors.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  
script-CBSessions.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True)}  
script-CBWatchlists.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  

### Playbooks
playbook-Block_File_-_Carbon_Black_Response.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  
playbook-Get_File_Sample_By_Hash_-_Carbon_Black_Enterprise_Response.yml depends on: {('CommonScripts', True)}  
playbook-Get_File_Sample_From_Path_-_Carbon_Black_Enterprise_Response.yml depends on: {('CommonScripts', True), ('Carbon_Black_Enterprise_Response', True)}  
playbook-Search_Endpoints_By_Hash_-_Carbon_Black_Response_V2.yml depends on: {('Carbon_Black_Enterprise_Response', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Threat_Crowd

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VirusTotal-Private_API

### Scripts

### Playbooks
playbook-File_Enrichment_-_Virus_Total_Private_API.yml depends on: {('VirusTotal-Private_API', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JoeSecurity

### Scripts

### Playbooks
playbook-Detonate_File_From_URL_-_JoeSecurity.yml depends on: {('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VMRay

### Scripts

### Playbooks
playbook-VMRay-Detonate-File.yml depends on: {('VMRay', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CuckooSandbox

### Scripts
script-CuckooDetonateFile.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDetonateURL.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDisplayReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetScreenshot.yml depends on: {('CuckooSandbox', True)}  
script-CuckooTaskStatus.yml depends on: {('CuckooSandbox', True)}  

### Playbooks
playbook-Detonate_File_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeHost

### Scripts
script-CrowdStrikeUrlParse.yml depends on: set()  

### Playbooks
playbook-CrowdStrike_Rapid_IOC_Hunting_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CrowdStrikeHost', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-CrowdStrike_Endpoint_Enrichment.yml depends on: {('CrowdStrikeHost', True)}  
playbook-Search_Endpoints_By_Hash_-_CrowdStrike.yml depends on: {('CrowdStrikeHost', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Traps

### Scripts

### Playbooks
playbook-Traps_Blacklist_File.yml depends on: {('Traps', True)}  
playbook-Isolate_Endpoint_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Block_File_-_Quarantine_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Retrieve_And_Download_Files.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Scan_Endpoint.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  
layoutscontainer-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Traps.json depends on: {('PANWComprehensiveInvestigation', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconX

### Scripts

### Playbooks
Detonate_File_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
Detonate_URL_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ExtraHop

### Scripts
ExtraHopTrackIncidents.yml depends on: {('ExtraHop', True)}  

### Playbooks
playbook-ExtraHop_-_CVE-2019-0708_(BlueKeep).yml depends on: {('CommonScripts', True), ('ExtraHop', True), ('CommonPlaybooks', True)}  
playbook-ExtraHop_-_Default.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Get_Peers_by_Host.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Ticket_Tracking_v2.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  

### Layouts
layout-mobile-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-close-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  
layout-quickView-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-edit-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-details-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layoutscontainer-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: ANYRUN

### Scripts

### Playbooks
playbook-Detonate_File_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: fireeye

### Scripts
script-FireEyeDetonateFile.yml depends on: {('CommonScripts', True), ('fireeye', True)}  

### Playbooks
playbook-Detonate_File_-_FireEye_AX.yml depends on: {('CommonScripts', True), ('fireeye', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconSandbox

### Scripts

### Playbooks
playbook-Detonate_File_-_CrowdStrike_Falcon_Sandbox.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  
playbook-Detonate_URL_-_CrowdStrike.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AccessInvestigation

### Scripts

### Playbooks
Access_Investigation_-_Generic.yml depends on: {('CommonScripts', True), ('CommonTypes', True), ('Active_Directory_Query', False), ('CommonPlaybooks', True)}  

### Layouts
layout-edit-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layout-details-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layoutscontainer-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MailSenderNew

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphMail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EWSMailSender

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphListener

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-MicrosoftGraphListener_5_9_9.json depends on: {('Phishing', True)}  
classifier-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incomming-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: GmailSingleUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-gmail-single-user_5_9_9.json depends on: {('Phishing', True)}  
classifier-gmail-single-user.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-gmail-single-user.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: Phishing

### Scripts
CheckEmailAuthenticity.yml depends on: set()  
PhishingDedupPreprocessingRule.yml depends on: {('CommonScripts', True)}  

### Playbooks
Calculate_Severity_By_Email_Authenticity.yml depends on: {('CommonScripts', True)}  
Entity_Enrichment_-_Phishing_v2.yml depends on: {('CommonPlaybooks', True)}  
Get_Original_Email_-_EWS.yml depends on: {('CommonScripts', True), ('EWS', True)}  
Get_Original_Email_-_Gmail.yml depends on: {('CommonScripts', True), ('Gmail', True), ('Phishing', True)}  
Phishing_-_Core.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('rasterize', True), ('Phishing', True), ('CommonPlaybooks', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Phishing_Investigation_-_Generic_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('Phishing', True), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Process_Email_-_Core.yml depends on: {('CommonScripts', True), ('Phishing', True)}  
Process_Email_-_Generic.yml depends on: {('CommonScripts', True), ('Phishing', True), ('CommonPlaybooks', True), ('rasterize', True)}  

### Layouts
layout-quickView-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-details-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-mobile-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-edit-Phishing.json depends on: {('Phishing', True)}  
layoutscontainer-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: rasterize

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pwned

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Recorded_Future

### Scripts
script-RecordedFutureDomainRiskList.yml depends on: set()  
script-RecordedFutureHashRiskList.yml depends on: set()  
script-RecordedFutureIPRiskList.yml depends on: set()  
script-RecordedFutureURLRiskList.yml depends on: set()  
script-RecordedFutureVulnerabilityRiskList.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_Enterprise

### Scripts

### Playbooks
playbook-Anomali_Enterprise-Retro_Forensic_Search.yml depends on: {('Anomali_Enterprise', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Lastline

### Scripts

### Playbooks
playbook-Detonate_File_-_Lastline.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_Lastline_v2.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline_v2.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: IsItPhishing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Ipstack

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AbuseDB

### Scripts
script-AbuseIPDBPopulateIndicators.yml depends on: {('AbuseDB', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HelloWorld

### Scripts
HelloWorldScript.yml depends on: set()  

### Playbooks
playbook-Handle_Hello_World_Alert.yml depends on: {('HelloWorld', True)}  
playbook-HelloWorld_Scan.yml depends on: {('HelloWorld', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Hello_World_Alert-V2.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  
layoutscontainer-Hello_World_Alert.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Hello_World_Alert.json depends on: {('HelloWorld', True)}  

### Classifiers
classifier-HelloWorld_5_9_9.json depends on: {('HelloWorld', True)}  
classifier-HelloWorld.json depends on: {('HelloWorld', True)}  

### Mappers
classifier-mapper-incoming-HelloWorld.json depends on: {('HelloWorld', True)}  

### Widgets


# Pack ID: VirusTotal

### Scripts

### Playbooks
playbook-Detonate_File-VirusTotal.yml depends on: {('CommonScripts', True), ('PolySwarm', False), ('VirusTotal', False), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_Threat_Vault

### Scripts

### Playbooks
Threat_Vault_-_Signature_Search.yml depends on: {('PaloAltoNetworks_Threat_Vault', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ipinfo

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: UrlScan

### Scripts
script-urlscan-get-http-transactions.yml depends on: {('UrlScan', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TruSTAR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Palo_Alto_Networks_WildFire

### Scripts

### Playbooks
playbook-Detonate_URL_-_WildFire-v2.1.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_WildFire-v2.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Zscaler

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AutoFocus

### Scripts

### Playbooks
playbook-Autofocus_Query_Samples_and_Sessions.yml depends on: {('AutoFocus', True)}  
playbook-AutoFocusPolling.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Synapse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Shodan

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pulsedive

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeIntel

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatMiner

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PolySwarm

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cofense-Intelligence

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MaxMind_GeoIP2

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatConnect

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PassiveTotal

### Scripts
script-PTEnrich.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalComponentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairChildrenScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairParentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalPDNSScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalSSLScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalTrackersScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalWhoisScript.yml depends on: {('PassiveTotal', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Flashpoint

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SlashNextPhishingIncidentResponse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EmailRepIO

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_Titanium_Cloud

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: illuminate

### Scripts

### Playbooks
playbook-Analyst1_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  
playbook-illuminate_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AlienVault_OTX

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Maltiverse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_A1000

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: RecordedFuture

### Scripts

### Playbooks
playbook-Recorded_Future_CVE_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_CVE_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IOC_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Threat_Assessment.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Reputation.yml depends on: {('RecordedFuture', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: URLHaus

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Spamcop

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Expanse

### Scripts
ExpanseParseRawIncident.yml depends on: set()  

### Playbooks
Expanse_Behavior_Severity_Update.yml depends on: {('CommonScripts', True), ('Expanse', True)}  
Expanse_Incident_Playbook.yml depends on: {('Expanse', True)}  

### Layouts
layout-details-Expanse_Appearance-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Appearance.json depends on: {('Expanse', True)}  
layout-details-Expanse_Behavior-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: DeHashed

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools_Iris

### Scripts

### Playbooks
playbook-Indicator_Pivoting-DomainTools_Iris.yml depends on: {('DomainTools_Iris', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AwakeSecurity

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeMalquery

### Scripts

### Playbooks
CrowdStrikeMalquery_-_GenericPolling_-_Multidownload_and_Fetch.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  
CrowdStrikeMalquery_-_GenericPolling_-_Search.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Barracuda

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PAN-OS

### Scripts

### Playbooks
playbook-NetOps_-_Firewall_Version_Content_Upgrade.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-NetOps_-_Firewall_Upgrade.yml depends on: {('PAN-OS', True)}  
playbook-NetSec_-_Palo_Alto_Networks_DUG_-_Tag_User.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_-_Add_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Static_Address_Group.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_URL_-_Custom_URL_Category.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_EDL_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Delete_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-Pan-OS_Commit_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-PAN-OS_DAG_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Log_Forwarding_Setup_And_Maintenance.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Query_Logs_For_Indicators.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-Panorama_Query_Logs.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-FirewallUpgrade.json depends on: {('PAN-OS', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: XForceExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Symantec_Deepsight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PhishTank

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TCPIPUtils

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DemistoRESTAPI

### Scripts
script-DemistoCreateList.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoGetIncidentTasksByState.yml depends on: set()  
script-DemistoLeaveAllInvestigations.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLinkIncidents.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLogsBundle.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoSendInvite.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFile.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFileToIncident.yml depends on: {('DemistoRESTAPI', True)}  
DemistoUploadFileV2.yml depends on: {('DemistoRESTAPI', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: isight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Alexa

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: APIVoid

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pipl

### Scripts
script-CheckSender.yml depends on: {('Pipl', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CyberTotal

### Scripts

### Playbooks
CyberTotal_Auto_Enrichment_-_CyCraft.yml depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('IsItPhishing', False), ('Lastline', False), ('Ipstack', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('Polygon', False), ('PaloAltoNetworks_Threat_Vault', False), ('DomainTools_Iris', False), ('ipinfo', False), ('AwakeSecurity', False), ('UrlScan', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('Zscaler', False), ('Barracuda', False), ('PAN-OS', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('ThreatExchange', False), ('isight', False), ('APIVoid', False), ('Alexa', False), ('CyberTotal', False), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False), ('GoogleSafeBrowsing', False)}  
CyberTotal_Whois_-_CyCraft.yml depends on: {('CyberTotal', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: OpenPhish

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MISP

### Scripts
script-misp_download_sample.yml depends on: set()  
script-misp_upload_sample.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EclecticIQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: iDefense

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_ThreatStream

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatStream.yml depends on: {('CommonScripts', True), ('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatStream.yml depends on: {('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cisco-umbrella

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Polygon

### Scripts

### Playbooks
playbook-Detonate_File_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  
playbook-Detonate_URL_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: GoogleSafeBrowsing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Malware

### Scripts

### Playbooks
playbook-Endpoint_Malware_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-edit-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-details-Malware-V2.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Malware.json depends on: {('Malware', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: Compliance

### Scripts
BreachConfirmationHTML.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VulnDB

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CVESearch

### Scripts
script-CveLatest.yml depends on: {('CVESearch', False), ('XForceExchange', False)}  
script-CveSearch.yml depends on: {('XForceExchange', True)}  
script-CveReputation.yml depends on: {('CVESearch', False), ('RecordedFuture', False), ('VulnDB', False)}  

### Playbooks
playbook-CVE_Enrichment_-_Generic.yml depends on: {('XForceExchange', True), ('CVESearch', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Jira

### Scripts
script-JiraCreaetIssueGeneric.yml depends on: {('Jira', True)}  
script-JIRAPrintIssue.yml depends on: {('Jira', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Rapid7_Nexpose

### Scripts
script-NexposeCreateIncidentsFromAssets.yml depends on: {('Rapid7_Nexpose', True)}  
script-NexposeEmailParser.yml depends on: set()  
script-NexposeEmailParserForVuln.yml depends on: set()  
script-NexposeVulnExtractor.yml depends on: set()  

### Playbooks
playbook-Scan_Nexpose_Assets.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Scan_Nexpose_Site.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Vulnerability_Handling_-_Nexpose.yml depends on: {('Rapid7_Nexpose', True), ('CommonTypes', True), ('CVESearch', True)}  
playbook-Vulnerability_Management_-_Nexpose_(Job).yml depends on: {('Rapid7_Nexpose', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JsonWhoIs

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: NIST

### Scripts

### Playbooks
playbook-NIST_-_Access_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('NIST', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-NIST_-_Handling_an_Incident.yml depends on: {('NIST', True)}  

### Layouts
layout-details-NIST-V2.json depends on: {('NIST', True)}  
layoutscontainer-NIST.json depends on: {('NIST', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-NIST.json depends on: {('NIST', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_PAN_OS_EDL_Management

### Scripts

### Playbooks
playbook-Block_IOCs_from_CSV_-_External_Dynamic_List.yml depends on: {('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_Domain_-_External_Dynamic_List.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_IP_and_URL_-_External_Dynamic_List_v2.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_EDL_Setup_v3.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cylance_Protect

### Scripts

### Playbooks
playbook-Block_File_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Endpoint_Enrichment_-_Cylance_Protect_v2.yml depends on: {('CommonScripts', True), ('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: FortiGate

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: D2

### Scripts
script-ActiveUsersD2.yml depends on: set()  
script-Autoruns.yml depends on: set()  
script-CommonD2.yml depends on: set()  
script-CopyFileD2.yml depends on: set()  
script-D2ActiveUsers.yml depends on: set()  
script-D2Autoruns.yml depends on: set()  
script-D2Drop.yml depends on: set()  
script-D2Exec.yml depends on: set()  
script-ExecuteCommandD2.yml depends on: set()  
script-D2GetFile.yml depends on: set()  
script-D2GetSystemLog.yml depends on: set()  
script-D2Hardware.yml depends on: set()  
script-D2O365ComplianceSearch.yml depends on: set()  
script-D2O365SearchAndDelete.yml depends on: set()  
script-D2PEDump.yml depends on: set()  
script-D2Processes.yml depends on: set()  
script-D2RegQuery.yml depends on: set()  
script-D2Rekall.yml depends on: set()  
D2Remove.yml depends on: set()  
script-D2Services.yml depends on: set()  
script-D2Users.yml depends on: set()  
script-D2Winpmem.yml depends on: set()  
script-FetchFileD2.yml depends on: set()  
script-O365SearchEmails.yml depends on: {('D2', True)}  
script-RegCollectValues.yml depends on: set()  
script-RegPathReputationBasicLists.yml depends on: set()  
script-RegProbeBasic.yml depends on: set()  
script-StaticAnalyze.yml depends on: {('D2', True)}  

### Playbooks
playbook-D2_-_Endpoint_data_collection.yml depends on: {('CommonScripts', True), ('D2', True)}  
playbook-Get_File_Sample_From_Path_-_D2.yml depends on: {('CommonScripts', True), ('D2', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: McAfee_Advanced_Threat_Defense

### Scripts
script-ATDDetonate.yml depends on: {('McAfee_Advanced_Threat_Defense', True)}  

### Playbooks
playbook-Detonate_File_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_Remote_File_from_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cybereason

### Scripts
script-CybereasonPreProcessing.yml depends on: set()  

### Playbooks
playbook-Block_File_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Isolate_Endpoint_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Search_Endpoints_By_Hash_-_Cybereason.yml depends on: {('Cybereason', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ImageOCR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatGrid

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatGrid.yml depends on: {('CommonScripts', True), ('ThreatGrid', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatGrid.yml depends on: {('ThreatGrid', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HybridAnalysis

### Scripts

### Playbooks
playbook-Detonate_File_-_HybridAnalysis.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  
playbook-Hybrid-analysis_quick-scan.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CheckpointFirewall

### Scripts
CheckPointDownloadBackup.yml depends on: {('CheckpointFirewall', True)}  
CheckpointFWBackupStatus.yml depends on: set()  
CheckpointFWCreateBackup.yml depends on: set()  

### Playbooks
Checkpoint_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Block_URL.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Publish&Install_configuration.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CarbonBlackProtect

### Scripts
script-CBPApproveHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPBanHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPCatalogFindHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindComputer.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindRule.yml depends on: {('CarbonBlackProtect', True)}  

### Playbooks
playbook-Carbon_black_Protection_Rapid_IOC_Hunting.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  
playbook-Search_Endpoints_By_Hash_-_Carbon_Black_Protection.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SNDBOX

### Scripts

### Playbooks
playbook-Detonate_File_-_SNDBOX.yml depends on: {('CommonScripts', True), ('SNDBOX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Threat_Crowd

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VirusTotal-Private_API

### Scripts

### Playbooks
playbook-File_Enrichment_-_Virus_Total_Private_API.yml depends on: {('VirusTotal-Private_API', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JoeSecurity

### Scripts

### Playbooks
playbook-Detonate_File_From_URL_-_JoeSecurity.yml depends on: {('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VMRay

### Scripts

### Playbooks
playbook-VMRay-Detonate-File.yml depends on: {('VMRay', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CuckooSandbox

### Scripts
script-CuckooDetonateFile.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDetonateURL.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDisplayReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetScreenshot.yml depends on: {('CuckooSandbox', True)}  
script-CuckooTaskStatus.yml depends on: {('CuckooSandbox', True)}  

### Playbooks
playbook-Detonate_File_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeHost

### Scripts
script-CrowdStrikeUrlParse.yml depends on: set()  

### Playbooks
playbook-CrowdStrike_Rapid_IOC_Hunting_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CrowdStrikeHost', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-CrowdStrike_Endpoint_Enrichment.yml depends on: {('CrowdStrikeHost', True)}  
playbook-Search_Endpoints_By_Hash_-_CrowdStrike.yml depends on: {('CrowdStrikeHost', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Traps

### Scripts

### Playbooks
playbook-Traps_Blacklist_File.yml depends on: {('Traps', True)}  
playbook-Isolate_Endpoint_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Block_File_-_Quarantine_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Retrieve_And_Download_Files.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Scan_Endpoint.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  
layoutscontainer-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Traps.json depends on: {('PANWComprehensiveInvestigation', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconX

### Scripts

### Playbooks
Detonate_File_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
Detonate_URL_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ExtraHop

### Scripts
ExtraHopTrackIncidents.yml depends on: {('ExtraHop', True)}  

### Playbooks
playbook-ExtraHop_-_CVE-2019-0708_(BlueKeep).yml depends on: {('CommonScripts', True), ('ExtraHop', True), ('CommonPlaybooks', True)}  
playbook-ExtraHop_-_Default.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Get_Peers_by_Host.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Ticket_Tracking_v2.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  

### Layouts
layout-mobile-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-close-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  
layout-quickView-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-edit-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-details-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layoutscontainer-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: ANYRUN

### Scripts

### Playbooks
playbook-Detonate_File_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: fireeye

### Scripts
script-FireEyeDetonateFile.yml depends on: {('CommonScripts', True), ('fireeye', True)}  

### Playbooks
playbook-Detonate_File_-_FireEye_AX.yml depends on: {('CommonScripts', True), ('fireeye', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconSandbox

### Scripts

### Playbooks
playbook-Detonate_File_-_CrowdStrike_Falcon_Sandbox.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  
playbook-Detonate_URL_-_CrowdStrike.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AccessInvestigation

### Scripts

### Playbooks
Access_Investigation_-_Generic.yml depends on: {('CommonScripts', True), ('CommonTypes', True), ('Active_Directory_Query', False), ('CommonPlaybooks', True)}  

### Layouts
layout-edit-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layout-details-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layoutscontainer-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: BruteForce

### Scripts

### Playbooks
Brute_Force_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Compliance', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('BruteForce', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-details-Brute_Force-V2.json depends on: {('BruteForce', True), ('CommonTypes', True), ('Compliance', True)}  
layoutscontainer-Brute_Force.json depends on: {('BruteForce', True), ('CommonTypes', True), ('Compliance', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Brute_Force.json depends on: {('BruteForce', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ServiceNow

### Scripts
ServiceNowCreateIncident.yml depends on: {('ServiceNow', True)}  
ServiceNowIncidentStatus.yml depends on: set()  
ServiceNowQueryIncident.yml depends on: {('ServiceNow', True)}  
ServiceNowUpdateIncident.yml depends on: {('ServiceNow', True)}  

### Playbooks
playbook-Create_ServiceNow_Ticket.yml depends on: {('ServiceNow', True)}  
playbook-Mirror_ServiceNow_Ticket.yml depends on: {('ServiceNow', True), ('CommonPlaybooks', True)}  
playbook-ServiceNow_Ticket_State_Polling.yml depends on: {('CommonScripts', True)}  

### Layouts
layoutscontainer-ServiceNow_Create_Ticket_and_Mirror.json depends on: {('ServiceNow', True), ('CommonTypes', True), ('Phishing', True)}  
layout-details-ServiceNow_Ticket.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
layoutscontainer-ServiceNow_Ticket.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-ServiceNow.json depends on: {('ServiceNow', True)}  
classifier-ServiceNow_5_9_9.json depends on: {('ServiceNow', True)}  

### Mappers
classifier-mapper-ServiceNow_Create_Ticket_-_Incoming_Mapper.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-incoming-ServiceNow.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-outgoing-ServiceNow.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-incoming-User-Profile-ServiceNow.json depends on: {('CommonTypes', True)}  
classifier-mapper-outgoing-ServiceNow-User-Profile.json depends on: {('CommonTypes', True)}  

### Widgets


# Pack ID: PANWComprehensiveInvestigation

### Scripts
PanwIndicatorCreateQueries.yml depends on: set()  

### Playbooks
Palo_Alto_Networks_-_Endpoint_Malware_Investigation.yml depends on: {('Traps', False), ('PANWComprehensiveInvestigation', False), ('Palo_Alto_Networks_WildFire', False), ('CommonTypes', True), ('Traps', True), ('CommonPlaybooks', True), ('AutoFocus', True)}  
Palo_Alto_Networks_-_Endpoint_Malware_Investigation_v3.yml depends on: {('CommonPlaybooks', True), ('DemistoRESTAPI', True), ('CommonScripts', True), ('CommonTypes', True), ('CortexXDR', False), ('PANWComprehensiveInvestigation', True), ('AutoFocus', True), ('Active_Directory_Query', True), ('Palo_Alto_Networks_WildFire', False)}  
Palo_Alto_Networks_-_Hunting_And_Threat_Detection.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('CortexDataLake', True), ('CommonPlaybooks', True), ('AutoFocus', True)}  
Palo_Alto_Networks_-_Malware_Remediation.yml depends on: {('CortexXDR', False), ('PaloAltoNetworks_PAN_OS_EDL_Management', False), ('PAN-OS', False), ('Traps', False)}  

### Layouts
layout-details-PANW_Endpoint_Malware-V2.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  
layoutscontainer-PANW_Endpoint_Malware.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Carbon_Black_Enterprise_Live_Response

### Scripts
script-CBLiveProcessList.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True)}  

### Playbooks
playbook-Carbon_Black_Live_Response_-_Create_active_session.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True), ('CommonPlaybooks', True)}  
playbook-Carbon_Black_Live_Response_-_Download_file.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True)}  
playbook-Carbon_Black_Live_Response_-_Wait_until_command_complete.yml depends on: {('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MailSenderNew

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphMail

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EWSMailSender

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphListener

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-MicrosoftGraphListener_5_9_9.json depends on: {('Phishing', True)}  
classifier-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incomming-MicrosoftGraphListener.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: GmailSingleUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-gmail-single-user_5_9_9.json depends on: {('Phishing', True)}  
classifier-gmail-single-user.json depends on: {('Phishing', True)}  

### Mappers
classifier-mapper-incoming-gmail-single-user.json depends on: {('Phishing', True)}  

### Widgets


# Pack ID: Phishing

### Scripts
CheckEmailAuthenticity.yml depends on: set()  
PhishingDedupPreprocessingRule.yml depends on: {('CommonScripts', True)}  

### Playbooks
Calculate_Severity_By_Email_Authenticity.yml depends on: {('CommonScripts', True)}  
Entity_Enrichment_-_Phishing_v2.yml depends on: {('CommonPlaybooks', True)}  
Get_Original_Email_-_EWS.yml depends on: {('CommonScripts', True), ('EWS', True)}  
Get_Original_Email_-_Gmail.yml depends on: {('CommonScripts', True), ('Gmail', True), ('Phishing', True)}  
Phishing_-_Core.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('rasterize', True), ('Phishing', True), ('CommonPlaybooks', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Phishing_Investigation_-_Generic_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('Phishing', True), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
Process_Email_-_Core.yml depends on: {('CommonScripts', True), ('Phishing', True)}  
Process_Email_-_Generic.yml depends on: {('CommonScripts', True), ('Phishing', True), ('CommonPlaybooks', True), ('rasterize', True)}  

### Layouts
layout-quickView-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-details-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-mobile-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  
layout-edit-Phishing.json depends on: {('Phishing', True)}  
layoutscontainer-Phishing.json depends on: {('CommonTypes', True), ('Phishing', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: rasterize

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pwned

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Recorded_Future

### Scripts
script-RecordedFutureDomainRiskList.yml depends on: set()  
script-RecordedFutureHashRiskList.yml depends on: set()  
script-RecordedFutureIPRiskList.yml depends on: set()  
script-RecordedFutureURLRiskList.yml depends on: set()  
script-RecordedFutureVulnerabilityRiskList.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_Enterprise

### Scripts

### Playbooks
playbook-Anomali_Enterprise-Retro_Forensic_Search.yml depends on: {('Anomali_Enterprise', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Lastline

### Scripts

### Playbooks
playbook-Detonate_File_-_Lastline.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_Lastline_v2.yml depends on: {('CommonScripts', True), ('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Lastline_v2.yml depends on: {('Lastline', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: IsItPhishing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Ipstack

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AbuseDB

### Scripts
script-AbuseIPDBPopulateIndicators.yml depends on: {('AbuseDB', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HelloWorld

### Scripts
HelloWorldScript.yml depends on: set()  

### Playbooks
playbook-Handle_Hello_World_Alert.yml depends on: {('HelloWorld', True)}  
playbook-HelloWorld_Scan.yml depends on: {('HelloWorld', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Hello_World_Alert-V2.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  
layoutscontainer-Hello_World_Alert.json depends on: {('HelloWorld', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Hello_World_Alert.json depends on: {('HelloWorld', True)}  

### Classifiers
classifier-HelloWorld_5_9_9.json depends on: {('HelloWorld', True)}  
classifier-HelloWorld.json depends on: {('HelloWorld', True)}  

### Mappers
classifier-mapper-incoming-HelloWorld.json depends on: {('HelloWorld', True)}  

### Widgets


# Pack ID: VirusTotal

### Scripts

### Playbooks
playbook-Detonate_File-VirusTotal.yml depends on: {('CommonScripts', True), ('PolySwarm', False), ('VirusTotal', False), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_Threat_Vault

### Scripts

### Playbooks
Threat_Vault_-_Signature_Search.yml depends on: {('PaloAltoNetworks_Threat_Vault', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ipinfo

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: UrlScan

### Scripts
script-urlscan-get-http-transactions.yml depends on: {('UrlScan', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TruSTAR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Palo_Alto_Networks_WildFire

### Scripts

### Playbooks
playbook-Detonate_URL_-_WildFire-v2.1.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_WildFire-v2.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_WildFire.yml depends on: {('Palo_Alto_Networks_WildFire', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Zscaler

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AutoFocus

### Scripts

### Playbooks
playbook-Autofocus_Query_Samples_and_Sessions.yml depends on: {('AutoFocus', True)}  
playbook-AutoFocusPolling.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Synapse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Shodan

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pulsedive

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeIntel

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatMiner

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PolySwarm

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cofense-Intelligence

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MaxMind_GeoIP2

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatConnect

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PassiveTotal

### Scripts
script-PTEnrich.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalComponentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairChildrenScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalHostPairParentsScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalPDNSScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalSSLScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalTrackersScript.yml depends on: {('PassiveTotal', True)}  
RiskIQPassiveTotalWhoisScript.yml depends on: {('PassiveTotal', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Flashpoint

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SlashNextPhishingIncidentResponse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EmailRepIO

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_Titanium_Cloud

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: illuminate

### Scripts

### Playbooks
playbook-Analyst1_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  
playbook-illuminate_Integration_Demonstration.yml depends on: {('CommonScripts', True), ('illuminate', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AlienVault_OTX

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Maltiverse

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ReversingLabs_A1000

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: RecordedFuture

### Scripts

### Playbooks
playbook-Recorded_Future_CVE_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_CVE_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Domain_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_File_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IOC_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_IP_Reputation.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_Threat_Assessment.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Intelligence.yml depends on: {('RecordedFuture', True)}  
playbook-Recorded_Future_URL_Reputation.yml depends on: {('RecordedFuture', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: URLHaus

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Spamcop

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Expanse

### Scripts
ExpanseParseRawIncident.yml depends on: set()  

### Playbooks
Expanse_Behavior_Severity_Update.yml depends on: {('CommonScripts', True), ('Expanse', True)}  
Expanse_Incident_Playbook.yml depends on: {('Expanse', True)}  

### Layouts
layout-details-Expanse_Appearance-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Appearance.json depends on: {('Expanse', True)}  
layout-details-Expanse_Behavior-V2.json depends on: {('Expanse', True)}  
layoutscontainer-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Expanse_Behavior.json depends on: {('Expanse', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: DeHashed

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DomainTools_Iris

### Scripts

### Playbooks
playbook-Indicator_Pivoting-DomainTools_Iris.yml depends on: {('DomainTools_Iris', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AwakeSecurity

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeMalquery

### Scripts

### Playbooks
CrowdStrikeMalquery_-_GenericPolling_-_Multidownload_and_Fetch.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  
CrowdStrikeMalquery_-_GenericPolling_-_Search.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeMalquery', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Barracuda

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PAN-OS

### Scripts

### Playbooks
playbook-NetOps_-_Firewall_Version_Content_Upgrade.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-NetOps_-_Firewall_Upgrade.yml depends on: {('PAN-OS', True)}  
playbook-NetSec_-_Palo_Alto_Networks_DUG_-_Tag_User.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_-_Add_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_IP_-_Static_Address_Group.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Block_URL_-_Custom_URL_Category.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_EDL_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Create_Or_Edit_Rule.yml depends on: {('PAN-OS', True)}  
playbook-PAN-OS_-_Delete_Static_Routes.yml depends on: {('PAN-OS', True)}  
playbook-Pan-OS_Commit_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-PAN-OS_DAG_Configuration.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Log_Forwarding_Setup_And_Maintenance.yml depends on: {('PAN-OS', True), ('CommonScripts', True)}  
playbook-PAN-OS_Query_Logs_For_Indicators.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  
playbook-Panorama_Query_Logs.yml depends on: {('PAN-OS', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-FirewallUpgrade.json depends on: {('PAN-OS', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: XForceExchange

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Symantec_Deepsight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: PhishTank

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: TCPIPUtils

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: DemistoRESTAPI

### Scripts
script-DemistoCreateList.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoGetIncidentTasksByState.yml depends on: set()  
script-DemistoLeaveAllInvestigations.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLinkIncidents.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoLogsBundle.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoSendInvite.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFile.yml depends on: {('DemistoRESTAPI', True)}  
script-DemistoUploadFileToIncident.yml depends on: {('DemistoRESTAPI', True)}  
DemistoUploadFileV2.yml depends on: {('DemistoRESTAPI', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: isight

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Alexa

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: APIVoid

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Pipl

### Scripts
script-CheckSender.yml depends on: {('Pipl', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CyberTotal

### Scripts

### Playbooks
CyberTotal_Auto_Enrichment_-_CyCraft.yml depends on: {('Cofense-Intelligence', False), ('Pwned', False), ('MaxMind_GeoIP2', False), ('ThreatConnect', False), ('XMCyber', False), ('PassiveTotal', False), ('Flashpoint', False), ('SlashNextPhishingIncidentResponse', False), ('Recorded_Future', False), ('Anomali_Enterprise', False), ('CommonScripts', True), ('IsItPhishing', False), ('Lastline', False), ('Ipstack', False), ('ReversingLabs_Titanium_Cloud', False), ('illuminate', False), ('AlienVault_OTX', False), ('Maltiverse', False), ('ReversingLabs_A1000', False), ('Zimperium', False), ('RecordedFuture', False), ('URLHaus', False), ('AbuseDB', False), ('ThreatQ', False), ('Spamcop', False), ('HelloWorld', False), ('VirusTotal', False), ('Expanse', False), ('Polygon', False), ('PaloAltoNetworks_Threat_Vault', False), ('DomainTools_Iris', False), ('ipinfo', False), ('AwakeSecurity', False), ('UrlScan', False), ('TruSTAR', False), ('Palo_Alto_Networks_WildFire', False), ('McAfee-TIE', False), ('Zscaler', False), ('Barracuda', False), ('PAN-OS', False), ('CrowdStrikeMalquery', False), ('XForceExchange', False), ('Symantec_Deepsight', False), ('PhishTank', False), ('AutoFocus', False), ('Synapse', False), ('TCPIPUtils', False), ('Shodan', False), ('ThreatExchange', False), ('isight', False), ('APIVoid', False), ('Alexa', False), ('CyberTotal', False), ('OpenPhish', False), ('MISP', False), ('EclecticIQ', False), ('Pulsedive', False), ('iDefense', False), ('Anomali_ThreatStream', False), ('CrowdStrikeIntel', False), ('DomainTools', False), ('Whois', False), ('ThreatMiner', False), ('Cisco-umbrella', False), ('PolySwarm', False), ('GoogleChronicleBackstory', False), ('GoogleSafeBrowsing', False)}  
CyberTotal_Whois_-_CyCraft.yml depends on: {('CyberTotal', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: OpenPhish

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: MISP

### Scripts
script-misp_download_sample.yml depends on: set()  
script-misp_upload_sample.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: EclecticIQ

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: iDefense

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Anomali_ThreatStream

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatStream.yml depends on: {('CommonScripts', True), ('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatStream.yml depends on: {('Anomali_ThreatStream', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cisco-umbrella

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Polygon

### Scripts

### Playbooks
playbook-Detonate_File_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  
playbook-Detonate_URL_-_Group-IB_TDS_Polygon.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('Polygon', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: GoogleSafeBrowsing

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Malware

### Scripts

### Playbooks
playbook-Endpoint_Malware_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-edit-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  
layout-details-Malware-V2.json depends on: {('CommonTypes', True), ('Malware', True)}  
layoutscontainer-Malware.json depends on: {('CommonTypes', True), ('Malware', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Malware.json depends on: {('Malware', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: Compliance

### Scripts
BreachConfirmationHTML.yml depends on: set()  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VulnDB

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CVESearch

### Scripts
script-CveLatest.yml depends on: {('CVESearch', False), ('XForceExchange', False)}  
script-CveSearch.yml depends on: {('XForceExchange', True)}  
script-CveReputation.yml depends on: {('CVESearch', False), ('RecordedFuture', False), ('VulnDB', False)}  

### Playbooks
playbook-CVE_Enrichment_-_Generic.yml depends on: {('XForceExchange', True), ('CVESearch', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Jira

### Scripts
script-JiraCreaetIssueGeneric.yml depends on: {('Jira', True)}  
script-JIRAPrintIssue.yml depends on: {('Jira', True)}  

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Rapid7_Nexpose

### Scripts
script-NexposeCreateIncidentsFromAssets.yml depends on: {('Rapid7_Nexpose', True)}  
script-NexposeEmailParser.yml depends on: set()  
script-NexposeEmailParserForVuln.yml depends on: set()  
script-NexposeVulnExtractor.yml depends on: set()  

### Playbooks
playbook-Scan_Nexpose_Assets.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Scan_Nexpose_Site.yml depends on: {('Rapid7_Nexpose', True), ('CommonPlaybooks', True)}  
playbook-Vulnerability_Handling_-_Nexpose.yml depends on: {('Rapid7_Nexpose', True), ('CommonTypes', True), ('CVESearch', True)}  
playbook-Vulnerability_Management_-_Nexpose_(Job).yml depends on: {('Rapid7_Nexpose', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JsonWhoIs

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: NIST

### Scripts

### Playbooks
playbook-NIST_-_Access_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('NIST', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-NIST_-_Handling_an_Incident.yml depends on: {('NIST', True)}  

### Layouts
layout-details-NIST-V2.json depends on: {('NIST', True)}  
layoutscontainer-NIST.json depends on: {('NIST', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-NIST.json depends on: {('NIST', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: PaloAltoNetworks_PAN_OS_EDL_Management

### Scripts

### Playbooks
playbook-Block_IOCs_from_CSV_-_External_Dynamic_List.yml depends on: {('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_Domain_-_External_Dynamic_List.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_-_Block_IP_and_URL_-_External_Dynamic_List_v2.yml depends on: {('PAN-OS', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  
playbook-PAN-OS_EDL_Setup_v3.yml depends on: {('PAN-OS', True), ('CommonScripts', True), ('PaloAltoNetworks_PAN_OS_EDL_Management', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cylance_Protect

### Scripts

### Playbooks
playbook-Block_File_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Endpoint_Enrichment_-_Cylance_Protect_v2.yml depends on: {('CommonScripts', True), ('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect_v2.yml depends on: {('Cylance_Protect', True)}  
playbook-Get_File_Sample_By_Hash_-_Cylance_Protect.yml depends on: {('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: FortiGate

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: D2

### Scripts
script-ActiveUsersD2.yml depends on: set()  
script-Autoruns.yml depends on: set()  
script-CommonD2.yml depends on: set()  
script-CopyFileD2.yml depends on: set()  
script-D2ActiveUsers.yml depends on: set()  
script-D2Autoruns.yml depends on: set()  
script-D2Drop.yml depends on: set()  
script-D2Exec.yml depends on: set()  
script-ExecuteCommandD2.yml depends on: set()  
script-D2GetFile.yml depends on: set()  
script-D2GetSystemLog.yml depends on: set()  
script-D2Hardware.yml depends on: set()  
script-D2O365ComplianceSearch.yml depends on: set()  
script-D2O365SearchAndDelete.yml depends on: set()  
script-D2PEDump.yml depends on: set()  
script-D2Processes.yml depends on: set()  
script-D2RegQuery.yml depends on: set()  
script-D2Rekall.yml depends on: set()  
D2Remove.yml depends on: set()  
script-D2Services.yml depends on: set()  
script-D2Users.yml depends on: set()  
script-D2Winpmem.yml depends on: set()  
script-FetchFileD2.yml depends on: set()  
script-O365SearchEmails.yml depends on: {('D2', True)}  
script-RegCollectValues.yml depends on: set()  
script-RegPathReputationBasicLists.yml depends on: set()  
script-RegProbeBasic.yml depends on: set()  
script-StaticAnalyze.yml depends on: {('D2', True)}  

### Playbooks
playbook-D2_-_Endpoint_data_collection.yml depends on: {('CommonScripts', True), ('D2', True)}  
playbook-Get_File_Sample_From_Path_-_D2.yml depends on: {('CommonScripts', True), ('D2', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: McAfee_Advanced_Threat_Defense

### Scripts
script-ATDDetonate.yml depends on: {('McAfee_Advanced_Threat_Defense', True)}  

### Playbooks
playbook-Detonate_File_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_Remote_File_from_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  
playbook-Detonate_URL_-_McAfee_ATD.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('McAfee_Advanced_Threat_Defense', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Cybereason

### Scripts
script-CybereasonPreProcessing.yml depends on: set()  

### Playbooks
playbook-Block_File_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Isolate_Endpoint_-_Cybereason.yml depends on: {('Cybereason', True)}  
playbook-Search_Endpoints_By_Hash_-_Cybereason.yml depends on: {('Cybereason', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ImageOCR

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ThreatGrid

### Scripts

### Playbooks
playbook-Detonate_File_-_ThreatGrid.yml depends on: {('CommonScripts', True), ('ThreatGrid', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ThreatGrid.yml depends on: {('ThreatGrid', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: HybridAnalysis

### Scripts

### Playbooks
playbook-Detonate_File_-_HybridAnalysis.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  
playbook-Hybrid-analysis_quick-scan.yml depends on: {('CommonPlaybooks', True), ('HybridAnalysis', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CheckpointFirewall

### Scripts
CheckPointDownloadBackup.yml depends on: {('CheckpointFirewall', True)}  
CheckpointFWBackupStatus.yml depends on: set()  
CheckpointFWCreateBackup.yml depends on: set()  

### Playbooks
Checkpoint_-_Block_IP_-_Custom_Block_Rule.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Block_URL.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True)}  
Checkpoint_-_Publish&Install_configuration.yml depends on: {('CommonScripts', True), ('CheckpointFirewall', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CarbonBlackProtect

### Scripts
script-CBPApproveHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPBanHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPCatalogFindHash.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindComputer.yml depends on: {('CarbonBlackProtect', True)}  
script-CBPFindRule.yml depends on: {('CarbonBlackProtect', True)}  

### Playbooks
playbook-Carbon_black_Protection_Rapid_IOC_Hunting.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  
playbook-Search_Endpoints_By_Hash_-_Carbon_Black_Protection.yml depends on: {('CarbonBlackProtect', True), ('CommonScripts', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: SNDBOX

### Scripts

### Playbooks
playbook-Detonate_File_-_SNDBOX.yml depends on: {('CommonScripts', True), ('SNDBOX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Threat_Crowd

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VirusTotal-Private_API

### Scripts

### Playbooks
playbook-File_Enrichment_-_Virus_Total_Private_API.yml depends on: {('VirusTotal-Private_API', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: JoeSecurity

### Scripts

### Playbooks
playbook-Detonate_File_From_URL_-_JoeSecurity.yml depends on: {('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_-_JoeSecurity.yml depends on: {('CommonScripts', True), ('JoeSecurity', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: VMRay

### Scripts

### Playbooks
playbook-VMRay-Detonate-File.yml depends on: {('VMRay', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CuckooSandbox

### Scripts
script-CuckooDetonateFile.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDetonateURL.yml depends on: {('CuckooSandbox', True)}  
script-CuckooDisplayReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetReport.yml depends on: {('CuckooSandbox', True)}  
script-CuckooGetScreenshot.yml depends on: {('CuckooSandbox', True)}  
script-CuckooTaskStatus.yml depends on: {('CuckooSandbox', True)}  

### Playbooks
playbook-Detonate_File_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_Cuckoo.yml depends on: {('CuckooSandbox', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeHost

### Scripts
script-CrowdStrikeUrlParse.yml depends on: set()  

### Playbooks
playbook-CrowdStrike_Rapid_IOC_Hunting_v2.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CrowdStrikeHost', True), ('CommonScripts', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False)}  
playbook-CrowdStrike_Endpoint_Enrichment.yml depends on: {('CrowdStrikeHost', True)}  
playbook-Search_Endpoints_By_Hash_-_CrowdStrike.yml depends on: {('CrowdStrikeHost', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: Traps

### Scripts

### Playbooks
playbook-Traps_Blacklist_File.yml depends on: {('Traps', True)}  
playbook-Isolate_Endpoint_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Block_File_-_Quarantine_-_Traps.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Retrieve_And_Download_Files.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  
playbook-Traps_Scan_Endpoint.yml depends on: {('Traps', True), ('CommonPlaybooks', True)}  

### Layouts
layout-details-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  
layoutscontainer-Traps.json depends on: {('Malware', True), ('CortexXDR', True), ('CommonTypes', True), ('Traps', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Traps.json depends on: {('PANWComprehensiveInvestigation', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconX

### Scripts

### Playbooks
Detonate_File_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonScripts', True), ('CommonPlaybooks', True)}  
Detonate_URL_-_CrowdStrike_Falcon_X.yml depends on: {('CrowdStrikeFalconX', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ExtraHop

### Scripts
ExtraHopTrackIncidents.yml depends on: {('ExtraHop', True)}  

### Playbooks
playbook-ExtraHop_-_CVE-2019-0708_(BlueKeep).yml depends on: {('CommonScripts', True), ('ExtraHop', True), ('CommonPlaybooks', True)}  
playbook-ExtraHop_-_Default.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Get_Peers_by_Host.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  
playbook-ExtraHop_-_Ticket_Tracking_v2.yml depends on: {('CommonScripts', True), ('ExtraHop', True)}  

### Layouts
layout-mobile-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-close-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  
layout-quickView-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-edit-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layout-details-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  
layoutscontainer-ExtraHop_Detection.json depends on: {('CommonTypes', True), ('ExtraHop', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-ExtraHop_Detection.json depends on: {('ExtraHop', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: ANYRUN

### Scripts

### Playbooks
playbook-Detonate_File_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_File_From_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  
playbook-Detonate_URL_-_ANYRUN.yml depends on: {('ANYRUN', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: fireeye

### Scripts
script-FireEyeDetonateFile.yml depends on: {('CommonScripts', True), ('fireeye', True)}  

### Playbooks
playbook-Detonate_File_-_FireEye_AX.yml depends on: {('CommonScripts', True), ('fireeye', True), ('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CrowdStrikeFalconSandbox

### Scripts

### Playbooks
playbook-Detonate_File_-_CrowdStrike_Falcon_Sandbox.yml depends on: {('CommonScripts', True), ('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  
playbook-Detonate_URL_-_CrowdStrike.yml depends on: {('CommonPlaybooks', True), ('CrowdStrikeFalconSandbox', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: AccessInvestigation

### Scripts

### Playbooks
Access_Investigation_-_Generic.yml depends on: {('CommonScripts', True), ('CommonTypes', True), ('Active_Directory_Query', False), ('CommonPlaybooks', True)}  

### Layouts
layout-edit-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layout-details-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  
layoutscontainer-Access.json depends on: {('AccessInvestigation', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: BruteForce

### Scripts

### Playbooks
Brute_Force_Investigation_-_Generic.yml depends on: {('MailSenderNew', False), ('MicrosoftGraphMail', False), ('Gmail', False), ('EWSMailSender', False), ('CommonPlaybooks', True), ('Compliance', True), ('Active_Directory_Query', True), ('CommonScripts', True), ('BruteForce', True), ('EWS', False), ('MicrosoftGraphListener', False), ('GmailSingleUser', False), ('CommonTypes', True)}  

### Layouts
layout-details-Brute_Force-V2.json depends on: {('BruteForce', True), ('CommonTypes', True), ('Compliance', True)}  
layoutscontainer-Brute_Force.json depends on: {('BruteForce', True), ('CommonTypes', True), ('Compliance', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types
incidenttype-Brute_Force.json depends on: {('BruteForce', True)}  

### Classifiers

### Mappers

### Widgets


# Pack ID: MicrosoftGraphUser

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: ServiceNow

### Scripts
ServiceNowCreateIncident.yml depends on: {('ServiceNow', True)}  
ServiceNowIncidentStatus.yml depends on: set()  
ServiceNowQueryIncident.yml depends on: {('ServiceNow', True)}  
ServiceNowUpdateIncident.yml depends on: {('ServiceNow', True)}  

### Playbooks
playbook-Create_ServiceNow_Ticket.yml depends on: {('ServiceNow', True)}  
playbook-Mirror_ServiceNow_Ticket.yml depends on: {('ServiceNow', True), ('CommonPlaybooks', True)}  
playbook-ServiceNow_Ticket_State_Polling.yml depends on: {('CommonScripts', True)}  

### Layouts
layoutscontainer-ServiceNow_Create_Ticket_and_Mirror.json depends on: {('ServiceNow', True), ('CommonTypes', True), ('Phishing', True)}  
layout-details-ServiceNow_Ticket.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
layoutscontainer-ServiceNow_Ticket.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers
classifier-ServiceNow.json depends on: {('ServiceNow', True)}  
classifier-ServiceNow_5_9_9.json depends on: {('ServiceNow', True)}  

### Mappers
classifier-mapper-ServiceNow_Create_Ticket_-_Incoming_Mapper.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-incoming-ServiceNow.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-outgoing-ServiceNow.json depends on: {('ServiceNow', True), ('CommonTypes', True)}  
classifier-mapper-incoming-User-Profile-ServiceNow.json depends on: {('CommonTypes', True)}  
classifier-mapper-outgoing-ServiceNow-User-Profile.json depends on: {('CommonTypes', True)}  

### Widgets


# Pack ID: Carbon_Black_Enterprise_Live_Response

### Scripts
script-CBLiveProcessList.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True)}  

### Playbooks
playbook-Carbon_Black_Live_Response_-_Create_active_session.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True), ('CommonPlaybooks', True)}  
playbook-Carbon_Black_Live_Response_-_Download_file.yml depends on: {('Carbon_Black_Enterprise_Live_Response', True)}  
playbook-Carbon_Black_Live_Response_-_Wait_until_command_complete.yml depends on: {('CommonPlaybooks', True)}  

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets


# Pack ID: CortexDataLake

### Scripts

### Playbooks

### Layouts

### Incident Fields

### Indicator Types

### Integrations

### Incident Types

### Classifiers

### Mappers

### Widgets
