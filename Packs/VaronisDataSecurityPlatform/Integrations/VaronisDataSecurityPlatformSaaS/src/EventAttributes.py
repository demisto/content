import fnmatch


class EventAttributes:
    Event_StatusReason_Name = "Event.StatusReason.Name"
    Event_StatusReason_ID = "Event.StatusReason.ID"
    Event_Location_BlacklistedLocation = "Event.Location.BlacklistedLocation"
    Event_Location_Subdivision_Name = "Event.Location.Subdivision.Name"
    Event_Location_Subdivision_ID = "Event.Location.Subdivision.ID"
    Event_Location_Country_Name = "Event.Location.Country.Name"
    Event_Location_Country_ID = "Event.Location.Country.ID"
    Event_Filer_Platform_Name = "Event.Filer.Platform.Name"
    Event_Filer_Platform_ID = "Event.Filer.Platform.ID"
    Event_OnResource_Stats_ExposureLevel_Name = "Event.OnResource.Stats.ExposureLevel.Name"
    Event_OnResource_Stats_ExposureLevel_ID = "Event.OnResource.Stats.ExposureLevel.ID"
    Event_ByAccount_Identity_Followup_Flag_Name = "Event.ByAccount.Identity.Followup.Flag.Name"
    Event_ByAccount_Identity_Followup_Flag_ID = "Event.ByAccount.Identity.Followup.Flag.ID"
    Event_ByAccount_SamAccountName = "Event.ByAccount.SamAccountName"
    Event_ByAccount_SidID = "Event.ByAccount.SidID"
    Event_ByAccount_Type_Name = "Event.ByAccount.Type.Name"
    Event_ByAccount_Type_ID = "Event.ByAccount.Type.ID"
    Event_ByAccount_DistinguishedName = "Event.ByAccount.DistinguishedName"
    Event_OnAccount_Domain_Name = "Event.OnAccount.Domain.Name"
    Event_OnAccount_Domain_ID = "Event.OnAccount.Domain.ID"
    Event_OnAccount_Identity_Followup_Flag_Name = "Event.OnAccount.Identity.Followup.Flag.Name"
    Event_OnAccount_Identity_Followup_Flag_ID = "Event.OnAccount.Identity.Followup.Flag.ID"
    Event_Time = "Event.Time"
    Event_Operation_Name = "Event.Operation.Name"
    Event_Operation_ID = "Event.Operation.ID"
    Event_EndTime = "Event.EndTime"
    Event_Type_Name = "Event.Type.Name"
    Event_Type_ID = "Event.Type.ID"
    Event_ByAccount_Identity_Name = "Event.ByAccount.Identity.Name"
    Event_ByAccount_Identity_ID = "Event.ByAccount.Identity.ID"
    Event_OnAccount_DNSDomain_Name = "Event.OnAccount.DNSDomain.Name"
    Event_OnAccount_DNSDomain_ID = "Event.OnAccount.DNSDomain.ID"
    Event_OnAccount_Identity_Name = "Event.OnAccount.Identity.Name"
    Event_OnAccount_Identity_ID = "Event.OnAccount.Identity.ID"
    Event_OnObjectName = "Event.OnObjectName"
    Event_OnResource_Path = "Event.OnResource.Path"
    Event_OnResource_EntityIdx = "Event.OnResource.EntityIdx"
    Event_ByAccount_Domain_Name = "Event.ByAccount.Domain.Name"
    Event_ByAccount_Domain_ID = "Event.ByAccount.Domain.ID"
    Event_ByAccount_DNSDomain_Name = "Event.ByAccount.DNSDomain.Name"
    Event_ByAccount_DNSDomain_ID = "Event.ByAccount.DNSDomain.ID"
    Event_OnResource_IsSensitive = "Event.OnResource.IsSensitive"
    Event_Status_Name = "Event.Status.Name"
    Event_Status_ID = "Event.Status.ID"
    Event_Filer_Name = "Event.Filer.Name"
    Event_Filer_ID = "Event.Filer.ID"
    Event_OnResource_ObjectType_Name = "Event.OnResource.ObjectType.Name"
    Event_OnResource_ObjectType_ID = "Event.OnResource.ObjectType.ID"
    Event_Device_UserAgent = "Event.Device.UserAgent"
    Event_CorrelationId = "Event.CorrelationId"
    Event_ByAccount_Identity_Followup_Notes = "Event.ByAccount.Identity.Followup.Notes"
    Event_OnAccount_Identity_Followup_Notes = "Event.OnAccount.Identity.Followup.Notes"
    Event_OnResource_Followup_Flag_Name = "Event.OnResource.Followup.Flag.Name"
    Event_OnResource_Followup_Flag_ID = "Event.OnResource.Followup.Flag.ID"
    Event_ByAccount_Identity_Department = "Event.ByAccount.Identity.Department"
    Event_OnAccount_Identity_Department = "Event.OnAccount.Identity.Department"
    Event_IP = "Event.IP"
    Event_ByAccount_Identity_Manager_Name = "Event.ByAccount.Identity.Manager.Name"
    Event_ByAccount_Identity_Manager_ID = "Event.ByAccount.Identity.Manager.ID"
    Event_OnAccount_Identity_Manager_Name = "Event.OnAccount.Identity.Manager.Name"
    Event_OnAccount_Identity_Manager_ID = "Event.OnAccount.Identity.Manager.ID"
    Event_ByAccount_IsDisabled = "Event.ByAccount.IsDisabled"
    Event_ByAccount_IsStale = "Event.ByAccount.IsStale"
    Event_OnAccount_IsStale = "Event.OnAccount.IsStale"
    Event_Device_Name = "Event.Device.Name"
    Event_ByAccount_LastLogonTime = "Event.ByAccount.LastLogonTime"
    Event_OnAccount_LastLogonTime = "Event.OnAccount.LastLogonTime"
    Event_OnResource_File_Type = "Event.OnResource.File.Type"
    Event_OnResource_AccessDate = "Event.OnResource.AccessDate"
    Event_OnResource_ModifyDate = "Event.OnResource.ModifyDate"
    Event_OnResource_FSOwner_Name = "Event.OnResource.FSOwner.Name"
    Event_OnResource_FSOwner_SidID = "Event.OnResource.FSOwner.SidID"
    Event_OnResource_Classification_TotalHitCount = "Event.OnResource.Classification.TotalHitCount"
    Event_OnMail_ItemType_Name = "Event.OnMail.ItemType.Name"
    Event_OnMail_ItemType_ID = "Event.OnMail.ItemType.ID"
    Event_OnMail_Recipient = "Event.OnMail.Recipient"
    Event_OnResource_CreateDate = "Event.OnResource.CreateDate"
    Event_OnMail_Source = "Event.OnMail.Source"
    Event_OnResource_PathDepth = "Event.OnResource.PathDepth"
    Event_OnResource_NumberOfNestedFiles = "Event.OnResource.NumberOfNestedFiles"
    Event_Alert_Rule_Name = "Event.Alert.Rule.Name"
    Event_Alert_Rule_ID = "Event.Alert.Rule.ID"
    Event_OnResource_SizeFolder = "Event.OnResource.SizeFolder"
    Event_Alert_Rule_Category_Name = "Event.Alert.Rule.Category.Name"
    Event_Alert_Rule_Category_ID = "Event.Alert.Rule.Category.ID"
    Event_OnResource_SizeFolderAndSubFolders = "Event.OnResource.SizeFolderAndSubFolders"
    Event_Alert_Rule_Severity_Name = "Event.Alert.Rule.Severity.Name"
    Event_Alert_Rule_Severity_ID = "Event.Alert.Rule.Severity.ID"
    Event_OnResource_NumberOfFiles = "Event.OnResource.NumberOfFiles"
    Event_Alert_Time = "Event.Alert.Time"
    Event_Alert_TimeUTC = "Event.Alert.TimeUTC"
    Event_TimeUTC = "Event.TimeUTC"
    Event_OnResource_NumberOfFilesInSubFolders = "Event.OnResource.NumberOfFilesInSubFolders"
    Event_Alert_ID = "Event.Alert.ID"
    Event_OnResource_NumberOfNestedFolders = "Event.OnResource.NumberOfNestedFolders"
    Event_Description = "Event.Description"
    Event_OnResource_SizePhysicalSDTFile = "Event.OnResource.SizePhysicalSDTFile"
    Event_EventsCount = "Event.EventsCount"
    Event_OnResource_SizePhysicalNestedFoldersFiles = "Event.OnResource.SizePhysicalNestedFoldersFiles"
    Event_ByAccount_PasswordStatus_Name = "Event.ByAccount.PasswordStatus.Name"
    Event_ByAccount_PasswordStatus_ID = "Event.ByAccount.PasswordStatus.ID"
    Event_OnResource_SizePhysicalFiles = "Event.OnResource.SizePhysicalFiles"
    Event_ByAccount_AccountExpirationDate = "Event.ByAccount.AccountExpirationDate"
    Event_OnResource_SizeSubFolders = "Event.OnResource.SizeSubFolders"
    Event_OnAccount_IsDisabled = "Event.OnAccount.IsDisabled"
    Event_OnResource_NumberOfNestedObjects = "Event.OnResource.NumberOfNestedObjects"
    Event_OnAccount_IsLockout = "Event.OnAccount.IsLockout"
    Event_UploadSize = "Event.UploadSize"
    Event_DownloadSize = "Event.DownloadSize"
    Event_OnAccount_PasswordStatus_Name = "Event.OnAccount.PasswordStatus.Name"
    Event_OnAccount_PasswordStatus_ID = "Event.OnAccount.PasswordStatus.ID"
    Event_SessionDuration = "Event.SessionDuration"
    Event_OnAccount_AccountExpirationDate = "Event.OnAccount.AccountExpirationDate"
    Event_ConnectionType_Name = "Event.ConnectionType.Name"
    Event_ConnectionType_ID = "Event.ConnectionType.ID"
    Event_ClientType_Name = "Event.ClientType.Name"
    Event_ClientType_ID = "Event.ClientType.ID"
    Event_AgentVersion = "Event.AgentVersion"
    Event_ByAccount_VPNGroups = "Event.ByAccount.VPNGroups"
    Event_ByAccount_IsLockout = "Event.ByAccount.IsLockout"
    Event_DC_HostName = "Event.DC.HostName"
    Event_Direction_Name = "Event.Direction.Name"
    Event_Direction_ID = "Event.Direction.ID"
    Event_OnAccount_SamAccountName = "Event.OnAccount.SamAccountName"
    Event_OnAccount_SidID = "Event.OnAccount.SidID"
    Event_ByAccount_PrivilegedAccountType_Name = "Event.ByAccount.PrivilegedAccountType.Name"
    Event_ByAccount_PrivilegedAccountType_ID = "Event.ByAccount.PrivilegedAccountType.ID"
    Event_DNSFlags = "Event.DNSFlags"
    Event_CollectionMethod_Name = "Event.CollectionMethod.Name"
    Event_CollectionMethod_ID = "Event.CollectionMethod.ID"
    Event_OnAccount_AccountType_Name = "Event.OnAccount.AccountType.Name"
    Event_OnAccount_AccountType_ID = "Event.OnAccount.AccountType.ID"
    Event_DNSRecordType = "Event.DNSRecordType"
    Event_OnResource_Classification_CategorySummary = "Event.OnResource.Classification.CategorySummary"
    Event_ByAccount_Identity_Affiliation_Name = "Event.ByAccount.Identity.Affiliation.Name"
    Event_ByAccount_Identity_Affiliation_ID = "Event.ByAccount.Identity.Affiliation.ID"
    Event_OnAccount_Application_ID = "Event.OnAccount.Application.ID"
    Event_TransportLayer_Name = "Event.TransportLayer.Name"
    Event_TransportLayer_ID = "Event.TransportLayer.ID"
    Event_OnAccount_Application_Name = "Event.OnAccount.Application.Name"
    Event_OnAccount_Identity_Affiliation_Name = "Event.OnAccount.Identity.Affiliation.Name"
    Event_OnAccount_Identity_Affiliation_ID = "Event.OnAccount.Identity.Affiliation.ID"
    Event_Destination_URL_Reputation_Name = "Event.Destination.URL.Reputation.Name"
    Event_Destination_URL_Reputation_ID = "Event.Destination.URL.Reputation.ID"
    Event_HttpMethod_Name = "Event.HttpMethod.Name"
    Event_HttpMethod_ID = "Event.HttpMethod.ID"
    Event_OnAccount_PublisherName = "Event.OnAccount.PublisherName"
    Event_Destination_IP = "Event.Destination.IP"
    Event_Destination_URL_Categorization_Name = "Event.Destination.URL.Categorization.Name"
    Event_Destination_URL_Categorization_ID = "Event.Destination.URL.Categorization.ID"
    Event_OnAccount_IsPublisherVerified = "Event.OnAccount.IsPublisherVerified"
    Event_Destination_DeviceName = "Event.Destination.DeviceName"
    Event_ByAccount_Application_ID = "Event.ByAccount.Application.ID"
    Event_Destination_Domain = "Event.Destination.Domain"
    Event_ByAccount_Application_Name = "Event.ByAccount.Application.Name"
    Event_Device_ExternalIP_IP = "Event.Device.ExternalIP.IP"
    Event_ByAccount_PublisherName = "Event.ByAccount.PublisherName"
    Event_ByAccount_IsPublisherVerified = "Event.ByAccount.IsPublisherVerified"
    Event_Device_OperatingSystem = "Event.Device.OperatingSystem"
    Event_SourcePort = "Event.SourcePort"
    Event_SourceZone = "Event.SourceZone"
    Event_App = "Event.App"
    Event_Device_ExternalIP_ThreatTypes_Name = "Event.Device.ExternalIP.ThreatTypes.Name"
    Event_Device_ExternalIP_ThreatTypes_ID = "Event.Device.ExternalIP.ThreatTypes.ID"
    Event_Destination_Port = "Event.Destination.Port"
    Event_Destination_Zone = "Event.Destination.Zone"
    Event_NAT_Source_Address = "Event.NAT.Source.Address"
    Event_NAT_Destination_Address = "Event.NAT.Destination.Address"
    Event_NAT_Source_Port = "Event.NAT.Source.Port"
    Event_NAT_Destination_Port = "Event.NAT.Destination.Port"
    Event_Protocol_Name = "Event.Protocol.Name"
    Event_Protocol_ID = "Event.Protocol.ID"
    Event_ApplicationProtocol_Name = "Event.ApplicationProtocol.Name"
    Event_ApplicationProtocol_ID = "Event.ApplicationProtocol.ID"
    Event_Device_ExternalIP_IsMalicious = "Event.Device.ExternalIP.IsMalicious"
    Event_Device_ExternalIP_Reputation_Name = "Event.Device.ExternalIP.Reputation.Name"
    Event_Device_ExternalIP_Reputation_ID = "Event.Device.ExternalIP.Reputation.ID"
    Event_ByAccount_IsMailboxOwner = "Event.ByAccount.IsMailboxOwner"
    Event_StatusReasonCodeName = "Event.StatusReasonCodeName"
    Event_StatusReasonCode = "Event.StatusReasonCode"
    Event_Authentication_TicketEncryption_Name = "Event.Authentication.TicketEncryption.Name"
    Event_Authentication_TicketEncryption_ID = "Event.Authentication.TicketEncryption.ID"
    Event_OnGPO_NewVersion = "Event.OnGPO.NewVersion"
    Event_Authentication_PreAuthenticationType = "Event.Authentication.PreAuthenticationType"
    Event_OnGPO_Settings_NewValue = "Event.OnGPO.Settings.NewValue"
    Event_Authentication_Protocol_Name = "Event.Authentication.Protocol.Name"
    Event_Authentication_Protocol_ID = "Event.Authentication.Protocol.ID"
    Event_OnGPO_Settings_OldValue = "Event.OnGPO.Settings.OldValue"
    Event_OrgOpCode = "Event.OrgOpCode"
    Event_OnGPO_Settings_Name = "Event.OnGPO.Settings.Name"
    Event_ByAccount_ExpirationStatus_Name = "Event.ByAccount.ExpirationStatus.Name"
    Event_ByAccount_ExpirationStatus_ID = "Event.ByAccount.ExpirationStatus.ID"
    Event_OnGPO_Settings_Path = "Event.OnGPO.Settings.Path"
    Event_OnAccount_ExpirationStatus_Name = "Event.OnAccount.ExpirationStatus.Name"
    Event_OnAccount_ExpirationStatus_ID = "Event.OnAccount.ExpirationStatus.ID"
    Event_OnGPO_ConfigurationType_Name = "Event.OnGPO.ConfigurationType.Name"
    Event_OnGPO_ConfigurationType_ID = "Event.OnGPO.ConfigurationType.ID"
    Event_Trustee_Identity_Name = "Event.Trustee.Identity.Name"
    Event_Trustee_Identity_ID = "Event.Trustee.Identity.ID"
    Event_OnMail_Mailbox_Type_Name = "Event.OnMail.Mailbox.Type.Name"
    Event_OnMail_Mailbox_Type_ID = "Event.OnMail.Mailbox.Type.ID"
    Event_Trustee_DNSDomain_Name = "Event.Trustee.DNSDomain.Name"
    Event_Trustee_DNSDomain_ID = "Event.Trustee.DNSDomain.ID"
    Event_Trustee_Type_Name = "Event.Trustee.Type.Name"
    Event_Trustee_Type_ID = "Event.Trustee.Type.ID"
    Event_Trustee_Application_ID = "Event.Trustee.Application.ID"
    Event_Trustee_Application_Name = "Event.Trustee.Application.Name"
    Event_Trustee_PublisherName = "Event.Trustee.PublisherName"
    Event_Trustee_IsPublisherVerified = "Event.Trustee.IsPublisherVerified"
    Event_Permission_IsDirectChange = "Event.Permission.IsDirectChange"
    Event_Permission_ChangedPermissionFlags = "Event.Permission.ChangedPermissionFlags"
    Event_Trustee_Identity_Affiliation_Name = "Event.Trustee.Identity.Affiliation.Name"
    Event_Trustee_Identity_Affiliation_ID = "Event.Trustee.Identity.Affiliation.ID"
    Event_LogonType = "Event.LogonType"
    Event_Authentication_Package = "Event.Authentication.Package"
    Event_ImpersonationLevel = "Event.ImpersonationLevel"
    Event_OnMail_AttachmentName = "Event.OnMail.AttachmentName"
    Event_OnMail_WithAttachments = "Event.OnMail.WithAttachments"
    Event_OnResource_ClassificationLabels_Summary = "Event.OnResource.ClassificationLabels.Summary"
    Event_OnMail_HasOutOfOrganizationReciever = "Event.OnMail.HasOutOfOrganizationReciever"
    Event_Type_Activity_Name = "Event.Type.Activity.Name"
    Event_Type_Activity_ID = "Event.Type.Activity.ID"
    Event_InfoTags_Name = "Event.InfoTags.Name"
    Event_InfoTags_ID = "Event.InfoTags.ID"
    Event_Authentication_TicketOptions = "Event.Authentication.TicketOptions"
    Event_OnMail_Headers_SentDate = "Event.OnMail.Headers.SentDate"
    Event_OnMail_Headers_AuthenticationResults_Spf_Passed = "Event.OnMail.Headers.AuthenticationResults.Spf.Passed"
    Event_OnMail_Headers_AuthenticationResults_Dkim_Passed = "Event.OnMail.Headers.AuthenticationResults.Dkim.Passed"
    Event_OnMail_Headers_AuthenticationResults_Dmarc_Passed = "Event.OnMail.Headers.AuthenticationResults.Dmarc.Passed"
    Event_OnMail_Headers_XOriginalSender = "Event.OnMail.Headers.XOriginalSender"
    Event_OnMail_Headers_ReceivedServerIP = "Event.OnMail.Headers.ReceivedServerIP"
    Event_OnResource_Classification_Summary = "Event.OnResource.Classification.Summary"
    Event_OnMail_Date = "Event.OnMail.Date"
    Event_OnResource_ShareAccessPaths = "Event.OnResource.ShareAccessPaths"
    Event_Permission_Before = "Event.Permission.Before"
    Event_Permission_After = "Event.Permission.After"
    Event_Permission_Type = "Event.Permission.Type"
    Event_OnResource_LocalMappedPath = "Event.OnResource.LocalMappedPath"
    Event_Session_BrowserType = "Event.Session.BrowserType"
    Event_Session_TrustDomain_Type = "Event.Session.TrustDomain.Type"
    Event_Session_AzureAuthentication_Requirement = "Event.Session.AzureAuthentication.Requirement"
    Event_Session_AzureAuthentication_ConditionalAccessStatus = "Event.Session.AzureAuthentication.ConditionalAccessStatus"
    Event_Session_AzureAuthentication_TokenIssuerType = "Event.Session.AzureAuthentication.TokenIssuerType"
    Event_Session_AzureAuthentication_Method = "Event.Session.AzureAuthentication.Method"
    Event_Session_AzureAuthentication_MethodDetail = "Event.Session.AzureAuthentication.MethodDetail"
    Event_Session_AzureAuthentication_Step = "Event.Session.AzureAuthentication.Step"
    Event_Session_AzureAuthentication_ResultDetail = "Event.Session.AzureAuthentication.ResultDetail"
    Event_Session_AzureAuthentication_ReasonDetails = "Event.Session.AzureAuthentication.ReasonDetails"
    Event_Device_TrustType = "Event.Device.TrustType"
    Event_Session_AzureAuthentication_Status_Name = "Event.Session.AzureAuthentication.Status.Name"
    Event_Session_AzureAuthentication_Status_ID = "Event.Session.AzureAuthentication.Status.ID"
    Event_Device_ManagedStatus_Name = "Event.Device.ManagedStatus.Name"
    Event_Device_ManagedStatus_ID = "Event.Device.ManagedStatus.ID"
    Event_ID = "Event.ID"
    Event_IsAlerted = "Event.IsAlerted"

    Columns = [
        Event_Type_Name, Event_Description, Event_Filer_Platform_Name, Event_Filer_Name, Event_ByAccount_SamAccountName,
        Event_OnObjectName,
        Event_Alert_ID, Event_ID, Event_TimeUTC,
        Event_Status_Name, Event_Location_Country_Name,
        Event_Location_Subdivision_Name, Event_Location_BlacklistedLocation,
        Event_Operation_Name, Event_ByAccount_Type_Name,
        Event_ByAccount_Domain_Name, Event_ByAccount_Identity_Name,
        Event_IP, Event_Device_ExternalIP_IP,
        Event_Destination_IP, Event_Device_Name, Event_Destination_DeviceName,
        Event_ByAccount_IsDisabled, Event_ByAccount_IsStale, Event_ByAccount_IsLockout,
        Event_Device_ExternalIP_ThreatTypes_Name, Event_Device_ExternalIP_IsMalicious,
        Event_Device_ExternalIP_Reputation_Name,
        Event_OnResource_ObjectType_Name, Event_OnAccount_SamAccountName,
        Event_OnResource_IsSensitive, Event_OnAccount_IsDisabled,
        Event_OnAccount_IsLockout, Event_OnResource_Path
    ]

    ExtraColumns = [
        Event_StatusReason_Name,
        Event_StatusReason_ID,
        Event_Location_Subdivision_ID,
        Event_Location_Country_ID,
        Event_Filer_Platform_ID,
        Event_OnResource_Stats_ExposureLevel_Name,
        Event_OnResource_Stats_ExposureLevel_ID,
        Event_ByAccount_Identity_Followup_Flag_Name,
        Event_ByAccount_Identity_Followup_Flag_ID,
        Event_ByAccount_SidID,
        Event_ByAccount_Type_ID,
        Event_ByAccount_DistinguishedName,
        Event_OnAccount_Domain_Name,
        Event_OnAccount_Domain_ID,
        Event_OnAccount_Identity_Followup_Flag_Name,
        Event_OnAccount_Identity_Followup_Flag_ID,
        Event_Time,
        Event_Operation_ID,
        Event_EndTime,
        Event_Type_ID,
        Event_ByAccount_Identity_ID,
        Event_OnAccount_DNSDomain_Name,
        Event_OnAccount_DNSDomain_ID,
        Event_OnAccount_Identity_Name,
        Event_OnAccount_Identity_ID,
        Event_OnResource_EntityIdx,
        Event_ByAccount_Domain_ID,
        Event_ByAccount_DNSDomain_Name,
        Event_ByAccount_DNSDomain_ID,
        Event_Status_ID,
        Event_Filer_ID,
        Event_OnResource_ObjectType_ID,
        Event_Device_UserAgent,
        Event_CorrelationId,
        Event_ByAccount_Identity_Followup_Notes,
        Event_OnAccount_Identity_Followup_Notes,
        Event_OnResource_Followup_Flag_Name,
        Event_OnResource_Followup_Flag_ID,
        Event_ByAccount_Identity_Department,
        Event_OnAccount_Identity_Department,
        Event_ByAccount_Identity_Manager_Name,
        Event_ByAccount_Identity_Manager_ID,
        Event_OnAccount_Identity_Manager_Name,
        Event_OnAccount_Identity_Manager_ID,
        Event_OnAccount_IsStale,
        Event_ByAccount_LastLogonTime,
        Event_OnAccount_LastLogonTime,
        Event_OnResource_File_Type,
        Event_OnResource_AccessDate,
        Event_OnResource_ModifyDate,
        Event_OnResource_FSOwner_Name,
        Event_OnResource_FSOwner_SidID,
        Event_OnResource_Classification_TotalHitCount,
        Event_OnMail_ItemType_Name,
        Event_OnMail_ItemType_ID,
        Event_OnMail_Recipient,
        Event_OnResource_CreateDate,
        Event_OnMail_Source,
        Event_OnResource_PathDepth,
        Event_OnResource_NumberOfNestedFiles,
        Event_Alert_Rule_Name,
        Event_Alert_Rule_ID,
        Event_OnResource_SizeFolder,
        Event_Alert_Rule_Category_Name,
        Event_Alert_Rule_Category_ID,
        Event_OnResource_SizeFolderAndSubFolders,
        Event_Alert_Rule_Severity_Name,
        Event_Alert_Rule_Severity_ID,
        Event_OnResource_NumberOfFiles,
        Event_Alert_Time,
        Event_Alert_TimeUTC,
        Event_OnResource_NumberOfFilesInSubFolders,
        Event_OnResource_NumberOfNestedFolders,
        Event_OnResource_SizePhysicalSDTFile,
        Event_EventsCount,
        Event_OnResource_SizePhysicalNestedFoldersFiles,
        Event_ByAccount_PasswordStatus_Name,
        Event_ByAccount_PasswordStatus_ID,
        Event_OnResource_SizePhysicalFiles,
        Event_ByAccount_AccountExpirationDate,
        Event_OnResource_SizeSubFolders,
        Event_OnResource_NumberOfNestedObjects,
        Event_UploadSize,
        Event_DownloadSize,
        Event_OnAccount_PasswordStatus_Name,
        Event_OnAccount_PasswordStatus_ID,
        Event_SessionDuration,
        Event_OnAccount_AccountExpirationDate,
        Event_ConnectionType_Name,
        Event_ConnectionType_ID,
        Event_ClientType_Name,
        Event_ClientType_ID,
        Event_AgentVersion,
        Event_ByAccount_VPNGroups,
        Event_DC_HostName,
        Event_Direction_Name,
        Event_Direction_ID,
        Event_OnAccount_SidID,
        Event_ByAccount_PrivilegedAccountType_Name,
        Event_ByAccount_PrivilegedAccountType_ID,
        Event_DNSFlags,
        Event_CollectionMethod_Name,
        Event_CollectionMethod_ID,
        Event_OnAccount_AccountType_Name,
        Event_OnAccount_AccountType_ID,
        Event_DNSRecordType,
        Event_OnResource_Classification_CategorySummary,
        Event_ByAccount_Identity_Affiliation_Name,
        Event_ByAccount_Identity_Affiliation_ID,
        Event_OnAccount_Application_ID,
        Event_TransportLayer_Name,
        Event_TransportLayer_ID,
        Event_OnAccount_Application_Name,
        Event_OnAccount_Identity_Affiliation_Name,
        Event_OnAccount_Identity_Affiliation_ID,
        Event_Destination_URL_Reputation_Name,
        Event_Destination_URL_Reputation_ID,
        Event_HttpMethod_Name,
        Event_HttpMethod_ID,
        Event_OnAccount_PublisherName,
        Event_Destination_URL_Categorization_Name,
        Event_Destination_URL_Categorization_ID,
        Event_OnAccount_IsPublisherVerified,
        Event_ByAccount_Application_ID,
        Event_Destination_Domain,
        Event_ByAccount_Application_Name,
        Event_ByAccount_PublisherName,
        Event_ByAccount_IsPublisherVerified,
        Event_Device_OperatingSystem,
        Event_SourcePort,
        Event_SourceZone,
        Event_App,
        Event_Device_ExternalIP_ThreatTypes_ID,
        Event_Destination_Port,
        Event_Destination_Zone,
        Event_NAT_Source_Address,
        Event_NAT_Destination_Address,
        Event_NAT_Source_Port,
        Event_NAT_Destination_Port,
        Event_Protocol_Name,
        Event_Protocol_ID,
        Event_ApplicationProtocol_Name,
        Event_ApplicationProtocol_ID,
        Event_Device_ExternalIP_Reputation_ID,
        Event_ByAccount_IsMailboxOwner,
        Event_StatusReasonCodeName,
        Event_StatusReasonCode,
        Event_Authentication_TicketEncryption_Name,
        Event_Authentication_TicketEncryption_ID,
        Event_OnGPO_NewVersion,
        Event_Authentication_PreAuthenticationType,
        Event_OnGPO_Settings_NewValue,
        Event_Authentication_Protocol_Name,
        Event_Authentication_Protocol_ID,
        Event_OnGPO_Settings_OldValue,
        Event_OrgOpCode,
        Event_OnGPO_Settings_Name,
        Event_ByAccount_ExpirationStatus_Name,
        Event_ByAccount_ExpirationStatus_ID,
        Event_OnGPO_Settings_Path,
        Event_OnAccount_ExpirationStatus_Name,
        Event_OnAccount_ExpirationStatus_ID,
        Event_OnGPO_ConfigurationType_Name,
        Event_OnGPO_ConfigurationType_ID,
        Event_Trustee_Identity_Name,
        Event_Trustee_Identity_ID,
        Event_OnMail_Mailbox_Type_Name,
        Event_OnMail_Mailbox_Type_ID,
        Event_Trustee_DNSDomain_Name,
        Event_Trustee_DNSDomain_ID,
        Event_Trustee_Type_Name,
        Event_Trustee_Type_ID,
        Event_Trustee_Application_ID,
        Event_Trustee_Application_Name,
        Event_Trustee_PublisherName,
        Event_Trustee_IsPublisherVerified,
        Event_Permission_IsDirectChange,
        Event_Permission_ChangedPermissionFlags,
        Event_Trustee_Identity_Affiliation_Name,
        Event_Trustee_Identity_Affiliation_ID,
        Event_LogonType,
        Event_Authentication_Package,
        Event_ImpersonationLevel,
        Event_OnMail_AttachmentName,
        Event_OnMail_WithAttachments,
        Event_OnResource_ClassificationLabels_Summary,
        Event_OnMail_HasOutOfOrganizationReciever,
        Event_Type_Activity_Name,
        Event_Type_Activity_ID,
        Event_InfoTags_Name,
        Event_InfoTags_ID,
        Event_Authentication_TicketOptions,
        Event_OnMail_Headers_SentDate,
        Event_OnMail_Headers_AuthenticationResults_Spf_Passed,
        Event_OnMail_Headers_AuthenticationResults_Dkim_Passed,
        Event_OnMail_Headers_AuthenticationResults_Dmarc_Passed,
        Event_OnMail_Headers_XOriginalSender,
        Event_OnMail_Headers_ReceivedServerIP,
        Event_OnResource_Classification_Summary,
        Event_OnMail_Date,
        Event_OnResource_ShareAccessPaths,
        Event_Permission_Before,
        Event_Permission_After,
        Event_Permission_Type,
        Event_OnResource_LocalMappedPath,
        Event_Session_BrowserType,
        Event_Session_TrustDomain_Type,
        Event_Session_AzureAuthentication_Requirement,
        Event_Session_AzureAuthentication_ConditionalAccessStatus,
        Event_Session_AzureAuthentication_TokenIssuerType,
        Event_Session_AzureAuthentication_Method,
        Event_Session_AzureAuthentication_MethodDetail,
        Event_Session_AzureAuthentication_Step,
        Event_Session_AzureAuthentication_ResultDetail,
        Event_Session_AzureAuthentication_ReasonDetails,
        Event_Device_TrustType,
        Event_Session_AzureAuthentication_Status_Name,
        Event_Session_AzureAuthentication_Status_ID,
        Event_Device_ManagedStatus_Name,
        Event_Device_ManagedStatus_ID,
        Event_IsAlerted
    ]

    def get_fields(self, extra_fields: list[str]) -> list[str]:
        output = self.Columns.copy()

        if extra_fields:
            for pattern in extra_fields:
                match_columns = fnmatch.filter(self.ExtraColumns, pattern)
                output.extend([item for item in match_columns if item not in output])

        return output
