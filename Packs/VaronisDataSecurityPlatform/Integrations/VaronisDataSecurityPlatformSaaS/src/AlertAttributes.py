import fnmatch


class AlertAttributes:
    Alert_ID = "Alert.ID"
    Alert_Rule_Name = "Alert.Rule.Name"
    Alert_Rule_ID = "Alert.Rule.ID"
    Alert_TimeUTC = "Alert.TimeUTC"
    Alert_Rule_Severity_Name = "Alert.Rule.Severity.Name"
    Alert_Rule_Severity_ID = "Alert.Rule.Severity.ID"
    Alert_Rule_Category_Name = "Alert.Rule.Category.Name"
    Alert_Rule_Category_ID = "Alert.Rule.Category.ID"
    Alert_Location_CountryName = "Alert.Location.CountryName"
    Alert_Location_CountryID = "Alert.Location.CountryID"
    Alert_Location_SubdivisionName = "Alert.Location.SubdivisionName"
    Alert_Location_SubdivisionID = "Alert.Location.SubdivisionID"
    Alert_Status_Name = "Alert.Status.Name"
    Alert_Status_ID = "Alert.Status.ID"
    Alert_EventsCount = "Alert.EventsCount"
    Alert_Initial_Event_TimeUTC = "Alert.Initial.Event.TimeUTC"
    Alert_Initial_Event_TimeLocal = "Alert.Initial.Event.TimeLocal"
    Alert_User_Name = "Alert.User.Name"
    Alert_User_SidID = "Alert.User.SidID"
    Alert_User_Identity_ID = "Alert.User.Identity.ID"
    Alert_User_Identity_Name = "Alert.User.Identity.Name"
    Alert_User_IsFlagged = "Alert.User.IsFlagged"
    Alert_User_AccountType_ID = "Alert.User.AccountType.ID"
    Alert_User_AccountType_Name = "Alert.User.AccountType.Name"
    Alert_User_AccountType_AggregatedName = "Alert.User.AccountType.AggregatedName"
    Alert_User_AccountType_AggregatedID = "Alert.User.AccountType.AggregatedID"
    Alert_User_SamAccountName = "Alert.User.SamAccountName"
    Alert_Device_HostName = "Alert.Device.HostName"
    Alert_Device_IsMaliciousExternalIP = "Alert.Device.IsMaliciousExternalIP"
    Alert_Device_ExternalIPThreatTypesName = "Alert.Device.ExternalIPThreatTypesName"
    Alert_Device_ExternalIPThreatTypesID = "Alert.Device.ExternalIPThreatTypesID"
    Alert_Data_IsFlagged = "Alert.Data.IsFlagged"
    Alert_Data_IsSensitive = "Alert.Data.IsSensitive"
    Alert_Filer_Name = "Alert.Filer.Name"
    Alert_Filer_ID = "Alert.Filer.ID"
    Alert_Filer_Platform_Name = "Alert.Filer.Platform.Name"
    Alert_Filer_Platform_ID = "Alert.Filer.Platform.ID"
    Alert_Asset_Path = "Alert.Asset.Path"
    Alert_Asset_ID = "Alert.Asset.ID"
    Alert_CloseReason_Name = "Alert.CloseReason.Name"
    Alert_CloseReason_ID = "Alert.CloseReason.ID"
    Alert_Location_AbnormalLocation = "Alert.Location.AbnormalLocation"
    Alert_Location_AbnormalLocationID = "Alert.Location.AbnormalLocationID"
    Alert_Location_BlacklistedLocation = "Alert.Location.BlacklistedLocation"
    Alert_MitreTactic_Name = "Alert.MitreTactic.Name"
    Alert_MitreTactic_ID = "Alert.MitreTactic.ID"
    Alert_Time = "Alert.Time"
    Alert_AggregationFilter = "Alert.AggregationFilter"
    Alert_IngestTime = "Alert.IngestTime"

    Columns = [
        Alert_Rule_Name, Alert_Rule_Severity_Name, Alert_TimeUTC, Alert_Rule_Category_Name, Alert_User_Name, Alert_Status_Name,
        Alert_ID, Alert_Rule_ID, Alert_Rule_Severity_ID, Alert_Location_CountryName, Alert_Location_SubdivisionName,
        Alert_Status_ID, Alert_EventsCount, Alert_Initial_Event_TimeUTC, Alert_User_SamAccountName, Alert_User_AccountType_Name,
        Alert_Device_HostName, Alert_Device_IsMaliciousExternalIP, Alert_Device_ExternalIPThreatTypesName, Alert_Data_IsFlagged,
        Alert_Data_IsSensitive, Alert_Filer_Platform_Name, Alert_Asset_Path, Alert_Filer_Name, Alert_CloseReason_Name,
        Alert_Location_BlacklistedLocation, Alert_Location_AbnormalLocation, Alert_User_SidID,
        Alert_IngestTime

    ]

    ExtraColumns = [
        Alert_Location_CountryID,
        Alert_Location_SubdivisionID,
        Alert_User_Identity_ID,
        Alert_User_Identity_Name,
        Alert_User_IsFlagged,
        Alert_User_AccountType_ID,
        Alert_Device_ExternalIPThreatTypesID,
        Alert_Filer_ID,
        Alert_Filer_Platform_ID,
        Alert_User_AccountType_AggregatedName,
        Alert_User_AccountType_AggregatedID,
        Alert_Asset_ID,
        Alert_CloseReason_ID,
        Alert_Location_AbnormalLocationID,
        Alert_MitreTactic_Name,
        Alert_MitreTactic_ID,
        Alert_Time
    ]

    def get_fields(self, extra_fields: list[str]) -> list[str]:
        output = self.Columns.copy()

        if extra_fields:
            for pattern in extra_fields:
                match_columns = fnmatch.filter(self.ExtraColumns, pattern)
                output.extend([item for item in match_columns if item not in output])
        
        return output
