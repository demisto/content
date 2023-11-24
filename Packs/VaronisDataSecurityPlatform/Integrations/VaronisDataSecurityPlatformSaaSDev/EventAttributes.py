class EventAttributes:
    EventAlertId = "Event.Alert.ID"
    EventGuid = "Event.ID"
    EventTypeName = "Event.Type.Name"
    EventTimeUtc = "Event.TimeUTC"
    EventStatusName = "Event.Status.Name"
    EventDescription = "Event.Description"
    EventLocationCountryName = "Event.Location.Country.Name"
    EventLocationSubdivisionName = "Event.Location.Subdivision.Name"
    EventLocationBlacklistedLocation = "Event.Location.BlacklistedLocation"
    EventOperationName = "Event.Operation.Name"
    EventByAccountIdentityName = "Event.ByAccount.Identity.Name"
    EventByAccountTypeName = "Event.ByAccount.Type.Name"
    EventByAccountDomainName = "Event.ByAccount.Domain.Name"
    EventByAccountSamAccountName = "Event.ByAccount.SamAccountName"
    EventFilerName = "Event.Filer.Name"
    EventFilerPlatformName = "Event.Filer.Platform.Name"
    EventIp = "Event.IP"
    EventDeviceExternalIp = "Event.Device.ExternalIP.IP"
    EventDestinationIp = "Event.Destination.IP"
    EventDeviceName = "Event.Device.Name"
    EventDestinationDeviceName = "Event.Destination.DeviceName"
    EventByAccountIsDisabled = "Event.ByAccount.IsDisabled"
    EventByAccountIsStale = "Event.ByAccount.IsStale"
    EventByAccountIsLockout = "Event.ByAccount.IsLockout"
    EventDeviceExternalIpThreatTypesName = "Event.Device.ExternalIP.ThreatTypes.Name"
    EventDeviceExternalIpIsMalicious = "Event.Device.ExternalIP.IsMalicious"
    EventDeviceExternalIpReputationName = "Event.Device.ExternalIP.Reputation.Name"
    EventOnObjectName = "Event.OnObjectName"
    EventOnResourceObjectTypeName = "Event.OnResource.ObjectType.Name"
    EventOnAccountSamAccountName = "Event.OnAccount.SamAccountName"
    EventOnResourceIsSensitive = "Event.OnResource.IsSensitive"
    EventOnAccountIsDisabled = "Event.OnAccount.IsDisabled"
    EventOnAccountIsLockout = "Event.OnAccount.IsLockout"
    EventOnResourcePath = "Event.OnResource.Path"

    Columns = [
        EventAlertId, EventGuid, EventTypeName, EventTimeUtc,
        EventStatusName, EventDescription, EventLocationCountryName,
        EventLocationSubdivisionName, EventLocationBlacklistedLocation,
        EventOperationName, EventByAccountIdentityName, EventByAccountTypeName,
        EventByAccountDomainName, EventByAccountSamAccountName,
        EventFilerName, EventFilerPlatformName, EventIp, EventDeviceExternalIp,
        EventDestinationIp, EventDeviceName, EventDestinationDeviceName,
        EventByAccountIsDisabled, EventByAccountIsStale, EventByAccountIsLockout,
        EventDeviceExternalIpThreatTypesName, EventDeviceExternalIpIsMalicious,
        EventDeviceExternalIpReputationName, EventOnObjectName,
        EventOnResourceObjectTypeName, EventOnAccountSamAccountName,
        EventOnResourceIsSensitive, EventOnAccountIsDisabled,
        EventOnAccountIsLockout, EventOnResourcePath
    ]