from BaseMapper import BaseMapper
from CommonServerPython import Dict, List, Optional, datetime
from EventAttributes import EventAttributes
from EventItem import EventItem


from typing import Dict, List


class SearchEventObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: Dict[str, str]) -> EventItem:
        event_item = EventItem(row)

        #event_item.AlertId = self.multi_value_to_guid_array(row, EventAttributes.EventAlertId)
        # event_item.Id = row.get(EventAttributes.EventGuid, '')
        # event_item.Type = row.get(EventAttributes.EventTypeName)
        # event_item.TimeUTC = self.get_date_value(row, EventAttributes.EventTimeUtc)
        # event_item.Status = row.get(EventAttributes.EventStatusName)
        # event_item.Description = row.get(EventAttributes.EventDescription)
        # event_item.Country = row.get(EventAttributes.EventLocationCountryName)
        # event_item.State = row.get(EventAttributes.EventLocationSubdivisionName)
        # event_item.BlacklistedLocation = self.get_bool_value(row, EventAttributes.EventLocationBlacklistedLocation)
        # event_item.EventOperation = row.get(EventAttributes.EventOperationName)
        # event_item.ByUserAccount = row.get(EventAttributes.EventByAccountIdentityName)
        # event_item.ByUserAccountType = row.get(EventAttributes.EventByAccountTypeName)
        # event_item.ByUserAccountDomain = row.get(EventAttributes.EventByAccountDomainName)
        # event_item.BySamAccountName = row.get(EventAttributes.EventByAccountSamAccountName)
        # event_item.Filer = row.get(EventAttributes.EventFilerName)
        # event_item.Platform = row.get(EventAttributes.EventFilerPlatformName)
        # event_item.SourceIP = row.get(EventAttributes.EventIp)
        # event_item.ExternalIP = row.get(EventAttributes.EventDeviceExternalIp)
        # event_item.DestinationIP = row.get(EventAttributes.EventDestinationIp)
        # event_item.SourceDevice = row.get(EventAttributes.EventDeviceName)
        # event_item.DestinationDevice = row.get(EventAttributes.EventDestinationDeviceName)
        # event_item.IsDisabledAccount = self.get_bool_value(row, EventAttributes.EventByAccountIsDisabled)
        # event_item.IsLockoutAccount = self.get_bool_value(row, EventAttributes.EventByAccountIsLockout)
        # event_item.IsStaleAccount = self.get_bool_value(row, EventAttributes.EventByAccountIsStale)
        # event_item.IsMaliciousIP = self.get_bool_value(row, EventAttributes.EventDeviceExternalIpIsMalicious)
        # event_item.ExternalIPThreatTypes = self.multi_value_to_array(
        #     row.get(EventAttributes.EventDeviceExternalIpThreatTypesName, ''))
        # event_item.ExternalIPReputation = row.get(EventAttributes.EventDeviceExternalIpReputationName)
        # event_item.OnObjectName = row.get(EventAttributes.EventOnObjectName)
        # event_item.OnObjectType = row.get(EventAttributes.EventOnResourceObjectTypeName)
        # event_item.OnSamAccountName = row.get(EventAttributes.EventOnAccountSamAccountName)
        # event_item.IsSensitive = self.get_bool_value(row, EventAttributes.EventOnResourceIsSensitive)
        # event_item.OnAccountIsDisabled = self.get_bool_value(row, EventAttributes.EventOnAccountIsDisabled)
        # event_item.OnAccountIsLockout = self.get_bool_value(row, EventAttributes.EventOnAccountIsLockout)
        # event_item.Path = row.get(EventAttributes.EventOnResourcePath)

        return event_item

    def multi_value_to_guid_array(self, row: Dict[str, str], field: str) -> Optional[List[str]]:
        value = row.get(field)
        if value:
            return [v for v in value.split(',')]
        return None

    def get_bool_value(self, row: Dict[str, str], name: str) -> Optional[bool]:
        value = row.get(name)
        if value:
            value = value.lower()
            if value == 'yes':
                return True
            if value == 'no':
                return False
            if value == 'true':
                return True
            if value == 'false':
                return False
        return None

    def get_date_value(self, row: Dict[str, str], name: str) -> Optional[datetime]:
        value = row.get(name)
        if value:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None

    def multi_value_to_array(self, multi_value: str) -> Optional[List[str]]:
        if multi_value:
            return [v.strip() for v in multi_value.split(',') if v.strip()]
        return None