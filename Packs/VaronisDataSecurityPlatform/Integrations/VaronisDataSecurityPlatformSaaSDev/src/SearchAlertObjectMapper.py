from AlertAttributes import AlertAttributes
from AlertItem import AlertItem
from BaseMapper import BaseMapper
from CommonServerPython import *


from typing import List


class SearchAlertObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> AlertItem:
        alert_item = AlertItem(row)
        # alert_item.ID = row[AlertAttributes.Id]
        # alert_item.Name = row[AlertAttributes.RuleName]
        # alert_item.Time = row[AlertAttributes.Time]
        # alert_item.Severity = row[AlertAttributes.RuleSeverityName]
        # alert_item.SeverityId = int(row[AlertAttributes.RuleSeverityId])
        # alert_item.Category = row[AlertAttributes.RuleCategoryName]
        # alert_item.Country = self.multi_value_to_string_list(row[AlertAttributes.LocationCountryName])
        # alert_item.State = self.multi_value_to_string_list(row[AlertAttributes.LocationSubdivisionName])
        # alert_item.Status = row[AlertAttributes.StatusName]
        # alert_item.StatusId = int(row[AlertAttributes.StatusId])
        # alert_item.CloseReason = row[AlertAttributes.CloseReasonName]
        # alert_item.BlacklistLocation = self.get_bool_value(row, AlertAttributes.LocationBlacklistedLocation)
        # alert_item.AbnormalLocation = self.multi_value_to_string_list(row[AlertAttributes.LocationAbnormalLocation])
        # alert_item.NumOfAlertedEvents = int(row[AlertAttributes.EventsCount])
        # alert_item.UserName = self.multi_value_to_string_list(row[AlertAttributes.UserName])
        # alert_item.SamAccountName = self.multi_value_to_string_list(row[AlertAttributes.UserSamAccountName])
        # alert_item.PrivilegedAccountType = self.multi_value_to_string_list(row[AlertAttributes.UserAccountTypeName])
        # alert_item.ContainMaliciousExternalIP = self.get_bool_value(row, AlertAttributes.DeviceIsMaliciousExternalIp)
        # alert_item.IPThreatTypes = self.multi_value_to_string_list(row[AlertAttributes.DeviceExternalIpThreatTypesName])
        # alert_item.Asset = self.multi_value_to_string_list(row[AlertAttributes.AssetPath])
        # alert_item.AssetContainsFlaggedData = self.multi_value_to_boolean_list(row[AlertAttributes.DataIsFlagged])
        # alert_item.AssetContainsSensitiveData = self.multi_value_to_boolean_list(row[AlertAttributes.DataIsSensitive])
        # alert_item.Platform = self.multi_value_to_string_list(row[AlertAttributes.FilerPlatformName])
        # alert_item.FileServerOrDomain = self.multi_value_to_string_list(row[AlertAttributes.FilerName])
        # alert_item.DeviceName = self.multi_value_to_string_list(row[AlertAttributes.DeviceHostname])
        # alert_item.IngestTime = row[AlertAttributes.IngestTime]
        # alert_item.EventUTC = self.get_date_value(row, AlertAttributes.InitialEventUtcTime)

        return alert_item

    def multi_value_to_string_list(self, multi_value: str) -> Optional[List[str]]:
        if not multi_value or multi_value.isspace():
            return None
        return [value.strip() for value in multi_value.split(',')]

    def multi_value_to_boolean_list(self, multi_value: str) -> Optional[List[Optional[bool]]]:
        if not multi_value or multi_value.isspace():
            return None
        return [self.convert_to_boolean(value) for value in multi_value.split(',')]

    def get_bool_value(self, row: dict, name: str) -> Optional[bool]:
        return self.convert_to_boolean(row.get(name))

    def convert_to_boolean(self, bool_str: str) -> Optional[bool]:
        if bool_str is None:
            return None
        bool_str = bool_str.lower().strip()
        if bool_str in ["yes", "1"]:
            return True
        if bool_str in ["no", "0"]:
            return False
        return bool_str.lower() in ['true', 'false'] and bool(bool_str)

    def get_date_value(self, row: dict, name: str) -> Optional[datetime]:
        date_str = row.get(name)
        if date_str is None:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None