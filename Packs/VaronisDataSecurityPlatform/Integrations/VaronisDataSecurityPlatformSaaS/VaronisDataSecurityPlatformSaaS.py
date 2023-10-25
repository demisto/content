"""Varonis Data Security Platform integration
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
import json
from typing import Dict, Any, List, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

MAX_USERS_TO_SEARCH = 5
MAX_DAYS_BACK = 180
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'new': 1, 'under investigation': 2, 'closed': 3, 'action required': 4, 'auto-resolved': 5}
ALERT_SEVERITIES = {'high': 0, 'medium': 1, 'low': 2}
CLOSE_REASONS = {
    'none': 0,
    'resolved': 1,
    'misconfiguration': 2,
    'threat model disabled or deleted': 3,
    'account misclassification': 4,
    'legitimate activity': 5,
    'other': 6
}
DISPLAY_NAME_KEY = 'DisplayName'
SAM_ACCOUNT_NAME_KEY = 'SAMAccountName'
EMAIL_KEY = 'Email'


''' MODELS '''


class FilterCondition:
    def __init__(self):
        self.path = None
        self.operator = None
        self.values = []

    def set_path(self, path):
        self.path = path
        return self

    def set_operator(self, operator):
        self.operator = operator
        return self

    def add_value(self, value):
        self.values.append(value)  # FilterValue(value)
        return self

    def __repr__(self):
        return f"{self.path} {self.operator} {self.values}"


class FilterValue:
    def __init__(self, value):
        self = value
        # self.displayValue = value.get("displayValue", None)

    def __repr__(self):
        return f"{self.value}"


class Filters:
    def __init__(self):
        self.filterOperator = None
        self.filters = []

    def set_filter_operator(self, filter_operator):
        self.filterOperator = filter_operator
        return self

    def add_filter(self, filter_):
        self.filters.append(filter_)
        return self

    def __repr__(self):
        return f"Filter Operator: {self.filterOperator}, Filters: {self.filters}"


class Query:
    def __init__(self):
        self.entityName = None
        self.filter = Filters()

    def set_entity_name(self, entity_name):
        self.entityName = entity_name
        return self

    def set_filter(self, filter_):
        self.filter = filter_
        return self

    def __repr__(self):
        return f"Entity Name: {self.entityName}, Filter: {self.filter}"


class Rows:
    def __init__(self):
        self.columns = []
        self.filter = []
        self.grouping = None
        self.ordering = []

    def add_column(self, column):
        self.columns.append(column)
        return self

    def add_filter(self, filter_):
        self.filter.append(filter_)
        return self

    def set_grouping(self, grouping):
        self.grouping = grouping
        return self

    def add_ordering(self, ordering):
        self.ordering.append(ordering)
        return self

    def __repr__(self):
        return f"Columns: {self.columns}, Filter: {self.filter}, Grouping: {self.grouping}, Ordering: {self.ordering}"


class RequestParams:
    def __init__(self):
        self.searchSource = None
        self.searchSourceName = None

    def set_search_source(self, search_source):
        self.searchSource = search_source
        return self

    def set_search_source_name(self, search_source_name):
        self.searchSourceName = search_source_name
        return self

    def __repr__(self):
        return f"Search Source: {self.searchSource}, Search Source Name: {self.searchSourceName}"


class SearchRequest:
    def __init__(self):
        self.query = Query()
        self.rows = Rows()
        self.requestParams = RequestParams()

    def set_query(self, query):
        self.query = query
        return self

    def set_rows(self, rows):
        self.rows = rows
        return self

    def set_request_params(self, request_params):
        self.requestParams = request_params
        return self

    def __repr__(self):
        return f"Query: {self.query}, Rows: {self.rows}, Request Params: {self.requestParams}"

    def to_json(self):
        dataJSON = json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        return dataJSON


class AlertAttributes:
    Id = "Alert.ID"
    RuleName = "Alert.Rule.Name"
    RuleId = "Alert.Rule.ID"
    Time = "Alert.TimeUTC"
    RuleSeverityName = "Alert.Rule.Severity.Name"
    RuleSeverityId = "Alert.Rule.Severity.ID"
    RuleCategoryName = "Alert.Rule.Category.Name"
    LocationCountryName = "Alert.Location.CountryName"
    LocationSubdivisionName = "Alert.Location.SubdivisionName"
    StatusName = "Alert.Status.Name"
    StatusId = "Alert.Status.ID"
    EventsCount = "Alert.EventsCount"
    InitialEventUtcTime = "Alert.Initial.Event.TimeUTC"
    UserName = "Alert.User.Name"
    UserSamAccountName = "Alert.User.SamAccountName"
    UserAccountTypeName = "Alert.User.AccountType.Name"
    DeviceHostname = "Alert.Device.HostName"
    DeviceIsMaliciousExternalIp = "Alert.Device.IsMaliciousExternalIP"
    DeviceExternalIpThreatTypesName = "Alert.Device.ExternalIPThreatTypesName"
    DataIsFlagged = "Alert.Data.IsFlagged"
    DataIsSensitive = "Alert.Data.IsSensitive"
    FilerPlatformName = "Alert.Filer.Platform.Name"
    AssetPath = "Alert.Asset.Path"
    FilerName = "Alert.Filer.Name"
    CloseReasonName = "Alert.CloseReason.Name"
    LocationBlacklistedLocation = "Alert.Location.BlacklistedLocation"
    LocationAbnormalLocation = "Alert.Location.AbnormalLocation"
    SidId = "Alert.User.SidID"
    Aggregate = "Alert.AggregationFilter"
    IngestTime = "Alert.IngestTime"

    Columns = [
        Id, RuleName, RuleId, Time, RuleSeverityName, RuleSeverityId,
        RuleCategoryName, LocationCountryName, LocationSubdivisionName,
        StatusName, StatusId, EventsCount, InitialEventUtcTime, UserName,
        UserSamAccountName, UserAccountTypeName, DeviceHostname,
        DeviceIsMaliciousExternalIp, DeviceExternalIpThreatTypesName,
        DataIsFlagged, DataIsSensitive, FilerPlatformName, AssetPath,
        FilerName, CloseReasonName, LocationBlacklistedLocation,
        LocationAbnormalLocation, SidId, IngestTime
    ]


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


class AlertItem:
    def __init__(self):
        self.ID: str = None
        self.Name: str = None
        self.Time: datetime = None
        self.Severity: str = None
        self.SeverityId: int = None
        self.Category: str = None
        self.Country: Optional[List[str]] = None
        self.State: Optional[List[str]] = None
        self.Status: str = None
        self.StatusId: int = None
        self.CloseReason: str = None
        self.BlacklistLocation: Optional[bool] = None
        self.AbnormalLocation: Optional[List[str]] = None
        self.NumOfAlertedEvents: int = None
        self.UserName: Optional[List[str]] = None
        self.SamAccountName: Optional[List[str]] = None
        self.PrivilegedAccountType: Optional[List[str]] = None
        self.ContainMaliciousExternalIP: Optional[bool] = None
        self.IPThreatTypes: Optional[List[str]] = None
        self.Asset: Optional[List[str]] = None
        self.AssetContainsFlaggedData: Optional[List[Optional[bool]]] = None
        self.AssetContainsSensitiveData: Optional[List[Optional[bool]]] = None
        self.Platform: Optional[List[str]] = None
        self.FileServerOrDomain: Optional[List[str]] = None
        self.EventUTC: Optional[datetime] = None
        self.DeviceName: Optional[List[str]] = None
        self.IngestTime: datetime = None

        self.Url: str = None

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


class EventItem:
    def __init__(self):
        self.alert_id: Optional[List[str]] = None
        self.id: Optional[str] = None
        self.type: Optional[str] = None
        self.utc_time: Optional[datetime] = None
        self.status: Optional[str] = None
        self.description: Optional[str] = None
        self.country: Optional[str] = None
        self.state: Optional[str] = None
        self.blacklisted_location: Optional[bool] = None
        self.event_operation: Optional[str] = None
        self.by_user_account: Optional[str] = None
        self.by_user_account_type: Optional[str] = None
        self.by_user_account_domain: Optional[str] = None
        self.by_sam_account_name: Optional[str] = None
        self.filer: Optional[str] = None
        self.platform: Optional[str] = None
        self.source_ip: Optional[str] = None
        self.external_ip: Optional[str] = None
        self.destination_ip: Optional[str] = None
        self.source_device: Optional[str] = None
        self.destination_device: Optional[str] = None
        self.is_disabled_account: Optional[bool] = None
        self.is_lockout_account: Optional[bool] = None
        self.is_stale_account: Optional[bool] = None
        self.is_malicious_ip: Optional[bool] = None
        self.external_ip_threat_types: Optional[List[str]] = None
        self.external_ip_reputation: Optional[str] = None
        self.on_object_name: Optional[str] = None
        self.on_object_type: Optional[str] = None
        self.on_sam_account_name: Optional[str] = None
        self.is_sensitive: Optional[bool] = None
        self.on_account_is_disabled: Optional[bool] = None
        self.on_account_is_lockout: Optional[bool] = None
        self.path: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"{key} not found in EventItem")

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


''' MAPPERS '''


class BaseMapper:
    @staticmethod
    def convert_json_to_key_value(json_data) -> List[Dict[str, Any]]:
        data = json_data
        result = []
        for row in data["rows"]:
            obj = {}
            for col, val in zip(data["columns"], row):
                obj[col] = val
            result.append(obj)
        return result


class SearchAlertObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> AlertItem:
        alert_item = AlertItem()
        alert_item.ID = row[AlertAttributes.Id]
        alert_item.Name = row[AlertAttributes.RuleName]
        alert_item.Time = row[AlertAttributes.Time]
        alert_item.Severity = row[AlertAttributes.RuleSeverityName]
        alert_item.SeverityId = int(row[AlertAttributes.RuleSeverityId])
        alert_item.Category = row[AlertAttributes.RuleCategoryName]
        alert_item.Country = self.multi_value_to_string_list(row[AlertAttributes.LocationCountryName])
        alert_item.State = self.multi_value_to_string_list(row[AlertAttributes.LocationSubdivisionName])
        alert_item.Status = row[AlertAttributes.StatusName]
        alert_item.StatusId = int(row[AlertAttributes.StatusId])
        alert_item.CloseReason = row[AlertAttributes.CloseReasonName]
        alert_item.BlacklistLocation = self.get_bool_value(row, AlertAttributes.LocationBlacklistedLocation)
        alert_item.AbnormalLocation = self.multi_value_to_string_list(row[AlertAttributes.LocationAbnormalLocation])
        alert_item.NumOfAlertedEvents = int(row[AlertAttributes.EventsCount])
        alert_item.UserName = self.multi_value_to_string_list(row[AlertAttributes.UserName])
        alert_item.SamAccountName = self.multi_value_to_string_list(row[AlertAttributes.UserSamAccountName])
        alert_item.PrivilegedAccountType = self.multi_value_to_string_list(row[AlertAttributes.UserAccountTypeName])
        alert_item.ContainMaliciousExternalIP = self.get_bool_value(row, AlertAttributes.DeviceIsMaliciousExternalIp)
        alert_item.IPThreatTypes = self.multi_value_to_string_list(row[AlertAttributes.DeviceExternalIpThreatTypesName])
        alert_item.Asset = self.multi_value_to_string_list(row[AlertAttributes.AssetPath])
        alert_item.AssetContainsFlaggedData = self.multi_value_to_boolean_list(row[AlertAttributes.DataIsFlagged])
        alert_item.AssetContainsSensitiveData = self.multi_value_to_boolean_list(row[AlertAttributes.DataIsSensitive])
        alert_item.Platform = self.multi_value_to_string_list(row[AlertAttributes.FilerPlatformName])
        alert_item.FileServerOrDomain = self.multi_value_to_string_list(row[AlertAttributes.FilerName])
        alert_item.DeviceName = self.multi_value_to_string_list(row[AlertAttributes.DeviceHostname])
        alert_item.IngestTime = row[AlertAttributes.IngestTime]
        alert_item.EventUTC = self.get_date_value(row, AlertAttributes.InitialEventUtcTime)

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


class SearchEventObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: Dict[str, str]) -> EventItem:
        event_item = EventItem()

        event_item.alert_id = self.multi_value_to_guid_array(row, EventAttributes.EventAlertId)
        event_item.id = row.get(EventAttributes.EventGuid, '')
        event_item.type = row.get(EventAttributes.EventTypeName)
        event_item.utc_time = self.get_date_value(row, EventAttributes.EventTimeUtc)
        event_item.status = row.get(EventAttributes.EventStatusName)
        event_item.description = row.get(EventAttributes.EventDescription)
        event_item.country = row.get(EventAttributes.EventLocationCountryName)
        event_item.state = row.get(EventAttributes.EventLocationSubdivisionName)
        event_item.blacklisted_location = self.get_bool_value(row, EventAttributes.EventLocationBlacklistedLocation)
        event_item.event_operation = row.get(EventAttributes.EventOperationName)
        event_item.by_user_account = row.get(EventAttributes.EventByAccountIdentityName)
        event_item.by_user_account_type = row.get(EventAttributes.EventByAccountTypeName)
        event_item.by_user_account_domain = row.get(EventAttributes.EventByAccountDomainName)
        event_item.by_sam_account_name = row.get(EventAttributes.EventByAccountSamAccountName)
        event_item.filer = row.get(EventAttributes.EventFilerName)
        event_item.platform = row.get(EventAttributes.EventFilerPlatformName)
        event_item.source_ip = row.get(EventAttributes.EventIp)
        event_item.external_ip = row.get(EventAttributes.EventDeviceExternalIp)
        event_item.destination_ip = row.get(EventAttributes.EventDestinationIp)
        event_item.source_device = row.get(EventAttributes.EventDeviceName)
        event_item.destination_device = row.get(EventAttributes.EventDestinationDeviceName)
        event_item.is_disabled_account = self.get_bool_value(row, EventAttributes.EventByAccountIsDisabled)
        event_item.is_lockout_account = self.get_bool_value(row, EventAttributes.EventByAccountIsLockout)
        event_item.is_stale_account = self.get_bool_value(row, EventAttributes.EventByAccountIsStale)
        event_item.is_malicious_ip = self.get_bool_value(row, EventAttributes.EventDeviceExternalIpIsMalicious)
        event_item.external_ip_threat_types = self.multi_value_to_array(
            row.get(EventAttributes.EventDeviceExternalIpThreatTypesName, ''))
        event_item.external_ip_reputation = row.get(EventAttributes.EventDeviceExternalIpReputationName)
        event_item.on_object_name = row.get(EventAttributes.EventOnObjectName)
        event_item.on_object_type = row.get(EventAttributes.EventOnResourceObjectTypeName)
        event_item.on_sam_account_name = row.get(EventAttributes.EventOnAccountSamAccountName)
        event_item.is_sensitive = self.get_bool_value(row, EventAttributes.EventOnResourceIsSensitive)
        event_item.on_account_is_disabled = self.get_bool_value(row, EventAttributes.EventOnAccountIsDisabled)
        event_item.on_account_is_lockout = self.get_bool_value(row, EventAttributes.EventOnAccountIsLockout)
        event_item.path = row.get(EventAttributes.EventOnResourcePath)

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


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self._session.verify = verify
        if not verify and self._session.adapters['https://']:
            if hasattr(self._session.adapters['https://'], "context"):
                self._session.adapters['https://'].context.check_hostname = verify

        self.headers: Dict[str, Any] = {}
        self.headers["authorization"] = None
        self.headers["content-type"] = 'application/json'

    def varonis_authenticate(self, apiKey: str) -> Dict[str, Any]:
        headers = {
            'x-api-key': apiKey
        }
        response = self._http_request('POST', url_suffix='/api/authentication/api_keys/token',
                                      data='grant_type=varonis_custom', headers=headers)
        token = response['access_token']
        token_type = response['token_type']
        self._expires_in = response['expires_in']

        demisto.debug(f'Token expires in {self._expires_in}')

        self.headers["authorization"] = f'{token_type} {token}'
        return response

    def varonis_get_alerts(self, ruleIds: Optional[List[str]], alertIds: Optional[List[str]], start_time: Optional[datetime],
                           end_time: Optional[datetime], ingest_time_from: Optional[datetime],
                           ingest_time_to: Optional[datetime], device_names: Optional[List[str]], 
                           user_names: Optional[List[str]],
                           last_days: Optional[int],
                           alert_statuses: Optional[List[str]],
                           alert_severities: Optional[List[str]],
                           descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerts

        :type ruleIds: ``Optional[List[str]]``
        :param ruleIds: List of threat models to filter by

        :type alertIds: ``Optional[List[str]]``
        :param alertIds: List of alertIds to filter by

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

        :type ingest_time_from: ``Optional[datetime]``
        :param ingest_time_from: Start ingest time of the range of alerts

        :type ingest_time_to: ``Optional[datetime]``
        :param ingest_time_to: End ingest time of the range of alerts

        :type device_names: ``Optional[List[str]]``
        :param device_names: List of device names to filter by

        :type user_names: ``Optional[List[str]]``
        :param user_names: List of user names to filter by

        :type last_days: ``Optional[List[int]]``
        :param last_days: Number of days you want the search to go back to

        :type alert_statuses: ``Optional[List[str]]``
        :param alert_statuses: List of alert statuses to filter by

        :type alert_severities: ``Optional[List[str]]``
        :param alert_severities: List of alert severities to filter by

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether alerts should be ordered in newest to oldest order

        :return: Alerts
        :rtype: ``List[Dict[str, Any]]``
        """

        search_request = SearchRequest()\
            .set_query(
            Query().set_entity_name("Alert")
            .set_filter(Filters().set_filter_operator(0))
        )\
            .set_rows(
                Rows()
                .set_grouping("")
        )\
            .set_request_params(
                RequestParams().set_search_source(1).set_search_source_name("MainTab")
        )

        for column in AlertAttributes.Columns:
            search_request.rows.add_column(column)

        filter_condition = FilterCondition()\
            .set_path("Alert.AggregationFilter")\
            .set_operator("Equals")\
            .add_value({"Alert.AggregationFilter": 1})\

        search_request.query.filter.add_filter(filter_condition)

        if ingest_time_from and ingest_time_to:
            ingest_time_condition = FilterCondition().set_path("Alert.IngestTime")\
                .set_operator("Between")\
                .add_value({"Alert.IngestTime": ingest_time_from.isoformat(
                ), "Alert.IngestTime0": ingest_time_to.isoformat()})  # "displayValue": ingest_time_from.isoformat(),
            search_request.query.filter.add_filter(ingest_time_condition)
        else:
            days_back = MAX_DAYS_BACK
            if start_time is None and end_time is None and last_days is None:
                last_days = days_back
            elif start_time is None and end_time is not None:
                start_time = end_time - timedelta(days=days_back)
            elif end_time is None and start_time is not None:
                end_time = start_time + timedelta(days=days_back)

            time_condition = FilterCondition().set_path("Alert.TimeUTC")
            if start_time and end_time:
                time_condition = time_condition\
                    .set_operator("Between")\
                    .add_value({"Alert.TimeUTC": start_time.isoformat(
                    ), "Alert.TimeUTC0": end_time.isoformat()})  # "displayValue": start_time.isoformat(),
            if last_days:
                time_condition\
                    .set_operator("LastDays")\
                    .add_value({"Alert.TimeUTC": last_days, "displayValue": last_days})
            search_request.query.filter.add_filter(time_condition)

        if ruleIds and len(ruleIds) > 0:
            rules_condition = FilterCondition()\
                .set_path("Alert.Rule.ID")\
                .set_operator("In")
            for alertId in ruleIds:
                rules_condition.add_value({"Alert.Rule.ID": alertId, "displayValue": "New"})
            search_request.query.filter.add_filter(rules_condition)

        if alertIds and len(alertIds) > 0:
            alert_condition = FilterCondition()\
                .set_path("Alert.ID")\
                .set_operator("In")
            for alertId in alertIds:
                rules_condition.add_value({"Alert.ID": alertId, "displayValue": "New"})
            search_request.query.filter.add_filter(alert_condition)

        if device_names and len(device_names) > 0:
            device_condition = FilterCondition()\
                .set_path("Alert.Device.HostName")\
                .set_operator("In")
            for device_name in device_names:
                rules_condition.add_value({"Alert.Device.HostName": device_name, "displayValue": device_name})
            search_request.query.filter.add_filter(device_condition)

        if user_names and len(user_names) > 0:
            user_condition = FilterCondition()\
                .set_path("Alert.User.Identity.Name")\
                .set_operator("In")
            for user_name in user_names:
                user_condition.add_value({"Alert.User.Identity.Name": user_name, "displayValue": user_name})
            search_request.query.filter.add_filter(user_condition)

        if alert_statuses and len(alert_statuses) > 0:
            status_condition = FilterCondition()\
                .set_path("Alert.Status.ID")\
                .set_operator("In")
            for status in alert_statuses:
                status_id = ALERT_STATUSES[status.lower()]
                status_condition.add_value({"Alert.Status.ID": status_id, "displayValue": status})
            search_request.query.filter.add_filter(status_condition)

        if alert_severities and len(alert_severities) > 0:
            severity_condition = FilterCondition()\
                .set_path("Alert.Rule.Severity.ID")\
                .set_operator("In")
            for severity in alert_severities:
                severity_id = ALERT_SEVERITIES[severity.lower()]
                severity_condition.add_value({"Alert.Rule.Severity.ID": severity_id, "displayValue": severity})
            search_request.query.filter.add_filter(severity_condition)

        if descending_order:
            search_request.rows.add_ordering({"path": "Alert.Time", "sortOrder": "Desc"})

        dataJSON = search_request.to_json()

        create_search = None
        create_search = self._http_request(
            'POST',
            '/app/dataquery/api/search/v2/search',
            data=dataJSON,
            headers=self.headers
        )
        
        url = create_search[0]["location"]
        json_data = self._http_request(
            method='GET',
            url_suffix=f'/app/dataquery/api/search/{url}',
            headers=self.headers,
            status_list_to_retry=[304],
            retries=10
        )

        mapper = SearchAlertObjectMapper()
        alerts = mapper.map(json_data)
        return alerts

    def varonis_get_alerted_events(self, alertIds: List[str], start_time: Optional[datetime], end_time: Optional[datetime],
                                   last_days: Optional[int], descending_order: bool) -> List[Dict[str, Any]]:
        """Get alerted events

        :type alertIds: ``List[str]``
        :param alertIds: List of alert ids

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

        :type count: ``int``
        :param count: Alerted events count

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether events should be ordered in newest to oldest order

        :return: Alerted events
        :rtype: ``List[Dict[str, Any]]``
        """

        days_back = MAX_DAYS_BACK
        if start_time is None and end_time is None and last_days is None:
            last_days = days_back
        elif start_time is None and end_time is not None:
            start_time = end_time - timedelta(days=days_back)
        elif end_time is None and start_time is not None:
            end_time = start_time + timedelta(days=days_back)

        search_request = SearchRequest()\
            .set_query(
            Query()
            .set_entity_name("Event")
            .set_filter(Filters().set_filter_operator(0))
        )\
            .set_rows(Rows().set_grouping(""))\
            .set_request_params(RequestParams().set_search_source(1).set_search_source_name("MainTab"))

        for column in EventAttributes.Columns:
            search_request.rows.add_column(column)

        if alertIds and len(alertIds) > 0:
            time_condition = FilterCondition()\
                .set_path("Event.Alert.ID")\
                .set_operator("In")
            for alertId in alertIds:
                time_condition.add_value({"Event.Alert.ID": alertId, "displayValue": alertId})

            search_request.query.filter.add_filter(time_condition)

        time_condition = FilterCondition().set_path("Event.TimeUTC")
        if start_time and end_time:
            time_condition = time_condition\
                .set_operator("Between")\
                .add_value({"Event.TimeUTC": start_time.isoformat(
                ), "Event.TimeUTC0": end_time.isoformat()})  # "displayValue": start_time.isoformat(),
        if last_days:
            time_condition\
                .set_operator("LastDays")\
                .add_value({"Event.TimeUTC": last_days, "displayValue": last_days})
        search_request.query.filter.add_filter(time_condition)

        if descending_order:
            search_request.rows.add_ordering({"path": "Event.Time", "sortOrder": "Desc"})

        dataJSON = search_request.to_json()

        create_search = self._http_request(
            'POST',
            '/app/dataquery/api/search/v2/search',
            data=dataJSON,
            headers=self.headers
        )

        url = create_search[0]["location"]
        json_data = self._http_request(
            method='GET',
            url_suffix=f'/app/dataquery/api/search/{url}',
            headers=self.headers,
            status_list_to_retry=[304],
            retries=10
        )

        mapper = SearchEventObjectMapper()
        events = mapper.map(json_data)
        return events

    def varonis_get_enum(self, enum_id: int) -> List[Any]:
        """Gets an enum by enum_id. Usually needs for retrieving object required for a search

        :type enum_id: ``int``
        :param enum_id: Id of enum stored in database

        :return: The list of objects required for a search filter
        :rtype: ``List[Any]``
        """
        response = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}', headers=self.headers)
        return response

    def varonis_update_alert_status(self, query: Dict[str, Any]) -> bool:
        """Update alert status

        :type query: ``Dict[str, Any]``
        :param query: Update request body

        :return: Result of execution
        :rtype: ``bool``

        """
        return self._http_request(
            'POST',
            '/api/alert/alert/SetStatusToAlerts',
            json_data=query,
            headers=self.headers)


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: Optional[str]) -> int:
    """Maps Varonis severity to Cortex XSOAR severity

    Converts the Varonis alert severity level ('Low', 'Medium',
    'High') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Varonis API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    if severity is None:
        return IncidentSeverity.LOW

    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH
    }[severity]


def get_included_severitires(severity: Optional[str]) -> List[str]:
    """ Return list of severities that is equal or higher then provided

    :type severity: ``Optional[str]``
    :param severity: Severity

    :return: List of severities
    :rtype: ``List[str]``
    """
    if not severity:
        return []

    severities = list(ALERT_SEVERITIES.keys()).copy()

    if severity.lower() == 'medium':
        severities.remove('low')

    if severity.lower() == 'high':
        severities.remove('low')
        severities.remove('medium')

    return severities


def validate_threat_models(client: Client, threat_models: List[str]):
    """ Validates if threat models exist in Varonis

    :type client: ``Client``
    :param client: Http client

    :type threat_models: ``Optional[List[str]]``
    :param threat_model: List of threat model names of alerts to fetch

    """

    rules_enum = client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
    for threat_model in threat_models:
        rule = next((r for r in rules_enum if strEqual(r['ruleName'], threat_model)), None)

        if not rule:
            raise ValueError(f'There is no threat model with name {threat_model}.')


def try_convert(item, converter, error=None):
    """Try to convert item

    :type item: ``Any``
    :param item: An item to convert

    :type converter: ``Any``
    :param converter: Converter function

    :type error: ``Any``
    :param error: Error object that will be raised in case of error convertion

    :return: A converted item or None
    :rtype: ``Any``
    """
    if item:
        try:
            return converter(item)
        except Exception:
            if error:
                raise error
            raise
    return None


def strEqual(text1: str, text2: str) -> bool:
    if not text1 and not text2:
        return True
    if not text1 or not text2:
        return False

    return text1.casefold() == text2.casefold()


def enrich_with_url(output: Dict[str, Any], baseUrl: str, id: str) -> Dict[str, Any]:
    """Enriches result with alert url

    :type output: ``Dict[str, Any]``
    :param output: Output to enrich

    :type baseUrl: ``str``
    :param baseUrl: Varonis UI based url

    :type id: ``str``
    :param id: Alert it

    :return: Enriched output
    :rtype: ``Dict[str, Any]``
    """

    output['Url'] = urljoin(baseUrl, f'/#/app/analytics/entity/Alert/{id}')
    return output


def get_rule_ids(client: Client, values: List[str]) -> List[int]:
    """Return list of user ids

    :type client: ``Client``
    :param client: Http client

    :type threat_model_names: ``List[str]``
    :param threat_model_names: A list of threat_model_names

    :return: List of rule ids
    :rtype: ``List[int]``
    """
    ruleIds: List[int] = []

    if not values:
        return ruleIds

    rules = client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
    for value in values:
        for rule in rules:
            if strEqual(rule['ruleName'], value):
                ruleIds.append(rule['ruleID'])
                # ruleIds.append(rule['templateID'])
                break

    return ruleIds


def varonis_update_alert(client: Client, close_reason_id: int, status_id: int, alert_ids: list) -> bool:
    """Update Varonis alert. It creates request and pass it to http client

    :type client: ``Client``
    :param client: Http client

    :type close_reason_id: ``int``
    :param close_reason_id: close reason enum id

    :type status_id: ``int``
    :param status_id: status id enum id

    :type alert_ids: ``list``
    :param alert_ids: list of alert id(s)

    :return: Result of execution
    :rtype: ``bool``

    """
    if len(alert_ids) == 0:
        raise ValueError('alert id(s) not specified')

    query: Dict[str, Any] = {
        'AlertGuids': alert_ids,
        'CloseReasonId': close_reason_id,
        'StatusId': status_id
    }

    return client.varonis_update_alert_status(query)


def convert_incident_alert_to_onprem_format(alert_saas_format):
    output = alert_saas_format

    # todo: fix when it will be converted to array
    output["Locations"] = []
    countries = [] if alert_saas_format.get("Country") is None else alert_saas_format.get("Country")
    states = [] if alert_saas_format.get("State") is None else alert_saas_format.get("State")
    blacklist_locations = [] if alert_saas_format.get(
        "BlacklistLocation") is None else [alert_saas_format.get("BlacklistLocation")]
    abnormal_locations = [] if alert_saas_format.get("AbnormalLocation") is None else alert_saas_format.get("AbnormalLocation")
    for i in range(len(countries)):
        entry = {
            "Country": "" if len(countries) <= i else countries[i],
            "State": "" if len(states) <= i else states[i],
            "BlacklistLocation": "" if len(blacklist_locations) <= i else blacklist_locations[i],
            "AbnormalLocation": "" if len(abnormal_locations) <= i else abnormal_locations[i]
        }
        output["Locations"].append(entry)

    # todo: fix when it will be converted to array
    output["Sources"] = []
    platforms = [] if alert_saas_format.get("Platform") is None else alert_saas_format.get("Platform")
    file_server_or_Domain = [] if alert_saas_format.get(
        "FileServerOrDomain") is None else alert_saas_format.get("FileServerOrDomain")
    for i in range(len(platforms)):
        entry = {
            "Platform": "" if len(platforms) <= i else platforms[i],
            "FileServerOrDomain": "" if len(file_server_or_Domain) <= i else file_server_or_Domain[i]
        }
        output["Sources"].append(entry)

    # todo: fix when it will be converted to array
    output["Devices"] = []
    device_names = [] if alert_saas_format.get("DeviceName") is None else alert_saas_format.get("DeviceName")
    assets = [] if alert_saas_format.get("Asset") is None else alert_saas_format.get("Asset")
    for i in range(len(device_names)):
        entry = {
            "Name": "" if len(device_names) <= i else device_names[i],
            "Asset": "" if len(assets) <= i else assets[i]
        }
        output["Devices"].append(entry)

    output["Users"] = []
    user_names = [] if alert_saas_format.get("UserName") is None else alert_saas_format["UserName"]
    sam_account_names = [] if alert_saas_format.get("SamAccountName") is None else alert_saas_format["SamAccountName"]
    privileged_account_types = [] if alert_saas_format.get(
        "PrivilegedAccountType") is None else alert_saas_format["PrivilegedAccountType"]
    departments = [] if alert_saas_format.get("Department") is None else alert_saas_format["Department"]
    for i in range(len(user_names)):
        entry = {
            "Name": "" if len(user_names) <= i else user_names[i],
            "SamAccountName": "" if len(sam_account_names) <= i else sam_account_names[i],
            "PrivilegedAccountType": "" if len(privileged_account_types) <= i else privileged_account_types[i],
            "Department": "" if len(departments) <= i else departments[i]
        }
        output["Users"].append(entry)

    return output


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
        message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: token is incorrect or expired.'
        else:
            raise e
    return message


def fetch_incidents_command(client: Client, last_run: Dict[str, datetime], first_fetch_time: Optional[datetime],
                            alert_status: Optional[str], threat_model: Optional[str], severity: Optional[str]
                            ) -> Tuple[Dict[str, Optional[datetime]], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param client: Http client

    :type last_run: ``Dict[str, datetime]``
    :param last_run:
        A dict with a key containing the latest alert ingest time we got from last fetch

    :type first_fetch_time: ``Optional[datetime]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the datetime on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status: status of the alert to search for. Options are 'New', 'Under investigation', 'Action Required', 'Auto-Resolved' or 'Closed' 

    :type threat_model: ``Optional[str]``
    :param threat_model: Comma-separated list of threat model names of alerts to fetch

    :type severity: ``Optional[str]``
    :param severity: severity of the alert to search for. Options are 'High', 'Medium' or 'Low'

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, Optional[int]]``): Contains last fetched id.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``

    """

    threat_model_names = argToList(threat_model)
    if threat_model_names and len(threat_model_names) > 0:
        validate_threat_models(client, threat_model_names)

    incidents: List[Dict[str, Any]] = []

    last_fetched_ingest_time_str = last_run.get('last_fetched_ingest_time', first_fetch_time.isoformat())
    last_fetched_ingest_time = try_convert(
        last_fetched_ingest_time_str,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'last_fetched_ingest_time should be in iso format, but it is {last_fetched_ingest_time_str}.')
    )
    ingest_time_to = datetime.now()

    demisto.debug(f'Fetching incidents. Last fetched ingest time: {last_fetched_ingest_time}')

    statuses = []
    if alert_status:
        statuses.append(alert_status)

    severities = get_included_severitires(severity)

    ruleIds = get_rule_ids(client, threat_model_names)

    alerts = client.varonis_get_alerts(ruleIds=ruleIds, alertIds=None, start_time=None, end_time=None,
                                       device_names=None, user_names=None, last_days=None,
                                       ingest_time_from=last_fetched_ingest_time,
                                       ingest_time_to=ingest_time_to,
                                       alert_statuses=statuses, alert_severities=severities,
                                       descending_order=True)

    demisto.debug(f'varonis_get_alerts returned: {len(alerts)} alerts')

    for alert in alerts:
        ingestTime_str = alert['IngestTime']
        ingestTime = try_convert(
            alert['IngestTime'],
            lambda x: datetime.fromisoformat(x),
            ValueError(f'IngestTime should be in iso format, but it is {ingestTime_str}.')
        )

        if not last_fetched_ingest_time or ingestTime > last_fetched_ingest_time:
            last_fetched_ingest_time = ingestTime + timedelta(minutes=1)
        guid = alert['ID']
        name = alert['Name']
        alert_time = alert['Time']
        enrich_with_url(alert, client._base_url, guid)

        alert_converted = convert_incident_alert_to_onprem_format(alert)

        incident = {
            'name': f'Varonis alert {name}',
            'occurred': f'{alert_time}Z',
            'rawJSON': json.dumps(alert_converted),
            'type': 'Varonis DSP Incident',
            'severity': convert_to_demisto_severity(alert_converted['Severity']),
        }

        incidents.append(incident)
        demisto.debug(f'new incident: {json.dumps(alert, indent=4, sort_keys=True, default=str)}')

    next_run = {'last_fetched_ingest_time': last_fetched_ingest_time.isoformat()}

    return next_run, incidents


def varonis_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerts from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['threat_model_name']`` List of requested threat models to retrieve
        ``args['ingest_time_from']`` Start ingest time of the range of alerts
        ``args['ingest_time_to']`` End ingest time of the range of alerts
        ``args['start_time']`` Start time of the range of alerts
        ``args['end_time']`` End time of the range of alerts
        ``args['alert_status']`` List of required alerts status
        ``args['alert_severity']`` List of alerts severity
        ``args['device_name']`` List of device names
        ``args['last_days']`` Number of days you want the search to go back to
        ``args['descending_order']`` Indicates whether alerts should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    threat_model_names = args.get('threat_model_name', None)
    alert_ids = args.get('alert_ids', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    ingest_time_from = args.get('ingest_time_from', None)
    ingest_time_to = args.get('ingest_time_to', None)
    alert_statuses = args.get('alert_status', None)
    alert_severities = args.get('alert_severity', None)
    device_names = args.get('device_name', None)
    user_names = args.get('user_name', None)
    last_days = args.get('last_days', None)
    descending_order = args.get('descending_order', True)

    if last_days:
        last_days = try_convert(
            last_days,
            lambda x: int(x),
            ValueError(f'last_days should be integer, but it is {last_days}.')
        )

        if last_days <= 0:
            raise ValueError('last_days cannot be less then 1')

    alert_severities = try_convert(alert_severities, lambda x: argToList(x))
    device_names = try_convert(device_names, lambda x: argToList(x))
    threat_model_names = try_convert(threat_model_names, lambda x: argToList(x))
    user_names = try_convert(user_names, lambda x: argToList(x))

    start_time = try_convert(
        start_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'start_time should be in iso format, but it is {start_time}.')
    )
    end_time = try_convert(
        end_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'end_time should be in iso format, but it is {start_time}.')
    )

    ingest_time_from = try_convert(
        ingest_time_from,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'ingest_time_from should be in iso format, but it is {ingest_time_from}.')
    )
    ingest_time_to = try_convert(
        ingest_time_to,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'ingest_time_to should be in iso format, but it is {ingest_time_to}.')
    )

    alert_statuses = try_convert(alert_statuses, lambda x: argToList(x))

    if alert_severities:
        for severity in alert_severities:
            if severity.lower() not in ALERT_SEVERITIES.keys():
                raise ValueError(f'There is no severity {severity}.')

    if alert_statuses:
        for status in alert_statuses:
            if status.lower() not in ALERT_STATUSES.keys():
                raise ValueError(f'There is no status {status}.')

    ruleIds = get_rule_ids(client, threat_model_names)

    alerts = client.varonis_get_alerts(ruleIds, alert_ids, start_time, end_time, ingest_time_from, ingest_time_to, device_names,
                                       user_names,
                                       last_days, alert_statuses, alert_severities,
                                       descending_order)
    outputs = dict()
    outputs['Alert'] = alerts

    if outputs:
        for alert in alerts:
            enrich_with_url(alert, client._base_url, alert['ID'])

    readable_output = tableToMarkdown('Varonis Alerts', alerts, headers=[
                                      'Name', 'Severity', 'Time', 'Category', 'UserName', 'Status'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Alert.ID',
        outputs=outputs
    )


def varonis_get_alerted_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get alerted events from Varonis DA

    :type client: ``Client``
    :param client: Http client 

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` List of alert ids
        ``args['start_time']`` Start time of the range of events
        ``args['end_time']`` End time of the range of events
        ``args['last_days']`` Number of days you want the search to go back to
        ``args['descending_order']`` Indicates whether events should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alertIds = args.get('alert_id', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    last_days = args.get('last_days', None)
    descending_order = args.get('descending_order', True)

    alertIds = try_convert(alertIds, lambda x: argToList(x))
    start_time = try_convert(
        start_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'start_time should be in iso format, but it is {start_time}.')
    )
    end_time = try_convert(
        end_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'end_time should be in iso format, but it is {start_time}.')
    )

    events = client.varonis_get_alerted_events(alertIds=alertIds, start_time=start_time, end_time=end_time,
                                               last_days=last_days,
                                               descending_order=descending_order)
    outputs = dict()
    outputs['Event'] = events

    readable_output = tableToMarkdown('Varonis Alerted Events', events)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Event.ID',
        outputs=outputs
    )


def varonis_update_alert_status_command(client: Client, args: Dict[str, Any]) -> bool:
    """Update Varonis alert status command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` Alert's new status
        ``args['alert_id']`` Array of alert ids to be updated

    :return: Result of execution
    :rtype: ``bool``

    """
    status = args.get('status', None)
    statuses = list(filter(lambda name: name != 'closed', ALERT_STATUSES.keys()))
    if status.lower() not in statuses:
        raise ValueError(f'status must be one of {statuses}.')

    status_id = ALERT_STATUSES[status.lower()]

    return varonis_update_alert(client, CLOSE_REASONS['none'], status_id, argToList(args.get('alert_id')))


def varonis_close_alert_command(client: Client, args: Dict[str, Any]) -> bool:
    """Close Varonis alert command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['close_reason']`` Alert's close reason
        ``args['alert_id']`` Array of alert ids to be closed

    :return: Result of execution
    :rtype: ``bool``

    """
    close_reason = args.get('close_reason', None)
    close_reasons = list(filter(lambda name: not strEqual(name, 'none'), CLOSE_REASONS.keys()))
    if close_reason.lower() not in close_reasons:
        raise ValueError(f'close reason must be one of {close_reasons}')

    close_reason_id = CLOSE_REASONS[close_reason.lower()]

    return varonis_update_alert(client, close_reason_id, ALERT_STATUSES['closed'], argToList(args.get('alert_id')))


def is_xsoar_env() -> bool:
    return not not demisto.params().get('url')


'''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    if not is_xsoar_env():
        url = 'https://int0bf5b.varonis-preprod.com'
        apiKey = 'vkey1_9e9575aa2665457c88a08bd496f5b87f_+vFM0cQ/XVzMF8+uYMWJPVNc3OF69cXtX77LOg+EeUY='
        command = 'varonis-get-alerts'  # 'test-module'|
        # 'varonis-get-alerts'|
        # 'varonis-get-alerted-events'|
        # 'varonis-update-alert-status'|
        # 'varonis-close-alert'|
        # 'fetch-incidents'
        params = {
            'url': url,
            'apiKey': apiKey,
            'insecure': True,
            'proxy': False,
            'status': None,
            'threat_model': None,
            'severity': None,
            'max_fetch': None,
            'first_fetch': '1 week'
        }

        if command == 'test-module':
            pass
        elif command == 'varonis-get-alerts':
            args['threat_model_name'] = None  # List of requested threat models
            args['ingest_time_from'] = None  # Start ingest time of the range of alerts
            args['ingest_time_to'] = None  # End ingest time of the range of alerts
            args['start_time'] = "2023-10-17T03:47:00"  # Start time of the range of alerts
            args['end_time'] = "2023-10-26T16:47:00"  # End time of the range of alerts
            args['alert_status'] = None  # List of required alerts status
            args['alert_severity'] = None  # List of alerts severity
            args['device_name'] = None  # List of device names
            args['user_name'] = "varadm"  # List of device names
            args['last_days'] = None  # Number of days you want the search to go back to
            args['descending_order'] = None  # Indicates whether alerts should be ordered in newest to oldest order

        elif command == 'varonis-get-alerted-events':
            args['alert_id'] = "982B74C2-C98E-4631-B034-1F1E3910C1C0"  # Array of alert ids
            args['start_time'] = None  # Start time of the range of events
            args['end_time'] = None  # End time of the range of events
            args['last_days'] = None  # Number of days you want the search to go back to
            args['descending_order'] = None  # Indicates whether events should be ordered in newest to oldest order

        elif command == 'varonis-update-alert-status':
            args['status'] = 'under investigation'  # Alert's new status
            args['alert_id'] = "215FF1FE-E25C-4C12-AB16-937BF186ABD9"  # Array of alert ids to be updated

        elif command == 'varonis-close-alert':
            args['close_reason'] = 'resolved'  # Alert's close reason
            args['alert_id'] = "215FF1FE-E25C-4C12-AB16-937BF186ABD9"  # Array of alert ids to be closed

        elif command == 'fetch-incidents':
            pass

    base_url = params['url']
    apiKey = params['apiKey']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', True)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        client.varonis_authenticate(apiKey)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client)
            return_results(result)

        elif command == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, args))

        elif command == 'varonis-get-alerted-events':
            return_results(varonis_get_alerted_events_command(client, args))

        elif command == 'varonis-update-alert-status':
            return_results(varonis_update_alert_status_command(client, args))

        elif command == 'varonis-close-alert':
            return_results(varonis_close_alert_command(client, args))

        elif command == 'fetch-incidents':
            alert_status = params.get('status', None)
            threat_model = params.get('threat_model', None)
            severity = params.get('severity', None)

            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '1 week'),
                arg_name='First fetch time',
                required=True
            )

            next_run, incidents = fetch_incidents_command(client=client,
                                                          last_run=demisto.getLastRun(),
                                                          first_fetch_time=first_fetch_time,
                                                          alert_status=alert_status,
                                                          threat_model=threat_model,
                                                          severity=severity)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
