from typing import Any
import json
import fnmatch
import traceback
import demistomock as demisto
from CommonServerUserPython import *
from CommonServerPython import *


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

    def get_fields(self, extra_fields: Optional[list[str]]) -> list[str]:
        output = self.Columns.copy()

        if extra_fields:
            for pattern in extra_fields:
                match_columns = fnmatch.filter(self.ExtraColumns, pattern)
                output.extend([item for item in match_columns if item not in output])

        return output


class AlertItem:
    def __init__(self, row: dict):
        self.row = row
        pass

    def __getitem__(self, key: str) -> Any:
        if hasattr(self.row, key):
            return getattr(self.row, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> dict[str, Any]:
        return self.row


class BaseMapper:
    @staticmethod
    def convert_json_to_key_value(json_data) -> list[dict[str, Any]]:
        data = json_data
        result = []
        for row in data["rows"]:
            obj = {}
            for col, val in zip(data["columns"], row):
                obj[col] = val
            result.append(obj)
        return result


MAX_DAYS_BACK = 180
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'new': 1, 'under investigation': 2, 'closed': 3, 'action required': 4, 'auto-resolved': 5}
ALERT_SEVERITIES = {'high': 0, 'medium': 1, 'low': 2}
INCIDENT_FIELDS = [
    "ID",
    "Category",
    "Name",
    "Status",
    "severity",
    "IPThreatTypes",
    "CloseReason",
    "CloseNotes",
    "NumOfAlertedEvents",
    "ContainsFlaggedData",
    "ContainMaliciousExternalIP",
    "ContainsSensitiveData",
    "Locations",
    "Devices",
    "Users"
]
MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Outgoing": "Out",
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self._session.verify = verify
        if not verify and self._session.adapters['https://'] and hasattr(self._session.adapters['https://'], "context"):
            self._session.adapters['https://'].context.check_hostname = verify

        self.headers: dict[str, Any] = {}
        self.headers["authorization"] = None
        self.headers["content-type"] = 'application/json'
        self.headers["varonis-integration"] = 'XSOAR Cortex'

    def varonis_authenticate(self, apiKey: str) -> dict[str, Any]:
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

    def varonis_search(self, search_query: str, max_fetch: Optional[int] = 1000):
        create_search = self._http_request(
            'POST',
            '/app/dataquery/api/search/v2/search',
            data=search_query,
            headers=self.headers
        )

        url = create_search[0]["location"]
        url_suffix = f'/app/dataquery/api/search/{url}'
        if max_fetch:
            url_suffix += f'?from=0&to={max_fetch - 1}'
        json_data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            headers=self.headers,
            status_list_to_retry=[304, 405, 206],
            retries=10
        )
        return json_data

    def varonis_get_alerts(self, threat_model_names: Optional[list[str]],
                           alertIds: Optional[list[str]], start_time: Optional[datetime],
                           end_time: Optional[datetime], ingest_time_from: Optional[datetime],
                           ingest_time_to: Optional[datetime], device_names: Optional[list[str]],
                           user_names: Optional[list[str]],
                           last_days: Optional[int],
                           alert_statuses: Optional[list[str]],
                           alert_severities: Optional[list[str]],
                           extra_fields: Optional[list[str]],
                           descending_order: bool,
                           max_fetch: Optional[int] = 1000) -> list[dict[str, Any]]:
        """Get alerts

        :type threat_model_names: ``Optional[List[str]]``
        :param threat_model_names: List of threat models to filter by

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

        :type extra_fields: ``Optional[List[str]]``
        :param extra_fields: List of extra fields to include in the response

        :type descendingOrder: ``bool``
        :param descendingOrder: Indicates whether alerts should be ordered in newest to oldest order

        :type max_fetch: ``Optional[int]``
        :param max_fetch: Maximum number of items

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

        alert_attributes = AlertAttributes()
        for column in alert_attributes.get_fields(extra_fields):
            search_request.rows.add_column(column)

        filter_condition = FilterCondition()\
            .set_path("Alert.AggregationFilter")\
            .set_operator("Equals")\
            .add_value({"Alert.AggregationFilter": 1})\

        search_request.query.filter.add_filter(filter_condition)

        if ingest_time_from and ingest_time_to:
            ingest_time_condition = FilterCondition().set_path(alert_attributes.Alert_IngestTime)\
                .set_operator("Between")\
                .add_value({alert_attributes.Alert_IngestTime: ingest_time_from.isoformat(
                ), f"{alert_attributes.Alert_IngestTime}0": ingest_time_to.isoformat()})
            search_request.query.filter.add_filter(ingest_time_condition)
        else:
            days_back = MAX_DAYS_BACK
            if start_time is None and end_time is None and last_days is None:
                last_days = days_back
            elif start_time is None and end_time is not None:
                start_time = end_time - timedelta(days=days_back)
            elif end_time is None and start_time is not None:
                end_time = start_time + timedelta(days=days_back)

            time_condition = FilterCondition().set_path(alert_attributes.Alert_TimeUTC)
            if start_time and end_time:
                time_condition = time_condition\
                    .set_operator("Between")\
                    .add_value({alert_attributes.Alert_TimeUTC: start_time.isoformat(
                    ), f"{alert_attributes.Alert_TimeUTC}0": end_time.isoformat()})  # "displayValue": start_time.isoformat(),
            if last_days:
                time_condition\
                    .set_operator("LastDays")\
                    .add_value({alert_attributes.Alert_TimeUTC: last_days, "displayValue": last_days})
            search_request.query.filter.add_filter(time_condition)

        if threat_model_names:
            rule_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Rule_Name)\
                .set_operator("In")
            for threat_model_name in threat_model_names:
                rule_condition.add_value({alert_attributes.Alert_Rule_Name: threat_model_name, "displayValue": "New"})
            search_request.query.filter.add_filter(rule_condition)

        if alertIds:
            alert_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_ID)\
                .set_operator("In")
            for alertId in alertIds:
                alert_condition.add_value({alert_attributes.Alert_ID: alertId, "displayValue": "New"})
            search_request.query.filter.add_filter(alert_condition)

        if device_names:
            device_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Device_HostName)\
                .set_operator("In")
            for device_name in device_names:
                device_condition.add_value({alert_attributes.Alert_Device_HostName: device_name, "displayValue": device_name})
            search_request.query.filter.add_filter(device_condition)

        if user_names:
            user_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_User_Identity_Name)\
                .set_operator("In")
            for user_name in user_names:
                user_condition.add_value({alert_attributes.Alert_User_Identity_Name: user_name, "displayValue": user_name})
            search_request.query.filter.add_filter(user_condition)

        if alert_statuses:
            status_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Status_ID)\
                .set_operator("In")
            for status in alert_statuses:
                status_id = ALERT_STATUSES[status.lower()]
                status_condition.add_value({alert_attributes.Alert_Status_ID: status_id, "displayValue": status})
            search_request.query.filter.add_filter(status_condition)

        if alert_severities:
            severity_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Rule_Severity_ID)\
                .set_operator("In")
            for severity in alert_severities:
                severity_id = ALERT_SEVERITIES[severity.lower()]
                severity_condition.add_value({alert_attributes.Alert_Rule_Severity_ID: severity_id, "displayValue": severity})
            search_request.query.filter.add_filter(severity_condition)

        if descending_order:
            search_request.rows.add_ordering({"path": "Alert.TimeUTC", "sortOrder": "Desc"})
        else:
            search_request.rows.add_ordering({"path": "Alert.TimeUTC", "sortOrder": "Asc"})

        dataJSON = search_request.to_json()
        json_data = self.varonis_search(dataJSON, max_fetch)
        mapper = SearchAlertObjectMapper()
        alerts = mapper.map(json_data)
        return alerts

    def varonis_get_alerted_events(self, alertIds: list[str], start_time: Optional[datetime], end_time: Optional[datetime],
                                   last_days: Optional[int], extra_fields: Optional[list[str]],
                                   descending_order: bool,
                                   max_fetch: Optional[int] = 1000) -> list[dict[str, Any]]:
        """Get alerted events

        :type alertIds: ``List[str]``
        :param alertIds: List of alert ids

        :type start_time: ``Optional[datetime]``
        :param start_time: Start time of the range of alerts

        :type end_time: ``Optional[datetime]``
        :param end_time: End time of the range of alerts

        :type count: ``int``
        :param count: Alerted events count

        :type extra_fields: ``Optional[List[str]]``
        :param extra_fields: List of extra fields to include in the response

        :type extra_fields: ``Optional[List[str]]``
        :param extra_fields: List of extra fields to include in the response

        :type descending_order: ``bool``
        :param descending_order: Indicates whether events should be ordered in newest to oldest order

        :type max_fetch: ``Optional[int]``
        :param max_fetch: Maximum number of items

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
                .set_filter(Filters().set_filter_operator(0)))\
            .set_rows(Rows().set_grouping(""))\
            .set_request_params(RequestParams().set_search_source(1).set_search_source_name("MainTab"))

        event_attributes = EventAttributes()
        for column in event_attributes.get_fields(extra_fields):
            search_request.rows.add_column(column)

        if alertIds and len(alertIds) > 0:
            time_condition = FilterCondition()\
                .set_path(event_attributes.Event_Alert_ID)\
                .set_operator("In")
            for alertId in alertIds:
                time_condition.add_value({event_attributes.Event_Alert_ID: alertId, "displayValue": alertId})

            search_request.query.filter.add_filter(time_condition)

        time_condition = FilterCondition().set_path(event_attributes.Event_TimeUTC)
        if start_time and end_time:
            time_condition = time_condition\
                .set_operator("Between")\
                .add_value({event_attributes.Event_TimeUTC: start_time.isoformat(),
                            f"{event_attributes.Event_TimeUTC}0": end_time.isoformat()})
            # "displayValue": start_time.isoformat(), (this line seems to be commented out)
        if last_days:
            time_condition\
                .set_operator("LastDays")\
                .add_value({event_attributes.Event_TimeUTC: last_days, "displayValue": last_days})
        search_request.query.filter.add_filter(time_condition)

        if descending_order:
            search_request.rows.add_ordering({"path": event_attributes.Event_TimeUTC, "sortOrder": "Desc"})
        else:
            search_request.rows.add_ordering({"path": event_attributes.Event_TimeUTC, "sortOrder": "Asc"})

        dataJSON = search_request.to_json()
        json_data = self.varonis_search(dataJSON, max_fetch)
        mapper = SearchEventObjectMapper()
        events = mapper.map(json_data)
        return events

    def varonis_get_enum(self, enum_id: int) -> list[Any]:
        """Gets an enum by enum_id. Usually needs for retrieving object required for a search

        :type enum_id: ``int``
        :param enum_id: Id of enum stored in database

        :return: The list of objects required for a search filter
        :rtype: ``List[Any]``
        """
        response = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}', headers=self.headers)
        return response

    def varonis_update_alert_status(self, query: dict[str, Any]) -> bool:
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

    def varonis_add_note_to_alerts(self, query: dict[str, Any]) -> bool:
        """Update alert status

        :type query: ``Dict[str, Any]``
        :param query: "add notes" request body

        :return: Result of execution
        :rtype: ``bool``

        """
        return self._http_request(
            'POST',
            '/api/alert/alert/AddNoteToAlerts',
            json_data=query,
            headers=self.headers)


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

    def get_fields(self, extra_fields: Optional[list[str]]) -> list[str]:
        output = self.Columns.copy()

        if extra_fields:
            for pattern in extra_fields:
                match_columns = fnmatch.filter(self.ExtraColumns, pattern)
                output.extend([item for item in match_columns if item not in output])

        return output


class EventItem:
    def __init__(self, row: dict):
        self.row = row

    def __getitem__(self, key: str) -> Any:
        if hasattr(self.row, key):
            return getattr(self.row, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> dict[str, Any]:
        return self.row


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
        self.value = value
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


class SearchAlertObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> AlertItem:
        alert_item = AlertItem(row)

        return alert_item


class SearchEventObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = self.convert_json_to_key_value(json_data)

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict[str, str]) -> EventItem:
        event_item = EventItem(row)

        return event_item

    def multi_value_to_guid_array(self, row: dict[str, str], field: str) -> Optional[list[str]]:
        value = row.get(field)
        if value:
            return list(value.split(','))
        return None

    def get_bool_value(self, row: dict[str, str], name: str) -> Optional[bool]:
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

    def get_date_value(self, row: dict[str, str], name: str) -> Optional[datetime]:
        value = row.get(name)
        if value:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None

    def multi_value_to_array(self, multi_value: str) -> Optional[list[str]]:
        if multi_value:
            return [v.strip() for v in multi_value.split(',') if v.strip()]
        return None


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


class ThreatModelAttributes:
    Id = "ruleID"
    Name = "ruleName"
    Category = "ruleArea"
    Source = "ruleSource"
    Severity = "severity"

    Columns = [Id, Name, Category, Source, Severity]


class ThreatModelItem:
    def __init__(self):
        self.ID: Optional[str] = None
        self.Name: Optional[list[str]] = None

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"{key} not found in EventItem")

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


class ThreatModelObjectMapper(BaseMapper):
    def map(self, json_data):
        key_valued_objects = json_data

        mapped_items = []
        for obj in key_valued_objects:
            mapped_items.append(self.map_item(obj).to_dict())

        return mapped_items

    def map_item(self, row: dict) -> ThreatModelItem:
        threat_model_item = ThreatModelItem()
        threat_model_item.ID = row.get(ThreatModelAttributes.Id, row.get('dataField'))
        threat_model_item.Name = row.get(ThreatModelAttributes.Name, row.get('displayField'))
        return threat_model_item


"""Varonis SaaS integration
"""


''' CONSTANTS '''

MAX_USERS_TO_SEARCH = 5
MAX_DAYS_BACK = 180
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'new': 1, 'under investigation': 2, 'closed': 3, 'action required': 4, 'auto-resolved': 5}
ALERT_SEVERITIES = {'high': 0, 'medium': 1, 'low': 2}
CLOSE_REASONS = {
    'none': 0,
    'other': 1,
    'benign activity': 2,
    'true positive': 3,
    'environment misconfiguration': 4,
    'alert recently customized': 5,
    'inaccurate alert logic': 6,
    'authorized activity': 7
}


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


def get_included_severitires(severity: Optional[str]) -> list[str]:
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


def enrich_with_url(output: dict[str, Any], baseUrl: str, id: str) -> dict[str, Any]:
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

    output['Url'] = urljoin(baseUrl, f'/analytics/entity/Alert/{id}')
    return output


def varonis_update_alert(client: Client, close_reason_id: Optional[int], status_id: Optional[int], alert_ids: list, note) -> bool:
    """Update Varonis alert. It creates request and pass it to http client

    :type client: ``Client``
    :param client: Http client

    :type close_reason_id: ``int``
    :param close_reason_id: close reason enum id

    :type status_id: ``int``
    :param status_id: status id enum id

    :type alert_ids: ``list``
    :param alert_ids: list of alert id(s)

    :type note: ``str``
    :param note: alert note

    :return: Result of execution
    :rtype: ``bool``

    """
    if len(alert_ids) == 0:
        raise ValueError('alert id(s) not specified')

    if (not note and not status_id):
        raise ValueError('To update update alert you must specify status or note')

    update_status_result = False
    add_note_result = False

    if note:
        add_note_query: dict[str, Any] = {
            'AlertGuids': alert_ids,
            'Note': note
        }
        add_note_result = client.varonis_add_note_to_alerts(add_note_query)

    if status_id:
        update_status_query: dict[str, Any] = {
            'AlertGuids': alert_ids,
            'CloseReasonId': close_reason_id,
            'StatusId': status_id
        }
        demisto.debug(f'update_status_query: {json.dumps(update_status_query)}')
        update_status_result = client.varonis_update_alert_status(update_status_query)

    return bool(update_status_result or add_note_result)


def convert_incident_alert_to_onprem_format(alert_saas_format):
    output = alert_saas_format

    output["Category"] = alert_saas_format.get(AlertAttributes.Alert_Rule_Category_Name)
    output["ID"] = alert_saas_format.get(AlertAttributes.Alert_ID)
    output["Name"] = alert_saas_format.get(AlertAttributes.Alert_Rule_Name)
    output["Status"] = alert_saas_format.get(AlertAttributes.Alert_Status_Name)
    output["IPThreatTypes"] = alert_saas_format.get(AlertAttributes.Alert_Device_ExternalIPThreatTypesName)
    output["CloseReason"] = alert_saas_format.get(AlertAttributes.Alert_CloseReason_Name)
    output["NumOfAlertedEvents"] = alert_saas_format.get(AlertAttributes.Alert_EventsCount)
    output["ContainsFlaggedData"] = alert_saas_format.get(AlertAttributes.Alert_Data_IsFlagged)
    output["ContainMaliciousExternalIP"] = alert_saas_format.get(AlertAttributes.Alert_Device_IsMaliciousExternalIP)
    output["ContainsSensitiveData"] = alert_saas_format.get(AlertAttributes.Alert_Data_IsSensitive)

    output["Locations"] = []
    countries = [] if alert_saas_format.get(AlertAttributes.Alert_Location_CountryName) is None else alert_saas_format.get(
        AlertAttributes.Alert_Location_CountryName).split(',')
    states = [] if alert_saas_format.get(AlertAttributes.Alert_Location_SubdivisionName) is None else alert_saas_format.get(
        AlertAttributes.Alert_Location_SubdivisionName).split(',')
    blacklist_locations = [] if alert_saas_format.get(
        AlertAttributes.Alert_Location_BlacklistedLocation) is None else alert_saas_format.get(
            AlertAttributes.Alert_Location_BlacklistedLocation).split(',')
    abnormal_locations = [] if alert_saas_format.get(
        AlertAttributes.Alert_Location_AbnormalLocation) is None else alert_saas_format.get(
            AlertAttributes.Alert_Location_AbnormalLocation).split(',')
    for i in range(len(countries)):
        entry = {
            "Country": "" if len(countries) <= i else countries[i],
            "State": "" if len(states) <= i else states[i],
            "BlacklistLocation": "" if len(blacklist_locations) <= i else blacklist_locations[i],
            "AbnormalLocation": "" if len(abnormal_locations) <= i else abnormal_locations[i]
        }
        output["Locations"].append(entry)

    output["Sources"] = []
    platforms = [] if alert_saas_format.get(AlertAttributes.Alert_Filer_Platform_Name) is None else alert_saas_format.get(
        AlertAttributes.Alert_Filer_Platform_Name).split(',')
    file_server_or_Domain = [] if alert_saas_format.get(
        AlertAttributes.Alert_Filer_Name) is None else alert_saas_format.get(AlertAttributes.Alert_Filer_Name).split(',')
    for i in range(len(platforms)):
        entry = {
            "Platform": "" if len(platforms) <= i else platforms[i],
            "FileServerOrDomain": "" if len(file_server_or_Domain) <= i else file_server_or_Domain[i]
        }
        output["Sources"].append(entry)

    output["Devices"] = []
    device_names = [] if alert_saas_format.get(AlertAttributes.Alert_Device_HostName) is None else alert_saas_format.get(
        AlertAttributes.Alert_Device_HostName).split(',')
    assets = [] if alert_saas_format.get(AlertAttributes.Alert_Asset_Path) is None else alert_saas_format.get(
        AlertAttributes.Alert_Asset_Path).split(',')
    for i in range(len(device_names)):
        entry = {
            "Name": "" if len(device_names) <= i else device_names[i],
            "Asset": "" if len(assets) <= i else assets[i]
        }
        output["Devices"].append(entry)

    output["Users"] = []
    user_names = [] if alert_saas_format.get(
        AlertAttributes.Alert_User_Name) is None else alert_saas_format[AlertAttributes.Alert_User_Name].split(',')
    sam_account_names = [] if alert_saas_format.get(
        AlertAttributes.Alert_User_SamAccountName) is None else alert_saas_format[AlertAttributes.Alert_User_SamAccountName] \
        .split(',')
    privileged_account_types = [] if alert_saas_format.get(
        AlertAttributes.Alert_User_AccountType_Name) is None else alert_saas_format[AlertAttributes.Alert_User_AccountType_Name] \
        .split(',')
    departments = [] if alert_saas_format.get("Department") is None else alert_saas_format["Department"].split(',')
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


def check_module_command(client: Client) -> CommandResults:
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
    return CommandResults(readable_output=message)


def varonis_get_threat_models_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get threat models from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['name'] = None  # List of requested threat model names

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """

    name = argToList(args.get('name'), separator='|')

    threat_models = client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
    mapper = ThreatModelObjectMapper()
    mapped_items = mapper.map(threat_models)

    def filter_threat_model_items(items, criteria):
        filtered_items = []
        # criteria is a dict of key: value or key: list of values
        keys = criteria.keys()

        for item in items:
            isMatch = True
            for key in keys:
                criteria_match = False
                if criteria[key] and len(criteria[key]) > 0:
                    for value in criteria[key]:
                        if isinstance(value, str) and fnmatch.filter([str(item[key])], value):
                            criteria_match = True
                            break
                    if not criteria_match:
                        isMatch = False
                        break
            if isMatch:
                filtered_items.append(item)

        return filtered_items

    filtered_items = filter_threat_model_items(mapped_items, {
        'Name': name
    })

    outputs = {}
    outputs['ThreatModel'] = filtered_items

    readable_output = tableToMarkdown('Varonis Threat Models', filtered_items, headers=['ID', 'Name'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='ID',
        outputs=outputs
    )


def fetch_incidents_command(client: Client, last_run: dict[str, datetime], first_fetch_time: Optional[datetime],
                            alert_status: Optional[str], threat_model: Optional[str], severity: Optional[str],
                            max_fetch: Optional[int] = 1000
                            ) -> tuple[dict[str, Optional[datetime]], list[dict]]:
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
    :param alert_status: status of the alert to search for.
        Options are 'New', 'Under investigation', 'Action Required', 'Auto-Resolved' or 'Closed'

    :type threat_model: ``Optional[str]``
    :param threat_model: Comma-separated list of threat model names of alerts to fetch

    :type severity: ``Optional[str]``
    :param severity: severity of the alert to search for. Options are 'High', 'Medium' or 'Low'

    :type max_fetch: ``Optional[int]``
    :param max_fetch: Maximum number of incidents per fetch

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, Optional[int]]``): Contains last fetched id.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``

    """

    threat_model_names = argToList(threat_model, separator='|')
    params = demisto.params()

    incidents: list[dict[str, Any]] = []

    if first_fetch_time is None:
        raise ValueError("first_fetch_time can't be None")

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

    alerts = client.varonis_get_alerts(threat_model_names=threat_model_names, alertIds=None, start_time=None, end_time=None,
                                       device_names=None, user_names=None, last_days=None,
                                       ingest_time_from=last_fetched_ingest_time,
                                       ingest_time_to=ingest_time_to,
                                       alert_statuses=statuses, alert_severities=severities,
                                       extra_fields=None,
                                       descending_order=False,
                                       max_fetch=max_fetch)

    demisto.debug(f'varonis_get_alerts returned: {len(alerts)} alerts')

    for alert in alerts:
        ingestTime_str = alert[AlertAttributes.Alert_IngestTime]
        ingestTime = try_convert(
            alert[AlertAttributes.Alert_IngestTime],
            lambda x: datetime.fromisoformat(x),
            ValueError(f'IngestTime should be in iso format, but it is {ingestTime_str}.')
        )

        if not last_fetched_ingest_time or ingestTime > last_fetched_ingest_time:
            last_fetched_ingest_time = ingestTime + timedelta(seconds=1)
        guid = alert[AlertAttributes.Alert_ID]
        name = alert[AlertAttributes.Alert_Rule_Name]
        alert_time = alert[AlertAttributes.Alert_TimeUTC]
        enrich_with_url(alert, client._base_url, guid)

        alert_converted = convert_incident_alert_to_onprem_format(alert)
        alert_converted.update({
            'mirror_direction': MIRROR_DIRECTION_MAPPING.get(params.get('mirror_direction')),
            'mirror_instance': demisto.integrationInstance()
        })

        incident = {
            'name': f'Varonis alert {name}',
            'occurred': f'{alert_time}Z',
            'rawJSON': json.dumps(alert_converted),
            'type': 'Varonis SaaS Incident',
            'severity': convert_to_demisto_severity(alert_converted[AlertAttributes.Alert_Rule_Severity_Name])
        }

        incidents.append(incident)
        demisto.debug(f'New incident: {json.dumps(alert, indent=4, sort_keys=True, default=str)}')

    next_run = {'last_fetched_ingest_time': last_fetched_ingest_time.isoformat()}

    return next_run, incidents


def varonis_get_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
        ``args['extra_fields']`` Extra fields
        ``args['descending_order']`` Indicates whether alerts should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    threat_model_names = args.get('threat_model_name')
    alert_ids = args.get('alert_ids')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    ingest_time_from = args.get('ingest_time_from')
    ingest_time_to = args.get('ingest_time_to')
    alert_statuses = args.get('alert_status')
    alert_severities = args.get('alert_severity')
    device_names = args.get('device_name')
    user_names = args.get('user_name')
    last_days = args.get('last_days')
    extra_fields = args.get('extra_fields')
    descending_order = argToBoolean(args.get('descending_order', 'True'))

    if last_days:
        last_days = try_convert(
            last_days,
            lambda x: int(x),
            ValueError(f'last_days should be integer, but it is {last_days}.')
        )

        if last_days <= 0:
            raise ValueError('last_days cannot be less then 1')

    alert_severities = try_convert(alert_severities, lambda x: argToList(x, separator='|'))
    device_names = try_convert(device_names, lambda x: argToList(x, separator='|'))
    threat_model_names = try_convert(threat_model_names, lambda x: argToList(x, separator='|'))
    user_names = try_convert(user_names, lambda x: argToList(x, separator='|'))
    extra_fields = try_convert(extra_fields, lambda x: argToList(x, separator='|'))

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

    alert_statuses = try_convert(alert_statuses, lambda x: argToList(x, separator='|'))

    if alert_severities:
        for severity in alert_severities:
            if severity.lower() not in ALERT_SEVERITIES.keys():
                raise ValueError(f'There is no severity {severity}.')

    if alert_statuses:
        for status in alert_statuses:
            if status.lower() not in ALERT_STATUSES.keys():
                raise ValueError(f'There is no status {status}.')

    alerts = client.varonis_get_alerts(threat_model_names, alert_ids, start_time, end_time, ingest_time_from, ingest_time_to,
                                       device_names,
                                       user_names,
                                       last_days, alert_statuses, alert_severities,
                                       extra_fields,
                                       descending_order)
    outputs = {}
    outputs['Alert'] = alerts

    alert_attributes = AlertAttributes()
    if outputs:
        for alert in alerts:
            enrich_with_url(alert, client._base_url, alert[alert_attributes.Alert_ID])

    readable_output = tableToMarkdown('Varonis Alerts', alerts, headers=alert_attributes.get_fields(extra_fields))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Alert.ID',
        outputs=outputs
    )


def varonis_get_alerted_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
        ``args['extra_fields']`` Extra fields
        ``args['descending_order']`` Indicates whether events should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    last_days = args.get('last_days')
    descending_order = argToBoolean(args.get('descending_order', 'True'))

    alertIds = try_convert(args.get('alert_id'), lambda x: argToList(x, separator='|'))
    start_time = try_convert(
        start_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'start_time should be in iso format, but it is {start_time}.')
    )
    end_time = try_convert(
        end_time,
        lambda x: datetime.fromisoformat(x),
        ValueError(f'end_time should be in iso format, but it is {end_time}.')
    )
    extra_fields = try_convert(args.get('extra_fields'), lambda x: argToList(x, separator='|'))

    events = client.varonis_get_alerted_events(alertIds=alertIds, start_time=start_time, end_time=end_time,
                                               last_days=last_days,
                                               extra_fields=extra_fields,
                                               descending_order=descending_order)
    outputs = {}
    outputs['Event'] = events

    event_attributes = EventAttributes()
    readable_output = tableToMarkdown('Varonis Alerted Events', events, headers=event_attributes.get_fields(extra_fields))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Event.ID',
        outputs=outputs
    )


def varonis_alert_add_note_command(client: Client, args: dict[str, Any]) -> bool:
    """Update Varonis alert status command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` Array of alert ids to be updated
        ``args['note']`` Note for alert

    :return: Result of execution
    :rtype: ``bool``

    """
    note = str(args.get('note'))

    return varonis_update_alert(client, close_reason_id=None, status_id=None,
                                alert_ids=argToList(args.get('alert_id'), separator='|'),
                                note=note)


def varonis_update_alert_status_command(client: Client, args: dict[str, Any]) -> bool:
    """Update Varonis alert status command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` Alert's new status
        ``args['alert_id']`` Array of alert ids to be updated
        ``args['note']`` Note for alert

    :return: Result of execution
    :rtype: ``bool``

    """
    status_id = None
    status = args.get('status')
    statuses = list(filter(lambda name: name != 'closed', ALERT_STATUSES.keys()))
    if status:
        if status.lower() not in statuses:
            raise ValueError(f'status must be one of {statuses}.')
        else:
            status_id = ALERT_STATUSES[status.lower()]

    note = args.get('note')

    return varonis_update_alert(client, close_reason_id=None, status_id=status_id,
                                alert_ids=argToList(args.get('alert_id'), separator='|'),
                                note=note)


def varonis_close_alert_command(client: Client, args: dict[str, Any]) -> bool:
    """Close Varonis alert command

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['close_reason']`` Alert's close reason
        ``args['alert_id']`` Array of alert ids to be closed
        ``args['note']`` Note for alert

    :return: Result of execution
    :rtype: ``bool``

    """
    close_reason = str(args.get('close_reason')).lower()
    close_reason_id = CLOSE_REASONS.get(close_reason)
    if not close_reason_id:
        raise ValueError(f'Close reason must be one of {list(CLOSE_REASONS.keys())}')

    note = args.get('note')
    return varonis_update_alert(client, close_reason_id, ALERT_STATUSES['closed'],
                                argToList(args.get('alert_id'), separator='|'), note)


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    alert_id = parsed_args.remote_incident_id

    if not parsed_args.incident_changed or not alert_id:
        return alert_id

    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {list(parsed_args.delta)}.')

    demisto.debug(f'Sending incident with remote ID [{alert_id}] to remote system. Status {parsed_args.inc_status}.')
    demisto.debug(f'Got the following data {parsed_args.data}.')

    if (
        ('Status' in parsed_args.delta or 'CloseReason' in parsed_args.delta)
        and (parsed_args.data.get('Status', '').lower() == 'closed' or parsed_args.inc_status == IncidentStatus.DONE)
    ):
        demisto.debug(f'Closing remote incident {alert_id}')
        note = parsed_args.data.get('CloseNotes', 'Closed from XSOAR')
        close_reason = parsed_args.data.get('CloseReason', '').lower()
        close_reason_id = CLOSE_REASONS.get(close_reason, CLOSE_REASONS['other'])
        if not close_reason_id:
            close_reason_id = CLOSE_REASONS['other']
        varonis_update_alert(
            client,
            close_reason_id,
            ALERT_STATUSES['closed'],
            argToList(alert_id),
            note
        )

    elif (
        'Status' in parsed_args.delta
        and parsed_args.data.get('Status').lower() != 'closed'
        or parsed_args.inc_status == IncidentStatus.ACTIVE
    ):
        demisto.debug(f'Update remote incident {alert_id}')
        note = 'Status changed from XSOAR'
        status = parsed_args.data.get('Status', 'action required').lower()
        status_id = ALERT_STATUSES.get(status)

        close_reason_id = CLOSE_REASONS['none']
        varonis_update_alert(
            client,
            close_reason_id,
            status_id,
            argToList(alert_id),
            note
        )

    return alert_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Returns the list of fields for an incident type.
    Args:
        client: XSOAR client to use

    Returns: Dictionary with keys as field names

    """
    demisto.debug('Start getting SchemeTypeMapping.')
    incident_type_scheme = SchemeTypeMapping(type_name='Varonis SaaS Incident')

    # If the type is sn_si_incident then add it specific fields else use the snow args as is.
    out_fields = INCIDENT_FIELDS
    for field in out_fields:
        incident_type_scheme.add_field(field)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


'''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params['url']
    apiKey = params.get('apiKey', {}).get('password')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = params.get('insecure', False)

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

        if command == 'varonis-get-threat-models':
            result = varonis_get_threat_models_command(client, args)
            return_results(result)

        elif command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = check_module_command(client)
            return_results('ok')

        elif command == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, args))

        elif command == 'varonis-get-alerted-events':
            return_results(varonis_get_alerted_events_command(client, args))

        elif command == 'varonis-alert-add-note':
            return_results(varonis_alert_add_note_command(client, args))

        elif command == 'varonis-update-alert-status':
            return_results(varonis_update_alert_status_command(client, args))

        elif command == 'varonis-close-alert':
            return_results(varonis_close_alert_command(client, args))

        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args))

        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif command == 'fetch-incidents':
            alert_status = params.get('status')
            threat_model = params.get('threat_model')
            severity = params.get('severity')
            max_fetch = arg_to_number(params.get('max_fetch'))
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
                                                          severity=severity,
                                                          max_fetch=max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
