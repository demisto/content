import demistomock as demisto
from AlertAttributes import AlertAttributes
from CommonServerPython import Any, BaseClient, Dict, List, Optional, datetime, demisto, timedelta
from EventAttributes import EventAttributes
from FilterCondition import FilterCondition
from Filters import Filters
from Query import Query
from RequestParams import RequestParams
from Rows import Rows
from SearchAlertObjectMapper import SearchAlertObjectMapper
from SearchEventObjectMapper import SearchEventObjectMapper
from SearchRequest import SearchRequest

MAX_DAYS_BACK = 180
THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = {'new': 1, 'under investigation': 2, 'closed': 3, 'action required': 4, 'auto-resolved': 5}
ALERT_SEVERITIES = {'high': 0, 'medium': 1, 'low': 2}

from typing import Any, Dict, List


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

    def varonis_get_alerts(self, threat_model_names: Optional[List[str]],
                           alertIds: Optional[List[str]], start_time: Optional[datetime],
                           end_time: Optional[datetime], ingest_time_from: Optional[datetime],
                           ingest_time_to: Optional[datetime], device_names: Optional[List[str]],
                           user_names: Optional[List[str]],
                           last_days: Optional[int],
                           alert_statuses: Optional[List[str]],
                           alert_severities: Optional[List[str]],
                           extra_fields: Optional[List[str]],
                           descending_order: bool) -> List[Dict[str, Any]]:
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
                ), f"{alert_attributes.Alert_IngestTime}0": ingest_time_to.isoformat()})  # "displayValue": ingest_time_from.isoformat(),
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
                    .add_value({alert_attributes.Alert_TimeUTC : start_time.isoformat(
                    ), f"{alert_attributes.Alert_TimeUTC}0": end_time.isoformat()})  # "displayValue": start_time.isoformat(),
            if last_days:
                time_condition\
                    .set_operator("LastDays")\
                    .add_value({alert_attributes.Alert_TimeUTC: last_days, "displayValue": last_days})
            search_request.query.filter.add_filter(time_condition)

        if threat_model_names and len(threat_model_names) > 0:
            rule_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Rule_Name)\
                .set_operator("In")
            for threat_model_name in threat_model_names:
                rule_condition.add_value({alert_attributes.Alert_Rule_Name: threat_model_name, "displayValue": "New"})
            search_request.query.filter.add_filter(rule_condition)

        if alertIds and len(alertIds) > 0:
            alert_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_ID)\
                .set_operator("In")
            for alertId in alertIds:
                alert_condition.add_value({alert_attributes.Alert_ID: alertId, "displayValue": "New"})
            search_request.query.filter.add_filter(alert_condition)

        if device_names and len(device_names) > 0:
            device_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Device_HostName)\
                .set_operator("In")
            for device_name in device_names:
                device_condition.add_value({alert_attributes.Alert_Device_HostName: device_name, "displayValue": device_name})
            search_request.query.filter.add_filter(device_condition)

        if user_names and len(user_names) > 0:
            user_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_User_Identity_Name)\
                .set_operator("In")
            for user_name in user_names:
                user_condition.add_value({alert_attributes.Alert_User_Identity_Name: user_name, "displayValue": user_name})
            search_request.query.filter.add_filter(user_condition)

        if alert_statuses and len(alert_statuses) > 0:
            status_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Status_ID)\
                .set_operator("In")
            for status in alert_statuses:
                status_id = ALERT_STATUSES[status.lower()]
                status_condition.add_value({alert_attributes.Alert_Status_ID: status_id, "displayValue": status})
            search_request.query.filter.add_filter(status_condition)

        if alert_severities and len(alert_severities) > 0:
            severity_condition = FilterCondition()\
                .set_path(alert_attributes.Alert_Rule_Severity_ID)\
                .set_operator("In")
            for severity in alert_severities:
                severity_id = ALERT_SEVERITIES[severity.lower()]
                severity_condition.add_value({alert_attributes.Alert_Rule_Severity_ID: severity_id, "displayValue": severity})
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
            status_list_to_retry=[304, 405, 206],
            retries=10
        )

        mapper = SearchAlertObjectMapper()
        alerts = mapper.map(json_data)
        return alerts

    def varonis_get_alerted_events(self, alertIds: List[str], start_time: Optional[datetime], end_time: Optional[datetime],
                                   last_days: Optional[int], extra_fields: Optional[List[str]],
                                   descending_order: bool) -> List[Dict[str, Any]]:
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

        :type extra_fields: ``Optional[List[str]]``
        :param extra_fields: List of extra fields to include in the response

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
            search_request.rows.add_ordering({"path": event_attributes.Event_Time, "sortOrder": "Desc"})

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
            status_list_to_retry=[304, 405, 206],
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

    def varonis_add_note_to_alerts(self, query: Dict[str, Any]) -> bool:
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