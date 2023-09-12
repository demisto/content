import hashlib

import dateparser

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from enum import Enum


# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC
DEFAULT_MAX_LIMIT = 1000
DEFAULT_URL = 'https://api.xdr.trendmicro.com'
PRODUCT = 'vision_one'
VENDOR = 'trend_micro'
ONE_YEAR = 365


class LastRunLogsStartTimeFields(Enum):
    OBSERVED_ATTACK_TECHNIQUES = 'oat_detection_start_time'
    WORKBENCH = 'workbench_start_time'
    SEARCH_DETECTIONS = 'search_detection_start_time'
    AUDIT = 'audit_start_time'


class LastRunLogsNextLink(Enum):
    OBSERVED_ATTACK_TECHNIQUES = 'oat_detection_next_link'
    SEARCH_DETECTIONS = 'search_detection_next_link'


class LastRunTimeCacheTimeFieldNames(Enum):
    OBSERVED_ATTACK_TECHNIQUES_DEDUP = 'dedup_found_oat_logs'
    OBSERVED_ATTACK_TECHNIQUES_PAGINATION = 'pagination_found_oat_logs'
    WORKBENCH = 'found_workbench_logs'
    SEARCH_DETECTIONS_DEDUP = 'dedup_found_search_detection_logs'
    SEARCH_DETECTIONS_PAGINATION = 'pagination_found_search_detection_logs'
    AUDIT = 'found_audit_logs'


class LogTypes(Enum):
    OBSERVED_ATTACK_TECHNIQUES = 'observed_attack_technique'
    WORKBENCH = 'workbench'
    SEARCH_DETECTIONS = 'search_detection'
    AUDIT = 'audit'


class UrlSuffixes(Enum):
    OBSERVED_ATTACK_TECHNIQUES = '/oat/detections'
    WORKBENCH = '/workbench/alerts'
    SEARCH_DETECTIONS = '/search/detections'
    AUDIT = '/audit/logs'


class CreatedTimeFields(Enum):
    OBSERVED_ATTACK_TECHNIQUES = 'detectedDateTime'
    WORKBENCH = 'createdDateTime'
    SEARCH_DETECTIONS = 'eventTime'
    AUDIT = 'loggedDateTime'


URL_SUFFIX_TO_EVENT_TYPE_AND_CREATED_TIME_FIELD = {
    UrlSuffixes.AUDIT.value: (
        LogTypes.AUDIT.value,
        CreatedTimeFields.AUDIT.value
    ),
    UrlSuffixes.WORKBENCH.value: (
        LogTypes.WORKBENCH.value,
        CreatedTimeFields.WORKBENCH.value
    ),
    UrlSuffixes.SEARCH_DETECTIONS.value: (
        LogTypes.SEARCH_DETECTIONS.value,
        CreatedTimeFields.SEARCH_DETECTIONS.value
    ),
    UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value: (
        LogTypes.OBSERVED_ATTACK_TECHNIQUES.value,
        CreatedTimeFields.OBSERVED_ATTACK_TECHNIQUES.value
    )
}


''' CLIENT CLASS '''


class Client(BaseClient):

    API_VERSION = 'v3.0'

    def __init__(self, base_url: str, api_key: str, proxy: bool, verify: bool):
        self.base_url = base_url
        self.api_key = api_key

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def http_request(
        self,
        url_suffix: str | None = None,
        method: str = 'GET',
        params: dict | None = None,
        headers: dict | None = None,
        next_link: str | None = None
    ) -> Any:
        """
        Implements a generic http request to Trend Micro Vision One api.

        Args:
            url_suffix (str): The URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            next_link (str): the next link for the api request (used mainly for pagination)
        """
        request_headers = headers or {
            "Authorization": f"Bearer {self.api_key}"
        }

        url = next_link or f"{self.base_url}/{self.API_VERSION}{url_suffix}"
        demisto.info(f'Sending the http request to {url=} with {params=}')

        return self._http_request(
            method=method,
            full_url=url,
            params=params,
            headers=request_headers,
        )

    def get_logs(
        self,
        url_suffix: str,
        method: str = 'GET',
        params: dict | None = None,
        headers: dict | None = None,
        limit: int = DEFAULT_MAX_LIMIT,
        next_link: str | None = None
    ) -> tuple[List[dict], str | None]:
        """
        Implements a generic method with pagination to retrieve logs from trend micro vision one.

        Args:
            url_suffix (str): the URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            limit (str): the maximum number of events to retrieve.
            next_link (str): the next link to continue pagination

        Returns:
            List[Dict]: a list of the requested logs.
        """
        logs: List[dict] = []

        if next_link:
            response = self.http_request(method=method, headers=headers, next_link=next_link)
        else:
            response = self.http_request(url_suffix=url_suffix, method=method, params=params, headers=headers)

        current_items = response.get('items') or []
        demisto.info(f'Received {current_items=} with {url_suffix=} and {params=}')
        logs.extend(current_items)

        while (new_next_link := response.get('nextLink')) and len(logs) < limit:
            response = self.http_request(method=method, headers=headers, next_link=new_next_link)
            current_items = response.get('items') or []
            demisto.info(f'Received {current_items=} with {new_next_link=}')
            logs.extend(current_items)

        log_type, created_time_field = URL_SUFFIX_TO_EVENT_TYPE_AND_CREATED_TIME_FIELD[url_suffix]

        if log_type not in (LogTypes.OBSERVED_ATTACK_TECHNIQUES.value, LogTypes.SEARCH_DETECTIONS.value) or not new_next_link:
            # only limit cases where the logs are in ascending order in order not to lose part of events of nextLink
            # if there is no next link, limit the logs as there is no chance we would lose events
            logs = logs[:limit]

        if url_suffix == UrlSuffixes.SEARCH_DETECTIONS.value:
            for log in logs:
                if log_time := log.get(created_time_field):
                    log[created_time_field] = timestamp_to_datestring(
                        timestamp=log_time, date_format=DATE_FORMAT, is_utc=True
                    )

        for log in logs:
            log['event_type'] = log_type
            if log_time := log.get(created_time_field):
                log['_time'] = log_time

        return logs, new_next_link

    def get_workbench_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        order_by: str = 'createdDateTime asc',
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[dict]:
        """
        Get the workbench logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Workbench

        Args:
            start_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start
                                  of the data retrieval time range.
            end_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end
                                of the data retrieval time range.
            order_by (str): Parameter to be used for sorting records. Records are returned in descending
                            order by default.
            limit (int): the maximum number of workbench events to retrieve.

        Returns:
            List[Dict]: The workbench events that were found.
        """
        # will retrieve all the events that are more or equal to start_datetime, does not support miliseconds
        params = {'startDateTime': start_datetime, 'orderBy': order_by}

        if end_datetime:
            params['endDateTime'] = end_datetime

        workbench_logs, _ = self.get_logs(
            url_suffix=UrlSuffixes.WORKBENCH.value,
            params=params,
            limit=limit
        )

        return workbench_logs

    def get_observed_attack_techniques_logs(
        self,
        detected_start_datetime: str = '',
        detected_end_datetime: str = '',
        top: int = 1000,
        limit: int = DEFAULT_MAX_LIMIT,
        next_link: str | None = None
    ) -> tuple[List[dict], str | None]:
        """
        Get the observed attack techniques logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Observed-Attack-Techniques/paths/~1v3.0~1oat~1detections/get

        Note: The data retrieval time range cannot be greater than 365 days.

        Args:
            detected_start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the event detection
                                           data retrieval time range. If no value is specified, detectedStartDateTime
                                           defaults to 1 hour before the time the request is made.
            detected_end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the event
                                         detection data retrieval time range. If no value is specified,
                                         detectedEndDateTime defaults to the time the request is made.
            top (int): Number of records displayed on a single page.
            limit (int): the maximum number of observed attack techniques logs to retrieve.
            next_link (str): the next link for the api request (used mainly for pagination).

        Returns:
            List[Dict]: The observe attack techniques that were found.
        """
        # will retrieve all the events that are more or equal to detected_start_datetime, does not support miliseconds
        # returns in descending order by default and cannot be changed
        # will retrieve all the events that are less than detected_end_datetime and not less equal
        # The data retrieval time range cannot be greater than 365 days.
        return self.get_logs(
            url_suffix=UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value,
            params={
                'detectedStartDateTime': detected_start_datetime,
                'detectedEndDateTime': detected_end_datetime,
                'top': top
            },
            limit=limit,
            next_link=next_link
        )

    def get_search_detection_logs(
        self,
        start_datetime: str = '',
        end_datetime: str | None = None,
        top: int = DEFAULT_MAX_LIMIT,
        limit: int = DEFAULT_MAX_LIMIT,
        next_link: str | None = None
    ) -> tuple[List[dict], str | None]:
        """
        Get the search detection logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1search~1detections/get

        Args:
            start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the data retrieval range.
            end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the data retrieval time range.
                                If no value is specified, 'endDateTime' defaults to the time the request is made.
            top (int): Number of records displayed on a page.
            limit (int): the maximum number of search detection logs to retrieve.
            next_link (str): the next link for the api request (used mainly for pagination).

        Returns:
            List[Dict]: The search detection logs that were found.
        """
        # will retrieve all the events that are more or equal to detected_start_datetime, does not support miliseconds
        # will retrieve all the events that are less or equal to end_datetime
        params = {'startDateTime': start_datetime, 'top': top}

        if end_datetime:
            params['endDateTime'] = end_datetime

        return self.get_logs(
            url_suffix=UrlSuffixes.SEARCH_DETECTIONS.value,
            params=params,
            limit=limit,
            headers={'TMV1-Query': '*', "Authorization": f"Bearer {self.api_key}"},
            next_link=next_link
        )

    def get_audit_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        order_by: str = 'loggedDateTime asc',
        top: int = 200,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[dict]:
        """
        Get the audit logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Audit-Logs

        Note:
            start_datetime: You can retrieve data for response tasks that were created no later than 180 days ago.

        Args:
            start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the data retrieval range.
                                  You can retrieve data for response tasks that were created no later than 180 days ago.
            end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the data retrieval time range.
                                If no value is specified, 'endDateTime' defaults to the time the request is made.
            order_by (str): Parameter that allows you to sort the retrieved search results in ascending or
                            descending order. If no order is specified, the results are shown in ascending order.
            top (int): Number of records displayed on a page.
            limit (int): the maximum number of audit logs to retrieve.

        Returns:
            List[Dict]: The audit logs that were found.
        """
        # will retrieve all the events that are only more or equal than detected_start_datetime, does not support miliseconds
        # start_datetime can be maximum 180 days ago
        params = {'startDateTime': start_datetime, 'top': top, 'orderBy': order_by}

        if end_datetime:
            params['endDateTime'] = end_datetime

        audit_logs, _ = self.get_logs(
            url_suffix=UrlSuffixes.AUDIT.value,
            params=params,
            limit=limit,
        )

        return audit_logs


''' HELPER FUNCTIONS '''


def get_datetime_range(
    last_run_time: str | None,
    first_fetch: str,
    log_type_time_field_name: str,
    date_format: str = DATE_FORMAT,
) -> tuple[str, str]:
    """
    Get a datetime range for any log type.

    Args:
        last_run_time (str): The time that is saved in the log for a specific log.
        first_fetch (str): First fetch time.
        log_type_time_field_name (str): the name of the field in the last run for a specific log type.
        date_format (str): The date format.

    Returns:
        Tuple[str, str]: start time and end time
    """
    now = get_current_time()

    if last_run_time:
        last_run_time_datetime = dateparser.parse(  # type: ignore[assignment]
            last_run_time, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True}
        )
    else:
        last_run_time_datetime = dateparser.parse(  # type: ignore[no-redef]
            first_fetch, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True}
        )

    last_run_time_before_parse = last_run_time_datetime.strftime(date_format)  # type: ignore[union-attr]
    demisto.info(f'{last_run_time_before_parse=}')

    if log_type_time_field_name == LastRunLogsStartTimeFields.AUDIT.value and now - last_run_time_datetime > timedelta(
        days=180
    ):
        # cannot retrieve audit logs that are older than 180 days.
        last_run_time_datetime = dateparser.parse(  # type: ignore[assignment]
            '180 days ago',
            settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True}
        )

    if log_type_time_field_name == LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value:

        # Note: The data retrieval time range cannot be greater than 365 days for oat logs,
        # it cannot exceed datetime.now, otherwise the api will return 400
        one_year_from_last_run_time = last_run_time_datetime + timedelta(  # type: ignore[operator]
            days=ONE_YEAR  # type: ignore[operator]
        )
        end_time_datetime = now if one_year_from_last_run_time > now else one_year_from_last_run_time
    else:
        end_time_datetime = now

    start_time, end_time = (
        last_run_time_datetime.strftime(date_format), end_time_datetime.strftime(date_format)  # type: ignore[union-attr]
    )
    demisto.info(f'{start_time=} and {end_time=} for {log_type_time_field_name=}')
    return start_time, end_time


def get_latest_log_created_time(
    logs: List[dict],
    log_type: str,
    created_time_field: str = '_time',
    date_format: str = DATE_FORMAT,
) -> str:
    """
    Get the time of the latest or earliest occurred log from a list of logs.

    Args:
        logs (list[dict]): A list of logs.
        created_time_field (str): The created time field for the logs.
        log_type (str): The log type for debugging purposes.
        date_format (str): The date format.

    Returns:
        str: The time of the latest occurred log, empty string if there aren't any logs.
    """
    if logs:
        latest_log_time = max(logs, key=lambda log: datetime.strptime(log[created_time_field], date_format))[created_time_field]
        demisto.info(f'{latest_log_time=} for {log_type=}')
        return latest_log_time

    demisto.info(f'No logs found for {log_type=}')
    return ''


def get_all_latest_logs_ids(
    logs: List[dict],
    log_type: str,
    log_id_field_name: str,
    log_created_time_field_name: str = '_time',
    date_format: str = DATE_FORMAT,
    latest_log_time: str = None
) -> tuple[List[str], str]:
    """
    Get all the logs that their time is equal to the last or earliest log that occurred.

    Args:
        logs (list): a list of logs.
        log_type (str): the log type
        log_id_field_name (str): the id field name of the log type
        log_created_time_field_name (str): the created time field of the log
        date_format (str): the date format of the logs
        latest_log_time (str): the latest log time from the logs list

    Returns: all the logs their created time is equal to the latest created time log & latest log time

    """
    latest_occurred_time_log = latest_log_time or get_latest_log_created_time(
        logs=logs,
        log_type=log_type,
        created_time_field=log_created_time_field_name,
        date_format=date_format
    )

    # if there aren't any new logs, no need to cache anything
    if not latest_occurred_time_log:
        return [], latest_occurred_time_log

    latest_occurred_time_log_ids: Set[str] = set()

    for log in logs:
        if log.get(log_created_time_field_name) == latest_occurred_time_log and (log_id := log.get(log_id_field_name)):
            demisto.info(f'adding log with ID {log_id} to latest occurred time logs')
            latest_occurred_time_log_ids.add(log_id)

    demisto.info(f'{latest_occurred_time_log_ids=} for {log_type=}')
    return list(latest_occurred_time_log_ids), latest_occurred_time_log


def dedup_fetched_logs(
    logs: List[dict],
    last_run: dict,
    log_id_field_name: str,
    log_cache_last_run_name_field_name: str,
    log_type: str
) -> List[dict]:
    """
    Retrieve a list of all the logs that were not fetched yet.

    Args:
        logs (list): a list of logs.
        last_run (dict): the last run object.
        log_id_field_name (str): the id field name of the log type
        log_cache_last_run_name_field_name (str): the name of the field that saves IDs of the logs in the last run
        log_type (str): the log type

    Returns: all the logs that were not fetched yet (which are not in the cache of the last run)
    """
    last_run_found_logs = set(last_run.get(log_cache_last_run_name_field_name) or [])

    un_fetched_logs = []

    for log in logs:
        log_id = log.get(log_id_field_name)
        if log_id not in last_run_found_logs:
            demisto.info(f'log with ID {log_id} for {log_type=} has not been fetched.')
            un_fetched_logs.append(log)
        else:
            demisto.info(f'log with ID {log_id} for {log_type=} has been fetched')

    demisto.info(f'{un_fetched_logs=}')
    return un_fetched_logs


def get_dedup_logs(
    logs: List[Dict],
    last_run: Dict,
    log_cache_last_run_name_field_name: str,
    log_type: str,
    date_format: str = DATE_FORMAT,
    latest_log_time: str = None
) -> tuple[List[Dict], List[str], str]:
    """
    dedup the logs and returns the IDs of all the latest logs.

    Args:
        logs (list): a list of logs.
        last_run (dict): the last run object.
        log_cache_last_run_name_field_name (str): the name of the field that saves IDs of the logs in the last run
        log_type (str): the log type
        date_format (str): the date format
        latest_log_time (str): latest log time for dedup

    Returns:
        tuple: dudped logs, new log ids for next dedup, latest time of the logs
    """
    logs = dedup_fetched_logs(
        logs=logs,
        last_run=last_run,
        log_id_field_name='uuid',
        log_cache_last_run_name_field_name=log_cache_last_run_name_field_name,
        log_type=log_type
    )

    dedup_log_ids, latest_log_time = get_all_latest_logs_ids(
        logs=logs,
        log_type=log_type,
        log_id_field_name='uuid',
        date_format=date_format,
        latest_log_time=latest_log_time
    )

    return logs, dedup_log_ids, latest_log_time


def get_workbench_logs(
    client: Client,
    first_fetch: str,
    last_run: dict,
    limit: int = DEFAULT_MAX_LIMIT,
    date_format: str = DATE_FORMAT,
) -> tuple[List[dict], dict]:
    """
    Get the workbench logs.

    Args:
        client (Client): the client object.
        first_fetch (str): the first fetch time.
        last_run (dict): the last run object
        limit (int): the maximum number of workbench logs to return.
        date_format (str): the date format.

    Returns:
        Tuple[List[Dict], Dict]: workbench logs & updated last run
    """
    def parse_workbench_logs(_workbench_logs):
        for _log in _workbench_logs:
            for _entity in (_log.get('impactScope') or {}).get('entities') or []:
                if (related_entities := _entity.get('relatedEntities')) and isinstance(related_entities, list):
                    _entity['relatedEntities'] = ','.join(related_entities)
                if (provenance := _entity.get('provenance')) and isinstance(provenance, list):
                    _entity['provenance'] = ','.join(provenance)
                if (entity_value := _entity.get('entityValue')) and isinstance(entity_value, dict):
                    if (_ips := entity_value.get('ips')) and isinstance(_ips, list):
                        entity_value['ips'] = ','.join(_ips)

    workbench_cache_time_field_name = LastRunTimeCacheTimeFieldNames.WORKBENCH.value
    workbench_log_type = LogTypes.WORKBENCH.value
    workbench_log_last_run_time = LastRunLogsStartTimeFields.WORKBENCH.value

    start_time, _ = get_datetime_range(
        last_run_time=last_run.get(workbench_log_last_run_time),
        first_fetch=first_fetch,
        log_type_time_field_name=workbench_log_last_run_time,
        date_format=date_format,
    )

    workbench_logs = client.get_workbench_logs(
        start_datetime=start_time,
        limit=limit + len(last_run.get(workbench_cache_time_field_name, []))
    )

    workbench_logs = dedup_fetched_logs(
        logs=workbench_logs,
        last_run=last_run,
        log_id_field_name='id',
        log_cache_last_run_name_field_name=workbench_cache_time_field_name,
        log_type=workbench_log_type
    )

    latest_occurred_workbench_log_ids, latest_log_time = get_all_latest_logs_ids(
        logs=workbench_logs,
        log_type=workbench_log_type,
        log_id_field_name='id',
        date_format=DATE_FORMAT
    )
    parse_workbench_logs(workbench_logs)

    latest_workbench_log_time = latest_log_time or (
        dateparser.parse(start_time) + timedelta(seconds=1)  # type: ignore
    ).strftime(DATE_FORMAT)  # type: ignore

    workbench_updated_last_run = {
        workbench_log_last_run_time: latest_workbench_log_time,
        workbench_cache_time_field_name: latest_occurred_workbench_log_ids
    }

    fetched_workbench_log_ids = [(_log.get('id'), _log.get('_time')) for _log in workbench_logs if _log.get('id')]

    demisto.info(f'{fetched_workbench_log_ids=}')
    demisto.info(f'{workbench_updated_last_run=}')
    return workbench_logs, workbench_updated_last_run


def get_observed_attack_techniques_logs(
    client: Client,
    first_fetch: str,
    last_run: dict,
    limit: int = DEFAULT_MAX_LIMIT,
    date_format: str = DATE_FORMAT,
) -> tuple[List[dict], dict]:
    """
    Get the observed attack techniques logs.

    Args:
        client (Client): the client object
        first_fetch (str): the first fetch time
        last_run (dict): last run time object
        limit (int): the maximum number of observed attack techniques logs to return.
        date_format (str): the date format.

    Returns:
        Tuple[List[Dict], Dict]: observed attack techniques logs & updated last run.
    """
    def parse_observed_attack_techniques_logs(_observed_attack_techniques_logs):
        for log in _observed_attack_techniques_logs:
            if filters := log.get('filters') or []:
                for _filter in filters:
                    if (mitre_tactic_ids := _filter.get('mitreTacticIds')) and isinstance(mitre_tactic_ids, list):
                        _filter['mitreTacticIds'] = ','.join(mitre_tactic_ids)
                    if (
                        mitre_technique_ids := _filter.get('mitreTechniqueIds')
                    ) and isinstance(mitre_technique_ids, list):
                        _filter['mitreTechniqueIds'] = ','.join(mitre_technique_ids)

    observed_attack_technique_log_type = LogTypes.OBSERVED_ATTACK_TECHNIQUES.value
    observed_attack_technique_start_run_time = LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value
    observed_attack_technique_next_link = LastRunLogsNextLink.OBSERVED_ATTACK_TECHNIQUES.value
    observed_attack_technique_dedup = LastRunTimeCacheTimeFieldNames.OBSERVED_ATTACK_TECHNIQUES_DEDUP.value
    observed_attack_technique_pagination = LastRunTimeCacheTimeFieldNames.OBSERVED_ATTACK_TECHNIQUES_PAGINATION.value

    last_run_next_link = last_run.get(observed_attack_technique_next_link)
    last_run_start_time = last_run.get(observed_attack_technique_start_run_time)
    dedup_log_ids = last_run.get(observed_attack_technique_dedup) or []
    pagination_log_ids = last_run.get(observed_attack_technique_pagination) or []

    if last_run_next_link:
        observed_attack_techniques_logs, new_next_link = client.get_observed_attack_techniques_logs(
            next_link=last_run_next_link, limit=limit
        )

        observed_attack_techniques_logs, subsequent_pagination_log_ids, _ = get_dedup_logs(
            logs=observed_attack_techniques_logs,
            last_run=last_run,
            log_cache_last_run_name_field_name=observed_attack_technique_pagination,
            log_type=observed_attack_technique_log_type,
            date_format=date_format,
            latest_log_time=last_run_start_time
        )
        # save in cache logs for subsequent pagination(s) in case they have the latest log time
        # handle cases where the amount of logs that happened at the same time is larger than the page size
        if subsequent_pagination_log_ids:
            pagination_log_ids.extend(subsequent_pagination_log_ids)

    else:
        start_time, end_time = get_datetime_range(
            last_run_time=last_run_start_time,
            first_fetch=first_fetch,
            log_type_time_field_name=observed_attack_technique_start_run_time,
            date_format=date_format
        )

        observed_attack_techniques_logs, new_next_link = client.get_observed_attack_techniques_logs(
            detected_start_datetime=start_time,
            detected_end_datetime=end_time,
            limit=limit
        )

        observed_attack_techniques_logs, dedup_log_ids, latest_log_time = get_dedup_logs(
            logs=observed_attack_techniques_logs,
            last_run=last_run,
            log_cache_last_run_name_field_name=observed_attack_technique_dedup,
            log_type=observed_attack_technique_log_type,
            date_format=date_format
        )

        last_run_start_time = latest_log_time or (
            dateparser.parse(start_time) + timedelta(seconds=1)  # type: ignore
        ).strftime(DATE_FORMAT)  # type: ignore

    fetched_observed_attack_technique_logs_ids = [
        (_log.get('uuid'), _log.get('_time')) for _log in observed_attack_techniques_logs if _log.get('uuid')
    ]

    if new_next_link:
        # save in cache the latest log ids from the first page
        if not last_run_next_link:
            pagination_log_ids = dedup_log_ids
        # always update the next link
        last_run_next_link = new_next_link
    else:
        if last_run_next_link:
            # pagination is over
            dedup_log_ids = pagination_log_ids
            demisto.info(
                f'pagination is over, received in the last page '
                f'the following log ids: {fetched_observed_attack_technique_logs_ids}'
            )
        last_run_next_link = ''

    parse_observed_attack_techniques_logs(observed_attack_techniques_logs)

    observed_attack_techniques_updated_last_run = {
        observed_attack_technique_start_run_time: last_run_start_time,
        observed_attack_technique_dedup: dedup_log_ids,
        observed_attack_technique_pagination: pagination_log_ids,
        observed_attack_technique_next_link: last_run_next_link
    }

    demisto.info(f'{fetched_observed_attack_technique_logs_ids=}')
    demisto.info(f'{observed_attack_techniques_updated_last_run=}')
    return observed_attack_techniques_logs, observed_attack_techniques_updated_last_run


def get_search_detection_logs(
    client: Client,
    first_fetch: str,
    last_run: dict,
    limit: int = DEFAULT_MAX_LIMIT,
    date_format: str = DATE_FORMAT,
) -> tuple[List[dict], dict]:
    """
    Get the search detection logs.

    Args:
        client (Client): the client object
        first_fetch (str): the first fetch time
        last_run (dict): last run time object
        limit (int): the maximum number of search detection logs to return.
        date_format (str): the date format.

    Returns:
        Tuple[List[Dict], Dict]: search detection logs & updated last run time
    """
    def parse_search_detection_logs(_search_detection_logs):
        for _log in _search_detection_logs:
            # add the None to any field that does not exist because of a bug in xsiam.
            for field in [
                'actResult', 'app', 'blocking', 'cat', 'component', 'deviceProcessName', 'processName', 'deviceMacAddress',
                'endpointMacAddress', 'interestedMacAddress', 'dhost', 'domainName', 'endpointHostName', 'hostName',
                'endpointIp', 'fileName', 'filePath', 'fileSize', 'httpReferer', 'malType', 'mitreMapping', 'objectCmd',
                'processCmd', 'objectFileName', 'objectName', 'processSigner', 'request', 'requestClientApplication',
                'threatName', 'mDevice', 'src'
            ]:
                if field not in _log:
                    _log[field] = None

    search_detections_log_type = LogTypes.SEARCH_DETECTIONS.value
    search_detection_start_run_time = LastRunLogsStartTimeFields.SEARCH_DETECTIONS.value
    search_detection_next_link = LastRunLogsNextLink.SEARCH_DETECTIONS.value
    search_detection_dedup = LastRunTimeCacheTimeFieldNames.SEARCH_DETECTIONS_DEDUP.value
    search_detection_pagination = LastRunTimeCacheTimeFieldNames.SEARCH_DETECTIONS_PAGINATION.value

    last_run_next_link = last_run.get(search_detection_next_link)
    last_run_start_time = last_run.get(search_detection_start_run_time)
    dedup_log_ids = last_run.get(search_detection_dedup) or []
    pagination_log_ids = last_run.get(search_detection_pagination) or []

    if last_run_next_link:
        search_detection_logs, new_next_link = client.get_search_detection_logs(
            next_link=last_run_next_link, limit=limit
        )

        search_detection_logs, subsequent_pagination_log_ids, _ = get_dedup_logs(
            logs=search_detection_logs,
            last_run=last_run,
            log_cache_last_run_name_field_name=search_detection_pagination,
            log_type=search_detections_log_type,
            date_format=date_format,
            latest_log_time=last_run_start_time
        )
        # save in cache logs for subsequent pagination(s) in case they have the latest log time
        if subsequent_pagination_log_ids:
            pagination_log_ids.extend(subsequent_pagination_log_ids)
    else:
        start_time, _ = get_datetime_range(
            last_run_time=last_run_start_time,
            first_fetch=first_fetch,
            log_type_time_field_name=LastRunLogsStartTimeFields.SEARCH_DETECTIONS.value,
            date_format=date_format
        )
        search_detection_logs, new_next_link = client.get_search_detection_logs(
            start_datetime=start_time, top=limit, limit=limit
        )

        search_detection_logs, dedup_log_ids, latest_log_time = get_dedup_logs(
            logs=search_detection_logs,
            last_run=last_run,
            log_cache_last_run_name_field_name=search_detection_dedup,
            log_type=search_detections_log_type,
            date_format=date_format
        )

        last_run_start_time = latest_log_time or (
            dateparser.parse(start_time) + timedelta(seconds=1)  # type: ignore
        ).strftime(DATE_FORMAT)  # type: ignore

    fetched_search_detection_logs_ids = [
        (_log.get('uuid'), _log.get('_time')) for _log in search_detection_logs if _log.get('uuid')
    ]

    if new_next_link:
        # save in cache the latest log ids from first pagination
        if not last_run_next_link:
            pagination_log_ids = dedup_log_ids
        # always update the next link
        last_run_next_link = new_next_link
    else:
        if last_run_next_link:
            # pagination is over
            dedup_log_ids = pagination_log_ids
            demisto.info(
                f'pagination is over, received in the last page '
                f'the following log ids: {fetched_search_detection_logs_ids}'
            )
        last_run_next_link = ''

    parse_search_detection_logs(search_detection_logs)

    search_detections_updated_last_run = {
        search_detection_start_run_time: last_run_start_time,
        search_detection_dedup: dedup_log_ids,
        search_detection_pagination: pagination_log_ids,
        search_detection_next_link: last_run_next_link
    }

    demisto.info(f'{fetched_search_detection_logs_ids=}')
    demisto.info(f'{search_detections_updated_last_run=}')
    return search_detection_logs, search_detections_updated_last_run


def get_audit_logs(
    client: Client,
    first_fetch: str,
    last_run: dict,
    limit: int = DEFAULT_MAX_LIMIT,
    date_format: str = DATE_FORMAT,
) -> tuple[List[dict], dict]:
    """
    Get the audit logs.

    Args:
        client (Client): the client object
        first_fetch (str): the first fetch time
        last_run (dict): the last run object
        limit (int): the maximum number of search detection logs to return.
        date_format (str): the date format.

    Returns:
        Tuple[List[Dict], Dict]: audit logs & last updated run
    """
    audit_cache_time_field_name = LastRunTimeCacheTimeFieldNames.AUDIT.value
    audit_log_type = LogTypes.AUDIT.value
    audit_log_last_run_time = LastRunLogsStartTimeFields.AUDIT.value

    start_time, end_time = get_datetime_range(
        last_run_time=last_run.get(audit_log_last_run_time),
        first_fetch=first_fetch,
        log_type_time_field_name=audit_log_last_run_time,
        date_format=date_format
    )
    audit_logs = client.get_audit_logs(
        start_datetime=start_time, end_datetime=end_time, limit=limit
    )

    for log in audit_logs:
        # since there isn't real uuid in audit logs, we hash the entire audit log to create a unique id
        encoded_audit_log = json.dumps(log, sort_keys=True).encode()
        log['id'] = hashlib.sha256(encoded_audit_log).hexdigest()

    audit_logs = dedup_fetched_logs(
        logs=audit_logs,
        last_run=last_run,
        log_id_field_name='id',
        log_cache_last_run_name_field_name=audit_cache_time_field_name,
        log_type=audit_log_type
    )

    latest_audit_log_ids, latest_log_time = get_all_latest_logs_ids(
        logs=audit_logs,
        log_type=audit_log_type,
        log_id_field_name='id',
        date_format=DATE_FORMAT
    )

    latest_audit_log_time = latest_log_time or (
        dateparser.parse(start_time) + timedelta(seconds=1)  # type: ignore
    ).strftime(DATE_FORMAT)  # type: ignore

    fetched_audit_logs_ids = [(_log.get('id'), _log.get('_time')) for _log in audit_logs if _log.get('id')]

    for log in audit_logs:
        # pop all the hashes used to find duplicates
        log.pop('id', None)

    audit_updated_last_run = {
        audit_log_last_run_time: latest_audit_log_time,
        audit_cache_time_field_name: latest_audit_log_ids
    }

    demisto.info(f'{fetched_audit_logs_ids=}')
    demisto.info(f'{audit_updated_last_run=}')
    return audit_logs, audit_updated_last_run


''' COMMAND FUNCTIONS '''


def fetch_events(
    client: Client,
    first_fetch: str,
    limit: int = DEFAULT_MAX_LIMIT
) -> tuple[List[dict], dict]:
    """
    Get all the logs.

    Args:
        client (Client): the client object
        first_fetch (str): the first fetch time
        limit (int): the maximum number of logs to fetch from each type

    Returns:
        Tuple[List[Dict], Dict]: events & updated last run for all the log types.
    """
    last_run = demisto.getLastRun()
    demisto.info(f'last run in the start of the fetch: {last_run}')

    demisto.info(f'starting to fetch {LogTypes.WORKBENCH} logs')
    workbench_logs, updated_workbench_last_run = get_workbench_logs(
        client=client,
        first_fetch=first_fetch,
        last_run=last_run,
        limit=limit
    )
    demisto.info(f'Fetched amount of workbench logs: {len(workbench_logs)}')

    demisto.info(f'starting to fetch {LogTypes.OBSERVED_ATTACK_TECHNIQUES} logs')
    observed_attack_techniques_logs, updated_observed_attack_technique_last_run = get_observed_attack_techniques_logs(
        client=client,
        first_fetch=first_fetch,
        last_run=last_run,
        limit=limit
    )
    demisto.info(f'Fetched amount of observed attack techniques logs: {len(observed_attack_techniques_logs)}')

    demisto.info(f'starting to fetch {LogTypes.SEARCH_DETECTIONS} logs')
    search_detection_logs, updated_search_detection_last_run = get_search_detection_logs(
        client=client,
        first_fetch=first_fetch,
        last_run=last_run,
        limit=limit,
    )
    demisto.info(f'Fetched amount of search detection logs: {len(search_detection_logs)}')

    demisto.info(f'starting to fetch {LogTypes.AUDIT} logs')
    audit_logs, updated_audit_last_run = get_audit_logs(
        client=client,
        first_fetch=first_fetch,
        last_run=last_run,
        limit=limit
    )
    demisto.info(f'Fetched amount of audit logs: {len(audit_logs)}')

    events = workbench_logs + observed_attack_techniques_logs + search_detection_logs + audit_logs

    for logs_last_run in [
        updated_workbench_last_run,
        updated_observed_attack_technique_last_run,
        updated_search_detection_last_run,
        updated_audit_last_run
    ]:
        last_run.update(logs_last_run)

    demisto.info(f'last run after fetching all logs: {last_run}')
    return events, last_run


def test_module(client: Client, first_fetch: str) -> str:
    """
    Tests that the collector is able to retrieve all logs without any error.

    Args:
        client (Client): the client object
        first_fetch (str): the first fetch time

    Returns:
        str: 'ok' in case of success, exception in case of an error.
    """
    fetch_events(client=client, first_fetch=first_fetch, limit=1)
    return 'ok'


def get_events_command(client: Client, args: dict) -> CommandResults:
    """
    implements the trend-micro-vision-one-get-events command, mainly used for debugging.

    Args:
        client (Client): the client object.
        args (dict): the command arguments.

    Returns:
        CommandResults: command results object.
    """
    limit = arg_to_number(args.get('limit')) or DEFAULT_MAX_LIMIT
    should_push_events = argToBoolean(args.get('should_push_events', False))
    log_types = argToList(args.get('log_type')) or []
    from_time = args.get('from_time')
    to_time = args.get('to_time') or datetime.now().strftime(DATE_FORMAT)

    def parse_workbench_logs() -> List[dict]:
        workbench_logs = client.get_workbench_logs(
            start_datetime=from_time,  # type: ignore[arg-type]
            end_datetime=to_time,
            limit=limit
        )
        return [
            {
                'Id': log.get('id'),
                'Time': log.get(CreatedTimeFields.WORKBENCH.value),
                'Type': 'Workbench',
            } for log in workbench_logs
        ]

    def parse_observed_attack_techniques_logs() -> List[dict]:
        observed_attack_techniques_logs, _ = client.get_observed_attack_techniques_logs(
            detected_start_datetime=from_time,  # type: ignore[arg-type]
            detected_end_datetime=to_time,  # type: ignore[arg-type]
            top=limit,
            limit=limit
        )
        return [
            {
                'Id': log.get('uuid'),
                'Time': log.get(CreatedTimeFields.OBSERVED_ATTACK_TECHNIQUES.value),
                'Type': 'Observed Attack Technique'
            } for log in observed_attack_techniques_logs
        ]

    def parse_search_detection_logs() -> List[dict]:
        search_detection_logs, _ = client.get_search_detection_logs(
            start_datetime=from_time,  # type: ignore[arg-type]
            end_datetime=to_time,
            top=limit,
            limit=limit
        )
        return [
            {
                'Id': log.get('uuid'),
                'Time': log.get(CreatedTimeFields.SEARCH_DETECTIONS.value),
                'Type': 'Search Detection'
            } for log in search_detection_logs
        ]

    def parse_audit_logs() -> List[dict]:
        audit_logs = client.get_audit_logs(
            start_datetime=from_time,  # type: ignore[arg-type]
            end_datetime=to_time,
            limit=limit
        )
        return [
            {
                'Id': log.get('loggedUser'),
                'Time': log.get(CreatedTimeFields.AUDIT.value),
                'Type': 'Audit'
            } for log in audit_logs
        ]

    events = []

    if LogTypes.WORKBENCH.value in log_types:
        events.extend(parse_workbench_logs())
    if LogTypes.OBSERVED_ATTACK_TECHNIQUES.value in log_types:
        events.extend(parse_observed_attack_techniques_logs())
    if LogTypes.SEARCH_DETECTIONS.value in log_types:
        events.extend(parse_search_detection_logs())
    if LogTypes.AUDIT.value in log_types:
        events.extend(parse_audit_logs())

    if should_push_events:
        send_events_to_xsiam(
            events=events, vendor=VENDOR, product=PRODUCT
        )

    return CommandResults(
        outputs=events,
        outputs_prefix='TrendMicroVisionOne.Events',
        readable_output=tableToMarkdown(f'events for {log_types=}', events, removeNull=True)
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()

    base_url = params.get('url') or DEFAULT_URL
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = params.get('proxy', False)
    first_fetch = params.get('first_fetch') or '3 days'
    limit = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_LIMIT

    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            proxy=proxy,
            verify=verify_certificate,
        )

        if demisto.command() == 'test-module':
            return_results(test_module(client=client, first_fetch=first_fetch))
        elif command == 'fetch-events':
            events, updated_last_run = fetch_events(
                client=client, first_fetch=first_fetch, limit=limit
            )
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(updated_last_run)
        elif command == 'trend-micro-vision-one-get-events':
            return_results(get_events_command(client=client, args=demisto.args()))
        else:
            raise NotImplementedError(f'{command} command is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
