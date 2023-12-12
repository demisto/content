"""Varonis Data Security Platform integration
"""

from AlertAttributes import AlertAttributes
from Client import Client
from EventAttributes import EventAttributes
from ThreatModelObjectMapper import ThreatModelObjectMapper
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

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


def varonis_update_alert(client: Client, close_reason_id: int, status_id: int, alert_ids: list, note: str) -> bool:
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
        add_note_query: Dict[str, Any] = {
            'AlertGuids': alert_ids,
            'Note': note
        }
        add_note_result = client.varonis_add_note_to_alerts(add_note_query)

    if status_id:
        update_status_query: Dict[str, Any] = {
            'AlertGuids': alert_ids,
            'CloseReasonId': close_reason_id,
            'StatusId': status_id
        }
        update_status_result = client.varonis_update_alert_status(update_status_query)

    return True if update_status_result or add_note_result else False


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

    # todo: fix when it will be converted to array
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


def varonis_get_threat_models_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get threaat models from Varonis DA

    :type client: ``Client``
    :param client: Http client

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['id'] = None  # List of requested threat model ids
        ``args['name'] = None  # List of requested threat model names
        ``args['category'] = None  # List of requested threat model categories
        ``args['severity'] = None  # List of requested threat model severities
        ``args['source'] = None  # List of requested threat model sources

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """

    id = args.get('id', None)
    name = args.get('name', None)
    category = args.get('category', None)
    severity = args.get('severity', None)
    source = args.get('source', None)

    id = try_convert(id, lambda x: argToList(x))
    name = try_convert(name, lambda x: argToList(x))
    category = try_convert(category, lambda x: argToList(x))
    severity = try_convert(severity, lambda x: argToList(x))
    source = try_convert(source, lambda x: argToList(x))

    id_int = []
    if id:
        for id_item in id:
            value = try_convert(
                id_item,
                lambda x: int(x),
                ValueError(f'id should be integer, but it is {id_item}.')
            )
            id_int.append(value)

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
                        if isinstance(value, str) and value in str(item[key]) or value == item[key]:
                            criteria_match = True
                            break
                    if not criteria_match:
                        isMatch = False
                        break
            if isMatch:
                filtered_items.append(item)

        return filtered_items

    filtered_items = filter_threat_model_items(mapped_items, {
        'ID': id_int,
        'Name': name,
        'Category': category,
        'Severity': severity,
        'Source': source
    })

    outputs = dict()
    outputs['ThreatModel'] = filtered_items

    readable_output = tableToMarkdown('Varonis Threat Models', filtered_items, headers=[
                                      'ID', 'Name', 'Category', 'Severity', 'Source'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='ID',
        outputs=outputs
    )


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

    alerts = client.varonis_get_alerts(threat_model_names=threat_model_names, alertIds=None, start_time=None, end_time=None,
                                       device_names=None, user_names=None, last_days=None,
                                       ingest_time_from=last_fetched_ingest_time,
                                       ingest_time_to=ingest_time_to,
                                       alert_statuses=statuses, alert_severities=severities,
                                       extra_fields=None,
                                       descending_order=True)

    demisto.debug(f'varonis_get_alerts returned: {len(alerts)} alerts')

    for alert in alerts:
        ingestTime_str = alert[AlertAttributes.Alert_IngestTime]
        ingestTime = try_convert(
            alert[AlertAttributes.Alert_IngestTime],
            lambda x: datetime.fromisoformat(x),
            ValueError(f'IngestTime should be in iso format, but it is {ingestTime_str}.')
        )

        if not last_fetched_ingest_time or ingestTime > last_fetched_ingest_time:
            last_fetched_ingest_time = ingestTime + timedelta(minutes=1)
        guid = alert[AlertAttributes.Alert_ID]
        name = alert[AlertAttributes.Alert_Rule_Name]
        alert_time = alert[AlertAttributes.Alert_Time]
        enrich_with_url(alert, client._base_url, guid)

        alert_converted = convert_incident_alert_to_onprem_format(alert)

        incident = {
            'name': f'Varonis alert {name}',
            'occurred': f'{alert_time}Z',
            'rawJSON': json.dumps(alert_converted),
            'type': 'Varonis DSP Incident',
            'severity': convert_to_demisto_severity(alert_converted[AlertAttributes.Alert_Rule_Severity_Name]),
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
        ``args['extra_fields']`` Extra fields
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
    extra_fields = args.get('extra_fields', None)
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
    extra_fields = try_convert(extra_fields, lambda x: argToList(x))

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

    alerts = client.varonis_get_alerts(threat_model_names, alert_ids, start_time, end_time, ingest_time_from, ingest_time_to,
                                       device_names,
                                       user_names,
                                       last_days, alert_statuses, alert_severities,
                                       extra_fields,
                                       descending_order)
    outputs = dict()
    outputs['Alert'] = alerts

    alert_attributes = AlertAttributes()
    if outputs:
        for alert in alerts:
            enrich_with_url(alert, client._base_url, alert[alert_attributes.Alert_ID])

    readable_output = tableToMarkdown('Varonis Alerts', alerts, headers=alert_attributes.get_fields(extra_fields))

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
        ``args['extra_fields']`` Extra fields
        ``args['descending_order']`` Indicates whether events should be ordered in newest to oldest order

    :return:
        A ``CommandResults`` object

    :rtype: ``CommandResults``
    """
    alertIds = args.get('alert_id', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    last_days = args.get('last_days', None)
    extra_fields = args.get('extra_fields', None)
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
    extra_fields = try_convert(extra_fields, lambda x: argToList(x))

    events = client.varonis_get_alerted_events(alertIds=alertIds, start_time=start_time, end_time=end_time,
                                               last_days=last_days,
                                               extra_fields=extra_fields,
                                               descending_order=descending_order)
    outputs = dict()
    outputs['Event'] = events

    event_attributes = EventAttributes()
    readable_output = tableToMarkdown('Varonis Alerted Events', events, headers=event_attributes.get_fields(extra_fields))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Varonis',
        outputs_key_field='Varonis.Event.ID',
        outputs=outputs
    )


def varonis_alert_add_note_command(client: Client, args: Dict[str, Any]) -> bool:
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
    note = args.get('note', None)

    return varonis_update_alert(client, CLOSE_REASONS['none'], status_id=None, alert_ids=argToList(args.get('alert_id')),
                                note=note)


def varonis_update_alert_status_command(client: Client, args: Dict[str, Any]) -> bool:
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
    status = args.get('status', None)
    statuses = list(filter(lambda name: name != 'closed', ALERT_STATUSES.keys()))
    if status.lower() not in statuses:
        raise ValueError(f'status must be one of {statuses}.')

    status_id = ALERT_STATUSES[status.lower()]
    note = args.get('note', None)

    return varonis_update_alert(client, CLOSE_REASONS['none'], status_id, argToList(args.get('alert_id')), note)


def varonis_close_alert_command(client: Client, args: Dict[str, Any]) -> bool:
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
    close_reason = args.get('close_reason', None)
    close_reasons = list(filter(lambda name: not strEqual(name, 'none'), CLOSE_REASONS.keys()))
    if close_reason.lower() not in close_reasons:
        raise ValueError(f'close reason must be one of {close_reasons}')

    close_reason_id = CLOSE_REASONS[close_reason.lower()]
    note = args.get('note', None)
    return varonis_update_alert(client, close_reason_id, ALERT_STATUSES['closed'], argToList(args.get('alert_id')), note)


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
        url = 'https://int2a26a.varonis-preprod.com/'
        apiKey = 'vkey1_17944a55aa824cfbb472ce2256bb9417_luHz5L/2ul2tGuiibpgSVDjcz/K8CC/HPyujFyieT18='
        command = 'varonis-get-alerted-events'
        # 'test-module'|
        # 'varonis-get-threat-models'|
        # 'varonis-get-alerts'|
        # 'varonis-get-alerted-events'|
        # 'varonis-alert-add-note'
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

        test_alert_id = '6769D061-A714-4C95-A8AE-121E5379BF3C'
        if command == 'test-module':
            pass

        if command == 'varonis-get-threat-models':
            args['id'] = "1,2,3"  # List of requested threat model ids
            # "Abnormal service behavior: access to atypical folders,Abnormal service behavior: access to atypical files"  # List of requested threat model names
            args['name'] = ""
            args['category'] = ""  # "Exfiltration,Reconnaissance"  # List of requested threat model categories
            args['severity'] = ""  # "3 - Error,4 - Warning"  # List of requested threat model severities
            args['source'] = ""  # "Predefined"  # List of requested threat model sources

        elif command == 'varonis-get-alerts':
            args['threat_model_name'] = None  # List of requested threat models
            args['ingest_time_from'] = None  # Start ingest time of the range of alerts
            args['ingest_time_to'] = None  # End ingest time of the range of alerts
            args['start_time'] = None  # Start time of the range of alerts
            args['end_time'] = None  # End time of the range of alerts
            args['alert_status'] = None  # List of required alerts status
            args['alert_severity'] = None  # List of alerts severity
            args['device_name'] = None  # List of device names
            args['user_name'] = None  # List of device names
            args['last_days'] = None  # Number of days you want the search to go back to
            args['extra_fields'] = ""  # extra fields
            args['descending_order'] = None  # Indicates whether alerts should be ordered in newest to oldest order

        elif command == 'varonis-get-alerted-events':
            args['alert_id'] = test_alert_id  # Array of alert ids
            args['start_time'] = None  # Start time of the range of events
            args['end_time'] = None  # End time of the range of events
            args['last_days'] = None  # Number of days you want the search to go back to
            args['extra_fields'] = ""  # extra fields
            args['descending_order'] = None  # Indicates whether events should be ordered in newest to oldest order
        
        elif command == 'varonis-alert-add-note':
            args['alert_id'] = test_alert_id  # Array of alert ids to be updated
            args['note'] = "user note"  # Note for alert
            
        elif command == 'varonis-update-alert-status':
            args['status'] = 'under investigation'  # Alert's new status
            args['alert_id'] = test_alert_id  # Array of alert ids to be updated
            args['note'] = "user note"  # Note for alert

        elif command == 'varonis-close-alert':
            args['close_reason'] = 'resolved'  # Alert's close reason
            args['alert_id'] = test_alert_id  # Array of alert ids to be closed
            args['note'] = "user note"  # Note for alert

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

        if command == 'varonis-get-threat-models':
            # This is the call made when pressing the integration Test button.
            result = varonis_get_threat_models_command(client, args)
            return_results(result)

        elif command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client)
            return_results(result)

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
