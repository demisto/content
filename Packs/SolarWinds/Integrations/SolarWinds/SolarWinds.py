import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *  # noqa

from typing import Dict, List, Callable, Tuple

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
READABLE_DATE_FORMAT = '%d/%m/%Y %I:%M %p'

BASE_URL = "https://{}:{}/SolarWinds/InformationService/v3/Json"

DEFAULT_FETCH_TYPE = "Alert"
DEFAULT_MAX_FETCH = "15"
DEFAULT_FIRST_FETCH = "3 days"

HTTP_ERRORS = {
    400: "Bad request: an error occurred while fetching the data. {}",
    401: "Authentication error: please provide valid username and password.",
    403: "Forbidden: please provide valid username and password.",
    404: "Resource not found: invalid endpoint was called.",
    500: "Internal server error: please try again after some time."
}

ERR_MSG = {
    "PAGE": "Invalid value for page argument. Value should be a positive number.",
    "LIMIT": "Invalid value for limit argument. Value should be a positive number.",
    "SORT_ORDER": "Invalid value for sort_order argument. Value should be ascending or descending only.",
    "ACKNOWLEDGED": "Invalid value for acknowledged argument. Value should be true or false only.",
    'NO_RECORDS_FOUND': 'No {} were found for the given argument(s).',
    'SEVERITIES_ERROR': 'Invalid value for severity argument. Value should be in {}.',
    'ID_ERROR': 'Invalid value for {} argument. Value should be a positive integer.',
    "INVALID_MAX_FETCH": "Argument 'Maximum number of incidents per fetch' should be a positive integer between 1 and "
                         "1000.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time interval' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "REQUIRED_ARGUMENT": "Invalid argument value. 'query' is a required argument."
}

SEVERITIES_MAP = ["INFORMATION", "WARNING", "CRITICAL", "SERIOUS", "NOTICE"]

URL_SUFFIX = {
    "QUERY": "Query"
}

FETCH_TYPES = ["Alert", "Event"]

QUERY_PARAM = {
    "LIST_ALERTS": "SELECT A.AlertActiveID, A.AlertObjectID, A.Acknowledged, A.AcknowledgedBy,"
                   "A.AcknowledgedDateTime, A.AcknowledgedNote, A.TriggeredDateTime, A.TriggeredMessage,"
                   "A.NumberOfNotes, A.LastExecutedEscalationLevel, A.DisplayName, A.Description as AlertDescription,"
                   "A.InstanceType, A.Uri, A.InstanceSiteId, B.AlertID, B.EntityUri, B.EntityType, B.EntityCaption,"
                   "B.EntityDetailsUrl, B.EntityNetObjectId, B.RelatedNodeUri, B.RelatedNodeId,"
                   "B.RelatedNodeDetailsUrl, B.RelatedNodeCaption, B.RealEntityUri, B.RealEntityType,"
                   "B.TriggeredCount, B.LastTriggeredDateTime, B.Context, B.AlertNote, C.AlertMessage, C.AlertRefID,"
                   "C.Name, C.Description as ConfigurationDescription, C.ObjectType, C.Enabled, C.Frequency,"
                   "C.Trigger, C.Reset, C.Severity, C.NotifyEnabled, C.NotificationSettings, C.LastEdit, C.CreatedBy,"
                   "C.Category, C.Canned, D.ResponsibleTeam FROM Orion.AlertActive AS A "
                   "INNER JOIN Orion.AlertObjects AS B ON A.AlertObjectID = B.AlertObjectID "
                   "INNER JOIN Orion.AlertConfigurations AS C ON B.AlertID = C.AlertID "
                   "INNER JOIN Orion.AlertConfigurationsCustomProperties AS D ON C.AlertID = D.AlertID",
    "GET_EVENTS": "SELECT E.EventID, E.EventTime, E.NetworkNode, N.Caption as Node, E.NetObjectID, E.NetObjectValue, "
                  "E.EngineID, E.EventType, ET.Name as EventTypeName, E.Message, E.Acknowledged, E.NetObjectType, "
                  "E.TimeStamp, E.DisplayName, E.Description, E.InstanceType, E.Uri, E.InstanceSiteId "
                  "FROM Orion.Events AS E INNER JOIN Orion.EventTypes AS ET ON E.EventType = ET.EventType "
                  "LEFT JOIN Orion.Nodes as N ON E.NetworkNode = N.NodeID",
    "FETCH_ALERTS": "SELECT TOP {} A.AlertActiveID, A.AlertObjectID, A.Acknowledged, A.AcknowledgedBy,"
                    "A.AcknowledgedDateTime, A.AcknowledgedNote, A.TriggeredDateTime, A.TriggeredMessage,"
                    "A.NumberOfNotes, A.LastExecutedEscalationLevel, A.DisplayName,"
                    "A.Description as AlertDescription, A.InstanceType, A.Uri, A.InstanceSiteId,"
                    "B.AlertID, B.EntityUri, B.EntityType, B.EntityCaption, B.EntityDetailsUrl, "
                    "B.EntityNetObjectId, B.RelatedNodeUri, B.RelatedNodeId, B.RelatedNodeDetailsUrl, "
                    "B.RelatedNodeCaption, B.RealEntityUri, B.RealEntityType, B.TriggeredCount, "
                    "B.LastTriggeredDateTime, "
                    "B.Context, B.AlertNote, C.AlertMessage, C.AlertRefID, C.Name, "
                    "C.Description as ConfigurationDescription, C.ObjectType, C.Enabled, C.Frequency, "
                    "C.Trigger, C.Reset, C.Severity, C.NotifyEnabled, C.NotificationSettings, C.LastEdit,"
                    "C.CreatedBy, C.Category, C.Canned, D.ResponsibleTeam "
                    "FROM Orion.AlertActive AS A "
                    "INNER JOIN Orion.AlertObjects AS B ON A.AlertObjectID = B.AlertObjectID "
                    "INNER JOIN Orion.AlertConfigurations AS C ON B.AlertID = C.AlertID "
                    "INNER JOIN Orion.AlertConfigurationsCustomProperties AS D ON C.AlertID = D.AlertID",
    "FETCH_EVENTS": "SELECT TOP {} A.EventID, A.EventTime, A.NetworkNode, A.NetObjectID, A.NetObjectValue,"
                    "A.EngineID, A.EventType, A.Message, A.Acknowledged, A.NetObjectType, A.TimeStamp,"
                    "A.DisplayName, A.Description, A.InstanceType, A.Uri,A.InstanceSiteId, B.Name "
                    "FROM Orion.Events as A "
                    "INNER JOIN Orion.EventTypes as B ON A.EventType=B.EventType"
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, server, port, verify, proxy, credentials):
        auth = (credentials.get("identifier"), credentials.get('password'))
        super().__init__(BASE_URL.format(server, port), verify=verify, proxy=proxy, auth=auth)

    def http_request(self, method: str, url_suffix: str, params: dict = None, json_data: dict = None, **kwargs):
        """
        The wrapper for BaseClient's http_request method.

        :param method: the HTTP method. Valid values 'GET', 'POST' etc.

        :param url_suffix: the suffix to the endpoint.

        :param params: URL parameters to specify the query.

        :param json_data: The dictionary to send in a request.

        :return: json response from the endpoint.
        """
        response = self._http_request(method, url_suffix, params=params, json_data=json_data, resp_type="response",
                                      ok_codes=[200, *list(HTTP_ERRORS.keys())], raise_on_status=False, **kwargs)
        if response.status_code == 400 and response.json() and response.json().get('Message'):
            raise DemistoException(
                HTTP_ERRORS[response.status_code].format("Message:" + response.json().get("Message")))
        elif response.status_code in list(HTTP_ERRORS.keys()):
            raise DemistoException(HTTP_ERRORS[response.status_code])
        return response.json()


''' HELPER FUNCTIONS '''


def validate_fetch_incidents_parameters(params: dict) -> dict:
    """
    Validate fetch incidents params, throw ValueError on non-compliant  arguments

    :param params: dictionary of parameters to be tested for fetch_incidents

    :rtype: ``dict``
    return: dictionary containing valid parameters
    """

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))
    if (max_fetch is None) or (not 0 < max_fetch <= 1000):
        raise ValueError(ERR_MSG["INVALID_MAX_FETCH"])
    params["max_fetch"] = max_fetch

    first_fetch = params.get("first_fetch")
    first_fetch_time = arg_to_datetime(first_fetch, required=True,
                                       settings={'TIMEZONE': "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
    if first_fetch_time is None:
        raise ValueError(ERR_MSG["INVALID_FIRST_FETCH"])
    params["first_fetch"] = first_fetch_time

    severities = params.get("severities", [])
    for severity in severities:
        if severity.upper() not in SEVERITIES_MAP:
            raise ValueError(ERR_MSG["SEVERITIES_ERROR"].format(SEVERITIES_MAP))
    params["severities"] = severities

    return params


def prepare_query_for_fetch_alerts(last_run: dict, params: dict) -> str:
    """
    Return the query to fetch alerts

    :param last_run: last run returned by function demisto.getLastRun.

    :param params: arguments for fetch-incident.

    :rtype: ``str``
    :return: query string to send in request
    """
    max_fetch = params.get("max_fetch")
    first_fetch = params.get("first_fetch")
    severities = params.get("severities")
    object_types = params.get("object_types")

    query = QUERY_PARAM["FETCH_ALERTS"].format(max_fetch)

    # The AlertActiveIDs are unique for alerts, so it is used instead of timestamp for the last run for simplicity
    if last_run.get('alert_active_id'):
        query += f" WHERE A.AlertActiveID>{last_run.get('alert_active_id')}"
    else:
        query += f" WHERE A.TriggeredDateTime>='{first_fetch.strftime(DATE_FORMAT)}'"  # type: ignore

    if severities:
        query += " AND (" + " OR ".join(
            [f"C.Severity={SEVERITIES_MAP.index(severity)}" for severity in severities]) + ")"
    if object_types:
        query += " AND (" + " OR ".join(
            [f"C.ObjectType='{object_type}'" for object_type in object_types]) + ")"

    query += " ORDER BY A.AlertActiveID"

    return query


def prepare_query_for_fetch_events(last_run: dict, params: dict) -> str:
    """
    Returns the query to fetch events

    :param last_run: last run returned by function demisto.getLastRun.

    :param params: arguments for fetch-incident.

    :rtype: ``str``
    :return: query string to send in request
    """
    max_fetch = params.get("max_fetch")
    first_fetch = params.get("first_fetch")
    event_types = params.get("event_types")

    query = QUERY_PARAM["FETCH_EVENTS"].format(max_fetch)
# The EventIDs are unique for events, so it is used instead of timestamp for the last run for simplicity
    if last_run.get('event_id'):
        query += f" WHERE A.EventID>{last_run.get('event_id')}"
    else:
        query += f" WHERE A.EventTime>='{first_fetch.strftime(DATE_FORMAT)}'"  # type: ignore

    if event_types:
        query += " AND (" + " OR ".join(
            [f"B.Name='{event_type}'" for event_type in event_types]) + ")"

    query += " ORDER BY A.EventID"

    return query


def validate_common_arguments(args: Dict) -> dict:
    """
    Validates common arguments and raises errors for invalid values.

    :type args: ``dict``
    :param args: Arguments to validate

    :rtype: `dict``
    :return: Returns a dictionary containing validated arguments

    :raises ValueError: Raises value errors for invalid values
    """
    page = arg_to_number(args.get("page", 0))
    if (page is None) or (page < 0):
        raise ValueError(ERR_MSG["PAGE"])
    args['page'] = page

    limit = arg_to_number(args.get("limit", 50))
    if (limit is None) or (limit < 1):
        raise ValueError(ERR_MSG["LIMIT"])
    args['limit'] = limit

    sort_order = args.get("sort_order", "ascending")
    if sort_order and sort_order.lower() not in ['ascending', 'descending']:
        raise ValueError(ERR_MSG["SORT_ORDER"])

    return args


def validate_and_prepare_query_for_list_alerts(args) -> str:
    """
    Validates and prepare arguments for alerts-list command and returns query.

    :param args: Arguments to validate and prepare query from

    :rtype: ``str``
    :return: Query prepared by provided arguments
    """
    args = validate_common_arguments(args)
    alert_types = argToList(args.get('type', ''), ',')
    severities = argToList(args.get('severity', '').upper(), ',')
    page = args.get('page', 0)
    limit = args.get('limit', 50)
    alert_ids = argToList(args.get('alert_id', []), ',')
    alert_ids = list(map(arg_to_number, alert_ids))
    if None in alert_ids:
        raise ValueError(ERR_MSG['ID_ERROR'].format('alert_id'))

    sort_key = args.get('sort_key', 'AlertActiveID')
    sort_order = 'DESC' if args.get('sort_order', 'ascending').lower() == 'descending' else 'ASC'
    filter_query = QUERY_PARAM['LIST_ALERTS']

    # flag for where clause has been added
    where_flag = False
    if alert_types:
        filter_query += " WHERE ( " + " OR ".join(
            [f"ObjectType = '{alert_type}'" for alert_type in alert_types]) + " )"
        where_flag = True

    if not set(severities).issubset(SEVERITIES_MAP):
        raise ValueError(ERR_MSG["SEVERITIES_ERROR"].format(SEVERITIES_MAP))

    if severities:
        filter_query += ' AND ' if where_flag else ' WHERE '
        filter_query += "( " + " OR ".join(
            [f"Severity = {SEVERITIES_MAP.index(severity)}" for severity in severities]) + " )"
        where_flag = True

    if alert_ids:
        filter_query += " AND " if where_flag else " WHERE "
        filter_query += "( " + " OR ".join(
            [f"AlertActiveID = {alert_id}" for alert_id in alert_ids]) + " )"

    filter_query += f' ORDER BY {sort_key} {sort_order} WITH ROWS {(page * limit) + 1} TO {(page + 1) * limit}'

    return filter_query


def validate_and_prepare_query_for_event_list(args: Dict) -> str:
    """
    Validates and prepare arguments for event-list command and returns query.

    :param args: Arguments to validate and prepare query from

    :rtype: ``str``
    :return: Query prepared by provided arguments
    """
    args = validate_common_arguments(args)
    acknowledged = args.get("acknowledged", "")
    event_type = argToList(args.get("event_type", []), ',')
    node = argToList(args.get("node", []), ',')
    event_ids = argToList(args.get('event_id', []), ',')
    event_ids = list(map(arg_to_number, event_ids))
    if None in event_ids:
        raise ValueError(ERR_MSG['ID_ERROR'].format('event_id'))
    args['event_id'] = event_ids
    page = args.get("page", 0)
    limit = args.get("limit", 50)
    sort_key = args.get("sort_key", "EventID")
    sort_order = "DESC" if args.get("sort_order", "ascending").lower() == "descending" else "ASC"
    query = QUERY_PARAM["GET_EVENTS"]
    where_added = False
    if acknowledged and acknowledged.lower() not in ['true', 'false']:
        raise ValueError(ERR_MSG["ACKNOWLEDGED"])
    elif acknowledged:
        query += f" WHERE Acknowledged = {acknowledged}"
        where_added = True
    if event_type:
        query += " AND " if where_added else " WHERE "
        query += "( " + " OR ".join(
            [f"EventTypeName = '{event_type_name}'" for event_type_name in event_type]) + " )"
        where_added = True
    if node:
        query += " AND " if where_added else " WHERE "
        query += "( " + " OR ".join(
            [f"Node = '{node_name}'" for node_name in node]) + " )"
    if event_ids:
        query += " AND " if where_added else " WHERE "
        query += "( " + " OR ".join(
            [f"EventID = {event_id}" for event_id in event_ids]) + " )"

    query += f" ORDER BY {sort_key} {sort_order} WITH ROWS {(page * limit) + 1} TO {(page + 1) * limit}"
    return query


def convert_events_outputs_to_hr(outputs: List) -> str:
    """
    Converts list of outputs received from response to human readable output.

    :param outputs: List outputs received from response

    :rtype: ``str``
    :return: Human readable output generated from tableToMarkDown
    """
    if len(outputs) == 0:
        return ERR_MSG['NO_RECORDS_FOUND'].format('event(s)')
    readable_outputs = []
    for output in outputs:
        event_time = arg_to_datetime(output.get("EventTime"))
        readable_outputs.append({
            "Event ID": output.get("EventID"),
            "Message": output.get("Message"),
            "Type": output.get("EventTypeName"),
            "Node": output.get("Node", ""),
            "Acknowledged": output.get("Acknowledged"),
            "Triggered At": event_time.strftime(READABLE_DATE_FORMAT),  # type: ignore
        })
    return tableToMarkdown(
        "Events",
        readable_outputs,
        ["Event ID", "Message", "Type", "Node", "Acknowledged", "Triggered At"],
        removeNull=True
    )


def convert_alerts_outputs_to_hr(outputs: List) -> str:
    """
    Converts list of outputs received from response to human readable output.

    :param outputs: List outputs received from response

    :rtype: ``str``
    :return: Human readable output generated from tableToMarkDown
    """
    if len(outputs) == 0:
        return ERR_MSG['NO_RECORDS_FOUND'].format('alert(s)')
    readable_outputs = []
    for output in outputs:
        alert_time = arg_to_datetime(output.get("TriggeredDateTime", ''))
        readable_outputs.append({
            "Active Alert ID": output.get("AlertActiveID"),
            "Alert Name": output.get("Name"),
            "Type": output.get("ObjectType"),
            "Triggered Message": output.get("TriggeredMessage"),
            "Configuration Description": output.get("ConfigurationDescription", ''),
            "Acknowledged": output.get("Acknowledged", ''),
            "Entity Caption": output.get("EntityCaption", ''),
            "Severity": SEVERITIES_MAP[output.get("Severity")],
            "Triggered At": alert_time.strftime(READABLE_DATE_FORMAT),  # type: ignore
        })
    return tableToMarkdown(
        "Alerts",
        readable_outputs,
        ["Active Alert ID", "Alert Name", "Triggered Message", "Entity Caption", "Triggered At", "Acknowledged",
         "Severity",
         "Type", "Configuration Description"],
        removeNull=True
    )


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :param client: client to use

    :param params: configuration parameters.

    :return: 'ok' if test passed, anything else will fail the test.
    """
    client.http_request("GET", URL_SUFFIX["QUERY"], params={
        "query": "SELECT TOP 0 NodeID FROM Orion.Nodes"
    })
    is_fetch = params.get("isFetch")
    if is_fetch:
        fetch_incidents(client, {}, params, True)
    return 'ok'


@logger
def swis_alert_list_command(client: Client, args: Dict) -> CommandResults:
    """
        Retrieves a list of alerts based on the filter values provided in the command arguments.

        :param client: Client to make endpoint calls

        :param args: Arguments provided by the user
        :rtype: ``CommandResults``
        :return: Response received from api in the form of CommandResults object
    """

    filtered_query = validate_and_prepare_query_for_list_alerts(args)
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["QUERY"],
                                   params={"query": filtered_query})

    outputs = createContext(response.get("results", []), removeNull=True)
    readable_outputs = convert_alerts_outputs_to_hr(outputs)
    return CommandResults(
        outputs_prefix="SolarWinds.Alert",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=response,
        outputs_key_field="AlertActiveID"
    )


@logger
def fetch_incidents(client: Client, last_run: dict, params: Dict, is_test=False) -> Tuple[dict, list]:
    """Fetches incidents from Solarwinds API.

    :param client: client to use

    :param last_run: last run returned by function demisto.getLastRun

    :param params: arguments for fetch-incident.

    :param is_test: whether this is a test function call or not.

    :rtype: ``Tuple``
    :return: tuple of dictionary of next run and list of fetched incidents
    """
    fetch_type = params.get("fetch_type", DEFAULT_FETCH_TYPE)
    if not fetch_type:
        fetch_type = DEFAULT_FETCH_TYPE
    params = validate_fetch_incidents_parameters(params)

    if fetch_type == DEFAULT_FETCH_TYPE:
        query = prepare_query_for_fetch_alerts(last_run, params)
    else:
        query = prepare_query_for_fetch_events(last_run, params)

    demisto.info(f'[SolarWinds]: Query: {query}')

    results = client.http_request("POST", URL_SUFFIX["QUERY"], json_data={
        "query": query
    }).get("results")

    next_run = last_run
    incidents = []
    for result in results:
        occurred = result['TriggeredDateTime'] if fetch_type == "Alert" else result['EventTime']
        incidents.append({
            'name': result['Name'],
            'occurred': arg_to_datetime(occurred).strftime(DATE_FORMAT),  # type: ignore
            'rawJSON': json.dumps(result)
        })

    if results:
        if fetch_type == DEFAULT_FETCH_TYPE:
            next_run['alert_active_id'] = results[-1]['AlertActiveID']
        else:
            next_run['event_id'] = results[-1]['EventID']

    if is_test:
        return {}, []

    return next_run, incidents


@logger
def swis_event_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of triggered events on the filter values provided in the command arguments.

    :param client: Client to make endpoint calls

    :param args: Arguments provided by the user

    :rtype: ``CommandResults``
    :return: Response received from api in the form of CommandResults object
    """

    query = validate_and_prepare_query_for_event_list(args)
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["QUERY"],
                                   params={"query": query})
    outputs = createContext(response.get("results", []), removeNull=True)
    readable_outputs = convert_events_outputs_to_hr(outputs)
    return CommandResults(
        outputs_prefix="SolarWinds.Event",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=response,
        outputs_key_field="EventID"
    )


def convert_query_output_to_hr(outputs) -> str:
    """
    Converts raw response received from the api to human readable response.

    :type outputs: ``list``
    :param outputs: raw response received from api

    :rtype: ``str``
    :return: Markdown that can be shown in War room.
    """
    if len(outputs) == 0:
        return ERR_MSG['NO_RECORDS_FOUND'].format('record(s)')
    readable_output = []
    for response_list in outputs:
        response_list = {pascalToSpace(k): v for k, v in response_list.items()}
        readable_output.append(response_list)
    return tableToMarkdown("Query Result", readable_output, removeNull=True)


def swis_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Executes a SWQL query entered by user

    :type client: ``Client``
    :param client: client to use

    :type args: ``dict``
    :param args: arguments provided by the user

    :rtype: ``CommandResults``
    :return: response received from api
    """
    query = args.get('query')
    if not query:
        raise ValueError(ERR_MSG['REQUIRED_ARGUMENT'])

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["QUERY"],
                                   params={"query": query})
    outputs = createContext(response.get("results", []), removeNull=True)
    readable_response = convert_query_output_to_hr(outputs)
    return CommandResults(
        outputs_prefix="SolarWinds.Query",
        outputs=outputs,
        readable_output=readable_response,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions
    """
    commands: Dict[str, Callable] = {
        'swis-alert-list': swis_alert_list_command,
        'swis-event-list': swis_event_list_command,
        'swis-query': swis_query_command
    }
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        params = demisto.params()
        args = demisto.args()
        server = params['server']
        port = params['port']
        credentials = params.get('credentials', {})

        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        client = Client(
            server=server,
            port=port,
            credentials=credentials,
            verify=verify_certificate,
            proxy=proxy)

        for key, value in args.items():
            if isinstance(value, str):
                args[key] = value.strip()

        remove_nulls_from_dictionary(args)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command in commands:
            return_results(commands[command](client, args))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
