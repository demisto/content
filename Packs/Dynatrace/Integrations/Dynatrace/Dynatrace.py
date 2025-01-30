from datetime import datetime, timezone, timedelta
import pytz
from typing import Any, Dict, Optional
import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = "Dynatrace"
PRODUCT = "Platform"
EVENTS_TYPE_DICT = {"Audit logs": "auditLogs", "APM": "events"}
EVENT_TYPES = ["APM", "Audit logs"]
LOG_PREFIX = "Dynatrace my logs"


""" CLIENT CLASS """

class DynatraceClient(BaseClient):
    def __init__(self, base_url, token, verify, proxy):
        super().__init__(proxy=proxy, base_url=base_url, verify=verify, headers={"Authorization": f"Api-Token {token}"})
            
            
    def get_audit_logs_events(self, query: str=""):
        return self._http_request("GET", "/api/v2/auditlogs"+query, headers=self._headers)
    
    
    def get_APM_events(self, query: str=""):
        return self._http_request("GET", "/api/v2/events"+query, headers=self._headers)


""" HELPER FUNCTIONS """

def validate_params(events_to_fetch, audit_max, apm_max):
    """
    Validates the integration parameters.

    1. `events_to_fetch` must contain at least one event type.
    2. `audit_max` must not exceed 25,000.
    3. `apm_max` must not exceed 5,000.

    If any of the parameters are invalid, the function raises a `ValueError` with a descriptive error message.
    """
    if not events_to_fetch:
        raise DemistoException("Please specify at least one event type to fetch.")
    for events_type in events_to_fetch:
        if events_type not in EVENT_TYPES:
            raise DemistoException("Events types to fetch can only include 'APM' or 'Audit logs'.")
    if audit_max < 1 or audit_max > 25000:
        raise DemistoException("The maximum number of audit logs events per fetch needs to be grater then 0 and not more then then 25000")
    if apm_max < 1 or apm_max > 7000:
        raise DemistoException("The maximum number of APM events per fetch needs to be grater then 0 and not more then then 5000")


def add_fields_to_events(events, event_type):
    """Adds SOURCE_LOG_TYPE and _time field to each event.

    Args:
        events (List): list of events.
        event_type (str): "APM" if events are apm type or "Audit logs" if events are audit logs type.

    Returns:
        list or events with the added fields.
    """
    
    field_mapping = {
        "Audit logs": ["Audit", "timestamp"],
        "APM": ["APM", "startTime"]
    
    }
    for event in events:
            event["SOURCE_LOG_TYPE"] = field_mapping[event_type][0]
            event["_time"] = event[field_mapping[event_type][1]]
            
    return events


def events_query(client: DynatraceClient, args: dict, event_type: str):
    """Calls the relevant api to get events of event_type type according to the args

    Args:
        client (DynatraceClient): client
        args (dict): A dictionary containing the arguments such as amp_limit or apm_from so we can call the api with the right query.
        event_type (str): "APM" or "Audit logs".

    Returns:
        The response from the api.
    """
    query_lst = []
    query = ""
    
    if event_type == "Audit logs":
        audit_limit = args.get("audit_limit")
        if audit_limit:
            query_lst.append(f"pageSize={audit_limit}")
        audit_from = args.get("audit_from")
        if audit_from:
            query_lst.append(f"from={audit_from}")
        if query_lst:
            query="?"+"&".join(query_lst)
        response = client.get_audit_logs_events(query)
    
    elif event_type == "APM":
        apm_limit = args.get("apm_limit")
        if apm_limit:
            query_lst.append(f"pageSize={apm_limit}")
        apm_from = args.get("apm_from")
        if apm_from:
            query_lst.append(f"from={apm_from}")
        if query_lst:
            query="?"+"&".join(query_lst)
        response = client.get_APM_events(query)
    return response


def fetch_apm_events(client, limit, fetch_start_time):
    """Fetches events of APM type from fetch_start_time and not more than the limit given.
    """
    # last_apm_run should look like this: {"nextPageKey": val, "last_timestamp": val}
    integration_cnx = demisto.getIntegrationContext()
    last_run = integration_cnx.get("last_apm_run") or {}

    last_run_to_save = {}
    events_to_return = []
    events_count = 0
    args = {}
    if last_run == {}:
        args["apm_from"] = fetch_start_time
    
    while min(limit-events_count, 1000) != 0:  # We didn't get to the limit needed, need to fetch more events
        
        args["apm_limit"] = min(limit-events_count, 1000)  # The api can bring up to 1000 events per call
                
        if last_run.get("nextPageKey"):
            args["apm_next_page_key"] = last_run["nextPageKey"]
        elif not args.get("apm_from"):
            args["apm_from"] = last_run["last_timestamp"]
            
        demisto.debug(f"{LOG_PREFIX} fetch APM. calling events_query with {args=}")
        response = events_query(client, args, "APM")
        events = response.get('events')
        demisto.debug(f"{LOG_PREFIX} fetch APM. got {len(events)} events from api")
        
        # dedup
        if last_run.get("last_timestamp") and response["totalCount"] != 0:  # If we did according to nextPageKey we for sure didn't get any duplicates
            for i in range(len(events)):
                if events[-i-1]["eventId"] not in last_run["last_events_ids"]:
                    events = events[0:-i]
                    demisto.debug(f"{LOG_PREFIX} deduped {i} events")
                    break
                if i==len(events) -1:
                    events = []
                    demisto.debug(f"{LOG_PREFIX} deduped all events")
                    break
        
        events_count += len(events)
            
        if response.get("nextPageKey"):
            demisto.debug(f"{LOG_PREFIX} fetch APM. setting last run with nextPageKey= {response['nextPageKey']}")
            last_run_to_save["nextPageKey"] = response["nextPageKey"]
            last_run_to_save["last_timestamp"] = None  # This timestamp won't be relevant at the next run.
            last_run_to_save["last_events_ids"] = None
        else:
            last_run_to_save["last_timestamp"] = response.get("events")[0]["startTime"] if response["totalCount"] != 0 \
                                                              else (last_run.get("last_timestamp") or fetch_start_time)
            demisto.debug(f"{LOG_PREFIX} fetch APM. setting last run with timestamp=\
                {last_run_to_save['last_timestamp']} and with last_events_ids")
            last_run_to_save["nextPageKey"] = None
            # All event ids that have the last timestamp, might be returned again at the next run and will need to be deduped.
            last_run_to_save["last_events_ids"] = \
                [event["eventId"] for event in response["events"] if event["startTime"] == last_run_to_save["last_timestamp"]]

        last_run = last_run_to_save
        args = {}
        
        if len(events) == 0 and not response.get("nextPageKey"):
            if response["totalCount"] !=0:
                demisto.debug("We deduped all events. Since we have no nextPageKey,\
                    we will reach an endless loop so we are breaking while loop")
            else:
                demisto.debug("Got no events in response, breaking while loop")
            break
        
        events = add_fields_to_events(events, "APM")
        events_to_return.extend(events)
    
    demisto.debug(f"{LOG_PREFIX} fetch APM out of loop. setting last_apm_run in integration context to {last_run_to_save}")
    integration_cnx["last_apm_run"] = last_run_to_save
    set_integration_context(integration_cnx)
    
    return events_to_return
                

def fetch_audit_log_events(client, limit, fetch_start_time):
    """Fetches events of Audit logs type from fetch_start_time and not more than the limit given.
    """
    
    # last_audit_run should be None or a {"nextPageKey": val, "last_timestamp": val}
    integration_cnx = demisto.getIntegrationContext()
    last_run = integration_cnx.get("last_audit_run") or {}

    last_run_to_save = {}
    events_to_return = []
    events_count = 0
    args = {}
    # First time fetching
    if last_run == {}:
        args["audit_from"] = fetch_start_time

    while min(limit-events_count, 5000) != 0:  # We didn't get to the limit needed, need to fetch more events
        
        args["audit_limit"] = min(limit-events_count, 5000)  # The api can return up to 5000 events per call
            
        if last_run.get("nextPageKey"):
            args["audit_next_page_key"] = last_run["nextPageKey"]
        elif not args.get("audit_from"):
            args["audit_from"] = last_run["last_timestamp"]
                
            
        demisto.debug(f"{LOG_PREFIX} fetch audit logs. calling query with {args=}")
        response = events_query(client, args, "Audit logs")
        events = response.get("auditLogs")
        demisto.debug(f"{LOG_PREFIX} fetch audit logs. got {len(events)} events from api")
        
        # dedup
        if last_run.get("last_timestamp") and response["totalCount"] != 0:
            for i in range(len(events)):
                if events[-i-1]["logId"] not in last_run["last_events_ids"]:
                    events = events[0:-i]
                    demisto.debug(f"{LOG_PREFIX} deduped {i} events")
                    break
                if i == len(events)-1:
                    events = []
                    demisto.debug(f"{LOG_PREFIX} deduped all events")
                    break
        
        events_count += len(events)
            
        if response.get("nextPageKey"):
            demisto.debug(f"{LOG_PREFIX} fetch audit logs. setting last run with nextPageKey= {response['nextPageKey']}")
            last_run_to_save["nextPageKey"] = response["nextPageKey"]
            last_run_to_save["last_timestamp"] = None  # This timestamp won't be relevant at the next run.
            last_run_to_save["last_events_ids"] = None
        else:
            last_run_to_save["last_timestamp"] = response.get("auditLogs")[0]["timestamp"] if response["totalCount"] != 0\
                else (last_run.get("last_timestamp") or fetch_start_time)
            demisto.debug(f"{LOG_PREFIX} fetch audit logs. setting last run with timestamp= {last_run_to_save['last_timestamp']}")
            last_run_to_save["nextPageKey"] = None  # This nextPageKey won't be relevant at the next run.
            last_run_to_save["last_events_ids"] = \
                [event['logId'] for event in response["auditLogs"] if event["timestamp"] == last_run_to_save["last_timestamp"]]
               
        last_run = last_run_to_save
        args = {}
        
        if len(events) == 0 and not response.get("nextPageKey"):
            if response["totalCount"] != 0:
                demisto.debug("We deduped all events. Since we have no nextPageKey,\
                    we will reach an endless loop so we are breaking while loop")
            else:
                demisto.debug("Got no eevents in response, breaking while loop")
            break
        
        events = add_fields_to_events(events, "Audit logs")
        events_to_return.extend(events)

        
    
    demisto.debug(f"{LOG_PREFIX} fetch Audit logs out of loop. setting last_audit_run to {last_run_to_save}")
    integration_cnx["last_audit_run"] = last_run_to_save
    set_integration_context(integration_cnx)
    
    return events_to_return


""" COMMAND FUNCTIONS """

def fetch_events(client: DynatraceClient, events_to_fetch: list, events_limits: dict[str, int]):
    """Gets events from the fetching functions, adds the events the relevant fields and sends the events to XSIAM.

    Args:
        client (DynatraceClient): client
        events_to_fetch (list): list of events types to fetch
        events_limit: dict[str, int]: limit of events to fetch by event type
    """
    fetch_start_time = int(datetime.now().timestamp() * 1000)  # We want this timestamp to look like this: 1737656746001
    demisto.debug(f"{LOG_PREFIX} fetch start time is {fetch_start_time}")
    
    events_to_send = []
    events_fetch_function = {"APM": fetch_apm_events, "Audit logs": fetch_audit_log_events}
    for event_type in events_to_fetch:
            demisto.debug(f"Fetching: {event_type} with limit {events_limits[event_type]}")
            events = events_fetch_function[event_type](client, events_limits[event_type], fetch_start_time)
            events_to_send.extend(events)
  
    
    demisto.debug(f"{LOG_PREFIX} sending {len(events_to_send)} to xsiam")
    send_events_to_xsiam(events_to_send, VENDOR, PRODUCT)


def get_events_command(client: DynatraceClient, args: dict):
    """Gets Dynatrace events according to the arguments given.
    """
    events_types = argToList(args.get("events_types_to_get"))
    events_to_return = []
            
    for event_type in events_types:
        demisto.debug(f"{LOG_PREFIX} calling {event_type} api with {args=}")
        response = events_query(client, args, event_type)
        events = response[EVENTS_TYPE_DICT[event_type]]
        demisto.debug(f"{LOG_PREFIX} got {len(events)} events of type {event_type}")
        events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type]], event_type)
        events_to_return.extend(events)
    
    if args["should_push_events"]:
        demisto.debug(f"{LOG_PREFIX} sending events to xsiam")
        send_events_to_xsiam(events=events_to_return, vendor=VENDOR, product=PRODUCT)
    
    if events_to_return!=[]:
        return CommandResults(readable_output=tableToMarkdown(name='Events', t=events_to_return))
    else:
        return CommandResults(readable_output="No events were received")


def test_module(client: DynatraceClient, events_to_fetch: List[str], audit_limit, apm_limit) -> str:
    
    validate_params(events_to_fetch, audit_limit, apm_limit)
    
    try:
        if "Audit logs" in events_to_fetch:
            client.get_audit_logs_events("?pageSize=1")
        if "APM" in events_to_fetch:
            client.get_APM_events("?pageSize=1")
    
    except Exception as e:
        raise DemistoException (str(e).lower())
    
    return "ok"


def main():  # pragma: no cover
    
    """main function, parses params and runs command functions"""
    
    params = demisto.params()
    url = params.get("url")
    token = params.get('token')
    events_to_fetch = argToList(params.get('events_to_fetch'))
    audit_limit = arg_to_number(params.get('audit_limit'))  or 25000
    apm_limit = arg_to_number(params.get('apm_limit'))  or 7000
    
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    
    command = demisto.command()
    
    demisto.debug(f"Command being called is {command}")
    
    try:
        
        client = DynatraceClient(url, token, verify, proxy)
        
        args = demisto.args()
        
        if command == "test-module":
            result = test_module(client, events_to_fetch, audit_limit, apm_limit)
            return_results(result)
        elif command == "dynatrace-get-events":
            result = get_events_command(client, args)
            return_results(result)
        elif command == "fetch-events":
            fetch_events(client, events_to_fetch, {"Audit logs": audit_limit, "APM": apm_limit})
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"{LOG_PREFIX} Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()