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


""" CLIENT CLASS """

class DynatraceClient(BaseClient):
    def __init__(self, base_url, token, verify, proxy):
        super().__init__(proxy=proxy, base_url=base_url, verify=verify, headers={"Authorization": f"Api-Token {token}"})
            
            
    def get_audit_logs_events(self, query: str=""):
        return self._http_request("GET", "/api/v2/auditlogs"+query, headers=self._headers)
    
    
    def get_APM_events(self, query: str=""):
        return self._http_request("GET", "/api/v2/events"+query, headers=self._headers)


""" HELPER FUNCTIONS """

def validate_params(url, token, events_to_fetch, audit_max, apm_max):
    
    if not events_to_fetch:
        raise DemistoException("Please specify at least one event type to fetch.")
    if audit_max < 1 or audit_max > 25000:
        raise DemistoException("The maximum number of audit logs events per fetch needs to be grater then 0 and not more then then 25000")
    if apm_max < 1 or apm_max > 5000:
        raise DemistoException("The maximum number of APM events per fetch needs to be grater then 0 and not more then then 5000")


def add_fields_to_events(events, event_type):
    
    # TODO ask sara if we need the word 'events' in the end of the type, I don't think we usually do so.
    
    field_mapping = {
        "Audit logs": ["Audit logs events", "timestamp"],
        "APM": ["APM events", "startTime"]
    
    }
    for event in events:
            event["SOURCE_LOG_TYPE"] = field_mapping[event_type][0]
            event["_time"] = event[field_mapping[event_type][1]]
            
    return events


def events_query(client: DynatraceClient, args: dict, event_type: str):
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
    
    # last_apm_run should be None or a {"nextPageKey": val, "last_timestamp": val}
    integration_cnx = demisto.getIntegrationContext()
    last_run = integration_cnx.get("last_apm_run") or {}

    last_run_to_save = {}
    events_to_return = []
    events_count = 0
    args = {}
    
    for i in range(5):  # Design says we will do at most five calls every fetch_interval so we can get more events per fetch
        args["apm_limit"] = min(limit-events_count, 1000)  # The api can bring up to 1000 events per call
            
        if args["apm_limit"] != 0:  # We didn't get to the limit needed, need to fetch more events
            
            # First time fetching
            if last_run == {}:
                args["apm_from"] = fetch_start_time
                
            else:
                if last_run.get("nextPageKey"):
                    args["apm_next_page_key"] = last_run["nextPageKey"]
                else:
                    # If the previous run did not return a nextPageKey, it indicates there are no more events
                    # with the same timestamp as the last_timestamp from the previous run.
                    # Therefore, we query for events starting from last_timestamp + 1 millisecond
                    # to avoid retrieving the same events as the previous run.
                    # This approach eliminates the need for deduplication.
                    args["apm_from"] = last_run["last_timestamp"] + 1
            
            demisto.debug(f"Dynatrace fetch APM {i+1} times in loop. calling query with {args=}")
            response = events_query(client, args, "APM")
            num_events = len(response.get("events"))
            events_count += num_events
            demisto.debug(f"Dynatrace fetch APM {i+1} times in loop. got {num_events} events")
            
            # TODO need to see what happens if we get no events is response.get("events") empty or None?
            if response.get("nextPageKey"):
                demisto.debug(f"Dynatrace fetch APM {i+1} times in loop. setting last run with nextPageKey")
                last_run_to_save["nextPageKey"] = response["nextPageKey"]
                last_run_to_save["last_timestamp"] = None  # This timestamp won't be relevant at the next run.
            else:
                demisto.debug(f"Dynatrace fetch APM {i+1} times in loop. setting last run with timestamp")
                # If events were retrieved during this run (which might not always happen),
                # we save the last timestamp from this run.
                # If no events were retrieved, we retain the same last_timestamp as before,
                # In cases where no events were retrieved and this is the first run (i.e., no last_run_timestamp exists),
                # the query will use start_fetch_time again in the next execution.
                last_run_to_save["last_timestamp"] = response.get("events")[0]["startTime"] if response["totalCount"] != 0 else (last_run.get("last_timestamp") or fetch_start_time)
                last_run_to_save["nextPageKey"] = None
                
            events = response.get("events")
            events = add_fields_to_events(events, "APM")
            events_to_return.extend(events)

        last_run = last_run_to_save
        args = {}
    
    demisto.debug(f"Dynatrace fetch APM ou of loop. setting last_apm_run to {last_run_to_save}")
    integration_cnx["last_apm_run"] = last_run_to_save
    set_integration_context(integration_cnx)
    
    return events_to_return
                

def fetch_audit_log_events(client, limit, fetch_start_time):
    
    # last_audit_run should be None or a {"nextPageKey": val, "last_timestamp": val}
    integration_cnx = demisto.getIntegrationContext()
    last_run = integration_cnx.get("last_audit_run") or {}

    last_run_to_save = {}
    events_to_return = []
    events_count = 0
    args = {}

    for i in range(5):  # Design says we will do at most five calls every fetch_interval so we can get more events per fetch
        args["audit_limit"] = min(limit-events_count, 5000)  # The api can return up to 5000 events per call
            
        if args["audit_limit"] != 0:  # We didn't get to the limit needed, need to fetch more events
            
            # First time fetching
            if last_run == {}:
                args["audit_from"] = fetch_start_time
                
            else:
                if last_run.get("nextPageKey"):
                    args["audit_next_page_key"] = last_run["nextPageKey"]
                else:
                    # If the previous run did not return a nextPageKey, it indicates there are no more events
                    # with the same timestamp as the last_timestamp from the previous run.
                    # Therefore, we query for events starting from last_timestamp + 1 millisecond
                    # to avoid retrieving the same events as the previous run.
                    # This approach eliminates the need for deduplication.
                    args["audit_from"] = last_run["last_timestamp"] + 1
            
            demisto.debug(f"Dynatrace fetch audit logs {i+1} times in loop. calling query with {args=}")
            response = events_query(client, args, "Audit logs")
            num_events = len(response.get("auditLogs"))
            events_count += num_events
            demisto.debug(f"Dynatrace fetch audit logs {i+1} times in loop. got {num_events} events")
            
            if response.get("nextPageKey"):
                demisto.debug(f"Dynatrace fetch audit logs {i+1} times in loop. setting last run with nextPageKey")
                last_run_to_save["nextPageKey"] = response["nextPageKey"]
                last_run_to_save["last_timestamp"] = None  # This timestamp won't be relevant at the next run.
            else:
                demisto.debug(f"Dynatrace fetch audit logs {i+1} times in loop. setting last run with timestamp")
                # If events were retrieved during this run (which might not always happen),
                # we save the last timestamp from this run.
                # If no events were retrieved, we retain the same last_timestamp as before,
                # In cases where no events were retrieved and this is the first run (i.e., no last_run_timestamp exists),
                # the query will use start_fetch_time again in the next execution.
                last_run_to_save["last_timestamp"] = response.get("auditLogs")[0]["timestamp"] if response["totalCount"] != 0 else (last_run.get("last_timestamp") or fetch_start_time)
                last_run_to_save["nextPageKey"] = None  # This nextPageKey won't be relevant at the next run.
                
            events = response.get("auditLogs")
            events = add_fields_to_events(events, "Audit logs")
            events_to_return.extend(events)

        last_run = last_run_to_save
        args = {}
    
    demisto.debug(f"Dynatrace fetch Audit logs out of loop. setting last_audit_run to {last_run_to_save}")
    integration_cnx["last_audit_run"] = last_run_to_save
    set_integration_context(integration_cnx)
    
    return events_to_return


""" COMMAND FUNCTIONS """

def fetch_events(client: DynatraceClient, events_to_fetch: list, audit_limit: int, apm_limit: int):
    
    fetch_start_time = int(datetime.now().timestamp() * 1000)  # We want this timestamp to look like this: 1737656746001
    demisto.debug(f"Dynatrace fetch Audit Logs events start time is {fetch_start_time}")
    
    events_to_send = []
    if "APM" in events_to_fetch:
        events = fetch_apm_events(client, apm_limit, fetch_start_time)
        events = add_fields_to_events(events, "APM")
        events_to_send.extend(events)
    if "Audit logs" in events_to_fetch:
        events = fetch_audit_log_events(client, audit_limit, fetch_start_time)
        events = add_fields_to_events(events, "Audit logs")
        events_to_send.extend(events)
    
    demisto.debug(f"Dynatrace sending {len(events_to_send)} to xsiam")
    send_events_to_xsiam(events_to_send, VENDOR, PRODUCT)


def get_events_command(client: DynatraceClient, args: dict):
    
    events_types = argToList(args.get("events_types_to_get"))
    events_to_return = []
            
    for event_type in events_types:
        response = events_query(client, args, event_type)
        events = response[EVENTS_TYPE_DICT[event_type]]
        demisto.debug(f"Dynatrace got {len(events)} events of type {event_type}")
        events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type]], event_type)
        events_to_return.extend(events)
    
    if args["should_push_events"]:
        demisto.debug("Dynatrace sending events to xsiam")
        send_events_to_xsiam(events=events_to_return, vendor=VENDOR, product=PRODUCT)
    
    if events_to_return!=[]:
        return CommandResults(readable_output=tableToMarkdown(name='Events', t=events_to_return))
    else:
        return CommandResults(readable_output="No events were received")


def test_module(client: DynatraceClient, events_to_fetch: List[str]) -> str:

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
    apm_limit = arg_to_number(params.get('apm_limit'))  or 25000
    
    validate_params(url, token, events_to_fetch, audit_limit, apm_limit)
    
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    
    command = demisto.command()
    
    demisto.debug(f"Command being called is {command}")
    
    try:
        
        client = DynatraceClient(url, token, verify, proxy)
        
        args = demisto.args()
        
        if command == "test-module":
            result = test_module(client, events_to_fetch)
            return_results(result)
        elif command == "dynatrace-get-events":
            result = get_events_command(client, args)
            return_results(result)
        elif command == "fetch-events":
            fetch_events(client, events_to_fetch, audit_limit, apm_limit)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()