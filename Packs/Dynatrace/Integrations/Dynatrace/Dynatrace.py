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
EVENTS_TYPE_DICT = {"Audit logs": ("auditLogs", "audit"), "APM": ("events", "apm")}
FIELD_MAPPING = {
        "Audit logs": ["Audit logs events", "timestamp"],
        "APM": ["APM events", "startTime"]
    }


""" CLIENT CLASS """

class DynatraceClient(BaseClient):
    def __init__(self, base_url, client_id, client_secret, uuid,
             token, events_to_fetch, verify, proxy):
        super().__init__(proxy=proxy, base_url=base_url, verify=verify)
        self.client_id = client_id
        self.client_secret = client_secret
        self.uuid = uuid
        self.token = token
        self.auth2_token = None
        
        if not self.token:  # We are using OAuth2 authentication
            self.auth2_token = self.create_auth2_token(events_to_fetch)
        
        if self.auth2_token:
            self._headers = {"Authorization": f"Bearer {self.auth2_token}"}
        else:
            self._headers = {"Authorization": f"Api-Token {self.token}"}
        
        
    def create_auth2_token(self, events_to_fetch):
        
        scopes = []
        
        if "Audit logs" in events_to_fetch:
            scopes.append("auditLogs.read")
        if "APM" in events_to_fetch:
            scopes.append("events.read")
        
        params = assign_params(
            grant_type = "client_credentials",
            client_id = self.client_id,
            client_secret = self.client_secret,
            scope = " ".join(scopes),
            resource = f"urn:dtaccount:{self.uuid}"
        )
        
        raw_response = self._http_request(
            method='POST',
            url_suffix="https://sso.dynatrace.com/sso/oauth2/token",
            json_data=params,
            headers=self._headers
        )
        
        return raw_response  # TODO test how response returns and return the token within it
    
    
    def get_audit_logs_events(self, query: str=""):
        url = "/api/v2/auditlogs"+query
        return self._http_request("GET", url, headers=self._headers)
    
    
    def get_APM_events(self, query: str=""):
        return self._http_request("GET", "/api/v2/events"+query, headers=self._headers)


""" HELPER FUNCTIONS """

def validate_params(url, client_id, client_secret, uuid, token, events_to_fetch, audit_max, apm_max):
    
    if not ((client_id and client_secret and uuid and not token) or (token and not client_id and not client_secret and not uuid)):
        raise DemistoException("When using OAuth 2, ensure to specify the client ID, client secret, and Account UUID. When using a personal access token, make sure to specify the access token. It's important to include only the required parameters for each type and avoid including any extra parameters.")
    if not events_to_fetch:
        raise DemistoException("Please specify at least one event type to fetch.")
    if not audit_max > 0 and not audit_max <= 2500:
        raise DemistoException("The maximum number of audit logs events per fetch needs to be grater then 0 and not more then then 25000")
    if not apm_max > 0 and not apm_max <= 25000:
        raise DemistoException("The maximum number of APM events per fetch needs to be grater then 0 and not more then then 5000")


""" COMMAND FUNCTIONS """


def fetch_apm_events(client, limit):
    # last_apm_run should be None or a {"nextPageKey": val, "last_timestamp": val}
    integration_cnx = demisto.getIntegrationContext()
    last_run = integration_cnx.get("last_apm_run") or {}

    last_run_to_save = {}
    events_to_return = []
    events_count = 0
    args = {}
    fetch_start_time = datetime.now()
    
    for _ in range(5):  # Design says we will do at most five calls every fetch_interval so we can get more events per fetch
        args["apm_limit"] = min(limit-events_count, 1000)
            
        if args["apm_limit"] != 0:  # We didn't get to the limit needed, need to fetch more events
            
            if not last_run:  # First time fetching
                args["apm_from"] = "now-1w"  # Change to "now" after I finish testing
            
            else:  # Not first fetch
                if last_run["nextPageKey"]:
                    args["apm_next_page_key"] = last_run["nextPageKey"]
                else:
                    args["apm_from"] = last_run["last_timestamp"]#+one mili second # Need to implement this
            
            response = events_query(client, args, "APM")
            # TODO need to see what happens if we get no events is respone.get("events") empty or None?
            if response.get("nextPageKey"):
                last_run_to_save["nextPageKey"] = response["nextPageKey"]
                last_run_to_save["last_timestamp"] = None
            else:
                last_run_to_save["last_timestamp"] = response.get("events")[0]["startTime"] or last_run.get("last_timestamp") or fetch_start_time#-1 mili second  # Need to implement
                last_run_to_save["nextPageKey"] = None
                
            events = response.get("events")
            events = add_fields_to_events(events, "APM")
            events_to_return.extend(events)

        last_run["last_apm_run"] = last_run_to_save
    
    integration_cnx["last_apm_run"] = last_run_to_save
    set_integration_context(integration_cnx)
    
    return events_to_return
                


def fetch_events(client: DynatraceClient, events_to_fetch: list, audit_limit: int, apm_limit: int):
    events_to_send = []
    if "APM" in events_to_fetch:
        events = fetch_apm_events(client, apm_limit)
        events_to_send.extend(events)
    if "Audit Logs" in events_to_fetch:
        events = fetch_audit_events(client, apm_limit)
        events_to_send.extend(events)
    return events_to_send
    
        
    
    # integration_context = demisto.getIntegrationContext()
    
    # integration_context_to_save = {}
    # events_to_return = []
    # audit_count, apm_count = 0, 0
    
    # args = {}
    
    # for _ in range(0, 5):
        
    #     args["audit_limit"] = min(audit_limit-audit_count, 5000)
    #     args["apm_limit"] = min(apm_limit-apm_count, 1000)
        
    #     for event_type in events_to_fetch:
            
    #         # set args
    #         if not integration_context.get(f"{events_to_fetch[0]}_last_timestamp"):  # first fetch
    #             args[EVENTS_TYPE_DICT[event_type][1]+"_from"] = "now-1d"
    #         else:
    #             args[EVENTS_TYPE_DICT[event_type][1]+"_from"] = integration_context.get(EVENTS_TYPE_DICT[event_type][1]+"_last_timestamp")
        
            
    #         if args[EVENTS_TYPE_DICT[event_type][1]+"_limit"] != 0:
    #             response = events_query(client, args, event_type)
                
    #             #dedup
    #             counter = 0
    #             for i in range(len(response[EVENTS_TYPE_DICT[event_type][0]])):
    #                 if response[EVENTS_TYPE_DICT[event_type][0]][i]["entityId"] in integration_context.get(f"{events_to_fetch[0]}_last_events_ids"):
    #                     continue
    #                 else:
    #                     counter = i+1
    #                     break
                        
    #             while counter == len(response[EVENTS_TYPE_DICT[event_type][0]]):
    #                 if response.get("nextPageKey"):
    #                     integration_context_to_save[EVENTS_TYPE_DICT[event_type][1]+"_last_run"] = (response.get("nextPageKey"), None)
    #                 else:
    #                     integration_context_to_save[EVENTS_TYPE_DICT[event_type][1]+"_last_timestamp"] = (None, response[EVENTS_TYPE_DICT[event_type][0]][0][FIELD_MAPPING[event_type][1]])
    #                 response = events_query(client, args, event_type)
                   
    #                 #dedup
    #                 counter = 0
    #                 for i in range(len(response[EVENTS_TYPE_DICT[event_type][0]])):
    #                     if response[EVENTS_TYPE_DICT[event_type][0]][i]["entityId"] in integration_context.get(f"{events_to_fetch[0]}_last_events_ids"):
    #                         continue
    #                     else:
    #                         counter = i+1
    #                         break
                
    #             events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type][0]], event_type)
    #             events_to_return.extend(events)
    #             if event_type == "APM":
    #                 apm_count += len(events)
    #             else:
    #                 audit_count += len(events)
    #             integration_context_to_save[EVENTS_TYPE_DICT[event_type][1]+"_next_page"] = response["nextPageKey"]  # TODO what happens when there are no more events? Do we still gat a nextPageKey? If not we need to go out of the loop, need to check this use case
        
    #     set_integration_context(integration_context_to_save)
        
    # return events_to_return


def add_fields_to_events(events, event_type):
    # Need to convert the dates to the right format
    # TODO ask sara if we need the word 'events' in the end of the type, I don't think we usually do so.
    
    for event in events:
            event["SOURCE_LOG_TYPE"] = FIELD_MAPPING[event_type][0]
            event["_time"] = event[FIELD_MAPPING[event_type][1]]
            
    return events


def get_events_command(client: DynatraceClient, args: dict):
    
    events_types = argToList(args.get("events_types_to_get"))
    events_to_return = []
            
    for event_type in events_types:
        response = events_query(client, args, event_type)
        events = response[EVENTS_TYPE_DICT[event_type][0]]
        events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type][0]], event_type)
        events_to_return.extend(events)
    
    if args.get("should_push_events"):
        send_events_to_xsiam(events=events_to_return, vendor=VENDOR, product=PRODUCT)
    
    return CommandResults(readable_output=tableToMarkdown(name='Events', t=events_to_return))


def test_module(client: DynatraceClient, events_to_fetch: List[str]) -> str:

    try:
        if "Audit logs" in events_to_fetch:
            client.get_audit_logs_events("?pageSize=1")
        if "APM" in events_to_fetch:
            client.get_APM_events("?pageSize=1")
    
    except Exception as e:
        raise DemistoException (str(e).lower())
    
    return "ok"


def events_query(client: DynatraceClient, args: dict, event_type: str):
    query_lst = []
    query = ""
    #query = "?from=now-1w&pageSize=2"
    if event_type == "Audit logs":
        audit_limit = args.get("audit_limit")
        if audit_limit:
            query_lst.append(f"pageSize={audit_limit}")
        audit_from = args.get("audit_from")
        if audit_from:
            query_lst.append(f"from={audit_from}")
        if query_lst:
            query="?"+"&".join(query_lst)
        response = client.get_audit_logs_events(query)    #"nextPageKey": args.get("Audit logs_next_page")
    
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


def main():
    
    """main function, parses params and runs command functions"""
    
    params = demisto.params()
    url = params.get("url")
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    uuid = params.get('uuid')
    token = params.get('token')
    events_to_fetch = argToList(params.get('events_to_fetch'))
    audit_limit = arg_to_number(params.get('audit_limit'))  or 25000
    apm_limit = arg_to_number(params.get('apm_limit'))  or 25000
    validate_params(url, client_id, client_secret, uuid, token, events_to_fetch, audit_limit, apm_limit)
    
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    
    command = demisto.command()
    
    demisto.debug(f"Command being called is {command}")
    
    try:
        
        client = DynatraceClient(url, client_id, client_secret, uuid, token, events_to_fetch, verify, proxy)
        
        args = demisto.args()
        
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, events_to_fetch)
        elif command == "dynatrace-get-events":
            result = get_events_command(client, args)
        elif command == "fetch-events":
            result = fetch_events(client, events_to_fetch, audit_limit, apm_limit)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )
    
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()