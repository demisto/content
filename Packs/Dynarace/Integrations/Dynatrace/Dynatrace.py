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
EVENTS_TYPE_DICT = {"Vulnerability": ("securityProblems", "vul_limit"), "Audit logs": ("auditLogs", "audit_limit"), "APM": ("events", "apm_limit")}


""" CLIENT CLASS """

class Client(BaseClient):
    def init(self, base_url: str, client_id: str, client_secret: str, uuid: str, token: str, events_to_fetch: List[str], verify: bool, proxy):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id,
        self.client_secret = client_secret,
        self.uuid = uuid,
        self.token = token
        self.personal_token = None
        if not self.token:  # We are using OAuth2 authentication
            self.personal_token = self.create_personal_token(events_to_fetch)
        self._headers = {"Authorization": f"Api-Token {self.personal_token}" if self.personal_token else f"Bearer {self.token}"}
    def create_personal_token(self, events_to_fetch):
        scopes = []
        if "Vulnerability" in events_to_fetch:
            scopes.append("securityProblems.read")
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
    
    
    def get_vulnerability_events(self, params: dict):
        return self._http_request("GET", "/api/v2/securityProblems", json_data=params, headers=self._headers)
    
    
    def get_audit_logs_events(self, params: dict):
        return self._http_request("GET", "/api/v2/auditlogs", json_data=params, headers=self._headers)
    
    
    def get_APM_events(self, params: dict):
        return self._http_request("GET", "/api/v2/events", json_data=params, headers=self._headers)


""" HELPER FUNCTIONS """

def validate_params(url, client_id, client_secret, uuid, token, events_to_fetch, vul_max, audit_max, apm_max):
    
    if not ((client_id and client_secret and uuid and not token) or (token and not client_id and not client_secret and not uuid)):
        raise DemistoException("When using OAuth 2, ensure to specify the client ID, client secret, and Account UUID. When using a personal access token, make sure to specify the access token. It's important to include only the required parameters for each type and avoid including any extra parameters.")
    if not events_to_fetch:
        raise DemistoException("Please specify at least one event type to fetch.")
    if not vul_max > 0 and not vul_max <= 2500:
        raise DemistoException("Thee maximum number of vulnerability events per fetch needs to be grater than 0 and not more than 2500")
    if not audit_max > 0 and not audit_max <= 2500:
        raise DemistoException("The maximum number of audit logs events per fetch needs to be grater then 0 and not more then then 25000")
    if not apm_max > 0 and not apm_max <= 25000:
        raise DemistoException("The maximum number of APM events per fetch needs to be grater then 0 and not more then then 5000")


""" COMMAND FUNCTIONS """

def fetch_events(client: Client, events_to_fetch: list, vul_limit: int, audit_limit: int, apm_limit: int):
    
    integration_context = demisto.getIntegrationContext()
    
    # first fetch
    if not integration_context:
        pass
        # TODO implement first run, need to specify from for each type and no next page. Maybe the defaulf from of the api is good for us.
    
    integration_context_to_save = {}
    events_to_return = []
    vul_count, audit_count, apm_count = 0, 0, 0
    
    for _ in range(0, 5):
        
        # TODO In the first time integration_context will be empty and there won't be a next page value in it, in this case the query function will not send an empty arg in the json body, the api has a default from date that can be used in the first fetch, need to see what happens when I send a nextPage, the api adds a from date? which one does it look at?
        
        args = {"vul_limit": min(vul_limit-vul_count, 500), "audit_limit": min(audit_limit-audit_count, 5000), "apm_limit": min(apm_limit-apm_count,1000),
          "Vulnerability_next_page": integration_context.get("Vulnerability_next_page"),
          "Audit logs_next_page": integration_context.get("Audit logs_next_page"),
          "APM_next_page": integration_context.get("APM_next_page")}
        
        for event_type in events_to_fetch:
            if args[EVENTS_TYPE_DICT[event_type][1]] != 0:
                response = events_query(client, args, event_type)
                events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type[0]]], event_type)
                events_to_return.extend(events)
                integration_context_to_save[event_type+"_next_page"] = response["nextPageKey"]  # TODO what happens when there are no more events? Do we still gat a nextPageKey? If not we need to go out of the loop, need to check this use case
        
        set_integration_context(integration_context_to_save)
        
    return events_to_return


def add_fields_to_events(events, event_type):
    
    # TODO ask sara if we need the word 'events' in the end of the type, I don't think we usually do so.
    
    field_mapping = {
        "Vulnerability": {"SOURCE_LOG_TYPE": "Vulnerability events", "_time": "firstSeenTimestamp"},
        "Audit logs": {"SOURCE_LOG_TYPE": "Audit logs events", "_time": "timestamp"},
        "APM events": {"SOURCE_LOG_TYPE": "APM events", "_time": "startTime"}
    }
    
    for event in events:
        for key, value in field_mapping[event_type].items():
            event[key] = event[value]
            
    return events


def get_events_command(client: Client, args: dict):
    
    events_types = argToList(args.get("events_types_to_get"))
    events_to_return = []
    
    for event_type in events_types:
        response = events_query(client, args, event_type)
        events = add_fields_to_events(response[EVENTS_TYPE_DICT[event_type[0]]], event_type)
        events_to_return.extend(events)
        # send_events_to_xsiam(events_to_return, vendor=VENDOR, product=PRODUCT) move this to main
    
    return events_to_return  # Make a human readable


def test_module(client: Client, events_to_fetch: List[str]) -> str:
    
    # TODO change this function to use query function
    
    try:
        if "Vulnerability" in events_to_fetch:
            client.get_vulnerability_events({"pageSize": 1})
        if "Audit logs" in events_to_fetch:
            client.get_audit_logs_events({"pageSize": 1})
        if "APM" in events_to_fetch:
            client.get_APM_events({"pageSize": 1})
    
    except Exception as e:
        raise DemistoException (str(e).lower())
    
    return "ok"


def events_query(client: Client, args: dict, event_type: str):
    #
    if event_type == "Vulnerability":
        events = client.get_vulnerability_events({key: value for key, value in {"pageSize": args.get("vul_limit"), "from": args.get("vul_from"), "nextPageKey": args.get("Vulnerability_next_page")}.items() if value})
    elif event_type == "Audit logs":
        events = client.get_audit_logs_events({key: value for key, value in {"pageSize": args.get("audit_limit"), "from": args.get("audit_from"), "nextPageKey": args.get("Audit logs_next_page")}.items() if value})
    elif event_type == "APM":
        events = client.get_audit_logs_events({key: value for key, value in {"pageSize": args.get("apm_limit"), "from": args.get("apm_from"), "nextPageKey": args.get("APM_next_page")}.items() if value})
    # TODO add needed fields for every event with calling a new function
    return events


def main():
    
    """main function, parses params and runs command functions"""
    
    params = demisto.params()
    url = params.get("url")
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    uuid = params.get('uuid')
    token = params.get('token')
    events_to_fetch = argToList(params.get('events_to_fetch'))
    vul_limit = arg_to_number(params.get('vul_limit')) or 1000
    audit_limit = arg_to_number(params.get('audit_limit'))  or 25000
    apm_limit = arg_to_number(params.get('apm_limit'))  or 25000
    validate_params(url, client_id, client_secret, uuid, token, events_to_fetch, vul_limit, audit_limit, apm_limit)
    
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    
    command = demisto.command()
    
    demisto.debug(f"Command being called is {command}")
    
    try:
        
        client = Client(base_url=url, client_id=client_id, client_secret=client_secret, uuid=uuid, token=token, events_to_fetch=events_to_fetch, verify=verify, proxy=proxy)
        
        args = demisto.args()
        
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, events_to_fetch)
        elif command == "dynatrace-get-events":
            result = get_events_command(client, args)
        elif command == "fetch-events":
            result = fetch_events(client, events_to_fetch, vul_limit, audit_limit, apm_limit)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()