import demistomock as demisto
import urllib3
import traceback
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "DaaS"
OPERATIONS_REQUEST_LIMIT = "1000"
ACCESS_TOKEN_CONST = "access_token"
CONTINUATION_TOKEN_CONST = "continuation_token"
SOURCE_LOG_TYPE = "configlog"

RES_EXAMPLE = {
    "Items": [
        {
            "Id": "0",
            "Text": "string",
            "User": "string",
            "UserIdentity": "string",
            "Source": "string",
            "AdminMachineIP": "string",
            "EndTime": "2024-01-02T13:22:36.848+00:00",
            "FormattedEndTime": "2024-01-02T13:22:36Z",
            "StartTime": "2024-01-02T13:22:36.614+00:00",
            "FormattedStartTime": "2025-09-03T13:22:36Z",
            "IsSuccessful": True,
            "TargetTypes": ["string"],
            "OperationType": "Unknown",
            "Labels": ["string"],
            "Metadata": [{"Name": "Name", "Value": "Value"}],
            "Parameters": [{"Name": "Name", "Value": "Value"}],
        },
        {
            "Id": "1",
            "Text": "string",
            "User": "string",
            "UserIdentity": "string",
            "Source": "string",
            "AdminMachineIP": "string",
            "EndTime": "2024-01-02T13:22:36.848+00:00",
            "FormattedEndTime": "2024-01-02T13:22:36Z",
            "StartTime": "2024-01-02T13:22:36.614+00:00",
            "FormattedStartTime": "2025-09-03T13:22:36Z",
            "IsSuccessful": True,
            "TargetTypes": ["string"],
            "OperationType": "Unknown",
            "Labels": ["string"],
            "Metadata": [{"Name": "Name", "Value": "Value"}],
            "Parameters": [{"Name": "Name", "Value": "Value"}],
        },
        {
            "Id": "2",
            "Text": "string",
            "User": "string",
            "UserIdentity": "string",
            "Source": "string",
            "AdminMachineIP": "string",
            "EndTime": "2024-01-02T13:22:36.848+00:00",
            "FormattedEndTime": "2024-01-02T13:22:36Z",
            "StartTime": "2024-01-02T13:22:36.614+00:00",
            "FormattedStartTime": "2025-09-03T13:22:36Z",
            "IsSuccessful": True,
            "TargetTypes": ["string"],
            "OperationType": "Unknown",
            "Labels": ["string"],
            "Metadata": [{"Name": "Name", "Value": "Value"}],
            "Parameters": [{"Name": "Name", "Value": "Value"}],
        },
        {
            "Id": "3",
            "Text": "string",
            "User": "string",
            "UserIdentity": "string",
            "Source": "string",
            "AdminMachineIP": "string",
            "EndTime": "2024-01-02T13:22:36.848+00:00",
            "FormattedEndTime": "2024-01-02T13:22:36Z",
            "StartTime": "2024-01-02T13:22:36.614+00:00",
            "FormattedStartTime": "2025-09-03T13:22:36Z",
            "IsSuccessful": True,
            "TargetTypes": ["string"],
            "OperationType": "Unknown",
            "Labels": ["string"],
            "Metadata": [{"Name": "Name", "Value": "Value"}],
            "Parameters": [{"Name": "Name", "Value": "Value"}],
        },
    ],
    "ContinuationToken": "string",
    "TotalItems": 0,
}


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self, base_url: str, customer_id: str, client_id: str, client_secret: str, instance_id: str, proxy: bool, verify: bool
    ):
        self.base_url = base_url
        self.customer_id = customer_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.instance_id = instance_id
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def request_access_token(self):
        # TODO: remove
        demisto.setIntegrationContext({ACCESS_TOKEN_CONST: "access_token"})
        return

        demisto.debug("prepare to create access token")

        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}

        data = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}

        token_res = self._http_request(
            "post", url_suffix=f"/cctrustoauth2/{self.customer_id}/tokens/clients", headers=headers, data=data
        )

        access_token = token_res["access_token"]
        demisto.setIntegrationContext({ACCESS_TOKEN_CONST: access_token})
        demisto.debug("access token created")
        return access_token

    def get_operations(self, search_date_option="LastMinute", continuation_token=None):
        # get access token value
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)
        if not access_token:
            access_token = self.request_access_token()

        # set request params
        params = {"searchDateOption": search_date_option, "limit": OPERATIONS_REQUEST_LIMIT, "async": "false"}
        if continuation_token:
            params["continuationToken"] = continuation_token

        headers = {
            "Authorization": f"CwsAuth Bearer={access_token}",
            "accept": "application/json",
            "Citrix-CustomerId": self.customer_id,
            "Citrix-InstanceId": self.instance_id,
            "User-Agent": "Mozilla/5.0",
            "Citrix-Locale": "en-US",
        }

        # TODO: remove
        return RES_EXAMPLE

        demisto.info(f"Sending http request to get operations with {params=}")
        response = self._http_request(
            "get", url_suffix="cvad/manage/ConfigLog/Operations", headers=headers, params=params, ok_codes=[200, 202, 401]
        )

        if response.status_code == 401:
            demisto.info("Invalid bearer token")
            self.request_access_token()
            access_token = integration_context.get(ACCESS_TOKEN_CONST)
            headers["Authorization"] = (f"CwsAuth Bearer={access_token}",)
            demisto.info(f"Sending http request to get operations with {params=}")
            return self._http_request("get", url_suffix="cvad/manage/ConfigLog/Operations", headers=headers, params=params)
        else:
            return response

    def get_operations_with_pagination(self, limit, search_date_option="LastMinute", continuation_token=None):
        operations: list[dict] = []

        while len(operations) <= limit:
            raw_res = self.get_operations(continuation_token, search_date_option)
            operations.extend(raw_res.get("Items", []))
            continuation_token = raw_res.get("ContinuationToken")

            if not continuation_token:
                break

        self.add_fields_to_events(operations)
        return operations[:limit], raw_res, continuation_token

    def add_fields_to_events(self, events: list[dict]):
        for event in events:
            event["source_log_type"] = SOURCE_LOG_TYPE
            event["_time"] = event.get("FormattedStartTime")


""" HELPER FUNCTIONS """


def get_events_command(client: Client, args: dict):  # type: ignore
    limit = args.get("limit", "100")
    search_date_option = args.get("search_date_option", "LastMinute")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-daas-get-events with {should_push_events=}")

    operations, raw_res, _ = client.get_operations_with_pagination(limit=int(limit), search_date_option=search_date_option)

    results = CommandResults(
        outputs_prefix="CitrixDaas.Event",
        outputs_key_field="Id",
        outputs=operations,
        readable_output=tableToMarkdown("Events List", operations),
        raw_response=raw_res,
    )

    if should_push_events:
        demisto.debug(f"send {len(operations)} events to xsiam")
        send_events_to_xsiam(operations, vendor=VENDOR, product=PRODUCT)

    return results


def fetch_events_command(client: Client, max_fetch: int, last_run: dict):
    operations, _, continuation_token = client.get_operations_with_pagination(
        limit=max_fetch, search_date_option="LastMinute", continuation_token=last_run.get(CONTINUATION_TOKEN_CONST)
    )
    return operations, {CONTINUATION_TOKEN_CONST: continuation_token}


def test_module(client: Client, args: dict):
    get_events_command(client, args)
    return "ok"


""" MAIN FUNCTION """


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=params.get("url"),
            customer_id=params.get("customer_id"),
            client_id=params.get("client_id"),
            client_secret=params.get("credentials", {}).get("password"),
            instance_id=params.get("instance_id"),
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
        )

        if command == "test-module":
            result = test_module(client, args)
            return_results(result)

        elif command == "citrix-daas-get-events":
            results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            max_fetch = int(params.get("max_fetch", "10000"))
            last_run = demisto.getLastRun()
            demisto.debug(f"last run is: {last_run}")

            events, last_run = fetch_events_command(client, max_fetch, last_run)

            demisto.debug(f"send {len(events)} events to xsiam")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)
            demisto.debug(f"Last run set to: {last_run}")

    except Exception as e:
        demisto.error(f"{type(e).__name__} in {command}: {str(e)}\nTraceback:\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
