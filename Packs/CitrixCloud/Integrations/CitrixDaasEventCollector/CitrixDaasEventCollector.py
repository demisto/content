import demistomock as demisto
import urllib3
import traceback
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "Daas"
# max value
RECORDS_REQUEST_LIMIT = 1000
ACCESS_TOKEN_CONST = "access_token"
SITE_ID_CONST = "site_id"
SOURCE_LOG_TYPE = "configlog"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


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
    "ContinuationToken": "W3sidG9rZW4iOiIrUklEOn5ETFZkQU9QMGprZFk4Q1lBQUFBQUFBPT0jUlQ6MSNUUkM6NSNSVEQ6Zms2aVNVYWlBVWNSZmFPNTJnWTdCVE14TXpZdU1qSXVNakZWTVRvN01URTdOamd2T2pZMk9EUTZPbHNBI0lTVjoyI0lFTzo2NTU2NyNRQ0Y6OCIsInJhbmdlIjp7Im1pbiI6IiIsIm1heCI6IkZGIn19XQ==",
    "TotalItems": 4,
}


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, customer_id: str, client_id: str, client_secret: str, proxy: bool, verify: bool):
        self.base_url = base_url
        self.customer_id = customer_id
        self.client_id = client_id
        self.client_secret = client_secret
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def request_access_token(self):
        demisto.debug("prepare to create access token")

        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}

        data = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}

        token_res = self._http_request(
            "post", url_suffix=f"/cctrustoauth2/{self.customer_id}/tokens/clients", headers=headers, data=data
        )

        access_token = token_res.get("access_token")
        if not access_token:
            raise DemistoException("Failed to obtain access token from Citrix daas response.")

        demisto.setIntegrationContext({ACCESS_TOKEN_CONST: access_token})
        demisto.debug("access token created")
        return access_token

    def get_site_id(self):
        # get access token value
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)

        if not access_token:
            access_token = self.request_access_token()

        headers = {"Authorization": f"CwsAuth Bearer={access_token}", "accept": "application/json"}

        url_suffix = f"catalogservice/{self.customer_id}/sites"

        demisto.info(f"Sending http request to get sites with customer id : {self.customer_id}")
        response = self._http_request("get", url_suffix=url_suffix, headers=headers, ok_codes=[200, 401], resp_type="response")

        if response.status_code == 401:
            demisto.info("Access token expired; refreshing...")
            access_token = self.request_access_token()
            headers["Authorization"] = f"CwsAuth Bearer={access_token}"
            demisto.info(f"Sending http request to get sites with customer id : {self.customer_id}")

            res = self._http_request("get", url_suffix=url_suffix, headers=headers)
        else:
            res = response.json()

        sites = res.get("sites", [])
        if not sites:
            raise DemistoException("Failed to obtain sites from Citrix daas response.")

        site_id = sites[0].get("id")
        demisto.setIntegrationContext({SITE_ID_CONST: site_id})
        demisto.debug(f"Site id is {site_id}")
        return site_id

    def get_operations(self, search_date_option: str | None, continuation_token: str = None, limit: int = None):
        # TODO: remove
        # return RES_EXAMPLE

        # get access token value
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)
        site_id = integration_context.get(SITE_ID_CONST)

        if not access_token:
            access_token = self.request_access_token()

        if not site_id:
            site_id = self.get_site_id()

        params = assign_params(
            limit=RECORDS_REQUEST_LIMIT,
            continuationToken=continuation_token,
            searchDateOption=search_date_option,
        )

        # Use the smaller of requested limit or API max per request
        params["limit"] = min(limit if limit else RECORDS_REQUEST_LIMIT, RECORDS_REQUEST_LIMIT)

        headers = {
            "Authorization": f"CwsAuth Bearer={access_token}",
            "accept": "application/json",
            "Citrix-InstanceId": site_id,
            "Citrix-CustomerId": self.customer_id,
        }

        demisto.info(f"Sending http request to get operations with {params=}")
        response = self._http_request(
            "get",
            url_suffix="cvad/manage/ConfigLog/Operations",
            headers=headers,
            params=params,
            ok_codes=[200, 401],
            resp_type="response",
        )

        if response.status_code == 401:
            demisto.info("Access token expired; refreshing...")
            access_token = self.request_access_token()
            headers["Authorization"] = f"CwsAuth Bearer={access_token}"
            demisto.info(f"Sending http request to get operations with {params=}")

            return self._http_request("get", url_suffix="cvad/manage/ConfigLog/Operations", headers=headers, params=params)
        else:
            return response.json()

    def get_operations_with_pagination(self, limit: int, search_date_option: str | None, last_operation_id: str | None = None):
        operations: list[dict] = []
        continuation_token = None
        raw_res = None

        while len(operations) < int(limit):
            raw_res = self.get_operations(
                search_date_option=search_date_option, continuation_token=continuation_token, limit=limit
            )

            items = raw_res.get("Items", [])

            # get the items after the last fetched record id to avoid duplicates
            if items and last_operation_id:
                for idx, item in enumerate(items):
                    if item.get("Id") == last_operation_id:
                        # DESCENDING ORDER → items AFTER this record are those BEFORE its index
                        items = items[:idx]
                        break

            operations.extend(items)
            continuation_token = raw_res.get("ContinuationToken")

            if not continuation_token:
                break

        for operation in operations:
            operation["_time"] = operation.get("FormattedStartTime")

        return operations[:limit], raw_res


""" HELPER FUNCTIONS """


def get_events_command(client: Client, args: dict):  # type: ignore
    limit = int(args.get("limit", "10"))
    search_date_option = args.get("search_date_option")

    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-daas-get-events with {should_push_events=}")

    operations, raw_res = client.get_operations_with_pagination(limit=limit, search_date_option=search_date_option)

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
    # TODO: implement last run by time
    search_date_option = last_run.get("LastRun") or "LastMinute"

    operations, _ = client.get_operations_with_pagination(
        limit=max_fetch, search_date_option=search_date_option, last_operation_id=last_run.get("Id")
    )

    # take the last record time because the response sort data in descending order,
    # the first value is the latest date
    if operations:
        last_run = {"LastRun": operations[0]["_time"], "Id": operations[0]["Id"]}

    return operations, last_run


def test_module_command(client: Client, args: dict):
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
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
        )

        if command == "test-module":
            result = test_module_command(client, args)
            return_results(result)

        elif command == "citrix-daas-get-events":
            results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            max_fetch = int(params.get("max_fetch", "2000"))
            last_run = demisto.getLastRun()
            demisto.debug(f"last run is: {last_run}")

            events, last_run = fetch_events_command(client, max_fetch, last_run)

            if not events:
                demisto.info("No events found")
            demisto.debug(f"send {len(events)} events to xsiam")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)
            demisto.debug(f"Last run set to: {last_run}")
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"{type(e).__name__} in {command}: {str(e)}\nTraceback:\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
