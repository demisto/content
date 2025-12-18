import demistomock as demisto
import urllib3
import traceback
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "DaaS"
# max value
RECORDS_REQUEST_LIMIT = 1000
ACCESS_TOKEN_CONST = "access_token"
SITE_ID_CONST = "site_id"
SOURCE_LOG_TYPE = "configlog"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


RES_EXAMPLE = {
    "ContinuationToken": "ContinuationToken",
    "Items": [
        {
            "FormattedStartTime": "2025-12-06T16:44:35.470Z",
            "Id": "id5",
            "OperationType": "ConfigurationChange",
            "Text": "Shutdown Machine",
        },
        {
            "FormattedStartTime": "2025-12-03T16:44:35.470Z",
            "Id": "id4",
            "OperationType": "ConfigurationChange",
            "Text": "Shutdown Machine",
        },
        {
            "FormattedStartTime": "2025-12-02T16:44:35.470Z",
            "Id": "id3",
            "OperationType": "ConfigurationChange",
            "Text": "Shutdown Machine",
        },
        {
            "FormattedStartTime": "2025-12-01T16:44:35.470Z",
            "Id": "id2",
            "OperationType": "ConfigurationChange",
            "Text": "Shutdown Machine",
        },
        {
            "FormattedStartTime": "2025-12-01T10:44:35.470Z",
            "Id": "id1",
            "OperationType": "ConfigurationChange",
            "Text": "Shutdown Machine",
        },
    ],
}


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self, base_url: str, customer_id: str, client_id: str, client_secret: str, site_name: str, proxy: bool, verify: bool
    ):
        self.base_url = base_url
        self.customer_id = customer_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.site_name = site_name
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
            raise DemistoException("Failed to obtain access token from Citrix DaaS response.")

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
            raise DemistoException("Failed to obtain sites from Citrix DaaS response.")

        if len(sites) == 1:
            site_id = sites[0].get("id")
        else:
            site_id = next((site.get("id") for site in sites if site.get("displayName") == self.site_name), None)
            if not site_id:
                raise DemistoException(f"Failed to obtain site with the name {self.site_name} from Citrix DaaS response.")

        demisto.setIntegrationContext({SITE_ID_CONST: site_id})
        demisto.debug(f"Site id is {site_id}")
        return site_id

    def get_operations(self, search_date_option: str | None, continuation_token: str = None, limit: int = None, days: int = None):
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
        if days:
            # Note: This parameter is exclusive with parameter searchDateOption.
            # If neither is specified, all records will be returned.
            params.pop("searchDateOption", None)
            params["days"] = days

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

    def get_operations_with_pagination(
        self,
        limit: int,
        search_date_option: str | None = None,
        last_operation_id: str | None = None,
        days: int | None = None,
        last_run_date: str | None = None,
    ):
        operations: list[dict] = []
        continuation_token = None
        raw_res = None

        while len(operations) < int(limit):
            raw_res = self.get_operations(
                search_date_option=search_date_option, continuation_token=continuation_token, limit=limit, days=days
            )

            items = raw_res.get("Items", [])

            if items and last_run_date:
                res_first_item_time = datetime.strptime(items[0].get("FormattedStartTime"), "%Y-%m-%dT%H:%M:%S.%fZ")
                last_fetched_item_time = datetime.strptime(last_run_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                if last_fetched_item_time > res_first_item_time:
                    continuation_token = raw_res.get("ContinuationToken")

                    if continuation_token:
                        continue
                    else:
                        break

            items.reverse()

            # get the items after the last fetched record id to avoid duplicates
            if items and last_operation_id:
                for idx, item in enumerate(items):
                    if item.get("Id") == last_operation_id:
                        items = items[idx + 1 :]
                        break

            operations.extend(items)
            continuation_token = raw_res.get("ContinuationToken")

            if not continuation_token:
                break

        operations = operations[:limit]

        for operation in operations:
            operation["_time"] = operation.get("FormattedStartTime")
        return operations, raw_res


""" HELPER FUNCTIONS """


def get_events_command(client: Client, args: dict):  # type: ignore
    limit = int(args.get("limit", "10"))
    search_date_option = args.get("search_date_option")
    days = args.get("days")

    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-daas-get-events with {should_push_events=}")

    operations, raw_res = client.get_operations_with_pagination(limit=limit, search_date_option=search_date_option, days=days)

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


def days_since(timestamp_str) -> int:
    # Parse the ISO-8601 timestamp with Zulu time (UTC)
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    dt = dt.replace(tzinfo=timezone.utc)

    # Current time in UTC
    now = datetime.now(timezone.utc)

    # Difference in days
    delta = now - dt
    days = delta.days
    if days < 0:
        return 1
    return delta.days



def deduplicate_events(events: list[dict[str, Any]], last_fetched_ids: list[str]) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched IDs."""

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched IDs")

    # Convert to set for O(1) lookup
    fetched_ids_set = set(last_fetched_ids)

    # Filter out events that were already fetched
    new_events = [event for event in events if event.get("id") not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events

def fetch_events_command(client: Client, max_fetch: int, last_run: dict):
    last_run_date = last_run.get("LastRun")
    last_fetched_ids = last_run.get("LastFechedIds",[])
    last_operation_id =last_fetched_ids[-1] if last_fetched_ids else None
    
    days = 0
    if last_run_date:
        days = days_since(last_run_date)

    operations, _ = client.get_operations_with_pagination(
        limit=max_fetch, last_operation_id=last_operation_id, days=days, last_run_date=last_run_date
    )

    if operations:
        # Deduplicate
        operations = deduplicate_events(operations, last_fetched_ids)
        new_last_run = operations[-1]["_time"]
              
        ids_at_last_timestamp = [
                operation.get("Id") for operation in operations if operation.get("_time") == new_last_run and operation.get("Id")
            ]

        
        last_run = {"LastRun": new_last_run, "LastFechedIds": ids_at_last_timestamp}

    return operations, last_run


def module_test_command(client: Client, args: dict):
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
            site_name=params.get("site_name", ""),
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
        )

        if command == "test-module":
            result = module_test_command(client, args)
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
