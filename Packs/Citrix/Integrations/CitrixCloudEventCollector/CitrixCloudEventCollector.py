import demistomock as demisto
import urllib3
import traceback
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "Cloud"
RECORDS_REQUEST_LIMIT = "200"
ACCESS_TOKEN_CONST = "access_token"
CONTINUATION_TOKEN_CONST = "continuation_token"
SOURCE_LOG_TYPE = "systemlog"
RECORDS_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
EVENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

RES_EXAMPLE = {
    "Items": [
        {
            "RecordId": "1",
            "UtcTimestamp": "2020-07-20T14:26:59.6103585Z",
            "CustomerId": "hulk",
            "EventType": "delegatedadministration:administrator/create",
            "TargetId": "6233644161364977157",
            "TargetDisplayName": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
            "TargetEmail": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
            "TargetUserId": "a90b4449675f4fcf97e1663623334d74",
            "TargetType": "administrator",
            "BeforeChanges": None,
            "AfterChanges": {
                "CustomerId": "hulk",
                "Principal": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "UserId": "6233644161364977157",
                "AccessType": "Full",
                "CreatedDate": "09/10/2025 14:26:53",
                "UpdatedDate": "09/10/2025 14:26:53",
                "DisplayName": "Rafa Doe",
                "Pending": "False",
            },
            "AgentId": "delegatedadministration",
            "ServiceProfileName": None,
            "ActorId": None,
            "ActorDisplayName": "CwcSystem",
            "ActorType": "system",
            "Message": {"en-US": "Created new administrator user '6233644161364977157'."},
        },
        {
            "RecordId": "2",
            "UtcTimestamp": "2020-07-20T14:26:59.6103585Z",
            "CustomerId": "hulk",
            "EventType": "delegatedadministration:administrator/create",
            "TargetId": "6233644161364977157",
            "TargetDisplayName": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
            "TargetEmail": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
            "TargetUserId": "a90b4449675f4fcf97e1663623334d74",
            "TargetType": "administrator",
            "BeforeChanges": None,
            "AfterChanges": {
                "CustomerId": "hulk",
                "Principal": "[testcduser1@gmail.com](mailto:testcduser1@gmail.com)",
                "UserId": "6233644161364977157",
                "AccessType": "Full",
                "CreatedDate": "09/10/2025 14:26:53",
                "UpdatedDate": "09/10/2025 15:26:53",
                "DisplayName": "Rafa Doe",
                "Pending": "False",
            },
            "AgentId": "delegatedadministration",
            "ServiceProfileName": None,
            "ActorId": None,
            "ActorDisplayName": "CwcSystem",
            "ActorType": "system",
            "Message": {"en-US": "Created new administrator user '6233644161364977157'."},
        },
    ],
    "Count": 74,
    "EstimatedTotalItems": 250,
    "ContinuationToken": "+RID:~ry4EAP",
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

    def get_records(self, start_date_time=None, continuation_token=None):
        # get access token value
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)
        if not access_token:
            access_token = self.request_access_token()

        # set request params
        params = {"limit": RECORDS_REQUEST_LIMIT}
        if continuation_token:
            params["continuationToken"] = continuation_token

        if start_date_time:
            params["startDateTime"] = start_date_time

        headers = {
            "Authorization": f"CwsAuth Bearer={access_token}",
            "accept": "application/json",
            "Citrix-CustomerId": self.customer_id,
        }

        # TODO: remove
        return RES_EXAMPLE

        demisto.info(f"Sending http request to get records with {params=}")
        response = self._http_request("get", url_suffix="systemlog/records", headers=headers, params=params, ok_codes=[200, 401])

        if response.status_code == 401:
            demisto.info("Invalid bearer token")
            self.request_access_token()
            access_token = integration_context.get(ACCESS_TOKEN_CONST)
            headers["Authorization"] = (f"CwsAuth Bearer={access_token}",)
            demisto.info(f"Sending http request to get records with {params=}")
            return self._http_request("get", url_suffix="systemlog/records", headers=headers, params=params)
        else:
            return response

    def get_records_with_pagination(self, limit, start_date_time=None, continuation_token=None):
        records: list[dict] = []

        while len(records) <= limit:
            raw_res = self.get_records(start_date_time=start_date_time, continuation_token=continuation_token)
            records.extend(raw_res.get("Items", []))
            continuation_token = raw_res.get("ContinuationToken")

            if not continuation_token:
                break

        self.add_fields_to_events(records)
        return records[:limit], raw_res, continuation_token

    def add_fields_to_events(self, events: list[dict]):
        for event in events:
            created_date = event.get("AfterChanges", {}).get("CreatedDate")
            updated_date = event.get("AfterChanges", {}).get("UpdatedDate")
            if created_date:
                created_date = datetime.strptime(created_date, RECORDS_DATE_FORMAT)
            if updated_date:
                updated_date = datetime.strptime(updated_date, RECORDS_DATE_FORMAT)

            event["source_log_type"] = SOURCE_LOG_TYPE
            event["_time"] = created_date.strftime(EVENT_DATE_FORMAT)

            # add _ENTRY_STATUS field
            if updated_date == created_date or not updated_date:
                event["_ENTRY_STATUS"] = "new"
            elif updated_date > created_date:
                event["_ENTRY_STATUS"] = "updated"


""" HELPER FUNCTIONS """


def get_events_command(client: Client, args: dict):  # type: ignore
    limit = args.get("limit", "100")
    start_date_time = args.get("start_date_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-cloud-get-events with {should_push_events=}")

    records, raw_res, _ = client.get_records_with_pagination(limit=int(limit), start_date_time=start_date_time)

    results = CommandResults(
        outputs_prefix="CitrixCloud.Event",
        outputs_key_field="recordId",
        outputs=records,
        readable_output=tableToMarkdown("Events List", records),
        raw_response=raw_res,
    )

    if should_push_events:
        demisto.debug(f"send {len(records)} events to xsiam")
        send_events_to_xsiam(records, vendor=VENDOR, product=PRODUCT)

    return results


def fetch_events_command(client: Client, max_fetch: int, last_run: dict):
    records, _, continuation_token = client.get_records_with_pagination(
        limit=max_fetch, continuation_token=last_run.get(CONTINUATION_TOKEN_CONST)
    )
    return records, {CONTINUATION_TOKEN_CONST: continuation_token}


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
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
        )

        if command == "test-module":
            result = test_module(client, args)
            return_results(result)

        elif command == "citrix-cloud-get-events":
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
