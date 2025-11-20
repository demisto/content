import demistomock as demisto
import urllib3
import traceback
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "Citrix"
PRODUCT = "Cloud"
# max value
RECORDS_REQUEST_LIMIT = 200
ACCESS_TOKEN_CONST = "access_token"
SOURCE_LOG_TYPE = "systemlog"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


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
            raise DemistoException("Failed to obtain access token from Citrix Cloud response.")

        demisto.setIntegrationContext({ACCESS_TOKEN_CONST: access_token})
        demisto.debug("access token created")
        return access_token

    def get_records(
        self, start_date_time: str | None, end_date_time: str | None, continuation_token: str = None, limit: int = None
    ):
        # get access token value
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)

        if not access_token:
            access_token = self.request_access_token()

        params = assign_params(
            Limit=RECORDS_REQUEST_LIMIT,
            continuationToken=continuation_token,
            startDateTime=start_date_time,
            endDateTime=end_date_time,
        )

        # Use the smaller of requested limit or API max per request
        params["Limit"] = min(limit if limit else RECORDS_REQUEST_LIMIT, RECORDS_REQUEST_LIMIT)

        headers = {
            "Authorization": f"CwsAuth Bearer={access_token}",
            "accept": "application/json",
            "Citrix-CustomerId": self.customer_id,
        }

        demisto.info(f"Sending http request to get records with {params=}")
        response = self._http_request(
            "get", url_suffix="systemlog/records", headers=headers, params=params, ok_codes=[200, 401], resp_type="response"
        )

        if response.status_code == 401:
            demisto.info("Access token expired; refreshing...")
            access_token = self.request_access_token()
            headers["Authorization"] = f"CwsAuth Bearer={access_token}"
            demisto.info(f"Sending http request to get records with {params=}")

            return self._http_request("get", url_suffix="systemlog/records", headers=headers, params=params)
        else:
            return response.json()

    def get_records_with_pagination(
        self, limit: int, start_date_time: str | None, end_date_time: str | None = None, last_record_id: str | None = None
    ):
        records: list[dict] = []
        continuation_token = None
        raw_res = None

        while len(records) < int(limit):
            raw_res = self.get_records(
                start_date_time=start_date_time, end_date_time=end_date_time, continuation_token=continuation_token, limit=limit
            )

            items = raw_res.get("items", [])

            # get the items after the last fetched record id to avoid duplicates
            if items and last_record_id:
                for idx, item in enumerate(items):
                    if item.get("recordId") == last_record_id:
                        # DESCENDING ORDER → items AFTER this record are those BEFORE its index
                        items = items[:idx]
                        break

            records.extend(items)
            continuation_token = raw_res.get("continuationToken")

            if not continuation_token:
                break

        for record in records:
            record["_time"] = record.get("utcTimestamp")

        return records[:limit], raw_res


""" HELPER FUNCTIONS """


def get_events_command(client: Client, args: dict):  # type: ignore
    limit = int(args.get("limit", "10"))

    end_date_time = args.get("end_date_time")
    end_date_time = dateparser.parse(end_date_time).strftime(DATE_FORMAT) if end_date_time else None

    start_date_time = args.get("start_date_time")
    start_date_time = dateparser.parse(start_date_time).strftime(DATE_FORMAT) if start_date_time else None

    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running citrix-cloud-get-events with {should_push_events=}")

    records, raw_res = client.get_records_with_pagination(
        limit=limit, start_date_time=start_date_time, end_date_time=end_date_time
    )

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
    start_date_time = last_run.get("LastRun") or datetime.utcnow().strftime(DATE_FORMAT)
    records, _ = client.get_records_with_pagination(
        limit=max_fetch, start_date_time=start_date_time, last_record_id=last_run.get("RecordId")
    )

    # take the last record time because the response sort data in descending order,
    # the first value is the latest date
    if records:
        last_run = {"LastRun": records[0]["_time"], "RecordId": records[0]["recordId"]}

    return records, last_run


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
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
        )

        if command == "test-module":
            result = module_test_command(client, args)
            return_results(result)

        elif command == "citrix-cloud-get-events":
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
