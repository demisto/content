import json
import uuid
from typing import Any

import dateparser
import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
_BASE_PREFIX_PATH = "/api/ex/v3/da"
_TEST_PATH = "/foo/ping"

_DD_COM_ACC_PATH = "/dd/dbwm/ca"

_DD_CUS_ACC_API_PATH = f"{_DD_COM_ACC_PATH}/customer-accounts"
_DD_COM_EMP_API_PATH = f"{_DD_COM_ACC_PATH}/compromised-employees"
_DD_PUB_ACC_API_PATH = f"{_DD_COM_ACC_PATH}/public-accounts-leaks"

_API_PATHS = {
    "CUS": _DD_CUS_ACC_API_PATH,
    "EMP": _DD_COM_EMP_API_PATH,
    "PUB": _DD_PUB_ACC_API_PATH,
}

_SKIP_FIELDS = [
    "alertDetails",
    "networkAttributes",
    "portDetails",
    "certificateDetails",
    "configurationDetails",
    "ipDomainReputationDetails",
    "assetDetails",
    "vulnerabilities",
    "additionalDetails",
    "hasActive",
    "isSafe",
    "category",
    "categoryLabel",
    "subCategory",
    "subCategoryLabel",
    "compromisedDetails",
    "user",
]


class Client(BaseClient):
    def call_api(self, end_point: str, params: dict | None = None):
        response = self._http_request(
            url_suffix=end_point,
            params=params,
            resp_type="response",
            method="GET",
            retries=3,
            status_list_to_retry=(502, 503, 504),
            raise_on_status=True,
        )
        if response.status_code == 200 and response.content:
            return response.json()

        return {}

    def _populate_custom_fields(self, data: dict):
        comon_fields: list[dict[str, Any]] = (
            [
                {"fields": "Subcategory", "values": data.get("subCategoryLabel", "")},
                {"fields": "Category", "values": data.get("categoryLabel", "")},
            ]
            + [{"fields": key.capitalize(), "values": value} for key, value in data.items() if key not in _SKIP_FIELDS]
            + [{"fields": key.capitalize(), "values": value} for key, value in data.get("compromisedDetails", {}).items()]
        )

        return {"cyfirmacompromisedaccountdetails": comon_fields}

    def _build_incident_json(self, event: dict) -> dict[str, Any]:
        occurred_date = dateparser.parse(event.get("lastModifiedDate", "createdDate"))
        occurred = occurred_date.strftime(DATE_FORMAT) if isinstance(occurred_date, datetime) else None

        category = event.get("category", "")
        sub_category = event.get("subCategory", "")

        custom_fields = self._populate_custom_fields(data=event)

        return_data = {
            "type": event.get("categoryLabel", ""),
            "name": event.get("title", ""),
            "occurred": occurred,
            "severity": IncidentSeverity.CRITICAL,
            "rawJSON": str(json.dumps(event)),
            "category": category,
            "subcategory": sub_category,
            "dbotMirrorId": event.get("uid", ""),
            "sourceBrand": "CYFIRMA",
            "CustomFields": custom_fields,
        }

        return return_data

    def get_incidents(self, params: dict):
        request_params: dict[str, Any] = params.copy()
        incidents = []

        for _k, api_path in _API_PATHS.items():
            request_params["page"] = 0
            self._headers["X-Request-Id"] = str(uuid.uuid4())  # pyright: ignore

            while True:
                current_page: int = request_params.get("page", 0)
                events_response = self.call_api(
                    end_point=api_path,
                    params=request_params,
                )

                meta_data: dict[str, Any] = events_response.get("metaData", {})
                is_last: bool = meta_data.get("isLast", True)

                data: List[dict[str, Any]] = events_response.get("data", [])

                if len(data) > 0:
                    for event in data:
                        incident = self._build_incident_json(event)
                        incidents.append(incident)

                if is_last:
                    break
                request_params["page"] = current_page + 1

        return incidents


def test_module(client: Client) -> str:
    try:
        res: dict = client.call_api(_TEST_PATH)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise e

    if res is None or res == {}:
        return "Not Authorized"

    org_active: bool = res.get("isOrgActive", False)

    if not org_active:
        return "Not Authorized"

    if "isCompanyActive" in res:
        company_active: bool = res.get("isCompanyActive", False)
        if not company_active:
            return "Not Authorized"

    return "ok"


def fetch_incidents(client, first_fetch, max_fetch):
    try:
        params = demisto.params()
        last_run = demisto.getLastRun()
        include_third_party = argToBoolean(params.get("includeThirdPartyCompromisedAccounts", False))
        start_fetch = dateparser.parse(last_run.get("last_fetch")) if last_run else dateparser.parse(first_fetch)
        start_fetch_timestamp_val: float = start_fetch.timestamp() if isinstance(start_fetch, datetime) else 0.0

        after_fetch_timestamp: int = int(start_fetch_timestamp_val * 1000)

        params: dict = {
            "page": 0,
            "size": max_fetch,
            "after": after_fetch_timestamp,
            "includeThirdParty": include_third_party,
        }

        incidents = client.get_incidents(params=params)

        last_fetch_time = datetime.now().strftime(DATE_FORMAT)
        last_fetch = {"last_fetch": last_fetch_time}

        # Pushing Incidents to XSOAR
        demisto.incidents(incidents)
        demisto.setLastRun(last_fetch)
    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e


def main():
    params = demisto.params()

    api_url = params.get("url", "").rstrip("/")
    api_key = (params.get("api_key") or {}).get("password")

    max_fetch: str = params.get("max_fetch", 2)
    verify_certificate = not argToBoolean(params.get("insecure", False))
    first_fetch = params.get("first_fetch", "90 days").strip()
    proxy = argToBoolean(params.get("proxy", False))

    base_url = urljoin(api_url, _BASE_PREFIX_PATH)
    command = demisto.command()
    headers = {"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_CA"}

    demisto.info(f"Command being called is {demisto.command()}")

    try:
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif demisto.command() == "fetch-incidents":
            fetch_incidents(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
            )
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
