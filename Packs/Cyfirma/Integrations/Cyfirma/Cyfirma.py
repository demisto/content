import json
import uuid
from typing import Any, Dict

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

_ALERTS_AS_API_PATH = "/al/as"
_ALERTS_BI_API_PATH = "/al/bi"
_ALERTS_DBWM_API_PATH = "/al/dbwm"
_ALERTS_SPE_API_PATH = "/al/spe"
_ALERTS_SEARCH_PATH = "/al/search"

_TAKE_DOWN_LIST_API_PATH = "/td/list"
_TAKE_DOWN_CREATE_API_PATH = "/td/create"

_DD_COM_ACC_PATH = "/dd/dbwm/ca"

_DD_CUS_ACC_API_PATH = f"{_DD_COM_ACC_PATH}/customer-accounts"
_DD_COM_EMP_API_PATH = f"{_DD_COM_ACC_PATH}/compromised-employees"
_DD_PUB_ACC_API_PATH = f"{_DD_COM_ACC_PATH}/public-accounts-leaks"

_API_PATHS = {
    "AS": _ALERTS_AS_API_PATH,
    "BI": _ALERTS_BI_API_PATH,
    "DW": _ALERTS_DBWM_API_PATH,
    "SP": _ALERTS_SPE_API_PATH,
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
    "user"
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

    def _get_severity(self, risk_score: int):
        if risk_score > 8:
            return IncidentSeverity.CRITICAL
        elif risk_score > 5:
            return IncidentSeverity.HIGH
        elif risk_score >= 3:
            return IncidentSeverity.MEDIUM
        elif risk_score >= 1:
            return IncidentSeverity.LOW
        else:
            return IncidentSeverity.UNKNOWN

    def _populate_custom_fields(self, data: dict):

        comon_fields = []

        event_details = data.get("alertDetails", data)

        comon_fields = [
            {"fields": "Subcategory", "values": data.get("subCategoryLabel", "")},
            {"fields": "Category", "values": data.get("categoryLabel", "")},
            {"fields": "Alertid", "values": data.get("alertId", "")},
            {"fields": "Objectid", "values": event_details.get("uid", "")},
        ] + [
            {"fields": key.capitalize(), "values": value}
            for key, value in event_details.items()
            if key not in _SKIP_FIELDS
        ]

        if data.get("compromisedDetails"):
            comon_fields = (
                [
                    {
                        "fields": "Subcategory",
                        "values": data.get("subCategoryLabel", ""),
                    },
                    {"fields": "Category", "values": data.get("categoryLabel", "")},
                ]
                + [
                    {"fields": key.capitalize(), "values": value}
                    for key, value in event_details.items()
                    if key not in _SKIP_FIELDS
                ]
                + [
                    {"fields": key.capitalize(), "values": value}
                    for key, value in event_details.get(
                        "compromisedDetails", {}
                    ).items()
                ]
            )
            retrun_data = {"cyfirmacompromisedaccountdetails": comon_fields}

        else:

            network_attributes = event_details.get("networkAttributes", {})

            retrun_data = {
                "cyfirmaalertdetails": comon_fields,
                "cyfirmanetworkattributes": [
                    {"fields": key.capitalize(), "values": value}
                    for key, value in network_attributes.items()
                ],
                "cyfirmadigitalfootprints": self._build_sub_category_data_fields(
                    event_details, data.get("subCategory", "")
                ),
            }

            deep_fake_details = event_details.get("deepFakeDetails", {})
            if deep_fake_details:
                retrun_data["cyfirmadeepfakedetails"] = [
                    {"fields": key.capitalize(), "values": value}
                    for key, value in deep_fake_details.items()
                ]

            if data.get("subCategory", "") == "DOMAIN_IP_VULNERABILITY":
                retrun_data["cyfirmavulnerabilities"] = self._vulnerability_fields(
                    event_details.get("vulnerabilities", [])
                )

        return retrun_data

    def _build_sub_category_data_fields(
        self, alert_details: dict, sub_category: str
    ) -> list:

        if sub_category == "OPEN_PORTS":
            ports = [
                str(port_data["port"])
                for port_data in alert_details.get("portDetails", [])
                if "port" in port_data
            ]
            return [{"fields": "Open Ports", "values": ",".join(ports)}]

        if sub_category == "CERTIFICATES":
            return self._details_fields(
                alert_details.get("certificateDetails", {}), join_keys={"issuer"}
            )

        if sub_category == "CONFIGURATION":
            return self._details_fields(
                alert_details.get("configurationDetails", {}),
                join_keys={"missingEppCodes"},
            )

        if sub_category == "IP_DOMAIN_REPUTATION":
            return self._details_fields(
                alert_details.get("ipDomainReputationDetails", {}),
                join_keys={"reportedCategories"},
                only_keys={"reportedCategories"},
            )

        return [
            {"fields": key.capitalize(), "values": value}
            for key, value in alert_details.get("assetDetails", {}).items()
        ]

    @staticmethod
    def _vulnerability_fields(vulnerabilities: list) -> list:
        data = []
        for vulnerability in vulnerabilities:
            vul = {
                "cve": vulnerability.get("cveNo", ""),
                "cvssscore": vulnerability.get("cvssScore", ""),
                "kev": str(vulnerability.get("isKev", False)),
                "products": ", ".join(vulnerability.get("products", [])),
            }
            data.append(vul)

        return data

    @staticmethod
    def _details_fields(
        details: dict, join_keys: set, only_keys: set | None = None
    ) -> list:
        result = []
        for key, value in details.items():
            if only_keys is not None and key not in only_keys:
                continue
            if key in join_keys:
                value = ",".join(value)
            result.append({"fields": key, "values": value})
        return result

    def _build_incident_json(self, event: dict) -> dict[str, Any]:

        occurred_date = dateparser.parse(
            event.get("alertCreatedDate", "lastModifiedDate")
        )
        occurred = (
            occurred_date.strftime(DATE_FORMAT)
            if isinstance(occurred_date, datetime)
            else None
        )

        category = event.get("category", "")
        sub_category = event.get("subCategory", "")
        custom_fields = self._populate_custom_fields(data=event)

        alert_details = event.get("alertDetails", event)
        exposure_score = alert_details.get("exposureScore", 0)

        return_data = {
            "type": event.get("categoryLabel", ""),
            "name": event.get("title", ""),
            "occurred": occurred,
            "severity": self._get_severity(exposure_score),
            "rawJSON": str(json.dumps(event)),
            "category": category,
            "subcategory": sub_category,
            "dbotMirrorId": event.get("alertId", event.get("uid", "")),
            "sourceBrand": "CYFIRMA",
            "CustomFields": custom_fields,
        }

        return return_data

    def get_incidents(self, params: dict, alerts_to_fetch: dict):
        request_params: Dict[str, Any] = params.copy()
        incidents = []

        for alert_type, is_fetch_alert in alerts_to_fetch.items():
            request_params["page"] = 0
            self._headers["X-Request-Id"] = str(uuid.uuid4())   # pyright: ignore
            if not is_fetch_alert:
                continue
            else:
                while True:
                    current_page: int = request_params.get("page", 0)
                    events_response = self.call_api(
                        end_point=_API_PATHS.get(alert_type, ""),
                        params=request_params,
                    )

                    meta_data: Dict[str, Any] = events_response.get("metaData", {})
                    is_last: bool = meta_data.get("isLast", True)

                    data: List[Dict[str, Any]] = events_response.get("data", [])

                    if len(data) > 0:
                        for event in data:
                            incident = self._build_incident_json(event)
                            incidents.append(incident)

                    if is_last:
                        break
                    else:
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


def take_down_list_command_results(data: List[Dict], title: str) -> CommandResults:
    if not data:
        return CommandResults(readable_output="No data found for current request.")

    if not isinstance(data, list):
        return CommandResults(readable_output="Unexpected response format.")

    table_data = []
    outputs = []

    for da in data:
        ticket_id = da.get("ticket_name", "")
        sub_category = da.get("sub_category", "")
        created_date = da.get("created_date", "")
        modified_date = da.get("modified_date", "")
        status = da.get("status", "")
        domain = da.get("domain", "")
        modified_by = da.get("modified_by", "")
        created_by = da.get("created_by", "")

        row = {
            "Ticket Id": ticket_id,
            "URL Status Updated By": da.get("url_status_updated_by", ""),
            "URL Status": da.get("url_status", ""),
            "Domain": domain,
            "Sub Category": sub_category,
            "Category": da.get("category", ""),
            "Status": status,
            "Created Date": created_date,
            "Modified Date": modified_date,
            "Created By": created_by,
            "Modified By": modified_by,
        }

        table_data.append(row)

        outputs.append(
            {
                "ticket_id": ticket_id,
                "sub_category": sub_category,
                "created_date": created_date,
                "modified_date": modified_date,
                "status": status,
                "domain": domain,
                "created_by": created_by,
                "modified_by": modified_by,
            }
        )

    if not table_data:
        human_readable = "No data found for current request."
    else:
        human_readable = tableToMarkdown(title, table_data, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Cyfirma.TakeDownList",
        outputs_key_field="ticket_id",
        outputs=outputs,
        raw_response=data,
    )


def initiate_take_down_request(client: Client):
    args = demisto.args()
    alert_id = args.get("alert_id")
    data: Dict = client.initiate_take_down(alert_id, "")
    msg: str = ""

    if not data:
        msg = "For no data found for current request."
    elif bool(data.get("error")) is True:
        msg = "Error in creating take down request"

    if msg:
        return CommandResults(
            readable_output=msg,
            outputs_prefix="Cyfirma.InitiateTakeDown",
            outputs_key_field="ticket_id",
            outputs=msg,
            raw_response=data,
        )

    da: Dict = data.get("response", {})
    if da:
        ticket_id = da.get("ticketName", "")
        msg = f"Take Down Request Created Successfully - TIcket ID: {ticket_id}"
    else:
        msg = "Error in creating take down request"

    return CommandResults(
        readable_output=msg,
        outputs_prefix="Cyfirma.InitiateTakeDown",
        outputs_key_field="ticket_id",
        outputs=msg,
        raw_response=data,
    )


def get_take_down_list(client):
    args = demisto.args()
    sub_category = args.get("sub_category", "")
    size = args.get("size", "50")
    page = args.get("page", "0")

    res_data: list = client.take_down_list_data(sub_category, page, size)
    return_results(
        take_down_list_command_results(
            res_data,
            f"DeCYFIR Take Down List - Sub Category: {sub_category if sub_category else 'All'}, Page: {page}, Size: {size}",
        )
    )


def fetch_incidents(client, first_fetch, max_fetch):
    try:
        params = demisto.params()
        last_run = demisto.getLastRun()
        include_third_party = argToBoolean(params.get("includeThirdParty", False))

        fetch_attack_surface = argToBoolean(params.get("fetchAttackSurface", False))
        fetch_brand_exposure = argToBoolean(params.get("fetchBrandExposure", False))
        fetch_data_breach_web_monitor = argToBoolean(
            params.get("fetchDataBreachWebMonitor", False)
        )
        fetch_social_public_exposure = argToBoolean(
            params.get("fetchSocialPublicExposure", False)
        )
        fetch_compromised_accounts = argToBoolean(
            params.get("fetchCompromisedAccounts", False)
        )

        alerts_to_fetch = {
            "AS": fetch_attack_surface,
            "BI": fetch_brand_exposure,
            "DW": fetch_data_breach_web_monitor,
            "SP": fetch_social_public_exposure,
            "CUS": fetch_compromised_accounts,
            "EMP": fetch_compromised_accounts,
            "PUB": fetch_compromised_accounts,
        }

        start_fetch = (
            dateparser.parse(last_run.get("last_fetch"))
            if last_run
            else dateparser.parse(first_fetch)
        )
        start_fetch_timestamp_val: float = (
            start_fetch.timestamp() if isinstance(start_fetch, datetime) else 0.0
        )

        after_fetch_timestamp: int = int(start_fetch_timestamp_val * 1000)

        params: dict = {
            "page": 0,
            "size": max_fetch,
            "after": after_fetch_timestamp,
            "includeThirdParty": include_third_party,
        }
        incidents = client.get_incidents(params=params, alerts_to_fetch=alerts_to_fetch)

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


def command_alertdetailextraction():
    raws = (demisto.incident().get("CustomFields") or {}).get(
        "cyfirmaalertdetails"
    ) or []
    if not raws:
        return_error("cyfirmaalertdetails is empty on this incident")

    result = {}
    for row in raws:
        name = row.get("fields")
        if name:
            result[name] = row.get("values")

    return_results(
        CommandResults(
            outputs_prefix="Cyfirma.Alert",
            outputs=result,
            readable_output=f"Parsed alert {str(result)}",
        )
    )


def main():
    params = demisto.params()

    api_url = params.get("url", "").rstrip("/")
    api_key = (params.get("api_key") or {}).get("password")

    max_fetch: str = params.get("max_fetch", 2)
    verify_certificate = not argToBoolean(params.get("insecure", False))
    first_fetch = params.get("first_fetch", "90 days").strip()
    proxy = argToBoolean(params.get("proxy", False))

    # include_third_party = argToBoolean(params.get("includeThirdParty", False))

    # fetch_attack_surface = argToBoolean(params.get("fetchAttackSurface", False))
    # fetch_brand_exposure = argToBoolean(params.get("fetchBrandExposure", False))
    # fetch_data_breach_web_monitor = argToBoolean(
    #     params.get("fetchDataBreachWebMonitor", False)
    # )
    # fetch_social_public_exposure = argToBoolean(
    #     params.get("fetchSocialPublicExposure", False)
    # )
    # fetch_compromised_accounts = argToBoolean(
    #     params.get("fetchCompromisedAccounts", False)
    # )

    # alerts_to_fetch = {
    #     "AS": fetch_attack_surface,
    #     "BI": fetch_brand_exposure,
    #     "DW": fetch_data_breach_web_monitor,
    #     "SP": fetch_social_public_exposure,
    #     "CUS": fetch_compromised_accounts,
    #     "EMP": fetch_compromised_accounts,
    #     "PUB": fetch_compromised_accounts,
    # }

    base_url = urljoin(api_url, _BASE_PREFIX_PATH)
    command = demisto.command()
    headers = {"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_AL"}

    demisto.info(f"Command being called is {demisto.command()}")

    try:
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif demisto.command() == "fetch-incidents":
            fetch_incidents(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
            )

        elif demisto.command() == "cyfirma-takedown-initiate":
            initiate_take_down_request(client)
        elif demisto.command() == "cyfirma-takedown-list":
            get_take_down_list(client)
        elif demisto.command() == "cyfirma-alert-parser":
            command_alertdetailextraction()
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
