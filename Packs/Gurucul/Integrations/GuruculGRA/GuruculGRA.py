import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """
import traceback
from typing import Any

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

MAX_INCIDENTS_TO_FETCH = 25
API_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

""" CLIENT CLASS """


class Client(BaseClient):
    def fetch_command_result(self, url_suffix, params, post_url):
        incidents: list = []
        try:
            if post_url is None:
                method = "GET"
            else:
                method = "POST"
                params = None
            r = self._http_request(method=method, url_suffix=url_suffix, data=post_url, params=params)
            incidents = r if isinstance(r, list) else [r]
        except Exception:
            demisto.error("Unable to fetch command result" + traceback.format_exc())
        return incidents

    def validate_api_key(self):
        self._http_request(method="GET", url_suffix="/validate", params={})
        return "ok"


""" HELPER FUNCTIONS """


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> int | None:
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        return int(arg)
    if isinstance(arg, str):
        date = dateparser.parse(arg, settings={"TIMEZONE": "UTC"})
        if date is None:
            raise ValueError(f"Invalid date: {arg_name}")

        return int(date.timestamp())
    if isinstance(arg, int | float):
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def _occurred_from_gra_date(raw_value: Any, gra_timezone: str = "UTC") -> str:
    """Parse a naive GRA date as gra_timezone and return a UTC ISO string; fallback to now."""
    now_ms = datetime.now().timestamp() * 1000
    if raw_value is None or raw_value == "":
        return timestamp_to_datestring(now_ms)
    timezone = gra_timezone or "UTC"
    try:
        parsed = dateparser.parse(
            str(raw_value),
            settings={"TIMEZONE": timezone, "TO_TIMEZONE": "UTC"},
        )
        if parsed is not None:
            return timestamp_to_datestring(parsed.timestamp() * 1000)
    except Exception:
        pass
    return timestamp_to_datestring(now_ms)


def _rewrite_gra_date_fields(record: dict[str, Any], keys: list[str], gra_timezone: str) -> None:
    """Replace naive GRA date fields with UTC ISO so incoming mappers do not treat them as UTC wall-clock."""
    for key in keys:
        raw = record.get(key)
        if raw is None or raw == "":
            continue
        record[key] = _occurred_from_gra_date(raw, gra_timezone)


""" COMMAND FUNCTIONS """


def fetch_record_command(client: Client, url_suffix, prefix, key, params, post_url=None):
    incidents: list = []
    r = client.fetch_command_result(url_suffix, params, post_url)
    incidents.extend(r)
    results = CommandResults(outputs_prefix=prefix, outputs_key_field=key, outputs=incidents)
    return results


def fetch_records(client: Client, url_suffix, prefix, key, params):
    results = fetch_record_command(client, url_suffix, prefix, key, params)
    return_results(results)


def fetch_post_records(client: Client, url_suffix, prefix, key, params, post_url):
    results = fetch_record_command(client, url_suffix, prefix, key, params, post_url)
    return_results(results)


def fetch_gra_incidents(
    client: Client,
    max_results: int,
    last_run: dict,
    first_fetch_time: int | None,
    gra_timezone: str = "UTC",
) -> tuple[dict, list[dict]]:
    """Fetch OPEN GRA Incidents using maxIncidentId cursor after first date bootstrap."""
    max_incident_id = last_run.get("maxIncidentId")
    if max_incident_id is None and last_run.get("maxCaseId") is not None:
        max_incident_id = last_run.get("maxCaseId")
    temp_max_incident_id = max_incident_id
    incidents: list[dict[str, Any]] = []
    page = 1
    is_continue = True

    demisto.debug(
        f"fetch_gra_incidents start max_fetch={max_results} maxIncidentId={max_incident_id} "
        f"first_fetch_time={first_fetch_time} gra_timezone={gra_timezone} page={page}"
    )

    while is_continue:
        params: dict[str, Any] = {
            "page": page,
            "max": max_results,
            "timezone": "UTC",
            "status": "OPEN",
        }
        if max_incident_id is not None:
            params["maxIncidentId"] = max_incident_id
        else:
            now = int(datetime.now().timestamp())
            params["startDate"] = (
                datetime.fromtimestamp(int(first_fetch_time or now)).replace(microsecond=0, second=0).strftime(API_DATE_FORMAT)
            )
            params["endDate"] = datetime.fromtimestamp(now).strftime(API_DATE_FORMAT)

        records = client.fetch_command_result("/incidents/v1/opendate", params, None)
        if len(records) < max_results:
            is_continue = False
        else:
            page += 1

        for record in records:
            incident_id = record.get("incidentId")
            if incident_id is None:
                continue
            if temp_max_incident_id is None or incident_id > temp_max_incident_id:
                temp_max_incident_id = incident_id

            record["incidentType"] = "GRAIncident"
            _rewrite_gra_date_fields(record, ["openDate", "riskDate"], gra_timezone)
            incidents.append(
                {
                    "name": record.get("entity"),
                    "occurred": record.get("openDate") or _occurred_from_gra_date(None, gra_timezone),
                    "rawJSON": json.dumps(record),
                }
            )

    next_run: dict[str, Any] = {}
    if temp_max_incident_id is not None:
        next_run["maxIncidentId"] = temp_max_incident_id
    demisto.info(f"fetch_gra_incidents end fetched={len(incidents)} next_run={next_run}")
    return next_run, incidents


def fetch_gra_alerts(
    client: Client,
    max_results: int,
    last_run: dict,
    first_fetch_time: int | None,
    gra_timezone: str = "UTC",
) -> tuple[dict, list[dict]]:
    """Fetch OPEN GRA Alerts using maxAlertId cursor after first date bootstrap."""
    max_alert_id = last_run.get("maxAlertId")
    temp_max_alert_id = max_alert_id
    incidents: list[dict[str, Any]] = []
    page = 1
    is_continue = True

    demisto.debug(
        f"fetch_gra_alerts start max_fetch={max_results} maxAlertId={max_alert_id} "
        f"first_fetch_time={first_fetch_time} gra_timezone={gra_timezone} page={page}"
    )

    while is_continue:
        params: dict[str, Any] = {
            "page": page,
            "max": max_results,
            "timezone": "UTC",
        }
        if max_alert_id is not None:
            params["maxAlertId"] = max_alert_id
        else:
            now = int(datetime.now().timestamp())
            params["startDate"] = (
                datetime.fromtimestamp(int(first_fetch_time or now)).replace(microsecond=0, second=0).strftime(API_DATE_FORMAT)
            )
            params["endDate"] = datetime.fromtimestamp(now).strftime(API_DATE_FORMAT)

        records = client.fetch_command_result("/alerts/v1/OPEN", params, None)
        if len(records) < max_results:
            is_continue = False
        else:
            page += 1

        for record in records:
            alert_id = record.get("alertId")
            if alert_id is None:
                continue
            if temp_max_alert_id is None or alert_id > temp_max_alert_id:
                temp_max_alert_id = alert_id

            record["incidentType"] = "GRAAlert"
            _rewrite_gra_date_fields(record, ["detectionTimestamp"], gra_timezone)
            name = record.get("anomalyName") or record.get("entity") or f"Alert {alert_id}"
            incidents.append(
                {
                    "name": name,
                    "occurred": record.get("detectionTimestamp") or _occurred_from_gra_date(None, gra_timezone),
                    "rawJSON": json.dumps(record),
                }
            )

    next_run: dict[str, Any] = {}
    if temp_max_alert_id is not None:
        next_run["maxAlertId"] = temp_max_alert_id
    demisto.info(f"fetch_gra_alerts end fetched={len(incidents)} next_run={next_run}")
    return next_run, incidents


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: dict,
    first_fetch_time: int | None,
    fetch_type: str = "Incidents",
    gra_timezone: str = "UTC",
) -> tuple[dict, list[dict]]:
    """Fetch GRA objects into XSOAR. Cases are no longer imported; use Incidents or Alerts."""
    demisto.debug(
        f"fetch_incidents dispatch fetch_type={fetch_type} max_results={max_results} "
        f"gra_timezone={gra_timezone} last_run={last_run}"
    )
    if fetch_type == "Alerts":
        return fetch_gra_alerts(client, max_results, last_run, first_fetch_time, gra_timezone)
    return fetch_gra_incidents(client, max_results, last_run, first_fetch_time, gra_timezone)


def test_module_command(client: Client) -> str:
    try:
        client.validate_api_key()
    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


""" MAIN FUNCTION """


def main() -> None:
    try:
        arguments = demisto.args()
        api_key = demisto.params().get("apikey")
        base_url = urljoin(demisto.params()["url"], "/api/")
        verify_certificate = not demisto.params().get("insecure", False)
        first_fetch_time = arg_to_timestamp(
            arg=demisto.params().get("first_fetch", "3 days"), arg_name="First fetch time", required=True
        )
        assert isinstance(first_fetch_time, int)
        proxy = demisto.params().get("proxy", False)
        page = arguments.get("page", "1")
        page_count_no = arguments.get("max", "25")
        demisto.debug(f"Command being called is {demisto.command()}")
        params = {"page": page, "max": page_count_no}
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            try:
                result = test_module_command(client)
                return_results(result)
            except Exception:
                return_error(
                    "Gurucul services are currently not available. Please contact the administrator for further assistance."
                )

        elif demisto.command() == "gra-validate-api":
            try:
                result = client.validate_api_key()
                return_results(result)
            except Exception:
                return_error("Error in service")

        elif demisto.command() == "fetch-incidents":
            max_results = arg_to_int(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            fetch_type = demisto.params().get("fetch_type") or "Incidents"
            gra_timezone = demisto.params().get("gra_server_timezone") or "UTC"

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                fetch_type=fetch_type,
                gra_timezone=gra_timezone,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "gra-fetch-users":
            fetch_records(client, "/users", "Gra.Users", "employeeId", params)

        elif demisto.command() == "gra-fetch-accounts":
            fetch_records(client, "/v1/accounts", "Gra.Accounts", "id", params)

        elif demisto.command() == "gra-fetch-active-resource-accounts":
            resource_name = arguments.get("resource_name", "Windows Security")
            active_resource_url = "/resources/" + resource_name + "/accounts"
            fetch_records(client, active_resource_url, "Gra.Active.Resource.Accounts", "id", params)

        elif demisto.command() == "gra-fetch-active-datasource-accounts":
            ds_params = dict(params)
            ds_params["datasourcename"] = arguments.get("datasource_name", "Windows Security")
            fetch_records(client, "/datasources/accounts", "Gra.Active.Datasource.Accounts", "id", ds_params)

        elif demisto.command() == "gra-fetch-user-accounts":
            employee_id = arguments.get("employee_id")
            user_account_params = dict(params)
            user_account_params["id"] = employee_id
            fetch_records(client, "/v1/users/accounts", "Gra.User.Accounts", "id", user_account_params)

        elif demisto.command() == "gra-fetch-resource-highrisk-accounts":
            res_name = arguments.get("Resource_name", "Windows Security")
            high_risk_account_resource_url = "/resources/" + res_name + "/accounts/highrisk"
            fetch_records(client, high_risk_account_resource_url, "Gra.Resource.Highrisk.Accounts", "id", params)

        elif demisto.command() == "gra-fetch-datasource-highrisk-accounts":
            ds_params = dict(params)
            ds_params["datasourcename"] = arguments.get("datasource_name", "Windows Security")
            fetch_records(client, "/datasources/accounts/highrisk", "Gra.Datasource.Highrisk.Accounts", "id", ds_params)

        elif demisto.command() == "gra-fetch-hpa":
            fetch_records(client, "/v1/accounts/highprivileged", "Gra.Hpa", "id", params)

        elif demisto.command() == "gra-fetch-resource-hpa":
            resource_name = arguments.get("Resource_name", "Windows Security")
            resource_hpa = "/resources/" + resource_name + "/accounts/highprivileged"
            fetch_records(client, resource_hpa, "Gra.Resource.Hpa", "id", params)

        elif demisto.command() == "gra-fetch-datasource-hpa":
            ds_params = dict(params)
            ds_params["datasourcename"] = arguments.get("datasource_name", "Windows Security")
            fetch_records(client, "/datasources/accounts/highprivileged", "Gra.Datasource.Hpa", "id", ds_params)

        elif demisto.command() == "gra-fetch-orphan-accounts":
            fetch_records(client, "/v1/accounts/orphan", "Gra.Orphan.Accounts", "id", params)

        elif demisto.command() == "gra-fetch-resource-orphan-accounts":
            resource_name = arguments.get("resource_name", "Windows Security")
            resource_orphan = "/resources/" + resource_name + "/accounts/orphan"
            fetch_records(client, resource_orphan, "Gra.Resource.Orphan.Accounts", "id", params)

        elif demisto.command() == "gra-fetch-datasource-orphan-accounts":
            ds_params = dict(params)
            ds_params["datasourcename"] = arguments.get("datasource_name", "Windows Security")
            fetch_records(client, "/datasources/accounts/orphan", "Gra.Datasource.Orphan.Accounts", "id", ds_params)

        elif demisto.command() == "gra-user-activities":
            employee_id = arguments.get("employee_id")
            activity_params = dict(params)
            activity_params["id"] = employee_id
            fetch_records(client, "/v1/user/activity", "Gra.User.Activity", "employee_id", activity_params)

        elif demisto.command() == "gra-fetch-users-details":
            employee_id = arguments.get("employee_id")
            fetch_records(client, "/users/" + employee_id, "Gra.User", "employeeId", params)

        elif demisto.command() == "gra-highRisk-users":
            fetch_records(client, "/users/highrisk", "Gra.Highrisk.Users", "employeeId", params)

        elif demisto.command() == "gra-cases":
            status = arguments.get("status")
            cases_url = "/cases/" + status
            fetch_records(client, cases_url, "Gra.Cases", "caseId", params)

        elif demisto.command() == "gra-user-anomalies":
            employee_id = arguments.get("employee_id")
            anomaly_url = "/users/" + employee_id + "/anomalies/"
            fetch_records(client, anomaly_url, "Gra.User.Anomalies", "anomaly_name", params)

        elif demisto.command() == "gra-case-action":
            action = arguments.get("action")
            caseId = arguments.get("caseId")
            subOption = arguments.get("subOption")
            caseComment = arguments.get("caseComment")
            riskAcceptDate = arguments.get("riskAcceptDate")
            cases_url = "/cases/" + action
            if action == "riskManageCase":
                post_url = {
                    "caseId": int(caseId),
                    "subOption": subOption,
                    "caseComment": caseComment,
                    "riskAcceptDate": riskAcceptDate,
                }
            else:
                post_url = {"caseId": int(caseId), "subOption": subOption, "caseComment": caseComment}
            post_url_json = json.dumps(post_url)
            fetch_post_records(client, cases_url, "Gra.Case.Action", "caseId", params, post_url_json)

        elif demisto.command() == "gra-case-action-anomaly":
            action = arguments.get("action")
            caseId = arguments.get("caseId")
            anomalyNames = arguments.get("anomalyNames")
            subOption = arguments.get("subOption")
            caseComment = arguments.get("caseComment")
            riskAcceptDate = arguments.get("riskAcceptDate")
            cases_url = "/cases/" + action
            if action == "riskAcceptCaseAnomaly":
                post_url = {
                    "caseId": int(caseId),
                    "anomalyNames": anomalyNames,
                    "subOption": subOption,
                    "caseComment": caseComment,
                    "riskAcceptDate": riskAcceptDate,
                }
            else:
                post_url = {
                    "caseId": int(caseId),
                    "anomalyNames": anomalyNames,
                    "subOption": subOption,
                    "caseComment": caseComment,
                }
            post_url_json = json.dumps(post_url)
            fetch_post_records(client, cases_url, "Gra.Cases.Action.Anomaly", "caseId", params, post_url_json)

        elif demisto.command() == "gra-investigate-anomaly-summary":
            fromDate = arguments.get("fromDate")
            toDate = arguments.get("toDate")
            modelName = arguments.get("modelName")
            investigate_params = dict(params)
            investigate_params["modelName"] = modelName
            if fromDate is not None and toDate is not None:
                investigate_params["fromDate"] = fromDate + " 00:00:00"
                investigate_params["toDate"] = toDate + " 23:59:59"
            fetch_records(
                client, "/investigateAnomaly/v1/anomalySummary", "Gra.Investigate.Anomaly.Summary", "modelId", investigate_params
            )

        elif demisto.command() == "gra-analytical-features-entity-value":
            fromDate = arguments.get("fromDate")
            toDate = arguments.get("toDate")
            modelName = arguments.get("modelName")
            entityValue = arguments.get("entityValue")
            entityTypeId = arguments.get("entityTypeId")
            analytical_params = dict(params)
            analytical_params["entityValue"] = entityValue
            analytical_params["modelName"] = modelName
            if fromDate is not None and toDate is not None:
                analytical_params["fromDate"] = fromDate + " 00:00:00"
                analytical_params["toDate"] = toDate + " 23:59:59"
            if entityTypeId is not None:
                analytical_params["entityTypeId"] = entityTypeId
            fetch_records(
                client, "/profile/analyticalFeatures", "Gra.Analytical.Features.Entity.Value", "entityID", analytical_params
            )
        elif demisto.command() == "gra-cases-anomaly":
            caseId = arguments.get("caseId")
            anomaliesUrl = "/anomalies/" + caseId
            fetch_records(client, anomaliesUrl, "Gra.Cases.anomalies", "caseId", params)

        elif demisto.command() == "gra-incidents":
            status = arguments.get("status")
            incidents_url = "/incidents/v1/" + status
            fetch_records(client, incidents_url, "Gra.Incidents", "incidentId", params)

        elif demisto.command() == "gra-incident-action":
            action = arguments.get("action")
            incident_id = arg_to_number(arguments.get("incidentId"))
            sub_option = arguments.get("subOption")
            incident_comment = arguments.get("incidentComment")
            risk_accept_date = arguments.get("riskAcceptDate")
            incidents_url = "/incidents/" + action
            if action == "riskManageIncident":
                post_url = {
                    "incidentId": incident_id,
                    "subOption": sub_option,
                    "incidentComment": incident_comment,
                    "riskAcceptDate": risk_accept_date,
                }
            else:
                post_url = {
                    "incidentId": incident_id,
                    "subOption": sub_option,
                    "incidentComment": incident_comment,
                }
            fetch_post_records(client, incidents_url, "Gra.Incident.Action", "incidentId", params, json.dumps(post_url))

        elif demisto.command() == "gra-incident-action-anomaly":
            action = arguments.get("action")
            incident_id = arg_to_number(arguments.get("incidentId"))
            anomaly_names = arguments.get("anomalyNames")
            sub_option = arguments.get("subOption")
            incident_comment = arguments.get("incidentComment")
            risk_accept_date = arguments.get("riskAcceptDate")
            incidents_url = "/incidents/" + action
            if action == "riskAcceptIncidentAnomaly":
                post_url = {
                    "incidentId": incident_id,
                    "anomalyNames": anomaly_names,
                    "subOption": sub_option,
                    "incidentComment": incident_comment,
                    "riskAcceptDate": risk_accept_date,
                }
            else:
                post_url = {
                    "incidentId": incident_id,
                    "anomalyNames": anomaly_names,
                    "subOption": sub_option,
                    "incidentComment": incident_comment,
                }
            fetch_post_records(client, incidents_url, "Gra.Incident.Action.Anomaly", "incidentId", params, json.dumps(post_url))

        elif demisto.command() == "gra-incidents-anomaly":
            incident_id = arguments.get("incidentId")
            anomalies_url = "/v1/anomalies/" + str(incident_id)
            fetch_records(client, anomalies_url, "Gra.Incidents.anomalies", "incidentId", params)

        elif demisto.command() == "gra-alerts":
            status = arguments.get("status")
            start_date = arguments.get("startDate")
            end_date = arguments.get("endDate")
            alerts_url = "/alerts/v1/" + status
            alert_params = dict(params)
            if start_date:
                alert_params["startDate"] = start_date
            if end_date:
                alert_params["endDate"] = end_date
            fetch_records(client, alerts_url, "Gra.Alerts", "alertId", alert_params)

        elif demisto.command() == "gra-alert-get":
            alert_id = arg_to_number(arguments.get("id"))
            fetch_records(client, "/alerts/v1/getAlert", "Gra.Alert", "alertId", {"id": alert_id})

        elif demisto.command() in (
            "gra-alert-action",
            "gra-alert-comment",
            "gra-alert-assign",
            "gra-alert-in-progress",
        ):
            command = demisto.command()
            if command == "gra-alert-comment":
                action = "addCommentOnAlert"
            elif command == "gra-alert-assign":
                action = "assignAlert"
            elif command == "gra-alert-in-progress":
                action = "inProgressAlert"
            else:
                action = arguments.get("action")

            alert_id = arg_to_number(arguments.get("alertId"))
            alert_comment = arguments.get("alertComment", "")
            alerts_url = "/alerts/" + action
            alert_post_url: dict[str, Any] = {"alertId": alert_id, "alertComment": alert_comment}
            if action == "closeAlert":
                alert_post_url["incidentType"] = arguments.get("incidentType")
                alert_post_url["subStatus"] = arguments.get("subStatus")
            elif action == "assignAlert":
                alert_post_url["assigneeType"] = arguments.get("assigneeType")
                alert_post_url["assigneeName"] = arguments.get("assigneeName")
            fetch_post_records(client, alerts_url, "Gra.Alert.Action", "alertId", params, json.dumps(alert_post_url))

        elif demisto.command() == "gra-alert-update-history":
            alert_id = arg_to_number(arguments.get("alertId"))
            fetch_records(client, "/alerts/getAlertUpdateHistory", "Gra.Alert.History", "alertId", {"alertId": alert_id})

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
