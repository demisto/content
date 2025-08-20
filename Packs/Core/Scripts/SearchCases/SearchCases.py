import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *

class Client(CoreClient):
    def get_extra_data_for_case_id(
        self,
        case_id,
        issues_limit=1000,
    ) -> dict:
        """
        Returns incident by id

        :param incident_id: The id of incident
        :param alerts_limit: Maximum number alerts to get
        :return:
        """
        request_data = {"incident_id": case_id, "alerts_limit": issues_limit, "full_alert_fields": True}

        reply = self._http_request(
            method="POST",
            url_suffix="/incidents/get_incident_extra_data/",
            json_data={"request_data": request_data},
            headers=self._headers,
            timeout=self.timeout,
        )

        return reply.get("reply", {})


def extract_ids(command_res, field_name):
    ids = []
    if command_res:
        if isinstance(command_res, dict):
            ids = [command_res.get(field_name)] if field_name in command_res else []
        elif isinstance(command_res, list):
            ids = [c.get(field_name) for c in command_res if isinstance(c, dict) and field_name in c]
            
    return ids


def get_cases_with_extra_data(client, args):
    demisto.debug(f"Calling core-get-cases, {args=}")
    cases_results = execute_command("core-get-cases", args) or []
    demisto.debug(f"After calling core-get-cases, {cases_results=}")
    issues_limit = int(args.get("alerts_limit", 1000))
    issues_limit = min(issues_limit, 1000)
    final_results = []
    for case in cases_results:
        case_id = case.get("case_id")
        if not case_id:
            continue
        case_extra_data = client.get_extra_data_for_case_id(case_id)
        alerts = case_extra_data.get("alerts", {}).get("data")
        issue_ids = extract_ids(alerts, "alert_id")
        network_artifacts = case_extra_data.get("network_artifacts")
        file_artifacts = case_extra_data.get("file_artifacts")
        case.update({"issue_ids": issue_ids, "network_artifacts": network_artifacts, "file_artifacts": file_artifacts})
        final_results.append(case)
    
    return final_results
        


def main():  # pragma: no cover
    args = demisto.args()
    headers: dict = {}
    base_url = "/api/webapp/public_api/v1"
    proxy = demisto.params().get("proxy", False)
    verify_cert = not demisto.params().get("insecure", False)

    try:
        timeout = int(demisto.params().get("timeout", 120))
    except ValueError as e:
        demisto.debug(f"Failed casting timeout parameter to int, falling back to 120 - {e}")
        timeout = 120

    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers,
        timeout=timeout,
    )
    try:
        return_results(get_cases_with_extra_data(client, args))
    except Exception as e:
        return_error("Error occurred while retrieving cases. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
