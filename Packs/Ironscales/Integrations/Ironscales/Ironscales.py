import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Dict

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, company_id: str, base_url: str, verify_certificate: bool, proxy: bool, headers: dict = None):
        self.company_id = company_id
        self.headers = headers
        super().__init__(base_url, verify_certificate, proxy)

    def get_jwt_token(self, api_key: str, scopes: list) -> Dict[str, Any]:
        jwt_key = self._http_request(
            method="POST",
            url_suffix="/get-token/",
            json_data={"key": api_key, "scopes": scopes},
        )
        return {"Authorization": f'JWT {jwt_key["jwt"]}'}

    def get_incident(self, incident_id: str, company_id=None) -> Dict[str, Any]:
        """Gets a specific Incident

        :type incident_id: ``str``
        :param incident_id: id of the incident to return
        :param company_id: company ID

        :return: dict containing the incident as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        if not company_id:
            company_id = self.company_id

        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{company_id}/details/{incident_id}",
            headers=self.headers,
            json_data={
                "company_id": company_id,
                "incident_id": incident_id,
            },
        )

    def classify_incident(
            self,
            incident_id: str,
            classification: str,
            prev_classification: str,
            classifying_user_email: str,
            company_id=None,
    ) -> str:

        if not company_id:
            company_id = self.company_id

        return self._http_request(
            method="POST",
            url_suffix=f"/incident/{company_id}/classify/{incident_id}",
            headers=self.headers,
            json_data={
                "incident_id": incident_id,
                "prev_classification": prev_classification,
                "classification": classification,
                "classifying_user_email": classifying_user_email,
            },
        )

    def get_open_incidents(
            self,
            company_id=None,
    ) -> Dict[str, Any]:

        if not company_id:
            company_id = self.company_id

        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{company_id}/open/",
            headers=self.headers,
        )


def get_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", None)
    company_id = args.get("company_id", None)

    incident = client.get_incident(incident_id, company_id)

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "created" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    # if 'created' in alert:
    #     created_time_ms = int(alert.get('created', '0')) * 1000
    #     alert['created'] = timestamp_to_datestring(created_time_ms)

    # tableToMarkdown() is defined is CommonServerPython.py and is used very
    # often to convert lists and dicts into a human readable format in markdown
    readable_output = tableToMarkdown(f"Ironscales Alert {incident_id}", incident)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Ironscales.Incident",
        outputs_key_field="incident_id",
        outputs=incident,
    )


def classify_incident_command(client: Client, args: Dict[str, Any]) -> str:
    incident_id = args.get("incident_id", None)
    company_id = args.get("company_id", None)
    classification = args.get("classification", None)
    prev_classification = args.get("prev_classification", None)
    email = args.get("email", None)

    if not (incident_id or classification or prev_classification or email):
        raise ValueError("Missing arguments!")

    classify = client.classify_incident(
        incident_id, classification, prev_classification, email, company_id
    )

    if classify:
        return "Classification Succeeded!"
    else:
        return "Classification Failed!"


def get_open_incidents_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    company_id = args.get("company_id", None)

    open_incidents = client.get_open_incidents(company_id)
    if open_incidents:
        readable_output = tableToMarkdown("Open Incidents:", open_incidents)
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="Ironscales.OpenIncidents",
            outputs_key_field="incident_ids",
            outputs=open_incidents,
        )
    return "No open incidents were found"


def test_module(client: Client, api_key, scopes) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_jwt_token(api_key, scopes)
    except DemistoException as e:
        if "FORBIDDEN" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def fetch_incidents(client: Client, last_run: Dict[str, Any]):
    last_run = last_run.get("data", None)
    if last_run is None:
        last_run = set()
    else:
        last_run = set(last_run)

    incidents_to_create = []
    new_incidents = client.get_open_incidents()["incident_ids"]
    if not new_incidents:
        new_incidents = set()

    incidents = set(new_incidents) - last_run

    for incident in incidents:
        data = client.get_incident(incident)
        incident_name = f"Ironscales incident: IS-{incident}"
        incident = {
            "name": incident_name,
            "occurred": data.get("first_reported_date"),
            "rawJSON": json.dumps(data),
        }

        incidents_to_create.append(incident)

    return list(new_incidents), incidents_to_create


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Remove trailing slash to prevent wrong URL path to service
    api_key = demisto.params().get("apikey")
    scopes = [demisto.params().get("scopes")]
    company_id = demisto.params().get("company_id")
    base_url = urljoin(demisto.params()["url"], "/appapi")

    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")

    try:
        client = Client(
            company_id,
            base_url,
            verify_certificate,
            proxy,
        )
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, api_key, scopes)
            return_results(result)
        else:
            headers = client.get_jwt_token(api_key, scopes)
            client.headers = headers

            if demisto.command() == "ironscales-get-incident":
                return_results(get_incident_command(client, demisto.args()))

            elif demisto.command() == "ironscales-classify-incident":
                return_results(classify_incident_command(client, demisto.args()))

            elif demisto.command() == "ironscales-get-open-incidents":
                return_results(get_open_incidents_command(client, demisto.args()))

            elif demisto.command() == "fetch-incidents":
                next_run, incidents = fetch_incidents(
                    client=client,
                    last_run=demisto.getLastRun(),
                )
                demisto.setLastRun({"data": next_run})
                demisto.incidents(incidents)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
