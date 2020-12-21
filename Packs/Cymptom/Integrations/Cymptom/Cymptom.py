import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# type: ignore
# flake8: noqa
# mypy: ignore-errors


# Imports

from enum import Enum

from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

headers = {}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class MitigationsState(Enum):
    open = "open"
    archive = "archive"
    all = "all"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def api_test(self):
        """
        Sends a test api call to the management server.
        """
        results = self._http_request(
            method='GET',
            url_suffix='test'
        )

        return results

    def get_mitigations(self, timeout=60, mitigations_state=MitigationsState.open.value):
        data = {mitigations_state: mitigations_state.lower()}

        if mitigations_state == MitigationsState.all.value:
            data.pop(mitigations_state)

        return self._http_request(
            method='GET',
            url_suffix="mitigations",
            data=data,
            timeout=timeout

        )

    def get_mitigation_by_id(self, mitigation_id, timeout=60):
        return self._http_request(
            method='GET',
            url_suffix="mitigations/mitigation",
            params={"id": str(mitigation_id)},
            timeout=timeout
        )

    def get_mitigations_subtechnique_procedure_by_id(self, sub_tech_proc_id, timeout=60):
        return self._http_request(
            method='GET',
            url_suffix=f"mitigations/subtechnique-procedures/{str(sub_tech_proc_id)}",
            timeout=timeout
        )


def api_test(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to and the Connection to the service is successful.
    :param client: Cymptom client
    """
    try:
        results = client.api_test()
    except Exception as e:
        return_error(
            f"There was an error in testing connection to URL: {client._base_url}, API Key: {client._headers['Authorization'].split()[-1]}. "
            f"Please make sure that the API key is valid and has the right permissions, and that the URL is in the correct form. Error: {str(e)}")

    if results and results.get("status") == "ok":
        return return_results('ok')
    else:
        return return_error("There was an error")


def fetch_incidents(client: Client) -> None:
    """ Fetches incidents from Cymptom's mitigations """

    integration_context = demisto.getIntegrationContext()

    mitigations_results = client.get_mitigations()
    incidents = []
    for mitigation in mitigations_results["mitigations"]:
        incidents.append({
            "name": mitigation["name"],
            "rawJSON": json.dumps(mitigation)
        })
    demisto.incidents(incidents)
    integration_context['incidents'] = incidents
    demisto.setIntegrationContext(integration_context)


def get_mitigations(client: Client) -> CommandResults:
    """
    This function uses a client argument
    """
    args = demisto.args()
    timeout = args.get("timeout", 60)
    state = args.get("state", MitigationsState.open.value)
    timeout = int(timeout)

    mitigations_results = client.get_mitigations(timeout=timeout, mitigations_state=state)
    mitigations_formatted = []
    table_headers = ["ID", "Name", "Severity Type", "Attack Vectors Use Percentage", "Attack Vectors Count",
                     "Procedures", "Techniques", "Sub Techniques", "References"]

    for mitigation in mitigations_results["mitigations"]:
        extended_info = client.get_mitigation_by_id(mitigation["id"])

        severity_type = mitigation["severity"]["name"].capitalize()
        severity_percentage = round(extended_info["severity"]["percentage"], 2)

        mitigations_formatted.append({"ID": mitigation["id"],
                                      "Name": mitigation["name"],
                                      "Severity Type": severity_type,
                                      "Attack Vectors Use Percentage": severity_percentage,
                                      "Attack Vectors Count": mitigation["vectorCount"],
                                      "Procedures": mitigation["procedures"],
                                      "Techniques": mitigation["mitigations"],
                                      "Sub Techniques": extended_info["subtechniques"],
                                      "References": extended_info["references"]})

    readable_output = tableToMarkdown('Mitigations', mitigations_formatted, headers=table_headers)

    command_results = CommandResults(
        outputs_prefix="Cymptom.Mitigations",
        outputs_key_field="ID",
        readable_output=readable_output,
        outputs=mitigations_formatted,
    )
    return command_results


def get_users_with_cracked_passwords(client: Client):
    """
    This function uses a client argument
    """

    args = demisto.args()
    timeout = args.get("timeout", 60)
    timeout = int(timeout)

    mitigations_results = client.get_mitigations(timeout=timeout)
    users_formatted = []
    table_headers = ["Username"]
    procedures_ids = set()
    mitigation_id = None
    privileged_users = []
    unprivileged_users = []

    privileged = argToBoolean(args.get("privileged", "True"))

    for mitigation in mitigations_results["mitigations"]:

        if mitigation["name"] == "Brute Force":
            mitigation_id: int = mitigation["id"]
            break

    if mitigation_id:
        l_mitigations = client.get_mitigation_by_id(mitigation_id)

        for subtechnique in l_mitigations["subtechniques"]:
            if subtechnique["name"] == "Password Guessing":
                procedures_ids.add(subtechnique["id"])

    if procedures_ids:

        for proc_id in procedures_ids:
            l_users = client.get_mitigations_subtechnique_procedure_by_id(proc_id)

            if l_users:
                l_users = l_users[0]["targets"]
                for user in l_users:
                    if "Domain" in user["labels"]:
                        username_dict = user["name"]
                        if privileged and ("DomainAdmin" in user["labels"] or "ComputerAdmin" in user["labels"]):
                            privileged_users.append(username_dict)
                        else:
                            unprivileged_users.append(username_dict)

    if privileged_users:
        for username in privileged_users:
            users_formatted.append({"Username": username})
        readable_output = tableToMarkdown('Privileged Users With Cracked Passwords', privileged_users,
                                          headers=table_headers)
    elif unprivileged_users:
        for username in unprivileged_users:
            users_formatted.append({"Username": username})
        readable_output = tableToMarkdown('Unprivileged Users With Cracked Passwords', unprivileged_users,
                                          headers=table_headers)
    else:
        readable_output = tableToMarkdown('Users With Cracked Passwords', unprivileged_users,
                                          headers=table_headers)

    command_results = CommandResults(
        outputs_prefix="Cymptom.CrackedUsers",
        outputs_key_field="Username",
        readable_output=readable_output,
        outputs=users_formatted,
    )

    return command_results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    LOG(f'Command being called is: {demisto.command()}')

    base_url = demisto.params()['url']

    api_key = demisto.params()['api_key']

    # How many time before the first fetch to retrieve incidents
    first_fetch = demisto.params().get('fetch_time', '3 days').strip()

    # Flag if use server proxy
    use_proxy = demisto.params().get('proxy', False)

    # Flag if use server 'verification'
    insecure = demisto.params().get('insecure', False)

    headers = {
        "Authorization": f"Bearer {api_key}"  # Replace ${token} with the token you have obtained
    }

    demisto.debug(" ---- MAIN CALL -----")
    demisto.debug(" ---- PARAMS -----")
    demisto.debug(f"base_url: {base_url}")
    demisto.debug(f"api_key: {api_key}")
    demisto.debug(f"first_fetch: {first_fetch}")
    demisto.debug(f"insecure: {insecure}")
    demisto.debug(f"use_proxy: {use_proxy}")

    client = Client(base_url=base_url, headers=headers, proxy=use_proxy, verify=insecure)

    try:
        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            return api_test(client)

        # Set and define the fetch incidents command to run after activated via integration settings.
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client)

        elif demisto.command() == 'cymptom-get-mitigations':
            return_results(get_mitigations(client))

        elif demisto.command() == 'cymptom-get-users-with-cracked-passwords':
            return_results(get_users_with_cracked_passwords(client))

    # Log exceptions
    except Exception as e:
        demisto.log(str(e))
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
