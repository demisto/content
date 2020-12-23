from typing import Dict, Set

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

# Imports

from enum import Enum

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

headers: Dict[str, str] = {}
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
        if results and results.get("status") == "ok":
            return return_results('ok')
        else:
            return return_error(f"There was an error: {results.get('status', 'Failure')} - {results.get('error')}")
    except Exception as e:
        return_error(f"There was an error in testing connection to URL: {client._base_url},"
                     f"API Key: {client._headers['Authorization'].split()[-1]}. "
                     f"Please make sure that the API key is valid and has the right permissions, "
                     f"and that the URL is in the correct form. Error: {str(e)}")


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
    table_headers = ["ID", "Name", "SeverityType", "AttackVectorsUsePercentage", "AttackVectorsCount",
                     "Procedures", "Techniques", "SubTechniques", "References"]

    for mitigation in mitigations_results.get("mitigations", {}):
        extended_info = client.get_mitigation_by_id(mitigation["id"])
        severity_type = mitigation["severity"]["name"].capitalize()
        severity_percentage = round(extended_info["severity"]["percentage"], 2)

        mitigations_formatted.append({"ID": mitigation["id"],
                                      "Name": mitigation["name"],
                                      "SeverityType": severity_type,
                                      "AttackVectorsUsePercentage": severity_percentage,
                                      "AttackVectorsCount": mitigation["vectorCount"],
                                      "Procedures": mitigation["procedures"],
                                      "Techniques": mitigation["mitigations"],
                                      "SubTechniques": extended_info["subtechniques"],
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
    procedures_ids: Set[str] = set()
    mitigation_id = None
    privileged_users = []
    unprivileged_users = []

    privileged = argToBoolean(args.get("privileged", "True"))

    for mitigation in mitigations_results["mitigations"]:

        if mitigation["name"] == "Brute Force":
            mitigation_id = mitigation["id"]
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

    params = demisto.params()

    base_url = params['url']

    api_key = params['api_key']

    # Flag if use server proxy
    use_proxy = params.get('proxy', False)

    # Flag if use server 'verification'
    insecure = params.get('insecure', False)

    headers = {
        "Authorization": f"Bearer {api_key}"  # Replace ${token} with the token you have obtained
    }

    demisto.debug(" ---- MAIN CALL -----")
    demisto.debug(" ---- PARAMS -----")
    demisto.debug(f"base_url: {base_url}")
    demisto.debug(f"api_key: {api_key}")
    demisto.debug(f"insecure: {insecure}")
    demisto.debug(f"use_proxy: {use_proxy}")

    client = Client(base_url=base_url, headers=headers, proxy=use_proxy, verify=insecure)

    try:
        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            return api_test(client)

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
