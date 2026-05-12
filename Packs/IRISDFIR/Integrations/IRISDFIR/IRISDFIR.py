import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS """

verify_cert = not demisto.params().get("insecure", False)
proxies = handle_proxy()


state_phases = {
    "In progress": 2,
    "Opened": 3,
    "Containement": 4,
    "Eradication": 5,
    "Recovery": 6,
    "Post-Incident": 7,
    "Reporting": 8,
    "Closed": 9,
}


class DFIRIrisAPI:
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {self.api_key}", "User-Agent": "Defined"}

    def get_last_case_id(self):
        response = requests.get(
            f"{self.api_endpoint}/manage/cases/list", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                list = []
                counter = 0
                for last_case in cases["data"]:
                    list.append(last_case["case_id"])
                    counter += 1

                return cases["data"][list.index(max(list))]
            else:
                return "No cases found."
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def get_all_cases(self):
        response = requests.get(
            f"{self.api_endpoint}/manage/cases/list", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return sorted(cases["data"], key=lambda k: k["case_id"], reverse=True)
            else:
                return "No cases found."
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def close_case(self, case_id):
        response = requests.post(
            f"{self.api_endpoint}/manage/cases/close/{case_id}", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return cases["data"]
            else:
                return "No case found."
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def reopen_case(self, case_id):
        response = requests.post(
            f"{self.api_endpoint}/manage/cases/reopen/{case_id}", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return cases["data"]
            else:
                return "No case found."
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def update_case_state(self, case_id, case_name, case_state):
        body = {"case_name": case_name, "state_id": state_phases[case_state]}

        response = requests.post(
            f"{self.api_endpoint}/manage/cases/update/{case_id}",
            headers=self.headers,
            verify=verify_cert,
            proxies=proxies,
            json=body,
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return cases["data"]
            else:
                return cases["message"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def create_notes_group(self, case_id, group_title):
        body = {"group_title": group_title, "cid": case_id}

        response = requests.post(
            f"{self.api_endpoint}/case/notes/groups/add", headers=self.headers, verify=verify_cert, proxies=proxies, json=body
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:  # noqa: RET503
                return cases["data"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def add_new_note_to_group(self, case_id, note_title, note_content, group_id):
        body = {"note_title": note_title, "cid": case_id, "note_content": note_content, "group_id": group_id}

        response = requests.post(
            f"{self.api_endpoint}/case/notes/add", headers=self.headers, verify=verify_cert, proxies=proxies, json=body
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:  # noqa: RET503
                return cases["data"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def get_list_of_groups_and_notes(self, case_id):
        response = requests.get(
            f"{self.api_endpoint}/case/notes/groups/list?cid={case_id}", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:  # noqa: RET503
                return cases["data"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def get_list_of_iocs(self, case_id):
        response = requests.get(
            f"{self.api_endpoint}/case/ioc/list?cid={case_id}", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:   # noqa: RET503
                return cases["data"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")

    def get_ioc_content(self, case_id, ioc_id):
        response = requests.get(
            f"{self.api_endpoint}/case/ioc/{ioc_id}?cid={case_id}", headers=self.headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return cases["data"]
            else:
                return cases["message"]
        else:
            raise DemistoException(f"Request failed with status code {response.status_code}.")


""" COMMAND FUNCTIONS """


def fetch_incidents(dfir_iris, params):
    context = demisto.getLastRun()
    cases = dfir_iris.get_all_cases()

    incidentLastCaseID = int(params.get("incidentLastCaseID", 0))
    LastCaseId = context.get("lastCaseId", incidentLastCaseID)

    incidents = []
    for case in cases:
        if case["case_id"] == LastCaseId:
            demisto.info("The case number is the same, do not continue the process")
            break
        if case["case_id"] < LastCaseId:
            demisto.info("The previous case was deleted, do not continue the process")
            break
        incident = {"name": case["case_name"], "rawJSON": json.dumps(case)}

        incidents.append(incident)

    return incidents, cases[0]["case_id"]


def test_module(dfir_iris):
    try:
        headers = {"Authorization": f"Bearer {dfir_iris.api_key}", "User-Agent": "Defined"}

        response = requests.get(
            f"{dfir_iris.api_endpoint}/manage/cases/list", headers=headers, verify=verify_cert, proxies=proxies
        )

        if response.status_code == 200:
            return "ok"
        else:
            if response.status_code == 401:
                raise DemistoException("Authorization Error: make sure API Key is correctly set")
            else:
                raise DemistoException(f"Not able to connect to {dfir_iris.api_endpoint}")

    except DemistoException as e:
        if "Forbidden" in str(e):
            raise DemistoException("Authorization Error: make sure API Key is correctly set")
        else:
            raise e


def process_iris_get_last_case_id(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    results = dfir_iris.get_last_case_id()

    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_get_all_cases(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    results = dfir_iris.get_all_cases()

    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_close_case(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    results = dfir_iris.close_case(case_id)

    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_reopen_case(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    results = dfir_iris.reopen_case(case_id)
    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_update_case_state(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    case_name = args.get("case_name")
    case_state = args.get("case_state")

    results = dfir_iris.update_case_state(case_id, case_name, case_state)

    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_create_notes_group(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    group_title = args.get("group_title")

    results = dfir_iris.create_notes_group(case_id, group_title)
    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_add_new_note_to_group(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    note_title = args.get("note_title")
    note_content = args.get("note_content")
    group_id = args.get("group_id")

    results = dfir_iris.add_new_note_to_group(case_id, note_title, note_content, group_id)
    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_get_list_of_groups_and_notes(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")

    results = dfir_iris.get_list_of_groups_and_notes(case_id)
    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_get_list_of_iocs(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    results = dfir_iris.get_list_of_iocs(case_id)

    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


def process_get_ioc_content(dfir_iris, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    ioc_id = args.get("ioc_id")

    results = dfir_iris.get_ioc_content(case_id, ioc_id)
    readable_output = tableToMarkdown('Command successfully sent to IRIS DFIR"', results, removeNull=True)

    return CommandResults(
        outputs_prefix="IRIS",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=results,
    )


""" MAIN FUNCTION """


def main():
    """COMMANDS MANAGER / SWITCH PANEL"""
    params = demisto.params()
    command = demisto.command()

    demisto.info(f"Command being called is {command}")
    try:
        # initialized Authentication client
        api_key = params.get("api_key", {}).get("password", "")
        api_endpoint = params.get("host")
        dfir_iris = DFIRIrisAPI(api_endpoint, api_key)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(dfir_iris)
            return_results(result)

        elif command == "fetch-incidents":
            incidents, lastCaseId = fetch_incidents(dfir_iris, demisto.params())
            demisto.incidents(incidents)

            demisto.setLastRun({"lastCaseId": lastCaseId})

        elif command == "iris-get-last-case-id":
            return_results(process_iris_get_last_case_id(dfir_iris, demisto.args()))
        elif command == "iris-get-all-cases":
            return_results(process_get_all_cases(dfir_iris, demisto.args()))
        elif command == "iris-close-case-id":
            return_results(process_close_case(dfir_iris, demisto.args()))
        elif command == "iris-reopen-case-id":
            return_results(process_reopen_case(dfir_iris, demisto.args()))
        elif command == "iris-change-case-state":
            return_results(process_update_case_state(dfir_iris, demisto.args()))
        elif command == "iris-create-notes-group":
            return_results(process_create_notes_group(dfir_iris, demisto.args()))
        elif command == "iris-add-new-note-to-group":
            return_results(process_add_new_note_to_group(dfir_iris, demisto.args()))
        elif command == "iris-get-list-of-groups-and-notes":
            return_results(process_get_list_of_groups_and_notes(dfir_iris, demisto.args()))
        elif command == "iris-get-list-of-iocs":
            return_results(process_get_list_of_iocs(dfir_iris, demisto.args()))
        elif command == "iris-get-ioc-content":
            return_results(process_get_ioc_content(dfir_iris, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to process incidents. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
