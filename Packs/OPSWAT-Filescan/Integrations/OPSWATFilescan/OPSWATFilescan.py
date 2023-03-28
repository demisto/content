from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
from typing import Any, Dict, List
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS """
INTEGRATION_NAME = "OPSWAT Filescan Integration"
INTEGRATION_CONTEXT_NAME = "OPSWAT.Filescan"


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key

        if self.api_key:
            self._headers = {"X-Api-Key": self.api_key}

    def test_module(self) -> Dict:
        """
        Return information about the user. (Need API key)
        """
        request_result = self._http_request(
            method="GET",
            ok_codes=([200]),
            url_suffix="/users/me",
        )
        return request_result

    def post_sample(self, args: Dict[str, Any]) -> Dict[str, Any]:
        data = {}

        if description := args.get("description"):
            data["description"] = description
        if tags := args.get("tags"):
            data["tags"] = tags
        if password := args.get("password"):
            data["password"] = password
        if is_private := args.get("is_private"):
            data["is_private"] = is_private

        if url := args.get("url"):
            data["url"] = url

            return self._http_request(
                method="POST", url_suffix="/scan/url", ok_codes=([200]), data=data
            )

        elif entry_id := args.get("entry_id"):
            try:
                file_entry = demisto.getFilePath(entry_id)
            except Exception as e:
                raise DemistoException(
                    f'Failed to find file entry with id:"{entry_id}". got error: {e}'
                )

            with open(file_entry["path"], "rb") as file:
                return self._http_request(
                    method="POST",
                    url_suffix="/scan/file",
                    ok_codes=([200]),
                    data=data,
                    files={"file": file},
                )
        else:
            raise DemistoException("No file or URL was provided.")

    def get_scan_result(self, flow_id: str) -> Dict[str, Any]:

        filters = [
            "filter=general",
            "filter=finalVerdict",
            "filter=allTags",
            "filter=overallState",
            "filter=taskReference",
            "filter=subtaskReferences",
            "filter=allSignalGroups",
        ]

        postfix = "&".join(filters)

        url_suffix = f"/scan/{flow_id}/report?{postfix}"

        response = self._http_request(
            method="GET",
            ok_codes=([200]),
            url_suffix=url_suffix,
        )

        return response

    def get_search_query(self, query_str: str) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            ok_codes=([200]),
            params={"query": query_str, "page_size": 10, "page": 1},
            url_suffix="/reports/search",
        )


""" HELPER FUNCTIONS """


def build_one_reputation_result(report: Dict[str, Any]):
    score = Common.DBotScore.NONE

    final_verdict = report.get("finalVerdict", {})
    verdict = final_verdict.get("verdict")
    if verdict == "BENIGN" or verdict == "INFORMATIONAL":
        score = Common.DBotScore.GOOD
    elif verdict == "MALICIOUS" or verdict == "LIKELY_MALICIOUS":
        score = Common.DBotScore.BAD
    elif verdict == "SUSPICIOUS":
        score = Common.DBotScore.SUSPICIOUS
    else:
        score = Common.DBotScore.NONE

    report_file = report.get("file", {})
    report_hash = report_file.get("hash", None)

    dbot_score = Common.DBotScore(
        indicator=report_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name="OPSWAT Filescan",
        score=score,
    )

    file = Common.File(
        name=report_file.get("name"), sha256=report_hash, dbot_score=dbot_score
    )

    tags = [tag.get("tag", {}).get("name") for tag in report.get("allTags", [])]
    subtasks = [subtask.get("name") for subtask in report.get("subtaskReferences", [])]
    human_readable = {
        "FileName": report_file.get("name"),
        "FileHash": report_hash,
        "FileType": report_file.get("type"),
        "FinalVerdict": report.get("finalVerdict", {}).get("verdict"),
        "Tags": tags,
        "SubtaskReferences": subtasks,
    }
    readable_output = tableToMarkdown("Scan Result (digest):", human_readable)

    results = CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Analysis",
        outputs_key_field="sha256",
        outputs=report,
        raw_response=report,
        readable_output=readable_output,
        indicator=file,
    )
    return results


def build_serach_query_result(
    query_str: str, raw_result: Dict[str, Any]
) -> List[CommandResults]:
    def build_analysis_hr(analysis: Dict[str, Any]) -> Dict[str, Any]:
        file_result = analysis.get("file", {})
        hr_analysis = {
            "Id": analysis.get("id"),
            "SampleName": file_result.get("name"),
            "SHA256": file_result.get("sha256"),
            "Verdict": analysis.get("verdict"),
            "State": analysis.get("state"),
            "Date": analysis.get("date"),
            "MIMEType": file_result.get("mime_type"),
            "Type": file_result.get("short_type"),
            "Tags": analysis.get("tags"),
        }
        return hr_analysis

    def build_indicator_object(analysis: Dict[str, Any]):
        score = Common.DBotScore.NONE

        verdict = analysis.get("verdict", "UNKNOWN")
        if verdict.upper() == "BENIGN" or verdict.upper() == "INFORMATIONAL":
            score = Common.DBotScore.GOOD
        elif verdict.upper() == "UNKNOWN":
            score = Common.DBotScore.NONE
        elif verdict.upper() == "SUSPICIOUS":
            score = Common.DBotScore.SUSPICIOUS
        else:
            score = Common.DBotScore.BAD

        analysis_file = analysis.get("file", {})
        dbot_score = Common.DBotScore(
            indicator=analysis_file.get("sha256"),
            indicator_type=DBotScoreType.FILE,
            integration_name="OPSWAT Filescan",
            score=score,
        )

        file = Common.File(
            name=analysis_file.get("name"),
            sha256=analysis_file.get("sha256"),
            dbot_score=dbot_score,
        )

        headers = ["File Name", "SHA256", "Verdict"]
        hr = {
            "File Name": analysis_file.get("name"),
            "SHA256": analysis_file.get("sha256"),
            "Verdict": verdict,
        }
        results = CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Analysis",
            outputs_key_field="sha256",
            outputs=hr,
            readable_output=tableToMarkdown("File Result:", hr, headers),
            indicator=file,
        )
        return results

    hr_headers = [
        "Id",
        "SampleName",
        "SHA256",
        "Verdict",
        "State",
        "Date",
        "MIMEType",
        "Type",
        "Tags",
    ]

    command_res_ls = []
    hr_analysis_ls = []

    analyses = raw_result.get("items", {})

    for analysis in analyses:
        hr_analysis_ls.append(build_analysis_hr(analysis))
        command_res_ls.append(build_indicator_object(analysis))

    command_result = CommandResults(
        outputs=analyses,
        readable_output=tableToMarkdown("Analysis Result:", hr_analysis_ls, hr_headers),
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Analysis",
    )

    command_res_ls.append(command_result)
    return command_res_ls


def sample_submission(client: Client, args: Dict[str, Any]) -> PollResult:
    res = client.post_sample(args)
    partial_res = CommandResults(
        readable_output=f'Waiting for submission "{res.get("flow_id")}" to finish...'
    )
    return PollResult(
        response=CommandResults(
            outputs=res,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Submission",
            outputs_key_field="flow_id",
        ),
        args_for_next_run={"flow_id": res.get("flow_id"), **args},
        continue_to_poll=True,
        partial_result=partial_res,
    )


def build_reputation_result(api_reponse: Dict[str, Any]):
    reports = api_reponse.get("reports", {})

    if len(reports) == 1:
        first_report = next(iter((api_reponse.get("reports", {}).items())))[1]
        return build_one_reputation_result(first_report)

    elif len(reports) > 1:
        command_res_ls = []
        for report in reports:
            command_res_ls.append(build_one_reputation_result(reports[report]))
        return command_res_ls


def is_valid_pass(api_response: Dict[str, Any]):
    if "rejected_files" not in api_response:
        return True
    for reject in api_response["rejected_files"]:
        if reject.get("rejected_reason") == "INVALID_PASSWORD":
            return False
    return True


@polling_function(
    name=demisto.command(),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    interval=1,
    poll_message="Polling result",
    requires_polling_arg=False,
)
def polling_submit_command(args: Dict[str, Any], client: Client):

    if flow_id := args.get("flow_id"):
        api_response = client.get_scan_result(flow_id)
        successful_response = False

        if api_response.get("allFinished", False):
            successful_response = True

        if successful_response:
            if not is_valid_pass(api_response):
                raise DemistoException("Invalid password!")

            return PollResult(
                response=build_reputation_result(api_response), continue_to_poll=False
            )

        return PollResult(
            response=[
                CommandResults(
                    outputs=api_response,
                    outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Submission",
                    outputs_key_field="flow_id",
                    readable_output=f'Waiting for submission "{api_response.get("flow_id")}" to finish...',
                ),
            ],
            continue_to_poll=True,
            args_for_next_run={"flow_id": args.get("flow_id"), **args},
        )
    else:
        return sample_submission(client, args)


""" COMMANDS """


def test_module_command(client: Client, *_) -> str:
    """Performs a basic GET request to check if the API is reachable and authentication is successful."""
    results = client.test_module()
    if "accountId" in results:
        return "ok"
    raise DemistoException("\nTest module failed, {}".format(results))


def scan_command(client: Client, args: Dict[str, Any]):
    return polling_submit_command(args=args, client=client)


def search_query_command(client: Client, args: Dict[str, Any]):
    query_string = args.get("query", "")
    result = client.get_search_query(query_string)
    if result:
        return build_serach_query_result(query_string, result)
    return CommandResults(readable_output="No Results were found.")


""" COMMANDS MANAGER / SWITCH PANEL """


def main():

    params = demisto.params()
    base_url = params.get("url", "")
    api_key = params.get('api_key', {}).get('password')
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    args = demisto.args()

    try:
        client = Client(api_key=api_key, base_url=base_url, verify=verify, proxy=proxy)
        handle_proxy()

        if command == "test-module":
            return_results(test_module_command(client))
        elif command == "filescan-scan-url":
            return_results(scan_command(client, args))
        elif command == "filescan-scan-file":
            return_results(scan_command(client, args))
        elif command == "filescan-search-query":
            return_results(search_query_command(client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except Exception as e:
        err_msg = f"Exception in {INTEGRATION_NAME} : Failed to execute {command} command: [{e!r}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
