import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" Imports """
import base64
import urllib.parse
from enum import Enum
from typing import Any

""" Global Variables """

INTEGRATION_NAME = "FortiSandbox"
INTEGRATION_PREFIX = "fortisandbox"
OUTPUTS_PREFIX = f"{INTEGRATION_NAME}.Submission"
SUBMISSION = "submission"
STEP_TO_NUMBER = {
    "anti_virus": "1",
    "cloud": "2",
    "sandbox": "4",
    "static_scan": "8",
}
COMMENT_MAX_LENGTH = 255
SCORE_TO_DBOT_SCORE = {
    -1: Common.DBotScore.NONE,
    0: Common.DBotScore.GOOD,
    1: Common.DBotScore.BAD,
    2: Common.DBotScore.BAD,
    3: Common.DBotScore.SUSPICIOUS,
    4: Common.DBotScore.SUSPICIOUS,
}
RATING_TO_DBOT_SCORE = {
    "canceled": Common.DBotScore.NONE,
    "Unknown": Common.DBotScore.NONE,
    "Clean": Common.DBotScore.GOOD,
    "Low Risk": Common.DBotScore.SUSPICIOUS,
    "Medium Risk": Common.DBotScore.SUSPICIOUS,
    "High Risk": Common.DBotScore.BAD,
    "Malicious": Common.DBotScore.BAD,
}
RELIABILITY = DBotScoreReliability.C
EXECUTION_METRICS = ExecutionMetrics()


class StatusCode(int, Enum):
    OK = 0
    DATA_NOT_EXIST = 3
    DATA_IN_QUEUE_OR_PROGRESS = 29


""" Client """


class Client(BaseClient):
    """Client class to interact with the API."""

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of the API.
            username (str | None, optional): The account username.
                Defaults to None.
            password (str | None, optional): The account password.
                Defaults to None.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to True.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        self.is_online = False
        self.username = username
        self.password = password
        self._session_id = ""

        super().__init__(
            base_url=urljoin(base_url, "jsonrpc"),
            verify=verify,
            proxy=proxy,
        )

    def login(self) -> None:
        """Attempt to login to the API.

        If successful a session ID will be returned which will be used in the body of each request.
        """
        raw_response = self._make_request(
            json_data={
                "id": 1,
                "ver": "2.3",
                "method": "exec",
                "params": [
                    {
                        "url": "/sys/login/user",
                        "user": self.username,
                        "passwd": self.password,
                    },
                ],
            },
        )
        self._session_id = raw_response["session"]
        self.is_online = True

    def logout(self) -> None:
        """Logout from the API."""
        if not self.is_online:
            return

        self._make_request(
            json_data={
                "id": 2,
                "ver": "2.0",
                "method": "exec",
                "session": self._session_id,
                "params": [{"url": "/sys/logout"}],
            },
        )
        self.is_online = False

    def submission_file_upload(
        self,
        file_name: str,
        file: str,
        comment: str | None = None,
        timeout: str | None = None,
        skip_steps: list[str] | None = None,
        archive_passwords: list[str] | None = None,
        overwrite_vm_list: str | None = None,
        force_vm_scan: bool = False,
        add_to_threat_package: bool = False,
        record: bool = False,
        enable_ai: bool = False,
    ) -> dict[str, Any]:
        """Upload a file to be sandboxed.

        Args:
            file_name (str): The name of the file to upload encoded in base64.
            file (str): The file content encoded in base64.
            comment (str | None, optional): A comment about the submission.
                Defaults to None.
            timeout (str | None, optional): Cancel processing a submission when timeout
                in seconds before entering virtual machine.
                Defaults to None.
            skip_steps (list[str] | None, optional): List of steps to skip from file analysis.
                Defaults to None.
            archive_passwords (list[str] | None, optional): List of passwords needed for extracting archived files.
                Defaults to None.
            overwrite_vm_list (str | None, optional): Comma-separated list of virtual machines to use..
                Defaults to None.
            force_vm_scan (bool, optional): Whether to for the file to be scanned in virtual machine.
                Defaults to False.
            add_to_threat_package (bool, optional): When set to true, the system will evaluate the sample and,
                if it qualifies, add it to the malware package.
                The default setting is false, indicating that the sample will not be added unless explicitly requested.
                Defaults to False.
            record (bool, optional): Record scan process in video if VMs are involved.
                Defaults to False.
            enable_ai (bool, optional): Enable Deep-AI mode for this scanning.
                Defaults to False.

        Returns:
            dict[str, Any]: The submission ID and status.
        """
        return self._make_request(
            json_data={
                "id": 11,
                "ver": "2.5",
                "method": "set",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/alert/ondemand/submit-file",
                        "type": "file",
                        "filename": file_name,
                        "file": file,
                        "comments": comment,
                        "timeout": timeout,
                        "skip_steps": skip_steps and ",".join([STEP_TO_NUMBER[step] for step in skip_steps]),
                        "archive_passwords": archive_passwords and "\n".join(archive_passwords),
                        "overwrite_vm_list": overwrite_vm_list,
                        "forcedvm": bool_to_int(force_vm_scan),
                        "malpackage": bool_to_str(add_to_threat_package),
                        "vrecord": bool_to_str(record),
                        "enable_ai": bool_to_int(enable_ai),
                    }
                ],
            },
        )

    def submission_url_upload(
        self,
        file_name: str,
        file: str,
        comment: str | None = None,
        timeout: str | None = None,
        depth: int | None = None,
        overwrite_vm_list: str | None = None,
        force_vm_scan: bool = False,
        add_to_threat_package: bool = False,
        record: bool = False,
        enable_ai: bool = False,
    ) -> dict[str, Any]:
        """Upload a file with URLs to be sandboxed.

        Args:
            file_name (str): The name of the file to upload encoded in base64.
            file (str): The file content encoded in base64.
            comment (str | None, optional): A comment about the submission.
                Defaults to None.
            timeout (str | None, optional): The time period to stop the URLs scan, in seconds.
                Defaults to None.
            depth (int | None, optional): The recursive depth in which URLs are examined.
                Level 0 for original URL page (between 0 and 5).
                Defaults to None.
            overwrite_vm_list (str | None, optional): Comma-separated list of virtual machines to use..
                Defaults to None.
            force_vm_scan (bool, optional): Whether to for the file to be scanned in virtual machine.
                Defaults to False.
            add_to_threat_package (bool, optional): When set to true, the system will evaluate the sample and,
                if it qualifies, add it to the threat package.
                The default setting is false, indicating that the sample will not be added unless explicitly requested.
                Defaults to False.
            record (bool, optional): Record scan process in video if VMs are involved.
                Defaults to False.
            enable_ai (bool, optional): Enable Deep-AI mode for this scanning.
                Defaults to False.

        Returns:
            dict[str, Any]: The submission ID and status.
        """
        return self._make_request(
            json_data={
                "id": 12,
                "ver": "2.2",
                "method": "set",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/alert/ondemand/submit-file",
                        "type": "url",
                        "filename": file_name,
                        "file": file,
                        "comments": comment,
                        "timeout": timeout,
                        "depth": depth,
                        "overwrite_vm_list": overwrite_vm_list,
                        "forcedvm": bool_to_int(force_vm_scan),
                        "malpackage": bool_to_str(add_to_threat_package),
                        "vrecord": bool_to_str(record),
                        "enable_ai": bool_to_int(enable_ai),
                    }
                ],
            },
        )

    def submission_cancel(self, sid: int) -> dict[str, Any]:
        """Cancel a submission with a given ID.

        Args:
            sid (int): The submission ID.

        Returns:
            dict[str, Any]: API response with status and message.
        """
        return self._make_request(
            json_data={
                "id": 16,
                "ver": "2.0",
                "method": "exec",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/alert/ondemand/cancel-submission",
                        "sid": sid,
                    }
                ],
            },
        )

    def submission_url_rating(self, urls: list[str]) -> dict[str, Any]:
        """Retrieve the URL rating for a given URL.

        Args:
            urls (list[str]): The URLs to retrieve the rating for.

        Returns:
            dict[str, Any]: The URL rating.
        """
        return self._make_request(
            json_data={
                "id": 14,
                "ver": "2.5",
                "method": "get",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/scan/result/urlrating",
                        "address": urls,
                    }
                ],
            },
        )

    def submission_job_verdict(self, jid: int) -> dict[str, Any]:
        """Retrieve the verdict for a given job ID.

        Args:
            jid (int): The job ID.

        Returns:
            dict[str, Any]: The job verdict.
        """
        return self._make_request(
            [StatusCode.OK.value, StatusCode.DATA_IN_QUEUE_OR_PROGRESS.value],
            json_data={
                "id": 15,
                "ver": "4.0.2",
                "method": "get",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/scan/result/job",
                        "jid": jid,
                    }
                ],
            },
        )

    def submission_file_verdict(self, checksum_type: str, checksum: str) -> dict[str, Any]:
        """Retrieve the verdict for a given file checksum.

        Args:
            checksum_type (str): The checksum type.
            checksum (str): The checksum value.

        Returns:
            dict[str, Any]: The file verdict.
        """
        return self._make_request(
            [StatusCode.OK.value, StatusCode.DATA_NOT_EXIST.value],
            json_data={
                "id": 10,
                "ver": "4.0.2",
                "method": "get",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/scan/result/file",
                        "ctype": checksum_type,
                        "checksum": checksum,
                    }
                ],
            },
        )

    def submission_job_list(self, sid: str) -> dict[str, Any]:
        """Retrieve the jobs of a given submission ID.

        Args:
            sid (str): The submission ID.

        Returns:
            dict[str, Any]: The jobs of the submission.
        """
        return self._make_request(
            json_data={
                "id": 17,
                "ver": "2.0",
                "method": "get",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/scan/result/get-jobs-of-submission",
                        "sid": sid,
                    }
                ],
            },
        )

    def submission_job_report(self, identifier_type: str, identifier: str) -> dict[str, Any]:
        """Retrieve a PDF report for a given identifier.

        Args:
            identifier_type (str): "jid" or "sha256".
            identifier (str): The identifier value.

        Returns:
            dict[str, Any]: The PDF report.
        """
        return self._make_request(
            json_data={
                "id": 50,
                "ver": "2.5",
                "method": "get",
                "session": self._session_id,
                "params": [
                    {
                        "url": "/scan/result/get-pdf-report",
                        "qtype": identifier_type,
                        "qval": identifier,
                    }
                ],
            },
        )

    def _make_request(self, accepted_codes: list[int] | None = None, **kwargs) -> dict[str, Any]:
        """Make a `POST` request to the API and validate the status code within the response.

        Args:
            accepted_codes (list[int] | None, optional): A list of codes that are accepted as valid responses.
                Defaults to None.
            **kwargs: The arguments to pass to the `http_request` method.

        Returns:
            dict[str, Any]: The API response.
        """
        response = self._http_request("POST", **kwargs)
        self.validate_response(response, accepted_codes)
        return response

    @staticmethod
    def validate_response(raw_response: dict[str, Any], accepted_codes: list[int] | None = None) -> None:
        """Validate the raw response from the API.

        In case the response's code is not within the accepted codes, update the error count in the execution metrics.

        Args:
            raw_response(dict[str, Any]): The API response body to validate.
            accepted_codes (list[int], optional): A list of codes that are accepted as valid responses.
                If the response's code isn't within the accepted codes, raise an error.
                Defaults to [0].

        Raises:
            DemistoException: If the response's code is not within the accepted codes,
                raises an exception with the response message.
        """
        status = dict_safe_get(raw_response, ["result", "status"], {})
        code = status.get("code")
        message = status.get("message", "")

        if code not in (accepted_codes or [StatusCode.OK.value]):
            if message == "INVALID_SESSION":
                EXECUTION_METRICS.service_error += 1
            elif message == "TIME_OUT":
                EXECUTION_METRICS.timeout_error += 1
            elif message in ["USER_HAS_NO_PERMISSION", "WRONG_CREDENTIAL"]:
                EXECUTION_METRICS.auth_error += 1
            else:
                EXECUTION_METRICS.general_error += 1

            raise DemistoException(f"Message from API: {message}")


""" Helper Commands  """


def bool_to_int(v: bool) -> int:
    """Converts a boolean value to an integer.

    Args:
        v (bool): A boolean value to convert.

    Returns:
        int: 1 if the boolean value is True, else 0.
    """
    return 1 if v else 0


def bool_to_str(v: bool) -> str:
    """Converts a boolean value to a string.

    Args:
        v (bool): A boolean value to convert.

    Returns:
        str: "1" if the boolean value is True, else "0".
    """
    return "1" if v else "0"


def build_dbot_score(
    indicator: str,
    indicator_type: str,
    score: int | None = None,
    rating: list[str] | str | None = None,
    detail_url: str | None = None,
) -> Common.DBotScore:
    """Build a DBotScore object.

    The `score` and `rating` arguments both provide a mapping to the DBotScore to be used, the differences between them
    is that `score` uses integers and `rating` uses a string.

    Args:
        indicator (str): The indicating entity.
        indicator_type (str): The type of the indicating entity.
        score (int | None, optional): The score of the indicating entity to be translated to a DBotScore.
            Defaults to None.
        rating (list[str] | str | None, optional): The rating of the indicating entity to be translated to a DBotScore.
            Defaults to None.
        detail_url (str | None, optional): The URL to the detailed report.
            Defaults to None.

    Returns:
        Common.DBotScore: The DBotScore object.
    """
    if score is not None:
        dbot_score = SCORE_TO_DBOT_SCORE.get(score, Common.DBotScore.NONE)
    elif rating is not None:
        if isinstance(rating, str):
            dbot_score = RATING_TO_DBOT_SCORE.get(rating, Common.DBotScore.NONE)
        else:
            dbot_score = RATING_TO_DBOT_SCORE.get(rating[0], Common.DBotScore.NONE)
    else:
        dbot_score = Common.DBotScore.NONE

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        score=dbot_score,
        reliability=RELIABILITY,
        message=detail_url,
    )


def build_relationship(entity_type: str, entity: str, malware: str) -> EntityRelationship:
    """Build an entity and malware relationship.

    Args:
        entity_type (str): The type of the entity.
        entity (str): The indicating entity
        malware (str): The indicated malware.

    Returns:
        EntityRelationship: The entity relationship.
    """
    return EntityRelationship(
        name=EntityRelationship.Relationships.INDICATOR_OF,
        entity_a=entity,
        entity_a_type=entity_type,
        entity_b=malware,
        entity_b_type=FeedIndicatorType.Malware,
        reverse_name=EntityRelationship.Relationships.INDICATED_BY,
        brand=INTEGRATION_NAME,
        source_reliability=RELIABILITY,
    )


def build_indicator(
    data: dict[str, Any],
    url: str | None = None,
    file_hash: str | None = None,
) -> Common.Indicator:
    """Build a URL or file indicator from the given job data.

    Args:
        data (dict[str, Any] | None): The job data to build the indicator from.
        url (str | None, optional): The URL to build the indicator from.
        file_hash (str | None, optional): The file hash to build the indicator from.

    Returns:
        Common.Indicator: The built indicator.
    """
    demisto.info(f"Building indicator with {data=}")
    entity: str
    indicator: Common.URL | Common.File

    score = data.get("score")
    rating = data.get("rating")
    malware_name = data.get("malware_name", [])
    detail_url: str = data.get("detail_url", "")

    # Get the request type from the detail URL, if it exists.
    parsed_url = urllib.parse.urlparse(detail_url)
    req_type = urllib.parse.parse_qs(parsed_url.query).get("req_type", [""])[0]

    # Set malware_name to a list if it's not already and remove "N/A" from the list.
    if not isinstance(malware_name, list):
        malware_name = [malware_name]

    malware_name = [malware for malware in malware_name if malware != "N/A"]

    demisto.debug(f"Indicator's malware name: {malware_name}")

    if url or req_type == "url-csearch":
        demisto.info("Indicator type is URL")
        entity_type = FeedIndicatorType.URL

        # If the entity has a download URL, decode it from base64, else use the input URL.
        if entity := data.get("download_url", ""):
            demisto.debug(f"Decoding download URL: {entity}")
            entity = base64.b64decode(entity).decode()
        else:
            demisto.debug(f"Using input URL: {url}")
            entity = data.get("url", url)

        dbot_score = build_dbot_score(
            indicator=entity,
            indicator_type=DBotScoreType.URL,
            score=score,
            rating=rating,
            detail_url=detail_url,
        )
        indicator = Common.URL(
            dbot_score=dbot_score,
            url=entity,
            category=category if (category := data.get("category")) and category != "NotApplicable" else None,
            malware_family=malware_name,
        )
    elif file_hash or req_type == "file-csearch":
        demisto.info("Indicator type is File")

        entity_type = FeedIndicatorType.File
        entity = data.get("sha256", file_hash)
        hash_type = get_hash_type(file_hash) if file_hash else "sha256"
        file_name: str = data.get("file_name", "")

        demisto.debug(f"Using hash type: {hash_type}")

        dbot_score = build_dbot_score(
            indicator=entity,
            indicator_type=DBotScoreType.FILE,
            score=score,
            rating=rating,
            detail_url=detail_url,
        )
        indicator = Common.File(
            dbot_score=dbot_score,
            name=file_name,
            extension=file_name.split(".")[-1],
            malware_family=malware_name,
            sha1=data.get("sha1"),
            **{hash_type: entity},
        )

    indicator.relationships = [
        build_relationship(
            entity_type=entity_type,
            entity=entity,
            malware=malware,
        )
        for malware in malware_name
    ]

    return indicator


def prepare_submission_content(args: dict[str, Any]) -> tuple[str, str]:
    """Prepares the content and file name for submission, handling both direct URL submissions and file uploads.

    This function supports preparing the submission content by either encoding the content of a file specified by
    `entry_id` in the arguments or by creating a text content from a list of URLs provided in `urls`.
    It ensures that either `entry_id` or `urls` is provided, but not both, and validates URLs if provided.
    Both the file name and content are returned base64-encoded to meet the API requirements.

    Args:
        args (dict[str, Any]): Arguments containing `entry_id` for file uploads or `urls` for direct URL submissions.

    Raises:
        DemistoException: If neither or both `entry_id` and `urls` are provided.

    Returns:
        tuple[str, str]: A tuple containing the base64-encoded file name and the base64-encoded content for submission.
    """
    file_name: str = ""
    content: bytes | str = ""

    entry_id = args.get("entry_id")
    urls = argToList(args.get("urls"))

    if not bool(entry_id) ^ bool(urls):
        raise DemistoException("Either `entry_id` or `urls` must be provided, not both.")
    elif entry_id:
        file_entry = demisto.getFilePath(entry_id)
        file_name = file_entry["name"].removesuffix("}")  # Remove the suffix added by `getFilePath` or prior commands.

        with open(file_entry["path"], "rb") as handler:
            content = handler.read()
    else:  # urls:
        file_name = f"urls_for_upload_{time.time()}.txt"
        content = "\n".join(urls)

    return b64_encode(file_name), b64_encode(content)


def poll_job_submissions(client: Client, args: dict[str, Any]) -> PollResult:
    """Poll for the verdicts/reports of the given submission job IDs.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        PollResult: The results of the polling, includes verdicts within CommandResults or fileResults.
    """
    sid = args["sid"]
    get_scan_report = argToBoolean(args.get("get_scan_report", False))

    integration_context = get_integration_context()
    demisto.debug(f"Fetching {integration_context=}")

    total_jids: int = integration_context.get("total_jids", 0)
    fetched_jids = set(integration_context.get("fetched_jids", []))
    remaining_jids = set(integration_context.get("remaining_jids", []))
    jid_to_raw_response: dict[str, dict[str, Any]] = integration_context.get("jid_to_raw_response", {})

    # Enter if the total number of jobs is not known yet, or if not all jobs were created.
    if not total_jids or (len(remaining_jids) + len(fetched_jids)) < total_jids:
        demisto.info(f"Polling for submission {sid} jobs.")
        raw_response = client.submission_job_list(sid)

        raw_response = dict_safe_get(raw_response, ["result", "data"], {})
        jids = set(raw_response.get("jids", []))
        total_jids = raw_response.get("total_jids", 0)

        remaining_jids = jids - fetched_jids if fetched_jids else jids

    # Poll for the verdicts/reports of the remaining jobs.
    for jid in remaining_jids.copy():
        demisto.debug(f"Polling for job {jid} verdict.")
        raw_response = client.submission_job_verdict(jid)
        data = dict_safe_get(raw_response, ["result", "data"])

        # If a result was fetched, add it to the list of results and remove it from the list of remaining jobs.
        if data:
            demisto.debug(f"Job {jid} verdict found.")
            fetched_jids.add(jid)
            remaining_jids.remove(jid)
            jid_to_raw_response[jid] = raw_response

    # Update the integration context with the new data for the next polling.
    integration_context = {
        "total_jids": total_jids,
        "fetched_jids": list(fetched_jids),
        "remaining_jids": list(remaining_jids),
        "jid_to_raw_response": jid_to_raw_response,
    }
    demisto.debug(f"Setting {integration_context=}")
    set_integration_context(integration_context)

    fetched_jids_count = len(fetched_jids)

    # If not all jobs were fetched, continue to poll.
    if not total_jids or fetched_jids_count < total_jids:
        demisto.info(f"Not all jobs were fetched for submission {sid}.")
        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run=args,
            partial_result=CommandResults(
                readable_output=(
                    f"## {fetched_jids_count} out of {total_jids} jobs were fetched for the submission {sid}."
                    if total_jids
                    else f"## No jobs were created yet for the submission {sid}."
                ),
            ),
        )

    # All jobs were fetched, clear the integration context and build the CommandResults or fileResult.
    demisto.info(f"All jobs were fetched for submission {sid}.")
    clear_integration_context()
    response = []

    for jid, raw_response in jid_to_raw_response.items():
        if get_scan_report:
            result = submission_job_report_command(client, {"identifier": jid})
        else:
            result = build_verdict_command_results(jid, raw_response)
            result.outputs["sid"] = sid

        response.append(result)

    if not get_scan_report:
        response.append(EXECUTION_METRICS.metrics)

    return PollResult(
        response=response,
        continue_to_poll=False,
    )


def clear_integration_context() -> None:
    """Clear all data within the integration context."""
    set_integration_context({})


def build_verdict_command_results(jid: str, raw_response: dict[str, Any]) -> CommandResults:
    """Build the command results for the verdict of a given job ID.

    Args:
        jid (str): The job ID.
        raw_response (dict[str, Any]): The raw response from the API.

    Returns:
        CommandResults: The command results for the verdict of the given job ID.
    """
    outputs = dict_safe_get(raw_response, ["result", "data"])

    if not outputs:
        return CommandResults(readable_output=f"## The job {jid} is still in progress.")

    download_url = outputs.get("download_url", "")
    outputs["name"] = base64.b64decode(download_url).decode()

    readable_output = tableToMarkdown(
        f"The verdict for the job {jid}:",
        outputs,
        headers=["jid", "name", "start_ts", "finish_ts", "category", "malware_name", "rating", "detail_url"],
        headerTransform=string_to_table_header,
    )
    indicator = build_indicator(outputs)

    return CommandResults(
        outputs_prefix=OUTPUTS_PREFIX,
        outputs_key_field="jid",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
        indicator=indicator,
    )


""" Command Handlers """


@logger
def test_module(client: Client) -> str:
    """Test the connection to the API.

    Args:
        client (Client): Session to the API to run HTTP requests.

    Returns:
        str: returns "ok" which represents that the test connection to the client was successful.
    """
    client.logout()
    return "ok"


@logger
def file_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Runs reputation on files.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent a list of entries in warroom.
    """
    file_hashes = argToList(args.get("file"))
    accepted_hash_types = ["md5", "sha1", "sha256"]
    command_results: list[CommandResults] = []

    for file_hash in file_hashes:
        hash_type = get_hash_type(file_hash)

        if hash_type not in accepted_hash_types:
            raise DemistoException(f"FortiSandbox - Hash type {hash_type} is not supported.")

        raw_response = client.submission_file_verdict(hash_type, file_hash)
        data = dict_safe_get(raw_response, ["result", "data"], {})

        EXECUTION_METRICS.success += 1

        if data:
            indicator = build_indicator(data, file_hash=file_hash)
            readable_output = tableToMarkdown(
                f"FortiSandbox - File/Hash Reputation for: {file_hash}",
                data,
                headers=["jid", "file_name", "start_ts", "finish_ts", "malware_name", "rating"],
                headerTransform=string_to_table_header,
            )

            command_result = CommandResults(
                readable_output=readable_output,
                raw_response=raw_response,
                indicator=indicator,
            )
        else:
            command_result = create_indicator_result_with_dbotscore_unknown(
                indicator=file_hash,
                indicator_type=DBotScoreType.FILE,
                reliability=RELIABILITY,
            )
            command_result.raw_response = raw_response

        command_results.append(command_result)

    if metrics := EXECUTION_METRICS.metrics:
        command_results.append(metrics)

    return command_results


@logger
def url_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Runs reputation on URLs.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent a list of entries in warroom.
    """
    urls = argToList(args.get("url"))
    raw_response = client.submission_url_rating(urls)
    data = dict_safe_get(raw_response, ["result", "data"])

    EXECUTION_METRICS.success += 1
    command_results: list[CommandResults] = []

    for item in data:
        url = item["url"]
        finish_ts = item.get("finish_ts")

        if finish_ts:
            indicator = build_indicator(item, url=url)
            readable_output = tableToMarkdown(
                f"{INTEGRATION_NAME} - URL Reputation for: {url}",
                data,
                headers=["url", "start_ts", "finish_ts", "rating"],
                headerTransform=string_to_table_header,
            )

            command_result = CommandResults(
                readable_output=readable_output,
                raw_response=raw_response,
                indicator=indicator,
            )
        else:
            command_result = create_indicator_result_with_dbotscore_unknown(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                reliability=RELIABILITY,
            )
            command_result.raw_response = raw_response

        command_results.append(command_result)

    if metrics := EXECUTION_METRICS.metrics:
        command_results.append(metrics)

    return command_results


@logger
@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    requires_polling_arg=False,
)
def submission_file_upload_command(args: dict[str, Any], client: Client) -> PollResult:
    """Scheduled command, upload a file to be sandboxed for the verdicts/reports of the given submission job IDs.

    Args:
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
        client (Client): Session to the API to run HTTP requests.

    Raises:
        DemistoException: If the comment is invalid.

    Returns:
        PollResult: The results of the polling, includes verdicts within CommandResults or fileResults.
    """
    comment = args.get("comment")

    if comment and len(comment) > COMMENT_MAX_LENGTH:
        raise DemistoException(f"The comment must be {COMMENT_MAX_LENGTH} characters or less.")

    if "sid" not in args:
        file_name, content = prepare_submission_content(args)
        raw_response = client.submission_file_upload(
            file_name=file_name,
            file=content,
            comment=comment,
            timeout=args.get("process_timeout"),
            skip_steps=argToList(args.get("skip_steps")),
            archive_passwords=args.get("archive_passwords"),
            overwrite_vm_list=args.get("overwrite_vm_list"),
            force_vm_scan=argToBoolean(args.get("force_vm_scan", False)),
            add_to_threat_package=argToBoolean(args.get("add_to_threat_package", False)),
            record=argToBoolean(args.get("record", False)),
            enable_ai=argToBoolean(args.get("enable_ai", False)),
        )
        args["sid"] = dict_safe_get(raw_response, ["result", "data", "sid"])
        demisto.info(f"Starting polling for submission {args['sid']}")

    return poll_job_submissions(client, args)


@logger
@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    requires_polling_arg=False,
)
def submission_url_upload_command(args: dict[str, Any], client: Client) -> PollResult:
    """Scheduled command, upload URLs through a text file or directly to be sandboxed individually.

    Args:
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
        client (Client): Session to the API to run HTTP requests.

    Raises:
        DemistoException: If the comment, depth, or process timeout are invalid.

    Returns:
        PollResult: The results of the polling, includes verdicts within CommandResults or fileResults.
    """
    comment = args.get("comment")
    depth = arg_to_number(args.get("depth"))
    process_timeout = args.get("process_timeout")

    if comment and len(comment) > COMMENT_MAX_LENGTH:
        raise DemistoException(f"The comment must be {COMMENT_MAX_LENGTH} characters or less.")

    if depth and not 0 <= depth <= 5:
        raise DemistoException("The depth must be between 0 and 5.")

    if (pt := arg_to_number(process_timeout)) is not None and not 30 <= pt <= 1200:
        raise DemistoException("The process timeout must be between 30 and 1200.")

    if "sid" not in args:
        file_name, content = prepare_submission_content(args)
        raw_response = client.submission_url_upload(
            file_name=file_name,
            file=content,
            comment=comment,
            timeout=process_timeout,
            depth=depth,
            overwrite_vm_list=args.get("overwrite_vm_list"),
            force_vm_scan=argToBoolean(args.get("force_vm_scan", False)),
            add_to_threat_package=argToBoolean(args.get("add_to_threat_package", False)),
            record=argToBoolean(args.get("record", False)),
            enable_ai=argToBoolean(args.get("enable_ai", False)),
        )
        args["sid"] = dict_safe_get(raw_response, ["result", "data", "sid"])
        demisto.info(f"Starting polling for submission {args['sid']}")

    return poll_job_submissions(client, args)


@logger
def submission_cancel_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Cancel a running job submission.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    sid = arg_to_number(args["id"], required=True) or 0  # Added 0 to avoid type error.
    raw_response = client.submission_cancel(sid)
    readable_output = f"## The cancellation of the submission {sid} was successfully sent."
    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def submission_job_verdict_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the verdict for a given submission job ID.

    Create a DBotScore and an indicator (URL or File) for the verdict.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    jid = args["id"]
    raw_response = client.submission_job_verdict(jid)
    return build_verdict_command_results(jid, raw_response)


@logger
def submission_job_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a list of jobs that were created from a submission.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    sid = args["id"]
    raw_response = client.submission_job_list(sid)

    jids = dict_safe_get(raw_response, ["result", "data", "jids"], [])
    outputs = [{"sid": sid, "jid": jid} for jid in jids]
    readable_output = tableToMarkdown(
        f"The submission {sid} job IDs:",
        jids,
        headers=["Jid"],
    )

    return CommandResults(
        outputs_prefix=OUTPUTS_PREFIX,
        outputs_key_field="jid",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def submission_job_report_command(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    """Retrieve a PDF report for a given identifier.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        dict[str, Any]: The PDF report.
    """
    identifier = args["identifier"]
    identifier_type = "sha256" if sha256Regex.match(identifier) else "jid"

    raw_response = client.submission_job_report(identifier_type, identifier)
    data = dict_safe_get(raw_response, ["result", "data"], {})

    return fileResult(
        filename=data.get("report_name"),
        data=base64.b64decode(data.get("report", "")),
        file_type=EntryType.ENTRY_INFO_FILE,
    )


""" Entry Point """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    global RELIABILITY
    RELIABILITY = params["integration_reliability"]
    base_url: str = params["base_url"]
    username = dict_safe_get(params, ["credentials", "identifier"])
    password = dict_safe_get(params, ["credentials", "password"])
    verify_certificate: bool = not argToBoolean(params.get("insecure", False))
    proxy: bool = argToBoolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")

    commands = {
        "file": file_command,
        "url": url_command,
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-cancel": submission_cancel_command,
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-job-verdict": submission_job_verdict_command,
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-job-list": submission_job_list_command,
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-job-report": submission_job_report_command,
    }
    scheduling_commands = {
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-file-upload": submission_file_upload_command,
        f"{INTEGRATION_PREFIX}-{SUBMISSION}-url-upload": submission_url_upload_command,
    }

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
        )
        client.login()

        if command == "test-module":
            results = test_module(client)
        elif command in scheduling_commands:
            results = scheduling_commands[command](args, client)
        elif command in commands:
            results = commands[command](client, args)
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

        return_results(results)

    except Exception as e:
        clear_integration_context()
        return_error(str(e))
    finally:
        client.logout()


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
