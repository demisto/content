import hashlib

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from urllib3 import disable_warnings

from CommonServerUserPython import *

INTEGRATION_COMMAND_NAME = "lastline"
INTEGRATION_NAME = "Lastline v2"

SUFFIX_TRANSFORMER = {
    "/analysis/submit/file": {"url": "papi/analysis/submit_file", "method": "POST"},
    "/analysis/get": {"url": "papi/analysis/get_result", "method": "GET"},
    "/analysis/get_completed": {"url": "papi/analysis/get_history", "method": "GET"},
    "/analysis/submit/url": {"url": "papi/analysis/submit_url", "method": "POST"},
}

disable_warnings()


class Client(BaseClient):
    MD5_LEN = 32
    SHA1_LEN = 40
    SHA256_LEN = 64
    DEFAULT_THRESHOLD = 70

    def __init__(self, base_url: str, api_params: dict, verify=True, proxy=False, credentials: dict = None, threshold=None):
        self.command_params = api_params
        self.threshold = threshold if threshold else Client.DEFAULT_THRESHOLD
        if credentials:
            self.credentials = {"username": credentials.get("identifier"), "password": credentials.get("password")}
        else:
            self.credentials = {}

        super().__init__(base_url, verify, proxy)

    def file(self):
        human_readable = ""
        context_entry: dict = {"Lastline": [], "File": [], "DBotScore": []}
        result = []
        hash_arg = argToList(self.command_params.get("file"))
        for arg in hash_arg:
            hash_type = hash_type_checker(arg)
            self.command_params[hash_type] = arg
            temp_result = self.http_request("/analysis/submit/file")
            temp_human_readable, temp_context_entry = report_generator(temp_result, self.threshold)
            human_readable += f"\n{temp_human_readable}"
            context_entry["Lastline"].append(temp_context_entry.get("Lastline"))
            context_entry["File"].append(temp_context_entry.get("File"))
            context_entry["DBotScore"].append(temp_context_entry.get("DBotScore"))
            result.append(temp_result)
            del self.command_params[hash_type]
        return human_readable, context_entry, result

    def check_status(self):
        result = self.http_request("/analysis/get")
        human_readable, context_entry = report_generator(result, self.threshold)
        return human_readable, context_entry, result

    def get_report(self):
        result = self.http_request("/analysis/get")
        if "data" in result and "score" not in result["data"]:
            uuid = self.command_params.get("uuid")
            raise DemistoException(f"task {uuid} is not ready")
        human_readable, context_entry = report_generator(result, self.threshold)
        return human_readable, context_entry, result

    def get_task_list(self):
        for param in ("before", "after"):
            if param in self.command_params:
                self.command_params[param] = self.command_params[param].replace("T", " ")
        result = self.http_request("/analysis/get_completed")
        if "data" in result:  # noqa: RET503
            context_entry: list = []
            if self.credentials:
                context_entry = self.get_status_and_time_from_get_history_response(argToList(result["data"]))
            else:
                context_entry = self.get_status_and_time(argToList(result["data"].get("tasks")))

            for i in range(len(context_entry)):
                context_entry[i] = {"UUID": context_entry[i][0], "Time": context_entry[i][1], "Status": context_entry[i][2]}
            human_readable = tableToMarkdown(name="tasks", t=context_entry, headers=["UUID", "Time", "Status"])
            return human_readable, {}, result

    def upload_file(self):
        entry_id = self.command_params.get("EntryID")
        self.command_params["push_to_portal"] = True
        file_params = demisto.getFilePath(entry_id)
        file_type = os.path.splitext(file_params["name"])[1]
        self.command_params["md5"] = file_hash(file_params.get("path"))
        # csv files requires different approach
        if file_type == ".csv":
            result = self.handle_csv(file_params)
        else:
            result = self.http_request("/analysis/submit/file", file_to_upload=file_params.get("path"))

        human_readable, context_entry = report_generator(result, self.threshold)
        return human_readable, context_entry, result

    def handle_csv(self, file_params):
        self._session.post(self._base_url + "/papi/login", data=self.credentials, verify=self._verify)
        with open(file_params["path"], "rb") as file_:
            result = self._session.post(
                self._base_url + "/papi/analysis/submit_file",
                data={"filename": file_params["name"]},
                files={"file": (file_params.get("path"), file_.read())},
                verify=self._verify,
            ).json()

        lastline_exception_handler(result)
        return result

    def upload_url(self):
        result = self.http_request("/analysis/submit/url")
        human_readable, context_entry = report_generator(result, self.threshold)
        return human_readable, context_entry, result

    def test_module_command(self):
        self.command_params.update({"after": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")})
        self.get_task_list()
        return "ok", {}, {}

    def get_status_and_time(self, uuids) -> list:
        task_list: list[list] = []
        for uuid in uuids:
            self.command_params["uuid"] = uuid
            result = self.http_request("/analysis/get")
            if "data" in result:
                task_time = result["data"].get("submission")
                if "score" in result["data"]:
                    status = "Completed"
                else:
                    status = "Analyzing"
            else:
                task_time = status = ""
            task_list.append([uuid, task_time.replace(" ", "T"), status])
        return task_list

    def get_status_and_time_from_get_history_response(self, tasks) -> list:
        task_list: list[list] = []
        filtered_tasks: list = []
        uuid_set: set = {[x.get("task_uuid") for x in tasks]}

        for uuid in uuid_set:
            tasks_same_uuid = [x for x in tasks if x.get("task_uuid") == uuid]
            latest_date = max(datetime.strptime(x.get("task_start_time"), "%Y-%m-%d %H:%M:%S") for x in tasks_same_uuid)
            latest_date_str = latest_date.strftime("%Y-%m-%d %H:%M:%S")
            task = [x for x in tasks_same_uuid if x.get("task_start_time") == latest_date_str][0]
            filtered_tasks.append(task)

        for task in filtered_tasks:
            task_time = task.get("task_start_time")
            if task.get("status"):
                status = task.get("status")
            else:
                status = "Analyzing"

            task_list.append([task.get("task_uuid"), task_time.replace(" ", "T"), status])
        return task_list

    def http_request(self, path: str, headers=None, file_to_upload=None) -> dict:
        if file_to_upload:
            with open(file_to_upload, "rb") as _file:
                file_to_upload = {"file": (file_to_upload, _file.read())}

        result: dict = {}
        if self.credentials:
            url_suffix = SUFFIX_TRANSFORMER[path]
            result = self._http_request(
                url_suffix["method"],
                url_suffix["url"],
                data=self.credentials,
                params=self.command_params,
                files=file_to_upload,
                timeout=2000,
            )
        else:
            result = self._http_request("POST", path, params=self.command_params, headers=headers, files=file_to_upload)

        lastline_exception_handler(result)
        return result


def lastline_exception_handler(result: dict):
    if result.get("success") is not None:
        if result.get("success") == 0:
            error_msg = "error "
            if "error_code" in result:
                error_msg += "(" + str(result["error_code"]) + ") "
            if "error" in result:
                error_msg += result["error"]
            raise DemistoException(error_msg)
    else:
        raise DemistoException("No response")


def hash_type_checker(hash_file: str) -> str:
    hash_types = {
        str(Client.MD5_LEN): "md5",
        str(Client.SHA1_LEN): "sha1",
        str(Client.SHA256_LEN): "sha256",
    }
    hash_type = hash_types.get(str(len(hash_file)))
    if hash_type is not None:
        return hash_type
    else:
        raise DemistoException(f"{INTEGRATION_NAME} File command support md5/ sha1/ sha256 only.")


def report_generator(result: dict, threshold=None):
    context_entry: dict = get_report_context(result, threshold)
    if "File" in context_entry:
        key = "File"
    elif "URL" in context_entry:
        key = "URL"
    else:
        key = ""
    score = result["data"].get("score")
    uuid = result["data"].get("task_uuid")
    submission_time = result["data"].get("submission")
    if key == "File":
        indicator = context_entry.get("DBotScore", [{}])[0].get("Indicator", "None")
    else:
        indicator = context_entry.get("DBotScore", {}).get("Indicator", "None")
    if score is not None:
        meta_data = f"**Score: {score}**\n\nTask UUID: {uuid}\nSubmission Time: {submission_time}"
    else:
        meta_data = "**Status: Analyzing**"
    human_readable = tableToMarkdown(
        name=f"Lastline analysis for {key.lower()}: {indicator}", metadata=meta_data, t=context_entry.get(key)
    )
    return human_readable, context_entry


def get_report_context(result: dict, threshold=None) -> dict:
    key = "File"
    context_entry: dict = {}
    if "data" in result:
        data: dict = {}
        dbotscore = {"Vendor": "Lastline", "Score": 0, "Reliability": demisto.params().get("integrationReliability")}
        dbotscore_list = []
        if "score" in result["data"]:
            status = "Completed"
            if threshold is None:
                threshold = Client.DEFAULT_THRESHOLD
            score = result["data"]["score"]
            if score > threshold:
                dbotscore["Score"] = 3
                data["Malicious"] = {"Vendor": "Lastline", "Score": score}
            elif score > 30:
                dbotscore["Score"] = 2
            else:
                dbotscore["Score"] = 1
        else:
            status = "Analyzing"
        lastline: dict = {
            "Submission": {
                "Status": status,
                "UUID": result["data"].get("task_uuid"),
                "SubmissionTime": result["data"].get("submission"),
            }
        }
        if "analysis_subject" in result["data"]:
            analysis_subject: dict = result["data"]["analysis_subject"]
            temp_dict: dict = {
                "YaraSignatures": analysis_subject.get("yara_signatures"),
                "DNSqueries": analysis_subject.get("dns_queries"),
                "NetworkConnections": analysis_subject.get("network_connections"),
                "DownloadedFiles": analysis_subject.get("downloaded_files"),
                "Process": analysis_subject.get("process"),
                "DomainDetections": analysis_subject.get("domain_detections"),
                "IPdetections": analysis_subject.get("ip_detections"),
                "URLdetections": analysis_subject.get("url_detections"),
            }
            temp_dict = {keys: values for keys, values in temp_dict.items() if values}
            lastline["Submission"].update(temp_dict)

            if "url" in analysis_subject:
                key = "URL"
                dbotscore["Indicator"] = analysis_subject["url"]
                data["Data"] = analysis_subject.get("url")
            else:
                dbotscore["Indicator"] = analysis_subject.get("md5")
                data["MD5"] = analysis_subject.get("md5")
                data["SHA1"] = analysis_subject.get("sha1")
                data["SHA256"] = analysis_subject.get("sha256")
                data["Type"] = analysis_subject.get("mime_type")
            dbotscore["Type"] = key
            if key == "File":
                dbotscore_copy = dbotscore.copy()
                dbotscore_copy["Type"] = "file"
                dbotscore_list = [dbotscore, dbotscore_copy]
            context_entry["Lastline"] = lastline
            context_entry[key] = data

        # in case of a file indicator
        if dbotscore_list and dbotscore_list[0]["Score"] != 0:
            context_entry["DBotScore"] = dbotscore_list

        if key == "URL" and dbotscore["Score"] != 0:
            context_entry["DBotScore"] = dbotscore
    return context_entry


def file_hash(path: str) -> str:
    block_size = 65536
    file_hasher = hashlib.md5()  # nosec
    with open(path, "rb") as file_obj:
        buf = file_obj.read(block_size)
        while len(buf) > 0:
            file_hasher.update(buf)
            buf = file_obj.read(block_size)
    return file_hasher.hexdigest()


def main():
    params = demisto.params()
    base_url = params.get("url")
    verify_ssl = not params.get("insecure", False)
    proxy = params.get("proxy")
    credentials = params.get("credentials")
    api_params = {
        "key": params.get("creds_key_and_token", {}).get("identifier", "") or params.get("api_key"),
        "api_token": params.get("creds_key_and_token", {}).get("password", "") or params.get("api_token"),
    }
    api_params.update(demisto.args())
    threshold = int(api_params.get("threshold", params.get("threshold", 70)))

    if not credentials or not credentials.get("identifier") or not credentials.get("password"):
        credentials = {}

    if not (api_params.get("key") or api_params.get("api_token")):
        api_params = {}

    if not (api_params or credentials):
        raise DemistoException(
            "Please fill the credentials in the integration params - api key and token or username and password"
        )

    client = Client(base_url, api_params, verify=verify_ssl, proxy=proxy, credentials=credentials, threshold=threshold)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    # Switch case
    commands = {
        "test-module": Client.test_module_command,
        "file": Client.file,
        f"{INTEGRATION_COMMAND_NAME}-check-status": Client.check_status,
        f"{INTEGRATION_COMMAND_NAME}-get-report": Client.get_report,
        f"{INTEGRATION_COMMAND_NAME}-get-task-list": Client.get_task_list,
        f"{INTEGRATION_COMMAND_NAME}-upload-file": Client.upload_file,
        f"{INTEGRATION_COMMAND_NAME}-upload-url": Client.upload_url,
    }
    try:
        if command in commands:
            readable_output, outputs, raw_response = commands[command](client)
            return_outputs(readable_output, outputs, raw_response)
        else:
            raise DemistoException(f"{demisto.command()} is not a command")
    # Log exceptions
    except Exception as every_error:
        err_msg = f"Error in {INTEGRATION_NAME} Integration [{every_error}]"
        return_error(err_msg, error=every_error)


if __name__ in ("__builtin__", "builtins"):
    main()
