import demistomock as demisto
from CommonServerPython import *

import urllib3
from typing import Any
import ntpath
from dateparser import parse


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VERSION = 24
MAX_RESULTS = 100
""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(
        self,
        base_url,
        project_name,
        params,
        verify=True,
        proxy=False,
        ok_codes=(),
        headers=None,
        auth=None,
    ):
        self.project_name = project_name
        self.params = params
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)

    def get_project_list(self):
        return self._http_request(
            method="GET", url_suffix="/projects", params=self.params
        )

    def get_webhooks_list(self, project_name: str):
        if project_name:
            project_name_to_pass = project_name
        else:
            project_name_to_pass = self.project_name
        return self._http_request(
            method="GET",
            url_suffix=f"/project/{project_name_to_pass}/webhooks",
            params=self.params,
        )

    def get_jobs_list(
        self,
        id_list: list,
        group_path: str,
        job_filter: str,
        job_exec_filter: str,
        group_path_exact: str,
        scheduled_filter: str,
        server_node_uuid_filter: str,
        project_name: str,
    ):
        """
        This function returns a list of all existing projects.
        :param id_list: list of Job IDs to include
        :param group_path: include all jobs within that group path. if not specified, default is: "*".
        :param job_filter: specify a filter for a job Name, apply to any job name that contains this value
        :param job_exec_filter: specify an exact job name to match
        :param group_path_exact: specify an exact group path to match. if not specified, default is: "*".
        :param scheduled_filter: return only scheduled or only not scheduled jobs. can either be "true" or "false
        :param server_node_uuid_filter: return all jobs related to a selected server UUID".
        :param project_name: A project name to list its jobs
        :return: api response.
        """
        request_params: dict[str, Any] = {}

        if id_list:
            request_params["idlist"] = ",".join(id_list)
        if group_path:
            request_params["groupPath"] = group_path
        if job_filter:
            request_params["jobFilter"] = job_filter
        if job_exec_filter:
            request_params["jobExactFilter"] = job_exec_filter
        if group_path_exact:
            request_params["groupPathExact"] = group_path_exact
        if scheduled_filter:
            request_params["scheduledFilter"] = scheduled_filter
        if server_node_uuid_filter:
            request_params["serverNodeUUIDFilter"] = server_node_uuid_filter

        project_name_to_pass = project_name if project_name else self.project_name
        request_params.update(self.params)

        return self._http_request(
            method="GET",
            url_suffix=f"/project/{project_name_to_pass}/jobs",
            params=request_params,
        )

    def execute_job(
        self,
        job_id: str,
        arg_string: str,
        log_level: str,
        as_user: str,
        node_filter: str,
        run_at_time: str,
        options: dict,
        run_at_time_raw: str,
    ):
        """
        This function runs an existing job
        :param arg_string: execution arguments for the selected job: -opt1 value1 -opt2 value2
        :param job_id: id of the job you want to execute
        :param log_level: specifying the loglevel to use: 'DEBUG','VERBOSE','INFO','WARN','ERROR'
        :param as_user: identifying the user who ran the job
        :param node_filter: can be a node filter string
        :param run_at_time:  select a time to run the job. can be either in: 1 hour, 1 week, 1 day.
        :param options: add options for running a job
        :param run_at_time_raw: select a time to run the job in iso 8061 time as string
        :return: api response
        """
        request_body: dict[str, Any] = {}

        if arg_string:
            request_body["argString"] = arg_string
        if log_level:
            request_body["loglevel"] = log_level
        if as_user:
            request_body["asUser"] = as_user
        if node_filter:
            request_body["filter"] = node_filter
        if options:
            request_body["options"] = options
        if run_at_time:
            request_body["runAtTime"] = run_at_time
        elif run_at_time_raw:
            request_body["runAtTime"] = run_at_time_raw

        return self._http_request(
            method="POST",
            url_suffix=f"/job/{job_id}/executions",
            params=self.params,
            data=str(request_body),
        )

    def retry_job(
        self,
        job_id: str,
        arg_string: str,
        log_level: str,
        as_user: str,
        failed_nodes: str,
        execution_id: str,
        options: dict,
    ):
        """
        This function retry running a failed execution.
        :param arg_string: execution arguments for the selected job: -opt1 value1 -opt2 value2
        :param job_id: id of the job you want to execute
        :param log_level: specifying the log level to use: 'DEBUG','VERBOSE','INFO','WARN','ERROR'
        :param as_user: identifying the user who ran the job
        :param failed_nodes: can either ben true or false. true for run all nodes and false for running only failed nodes
        :param execution_id: for specified what execution to rerun
        :param options: add options for running a job
        :return: api response
        """
        request_body: dict[str, Any] = {}

        if arg_string:
            request_body["argString"] = arg_string
        if log_level:
            request_body["loglevel"] = log_level
        if as_user:
            request_body["asUser"] = as_user
        if failed_nodes:
            request_body["failedNodes"] = failed_nodes
        if options:
            request_body["options"] = options

        return self._http_request(
            method="POST",
            url_suffix=f"/job/{job_id}/retry/{execution_id}",
            params=self.params,
            data=str(request_body),
        )

    def job_execution_query(
        self,
        status_filter: str,
        aborted_by_filter: str,
        user_filter: str,
        recent_filter: str,
        older_filter: str,
        begin: str,
        end: str,
        adhoc: str,
        job_id_list_filter: list,
        exclude_job_id_list_filter: list,
        job_list_filter: list,
        exclude_job_list_filter: list,
        group_path: str,
        group_path_exact: str,
        exclude_group_path: str,
        exclude_group_path_exact: str,
        job_filter: str,
        exclude_job_filter: str,
        job_exact_filter: str,
        exclude_job_exact_filter: str,
        execution_type_filter: str,
        max_results: int | None,
        offset: int | None,
        project_name: str,
    ):
        """
        This function returns previous and active executions
        :param status_filter: execution status, can be either: "running", succeeded", "failed" or "aborted"
        :param aborted_by_filter: Username who aborted an execution
        :param user_filter: Username who started the execution
        :param recent_filter: for specify when the execution has occur. the format is 'XY' when 'X' is a number and 'Y'
        can be: h - hour, d - day, w - week, m - month, y - year
        :param older_filter: return executions that completed before the specified relative period of time. works with
        the same format as 'recent_filter'
        :param begin: Specify exact date for earliest execution completion time
        :param end: Specify exact date for latest execution completion time
        :param adhoc: can be true or false. true for include Adhoc executions
        :param job_id_list_filter: specify a Job IDs to filter by
        :param exclude_job_id_list_filter: specify a Job IDs to exclude
        :param job_list_filter: specify a full job group/name to include.
        :param exclude_job_list_filter: specify a full Job group/name to exclude
        :param group_path: specify a group or partial group to include all jobs within that group path.
        :param group_path_exact: like 'group_path' but you need to specify an exact group path to match
        :param exclude_group_path specify a group or partial group path to exclude all jobs within that group path
        :param exclude_group_path_exact: specify a group or partial group path to exclude jobs within that group path
        :param job_filter: provide here a job name to query
        :param exclude_job_filter: provide here a job name to exclude
        :param job_exact_filter: provide here an exact job name to match
        :param exclude_job_exact_filter: specify an exact job name to exclude
        :param execution_type_filter: specify the execution type, can be: 'scheduled', 'user' or 'user-scheduled'
        :param max_results: maximum number of results to get from the api
        :param offset: offset for first result to include
        :param project_name: the project name that you want to get its execution
        :return: api response
        """

        request_params: dict[str, Any] = {}

        if status_filter:
            request_params["statusFilter"] = status_filter
        if aborted_by_filter:
            request_params["abortedbyFilter"] = aborted_by_filter
        if user_filter:
            request_params["userFilter"] = user_filter
        if recent_filter:
            request_params["recentFilter"] = recent_filter
        if older_filter:
            request_params["olderFilter"] = older_filter
        if begin:
            request_params["begin"] = begin
        if end:
            request_params["end"] = end
        if adhoc:
            request_params["adhoc"] = adhoc
        if job_id_list_filter:
            request_params["jobIdListFilter"] = job_id_list_filter
        if exclude_job_id_list_filter:
            request_params["excludeJobIdListFilter"] = exclude_job_id_list_filter
        if job_list_filter:
            request_params["jobListFilter"] = job_list_filter
        if exclude_job_list_filter:
            request_params["excludeJobListFilter"] = exclude_job_list_filter
        if group_path:
            request_params["groupPath"] = group_path
        if group_path_exact:
            request_params["groupPathExact"] = group_path_exact
        if exclude_group_path:
            request_params["excludeGroupPath"] = exclude_group_path
        if exclude_group_path_exact:
            request_params["excludeGroupPathExact"] = exclude_group_path_exact
        if job_filter:
            request_params["jobFilter"] = job_filter
        if exclude_job_filter:
            request_params["excludeJobFilter"] = exclude_job_filter
        if job_exact_filter:
            request_params["jobExactFilter"] = job_exact_filter
        if exclude_job_exact_filter:
            request_params["excludeJobExactFilter"] = exclude_job_exact_filter
        if execution_type_filter:
            request_params["executionTypeFilter"] = execution_type_filter
        if max_results:
            request_params["max"] = max_results
        if offset:
            request_params["offset"] = offset

        project_name_to_pass = project_name if project_name else self.project_name
        request_params["max"] = max_results if max_results else MAX_RESULTS

        request_params.update(self.params)

        return self._http_request(
            method="POST",
            url_suffix=f"/project/{project_name_to_pass}/executions",
            params=request_params,
        )

    def job_execution_output(self, execution_id: int):
        """
        This function gets metadata regarding workflow state
        :param execution_id: id to execute.
        :return: api response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/execution/{execution_id}/output/state",
            params=self.params,
        )

    def job_execution_abort(self, execution_id: int):
        """
        This function aborts live executions
        :param execution_id: id to abort execution
        :return: api response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/execution/{execution_id}/abort",
            params=self.params,
        )

    def adhoc_run(
        self,
        project_name: str,
        exec_command: str,
        node_thread_count: str,
        node_keepgoing: str,
        as_user: str,
        node_filter: str,
    ):
        """
        This function executes shell commands in nodes.
        :param project_name: project to run the command on
        :param exec_command: the shell command that you want to run
        :param node_thread_count: threadcount to use
        :param node_keepgoing: 'true' for continue executing on other nodes after a failure. 'false' otherwise
        :param as_user: specifies a username identifying the user who ran the command
        :param node_filter: node filter to add
        :return: api response
        """
        request_params: dict[str, Any] = {}

        if exec_command:
            request_params["exec"] = exec_command
        if node_thread_count:
            request_params["nodeThreadcount"] = node_thread_count
        if node_keepgoing:
            request_params["nodeKeepgoing"] = node_keepgoing
        if as_user:
            request_params["asUser"] = as_user
        if node_filter:
            request_params["filter"] = node_filter
        if project_name:
            project_name_to_pass = project_name
        else:
            project_name_to_pass = self.project_name

        request_params.update(self.params)

        return self._http_request(
            method="GET",
            url_suffix=f"/project/{project_name_to_pass}/run/command",
            params=request_params,
        )

    def adhoc_script_run_from_url(
        self,
        project_name: str,
        script_url: str,
        node_thread_count: str,
        node_keepgoing: str,
        as_user: str,
        node_filter: str,
        script_interpreter: str,
        interpreter_args_quoted: str,
        file_extension: str,
        arg_string: str,
    ):
        """
        This function runs a script downloaded from a URL
        :param project_name: project to run the command on
        :param script_url: a URL pointing to a script file
        :param node_thread_count: threadcount to use
        :param node_keepgoing: 'true' for continue executing on other nodes after a failure. false otherwise
        :param as_user: specifies a username identifying the user who ran the command
        :param node_filter: node filter string
        :param script_interpreter: a command to use to run the script
        :param interpreter_args_quoted: if true, the script file and arguments will be quoted as the last argument to
        the script_interpreter. false otherwise.
        :param file_extension: extension of the script file
        :param arg_string: arguments to pass to the script when executed.
        :return: api response
        """
        request_params: dict[str, Any] = {}

        if node_thread_count:
            request_params["nodeThreadcount"] = node_thread_count
        if node_keepgoing:
            request_params["nodeKeepgoing"] = node_keepgoing
        if as_user:
            request_params["asUser"] = as_user
        if node_filter:
            request_params["filter"] = node_filter
        if script_interpreter:
            request_params["scriptInterpreter"] = script_interpreter
        if interpreter_args_quoted:
            request_params["interpreterArgsQuoted"] = interpreter_args_quoted
        if file_extension:
            request_params["fileExtension"] = file_extension
        if arg_string:
            request_params["argString"] = arg_string
        if project_name:
            project_name_to_pass = project_name
        else:
            project_name_to_pass = self.project_name

        request_params.update(self.params)
        self._headers["Content-Type"] = "application/x-www-form-urlencoded"

        return self._http_request(
            method="POST",
            data={"scriptURL": script_url},
            url_suffix=f"/project/{project_name_to_pass}/run/url",
            params=request_params,
        )

    def webhook_event_send(self, auth_token: str, options: str, free_json: str):
        """
        This function posts data to the webhook endpoint
        :param options: data that you want to post as dict
        :param free_json: data you want to post as json
        :param auth_token: auto token of the webhook
        :return: api response
        """

        request_params = ""
        if options:
            request_params = options
        else:
            if free_json:
                request_params = free_json

        return self._http_request(
            method="POST",
            url_suffix=f"/webhook/{auth_token}",
            params=self.params,
            data=request_params,
        )

    def adhoc_script_run(
        self,
        project_name: str,
        arg_string: str,
        node_thread_count: str,
        node_keepgoing: str,
        as_user: str,
        node_filter: str,
        script_interpreter: str,
        interpreter_args_quoted: str,
        file_extension: str,
        entry_id: str,
    ):
        """
        This function runs a script from file
        :param project_name: project to run the script file
        :param arg_string: arguments for the script when executed
        :param node_thread_count: threadcount to use
        :param node_keepgoing: 'true' for continue executing on other nodes after a failure. false otherwise
        :param as_user: identifying the user who ran the job
        :param node_filter:
        :param script_interpreter: a command to use to run the script
        :param interpreter_args_quoted: if true, the script file and arguments will be quoted as the last argument to
        :param file_extension: extension of of the script file
        :param entry_id: Demisto id for the uploaded script file you want to run
        :return: api response
        """

        request_params: dict[str, str] = {}
        if arg_string:
            request_params["argString"] = arg_string
        if node_thread_count:
            request_params["nodeThreadcount"] = node_thread_count
        if node_keepgoing:
            request_params["nodeKeepgoing"] = node_keepgoing
        if as_user:
            request_params["asUser"] = as_user
        if script_interpreter:
            request_params["scriptInterpreter"] = script_interpreter
        if interpreter_args_quoted:
            request_params["interpreterArgsQuoted"] = interpreter_args_quoted
        if file_extension:
            request_params["fileExtension"] = file_extension
        if node_filter:
            request_params["filter"] = node_filter
        if project_name:
            project_name_to_pass = project_name
        else:
            project_name_to_pass = self.project_name

        file_path = demisto.getFilePath(entry_id).get("path", None)
        if not file_path:
            raise DemistoException(
                f"Could not find file path to the next entry id: {entry_id}. \n"
                f"Please provide another one."
            )
        else:
            file_name = ntpath.basename(file_path)

        request_params.update(self.params)
        del self._headers["Content-Type"]
        with open(file_path, "rb") as file:
            self._headers.update(
                {
                    "Content-Disposition": f'form-data; name="file"; filename="{file_name}"'
                }
            )
            return self._http_request(
                method="POST",
                files={"scriptFile": file},
                url_suffix=f"/project/{project_name_to_pass}/run/script",
                params=request_params,
            )


""" HELPER FUNCTIONS """


def filter_results(
    results: list | dict, fields_to_remove: list, remove_signs: list
) -> list | dict:
    new_results = []
    if isinstance(results, dict):
        demisto.info("got results as dictionary")
        new_record = {}
        demisto.info("start looping over results")
        for key, value in results.items():
            if key not in fields_to_remove:
                demisto.debug(f'add this key: "{key}" to filtered results')
                if isinstance(value, dict):
                    demisto.debug(
                        f"found {value} is a dict, calling this function again"
                    )
                    value = filter_results(value, fields_to_remove, remove_signs)
                demisto.info("searching not allowed signs to remove")
                for sign in remove_signs:
                    if sign in key:
                        demisto.debug(
                            f'found "{sign}" in the next key: "{key}". remove it.'
                        )
                        new_record[key.replace(sign, "")] = value
                        demisto.debug("finish remove it")
                    else:
                        demisto.debug(
                            f"not allowed signs were not found. add the next key to filter results: {key}"
                        )
                        new_record[key] = value
                demisto.info("finish remove not allowed signs in results keys")
        demisto.info("finish looping over results")
        return new_record
    else:
        demisto.info("got results as list")
        for record in results:
            new_record = {}
            for key, value in record.items():
                if key not in fields_to_remove:
                    if isinstance(value, dict):
                        value = filter_results(value, fields_to_remove, remove_signs)
                    for sign in remove_signs:
                        if sign in key:
                            new_record[key.replace(sign, "")] = value
                        else:
                            new_record[key] = value
            new_results.append(new_record)
    return new_results


def attribute_pairs_to_dict(attrs_str: str | None, delim_char: str = ","):
    """
    Transforms a string of multiple inputs to a dictionary list

    :param attrs_str: attributes separated by key=val pairs sepearated by ','
    :param delim_char: delimiter character between atrribute pairs
    :return:
    """
    if not attrs_str:
        return attrs_str
    demisto.info("start convert string of multiple inputs to a dictionary")
    attrs = {}
    regex = re.compile(r"(.*)=(.*)")

    demisto.info("start looping over the found keys and values")
    demisto.debug(f"start looping over the next found keys and values: {regex}")

    for f in attrs_str.split(delim_char):
        match = regex.match(f)
        if match is None:
            raise ValueError(f"Could not parse field: {f}")
        demisto.debug(
            f"add this key: {match.group(1)} and this value: {match.group(2)} to attrs"
        )
        attrs.update({match.group(1): match.group(2)})
        demisto.debug(
            f"finish adding this key: {match.group(1)} and this value: {match.group(2)} to attrs"
        )

    return attrs


def convert_str_to_int(val_to_convert: str | None, param_name: str):
    """
    This function get a parameter from Demisto as string and try converting it to integer
    :param val_to_convert: the value to convert
    :param param_name: string of the parameter name that is trying to be converted.
    :return: the converted value
    """
    demisto.info(f"start converting {val_to_convert} to integer")
    if val_to_convert:
        try:
            return int(val_to_convert)
        except ValueError:
            raise DemistoException(f"'{param_name}' most be a number.")
        except Exception:
            demisto.error(f"failed to convert {val_to_convert} to integer")
            raise
    demisto.info(f"finish converting {val_to_convert} to integer")
    return None


def calc_run_at_time(selected_time: str) -> str:
    """
    This function gets a specified time(1 hour, 1 day, 1 year) and returns the selected time in ISO-8601 format
    :param selected_time: the delta you want to get from today:
    '1 hour': for one hour from now
    '1 week': for one week from now
    '1 day': for one day from now
    :return: the selected time in ISO-8601 format.
    """
    selected_iso_time = ""
    if not selected_time:
        return selected_iso_time
    selected_time_date = parse(f"in {selected_time} UTC")
    assert selected_time_date is not None, f'could not parse {selected_time} UTC'
    iso_with_timezone = selected_time_date.isoformat()
    return iso_with_timezone


def collect_headers(entries_list: list) -> list:
    """
    This function collect all keys in a list of dictionaries
    :param entries_list: list of dictionaries
    :return: list of all keys formatted
    """
    headers = [""]
    for entry in entries_list:
        for key, _value in entry.items():
            if key == "log":
                headers[0] = "log"
            headers.append(key.replace("_", " "))
    if not headers[0]:
        return headers[1:]
    return headers


def collect_log_from_output(entries: list) -> list:
    logs_entry = []
    for entry in entries:
        if entry["type"] == "log":
            logs_entry.append(entry)
    return logs_entry


""" COMMAND FUNCTIONS """


def job_retry_command(client: Client, args: dict):
    arg_string: str = args.get("arg_string", "")
    log_level: str = args.get("log_level", "")
    as_user: str = args.get("as_user", "")
    failed_nodes: str = args.get("failed_nodes", "")
    job_id: str = args.get("job_id", "")
    execution_id: str = args.get("execution_id", "")
    options: str = args.get("options", "")

    converted_options: dict = attribute_pairs_to_dict(options)
    result = client.retry_job(
        job_id,
        arg_string,
        log_level,
        as_user,
        failed_nodes,
        execution_id,
        converted_options,
    )

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore
    headers = [key.replace("-", " ") for key in [*filtered_results.keys()]]

    readable_output = tableToMarkdown(
        "Execute Job:", filtered_results, headers=headers, headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ExecutedJobs",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def execute_job_command(client: Client, args: dict):
    arg_string: str = args.get("arg_string", "")
    log_level: str = args.get("log_level", "")
    as_user: str = args.get("as_user", "")
    node_filter: str = args.get("filter", "")
    run_at_time: str = calc_run_at_time(args.get("run_at_time", ""))
    run_at_time_raw: str = args.get("run_at_time_raw", "")
    options: str = args.get("options", "")
    job_id: str = args.get("job_id", "")

    converted_options: dict = attribute_pairs_to_dict(options)
    demisto.info("sending execute job request")
    result = client.execute_job(
        job_id,
        arg_string,
        log_level,
        as_user,
        node_filter,
        run_at_time,
        converted_options,
        run_at_time_raw,
    )
    demisto.info("finish sending execute job request")

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore

    headers = [key.replace("-", " ") for key in [*filtered_results.keys()]]

    readable_output = tableToMarkdown(
        "Execute Job:", filtered_results, headers=headers, headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ExecutedJobs",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def project_list_command(client: Client):
    """
    This function returns a list of all existing projects.
    :param client: Demisto client
    :return: CommandResults object
    """
    demisto.info("sending get project list request")
    result = client.get_project_list()
    demisto.info("finish get project list request")
    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    filtered_results = filter_results(result, ["url"], ["-"])

    headers = [key.replace("_", " ") for key in [*filtered_results[0].keys()]]

    readable_output = tableToMarkdown(
        "Projects List:",
        filtered_results,
        headers=headers,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.Projects",
        outputs=filtered_results,
        outputs_key_field="name",
    )


def jobs_list_command(client: Client, args: dict):
    """
    This function returns a list of all existing jobs.
    :param client: Demisto client
    :param args: command's arguments
    :return: CommandResults object
    """
    id_list: list = argToList(args.get("id_list", []))
    group_path: str = args.get("group_path", "")
    job_filter: str = args.get("job_filter", "")
    job_exec_filter: str = args.get("job_exec_filter", "")
    group_path_exact: str = args.get("group_path_exact", "")
    scheduled_filter: str = args.get("scheduled_filter", "")
    server_node_uuid_filter: str = args.get("server_node_uuid_filter", "")
    max_results: int | None = convert_str_to_int(
        args.get("max_results", ""), "max_results"
    )
    project_name: str = args.get("project_name", "")
    demisto.info("sending get jobs list request")
    result = client.get_jobs_list(
        id_list,
        group_path,
        job_filter,
        job_exec_filter,
        group_path_exact,
        scheduled_filter,
        server_node_uuid_filter,
        project_name,
    )
    demisto.info("finish sending get jobs list request")

    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    if result:
        max_entries: list = result[:max_results] if max_results else result[
            :MAX_RESULTS
        ]
        filtered_results = filter_results(max_entries, ["href", "permalink"], ["-"])
        headers = [key.replace("_", " ") for key in [*filtered_results[0].keys()]]
        readable_output = tableToMarkdown(
            "Jobs List:",
            filtered_results,
            headers=headers,
            headerTransform=pascalToSpace,
        )

    else:
        filtered_results = result

        readable_output = "No results were found"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.Jobs",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def webhooks_list_command(client: Client, args: dict):
    """
    This function returns a list of all existing webhooks.
    :param client: Demisto client
    :return: CommandResults object
    """
    project_name: str = args.get("project_name", "")
    max_results: int | None = convert_str_to_int(args.get('max_results', ''), 'max_results')
    demisto.info("sending get webhooks list request")
    result = client.get_webhooks_list(project_name)
    demisto.info("finish sending get webhooks list request")

    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    headers = [key.replace("_", " ") for key in [*result[0].keys()]]

    returned_results = result[:max_results] if max_results else result[:MAX_RESULTS]
    readable_output = tableToMarkdown(
        "Webhooks List:", result, headers=headers, headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.Webhooks",
        outputs=returned_results,
        outputs_key_field="id",
    )


def job_execution_query_command(client: Client, args: dict):
    """
    This function returns a list of all existing executions.
    :param client: Demisto client
    :param args: command's arguments
    :return: CommandResults object
    """
    status_filter: str = args.get("status_filter", "")
    aborted_by_filter: str = args.get("aborted_by_filter", "")
    user_filter: str = args.get("user_filter", "")
    recent_filter: str = args.get("recent_filter", "")
    older_filter: str = args.get("older_filter", "")
    begin: str = args.get("begin", "")
    end: str = args.get("end", "")
    adhoc: str = args.get("adhoc", "")
    job_id_list_filter: list = argToList(args.get("job_id_list_filter", []))
    exclude_job_id_list_filter: list = argToList(
        args.get("exclude_job_id_list_filter", [])
    )
    job_list_filter: list = argToList(args.get("job_list_filter", []))
    exclude_job_list_filter: list = argToList(args.get("exclude_job_list_filter", []))
    group_path: str = args.get("group_path", "")
    group_path_exact: str = args.get("group_path_exact", "")
    exclude_group_path_exact: str = args.get("exclude_group_path_exact", "")
    job_filter: str = args.get("job_filter", "")
    exclude_job_filter: str = args.get("exclude_job_filter", "")
    job_exact_filter: str = args.get("job_exact_filter", "")
    exclude_job_exact_filter: str = args.get("exclude_job_exact_filter", "")
    execution_type_filter: str = args.get("execution_type_filter", "")
    max_results: int | None = convert_str_to_int(args.get("max_results"), "max")
    offset: int | None = convert_str_to_int(args.get("offset"), "offset")
    project_name: str = args.get("project_name", "")
    exclude_group_path: str = args.get("exclude_group_path", "")
    demisto.info("sending job execution query request")
    result = client.job_execution_query(
        status_filter,
        aborted_by_filter,
        user_filter,
        recent_filter,
        older_filter,
        begin,
        end,
        adhoc,
        job_id_list_filter,
        exclude_job_id_list_filter,
        job_list_filter,
        exclude_job_list_filter,
        group_path,
        group_path_exact,
        exclude_group_path,
        exclude_group_path_exact,
        job_filter,
        exclude_job_filter,
        job_exact_filter,
        exclude_job_exact_filter,
        execution_type_filter,
        max_results,
        offset,
        project_name,
    )
    demisto.info("finish sending job execution query request")

    if not isinstance(result, dict):
        raise DemistoException(f"got unexpected results from api: {result}")

    executions: list = result.get("executions", [])
    demisto.info("start filter results from the api")
    filtered_executions = filter_results(executions, ["href", "permalink"], ["-"])
    demisto.info("finish filter results from the api")

    if isinstance(filtered_executions, list):
        headers = [key.replace("_", " ") for key in [*filtered_executions[0].keys()]]
    else:
        raise DemistoException(f"Got unexpected results from the api: {result}")

    readable_output = tableToMarkdown(
        f'Job Execution Query - got total results: {result.get("paging",{}).get("total")}',
        filtered_executions,
        headers=headers,
        headerTransform=pascalToSpace,
    )

    result["executions"] = filtered_executions

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ExecutionsQuery",
        outputs=result,
        outputs_key_field="id",
    )


def job_execution_output_command(client: Client, args: dict):
    """
    This function gets metadata regarding workflow state
    :param client: demisto client object
    :param args: command's arguments
    :return: CommandRusult object
    """
    execution_id: int | None = convert_str_to_int(
        args.get("execution_id"), "execution_id"
    )
    return_full_output: bool = argToBoolean(args.get("return_full_output", False))
    max_results: int | None = convert_str_to_int(
        args.get("max_results", ""), "max_results"
    )
    aggregate_log: bool = argToBoolean(args.get("aggregate_log", False))
    demisto.info("sending job execution output request")
    result: dict = client.job_execution_output(execution_id)  # type: ignore
    demisto.info("finish sending job execution output request")

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected response: {result}")

    headers_general = [key.replace("_", " ") for key in [*result.keys()]]
    readable_output_general = tableToMarkdown(
        "Job Execution Output:",
        result,
        headers=headers_general,
        headerTransform=pascalToSpace,
    )

    if result["entries"]:
        result["entries"] = result["entries"][:max_results] if max_results else result["entries"][:MAX_RESULTS]
        readable_output_entries = tableToMarkdown(
            "Job Execution Entries View:",
            result["entries"],
            headers=collect_headers(result["entries"]),
            headerTransform=pascalToSpace,
        )
        if aggregate_log:
            result["logEntries"] = collect_log_from_output(result["entries"])

        human_readable = readable_output_general + readable_output_entries
    else:
        human_readable = readable_output_general

    if return_full_output:
        return fileResult(args.get("execution_id"), json.dumps(result))
    else:
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Rundeck.ExecutionsOutput",
            outputs=result,
            outputs_key_field="id",
        )


def job_execution_abort_command(client: Client, args: dict):
    """
    This function abort an active execution
    :param client: demisto client object
    :param args: command's arguments
    :return: CommandRusult object
    """
    execution_id: int | None = convert_str_to_int(
        args.get("execution_id"), "execution_id"
    )

    demisto.info("sending job execution abort request")
    result = client.job_execution_abort(execution_id)  # type: ignore
    demisto.info("finish sending job execution abort request")

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected response: {result}")

    demisto.info("start filter results from the api")
    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore
    demisto.info("finish filter results from the api")

    headers = [key.replace("_", " ") for key in [*filtered_results.keys()]]
    readable_output = tableToMarkdown(
        "Job Execution Abort:",
        filtered_results,
        headers=headers,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.Aborted",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def adhoc_run_command(client: Client, args: dict):
    project_name: str = args.get("project_name", "")
    exec_command: str = args.get("exec_command", "")
    node_thread_count: str = args.get("node_thread_count", "")
    node_keepgoing: str = args.get("node_keepgoing", "")
    as_user: str = args.get("as_user", "")
    node_filter: str = args.get("node_filter", "")

    demisto.info("sending adhoc run request")
    result = client.adhoc_run(
        project_name,
        exec_command,
        node_thread_count,
        node_keepgoing,
        as_user,
        node_filter,
    )
    demisto.info("finish sending adhoc run request")

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected response: {result}")

    demisto.info("start filter results from the api")
    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore
    demisto.info("finish filter results from the api")

    headers = [key.replace("_", " ") for key in [*filtered_results.keys()]]
    readable_output = tableToMarkdown(
        "Adhoc Run:", filtered_results, headers=headers, headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ExecuteCommand",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def adhoc_script_run_command(client: Client, args: dict):
    project_name: str = args.get("project_name", "")
    arg_string: str = args.get("arg_string", "")
    node_thread_count: str = args.get("node_thread_count", "")
    node_keepgoing: str = args.get("node_keepgoing", "")
    as_user: str = args.get("as_user", "")
    script_interpreter: str = args.get("script_interpreter", "")
    interpreter_args_quoted: str = args.get("interpreter_args_quoted", "")
    file_extension: str = args.get("file_extension", "")
    node_filter: str = args.get("node_filter", "")
    entry_id: str = args.get("entry_id", "")
    demisto.info("sending adhoc script run request")
    result = client.adhoc_script_run(
        project_name,
        arg_string,
        node_thread_count,
        node_keepgoing,
        as_user,
        node_filter,
        script_interpreter,
        interpreter_args_quoted,
        file_extension,
        entry_id,
    )
    demisto.info("finish sending adhoc script run request")

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected response: {result}")
    demisto.info("start filter results from the api")
    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore
    demisto.info("finish filter results from the api")

    headers = [key.replace("_", " ") for key in [*filtered_results.keys()]]
    readable_output = tableToMarkdown(
        "Adhoc Run Script:",
        filtered_results,
        headers=headers,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ExecuteScriptFile",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def adhoc_script_run_from_url_command(client: Client, args: dict):
    project_name: str = args.get("project_name", "")
    script_url: str = args.get("script_url", "")
    node_thread_count: str = args.get("node_thread_count", "")
    node_keepgoing: str = args.get("node_keepgoing", "")
    as_user: str = args.get("as_user", "")
    script_interpreter: str = args.get("script_interpreter", "")
    interpreter_args_quoted: str = args.get("interpreter_args_quoted", "")
    file_extension: str = args.get("file_extension", "")
    node_filter: str = args.get("node_filter", "")
    arg_string: str = args.get("arg_string", "")

    result = client.adhoc_script_run_from_url(
        project_name,
        script_url,
        node_thread_count,
        node_keepgoing,
        as_user,
        node_filter,
        script_interpreter,
        interpreter_args_quoted,
        file_extension,
        arg_string,
    )
    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected response: {result}")
    filtered_results: dict = filter_results(result, ["href", "permalink"], ["-"])  # type: ignore

    headers = [key.replace("_", " ") for key in [*filtered_results.keys()]]
    readable_output = tableToMarkdown(
        "Adhoc Run Script From Url:",
        filtered_results,
        headers=headers,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.ScriptExecutionFromUrl",
        outputs=filtered_results,
        outputs_key_field="id",
    )


def webhook_event_send_command(client: Client, args: dict):
    auth_token = args.get("auth_token", "")
    options: str = args.get("options", "")
    free_json: str = args.get("json", "")
    options_as_dict: dict = attribute_pairs_to_dict(options)

    try:
        demisto.info('start convert "options" argument to str')
        if options_as_dict:
            options_as_str: str = json.dumps(options_as_dict)
        else:
            options_as_str = free_json
            demisto.info('finish convert "options" argument to str')
    except Exception as e:
        raise DemistoException(
            f'There was a problem converting "json" to json. The reason is: {e}'
        )
    result = client.webhook_event_send(auth_token, options_as_str, free_json)

    headers = [key.replace("_", " ") for key in [*result.keys()]]
    readable_output = tableToMarkdown(
        "Webhook event send:", result, headers=headers, headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Rundeck.WebhookEvent",
        outputs=result,
        outputs_key_field="id",
    )


def test_module(client: Client, project_name: str | None) -> str:
    try:
        projects_list = client.get_project_list()
    except DemistoException as e:
        if "unauthorized" in str(e):
            return "Authorization Error: make sure your token is correctly set"
        else:
            raise e
    else:
        if project_name:
            for project in projects_list:
                if project_name == project.get("name"):
                    return "ok"
            return (
                f'Could not find the next project: "{project_name}"'
                f". please enter another one or delete it completely."
            )
        else:
            return "ok"


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params: dict = demisto.params()
    token: str = params.get('token_creds', {}).get('password') or params.get("token", "")
    project_name: str = params.get("project_name", "")

    # get the service API url
    base_url: str = urljoin(demisto.params()["url"], f"/api/{VERSION}")

    verify_certificate = not demisto.params().get("insecure", False)

    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    args: dict = demisto.args()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            params={"authtoken": f"{token}"},
            project_name=project_name,
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, project_name)
            return_results(result)
        elif demisto.command() == "rundeck-projects-list":
            result = project_list_command(client)
            return_results(result)
        elif demisto.command() == "rundeck-jobs-list":
            result = jobs_list_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-webhooks-list":
            result = webhooks_list_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-job-execute":
            result = execute_job_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-job-retry":
            result = job_retry_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-job-executions-query":
            result = job_execution_query_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-job-execution-output":
            result = job_execution_output_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-job-execution-abort":
            result = job_execution_abort_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-adhoc-command-run":
            result = adhoc_run_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-adhoc-script-run":
            result = adhoc_script_run_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-adhoc-script-run-from-url":
            result = adhoc_script_run_from_url_command(client, args)
            return_results(result)
        elif demisto.command() == "rundeck-webhook-event-send":
            result = webhook_event_send_command(client, args)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        error_msg = str(e).replace("\\n", "\n")
        return_error(
            f"Failed to execute {demisto.command()} command.\n Error:\n {error_msg}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
