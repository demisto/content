from Rundeck import (
    filter_results,
    attribute_pairs_to_dict,
    convert_str_to_int,
    project_list_command,
    Client,
    jobs_list_command,
    execute_job_command,
    job_retry_command,
    job_execution_query_command,
    job_execution_output_command,
    job_execution_abort_command,
    adhoc_run_command,
    adhoc_script_run_command,
    adhoc_script_run_from_url_command,
    webhooks_list_command,
    webhook_event_send_command,
    calc_run_at_time,
    collect_headers,
    collect_log_from_output,
)


from CommonServerPython import DemistoException
from datetime import datetime, timezone
import demistomock as demisto
from dateparser import parse


def test_filter_results_when_response_is_dict(mocker):
    """
    Given:
        - response as dict
    When
        - performing an api request and the api response is a dict
    Then
        - filter out all selected fields and signs
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    results_to_filter = {"key1": "val1", "key2": "val2", "key_3": "val3"}

    result = filter_results(results_to_filter, "key1", "_")
    assert "key1" not in result.keys()
    assert "key3" in result.keys()


def test_filter_results_when_response_is_list(mocker):
    """
    Given:
        - response as list
    When
        - performing an api request and the api response is a list
    Then
        - filter out all selected fields and signs
    """
    mocker.patch.object(demisto, 'info')
    results_to_filter = [{"key1": "val1", "key2": "val2"}, {"key_3": "val3"}]

    result = filter_results(results_to_filter, "key1", "_")

    assert "key1" not in result[0].keys()
    assert "key3" in result[1].keys()


def test_attribute_pairs_to_dict(mocker):
    """
    Given:
        - string convert to a dict
    When
        - getting a dict from Demisto
    Then
        - a string is converted to dict
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    result = attribute_pairs_to_dict("key1=val1,key2=val2")
    assert result == {"key1": "val1", "key2": "val2"}


def test_convert_str_to_int(mocker):
    """
    Given:
        - string convert to a int
    When
        - getting an integer from Demisto
    Then
        - the passed string is converted to int
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    result = convert_str_to_int("5", "argument")
    assert result == 5


def test_convert_str_to_int_with_bad_input(mocker):
    """
    Given:
        - string convert to a int that can't be converted to int
    When
        - getting it from Demisto as a command's input
    Then
        - DemistoExeption is raised
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    try:
        convert_str_to_int("\\", "argument")
    except DemistoException:
        pass
    else:
        assert (
            1 == 2
        ), "error when try converting string to int should throw DemistoException"


def test_project_list_command(mocker):
    """
    Given:
        - None.    When
        - a user wants to get a list of all the existing projects.
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = [
        {
            "url": "https://test/api/35/project/Demisto",
            "name": "Demisto",
            "description": "Demisto Test",
        }
    ]
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "get_project_list", return_value=return_value)
    result = project_list_command(client)
    assert result.outputs == [{"name": "Demisto", "description": "Demisto Test"}]
    assert result.outputs_key_field == "name"
    assert result.outputs_prefix == "Rundeck.Projects"
    assert (
        result.readable_output
        == "### Projects List:\n|Name|Description|\n|---|---|\n| Demisto | Demisto Test |\n"
    )


def test_jobs_list_command(mocker):
    """
    Given:
        - None.
    When
        - a user wants to get a list of all the existing jobs.
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = [
        {
            "href": "123",
            "id": "123",
            "scheduleEnabled": True,
            "scheduled": False,
            "enabled": True,
            "permalink": "123",
            "group": None,
            "description": "just a sample job",
            "project": "Demisto",
            "name": "Test Job",
        },
        {"another": "job"},
    ]
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "get_jobs_list", return_value=return_value)
    result = jobs_list_command(client, {"max_results": 1})
    assert result.outputs == [
        {
            "id": "123",
            "scheduleEnabled": True,
            "scheduled": False,
            "enabled": True,
            "group": None,
            "description": "just a sample job",
            "project": "Demisto",
            "name": "Test Job",
        }
    ]
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.Jobs"
    assert (
        result.readable_output
        == "### Jobs List:\n|Id|Schedule Enabled|Scheduled|Enabled|Group|Description"
        "|Project|Name|\n|---|---|---|---|---|---|---|---|\n| 123 | true | false |"
        " true |  | just a sample job | Demisto | Test Job |\n"
    )


def test_execute_job_command(mocker):
    """
    Given:
        - job id to execute.
    When
        - executing a job from Demisto
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "id": 194,
        "status": "running",
        "project": "Demisto",
        "executionType": "user",
        "user": "Galb",
        "datestarted": {"unixtime": 123, "date": "123"},
        "job": {
            "id": "123",
            "averageDuration": 463,
            "name": "Test Job",
            "group": "",
            "project": "Demisto",
            "description": "just a sample job",
            "options": {"foo": "0"},
        },
        "description": "123",
        "argstring": "-foo 0",
    }

    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "execute_job", return_value=return_value)
    result = execute_job_command(client, {"job_id": "123"})
    assert result.outputs == return_value
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecutedJobs"
    assert (
        result.readable_output
        == "### Execute Job:\n|Id|Status|Project|Execution Type|User|Datestarted|Job"
        "|Description|Argstring|\n|---|---|---|---|---|---|---|---|---|\n| 194 | "
        "running | Demisto | user | Galb | unixtime: 123<br>date: 123 | id: 123<br>"
        "averageDuration: 463<br>name: Test Job<br>group: <br>project: Demisto"
        '<br>description: just a sample job<br>options: {"foo": "0"} | 123 | -foo'
        " 0 |\n"
    )


def test_job_retry_command(mocker):
    """
    Given:
        - job id to re execute.
    When
        - a user wants to re execute a job.
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "id": 194,
        "status": "running",
        "project": "Demisto",
        "executionType": "user",
        "user": "Galb",
        "datestarted": {"unixtime": 123, "date": "123"},
        "job": {
            "id": "123",
            "averageDuration": 463,
            "name": "Test Job",
            "group": "",
            "project": "Demisto",
            "description": "just a sample job",
            "options": {"foo": "0"},
        },
        "description": "123",
        "argstring": "-foo 0",
    }

    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "retry_job", return_value=return_value)
    result = job_retry_command(client, {"execution_id": "69"})
    assert result.outputs == return_value
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecutedJobs"
    assert (
        result.readable_output
        == "### Execute Job:\n|Id|Status|Project|Execution Type|User|Datestarted|Job"
        "|Description|Argstring|\n|---|---|---|---|---|---|---|---|---|\n| 194 | "
        "running | Demisto | user | Galb | unixtime: 123<br>date: 123 | id: 123<br>"
        "averageDuration: 463<br>name: Test Job<br>group: <br>project: Demisto"
        '<br>description: just a sample job<br>options: {"foo": "0"} | 123 | -foo'
        " 0 |\n"
    )


def test_job_executions_query_command(mocker):
    """
    Given:
        - project name
    When
        - a user wants to get a list of all existing executions.
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "paging": {"total": 2},
        "executions": [
            {
                "id": 195,
                "href": "123",
                "permalink": "123",
                "status": "failed",
                "project": "Demisto",
                "executionType": "user",
                "user": "Galb",
                "date-started": {"unixtime": 123, "date": "123"},
                "date-ended": {"unixtime": 123, "date": "123"},
                "job": {
                    "id": "123",
                    "averageDuration": 463,
                    "name": "Test Job",
                    "group": "",
                    "project": "Demisto",
                    "description": "just a sample job",
                    "options": {"foo": "0"},
                    "href": "123",
                    "permalink": "123",
                },
                "description": "123",
                "argstring": "-foo 0",
                "failedNodes": ["localhost"],
            }
        ],
    }
    output = {
        "paging": {"total": 2},
        "executions": [
            {
                "id": 195,
                "status": "failed",
                "project": "Demisto",
                "executionType": "user",
                "user": "Galb",
                "datestarted": {"unixtime": 123, "date": "123"},
                "dateended": {"unixtime": 123, "date": "123"},
                "job": {
                    "id": "123",
                    "averageDuration": 463,
                    "name": "Test Job",
                    "group": "",
                    "project": "Demisto",
                    "description": "just a sample job",
                    "options": {"foo": "0"},
                },
                "description": "123",
                "argstring": "-foo 0",
                "failedNodes": ["localhost"],
            }
        ],
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "job_execution_query", return_value=return_value)
    result = job_execution_query_command(client, {})
    assert result.outputs == output
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecutionsQuery"


def test_job_execution_output_command(mocker):
    """
    Given:
        - job id.
    When
        - a user wants to get metadata regarding workflow state
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value_test = {
        "id": "69",
        "offset": "3732",
        "completed": True,
        "execCompleted": True,
        "hasFailedNodes": True,
        "execState": "failed",
        "lastModified": "123",
        "execDuration": 237,
        "percentLoaded": 12,
        "totalSize": 3738,
        "retryBackoff": 0,
        "clusterExec": False,
        "compacted": False,
        "entries": [
            {
                "node": "localhost",
                "step": "1",
                "stepctx": "1",
                "user": "admin",
                "time": "10:54:52",
                "level": "NORMAL",
                "type": "stepbegin",
                "absolute_time": "123",
                "log": "",
            }, {"another": 1}
        ],
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "job_execution_output", return_value=return_value_test)
    result = job_execution_output_command(client, {"execution_id": "69", "max_results": 1})
    assert result.outputs == return_value_test
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecutionsOutput"
    assert (
        result.readable_output
        == "### Job Execution Output:\n|Id|Offset|Completed|Exec Completed|Has Failed"
           " Nodes|Exec State|Last Modified|Exec Duration|Percent Loaded|Total Size|Retr"
           "y Backoff|Cluster Exec|Compacted|Entries|\n|---|---|---|---|---|---|---|---|-"
           "--|---|---|---|---|---|\n| 69 | 3732 | true | true | true | failed | 123 | 237"
           " | 12 | 3738 | 0 | false | false | {'node': 'localhost', 'step': '1', 'stepctx':"
           " '1', 'user': 'admin', 'time': '10:54:52', 'level': 'NORMAL', 'type': 'stepbegin',"
           " 'absolute_time': '123', 'log': ''},<br>{'another': 1} |\n### Job Execution Entries "
           "View:\n|Log|Node|Step|Stepctx|User|Time|Level|Type|Absolute Time|Log|\n|---|---|---|-"
           "--|---|---|---|---|---|---|\n|  | localhost | 1 | 1 | admin | 10:54:52 | NORMAL | stepbegin |  |  |\n"
    )


def test_job_execution_abort_command(mocker):
    """
    Given:
        - execution id.
    When
        - a user wants to abort an execution.
    Then
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "abort": {"status": "failed", "reason": "Job is not running"},
        "execution": {
            "id": "69",
            "status": "failed",
            "href": "123",
            "permalink": "123",
        },
    }
    output = {
        "abort": {"status": "failed", "reason": "Job is not running"},
        "execution": {"id": "69", "status": "failed"},
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "job_execution_abort", return_value=return_value)
    result = job_execution_abort_command(client, {"execution_id": "69"})
    assert result.outputs == output
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.Aborted"
    assert (
        result.readable_output
        == "### Job Execution Abort:\n|Abort|Execution|\n|---|---|\n|"
        " status: failed<br>reason: Job is not running | id: 69<br>status:"
        " failed |\n"
    )


def test_adhoc_command_run_command(mocker):
    """
    Given:
        - command to execute.
    When:
        - a user wants to executes shell commands in nodes.
    Then:
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196, "href": "123", "permalink": "123"},
    }
    output = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196},
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "adhoc_run", return_value=return_value)
    result = adhoc_run_command(client, {"exec_command": "echo hello"})
    assert result.outputs == output
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecuteCommand"
    assert (
        result.readable_output == "### Adhoc Run:\n|Message|Execution|\n|---|---|\n| "
        "Immediate execution scheduled (196) | id: 196 |\n"
    )


def test_adhoc_script_run_command(mocker):
    """
    Given:
        - Demisto entry_id.
    When:
        - a user wants to run a script from a file
    Then:
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196, "href": "123", "permalink": "123"},
    }
    output = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196},
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "adhoc_script_run", return_value=return_value)
    result = adhoc_script_run_command(client, {"entry_id": "123"})
    assert result.outputs == output
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ExecuteScriptFile"
    assert (
        result.readable_output
        == "### Adhoc Run Script:\n|Message|Execution|\n|---|---|\n|"
        " Immediate execution scheduled (196) | id: 196 |\n"
    )


def test_adhoc_script_run_from_url_command(mocker):
    """
    Given:
        - url to a script file
    When:
        - a user wants to run a script from a url
    Then:
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196, "href": "123", "permalink": "123"},
    }
    output = {
        "message": "Immediate execution scheduled (196)",
        "execution": {"id": 196},
    }
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "adhoc_script_run_from_url", return_value=return_value)
    result = adhoc_script_run_from_url_command(client, {"script_url": "123"})
    assert result.outputs == output
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.ScriptExecutionFromUrl"
    assert (
        result.readable_output
        == "### Adhoc Run Script From Url:\n|Message|Execution|\n|---|---|\n|"
        " Immediate execution scheduled (196) | id: 196 |\n"
    )


def test_webhooks_list_command(mocker):
    """
    Given:
        - None
    When:
        - a user wants to get a list of all existing webhooks.
    Then:
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = [
        {
            "id": 1,
            "uuid": "123",
            "name": "Test hook",
            "project": "Demisto",
            "enabled": True,
            "user": "admin",
            "creator": "admin",
            "roles": "123",
            "authToken": "123",
            "eventPlugin": "webhook-run-job",
            "config": {"jobId": "123", "argString": "123"},
        }, {"another": 1}
    ]
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "get_webhooks_list", return_value=return_value)
    result = webhooks_list_command(client, {"max_results": 1})
    assert result.outputs == [return_value[0]]
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.Webhooks"
    assert (
        result.readable_output
        == "### Webhooks List:\n|Id|Uuid|Name|Project|Enabled|User|Creator|Roles|Auth Token"
           "|Event Plugin|Config|\n|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | 123 "
           "| Test hook | Demisto | true | admin | admin | 123 | 123 | webhook-run-job | jobId:"
           " 123<br>argString: 123 |\n|  |  |  |  |  |  |  |  |  |  |  |\n"
    )


def test_webhook_event_send(mocker):
    """
    Given:
        - None
    When:
        - a user wants to get a list of all existing webhooks.
    Then:
        - CommonResults object returns with the api response.
    """
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    return_value = {"jobId": "123", "executionId": "199"}
    client = Client(
        base_url="base_url",
        verify=False,
        params={"authtoken": "123"},
        project_name="Demisto",
    )
    mocker.patch.object(client, "webhook_event_send", return_value=return_value)

    result = webhook_event_send_command(client, {"auth_token": "123"})
    assert result.outputs == return_value
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == "Rundeck.WebhookEvent"
    assert (
        result.readable_output
        == "### Webhook event send:\n|Job Id|Execution Id|\n|---|---|\n| 123 | 199 |\n"
    )


def test_calc_run_at_time():
    """
    Given:
        - delta from current time
    When:
        - need to get ISO 8601 time for the givan delta
    Then:
        - ISO 8601 time
    """
    cur_date = datetime.now().replace(tzinfo=timezone.utc)
    result = parse(calc_run_at_time("1 second")).replace(tzinfo=timezone.utc)
    assert cur_date.year == result.year
    assert cur_date.month == result.month
    assert cur_date.day == result.day


def test_collect_headers():
    """
    Given:
        - list of dictionaries
    When:
        - need to collect all keys from all dictionaries
    Then:
        - get list of keys
    """
    result = collect_headers([{"1": 2, "3": 4}, {"5": 6, "7": 8}])
    assert result == ["1", "3", "5", "7"]


def test_collect_log_from_output():
    """
    Given:
        - list of execution output
    When:
        - need to collect all all log entries
    Then:
        - get list of log entries
    """

    entries = [
        {
            "node": "localhost",
            "step": "1",
            "stepctx": "1",
            "user": "admin",
            "time": "10:54:52",
            "level": "NORMAL",
            "type": "log",
            "absolute_time": "2020-10-11T10:54:52Z",
            "log": "",
        },
        {
            "node": "localhost",
            "step": "1",
            "stepctx": "1",
            "time": "10:54:52",
            "level": "NORMAL",
            "type": "nodebegin",
            "absolute_time": "2020-10-11T10:54:52Z",
            "log": "",
        },
        {
            "node": "localhost",
            "step": "1",
            "stepctx": "1",
            "time": "10:54:52",
            "level": "NORMAL",
            "type": "log",
            "absolute_time": "2020-10-11T10:54:52Z",
            "log": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001",
        },
    ]

    result = collect_log_from_output(entries)
    assert len(result) == 2
