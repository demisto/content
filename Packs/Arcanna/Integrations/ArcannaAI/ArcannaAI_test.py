import json
import demistomock as demisto

from ArcannaAI import Client, get_jobs, post_event, get_event_status, \
    send_event_feedback, get_decision_set, trigger_training

client = Client(base_url="demisto.con", verify=False, proxy=False, headers={})


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


connection_json = {"connected": True}

arcanna_get_decision_set_response = ['Drop', 'Escalate']

arcanna_trigger_train_response = {
    "status": "OK",
    "error_message": ""
}

arcanna_inference_response = {
    "event_id": "11013867751676",
    "ingest_timestamp": "2021-06-30T13:57:47.386775",
    "status": "OK",
    "confidence_level": 0.9961161017417908,
    "result": "escalate_alert",
    "is_duplicated": True,
    "error_message": ""
}

arcanna_ingest_response = {
    "event_id": "20198",
    "ingest_timestamp": "2021-07-01T07:58:03.801992",
    "status": "Pending inference",
    "error_message": ""
}

arcanna_jobs_response = [
    {
        "job_id": 1,
        "data_type": "a",
        "title": "cortex",
        "status": "STARTED"
    },
    {
        "job_id": 2,
        "data_type": "palo",
        "title": "cortex5",
        "status": "IDLE"
    }
]

arcanna_event_feedback_response = {
    "status": "updated"
}


def test_arcanna_get_jobs_command(mocker):
    mocker.patch.object(client, "list_jobs", return_value=arcanna_jobs_response)
    command_result = get_jobs(client)
    assert len(command_result.raw_response) == 2
    assert command_result.raw_response[0]["job_id"] == 1
    assert command_result.raw_response[0]["status"] == "STARTED"
    assert command_result.raw_response[1]["job_id"] == 2
    assert command_result.raw_response[1]["status"] == "IDLE"


def test_arcanna_send_event_command(mocker):
    mocker.patch.object(client, "send_raw_event", return_value=arcanna_ingest_response)
    command_args = {
        "job_id": 10,
        "event_json": "{\"offset\": 1739561255, \"destination\": \"127.0.0.1\"}",
        "severity": 3,
        "title": "Incident id #20198",
        "id_value": "20198"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = post_event(client, 1201, command_args)

    assert command_result.raw_response['event_id'] == "20198"
    assert command_result.raw_response['error_message'] == ""
    assert command_result.raw_response['status'] == "Pending inference"


def test_arcanna_get_decision_set(mocker):
    mocker.patch.object(client, "get_decision_set", return_value=arcanna_get_decision_set_response)
    command_args = {
        "job_id": 10
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = get_decision_set(client, 1201, command_args)
    assert isinstance(command_result.raw_response, list)
    assert "Drop" in command_result.raw_response


def test_arcanna_trigger_train(mocker):
    mocker.patch.object(client, "trigger_training", return_value=arcanna_trigger_train_response)
    command_args = {
        "job_id": 10,
        "username": "myusername"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = trigger_training(client, 1201, command_args)
    assert command_result.raw_response["status"] == "OK"
    assert command_result.raw_response["error_message"] == ""


def test_arcanna_get_event_status_command(mocker):
    mocker.patch.object(client, "get_event_status", return_value=arcanna_inference_response)
    command_args = {
        "job_id": 10,
        "event_id": "11013867751676",
        "polling": "false",
        "interval": 10,
        "timeout": 60
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = get_event_status(command_args, client, 1201)
    assert command_result.raw_response['status'] == "OK"
    assert command_result.raw_response['result'] == "escalate_alert"


def test_arcanna_send_event_feedback_command(mocker):
    mocker.patch.object(client, "send_feedback", return_value=arcanna_event_feedback_response)
    command_args = {
        "job_id": 10,
        "event_id": 10110011,
        "feedback": "Escalate",
        "decision_set": ["Drop", "Escalate"],
        "username": "dbot"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = send_event_feedback(client=client, default_job_id=1201, args=command_args)

    assert command_result.raw_response['status'] == "updated"
