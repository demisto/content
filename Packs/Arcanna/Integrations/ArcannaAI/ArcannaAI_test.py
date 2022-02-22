import json
import io
import demistomock as demisto

from ArcannaAI import Client, get_jobs, post_event, get_default_job_id, set_default_job_id, get_event_status, \
    send_event_feedback, get_feedback_field

client = Client(api_key="dummy", base_url="demisto.con", verify=False, proxy=False, default_job_id=-1)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


connection_json = {"connected": True}

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
    "event_id": "11018019921461",
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


def test_arcanna_get_default_job_id_command(mocker):
    mocker.patch.object(client, "get_default_job_id", return_value=10)
    command_result = get_default_job_id(client)
    assert command_result.raw_response == 10


def test_arcanna_set_default_job_id_command(mocker):
    mocker.patch.object(client, "set_default_job_id")
    mocker.patch.object(client, "get_default_job_id", return_value=10)
    command_args = {
        "job_id": 10
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = set_default_job_id(client, command_args)
    assert command_result.raw_response == 10


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
        "title": "Incident id #20198"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = post_event(client, command_args)

    assert command_result.outputs_prefix == "Arcanna.Event"
    assert command_result.raw_response['event_id'] == "11018019921461"
    assert command_result.raw_response['error_message'] == ""
    assert command_result.raw_response['status'] == "Pending inference"


def test_arcanna_get_event_status_command(mocker):
    mocker.patch.object(client, "get_event_status", return_value=arcanna_inference_response)
    command_args = {
        "job_id": 10,
        "event_id": "11013867751676"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = get_event_status(client, command_args)
    assert command_result.outputs_prefix == "Arcanna.Event"
    assert command_result.outputs_key_field == "event_id"
    assert command_result.raw_response['status'] == "OK"
    assert command_result.raw_response['result'] == "escalate_alert"


def test_arcanna_send_event_feedback_command(mocker):
    mocker.patch.object(client, "send_feedback", return_value=arcanna_event_feedback_response)
    command_args = {
        "job_id": 10,
        "event_id": 10110011,
        "label": "Resolved",
        "cortex_user": "dbot",
        "closing_notes": "notes"
    }
    mocker.patch.object(demisto, 'args', return_value=command_args)
    command_result = send_event_feedback(client=client,
                                         feature_mapping_field='"Resolved"="escalate_alert"',
                                         args=command_args)

    assert command_result.outputs_prefix == "Arcanna.Event"
    assert command_result.raw_response['status'] == "updated"


def test_arcanna_get_feedback_field():
    params = {
        "closing_reason_field": "closeReason"
    }
    command_result = get_feedback_field(params)
    assert command_result.outputs_prefix == "Arcanna.FeedbackField"
