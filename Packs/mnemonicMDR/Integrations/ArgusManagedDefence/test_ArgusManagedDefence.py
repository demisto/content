import json
import pytest

BASE_URL = "https://api.mnemonic.no"
CASE_ID = 1337
COMMENT_ID = "some-long-hash"
TAG_ID = "some-long-hash"
TAG_KEY = "test_key"
TAG_VALUE = "test_value"
ATTACHMENT_ID = "some-long-hash"
EVENT_TYPE = "NIDS"
TIMESTAMP = "some-timestamp"
CUSTOMER_ID = 5381
EVENT_ID = "some-hash"


def test_argus_priority_to_demisto_severity():
    from ArgusManagedDefence import argus_priority_to_demisto_severity

    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4, "not valid value": 0}
    for key, value in mapping.items():
        assert argus_priority_to_demisto_severity(key) == value


def test_argus_status_to_demisto_status():
    from ArgusManagedDefence import argus_status_to_demisto_status

    mapping = {
        "pendingCustomer": 0,
        "pendingSoc": 0,
        "pendingVendor": 0,
        "pendingClose": 0,
        "workingSoc": 1,
        "workingCustomer": 1,
        "closed": 2,
        "not valid value": 0,
    }
    for key, value in mapping.items():
        assert argus_status_to_demisto_status(key) == value


def test_build_argus_priority_from_min_severity():
    from ArgusManagedDefence import build_argus_priority_from_min_severity

    assert build_argus_priority_from_min_severity("low") == [
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert build_argus_priority_from_min_severity("medium") == [
        "medium",
        "high",
        "critical",
    ]
    assert build_argus_priority_from_min_severity("high") == ["high", "critical"]
    assert build_argus_priority_from_min_severity("critical") == ["critical"]
    assert build_argus_priority_from_min_severity("not valid") == [
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_date_time_to_epoch_milliseconds_datetime():
    from ArgusManagedDefence import date_time_to_epoch_milliseconds
    import datetime

    date = datetime.datetime(2000, 1, 1, 00, 00, 00)
    timestamp = date.timestamp() * 1000
    assert date_time_to_epoch_milliseconds(date) == timestamp


def test_date_time_to_epoch_milliseconds_str():
    from ArgusManagedDefence import date_time_to_epoch_milliseconds
    import datetime

    timestamp = int(datetime.datetime(2000, 1, 1, 00, 00, 00).timestamp() * 1000)
    assert date_time_to_epoch_milliseconds("2000-01-01 00:00:00") == timestamp


def test_date_time_to_epoch_milliseconds_malformed_str():
    from ArgusManagedDefence import date_time_to_epoch_milliseconds

    assert date_time_to_epoch_milliseconds("gibberish")


def test_date_time_to_epoch_milliseconds_empty():
    from ArgusManagedDefence import date_time_to_epoch_milliseconds

    assert date_time_to_epoch_milliseconds()


def test_pretty_print_date_datetime():
    from ArgusManagedDefence import pretty_print_date, PRETTY_DATE_FORMAT
    import datetime

    date = datetime.datetime(2000, 1, 1, 00, 00, 00)
    assert pretty_print_date(date) == date.strftime(PRETTY_DATE_FORMAT)


def test_pretty_print_date_str():
    from ArgusManagedDefence import pretty_print_date

    date_string = "Jan 01, 2000, 00:00:00"
    assert pretty_print_date(date_string) == date_string


def test_pretty_print_date_malformed_str():
    from ArgusManagedDefence import pretty_print_date

    date_string = "gibberish"
    assert pretty_print_date(date_string)


def test_pretty_print_date_empty():
    from ArgusManagedDefence import pretty_print_date

    assert pretty_print_date()


def test_build_tags_from_list():
    from ArgusManagedDefence import build_tags_from_list

    assert build_tags_from_list(None) == []
    assert build_tags_from_list([]) == []
    assert build_tags_from_list(["list must be divisible by two"]) == []
    assert build_tags_from_list(["foo", "bar"]) == [{"key": "foo", "value": "bar"}]


def test_str_to_dict():
    from ArgusManagedDefence import str_to_dict

    assert str_to_dict(None) == {}
    assert str_to_dict("") == {}
    assert str_to_dict("one_value") == {}
    assert str_to_dict("foo,bar") == {"foo": "bar"}
    assert str_to_dict("foo,bar,key,value") == {"foo": "bar", "key": "value"}


def test_parse_first_fetch():
    from ArgusManagedDefence import parse_first_fetch

    assert parse_first_fetch("some string") == "-some string"
    assert parse_first_fetch("-some string") == "-some string"
    assert parse_first_fetch(123) == 123


def test_test_module_command(requests_mock):
    from ArgusManagedDefence import test_module_command

    with open("argus_json/argus_currentuser.json") as json_file:
        data = json.load(json_file)
    method_url = "/currentuser/v1/user"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    assert test_module_command() != "ok"
    data["responseCode"] = 200
    assert test_module_command() == "ok"


def test_fetch_incidents(requests_mock):
    from ArgusManagedDefence import fetch_incidents

    with open("argus_json/argus_case_search.json") as json_file:
        data = json.load(json_file)
    method_url = "/cases/v2/case/search"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    last_run = {"start_time": 1603372183576}
    next_run, incidents = fetch_incidents(last_run, "-1 day")
    assert len(incidents) == 1
    assert incidents[0]["name"] == "#0: string"
    assert next_run.get("start_time") == "1"


def test_fetch_incidents_increment_timestamp(requests_mock):
    from ArgusManagedDefence import fetch_incidents

    method_url = "/cases/v2/case/search"
    timestamp = 327645
    with open("argus_json/argus_case_search.json") as json_file:
        data = json.load(json_file)
    data["data"][0]["createdTimestamp"] = timestamp

    requests_mock.post(f"{BASE_URL}{method_url}", json=data)

    next_run, incidents = fetch_incidents({}, "-1 day")
    assert len(incidents) == 1
    assert next_run.get("start_time") == str(timestamp + 1)


def test_get_remote_data_command(requests_mock):
    raise NotImplementedError


def test_get_modified_remote_data_command(requests_mock):
    raise NotImplementedError


def test_update_remote_system_command(requests_mock):
    raise NotImplementedError


def test_get_mapping_fields_command(requests_mock):
    raise NotImplementedError


def test_add_case_tag_command(requests_mock):
    from ArgusManagedDefence import add_case_tag_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/tags"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "key": "test_key", "value": "test_value"}
    result = add_case_tag_command(args)
    assert result.raw_response == data


def test_add_comment_command(requests_mock):
    from ArgusManagedDefence import add_comment_command

    with open("argus_json/argus_case_comment.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/comments"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "comment": "test_comment"}
    result = add_comment_command(args)
    assert result.raw_response == data


def test_advanced_case_search_command(requests_mock):
    from ArgusManagedDefence import advanced_case_search_command

    with open("argus_json/argus_case_search.json") as json_file:
        data = json.load(json_file)
    method_url = "/cases/v2/case/search"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    result = advanced_case_search_command({})
    assert result.raw_response == data


def test_close_case_command(requests_mock):
    from ArgusManagedDefence import close_case_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/close"
    requests_mock.put(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = close_case_command(args)
    assert result.raw_response == data


def test_create_case_command(requests_mock):
    from ArgusManagedDefence import create_case_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = "/cases/v2/case"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    args = {
        "subject": "test subject",
        "description": "test description",
        "service": "administrative",
        "type": "informational",
        "tags": "test_key,test_value",
    }
    result = create_case_command(args)
    assert result.raw_response == data


def test_delete_case_command(requests_mock):
    from ArgusManagedDefence import delete_case_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}"
    requests_mock.delete(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = delete_case_command(args)
    assert result.raw_response == data


def test_delete_comment_command(requests_mock):
    from ArgusManagedDefence import delete_comment_command

    with open("argus_json/argus_case_comment.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/comments/{COMMENT_ID}"
    requests_mock.delete(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "comment_id": COMMENT_ID}
    result = delete_comment_command(args)
    assert result.raw_response == data


def test_download_attachment_command(requests_mock):
    from ArgusManagedDefence import download_attachment_command

    with open("argus_json/argus_case_attachment.json", "rb") as file:
        content = file.read()
    method_url = f"/cases/v2/case/{CASE_ID}/attachments/{ATTACHMENT_ID}/download"
    requests_mock.get(f"{BASE_URL}{method_url}", content=content)
    args = {"case_id": CASE_ID, "attachment_id": ATTACHMENT_ID}
    result = download_attachment_command(args)
    assert result["File"] == ATTACHMENT_ID


def test_download_attachment_command_failed(requests_mock):
    from ArgusManagedDefence import download_attachment_command

    with open("argus_json/argus_case_attachment.json", "rb") as file:
        content = file.read()
    method_url = f"/cases/v2/case/{CASE_ID}/attachments/{ATTACHMENT_ID}/download"
    requests_mock.get(f"{BASE_URL}{method_url}", content=content, status_code=412)
    args = {"case_id": CASE_ID, "attachment_id": ATTACHMENT_ID}
    with pytest.raises(SystemExit) as method_exit:
        download_attachment_command(args)
    assert method_exit.type == SystemExit


def test_edit_comment_command(requests_mock):
    from ArgusManagedDefence import edit_comment_command

    with open("argus_json/argus_case_comment.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/comments/{COMMENT_ID}"
    requests_mock.put(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "comment_id": COMMENT_ID, "comment": "test comment"}
    result = edit_comment_command(args)
    assert result.raw_response == data


def test_get_attachment_command(requests_mock):
    from ArgusManagedDefence import get_attachment_command

    with open("argus_json/argus_case_attachment.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/attachments/{ATTACHMENT_ID}"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "attachment_id": ATTACHMENT_ID}
    result = get_attachment_command(args)
    assert result.raw_response == data


def test_get_case_metadata_by_id_command(requests_mock):
    from ArgusManagedDefence import get_case_metadata_by_id_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = get_case_metadata_by_id_command(args)
    assert result.raw_response == data


def test_list_case_attachments_command(requests_mock):
    from ArgusManagedDefence import list_case_attachments_command

    with open("argus_json/argus_case_attachments.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/attachments"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = list_case_attachments_command(args)
    assert result.raw_response == data


def test_list_case_tags_command(requests_mock):
    from ArgusManagedDefence import list_case_tags_command

    with open("argus_json/argus_case_tags.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/tags"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = list_case_tags_command(args)
    assert result.raw_response == data


def test_list_case_comments_command(requests_mock):
    from ArgusManagedDefence import list_case_comments_command

    with open("argus_json/argus_case_comments.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/comments"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = list_case_comments_command(args)
    assert result.raw_response == data


def test_remove_case_tag_by_id_command(requests_mock):
    from ArgusManagedDefence import remove_case_tag_by_id_command

    with open("argus_json/argus_case_tags.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/tags/{TAG_ID}"
    requests_mock.delete(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "tag_id": TAG_ID}
    result = remove_case_tag_by_id_command(args)
    assert result.raw_response == data


def test_remove_case_tag_by_key_value_command(requests_mock):
    from ArgusManagedDefence import remove_case_tag_by_key_value_command

    with open("argus_json/argus_case_tags.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}/tags/{TAG_KEY}/{TAG_VALUE}"
    requests_mock.delete(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID, "key": TAG_KEY, "value": TAG_VALUE}
    result = remove_case_tag_by_key_value_command(args)
    assert result.raw_response == data


def test_update_case_command(requests_mock):
    from ArgusManagedDefence import update_case_command

    with open("argus_json/argus_case_metadata.json") as json_file:
        data = json.load(json_file)
    method_url = f"/cases/v2/case/{CASE_ID}"
    requests_mock.put(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = update_case_command(args)
    assert result.raw_response == data


def test_get_events_for_case_command(requests_mock):
    from ArgusManagedDefence import get_events_for_case_command

    with open("argus_json/argus_events.json") as json_file:
        data = json.load(json_file)
    method_url = f"/events/v1/case/{CASE_ID}"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {"case_id": CASE_ID}
    result = get_events_for_case_command(args)
    assert result.raw_response == data


def test_find_aggregated_events_command(requests_mock):
    from ArgusManagedDefence import find_aggregated_events_command

    with open("argus_json/argus_events.json") as json_file:
        data = json.load(json_file)
    method_url = "/events/v1/aggregated/search"
    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    result = find_aggregated_events_command({})
    assert result.raw_response == data


def test_list_aggregated_events_command(requests_mock):
    from ArgusManagedDefence import list_aggregated_events_command

    with open("argus_json/argus_events.json") as json_file:
        data = json.load(json_file)
    method_url = "/events/v1/aggregated"
    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    result = list_aggregated_events_command({})
    assert result.raw_response == data


def test_get_event(requests_mock):
    from ArgusManagedDefence import get_event_command

    with open("argus_json/argus_event.json") as json_file:
        data = json.load(json_file)

    method_url = f"/events/v1/{EVENT_TYPE}/{TIMESTAMP}/{CUSTOMER_ID}/{EVENT_ID}"

    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {
        "type": EVENT_TYPE,
        "timestamp": TIMESTAMP,
        "customer_id": CUSTOMER_ID,
        "event_id": EVENT_ID,
    }
    result = get_event_command(args)
    assert result.raw_response == data


def test_get_payload_command(requests_mock):
    from ArgusManagedDefence import get_payload_command

    with open("argus_json/argus_event_payload.json") as json_file:
        data = json.load(json_file)

    method_url = f"/events/v1/{EVENT_TYPE}/{TIMESTAMP}/{CUSTOMER_ID}/{EVENT_ID}/payload"

    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    args = {
        "type": EVENT_TYPE,
        "timestamp": TIMESTAMP,
        "customer_id": CUSTOMER_ID,
        "event_id": EVENT_ID,
    }
    result = get_payload_command(args)
    assert result.raw_response == data


def test_get_pcap_command(requests_mock):
    from ArgusManagedDefence import get_pcap_command

    with open("argus_json/argus_event.json", "rb") as file:
        content = file.read()

    method_url = f"/events/v1/{EVENT_TYPE}/{TIMESTAMP}/{CUSTOMER_ID}/{EVENT_ID}/pcap"

    requests_mock.get(f"{BASE_URL}{method_url}", content=content)
    args = {
        "type": EVENT_TYPE,
        "timestamp": TIMESTAMP,
        "customer_id": CUSTOMER_ID,
        "event_id": EVENT_ID,
    }
    result = get_pcap_command(args)
    assert result["File"] == f"{EVENT_ID}_pcap"


def test_search_records_command(requests_mock):
    from ArgusManagedDefence import search_records_command

    with open("argus_json/argus_event_pdns.json") as json_file:
        data = json.load(json_file)

    query = "mnemonic.no"
    method_url = "/pdns/v3/search"

    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    result = search_records_command({"query": query})
    assert result.raw_response == data


def test_fetch_observations_for_domain_command(requests_mock):
    from ArgusManagedDefence import fetch_observations_for_domain_command

    with open("argus_json/argus_event_obs_domain.json") as json_file:
        data = json.load(json_file)
    fqdn = "domain.test"
    method_url = f"/reputation/v1/observation/domain/{fqdn}"

    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    result = fetch_observations_for_domain_command({"fqdn": fqdn})
    assert result.raw_response == data


def test_fetch_observations_for_i_p_command(requests_mock):
    from ArgusManagedDefence import fetch_observations_for_i_p_command

    with open("argus_json/argus_event_obs_ip.json") as json_file:
        data = json.load(json_file)

    ip = "0.0.0.0"
    method_url = f"/reputation/v1/observation/ip/{ip}"

    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    result = fetch_observations_for_i_p_command({"ip": ip})
    assert result.raw_response == data


def test_find_nids_events(requests_mock):
    from ArgusManagedDefence import find_nids_events_command

    with open("argus_json/argus_event_nids.json") as json_file:
        data = json.load(json_file)
    method_url = "/events/v1/nids/search"

    requests_mock.post(f"{BASE_URL}{method_url}", json=data)
    result = find_nids_events_command({})
    assert result.raw_response == data


def test_list_nids_events(requests_mock):
    from ArgusManagedDefence import list_nids_events_command

    with open("argus_json/argus_event_nids.json") as json_file:
        data = json.load(json_file)
    method_url = "/events/v1/nids"

    requests_mock.get(f"{BASE_URL}{method_url}", json=data)
    result = list_nids_events_command({})
    assert result.raw_response == data
