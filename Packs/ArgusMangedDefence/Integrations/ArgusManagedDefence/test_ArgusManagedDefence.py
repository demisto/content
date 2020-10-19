BASE_URL = "https://api.mnemonic.no"
CASE_ID = 1337
COMMENT_ID = "some-long-hash"
TAG_ID = "some-long-hash"
TAG_KEY = "test_key"
TAG_VALUE = "test_value"
ATTACHMENT_ID = "some-long-hash"


def test_is_valid_service():
    from ArgusManagedDefence import is_valid_service

    assert is_valid_service("ids")
    assert is_valid_service("support")
    assert is_valid_service("administrative")
    assert is_valid_service("advisory")
    assert is_valid_service("vulnscan")
    assert not is_valid_service("not_a_service")


def test_is_valid_case_type():
    from ArgusManagedDefence import is_valid_case_type

    assert is_valid_case_type("ids", "change")
    assert not is_valid_case_type("not_a_service", "change")
    assert not is_valid_case_type("ids", "not_a_type")


def test_fetch_incidents():
    raise NotImplementedError


def test_add_case_tag_command(requests_mock):
    from ArgusManagedDefence import add_case_tag_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/tags"

    requests_mock.post(f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_TAGS)
    args = {"case_id": CASE_ID, "key": "test_key", "value": "test_value"}
    result = add_case_tag_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_TAGS


def test_add_comment_command(requests_mock):
    from ArgusManagedDefence import add_comment_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/comments"

    requests_mock.post(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_COMMENT
    )
    args = {"case_id": CASE_ID, "comment": "test_comment"}
    result = add_comment_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_COMMENT


def test_advanced_case_search_command(requests_mock):
    from ArgusManagedDefence import advanced_case_search_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/search"

    requests_mock.post(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_SEARCH_RESULT
    )
    result = advanced_case_search_command({})
    assert result.raw_response == argus_case_data.ARGUS_CASE_SEARCH_RESULT


def test_close_case_command(requests_mock):
    from ArgusManagedDefence import close_case_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/close"
    requests_mock.put(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_METADATA
    )
    args = {"case_id": CASE_ID}
    result = close_case_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_METADATA


def test_create_case_command(requests_mock):
    from ArgusManagedDefence import create_case_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case"

    requests_mock.post(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_METADATA
    )
    args = {
        "subject": "test subject",
        "description": "test description",
        "service": "administrative",
        "type": "informational",
        "tags": "test_key,test_value",
    }
    result = create_case_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_METADATA


def test_delete_case_command(requests_mock):
    from ArgusManagedDefence import delete_case_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}"

    requests_mock.delete(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_METADATA
    )
    args = {"case_id": CASE_ID}
    result = delete_case_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_METADATA


def test_delete_comment_command(requests_mock):
    from ArgusManagedDefence import delete_comment_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/comments/{COMMENT_ID}"

    requests_mock.delete(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_COMMENT
    )
    args = {"case_id": CASE_ID, "comment_id": COMMENT_ID}
    result = delete_comment_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_COMMENT


def test_download_attachment_command(requests_mock):
    from ArgusManagedDefence import download_attachment_command
    with open("argus_json/argus_case_data.py", "rb") as file:
        content = file.read()

    method_url = f"/cases/v2/case/{CASE_ID}/attachments/{ATTACHMENT_ID}/download"

    requests_mock.get(f"{BASE_URL}{method_url}", content=content)
    args = {"case_id": CASE_ID, "attachment_id": ATTACHMENT_ID}
    result = download_attachment_command(args)
    assert result['File'] == ATTACHMENT_ID


def test_edit_comment_command(requests_mock):
    from ArgusManagedDefence import edit_comment_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/comments/{COMMENT_ID}"

    requests_mock.put(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_COMMENT
    )
    args = {"case_id": CASE_ID, "comment_id": COMMENT_ID, "comment": "test comment"}
    result = edit_comment_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_COMMENT


def test_get_attachment_command(requests_mock):
    from ArgusManagedDefence import get_attachment_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/attachments/{ATTACHMENT_ID}"

    requests_mock.get(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_ATTACHMENT
    )
    args = {"case_id": CASE_ID, "attachment_id": ATTACHMENT_ID}
    result = get_attachment_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_ATTACHMENT


def test_get_case_metadata_by_id_command(requests_mock):
    from ArgusManagedDefence import get_case_metadata_by_id_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}"

    requests_mock.get(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_METADATA
    )
    args = {"case_id": CASE_ID}
    result = get_case_metadata_by_id_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_METADATA


def test_list_case_attachments_command(requests_mock):
    from ArgusManagedDefence import list_case_attachments_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/attachments"

    requests_mock.get(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_ATTACHMENTS
    )
    args = {"case_id": CASE_ID}
    result = list_case_attachments_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_ATTACHMENTS


def test_list_case_tags_command(requests_mock):
    from ArgusManagedDefence import list_case_tags_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/tags"

    requests_mock.get(f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_TAGS)
    args = {"case_id": CASE_ID}
    result = list_case_tags_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_TAGS


def test_list_case_comments_command(requests_mock):
    from ArgusManagedDefence import list_case_comments_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/comments"

    requests_mock.get(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_COMMENTS_LIST
    )
    args = {"case_id": CASE_ID}
    result = list_case_comments_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_COMMENTS_LIST


def test_remove_case_tag_by_id_command(requests_mock):
    from ArgusManagedDefence import remove_case_tag_by_id_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/tags/{TAG_ID}"

    requests_mock.delete(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_TAGS
    )
    args = {"case_id": CASE_ID, "tag_id": TAG_ID}
    result = remove_case_tag_by_id_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_TAGS


def test_remove_case_tag_by_key_value_command(requests_mock):
    from ArgusManagedDefence import remove_case_tag_by_key_value_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}/tags/{TAG_KEY}/{TAG_VALUE}"

    requests_mock.delete(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_TAGS
    )
    args = {"case_id": CASE_ID, "key": TAG_KEY, "value": TAG_VALUE}
    result = remove_case_tag_by_key_value_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_TAGS


def test_update_case_command(requests_mock):
    from ArgusManagedDefence import update_case_command
    from argus_json import argus_case_data

    method_url = f"/cases/v2/case/{CASE_ID}"

    requests_mock.put(
        f"{BASE_URL}{method_url}", json=argus_case_data.ARGUS_CASE_METADATA
    )
    args = {"case_id": CASE_ID}
    result = update_case_command(args)
    assert result.raw_response == argus_case_data.ARGUS_CASE_METADATA


def test_get_events_for_case_command(requests_mock):
    from ArgusManagedDefence import get_events_for_case_command
    from argus_json import argus_event_data

    method_url = f"/events/v1/case/{CASE_ID}"

    requests_mock.get(f"{BASE_URL}{method_url}", json=argus_event_data.ARGUS_EVENTS_FOR_CASE)
    args = {"case_id": CASE_ID}
    result = get_events_for_case_command(args)
    assert result.raw_response == argus_event_data.ARGUS_EVENTS_FOR_CASE


def test_find_aggregated_events_command(requests_mock):
    from ArgusManagedDefence import find_aggregated_events_command
    from argus_json import argus_event_data

    method_url = f"/events/v1/aggregated/search"

    requests_mock.post(f"{BASE_URL}{method_url}", json=argus_event_data.ARGUS_EVENTS_FOR_CASE)
    result = find_aggregated_events_command({})
    assert result.raw_response == argus_event_data.ARGUS_EVENTS_FOR_CASE


def test_list_aggregated_events_command(requests_mock):
    from ArgusManagedDefence import list_aggregated_events_command
    from argus_json import argus_event_data

    method_url = f"/events/v1/aggregated"

    requests_mock.get(f"{BASE_URL}{method_url}", json=argus_event_data.ARGUS_EVENTS_FOR_CASE)
    result = list_aggregated_events_command({})
    assert result.raw_response == argus_event_data.ARGUS_EVENTS_FOR_CASE


def test_get_event(requests_mock):
    from ArgusManagedDefence import get_event_command
    from argus_json import argus_event_data

    event_type = "NIDS"
    timestamp = "some-timestamp"
    customer_id = 5381
    event_id = "some-hash"
    method_url = f"/events/v1/{event_type}/{timestamp}/{customer_id}/{event_id}"

    requests_mock.get(f"{BASE_URL}{method_url}", json=argus_event_data.ARGUS_EVENT)
    args = {"type": event_type, "timestamp": timestamp, "customer_id": customer_id, "event_id": event_id}
    result = get_event_command(args)
    assert result.raw_response == argus_event_data.ARGUS_EVENT


def test_get_payload_command(requests_mock):
    from ArgusManagedDefence import get_payload_command
    from argus_json import argus_event_data

    event_type = "NIDS"
    timestamp = "some-timestamp"
    customer_id = 5381
    event_id = "some-hash"
    method_url = f"/events/v1/{event_type}/{timestamp}/{customer_id}/{event_id}/payload"

    requests_mock.get(f"{BASE_URL}{method_url}", json=argus_event_data.ARGUS_EVENT_PAYLOAD)
    args = {"type": event_type, "timestamp": timestamp, "customer_id": customer_id, "event_id": event_id}
    result = get_payload_command(args)
    assert result.raw_response == argus_event_data.ARGUS_EVENT_PAYLOAD


def test_get_pcap_command(requests_mock):
    from ArgusManagedDefence import get_pcap_command
    from argus_json import argus_event_data

    with open("argus_json/argus_case_data.py", "rb") as file:
        content = file.read()

    event_type = "NIDS"
    timestamp = "some-timestamp"
    customer_id = 5381
    event_id = "some-hash"
    method_url = f"/events/v1/{event_type}/{timestamp}/{customer_id}/{event_id}/pcap"

    requests_mock.get(f"{BASE_URL}{method_url}", content=content)
    args = {"type": event_type, "timestamp": timestamp, "customer_id": customer_id, "event_id": event_id}
    result = get_pcap_command(args)
    assert result['File'] == f"{event_id}_pcap"


def test_search_records_command(requests_mock):
    raise NotImplementedError


def test_fetch_observations_for_domain_command(requests_mock):
    raise NotImplementedError


def test_fetch_observations_for_i_p_command(requests_mock):
    raise NotImplementedError


def test_find_n_ids_events(requests_mock):
    raise NotImplementedError


def test_list_n_ids_events(requests_mock):
    raise NotImplementedError