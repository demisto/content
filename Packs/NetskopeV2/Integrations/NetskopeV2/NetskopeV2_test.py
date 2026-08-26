import json
import os
from unittest.mock import patch

import pytest
from CommonServerPython import DemistoException
from NetskopeV2 import (
    Client,
    apply_device_tags,
    create_destination_profile,
    create_device_classification_rule,
    create_device_classification_tag,
    create_device_tag,
    create_network_profile,
    create_private_app,
    delete_network_profile,
    delete_private_app,
    deploy_destination_profiles,
    find_device,
    get_destination_profile_applied_version,
    get_scan_report,
    list_device_classification_tags,
    list_device_tags,
    list_destination_profiles,
    list_network_profiles,
    list_private_apps,
    list_publishers,
    migrate_url_list_into_destination_profile,
    migrate_url_list_to_destination_profile,
    replace_private_app,
    revert_destination_profile,
    submit_file_scan,
    update_destination_profile,
    update_destination_profile_values,
    update_file_hash_list,
    update_network_profile_values,
    update_private_app,
    update_private_app_tags,
    url_lookup,
)

SERVER_URL = "https://test_url.com/"
API_KEY = "api_key"
API_V1_TOKEN = "api_v1_token"


def util_load_json(file_name):
    with open(os.path.join("test_data", f"{file_name}.json"), encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def client():
    return Client(
        base_url=SERVER_URL,
        verify=False,
        proxy=False,
        headers={"Netskope-Api-Token": API_KEY},
        api_key=API_KEY,
        api_v1_token=API_V1_TOKEN,
    )


def test_list_device_classification_tags(client, requests_mock):
    mock_response = util_load_json("device_classification_tags")
    requests_mock.get(f"{SERVER_URL}api/v2/deviceclassification/tags", json=mock_response)

    result = list_device_classification_tags(client, {})

    assert result.outputs == mock_response
    assert result.outputs_prefix == "Netskope.DeviceClassificationTag"


def test_create_device_classification_tag(client, requests_mock):
    mock_response = util_load_json("create_device_classification_tag_response")
    requests_mock.post(f"{SERVER_URL}api/v2/deviceclassification/tags", json=mock_response)

    result = create_device_classification_tag(client, {"name": "low risk", "description": "low risk devices"})

    assert result.outputs["ids"] == [18006]
    assert requests_mock.last_request.json() == [{"name": "low risk", "description": "low risk devices"}]


def test_create_device_classification_tag_invalid_name(client):
    with pytest.raises(DemistoException, match="alphanumeric"):
        create_device_classification_tag(client, {"name": "low risk!"})


def test_create_device_classification_tag_description_too_long(client):
    with pytest.raises(DemistoException, match="Description must be at most 80 characters"):
        create_device_classification_tag(client, {"name": "low risk", "description": "x" * 81})


def test_create_device_classification_rule(client, requests_mock):
    mock_response = util_load_json("create_device_classification_rule_response")
    requests_mock.post(f"{SERVER_URL}api/v2/deviceclassification/rules", json=mock_response)

    args = {
        "name": "low risk tag rule",
        "label": "low risk",
        "os": "windows",
        "conditions": json.dumps({"$and": [{"device_tag_check": {"tag_id": 1137}}]}),
    }
    result = create_device_classification_rule(client, args)

    assert result.outputs["ids"] == [42]
    sent_body = requests_mock.last_request.json()
    assert sent_body[0]["conditions"] == {"$and": [{"device_tag_check": {"tag_id": 1137}}]}


def test_create_device_classification_rule_empty_response_body(client, requests_mock):
    # Confirmed against the live API: a successful create returns 201 with no body at all.
    requests_mock.post(f"{SERVER_URL}api/v2/deviceclassification/rules", status_code=201, text="")

    args = {
        "name": "low risk tag rule",
        "label": "low risk",
        "os": "windows",
        "conditions": json.dumps({"$and": [{"device_tag_check": {"tag_id": 1137}}]}),
    }
    result = create_device_classification_rule(client, args)

    assert result.outputs["ids"] is None
    assert "did not return a rule ID" in result.readable_output


def test_find_device(client, requests_mock):
    mock_response = util_load_json("find_device_response")
    requests_mock.get(f"{SERVER_URL}api/v2/events/datasearch/clientstatus", json=mock_response)

    result = find_device(client, {"start_time": "1773101400", "end_time": "1773187800"})

    assert result.outputs == mock_response["result"]


def test_create_device_tag(client, requests_mock):
    mock_response = util_load_json("create_device_tag_response")
    requests_mock.post(f"{SERVER_URL}api/v2/devices/device/tags", json=mock_response)

    result = create_device_tag(client, {"name": "low risk", "description": "Devices with low risk classification"})

    assert result.outputs == mock_response["data"]


def test_list_device_tags(client, requests_mock):
    mock_response = util_load_json("list_device_tags_response")
    requests_mock.post(f"{SERVER_URL}api/v2/devices/device/tags/gettags", json=mock_response)

    result = list_device_tags(client, {"device_id": "AB2E7066-747D-8728-71F9-6163532C2BD0"})

    assert result.outputs == mock_response["data"]
    assert requests_mock.last_request.json() == {"device_id": "AB2E7066-747D-8728-71F9-6163532C2BD0"}


def test_apply_device_tags(client, requests_mock):
    mock_response = util_load_json("apply_device_tags_response")
    requests_mock.post(f"{SERVER_URL}api/v2/devices/device/tags/bulkreplace", json=mock_response)

    result = apply_device_tags(
        client,
        {"tag_id": "1137", "nsdeviceuid": "AB2E7066-747D-8728-71F9-6163532C2BD0", "hostname": "Jenga-Surface"},
    )

    assert result.outputs == [mock_response["data"]]
    sent_body = requests_mock.last_request.json()
    assert sent_body["tags"] == [1137]
    assert sent_body["devices"] == [
        {"nsdeviceuid": "AB2E7066-747D-8728-71F9-6163532C2BD0", "userkey": "AB2E7066-747D-8728-71F9-6163532C2BD0",
         "hostname": "Jenga-Surface"}
    ]


def test_apply_device_tags_too_many_tags(client):
    with pytest.raises(DemistoException, match="at most 5 tags"):
        apply_device_tags(client, {"tag_id": ["1", "2", "3", "4", "5", "6"], "nsdeviceuid": "uid-1"})


def test_apply_device_tags_no_devices(client):
    with pytest.raises(DemistoException, match="empty list of device UIDs"):
        apply_device_tags(client, {"tag_id": "1137", "nsdeviceuid": []})


def test_list_destination_profiles(client, requests_mock):
    mock_response = util_load_json("list_destination_profiles_response")
    requests_mock.get(f"{SERVER_URL}api/v2/profiles/destinations", json=mock_response)

    result = list_destination_profiles(client, {"filter": 'name co "eng"'})

    assert result.outputs == mock_response["elements"]
    assert requests_mock.last_request.qs.get("filter") == ['name co "eng"']


def test_create_destination_profile(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.post(f"{SERVER_URL}api/v2/profiles/destinations", json=mock_response)

    result = create_destination_profile(
        client, {"name": "my destination", "type": "regex", "values": ["google.com", "netskope.com"]}
    )

    assert result.outputs == mock_response
    assert requests_mock.last_request.qs.get("interactive") == ["false"]
    assert requests_mock.last_request.json()["type"] == "regex"


def test_create_destination_profile_requires_type(client):
    with pytest.raises(DemistoException, match="type is required"):
        create_destination_profile(client, {"name": "my destination", "values": ["google.com"]})


def test_create_destination_profile_name_too_long(client):
    with pytest.raises(DemistoException, match="name must be between 1 and 100"):
        create_destination_profile(client, {"name": "x" * 101, "type": "regex"})


def test_update_destination_profile_type_requires_values(client):
    with pytest.raises(DemistoException, match='the "values" argument is required'):
        update_destination_profile(client, {"id": "profile-1", "type": "insensitive"})


def test_update_destination_profile_values_append(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.patch(f"{SERVER_URL}api/v2/profiles/destinations/profile-1/values", json=mock_response)

    result = update_destination_profile_values(
        client, {"id": "profile-1", "operation": "append", "values": ["bad-sase.com", "www.good.com"]}
    )

    assert result.outputs == mock_response
    sent_body = requests_mock.last_request.json()
    assert sent_body == {"operation": {"op": "append", "values": ["bad-sase.com", "www.good.com"]}}


def test_update_destination_profile_values_remove_by_index(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.patch(f"{SERVER_URL}api/v2/profiles/destinations/profile-1/values", json=mock_response)

    update_destination_profile_values(client, {"id": "profile-1", "operation": "remove", "indexes": ["0", "10"]})

    sent_body = requests_mock.last_request.json()
    assert sent_body == {"operation": {"op": "remove", "indexes": [0, 10]}}


def test_update_network_profile_values_index_removal_not_supported(client):
    with pytest.raises(DemistoException, match="index-based removal is not supported"):
        update_network_profile_values(client, {"id": "profile-1", "operation": "remove", "indexes": ["0"]})


def test_deploy_destination_profiles(client, requests_mock):
    mock_response = util_load_json("deploy_profiles_response")
    requests_mock.post(f"{SERVER_URL}api/v2/profiles/destinations/deploy", json=mock_response)

    result = deploy_destination_profiles(
        client, {"ids": ["69c0661d-3e5d-49d6-88ee-3c1390955004"], "change_note": "add custom ftp destination"}
    )

    assert result.outputs == mock_response
    sent_body = requests_mock.last_request.json()
    assert sent_body == {"ids": ["69c0661d-3e5d-49d6-88ee-3c1390955004"], "change_note": "add custom ftp destination"}


def test_deploy_destination_profiles_too_many_ids(client):
    with pytest.raises(DemistoException, match="at most 50 profile IDs"):
        deploy_destination_profiles(client, {"ids": [str(i) for i in range(51)]})


def test_deploy_destination_profiles_requires_ids_or_all(client):
    with pytest.raises(DemistoException, match='either "ids" or "all" must be provided'):
        deploy_destination_profiles(client, {})


def test_revert_destination_profile(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.post(f"{SERVER_URL}api/v2/profiles/destinations/profile-1/revert", json=mock_response)

    result = revert_destination_profile(client, {"id": "profile-1"})

    assert result.outputs == mock_response


def test_get_destination_profile_applied_version(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.get(f"{SERVER_URL}api/v2/profiles/destinations/profile-1/versions/applied", json=mock_response)

    result = get_destination_profile_applied_version(client, {"id": "profile-1"})

    assert result.outputs == mock_response


def test_migrate_url_list_to_destination_profile(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.post(f"{SERVER_URL}api/v2/profiles/destinations/migrate", json=mock_response)

    result = migrate_url_list_to_destination_profile(client, {"url_list_id": "1234", "destination_profile_name": "URL List 1"})

    assert result.outputs == mock_response
    assert requests_mock.last_request.json() == {"url_list_id": "1234", "destination_profile_name": "URL List 1"}


def test_migrate_url_list_into_destination_profile(client, requests_mock):
    mock_response = util_load_json("create_destination_profile_response")
    requests_mock.patch(f"{SERVER_URL}api/v2/profiles/destinations/profile-1/migrate", json=mock_response)

    result = migrate_url_list_into_destination_profile(client, {"id": "profile-1", "url_list_id": "1234"})

    assert result.outputs == mock_response
    assert requests_mock.last_request.json() == {"url_list_id": "1234"}


def test_list_network_profiles(client, requests_mock):
    mock_response = util_load_json("list_network_profiles_response")
    requests_mock.get(f"{SERVER_URL}api/v2/profiles/networks", json=mock_response)

    result = list_network_profiles(client, {})

    assert result.outputs == mock_response["elements"]


def test_create_network_profile_has_no_type_field(client, requests_mock):
    mock_response = util_load_json("list_network_profiles_response")["elements"][0]
    requests_mock.post(f"{SERVER_URL}api/v2/profiles/networks", json=mock_response)

    create_network_profile(client, {"name": "my network", "values": ["192.168.0.1/24"]})

    sent_body = requests_mock.last_request.json()
    assert "type" not in sent_body


def test_delete_network_profile(client, requests_mock):
    requests_mock.delete(f"{SERVER_URL}api/v2/profiles/networks/profile-1", json={"status": "success"})

    result = delete_network_profile(client, {"id": "profile-1"})

    assert result.outputs == {"status": "success"}


def test_update_file_hash_list(client, requests_mock):
    requests_mock.post(
        f"{SERVER_URL}api/v1/updateFileHashList", json={"status": "success", "msg": "File Filter Profile updated successfully"}
    )

    expected_hash = "44d88612fea8a8f36de82e1278abb02f"
    result = update_file_hash_list(client, {"name": "TestIOCv1", "hash": expected_hash})

    assert result.outputs_prefix == "Netskope.FileHashList"
    assert result.outputs["name"] == "TestIOCv1"
    assert result.outputs["hash"] == [expected_hash]
    assert requests_mock.last_request.json() == {"name": "TestIOCv1", "list": expected_hash}
    assert requests_mock.last_request.qs["token"] == [API_V1_TOKEN]
    assert requests_mock.last_request.headers["Netskope-Api-Token"] == API_KEY


def test_update_file_hash_list_requires_api_v1_token(requests_mock):
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        proxy=False,
        headers={"Netskope-Api-Token": API_KEY},
        api_key=API_KEY,
    )
    expected_hash = "44d88612fea8a8f36de82e1278abb02f"

    with pytest.raises(DemistoException, match="API v1 Token is required"):
        update_file_hash_list(client, {"name": "TestIOCv1", "hash": expected_hash})

    assert not requests_mock.called


def test_update_file_hash_list_strips_api_v1_token(requests_mock):
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        proxy=False,
        headers={"Netskope-Api-Token": API_KEY},
        api_key=API_KEY,
        api_v1_token=f"  {API_V1_TOKEN}\n",
    )
    requests_mock.post(f"{SERVER_URL}api/v1/updateFileHashList", json={"status": "success"})

    update_file_hash_list(client, {"name": "TestIOCv1", "hash": "44d88612fea8a8f36de82e1278abb02f"})

    assert requests_mock.last_request.qs["token"] == [API_V1_TOKEN]


def test_update_file_hash_list_no_hashes(client):
    with pytest.raises(DemistoException, match="empty list of hashes"):
        update_file_hash_list(client, {"name": "TestIOCv1", "hash": []})


def test_update_file_hash_list_accepts_sha256(client, requests_mock):
    requests_mock.post(f"{SERVER_URL}api/v1/updateFileHashList", json={"status": "success"})

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = update_file_hash_list(client, {"name": "TestIOCv1", "hash": sha256})

    assert result.outputs["hash"] == [sha256]


def test_update_file_hash_list_rejects_invalid_format(client):
    with pytest.raises(DemistoException, match="only MD5 .* or SHA256 .* are accepted"):
        update_file_hash_list(client, {"name": "TestIOCv1", "hash": "not-a-real-hash"})


def test_update_file_hash_list_strips_blank_entries(client, requests_mock):
    # A leading/trailing comma (e.g. from joining an empty "existing hashes" input) should not
    # turn into a bogus blank entry that fails validation.
    requests_mock.post(f"{SERVER_URL}api/v1/updateFileHashList", json={"status": "success"})

    md5 = "44d88612fea8a8f36de82e1278abb02f"
    result = update_file_hash_list(client, {"name": "TestIOCv1", "hash": f",{md5},"})

    assert result.outputs["hash"] == [md5]


def test_update_file_hash_list_duplicate_is_treated_as_success(client, requests_mock):
    # This API returns HTTP 200 even when the update logically fails - the real status is only
    # in the response body. A "duplicate request, no change" response means the desired state
    # (these hashes being in the list) is already true, which for this idempotent operation is a
    # success, not a failure - otherwise re-running with the same hash set (e.g. after a prior
    # client-side timeout whose request actually succeeded) breaks playbooks for no real reason.
    requests_mock.post(
        f"{SERVER_URL}api/v1/updateFileHashList",
        json={
            "status": "error",
            "errorCode": "Configuration Error",
            "errors": ["Duplicate request, no change in file hashes for the file filter - TestIOCv1"],
        },
    )

    result = update_file_hash_list(client, {"name": "TestIOCv1", "hash": "44d88612fea8a8f36de82e1278abb02f"})

    assert result.outputs["name"] == "TestIOCv1"
    assert "no change needed" in result.readable_output


def test_update_file_hash_list_other_api_error_still_raises(client, requests_mock):
    # A genuinely different error (not the duplicate/no-op case) must still raise.
    requests_mock.post(
        f"{SERVER_URL}api/v1/updateFileHashList",
        json={
            "status": "error",
            "errorCode": "Configuration Error",
            "errors": ["Please use right request to query"],
        },
    )

    with pytest.raises(DemistoException, match="Please use right request to query"):
        update_file_hash_list(client, {"name": "TestIOCv1", "hash": "44d88612fea8a8f36de82e1278abb02f"})


def test_list_private_apps(client, requests_mock):
    mock_response = util_load_json("list_private_apps_response")
    requests_mock.get(f"{SERVER_URL}api/v2/steering/apps/private", json=mock_response)

    result = list_private_apps(client, {})

    assert result.outputs == mock_response["data"]["private_apps"]
    assert result.outputs_prefix == "Netskope.PrivateApp"


def test_list_publishers(client, requests_mock):
    mock_response = util_load_json("list_publishers_response")
    requests_mock.get(f"{SERVER_URL}api/v2/infrastructure/publishers", json=mock_response)

    result = list_publishers(client, {})

    assert result.outputs == mock_response["data"]["publishers"]
    assert result.outputs_prefix == "Netskope.Publisher"
    assert requests_mock.last_request.qs.get("fields") is None


def test_list_publishers_with_fields(client, requests_mock):
    mock_response = util_load_json("list_publishers_response")
    requests_mock.get(f"{SERVER_URL}api/v2/infrastructure/publishers", json=mock_response)

    list_publishers(client, {"fields": "publisher_id,publisher_name"})

    assert requests_mock.last_request.qs.get("fields") == ["publisher_id,publisher_name"]


def test_create_private_app(client, requests_mock):
    mock_response = util_load_json("create_private_app_response")
    requests_mock.post(f"{SERVER_URL}api/v2/steering/apps/private", json=mock_response)

    result = create_private_app(
        client,
        {
            "app_name": "quarantine",
            "host": "172.31.34.6",
            "protocols": json.dumps([{"type": "tcp", "port": "443"}]),
            "publishers": json.dumps([{"publisher_id": "15", "publisher_name": "AWS-NPA"}]),
            "tags": "quarantine",
            "clientless_access": "true",
        },
    )

    assert result.outputs == mock_response["data"]
    sent_body = requests_mock.last_request.json()
    assert sent_body["protocols"] == [{"type": "tcp", "port": "443"}]
    assert sent_body["publishers"] == [{"publisher_id": "15", "publisher_name": "AWS-NPA"}]
    assert sent_body["tags"] == [{"tag_name": "quarantine"}]
    assert sent_body["clientless_access"] is True


def test_create_private_app_invalid_protocols_json(client):
    with pytest.raises(DemistoException, match="must be valid JSON"):
        create_private_app(
            client,
            {
                "app_name": "quarantine",
                "host": "172.31.34.6",
                "protocols": "not json",
                "publishers": json.dumps([{"publisher_id": "15"}]),
            },
        )


def test_create_private_app_rejects_bare_json_scalar_protocols(client):
    # A bare number is valid JSON on its own (json.loads("443") == 443) - confirmed against the
    # live API that this silently creates nothing rather than erroring, so it must be rejected
    # client-side instead of just checking "is it valid JSON at all".
    with pytest.raises(DemistoException, match='"protocols" argument must be a JSON array of objects'):
        create_private_app(
            client,
            {
                "app_name": "quarantine",
                "host": "172.31.34.6",
                "protocols": "443",
                "publishers": json.dumps([{"publisher_id": "15"}]),
            },
        )


def test_update_private_app(client, requests_mock):
    mock_response = util_load_json("update_private_app_response")
    requests_mock.patch(f"{SERVER_URL}api/v2/steering/apps/private/3", json=mock_response)

    result = update_private_app(client, {"app_id": "3", "host": "172.31.34.6"})

    assert result.outputs == mock_response["data"]
    assert requests_mock.last_request.json() == {"host": "172.31.34.6"}


def test_update_private_app_requires_at_least_one_field(client):
    with pytest.raises(DemistoException, match="at least one field"):
        update_private_app(client, {"app_id": "3"})


def test_update_private_app_empty_string_protocols_and_publishers_are_ignored(client, requests_mock):
    # Playbooks commonly pass an explicit "" for an unfilled optional argument rather than
    # omitting it - this must not be treated as invalid JSON.
    mock_response = util_load_json("update_private_app_response")
    requests_mock.patch(f"{SERVER_URL}api/v2/steering/apps/private/3", json=mock_response)

    result = update_private_app(client, {"app_id": "3", "host": "172.31.34.6", "protocols": "", "publishers": ""})

    assert result.outputs == mock_response["data"]
    assert requests_mock.last_request.json() == {"host": "172.31.34.6"}


def test_replace_private_app(client, requests_mock):
    mock_response = util_load_json("update_private_app_response")
    requests_mock.put(f"{SERVER_URL}api/v2/steering/apps/private/3", json=mock_response)

    result = replace_private_app(
        client,
        {
            "app_id": "3",
            "host": "172.31.34.6",
            "protocols": json.dumps([{"type": "tcp", "port": "443"}]),
            "publishers": json.dumps([{"publisher_id": "15", "publisher_name": "AWS-NPA"}]),
        },
    )

    assert result.outputs == mock_response["data"]
    assert requests_mock.last_request.json() == {
        "host": "172.31.34.6",
        "protocols": [{"type": "tcp", "port": "443"}],
        "publishers": [{"publisher_id": "15", "publisher_name": "AWS-NPA"}],
    }


def test_replace_private_app_requires_app_id(client):
    with pytest.raises(DemistoException, match="app_id is required"):
        replace_private_app(client, {"host": "172.31.34.6", "protocols": "[]", "publishers": "[]"})


def test_replace_private_app_requires_host(client):
    with pytest.raises(DemistoException, match="host is required"):
        replace_private_app(client, {"app_id": "3", "protocols": "[]", "publishers": "[]"})


def test_replace_private_app_requires_protocols_and_publishers(client):
    with pytest.raises(DemistoException, match='the "protocols" argument is required'):
        replace_private_app(client, {"app_id": "3", "host": "172.31.34.6"})


def test_update_private_app_tags(client, requests_mock):
    # Confirmed against the live API: "data" is the list of full app objects directly.
    mock_response = util_load_json("update_private_app_tags_response")
    requests_mock.put(f"{SERVER_URL}api/v2/steering/apps/private/tags", json=mock_response)

    result = update_private_app_tags(client, {"app_id": "3", "tags": "quarantine"})

    assert result.outputs == mock_response["data"]
    assert requests_mock.last_request.json() == {"ids": [3], "tags": [{"tag_name": "quarantine"}]}


def test_update_private_app_tags_nested_private_apps_shape(client, requests_mock):
    # The reference doc's example response nests the list under "private_apps" instead - support
    # both shapes defensively.
    mock_response = {
        "data": {"private_apps": [{"app_id": 3, "app_name": "[quarantine]", "tags": [{"tag_id": 3, "tag_name": "quarantine"}]}]},
        "status": "success",
    }
    requests_mock.put(f"{SERVER_URL}api/v2/steering/apps/private/tags", json=mock_response)

    result = update_private_app_tags(client, {"app_id": "3", "tags": "quarantine"})

    assert result.outputs == mock_response["data"]["private_apps"]


def test_delete_private_app(client, requests_mock):
    requests_mock.delete(f"{SERVER_URL}api/v2/steering/apps/private/3", json={"data": {"app_id": 3}, "status": "success"})

    result = delete_private_app(client, {"app_id": "3"})

    assert result.outputs == {"app_id": 3}


def test_submit_file_scan(client, requests_mock, tmp_path):
    mock_response = util_load_json("submit_file_scan_response")
    requests_mock.post(f"{SERVER_URL}api/v2/atp/scans/filescan", json=mock_response)

    zip_path = tmp_path / "sample.zip"
    zip_path.write_bytes(b"fake zip content")

    with patch("NetskopeV2.demisto.getFilePath", return_value={"path": str(zip_path), "name": "sample.zip"}):
        result = submit_file_scan(client, {"entry_id": "123@abc"})

    assert result.outputs_prefix == "Netskope.FileScan"
    assert result.outputs["jobid"] == mock_response["jobid"]
    assert result.outputs["status"] == "Ok"
    assert requests_mock.last_request.qs.get("scantype") == ["sandbox"]


def test_submit_file_scan_requires_entry_id(client):
    with pytest.raises(DemistoException, match="entry_id is required"):
        submit_file_scan(client, {})


def test_submit_file_scan_rejects_unsupported_extension(client, tmp_path):
    txt_path = tmp_path / "sample.txt"
    txt_path.write_bytes(b"fake text content")

    with (
        patch("NetskopeV2.demisto.getFilePath", return_value={"path": str(txt_path), "name": "sample.txt"}),
        pytest.raises(DemistoException, match='Unsupported file type ".txt"'),
    ):
        submit_file_scan(client, {"entry_id": "123@abc"})


def test_submit_file_scan_accepts_all_documented_extensions(client, requests_mock, tmp_path):
    mock_response = util_load_json("submit_file_scan_response")
    requests_mock.post(f"{SERVER_URL}api/v2/atp/scans/filescan", json=mock_response)

    for ext in ("zip", "exe", "pdf", "doc", "xls", "ppt", "rtf"):
        file_path = tmp_path / f"sample.{ext}"
        file_path.write_bytes(b"fake content")
        with patch("NetskopeV2.demisto.getFilePath", return_value={"path": str(file_path), "name": f"sample.{ext}"}):
            result = submit_file_scan(client, {"entry_id": "123@abc"})
        assert result.outputs["jobid"] == mock_response["jobid"]


def test_get_scan_report_ready(client, requests_mock):
    mock_response = util_load_json("get_scan_report_response")
    requests_mock.get(f"{SERVER_URL}api/v2/atp/scans/reports/8ffdffbdbe1efccb32edfaca", json=mock_response)

    result = get_scan_report(client, {"jobid": "8ffdffbdbe1efccb32edfaca"})

    assert result.outputs == mock_response
    assert result.outputs["verdict"] == "malicious"


def test_get_scan_report_in_progress(client, requests_mock):
    mock_response = util_load_json("get_scan_report_in_progress_response")
    requests_mock.get(
        f"{SERVER_URL}api/v2/atp/scans/reports/8ffdffbdbe1efccb32edfaca", json=mock_response, status_code=202
    )

    result = get_scan_report(client, {"jobid": "8ffdffbdbe1efccb32edfaca"})

    assert result.outputs["status"] == "InProgress"


def test_get_scan_report_requires_jobid(client):
    with pytest.raises(DemistoException, match="jobid is required"):
        get_scan_report(client, {})


def test_url_lookup(client, requests_mock):
    mock_response = util_load_json("url_lookup_response")
    requests_mock.post(f"{SERVER_URL}api/v2/nsiq/urllookup", json=mock_response)

    result = url_lookup(client, {"urls": "https://www.netskope.com,https://www.google.com"})

    assert result.outputs_prefix == "Netskope.URLLookup"
    assert result.outputs == mock_response["result"]
    assert requests_mock.last_request.json() == {
        "query": {"urls": ["https://www.netskope.com", "https://www.google.com"]}
    }


def test_url_lookup_passes_optional_args(client, requests_mock):
    mock_response = util_load_json("url_lookup_response")
    requests_mock.post(f"{SERVER_URL}api/v2/nsiq/urllookup", json=mock_response)

    url_lookup(client, {"urls": "https://www.netskope.com", "disable_dns_lookup": "true", "category": "swg"})

    assert requests_mock.last_request.json() == {
        "query": {"urls": ["https://www.netskope.com"], "disable_dns_lookup": True, "category": "swg"}
    }


def test_url_lookup_requires_urls(client):
    with pytest.raises(DemistoException, match="urls must not be empty"):
        url_lookup(client, {})


def test_url_lookup_rejects_too_many_urls(client):
    urls = ",".join(f"https://example{i}.com" for i in range(101))
    with pytest.raises(DemistoException, match="at most 100 urls are allowed per call, got 101"):
        url_lookup(client, {"urls": urls})


def test_url_lookup_rejects_invalid_category(client):
    with pytest.raises(DemistoException, match='category must be one of'):
        url_lookup(client, {"urls": "https://www.netskope.com", "category": "invalid"})
