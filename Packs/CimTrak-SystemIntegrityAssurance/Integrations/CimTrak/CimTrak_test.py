"""CimTrak Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the CimTrak Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""
from CimTrak import Client
import CimTrak
from typing import Any
import pytest
import json


def util_load_json(path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(
        base_url='https://test.com/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )


def test_add_hash_allow_list(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/add_hash_allow_list.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.add_hash_allow_list_command(client, {
        'hash': 'SHA256:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_add_hash_deny_list(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/add_hash_deny_list.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.add_hash_deny_list_command(client, {
        'hash': 'SHA256:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_add_ticket(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/add_ticket.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.add_ticket_command(client, {'title': 'test', 'priority': 1, 'autoPromote': 'False',
                                                       'requiresAcknowledgement': 'False', 'requiresAssessment': 'False',
                                                       'requiresConfirmation': 'False', 'assignedToUserId': '0',
                                                       'assignedToGroupId': '0'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_add_ticket_comment(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/add_ticket_comment.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.add_ticket_comment_command(client, {'ticketId': '6', 'comment': 'test'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_check_file_against_trusted_file_registry_by_hash(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/check_file_against_trusted_file_registry_by_hash.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.check_file_against_trusted_file_registry_by_hash_command(client, {
        'Hashes': 'B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_compliance_scan_children(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/compliance_scan_children.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.compliance_scan_children_command(client, {'objectParentId': 1})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_compliance_scan_with_summary(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/compliance_scan_with_summary.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.compliance_scan_with_summary_command(client, {'objectId': 1, 'retryCount': 20, 'retrySeconds': 10})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_delete_hash_allow_list(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/delete_hash_allow_list.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.delete_hash_allow_list_command(client, {
        'hash': 'SHA256:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_delete_hash_deny_list(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/delete_hash_deny_list.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.delete_hash_deny_list_command(client, {
        'hash': 'SHA256:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_demote_authoritative_baseline_files(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/demote_authoritative_baseline_files.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.demote_authoritative_baseline_files_command(client, {'ObjectDetaildIds': '42'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_deploy(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/deploy.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.deploy_command(client, {'agentObjectId': 2, 'subGenerationId': 1})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_deploy_by_date(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/deploy_by_date.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.deploy_by_date_command(client, {'date': '2021-12-20 15:08:29', 'objectId': '2'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_test_fetch_incidents(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/fetch_incidents.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    last_run = {'last_fetch': 1}
    _, response_raw = CimTrak.fetch_incidents(client=client, max_results=2, last_run=last_run, alert_status='ACTIVE',
                                              min_severity='Low', alert_type=None, first_fetch_time=None)
    response_raw[0]['rawJSON'] = json.loads(response_raw[0]['rawJSON'])
    response = response_raw[0]
    assert response == test_json_data["response"]


def test_file_analysis_by_hash(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/file_analysis_by_hash.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.file_analysis_by_hash_command(client, {
        'Hash': 'SHA256:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_file_analysis_by_object_detail_id(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/file_analysis_by_object_detail_id.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.file_analysis_by_object_detail_id_command(client, {'ObjectDetailId': 42})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_force_sync(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/force_sync.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.force_sync_command(client, {'objectId': 2})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_get_agent_info(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_agent_info.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_agent_info_command(client, {'ObjectId': '2'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_agent_object_by_alternate_id(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_agent_object_by_alternate_id.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_agent_object_by_alternate_id_command(client, {'alternateSystemId': 'test'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_agent_object_by_ip(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_agent_object_by_ip.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_agent_object_by_ip_command(client, {'ip': '127.0.0.1'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_agent_object_by_name(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_agent_object_by_name.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_agent_object_by_name_command(client, {'agentName': 'local'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_agent_object_id_by_alternate_system_id(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_agent_object_id_by_alternate_system_id.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_agent_object_id_by_alternate_system_id_command(client, {'alternateSystemId': 'test'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_compliance_archive_details(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_compliance_archive_details.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_compliance_archive_details_command(client,
                                                                  {'Start': 1, 'End': 1, 'ObjectId': 1, 'ComplianceScanId': -1})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_compliance_archive_summary(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_compliance_archive_summary.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_compliance_archive_summary_command(client,
                                                                  {'Start': 1, 'End': 1, 'ObjectId': 1, 'ComplianceScanId': -1})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_current_compliance_items(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_current_compliance_items.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_current_compliance_items_command(client, {'ObjectId': '2', 'ComplianceScanId': '-1'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_events(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_events.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_events_command(client, {'Start': 1, 'End': 1})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_object(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_object.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_object_command(client, {'objectId': 2})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_object_group(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_object_group.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_object_group_command(client, {'objectId': 2})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_objects(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_objects.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_objects_command(client,
                                               {'ObjectId': '2', 'ObjectType': '-1', 'ObjectSubType': '-1', 'ParentId': '-1',
                                                'Recursive': 'false'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_sub_generations(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_sub_generations.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_sub_generations_command(client, {'objectId': 2})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_ticket_tasks(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_ticket_tasks.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_ticket_tasks_command(client, {})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_get_tickets(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/get_tickets.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.get_tickets_command(client, {})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_lock(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/lock.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.lock_command(client, {'objectId': 2})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_promote_authoritative_baseline_files(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/promote_authoritative_baseline_files.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.promote_authoritative_baseline_files_command(client, {'ObjectDetaildIds': '42'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_run_report_by_name(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/run_report_by_name.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.run_report_by_name_command(client, {'Name': 'Active Directory Users', 'objectId': '0'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_unlock(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/unlock.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.unlock_command(client, {'objectId': 2})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_update_task_disposition(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/update_task_disposition.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.update_task_disposition_command(client, {'taskId': 2, 'Disposition': 'REJECTED'})
    response = response_raw[0].outputs

    assert response == test_json_data["response"]


def test_update_ticket(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/update_ticket.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.update_ticket_command(client, {'ticketId': '6', 'title': 'test', 'priority': 1, 'autoPromote': 'False',
                                                          'requiresAcknowledgement': 'False', 'requiresAssessment': 'False',
                                                          'requiresConfirmation': 'False', 'assignedToUserId': '0',
                                                          'assignedToGroupId': '0'})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]


def test_view_file(client: Client, requests_mock):
    test_json_data = util_load_json("test_data/view_file.json")
    for post in test_json_data["posts"]:
        requests_mock.post(post["url"], json=post["reply"])

    response_raw = CimTrak.view_file_command(client, {'objectDetailId': 2})
    response = response_raw[0].outputs
    ret_results: list[dict[str, Any]] = response_raw[1].outputs
    response['results'] = list()
    response['results'].append(ret_results)
    assert response == test_json_data["response"]
