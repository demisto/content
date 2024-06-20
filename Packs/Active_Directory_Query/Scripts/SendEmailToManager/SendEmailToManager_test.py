import re

import pytest

from SendEmailToManager import *


def executeCommand_mock(command: str, args: dict) -> list:
    with open("test_data/ad-search.json") as file:
        test_data = json.load(file)

    if command == "ad-search":
        if (re.match(r"\(&\(objectClass=user\)\(mail=[\w@.]+\)\)$", args.get("filter"))) \
                and args.get("attributes") == "displayName,manager":
            return [test_data[0]]
        elif (re.match(r"\(&\(objectClass=User\)\(distinguishedName=.+\)\)$", args.get("filter"))) \
                and args.get("attributes") == "displayName,mail":
            return [test_data[1]]

    return []


@pytest.mark.parametrize("test_input_path, expected_items_in_dict", [
    ("test_data/incident.json", {"employee_email": "employee_email", "incident_subject": "incident_subject",
                                 "employee_request": "employee_request"}),
])
def test_find_additional_incident_info(test_input_path: str, expected_items_in_dict: dict):
    with open(test_input_path) as file:
        test_input = json.load(file)

    additional_info = find_additional_incident_info(test_input)

    for key, value in expected_items_in_dict.items():
        assert value == additional_info[key]


@pytest.mark.parametrize("email, manager_attribute, expected_result", [
    ("user@test.local", "manager", {
        "manager_dn": "CN=Sample Manager,CN=Users,DC=example_dc,DC=local",
        "employee_name": "Sample User",
        "manager_email": "manager@test.local",
        "manager_name": "Sample Manager"
    }),
])
def test_find_additional_ad_info(mocker, email: str, manager_attribute: str, expected_result: dict):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_mock)
    result = find_additional_ad_info(email, manager_attribute)

    assert result == expected_result


@pytest.mark.parametrize("test_input_path, incident_subject, investigation_id, allow_reply, entitlement_id", [
    ("test_data/addentitlement.json", "test_subject", "1", False, None),
    ("test_data/addentitlement.json", "test_subject", "2", True, "9b1b7a14-0c88-432f-8b8f-96b21fcb058e"),

])
def test_generate_mail_subject(mocker, test_input_path: str, incident_subject: str,
                               investigation_id: str, allow_reply: bool, entitlement_id: Optional[str]):
    with open(test_input_path) as file:
        example_entitlement = json.load(file)

    mocker.patch.object(demisto, 'executeCommand', return_value=example_entitlement)

    expected_result = f"{incident_subject} - #{investigation_id}"

    if allow_reply:
        assert entitlement_id is not None
        expected_result += f" {entitlement_id}"

    assert generate_mail_subject(incident_subject=incident_subject, investigation_id=investigation_id,
                                 allow_reply=allow_reply) == expected_result


@pytest.mark.parametrize("manager_name, employee_name, employee_request", [
    ("test_manager", "test_employee", "test_employee_request"),

])
def test_generate_mail_body(manager_name: str, employee_name: str, employee_request: str):
    returned_body = generate_mail_body(
        manager_name=manager_name,
        employee_name=employee_name,
        employee_request=employee_request)

    for item in (manager_name, employee_name, employee_request):
        assert item in returned_body
