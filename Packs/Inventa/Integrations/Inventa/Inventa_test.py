"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from pytest import raises
# from __future__ import print_function
from Inventa import main, Client, format_pii_entities, generate_datasubject_payload, validate_incident_inputs_command
# import pytest
import demistomock as demisto
# from CommonServerPython import entryTypes

constraints_cmds = [
    "inventa-get-datasubjects",
    "inventa-get-datasubject-id"
]

ticket_cmds = [
    "inventa-get-datasubject-details",
    "inventa-get-dsar-piis",
    "inventa-get-dsar-transactions",
    "inventa-get-dsar-files",
    "inventa-get-dsar-databases",
    "inventa-get-dsar-dataassets",
    "inventa-get-datasubject-id-from-ticket"
]

reason_cmds = [
    "inventa-create-ticket"
]

noarg_cmds = [
    "inventa-get-entities"
]

mock_arguments_constraints = {
    "national_id": "TEST_NATIONAL_ID",
    "passport_number": "TEST_PASSPORT_NUMBER",
    "driver_license": "TEST_DRIVER_LICENSE",
    "tax_id": "TEST_TAX_ID",
    "cc_number": "TEST_CC_NUMBER",
    "given_name": "TEST_GIVEN_NAME",
    "surname": "TEST_SURNAME",
    "full_name": "TEST_FULL_NAME",
    "vehicle_number": "TEST_VEHICLE_NUMBER",
    "phone_number": "TEST_PHONE_NUMBER",
    "birthday": "TEST_BIRTHDAY",
    "city": "TEST_CITY",
    "street_address": "TEST_STREET_ADDRESS"
}
mock_arguments_constraints_fail = {
    "given_name": "TEST_GIVEN_NAME",
    "surname": "TEST_SURNAME"
}
mock_arguments_ticket = {
    "ticket_id": "TEST_TICKET_ID"
}

mock_arguments_reason_dsid = {
    "reason": "TEST_REASON",
    "datasubject_id": "TEST_DATASUBJECT_ID"
}

mock_demisto_params = {
    "url": "--TEST URL--",
    "apikey": "---TEST_API_KEY---",
    "insecure": "True"
}


def mock_params():
    return mock_demisto_params


def mock_args(command_name):
    if command_name in constraints_cmds:
        return mock_arguments_constraints
    if command_name in reason_cmds:
        return mock_arguments_reason_dsid
    if command_name in ticket_cmds:
        return mock_arguments_ticket
    if command_name in noarg_cmds:
        return {}
    raise ValueError('Unimplemented command called: {}'.format(command_name))


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


mock_data = util_load_json("test_data/test_commands.json")
mock_response = util_load_json("test_data/test_client.json")

client_get_entities_mock_data = mock_response.get("get_entities", "")
client_get_datasubject_mock_data = mock_response.get("get_datasubject", "")
client_prepare_ticket_mock_data = mock_response.get("prepare_ticket", "")
client_create_ticket_mock_data = mock_response.get("create_ticket", "")
client_get_ticket_mock_data = mock_response.get("get_ticket", "")
client_get_dsar_mock_data = mock_response.get("get_dsar", "")

get_entities_cmd_mock_data = mock_data.get("inventa-get-entities", "")
get_datasubjects_cmd_mock_data = mock_data.get("inventa-get-datasubjects", "")
get_datasubject_id_cmd_mock_data = mock_data.get("inventa-get-datasubject-id", "")
create_ticket_cmd_mock_data = mock_data.get("inventa-create-ticket", "")
get_datasubjectid_from_ticket_cmd_mock_data = mock_data.get("inventa-get-datasubject-id-from-ticket", "")
get_datasubject_details_cmd_mock_data = mock_data.get("inventa-get-datasubject-details", "")
get_dsar_piis_cmd_mock_data = mock_data.get("inventa-get-dsar-piis", "")
get_dsar_files_cmd_mock_data = mock_data.get("inventa-get-dsar-files", "")
get_dsar_databases_cmd_mock_data = mock_data.get("inventa-get-dsar-databases", "")
get_dsar_transactions_cmd_mock_data = mock_data.get("inventa-get-dsar-transactions", "")
get_dsar_dataassets_cmd_mock_data = mock_data.get("inventa-get-dsar-dataassets", "")


def executeCommand(command, args=None):
    return mock_data.get(command, "")


def executeClient(method, args=None):
    return mock_response.get(method, "")


def mocker_automate(mocker, command_name, method_names):
    mocker.patch.object(demisto, "params", return_value=mock_params())
    mocker.patch.object(demisto, "args", return_value=mock_args(command_name))
    mocker.patch.object(demisto, "command", return_value=command_name)
    mocker.patch.object(demisto, 'results')
    for method_name in method_names:
        mocker.patch.object(Client, method_name, return_value=executeClient(method_name))


def test_get_entities_cmd(mocker):
    command_name = 'inventa-get-entities'
    method_name = 'get_entities'

    mocker_automate(mocker, command_name, [method_name])

    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_datasubjects_cmd(mocker):
    command_name = 'inventa-get-datasubjects'
    method_name = 'get_datasubject'

    mocker_automate(mocker, command_name, [method_name])

    NATIONAL_ID = demisto.args().get("national_id", "")
    PASSPORT_NUMBER = demisto.args().get("passport_number", "")
    DRIVER_LICENSE = demisto.args().get("driver_license", "")
    TAX_ID = demisto.args().get("tax_id", "")
    CC_NUMBER = demisto.args().get("cc_number", "")
    GIVEN_NAME = demisto.args().get("given_name", "")
    SURNAME = demisto.args().get("surname", "")
    FULL_NAME = demisto.args().get("full_name", "")
    VEHICLE_NUMBER = demisto.args().get("vehicle_number", "")
    PHONE_NUMBER = demisto.args().get("phone_number", "")
    BIRTHDAY = demisto.args().get("birthday", "")
    CITY = demisto.args().get("city", "")
    STREET_ADDRESS = demisto.args().get("street_address", "")

    # test presence of constraints
    constraints = [
        NATIONAL_ID,
        PASSPORT_NUMBER,
        DRIVER_LICENSE,
        TAX_ID,
        CC_NUMBER,
        (GIVEN_NAME and VEHICLE_NUMBER),
        (GIVEN_NAME and PHONE_NUMBER),
        (GIVEN_NAME and SURNAME and BIRTHDAY),
        (GIVEN_NAME and SURNAME and CITY and STREET_ADDRESS),
        (FULL_NAME and BIRTHDAY),
        (FULL_NAME and CITY and STREET_ADDRESS)
    ]

    constraint_passed = False
    for constraint in constraints:
        if constraint:
            constraint_passed = True
            break

    assert constraint_passed

    # test passed values
    assert (NATIONAL_ID == "TEST_NATIONAL_ID")
    assert (PASSPORT_NUMBER == "TEST_PASSPORT_NUMBER")
    assert (DRIVER_LICENSE == "TEST_DRIVER_LICENSE")
    assert (TAX_ID == "TEST_TAX_ID")
    assert (CC_NUMBER == "TEST_CC_NUMBER")
    assert (GIVEN_NAME == "TEST_GIVEN_NAME")
    assert (SURNAME == "TEST_SURNAME")
    assert (FULL_NAME == "TEST_FULL_NAME")
    assert (VEHICLE_NUMBER == "TEST_VEHICLE_NUMBER")
    assert (PHONE_NUMBER == "TEST_PHONE_NUMBER")
    assert (BIRTHDAY == "TEST_BIRTHDAY")
    assert (CITY == "TEST_CITY")
    assert (STREET_ADDRESS == "TEST_STREET_ADDRESS")

    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_datasubject_id_cmd(mocker):
    command_name = 'inventa-get-datasubject-id'
    method_name = "get_datasubject"

    mocker_automate(mocker, command_name, [method_name])

    NATIONAL_ID = demisto.args().get("national_id", "")
    PASSPORT_NUMBER = demisto.args().get("passport_number", "")
    DRIVER_LICENSE = demisto.args().get("driver_license", "")
    TAX_ID = demisto.args().get("tax_id", "")
    CC_NUMBER = demisto.args().get("cc_number", "")
    GIVEN_NAME = demisto.args().get("given_name", "")
    SURNAME = demisto.args().get("surname", "")
    FULL_NAME = demisto.args().get("full_name", "")
    VEHICLE_NUMBER = demisto.args().get("vehicle_number", "")
    PHONE_NUMBER = demisto.args().get("phone_number", "")
    BIRTHDAY = demisto.args().get("birthday", "")
    CITY = demisto.args().get("city", "")
    STREET_ADDRESS = demisto.args().get("street_address", "")

    # test presence of constraints
    constraints = [
        NATIONAL_ID,
        PASSPORT_NUMBER,
        DRIVER_LICENSE,
        TAX_ID,
        CC_NUMBER,
        (GIVEN_NAME and VEHICLE_NUMBER),
        (GIVEN_NAME and PHONE_NUMBER),
        (GIVEN_NAME and SURNAME and BIRTHDAY),
        (GIVEN_NAME and SURNAME and CITY and STREET_ADDRESS),
        (FULL_NAME and BIRTHDAY),
        (FULL_NAME and CITY and STREET_ADDRESS)
    ]

    constraint_passed = False
    for constraint in constraints:
        if constraint:
            constraint_passed = True
            break

    assert constraint_passed

    # test passed values
    assert (NATIONAL_ID == "TEST_NATIONAL_ID")
    assert (PASSPORT_NUMBER == "TEST_PASSPORT_NUMBER")
    assert (DRIVER_LICENSE == "TEST_DRIVER_LICENSE")
    assert (TAX_ID == "TEST_TAX_ID")
    assert (CC_NUMBER == "TEST_CC_NUMBER")
    assert (GIVEN_NAME == "TEST_GIVEN_NAME")
    assert (SURNAME == "TEST_SURNAME")
    assert (FULL_NAME == "TEST_FULL_NAME")
    assert (VEHICLE_NUMBER == "TEST_VEHICLE_NUMBER")
    assert (PHONE_NUMBER == "TEST_PHONE_NUMBER")
    assert (BIRTHDAY == "TEST_BIRTHDAY")
    assert (CITY == "TEST_CITY")
    assert (STREET_ADDRESS == "TEST_STREET_ADDRESS")

    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_create_ticket_cmd(mocker):
    command_name = 'inventa-create-ticket'
    method_name_1 = "prepare_ticket"
    method_name_2 = "create_ticket"

    mocker_automate(mocker, command_name, [method_name_1, method_name_2])

    assert demisto.args()["datasubject_id"] == "TEST_DATASUBJECT_ID"
    assert demisto.args()["reason"] == "TEST_REASON"

    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_datasubject_details_cmd(mocker):
    command_name = 'inventa-get-datasubject-details'
    method_name = "get_ticket"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_datasubjectid_from_ticket_cmd(mocker):
    command_name = 'inventa-get-datasubject-id-from-ticket'
    method_name = 'get_ticket'

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_dsar_piis_cmd(mocker):
    command_name = 'inventa-get-dsar-piis'
    method_name = "get_dsar"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    piis_1 = []
    piis_2 = []
    piis_1.extend(results[0]["Contents"]["piis"])
    piis_2.extend(mock_data.get(command_name, "")["piis"])
    piis_1.sort()
    piis_2.sort()
    assert piis_1 == piis_2


def test_get_dsar_files_cmd(mocker):
    command_name = 'inventa-get-dsar-files'
    method_name = "get_dsar"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]

    files_1 = results[0]["Contents"]["files"]
    files_2 = mock_data.get(command_name, "")["files"]

    files_1.sort(key=lambda x: x["id"])
    files_2.sort(key=lambda x: x["id"])

    assert len(files_1) == len(files_2)

    for index in range(0, len(files_1)):
        file_1 = files_1[index]
        file_2 = files_2[index]
        entity_types_1 = file_1["entityTypes"]
        entity_types_2 = file_2["entityTypes"]
        entity_types_1 = set(entity_types_1.split(", "))
        entity_types_2 = set(entity_types_2.split(", "))

        assert entity_types_1 == entity_types_2
        assert file_1["id"] == file_2["id"]
        assert file_1["name"] == file_2["name"]
        assert file_1["path"] == file_2["path"]
        assert file_1["size"] == file_2["size"]
        assert file_1["timestamp"] == file_2["timestamp"]
        assert file_1["url"] == file_2["url"]


def test_get_dsar_transactions_cmd(mocker):
    command_name = 'inventa-get-dsar-transactions'
    method_name = "get_dsar"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert results[0]["Contents"] == mock_data.get(command_name, "")


def test_get_dsar_databases_cmd(mocker):
    command_name = 'inventa-get-dsar-databases'
    method_name = "get_dsar"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]

    databases_1 = results[0]["Contents"]["databases"]
    databases_2 = mock_data.get(command_name, "")["databases"]

    databases_1.sort(key=lambda x: f"{x['database']}.{x['name']}")
    databases_2.sort(key=lambda x: f"{x['database']}.{x['name']}")

    assert len(databases_1) == len(databases_2)

    for index in range(0, len(databases_1)):
        db_1 = databases_1[index]
        db_2 = databases_2[index]
        assert db_1["id"] == db_2["id"]
        assert db_1["name"] == db_2["name"]
        assert db_1["database"] == db_2["database"]
        entity_types_1 = db_1["entityTypes"]
        entity_types_2 = db_2["entityTypes"]
        entity_types_1 = set(entity_types_1.split(", "))
        entity_types_2 = set(entity_types_2.split(", "))
        assert entity_types_1 == entity_types_2


def test_get_dsar_dataassets_cmd(mocker):
    command_name = 'inventa-get-dsar-dataassets'
    method_name = "get_dsar"

    mocker_automate(mocker, command_name, [method_name])

    assert demisto.args()["ticket_id"] == "TEST_TICKET_ID"
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]

    dataassets_1 = results[0]["Contents"]["dataAssets"]
    dataassets_2 = mock_data.get(command_name, "")["dataAssets"]

    dataassets_1.sort(key=lambda x: x["id"])
    dataassets_2.sort(key=lambda x: x["id"])

    assert len(dataassets_1) == len(dataassets_2)

    for index in range(0, len(dataassets_1)):
        dataasset_1 = dataassets_1[index]
        dataasset_2 = dataassets_2[index]
        piis_1 = dataasset_1["piis"]
        piis_2 = dataasset_2["piis"]
        piis_1 = set(piis_1.split(", "))
        piis_2 = set(piis_2.split(", "))
        reasons_1 = dataasset_1["reasonsOfProcessing"]
        reasons_2 = dataasset_2["reasonsOfProcessing"]
        reasons_1 = set(reasons_1.split(", "))
        reasons_2 = set(reasons_2.split(", "))

        assert piis_1 == piis_2
        assert dataasset_1["id"] == dataasset_2["id"]
        assert dataasset_1["name"] == dataasset_2["name"]
        assert dataasset_1["description"] == dataasset_2["description"]
        assert reasons_1 == reasons_2


def test_validate_incident_inputs_cmd(mocker):
    command_name = 'inventa-get-dsar-dataassets'
    mocker_automate(mocker, command_name, [])

    NATIONAL_ID = demisto.args().get("national_id", "")
    PASSPORT_NUMBER = demisto.args().get("passport_number", "")
    DRIVER_LICENSE = demisto.args().get("driver_license", "")
    TAX_ID = demisto.args().get("tax_id", "")
    CC_NUMBER = demisto.args().get("cc_number", "")
    GIVEN_NAME = demisto.args().get("given_name", "")
    SURNAME = demisto.args().get("surname", "")
    FULL_NAME = demisto.args().get("full_name", "")
    VEHICLE_NUMBER = demisto.args().get("vehicle_number", "")
    PHONE_NUMBER = demisto.args().get("phone_number", "")
    BIRTHDAY = demisto.args().get("birthday", "")
    CITY = demisto.args().get("city", "")
    STREET_ADDRESS = demisto.args().get("street_address", "")
    TICKET_ID = demisto.args().get("ticket_id", "")
    DATASUBJECT_ID = demisto.args().get("datasubject_id", "")

    # test presence of constraints
    constraints = [
        TICKET_ID,
        DATASUBJECT_ID,
        NATIONAL_ID,
        PASSPORT_NUMBER,
        DRIVER_LICENSE,
        TAX_ID,
        CC_NUMBER,
        (GIVEN_NAME and VEHICLE_NUMBER),
        (GIVEN_NAME and PHONE_NUMBER),
        (GIVEN_NAME and SURNAME and BIRTHDAY),
        (GIVEN_NAME and SURNAME and CITY and STREET_ADDRESS),
        (FULL_NAME and BIRTHDAY),
        (FULL_NAME and CITY and STREET_ADDRESS)
    ]

    constraint_passed = False
    for constraint in constraints:
        if constraint:
            constraint_passed = True
            break

    assert constraint_passed

    with raises(Exception, match="Validation failed: constraints missing. Check incident's inputs."):
        validate_incident_inputs_command(**mock_arguments_constraints_fail)


def test_generate_datasubject_payload():

    pii_entities = [
        "CC_CVV",
        "CC_NUMBER",
        "CC_TYPE"
    ]
    test_kwargs = {
        "national_id": "TEST NATIONAL ID",
        "given_name": "TEST NAME",
        "cc_cvv": "TEST_CC_CVV",
        "cc_number": "TEST_CC_NUMBER",
        "cc_type": "TEST_CC_TYPE"
    }
    payload = generate_datasubject_payload(pii_entities, **test_kwargs)
    test_payload = [
        {
            "piiEntityType": "CC_CVV",
            "piiEntityValue": "TEST_CC_CVV"
        },
        {
            "piiEntityType": "CC_NUMBER",
            "piiEntityValue": "TEST_CC_NUMBER"
        },
        {
            "piiEntityType": "CC_TYPE",
            "piiEntityValue": "TEST_CC_TYPE"
        },
    ]
    assert test_payload == payload


def test_format_pii_entities():
    entities = {
        "Demographic": [
            {
                "entityName": "BIRTHDAY",
                "sensitive": False
            }
        ],
        "Digital Identification": [
            {
                "entityName": "BROWSER_USER_AGENT",
                "sensitive": False
            },
            {
                "entityName": "GUID",
                "sensitive": False
            }
        ],
        "Financial information": [
            {
                "entityName": "ACCOUNT_NUMBER",
                "sensitive": False
            },
            {
                "entityName": "CC_CVV",
                "sensitive": True
            },
            {
                "entityName": "CC_EXPIRES",
                "sensitive": False
            },
            {
                "entityName": "CC_NUMBER",
                "sensitive": False
            },
            {
                "entityName": "CC_TYPE",
                "sensitive": False
            }
        ]
    }

    test_value = {"entities": [
        "BIRTHDAY",
        "BROWSER_USER_AGENT",
        "GUID",
        "ACCOUNT_NUMBER",
        "CC_CVV",
        "CC_EXPIRES",
        "CC_NUMBER",
        "CC_TYPE"]
    }

    assert format_pii_entities(entities) == test_value
