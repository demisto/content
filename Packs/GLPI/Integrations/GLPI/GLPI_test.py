"""GLPI Integration for Cortex XSOAR - Unit Tests file"""

import json
import io
import ast

# from unittest.mock import Mock
import demistomock as demisto
from GLPI import (
    Client,
    upload_file_command,
    get_user_name_command,
    create_user_command,
    update_user_command,
    delete_user_command,
    enable_user_command,
    disable_user_command,
    add_link_command,
    add_comment_command,
    create_ticket_command,
    update_ticket_command,
    delete_ticket_command,
    get_ticket_command,
    get_item_command,
    search_command,
    fetch_incidents,
    get_mapping_fields_command,
    get_remote_data_command,
    update_remote_system_command,
    get_modified_remote_data_command,
    get_user_id_command,
)
from test_data.glpi_fetch_incidents import (
    FETCHINCIDENTS_SEARCHTICKET,
    FETCHINCIDENTS_TICKET,
    FETCHINCIDENTS_TICKETUSER,
    FETCHINCIDENTS_TICKETDOC,
    FETCHINCIDENTS_TICKETDOCFILE,
)


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_mock(path):
    with open(path) as f:
        data = f.read()
    return ast.literal_eval(data)


def util_load_mock_without_ast(path):
    with open(path) as f:
        return f.read()


MOCK_URL = "mock://myglpi.mydomain.tld/apirest.php"
PARAMETERS = {
    "base_url": "mock://myglpi.mydomain.tld/apirest.php",
    "app_token": "TESTAPPTOKEN",
    "auth_token": "TESTUSERTOKEN",
    "verify": "True",
    "first_fetch_time": "3 days",
    "mirror_limit": "100",
    "proxy": "False",
}
MOCK_INIT_SESSION = "/initSession"
TESTDATA_INITSESSION = {"session_token": "SAMPLETOKEN"}


def test_glpi_upload_file(requests_mock, mocker):
    command_mock_args = {"entryid": "3@101177"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_document = util_load_mock("test_data/glpi_upload_file_document.mock")
    requests_mock.post("mock://myglpi.mydomain.tld/apirest.php/Document", json=mock_response_document)
    client = Client(PARAMETERS)
    mocker.patch.object(demisto, "getFilePath", return_value={"id": id, "path": "test_data/test.txt", "name": "test.txt"})
    response = upload_file_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Document"
    assert response.outputs == util_load_mock("test_data/glpi_upload_file_document.resmock")


def test_glpi_get_username(requests_mock):
    command_mock_args = {"id": 2}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_user = util_load_mock("test_data/glpi_getusername_user.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/user/2", json=mock_response_user)
    client = Client(PARAMETERS)
    response = get_user_name_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.User"
    assert response.outputs == {"id": 2, "username": "glpi"}


def test_glpi_get_userid(requests_mock):
    command_mock_args = {"name": "glpi"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_user = {"data": [{"1": "glpi", "2": 2}]}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = get_user_id_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.User"
    assert response.outputs == {"id": 2, "username": "glpi"}


def test_glpi_create_user(requests_mock):
    command_mock_args = {
        "name": "MyUser",
        "firstname": "MyFirstName",
        "lastname": "MyLastName",
        "email": "myuser@company.com",
        "password": "azerty1",
    }
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_user = [{"id": 31, "message": "Item successfully added: MyLastName MyFirstName"}]
    requests_mock.post("mock://myglpi.mydomain.tld/apirest.php/user", json=mock_response_user, status_code=201)
    client = Client(PARAMETERS)
    response = create_user_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.User"
    assert response.outputs == [{"id": 31, "message": "Item successfully added: MyLastName MyFirstName"}]


def test_glpi_update_user(requests_mock):
    command_mock_args = {"id": 31, "update_fields": "firstname=MyNewUser"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_user = [{"31": True, "message": ""}]
    requests_mock.put("mock://myglpi.mydomain.tld/apirest.php/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = update_user_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.User"


def test_glpi_delete_user(requests_mock):
    command_mock_args = {"name": "MyUser"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_search = {"data": [{"1": "MyUser", "2": 31}]}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/user", json=mock_response_search)
    mock_response_user = [{"31": True, "message": ""}]
    requests_mock.delete("mock://myglpi.mydomain.tld/apirest.php/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = delete_user_command(client, command_mock_args)
    assert response == "User MyUser successfully deleted"
    assert type(response) is not object


def test_glpi_enable_user(requests_mock):
    command_mock_args = {"name": "MyUser"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_search = {"data": [{"1": "MyUser", "2": 31}]}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/user", json=mock_response_search)
    mock_response_user = [{"31": True, "message": ""}]
    requests_mock.put("mock://myglpi.mydomain.tld/apirest.php/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = enable_user_command(client, command_mock_args)
    assert response == "User MyUser successfully enabled"
    assert type(response) is not object


def test_glpi_disable_user(requests_mock):
    command_mock_args = {"name": "MyUser"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_search = {"data": [{"1": "MyUser", "2": 31}]}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/user", json=mock_response_search)
    mock_response_user = [{"31": True, "message": ""}]
    requests_mock.put("mock://myglpi.mydomain.tld/apirest.php/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = disable_user_command(client, command_mock_args)
    assert response == "User MyUser successfully disabled"
    assert type(response) is not object


def test_glpi_add_comment(requests_mock):
    command_mock_args = {"ticket_id": 289, "comment": "My new comment"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_ticketfollowup = [{"id": 63, "message": ""}]
    requests_mock.post(
        "mock://myglpi.mydomain.tld/apirest.php/ticketfollowup", json=mock_response_ticketfollowup, status_code=201
    )
    client = Client(PARAMETERS)
    response = add_comment_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Comment"
    assert response.outputs == [{"id": 63, "message": ""}]


def test_glpi_add_link(requests_mock):
    command_mock_args = {"ticket_ID_1": 289, "ticket_ID_2": 287, "link": "Duplicate"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_ticket = [{"id": 4, "message": "Item successfully added: General - ID 4"}]
    requests_mock.post("mock://myglpi.mydomain.tld/apirest.php/ticket_ticket", json=mock_response_ticket, status_code=201)
    client = Client(PARAMETERS)
    response = add_link_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Link"
    assert response.outputs == [{"id": 4, "message": "Item successfully added: General - ID 4"}]


def test_glpi_create_ticket(requests_mock):
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    command_mock_args = {"name": "MyNewTicket", "type": "Incident", "content": "My Ticket description"}
    mock_response_ticket = [{"id": 290, "message": "Item successfully added: MyNewTicket"}]
    requests_mock.post("mock://myglpi.mydomain.tld/apirest.php/ticket", json=mock_response_ticket, status_code=201)
    client = Client(PARAMETERS)
    response = create_ticket_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Ticket"
    assert response.outputs == [{"id": 290, "message": "Item successfully added: MyNewTicket"}]


def test_glpi_update_ticket(requests_mock):
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    command_mock_args = {"id": 290, "severity": 3, "description": "My new description"}
    mock_response_ticket = [{"290": True, "message": ""}]
    requests_mock.put("mock://myglpi.mydomain.tld/apirest.php/ticket", json=mock_response_ticket)
    client = Client(PARAMETERS)
    response = update_ticket_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Ticket"
    assert response.outputs == [{"290": True, "message": ""}]


def test_glpi_delete_ticket(requests_mock):
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    command_mock_args = {"ticket_id": 290, "purge": True}
    mock_response_ticket = [{"290": True, "message": ""}]
    requests_mock.delete("mock://myglpi.mydomain.tld/apirest.php/ticket", json=mock_response_ticket)
    client = Client(PARAMETERS)
    response = delete_ticket_command(client, command_mock_args)
    assert response == "Ticket ID 290 successfully deleted"
    assert type(response) is not object


def test_glpi_get_ticket(requests_mock):
    command_mock_args = {"ticket_id": 289}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_ticket = util_load_mock("test_data/glpi_ticket_ticket.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289", json=mock_response_ticket)
    mock_response_ticket_user = util_load_mock("test_data/glpi_ticket_user.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289/Ticket_User", json=mock_response_ticket_user)
    mock_response_ticket_group = util_load_mock("test_data/glpi_ticket_group.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289/Group_Ticket", json=mock_response_ticket_group)
    mock_response_ticketfollowup = util_load_mock("test_data/glpi_ticket_followup.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289/ticketfollowup", json=mock_response_ticketfollowup)
    client = Client(PARAMETERS)
    response = get_ticket_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.Ticket"
    assert response.outputs == util_load_mock("test_data/glpi_ticket.resmock")
    assert response.outputs["id"] == 289


def test_glpi_get_item(requests_mock):
    command_mock_args = {"item_id": 2, "item_type": "user"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_user = util_load_mock("test_data/glpi_item.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/user/2", json=mock_response_user)
    client = Client(PARAMETERS)
    response = get_item_command(client, command_mock_args)
    assert response.outputs_prefix == "GLPI.user"
    assert response.outputs == util_load_mock("test_data/glpi_item.resmock")


def test_glpi_search(requests_mock):
    command_mock_args = {"query": [{"field": 1, "searchtype": "contains", "value": "^MyUser$"}], "item_type": "user"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_search = {"totalcount": 1, "count": 1, "data": {"33": {"1": "MyUser"}}}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/listSearchOptions/user", json=mock_response_search)
    mock_response_user = util_load_mock("test_data/glpi_search.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/user", json=mock_response_user)
    client = Client(PARAMETERS)
    response = search_command(client, command_mock_args)
    assert response[0].outputs_prefix == "GLPI.Search.User"
    assert response[0].outputs == {
        "name": "MyUser",
        "realname": "MyLastName",
        "UserEmail.email": "myuser@company.com",
        "phone": None,
        "Location.completename": None,
        "is_active": 1,
    }


def test_glpi_fetch_incidents(requests_mock):
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/ticket", json=FETCHINCIDENTS_SEARCHTICKET)
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/291", json=FETCHINCIDENTS_TICKET)
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/291/Ticket_User", json=FETCHINCIDENTS_TICKETUSER)
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/291/Group_Ticket", json=[])
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/291/Document_Item", json=FETCHINCIDENTS_TICKETDOC)
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/Document/33847", json=FETCHINCIDENTS_TICKETDOCFILE)
    last_run_mock = {"last_fetch": "2022-04-14T13:51:36"}
    client = Client(PARAMETERS)
    new_run, incidents = fetch_incidents(client=client, last_run=last_run_mock, max_results=50, first_fetch_time="3 days")
    assert new_run["last_fetch"] == "2022-04-14T13:51:36Z"
    assert len(incidents) == 1
    assert incidents[0]["name"] == "testing fetch incident"
    assert incidents[0]["occurred"] == "2022-04-14T11:47:34Z"
    assert incidents[0]["attachment"][0]["name"] == "testingupload.txt"


def test_glpi_get_mapping_fields():
    response = get_mapping_fields_command()
    assert response.extract_mapping() == util_load_mock("test_data/glpi_mapping.resmock")


def test_glpi_get_remote_data(requests_mock):
    command_mock_args = {"id": 289, "lastUpdate": "Thu Apr 07 2022 17:50:13 GMT+0200 (CEST)"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_ticket = util_load_mock("test_data/glpi_remotedata_ticket.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289", json=mock_response_ticket)
    mock_response_ticketdocs = util_load_mock("test_data/glpi_remotedata_ticketdocs.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289/Document_Item", json=mock_response_ticketdocs)
    mock_response_document = util_load_mock("test_data/glpi_remotedata_document.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/Document/33836", json=mock_response_document)
    mock_response_ticketfollowup = util_load_mock("test_data/glpi_ticket_followup.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/ticket/289/ticketfollowup", json=mock_response_ticketfollowup)
    client = Client(PARAMETERS)
    response = get_remote_data_command(client, command_mock_args, params={})
    assert response.entries[0]["File"] == "test_file.txt"
    assert response.entries[0]["ContentsFormat"] == "text"
    assert response.mirrored_object == util_load_mock("test_data/glpi_remotedata_mirror.resmock")


def test_glpi_update_remote_system(requests_mock):
    command_mock_args = {"remoteId": 289, "delta": {}, "data": {}}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    client = Client(PARAMETERS)
    response = update_remote_system_command(client, command_mock_args)
    assert response == 289


def test_glpi_get_modified_remote_data(requests_mock):
    command_mock_args = {"lastUpdate": "Thu Apr 07 2022 17:50:13 GMT+0200 (CEST)"}
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/initSession", json=TESTDATA_INITSESSION)
    mock_response_search = util_load_mock("test_data/glpi_modified_remotedata_search.mock")
    requests_mock.get("mock://myglpi.mydomain.tld/apirest.php/search/ticket", json=mock_response_search)
    client = Client(PARAMETERS)
    response = get_modified_remote_data_command(client, command_mock_args, 50)
    assert response.modified_incident_ids == [
        "146",
        "193",
        "260",
        "279",
        "230",
        "289",
        "197",
        "278",
        "133",
        "250",
        "212",
        "144",
        "192",
        "186",
        "187",
        "156",
        "210",
        "259",
        "282",
        "135",
        "207",
        "184",
        "163",
        "169",
        "245",
        "258",
        "149",
        "136",
        "152",
        "221",
        "285",
        "191",
        "147",
        "132",
        "275",
        "142",
        "219",
        "244",
        "231",
        "200",
        "280",
        "178",
        "199",
        "246",
        "263",
        "261",
        "288",
        "220",
        "264",
        "176",
        "235",
    ]
