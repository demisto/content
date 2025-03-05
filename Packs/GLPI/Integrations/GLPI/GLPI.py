import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


""" IMPORTS """

import json
import os
from html import unescape

import bcrypt
import dateparser
import requests
from glpi_api import GLPI

""" CONSTANTS, GLPI DATA """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = 50


"""Manifest when uploading a document passed as JSON in the multipart/form-data POST
request. Note the double curly is used for representing only one curly."""
UPLOAD_MANIFEST = '{{ "input": {{ "name": "{name:s}", "_filename" : ["{filename:s}"] }} }}'

"""Warning when we need to delete an incomplete document due to upload error."""
WARN_DEL_DOC = "The file could not be uploaded but a document with id '{:d}' was created, " "this document will be purged."

"""Warning when an invalid document could not be purged."""
WARN_DEL_ERR = "The created document could not be purged, you may need to clean it manually: {:s}"


GLPI_ARGS = [
    "id",
    "entities_id",
    "name",
    "date",
    "closedate",
    "solvedate",
    "date_mod",
    "users_id_lastupdater",
    "status",
    "users_id_recipient",
    "requesttypes_id",
    "content",
    "urgency",
    "impact",
    "priority",
    "itilcategories_id",
    "type",
    "global_validation",
    "slas_id_ttr",
    "slas_id_tto",
    "slalevels_id_ttr",
    "time_to_resolve",
    "time_to_own",
    "begin_waiting_date",
    "sla_waiting_duration",
    "ola_waiting_duration",
    "olas_id_tto",
    "olas_id_ttr",
    "olalevels_id_ttr",
    "ola_ttr_begin_date",
    "internal_time_to_resolve",
    "internal_time_to_own",
    "waiting_duration",
    "close_delay_stat",
    "solve_delay_stat",
    "takeintoaccount_delay_stat",
    "actiontime",
    "is_deleted",
    "locations_id",
    "validation_percent",
    "date_creation",
    "links",
]

MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}

TICKET_TYPE = {"Incident": 1, "Request": 2}

TICKET_HIGHLOW = {"Veryhigh": 5, "High": 4, "Medium": 3, "Low": 2, "Verylow": 1}

TICKET_MAJORLOW = {"Major": 6, "Veryhigh": 5, "High": 4, "Medium": 3, "Low": 2, "Verylow": 1}

TICKET_STATUS = {"New": 1, "Processing(assigned)": 2, "Processing(planned)": 3, "Pending": 4, "Solved": 5, "Closed": 6}

TICKET_LINK = {"Link": 1, "Duplicate": 2, "Child": 3, "Parent": 4}

USER_TYPE = {"REQUESTER": 1, "ASSIGNED": 2, "WATCHER": 3}

TICKET_FIELDS = (
    "closedate",
    "content",
    "date",
    "id",
    "impact",
    "internal_time_to_own",
    "internal_time_to_resolve",
    "itilcategories_id",
    "name",
    "priority",
    "requesttypes_id",
    "solvedate",
    "status",
    "time_to_own",
    "type",
    "urgency",
)


class myglpi(GLPI):
    def upload_document(self, name, filepath, fhandler=None, doc_name=None):
        """`API documentation
        <https://github.com/glpi-project/glpi/blob/master/apirest.md#upload-a-document-file>`__
        Upload the file at ``filepath`` as a document named ``name``.
        .. code::
            glpi.upload_document("My test document", '/path/to/file/locally')
            {'id': 55,
             'message': 'Item successfully added: My test document',
             'upload_result': {'filename': [{'name': ...}]}}
        There may be errors while uploading the file (like a non managed file type).
        In this case, the API create a document but without a file attached to it.
        This method raise a warning (and another warning if the document could not
        be deleted for some reasons) and purge the created but incomplete document.
        """
        if not doc_name:
            doc_name = name
        if not fhandler:
            fhandler = open(filepath, "rb")

        response = requests.post(
            url=self._set_method("Document"),
            headers={"Session-Token": self.session.headers["Session-Token"], "App-Token": self.session.headers["App-Token"]},
            files={  # type:ignore[arg-type]
                "uploadManifest": (None, UPLOAD_MANIFEST.format(name=doc_name, filename=name), "application/json"),
                "filename[0]": (name, fhandler),
            },
        )

        if response.status_code != 201:
            DemistoException(response)

        doc_id = response.json()["id"]
        error = response.json()["upload_result"]["filename"][0].get("error", None)
        if error is not None:
            demisto.error(WARN_DEL_DOC.format(doc_id), UserWarning)
            try:
                self.delete("Document", {"id": doc_id}, force_purge=True)
            except DemistoException as err:
                demisto.error(WARN_DEL_ERR.format(doc_id + " " + str(err)), UserWarning)
            raise DemistoException("(ERROR_GLPI_INVALID_DOCUMENT) {:s}".format(error))

        return response.json()


class Client(BaseClient):
    """
    implement the GLPI API
    """

    def __init__(self, params):
        super().__init__(base_url=params["base_url"], verify=params["verify"], proxy=params["proxy"])
        self.glpi = myglpi(params["base_url"], params["app_token"], params["auth_token"])

    def test(self):
        res = self.glpi.get_full_session()
        return res

    def get_ticket(self, ticket_id):
        res = self.glpi.get_item("ticket", ticket_id)
        return res

    def get_item(self, item_type, item_id):
        res = self.glpi.get_item(item_type, item_id)
        return res

    def get_user(self, user_id):
        res = self.glpi.get_item("user", user_id)
        return res

    def get_ticket_users(self, ticket_id):
        res = self.glpi.get_sub_items("ticket", ticket_id, "Ticket_User", expand_dropdowns=True)
        return res

    def get_ticket_groups(self, ticket_id):
        res = self.glpi.get_sub_items("ticket", ticket_id, "Group_Ticket", expand_dropdowns=True)
        return res

    def get_ticket_docs(self, ticket_id):
        res = self.glpi.get_sub_items("ticket", ticket_id, "Document_Item")
        return res

    def get_ticket_comments(self, ticket_id):
        res = self.glpi.get_sub_items("ticket", ticket_id, "ticketfollowup", expand_dropdowns=True)
        return res

    def download_document(self, doc_id, dirpath="/tmp", filename=None):
        res = self.glpi.download_document(doc_id, dirpath, filename)
        return res

    def upload_document(self, file_name, file_path, fhandler=None, doc_name=None):
        res = self.glpi.upload_document(file_name, file_path, fhandler, doc_name)
        return res

    def get_profile_list(self):
        res = self.glpi.get_all_items("Profile")
        return res

    def add_link(self, ticket_id_1, ticket_id_2, link):
        res = self.glpi.add("ticket_ticket", {"tickets_id_1": ticket_id_1, "tickets_id_2": ticket_id_2, "link": link})
        return res

    def create_user(self, userinfo):
        res = self.glpi.add("user", userinfo)
        return res

    def update_user(self, userinfo):
        res = self.glpi.update("user", userinfo)
        return res

    def link_document_to_ticket(self, document_id, ticket_id):
        res = self.glpi.add("Document_Item", {"documents_id": document_id, "itemtype": "ticket", "items_id": ticket_id})
        return res

    def add_comment(self, ticket_id, content):
        res = self.glpi.add(
            "ticketfollowup", {"tickets_id": ticket_id, "is_private": "0", "requesttypes_id": 1, "content": content}
        )
        return res

    def delete_user(self, userid, purge):
        res = self.glpi.delete("user", {"id": userid}, force_purge=purge)
        return res

    def disable_user(self, userid):
        res = self.glpi.update("user", {"id": userid, "is_active": "0"})
        return res

    def enable_user(self, userid):
        res = self.glpi.update("user", {"id": userid, "is_active": "1"})
        return res

    def get_user_id(self, username):
        criteria = [{"field": 1, "searchtype": "contains", "value": "^" + username + "$"}]
        forcedisplay = [2]
        res = self.glpi.search("user", criteria=criteria, forcedisplay=forcedisplay)[0]["2"]
        return res

    def list_incidents(self, last_fetch):
        criteria = [{"field": 15, "searchtype": "morethan", "value": last_fetch}]
        res = self.glpi.search("ticket", criteria=criteria)
        return res

    def modified_incidents(self, last_fetch, srange):
        criteria = [{"field": 19, "searchtype": "morethan", "value": last_fetch}]
        res = self.glpi.search("ticket", criteria=criteria, range=srange)
        return res

    def update_ticket(self, data):
        res = self.glpi.update("ticket", data)
        return res

    def create_ticket(self, data):
        res = self.glpi.add("ticket", data)
        return res

    def close_ticket(self, ticket_id):
        res = self.glpi.update("ticket", {"id": ticket_id, "status": 6})
        return res

    def delete_ticket(self, ticket_id, purge=False):
        res = self.glpi.delete("ticket", {"id": ticket_id}, force_purge=purge)
        return res

    def search(self, item_type, query, display):
        res = self.glpi.search(item_type, criteria=query, forcedisplay=display, uid_cols=True)
        return res


def test_module(params):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        client = Client(params)
        result = client.test()
        if "valid_id" in result:
            return "ok"
        return "Test Failed! Check your GLPI server"
    except Exception as e:
        if "ERROR_WRONG_APP_TOKEN_PARAMETER" in str(e):
            return "Test Failed! Authentication Error: " + str(e)
        else:
            return "Test Failed! Make sure the URL is correctly set. Error: " + str(e)


def get_profile_id_helper(client, args):
    profile_name = args.get("profile")
    profile_id = None
    if profile_name is not None:
        profile_list = client.get_profile_list()
        for profile in profile_list:
            if profile["name"] == profile_name:
                profile_id = profile["id"]
        if profile_id is None:
            raise DemistoException("Profile does not exist")
    return profile_id


def get_user_id_helper(client, args):
    user_name = args.get("name")
    user_id = None
    user_id = client.get_user_id(user_name)
    if user_id is None:
        raise DemistoException("User does not exist")
    return user_id


def get_ticket_users_helper(client, ticket_id):
    requester = []
    assigned = []
    watcher = []
    users = client.get_ticket_users(ticket_id)
    for user in users:
        if user["type"] == USER_TYPE["REQUESTER"]:
            requester.append(user["users_id"])
        elif user["type"] == USER_TYPE["ASSIGNED"]:
            assigned.append(user["users_id"])
        elif user["type"] == USER_TYPE["WATCHER"]:
            watcher.append(user["users_id"])
    return requester, assigned, watcher


def get_ticket_groups_helper(client, ticket_id):
    requester = []
    assigned = []
    watcher = []
    groups = client.get_ticket_groups(ticket_id)
    for group in groups:
        if group["type"] == 1:
            requester.append(group["groups_id"])
        elif group["type"] == 2:
            assigned.append(group["groups_id"])
        elif group["type"] == 3:
            watcher.append(group["groups_id"])
    return requester, assigned, watcher


def get_ticket_docs_helper(client, ticket_id):
    docs = client.get_ticket_docs(ticket_id)
    files = []
    if docs:
        for doc in docs:
            display_name = client.get_item("Document", doc["documents_id"]).get("filename")
            file = client.download_document(doc["documents_id"], filename=display_name)
            filename = os.path.split(file)[1]
            f = open(file, "rb")
            data = f.read()
            files.append(fileResult(filename, data))
    return files


def ticket_format(args):
    ticket_fields = {}
    for arg in GLPI_ARGS:
        input_arg = args.get(arg)
        if input_arg:
            if arg in ["impact", "urgency"]:
                ticket_fields[arg] = TICKET_HIGHLOW.get(input_arg)
            elif arg == "priority":
                ticket_fields[arg] = TICKET_MAJORLOW.get(input_arg)
            elif arg == "status":
                ticket_fields[arg] = TICKET_STATUS.get(input_arg)
            elif arg == "type":
                ticket_fields[arg] = TICKET_TYPE.get(input_arg)
            else:
                ticket_fields[arg] = input_arg
    return ticket_fields


def output_format(res, output_type=None, readable=None):
    if res:
        if isinstance(res, list):
            keys = res[0].keys()
        elif isinstance(res, str):
            return CommandResults(outputs_prefix="GLPI." + output_type, outputs_key_field="id", outputs=res, raw_response=res)
        else:
            keys = res.keys()
        key_list = [key for key in keys]
        if not output_type:
            output_type = key_list[0].split(".")[0]
        if not readable:
            readable = output_type
        result = CommandResults(
            outputs_prefix="GLPI." + output_type,
            outputs_key_field="id",
            outputs=res,
            raw_response=res,
            readable_output=tableToMarkdown(name="GLPI " + readable, t=res, headers=key_list),
        )
        return result
    else:
        return "No result"


def split_fields(fields: str = "", delimiter: str = ";") -> dict:
    dic_fields = {}
    if fields:
        if "=" not in fields:
            raise Exception(f"The argument: {fields}.\nmust contain a '=' to specify the keys and values. e.g: key=val.")
        arr_fields = fields.split(delimiter)
        for f in arr_fields:
            field = f.split("=", 1)  # a field might include a '=' sign in the value. thus, splitting only once.
            if len(field) > 1:
                dic_fields[field[0]] = field[1]

    return dic_fields


def upload_files(client, entries, ticket_id=None, filename=None, doc_name=None):
    entry_ids = argToList(entries)
    if filename:
        entry_names = argToList(filename)
        files = {entry_ids[i]: entry_names[i] for i in range(len(entry_names))}
    for entry in entry_ids:
        path_res = demisto.getFilePath(entry)
        full_file_name = path_res.get("name")
        file_extension = os.path.splitext(full_file_name)[1]
        if filename:
            full_file_name = files[entry]
        filename = os.path.split(path_res.get("path"))[1]
        with open(path_res.get("path"), "rb") as fhandler:
            if not file_extension:
                file_extension = ""
            up = client.upload_document(full_file_name, path_res.get("path"), fhandler, doc_name)
        if ticket_id:
            client.link_document_to_ticket(up["id"], ticket_id)
    return up


def upload_file_command(client, args):
    entries = args.get("entryid")
    filename = args.get("filename")
    doc_name = args.get("doc_name")
    res = upload_files(client, entries, None, filename, doc_name)
    result = output_format(res, "Document", "Document successfully added with ID : " + str(res["id"]))
    return result


def get_user_id_command(client, args):
    user_id = get_user_id_helper(client, args)
    if user_id:
        res_format = {"id": user_id, "username": args.get("name")}
        result = CommandResults(
            outputs_prefix="GLPI.User",
            outputs_key_field=["id", "username"],
            outputs=res_format,
            raw_response=res_format,
            readable_output=tableToMarkdown(name="GLPI username", t=res_format, headers=["id", "username"]),
        )
        return result
    else:
        raise DemistoException("Username does not exist")


def get_user_name_command(client, args):
    user_id = args.get("id")
    res = client.get_user(user_id)
    if res:
        user_name = res["name"]
        res_format = {"id": user_id, "username": user_name}
        result = CommandResults(
            outputs_prefix="GLPI.User",
            outputs_key_field=["id", "username"],
            outputs=res_format,
            raw_response=res_format,
            readable_output=tableToMarkdown(name="GLPI username", t=res_format, headers=["id", "username"]),
        )
        return result
    else:
        raise DemistoException("User ID does not exist")


def create_user_command(client, args):
    username = args.get("name")
    firstname = args.get("firstname")
    lastname = args.get("lastname")
    email = args.get("email")
    userpass = args.get("password").encode("utf-8")
    bpass = bcrypt.hashpw(userpass, bcrypt.gensalt(rounds=10)).decode("utf-8")
    glpi_pass = bpass.replace("$2b", "$2y")
    additional_fields = split_fields(str(args.get("additional_fields", "")), ";")
    profile_id = get_profile_id_helper(client, args)

    user = {
        "name": username,
        "realname": lastname,
        "_useremails": [email],
        "firstname": firstname,
        "password": glpi_pass,
        "_profiles_id": [profile_id],
    }

    if additional_fields:
        user.update(additional_fields)
    res = client.create_user(user)
    result = output_format(res, "User", "User successfully added with ID : " + str(res[0]["id"]))
    return result


def update_user_command(client, args):
    user_id = args.get("id")
    user = {"id": user_id}
    additional_fields = split_fields(str(args.get("update_fields", "")), ";")
    if additional_fields:
        user.update(additional_fields)
    res = client.update_user(user)
    if res[0][str(user_id)] is True:
        return output_format(res, "User", "User with ID " + str(user_id) + " successfully updated")
    raise DemistoException("Error when trying to update user ID " + str(user_id) + ": " + str(res))


def delete_user_command(client, args):
    username = args.get("name")
    purge = args.get("purge")
    user_id = get_user_id_helper(client, args)
    res = client.delete_user(user_id, purge)
    if res[0][str(user_id)] is True:
        return "User " + str(username) + " successfully deleted"
    raise DemistoException("Error when trying to delete user " + str(username) + ": " + str(res))


def enable_user_command(client, args):
    username = args.get("name")
    user_id = get_user_id_helper(client, args)
    res = client.enable_user(user_id)
    if res[0][str(user_id)] is True:
        return "User " + str(username) + " successfully enabled"
    raise DemistoException("Error when trying to enable user " + str(username) + ": " + str(res))


def disable_user_command(client, args):
    username = args.get("name")
    user_id = get_user_id_helper(client, args)
    res = client.disable_user(user_id)
    if res[0][str(user_id)] is True:
        return "User " + str(username) + " successfully disabled"
    raise DemistoException("Error when trying to disable user " + str(username) + ": " + str(res))


def add_comment_command(client, args):
    ticket_id = args.get("ticket_id")
    text = args.get("comment")
    res = client.add_comment(ticket_id, text)
    if res:
        if "id" in res[0]:
            result = output_format(res, "Comment", "Comment successfully added to ticket ID : " + str(ticket_id))
            return result
    else:
        raise DemistoException("Error when trying to add comment: " + str(res))


def add_link_command(client, args):
    ticket_id_1 = args.get("ticket_ID_1")
    ticket_id_2 = args.get("ticket_ID_2")
    link = TICKET_LINK.get(args.get("link"))
    res = client.add_link(ticket_id_1, ticket_id_2, link)
    if res:
        if "id" in res[0]:
            result = output_format(res, "Link", "Link successfully added to ticket ID : " + str(ticket_id_1))
            return result
    else:
        raise DemistoException("Error when trying to add link: " + str(res))


def create_ticket_command(client, args):
    additional_fields = split_fields(str(args.get("additional_fields", "")), ";")
    ticket_data = ticket_format(args)
    if additional_fields:
        ticket_data.update(additional_fields)
    # create ticket
    ticket = client.create_ticket(ticket_data)
    ticket_id = ticket[0].get("id")
    # upload files
    entries = args.get("entryid")
    if entries:
        upload_files(client, entries, ticket_id, None, "Document Ticket " + str(ticket_id))
    result = output_format(ticket, "Ticket", "Ticket successfully created")
    return result


def update_ticket_command(client, args):
    ticket_id = args.get("id")
    additional_fields = split_fields(str(args.get("additional_fields", "")), ";")
    ticket_data = ticket_format(args)
    if additional_fields:
        ticket_data.update(additional_fields)
    res = client.update_ticket(ticket_data)
    # upload files
    entries = args.get("entryid")
    if entries:
        upload_files(client, entries, ticket_data["id"], None, "Document Ticket " + str(ticket_data["id"]))
    if res[0][str(ticket_id)] is True:
        return output_format(res, "Ticket", "Ticket successfully updated")
    raise DemistoException("Error when trying to update ticket " + ticket_id + ": " + str(res))


def delete_ticket_command(client, args):
    ticket_id = args.get("ticket_id")
    purge = args.get("purge")
    res = client.delete_ticket(ticket_id, purge)
    if res[0][str(ticket_id)] is True:
        return "Ticket ID " + str(ticket_id) + " successfully deleted"
    raise DemistoException("Error when trying to delete ticket " + ticket_id + ": " + str(res))


def get_ticket_command(client, args):
    ticket_id = args.get("ticket_id")
    res = client.get_ticket(ticket_id)
    res["requester_users"], res["assigned_users"], res["watcher_users"] = get_ticket_users_helper(client, ticket_id)
    res["requester_groups"], res["assigned_groups"], res["watcher_groups"] = get_ticket_groups_helper(client, ticket_id)

    comments = client.get_ticket_comments(ticket_id)
    for comment in comments:
        html = unescape(comment.get("content"))
        comment["content"] = html
    res["comments"] = comments
    if args.get("get_attachments") is True:
        files_entries = get_ticket_docs_helper(client, ticket_id)
        for file in files_entries:
            demisto.results(file)
    result = output_format(res, "Ticket")
    return result


def get_item_command(client, args):
    item_id = args.get("item_id")
    item_type = args.get("item_type")
    res = client.get_item(item_type, item_id)
    result = output_format(res, item_type)
    return result


def search_command(client, args):
    item_type = args.get("item_type")
    query = argToList(args.get("query"))
    forcedisplay = args.get("forcedisplay")

    if not query:
        query = []
    if not forcedisplay:
        forcedisplay = []
    res = client.search(item_type, query, forcedisplay)
    if res:
        keys = list(res[0].keys())
        output_type = keys[0].split(".")[0]
        key_list = []
        my_output = {}
        for key in keys:
            key_list.append(key.replace(output_type + ".", ""))
            my_output[key.replace(output_type + ".", "")] = res[0][key]
        result = []
        result.append(
            CommandResults(
                outputs_prefix="GLPI.Search." + output_type,
                outputs_key_field=key_list,
                outputs=my_output,
                raw_response=my_output,
                readable_output=tableToMarkdown(name="GLPI Search", t=my_output, headers=key_list),
            )
        )
        return result
    else:
        return "Nothing found"


def fetch_incidents(client, last_run, max_results, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        max_results (int): Maximum numbers of incidents per fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """

    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch")

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = dateparser.parse(last_fetch.strftime("%Y-%m-%d %H:%M:%S"))
    search_date = last_fetch.strftime("%Y-%m-%d %H:%M:%S")
    incidents = []
    demisto.info(f"Fetching GLPI tickets since: {str(search_date)}")
    items = client.list_incidents(search_date)
    for item in items:
        ticket_id = item.get("2")
        ticket = client.get_ticket(ticket_id)
        ticket["requester_users"], ticket["assigned_users"], ticket["watcher_users"] = get_ticket_users_helper(client, ticket_id)  # noqa: E501
        ticket["requester_groups"], ticket["assigned_groups"], ticket["watcher_groups"] = get_ticket_groups_helper(
            client, ticket_id
        )  # noqa: E501
        ticket["content"] = unescape(ticket["content"])
        files = []
        files_entries = get_ticket_docs_helper(client, ticket_id)
        for file in files_entries:
            files.append({"path": file.get("FileID", ""), "name": file.get("File", "")})
        incident_created_time = dateparser.parse(ticket["date"])
        ticket["mirror_direction"] = MIRROR_DIRECTION.get(demisto.params().get("mirror_direction"))
        ticket["mirror_instance"] = demisto.integrationInstance()
        ticket["mirror_tags"] = [
            demisto.params().get("comment_tag"),
            demisto.params().get("file_tag"),
            demisto.params().get("work_notes_tag"),
        ]
        demisto.debug(
            f'Incident with ID {ticket_id} and name {ticket["name"]} occured: {str(incident_created_time.strftime(DATE_FORMAT))}'
        )  # type: ignore[union-attr]  # noqa: E501

        incident = {
            "name": ticket["name"],
            "occurred": incident_created_time.strftime(DATE_FORMAT),  # type: ignore[union-attr]
            "attachment": files,
            "rawJSON": json.dumps(ticket),
        }
        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:  # type: ignore[operator]
            latest_created_time = incident_created_time

        if len(incidents) >= max_results:
            demisto.debug("max_results reached")
            break

    next_run = {"last_fetch": latest_created_time.strftime(DATE_FORMAT)}  # type: ignore[union-attr]
    return next_run, incidents


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Returns the list of fields for an incident type.
    Args:
        client: XSOAR client to use
    Returns: Dictionary with keys as field names
    """

    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name="GLPI Incident")
    for field in GLPI_ARGS:
        incident_type_scheme.add_field(field)
    mapping_response.add_scheme_type(incident_type_scheme)

    request_type_scheme = SchemeTypeMapping(type_name="GLPI Request")
    for field in GLPI_ARGS:
        request_type_scheme.add_field(field)
    mapping_response.add_scheme_type(request_type_scheme)

    return mapping_response


def get_remote_data_command(client, args, params={}):
    """
    get-remote-data command: Returns an updated incident and entries
    Args:
        client: XSOAR client to use
        args:
            id: incident id to retrieve
            lastUpdate: when was the last time we retrieved data
    Returns:
        List[Dict[str, Any]]: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    # ticket_id = args.get('id', '')
    ticket_id = parsed_args.remote_incident_id
    last_update = args.get("lastUpdate")
    demisto.debug(f"Getting update for remote id {ticket_id} with last_update: {str(last_update)}")
    formated_date = last_update.replace("T", " ").split(".")[0]
    try:
        new_incident_data = client.get_ticket(ticket_id)
        entries = []
        demisto.debug(f"fetch files for ticket with id {ticket_id}")
        ticket_docs = client.get_ticket_docs(ticket_id)
        if ticket_docs:
            for ticket_doc in ticket_docs:
                if ticket_doc.get("date_mod") > formated_date:
                    document = client.get_item("Document", ticket_doc.get("documents_id"))
                    if "_mirrored_from_xsoar" not in document.get("filename"):
                        file = client.download_document(ticket_doc.get("documents_id"), filename=document.get("filename"))
                        demisto.debug(f'file {document.get("filename")} fetched for ticket with id {ticket_id}')
                        filename = os.path.split(file)[1]
                        f = open(file, "rb")
                        data = f.read()
                        entries.append(fileResult(filename, data))

        comments_result = client.get_ticket_comments(ticket_id)
        if comments_result:
            for note in comments_result:
                if "Mirrored from Cortex XSOAR" not in note.get("content") and note.get("date_mod") > formated_date:
                    comments_context = {"comments_and_work_notes": unescape(note.get("content"))}
                    entries.append(
                        {
                            "ContentsFormat": formats["html"],
                            "Type": entryTypes["note"],
                            "Contents": unescape(note.get("content")),
                            "Note": True,
                            "EntryContext": comments_context,
                        }
                    )
        demisto.debug(f"Pull result is {new_incident_data}")
        return GetRemoteDataResponse(new_incident_data, entries)
    except Exception as e:
        raise DemistoException(f"Error in incoming mirror for incident id {ticket_id}. :Error message: {str(e)}")


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f"Got the following delta keys {str(list(parsed_args.delta.keys()))}")

    demisto.debug(f"Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n")
    new_incident_id: str = parsed_args.remote_incident_id
    updated_incident = {}

    if not parsed_args.remote_incident_id or parsed_args.incident_changed:
        if parsed_args.remote_incident_id:
            old_incident = client.get_ticket(parsed_args.remote_incident_id)
            for changed_key in parsed_args.delta.keys():
                if changed_key in TICKET_FIELDS:
                    old_incident[changed_key] = parsed_args.delta[changed_key]  # type: ignore
            parsed_args.data = old_incident
        else:
            parsed_args.data["createInvestigation"] = True
        updated_incident = client.update_ticket(parsed_args.data)

    else:
        demisto.debug(
            f"Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is " f"not new nor changed."
        )

    # Close incident if relevant
    if updated_incident and parsed_args.inc_status == IncidentStatus.DONE:
        demisto.debug(f"Closing remote incident {new_incident_id}")
        client.close_ticket(new_incident_id)

    entries = parsed_args.entries

    if entries:
        demisto.debug(f"New entries {entries}")
        for entry in entries:
            demisto.debug(f'Sending entry {entry.get("id")}, type: {entry.get("type")}')
            # Mirroring files as entries
            if entry.get("type") == 3:
                path_res = demisto.getFilePath(entry.get("id"))
                demisto.debug("path res" + str(path_res))
                full_file_name = path_res.get("name")
                file_name, file_extension = os.path.splitext(full_file_name)
                if not file_extension:
                    file_extension = ""
                up = client.upload_document(file_name + "_mirrored_from_xsoar" + file_extension, path_res.get("path"))
                client.link_document_to_ticket(up["id"], new_incident_id)
            else:
                # Mirroring comment and work notes as entries
                user = entry.get("user", "dbot") or "dbot"
                text = f"({user}): {str(entry.get('contents', ''))}\n\n Mirrored from Cortex XSOAR"
                client.add_comment(new_incident_id, text)

    return new_incident_id


def get_modified_remote_data_command(client, args, mirror_limit):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    # last_update_utc = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    search_range = "0-" + str(mirror_limit)

    raw_incidents = client.modified_incidents(last_update, search_range)
    modified_incident_ids = list()
    for raw_incident in raw_incidents:
        incident_id = str(raw_incident.get("2"))
        modified_incident_ids.append(incident_id)
    return GetModifiedRemoteDataResponse(modified_incident_ids)


def main():
    """
    parse and validate integration params
    """
    command_list: Dict[str, Any] = {
        "glpi-create-ticket": create_ticket_command,
        "glpi-update-ticket": update_ticket_command,
        "glpi-delete-ticket": delete_ticket_command,
        "glpi-get-ticket": get_ticket_command,
        "glpi-get-item": get_item_command,
        "glpi-add-comment": add_comment_command,
        "glpi-add-link": add_link_command,
        "glpi-upload-file": upload_file_command,
        "glpi-search": search_command,
        "glpi-create-user": create_user_command,
        "glpi-update-user": update_user_command,
        "glpi-delete-user": delete_user_command,
        "glpi-enable-user": enable_user_command,
        "glpi-disable-user": disable_user_command,
        "glpi-get-username": get_user_name_command,
        "glpi-get-userid": get_user_id_command,
        "get-remote-data": get_remote_data_command,
    }

    params = {
        "base_url": urljoin(demisto.params().get("url", ""), ""),
        "app_token": demisto.params().get("app_token", ""),
        "auth_token": demisto.params().get("user_token", ""),
        "verify": not demisto.params().get("insecure", False),
        "first_fetch_time": demisto.params().get("fetch_time", "3 days").strip(),
        "mirror_limit": demisto.params().get("mirror_limit", "100"),
        "proxy": demisto.params().get("proxy", False),
    }

    cmd = demisto.command()

    if cmd == "test-module":
        return_results(test_module(params))

    try:
        client = Client(params)
        if cmd == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif cmd == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, demisto.args(), params["mirror_limit"]))
        elif cmd == "update-remote-system":
            return_results(update_remote_system_command(client, demisto.args()))
        elif cmd == "fetch-incidents":
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            # Set and define the fetch incidents command to run after activated via integration settings.
            new_run, incidents = fetch_incidents(
                client=client, last_run=demisto.getLastRun(), max_results=max_results, first_fetch_time=params["first_fetch_time"]
            )
            demisto.setLastRun(new_run)
            demisto.incidents(incidents)
        elif cmd in command_list.keys():
            return_results(command_list[cmd](client, demisto.args()))
        else:
            raise DemistoException('Command "%s" not implemented' % cmd)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
