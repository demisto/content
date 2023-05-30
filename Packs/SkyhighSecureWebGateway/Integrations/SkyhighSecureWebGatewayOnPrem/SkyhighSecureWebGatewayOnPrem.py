import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

""" IMPORTS """

import urllib
import urllib3
import xml.etree.ElementTree as ET
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API
    """
    def __init__(self, username, password, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username = username
        self.password = password

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, _type, *args):
        self.close()

    def connect(self):
        """User login
        """
        self._http_request(
            method="POST",
            url_suffix=f"/login?{urllib.parse.urlencode({'userName':self.username,'pass':self.password})}",
            resp_type="xml",
        )

    def close(self):
        """User logout
        """
        self._http_request(method="POST", url_suffix="/logout", resp_type="text")

    def get_lists(self) -> str:
        """Gets all available lists using the '/list' API endpoint

        """
        return self._http_request(method="GET", url_suffix="/list", resp_type="text")

    def get_list(self, list_id):
        return self._http_request(
            method="GET", url_suffix=f"/list/{list_id}", resp_type="text"
        )

    def get_list_entry(self, list_id, entry_pos):
        return self._http_request(
            method="GET",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}",
            resp_type="text",
            ok_codes=(200, 202, 203, 404),
        )

    def commit(self):
        return self._http_request(method="POST", url_suffix="/commit", resp_type="text")

    def put_list(self, list_id, config):
        return self._http_request(
            method="PUT", url_suffix=f"/list/{list_id}", data=config, resp_type="text"
        )

    def insert_entry(self, list_id, entry_pos, data):
        return self._http_request(
            method="POST",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}/insert",
            data=data,
            resp_type="text",
        )

    def delete_entry(self, list_id, entry_pos):
        return self._http_request(
            method="DELETE",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}",
            resp_type="text",
        )


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client, args: Dict[str, Any]) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    return "ok"


def get_lists_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get lists command: Returns available lists for matching pattern

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['filter']`` is used for pattern matching.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains available lists.
    """
    res = []
    result = client.get_lists()
    data = ET.fromstring(result)
    title = data.find("title").text
    for entry in data.iter("entry"):
        if (
            not args.get("filter")
            or args.get("filter", "").lower() in entry.find("title").text.lower()
        ):
            res.append(
                {
                    "Title": entry.find("title").text,
                    "ID": entry.find("id").text,
                    "Type": entry.find("listType").text,
                }
            )

    return CommandResults(
        readable_output=tableToMarkdown(title, res, headers=["Title", "ID", "Type"]),
        outputs_prefix="SWG.Lists",
        outputs_key_field="ID",
        outputs=res,
        raw_response=result
    )


def get_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get list command: Returns list details and content

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to query.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list details and content.
    """
    resEntries = []
    list_id = args.get("list_id")
    if not list_id:
        return "Missing mandatory arguments `list_id`."
    result = client.get_list(list_id)

    data = ET.fromstring(result)
    config = ET.tostring(data.find("content")[0], encoding="unicode")
    title = data.find("title").text
    res = {
        "ID": list_id,
        "Title": title,
        "Type": data.find("listType").text,
        "Description": data.find("content")[0].find("description").text,
    }

    i = 0

    for entry in data.iter("listEntry"):
        resEntries.append(
            {
                "ListID": list_id,
                "Position": i,
                "Name": entry.find("entry").text,
                "Description": entry.find("description").text,
            }
        )
        i += 1
    hr = tableToMarkdown(
        "List Properties", res, headers=["Title", "ID", "Description", "Type"]
    )
    res = {"List": res, "ListEntries": resEntries}

    return CommandResults(
        readable_output=hr
        + tableToMarkdown(
            title, resEntries, headers=["Position", "Name", "Description"]
        ),
        outputs_prefix="SWG",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=config
    )


def get_list_entry_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get list entry command: Returns a single entry form a list

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to query.
            ``args['entry_pos']`` the entry position to query.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list entry.
    """
    list_id = args.get("list_id")
    entry_pos = args.get("entry_pos")

    if not list_id or not entry_pos:
        return "Missing mandatory arguments `list_id` or `entry_pos`."

    result = client.get_list_entry(list_id, entry_pos)
    if result == "List entry not found":
        return "List entry not found."

    data = ET.fromstring(result)
    title = data.find("title").text

    for entry in data.iter("listEntry"):
        res = {
            "ListID": list_id,
            "Position": int(entry_pos),
            "Name": entry.find("entry").text,
            "Description": entry.find("description").text,
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res, headers=["ListID", "Position", "Name", "Description"]
        ),
        outputs_prefix="SWG.ListEntries",
        outputs_key_field=["ListID", "Position"],
        outputs=res,
        raw_response=result
    )


def modify_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    modify list command: Modify the list content

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be modified.
            ``args['config']`` the config that should be modified to.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list details and content.
    """
    list_id = args.get("list_id")
    config = args.get("config")
    if not list_id or not config:
        return "Missing mandatory arguments `list_id` or `config`."

    try:
        result = client.put_list(list_id, config.encode("utf-8"))
        client.commit()
    except Exception as e:
        return f"Faild to insert entry: {e}"

    data = ET.fromstring(result)
    config = ET.tostring(data.find("content")[0], encoding="unicode")
    title = f'Modified {data.find("title").text}'

    res = {
        "ID": list_id,
        "Title": data.find("title").text,
        "Type": data.find("listType").text,
        "Description": data.find("content")[0].find("description").text,
    }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res, headers=["Title", "ID", "Description", "Type"]
        ),
        outputs_prefix="SWG.List",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=config
    )


def insert_entry_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    insert entry command: Insert an entry to the list

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be modified.
            ``args['entry_pos']`` the entry position to insert at.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the inserted list entry.
    """
    list_id = args.get("list_id")
    entry_pos = args.get("entry_pos")
    name = args.get("name")
    description = args.get("description", "")
    if not list_id or not entry_pos or not name:
        return "Missing mandatory arguments `name`, `list_id` or `entry_pos`."

    entry = f"<listEntry><entry>{name}</entry><description>{description}</description></listEntry>"

    try:
        result = client.insert_entry(list_id, entry_pos, entry)
        client.commit()
    except Exception as e:
        return f"Faild to insert entry: {e}"

    data = ET.fromstring(result)
    title = f'Added {data.find("title").text}'

    for entry in data.iter("listEntry"):
        res = {
            "ListID": list_id,
            "Position": entry_pos,
            "Name": entry.find("entry").text,
            "Description": entry.find("description").text,
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res, headers=["ListID", "Position", "Name", "Description"]
        ),
        outputs_prefix="SWG.ListEntries",
        outputs_key_field=["ListID", "Position"],
        outputs=res,
        raw_response=result
    )


def delete_entry_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    delete entry command: Delete the list entry

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be modified.
            ``args['entry_pos']`` the entry position to be deleted.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list entry.
    """
    list_id = args.get("list_id")
    entry_pos = args.get("entry_pos")
    if not list_id or not entry_pos:
        return "Missing mandatory arguments `list_id` or `entry_pos`."

    try:
        result = client.delete_entry(list_id, entry_pos)
        client.commit()
    except Exception as e:
        return f"Faild to insert entry: {e}"

    data = ET.fromstring(result)
    title = f'Deleted {data.find("title").text}'

    for entry in data.iter("listEntry"):
        res = {
            "ListID": list_id,
            "Position": entry_pos,
            "Name": entry.find("entry").text,
            "Description": entry.find("description").text,
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res, headers=["ListID", "Position", "Name", "Description"]
        ),
        raw_response=result
    )


""" MAIN FUNCTION """


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    user = demisto.params().get("credentials", {}).get("identifier")
    password = demisto.params().get("credentials", {}).get("password")

    base_url = urljoin(demisto.params()["url"], "/Konfigurator/REST")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    headers = {"Content-Type": "application/mwg+xml"}

    demisto.debug(f"Command being called is {demisto.command()}")

    with Client(
        username=user,
        password=password,
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        proxy=proxy,
    ) as client:
        commands = {
            "test-module": test_module,
            "swg-get-available-lists": get_lists_command,
            "swg-get-list": get_list_command,
            "swg-get-list-entry": get_list_entry_command,
            "swg-modify-list": modify_list_command,
            "swg-insert-entry": insert_entry_command,
            "swg-delete-entry": delete_entry_command,
        }
        return_results(commands[demisto.command()](client, demisto.args()))


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
