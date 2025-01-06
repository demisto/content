import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

""" IMPORTS """

import urllib
import urllib3
from typing import Any

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

    def __exit__(self, _type: Any, *args: Any):
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

    def get_lists(self, list_name: str | None = None, list_type: str | None = None) -> str:
        """Gets all available lists using the '/list' API endpoint

        """
        url_suffix = "/list"
        list_filter = []
        if list_name:
            list_filter.append(f"name={list_name}")
        if list_type:
            list_filter.append(f"type={list_type}")
        if list_filter:
            url_suffix += f"?{'&'.join(list_filter)}"
        return self._http_request(method="GET", url_suffix=url_suffix, resp_type="text")

    def get_list(self, list_id: str):
        return self._http_request(
            method="GET", url_suffix=f"/list/{list_id}", resp_type="text"
        )

    def get_list_entry(self, list_id: str, entry_pos: str):
        return self._http_request(
            method="GET",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}",
            resp_type="text",
            ok_codes=(200, 202, 203, 404),
        )

    def commit(self):
        return self._http_request(method="POST", url_suffix="/commit", resp_type="text")

    def put_list(self, list_id: str, config: bytes):
        return self._http_request(
            method="PUT", url_suffix=f"/list/{list_id}", data=config, resp_type="text"
        )

    def insert_entry(self, list_id: str, entry_pos: str, data: str):
        return self._http_request(
            method="POST",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}/insert",
            data=data,
            resp_type="text",
        )

    def delete_entry(self, list_id: str, entry_pos: str):
        return self._http_request(
            method="DELETE",
            url_suffix=f"/list/{list_id}/entry/{entry_pos}",
            resp_type="text",
        )

    def create_list(self, data: str):
        return self._http_request(
            method="POST",
            url_suffix="/list",
            resp_type="text",
            data=data
        )

    def delete_list(self, list_id: str):
        return self._http_request(
            method="Delete",
            url_suffix=f"/list/{list_id}",
            resp_type="text"
        )


""" COMMAND FUNCTIONS """


def test_module(client: Client, args: dict[str, Any]) -> str:
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
    client.get_lists()
    return 'ok'


def get_lists_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    get lists command: Returns available lists for matching pattern

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` is used to filter lists by name.
            ``args['type']`` is used to filter lists by type.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains available lists.
    """
    list_name = args.get("name", "")
    list_type = args.get("type", "")
    res = []
    result = client.get_lists(list_name, list_type)
    data = json.loads(xml2json(result))
    title = demisto.get(data, "feed.title")
    entries = demisto.get(data, "feed.entry", [])
    if isinstance(entries, dict):
        entries = [entries]
    for entry in entries:
        res.append(
            {
                "Title": entry.get("title", ""),
                "ID": entry.get("id", ""),
                "Type": entry.get("listType", ""),
            }
        )

    return CommandResults(
        readable_output=tableToMarkdown(title, res, headers=["Title", "ID", "Type"]),
        outputs_prefix="SWG.List",
        outputs_key_field="ID",
        outputs=res,
        raw_response=result
    )


def get_list_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """
    get list command: Returns list details and content

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to query.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
                        that contains the list details and content.
    """
    resEntries = []
    list_id: str = args.get("list_id", "")
    result = client.get_list(list_id)

    data = json.loads(xml2json(result))
    config = json2xml(demisto.get(data, "entry.content", data)).decode("utf-8")
    title = demisto.get(data, "entry.title")
    res = {
        "ID": list_id,
        "Title": title,
        "Type": demisto.get(data, "entry.listType", ""),
        "Description": demisto.get(data, "entry.content.list.description"),
    }

    entries = demisto.get(data, "entry.content.list.content.listEntry", [])
    if isinstance(entries, dict):
        entries = [entries]
    for pos, entry in enumerate(entries):
        description = entry.get("description")
        if not description:
            description = ""
        resEntries.append(
            {
                "ListID": list_id,
                "Position": str(pos),
                "Name": entry.get("entry", ""),
                "Description": description,
            }
        )

    hr = tableToMarkdown(
        "List Properties", res, headers=["Title", "ID", "Description", "Type"]
    )
    res["ListEntries"] = resEntries

    return CommandResults(
        readable_output=hr
        + tableToMarkdown(
            title, resEntries, headers=["Position", "Name", "Description"]
        ),
        outputs_prefix="SWG.List",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=config
    )


def get_list_entry_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
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
    list_id: str = args.get("list_id", "")
    entry_pos: str = args.get("entry_pos", "")

    result = client.get_list_entry(list_id, entry_pos)

    data = json.loads(xml2json(result))
    title = demisto.get(data, "entry.title")

    entry = demisto.get(data, "entry.content.listEntry", {})
    description = entry.get("description")
    if not description:
        description = ""
    res = {
        "ID": list_id,
        "ListEntries": [
            {
                "ListID": list_id,
                "Position": entry_pos,
                "Name": entry.get("entry", ""),
                "Description": description,
            }
        ]
    }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res["ListEntries"], headers=["ListID", "Position", "Name", "Description"]
        ),
        outputs_prefix="SWG.List",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=result
    )


def modify_list_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """
    modify list command: Modify the list content

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be modified.
            ``args['config']`` the config that should be modified to.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
                        that contains the list details and content.
    """
    resEntries = []
    list_id: str = args.get("list_id", "")
    conf: str = args.get("config", "")

    result = client.put_list(list_id, conf.encode("utf-8"))
    client.commit()

    data = json.loads(xml2json(result))
    config = json2xml(demisto.get(data, "entry.content", data)).decode("utf-8")
    title = demisto.get(data, "entry.title", "")
    description = demisto.get(data, "entry.content.list.description")
    if not description:
        description = ""

    res = {
        "ID": list_id,
        "Title": title,
        "Type": demisto.get(data, "entry.listType", ""),
        "Description": description,
    }

    entries = demisto.get(data, "entry.content.list.content.listEntry", [])
    if isinstance(entries, dict):
        entries = [entries]
    for pos, entry in enumerate(entries):
        description = entry.get("description")
        if not description:
            description = ""
        resEntries.append(
            {
                "ListID": list_id,
                "Position": str(pos),
                "Name": entry.get("entry", ""),
                "Description": description,
            }
        )

    hr = tableToMarkdown(
        'List Properties', res, headers=["Title", "ID", "Description", "Type"]
    )
    res["ListEntries"] = resEntries

    return CommandResults(
        readable_output=hr
        + tableToMarkdown(
            title, resEntries, headers=["Position", "Name", "Description"]
        ),
        outputs_prefix="SWG.List",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=config
    )


def insert_entry_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """
    insert entry command: Insert an entry to the list

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be modified.
            ``args['entry_pos']`` the entry position to insert at.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
                        that contains the inserted list entry.
    """
    list_id: str = args.get("list_id", "")
    entry_pos: str = args.get("entry_pos", "")
    name: str = args.get("name", "")
    description: str = args.get("description", "")

    entry = f"<listEntry><entry>{name}</entry><description>{description}</description></listEntry>"

    result = client.insert_entry(list_id, entry_pos, entry)
    client.commit()

    data = json.loads(xml2json(result))
    title = f'Added {demisto.get(data, "entry.title")}'

    entry = demisto.get(data, "entry.content.listEntry", {})
    description = entry.get("description")
    if not description:
        description = ""
    entry_name = entry.get("entry", "")
    list_entry = {
        "ListID": list_id,
        "Position": entry_pos,
        "Name": entry_name,
        "Description": description,
    }

    swg_lists = demisto.get(demisto.context(), "SWG.List", [])
    if isinstance(swg_lists, dict):
        swg_lists = [swg_lists]
    if any(item["ID"] == list_id for item in swg_lists):
        outputs_prefix = f'SWG.List(val.ID && val.ID == "{list_id}").ListEntries'
        outputs_key_field = "Name"
        res = list_entry
    else:
        outputs_prefix = 'SWG.List'
        outputs_key_field = "ID"
        res = {
            "ID": list_id,
            "ListEntries": [list_entry]
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, list_entry, headers=["ListID", "Position", "Name", "Description"]
        ),
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=res,
        raw_response=result
    )


def delete_entry_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
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
    list_id: str = args.get("list_id", "")
    entry_pos: str = args.get("entry_pos", "")

    result = client.delete_entry(list_id, entry_pos)
    client.commit()

    data = json.loads(xml2json(result))
    title = f'Deleted {demisto.get(data, "entry.title")}'

    entry = demisto.get(data, "entry.content.listEntry", {})
    description = entry.get("description")
    if not description:
        description = ""
    res = {
        "ID": list_id,
        "ListEntries": [
            {
                "ListID": list_id,
                "Position": entry_pos,
                "Name": entry.get("entry", ""),
                "Description": description,
            }
        ]
    }

    return CommandResults(
        readable_output=tableToMarkdown(
            title, res["ListEntries"], headers=["ListID", "Position", "Name", "Description"]
        ),
        raw_response=result
    )


def create_list_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """
    create list command: Create an empty list

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` the list name to be added.
            ``args['type']`` the list type to be added.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list entry.
    """
    list_name: str = args.get("name", "")
    list_type: str = args.get("type", "")

    list_data = f'<list name="{list_name}" typeId="com.scur.type.{list_type}" classifier="Other" systemList="false" ' \
                + 'structuralList="false" defaultRights="2"><description /><content /></list>'

    result = client.create_list(list_data)
    client.commit()

    data = json.loads(xml2json(result))
    config = json2xml(demisto.get(data, "entry.content", data)).decode("utf-8")

    title = demisto.get(data, "entry.title")
    description = demisto.get(data, "entry.content.list.description")
    if not description:
        description = ""
    res = {
        "ID": demisto.get(data, "entry.id"),
        "Title": title,
        "Type": demisto.get(data, "entry.listType"),
        "Description": description,
    }
    hr = tableToMarkdown(
        "Created List Properties", res, headers=["Title", "ID", "Description", "Type"]
    )

    return CommandResults(
        readable_output=hr,
        outputs_prefix="SWG.List",
        outputs_key_field=["ID"],
        outputs=res,
        raw_response=config
    )


def delete_list_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """
    create list command: Create an empty list

    Args:
        client (Client): API client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['list_id']`` the list id to be deleted.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains the list entry.
    """
    list_id: str = args.get("list_id", "")

    result = client.delete_list(list_id)
    client.commit()

    data = json.loads(xml2json(result))

    title = demisto.get(data, "entry.title")
    description = demisto.get(data, "entry.content.list.description")
    if not description:
        description = ""
    res = {
        "ID": demisto.get(data, "entry.id"),
        "Title": title,
        "Type": demisto.get(data, "entry.listType"),
        "Description": description,
    }
    hr = tableToMarkdown(
        "Deleted List Properties", res, headers=["Title", "ID", "Description", "Type"]
    )

    return CommandResults(
        readable_output=hr,
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

    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
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
                "swg-create-list": create_list_command,
                "swg-delete-list": delete_list_command,
            }
            if command not in commands:
                raise NotImplementedError(f'Command {command} was not implemented.')
            return_results(commands[command](client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
