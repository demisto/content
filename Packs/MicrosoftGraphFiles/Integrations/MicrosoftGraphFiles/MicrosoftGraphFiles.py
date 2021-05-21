import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

from urllib.parse import parse_qs, urlparse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" GLOBALS/PARAMS """

INTEGRATION_NAME = "MsGraphFiles"
APP_NAME = "ms-graph-files"

RESPONSE_KEYS_DICTIONARY = {
    "@odata.context": "OdataContext",
    "@microsoft.graph.downloadUrl": "DownloadUrl",
    "id": "ID",
    "@odata.nextLink": "OdataNextLink",
}

EXCLUDE_LIST = ["eTag", "cTag", "quota"]


def parse_key_to_context(obj):
    """Parse graph api data as received from Microsoft Graph API into Demisto's conventions

    Args:
        item object: a dictionary containing the item data

    Returns:
        A Camel Cased dictionary with the relevant fields.
        groups_readable: for the human readable
        groups_outputs: for the entry context
    """
    parsed_obj = {}
    for key, value in obj.items():
        if key in EXCLUDE_LIST:
            continue
        new_key = RESPONSE_KEYS_DICTIONARY.get(key, key)
        parsed_obj[new_key] = value
        if type(value) == dict:
            parsed_obj[new_key] = parse_key_to_context(value)

    under_score_obj = createContext(parsed_obj, keyTransform=camel_case_to_underscore)
    context_entry = createContext(under_score_obj, keyTransform=string_to_context_key)

    if "Id" in list(context_entry.keys()):
        context_entry["ID"] = context_entry["Id"]
        del context_entry["Id"]
    if "CreatedBy" in list(context_entry.keys()):
        context_entry["CreatedBy"] = remove_identity_key(context_entry["CreatedBy"])
    if "LastModifiedBy" in list(context_entry.keys()):
        context_entry["LastModifiedBy"] = remove_identity_key(
            context_entry["LastModifiedBy"]
        )
    return context_entry


def remove_identity_key(source):
    """
    this function removes identity key (application, device or user) from LastModifiedBy and CreatedBy keys and
    convert it to "type" key.
    :param source: LastModifiedBy and CreatedBy dictionaries
    :return: camel case dictionary with identity key as type.
    """
    if not isinstance(source, dict):
        LOG("Input is not dictionary. Exist function.")
        return source

    dict_keys = list(source.keys())
    if len(dict_keys) != 1:
        demisto.log("Got more then one identity creator. Exit function")
        return source

    identity_key = dict_keys[0]
    new_source = {}
    if source[identity_key].get("ID"):
        new_source["ID"] = source[identity_key].get("ID")

    new_source["DisplayName"] = source[identity_key].get("DisplayName")
    new_source["Type"] = identity_key

    return new_source


def url_validation(url):
    """
    this function tests if a user provided a valid next link url
    :param url: next_link_url from graph api
    :return: checked url if url is valid. demisto error if not.
    """
    parsed_url = urlparse(url)
    # test if exits $skiptoken
    url_parameters = parse_qs(parsed_url.query)
    if not url_parameters.get("$skiptoken") or not url_parameters["$skiptoken"]:
        raise DemistoException(
            f"Url: {url} is not valid. Please provide another one. missing $skiptoken"
        )
    return url


class MsGraphClient:
    """
    Microsoft Graph Client enables authorized access to organization's files in OneDrive, SharePoint, and MS Teams.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed, ok_codes):
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
            base_url=base_url, verify=verify, proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes)

    def list_sharepoint_sites(self):
        """
        This function returns a list of the tenant sites
        :return: graph api raw response
        """
        query_string = {"search": "*"}
        return self.ms_client.http_request(
            method="GET",
            url_suffix="sites",
            params=query_string,
        )

    def list_drives_in_site(self, site_id=None, limit=None, next_page_url=None):
        """
        Returns the list of Drive resources available for a target Site
        :param site_id: selected Site ID.
        :param limit: sets the page size of results.
        :param next_page_url: the URL for the next results page.
        :return:
        """
        if not any([site_id, next_page_url]):
            raise DemistoException(
                "Please pass at least one argument to this command: \n"
                "site_id: if you want to get all sites.\n"
                "limit: if you want to limit the number of command's results. \n"
                "next_page_url: if you have used the limit argument."
            )

        params = {"$top": limit} if limit else ""

        if next_page_url:
            url = url_validation(next_page_url)
            return self.ms_client.http_request(method="GET", full_url=url, params=params)

        url_suffix = f"sites/{site_id}/drives"
        return self.ms_client.http_request(method="GET", params=params, url_suffix=url_suffix)

    def list_drive_content(self, object_type, object_type_id, item_id=None, limit=None, next_page_url=None):
        """
        This command list all the drive's files and folders
        :param object_type: ms graph resource.
        :param object_type_id: ms graph resource id.
        :param item_id: ms graph item_id. optional.
        :param limit: sets the page size of results. optional.
        :param next_page_url: the URL for the next results page. optional.
        :return: graph api raw response
        """
        params = {"$top": limit} if limit else ""

        if next_page_url:
            url = url_validation(next_page_url)
            return self.ms_client.http_request(method="GET", full_url=url, params=params)

        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/children"
        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}/children"

        return self.ms_client.http_request(
            method="GET",
            url_suffix=uri,
            params=params,
        )

    def replace_existing_file(self, object_type, object_type_id, item_id, entry_id):
        """
        replace file context in MS Graph resource
        :param object_type: ms graph resource.
        :param object_type_id: ms graph resource id.
        :param item_id: item_id: ms graph item_id.
        :param entry_id: demisto file entry id
        :return: graph api raw response
        """

        file_path = demisto.getFilePath(entry_id).get("path", None)
        if not file_path:
            raise DemistoException(
                f"Could not find file path to the next entry id: {entry_id}. \n"
                f"Please provide another one."
            )
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/content"

        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}/content"
        with open(file_path, "rb") as file:
            headers = {"Content-Type": "application/octet-stream"}
            return self.ms_client.http_request(
                method="PUT", data=file, headers=headers, url_suffix=uri
            )

    def delete_file(self, object_type, object_type_id, item_id):
        """
        Delete a DriveItem by using its ID
        :param object_type: ms graph resource.
        :param object_type_id: ms graph resource id.
        :param item_id: ms graph item_id.
        :return: graph api raw response
        """
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}"

        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}"

        # send request
        self.ms_client.http_request(
            method="DELETE",
            url_suffix=uri,
            resp_type="text")

        return "Item was deleted successfully"

    def upload_new_file(self, object_type, object_type_id, parent_id, file_name, entry_id):
        """
        this function upload new file to a selected folder(parent_id)
        :param object_type: drive/ group/ me/ site/ users
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the folder to upload the file to.
        :param file_name: file name
        :param entry_id: demisto file entry ID
        :return: graph api raw response
        """
        file_path = demisto.getFilePath(entry_id).get("path")

        if "drives" == object_type:
            uri = f"{object_type}/{object_type_id}/items/{parent_id}:/{file_name}:/content"

        elif object_type in ["groups", "users", "sites"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{parent_id}:/{file_name}:/content"

        with open(file_path, "rb") as file:
            headers = {"Content-Type": "application/octet-stream"}
            return self.ms_client.http_request(
                method="PUT", headers=headers, url_suffix=uri, data=file)

    def download_file(self, object_type, object_type_id, item_id):
        """
        Download the contents of the file of a DriveItem.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param item_id: ms graph item_id.
        :return: graph api raw response
        """
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/content"

        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}/content"

        # send request
        return self.ms_client.http_request(method="GET", url_suffix=uri, resp_type='response')

    def create_new_folder(self, object_type, object_type_id, parent_id, folder_name):
        """
        Create a new folder in a Drive with a specified parent item or path.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the parent to upload the folder to.
        :param folder_name: folder name
        :return: graph api raw response
        """
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{parent_id}/children"

        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{parent_id}/children"

        # send request
        payload = {
            "name": folder_name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename",
        }

        return self.ms_client.http_request(method="POST", json_data=payload, url_suffix=uri)


def module_test(client: MsGraphClient, *_):
    """
    Performs basic get request to get item samples
    """
    try:
        client.ms_client.http_request(
            url_suffix="sites/root",
            params={"top": "1"},
            timeout=7,
            method="GET")

    except Exception as e:
        raise DemistoException(
            f"Test failed. please check if Server Url is correct. \n {e}"
        )
    return 'ok'


def download_file_command(client: MsGraphClient, args):
    """
    This function runs download file command
    :return: FileResult object
    """
    object_type = args.get("object_type")
    object_type_id = args.get("object_type_id")
    item_id = args.get("item_id")

    result = client.download_file(
        object_type=object_type, object_type_id=object_type_id, item_id=item_id
    )
    stored_img = fileResult(item_id, result.content)
    return stored_img


def list_drive_content_human_readable_object(parsed_drive_items):
    human_readable_content_obj = {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedBy": parsed_drive_items.get("CreatedBy").get("DisplayName"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "Description": parsed_drive_items.get("Description"),
        "Size": parsed_drive_items.get("Size"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }
    return human_readable_content_obj


def list_drive_content_command(client: MsGraphClient, args):
    """
    This function runs list drive children command
    :return: human_readable, context, result
    """
    object_type = args.get("object_type")
    object_type_id = args.get("object_type_id")
    item_id = args.get("item_id")
    limit = args.get("limit")
    next_page_url = args.get("next_page_url")

    if not item_id:
        item_id = "root"

    result = client.list_drive_content(
        object_type=object_type,
        object_type_id=object_type_id,
        item_id=item_id,
        limit=limit,
        next_page_url=next_page_url,
    )

    title = f"{INTEGRATION_NAME} - drivesItems information:"

    parsed_drive_items = [parse_key_to_context(item) for item in result["value"]]
    human_readable_content = [
        list_drive_content_human_readable_object(item) for item in parsed_drive_items
    ]
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    drive_items_outputs = {
        "OdataContext": result["@odata.context"],
        "Value": parsed_drive_items,
    }
    context = {
        f"{INTEGRATION_NAME}.ListChildren(val.ItemID == obj.ItemID)": {
            "ParentID": item_id,
            "Children": drive_items_outputs,
        }
    }

    return human_readable, context, result


def list_share_point_sites_human_readable_object(parsed_drive_items):
    human_readable_content_obj = {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }
    return human_readable_content_obj


def list_sharepoint_sites_command(client: MsGraphClient, *_):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    result = client.list_sharepoint_sites()

    parsed_sites_items = [parse_key_to_context(item) for item in result["value"]]

    human_readable_content = [
        list_share_point_sites_human_readable_object(item)
        for item in parsed_sites_items
    ]

    context_entry = {
        "OdataContext": result.get("@odata.context"),
        "Value": parsed_sites_items,
    }
    context = {f"{INTEGRATION_NAME}.ListSites(val.ID === obj.ID)": context_entry}

    title = "List Sites:"
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    return human_readable, context, result


def list_drives_human_readable_object(parsed_drive_items):
    human_readable_content_obj = {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedBy": parsed_drive_items.get("CreatedBy").get("DisplayName"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "Description": parsed_drive_items.get("Description"),
        "DriveType": parsed_drive_items.get("DriveType"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }
    return human_readable_content_obj


def list_drives_in_site_command(client: MsGraphClient, args):
    """
    This function run the list drives in site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    limit = args.get("limit")
    next_page_url = args.get("next_page_url")

    if next_page_url:
        url_validation(next_page_url)

    result = client.list_drives_in_site(
        site_id=site_id, limit=limit, next_page_url=next_page_url
    )
    parsed_drive_items = [parse_key_to_context(item) for item in result["value"]]

    human_readable_content = [
        list_drives_human_readable_object(item) for item in parsed_drive_items
    ]

    context_entry = {
        "OdataContext": result.get("@odata.context", None),
        "Value": parsed_drive_items,
    }

    title = f"{INTEGRATION_NAME} - Drives information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    # context == output
    context = {f"{INTEGRATION_NAME}.ListDrives(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def replace_an_existing_file_command(client: MsGraphClient, args):
    """
    This function runs the replace existing file command
    :return: human_readable, context, result
    """
    object_type = args.get("object_type")
    item_id = args.get("item_id")
    entry_id = args.get("entry_id")
    object_type_id = args.get("object_type_id")

    result = client.replace_existing_file(
        object_type, object_type_id, item_id, entry_id
    )
    context_entry = parse_key_to_context(result)

    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy").get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime"),
        "LastModifiedBy": context_entry.get("LastModifiedBy").get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }

    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    # context == output
    context = {f"{INTEGRATION_NAME}.ReplacedFiles(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def upload_new_file_command(client: MsGraphClient, args):
    """
    This function uploads new file to graph api
    :return: human_readable, context, result
    """
    object_type = args.get("object_type")
    object_type_id = args.get("object_type_id")
    parent_id = args.get("parent_id")
    file_name = args.get("file_name")
    entry_id = args.get("entry_id")

    result = client.upload_new_file(
        object_type, object_type_id, parent_id, file_name, entry_id
    )
    context_entry = parse_key_to_context(result)

    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy").get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime"),
        "LastModifiedBy": context_entry.get("LastModifiedBy").get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }

    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, human_readable_content)

    # context == output
    context = {f"{INTEGRATION_NAME}.UploadedFiles(val.ID === obj.ID)": context_entry}
    return human_readable, context, result


def create_new_folder_command(client: MsGraphClient, args):
    """
    This function runs create new folder command
    :return: human_readable, context, result
    """
    object_type = args.get("object_type")
    parent_id = args.get("parent_id")
    folder_name = args.get("folder_name")
    object_type_id = args.get("object_type_id")

    result = client.create_new_folder(
        object_type, object_type_id, parent_id, folder_name
    )

    context_entry = parse_key_to_context(result)

    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy").get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime"),
        "ChildCount": context_entry.get("Folder"),
        "LastModifiedBy": context_entry.get("LastModifiedBy").get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }
    title = f"{INTEGRATION_NAME} - Folder information:"
    # Creating human readable for War room

    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    # context == output
    context = {f"{INTEGRATION_NAME}.CreatedFolders(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def delete_file_command(client: MsGraphClient, args):
    """
    runs delete file command
    :return: raw response and action result test
    """
    object_type = args.get("object_type")
    item_id = args.get("item_id")
    object_type_id = args.get("object_type_id")

    text = client.delete_file(object_type, object_type_id, item_id)

    context_entry = text

    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry, headers=item_id)

    return human_readable, text  # == raw response


def main():
    params: dict = demisto.params()
    base_url: str = params.get('host', '').rstrip('/') + '/v1.0/'
    tenant = params.get('tenant_id')
    auth_id = params.get('auth_id')
    enc_key = params.get('enc_key')
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    ok_codes: tuple = (200, 204, 201)

    try:
        client = MsGraphClient(base_url=base_url, tenant_id=tenant, auth_id=auth_id, enc_key=enc_key, app_name=APP_NAME,
                               verify=use_ssl, proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes)

        LOG(f"Command being called is {demisto.command()}")

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = module_test(client)
            demisto.results(result)
        elif demisto.command() == "msgraph-delete-file":
            readable_output, raw_response = delete_file_command(client, demisto.args())
            return_outputs(readable_output=readable_output, raw_response=raw_response)
        elif demisto.command() == "msgraph-list-sharepoint-sites":
            return_outputs(*list_sharepoint_sites_command(client, demisto.args()))
        elif demisto.command() == "msgraph-download-file":
            # it has to be demisto.results instead of return_outputs.
            # because fileResult contains 'content': '' and if that key is empty return_outputs returns error.
            demisto.results(download_file_command(client, demisto.args()))
        elif demisto.command() == "msgraph-list-drive-content":
            return_outputs(*list_drive_content_command(client, demisto.args()))
        elif demisto.command() == "msgraph-create-new-folder":
            return_outputs(*create_new_folder_command(client, demisto.args()))
        elif demisto.command() == "msgraph-replace-existing-file":
            return_outputs(*replace_an_existing_file_command(client, demisto.args()))
        elif demisto.command() == "msgraph-list-drives-in-site":
            return_outputs(*list_drives_in_site_command(client, demisto.args()))
        elif demisto.command() == "msgraph-upload-new-file":
            return_outputs(*upload_new_file_command(client, demisto.args()))

    # Log exceptions
    except Exception as err:
        return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(err)}", err
        )


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
