import base64
import re
from typing import Dict, List, Optional, Tuple

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    def list_sharepoint_sites(self, search_query="*"):
        """
        This function returns a list of the tenant sites
        :return: graph api raw response
        """
        query_string = {"search": search_query}
        return self.ms_client.http_request(
            method="GET",
            url_suffix="sites",
            params=query_string,
        )

    def list_sharepoint_subsites(self, site_id):
        """
        This function returns a list of the tenant sites
        :return: graph api raw response
        """
        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"sites/{site_id}/sites"
        )

    def list_lists_in_site(self, site_id):
        """
        This function returns a list of the tenant lists
        :return: graph api raw response
        """
        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"sites/{site_id}/lists"
        )

    def get_sharepoint_list_columns(self, site_id, list_id):
        """
        This function returns a list of items in a list
        :return: graph api raw response
        """
        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"sites/{site_id}/lists/{list_id}/columns"
        )

    def get_sharepoint_list_items(self, site_id, list_id, search_query=None):
        """
        This function returns a list of items in a list
        :return: graph api raw response
        """
        query_string = {"expand": "fields"}
        # if search_query:
        #    query_string["filter"] = search_query
        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"sites/{site_id}/lists/{list_id}/items",
            params=query_string
        )

    def create_new_list_item(self, site_id, list_id, list_fields):
        """ FIX THIS
        Create a new folder in a Drive with a specified parent item or path.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the parent to upload the folder to.
        :param folder_name: folder name
        :return: graph api raw response
        """
        uri = f"sites/{site_id}/lists/{list_id}/items"

        fields_dict = safe_load_json(list_fields)

        # send request
        payload = {
            "fields": fields_dict
        }

        return self.ms_client.http_request(method="POST", json_data=payload, url_suffix=uri)

    def delete_list_item(self, site_id, list_id, item_id):
        """ FIX THIS
        Create a new folder in a Drive with a specified parent item or path.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the parent to upload the folder to.
        :param folder_name: folder name
        :return: graph api raw response
        """
        uri = f"sites/{site_id}/lists/{list_id}/items/{item_id}"

        response = self.ms_client.http_request(method="DELETE", return_empty_response=True, url_suffix=uri)

        if response.status_code == 204:
            return "Item was deleted successfully"
        else:
            return "Item may not have been removed. Please check the list."

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


def parse_human_readable_object(dict_item):
    human_readable_content_obj = {
        "Name": dict_item.get("Name"),
        "ID": dict_item.get("ID"),
        "Description": dict_item.get("Description")
    }

    if 'List' in dict_item:
        human_readable_content_obj['List'] = dict_item['List']
    if 'DriveType' in dict_item:
        human_readable_content_obj['DriveType'] = dict_item['DriveType']
    if 'Size' in dict_item:
        human_readable_content_obj['Size'] = dict_item['Size']
    if 'CreatedBy' in dict_item:
        human_readable_content_obj['CreatedBy'] = dict_item['CreatedBy']
    if 'CreatedDateTime' in dict_item:
        human_readable_content_obj['CreatedDateTime'] = dict_item['CreatedDateTime']
    if 'LastModifiedDateTime' in dict_item:
        human_readable_content_obj['LastModifiedDateTime'] = dict_item['LastModifiedDateTime']
    if 'DisplayName' in dict_item:
        human_readable_content_obj['DisplayName'] = dict_item['DisplayName']
    if 'Required' in dict_item:
        human_readable_content_obj['Required'] = dict_item['Required']
    if 'Lookup' in dict_item:
        human_readable_content_obj['Lookup'] = dict_item['Lookup']
    if 'Text' in dict_item:
        human_readable_content_obj['Text'] = dict_item['Text']
    if 'Choice' in dict_item:
        human_readable_content_obj['Choice'] = dict_item['Choice']
    if 'Integer' in dict_item:
        human_readable_content_obj['Integer'] = dict_item['Integer']
    if 'Note' in dict_item:
        human_readable_content_obj['Note'] = dict_item['Note']
    if 'DateTime' in dict_item:
        human_readable_content_obj['DateTime'] = dict_item['DateTime']
    if 'Counter' in dict_item:
        human_readable_content_obj['Counter'] = dict_item['Counter']
    if 'Boolean' in dict_item:
        human_readable_content_obj['Boolean'] = dict_item['Boolean']
    if 'Number' in dict_item:
        human_readable_content_obj['Number'] = dict_item['Number']
    if 'URL' in dict_item:
        human_readable_content_obj['URL'] = dict_item['URL']
    if 'Computed' in dict_item:
        human_readable_content_obj['Computed'] = dict_item['Computed']
    if 'MultiChoice' in dict_item:
        human_readable_content_obj['MultiChoice'] = dict_item['MultiChoice']
    if 'Calculated' in dict_item:
        human_readable_content_obj['Calculated'] = dict_item['Calculated']
    if 'File' in dict_item:
        human_readable_content_obj['File'] = dict_item['File']
    if 'Attachments' in dict_item:
        human_readable_content_obj['Attachments'] = dict_item['Attachments']
    if 'User' in dict_item:
        human_readable_content_obj['User'] = dict_item['User']
    if 'Fields' in dict_item:
        human_readable_content_obj['Fields'] = dict_item['Fields']

    return human_readable_content_obj


def list_sharepoint_sites_command(client: MsGraphClient, args):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    search_query = args.get("query", "*")
    result = client.list_sharepoint_sites(search_query)

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


def list_sharepoint_subsites_command(client: MsGraphClient, args):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    result = client.list_sharepoint_subsites(site_id)

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


def get_sharepoint_lists_command(client: MsGraphClient, args):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    result = client.list_lists_in_site(site_id)

    #demisto.debug(f'Raw Results - {result}')

    parsed_site_lists = [parse_key_to_context(item) for item in result["value"]]

    #demisto.debug(f'Parsed list from site - {parsed_site_lists}\n\n')

    human_readable_content = [
        parse_human_readable_object(item)
        for item in parsed_site_lists
    ]

    context_entry = {
        "OdataContext": result.get("@odata.context"),
        "Value": parsed_site_lists,
    }
    context = {f"MsGraphLists.List(val.ID === obj.ID)": parsed_site_lists}

    title = "Lists:"
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    return human_readable, context, result


def get_sharepoint_list_columns_command(client: MsGraphClient, args):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    list_id = args.get("list_id")
    result = client.get_sharepoint_list_columns(site_id, list_id)

    demisto.debug(f'Raw Results - {result}')

    parsed_content = [parse_key_to_context(item) for item in result["value"]]

    demisto.debug(f'Parsed list from site - {parsed_content}\n\n')

    human_readable_content = [
        parse_human_readable_object(item)
        for item in parsed_content
    ]

    context_entry = {
        "SiteID": site_id,
        "ListID": list_id,
        "Column": parsed_content,
    }
    context = {f"MsGraphList.Columns(val.ID === obj.ID)": context_entry}

    title = "Column"
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    return human_readable, context, result


def get_sharepoint_list_items_command(client: MsGraphClient, args):
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    list_id = args.get("list_id")
    search_query = args.get("query", None)
    result = client.get_sharepoint_list_items(site_id, list_id, search_query)

    #demisto.debug(f'Raw Results - {result}')

    parsed_content = [parse_key_to_context(item) for item in result["value"]]

    #demisto.debug(f'Parsed list from site - {parsed_content}\n\n')

    list_entries = [parse_key_to_context(item["Fields"]) for item in parsed_content]

    demisto.debug(f'Parsed Fields from site - {list_entries}\n\n')

    human_readable_content = [
        parse_human_readable_object(item)
        for item in parsed_content
    ]

    context_entry = {
        "OdataContext": result.get("@odata.context"),
        "Value": parsed_content,
    }
    context = {f"MsGraphLists.List(val.ID === obj.ID)": parsed_content}

    title = "Lists:"
    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    return human_readable, context, result


def create_new_list_item_command(client: MsGraphClient, args):
    """
    This function runs create new folder command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    list_id = args.get("list_id")
    list_fields = args.get("json_data", None)

    result = client.create_new_list_item(
        site_id, list_id, list_fields
    )

    demisto.debug(f'List item create raw result - {result}')
    context_entry = {
        "SiteID": site_id,
        "ListID": list_id,
        "ListEntry": parse_key_to_context(result)
    }

    human_readable_content = {
        "ID": context_entry.get("ListEntry").get("ID"),
        "CreatedDateTime": context_entry.get("ListEntry").get("CreatedDateTime")
    }
    title = f"List item summary:"
    # Creating human readable for War room

    human_readable = tableToMarkdown(
        title, human_readable_content, headerTransform=pascalToSpace
    )

    # context == output
    context = {f"MsGraphList.CreatedItem(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def delete_list_item_command(client: MsGraphClient, args):
    """
    This function deletes an item from a list
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    list_id = args.get("list_id")
    item_id = args.get("item_id")

    try:
        result = client.delete_list_item(site_id, list_id, item_id)

    except NotFoundError as err:
        err_details = err.args[0]
        error_dict = err_details.get('error')
        error_message = error_dict.get('message')

        demisto.debug(f'Exception data - {error_message}')
        result = error_message

    finally:
        context_entry = {
            "SiteID": site_id,
            "ListID": list_id,
            "ItemID": item_id,
            "Result": result
        }

        title = f"Deleted - Item information:"
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, headers=context_entry.keys())

        return human_readable, context_entry, result


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

    try:
        result = client.delete_file(object_type, object_type_id, item_id)

    except NotFoundError as err:
        err_details = err.args[0]
        error_dict = err_details.get('error')
        error_message = error_dict.get('message')

        demisto.debug(f'Exception data - {error_message}')
        result = error_message

    finally:
        context_entry = {
            "ObjectType": object_type,
            "ObjectTypeID": object_type_id,
            "ItemID": item_id,
            "Result": result
        }

        title = f"{INTEGRATION_NAME} - File information:"
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, headers=context_entry.keys())

        return human_readable, context_entry, result


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
        elif demisto.command() == "msgraph-list-sharepoint-subsites":
            return_outputs(*list_sharepoint_subsites_command(client, demisto.args()))
        elif demisto.command() == "msgraph-get-site-lists":
            return_outputs(*get_sharepoint_lists_command(client, demisto.args()))
        elif demisto.command() == "msgraph-get-list-columns":
            return_outputs(*get_sharepoint_list_columns_command(client, demisto.args()))
        elif demisto.command() == "msgraph-get-list-items":
            return_outputs(*get_sharepoint_list_items_command(client, demisto.args()))
        elif demisto.command() == "msgraph-create-list-item":
            return_outputs(*create_new_list_item_command(client, demisto.args()))
        elif demisto.command() == "msgraph-delete-list-item":
            return_outputs(*delete_list_item_command(client, demisto.args()))
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


### GENERATED CODE ###
# This code was inserted in place of an API module.import traceback


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
