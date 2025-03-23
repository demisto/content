import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402

from urllib.parse import parse_qs, urlparse


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


def parse_key_to_context(obj: dict) -> dict:
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
        if isinstance(value, dict):
            parsed_obj[new_key] = parse_key_to_context(value)

    under_score_obj = createContext(parsed_obj, keyTransform=camel_case_to_underscore)
    context_entry: dict = createContext(under_score_obj, keyTransform=string_to_context_key)

    if "Id" in list(context_entry.keys()):
        context_entry["ID"] = context_entry["Id"]
        del context_entry["Id"]
    if "CreatedBy" in list(context_entry.keys()):
        context_entry["CreatedBy"] = remove_identity_key(context_entry["CreatedBy"])
    if "LastModifiedBy" in list(context_entry.keys()):
        context_entry["LastModifiedBy"] = remove_identity_key(context_entry["LastModifiedBy"])
    return context_entry


def remove_identity_key(source: Any) -> dict:
    """
    this function removes identity key (application, device or user) from LastModifiedBy and CreatedBy keys and
    convert it to "type" key.
    :param source: LastModifiedBy and CreatedBy dictionaries
    :return: camel case dictionary with identity key as type.
    """
    if not isinstance(source, dict):
        demisto.debug("Input is not dictionary. Exist function.")
        return source

    dict_keys = list(source.keys())
    if len(dict_keys) != 1:
        demisto.debug("Got more then one identity creator. Exit function")
        return source

    identity_key = dict_keys[0]
    new_source = {}
    if source[identity_key].get("ID"):
        new_source["ID"] = source[identity_key].get("ID")

    new_source["DisplayName"] = source[identity_key].get("DisplayName")
    new_source["Type"] = identity_key

    return new_source


def url_validation(url: str) -> str:
    """
    this function tests if a user provided a valid next link url
    :param url: next_link_url from graph api
    :return: checked url if url is valid. demisto error if not.
    """
    parsed_url = urlparse(url)
    # test if exits $skiptoken
    url_parameters = parse_qs(parsed_url.query)
    if not url_parameters.get("$skiptoken") or not url_parameters["$skiptoken"]:
        raise DemistoException(f"Url: {url} is not valid. Please provide another one. missing $skiptoken")
    return url


class MsGraphClient:
    """
    Microsoft Graph Client enables authorized access to organization's files in OneDrive, SharePoint, and MS Teams.
    """

    MAX_ATTACHMENT_SIZE = 3145728  # 3mb = 3145728 bytes
    MAX_ATTACHMENT_UPLOAD = 327680  # 320 KiB = 327680 bytes

    def __init__(
        self,
        tenant_id,
        auth_id,
        enc_key,
        app_name,
        base_url,
        verify,
        proxy,
        self_deployed,
        ok_codes,
        redirect_uri,
        auth_code,
        certificate_thumbprint: Optional[str] = None,
        private_key: Optional[str] = None,
        managed_identities_client_id: Optional[str] = None,
    ):
        if not managed_identities_client_id:
            if not self_deployed and not enc_key:
                raise DemistoException(
                    "Key must be provided. For further information see "
                    "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
                )
            if self_deployed and (not enc_key and not (certificate_thumbprint and private_key)):
                raise DemistoException(
                    "Either Key or (Certificate Thumbprint and Private Key) must be provided. For further "
                    "information see "
                    "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
                )
            elif self_deployed and auth_code and not redirect_uri:
                raise DemistoException(
                    "Please provide both Application redirect URI and Authorization code "
                    "for Authorization Code flow, or None for the Client Credentials flow"
                )

        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id,
            auth_id=auth_id,
            enc_key=enc_key,
            app_name=app_name,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            self_deployed=self_deployed,
            ok_codes=ok_codes,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.graph,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            grant_type=grant_type,
            command_prefix="msgraph-files",
        )

    def list_sharepoint_sites(self, keyword: str) -> dict:
        """
        This function lists the tenant sites
        :return: graph api raw response
        """
        return self.ms_client.http_request(
            method="GET",
            url_suffix="sites",
            params={"search": keyword},
        )

    def list_drives_in_site(self, site_id=None, limit=None, next_page_url=None) -> dict:
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
                "next_page_url: if you have used the limit argument."
            )

        params = {"$top": limit} if limit else ""

        if next_page_url:
            url = url_validation(next_page_url)
            return self.ms_client.http_request(method="GET", full_url=url, params=params)

        url_suffix = f"sites/{site_id}/drives"
        return self.ms_client.http_request(method="GET", params=params, url_suffix=url_suffix)

    def list_site_permissions(self, site_id: str, permission_id: str | None) -> dict:
        """Lists permissions for a SharePoint site.

        Args:
            site_id: The ID of the site to list permissions for.
            permission_id: The unique identifier for the permission to retrieve.
                When not provided, a list of all permissions is returned.

        Returns:
            dict: The raw response from the Graph API.

        Note:
            When the permission_id parameter is not provided in the command,
            a list of permissions is returned, but the `roles` field is not included in each permission object.
            To get the `roles` field, you must provide the permission_id parameter.
        """
        url_suffix = f"sites/{site_id}/permissions"
        if permission_id:
            url_suffix += f"/{permission_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url_suffix)

    def create_site_permission(self, site_id: str, app_id: str, display_name: str, role: list[str]) -> dict:
        url_suffix = f"sites/{site_id}/permissions"
        body = {"roles": role, "grantedToIdentities": [{"application": {"id": app_id, "displayName": display_name}}]}
        return self.ms_client.http_request(method="POST", url_suffix=url_suffix, json_data=body)

    def update_site_permission(self, site_id: str, permission_id: str, role: list[str]) -> dict:
        url_suffix = f"sites/{site_id}/permissions/{permission_id}"
        body = {"roles": role}
        return self.ms_client.http_request(method="PATCH", url_suffix=url_suffix, json_data=body)

    def delete_site_permission(self, site_id: str, permission_id: str) -> requests.Response:
        """
        We will always receive a 204 status code when attempting to remove a permission,
        even if the specified permission ID does not exist in the permission list.
        """
        url_suffix = f"/sites/{site_id}/permissions/{permission_id}"
        return self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

    def list_drive_content(self, object_type: str, object_type_id: str, item_id: str, limit=None, next_page_url=None) -> dict:
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
        uri = ""
        if next_page_url:
            url = url_validation(next_page_url)
            return self.ms_client.http_request(method="GET", full_url=url, params=params)

        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/children"
        elif object_type in {"groups", "sites", "users"}:
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
        uri = ""
        file_path = demisto.getFilePath(entry_id).get("path", None)
        if not file_path:
            raise DemistoException(
                f"Could not find file path to the next entry id: {entry_id}. \nPlease provide another one."
            )
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/content"

        elif object_type in ["groups", "sites", "users"]:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}/content"
        with open(file_path, "rb") as file:
            headers = {"Content-Type": "application/octet-stream"}
            return self.ms_client.http_request(method="PUT", data=file, headers=headers, url_suffix=uri)

    def replace_existing_file_with_upload_session(
        self, object_type: str, object_type_id: str, item_id: str, entry_id: str, file_data: bytes, file_size: int, file_name: str
    ) -> requests.Response:
        """
        Replace a file with upload session.

        Args:
        object_type: ms graph resource.
        object_type_id: ms graph resource id.
        item_id: ms graph item_id.
        entry_id: demisto file entry id

        Returns:
            MsGraph api raw response.
        """
        file_path = demisto.getFilePath(entry_id).get("path", None)
        if not file_path:
            raise DemistoException(
                f"Could not find file path to the next entry id: {entry_id}. \nPlease provide another one."
            )
        uri = ""
        # create suitable upload session
        if object_type == "drives":
            uri = f"/drives/{object_type_id}/items/{item_id}/createUploadSession"
        elif object_type == "groups":
            uri = f"/groups/{object_type_id}/drive/items/{item_id}/createUploadSession"
        elif object_type == "sites":
            uri = f"/sites/{object_type_id}/drive/items/{item_id}/createUploadSession"
        elif object_type == "users":
            uri = f"/users/{object_type_id}/drive/items/{item_id}/createUploadSession"
        response, upload_url = self.create_an_upload_session(uri)
        if not upload_url:
            raise Exception(f"Cannot get upload URL for attachment {file_name}")
        demisto.debug(f'response of "create_an_upload_session": {response}')
        response_file_upload = self.upload_file_with_upload_session(upload_url, file_data, file_size)
        demisto.debug(f'response of "upload_file_with_upload_session": {response_file_upload}')
        return response_file_upload

    def delete_file(self, object_type: str, object_type_id: str, item_id: str) -> str:
        """
        Delete a DriveItem by using its ID
        :param object_type: ms graph resource.
        :param object_type_id: ms graph resource id.
        :param item_id: ms graph item_id.
        :return: graph api raw response
        """
        uri = ""
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}"

        elif object_type in {"groups", "sites", "users"}:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}"

        # send request
        self.ms_client.http_request(method="DELETE", url_suffix=uri, resp_type="text")

        return "Item was deleted successfully"

    @staticmethod
    def upload_attachment(upload_url, start_chunk_idx, end_chunk_idx, chunk_data, attachment_size) -> requests.Response:
        """
        Upload an attachment to the upload URL.

        Args:
            upload_url (str): upload URL provided when running 'get_upload_session'
            start_chunk_idx (int): the start of the chunk file data.
            end_chunk_idx (int): the end of the chunk file data.
            chunk_data (bytes): the chunk data in bytes from start_chunk_idx to end_chunk_idx
            attachment_size (int): the entire attachment size in bytes.

        Returns:
            Response: response indicating whether the operation succeeded. 200 if a chunk was added successfully,
                201 (created) if the file was uploaded completely. 400 in case of errors.
        """
        chunk_size = len(chunk_data)
        headers = {
            "Content-Length": f"{chunk_size}",
            "Content-Range": f"bytes {start_chunk_idx}-{end_chunk_idx - 1}/{attachment_size}",
            "Content-Type": "application/octet-stream",
        }
        try:
            response = requests.put(url=upload_url, data=chunk_data, headers=headers)
        except Exception as e:
            raise (e)
        return response

    def upload_file_with_upload_session(self, upload_url: str, file_data: bytes, file_size: int) -> requests.Response:
        """
        Add an attachment using an upload session by dividing the file bytes into chunks and sent each chunk each time.
        more info here -
        https://learn.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_createuploadsession?view=odsp-graph-online#upload-bytes-to-the-upload-session

        Args:
            upload_url (str): url to file upload.
            file_data (bytes): The file data.
            file_size (int): The file size in bytes.
        Returns:
            Response: response indicating whether the operation succeeded. 200 or
                      201 (created) if the file was uploaded completely. 400 in case of errors.
        """
        start_chunk_index = 0
        end_chunk_index = self.MAX_ATTACHMENT_UPLOAD

        chunk_data = file_data[start_chunk_index:end_chunk_index]

        response = self.upload_attachment(
            upload_url=upload_url,
            start_chunk_idx=start_chunk_index,
            end_chunk_idx=end_chunk_index,
            chunk_data=chunk_data,
            attachment_size=file_size,
        )
        demisto.debug(f"start_chunk_idx:{start_chunk_index}, end_chunk_idx:{end_chunk_index}")
        while response.status_code not in [201, 200]:  # the api returns 201 when the file is created
            start_chunk_index = end_chunk_index
            next_chunk = end_chunk_index + self.MAX_ATTACHMENT_UPLOAD
            end_chunk_index = min(next_chunk, file_size)
            chunk_data = file_data[start_chunk_index:end_chunk_index]
            demisto.debug(f"start_chunk_idx:{start_chunk_index}, end_chunk_idx:{end_chunk_index}")
            response = self.upload_attachment(
                upload_url=upload_url,
                start_chunk_idx=start_chunk_index,
                end_chunk_idx=end_chunk_index,
                chunk_data=chunk_data,
                attachment_size=file_size,
            )
            if response.status_code not in (201, 200, 202):
                raise Exception(f"{response.json()}")
        return response

    def create_an_upload_session(self, uri: str) -> tuple:
        """
        Creates an upload session to the file.

        Args:
            uri (str): uri of the request.
            file_name (str): the name of the file.

        Returns:
            Response: The response to this request, if successful, will provide the details for where the
                      remainder of the requests should be sent as an UploadSession resource.
            Upload_url: A url upload resource.
        """
        request_body = {"item": {"@microsoft.graph.conflictBehavior": "replace"}}
        response = self.ms_client.http_request(method="POST", json_data=request_body, url_suffix=uri)
        return response, response.get("uploadUrl")

    def upload_file_with_upload_session_flow(
        self, object_type: str, object_type_id: str, parent_id: str, file_name: str, file_data: bytes, file_size: int
    ) -> requests.Response:
        """
        Uploads a file with the upload session flow, this is used only when the file is larger
        than 3 MB.

        Args:
            object_type (str): drive/ group/ site/ users
            object_type_id (str): the selected object type id.
            parent_id (str): an ID of the folder to upload the file to.
            file_name (str): file name.
            file_data (bytes): The file data.
            file_size (int): The file size in bytes.
        Returns:
            Response: response indicating whether the operation succeeded. 200 or
                      201 (created) if the file was uploaded completely. 400 in case of errors.
        """
        # create suitable upload session
        uri = ""
        if object_type == "drives":
            uri = f"/drives/{object_type_id}/items/{parent_id}:/{file_name}:/createUploadSession"
        elif object_type == "groups":
            uri = f"/groups/{object_type_id}/drive/items/{parent_id}:/{file_name}:/createUploadSession"
        elif object_type == "sites":
            uri = f"/sites/{object_type_id}/drive/items/{parent_id}:/{file_name}:/createUploadSession"
        elif object_type == "users":
            uri = f"/users/{object_type_id}/drive/items/{parent_id}:/{file_name}:/createUploadSession"
        response, upload_url = self.create_an_upload_session(uri)
        if not upload_url:
            raise Exception(f"Cannot get upload URL for attachment {file_name}")
        demisto.debug(f'Create upload session response": {response}')
        response_file_upload = self.upload_file_with_upload_session(upload_url, file_data, file_size)
        demisto.debug(f'response of "upload_file_with_upload_session": {response}')
        return response_file_upload

    def upload_new_file(self, object_type: str, object_type_id: str, parent_id: str, file_name: str, entry_id: str):
        """
        this function upload new file to a selected folder(parent_id)
        :param object_type: drive/ group/ site/ users
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the folder to upload the file to.
        :param file_name: file name
        :param entry_id: demisto file entry ID.
        :return: graph api raw response.
        """
        file_path: str = demisto.getFilePath(entry_id).get("path", "")
        uri = ""
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{parent_id}:/{file_name}:/content"

        elif object_type in {"groups", "users", "sites"}:
            uri = f"{object_type}/{object_type_id}/drive/items/{parent_id}:/{file_name}:/content"

        with open(file_path, "rb") as file:
            headers = {"Content-Type": "application/octet-stream"}
            return self.ms_client.http_request(method="PUT", headers=headers, url_suffix=uri, data=file)

    def download_file(self, object_type: str, object_type_id: str, item_id: str) -> requests.Response:
        """
        Download the contents of the file of a DriveItem.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param item_id: ms graph item_id.
        :return: graph api raw response
        """
        uri = ""
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{item_id}/content"

        elif object_type in {"groups", "sites", "users"}:
            uri = f"{object_type}/{object_type_id}/drive/items/{item_id}/content"

        return self.ms_client.http_request(method="GET", url_suffix=uri, resp_type="response")

    def create_new_folder(self, object_type: str, object_type_id: str, parent_id: str, folder_name: str) -> dict:
        """
        Create a new folder in a Drive with a specified parent item or path.
        :param object_type: ms graph resource.
        :param object_type_id: the selected object type id.
        :param parent_id: an ID of the parent to upload the folder to.
        :param folder_name: folder name
        :return: graph api raw response
        """
        uri = ""
        if object_type == "drives":
            uri = f"{object_type}/{object_type_id}/items/{parent_id}/children"

        elif object_type in {"groups", "sites", "users"}:
            uri = f"{object_type}/{object_type_id}/drive/items/{parent_id}/children"

        # send request
        payload = {
            "name": folder_name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename",
        }

        return self.ms_client.http_request(method="POST", json_data=payload, url_suffix=uri)


def test_function(client: MsGraphClient) -> str:
    """
    Performs basic get request to get item samples
    """
    response = "ok" if demisto.command() == "test-module" else "```✅ Success!```"
    if (demisto.params().get("self_deployed", False) and demisto.command() == "test-module"
        and (client.ms_client.grant_type == AUTHORIZATION_CODE
             or demisto.params().get("redirect_uri")
             or demisto.params().get("auth_code_creds", {}).get("password", ""))):
        raise DemistoException(
            "The *Test* button is not available for the `self-deployed - Authorization Code Flow`.\n "
            "Use the !msgraph-files-auth-test command instead "
            "once all relevant parameters have been entered."
        )

    client.ms_client.http_request(url_suffix="sites", timeout=7, method="GET")
    return response


def download_file_command(client: MsGraphClient, args: dict[str, str]) -> dict:
    """
    This function runs download file command
    :return: FileResult object
    """
    object_type = args["object_type"]
    object_type_id = args["object_type_id"]
    item_id = args["item_id"]
    file_name = args.get("file_name") or item_id

    result = client.download_file(object_type=object_type, object_type_id=object_type_id, item_id=item_id)
    return fileResult(file_name, result.content)


def list_drive_content_human_readable_object(parsed_drive_items: dict) -> dict:
    return {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedBy": parsed_drive_items.get("CreatedBy", {}).get("DisplayName"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "Description": parsed_drive_items.get("Description"),
        "Size": parsed_drive_items.get("Size"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }


def list_drive_content_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function runs list drive children command
    Note:
        If the response does not contain results,
        the Microsoft Graph API returns a dict with the key `@odata.null` set to true, indicating no data was found.

    :return: human_readable, context, result
    """
    object_type = args["object_type"]
    object_type_id = args["object_type_id"]
    item_id = args.get("item_id", "root")
    limit = args.get("limit")
    next_page_url = args.get("next_page_url")

    result = client.list_drive_content(
        object_type=object_type,
        object_type_id=object_type_id,
        item_id=item_id,
        limit=limit,
        next_page_url=next_page_url,
    )

    title = f"{INTEGRATION_NAME} - drivesItems information:"

    parsed_drive_items = [parse_key_to_context(item) for item in result.get("value", [{}])]
    human_readable_content = [list_drive_content_human_readable_object(item) for item in parsed_drive_items]
    human_readable = tableToMarkdown(title, human_readable_content, headerTransform=pascalToSpace)

    drive_items_outputs = {
        "OdataContext": result["@odata.context"],
        "Value": parsed_drive_items,
    }
    context = {
        f"{INTEGRATION_NAME}.ListChildren(val.ItemID == obj.ItemID)": {
            "ParentID": item_id,
            "Children": drive_items_outputs,
            "NextToken": result.get("@odata.nextLink"),
        }
    }

    return human_readable, context, result


def list_share_point_sites_human_readable_object(parsed_drive_items: dict) -> dict:
    return {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }


def list_sharepoint_sites_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function runs list tenant site command
    :return: human_readable, context, result
    """
    keyword = args.get("keyword", "*")
    result = client.list_sharepoint_sites(keyword)
    parsed_sites_items = [parse_key_to_context(item) for item in result["value"]]

    human_readable_content = [list_share_point_sites_human_readable_object(item) for item in parsed_sites_items]

    context_entry = {
        "OdataContext": result.get("@odata.context"),
        "Value": parsed_sites_items,
    }
    context = {f"{INTEGRATION_NAME}.ListSites(val.ID === obj.ID)": context_entry}

    title = "List Sites:"
    human_readable = tableToMarkdown(title, human_readable_content, headerTransform=pascalToSpace)

    return human_readable, context, result


def list_drives_human_readable_object(parsed_drive_items: dict) -> dict:
    return {
        "Name": parsed_drive_items.get("Name"),
        "ID": parsed_drive_items.get("ID"),
        "CreatedBy": parsed_drive_items.get("CreatedBy", {}).get("DisplayName"),
        "CreatedDateTime": parsed_drive_items.get("CreatedDateTime"),
        "Description": parsed_drive_items.get("Description"),
        "DriveType": parsed_drive_items.get("DriveType"),
        "LastModifiedDateTime": parsed_drive_items.get("LastModifiedDateTime"),
        "WebUrl": parsed_drive_items.get("WebUrl"),
    }


def list_drives_in_site_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function run the list drives in site command
    :return: human_readable, context, result
    """
    site_id = args.get("site_id")
    limit = args.get("limit")
    next_page_url = args.get("next_page_url")

    if next_page_url:
        url_validation(next_page_url)

    result = client.list_drives_in_site(site_id=site_id, limit=limit, next_page_url=next_page_url)
    parsed_drive_items = [parse_key_to_context(item) for item in result["value"]]

    human_readable_content = [list_drives_human_readable_object(item) for item in parsed_drive_items]

    context_entry = {
        "OdataContext": result.get("@odata.context"),
        "Value": parsed_drive_items,
        "NextToken": result.get("@odata.nextLink"),
    }

    title = f"{INTEGRATION_NAME} - Drives information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, human_readable_content, headerTransform=pascalToSpace)

    # context == output
    context = {f"{INTEGRATION_NAME}.ListDrives(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def replace_an_existing_file_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function runs the replace existing file command
    :return: human_readable, context, result
    """
    object_type = args["object_type"]
    item_id = args["item_id"]
    entry_id = args["entry_id"]
    object_type_id = args["object_type_id"]
    file_data, file_size, file_name = read_file(entry_id)
    if file_size < client.MAX_ATTACHMENT_SIZE:
        result = client.replace_existing_file(object_type, object_type_id, item_id, entry_id)
    else:
        result = client.replace_existing_file_with_upload_session(
            object_type, object_type_id, item_id, entry_id, file_data, file_size, file_name
        )
        result = result.json()
        demisto.debug(f"Response replace large existing file: \n {result} \n")
    context_entry = parse_key_to_context(result)

    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy", {}).get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime", {}),
        "LastModifiedBy": context_entry.get("LastModifiedBy", {}).get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }
    remove_nulls_from_dictionary(human_readable_content)
    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, human_readable_content, headerTransform=pascalToSpace)

    # context == output
    context = {f"{INTEGRATION_NAME}.ReplacedFiles(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def read_file(attach_id: str) -> tuple[bytes, int, str]:
    """
    Reads file that was uploaded to War Room.

    Args:
        attach_id (str): The id of uploaded file to War Room.

    Returns:
        file_data (bytes): The file data.
        file_size (int): The size of the file in bytes.
        file_name (str): Uploaded file name.
    """
    try:
        file_info = demisto.getFilePath(attach_id)
        with open(file_info["path"], "rb") as file_data:
            file_data_read = file_data.read()
            file_size = os.path.getsize(file_info["path"])
            return file_data_read, file_size, file_info["name"]
    except Exception as e:
        raise Exception(f"Unable to read and decode in base 64 file with id {attach_id}", e) from e


def upload_new_file_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function uploads new file to graph api
    :return: human_readable, context, result
    """
    object_type = args["object_type"]
    object_type_id = args["object_type_id"]
    parent_id = args["parent_id"]
    entry_id = args["entry_id"]
    file_data, file_size, _ = read_file(entry_id)
    file_name = args["file_name"]

    if file_size < client.MAX_ATTACHMENT_SIZE:
        result = client.upload_new_file(object_type, object_type_id, parent_id, file_name, entry_id)
    else:
        result = client.upload_file_with_upload_session_flow(
            object_type, object_type_id, parent_id, file_name, file_data, file_size
        )
        result = result.json()
        demisto.debug(f"Response large file upload: \n {result} \n")
    context_entry = parse_key_to_context(result)
    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy", {}).get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime"),
        "LastModifiedBy": context_entry.get("LastModifiedBy", {}).get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }
    remove_nulls_from_dictionary(human_readable_content)
    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, human_readable_content)

    # context == output
    context = {f"{INTEGRATION_NAME}.UploadedFiles(val.ID === obj.ID)": context_entry}
    return human_readable, context, result


def create_new_folder_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    This function runs create new folder command
    :return: human_readable, context, result
    """
    object_type = args["object_type"]
    parent_id = args["parent_id"]
    folder_name = args["folder_name"]
    object_type_id = args["object_type_id"]

    result = client.create_new_folder(object_type, object_type_id, parent_id, folder_name)

    context_entry = parse_key_to_context(result)

    human_readable_content = {
        "ID": context_entry.get("ID"),
        "Name": context_entry.get("Name"),
        "CreatedBy": context_entry.get("CreatedBy", {}).get("DisplayName"),
        "CreatedDateTime": context_entry.get("CreatedDateTime"),
        "ChildCount": context_entry.get("Folder"),
        "LastModifiedBy": context_entry.get("LastModifiedBy", {}).get("DisplayName"),
        "Size": context_entry.get("Size"),
        "WebUrl": context_entry.get("WebUrl"),
    }
    title = f"{INTEGRATION_NAME} - Folder information:"
    # Creating human readable for War room

    human_readable = tableToMarkdown(title, human_readable_content, headerTransform=pascalToSpace)

    # context == output
    context = {f"{INTEGRATION_NAME}.CreatedFolders(val.ID === obj.ID)": context_entry}

    return human_readable, context, result


def delete_file_command(client: MsGraphClient, args: dict[str, str]) -> tuple[str, str]:
    """
    runs delete file command
    :return: raw response and action result test
    """
    object_type = args["object_type"]
    item_id = args["item_id"]
    object_type_id = args["object_type_id"]

    text = client.delete_file(object_type, object_type_id, item_id)

    context_entry = text

    title = f"{INTEGRATION_NAME} - File information:"
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry, headers=item_id)

    return human_readable, text  # == raw response


def get_site_id_from_site_name(client: MsGraphClient, site_name: str | None) -> str:
    """
    Retrieves the SharePoint site ID based on either the provided site ID or site name.

    Args:
        client (MsGraphClient): An instance of the Microsoft Graph client.
        site_name (Optional[str]): The name of the SharePoint site.

    Returns:
        str: The SharePoint site ID.

    Raises:
        DemistoException: If neither site_id nor site_name is provided.
        DemistoException: If the user has no permission to the site, the API returns a 404 error.
        DemistoException: If the provided site name is invalid.
    """
    if site_name:
        try:
            site_details = client.list_sharepoint_sites(site_name)["value"]
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 404 and "Item not found" in e.res.text:
                raise DemistoException(
                    f"Error getting site ID for {site_name}."
                    f" Ensure integration instance has permission for this site and site name is valid. Error details: {e}"
                ) from e
            raise
        if site_details:
            return site_details[0]["id"]
        else:
            raise DemistoException(f"Site '{site_name}' not found. Please provide a valid site name.")

    raise DemistoException("Please provide 'site_id' or 'site_name' parameter.")


def _md_parse_permission(permission: dict) -> dict:
    """Parses a permission dictionary into an output format.

    Args:
        permission: (dict) The permission dictionary to parse.

    Returns:
        dict: The parsed permission dictionary.

    Example:
    ```
    >>> permission =  {
                "id": "123",
                "roles": ["role1", "role2"],
                "grantedToIdentitiesV2": [{
                    "application": {
                        "displayName": "app1",
                        "id": "456"
                    }
                }]
            }
    >>> permission_md = _md_parse_permission(permission)
    >>> permission_md
        {
            "ID": "123",
            "Roles": ["role1", "role2"],
            "Application Name": ["app1"],
            "Application ID": ["456"]
        }
    ```

    """
    identities: list[dict[str, dict[str, str]]] = permission.get("grantedToIdentitiesV2", [{}])
    return {
        "ID": permission.get("id"),
        "Roles": permission.get("roles"),
        "Application Name": [identity.get("application", {}).get("displayName") for identity in identities],
        "Application ID": [identity.get("application", {}).get("id") for identity in identities],
    }


def list_site_permissions_command(client: MsGraphClient, args: dict[str, str]) -> CommandResults:
    """Lists permissions for a SharePoint site.

    Args:
        client (MsGraphClient): The Microsoft Graph client.
        args (dict): The command arguments.
            permission_id (Optional): The unique identifier for the permission.
            limit (Optional): Number of items to return. Default is 50.
            all_results (Optional): Return all results. Default is False.
            site_name (Optional): The display name of the site. Either site_id or site_name is required.
            site_id (Optional): The unique identifier for the site. Either site_id or site_name is required.

    Returns:
        CommandResults: The command results with outputs and readable output.
    """
    permission_id = args.get("permission_id")
    limit = arg_to_number(args.get("limit", 50))
    all_results = argToBoolean(args.get("all_results", False))
    site_id = args.get("site_id") or get_site_id_from_site_name(client, args.get("site_name"))
    results = client.list_site_permissions(site_id, permission_id)

    if permission_id:
        return CommandResults(
            outputs_prefix="MsGraphFiles.SitePermission",
            outputs_key_field="id",
            outputs=results,
            readable_output=tableToMarkdown(name="Site Permission", t=_md_parse_permission(results)),
        )

    list_permissions = results.get("value", [])
    return CommandResults(
        outputs_prefix="MsGraphFiles.SitePermission",
        outputs_key_field="id",
        outputs=list_permissions if all_results else list_permissions[:limit],
        readable_output=tableToMarkdown(
            name="Site Permission", t=[_md_parse_permission(permission) for permission in list_permissions], removeNull=True
        ),
    )


def create_site_permissions_command(client: MsGraphClient, args: dict[str, str]) -> CommandResults:
    """Creates a new permission for a SharePoint site.

    Args:
        client (MsGraphClient): The Microsoft Graph client.

        args (dict): The command arguments.
            app_id (Required): The app ID to assign permissions to.
            role (Required): The role(s) to assign. Can be "read", "write", or "owner".
            display_name (Required): The display name for the permission.
            site_name (Optional): The display name of the site. Either site_id or site_name is required.
            site_id (Optional): The unique identifier for the site. Either site_id or site_name is required.

    Returns:
        CommandResults: The results including the new permission that was created.

    """
    app_id = args["app_id"]
    role = argToList(args["role"])
    display_name = args["display_name"]
    site_id = args.get("site_id") or get_site_id_from_site_name(client, args.get("site_name"))

    results = client.create_site_permission(site_id, app_id, display_name, role)

    return CommandResults(
        outputs_prefix="MsGraphFiles.SitePermission",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("Site Permission", t=_md_parse_permission(results)),
    )


def update_site_permissions_command(client: MsGraphClient, args: dict[str, str]) -> CommandResults:
    """Updates the permissions for a SharePoint site.

    Args:
        client (MsGraphClient): The Microsoft Graph client.
        args (dict): The command arguments.
            permission_id (Required): The ID of the permission to update.
            role (Required): The updated role(s) for the permission. read/write/owner.
            site_name (Optional): The display name of the site. Either site_id or site_name is required.
            site_id (Optional): The unique identifier for the site. Either site_id or site_name is required.

    Returns:
        CommandResults: The command results with readable output.

    """
    permission_id = args["permission_id"]
    role = argToList(args["role"])
    site_id = args.get("site_id") or get_site_id_from_site_name(client, args.get("site_name"))

    results = client.update_site_permission(site_id, permission_id, role)

    return CommandResults(
        readable_output=(
            f"Permission {permission_id} of site {site_id} was updated successfully with new role {results['roles']}."
        )
    )


def delete_site_permission_command(client: MsGraphClient, args: dict[str, str]) -> CommandResults:
    """Deletes a permission from a SharePoint site.

    Args:
        client (MsGraphClient): The Microsoft Graph client.
        args (dict): The command arguments.
            permission_id (Required): The ID of the permission to delete.
            site_name (Optional): The display name of the site. Either site_id or site_name is required.
            site_id (Optional): The unique identifier for the site. Either site_id or site_name is required.

    Returns:
        CommandResults: The command results with readable output.

    """
    permission_id = args["permission_id"]
    site_id = args.get("site_id") or get_site_id_from_site_name(client, args.get("site_name"))

    client.delete_site_permission(site_id, permission_id)
    return CommandResults(readable_output="Site permission was deleted.")


def main():
    params: dict = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url: str = params.get("host", "").rstrip("/") + "/v1.0/"
    tenant = params.get("credentials_tenant_id", {}).get("password") or params.get("tenant_id")
    auth_id = params.get("credentials_auth_id", {}).get("password") or params.get("auth_id")
    enc_key = params.get("credentials_enc_key", {}).get("password") or params.get("enc_key")
    use_ssl: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)
    ok_codes: tuple = (200, 204, 201)
    certificate_thumbprint = params.get("credentials_certificate_thumbprint", {}).get("password") or params.get(
        "certificate_thumbprint"
    )
    private_key = params.get("private_key")
    managed_identities_client_id: Optional[str] = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get("self_deployed", False) or managed_identities_client_id is not None
    auth_code = params.get("auth_code_creds", {}).get("password", "")
    redirect_uri = params.get("redirect_uri", "")

    try:
        client = MsGraphClient(
            base_url=base_url,
            tenant_id=tenant,
            auth_id=auth_id,
            enc_key=enc_key,
            app_name=APP_NAME,
            verify=use_ssl,
            proxy=proxy,
            self_deployed=self_deployed,
            ok_codes=ok_codes,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
        )

        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_function(client))
        elif command == "msgraph-files-auth-test":
            return_results(test_function(client))
        elif command == "msgraph-files-generate-login-url":
            return_results(generate_login_url(client.ms_client))
        elif command == "msgraph-files-auth-reset":
            return_results(reset_auth())
        elif command == "msgraph-delete-file":
            readable_output, raw_response = delete_file_command(client, args)
            return_outputs(readable_output=readable_output, raw_response=raw_response)
        elif command == "msgraph-list-sharepoint-sites":
            return_outputs(*list_sharepoint_sites_command(client, args))
        elif command == "msgraph-download-file":
            # it has to be demisto.results instead of return_outputs.
            # because fileResult contains 'content': '' and if that key is empty return_outputs returns error.
            demisto.results(download_file_command(client, args))
        elif command == "msgraph-list-drive-content":
            return_outputs(*list_drive_content_command(client, args))
        elif command == "msgraph-create-new-folder":
            return_outputs(*create_new_folder_command(client, args))
        elif command == "msgraph-replace-existing-file":
            return_outputs(*replace_an_existing_file_command(client, args))
        elif command == "msgraph-list-drives-in-site":
            return_outputs(*list_drives_in_site_command(client, args))
        elif command == "msgraph-upload-new-file":
            return_outputs(*upload_new_file_command(client, args))
        elif command == "msgraph-list-site-permissions":
            return_results(list_site_permissions_command(client, args))
        elif command == "msgraph-create-site-permissions":
            return_results(create_site_permissions_command(client, args))
        elif command == "msgraph-update-site-permissions":
            return_results(update_site_permissions_command(client, args))
        elif command == "msgraph-delete-site-permissions":
            return_results(delete_site_permission_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
