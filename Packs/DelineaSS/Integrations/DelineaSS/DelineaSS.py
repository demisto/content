import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, server_url: str, username: str, password: str, proxy: bool, verify: bool):
        super().__init__(base_url=server_url, proxy=proxy, verify=verify)
        self._username = username
        self._password = password
        self._token = self._generate_token()
        self._headers = {"Authorization": self._token, "Content-Type": "application/json"}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {"username": self._username, "password": self._password, "grant_type": "password"}

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        return "Bearer " + (self._http_request("POST", "/oauth2/token", headers=headers, data=body)).get("access_token")

    def getPasswordById(self, secret_id: str, autoComment: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        params = {"autoComment": autoComment}
        return self._http_request("GET", url_suffix, params=params)

    def getUsernameById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/username"
        return self._http_request("GET", url_suffix)

    def getSecret(self, secret_id: str, autocommit: str = "") -> str:
        params = {"autocomment": autocommit}
        url_suffix = "/api/v1/secrets/" + str(secret_id)
        return self._http_request("GET", url_suffix, params=params)

    def searchSecretIdByName(self, search_name: str) -> list:
        url_suffix = "/api/v1/secrets/lookup?filter.searchText=" + search_name
        response = self._http_request("GET", url_suffix).get("records")
        idSecret = argToList(response)
        search_id = []

        if idSecret:
            for element in idSecret:
                getID = element.get("id")
                search_id.append(getID)

        return search_id

    def searchSecret(self, **kwargs) -> list:
        count_params = len(kwargs)
        params = {}
        if count_params > 0:
            for key, value in kwargs.items():
                key = key.replace("_", ".")
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        response = self._http_request("GET", url_suffix="/api/v1/secrets", params=params).get("records")
        idSecret = [id_obj.get("id") for id_obj in response]
        return idSecret

    def updateSecretPassword(self, secret_id: str, new_password: str, auto_comment: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        body = {"id": secret_id, "value": new_password}
        params = {"autoComment": auto_comment}
        return self._http_request("PUT", url_suffix, params=params, json_data=body)

    def secret_checkout(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-out"
        return self._http_request("POST", url_suffix)

    def secret_checkin(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-in"

        return self._http_request("POST", url_suffix)

    def secretChangePassword(self, secret_id: str, newPassword: str, autoComment: str) -> str:
        body = {"newPassword": newPassword}
        params = {"autoComment": autoComment}

        return self._http_request(
            "POST", url_suffix="/api/v1/secrets/" + str(secret_id) + "/change-password", params=params, json_data=body
        )

    def secretCreate(self, name: str, secret_template_id: str, **kwargs) -> str:
        secretjson = {"name": name, "secretTemplateId": secret_template_id, "items": []}  # type: Dict[str, Any]

        for key, value in kwargs.items():
            JSON = {}
            if key == "domain_item":
                JSON["fieldName"] = "Domain"
                JSON["itemValue"] = value
                JSON["slug"] = "domain"
                secretjson["items"].append(JSON)

            elif key == "machine_item":
                JSON["fieldName"] = "Machine"
                JSON["itemValue"] = value
                JSON["slug"] = "machine"
                secretjson["items"].append(JSON)

            elif key == "username_item":
                JSON["fieldName"] = "Username"
                JSON["itemValue"] = value
                JSON["slug"] = "username"
                secretjson["items"].append(JSON)

            elif key == "password_item":
                JSON["fieldName"] = "Password"
                JSON["itemValue"] = value
                JSON["slug"] = "password"
                JSON["isPassword"] = "true"
                secretjson["items"].append(JSON)

            elif key == "notes_item":
                JSON["fieldName"] = "Notes"
                JSON["itemValue"] = value
                JSON["slug"] = "notes"
                JSON["isNotes"] = "true"
                secretjson["items"].append(JSON)

            else:
                secretjson[key] = value

        return self._http_request("POST", url_suffix="/api/v1/secrets", json_data=secretjson)

    def secretDelete(self, id: int, auto_comment: str) -> str:
        params = {"autoComment": auto_comment}

        return self._http_request("DELETE", url_suffix="/api/v1/secrets/" + str(id), params=params)

    def folderCreate(self, name: str, type: int, parent: int, **kwargs) -> str:
        url_suffix = "/api/v1/folders"

        body = {
            "folderName": name,
            "folderTypeId": type,
            "parentFolderId": parent,
        }

        for key, value in kwargs.items():
            body[key] = value
        return self._http_request("POST", url_suffix, json_data=body)

    def searchFolder(self, search_folder: str) -> list:
        url_suffix = "/api/v1/folders/lookup?filter.searchText=" + search_folder

        response_records = self._http_request("GET", url_suffix).get("records")
        idfolder = [x.get("id") for x in response_records]
        return idfolder

    def folderDelete(self, folder_id: str) -> str:
        url_suffix = "/api/v1/folders/" + folder_id

        return self._http_request("DELETE", url_suffix)

    def folderUpdate(self, id: str, **kwargs) -> str:
        # Get exist folder
        response = self._http_request("GET", url_suffix="/api/v1/folders/" + str(id))

        for key, value in kwargs.items():
            response[key] = value
        return self._http_request("PUT", url_suffix="/api/v1/folders/" + str(id), json_data=response)

    def userCreate(self, **kwargs) -> str:
        bodyJSON = {}

        for key, value in kwargs.items():
            bodyJSON[key] = value

        return self._http_request("POST", url_suffix="/api/v1/users", json_data=bodyJSON)

    def userSearch(self, **kwargs) -> str:
        params = {}
        count_params = len(kwargs)
        if count_params > 0:
            for key, value in kwargs.items():
                key = key.replace("_", ".")
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        return (self._http_request("GET", url_suffix="/api/v1/users", params=params)).get("records")

    def userUpdate(self, id: str, **kwargs) -> str:
        response = self._http_request("GET", url_suffix="/api/v1/users/" + str(id))

        for key, value in kwargs.items():
            response[key] = value

        return self._http_request("PUT", url_suffix="/api/v1/users/" + str(id), json_data=response)

    def userDelete(self, id: str) -> str:
        return self._http_request("DELETE", url_suffix="/api/v1/users/" + str(id))


def test_module(client) -> str:
    # Test for get authority
    if client._token == "":
        return "Failed to get authorization token. Check you credential and access to Secret Server.'"

    return "ok"


def secret_password_get_command(client, secret_id: str = "", autoComment: str = ""):
    secret_password = client.getPasswordById(secret_id, autoComment)
    markdown = tableToMarkdown("Password for secret", {"Secret ID": secret_id, "Password": secret_password})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Password",
        outputs_key_field="secret_password",
        raw_response=secret_password,
        outputs=secret_password,
    )


def secret_username_get_command(client, secret_id: str = ""):
    secret_username = client.getUsernameById(secret_id)
    markdown = tableToMarkdown("Username for secret", {"Secret ID": secret_id, "Password": secret_username})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Username",
        outputs_key_field="secret_username",
        raw_response=secret_username,
        outputs=secret_username,
    )


def secret_get_command(client, secret_id: str = "", autoComment: str = ""):
    secret = client.getSecret(secret_id, autoComment)
    markdown = tableToMarkdown("Full secret object", secret)
    markdown += tableToMarkdown("Items for secret", secret["items"])

    return CommandResults(
        readable_output=markdown, outputs_prefix="Delinea.Secret", outputs_key_field="secret", raw_response=secret, outputs=secret
    )


def secret_search_name_command(client, search_name: str = ""):
    search_id = client.searchSecretIdByName(search_name)
    markdown = tableToMarkdown("Retrieves IDs for secret name", search_id, headers=["Secret id"])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Id",
        outputs_key_field="search_id",
        raw_response=search_id,
        outputs=search_id,
    )


def secret_search_command(client, **kwargs):
    search_result = client.searchSecret(**kwargs)
    markdown = tableToMarkdown("Search secret", search_result, headers=["id"])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Secret",
        outputs_key_field="search_secret",
        raw_response=search_result,
        outputs=search_result,
    )


def secret_password_update_command(client, secret_id: str = "", newpassword: str = "", autoComment: str = ""):
    secret_newpassword = client.updateSecretPassword(secret_id, newpassword, autoComment)
    markdown = tableToMarkdown("Set new password for secret", {"Secret ID": secret_id, "New password": newpassword})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Newpassword",
        outputs_key_field="secret_newpassword",
        raw_response=secret_newpassword,
        outputs=secret_newpassword,
    )


def secret_checkout_command(client, secret_id: str = ""):
    secret_checkout = client.secret_checkout(secret_id)
    if len(secret_checkout.get("responseCodes")) == 0:
        markdown = "Checkout Success\n"
    else:
        markdown = tableToMarkdown("Check Out Secret", secret_checkout)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Checkout",
        outputs_key_field="secret_checkout",
        raw_response=secret_checkout,
        outputs=secret_checkout,
    )


def secret_checkin_command(client, secret_id: str = ""):
    secret_checkin = client.secret_checkin(secret_id)
    markdown = tableToMarkdown("Check In Secret", secret_checkin)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Checkin",
        outputs_key_field="secret_checkin",
        raw_response=secret_checkin,
        outputs=secret_checkin,
    )


def secret_create_command(client, name: str = "", secretTemplateId: int = 0, **kwargs):
    secret = client.secretCreate(name, secretTemplateId, **kwargs)
    markdown = tableToMarkdown("Created new secret", secret)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Create",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret,
    )


def secret_delete_command(client, id: int = 0, autoComment: str = ""):
    delete = client.secretDelete(id, autoComment)
    markdown = tableToMarkdown("Deleted secret", delete)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Deleted",
        outputs_key_field="delete",
        raw_response=delete,
        outputs=delete,
    )


def folder_create_command(client, foldername: str = "", foldertypeid: int = 1, parentfolderid: int = 1, **kwargs):
    folder = client.folderCreate(foldername, foldertypeid, parentfolderid, **kwargs)
    markdown = tableToMarkdown("Created new folder", folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Create",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder,
    )


def folder_search_command(client, foldername: str = ""):
    folder_id = client.searchFolder(foldername)
    markdown = tableToMarkdown("Search folder", folder_id, headers=["id"])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Id",
        outputs_key_field="folder_id",
        raw_response=folder_id,
        outputs=folder_id,
    )


def folder_update_command(client, id: str = "", **kwargs):
    folder = client.folderUpdate(id, **kwargs)
    markdown = tableToMarkdown("Updated folder", folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Update",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder,
    )


def folder_delete_command(client, folder_id: str = ""):
    folder = client.folderDelete(folder_id)
    markdown = tableToMarkdown("Deleted folder", folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Folder.Delete",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder,
    )


def user_create_command(client, **kwargs):
    user = client.userCreate(**kwargs)
    markdown = tableToMarkdown("Created new user", user)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Delinea.User.Create", outputs_key_field="user", raw_response=user, outputs=user
    )


def user_search_command(client, **kwargs):
    user = client.userSearch(**kwargs)
    markdown = tableToMarkdown("Search user", user)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Delinea.User.Search", outputs_key_field="user", raw_response=user, outputs=user
    )


def user_update_command(client, id: str = "", **kwargs):
    user = client.userUpdate(id, **kwargs)
    markdown = tableToMarkdown("Updated user", user)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Delinea.User.Update", outputs_key_field="user", raw_response=user, outputs=user
    )


def user_delete_command(client, id: str = ""):
    user = client.userDelete(id)
    markdown = tableToMarkdown("Deleted user", user)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Delinea.User.Delete", outputs_key_field="user", raw_response=user, outputs=user
    )


def secret_rpc_changepassword_command(client, secret_id: str = "", newpassword: str = "", autoComment: str = ""):
    secret = client.secretChangePassword(secret_id, newpassword, autoComment)
    markdown = tableToMarkdown("Change password for remote machine", secret)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.ChangePassword",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret,
    )


def get_credentials(client, secret_id):
    obj = {}
    secret = client.getSecret(secret_id, "XSOAR Fetch Credential")
    items = secret.get("items")
    username = None
    password = None
    for item in items:
        if item.get("fieldName") == "Username":
            username = item.get("itemValue")
        if item.get("fieldName") == "Password":
            password = item.get("itemValue")
        obj = {"user": username, "password": password, "name": str(secret.get("id"))}
    return obj


def fetch_credentials_command(client, secretids):
    credentials: List[Any] = []
    args: dict = demisto.args()
    credentials_name: Any = args.get("identifier")

    try:
        secretsid = argToList(secretids)
    except Exception as e:
        demisto.debug(f"Could not fetch credentials: Provide valid secret id.{e}")
        credentials = []

    for id in secretsid:
        if id not in secretsid:
            secretsid.append(id)

    if len(secretsid) == 0:
        demisto.credentials(credentials)
        demisto.debug(
            "Could not fetch credentials: Enter valid secret ID to fetch credentials.\n For multiple ID use ,(e.g. 1,2)"
        )
        credentials = []
    else:
        if credentials_name:
            try:
                credentials = [get_credentials(client, credentials_name)]
            except Exception as e:
                demisto.debug(f"Could not fetch credentials: {credentials_name}. Error: {e}")
                credentials = []
        else:
            for secret_id in secretsid:
                obj = get_credentials(client, secret_id)
                credentials.append(obj)

    demisto.credentials(credentials)
    markdown = tableToMarkdown("Fetched Credentials", credentials)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Delinea.Secret.Fetch.Credentials",
        outputs_key_field="credentials",
        raw_response=credentials,
        outputs=credentials,
    )


def main():
    params = demisto.params()

    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    # get the service API url
    url = params.get("url")
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    secretids = params.get("secrets")

    demisto.info(f"Command being called is {demisto.command()}")

    delinea_commands = {
        "delinea-secret-password-get": secret_password_get_command,
        "delinea-secret-username-get": secret_username_get_command,
        "delinea-secret-get": secret_get_command,
        "delinea-secret-search-name": secret_search_name_command,
        "delinea-secret-search": secret_search_command,
        "delinea-secret-password-update": secret_password_update_command,
        "delinea-secret-checkout": secret_checkout_command,
        "delinea-secret-checkin": secret_checkin_command,
        "delinea-secret-create": secret_create_command,
        "delinea-secret-delete": secret_delete_command,
        "delinea-secret-rpc-changepassword": secret_rpc_changepassword_command,
        "delinea-folder-create": folder_create_command,
        "delinea-folder-search": folder_search_command,
        "delinea-folder-update": folder_update_command,
        "delinea-folder-delete": folder_delete_command,
        "delinea-user-create": user_create_command,
        "delinea-user-search": user_search_command,
        "delinea-user-update": user_update_command,
        "delinea-user-delete": user_delete_command,
    }
    command = demisto.command()
    try:
        client = Client(server_url=url, username=username, password=password, proxy=proxy, verify=verify)
        if command in delinea_commands:
            return_results(
                delinea_commands[command](client, **demisto.args())  # type: ignore[operator]
            )
        if command == "fetch-credentials":
            return_results(fetch_credentials_command(client, secretids))
        elif command == "test-module":
            result = test_module(client)
            demisto.results(result)
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
