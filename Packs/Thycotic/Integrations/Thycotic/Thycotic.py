import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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
        self._headers = {'Authorization': self._token, 'Content-Type': 'application/json'}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            "username": self._username,
            "password": self._password,
            "grant_type": "password"
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return "Bearer " + (self._http_request("POST", "/oauth2/token", headers=headers, data=body)).get('access_token')

    def getPasswordById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        return self._http_request("GET", url_suffix)

    def getUsernameById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/username"
        return self._http_request("GET", url_suffix)

    def getSecret(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id)

        return self._http_request("GET", url_suffix)

    def searchSecretIdByName(self, search_name: str) -> list:
        url_suffix = "/api/v1/secrets/lookup?filter.searchText=" + search_name
        response = self._http_request("GET", url_suffix).get('records')
        idSecret = argToList(response)
        search_id = []

        if len(idSecret) != 0:
            for element in idSecret:
                getID = element.get('id')
                search_id.append(getID)

        return search_id

    def searchSecret(self, **kwargs) -> list:
        count_params = len(kwargs)
        params = {}
        if count_params > 0:
            for key, value in kwargs.items():
                key = key.replace('_', '.')
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        response = self._http_request("GET", url_suffix="/api/v1/secrets", params=params).get("records")
        idSecret = list(map(lambda x: x.get('id'), response))
        return idSecret

    def updateSecretPassword(self, secret_id: str, newpassword: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/fields/password"
        body = {
            "id": secret_id,
            "value": newpassword
        }
        return self._http_request("PUT", url_suffix, json_data=body)

    def secret_checkout(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-out"
        return self._http_request("POST", url_suffix)

    def secret_checkin(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + str(secret_id) + "/check-in"

        return self._http_request("POST", url_suffix)

    def secretChangePassword(self, secret_id: str, newPassword: str) -> str:
        body = {
            "newPassword": newPassword
        }

        return self._http_request("POST", url_suffix="/api/v1/secrets/" + str(secret_id) + "/change-password", json_data=body)

    def secretCreate(self, name: str, secretTemplateId: str, **kwargs) -> str:
        secretJSON = {'name': name, 'secretTemplateId': secretTemplateId, 'items': []}  # type: Dict[str, Any]

        for key, value in kwargs.items():
            JSON = {}
            if key == 'domain_item':
                JSON['fieldName'] = 'Domain'
                JSON['itemValue'] = value
                JSON['slug'] = 'domain'
                secretJSON['items'].append(JSON)

            elif key == 'machine_item':
                JSON['fieldName'] = 'Machine'
                JSON['itemValue'] = value
                JSON['slug'] = 'machine'
                secretJSON['items'].append(JSON)

            elif key == 'username_item':
                JSON['fieldName'] = 'Username'
                JSON['itemValue'] = value
                JSON['slug'] = 'username'
                secretJSON['items'].append(JSON)

            elif key == 'password_item':
                JSON['fieldName'] = 'Password'
                JSON['itemValue'] = value
                JSON['slug'] = 'password'
                JSON['isPassword'] = "true"
                secretJSON['items'].append(JSON)

            elif key == 'notes_item':
                JSON['fieldName'] = 'Notes'
                JSON['itemValue'] = value
                JSON['slug'] = 'notes'
                JSON['isNotes'] = "true"
                secretJSON['items'].append(JSON)

            else:
                secretJSON[key] = value

        return self._http_request("POST", url_suffix="/api/v1/secrets", json_data=secretJSON)

    def secretDelete(self, id: int) -> str:
        return self._http_request("DELETE", url_suffix="/api/v1/secrets/" + str(id))

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

        responseRecords = self._http_request("GET", url_suffix).get('records')
        idFolder = list(map(lambda x: x.get('id'), responseRecords))
        return idFolder

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
                key = key.replace('_', '.')
                key = key.replace("sortBy_", "sortBy[0]_")
                params[key] = value

        return (self._http_request("GET", url_suffix="/api/v1/users", params=params)).get('records')

    def userUpdate(self, id: str, **kwargs) -> str:
        response = self._http_request("GET", url_suffix="/api/v1/users/" + str(id))

        for key, value in kwargs.items():
            response[key] = value

        return self._http_request("PUT", url_suffix="/api/v1/users/" + str(id), json_data=response)

    def userDelete(self, id: str) -> str:
        return self._http_request("DELETE", url_suffix="/api/v1/users/" + str(id))


def test_module(client) -> str:
    # Test for get authority
    if client._token == '':
        return "Failed to get authorization token. Check you credential and access to Secret Server.'"

    return "ok"


def secret_password_get_command(client, secret_id: str = ''):
    secret_password = client.getPasswordById(secret_id)

    markdown = tableToMarkdown('Password for secret',
                               {'Secret ID': secret_id, 'Password': secret_password})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Thycotic.Secret.Password',
        outputs_key_field="secret_password",
        raw_response=secret_password,
        outputs=secret_password
    )


def secret_username_get_command(client, secret_id: str = ''):
    secret_username = client.getUsernameById(secret_id)

    markdown = tableToMarkdown('Username for secret',
                               {'Secret ID': secret_id, 'Password': secret_username})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Thycotic.Secret.Username',
        outputs_key_field="secret_username",
        raw_response=secret_username,
        outputs=secret_username
    )


def secret_get_command(client, secret_id: str = ''):
    secret = client.getSecret(secret_id)

    markdown = tableToMarkdown('Full secret object', secret)
    markdown += tableToMarkdown('Items for secret', secret['items'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Thycotic.Secret',
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def secret_search_name_command(client, search_name: str = ''):
    search_id = client.searchSecretIdByName(search_name)
    markdown = tableToMarkdown('Retrieves IDs for secret name', search_id, headers=['Secret id'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Id",
        outputs_key_field="search_id",
        raw_response=search_id,
        outputs=search_id
    )


def secret_search_command(client, **kwargs):
    search_result = client.searchSecret(**kwargs)
    markdown = tableToMarkdown('Search secret', search_result, headers=['id'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Secret",
        outputs_key_field="search_secret",
        raw_response=search_result,
        outputs=search_result
    )


def secret_password_update_command(client, secret_id: str = '', newpassword: str = ''):
    secret_newpassword = client.updateSecretPassword(secret_id, newpassword)

    markdown = tableToMarkdown('Set new password for secret',
                               {'Secret ID': secret_id, 'New password': newpassword})

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Newpassword",
        outputs_key_field="secret_newpassword",
        raw_response=secret_newpassword,
        outputs=secret_newpassword
    )


def secret_checkout_command(client, secret_id: str = ''):
    secret_checkout = client.secret_checkout(secret_id)

    markdown = tableToMarkdown('Check Out Secret', secret_checkout)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Checkout",
        outputs_key_field="secret_checkout",
        raw_response=secret_checkout,
        outputs=secret_checkout
    )


def secret_checkin_command(client, secret_id: str = ''):
    secret_checkin = client.secret_checkin(secret_id)
    markdown = tableToMarkdown('Check In Secret', secret_checkin)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Checkin",
        outputs_key_field="secret_checkin",
        raw_response=secret_checkin,
        outputs=secret_checkin
    )


def secret_create_command(client, name: str = '', secretTemplateId: int = 0, **kwargs):
    secret = client.secretCreate(name, secretTemplateId, **kwargs)
    markdown = tableToMarkdown('Created new secret', secret)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Create",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def secret_delete_command(client, id: int = 0):
    delete = client.secretDelete(id)
    markdown = tableToMarkdown('Deleted secret', delete)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.Deleted",
        outputs_key_field="delete",
        raw_response=delete,
        outputs=delete
    )


def folder_create_command(client, foldername: str = '', foldertypeid: int = 1, parentfolderid: int = 1, **kwargs):
    folder = client.folderCreate(foldername, foldertypeid, parentfolderid, **kwargs)

    markdown = tableToMarkdown('Created new folder', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Folder.Create",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def folder_search_command(client, foldername: str = ''):
    folder_id = client.searchFolder(foldername)
    markdown = tableToMarkdown('Search folder', folder_id, headers=['id'])

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Folder.Id",
        outputs_key_field="folder_id",
        raw_response=folder_id,
        outputs=folder_id
    )


def folder_update_command(client, id: str = '', **kwargs):
    folder = client.folderUpdate(id, **kwargs)
    markdown = tableToMarkdown('Updated folder', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Folder.Update",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def folder_delete_command(client, folder_id: str = ''):
    folder = client.folderDelete(folder_id)
    markdown = tableToMarkdown('Deleted folder', folder)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Folder.Delete",
        outputs_key_field="folder",
        raw_response=folder,
        outputs=folder
    )


def user_create_command(client, **kwargs):
    user = client.userCreate(**kwargs)

    markdown = tableToMarkdown('Created new user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.User.Create",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def user_search_command(client, **kwargs):
    user = client.userSearch(**kwargs)
    markdown = tableToMarkdown('Search user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.User.Search",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def user_update_command(client, id: str = '', **kwargs):
    user = client.userUpdate(id, **kwargs)
    markdown = tableToMarkdown('Updated user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.User.Update",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def user_delete_command(client, id: str = ''):
    user = client.userDelete(id)
    markdown = tableToMarkdown('Deleted user', user)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.User.Delete",
        outputs_key_field="user",
        raw_response=user,
        outputs=user
    )


def secret_rpc_changepassword_command(client, secret_id: str = '', newpassword: str = ''):
    secret = client.secretChangePassword(secret_id, newpassword)
    markdown = tableToMarkdown('Change password for remote machine', secret)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Thycotic.Secret.ChangePassword",
        outputs_key_field="secret",
        raw_response=secret,
        outputs=secret
    )


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    url = demisto.params().get('url')
    proxy = demisto.params().get('proxy', False)
    verify = not demisto.params().get('insecure', False)

    LOG(f'Command being called is {demisto.command()}')

    thycotic_commands = {
        'thycotic-secret-password-get': secret_password_get_command,
        'thycotic-secret-username-get': secret_username_get_command,
        'thycotic-secret-get': secret_get_command,
        'thycotic-secret-search-name': secret_search_name_command,
        'thycotic-secret-search': secret_search_command,
        'thycotic-secret-password-update': secret_password_update_command,
        'thycotic-secret-checkout': secret_checkout_command,
        'thycotic-secret-checkin': secret_checkin_command,
        'thycotic-secret-create': secret_create_command,
        'thycotic-secret-delete': secret_delete_command,
        'thycotic-secret-rpc-changepassword': secret_rpc_changepassword_command,
        'thycotic-folder-create': folder_create_command,
        'thycotic-folder-search': folder_search_command,
        'thycotic-folder-update': folder_update_command,
        'thycotic-folder-delete': folder_delete_command,
        'thycotic-user-create': user_create_command,
        'thycotic-user-search': user_search_command,
        'thycotic-user-update': user_update_command,
        'thycotic-user-delete': user_delete_command
    }
    try:
        client = Client(server_url=url,
                        username=username,
                        password=password,
                        proxy=proxy,
                        verify=verify)

        if demisto.command() in thycotic_commands:
            return_results(
                thycotic_commands[demisto.command()](client, **demisto.args())  # type: ignore[operator]
            )

        elif demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
