from requests_ntlm import HttpNtlmAuth
import tempfile

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url: str, use_ssl: bool, proxy: bool, app_id: str, folder: str, safe: str,
                 credentials_object: str, username: str, password: str, cert_text: str, key_text: str):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self._app_id = app_id
        self._folder = folder
        self._safe = safe
        self._credentials_list = credentials_object.split(',')
        self._username = username
        self._password = password
        self._cert_text = cert_text
        self._key_text = key_text
        self.auth = self.create_windows_authentication_param()
        self.crt, self.cf, self.kf = self.create_crt_param()

    def create_windows_authentication_param(self):
        auth = None
        if self._username:
            # if username and password were added - use ntlm authentication
            auth = HttpNtlmAuth(self._username, self._password)
        return auth

    def create_crt_param(self):
        if not self._cert_text and not self._key_text:
            return None, None, None
        elif not self._cert_text or not self._key_text:
            raise Exception('You can not configure either certificate text or key, both are required.')
        elif self._cert_text and self._key_text:
            cert_text_list = self._cert_text.split('-----')
            # replace spaces with newline characters
            cert_text_fixed = '-----'.join(
                cert_text_list[:2] + [cert_text_list[2].replace(' ', '\n')] + cert_text_list[3:])
            cf = tempfile.NamedTemporaryFile(delete=False)
            cf.write(cert_text_fixed.encode())
            cf.flush()

            key_text_list = self._key_text.split('-----')
            # replace spaces with newline characters
            key_text_fixed = '-----'.join(
                key_text_list[:2] + [key_text_list[2].replace(' ', '\n')] + key_text_list[3:])
            kf = tempfile.NamedTemporaryFile(delete=False)
            kf.write(key_text_fixed.encode())
            kf.flush()
            return (cf.name, kf.name), cf, kf

    def get_credentials(self, creds_object):
        url_suffix = '/AIMWebService/api/Accounts'
        params = {
            "AppID": self._app_id,
            "Safe": self._safe,
            "Folder": self._folder,
            "Object": creds_object,
        }

        return self._http_request("GET", url_suffix, params=params, auth=self.auth, cert=self.crt)

    def list_credentials(self):
        credential_result = [self.get_credentials(credentials.strip()) for credentials in self._credentials_list]
        return credential_result


def list_credentials_command(client):
    """Lists all credentials available.
    :param client: the client object with the given params
    :return: the credentials info without the explicit password
    """
    creds_list = client.list_credentials()
    for cred in creds_list:
        # the password value in the json appears under the key "Content"
        if "Content" in cred:
            del cred["Content"]
    # notice that the raw_response doesn't contain the password either
    results = CommandResults(
        outputs=creds_list,
        raw_response=creds_list,
        outputs_prefix='CyberArkAIM',
        outputs_key_field='Name',
    )
    return results


def fetch_credentials(client):
    """Fetches the available credentials.
    :param client: the client object with the given params
    :return: a credentials object
    """
    creds_list = client.list_credentials()
    credentials = []
    for cred in creds_list:
        credentials.append({
            "user": cred.get("UserName"),
            "password": cred.get("Content"),
            "name": cred.get("Name"),
        })
    demisto.credentials([credentials])


def test_module(client: Client) -> str:
    """Performing a request to the AIM server with the given params
    :param client: the client object with the given params
    :return: ok if the request succeeded
    """
    client.list_credentials()
    return "ok"


def main():

    params = demisto.params()

    url = params.get('url')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    app_id = params.get('app_id') or ""
    folder = params.get('folder')
    safe = params.get('safe')
    credentials_object = params.get('credential_names') or ""

    cert_text = params.get('cert_text') or ""
    key_text = params.get('key_text') or ""

    username = ""
    password = ""
    if params.get('credentials'):
        # credentials are not mandatory in this integration
        username = params.get('credentials').get('identifier')
        password = params.get('credentials').get('password')

    try:
        client = Client(server_url=url, use_ssl=use_ssl, proxy=proxy, app_id=app_id, folder=folder, safe=safe,
                        credentials_object=credentials_object, username=username, password=password,
                        cert_text=cert_text, key_text=key_text)

        command = demisto.command()
        demisto.debug(f'Command being called in CyberArk AIM is: {command}')

        commands = {
            'test-module': test_module,
            'cyberark-aim-list-credentials': list_credentials_command,
            'fetch-credentials': fetch_credentials
        }
        if command in commands:
            return_results(commands[command](client))  # type: ignore[operator]
        else:
            raise NotImplementedError(f'{command} is not an existing CyberArk AIM command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())
    finally:
        try:
            if client.crt:
                cf_name, kf_name = client.crt
                if client.cf:
                    client.cf.close()
                    os.remove(cf_name)
                if client.cf:
                    client.kf.close()
                    os.remove(kf_name)
        except Exception as err:
            return_error(f"CyberArk AIM error: {str(err)}")


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
