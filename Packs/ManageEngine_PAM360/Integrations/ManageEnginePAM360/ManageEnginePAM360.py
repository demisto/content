import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url: str, verify_certificate: bool, proxy: bool, app_token=str):
        super().__init__(base_url=server_url, verify=verify_certificate, proxy=proxy)
        self._app_token = app_token

    def fetch_password(self, method, resource_id, account_id, reason, ticket_id):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts/{account_id}/password'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "REASON": reason,
                    "TICKETID": ticket_id
                }
            }
        }
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, params=params)

    def create_resource(
        self,
        method,
        resource_name,
        account_name,
        resource_type,
        resource_url,
        password,
        notes,
        location,
        dnsname,
        department,
        resource_description,
        domain_name,
        resourcegroup_name,
        owner_name,
        resource_password_policy,
        account_password_policy
    ):
        URL_SUFFIX = '/restapi/json/v1/resources'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "RESOURCENAME": resource_name,
                    "ACCOUNTNAME": account_name,
                    "RESOURCETYPE": resource_type,
                    "PASSWORD": password,
                    "NOTES": notes,
                    "LOCATION": location,
                    "DNSNAME": dnsname,
                    "DEPARTMENT": department,
                    "RESOURCEDESCRIPTION": resource_description,
                    "DOMAINNAME": domain_name,
                    "RESOURCEGROUPNAME": resourcegroup_name,
                    "OWNERNAME": owner_name,
                    "RESOURCEURL": resource_url,
                    "RESOURCEPASSWORDPOLICY": resource_password_policy,
                    "ACCOUNTPASSWORDPOLICY": account_password_policy
                }
            }
        }
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, data=params)

    def create_account(self, method, resource_id, account_name, password, notes, account_password_policy):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "ACCOUNTLIST": [{
                        "ACCOUNTNAME": account_name,
                        "PASSWORD": password,
                        "NOTES": notes,
                        "ACCOUNTPASSWORDPOLICY": account_password_policy
                    }]
                }
            }
        }
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, data=params)

    def update_resource(
        self,
        method,
        resource_id,
        resource_name,
        resource_type,
        resource_url,
        resource_description,
        resource_password_policy,
        location,
        department,
        dnsname,
        owner_name
    ):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "RESOURCENAME": resource_name,
                    "RESOURCETYPE": resource_type,
                    "RESOURCEDESCRIPTION": resource_description,
                    "RESOURCEURL": resource_url,
                    "RESOURCEPASSWORDPOLICY": resource_password_policy,
                    "LOCATION": location,
                    "DEPARTMENT": department,
                    "DNSNAME": dnsname,
                }
            }
        }
        if owner_name != "":
            query["operation"]["Details"]["OWNERNAME"] = owner_name
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, data=params)

    def update_account(self, method, resource_id, account_id, account_name, notes, owner_name, account_password_policy):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts/{account_id}'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "ACCOUNTNAME": account_name,
                    "NOTES": notes,
                    "ACCOUNTPASSWORDPOLICY": account_password_policy,
                }
            }
        }
        if owner_name != "":
            query["operation"]["Details"]["OWNERNAME"] = owner_name
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, data=params)

    def fetch_account_details(self, method, resource_id, account_id):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts/{account_id}'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers)

    def fetch_resources(self, method):
        URL_SUFFIX = '/restapi/json/v1/resources'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers)

    def fetch_accounts(self, method, resource_id):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers)

    def update_account_password(self, method, resource_id, account_id, new_password, reset_type, reason, ticket_id):
        URL_SUFFIX = f'/restapi/json/v1/resources/{resource_id}/accounts/{account_id}/password'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        query = {
            "operation": {
                "Details": {
                    "NEWPASSWORD": new_password,
                    "RESETTYPE": reset_type,
                    "REASON": reason,
                    "TICKETID": ticket_id
                }
            }
        }
        params = {
            'INPUT_DATA': f'{query}'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers, data=params)

    def fetch_resource_account_id(self, method, resource_name, account_name):
        URL_SUFFIX = f'/restapi/json/v1/resources/getResourceIdAccountId?RESOURCENAME={resource_name}&ACCOUNTNAME={account_name}'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers)

    def check_connection(self, method):
        URL_SUFFIX = '/restapi/json/v1/resources/resourcetypes'
        headers = {
            'APP_AUTHTOKEN': self._app_token,
            'APP_TYPE': '17'
        }
        return self._http_request(method, URL_SUFFIX, headers=headers)


def test_module(
        client: Client,
):
    URL_SUFFIX = '/restapi/json/v1/resources/resourcetypes'
    headers = {
        'APP_AUTHTOKEN': client._app_token,
        'APP_TYPE': '17'
    }
    r = requests.request("GET", client._base_url + URL_SUFFIX, headers=headers, verify=client._verify)
    if r.status_code != 200:
        return 'Failed to connect to server'
    else:
        return 'ok'


def pam360_fetch_password(
        client: Client,
        resource_id: str = "",
        account_id: str = "",
        reason: str = "",
        ticket_id: str = ""
):
    creds_list = client.fetch_password("GET", resource_id, account_id, reason, ticket_id)
    readable_output = f'{creds_list}'
    results = CommandResults(
        outputs=creds_list,
        raw_response=creds_list,
        outputs_prefix='PAM360.Account',
        outputs_key_field='PASSWORD',
        readable_output=readable_output,
    )
    return results


def pam360_create_resource(
        client: Client,
        resource_name: str = "",
        account_name: str = "",
        resource_type: str = "",
        resource_url: str = "",
        password: str = "",
        notes: str = "",
        location: str = "",
        dnsname: str = "",
        department: str = "",
        resource_description: str = "",
        domain_name: str = "",
        resourcegroup_name: str = "",
        owner_name: str = "",
        resource_password_policy: str = "",
        account_password_policy: str = ""
):
    create_resource = client.create_resource("POST", resource_name, account_name, resource_type, resource_url,
                                             password, notes, location, dnsname, department, resource_description,
                                             domain_name, resourcegroup_name, owner_name, resource_password_policy,
                                             account_password_policy)
    readable_output = f'{create_resource}'
    results = CommandResults(
        outputs=create_resource,
        raw_response=create_resource,
        outputs_prefix='PAM360.Resource',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_create_account(
        client: Client,
        resource_id: str = "",
        account_name: str = "",
        password: str = "",
        notes: str = "",
        account_password_policy: str = ""
):
    create_account = client.create_account("POST", resource_id, account_name, password, notes, account_password_policy)
    readable_output = f'{create_account}'
    results = CommandResults(
        outputs=create_account,
        raw_response=create_account,
        outputs_prefix='PAM360.Account',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_update_resource(
        client: Client,
        resource_id: str = "",
        resource_name: str = "",
        resource_type: str = "",
        resource_url: str = "",
        resource_description: str = "",
        resource_password_policy: str = "",
        location: str = "",
        department: str = "",
        dnsname: str = "",
        owner_name: str = ""
):
    update_resource = client.update_resource("PUT", resource_id, resource_name, resource_type, resource_url,
                                             resource_description, resource_password_policy, location, department,
                                             dnsname, owner_name)
    readable_output = f'{update_resource}'
    results = CommandResults(
        outputs=update_resource,
        raw_response=update_resource,
        outputs_prefix='PAM360.Resource',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_update_account(
        client: Client,
        resource_id: str = "",
        account_id: str = "",
        account_name: str = "",
        notes: str = "",
        owner_name: str = "",
        account_password_policy: str = ""
):
    update_account = client.update_account("PUT", resource_id, account_id, account_name, notes, owner_name,
                                           account_password_policy)
    readable_output = f'{update_account}'
    results = CommandResults(
        outputs=update_account,
        raw_response=update_account,
        outputs_prefix='PAM360.Account',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_fetch_account_details(
        client: Client,
        resource_id: str = "",
        account_id: str = ""
):
    account_details = client.fetch_account_details("GET", resource_id, account_id)
    readable_output = f'{account_details}'
    results = CommandResults(
        outputs=account_details,
        raw_response=account_details,
        outputs_prefix='PAM360.Account',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_list_resources(client, **args):
    resource_list = client.fetch_resources("GET")
    readable_output = f'{resource_list}'
    results = CommandResults(
        outputs=resource_list,
        raw_response=resource_list,
        outputs_prefix='PAM360.Resource',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_list_accounts(
        client: Client,
        resource_id: str = ""
):
    account_list = client.fetch_accounts("GET", resource_id)
    readable_output = f'{account_list}'
    results = CommandResults(
        outputs=account_list,
        raw_response=account_list,
        outputs_prefix='PAM360.Account',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_update_account_password(
        client: Client,
        resource_id: str = "",
        account_id: str = "",
        new_password: str = "",
        reset_type: str = "",
        reason: str = "",
        ticket_id: str = ""
):
    update_password = client.update_account_password("PUT", resource_id, account_id, new_password, reset_type, reason, ticket_id)
    readable_output = f'{update_password}'
    results = CommandResults(
        outputs=update_password,
        raw_response=update_password,
        outputs_prefix='PAM360.Account',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def pam360_fetch_resource_account_id(
        client: Client,
        resource_name: str = "",
        account_name: str = ""
):
    fetch_id = client.fetch_resource_account_id("GET", resource_name, account_name)
    readable_output = f'{fetch_id}'
    results = CommandResults(
        outputs=fetch_id,
        raw_response=fetch_id,
        outputs_prefix='PAM360.Resource',
        outputs_key_field='message',
        readable_output=readable_output,
    )
    return results


def main():

    params = demisto.params()
    url = params.get('url')
    app_token = params.get('appToken')
    verify_certificate = not params.get('insecure')
    proxy = params.get('proxy')
    try:
        client = Client(server_url=url, verify_certificate=verify_certificate, proxy=proxy, app_token=app_token)
        command = demisto.command()
        demisto.debug(f'Command being called in ManageEngine PAM360 is: {command}')
        commands = {
            'test-module': test_module,
            'pam360-fetch-password': pam360_fetch_password,
            'pam360-create-resource': pam360_create_resource,
            'pam360-create-account': pam360_create_account,
            'pam360-update-resource': pam360_update_resource,
            'pam360-update-account': pam360_update_account,
            'pam360-fetch-account-details': pam360_fetch_account_details,
            'pam360-list-all-resources': pam360_list_resources,
            'pam360-list-all-accounts': pam360_list_accounts,
            'pam360-update-account-password': pam360_update_account_password,
            'pam360-fetch-resource-account-id': pam360_fetch_resource_account_id,
        }
        if command in commands:
            return_results(commands[command](client, **demisto.args()))  # type: ignore[operator]

        else:
            raise NotImplementedError(f'{command} is not an existing PAM360 command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
