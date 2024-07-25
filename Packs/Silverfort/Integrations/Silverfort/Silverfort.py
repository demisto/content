import time
import jwt
import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
UPDATE_REQ_RESPONSE = {'result': 'updated successfully!'}


def get_jwt_token(app_user_id: str, app_user_secret: str, current_time: float = time.time(), expire_time_sec: int = 60):
    payload = {
        "issuer": app_user_id,  # REQUIRED - Generated in the UI
        "iat": current_time,  # REQUIRED - Issued time - current epoch timestamp
        "exp": current_time + expire_time_sec  # OPTIONAL - Expire time - token expiry (default 30 seconds from iat)
    }
    return jwt.encode(payload, app_user_secret, algorithm="HS256")


class Client(BaseClient):
    def __init__(self, app_user_id, app_user_secret, *args, **kwargs):
        self.app_user_id = app_user_id
        self.app_user_secret = app_user_secret
        super().__init__(*args, **kwargs)

    def get_status_http_request(self):
        """
        initiates an http request to get the service status
        """
        response = self._http_request(
            method='GET',
            url_suffix='getBootStatus',
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)}
        )
        return response

    def get_upn_by_email_or_sam_account_http_request(self, domain=None, email=None, sam_account=None):
        """
        initiates an http request to get the upn by email or sam account
        """
        params = {'domain': domain}
        if email:
            params['email'] = email
        else:
            params['sam_account'] = sam_account

        response = self._http_request(
            method='GET',
            url_suffix='getUPN',
            params=params,
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)}
        )
        return response['user_principal_name']

    def get_user_entity_risk_http_request(self, upn):
        """
        initiates an http request to get the user entity's risk from Silverfort DB
        """
        response = self._http_request(
            method='GET',
            url_suffix='getEntityRisk',
            params={'user_principal_name': upn},
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)}
        )
        return response

    def get_resource_entity_risk_http_request(self, resource_name, domain_name):
        """
        initiates an http request to get the resource entity's risk from Silverfort DB
        """
        response = self._http_request(
            method='GET',
            url_suffix='getEntityRisk',
            params={'resource_name': resource_name, 'domain_name': domain_name},
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)}
        )
        return response

    def update_user_entity_risk_http_request(self, upn, risks):
        """
        initiates an http request to update the user entity's risk in Silverfort DB
        """
        response = self._http_request(
            method='POST',
            url_suffix='updateEntityRisk',
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)},
            json_data={'user_principal_name': upn, 'risks': risks}
        )
        return response

    def update_resource_entity_risk_http_request(self, resource_name, domain_name, risks):
        """
        initiates an http request to update resource entity's risk in Silverfort DB
        """
        response = self._http_request(
            method='POST',
            url_suffix='updateEntityRisk',
            json_data={'resource_name': resource_name, 'domain_name': domain_name, 'risks': risks},
            headers={'Authorization': 'Bearer %s' % get_jwt_token(self.app_user_id, self.app_user_secret)}
        )
        return response


def create_risk_json(args):
    try:
        valid_for = args.get('valid_for')
        valid_for = int(valid_for)
    except Exception:
        raise Exception('valid_for must be a positive number greater than 1')
    risk_name = args.get('risk_name')
    severity = args.get('severity')
    description = args.get('description')
    return {risk_name: {"severity": severity, "valid_for": valid_for, "description": description}}


def get_upn(client, args):
    email = args.get('email')
    sam_account = args.get('sam_account')
    domain = args.get('domain')
    return client.get_upn_by_email_or_sam_account_http_request(domain, email, sam_account)


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    result = client.get_status_http_request()
    if result["status"] == "Active" or result["status"] == "Standby":
        return 'ok'
    else:
        return 'Something went wrong with the risk api checking'


def get_user_entity_risk_command(client, args):
    upn = args.get('upn')
    if not upn:
        upn = get_upn(client, args)
    result = client.get_user_entity_risk_http_request(upn)

    outputs = {
        'UPN': upn,
        'Risk': result.get('risk'),
        'Reasons': result.get('reasons')
    }
    name = 'Silverfort User Risk'
    headers = ['UPN', 'Risk', 'Reasons']
    readable_output = tableToMarkdown(name, outputs, headers)

    return (
        readable_output,
        {'Silverfort.UserRisk(val.UPN && val.UPN == obj.UPN)': outputs},
        result  # raw response - the original response
    )


def get_resource_entity_risk_command(client, args):
    resource_name = args.get('resource_name')
    domain_name = args.get('domain_name')
    result = client.get_resource_entity_risk_http_request(resource_name, domain_name)

    outputs = {
        'ResourceName': resource_name,
        'Risk': result.get('risk'),
        'Reasons': result.get('reasons')
    }
    name = 'Silverfort Resource Risk'
    headers = ['ResourceName', 'Risk', 'Reasons']
    readable_output = tableToMarkdown(name, outputs, headers)

    return (
        readable_output,
        {'Silverfort.ResourceRisk(val.ResourceName && val.ResourceName == obj.ResourceName)': outputs},
        result  # raw response - the original response
    )


def update_user_entity_risk_command(client, args):
    upn = args.get('upn')
    if not upn:
        upn = get_upn(client, args)
    risks = create_risk_json(args)
    result = client.update_user_entity_risk_http_request(upn, risks)

    if result == UPDATE_REQ_RESPONSE:
        return "updated successfully!"
    else:
        return "Couldn't update the user entity's risk"


def update_resource_entity_risk_command(client, args):
    resource_name = args.get('resource_name')
    domain_name = args.get('domain_name')
    risks = create_risk_json(args)
    result = client.update_resource_entity_risk_http_request(resource_name, domain_name, risks)

    if result == UPDATE_REQ_RESPONSE:
        return "updated successfully!"
    else:
        return "Couldn't update the resource entity's risk"


def main():  # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = urljoin(demisto.params().get('url'), '/v1/public')
    verify_certificate = not demisto.params().get('insecure', False)
    api_key = demisto.params().get('apikey')
    app_user_id, app_user_secret = api_key.split(":")
    if not app_user_id or not app_user_secret:
        return_error('Verify the API KEY parameter is correct')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            app_user_id=app_user_id,
            app_user_secret=app_user_secret,
            base_url=base_url,
            verify=verify_certificate)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'silverfort-get-user-risk':
            return_outputs(*get_user_entity_risk_command(client, demisto.args()))

        elif demisto.command() == 'silverfort-get-resource-risk':
            return_outputs(*get_resource_entity_risk_command(client, demisto.args()))

        elif demisto.command() == 'silverfort-update-user-risk':
            result = update_user_entity_risk_command(client, demisto.args())
            demisto.results(result)

        elif demisto.command() == 'silverfort-update-resource-risk':
            result = update_resource_entity_risk_command(client, demisto.args())
            demisto.results(result)
    # Log exceptions
    except Exception as e:
        error_message = f'Failed to execute {demisto.command()} command. Error: '
        if 'Failed to parse' in e.args[0]:
            return_error(message=error_message + 'Verify the URL parameter is correct')
        elif 'riskapi' not in e.args[0]:
            return_error(message=error_message + str(e.args[0]))
        else:
            return_error(error_message + 'Something went wrong')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
