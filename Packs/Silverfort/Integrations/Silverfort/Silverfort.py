from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
API_KEY = demisto.params().get('apikey')
UPDATE_REQ_RESPONSE = {'result': 'updated successfully!'}


class Client(BaseClient):
    def get_status_http_request(self):
        """
        initiates an http request to get the service status
        """
        params = {'apikey': API_KEY}
        response = self._http_request(
            method='GET',
            url_suffix='getBootStatus',
            params=params
        )
        return response

    def get_upn_by_email_or_sam_account_http_request(self, domain=None, email=None, sam_account=None):
        """
        initiates an http request to get the upn by email or sam account
        """
        params = {'apikey': API_KEY, 'domain': domain}
        if email:
            params['email'] = email
        else:
            params['sam_account'] = sam_account
        response = self._http_request(
            method='GET',
            url_suffix='getUPN',
            params=params
        )
        return response['user_principal_name']

    def get_user_entity_risk_http_request(self, upn):
        """
        initiates an http request to get the user entity's risk from Silverfort DB
        """
        params = {'apikey': API_KEY, 'user_principal_name': upn}
        response = self._http_request(
            method='GET',
            url_suffix='getEntityRisk',
            params=params
        )
        return response

    def get_resource_entity_risk_http_request(self, resource_name, domain_name):
        """
        initiates an http request to get the resource entity's risk from Silverfort DB
        """
        params = {'apikey': API_KEY, 'resource_name': resource_name, 'domain_name': domain_name}
        response = self._http_request(
            method='GET',
            url_suffix='getEntityRisk',
            params=params
        )
        return response

    def update_user_entity_risk_http_request(self, upn, risks):
        """
        initiates an http request to update the user entity's risk in Silverfort DB
        """
        params = {'apikey': API_KEY}
        data = {'user_principal_name': upn, 'risks': risks}
        response = self._http_request(
            method='POST',
            url_suffix='updateEntityRisk',
            params=params,
            json_data=data
        )
        return response

    def update_resource_entity_risk_http_request(self, resource_name, domain_name, risks):
        """
        initiates an http request to update resource entity's risk in Silverfort DB
        """
        params = {'apikey': API_KEY}
        data = {'resource_name': resource_name, 'domain_name': domain_name, 'risks': risks}
        response = self._http_request(
            method='POST',
            url_suffix='updateEntityRisk',
            params=params,
            json_data=data
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
    if result == "True":
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


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = urljoin(demisto.params().get('url'), '/riskapi')

    verify_certificate = demisto.params().get('insecure', True)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
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
            return_error(message=error_message + 'Something went wrong')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
