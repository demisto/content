import pytest
from unittest.mock import patch
from Silverfort import get_user_entity_risk_command, get_resource_entity_risk_command,\
    update_user_entity_risk_command, update_resource_entity_risk_command
API_KEY = "APIKEY"


@pytest.fixture(autouse=True)
def upn():
    return 'sfuser@silverfort.io'


@pytest.fixture(autouse=True)
def base_url():
    return 'https://test.com'


@pytest.fixture(autouse=True)
def email():
    return 'john@silverfort.com'


@pytest.fixture(autouse=True)
def domain():
    return 'silverfort.io'


@pytest.fixture(autouse=True)
def api_key():
    return 'APIKEY'


@pytest.fixture(autouse=True)
def risk():
    return {'risk_name': 'activity_risk', 'severity': 'medium', 'valid_for': 1, 'description': 'Suspicious activity'}


@pytest.fixture(autouse=True)
def resource_name():
    return 'AA--DC-1'


@pytest.fixture(autouse=True)
def bad_response():
    return 'No valid response'


@pytest.fixture(autouse=True)
def valid_update_response():
    return {"result": "updated successfully!"}


@pytest.fixture(autouse=True)
def valid_get_risk_response():
    return {"risk": "Low", "reasons": ["Password never expires", "Suspicious activity"]}


@pytest.fixture(autouse=True)
def valid_get_upn_response(upn):
    return {"user_principal_name": upn}


@pytest.fixture(autouse=True)
def sam_account():
    return 'sfuser'


@pytest.fixture(autouse=True)
def client(base_url):
    from Silverfort import Client
    return Client(base_url=base_url, verify=False)


@pytest.fixture(autouse=True)
def risk_args(risk):
    return {'risk_name': 'activity_risk', 'severity': 'medium', 'valid_for': 1, 'description': 'Suspicious activity'}


class TestSiverfort(object):
    @patch('Silverfort.API_KEY', API_KEY)
    def test_get_status(self, requests_mock, base_url, api_key, client):
        from Silverfort import test_module

        requests_mock.get(f'{base_url}/getBootStatus?apikey={api_key}', json="True")
        output = test_module(client)
        assert output == "ok"

    @patch('Silverfort.API_KEY', API_KEY)
    def test_get_upn_by_email(self, requests_mock, upn, base_url, valid_get_upn_response, api_key, client, email, domain):
        requests_mock.get(f'{base_url}/getUPN?apikey={api_key}&email={email}&domain={domain}', json=valid_get_upn_response)

        output = client.get_upn_by_email_or_sam_account_http_request(domain, email=email)
        assert output == upn

    @patch('Silverfort.API_KEY', API_KEY)
    def test_get_upn_by_sam_account(self, requests_mock, upn, base_url, valid_get_upn_response, api_key, client, sam_account,
                                    domain):
        requests_mock.get(f'{base_url}/getUPN?apikey={api_key}&sam_account={sam_account}&domain={domain}',
                          json=valid_get_upn_response)

        output = client.get_upn_by_email_or_sam_account_http_request(domain, sam_account=sam_account)
        assert output == upn

    @patch('Silverfort.API_KEY', API_KEY)
    def test_get_user_entity_risk(self, requests_mock, upn, base_url, api_key, client, valid_get_risk_response):
        args = {'upn': upn}
        requests_mock.get(f'{base_url}/getEntityRisk?apikey={api_key}&user_principal_name={upn}',
                          json=valid_get_risk_response)

        _, outputs, _ = get_user_entity_risk_command(client, args)

        outputs = outputs['Silverfort.UserRisk(val.UPN && val.UPN == obj.UPN)']

        assert outputs["UPN"] == upn
        assert outputs["Risk"] == valid_get_risk_response["risk"]
        assert outputs["Reasons"] == valid_get_risk_response["reasons"]

    @patch('Silverfort.API_KEY', API_KEY)
    def test_get_resource_entity_risk(self, requests_mock, base_url, api_key, client, valid_get_risk_response, resource_name,
                                      domain):
        args = {'resource_name': resource_name, 'domain_name': domain}
        requests_mock.get(f'{base_url}/getEntityRisk?apikey={api_key}&resource_name={resource_name}'
                          f'&domain_name={domain}', json=valid_get_risk_response)

        _, outputs, _ = get_resource_entity_risk_command(client, args)

        outputs = outputs['Silverfort.ResourceRisk(val.ResourceName && val.ResourceName == obj.ResourceName)']

        assert outputs["ResourceName"] == resource_name
        assert outputs["Risk"] == valid_get_risk_response["risk"]
        assert outputs["Reasons"] == valid_get_risk_response["reasons"]

    @patch('Silverfort.API_KEY', API_KEY)
    def test_update_user_entity_risk(self, requests_mock, upn, base_url, api_key, client, valid_update_response, bad_response,
                                     risk_args):
        args = risk_args
        args['upn'] = upn

        requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=valid_update_response)
        assert update_user_entity_risk_command(client, args) == "updated successfully!"

        requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=bad_response)
        assert update_user_entity_risk_command(client, args) == "Couldn't update the user entity's risk"

    @patch('Silverfort.API_KEY', API_KEY)
    def test_update_resource_entity_risk_successfully(self, requests_mock, base_url, api_key, client, valid_update_response,
                                                      bad_response, risk_args, resource_name, domain):
        args = risk_args
        args['resource_name'] = resource_name
        args['domain_name'] = domain

        requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=valid_update_response)
        assert update_resource_entity_risk_command(client, args) == 'updated successfully!'

        requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=bad_response)
        assert update_resource_entity_risk_command(client, args) == "Couldn't update the resource entity's risk"
