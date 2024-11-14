import pytest
from Silverfort import get_user_entity_risk_command, get_resource_entity_risk_command, get_jwt_token, \
    update_user_entity_risk_command, update_resource_entity_risk_command


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
    return 'APP_USER_ID:APP_USER_SECRET'


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
def client(base_url, api_key):
    from Silverfort import Client
    app_user_id, app_user_secret = api_key.split(":")
    return Client(app_user_id=app_user_id, app_user_secret=app_user_secret, base_url=base_url, verify=False)


@pytest.fixture(autouse=True)
def risk_args(risk):
    return {'risk_name': 'activity_risk', 'severity': 'medium', 'valid_for': 1, 'description': 'Suspicious activity'}


@pytest.fixture(autouse=True)
def current_time(risk):
    return 1656417207.2854111


@pytest.fixture(autouse=True)
def expected_jwt_token(api_key, current_time):
    import jwt
    app_user_id, app_user_secret = api_key.split(":")
    payload = {
        "issuer": app_user_id,  # REQUIRED - Generated in the UI
        "iat": current_time,  # REQUIRED - Issued time - current epoch timestamp
        "exp": current_time + 60
    }
    return jwt.encode(payload, app_user_secret, algorithm="HS256")


class TestSiverfort(object):
    def test_get_status(self, requests_mock, base_url, api_key, client):
        from Silverfort import test_module
        requests_mock.get(f'{base_url}/getBootStatus', json={'status': 'Active'})
        output = test_module(client)
        assert output == "ok"

    def test_get_upn_by_email(self, requests_mock, upn, base_url, valid_get_upn_response, api_key, client, email, domain):
        requests_mock.get(f'{base_url}/getUPN?email={email}&domain={domain}', json=valid_get_upn_response)

        output = client.get_upn_by_email_or_sam_account_http_request(domain, email=email)
        assert output == upn

    def test_get_upn_by_sam_account(self, requests_mock, upn, base_url, valid_get_upn_response, api_key, client, sam_account,
                                    domain):
        requests_mock.get(f'{base_url}/getUPN?sam_account={sam_account}&domain={domain}',
                          json=valid_get_upn_response)

        output = client.get_upn_by_email_or_sam_account_http_request(domain, sam_account=sam_account)
        assert output == upn

    def test_get_user_entity_risk(self, requests_mock, upn, base_url, api_key, client, valid_get_risk_response):
        args = {'upn': upn}
        requests_mock.get(f'{base_url}/getEntityRisk?user_principal_name={upn}',
                          json=valid_get_risk_response)

        _, outputs, _ = get_user_entity_risk_command(client, args)

        outputs = outputs['Silverfort.UserRisk(val.UPN && val.UPN == obj.UPN)']

        assert outputs["UPN"] == upn
        assert outputs["Risk"] == valid_get_risk_response["risk"]
        assert outputs["Reasons"] == valid_get_risk_response["reasons"]

    def test_get_resource_entity_risk(self, requests_mock, base_url, api_key, client, valid_get_risk_response, resource_name,
                                      domain):
        args = {'resource_name': resource_name, 'domain_name': domain}
        requests_mock.get(f'{base_url}/getEntityRisk?resource_name={resource_name}'
                          f'&domain_name={domain}', json=valid_get_risk_response)

        _, outputs, _ = get_resource_entity_risk_command(client, args)

        outputs = outputs['Silverfort.ResourceRisk(val.ResourceName && val.ResourceName == obj.ResourceName)']

        assert outputs["ResourceName"] == resource_name
        assert outputs["Risk"] == valid_get_risk_response["risk"]
        assert outputs["Reasons"] == valid_get_risk_response["reasons"]

    def test_update_user_entity_risk(self, requests_mock, upn, base_url, api_key, client, valid_update_response, bad_response,
                                     risk_args):
        args = risk_args
        args['upn'] = upn

        requests_mock.post(f'{base_url}/updateEntityRisk', json=valid_update_response)
        assert update_user_entity_risk_command(client, args) == "updated successfully!"

        requests_mock.post(f'{base_url}/updateEntityRisk', json=bad_response)
        assert update_user_entity_risk_command(client, args) == "Couldn't update the user entity's risk"

    def test_update_resource_entity_risk_successfully(self, requests_mock, base_url, api_key, client, valid_update_response,
                                                      bad_response, risk_args, resource_name, domain):
        args = risk_args
        args['resource_name'] = resource_name
        args['domain_name'] = domain

        requests_mock.post(f'{base_url}/updateEntityRisk', json=valid_update_response)
        assert update_resource_entity_risk_command(client, args) == 'updated successfully!'

        requests_mock.post(f'{base_url}/updateEntityRisk', json=bad_response)
        assert update_resource_entity_risk_command(client, args) == "Couldn't update the resource entity's risk"

    def test_get_jwt_token(self, api_key, current_time, expected_jwt_token):
        app_user_id, app_user_secret = api_key.split(":")
        jwt_token = get_jwt_token(app_user_id, app_user_secret, current_time)

        assert jwt_token == expected_jwt_token
