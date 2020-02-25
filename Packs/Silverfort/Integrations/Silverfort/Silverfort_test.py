from unittest.mock import patch
from Silverfort import get_user_entity_risk_command, get_resource_entity_risk_command,\
    update_user_entity_risk_command, update_resource_entity_risk_command

API_KEY = "XXXXXXXXXXXXXXXXXXXXX"


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_get_status(requests_mock, base_url, api_key, client):
    from Silverfort import test_module

    requests_mock.get(f'{base_url}/getBootStatus?apikey={api_key}', json="True")
    output = test_module(client)
    assert output == "ok"


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_get_upn_by_email(requests_mock, upn, base_url, valid_get_upn_response, api_key, client, email, domain):
    requests_mock.get(f'{base_url}/getUPN?apikey={api_key}&email={email}&domain={domain}', json=valid_get_upn_response)

    output = client.get_upn_by_email_or_sam_account_http_request(domain, email=email)
    assert output["upn"] == upn


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_get_upn_by_sam_account(requests_mock, upn, base_url, valid_get_upn_response, api_key, client, sam_account,
                                domain):
    requests_mock.get(f'{base_url}/getUPN?apikey={api_key}&sam_account={sam_account}&domain={domain}',
                      json=valid_get_upn_response)

    output = client.get_upn_by_email_or_sam_account_http_request(domain, sam_account=sam_account)
    assert output["upn"] == upn


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_get_user_entity_risk(requests_mock, upn, base_url, api_key, client, valid_get_risk_response):
    args = {'upn': upn}
    requests_mock.get(f'{base_url}/getEntityRisk?apikey={api_key}&user_principal_name={upn}',
                      json=valid_get_risk_response)

    _, outputs, _ = get_user_entity_risk_command(client, args)

    outputs = outputs['Silverfort.UserRisk(val.UPN && val.UPN == obj.UPN)']

    assert outputs["UPN"] == upn
    assert outputs["Risk"] == valid_get_risk_response["risk"]
    assert outputs["Reasons"] == valid_get_risk_response["reasons"]


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_get_resource_entity_risk(requests_mock, base_url, api_key, client, valid_get_risk_response, resource_name,
                                  domain):
    args = {'resource_name': resource_name, 'domain_name': domain}
    requests_mock.get(f'{base_url}/getEntityRisk?apikey={api_key}&resource_name={resource_name}'
                      f'&domain_name={domain}', json=valid_get_risk_response)

    _, outputs, _ = get_resource_entity_risk_command(client, args)

    outputs = outputs['Silverfort.ResourceRisk(val.ResourceName && val.ResourceName == obj.ResourceName)']

    assert outputs["ResourceName"] == resource_name
    assert outputs["Risk"] == valid_get_risk_response["risk"]
    assert outputs["Reasons"] == valid_get_risk_response["reasons"]


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_update_user_entity_risk(requests_mock, upn, base_url, api_key, client, valid_update_response, bad_response,
                                 risk_args):
    args = risk_args
    args['upn'] = upn

    requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=valid_update_response)
    assert update_user_entity_risk_command(client, args) == "ok"

    requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=bad_response)
    assert update_user_entity_risk_command(client, args) == "Couldn't update the user entity's risk"


@patch('Packs.Silverfort.Integrations.Silverfort.Silverfort.API_KEY', API_KEY)
def test_update_resource_entity_risk_successfully(requests_mock, base_url, api_key, client, valid_update_response,
                                                  bad_response, risk_args, resource_name, domain):
    args = risk_args
    args['resource_name'] = resource_name
    args['domain_name'] = domain

    requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=valid_update_response)
    assert update_resource_entity_risk_command(client, args) == 'ok'

    requests_mock.post(f'{base_url}/updateEntityRisk?apikey={api_key}', json=bad_response)
    assert update_resource_entity_risk_command(client, args) == "Couldn't update the resource entity's risk"
