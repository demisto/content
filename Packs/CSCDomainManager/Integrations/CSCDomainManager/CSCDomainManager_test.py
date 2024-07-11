import json
from CSCDomainManager import Client
from CSCDomainManager import csc_domains_search_command
from CSCDomainManager import csc_domains_availability_check_command
from CSCDomainManager import csc_domains_configuration_search_command
from CSCDomainManager import domain
from CSCDomainManager import create_params_string
from CSCDomainManager import get_domains_search_hr_fields
from CSCDomainManager import get_domains_configurations_hr_fields
from CSCDomainManager import get_domains_availability_check_hr_fields
from CSCDomainManager import get_domain_hr_fields
from CSCDomainManager import get_whois_contacts_fields_for_domain
from CommonServerPython import DBotScoreReliability


EXAMPLE_BASE_URL = 'https://test.com/api'
VERIFY = True
ACCEPT_VAL = "example"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


GET_REQUEST_EXAMPLE1 = util_load_json('./test_data/get_domain.json')
GET_REQUEST_QUALIFIED_DOMAIN_NAME = util_load_json('./test_data/get_domain_qualified_domain_name.json')
GET_DOMAINS_AVAILABILITY_CHECK = util_load_json('./test_data/get_domain_availability_check.json')
GET_DOMAINS_CONFI_LIST = util_load_json('./test_data/get_domains_configuration_list.json')
DOMAIN_DOMAIN = util_load_json('./test_data/domain_domain.json')
DOMAINS_LIST = util_load_json('./test_data/domains_list_for_get_domains_search_hr_fields.json')
CONFIGURATIONS_LIST = util_load_json('./test_data/configurations_list_for_get_domains_search_hr_fields.json')
AVAILABLE_DOMAINS_LIST = util_load_json('./test_data/available_domains_list_for_get_domains_availability_check_hr_fields.json')
WHOIS_CONTACTS = util_load_json('./test_data/whois_contacts.json')


def create_mock_client():
    return Client(
        base_url=EXAMPLE_BASE_URL,
        verify=VERIFY,
        apikey='test',
        token='test'
    )


def test_create_params_string():
    args = {
        'domain_name': 'csc-panw',
        'registry_expiry_date': '22-Apr-2025'
    }
    params_str = create_params_string(args)
    assert params_str == 'filter=domain==csc-panw,registryExpiryDate==22-Apr-2025'

    args = {
        'domain_name': 'csc-panw',
        'registry_expiry_date': '22/04/2025'
    }

    params_str = create_params_string(args)
    assert params_str == 'filter=domain==csc-panw,registryExpiryDate==22-Apr-2025'

    args = {
        'domain_name': 'csc-panw',
        'registry_expiry_date': '22-Apr-2025',
        'page': '2'
    }
    params_str = create_params_string(args)
    assert params_str == 'filter=domain==csc-panw,registryExpiryDate==22-Apr-2025&page=2'

    args = {
        'admin_email': 'example@panw.com',
        'email': 'example@panwcom',
        'organization': 'panw'
    }
    params_str = create_params_string(args)
    assert params_str == 'filter=adminEmail==example@panw.com,email==example@panwcom,organization==panw'


def test_get_domains_search_hr_fields():
    results = get_domains_search_hr_fields(DOMAINS_LIST)
    assert len(results) == 1
    assert len(results[0]) == 11
    assert results[0].get('Dns Type') == "CSC_BASIC"


def test_get_domains_configurations_hr_fields():
    results = get_domains_configurations_hr_fields(CONFIGURATIONS_LIST)
    assert len(results) == 1
    assert len(results[0]) == 9
    assert results[0].get('Domain extension') == 'biz'


def test_get_domains_availability_check_hr_fields():
    results = get_domains_availability_check_hr_fields(AVAILABLE_DOMAINS_LIST)
    assert len(results) == 1
    assert len(results[0]) == 6
    assert results[0].get('Message') == 'Domain already in portfolio'


def test_get_domain_hr_fields():
    results = get_domain_hr_fields(DOMAIN_DOMAIN)
    assert len(results) == 17
    assert results.get('Domain') == 'example'
    assert results.get('Generic top-level domains') is False


def test_get_whois_contacts_fields_for_domain():
    results = get_whois_contacts_fields_for_domain(WHOIS_CONTACTS, ['firstName', 'lastName'], 'REGISTRANT')
    assert results == ['Domain Administrator']


def test_csc_domains_search(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'csc-panw',
        'registry_expiry_date': '22-Apr-2025 UTC'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_EXAMPLE1)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('qualifiedDomainName') == 'csc-panw.com'
    assert result_output[1].get('registrationDate') == '22-Apr-2024 UTC'
    assert result_output[1].get('extension') == 'com'


def test_csc_domains_search_with_operator(mocker):
    client = create_mock_client()
    args = {
        'registration_date': 'ge=22-Apr-2024'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_EXAMPLE1)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('qualifiedDomainName') == 'csc-panw.com'
    assert result_output[1].get('registrationDate') == '22-Apr-2024 UTC'
    assert result_output[1].get('extension') == 'com'


def test_csc_domains_search_with_qualified_domain_name(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'csc-panw.com'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_QUALIFIED_DOMAIN_NAME)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert result_output.get('qualifiedDomainName') == 'csc-panw.com'
    assert result_output.get('registrationDate') == '22-Apr-2024 UTC'
    assert result_output.get('extension') == 'com'


def test_csc_domains_availability_check(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'cscpanw.org,csc-panw.info'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_DOMAINS_AVAILABILITY_CHECK)
    result = csc_domains_availability_check_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('qualifiedDomainName') == 'csc-panw.info'
    assert result_output[1].get('result').get('message') == 'Domain already in portfolio'
    assert result_output[1].get('result').get('code') == 'DOMAIN_IN_PORTFOLIO'


def test_csc_domains_configuration_list(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'csc-panw.biz'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_DOMAINS_CONFI_LIST)
    result = csc_domains_configuration_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 1
    assert result_output[0].get('domain') == 'csc-panw.biz'
    assert result_output[0].get('domainLabel') == 'csc-panw'


def test_domain(mocker):
    client = create_mock_client()
    args = {
        'domain': 'example.com'
    }
    mocker.patch.object(client, 'send_get_request', return_value=DOMAIN_DOMAIN)
    reliability = DBotScoreReliability.A
    result = domain(client, args, reliability)
    result_output = result[0].to_context()
    result_output = result_output.get('Contents')
    assert result_output.get('qualifiedDomainName') == 'example.com'
    assert result_output.get('domain') == 'example'
    assert result_output.get('registrationDate') == '09-Dec-2011 UTC'
