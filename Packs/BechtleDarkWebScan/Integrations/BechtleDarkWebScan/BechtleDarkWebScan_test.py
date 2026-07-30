"""BechtleDarkWebScan Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

from test_data.constants import *
from BechtleDarkWebScan import Client, \
    darkwebscan_getcompanies_command, \
    darkwebscan_getleaks_command, \
    darkwebscan_resetcontext_command, \
    darkwebscan_getemailsecurity_command, \
    darkwebscan_getosint_command, \
    darkwebscan_getwaf_command
import json



def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_command_darkwebscan_getcompanies(requests_mock):
    """Tests darkwebscan-getcompanies command function.

    Checks the output of the command function with the expected output.
    """
    mock_api_response = MOCK_GET_COMPANIES_RESPONSE

    mock_url = MOCK_BASE_URL + "/user/companies"
    requests_mock.get(mock_url, json=mock_api_response)

    client = Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        api_key="dummyapikey",
        additional_request_headers={}
    )

    response = darkwebscan_getcompanies_command(client, {})

    assert response.outputs_prefix == "BechtleDarkWebScan.Companies"
    assert response.outputs == MOCK_GET_COMPANIES_RESPONSE
    assert "Test Company" in response.readable_output


def test_command_darkwebscan_getleaks(requests_mock):
    """Tests darkwebscan-getleaks command function.

    Checks the output of the command function with the expected output.
    """
    mock_api_response = MOCK_GET_LEAKS_RESPONSE

    mock_url = MOCK_BASE_URL + "/user/lookout/my-leaked-data"
    requests_mock.get(mock_url, json=mock_api_response)

    client = Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        api_key="dummyapikey",
        additional_request_headers={}
    )

    response = darkwebscan_getleaks_command(client, {})

    assert response.outputs_prefix == "BechtleDarkWebScan.LeakedCredentials"
    assert response.outputs == MOCK_GET_LEAKS_RESPONSE.get('searchResults')
    assert "john.doe@example.org" in response.readable_output
    

def test_command_darkwebscan_getemailsecurity(requests_mock):
    """Tests darkwebscan-getemailsecurity command function.

    Checks the output of the command function with the expected output.
    """
    mock_api_response = MOCK_GET_EMAILSECURITY_RESPONSE

    mock_url = MOCK_BASE_URL + "/scan/email-security"
    requests_mock.get(mock_url, json=mock_api_response)

    client = Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        api_key="dummyapikey",
        additional_request_headers={}
    )

    response = darkwebscan_getemailsecurity_command(client, {})
    
    spf = MOCK_GET_EMAILSECURITY_RESPONSE.get('spf')
    dmarc = MOCK_GET_EMAILSECURITY_RESPONSE.get('dmarc')
    dane = MOCK_GET_EMAILSECURITY_RESPONSE.get('dane')
    expected_output  = {
            "SPF": {
                "Record": spf.get("spfRecord"),
                "Info": spf.get("warning"),
                "Summary": spf.get("summary")
            },
            "DMARC": {
                "Record": dmarc.get("dmarcRecord"),
                "Info": dmarc.get("warning"),
                "Summary": dmarc.get("summary")
            },
            "DANE": {
                "EmailHosts": dane.get("emailHosts"),
                "Info": dane.get("warning"),
                "Summary": dane.get("summary")
            }
        }

    assert response.outputs_prefix == "BechtleDarkWebScan.EmailSecurity"
    assert response.outputs == expected_output
    assert "policy" in response.readable_output


def test_command_darkwebscan_resetcontext():
    """Tests darkwebscan-resetcontext command function.

    Checks the output of the command function with the expected output.
    
    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    response = darkwebscan_resetcontext_command()

    assert response.readable_output == MOCK_RESETCONTEXT_RESPONSE
    

def test_command_darkwebscan_getwaf(requests_mock):
    """Tests darkwebscan-getwaf command function.

    Checks the output of the command function with the expected output.
    """
    mock_api_response = MOCK_GET_WAF_RESPONSE

    mock_url = MOCK_BASE_URL + "/scan/waf"
    requests_mock.get(mock_url, json=mock_api_response)

    client = Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        api_key="dummyapikey",
        additional_request_headers={}
    )

    response = darkwebscan_getwaf_command(client, {})

    assert response.outputs_prefix == "BechtleDarkWebScan.WAF"
    assert response.outputs == MOCK_GET_WAF_RESPONSE
    assert "is in use" in response.readable_output    
    

def test_command_darkwebscan_getosint(requests_mock):
    """Tests darkwebscan-getosint command function.

    Checks the output of the command function with the expected output.
    """
    mock_api_response = MOCK_GET_OSINT_RESPONSE

    mock_url = MOCK_BASE_URL + "/scan/osint"
    requests_mock.get(mock_url, json=mock_api_response)

    client = Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        api_key="dummyapikey",
        additional_request_headers={}
    )

    response = darkwebscan_getosint_command(client, {})

    assert response.outputs_prefix == "BechtleDarkWebScan.OSINT"
    assert response.outputs == MOCK_GET_OSINT_RESPONSE
    assert "rbrk01.example.org" in response.readable_output
