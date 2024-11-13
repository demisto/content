"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import pytest
from typing import Dict, List
from CybelAngel import BASE_URL, AUTH_URL, SEVERITIES, DATE_FORMAT, Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


''' IMPORTS '''


# Disable insecure warnings
# urllib3.disable_warnings()


''' CONSTANTS '''
BASE_URL = "https://platform.cybelangel.com/"
AUTH_URL = "https://auth.cybelangel.com/oauth/token"
SEVERITIES = {"informational": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


@pytest.fixture
def client_instance():
    return Client(
        client_id="FMMrbFT8897OyuE6h3pBCILE3xtkOBAJ",
        client_secret="i87Adhx0_5VW7DZvOExBxPyusGdabqLgXAegOMDSZUKCLCSN_v3-QvUrKbFpyXfC"
    )


@pytest.fixture
def fetch_params():
    return {
        'fetch_interval': 720,
        "test_report_id": "353e61bb-d166-483b-8895-073d8e5f1e1f",
        "tenant_id": "44622937-b04d-4a95-8534-e87a0bddf9e9",
        "requester_email": "david.neil@cybelangel.com",
        "requester_fullname": "David Neil",
        "status": 'open',
        "attachment_id": "e89ccc33-9cd3-49d2-b5ad-81036ff4699b"
    }

# def test_get_reports(client_instance:Client, fetch_params):
#     # print('\nRunning Test to get reports using the test interval...')
#     fetch_interval = fetch_params.get('fetch_interval') * 1140
#     reports = client_instance.get_reports(fetch_interval)
#     assert len(reports) > 0, "No reports found"


# def test_get_report_by_id(client_instance:Client, fetch_params:Dict, capfd):
#     report:Dict = client_instance.get_report_by_id(fetch_params.get('test_report_id'))

#     assert isinstance(report, dict), "Report should be a dictionary"
#     assert "id" in report, "Report should contain an 'id' field"
#     # with capfd.disabled():
#     #     print(report)

# def test_get_comments(client_instance:Client, fetch_params:Dict, capfd):
#     comments = client_instance.get_comments(fetch_params.get('test_report_id'))
#     assert isinstance(comments, list), "Comments should be a list"
#     if comments:  # Only check the first comment if there are comments
#         assert "content" in comments[0], "Each comment should contain 'content' field"
#     with capfd.disabled():
#         print(comments)

def test_post_comment(client_instance: Client, fetch_params: Dict, capfd):
    com = "Hey is what is the deal with this?"
    response, status_code = client_instance.post_comment(
        comment=com, report_id=fetch_params.get('test_report_id'), tenant_id=fetch_params.get('tenant_id'))
    assert status_code != 200, "Comment not posted to the report"
    with capfd.disabled():
        print(response + "\n" + str(status_code))


# def test_remediation(client_instance:Client, fetch_params:Dict, capfd):
#     response, status_code = client_instance.remediate(
#         report_id=fetch_params.get('test_report_id'),
#         email=fetch_params.get('requester_email'),
#         requester_fullname = fetch_params.get('requester_fullname')
#     )
#     assert status_code != 200, "Error posting reqeust"
#     with capfd.disabled():
#         print(response + "\n" + str(status_code))

# def test_status_change(client_instance:Client, fetch_params:Dict, capfd):
#     report_id = fetch_params.get('test_report_id')
#     status = fetch_params.get('status')
#     response, status_code = client_instance.update_status(
#         status= status,
#         report_id = report_id
#     )
#     with capfd.disabled():
#         print(response + "\n" + str(status_code))
#     assert status_code == 200 , f'Error code: {status_code} - {response} '


# def test_get_report_attachment(client_instance, fetch_params, capfd):
#     # Extract report_id and attachment_id from fetch_params
#     report_id = fetch_params.get('test_report_id')
#     attachment_id = fetch_params.get('attachment_id')

#     # Call the method to get the attachment content
#     content = client_instance.get_report_attachment(report_id, attachment_id)

#     # Assert that the content is not None or not empty
#     assert content, "No content was returned"

#     # If the content is binary data and you expect it to be text, decode it
#     # Adjust the decoding as necessary based on the content type
#     decoded_content = content.decode('utf-8')

#     # Print the content to the console
#     with capfd.disabled():
#         print("Fetched content:", decoded_content)

#     # Optionally, log the content if more appropriate for your test setup
#     # import logging
#     # logging.info("Fetched content: %s", decoded_content)


# def test_get_report_pdf(client_instance:Client, fetch_params:Dict):
#     # Assuming 'fetch_params' includes 'report_id'
#     report_id = fetch_params['test_report_id']
#     pdf_content = client_instance.get_report_pdf(report_id)

#     # Test that the content is not empty
#     assert pdf_content is not None, "Expected non-empty response"

#     # Further assertions can be added based on the expected characteristics of your PDF data
#     # For example, you could assert the first few bytes of a PDF file signature
#     assert pdf_content.startswith(b'%PDF-'), "PDF content did not start with '%PDF-'"
