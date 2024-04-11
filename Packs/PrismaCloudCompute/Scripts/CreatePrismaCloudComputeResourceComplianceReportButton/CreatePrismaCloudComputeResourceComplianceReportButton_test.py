import json
from unittest.mock import patch

import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CreatePrismaCloudComputeResourceComplianceReportButton import (
    filter_resources,
    filter_severities,
    transform_html_for_resource,
    send_html_email,
    send_xlsx_email,
    main
)

# Test transformation functions

# "Table" Test data
with open("test_data/hosts_table.json") as file:
    test_table_data = json.load(file)


def test_filter_resources_no_desired_resources():
    """
    Given:
        Hosts table.

    When:
        Running filter_resources

    Then:
        Assert the returned output matches the given hosts table.
    """
    # Test with no desired resources
    filtered_data = filter_resources(test_table_data, 'host', [])
    # Assert that the filtered data matches the input data
    assert filtered_data == test_table_data


def test_filter_resources_with_desired_resources():
    """
    Given:
        Hosts table and a desired resource.

    When:
        Running filter_resources

    Then:
        Assert the returned output matches filtered hosts table based on the given desired resource.
    """
    desired_resource = "VM001-MYRESOURCEGROUPNAT-abc123-def456-ghi789-jkl012"
    # Test with a desired resource
    filtered_data = filter_resources(test_table_data, 'host', [desired_resource])
    # Assert that the filtered data contains only the desired resource
    assert filtered_data == [test_table_data[0]]


def test_filter_severities_no_desired_severities():
    """
    Given:
        Hosts table.

    When:
        Running filter_severities

    Then:
        Assert the returned output matches the given hosts table.
    """
    # Test with no desired severities
    filtered_data = filter_severities(test_table_data, [])
    # Assert that the filtered data matches the input data
    assert filtered_data == test_table_data


def test_filter_severities_with_critical_severity():
    """
    Given:
        Hosts table and a desired severity.

    When:
        Running filter_severities

    Then:
        Assert the returned output matches filtered hosts table based on the given desired severity.
    """
    # Test with critical severity only
    filtered_data = filter_severities(test_table_data, ['critical'])
    # Assert that the filtered data contains only entries with critical severity
    expected_data = [entry for entry in test_table_data if 'critical' in entry['complianceissues'].lower()]
    assert filtered_data == expected_data


# "HTML" test data

with open("test_data/html_hosts_table_pre_transform.html") as file:
    html_hosts_test_data = file.read()

with open("test_data/html_containers_table_pre_transform.html") as file:
    html_containers_test_data = file.read()

with open("test_data/html_images_table_pre_transform.html") as file:
    html_images_test_data = file.read()


def test_transform_html_for_resource_host():
    """
    Given:
        Hosts HTML data.

    When:
        Running transform_html_for_resource

    Then:
        Assert the returned output contains the desired changes.
    """
    # Test transformation for resource type 'host'
    transformed_html = transform_html_for_resource(html_hosts_test_data, "host")
    # Assert transformations for 'host'
    assert 'cellpadding="3" width="100%" style="word-break: break-all;">' in transformed_html
    assert '<th width="40%">Compliance Issues' in transformed_html
    assert '<th width="25%">Cloud MetaData' in transformed_html
    assert '<th width="15%">Compliance Distribution' in transformed_html
    assert '<th width="20%">Hostname' in transformed_html


def test_transform_html_for_resource_container():
    """
    Given:
        Containers HTML data.

    When:
        Running transform_html_for_resource

    Then:
        Assert the returned output contains the desired changes.
    """
    # Test transformation for resource type 'container'
    transformed_html = transform_html_for_resource(html_containers_test_data, "container")
    # Assert transformations for 'container'
    assert 'cellpadding="3" width="120%" style="word-break: break-all;">' in transformed_html
    assert '<th width="23%">Compliance Issues' in transformed_html
    assert '<th width="15%">Cloud MetaData' in transformed_html
    assert '<th width="8%">Compliance Distribution' in transformed_html
    assert '<th width="15%">Container ID' in transformed_html
    assert '<th width="15%">Hostname' in transformed_html
    assert '<th width="15%">Image Name' in transformed_html


def test_transform_html_for_resource_image():
    """
    Given:
        Images HTML data.

    When:
        Running transform_html_for_resource

    Then:
        Assert the returned output contains the desired changes.
    """
    # Test transformation for resource type 'image'
    transformed_html = transform_html_for_resource(html_images_test_data, "image")
    # Assert transformations for 'image'
    assert 'cellpadding="3" width="120%" style="word-break: break-all;">' in transformed_html
    assert '<th width="23%">Compliance Issues' in transformed_html
    assert '<th width="15%">Cloud MetaData' in transformed_html
    assert '<th width="8%">Compliance Distribution' in transformed_html
    assert '<th width="15%">Image ID' in transformed_html
    assert '<th width="15%">Hosts' in transformed_html
    assert '<th width="15%">Image Instances' in transformed_html


@pytest.fixture
def html_content():
    return "<html><body><h1>Hello, World!</h1></body></html>"


@pytest.fixture
def email_data():
    return {
        "html": "<html><body><h1>Hello, World!</h1></body></html>",
        "resource_type": "vm",
        "to_email": "example@example.com"
    }


@patch("CreatePrismaCloudComputeResourceComplianceReportButton.demisto.executeCommand")
def test_send_html_email(mock_executeCommand, html_content, email_data):
    """
    Given:
        Email data and html content

    When:
        Running send_html_email

    Then:
        Assert the mocked send command with the expected body and output.
    """
    mock_executeCommand.return_value = [{'Type': EntryType.NOTE, "Contents": "Email sent successfully"}]
    send_html_email(**email_data)
    expected_html_body = email_data['html'].strip()
    mock_executeCommand.assert_called_once_with(
        "send-mail",
        {
            "to": email_data["to_email"],
            "subject": f"IMPORTANT: Prisma Cloud Compute {email_data['resource_type'].capitalize()} Compliance",
            "htmlBody": f"""
    Hello,

    Please see below the details for the compliance report from Prisma Cloud Compute

    {expected_html_body}
    """
        }
    )


@pytest.fixture
def email_xlsx_data():
    return {
        "file_id": "file_id_123",
        "file_name": "compliance_report.xlsx",
        "to_email": "example@example.com",
        "resource_type": "vm",
    }


@patch("CreatePrismaCloudComputeResourceComplianceReportButton.demisto.executeCommand")
def test_send_xlsx_email(mock_executeCommand, email_xlsx_data):
    """
    Given:
        Email data and xlsx data

    When:
        Running send_xlsx_email

    Then:
        Assert the mocked send command with the expected body and output.
    """
    mock_executeCommand.return_value = [{"Type": "NOTE", "Contents": "Email sent successfully"}]
    send_xlsx_email(**email_xlsx_data)
    mock_executeCommand.assert_called_once_with(
        "send-mail",
        {
            "to": email_xlsx_data["to_email"],
            "subject": f"IMPORTANT: Prisma Cloud Compute {email_xlsx_data['resource_type'].capitalize()} Compliance",
            "attachIDs": email_xlsx_data["file_id"],
            "attachNames": email_xlsx_data["file_name"],
            "body": "Please find attached file for the compliance report from Prisma Cloud Compute.",
        },
    )


RETURN_ERROR_TARGET = 'CreatePrismaCloudComputeResourceComplianceReportButton.return_error'


def test_main_function_with_error(mocker):
    """
    Given:
        An invalid output_type

    When:
        Running main

    Then:
        Assert the returned error matches the expected error.
    """
    # Mock the necessary components
    mocker.patch.object(demisto, 'args', return_value={'table': test_table_data, 'to': 'example@example.com',
                                                       'output_type': 'invalid', 'resource_type': 'host'})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    main()
    err_msg = return_error_mock.call_args_list[0][0][0]
    assert "Invalid output type. Supported types: 'html', 'xlsx'." in err_msg
