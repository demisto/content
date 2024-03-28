from PCComputeContainerComplianceIssuesButton import (
    run_prisma_cloud_compute_containers_scan_list,
    filter_compliance_issues,
    process_and_output_compliance_issues,
    main,
)
import pytest
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


compliance_issues: object = util_load_json("test_data/compliance_issues.json")

FILTERED_TEST_CASES = [
    ({"compliance_issues": compliance_issues, "compliance_ids": []}, compliance_issues),
    (
        {"compliance_issues": compliance_issues, "compliance_ids": "6112"},
        [compliance_issues[0]],
    ),
    (
        {"compliance_issues": compliance_issues, "compliance_ids": "6116, 6117"},
        [compliance_issues[1], compliance_issues[2]],
    ),
]

PROCESSED_TEST_CASES = [
    (
        {
            "compliance_issues": [compliance_issues[0]],
            "container_id": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        },
        [
            {
                "ComplianceID": "6112",
                "Cause": "The directory /tmp should be mounted. File: /proc/mounts",
                "Severity": "high",
                "Title": "(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured",
                "Description": "The /tmp directory is a world-writable directory used for temporary storage by all users\nand "
                               "some applications.",
            }
        ],
    ),
    (
        {
            "compliance_issues": [
                compliance_issues[0],
                compliance_issues[1],
                compliance_issues[2],
            ],
            "container_id": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        },
        [
            {
                "ComplianceID": "6112",
                "Cause": "The directory /tmp should be mounted. File: /proc/mounts",
                "Severity": "high",
                "Title": "(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured",
                "Description": "The /tmp directory is a world-writable directory used for temporary storage by all users\nand "
                               "some "
                "applications.",
            },
            {
                "ComplianceID": "6116",
                "Cause": "The directory /var should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var",
                "Description": "Description for compliance ID 6116",
            },
            {
                "ComplianceID": "6117",
                "Cause": "The directory /var/tmp should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp",
                "Description": "Description for compliance ID 6117",
            },
        ],
    ),
    (
        {
            "compliance_issues": compliance_issues,
            "container_id": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        },
        [
            {
                "ComplianceID": "6112",
                "Cause": "The directory /tmp should be mounted. File: /proc/mounts",
                "Severity": "high",
                "Title": "(CIS_Linux_2.0.0 - 1.1.2) Ensure /tmp is configured",
                "Description": "The /tmp directory is a world-writable directory used for temporary storage by all users\nand "
                               "some applications.",
            },
            {
                "ComplianceID": "6116",
                "Cause": "The directory /var should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.6) Ensure separate partition exists for /var",
                "Description": "Description for compliance ID 6116",
            },
            {
                "ComplianceID": "6117",
                "Cause": "The directory /var/tmp should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.7) Ensure separate partition exists for /var/tmp",
                "Description": "Description for compliance ID 6117",
            },
            {
                "ComplianceID": "61115",
                "Cause": "The directory /var/log should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.11) Ensure separate partition exists for /var/log",
                "Description": "Description for compliance ID 61115",
            },
            {
                "ComplianceID": "61116",
                "Cause": "The directory /var/log/audit should be mounted. File: /proc/mounts",
                "Severity": "medium",
                "Title": "(CIS_Linux_2.0.0 - 1.1.12) Ensure separate partition exists for /var/log/audit",
                "Description": "Description for compliance ID 61116",
            },
            {
                "ComplianceID": "602214",
                "Cause": "The service systemd-timesyncd.service should be enabled",
                "Severity": "low",
                "Title": "(CIS_Linux_2.0.0 - 2.2.1.4) Ensure systemd-timesyncd is configured",
                "Description": "Description for compliance ID 602214",
            },
        ],
    ),
]


def test_run_prisma_cloud_compute_containers_scan_list(mocker):
    """
    Given:
        A specific container ID.
        Given The results from the command "prisma-cloud-compute-container-scan-results-list" for that container ID.

    When:
        Running run_prisma_cloud_compute_containers_scan_list

    Then:
        Assert the returned output is the same as the given results for the given container ID.
    """
    # Mock the executeCommand function
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": EntryType.NOTE,
                "Contents": [{"info": {"complianceIssues": compliance_issues}}],
            }
        ],
    )

    # Run the function
    mocker.patch.object(demisto, "results")
    returned_compliance_issues = run_prisma_cloud_compute_containers_scan_list(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )

    assert returned_compliance_issues == compliance_issues


@pytest.mark.parametrize("args, expected", FILTERED_TEST_CASES)
def test_filter_compliance_issues(args, expected):
    """
    Given:
        All results for a container.

    When:
        Running filter_compliance_issues

    Then:
        Assert the returned output matches the filtered results, based on the "FILTERED_TEST_CASES" object.
    """
    filtered_results = filter_compliance_issues(
        args.get("compliance_issues"), args.get("compliance_ids")
    )
    assert filtered_results == expected


@pytest.mark.parametrize("args, expected", PROCESSED_TEST_CASES)
def test_process_and_output_compliance_issues(args, expected):
    """
    Given:
        Filtered results for a container.

    When:
        Running process_and_output_compliance_issues

    Then:
        Assert the returned output matches the processed results, based on the "PROCESSED_TEST_CASES" object.
    """
    processed_results = process_and_output_compliance_issues(
        args.get("compliance_issues"), args.get("container_id")
    )
    assert processed_results.outputs["compliance_issues"] == expected


RETURN_ERROR_TARGET = "PCComputeContainerComplianceIssuesButton.return_error"


def test_main_with_error(mocker):
    """
    Given:
        An invalid container ID argument

    When:
        Running main

    Then:
        Assert the returned error matches the expected error.
    """
    # Mock the necessary components
    mocker.patch.object(demisto, "getArg", side_effect="invalid_container_id")
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    main()
    err_msg = return_error_mock.call_args_list[0][0][0]
    assert (
        "Invalid container_id. Please verify that you entered a valid 64-character container ID."
        in err_msg
    )
