import demistomock as demisto  # noqa: F401
import pytest
import unittest
from GetProjectOwners import is_gcp_iam_account, extract_project_name, get_project_owners, get_iam_policy, main
from contextlib import nullcontext as does_not_raise


TEST_IAM_POLICY = [{
    "Contents": {
        "bindings": [
            {
                "members": [
                    "user:kball@paloaltonetworks.com",
                    "user:ptoman@paloaltonetworks.com"
                ],
                "role": "projects/expanse-afr-sbx/roles/CustomRole180"
            },
            {
                "members": [
                    "user:adm.aalshaea@paloaltonetworks.com",
                    "user:callu@paloaltonetworks.com",
                    "user:janny@paloaltonetworks.com",
                    "user:jwilkes@paloaltonetworks.com",
                    "user:pparikh@paloaltonetworks.com"
                ],
                "role": "roles/owner"
            },
        ],
        "etag": "BwX6ants6Ho=",
        "version": 1
    }
}]


@pytest.mark.parametrize('service_account, expected_out', [
    ('service-account-name@project-id.iam.gserviceaccount.com', True),
    ('project-id@appspot.gserviceaccount.com', False),  # App Engine default service account
    ('project-number-compute@developer.gserviceaccount.com', False),  # Compute Engine default service account
    ('service-agent-manager@system.gserviceaccount.com', False),  # Role manager for Google-managed service accounts
    ('person@example.com', False),
])
def test_is_gcp_iam_account(service_account, expected_out):
    assert is_gcp_iam_account(service_account) == expected_out


@pytest.mark.parametrize('service_account, expected_out, expected_raises', [
    ('service-account-name@project-id.iam.gserviceaccount.com', 'project-id', does_not_raise()),
    (
        'project-number-compute@developer.gserviceaccount.com',
        None,
        pytest.raises(
            ValueError,
            match="Could not extract project name from service account project-number-compute@developer.gserviceaccount.com"
        )
    ),
    (
        'person@example.com',
        None,
        pytest.raises(
            ValueError,
            match="Could not extract project name from service account person@example.com"
        )
    ),
])
def test_extract_project_name(service_account, expected_out, expected_raises):
    with expected_raises:
        assert extract_project_name(service_account) == expected_out


def test_get_iam_policy(mocker):
    # integration enabled; no error thrown
    demisto_execution_mock = mocker.patch.object(demisto, 'executeCommand', return_value=TEST_IAM_POLICY)
    with does_not_raise():
        assert get_iam_policy('project-id') == TEST_IAM_POLICY

    # integration disabled and/or error thrown
    demisto_execution_mock.side_effect = Exception('<Integration Error Msg>')
    with pytest.raises(RuntimeError, match='Error retrieving IAM policy for GCP project project-id'):
        get_iam_policy('project-id')


@pytest.mark.parametrize('results, expected_out, expected_raises', [
    (
        TEST_IAM_POLICY,
        [
            "adm.aalshaea@paloaltonetworks.com",
            "callu@paloaltonetworks.com",
            "janny@paloaltonetworks.com",
            "jwilkes@paloaltonetworks.com",
            "pparikh@paloaltonetworks.com"
        ],
        does_not_raise()
    ),
    (
        # no owners (not sure if this is even possible)
        [{
            "Contents": {
                "bindings": [
                    {
                        "members": [
                            "user:kball@paloaltonetworks.com",
                            "user:ptoman@paloaltonetworks.com"
                        ],
                        "role": "projects/expanse-afr-sbx/roles/CustomRole180"
                    },
                ],
                "etag": "BwX6ants6Ho=",
                "version": 1
            }
        }],
        [],
        does_not_raise()
    ),
    (
        [],
        None,
        pytest.raises(ValueError, match="Error getting project owners from IAM policy")
    ),

])
def test_get_project_owners(results, expected_out, expected_raises):
    with expected_raises:
        assert get_project_owners(results) == expected_out


@pytest.mark.parametrize('owners, external_service, expected_out', [
    (
        [],
        "Amazon Web Services",
        "No additional project owners found",
    ),
    (
        [],
        "Azure",
        "No additional project owners found",
    ),
    (
        [
            {
                "email": "test-service-5@expanse-afr-sbx.iam.gserviceaccount.com",
                "name": "n/a",
                "source": "GCP",
                "timestamp": "2023-05-30T00:00:00.000000Z",
            }

        ],
        "Google",
        "Project owners of service accounts written to asmserviceownerunrankedraw",
    ),
])
def test_main(mocker, owners, external_service, expected_out):
    arg_payload = {}
    arg_payload["owners"] = owners
    arg_payload["external_service"] = external_service
    mocker.patch.object(
        demisto,
        'args',
        return_value=arg_payload
    )
    mocker.patch(
        'GetProjectOwners.get_iam_policy',
        return_value=TEST_IAM_POLICY
    )
    mocker.patch("GetProjectOwners.return_results")
    results_mock = mocker.patch('GetProjectOwners.CommandResults')
    main()
    assert results_mock.call_args_list == [unittest.mock.call(readable_output=expected_out)]


def test_main_integration_error(mocker):
    """
    Verify that if get_iam_policy raises a RuntimeError, it's handled in main (main does not raise)
    """
    arg_payload = {}
    arg_payload["owners"] = [{
        "email": "test-service-5@expanse-afr-sbx.iam.gserviceaccount.com",
        "name": "n/a",
        "source": "GCP",
        "timestamp": "2023-05-30T00:00:00.000000Z",
    }]
    arg_payload["external_service"] = "Google"
    mocker.patch.object(
        demisto,
        'args',
        return_value=arg_payload
    )
    iam_policy_mock = mocker.patch("GetProjectOwners.get_iam_policy")
    iam_policy_mock.side_effect = RuntimeError("Error retrieving IAM policy for GCP project expanse-afr-sbx")

    mocker.patch("GetProjectOwners.return_results")
    results_mock = mocker.patch('GetProjectOwners.CommandResults')
    with does_not_raise():
        main()
    assert results_mock.call_args_list == [unittest.mock.call(readable_output="No additional project owners found")]


def test_main_project_name_error(mocker):
    """
    Verify that if extract_project_name raises a ValueError, it's handled in main (main does not raise)
    """
    arg_payload = {}
    arg_payload["owners"] = [{
        "email": "project-number-compute@developer.gserviceaccount.com",
        "name": "n/a",
        "source": "GCP",
        "timestamp": "2023-05-30T00:00:00.000000Z",
    }]
    arg_payload["external_service"] = "Google"
    mocker.patch.object(
        demisto,
        'args',
        return_value=arg_payload
    )
    project_mock = mocker.patch("GetProjectOwners.extract_project_name")
    project_mock.side_effect = ValueError(
        "Could not extract project name from service account project-number-compute@developer.gserviceaccount.com"
    )

    mocker.patch("GetProjectOwners.return_results")
    results_mock = mocker.patch('GetProjectOwners.CommandResults')
    with does_not_raise():
        main()
    assert results_mock.call_args_list == [unittest.mock.call(readable_output="No additional project owners found")]


def test_main_get_project_owners_error(mocker):
    """
    Verify that if get_project_owners raises a ValueError, it's handled in main (main does not raise)
    """
    arg_payload = {}
    arg_payload["owners"] = [{
        "email": "test-service-5@expanse-afr-sbx.iam.gserviceaccount.com",
        "name": "n/a",
        "source": "GCP",
        "timestamp": "2023-05-30T00:00:00.000000Z",
    }]
    arg_payload["external_service"] = "Google"
    mocker.patch.object(
        demisto,
        'args',
        return_value=arg_payload
    )
    project_mock = mocker.patch("GetProjectOwners.get_project_owners")
    project_mock.side_effect = ValueError("Error getting project owners from IAM policy")

    mocker.patch("GetProjectOwners.return_results")
    results_mock = mocker.patch('GetProjectOwners.CommandResults')
    with does_not_raise():
        main()
    assert results_mock.call_args_list == [unittest.mock.call(readable_output="No additional project owners found")]
