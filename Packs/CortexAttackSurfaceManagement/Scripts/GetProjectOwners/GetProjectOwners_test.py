import demistomock as demisto  # noqa: F401
import pytest
import unittest
from GetProjectOwners import is_gcp_iam_account, extract_project_name, get_project_owners, main
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
    ('project-number-compute@developer.gserviceaccount.com', None, pytest.raises(ValueError)),
    ('person@example.com', None, pytest.raises(ValueError)),
])
def test_extract_project_name(service_account, expected_out, expected_raises):
    with expected_raises:
        assert extract_project_name(service_account) == expected_out


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
        pytest.raises(ValueError)
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
