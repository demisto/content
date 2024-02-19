import json
import os
import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mocked_content_repo():
    mocked_content_repo = MagicMock()
    mocked_commit = MagicMock()
    mocked_blob = MagicMock()
    mocked_blob.data_stream.read.return_value = b'{\
            "server_version": "8.3.0",\
            "xsoar":\
                {\
                    "updated_corepacks_content":\
                        {\
                            "corePacks": [],\
                            "upgradeCorePacks": [],\
                            "buildNumber": "123"\
                        }\
                }\
        }'
    mocked_commit.tree.__truediv__.return_value = mocked_blob
    mocked_content_repo.commit.return_value = mocked_commit
    yield mocked_content_repo


def test_should_override_locked_corepacks_file(mocker, mocked_content_repo):
    """
    When:
        - running the should_override_locked_corepacks_file command
    Given:
        1. corepacks_versions.json file that wasn't changed since last upload.
        2. corepacks_versions.json file that was changed since last upload, and the marketplace is as the upload.
        3. corepacks_versions.json file that was changed since last upload, but the marketplace is not as the upload.
    Then:
        1. Assert that the result returned from the function is False
        2. Assert that the result returned from the function is True
        3. Assert that the result returned from the function is False
    """

    from Tests.Marketplace.override_core_packs_versions import should_override_locked_corepacks_file
    from Tests.Marketplace.marketplace_constants import GCPConfig
    marketplace = "xsoar"
    last_upload_commit = "abcd1234"

    mocker.patch('Tests.Marketplace.override_core_packs_versions.get_content_git_client', return_value=mocked_content_repo)

    # Case 1
    corepacks_override = {
        "server_version": "8.3.0",
        'xsoar':
            {
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }

            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert not should_override_locked_corepacks_file(marketplace, last_upload_commit)

    # Case 2
    corepacks_override = {
        "server_version": "8.2.0",
        'xsoar':
            {
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }
            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert should_override_locked_corepacks_file(marketplace, last_upload_commit)

    # Case 3
    corepacks_override = {
        "server_version": "8.2.0",
        'marketplacev2':
            {
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }
            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert not should_override_locked_corepacks_file(marketplace, last_upload_commit)


def test_override_locked_corepacks_file(mocker):
    """
    Test the override_locked_corepacks_file function.
    """
    from Tests.Marketplace.override_core_packs_versions import override_locked_corepacks_file
    from Tests.Marketplace.marketplace_constants import GCPConfig
    import shutil

    # Create a temp artifacts dir for the corepacks files:
    artifacts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
    os.makedirs(artifacts_dir, exist_ok=True)

    corepacks_override = {
        "server_version": "8.2.0",
        "xsoar": {
            "updated_corepacks_content":
                {
                    "corePacks": ['pack1', 'pack2'],
                    "upgradeCorePacks": ['pack3'],
                    "buildNumber": "123"
                }

        }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)

    override_locked_corepacks_file(build_number='456', artifacts_dir=artifacts_dir, marketplace='xsoar')

    # Assert that the file was created in the artifacts folder with the build number as expected:
    with open(os.path.join(artifacts_dir, 'corepacks-8.2.0.json')) as corepacks_file:
        corepacks_file_contents = json.load(corepacks_file)
        assert corepacks_file_contents.get('buildNumber') == '456'
        assert corepacks_file_contents.get('corePacks') == ['pack1', 'pack2']

    # Remove the temp artifacts dir that was created for testing:
    shutil.rmtree(artifacts_dir)
