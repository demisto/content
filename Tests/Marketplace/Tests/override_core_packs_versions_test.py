import json
import os


def test_should_override_locked_corepacks_file(mocker):
    """
    When:
        - running the should_override_locked_corepacks_file command
    Given:
        1. A server version in the corepacks_override file that does not exist in the versions-metadata file
        2. A valid server version in the corepacks_override file, but a file version that is not greater than the
            file version in the versions-metadata file.
        3. The marketplace to override the corepacks file to, doesn't match the current marketplace.
        4. A valid server version and a file version greater than the file version in the versions-metadata file.
    Then:
        1. Assert that the result returned from the function is False
        2. Assert that the result returned from the function is False
        3. Assert that the result returned from the function is False
        4. Assert that the result returned from the function is True
    """

    from Tests.Marketplace.override_core_packs_versions import should_override_locked_corepacks_file
    from Tests.Marketplace.marketplace_constants import GCPConfig

    versions_metadata = {
        "8.2.0": {
            "core_packs_file": "corepacks-8.2.0.json",
            "core_packs_file_is_locked": True,
            "file_version": {
                "xsoar": "1",
                "xsoar_saas": "1",
                "marketplacev2": "1",
                "xpanse": "1"
            }
        }
    }
    mocker.patch.object(GCPConfig, "core_packs_file_versions", versions_metadata)

    # Case 1
    corepacks_override = {
        "server_version": "8.3.0",
        'xsoar':
            {
                "file_version": "1",
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }

            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert not should_override_locked_corepacks_file()

    # Case 2
    corepacks_override = {
        "server_version": "8.2.0",
        'xsoar':
            {
                "file_version": "1",
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }
            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert not should_override_locked_corepacks_file()

    # Case 3
    corepacks_override = {
        "server_version": "8.2.0",
        'xsoar':
            {
                "file_version": "1",
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }
            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert not should_override_locked_corepacks_file(marketplace='marketplacev2')

    # Case 4
    corepacks_override = {
        "server_version": "8.2.0",
        'xsoar':
            {
                "file_version": "2",
                "updated_corepacks_content":
                    {
                        "corePacks": [],
                        "upgradeCorePacks": [],
                        "buildNumber": "123"
                    }
            }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
    assert should_override_locked_corepacks_file()


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
            "file_version": "2",
            "updated_corepacks_content":
                {
                    "corePacks": ['pack1', 'pack2'],
                    "upgradeCorePacks": ['pack3'],
                    "buildNumber": "123"
                }

        }
    }
    mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)

    versions_metadata_content = {
        "version_map": {
            "8.2.0": {
                "core_packs_file": "corepacks-8.2.0.json",
                "core_packs_file_is_locked": True,
                "file_version": {
                    "xsoar": "1",
                    "xsoar_saas": "1",
                    "marketplacev2": "1",
                    "xpanse": "1"
                }
            }
        }
    }
    mocker.patch.object(GCPConfig, "versions_metadata_contents", versions_metadata_content)

    override_locked_corepacks_file(build_number='456', artifacts_dir=artifacts_dir, marketplace='xsoar')

    # Assert that the file was created in the artifacts folder with the build number as expected:
    with open(os.path.join(artifacts_dir, 'corepacks-8.2.0.json')) as corepacks_file:
        corepacks_file_contents = json.load(corepacks_file)
        assert corepacks_file_contents.get('buildNumber') == '456'
        assert corepacks_file_contents.get('corePacks') == ['pack1', 'pack2']

    # Assert that the versions-metadata file was updated with the required file version:
    assert GCPConfig.versions_metadata_contents.get('version_map').get('8.2.0').get('file_version').get('xsoar') == '2'

    # Remove the temp artifacts dir that was created for testing:
    shutil.rmtree(artifacts_dir)
