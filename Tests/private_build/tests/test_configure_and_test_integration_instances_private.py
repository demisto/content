import tempfile
import glob
import zipfile
from io import StringIO
import demisto_client

from Tests.private_build.configure_and_test_integration_instances_private import \
    find_needed_test_playbook_paths, install_private_testing_pack, write_test_pack_zip,\
    install_packs_private
import Tests.Marketplace.search_and_install_packs as script


class ServerMock:

    def __init__(self):
        self.__ssh_client = None
        self.__client = None
        self.host = 'https://8.8.8.8'
        self.user_name = 'TestUser'
        self.password = 'TestPassword'

    @property
    def client(self):
        client = MockClient()
        return client


class MockConfiguration:
    def __init__(self):
        self.host = None


class MockApiClient:
    def __init__(self):
        self.configuration = MockConfiguration()

    def call_api(self, resource_path, method, header_params, files):

        return 'MOCK_HELLOWORLD_SEARCH_RESULTS', 200, None


class MockClient:
    def __init__(self):
        self.api_client = MockApiClient()


class BuildMock:

    def __init__(self):
        self.git_sha1 = 'sampleSHA1'
        self.branch_name = 'test-branch'
        self.ci_build_number = '100'
        self.is_nightly = False
        self.ami_env = 'Server Master'
        self.servers, self.server_numeric_version = ('8.8.8.8', '6.1.0')
        self.secret_conf = {}
        self.username = 'TestUser'
        self.password = 'TestPassword'
        self.servers = [ServerMock()]
        self.is_private = True
        self.tests = {}
        self.skipped_integrations_conf = {}
        self.id_set = {}
        self.test_pack_path = ''
        self.pack_ids_to_install = []
        self.service_account = None


def test_find_needed_test_playbook_paths():
    """
    Scenario: Matching a test which is needed with available playbooks found in the ID set.
    Given: Test filter with HelloWorld_Scan-Test in it and a sample test playbook conf
    When: Finding the file path of the test
    Then: Return a set with 51 items (50 from DeveloperTools, 1 From test filter) in it where the
          item is the file_path for the test.
    """
    tests_to_run = ["HelloWorldPremium_Scan-Test", "AnotherTest"]
    test_playbook_conf = [
        {
            "HelloWorldPremium_Scan-Test": {
                "name": "HelloWorld_Scan-Test",
                "file_path": "Packs/HelloWorld/TestPlaybooks/playbook-HelloWorld_Scan-Test.yml",
                "fromversion": "5.0.0",
                "implementing_scripts": [
                    "DeleteContext"
                ],
                "implementing_playbooks": [
                    "HelloWorld Scan"
                ],
                "pack": "HelloWorld"
            }
        }
    ]

    file_paths = find_needed_test_playbook_paths(test_playbooks=test_playbook_conf,
                                                 tests_to_run=tests_to_run,
                                                 path_to_content='.')
    assert len(file_paths) == 52
    assert './Packs/HelloWorld/TestPlaybooks/playbook-HelloWorld_Scan-Test.yml' in file_paths


def test_create_install_private_testing_pack(mocker):
    """
    Scenario: Creating and installing a pack for testing. Pack will contain no items as it is mocked
              in this test. Empty pack will be created and uploaded to mock server. Server returns a
              200 status code.
    Given: A mocked test pack
    When: Installing a pack to the server
    Then: Return the success flag set to true indicating the request to install the pack was successful

    """

    def mocked_generic_request_func(self, path: str, method, body=None, accept=None,
                                    _request_timeout=None):
        if path == '/contentpacks/marketplace/install':
            return 'MOCK_PACKS_INSTALLATION_RESULT', 200, None
        return None, None, None

    mocker.patch.object(demisto_client, 'generic_request_func',
                        side_effect=mocked_generic_request_func)
    mock_build = BuildMock()
    install_private_testing_pack(mock_build, 'testing/path/to/test_pack.zip')
    assert script.SUCCESS_FLAG


def test_write_test_pack_zip(tmpdir):
    """
    Scenario: Testing the HelloWorld pack should result in the test pack containing the HelloWorld
              Scan test.
    Given: a set containing the HelloWorld-Scan_test playbook.
    When: Creating a testing pack for premium builds
    Then: Create a valid test pack containing metadata, items from developer tools, and the given
          test playbook.
    """

    set_of_test_paths = {'./Packs/HelloWorld/TestPlaybooks/playbook-HelloWorld_Scan-Test.yml',
                         './Packs/DeveloperTools/TestPlaybooks/script-TestCreateIncidentsFile.yml'}
    private_content_test_zip = write_test_pack_zip(path_to_content='.', zip_destination_dir=tmpdir,
                                                   tests_file_paths=set_of_test_paths)
    #  Opening created pack
    with tempfile.TemporaryDirectory() as extract_dir:
        with zipfile.ZipFile(private_content_test_zip, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
            #  Check that metadata is present
            dir_containing_metadata = glob.glob(extract_dir + '/test_pack/*')
            expected_metadata_file_path = extract_dir + '/test_pack/metadata.json'
            assert expected_metadata_file_path in dir_containing_metadata

            #  Check that file from DeveloperTools is present
            dir_containing_test_script = glob.glob(extract_dir + '/test_pack/*/*')
            expected_test_script_file_path = extract_dir + '/test_pack/TestPlaybooks/script-' \
                                                           'TestCreateIncidentsFile.yml'
            assert expected_test_script_file_path in dir_containing_test_script
            #  Check that item collected in needed_test_playbook_paths is present.
            expected_hello_world_test_file_path = extract_dir + '/test_pack/TestPlaybooks/' \
                                                                'playbook-HelloWorld_Scan-Test.yml'
            assert expected_hello_world_test_file_path in dir_containing_test_script


def test_install_packs_private(mocker):
    """
    Scenario: Given a pack ID to install, the test will simulate opening the content_packs_to_install
              file and will first install the Demisto test license, then install the pack from the
              artifacts directory. Important to note here, that the server does not return any status
              code to indicate that the upload was successful. As long as the request returns a 200,
              we assume the installation was successful. This should be changed at some point however.
    Given: The test pack ID "TEST"
    When: Installing the pack from the artifacts directory
    Then: Collect the pack ID from the packs to install file, update the license, and upload the pack.
    """

    mocker.patch('Tests.Marketplace.search_and_install_packs.open', return_value=StringIO('HelloWorld\nTEST'))
    mocker.patch('Tests.Marketplace.search_and_install_packs.search_pack_and_its_dependencies')

    def mocked_generic_request_func(self, path: str, method, body=None, accept=None,
                                    _request_timeout=None):
        if path == '/contentpacks/marketplace/install':
            return 'MOCK_PACKS_INSTALLATION_RESULT', 200, None
        return None, None, None

    mocker.patch.object(demisto_client, 'generic_request_func',
                        side_effect=mocked_generic_request_func)
    mocker.patch.object(glob, 'glob', return_value=['content/artifacts/packs/TEST.zip'])
    mock_build = BuildMock()
    mock_build.test_pack_path = 'content/artifacts/packs'
    mock_build.pack_ids_to_install = ['TestPack']
    test_results = install_packs_private(build=mock_build, pack_ids=['TEST'])
    assert test_results is True
