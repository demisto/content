import tempfile
import glob
import zipfile
import demisto_client

from Tests.private_build.configure_and_test_integration_instances_private import \
    find_needed_test_playbook_paths, create_install_private_testing_pack, create_private_test_pack_zip
import Tests.Marketplace.search_and_install_packs as script
from Tests.configure_and_test_integration_instances import get_json_file
from Tests.tests.constants_testing import SAMPLE_TESTPLAYBOOK_CONF
from Tests.test_content import ParallelPrintsManager


TEST_PLAYBOOK_FILE_PATHS = {'/Packs/HelloWorld/TestPlaybooks/playbook-HelloWorld_Scan-Test.yml'}


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


def mocked_generic_request_func(self, path: str, method, body=None, accept=None, _request_timeout=None):
    if path == '/contentpacks/marketplace/install':
        return 'MOCK_PACKS_INSTALLATION_RESULT', 200, None
    return None, None, None


def test_find_needed_test_playbook_paths():
    """
    Scenario: Matching a test which is needed with available playbooks found in the ID set.
    Given: Test filter with HelloWorld_Scan-Test in it and a sample test playbook conf
    When: Finding the file path of the test
    Then: Return a set with one item in it where the item is the file_path for the test.
    :return:
    """
    sample_test_filter_path = './Utils/tests/test_data_old_content/sample_test_filter.txt'
    file_paths = find_needed_test_playbook_paths(test_playbooks=SAMPLE_TESTPLAYBOOK_CONF,
                                                 filter_file_path=sample_test_filter_path)
    assert len(file_paths) == 1
    assert file_paths == TEST_PLAYBOOK_FILE_PATHS


def test_create_install_private_testing_pack(mocker):
    """
    Scenario: Creating and installing a pack for testing. Pack will contain no items as it is mocked
              in this test. Empty pack will be created and uploaded to mock server. Server returns a
              200 status code.
    Given: A mocked test pack
    When: Installing a pack to the server
    Then: Return the success flag set to true indicating the request to install the pack was successful

    """
    prints_manager = ParallelPrintsManager(len(BuildMock().servers))
    mocker.patch('Tests.private_build.configure_and_test_integration_instances_private.create_'
                 'private_test_pack_zip')
    mocker.patch.object(demisto_client, 'generic_request_func',
                        side_effect=mocked_generic_request_func)
    create_install_private_testing_pack(BuildMock(), prints_manager)
    assert script.SUCCESS_FLAG


def test_create_private_test_pack_zip(mocker):
    """
    Scenario: Testing the HelloWorld pack should result in the test pack containing the HelloWorld
              Scan test.
    Given: a set containing the HelloWorld-Scan_test playbook.
    When: Creating a testing pack for premium builds
    Then: Create a valid test pack containing metadata, items from developer tools, and the given
          test playbook.
    """
    with tempfile.TemporaryDirectory() as dirpath:
        id_set = get_json_file('Utils/tests/id_set.json')
        mocker.patch('Tests.private_build.configure_and_test_integration_instances_private.find_'
                     'needed_test_playbook_paths', return_value=TEST_PLAYBOOK_FILE_PATHS)
        mocker.patch('Tests.private_build.configure_and_test_integration_instances_private.PRIVATE_'
                     'CONTENT_TEST_ZIP', dirpath + 'test.zip')
        mocker.patch('Tests.private_build.configure_and_test_integration_instances_private.PRIVATE_'
                     'CONTENT_PATH', './')
        mocker.patch('shutil.copy')
        create_private_test_pack_zip(id_set)
        #  Opening created pack
        with tempfile.TemporaryDirectory() as extract_dir:
            with zipfile.ZipFile(dirpath+'test.zip', "r") as zip_ref:
                zip_ref.extractall(extract_dir)
                dir_containing_metadata = glob.glob(extract_dir + '/test_pack/*')
                #  Check that metadata is present
                expected_metadata_file_path = extract_dir+'/test_pack/metadata.json'
                assert expected_metadata_file_path in dir_containing_metadata
                dir_containing_test_script = glob.glob(extract_dir + '/test_pack/*/*')
                #  Check that file from DeveloperTools is present
                expected_test_script_file_path = extract_dir + '/test_pack/TestPlaybooks/script-' \
                                                               'TestCreateIncidentsFile.yml'
                assert expected_test_script_file_path in dir_containing_test_script
                #  Check that item collected in needed_test_playbook_paths is present.
                expected_hello_world_test_file_path = extract_dir + '/test_pack/TestPlaybooks/' \
                                                                    'playbook-HelloWorld_Scan-Test.yml'
                assert expected_hello_world_test_file_path in dir_containing_test_script

