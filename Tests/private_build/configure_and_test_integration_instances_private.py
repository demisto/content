from __future__ import print_function

import glob
import shutil
import sys
import zipfile
from time import sleep
from ruamel import yaml

from demisto_sdk.commands.common.tools import print_error, print_warning, find_type
from Tests.test_content import ParallelPrintsManager
from Tests.Marketplace.search_and_install_packs import \
    search_and_install_packs_and_their_dependencies_private, upload_zipped_packs
from Tests.configure_and_test_integration_instances import Build, configure_servers_and_restart, \
    get_tests, \
    get_changed_integrations, configure_server_instances, instance_testing, disable_instances, \
    report_tests_status, nightly_install_packs, get_pack_ids_to_install, test_files, \
    test_pack_metadata, options_handler


PRIVATE_CONTENT_PATH = '/home/runner/work/content-private/content-private/content'
PRIVATE_CONTENT_TEST_ZIP = PRIVATE_CONTENT_PATH + '/test_pack.zip'
FILTER_FILE_PATH = "./Tests/filter_file.txt"


def create_install_private_testing_pack(build, prints_manager):
    """
    Creates and installs the test pack used in the private build. This pack contains the test
    playbooks and test scripts that will be used for the tests.
    :param build: Build object containing the build settings.
    :param prints_manager: PrintsManager object used for reporting status. Will be deprecated.
    :return: No object is returned. nightly_install_packs will wait for the process to finish.
    """
    threads_print_manager = ParallelPrintsManager(len(build.servers))

    create_private_test_pack_zip(build.id_set)
    nightly_install_packs(build, threads_print_manager, install_method=upload_zipped_packs,
                          pack_path=PRIVATE_CONTENT_TEST_ZIP)

    prints_manager.add_print_job('Sleeping for 45 seconds...', print_warning, 0,
                                 include_timestamp=True)
    prints_manager.execute_thread_prints(0)
    sleep(45)


def install_packs_private(build, prints_manager, pack_ids=None):
    """
    Wrapper for the search and install packs function.

    :param build: Build object containing the build settings.
    :param prints_manager: PrintsManager object used for reporting status. Will be deprecated.
    :param pack_ids: Optional, list of packs to install. List contains pack id and version requested.
    :return: Boolean indicating if the installation was successful.
    """
    pack_ids = get_pack_ids_to_install() if pack_ids is None else pack_ids
    installed_content_packs_successfully = True
    for server in build.servers:
        try:
            _, flag = search_and_install_packs_and_their_dependencies_private(pack_ids, server.client, prints_manager)
            if not flag:
                raise Exception('Failed to search and install packs.')
        except Exception as exc:
            prints_manager.add_print_job(str(exc), print_error, 0)
            prints_manager.execute_thread_prints(0)
            installed_content_packs_successfully = False

    return installed_content_packs_successfully


def find_needed_test_playbook_paths(test_playbooks, filter_file_path):
    """
    Uses the test filter file to determine which test playbooks are needed to run, then will use the
    test playbook IDs found in the ID set to determine what the path is for that test.
    :param filter_file_path:
    :param test_playbooks: The test_playbooks dictionary from the ID set.
    :return: tests_file_paths set used to keep file paths of found tests.
    """
    tests_file_paths = set()
    with open(filter_file_path, "r") as filter_file:
        tests_to_run = filter_file.readlines()
        for test_to_run in tests_to_run:
            test_clean = test_to_run.rstrip()
            if any(test_clean in d for d in test_playbooks):
                for test_pb in test_playbooks:
                    if test_clean in test_pb:
                        tests_file_paths.add(PRIVATE_CONTENT_PATH + '/' + test_pb[test_clean].get("file_path"))
    return tests_file_paths


def write_test_pack_zip(tests_file_paths):
    """
    Builds and writes the test pack when given a set of file paths.
    :param tests_file_paths: Set of file paths to add to the test pack zip.
    :return:
    """
    with zipfile.ZipFile(PRIVATE_CONTENT_TEST_ZIP, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('test_pack/metadata.json', test_pack_metadata())
        for test_path, test in test_files(PRIVATE_CONTENT_PATH):
            if test_path not in tests_file_paths:
                continue
            if not test_path.endswith('.yml'):
                continue
            test = test.name
            with open(test_path, 'r') as test_file:
                if not (test.startswith('playbook-') or test.startswith('script-')):
                    test_type = find_type(_dict=yaml.safe_load(test_file), file_type='yml').value
                    test_file.seek(0)
                    test_target = f'test_pack/TestPlaybooks/{test_type}-{test}'
                else:
                    test_target = f'test_pack/TestPlaybooks/{test}'
                zip_file.writestr(test_target, test_file.read())


def create_private_test_pack_zip(id_set=None):
    """
    Creates the test pack with all of the scripts and dependant playbooks for the private tests.
    :param id_set: ID set file object.
    :return: None
    """
    #  Retrieve test playbooks object from the ID set.
    test_playbooks = id_set.get('TestPlaybooks', [])
    #  Finding test playbook paths needed for testing
    tests_file_paths = find_needed_test_playbook_paths(test_playbooks, FILTER_FILE_PATH)
    #  Adding contents of DeveloperPack for testing.
    #  TODO: Remove this when we have migrated test content out of this pack.
    developer_pack_items = glob.glob(PRIVATE_CONTENT_PATH + "/Packs/DeveloperTools/*/*.yml")
    for dev_pack_item in developer_pack_items:
        tests_file_paths.add(dev_pack_item)
    #  Write the test pack using collected file paths
    write_test_pack_zip(tests_file_paths)
    #  Copy the test pack to the private artifacts directory.
    shutil.copy(PRIVATE_CONTENT_TEST_ZIP,
                '/home/runner/work/content-private/content'
                '-private/content/artifacts/packs/test_pack.zip')
    print("Finished creating test pack.")


def main():
    build = Build(options_handler())
    prints_manager = ParallelPrintsManager(1)

    configure_servers_and_restart(build, prints_manager)
    #  Get a list of the test we need to run.
    tests_for_iteration = get_tests(build.server_numeric_version, prints_manager, build.tests)
    #  Installing the packs.
    installed_content_packs_successfully = install_packs_private(build, prints_manager)
    #  Get a list of the integrations that have changed.
    new_integrations, modified_integrations = get_changed_integrations(build, prints_manager)
    #  Configuring the instances which are used in testing.
    all_module_instances, brand_new_integrations = \
        configure_server_instances(build, tests_for_iteration, new_integrations,
                                   modified_integrations, prints_manager)

    #  Running the instance tests (pushing the test button)
    successful_tests_pre, failed_tests_pre = instance_testing(build, all_module_instances,
                                                              prints_manager,
                                                              pre_update=True)
    #  Adding the new integrations to the instance test list and testing them.
    all_module_instances.extend(brand_new_integrations)
    successful_tests_post, failed_tests_post = instance_testing(build, all_module_instances,
                                                                prints_manager,
                                                                pre_update=False)
    #  Done running tests so we are disabling the instances.
    disable_instances(build, all_module_instances, prints_manager)
    # Create and install private test pack
    create_install_private_testing_pack(build, prints_manager)

    success = report_tests_status(failed_tests_pre, failed_tests_post, successful_tests_pre, successful_tests_post,
                                  new_integrations, prints_manager)
    sleep(30)
    if not success or not installed_content_packs_successfully:
        sys.exit(2)


if __name__ == '__main__':
    main()
