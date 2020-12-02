from __future__ import print_function

import glob
import sys
import zipfile
from time import sleep
from ruamel import yaml
from typing import List
import logging

from Tests.scripts.utils.log_util import install_simple_logging
from demisto_sdk.commands.common.tools import find_type
from Tests.configure_and_test_integration_instances import Build, configure_servers_and_restart, \
    get_tests, \
    get_changed_integrations, configure_server_instances, instance_testing, disable_instances, \
    report_tests_status, nightly_install_packs, test_files, \
    test_pack_metadata, options_handler
from Tests.Marketplace.search_and_install_packs import \
    search_and_install_packs_and_their_dependencies_private, upload_zipped_packs


def install_private_testing_pack(build: Build, test_pack_zip_path: str):
    """
    Creates and installs the test pack used in the private build. This pack contains the test
    playbooks and test scripts that will be used for the tests.

    :param build: Build object containing the build settings.
    :param test_pack_zip_path: Path to test_pack zip.
    :return: No object is returned. nightly_install_packs will wait for the process to finish.
    """
    nightly_install_packs(build, install_method=upload_zipped_packs,
                          pack_path=test_pack_zip_path)


def install_packs_private(build: Build, pack_ids: list = None) -> bool:
    """
    Wrapper for the search and install packs function.

    :param build: Build object containing the build settings.
    :param pack_ids: Optional, list of packs to install. List contains pack id and version requested.
    :return: Boolean indicating if the installation was successful.
    """
    pack_ids = pack_ids if pack_ids else build.pack_ids_to_install
    installed_content_packs_successfully = True
    for server in build.servers:
        try:
            flag = search_and_install_packs_and_their_dependencies_private(build.test_pack_path,
                                                                           pack_ids, server.client)
            if not flag:
                raise Exception('Failed to search and install packs.')
        except Exception:
            logging.exception('Failed to search and install packs.')
            installed_content_packs_successfully = False

    return installed_content_packs_successfully


def find_needed_test_playbook_paths(test_playbooks: List[dict], tests_to_run: List,
                                    path_to_content: str) -> set:
    """
    Uses the test filter file to determine which test playbooks are needed to run, then will use the
    test playbook IDs found in the ID set to determine what the path is for that test.

    :param tests_to_run: List of tests to run.
    :param path_to_content: Path to the content root.
    :param test_playbooks: The test_playbooks dictionary from the ID set.
    :return: tests_file_paths set used to keep file paths of found tests.
    """
    tests_file_paths = set()
    for test_to_run in tests_to_run:
        if any(test_to_run in d for d in test_playbooks):
            for test_pb in test_playbooks:
                if test_to_run in test_pb:
                    tests_file_paths.add(path_to_content + '/' + test_pb[test_to_run].get("file_path"))
    #  Adding contents of DeveloperPack for testing.
    #  TODO: Remove this when we have migrated test content out of this pack.
    developer_pack_items = glob.glob(path_to_content + "/Packs/DeveloperTools/*/*.yml")
    for dev_pack_item in developer_pack_items:
        tests_file_paths.add(dev_pack_item)
    return tests_file_paths


def write_test_pack_zip(tests_file_paths: set, path_to_content: str,
                        zip_destination_dir: str) -> str:
    """
    Builds and writes the test pack when given a set of file paths.

    :param path_to_content: Path to the content root.
    :param tests_file_paths: Set of file paths to add to the test pack zip.
    :param zip_destination_dir: Directory to create the test pack in.
    :return: Path to where the private content test pack is located.
    """
    private_content_test_zip = zip_destination_dir + '/test_pack.zip'
    with zipfile.ZipFile(private_content_test_zip, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('test_pack/metadata.json', test_pack_metadata())
        for test_path, test in test_files(path_to_content):
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
    return private_content_test_zip


def main():
    install_simple_logging()
    build = Build(options_handler())

    configure_servers_and_restart(build)
    #  Get a list of the test we need to run.
    tests_for_iteration = get_tests(build)
    #  Installing the packs.
    installed_content_packs_successfully = install_packs_private(build)
    #  Get a list of the integrations that have changed.
    new_integrations, modified_integrations = get_changed_integrations(build)
    #  Configuring the instances which are used in testing.
    all_module_instances, brand_new_integrations = \
        configure_server_instances(build, tests_for_iteration, new_integrations, modified_integrations)

    #  Running the instance tests (pushing the test button)
    successful_tests_pre, failed_tests_pre = instance_testing(build, all_module_instances, pre_update=True)
    #  Adding the new integrations to the instance test list and testing them.
    all_module_instances.extend(brand_new_integrations)
    successful_tests_post, failed_tests_post = instance_testing(build, all_module_instances, pre_update=False)
    #  Done running tests so we are disabling the instances.
    disable_instances(build)
    #  Gather tests to add to test pack
    test_playbooks_from_id_set = build.id_set.get('TestPlaybooks', [])
    tests_to_add_to_test_pack = find_needed_test_playbook_paths(test_playbooks=test_playbooks_from_id_set,
                                                                tests_to_run=build.tests_to_run,
                                                                path_to_content=build.content_root)
    #  Write the test pack
    private_content_test_zip = write_test_pack_zip(zip_destination_dir=build.test_pack_path,
                                                   tests_file_paths=tests_to_add_to_test_pack,
                                                   path_to_content=build.content_root)
    # Create and install private test pack
    install_private_testing_pack(build, private_content_test_zip)

    success = report_tests_status(failed_tests_pre, failed_tests_post, successful_tests_pre, successful_tests_post,
                                  new_integrations)
    sleep(30)
    if not success or not installed_content_packs_successfully:
        sys.exit(2)


if __name__ == '__main__':
    main()
