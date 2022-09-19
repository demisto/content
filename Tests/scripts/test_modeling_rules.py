import argparse
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import sys
from typing import Any, Optional, no_type_check
from Tests.Marketplace.search_and_uninstall_pack import (reset_base_pack_version,
                                                         uninstall_all_packs,
                                                         wait_for_uninstallation_to_complete)
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import PackManager

from Tests.configure_and_test_integration_instances import XSIAMBuild
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from time import sleep
from demisto_sdk.commands.common.content.objects.pack_objects.modeling_rule.modeling_rule import ModelingRule
from google.oauth2 import service_account
from google.cloud import pubsub_v1
from pubsub_v1 import PublishClient


class ModelingRuleTestException(BaseException):
    pass


PATHS = PathManager(Path(__file__).absolute().parents[3])
PACK_MANAGER = PackManager(PATHS)


def options_handler(args=None):
    """
    Returns: options parsed from input arguments.
    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')

    parser.add_argument('-l', '--tests_to_run', help='Path to the Test Filter.',
                        default='./artifacts/filter_file.txt')
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.',
                        default='./artifacts/content_packs_to_install.txt')
    parser.add_argument('--build_object_type', help='Build type running: XSOAR or XSIAM')
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to secret xsiam server metadata file.')
    parser.add_argument('--xsiam_servers_api_keys', help='Path to file with XSIAM Servers api keys.')
    # disable-secrets-detection-start
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    options = parser.parse_args(args)
    return options


def clean_xsiam_tenant(xsiam_build: XSIAMBuild) -> bool:
    client = xsiam_build.servers[0].client
    if not client:
        err_msg = (f'expected {xsiam_build=} to have a "server" property whose value is a list of Server class'
                   'instances with a length of at least 1 where the server instance has a "client" property.')
        raise AttributeError(err_msg)
    host = xsiam_build.xsiam_machine
    success = reset_base_pack_version(client)
    success = success and uninstall_all_packs(client, host) and wait_for_uninstallation_to_complete(client)
    return success


def get_modeling_rules_to_test(mrs_to_test_filepath: Path = PATHS.output_mrs_to_test_file) -> list[Path]:
    """
    Fetches the modeling rules list to test from the file created during test collection.

    Arguments:
        mrs_to_test_filepath(Path): Path to location of the list of modeling rules that need to be tested

    Returns:
        list[Path]: List of paths to the modeling rules that need to be tested
    """
    modeling_rules = []
    with open(mrs_to_test_filepath, "r") as mrs_list_file:
        mrs_from_file = mrs_list_file.readlines()
        for mr_from_file in mrs_from_file:
            mr = mr_from_file.rstrip()
            modeling_rules.append(PATHS.packs_path / mr)
    return modeling_rules


def create_google_pubsub_client(service_account_filepath: str):
    credentials = service_account.Credentials.from_service_account_file(service_account_filepath)
    publisher = pubsub_v1.PublisherClient(credentials)
    return publisher


def create_dataset(xsiam_build: XSIAMBuild, modeling_rule: ModelingRule, pub_sub_client: PublishClient) -> bool:
    if not modeling_rule.testdata_path:
        testdata_filepath = modeling_rule.path.parent / f'{modeling_rule.path.parent.name}_testdata.json'
        raise ModelingRuleTestException(f'No file with test data was found in {testdata_filepath}')
    else:
        data = json.load(modeling_rule.testdata_path.open('r'))
        metablob: dict[str, Any] = data.get('metablob')
        event_data: list[dict[str, Any]] = data.get('event_data')
        event_data_as_str = '\n'.join([json.dumps(event) for event in event_data])
        pubsub_msg = BytesIO(bytes(f'{json.dumps(metablob)}\n{event_data_as_str}', encoding='utf-8'))
        xsiam_project_number = xsiam_build.xsiam_machine.split('-')[-1]
        topic = pub_sub_client.topic_path(xsiam_build.xsiam_machine, f'ext-logs-{xsiam_project_number}')
        # topic_name = f'projects/{xsiam_build.xsiam_machine}/topics/ext-logs-{xsiam_project_number}'
        future = pub_sub_client.publish(topic, pubsub_msg.getvalue())
        future.result()
        return True


def get_mr_instance(modeling_rule: Path) -> ModelingRule:
    mr = ModelingRule(modeling_rule.as_posix())
    unified = mr._unify(mr.path.parent)[0]
    mr = ModelingRule(unified)
    return mr


def test_modeling_rule(xsiam_build: XSIAMBuild, modeling_rule: ModelingRule, pub_sub_client: PublishClient) -> bool:
    # clean tenant
    if not clean_xsiam_tenant(xsiam_build):
        raise ModelingRuleTestException(f'Failed to clean the xsiam tenant for testing of {modeling_rule.path.parent}')

    # install pack of modeling rule
    pack_id = modeling_rule.path.parts[modeling_rule.path.parts.index('Packs') + 1]
    if not xsiam_build.install_packs([pack_id]):
        raise ModelingRuleTestException(f'Failed to install the pack for testing of {modeling_rule.path.parent}')

    try:
        # create dataset from modeling rule's testdata
        if not create_dataset(xsiam_build, modeling_rule, pub_sub_client):
            ...
    except ModelingRuleTestException as e:
        testdata_filepath = modeling_rule.path.parent / f'{modeling_rule.path.parent.name}_testdata.json'
        no_testdata_err = f'No file with test data was found in {testdata_filepath}'
        if f'{e}' == no_testdata_err:
            logging.warning(no_testdata_err)
            return True
        raise

    # perform xql query
    if not execute_xql_query():
        ...
    return True


def main():
    install_logging('test_modeling_rules.log', logger=logging)

    # in xsiam we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    xsiam_build = XSIAMBuild(options)
    modeling_rules_to_test = get_modeling_rules_to_test()

    google_client = create_google_pubsub_client(options.service_account)

    errs = []
    success = True
    mr: Optional[ModelingRule | None] = None
    for modeling_rule in modeling_rules_to_test:
        try:
            mr = get_mr_instance(modeling_rule)
            if not test_modeling_rule(xsiam_build, mr, google_client):
                success = False
        except ModelingRuleTestException as e:
            errs.append(e)
            success = False
        finally:
            if mr:
                os.remove(mr.path)
    if not success:
        if errs:
            logging.error(f'The following errors happened during testing of modeling rules:\n{errs}')
        sys.exit(2)


if __name__ == '__main__':
    # main()
    print('blah')
