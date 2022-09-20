import argparse
import ast
from io import BytesIO
import json
import os
from pathlib import Path
import sys
from typing import Any, Optional
import demisto_client
from Tests.Marketplace.search_and_uninstall_pack import (reset_base_pack_version,
                                                         uninstall_all_packs,
                                                         wait_for_uninstallation_to_complete)
from Tests.scripts.collect_tests.path_manager import PathManager

from Tests.configure_and_test_integration_instances import XSIAMBuild
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.content.objects.pack_objects.modeling_rule.modeling_rule import ModelingRule, MRule
from google.oauth2 import service_account
from google.cloud.pubsub_v1 import PublisherClient
from google.cloud import bigquery


class ModelingRuleTestException(BaseException):
    pass


def options_handler(args=None):
    """
    Returns: options parsed from input arguments.
    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')

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


def get_modeling_rules_to_test(paths_manager: PathManager) -> list[Path]:
    """
    Fetches the modeling rules list to test from the file created during test collection.

    Arguments:
        paths_manager(PathManager): PathManager class instance for commonly used paths in content

    Returns:
        list[Path]: List of paths to the modeling rules that need to be tested
    """
    mrs_to_test_filepath = paths_manager.output_mrs_to_test_file
    modeling_rules = []
    with open(mrs_to_test_filepath, "r") as mrs_list_file:
        mrs_from_file = mrs_list_file.readlines()
        for mr_from_file in mrs_from_file:
            mr = mr_from_file.rstrip()
            modeling_rules.append(paths_manager.packs_path / mr)
    return modeling_rules


def create_google_pubsub_client(project_id: str, service_account_filepath: Optional[str]) -> PublisherClient:
    if service_account_filepath:
        credentials = service_account.Credentials.from_service_account_file(service_account_filepath)
        publisher = PublisherClient(project=project_id, credentials=credentials)
    else:
        publisher = PublisherClient(project=project_id)
    return publisher


def create_google_bigquery_client(project_id: str, service_account_filepath: Optional[str]):
    if service_account_filepath:
        credentials = service_account.Credentials.from_service_account_file(service_account_filepath)
        bigquery_client = bigquery.Client(project=project_id, credentials=credentials)
    else:
        bigquery_client = bigquery.Client(project=project_id)
    return bigquery_client


def create_dataset(xsiam_build: XSIAMBuild, modeling_rule: ModelingRule, pub_sub_client: PublisherClient) -> bool:
    if not modeling_rule.testdata_path:
        testdata_filepath = modeling_rule.path.parent / f'{modeling_rule.path.parent.name}_testdata.json'
        raise ModelingRuleTestException(f'No file with test data was found in {testdata_filepath}')
    else:
        data = json.load(modeling_rule.testdata_path.open('r'))
        metablob: dict[str, Any] = data.get('metablob', {})
        # match the vendor and product in the metablob to the one listed in the modeling_rule's rules -
        # all the rules in a modeling rule xif file should use the same dataset (and ergo the same vendor and product)
        metablob['vendor'] = modeling_rule.rules[0].vendor
        metablob['product'] = modeling_rule.rules[0].product
        metablob.setdefault('format', 'json')
        event_data: list[dict[str, Any]] = data.get('event_data')
        event_data_as_str = '\n'.join([json.dumps(event) for event in event_data])
        pubsub_msg = BytesIO(bytes(f'{json.dumps(metablob)}\n{event_data_as_str}', encoding='utf-8'))
        xsiam_project_number = xsiam_build.xsiam_machine.split('-')[-1]
        topic = pub_sub_client.topic_path(xsiam_build.xsiam_machine, f'ext-logs-{xsiam_project_number}')
        # topic_name = f'projects/{xsiam_build.xsiam_machine}/topics/ext-logs-{xsiam_project_number}'
        future = pub_sub_client.publish(topic, pubsub_msg.getvalue())
        future.result()
        return True


def start_xql_query(client: demisto_client.ApiClient, query: str) -> str:
    body = {
        "request_data": {
            "query": query
        }
    }
    response_data, status_code, _ = demisto_client.generic_request_func(
        client,
        path='/public_api/v1/xql/start_xql_query/',
        method='POST',
        body=body,
        _request_timeout=120
    )

    data = ast.literal_eval(response_data)
    if 200 <= status_code < 300:
        execution_id = data.get('reply', '')
        return execution_id
    else:
        raise ModelingRuleTestException(
            f'Failed to start xql query "{query}" - with status code {status_code}\n{data}\n')


def get_xql_query_results(client: demisto_client.ApiClient, execution_id: str) -> list[dict[str, Any]]:
    body = {
        "request_data": {
            "query_id": execution_id,
            "pending_flag": False,
            "limit": 1000,
            "format": "json"
        }
    }
    response_data, status_code, _ = demisto_client.generic_request_func(
        client,
        path='/public_api/v1/xql/get_query_results/',
        method='POST',
        body=body,
        _request_timeout=120
    )

    data = ast.literal_eval(response_data)
    if 200 <= status_code < 300:
        reply_results_data = data.get('reply', {}).get('results', {}).get('data', [])
        return reply_results_data
    else:
        err_msg = (f'Failed to get xql query results for execution_id "{execution_id}"'
                   f' - with status code {status_code}\n{data}\n')
        raise ModelingRuleTestException(err_msg)


def execute_xql_query(xsiam_build: XSIAMBuild, m_rule: MRule) -> bool:
    """Verify that a modeling rule maps to fields correctly given the test dataset

    Perform an xql query using the modeling rule's fields to check that the data in the dataset
    created from the test data has been mapped correctly in the system

    Args:
        xsiam_build (XSIAMBuild): XSIAM build context object
        m_rule (MRule): Individual rule from a modeling rule xif file

    Returns:
        bool: Whether the fields were mapped correctly or not
    """
    xql_query = f'config timeframe = 5y | datamodel = {m_rule.datamodel} | fields {", ".join(m_rule.fields)}'
    client = xsiam_build.servers[0].reconnect_client()
    execution_id = start_xql_query(client, xql_query)
    xql_query_results_data = get_xql_query_results(client, execution_id)
    data = xql_query_results_data[0]
    logging.debug(f'xql_query_results_data = {data}')
    err_msgs = []
    for field in m_rule.fields:
        if field not in data:
            err_msgs.append(f'"{field}" not found in xql query results data')
        elif not data.get(field):
            err_msgs.append(f'no value was mapped for the field "{field}" in the xql query results data')
        else:
            logging.debug(f'{field}: {data.get(field)}')
    if err_msgs:
        grouped_err_msgs = "\n".join(err_msgs)
        err = ('modeling rule mapping expectatins were not met for the '
               f'xql query "{xql_query}" - \n{grouped_err_msgs}')
        raise ModelingRuleTestException(err)
    return True


def test_modeling_rule(xsiam_build: XSIAMBuild, modeling_rule: ModelingRule, pubsub_client: PublisherClient) -> bool:
    # clean tenant
    if not clean_xsiam_tenant(xsiam_build):
        raise ModelingRuleTestException(f'Failed to clean the xsiam tenant for testing of {modeling_rule.path.parent}')

    # install pack of modeling rule
    pack_id = modeling_rule.path.parts[modeling_rule.path.parts.index('Packs') + 1]
    if not xsiam_build.install_packs([pack_id]):
        raise ModelingRuleTestException(f'Failed to install the pack for testing of {modeling_rule.path.parent}')

    try:
        # create dataset from modeling rule's testdata
        create_dataset(xsiam_build, modeling_rule, pubsub_client)
    except ModelingRuleTestException as e:
        testdata_filepath = modeling_rule.path.parent / f'{modeling_rule.path.parent.name}_testdata.json'
        no_testdata_err = f'No file with test data was found in {testdata_filepath}'
        if f'{e}' == no_testdata_err:
            logging.warning(no_testdata_err)
            return True
        raise

    valid = True
    errors = []
    # note that a single modeling rule xif file can/usually really contain multiple rules - they're usually in a single
    # xif file if the event logs originate from the same product source
    for m_rule in modeling_rule.rules:
        try:
            # perform xql query
            execute_xql_query(xsiam_build, m_rule)
        except ModelingRuleTestException as e:
            valid = False
            errors.append(e)
    if errors:
        logging.debug('leaving the created dataset for user inspection and debugging')
        # group errors into one
        grouped_err_msgs = "\n".join([f"{e}" for e in errors])
        raise ModelingRuleTestException(f'{grouped_err_msgs}')
    return valid


def main():
    install_logging('test_modeling_rules.log', logger=logging)

    # in xsiam we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    xsiam_build = XSIAMBuild(options)

    cur_filepath = Path(__file__).absolute()
    try:
        content_dir_up = len(cur_filepath.parent.parts) - (cur_filepath.parts.index('content') + 1)
    except ValueError:
        content_dir_up = 2
    paths_manager = PathManager(cur_filepath.parents[content_dir_up])
    modeling_rules_to_test = get_modeling_rules_to_test(paths_manager)

    pubsub_client = create_google_pubsub_client(xsiam_build.xsiam_machine, options.service_account)
    bq_client = create_google_bigquery_client(xsiam_build.xsiam_machine, options.service_account)

    # e.g. the numbers off the google project "qa2-test-9918425195851" would be "9918425195851"
    project_name_number = xsiam_build.xsiam_machine.split('-')[-1]

    errs = []
    success = True
    for modeling_rule in modeling_rules_to_test:
        mr = ModelingRule(modeling_rule.as_posix())
        try:
            if not test_modeling_rule(xsiam_build, mr, pubsub_client):
                success = False
        except ModelingRuleTestException as e:
            if mr.testdata_path and mr.testdata_path.exists():
                err_msg = (f'modeling rule failed: not deleting the dataset "{mr.rules[0].dataset}" '
                           'that was created from the test data so that you can inspect and investigate')
                logging.debug(err_msg)
            errs.append(f'{e}')
            success = False
        else:
            err_msg = (f'modeling rule succeeded: deleting dataset "{mr.rules[0].dataset}"'
                       ' that was created from test data.')
            logging.debug(err_msg)
            bq_client.delete_table(f'external_data_{project_name_number}.{mr.rules[0].dataset}', not_found_ok=True)

    if not success:
        if errs:
            logging.error(f'The following errors happened during testing of modeling rules:\n{errs}')
        sys.exit(2)


if __name__ == '__main__':
    main()
