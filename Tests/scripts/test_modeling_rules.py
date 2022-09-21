import argparse
import json
import os
import sys
from pathlib import Path
from pprint import pformat
from typing import Any, Optional

import requests
from demisto_sdk.commands.common.content.objects.pack_objects.modeling_rule.modeling_rule import (
    ModelingRule, MRule)
from google.cloud import bigquery
from google.cloud.pubsub_v1 import PublisherClient
from google.oauth2 import service_account
from pydantic import BaseModel, Field, ValidationError, parse_file_as
from Tests.configure_and_test_integration_instances import (XSIAMBuild,
                                                            XSIAMServer)
from Tests.Marketplace.configure_and_install_packs import \
    install_packs_from_content_packs_to_install_path
from Tests.Marketplace.search_and_uninstall_pack import (
    reset_base_pack_version, uninstall_all_packs,
    wait_for_uninstallation_to_complete)
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging


class ModelingRuleTestData(BaseModel):
    metablob: dict[str, Any] = Field(default_factory=dict)
    events_data: list[dict[str, Any]]


class ModelingRuleTestException(BaseException):
    pass


def options_handler(args=None):
    """
    Returns: options parsed from input arguments.
    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')

    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-n', '--is-nightly', default=False,
                        action=argparse.BooleanOptionalAction, help='Is nightly build')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.',
                        default='./artifacts/content_packs_to_install.txt')
    parser.add_argument('--build_object_type', help='Build type running: XSOAR or XSIAM')
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to secret xsiam server metadata file.')
    parser.add_argument('--xsiam_servers_api_keys', help='Path to file with XSIAM Servers api keys.')
    parser.add_argument(
        '--mr', '--modeling-rules-to-test',
        help=('Path to file with the modeling rules that require testing as a newline separated list '
              'where each item is "<pack-name>/ModelingRules/<name-of-modeling-rule-dir>/"'
              '. If no path is passed then will search for the file at "./artifacts/mrs_to_test.txt"')
    )
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


def clean_xsiam_tenant(xsiam_server: XSIAMServer) -> bool:
    client = xsiam_server.client
    if not client:
        err_msg = (f'expected {xsiam_server=} to have a "client" property.')
        raise AttributeError(err_msg)
    host = xsiam_server.name
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


def create_google_pubsub_client(service_account_filepath: Optional[str]) -> PublisherClient:
    if service_account_filepath:
        credentials = service_account.Credentials.from_service_account_file(service_account_filepath)
        publisher = PublisherClient(credentials=credentials)
    else:
        publisher = PublisherClient()
    return publisher


def create_google_bigquery_client(project_id: str, service_account_filepath: Optional[str]):
    if service_account_filepath:
        credentials = service_account.Credentials.from_service_account_file(service_account_filepath)
        bigquery_client = bigquery.Client(project=project_id, credentials=credentials)
    else:
        bigquery_client = bigquery.Client(project=project_id)
    return bigquery_client


def create_dataset(xsiam_server: XSIAMServer, modeling_rule: ModelingRule, pub_sub_client: PublisherClient) -> bool:
    if not modeling_rule.testdata_path:
        testdata_filepath = modeling_rule.path.parent / f'{modeling_rule.path.parent.name}_testdata.json'
        raise ModelingRuleTestException(f'No file with test data was found in {testdata_filepath}')
    else:
        vendor = modeling_rule.rules[0].vendor
        product = modeling_rule.rules[0].product
        data: ModelingRuleTestData = parse_file_as(path=modeling_rule.testdata_path, type_=ModelingRuleTestData)
        metablob: dict[str, Any] = data.metablob
        # match the vendor and product in the metablob to the one listed in the modeling_rule's rules -
        # all the rules in a modeling rule xif file should use the same dataset (and ergo the same vendor and product)
        metablob['vendor'] = vendor
        metablob['product'] = product
        metablob.setdefault('format', 'json')
        events_data: list[dict[str, Any]] = data.events_data
        events_data_as_str = '\n'.join([json.dumps(event) for event in events_data])
        msg_str = f'{json.dumps(metablob)}\n{events_data_as_str}'
        pubsub_msg = msg_str.encode('utf-8')
        xsiam_project_number = xsiam_server.name.split('-')[-1]
        topic = pub_sub_client.topic_path(xsiam_server.name, f'ext-logs-{xsiam_project_number}')

        logging.debug(f'pubsub msg:\n {pubsub_msg}')
        future = pub_sub_client.publish(topic, pubsub_msg)
        future.result()
        logging.success(
            f'Successfully created dataset with {vendor=} {product=} from test data at {modeling_rule.testdata_path}'
        )
        return True


def start_xql_query(xsiam_server: XSIAMServer, query: str) -> str:
    body = {
        "request_data": {
            "query": query
        }
    }
    url = os.path.join(xsiam_server.base_url, 'public_api/v1/xql/start_xql_query/')
    headers = {
        'x-xdr-auth-id': xsiam_server.xdr_auth_id,
        'Authorization': xsiam_server.api_key,
        'Content-Type': 'application/json'
    }
    logging.info(f'Starting xql query:\nendpoint={url}\n{query=}')
    response = requests.post(url=url, json=body, headers=headers)
    data = response.json()

    if 200 <= response.status_code < 300:
        execution_id = data.get('reply', '')
        return execution_id
    else:
        raise ModelingRuleTestException(
            f'Failed to start xql query "{query}" - with status code {response.status_code}\n{pformat(data)}'
        )


def get_xql_query_results(xsiam_server: XSIAMServer, execution_id: str) -> list[dict[str, Any]]:
    payload = json.dumps({
        "request_data": {
            "query_id": execution_id,
            "pending_flag": False,
            "limit": 1000,
            "format": "json"
        }
    })
    url = os.path.join(xsiam_server.base_url, 'public_api/v1/xql/get_query_results/')
    headers = {
        'x-xdr-auth-id': xsiam_server.xdr_auth_id,
        'Authorization': xsiam_server.api_key,
        'Content-Type': 'application/json'
    }
    logging.info(f'Getting xql query results: endpoint={url}')
    response = requests.post(url=url, data=payload, headers=headers)
    data = response.json()
    logging.debug(pformat(data))

    if 200 <= response.status_code < 300 and data.get('reply', {}).get('status', '') == 'SUCCESS':
        reply_results_data = data.get('reply', {}).get('results', {}).get('data', [])
        return reply_results_data
    else:
        err_msg = (f'Failed to get xql query results for execution_id "{execution_id}"'
                   f' - with status code {response.status_code}\n{pformat(data)}')
        raise ModelingRuleTestException(err_msg)


def execute_xql_query(xsiam_server: XSIAMServer, m_rule: MRule) -> bool:
    """Verify that a modeling rule maps to fields correctly given the test dataset

    Perform an xql query using the modeling rule's fields to check that the data in the dataset
    created from the test data has been mapped correctly in the system

    Args:
        xsiam_server (XSIAMServer): XSIAM Server object
        m_rule (MRule): Individual rule from a modeling rule xif file

    Returns:
        bool: Whether the fields were mapped correctly or not
    """
    xql_query = f'config timeframe = 5y | datamodel = {m_rule.datamodel} | fields {", ".join(m_rule.fields)}'
    execution_id = start_xql_query(xsiam_server, xql_query)
    xql_query_results_data = get_xql_query_results(xsiam_server, execution_id)
    data = xql_query_results_data[0] if xql_query_results_data else xql_query_results_data
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
        err = ('modeling rule mapping expectations were not met for the '
               f'xql query "{xql_query}" - \n{grouped_err_msgs}')
        raise ModelingRuleTestException(err)
    return True


class BuildContext:
    def __init__(self, branch_name: str, build_number: str):
        self.branch_name = branch_name if branch_name else 'master'
        self.build_number = build_number


def install_packs_on_xsiam_server(server: XSIAMServer, ctx: BuildContext, pack_ids: list[str]) -> bool:
    XSIAMBuild.set_marketplace_url(
        servers=[server], branch_name=ctx.branch_name, ci_build_number=ctx.build_number
    )
    install_packs_from_content_packs_to_install_path([server], pack_ids, server.name)
    return True


def test_modeling_rule(xsiam_server: XSIAMServer, ctx: BuildContext, modeling_rule: ModelingRule,
                       pubsub_client: PublisherClient) -> bool:
    # clean tenant
    if not clean_xsiam_tenant(xsiam_server):
        raise ModelingRuleTestException(f'Failed to clean the xsiam tenant for testing of {modeling_rule.path.parent}')

    # install pack of modeling rule
    pack_id = modeling_rule.path.parts[modeling_rule.path.parts.index('Packs') + 1]
    if not install_packs_on_xsiam_server(xsiam_server, ctx, [pack_id]):
        raise ModelingRuleTestException(f'Failed to install the pack for testing of {modeling_rule.path.parent}')

    try:
        # create dataset from modeling rule's testdata
        create_dataset(xsiam_server, modeling_rule, pubsub_client)
    except ValidationError as e:
        err_msg = (f'modeling rule test data at "{modeling_rule.testdata_path}"'
                   f' did not conform to required format: \n{e}')
        logging.error(err_msg)
        return False
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
            execute_xql_query(xsiam_server, m_rule)
        except ModelingRuleTestException as e:
            valid = False
            errors.append(e)
    if errors:
        logging.debug('leaving the created dataset for user inspection and debugging')
        # group errors into one
        grouped_err_msgs = "\n".join([f"{e}" for e in errors])
        raise ModelingRuleTestException(f'{modeling_rule.path}\n{grouped_err_msgs}')
    return valid


def main():
    install_logging('test_modeling_rules.log', logger=logging)

    # in xsiam we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    # xsiam_build = XSIAMBuild(options)
    xsiam_machine = options.xsiam_machine
    api_key, server_numeric_version, base_url, xdr_auth_id = XSIAMBuild.get_xsiam_configuration(
        xsiam_machine,
        options.xsiam_servers_path,
        options.xsiam_servers_api_keys)
    # Configure the Server
    server = XSIAMServer(api_key, server_numeric_version, base_url, xdr_auth_id, xsiam_machine)
    ctx = BuildContext(options.branch, options.build_number)

    cur_filepath = Path(__file__).absolute()
    try:
        content_dir_up = len(cur_filepath.parent.parts) - (cur_filepath.parts.index('content') + 1)
    except ValueError:
        content_dir_up = 2
    paths_manager = PathManager(cur_filepath.parents[content_dir_up])
    modeling_rules_to_test = get_modeling_rules_to_test(paths_manager)

    pubsub_client = create_google_pubsub_client(options.service_account)
    bq_client = create_google_bigquery_client(server.name, options.service_account)

    # e.g. the numbers off the google project "qa2-test-9918425195851" would be "9918425195851"
    project_name_number = server.name.split('-')[-1]

    errs = []
    success = True
    for modeling_rule in modeling_rules_to_test:
        mr = ModelingRule(modeling_rule.as_posix())
        try:
            if not test_modeling_rule(server, ctx, mr, pubsub_client):
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
            errs_str = '\n'.join(errs)
            logging.error(f'The following errors happened during testing of modeling rules:\n{errs_str}')
        sys.exit(2)


if __name__ == '__main__':
    main()
