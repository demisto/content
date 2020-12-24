import argparse
import os
import sys
from threading import Thread

import requests

from Tests.Common.TestContentClasses import BuildContext, TestsExecution
from Tests.scripts.utils.log_util import ParallelLoggingManager
from demisto_sdk.commands.common.tools import str2bool


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-k', '--apiKey', help='The Demisto API key for the server', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly tests')
    parser.add_argument('-t', '--slack', help='The token for slack', required=True)
    parser.add_argument('-a', '--circleci', help='The token for circleci', required=True)
    parser.add_argument('-b', '--buildNumber', help='The build number', required=True)
    parser.add_argument('-g', '--buildName', help='The build name', required=True)
    parser.add_argument('-i', '--isAMI', type=str2bool, help='is AMI build or not', default=False)
    parser.add_argument('-m', '--memCheck', type=str2bool,
                        help='Should trigger memory checks or not. The slack channel to check the data is: '
                             'dmst_content_nightly_memory_data', default=False)
    parser.add_argument('-d', '--serverVersion', help='Which server version to run the '
                                                      'tests on(Valid only when using AMI)', default="NonAMI")
    parser.add_argument('-l', '--testsList', help='List of specific, comma separated'
                                                  'tests to run')

    options = parser.parse_args()
    return options


def _handle_github_response(response, logging_module):
    res_dict = response.json()
    if not res_dict.ok:
        logging_module.error(f'Add pull request comment failed: {res_dict.get("message")}', real_time=True)
    return res_dict


def _add_pr_comment(comment, logging_module):
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CIRCLE_BRANCH']
    sha1 = os.environ['CIRCLE_SHA1']

    query = '?q={}+repo:demisto/content+org:demisto+is:pr+is:open+head:{}+is:open'.format(sha1, branch_name)
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        res = requests.get(url + query, headers=headers, verify=False)
        res = _handle_github_response(res, logging_module)

        if res and res.get('total_count', 0) == 1:
            issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
            if issue_url:
                res = requests.post(issue_url, json={'body': comment}, headers=headers, verify=False)
                _handle_github_response(res, logging_module)
        else:
            logging_module.warning('Add pull request comment failed: There is more then one open pull '
                                   f'request for branch {branch_name}.', real_time=True)
    except Exception:
        logging_module.exception('Add pull request comment failed')


def main():
    tests_settings = options_handler()
    logging_manager = ParallelLoggingManager('Run_Tests.log', real_time_logs_only=not tests_settings.nightly)
    build_context = BuildContext(tests_settings, logging_manager)
    threads_list = []
    for server_ip in build_context.instances_ips:
        tests_execution_instance = TestsExecution(build_context, server_ip)
        threads_list.append(Thread(target=tests_execution_instance.execute_tests))

    for thread in threads_list:
        thread.start()

    for t in threads_list:
        t.join()
    if not build_context.unmockable_tests_to_run.empty() or not build_context.mockable_tests_to_run.empty():
        raise Exception('Not all tests have been executed')
    if build_context.tests_data_keeper.playbook_skipped_integration and build_context.build_name != 'master':
        comment = 'The following integrations are skipped and critical for the test:\n {}'. \
            format('\n- '.join(build_context.tests_data_keeper.playbook_skipped_integration))
        _add_pr_comment(comment, logging_manager)
    build_context.tests_data_keeper.print_test_summary(build_context.isAMI, logging_manager)
    if build_context.tests_data_keeper.failed_playbooks:
        logging_manager.critical("Some tests have failed. Not destroying instances.", real_time=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

# TODO reformat printing
