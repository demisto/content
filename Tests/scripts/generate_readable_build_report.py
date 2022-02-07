import os
import re
from gitlab_slack_notifier import get_artifact_data
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
JOB_ID = os.environ.get('CI_JOB_ID')


def create_pr_comment():
    comment = ''
    comment += get_failing_ut()
    comment += get_failing_validations()
    comment += get_failing_tests()
    comment += f'here is a link to the full report: https://xsoar.docs.pan.run/-/content/-/jobs/{JOB_ID}/artifacts/'
    return comment


def get_failing_ut():
    failed_ut = get_artifact_data(ARTIFACTS_FOLDER, 'failed_unit_tests.txt')
    if failed_ut:
        failed_ut_list = failed_ut.split('\n')
        write_data_to_summary_file()
        return f'you have {len(failed_ut_list)} failed unit test on this push.\n'
    return 'no failing unit tests on this one. nice job!\n'


def get_failing_validations():
    # TODO check the file name
    failed_validations = get_artifact_data(ARTIFACTS_FOLDER, 'failed_validations.txt')
    if failed_validations:
        failed_validations_list = failed_validations.split('\n')
        write_data_to_summary_file()
        return f'you have {len(failed_validations_list)} failed validations on this push.\n'
    return 'no failing validations on this one. nice job!\n'


def get_failing_tests():
    # TODO check the file name
    failed_tests = get_artifact_data(ARTIFACTS_FOLDER, "failed_tests.txt")
    if failed_tests:
        failed_tests_list = failed_tests.split('\n')
        for failed_test in failed_tests_list:
            test_data = get_test_data(failed_test)
        write_data_to_summary_file()
        return f'you have {len(failed_tests_list)} failed tests on this push.\n'
    return 'no failing tests on this one. nice job!\n'


def write_data_to_summary_file():
    pass


def get_test_data(failed_test_name: str) -> str:
    # TODO check the file name
    log_data = get_artifact_data(ARTIFACTS_FOLDER, 'xsoar/logs/Run_Tests.log')
    index_to_trim = failed_test_name.find('(Mock Disabled)')
    if index_to_trim > -1:
        failed_test_name = failed_test_name[:index_to_trim - 1]
    test_log_pattern = f'------ Test playbook: {failed_test_name}.*start ------' \
                       f'.*' \
                       f'------ Test playbook: {failed_test_name}.*end ------'
    re.search(test_log_pattern, log_data)


def main():
    logging_manager = ParallelLoggingManager('generate_build_report.log')
    _add_pr_comment(create_pr_comment(), logging_manager)


if __name__ == "__main__":
    main()
