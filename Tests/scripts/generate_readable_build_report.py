import json
import os
from junit_xml import TestSuite, TestCase
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
JOB_ID = os.environ.get('CI_JOB_ID')
summary_file = os.path.join(ARTIFACTS_FOLDER, 'summary.html')


def get_file_data(file_path: str) -> dict:
    """
    """
    # TODO change print to log
    try:
        if os.path.isfile(file_path):
            print(f'Extracting {file_path}')
            with open(file_path, 'r') as file_data:
                try:
                    return json.load(file_data)
                except Exception:
                    print(f'could not parse json correctly, skipping {file_path}')
        else:
            print(f'Did not find {file_path} file')
            return {}
    except Exception as e:
        print(f'Error getting {file_path} file, error: {str(e)}')
        return {}


def create_pr_comment(validate_pr_comment, unit_tests_pr_comment) -> str:
    comment = ''
    comment += validate_pr_comment
    comment += unit_tests_pr_comment
    comment += f'here is a link to the full report: ' \
               f'https://xsoar.docs.pan.run/-/content/-/jobs/{JOB_ID}/artifacts/artifacts/summary.html'
    return comment


def build_summary_report(validate_summary, unit_tests_summary, create_instances_summary,server_6_1_summary,
                         server_6_2_summary,
                         server_master_summary):
    json_summary = {
        'Validate': validate_summary,
        'Unit tests': unit_tests_summary,
        'Create instances': create_instances_summary,
        'server 6.1': server_6_1_summary,
        'server 6.2': server_6_2_summary,
        'server master': server_master_summary,
    }

    for file, failing_validations in validate_summary.items():
        # test_case = TestCase('Test1', 'some.class.name', 123.345, 'I am stdout!', 'I am stderr!')
        test_cases = []
        for failing_validation in failing_validations:
            test_cases.append(TestCase('Validate', f'validate.{file}', stdout='I am stdout!', stderr=failing_validation))
    ts = TestSuite("Validate", test_cases)
    with open('output.xml', 'a') as f:
        TestSuite.to_file(f, [ts], prettyprint=False)


def test_get_failing_ut():
    failed_ut = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'failed_unit_tests.json'))
    if failed_ut:
        # TODO change method of counting
        number_of_failing_ut = 1
        pr_message = f'You have {number_of_failing_ut} failing unit tests in this push.\n'
    else:
        pr_message = 'No failing unit tests in this push!\n'
    return pr_message, failed_ut


def test_get_failing_validations():
    # failed_validations = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'validate_outputs.json'))
    file = open('validate_outputs.json', 'r')
    failed_validations = json.load(file)
    validate_summary = {}
    if failed_validations:
        pr_message = f'You have {len(failed_validations)} failing validations in this push.\n'
        for failed_validation in failed_validations:
            file_path = failed_validation.get('filePath')
            file_path = file_path[file_path.index('Packs/'):]
            error_code = failed_validation.get('errorCode')
            message = failed_validation.get('message')
            validate_summary.setdefault(file_path, []).append(f"{error_code} - {message}")
    else:
        pr_message = 'No failing validations in this push!\n'
    return pr_message, validate_summary


def test_get_failing_create_instances():
    failed_create_instances = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'packs_results.json'))
    # file = open('validate_outputs.json', 'r')
    # failed_validations = json.load(file)
    create_instances_summary = {}

    return 'pr_message', create_instances_summary


def generate_build_report(logging_manager):
    validate_pr_comment, validate_summary = test_get_failing_validations()
    unit_tests_pr_comment, unit_tests_summary = test_get_failing_ut()
    pr_comment = create_pr_comment(validate_pr_comment, unit_tests_pr_comment)
    _add_pr_comment(pr_comment, logging_manager, 'here is a link to the full report')
    build_summary_report(validate_summary,
                         unit_tests_summary,
                         create_instances_summary = {},
                         server_6_1_summary = {},
                         server_6_2_summary = {},
                         server_master_summary = {})


def main():
    logging_manager = ParallelLoggingManager('generate_build_report.log')
    generate_build_report(logging_manager)


if __name__ == "__main__":
    main()
