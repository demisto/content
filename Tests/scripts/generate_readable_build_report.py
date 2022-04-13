import json
import os
# import re
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager
# from json2html import *

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
JOB_ID = os.environ.get('CI_JOB_ID')
summary_file = os.path.join(ARTIFACTS_FOLDER, 'summary.html')


def get_file_data(file_path: str):
    """
    """
    try:
        if os.path.isfile(file_path):
            print(f'Extracting {file_path}')
            with open(file_path, 'r') as file_data:
                artifact_data = file_data
        else:
            print(f'Did not find {file_path} file')
            return ''
    except Exception:
        print(f'Error getting {file_path} file')
        return ''
    return artifact_data


def create_pr_comment(validate_pr_comment, unit_tests_pr_comment):
    comment = ''
    comment += validate_pr_comment
    comment += unit_tests_pr_comment
    comment += f'here is a link to the full report: ' \
               f'https://xsoar.docs.pan.run/-/content/-/jobs/{JOB_ID}/artifacts/artifacts/summary.html'
    return comment


def convert_json_to_html(json_obj):
    with open(summary_file, 'a') as file_data:
        file_data.write(json_obj)


def build_summary_report(validate_summary, unit_tests_summary):
    json_summary = {
        'Validate': validate_summary,
        'Unit tests': unit_tests_summary,
    }
    convert_json_to_html(json_summary)


def test_get_failing_ut():
    file = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'failed_unit_tests.json'))
    # file = open('failed_unit_tests.json', 'r')
    failed_ut = json.load(file)
    if failed_ut:
        # TODO change method of counting
        number_of_failing_ut = 1
        pr_message = f'You have {number_of_failing_ut} failing unit tests in this push.\n'
    else:
        pr_message = 'No failing unit tests in this push!\n'
    return pr_message, failed_ut


def test_get_failing_validations():
    file = open(os.path.join(ARTIFACTS_FOLDER, 'validate_outputs.json'), 'r')
    # file = open('validate_outputs.json', 'r')
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


def generate_build_report(logging_manager):
    validate_pr_comment, validate_summary = test_get_failing_validations()
    unit_tests_pr_comment, unit_tests_summary = test_get_failing_validations()
    pr_comment = create_pr_comment(validate_pr_comment, unit_tests_pr_comment)
    _add_pr_comment(pr_comment, logging_manager, 'here is a link to the full report')
    build_summary_report(validate_summary, unit_tests_summary)


def main():
    logging_manager = ParallelLoggingManager('generate_build_report.log')
    generate_build_report(logging_manager)


if __name__ == "__main__":
    main()
