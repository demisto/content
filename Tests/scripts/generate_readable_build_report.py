import argparse
import json
import os
from junit_xml import TestSuite, TestCase, to_xml_report_file
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
JOB_ID = os.environ.get('CI_JOB_ID')


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
    comment += f'here is a link to the full report: ' \
               f'code.pan.run/xsoar/content/-/pipelines/{JOB_ID}/test_report'
    return comment


def generate_error_msg_for_servers(failing_test_data):
    return f'Investigate your failing test throw this ssh: {failing_test_data.get("ssh_tunnel", "")}' \
           f'and use this link: {failing_test_data.get("server_url", "")}.' \
           f'The error as it appears in the logs: {failing_test_data.get("error", "")}'

def build_summary_report(logging_manager,
                         validate_summary, unit_tests_summary, create_instances_summary, server_6_1_summary,
                         server_6_2_summary,
                         server_master_summary,
                         output_file):

    test_cases = []

    for file, failing_validations in validate_summary.items():
        # test_case = TestCase('Test1', 'some.class.name', 123.345, 'I am stdout!', 'I am stderr!')
        for failing_validation in failing_validations:
            test_case = TestCase(f'validate.{file}', 'Validate', stdout='I am stdout!', stderr=failing_validation)
            test_case.add_failure_info(message=failing_validation)
            test_cases.append(test_case)

            logging_manager.info(f"creating test case for {failing_validation}")
    validate_ts = TestSuite("Validate", test_cases)

    create_test_cases = []
    for failing_pack, failing_pack_data in create_instances_summary.items():
        test_case = TestCase(f'create_instances.{failing_pack}', 'Create Instances')
        # TODO change to all list
        test_case.add_failure_info(message=failing_pack_data.get('errors')[0])
        create_test_cases.append(test_case)
    create_ts = TestSuite("Create Instances", create_test_cases)

    six_one_test_cases = []
    for failing_test, failing_test_data in server_6_1_summary.items():
        test_case = TestCase(f'6_1.{failing_test}', 'Server 6.1')
        test_case.add_failure_info(message=generate_error_msg_for_servers(failing_test_data[0]))
        six_one_test_cases.append(test_case)
    six_one_ts = TestSuite("Server 6.1", create_test_cases)


    with open(output_file, 'a') as f:
        logging_manager.info("opened file")
        to_xml_report_file(f, [validate_ts, create_ts, six_one_ts], prettyprint=False)


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
    failed_validations = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'validate_outputs.json'))
    # file = open('validate_outputs.json', 'r')
    # failed_validations = json.load(file)
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


def get_failing_create_instances():
    failing_create = get_file_data(os.path.join(f'{ARTIFACTS_FOLDER}/xsoar', 'packs_results.json'))
    # file = open('validate_outputs.json', 'r')
    # failed_validations = json.load(file)
    create_instances_summary = failing_create.get('prepare_content_for_testing', {}).get('failed_packs', {})

    return 'pr_message', create_instances_summary

def get_failing_server_6_1():
    failing_6_1 = get_file_data(os.path.join(f'{ARTIFACTS_FOLDER}/xsoar', 'test_playbooks_report_Server 6.1.json'))
    # file = open('validate_outputs.json', 'r')
    # failed_validations = json.load(file)

    return 'pr_message', failing_6_1


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for build_report args')
    parser.add_argument('-o', '--output', help='The xml file of the report')
    options = parser.parse_args()

    return options


def generate_build_report(logging_manager, output_file):
    validate_pr_comment, validate_summary = test_get_failing_validations()
    unit_tests_pr_comment, unit_tests_summary = test_get_failing_ut()
    create_instances_pr_comment, create_instances_summary = get_failing_create_instances()
    server_6_1_pr_comment, server_6_1_summary = get_failing_server_6_1()
    pr_comment = create_pr_comment(validate_pr_comment, unit_tests_pr_comment)
    _add_pr_comment(pr_comment, logging_manager, 'here is a link to the full report')
    build_summary_report(logging_manager,
                         validate_summary,
                         unit_tests_summary,
                         create_instances_summary,
                         server_6_1_summary,
                         server_6_2_summary={},
                         server_master_summary={}, output_file=output_file)


def main():
    options = options_handler()
    output_file = options.output
    logging_manager = ParallelLoggingManager('generate_build_report.log')
    generate_build_report(logging_manager, output_file)


if __name__ == "__main__":
    main()
