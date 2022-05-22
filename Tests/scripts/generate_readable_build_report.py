import argparse
import json
import os
from junit_xml import TestSuite, TestCase, to_xml_report_file, decode
import xml.etree.ElementTree as ET
from demisto_sdk.commands.test_content.execute_test_content import _add_pr_comment
from demisto_sdk.commands.test_content.execute_test_content import ParallelLoggingManager

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
JOB_ID = os.environ.get('CI_JOB_ID')


def _build_xml_doc(self, encoding=None):
    """
    Builds the XML document for the JUnit test suite.
    Produces clean unicode strings and decodes non-unicode with the help of encoding.
    @param encoding: Used to decode encoded strings.
    @return: XML document with unicode string elements
    """

    # build the test suite element
    test_suite_attributes = dict()
    if any(c.assertions for c in self.test_cases):
        test_suite_attributes["assertions"] = str(sum([int(c.assertions) for c in self.test_cases if c.assertions]))
    test_suite_attributes["disabled"] = str(len([c for c in self.test_cases if not c.is_enabled]))
    test_suite_attributes["errors"] = str(len([c for c in self.test_cases if c.is_error()]))
    test_suite_attributes["failures"] = str(len([c for c in self.test_cases if c.is_failure()]))
    test_suite_attributes["name"] = decode(self.name, encoding)
    test_suite_attributes["skipped"] = str(len([c for c in self.test_cases if c.is_skipped()]))
    test_suite_attributes["tests"] = str(len(self.test_cases))
    test_suite_attributes["time"] = str(sum(c.elapsed_sec for c in self.test_cases if c.elapsed_sec))

    if self.hostname:
        test_suite_attributes["hostname"] = decode(self.hostname, encoding)
    if self.id:
        test_suite_attributes["id"] = decode(self.id, encoding)
    if self.package:
        test_suite_attributes["package"] = decode(self.package, encoding)
    if self.timestamp:
        test_suite_attributes["timestamp"] = decode(self.timestamp, encoding)
    if self.file:
        test_suite_attributes["file"] = decode(self.file, encoding)
    if self.log:
        test_suite_attributes["log"] = decode(self.log, encoding)
    if self.url:
        test_suite_attributes["url"] = decode(self.url, encoding)

    xml_element = ET.Element("testsuite", test_suite_attributes)

    # add any properties
    if self.properties:
        props_element = ET.SubElement(xml_element, "properties")
        for k, v in self.properties.items():
            attrs = {"name": decode(k, encoding), "value": decode(v, encoding)}
            ET.SubElement(props_element, "property", attrs)

    # add test suite stdout
    if self.stdout:
        stdout_element = ET.SubElement(xml_element, "system-out")
        stdout_element.text = decode(self.stdout, encoding)

    # add test suite stderr
    if self.stderr:
        stderr_element = ET.SubElement(xml_element, "system-err")
        stderr_element.text = decode(self.stderr, encoding)

    # test cases
    for case in self.test_cases:
        test_case_attributes = dict()
        test_case_attributes["name"] = decode(case.name, encoding)
        if case.assertions:
            # Number of assertions in the test case
            test_case_attributes["assertions"] = "%d" % case.assertions
        if case.elapsed_sec:
            test_case_attributes["time"] = "%f" % case.elapsed_sec
        if case.timestamp:
            test_case_attributes["timestamp"] = decode(case.timestamp, encoding)
        if case.classname:
            test_case_attributes["classname"] = decode(case.classname, encoding)
        if case.status:
            test_case_attributes["status"] = decode(case.status, encoding)
        if case.category:
            test_case_attributes["class"] = decode(case.category, encoding)
        if case.file:
            test_case_attributes["file"] = decode(case.file, encoding)
        if case.line:
            test_case_attributes["line"] = decode(case.line, encoding)
        if case.log:
            test_case_attributes["log"] = decode(case.log, encoding)
        if case.url:
            test_case_attributes["url"] = decode(case.url, encoding)

        test_case_element = ET.SubElement(xml_element, "testcase", test_case_attributes)

        # failures
        for failure in case.failures:
            if failure["output"] or failure["message"]:
                attrs = {}
                if failure["message"]:
                    attrs["message"] = decode(failure["message"], encoding)
                if failure["type"]:
                    attrs["type"] = decode(failure["type"], encoding)
                failure_element = ET.Element("failure", attrs)
                if failure["output"]:
                    failure_element.text = decode(failure["output"], encoding)
                test_case_element.append(failure_element)

        # errors
        for error in case.errors:
            if error["message"] or error["output"]:
                attrs = {}
                if error["message"]:
                    attrs["message"] = decode(error["message"], encoding)
                if error["type"]:
                    attrs["type"] = decode(error["type"], encoding)
                error_element = ET.Element("error", attrs)
                if error["output"]:
                    error_element.text = decode(error["output"], encoding)
                test_case_element.append(error_element)

        # skippeds
        for skipped in case.skipped:
            attrs = {}
            if skipped["message"]:
                attrs["message"] = decode(skipped["message"], encoding)
            skipped_element = ET.Element("skipped", attrs)
            if skipped["output"]:
                skipped_element.text = decode(skipped["output"], encoding)
            test_case_element.append(skipped_element)

        # test stdout
        if case.stdout:
            stdout_element = ET.Element("system-out")
            stdout_element.text = decode(case.stdout, encoding)
            test_case_element.append(stdout_element)

        # test stderr
        if case.stderr:
            stderr_element = ET.Element("system-err")
            stderr_element.text = decode(case.stderr, encoding)
            test_case_element.append(stderr_element)

    return xml_element


TestSuite.build_xml_doc = _build_xml_doc


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
    comment += f'here is a link to the full report: code.pan.run/xsoar/content/-/pipelines/{JOB_ID}/test_report'
    return comment


def generate_error_msg_for_servers(failing_test_data):
    return f'Investigate your failing test throw this ssh: {failing_test_data.get("ssh_tunnel", "")} ' \
           f'and use this link: {failing_test_data.get("server_url", "")}. ' \
           f'The error as it appears in the logs: {failing_test_data.get("error", "")}'


def build_summary_report(logging_manager,
                         validate_summary,
                         unit_tests_summary,
                         create_instances_summary,
                         server_6_2_summary,
                         server_master_summary, output_file):

    create_test_cases = []
    for failing_pack, failing_pack_data in create_instances_summary.items():
        test_case = TestCase(f'create_instances.{failing_pack}', 'Create Instances')
        errors = failing_pack_data.get('errors', [])
        for error in errors:
            test_case.add_failure_info(message=error)
        create_test_cases.append(test_case)
    create_ts = TestSuite("Create Instances", create_test_cases)

    test_cases_6_2 = []
    for failing_test, failing_test_data in server_6_2_summary.items():
        test_case = TestCase(f'6_2.{failing_test}', 'Server 6.2')
        test_case.add_failure_info(message=generate_error_msg_for_servers(failing_test_data[0]))
        test_cases_6_2.append(test_case)
    ts_6_2 = TestSuite("Server 6.2", test_cases_6_2)

    test_cases_server_master = []
    for failing_test, failing_test_data in server_master_summary.items():
        test_case = TestCase(f'master.{failing_test}', 'Server Master')
        test_case.add_failure_info(message=generate_error_msg_for_servers(failing_test_data[0]))
        test_cases_server_master.append(test_case)
    ts_master = TestSuite("Server Master", test_cases_server_master)

    test_cases_lint = get_failing_lint()

    with open(output_file, 'a') as f:
        to_xml_report_file(f, [create_ts, ts_6_2, ts_master, test_cases_lint], prettyprint=False)


def get_failing_ut():
    failed_ut = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'failed_unit_tests.json'))
    if failed_ut:
        # TODO change method of counting
        number_of_failing_ut = 1
        pr_message = f'You have {number_of_failing_ut} failing unit tests in this push.\n'
    else:
        pr_message = 'No failing unit tests in this push!\n'
    return pr_message, failed_ut


def get_failing_lint():
    failing_lints = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'lint_outputs.json'))
    if failing_lints:
        test_cases_lint = []
        for failing_test in failing_lints:
            if failing_test.get('severity') == 'error':
                name = failing_test.get('filePath', '') + " " + failing_test.get('Row', '')
                test_case = TestCase(f'lint.{name}', 'Lint')
                test_case.add_failure_info(message=failing_test.get('message'))
                test_cases_lint.append(test_case)
        ts = TestSuite("Lint", test_cases_lint)
        return ts
    return None


def get_failing_validations():
    failed_validations = get_file_data(os.path.join(ARTIFACTS_FOLDER, 'validate_outputs.json'))
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


def get_failing_server_6_2():
    failing_6_1 = get_file_data(os.path.join(f'{ARTIFACTS_FOLDER}/xsoar', 'test_playbooks_report_Server 6.2.json'))
    # file = open('validate_outputs.json', 'r')
    # failed_validations = json.load(file)
    return 'pr_message', failing_6_1


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for build_report args')
    parser.add_argument('-o', '--output', help='The xml file of the report')
    options = parser.parse_args()

    return options


def generate_build_report(logging_manager, output_file):
    validate_pr_comment, validate_summary = get_failing_validations()
    unit_tests_pr_comment, unit_tests_summary = get_failing_ut()
    create_instances_pr_comment, create_instances_summary = get_failing_create_instances()
    server_6_2_pr_comment, server_6_2_summary = get_failing_server_6_2()
    pr_comment = create_pr_comment(validate_pr_comment, unit_tests_pr_comment)
    _add_pr_comment(pr_comment, logging_manager, 'here is a link to the full report')
    build_summary_report(logging_manager,
                         validate_summary,
                         unit_tests_summary,
                         create_instances_summary,
                         server_6_2_summary,
                         server_master_summary={}, output_file=output_file)


def main():
    options = options_handler()
    output_file = options.output
    logging_manager = ParallelLoggingManager('generate_build_report.log')
    generate_build_report(logging_manager, output_file)


if __name__ == "__main__":
    main()
