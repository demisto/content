
from pathlib import Path
from typing import Any


from junitparser import TestSuite, JUnitXml

from Tests.scripts.utils import logging_wrapper as logging


E2E_BASE_HEADERS = ["Test Name"]


def calculate_e2e_tests_results(e2e_tests_results_files: dict[str, Path]):

    e2e_tests_results: dict[str, dict[str, Any]] = {}
    server_versions = set()
    for instance_role, e2e_test_result_file in e2e_tests_results_files.items():
        logging.debug(f"Processing test e2e result file: {e2e_test_result_file} for instance role: {instance_role}")
        xml = JUnitXml.fromfile(e2e_test_result_file.as_posix())
        server_versions.add(instance_role)
        for test_suite_item in xml.iterchildren(TestSuite):
            test_names = [case.classname for case in test_suite_item]
            for test_name in test_names:
                e2e_tests_results[test_name] = {instance_role: test_suite_item}

    return e2e_tests_results, server_versions
