import argparse
import sys
import traceback

from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging


def options_handler():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--output-path', help='Output path', required=True)
    options = parser.parse_args()

    return options


def main():
    try:
        install_logging('Install_Packs.log', logger=logging)
        options = options_handler()
        logging.info(f'Output path: {options.output_path}')
        from junitparser import TestCase, TestSuite, JUnitXml, Skipped, Error

        # Create cases
        case1 = TestCase('case1', 'class.name', 0.5) # params are optional
        case1.classname = "modified.class.name" # specify or change case attrs
        case1.result = [Skipped()] # You can have a list of results
        case2 = TestCase('case2')
        case2.result = [Error('Example error message', 'the_error_type')]

        # Create suite and add cases
        suite = TestSuite('suite1')
        suite.add_property('build', '55')
        suite.add_testcase(case1)
        suite.add_testcase(case2)
        suite.remove_testcase(case2)

        # Bulk add cases to suite
        case3 = TestCase('case3')
        case4 = TestCase('case4')
        suite.add_testcases([case3, case4])

        # Add suite to JunitXml
        xml = JUnitXml()
        xml.add_testsuite(suite)
        xml.write(options.output_path)

    except Exception as e:
        logging.error(f'Failed to configure and install packs: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
