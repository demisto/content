import argparse
import traceback
import sys
import os

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the tests summary')
    parser.add_argument('--failed_tests_path', help='Path to the failed tests report file', required=True)
    parser.add_argument('--succeeded_tests_path', help='Path to the succeeded tests report file', required=True)
    return parser.parse_args()


def read_file_contents(file_path: str) -> list | None:
    """
        Returns the file contents as a list of lines if the file exists, else returns None.
    """
    if os.path.isfile(file_path):
        with open(file_path) as file:
            return file.read().splitlines()
    else:
        logging.error(f"{file_path} does not exist.")
    return None


def print_test_summary(failed_tests_path: str, succeeded_tests_path: str) -> None:
    """
    Takes the information stored in the files and prints it in a human readable way.
    """
    succeeded_playbooks = read_file_contents(succeeded_tests_path)
    failed_playbooks = read_file_contents(failed_tests_path)

    # if one of the files isn't existing, we want to fail.
    if succeeded_playbooks is None or failed_playbooks is None:
        sys.exit(1)

    succeeded_count = len(succeeded_playbooks)
    failed_count = len(failed_playbooks)

    logging.info("TEST RESULTS:")
    logging.info(f"Number of playbooks tested - { succeeded_count + failed_count}")

    if succeeded_count:
        logging.success(f"Number of succeeded tests - { succeeded_count}")
        logging.success("Successful Tests:")
        for playbook_id in succeeded_playbooks:
            logging.success(f"\t- {playbook_id}")

    if failed_count:
        logging.error(f"Number of failed tests - {failed_count}:")
        logging.error("Failed Tests:")
        for playbook_id in failed_playbooks:
            logging.error(f"\t- {playbook_id}")
        sys.exit(1)


def main():
    try:
        install_logging('print_testplaybook_summary.log', logger=logging)
        options = options_handler()
        print_test_summary(failed_tests_path=options.failed_tests_path,
                           succeeded_tests_path=options.succeeded_tests_path)
    except Exception as e:
        logging.error(f'Failed to get the summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
