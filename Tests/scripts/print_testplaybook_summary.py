import argparse
import traceback
import sys
import prettytable

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the tests summary')
    parser.add_argument('--failed_tests_path', help='Path to the failed tests report file', required=True)
    parser.add_argument('--skipped_tests_path', help='Path to the skipped tests report file', required=True)
    parser.add_argument('--succeeded_tests_path', help='Path to the succeeded tests report file', required=True)
    return parser.parse_args()


def read_file_contents(file_path: str) -> list:
    with open(file_path, 'r') as file:
        contents = file.read().splitlines()
    return contents


def print_test_summary(failed_tests_path, skipped_tests_path, succeeded_tests_path) -> None:
    """
    Takes the information stored in the tests_data_keeper and prints it in a human readable way.
    """
    succeed_playbooks = read_file_contents(succeeded_tests_path)
    failed_playbooks = read_file_contents(failed_tests_path)
    skipped_tests = read_file_contents(skipped_tests_path)

    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)
    logging.info("TEST RESULTS:")
    logging.info(f"Number of playbooks tested - {succeed_count + failed_count}")

    if failed_count:
        logging.error(f"Number of failed tests - {failed_count}:")
        logging.error("Failed Tests:")
        for playbook_id in failed_playbooks:
            logging.error(f"\t- {playbook_id}")

    if succeed_count:
        logging.success(f"Number of succeeded tests - {succeed_count}")
        logging.success("Successful Tests:")
        for playbook_id in succeed_playbooks:
            logging.success(f"\t- {playbook_id}")

    if skipped_tests:
        print_table("Skipped Tests", skipped_tests)


def print_table(table_name: str, table_data: dict) -> None:
    table = prettytable.PrettyTable()
    table.field_names = ["Index", "Name", "Reason"]

    for index, record in enumerate(table_data, start=1):
        row = [index, record, table_data[record]]
        table.add_row(row)

    logging.info(f"{table_name}:")
    logging.info(table.get_string())


def main():
    try:
        install_logging('Print_summary.log', logger=logging)
        options = options_handler()
        print_test_summary(failed_tests_path=options.failed_tests_path,
                           skipped_tests_path=options.skipped_tests_path,
                           succeeded_tests_path=options.succeeded_tests_path)
    except Exception as e:
        logging.error(f'Failed to get the summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)
