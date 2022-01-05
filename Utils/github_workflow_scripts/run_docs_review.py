#!/usr/bin/env python3

import argparse
import sys

from demisto_sdk.commands.doc_reviewer.doc_reviewer import DocReviewer
from typing import List

import urllib3
from Utils.github_workflow_scripts.utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print


def pass_files_to_docs_review(files_for_review: List[str]) -> int:
    """
    This function passes each file of the files_for_review list to the demisto-sdk docs reviewer.
    Args:
        files_for_review: the files that should be reviewed.

    Returns: the exit code according to the docs reviewer result.
    """
    exit_code = 0
    for file_path in files_for_review:
        print(f'Checking file: {file_path}\n')
        doc_reviewer = DocReviewer(file_path=file_path,
                                   release_notes_only=True,
                                   known_words_file_path='Tests/known_words.txt')

        result = doc_reviewer.run_doc_review()
        if not result:
            print('Setting Overall Exit Code to 1')
            exit_code = 1

    return exit_code


def parse_changed_files_names_to_list() -> List[str]:
    """
    Run_doc_review script gets the file that was changed in the PR as a string (delimiter is ' ').
    This function is in charge of parsing the info and separate the files names.

    Returns: a list contains the changed files names.
    """
    parser = argparse.ArgumentParser(description='Parse the changed files names.')
    parser.add_argument('-c', '--changed_files', help="The files that are passed to docs review (passed as one string,"
                                                      " delimiter is ' '")
    args = parser.parse_args()

    return args.changed_files.split()


def main():
    """
    Parse the changed files names and passes them to demisto-sdk docs review.
    """
    changed_files_list = parse_changed_files_names_to_list()
    exit_code = pass_files_to_docs_review(files_for_review=changed_files_list)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
