#!/usr/bin/env python3

import argparse
import sys

from demisto_sdk.commands.doc_reviewer.doc_reviewer import DocReviewer
from typing import List

import urllib3
from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print


def pass_files_to_docs_review(files_for_review: List[str]):
    """
    This function passes each file of the files_for_review list to the demisto-sdk docs reviewer.
    Args:
        files_for_review: the files that should be reviewed.

    Returns: None
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

    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(description='Passes the changed files to demisto-sdk docs review.')
    parser.add_argument('-c', '--changed_files', help="The files that are passed to docs review (passed as one string,"
                                                      " delimiter is ' '")
    args = parser.parse_args()
    changed_files = args.changed_files.split()
    pass_files_to_docs_review(files_for_review=changed_files)


if __name__ == "__main__":
    main()
