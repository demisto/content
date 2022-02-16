#!/usr/bin/env python3

import argparse
import sys

import click
from demisto_sdk.commands.doc_reviewer.doc_reviewer import DocReviewer
from typing import List

import urllib3
from utils import timestamped_print

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
        click.secho(f'Checking file: {file_path}\n', fg="yellow")
        doc_reviewer = DocReviewer(file_path=file_path,
                                   release_notes_only=True,
                                   known_words_file_path='Tests/known_words.txt',
                                   no_camel_case=True)

        result = doc_reviewer.run_doc_review()
        if not result:
            click.secho('Docs review resulted in failure, the exact logs can be found above.', fg="red")
            exit_code = 1

    return exit_code


def parse_changed_files_names() -> argparse.Namespace:
    """
    Run_doc_review script gets the files that were changed in the PR as a string (default delimiter is ';').
    This function is in charge of parsing the info and separate the files names.

    Returns: an argparse.Namespace object which includes the changed files names and the delimiter argument.
    """
    parser = argparse.ArgumentParser(description='Parse the changed files names.')
    parser.add_argument('-c', '--changed_files',
                        help="The files that are passed to docs review (passed as one string).")
    parser.add_argument('-d', '--delimiter', help="the delimiter that separates the changed files names (determined in"
                                                  " the call to tj-actions/changed-files@v2.0.0 in "
                                                  "review_release_notes script).")
    args = parser.parse_args()

    return args


def run_docs_review():
    """
    Parse the changed files names and passes them to demisto-sdk docs review.
    """
    parser_args = parse_changed_files_names()
    changed_files_list = parser_args.changed_files.split(parser_args.delimiter)
    exit_code = pass_files_to_docs_review(files_for_review=changed_files_list)
    return exit_code


if __name__ == "__main__":
    sys.exit(run_docs_review())
