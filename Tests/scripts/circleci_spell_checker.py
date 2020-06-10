import re
import sys

from Tests.scripts.spell_checker import spell_checker
from demisto_sdk.commands.common.tools import run_command, checked_type
from demisto_sdk.commands.common.constants import SPELLCHECK_FILE_TYPES, DESCRIPTION_REGEX


def get_modified_files(files_string):
    """Get lists of the modified files in your branch according to the files string.

    Args:
        files_string (string): String that was calculated by git using `git diff` command.

    Returns:
        (yml_files, md_files). Tuple of sets.
    """
    all_files = files_string.split('\n')
    yml_files = set([])
    md_files = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_path.endswith('.js') or file_path.endswith('.py'):
            continue
        if file_status.lower().startswith('r'):
            file_path = file_data[2]

        if file_status.lower() == 'm' or file_status.lower() == 'a' or file_status.lower().startswith('r'):
            if checked_type(file_path, SPELLCHECK_FILE_TYPES):
                yml_files.add(file_path)
            elif re.match(DESCRIPTION_REGEX, file_path, re.IGNORECASE):
                md_files.add(file_path)

    return yml_files, md_files


def check_changed_files():
    branch_name = sys.argv[1]

    if branch_name != "master":
        all_changed_files_string = run_command("git diff --name-status origin/master...{}".format(branch_name))
        yml_files, md_files = get_modified_files(all_changed_files_string)
        for yml_file in yml_files:
            print("Checking the file - {}".format(yml_file))
            spell_checker(yml_file)

        for md_file in md_files:
            print("Checking the file - {}".format(md_file))
            spell_checker(md_file, is_md=True)

    else:
        print("Not checking for spelling errors in master branch")


if __name__ == "__main__":
    check_changed_files()
