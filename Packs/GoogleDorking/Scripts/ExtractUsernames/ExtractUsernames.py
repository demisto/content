import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import re

''' STANDALONE FUNCTION '''


def extract_users_from_file(entry_id: str, pattern: str) -> list:
    users = []
    res = demisto.getFilePath(entry_id)
    if not res:
        raise DemistoException(f"Entry {entry_id} was not found")

    file_path = res['path']
    with open(file_path, mode='r') as file:
        for line in file.readlines():
            regex_res = re.search(pattern, line)
            if regex_res and (user := regex_res.groups()[1]):
                users.append(user.lstrip())
    return users


def extract_users_from_text(text: str, pattern: str) -> list:
    users = []
    for line in text.split('\n'):
        regex_res = re.search(pattern, line)
        if regex_res and (user := regex_res.groups()[1]):
            users.append(user.lstrip())
    return users


''' COMMAND FUNCTION '''


def extract_user(user_regex: str, entry_id: Optional[str] = None, text: Optional[str] = None) -> CommandResults:
    users = []
    pattern = f"({user_regex})(.*)"
    if entry_id:
        users.extend(extract_users_from_file(entry_id, pattern))
    if text:
        users.extend(extract_users_from_text(text, pattern))
    return CommandResults(
        outputs_key_field='DetectedUserName',
        outputs={
            'User': users
        }
    )


''' MAIN FUNCTION '''


def main():
    args = demisto.args()
    if 'entry_id' not in args and 'text' not in args:
        return_error('Please provide an `entry_id` or `text`.')
    try:
        return_results(extract_user(**args))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExtractUsernames. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
