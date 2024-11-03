import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import re

''' STANDALONE FUNCTION '''


def extract_users_from_file(entry_id: str, pattern: Optional[str]) -> list:
    users = []
    res = demisto.getFilePath(entry_id)
    if not res:
        raise DemistoException(f"Entry {entry_id} was not found")
    regex = re.compile(pattern) if pattern else None
    file_path = res['path']
    with open(file_path) as file:
        for line in file.readlines():
            if regex:
                regex_res = regex.search(line)
                if regex_res and (user := regex_res.groups()[1]):
                    users.append(user.lstrip())
            else:
                users.append(line)
    return users


def extract_users_from_text(text: str, pattern: Optional[str]) -> list:
    users = []
    regex = re.compile(pattern) if pattern else None
    for line in text.split('\n'):
        if regex:
            regex_res = regex.search(line)
            if regex_res and (user := regex_res.groups()[1]):
                users.append(user.lstrip())
        else:
            users.append(line)
    return users


''' COMMAND FUNCTION '''


def extract_user(user_regex: Optional[str] = None, entry_id: Optional[str] = None, text: Optional[str] = None) -> CommandResults:
    users = []
    pattern = f"({user_regex})(.*)" if user_regex else None
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
