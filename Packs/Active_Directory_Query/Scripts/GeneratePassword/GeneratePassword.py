import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import string
import secrets


def main():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(12))  # for a 12-character password
    return_results(password)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
