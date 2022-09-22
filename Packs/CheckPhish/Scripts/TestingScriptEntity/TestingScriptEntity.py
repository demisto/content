import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_zip_path(args):
    """
    :param args: arg from demisto
    :return: path of zip file
    """
    print("TESTING SCRIPT")


def main():
    get_zip_path()


if __name__ in ('__builtin__', 'builtins'):
    main()
