from typing import Text
import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        return_results(list(re.findall(emailRegex, demisto.args().get('value'))))
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
