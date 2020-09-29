from typing import List

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    data = demisto.executeCommand("panorama-get-unallocated-users-bandwidth", {})[0]['Contents']
    demisto.results(int(data['UnallocatedBandwidth']))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
