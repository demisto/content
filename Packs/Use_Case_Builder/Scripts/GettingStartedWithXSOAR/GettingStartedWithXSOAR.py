import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

WELCOME_MESSAGE = '''\n
# Welcome to the XSOAR Use Case Builder!

**Please Watch this video to learn the basics of XSOAR.**
'''


def download_clip(verify_ssl=False):
    res = requests.get(
        'https://github.com/joe-cosgrove/xsoar-videos/blob/main/Cortex%20XSOAR%20In%20Under%205%20Minutes.mp4?raw=true',
        verify=verify_ssl
    )
    res.raise_for_status()

    return res.content


def main():
    data = download_clip()
    entry = fileResult('Getting Started with XSOAR', data)
    entry.update({
        "Type": 10,  # EntryVideoFile
        'HumanReadable': WELCOME_MESSAGE,
    })
    return_results(entry)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
