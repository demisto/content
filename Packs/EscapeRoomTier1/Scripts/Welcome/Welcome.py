import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

WELCOME_MESSAGE = '''\n
# Welcome to XSOAR escape room
Here you will learn where all the magic happens.
But!
Before we start, you must prove you are a truly diamond in the rough.

Only the worthy shall pass.

**Follow the trail of clues and find the path to success.**

'''


def download_clip(verify_ssl=False):
    res = requests.get('https://github.com/demisto/content/raw/EscapeRoomMaterials/Packs/EscapeRoomTier1/Resources/WelcomeClip.mp4',
                       verify=verify_ssl)
    res.raise_for_status()

    return res.content


def main():
    data = download_clip()
    entry = fileResult('WelcomeClip', data)
    entry.update({
        "Type": 10,  # EntryVideoFile
        'HumanReadable': WELCOME_MESSAGE,
    })
    return_results(entry)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
