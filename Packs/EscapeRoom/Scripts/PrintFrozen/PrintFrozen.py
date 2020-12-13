import traceback

import demistomock as demisto
from CommonServerPython import *

GIF_URL = ''
HTML_MESSAGE = '''
<img src="https://media.giphy.com/media/qiGNN3XtoWYZGjnczG/giphy.gif" alt="Frozen">
<div style='font-size:18px;'>
Let it <span style="color:cyan">snow</span>
Let it <span style="color:cyan">SNOW</span>
Can't fetch that anymore

Let it <span style="color:cyan">S-Now</span>
Let it <span style="color:cyan">S-NOW</span>
Turn it on and make it work
</div>
'''


# MAIN FUNCTION #


def main():
    try:
        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': HTML_MESSAGE,
        })
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenReputation. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
