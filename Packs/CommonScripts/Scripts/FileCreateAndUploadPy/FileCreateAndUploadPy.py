import base64
import binascii

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    filename = args.get('filename') or ''
    data = args.get('data') or ''
    data_encoding = args.get('data_encoding') or 'raw'
    entdy_id = args.get('entryId')

    try:
        if entdy_id:
            res = demisto.executeCommand('getEntry', {'id': entdy_id})
            if is_error(res):
                demisto.results(res)  # noqa
                sys.exit(0)

            data = demisto.get(res[0], 'Contents')

        if data_encoding == 'raw':
            pass
        elif data_encoding == 'base64':
            data = base64.b64decode(data)
        else:
            raise ValueError(f'Invalid data encoding name: {data_encoding}')

        demisto.results(fileResult(filename, data))  # noqa
    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
