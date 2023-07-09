import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64


def main():
    args = demisto.args()
    filename = args.get('filename', '')
    data = args.get('data', '')
    data_encoding = args.get('data_encoding', 'raw')
    entdy_id = args.get('entryId')

    try:
        if entdy_id:
            res = demisto.executeCommand('getEntry', {'id': entdy_id})
            if is_error(res):
                raise DemistoException(get_error(res))

            data = demisto.get(res[0], 'Contents')

        if data_encoding == 'base64':
            data = base64.b64decode(data)
        elif data_encoding != 'raw':
            raise ValueError(f'Invalid data encoding name: {data_encoding}')

        return_results(fileResult(filename, data))
    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
