import demistomock as demisto
from urllib.parse import quote, unquote
''' MAIN FUNCTION '''


def main(args):
    value = args.get('value')
    decoded_value = unquote(value)
    processed_value = quote(decoded_value)

    eContext = {
        'EncodedURL': processed_value
    }

    return CommandResults(readable_output=processed_value,
                          outputs=eContext,
                          raw_response=[])


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
