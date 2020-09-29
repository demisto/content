import demistomock as demisto

''' MAIN FUNCTION '''


def main():
    from urllib.parse import quote, unquote

    value = demisto.args()["value"]
    decoded_value = unquote(value)
    processed_value = quote(decoded_value)

    eContext = {
        'EncodedURL': processed_value
    }

    return_outputs(processed_value, eContext)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
