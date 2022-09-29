import demistomock as demisto
from CommonServerPython import *

import base64

MULTIPLIER = 4


def add_padding(value: str) -> str:
    value_length = len(value)
    return f'{value}{"="*((MULTIPLIER - value_length % MULTIPLIER) % MULTIPLIER)}'


def decode(value: str):
    decoded_bytes = base64.urlsafe_b64decode(add_padding(value))
    res = decoded_bytes.decode(errors='ignore')

    outputs = {
        "Base64":
            {
                "originalValue": value,
                "decoded": res
            }
    }

    return res, outputs


def main():
    value = demisto.args().get('value')
    try:
        return_outputs(*decode(value))
    except Exception as e:
        return_error(f'Failed to execute command.'
                     f'\nError:\n{str(e)}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
