import demistomock as demisto
from CommonServerPython import *
import base64

MULTIPLIER = 4
PADDING_CHAR = '='


def add_padding(value: str) -> str:
    """
    Since a valid Base64 string has a length that is a multiplication of 4, we need to add padding
    to the string if this is not the case by using the character '=' ('=' does not change the decoded value).
    We first retrieve the remainder of the length divided by 4 and then subtract it from 4
    to know how much padding we need to append to reach the nearest biggest number that is a multiplication of 4.
    For instance, if the length is 17, then 17 % 4 is 1, this means we need to pad the string 3 times (4 - 1)
    to reach a length of 20. We deal with the edge case where the length is already a multiplication of 4 by adding
    a final modulo operation with 4 as the divisor.
    """
    # = doesnt chage value
    # Since white spaces are ignored, we must ignore them when calculating the length in order to calculate the correct padding.
    value_length = len(value) - value.count(' ')
    return f'{value}{PADDING_CHAR*((MULTIPLIER - (value_length % MULTIPLIER)) % MULTIPLIER)}'


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

    return CommandResults(outputs=outputs, readable_output=tableToMarkdown('Results', outputs))


def main():  # pragma: no cover
    value = demisto.args().get('value')
    try:
        return_results(decode(value))
    except Exception as e:
        return_error(f'Failed to execute command.'
                     f'\nError:\n{str(e)}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
