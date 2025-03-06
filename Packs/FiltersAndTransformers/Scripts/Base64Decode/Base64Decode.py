import demistomock as demisto
from CommonServerPython import *
import base64

MULTIPLIER = 4
PADDING_CHAR = "="
HUMAN_READABLE_EMPTY_STRING = "The decoded value is empty (empty string)"


def add_padding(value: str) -> str:
    """
    Since a valid Base64 string has a length that is a multiplication of 4, when the string isn't dividable by 4
    the character '=' will be a placeholder to complete the string so it'll be dividable by 4
    ('=' does not change the decoded value).
    We first retrieve the remainder of the length divided by 4 and then subtract it from 4
    to know how much padding we need to append to reach the nearest biggest number that is a multiplication of 4.
    For instance, if the length is 17, then 17 % 4 is 1, this means we need to pad the string 3 times (4 - 1)
    to reach a length of 20. We deal with the edge case where the length is already a multiplication of 4 by adding
    a final modulo operation with 4 as the divisor.
    """
    # Since white spaces are ignored, we must ignore them when calculating the length in order to calculate the correct padding.
    value_length = len(value) - value.count(" ")
    padding_length = (MULTIPLIER - (value_length % MULTIPLIER)) % MULTIPLIER
    return f"{value}{PADDING_CHAR*padding_length}"


def decode(value: str) -> CommandResults:
    decoded_bytes = base64.urlsafe_b64decode(add_padding(value))
    res = decoded_bytes.decode(errors="ignore")

    outputs = {"Base64": {"originalValue": value, "decoded": res}}
    human_readable = res if res else HUMAN_READABLE_EMPTY_STRING
    return CommandResults(outputs=outputs, readable_output=human_readable)


def main():  # pragma: no cover
    value = demisto.args().get("value")
    try:
        return_results(decode(value))
    except Exception as e:
        return_error(f"Failed to execute command.\nError:\n{str(e)}")


if __name__ in ("__main__", "builtins", "__builtin__"):
    main()
