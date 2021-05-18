import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
import math
import string


def calculate_shannon_entropy(data, minimum_entropy):
    """Algorithm to determine the randomness of a given data.
    Higher is more random/complex, most English words will yield in average result of 3
    Args:
        data (str): The data to calculate entropy on.
        minimum_entropy (float): The minimum entropy.
    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    entropy = 0.0
    # each unicode code representation of all characters which are considered printable
    for char in (ord(c) for c in string.printable):
        # probability of event X
        p_x = float(data.count(chr(char))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    if entropy >= minimum_entropy:
        human_readable = tableToMarkdown("Entropy results", {'Checked Value': data, 'Entropy': entropy},
                                         headers=['Checked Value', 'Entropy'])

        return human_readable, {'EntropyResult': {'checked_value': data, 'entropy': entropy}}, {}

    return f'Entropy for {data} is {entropy} - lower than {minimum_entropy}', {}, {}


def main():
    try:
        data = demisto.args().get('data', '')
        minimum_entropy = float(demisto.args().get('minimum_entropy', 0))

        return_outputs(*calculate_shannon_entropy(data, minimum_entropy))
    except Exception as ex:
        return_error(f'Failed to execute calculate entropy script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
