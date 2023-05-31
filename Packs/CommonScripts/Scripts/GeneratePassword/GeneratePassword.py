import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import secrets
import string

DEFAULT_MIN = 0
DEFAULT_MAX = 10


def print_char_values(pw):
    ascii_values = [ord(char) for char in pw]
    ascii_string = ', '.join(str(value) for value in ascii_values)
    demisto.debug(f"ASCII for password = {ascii_string}")


def generate_password(args: Dict[str, Any]) -> CommandResults:
    is_debug = argToBoolean(args.get('debug'))
    min_lcase = arg_to_number(args.get('min_lcase')) or DEFAULT_MIN
    max_lcase = arg_to_number(args.get('max_lcase')) or DEFAULT_MAX
    min_ucase = arg_to_number(args.get('min_ucase')) or DEFAULT_MIN
    max_ucase = arg_to_number(args.get('max_ucase')) or DEFAULT_MAX
    min_digits = arg_to_number(args.get('min_digits')) or DEFAULT_MIN
    max_digits = arg_to_number(args.get('max_digits')) or DEFAULT_MAX
    min_symbols = arg_to_number(args.get('min_symbols')) or DEFAULT_MIN
    max_symbols = arg_to_number(args.get('max_symbols')) or DEFAULT_MAX

    # Define the characters of our classes
    lcase = string.ascii_lowercase
    ucase = string.ascii_uppercase
    n = string.digits
    s = "!@#$%^&*()[]+:\"?_><=';/-.,\\|"

    # randomize the amount of characters we get as per parameters
    numu = max_ucase - min_ucase
    numu = max(numu, 0)
    numu = secrets.randbelow(numu + 1) + min_ucase

    numl = max_lcase - min_lcase
    numl = max(numl, 0)
    numl = secrets.randbelow(numl + 1) + min_lcase

    numn = max_digits - min_digits
    numn = max(numn, 0)
    numn = secrets.randbelow(numn + 1) + min_digits

    nums = max_symbols - min_symbols
    nums = max(nums, 0)
    nums = secrets.randbelow(nums + 1) + min_symbols

    if numu + numl + numn + nums == 0:
        raise DemistoException("error: insane password. No character length.")

    # start with a blank password
    pw = []

    # iterate through each character class and add
    for _ in range(numu):
        pw.append(secrets.choice(ucase))
    for _ in range(numl):
        pw.append(secrets.choice(lcase))
    for _ in range(numn):
        pw.append(secrets.choice(n))
    for _ in range(nums):
        pw.append(secrets.choice(s))

    # randomize our new password string
    rpw = ''.join(secrets.choice(pw) for _ in range(len(pw)))

    if is_debug:
        print_char_values(rpw)
    return CommandResults(
        outputs_prefix="NEW_PASSWORD",
        outputs=rpw,
        readable_output=tableToMarkdown('Newly Generated Password', {'password': rpw})
    )


def main():  # pragma: no cover
    try:
        args = demisto.args()
        return_results(generate_password(args))
    except Exception as e:
        return_error(str(e))


if __name__ in ('__builtin__', 'builtins'):
    main()
