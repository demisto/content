import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random
import string


MAX_LENGTH = 10000


def set_length(length):
    if length <= 0:
        return_error("Length must be greater than 0. Maximum value is {}.".format(MAX_LENGTH))

    return min(length, MAX_LENGTH)


def set_characters(characters: str, digits: bool, lowercase: bool, punctuation: bool, uppercase: bool):
    if not any([uppercase, lowercase, digits, punctuation]):
        return_error("Punctuation, Digits, Uppercase or Lowercase must be True.")

    characters += string.ascii_lowercase if lowercase else ''
    characters += string.ascii_uppercase if uppercase else ''
    characters += string.digits if digits else ''
    characters += string.punctuation if punctuation else ''
    return characters


def create_password(characters, length):
    password = ""
    for x in range(0, length):
        password += random.SystemRandom(random.seed(time.time())).choice(characters)  # type: ignore

    entry_context = {'RandomString': password}
    raw = json.loads(json.dumps(entry_context))
    results = CommandResults(content_format=EntryFormat.JSON,
                             entry_type=EntryType.NOTE,
                             outputs=entry_context,
                             readable_output=tableToMarkdown('RandomString Generated.', raw) if raw else 'No result were found',
                             raw_response=raw)
    return results


def main():
    args = demisto.args()

    punctuation = argToBoolean(args["Punctuation"])
    lowercase = argToBoolean(args["Lowercase"])
    uppercase = argToBoolean(args["Uppercase"])
    digits = argToBoolean(args["Digits"])
    length = set_length(arg_to_number(args["Length"], required=True))

    characters = set_characters("", digits, lowercase, punctuation, uppercase)

    results = create_password(characters, length)
    return_results(results)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
