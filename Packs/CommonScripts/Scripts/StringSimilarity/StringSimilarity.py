import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib
# import Levenshtein


def main():
    similiarity_threshold = float(demisto.getArg('similiarity_threshold'))
    first_string = demisto.getArg('string_A')
    second_string = demisto.getArg('string_B')

    similarity_ratio = difflib.SequenceMatcher(None, first_string, second_string).ratio()
    if similarity_ratio >= similiarity_threshold:
        commandResults = CommandResults("StringSimilarity", "SimilarityScore", {
            "StringA": first_string,
            "StringB": second_string,
            "SimilarityScore": similarity_ratio
        })

        return_results(commandResults)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
