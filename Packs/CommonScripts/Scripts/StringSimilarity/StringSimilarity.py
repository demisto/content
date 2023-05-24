import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib
#import Levenshtein

def main():
    similiarity_threshold = float(demisto.getArg('similiarity_threshold'))
    first_string = demisto.getArg('string_A')
    second_string = demisto.getArg('string_B')

    similarity_ratio = difflib.SequenceMatcher(None, first_string, second_string).ratio()
    if similarity_ratio >= similiarity_threshold:
        results = {"string_A": first_string, "string_B": second_string, "similarityScore": similarity_ratio}

        json_results = {
            "EntryContext": {"StringSimilarity": results},
            "Type": entryTypes['note'],
            "ContentsFormat": formats['json'],
            "Contents": results
        }

        return_results(json_results)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
