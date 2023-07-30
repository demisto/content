import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib


def stringSimilarity(firstString: str, secondString: str, similarityThreshold: float):
    """
    Calculate the similarity score between two strings using the SequenceMatcher.

    The function calculates the similarity ratio between the provided 'firstString' and 'secondString'
    using the SequenceMatcher from the 'difflib' library. If the similarity ratio is greater than or equal
    to the specified 'similarityThreshold', a CommandResults object containing the similarity score
    and the input strings is returned.

    Args:
        firstString (str): The first string to compare.
        second_string (str): The second string to compare.
        similarityThreshold (float): The minimum similarity threshold required for a match.

    Returns:
        CommandResults: A CommandResults object with the similarity score and input strings if the
                        similarity ratio is greater than or equal to the 'similarityThreshold'.

    Raises:
        ValueError: If the similarity ratio is below the 'similarityThreshold', a ValueError is raised
                    with a message indicating that no similarity score is calculated.
    """

    similarity_ratio = difflib.SequenceMatcher(None, firstString, secondString).ratio()
    if similarity_ratio >= float(similarityThreshold):
        json_results = {
            "StringA": firstString,
            "StringB": secondString,
            "SimilarityScore": similarity_ratio
        }

    return json_results


def main():
    similarityThreshold = demisto.getArg('similarity_threshold')
    firstString = demisto.getArg('string_A')
    secondString = demisto.getArg('string_B')

    try:
        results = stringSimilarity(firstString, secondString, similarityThreshold)

        commandResults = CommandResults("StringSimilarity", ["StringA", "StringB"], results)

        return_results(commandResults)
    except Exception as e:
        return_error(f'Failed to check string similarity. Problem: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
