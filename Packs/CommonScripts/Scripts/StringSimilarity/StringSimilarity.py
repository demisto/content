import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib


def stringSimilarity(firstString: str, second_string: str, similarityThreshold: float):
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
    similarity_ratio = difflib.SequenceMatcher(None, firstString, second_string).ratio()
    if similarity_ratio >= similarityThreshold:
        commandResults = CommandResults("StringSimilarity", "SimilarityScore", {
            "StringA": firstString,
            "StringB": second_string,
            "SimilarityScore": similarity_ratio
        })
        return commandResults

    # Raise an exception if none of the conditions are met.
    return ValueError("No similarity score calculated. Check the similarityThreshold value.")


def main():
    similarity_threshold = float(demisto.getArg('similarity_threshold'))
    first_string = demisto.getArg('string_A')
    second_string = demisto.getArg('string_B')
    commandResults = stringSimilarity(first_string, second_string, similarity_threshold)

    return_results(commandResults)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
