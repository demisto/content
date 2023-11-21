import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib


def stringSimilarity(first_array: str, second_array: str, similarity_threshold: float):
    """
    Calculate the similarity score between two strings using the SequenceMatcher.

    The function calculates the similarity ratio between the provided 'first_string' and 'second_string'
    using the SequenceMatcher from the 'difflib' library. If the similarity ratio is greater than or equal
    to the specified 'similarity_threshold', a CommandResults object containing the similarity score
    and the input strings is returned.

    Args:
        first_string (str): The first string to compare.
        second_string (str): The second string to compare.
        similarity_threshold (float): The minimum similarity threshold required for a match.

    Returns:
        CommandResults: A CommandResults object with the similarity score and input strings if the
                        similarity ratio is greater than or equal to the 'similarity_threshold'.

    Raises:
        ValueError: If the similarity ratio is below the 'similarity_threshold', a ValueError is raised
                    with a message indicating that no similarity score is calculated.
    """

    results = []
    for string_a in first_array:
        for string_b in second_array:
            similarity_ratio = difflib.SequenceMatcher(None, string_a, string_b).ratio()
            if similarity_ratio >= float(similarity_threshold):
                results.append({
                    "StringA": string_a,
                    "StringB": string_b,
                    "SimilarityScore": similarity_ratio
                })
    if not results:
        return None
    return CommandResults("StringSimilarity", ["StringA", "StringB"], results)


def main():
    similarity_threshold = demisto.getArg('similarity_threshold')
    first_array = argToList(demisto.getArg('string_A'))
    second_array = argToList(demisto.getArg('string_B'))
    try:
        results = stringSimilarity(first_array, second_array, similarity_threshold)
        return_results(results)
    except Exception as e:
        return_error(f'Failed to check string similarity. Problem: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
