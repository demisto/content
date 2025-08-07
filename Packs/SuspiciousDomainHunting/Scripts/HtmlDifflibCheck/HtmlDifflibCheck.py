import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib


def calculate_similarity(html1, html2):
    # Calculate the similarity between the two HTML contents
    similarity = difflib.SequenceMatcher(None, html1, html2).ratio()
    return similarity


def main():
    try:
        html1 = demisto.getArg("html1")
        html2 = demisto.getArg("html2")

        if not html1 or not html2:
            return_error("Please provide both HTML contents as inputs.")

        similarity = calculate_similarity(html1, html2)
        similarity_percentage = similarity * 100

        context = {"HTMLSimilarity": {"SimilarityPercentage": similarity_percentage}}

        return_results(CommandResults(outputs=context, readable_output=f"Similarity Percentage: {similarity_percentage:.2f}%"))

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
