import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_widget_entry(similarity_percentage) -> dict:
    data = {
        "Type": 17,
        "size": 30,
        "ContentsFormat": "number",
        "Contents": {
            "stats": round(similarity_percentage, 2),
            "params": {
                "layout": "horizontal",
                "name": "Similarity Percentage",
                "sign": "%",
                "signAlignment": "right",
                "colors": {
                    "isEnabled": True,
                    "items": {"#00cd33": {"value": 0}, "#f57d00": {"value": 50}, "#fe1403": {"value": 75}},
                },
                "type": "above",
            },
        },
    }

    return data


def main():
    try:
        demisto_context = demisto.context()
        similarity_percentage = demisto.get(demisto_context, "HTMLSimilarity.SimilarityPercentage")
        if not similarity_percentage:
            root = demisto.get(demisto_context, "HTMLSimilarity")
            if isinstance(root, list):
                similarity_percentage = root[0].get("SimilarityPercentage")
                return_results(create_widget_entry(similarity_percentage))
            else:
                return_results("Please wait for calculation.")
        else:
            return_results(create_widget_entry(similarity_percentage))

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
