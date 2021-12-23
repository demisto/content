import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_campaign_incident_similarities() -> list:
    """
    Gets all the campaign incident similarities.

    Returns:
        List of all the similarities.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident["similarity"] for incident in incidents]


def calculate_similarity_range(incident_similarities) -> str:
    """
    Gets the campaign incidents similarity range.

    Args:
        incident_similarities: The campaign incident similarities.

    Returns:
        The campaign incidents similarity range.
    """
    max_similarity, min_similarity = max(incident_similarities), min(incident_similarities)

    if max_similarity > min_similarity + 10 ** -3:
        similarity_range = f"{min_similarity * 100:.1f}%-{max_similarity * 100:.1f}%"

    else:
        similarity_range = f"{max_similarity * 100:.1f}%"

    return similarity_range


def main():

    try:
        incident_similarities = get_campaign_incident_similarities()

        if incident_similarities:

            similarity_range = calculate_similarity_range(incident_similarities)
            header = 'Similarity Range' if len(similarity_range.split('-')) > 1 else 'Similarity'

            html_readable_output = f"<div style='text-align:center; font-size:17px; padding: 15px;'>{header}" \
                                   f"</br> <div style='font-size:24px;'> {similarity_range} </div></div>"

        else:
            html_readable_output = "<div style='text-align:center; font-size:17px; padding: 15px;'>Similarity" \
                                   "</br> <div style='font-size:20px;'> No incident similarities were found. </div></div>"

        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html_readable_output
        })

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
