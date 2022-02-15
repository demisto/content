import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Tuple

BELOW_THRESHOLD_ITEMS_CONTEXT_PATH = 'LowerSimilarityIncidents'
ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH = 'incidents'


def save_to_context(items: list, context_path: str, delete_existing: bool = False, is_sub_playbook: str = 'auto',
                    table_header='Incidents Result'):
    if delete_existing:
        res = demisto.executeCommand('DeleteContext', {"key": context_path, "subplaybook": is_sub_playbook})
        if is_error(res):
            return_error('Failed to delete current context. Error details:\n{}'.format(get_error(res)))

    return CommandResults(
        outputs_prefix=context_path,
        outputs=items,
        readable_output=tableToMarkdown(table_header, items))


def _get_incident_campaign(_id: int):
    res = demisto.executeCommand('getIncidents', {'id': _id})

    if is_error(res):
        return

    res_custom_fields = res[0]['Contents']['data'][0]['CustomFields']
    return res_custom_fields['partofcampaign'] if 'partofcampaign' in res_custom_fields else None


def filter_by_threshold(context: list, threshold: float) -> Tuple[list, list]:
    low = []
    high = []
    for item in context:
        if item.get('similarity') >= threshold:
            high.append(item)
        else:
            campaign = _get_incident_campaign(item['id'])
            if campaign:
                high.append(item)
            else:
                low.append(item)
    return low, high


def main():
    input_args = demisto.args()
    # If user did not provide a lower threshold then split is not needed.
    threshold = input_args.get('similarity_threshold')

    try:
        threshold = float(threshold)
    except ValueError as e:
        raise DemistoException(f'Could not use threshold: {threshold}. Error: {e}')

    root_context_path = 'EmailCampaign'
    above_threshold_context_path = f'{root_context_path}.{ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH}'
    below_threshold_context_path = f'{root_context_path}.{BELOW_THRESHOLD_ITEMS_CONTEXT_PATH}'
    context = demisto.get(demisto.context(), f'{above_threshold_context_path}')

    # If there are no incident to split
    if not context:
        return
    only_lower_values, only_higher_values = filter_by_threshold(context, threshold)
    result = []
    result.append(save_to_context(only_lower_values, below_threshold_context_path,
                                  table_header='Low Similarity Incidents Result'))
    result.append(save_to_context(only_higher_values, above_threshold_context_path, True,
                                  table_header='High Similarity Incidents Result'))
    return_results(result)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
