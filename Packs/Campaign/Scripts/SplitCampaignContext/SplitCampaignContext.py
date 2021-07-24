import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BELOW_THRESHOLD_ITEMS_CONTEXT_PATH = 'LowerSimilarityIncidents'
ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH = 'incidents'


def save_to_context(items: list, context_path: str, delete_existing: bool = False, is_sub_playbook: str = 'auto'):
    if delete_existing:
        demisto.executeCommand('DeleteContext', {"key": context_path, "subplaybook": is_sub_playbook})

    return CommandResults(
        outputs_prefix=context_path,
        outputs=items)


def _get_incident_campaign(id: int):
    return demisto.executeCommand('GetByIncidentId', {'incident_id': id, 'get_key': 'partofcampaign'})


def filter_by_threshold(context: list, threshold: float):
    low = []
    high = []
    for item in context:
        demisto.log(f'campaign: {item}')
        if item.get('similarity') >= threshold:
            high.append(item)
        else:
            campaign = _get_incident_campaign(item['id'])
            if campaign:
                demisto.log(f'campaign found : {campaign}')
                high.append(item)
            else:
                low.append(item)
    return low, high


def main():
    input_args = demisto.args()
    # If user did not provide a lower threshold then split is not needed.
    threshold = input_args.get('LowerSimilarityThreshold')
    if not threshold:
        return
    try:
        threshold = float(threshold)
    except ValueError as e:
        raise DemistoException(f'Could not use threshold: {threshold}. Error: {e}')

    root_context_path = 'EmailCampaign'
    above_threshold_context_path = f'{root_context_path}.{ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH}'
    below_threshold_context_path = f'{root_context_path}.{BELOW_THRESHOLD_ITEMS_CONTEXT_PATH}'
    context = demisto.get(demisto.context(), f'{root_context_path}.incidents')

    # If there are no incident to split
    if not context:
        return
    only_lower_values, only_higher_values = filter_by_threshold(context, threshold)
    result = []
    result.append(save_to_context(only_lower_values, below_threshold_context_path))
    result.append(save_to_context(only_higher_values, above_threshold_context_path, True))
    return_results(result)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
