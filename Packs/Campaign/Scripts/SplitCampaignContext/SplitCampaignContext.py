import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BELOW_THRESHOLD_ITEMS_CONTEXT_PATH = 'LowerSimilarityIncidents'
ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH = 'incidents'


def save_to_context(items, context_path, delete_existing=False):
    # clean the context
    if delete_existing:
        res = demisto.executeCommand('DeleteContext', {"key": context_path, "subplaybook": "yes"})
        print(res)

    print(len(items))
    return CommandResults(
        outputs_prefix=context_path,
        outputs=items)


def filter_by_threshold(context, threshold):
    low = []
    high = []
    for item in context:
        if item.get('similarity') >= threshold or item.get('PartOfCampaign'):
            high.append(item)
        else:
            low.append(item)
    return low, high


def main():
    input_args = demisto.args()
    # If user did not provide a lower threshold then split is not needed.
    threshold = input_args.get('SimilarityThresholdToSplitBy')
    if not threshold:
        return
    try:
        threshold = float(threshold)
    except ValueError as e:
        raise(f'Could not use threshold: {threshold}. Error: {e}')

    root_context_path = input_args.get('campaign_context_path')
    above_threshold_context_path = f'{root_context_path}.{ABOVE_THE_THRESHOLD_ITEMS_CONTEXT_PATH}'
    below_threshold_context_path = f'{root_context_path}.{BELOW_THRESHOLD_ITEMS_CONTEXT_PATH}'
    context = demisto.get(demisto.context(), f'{root_context_path}.incidents')

    # If there are no incident to split
    if not context:
        return
    print(context)
    only_lower_values, only_higher_values = filter_by_threshold(context, threshold)
    result = []
    result.append(save_to_context(only_lower_values, below_threshold_context_path))
    result.append(save_to_context(only_higher_values, above_threshold_context_path, True))
    return_results(result)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
