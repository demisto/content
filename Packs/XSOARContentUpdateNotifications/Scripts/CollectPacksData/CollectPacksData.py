import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_packs_data_from_context() -> List[Dict[str, str]]:
    """Fetched packs' data from context and formats it to an installable object.

    Returns:
        List[Dict[str, str]]: Installable objects list.
    """
    instance_context = demisto.context()
    context_packs_data = instance_context.get('ContentData')

    if isinstance(context_packs_data, list):

        context_entries = [
            {
                'packid': pack['packID'],
                'packversion': 'latest',
            }
            for pack in context_packs_data
        ]

    else:
        context_entries = [
            {
                'packid': context_packs_data['packID'],
                'packversion': 'latest',
            }
        ]

    return_results(
        CommandResults(
            outputs_prefix='ConfigurationSetup',
            outputs={'MarketplacePacks': context_entries},
        )
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    get_packs_data_from_context()
