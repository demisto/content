import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'CollectPacksData'


def get_packs_data_from_context() -> None:
    """Fetched packs' data from context and formats it to an installable object.
    """
    instance_context = demisto.context()
    context_packs_data = instance_context.get('ContentData', [])

    context_entries = [
        {
            'packid': pack['packID'],
            'packversion': 'latest',
        }
        for pack in context_packs_data
    ]

    return_results(
        CommandResults(
            outputs_prefix='ConfigurationSetup',
            outputs={'MarketplacePacks': context_entries},
        )
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    get_packs_data_from_context()