from demisto_sdk.commands.test_content.xsiam_tools.xsiam_client import XsiamApiClient


def create_filter(size=50, show_installed=True, with_collection_type=False):

    filter = {
        "page": 0,
        "size": size,
        "sort": [
            {
                "field": "searchRank",
                "asc": False
            },
            {
                "field": "updated",
                "acs": False
            }
        ]
    }

    if not show_installed:
        if 'general' not in filter:
            filter['general'] = []
        filter['general'].append('generalFieldNotInstalled')

    if with_collection_type:
        if 'types' not in filter:
            filter['types'] = []
        filter['types'].append('Collection')

    return filter


def test_check_number_of_packs_in_marketplace(xsiam_client: XsiamApiClient):
    """
    Given
    - XSIAM tenant
    - XSIAM marketplace

    When
    - searching for all the packs

    Then
    - ensure there are more than 900 packs in the marketplace
    """
    search_all_packs_filter = create_filter(size=1)
    results = xsiam_client.search_marketplace(search_all_packs_filter)

    assert results['total'] > 900


def test_check_number_of_collector_packs_in_marketplace(xsiam_client: XsiamApiClient):
    """
    Given
    - XSIAM tenant
    - XSIAM marketplace

    When
    - searching for collection packs

    Then
    - ensure there are more than 120
    """
    collection_packs_filter = create_filter(size=1, with_collection_type=True)
    results = xsiam_client.search_marketplace(collection_packs_filter)

    assert results['total'] > 120
