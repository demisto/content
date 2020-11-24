import time
from CiscoUmbrellaEnforcement import Client, domains_list_suffix


def test_domains_list_suffix():
    """Unit test
            Given
            - fetch incidents command
            - command args
            When
            - mock the Clients's get token function.
            - mock the Demisto's getIntegrationContext.
            - mock the set_shaping function.
            Then
            - run the fetch incidents command using the Client
            Validate when a day has passed since last update of shaping, Then the shaping will be checked again.
            Validate That the shaping is set to new shaping.
    """
    page = '1'
    limit = '50'
    request = '"https://s-platform.api.opendns.com/1.0/domains?customerKey=XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX&page=2' \
              '&limit=200" '
    suffix = domains_list_suffix(page='', limit='', request=request)
    assert suffix == request
    suffix = domains_list_suffix(page=page, limit='', request='')
    assert 'page=1' in suffix
    suffix = domains_list_suffix(page=page, limit=limit, request='')
    assert 'page=1' in suffix and 'limit=50' in suffix
