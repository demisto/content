from CiscoUmbrellaEnforcement import prepare_suffix


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
    suffix = prepare_suffix(page=page, limit='')
    assert 'page=1' in suffix
    suffix = prepare_suffix(page=page, limit=limit)
    assert 'page=1' in suffix and 'limit=50' in suffix
