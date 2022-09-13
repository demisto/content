import demistomock as demisto


def test_create_space_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_space_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'description': 'description',
                                                       'key': 'key',
                                                       'name': 'name'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'id': 'id',
                                                                  'key': 'key',
                                                                  'name': 'name'})

    Confluence.create_space_command()

    assert 'Space created successfully' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_create_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'type': 'type',
                                                       'title': 'title',
                                                       'space': 'space',
                                                       'body': 'body'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'id': 'id',
                                                                  'title': 'title',
                                                                  'space': 'space',
                                                                  'body': 'body'})

    Confluence.create_content_command()

    assert 'New Content' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_get_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'key': 'key',
                                                       'title': 'title'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'results': [{'id': 'id',
                                                                  'title': 'title',
                                                                               'type': 'type',
                                                                               'version': {'number': 'number'},
                                                                               'body': {'view': {'value': 'value'}}}]})

    Confluence.get_content_command()

    assert 'Content' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_list_spaces_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_host_status_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'status': 'status',
                                                       'type': 'type'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'results': [{'id': 'id',
                                                                  'key': 'key',
                                                                               'name': 'name', }]})

    Confluence.list_spaces_command()

    assert 'Spaces' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_delete_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a delete_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'id': 'id'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={"Results": "Successfully Deleted Content ID id", "ID": 'id'})

    Confluence.delete_content_command()

    assert 'Content' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_update_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a pdate_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'pageid': 'pageid',
                                                       'title': 'title',
                                                       'space': 'space',
                                                       'body': 'body',
                                                       'type': 'type',
                                                       'currentversion': '1'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'results': [{'id': 'id',
                                                                  'key': 'key',
                                                                               'name': 'name', }]})

    Confluence.update_content_command()

    assert 'Updated Content' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_search_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a search_content_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': 'url',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'cql': 'cql',
                                                       'cqlcontext': 'cqlcontext',
                                                       'expand': 'expand',
                                                       'start': 'start',
                                                       'limit': 'limit'})

    import Confluence
    mocker.patch.object(Confluence, 'http_request', return_value={'results': [{'id': 'id',
                                                                               'title': 'title',
                                                                               'type': 'type',
                                                                               'version': {'number': 'number'}}]})

    Confluence.search_content_command()

    assert 'Content Search' in demisto.results.call_args_list[0][0][0].get('HumanReadable')
