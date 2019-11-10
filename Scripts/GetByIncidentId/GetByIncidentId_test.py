import demistomock as demisto
from GetByIncidentId import main


def test_get_depth_one(mocker):

    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert result[0]['Contents'][key] == 'test1value'


def test_get_depth_two(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                                              "test2key1": {"test2key2": "test2value"},
                                              "test3key1": {"test3key2": {
                                                  "test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}
                                  }
                     }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test2key1.test2key2"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()

    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert result[0]['Contents'][key] == 'test2value'


def test_get_depth_five(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                                              "test2key1": {"test2key2": "test2value"},
                                              "test3key1": {"test3key2": {
                                                  "test3key3": {"test3key4": {"test3key5": "test3value"}}}}}
                                  }
                     }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key':
                                                       'test3key1.test3key2.test3key3.test3key4.test3key5'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert result[0]['Contents'][key] == 'test3value'


def test_set_default(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert list(result[0]['EntryContext'].keys())[0] == key


def test_set_depth_one(mocker):

    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key", 'set_key':
                                                                                      "testSet1"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['set_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == 'test1value'


def test_set_depth_two(mocker):

    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key", 'set_key':
                                                                                      "testSet1.testSet2"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['set_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == 'test1value'


def test_set_depth_five(mocker):

    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1',
                                                       'get_key': "test1key",
                                                       'set_key': 'testSet1.testSet2.testSet3.testSet4.testSet5'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['set_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == 'test1value'


def test_get_and_set_multi_depth(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": "test1value",
                    "test2key1": {"test2key2": "test2value"},
                    "test3key1": {"test3key2": {"test3key3": {"test3key4": {"test3key5": {"test3value"}}}}}}}
            }]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test2key1.test2key2", 'set_key':
                                                                                      "testSet1.testSet2"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['set_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == 'test2value'


def test_get_array(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": ["testvalue1", "testvalue2", "testvalue3"]}}}]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == ["testvalue1", "testvalue2", "testvalue3"]


def test_get_object(mocker):
    def execute_command(name, args=None):
        if name == 'getContext':
            return [{'Contents': {'context': {"test1key": {"testobjkey": "testobjval"}}}}]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'incident_id': '1', 'get_key': "test1key"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'results')

    main()
    result = demisto.results.call_args[0]

    key = demisto.args()['get_key']
    assert list(result[0]['EntryContext'].keys())[0] == key
    assert result[0]['Contents'][key] == {"testobjkey": "testobjval"}
