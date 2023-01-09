import demistomock as demisto


def test_main(mocker):
    from ServerLogsDocker import main
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'output': 'output'}}])
    return_results = mocker.patch.object(demisto, 'results')
    main()
    return_results.assert_called_with('File: /var/log/demisto/docker.log\noutput')
