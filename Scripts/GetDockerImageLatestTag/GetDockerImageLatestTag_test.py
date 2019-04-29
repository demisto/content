from GetDockerImageLatestTag import main
import demistomock as demisto

RETURN_ERROR_TARGET = 'GetDockerImageLatestTag.return_error'


def test_valid_docker_image(mocker):
    demisto_image = 'demisto/python'
    args = {'docker_image': demisto_image}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['docker_image'] == demisto_image
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0].startswith('2.7')


def test_invalid_docker_image(mocker):
    image_name = 'demisto/notrealdockerimage'
    mocker.patch.object(demisto, 'args', return_value={'docker_image': image_name})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()['docker_image'] == image_name
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg is not None
