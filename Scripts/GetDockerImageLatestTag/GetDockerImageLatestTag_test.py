from GetDockerImageLatestTag import main
import demistomock as demisto
import pytest

RETURN_ERROR_TARGET = 'GetDockerImageLatestTag.return_error'


# demisto/python-deb doesn't contain a latest tag
@pytest.mark.parametrize('image', ['python', 'python-deb', 'python3', 'python3-deb'])
def test_valid_docker_image(mocker, image):
    demisto_image = 'demisto/' + image
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
    # current latest tag is 2.7.16.214 or 3.7.2.214 disable-secrets-detection
    assert int(results[0].split('.')[3]) >= 214


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
