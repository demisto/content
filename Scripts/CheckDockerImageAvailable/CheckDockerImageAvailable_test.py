from CheckDockerImageAvailable import docker_auth, main, docker_min_layer
import demistomock as demisto
import json

RETURN_ERROR_TARGET = 'CheckDockerImageAvailable.return_error'


def test_auth():
    token = docker_auth('demisto/python')
    assert token is not None


def test_min_layer():
    layers_text = """
    [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 2207038,
         "digest": "sha256:169185f82c45a6eb72e0ca4ee66152626e7ace92a0cbc53624fb46d0a553f0bd"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 309123,
         "digest": "sha256:ef00a8db125d3a25e193b96e6786193f744e24b01db96dab132e687e53848f9a"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 24623747,
         "digest": "sha256:b5c6e736c1549dc0f0b4e41465ad17defc8d2af10f7c28e0a3bfc530298a8a42"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 233,
         "digest": "sha256:ae23d06361f0ec0edf69341d705ab828a0b28c162a47e7733217ca7e4003606c"
      }
    ]
    """
    layers = json.loads(layers_text)
    min_layer = docker_min_layer(layers)
    assert min_layer['size'] == 233


def test_valid_docker_image(mocker):
    image_name = 'demisto/python:2.7.15.155'  # disable-secrets-detection
    mocker.patch.object(demisto, 'args', return_value={'input': image_name})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['input'] == image_name
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'ok'


def test_invalid_docker_image(mocker):
    image_name = 'demisto/python:bad_tag'
    mocker.patch.object(demisto, 'args', return_value={'input': image_name})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()['input'] == image_name
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg is not None
