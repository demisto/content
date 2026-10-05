import json

import demistomock as demisto
import pytest
import urllib3
from CheckDockerImageAvailable import docker_auth, docker_min_layer, main, parse_www_auth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RETURN_ERROR_TARGET = "CheckDockerImageAvailable.return_error"


@pytest.mark.skip(reason="Should be fixed in future versions (related to CIAC-11614)")
@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
def test_auth():
    token = docker_auth("demisto/python", verify_ssl=False)
    assert token is not None


def test_parse_www_auth():
    res = parse_www_auth('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
    assert len(res) == 2
    assert res[0] == "https://auth.docker.io/token"
    assert res[1] == "registry.docker.io"
    res = parse_www_auth('Bearer realm="https://gcr.io/v2/token",service="gcr.io"')
    assert len(res) == 2
    assert res[0] == "https://gcr.io/v2/token"
    assert res[1] == "gcr.io"


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
    assert min_layer["size"] == 233


@pytest.mark.skip(reason="Should be fixed in future versions (related to CIAC-11614)")
def test_valid_docker_image(mocker):
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    demisto_image = "demisto/python:2.7.15.155"  # disable-secrets-detection
    args = {"input": demisto_image, "trust_any_certificate": "yes"}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "results")

    # validate our mocks are good
    assert demisto.args()["input"] == demisto_image
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == "ok"
    demisto.results.reset_mock()
    gcr_image = "gcr.io/google-containers/alpine-with-bash:1.0"  # disable-secrets-detection
    args["input"] = gcr_image
    assert demisto.args()["input"] == gcr_image
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == "ok"


@pytest.mark.skip(reason="Should be fixed in future versions (related to CIAC-11614)")
def test_invalid_docker_image(mocker):
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    image_name = "demisto/python:bad_tag"
    mocker.patch.object(demisto, "args", return_value={"input": image_name, "trust_any_certificate": "yes"})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()["input"] == image_name
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg is not None


OCI_MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def test_main_oci_manifest_image_ok(mocker, requests_mock):
    """
    Given: an xsoar-registry image stored with an OCI image manifest. The registry only serves it to clients that
        accept that media type, otherwise it returns 404 MANIFEST_UNKNOWN (XSUP-76350).
    When: running the script.
    Then: the image is reported as available ("ok").
    """
    registry, image, tag = "xsoar-registry.pan.dev", "demisto/sklearn", "1.0.0.12545527"
    layer_digest = "sha256:" + "c" * 64
    manifest_url = f"https://{registry}/v2/{image}/manifests/{tag}"
    mocker.patch.object(demisto, "args", return_value={"input": f"{registry}/{image}:{tag}"})
    mocker.patch("CheckDockerImageAvailable.docker_auth", return_value="token")
    results = mocker.patch.object(demisto, "results")
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    requests_mock.get(
        manifest_url,
        status_code=404,
        json={"errors": [{"code": "MANIFEST_UNKNOWN", "message": f'Manifest has media type "{OCI_MANIFEST_TYPE}"'}]},
    )
    requests_mock.get(
        manifest_url,
        json={"mediaType": OCI_MANIFEST_TYPE, "layers": [{"size": 150, "digest": layer_digest}]},
        additional_matcher=lambda request: OCI_MANIFEST_TYPE in request.headers.get("Accept", ""),
    )
    requests_mock.get(f"https://{registry}/v2/{image}/blobs/{layer_digest}", content=b"x" * 100)

    main()

    return_error_mock.assert_not_called()
    results.assert_called_once_with("ok")
