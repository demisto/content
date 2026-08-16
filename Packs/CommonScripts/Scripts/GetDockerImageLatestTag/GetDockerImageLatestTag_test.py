import demistomock as demisto
import pytest
import requests_mock
from GetDockerImageLatestTag import find_latest_tag_by_date, is_runnable_tag, lexical_find_latest_tag, main

RETURN_ERROR_TARGET = "GetDockerImageLatestTag.return_error"

MOCK_TAG_LIST = [
    {
        "last_updated": "2019-10-23T09:13:30.84299Z",
        "name": "1.0.0.2876",
        "repository": 7863337,
        "creator": 4824052,
        "image_id": None,
        "v2": True,
        "last_updater_username": "containersci",
        "last_updater": 4824052,
        "images": [
            {
                "features": "",
                "os_features": "",
                "variant": None,
                "os_version": None,
                "architecture": "amd64",
                "os": "linux",
                "digest": "sha256:776a9e00733cd130a2b06ee94254c72c0ae5e11dcfeff24e68c2e1980e320685",
                "size": 79019268,
            }
        ],
        "full_size": 79019268,
        "id": 73482510,
    },
    {
        "last_updated": "2019-10-16T06:47:29.631011Z",
        "name": "1.0.0.2689",
        "repository": 7863337,
        "creator": 4824052,
        "image_id": None,
        "v2": True,
        "last_updater_username": "containersci",
        "last_updater": 4824052,
        "images": [
            {
                "features": "",
                "os_features": "",
                "variant": None,
                "os_version": None,
                "architecture": "amd64",
                "os": "linux",
                "digest": "sha256:95aaaadeec53a11ec2ce58769e3d00acc593981f470c31e22ceba8f2bc673fcb",
                "size": 77021619,
            }
        ],
        "full_size": 77021619,
        "id": 72714981,
    },
]


# demisto/python-deb doesn't contain a latest tag


@pytest.mark.parametrize("image", ["python", "python-deb", "python3", "python3-deb"])
def test_valid_docker_image(mocker, image):
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import os

    os.environ["HTTP_PROXY"] = ""
    os.environ["HTTPS_PROXY"] = ""
    os.environ["http_proxy"] = ""
    os.environ["https_proxy"] = ""
    demisto_image = "demisto/" + image
    args = {"docker_image": demisto_image, "trust_any_certificate": "yes", "use_system_proxy": "no"}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["docker_image"] == demisto_image
    with requests_mock.Mocker() as m:
        m.get(
            "https://registry-1.docker.io/v2/",
            status_code=401,
            headers={"www-authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'},
        )
        m.get(
            f"https://auth.docker.io/token?scope=repository:{demisto_image}:pull&service=registry.docker.io",
            status_code=200,
            json={"token": 123465},
        )
        m.get(f"https://hub.docker.com/v2/repositories/{demisto_image}/tags", status_code=200, json={"results": MOCK_TAG_LIST})
        main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    # current latest tag is 2.7.16.2728 or 3.7.2.2728 disable-secrets-detection
    assert int(results[0].split(".")[3]) >= 2728


def test_invalid_docker_image(mocker):
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    image_name = "demisto/notrealdockerimage"
    mocker.patch.object(demisto, "args", return_value={"docker_image": image_name, "trust_any_certificate": "yes"})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()["docker_image"] == image_name
    with requests_mock.Mocker() as m:
        m.get("https://registry-1.docker.io/v2/", status_code=401)
        m.get(
            "https://auth.docker.io/token?scope=repository:demisto/notrealdockerimage:pull&service=registry.docker.io",
            status_code=200,
            json={"token": 123465},
        )
        m.get("https://hub.docker.com/v2/repositories/demisto/notrealdockerimage/tags", status_code=404)
        m.get("https://registry-1.docker.io/v2/demisto/notrealdockerimage/tags/list", status_code=401)
        main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg is not None


def test_lexical_latest_tag():
    tag_list = ["2.0.2000", "2.1.2700", "2.1.373", "latest"]
    tag = lexical_find_latest_tag(tag_list)
    assert tag == "2.1.2700"


def test_date_latest_tag():
    tag = find_latest_tag_by_date(MOCK_TAG_LIST)
    assert tag == "1.0.0.2876"


# ---------------------------------------------------------------------------
# Tests for is_runnable_tag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tag",
    [
        "3.10.13.87159",
        "latest",
        "1.0.0.2876",
        "2.1.2700",
        "3.12.12.7090913",
        # Tags containing an artifact suffix that is NOT at the end must be kept.
        "my.sig.image",
        "my.att.image",
        "my.sbom.image",
        "1.0.sig.2876",
        ".sig-build",
    ],
)
def test_is_runnable_tag_valid(tag):
    """Runnable image tags must pass the filter.

    Includes tags that merely *contain* an artifact suffix (e.g. ``my.sig.image``)
    to verify that ``endswith`` matching does not filter valid tags.
    """
    assert is_runnable_tag(tag) is True


@pytest.mark.parametrize("tag", [None, 123, "", [], {}])
def test_is_runnable_tag_non_string(tag):
    """Non-string or empty tag values must be rejected without raising."""
    assert is_runnable_tag(tag) is False


@pytest.mark.parametrize(
    "tag",
    [
        "sha256-0535a854557dc43a03595eb7ef1625f79896e9d3e8da67b9ed17362546c80c0b.sig",
        "sha256-abcdef1234567890.sig",
        "sha256-abcdef1234567890.att",
        "sha256-abcdef1234567890.sbom",
        "3.10.13.87159.sig",
    ],
)
def test_is_runnable_tag_artifact(tag):
    """OCI artifact tags (.sig, .att, .sbom) must be rejected."""
    assert is_runnable_tag(tag) is False


def test_lexical_find_latest_tag_filters_sig_tags():
    """lexical_find_latest_tag must ignore .sig/.att/.sbom artifact tags."""
    tag_list = [
        "2.0.2000",
        "sha256-0535a854557dc43a03595eb7ef1625f79896e9d3e8da67b9ed17362546c80c0b.sig",
        "2.1.2700",
        "sha256-abcdef.att",
        "2.1.373",
        "latest",
    ]
    tag = lexical_find_latest_tag(tag_list)
    assert tag == "2.1.2700"


def test_find_latest_tag_by_date_filters_sig_tags():
    """find_latest_tag_by_date must ignore .sig/.att/.sbom artifact tags even when they are the most recent."""
    sig_tag = {
        "last_updated": "2026-08-05T17:49:28.179522Z",  # newer than all real tags
        "name": "sha256-0535a854557dc43a03595eb7ef1625f79896e9d3e8da67b9ed17362546c80c0b.sig",
    }
    tags_with_sig = [sig_tag] + MOCK_TAG_LIST
    tag = find_latest_tag_by_date(tags_with_sig)
    # The .sig tag is the most recent but must be skipped; 1.0.0.2876 is the latest real tag.
    assert tag == "1.0.0.2876"


def test_find_latest_tag_by_date_filters_att_and_sbom_tags():
    """find_latest_tag_by_date must ignore .att and .sbom artifact tags."""
    att_tag = {
        "last_updated": "2026-08-05T17:49:28.179522Z",
        "name": "sha256-abcdef1234567890.att",
    }
    sbom_tag = {
        "last_updated": "2026-08-05T17:49:29.000000Z",
        "name": "sha256-abcdef1234567890.sbom",
    }
    tags = [att_tag, sbom_tag] + MOCK_TAG_LIST
    tag = find_latest_tag_by_date(tags)
    assert tag == "1.0.0.2876"


def test_lexical_find_latest_tag_all_tags_filtered():
    """When every tag is a non-runnable artifact, an empty string is returned (no IndexError)."""
    tag_list = [
        "sha256-0535a854557dc43a03595eb7ef1625f79896e9d3e8da67b9ed17362546c80c0b.sig",
        "sha256-abcdef1234567890.att",
        "sha256-abcdef1234567890.sbom",
    ]
    assert lexical_find_latest_tag(tag_list) == ""


def test_lexical_find_latest_tag_empty_list():
    """An empty tag list must return an empty string rather than raising IndexError."""
    assert lexical_find_latest_tag([]) == ""


def test_lexical_find_latest_tag_keeps_tag_containing_suffix():
    """A non-numeric tag that only contains an artifact suffix must still be returned."""
    assert lexical_find_latest_tag(["my.sig.image"]) == "my.sig.image"


def test_find_latest_tag_by_date_handles_missing_name():
    """Tags with a missing or non-string name must be skipped without raising."""
    tags = [{"last_updated": "2026-08-05T17:49:28.179522Z"}, {"name": None, "last_updated": "2026-08-05T17:49:28.179522Z"}]
    tags = tags + MOCK_TAG_LIST
    assert find_latest_tag_by_date(tags) == "1.0.0.2876"


def test_find_latest_tag_by_date_handles_bad_last_updated():
    """Tags with a missing or unparsable last_updated must be skipped without raising."""
    tags = [
        {"name": "9.9.9.9999", "last_updated": None},
        {"name": "8.8.8.8888", "last_updated": "not-a-date"},
        {"name": "7.7.7.7777"},
    ]
    tags = tags + MOCK_TAG_LIST
    assert find_latest_tag_by_date(tags) == "1.0.0.2876"
