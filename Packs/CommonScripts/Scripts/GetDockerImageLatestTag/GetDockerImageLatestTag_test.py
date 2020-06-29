from GetDockerImageLatestTag import main, find_latest_tag_by_date, lexical_find_latest_tag
import demistomock as demisto
import pytest

RETURN_ERROR_TARGET = 'GetDockerImageLatestTag.return_error'

MOCK_TAG_LIST = [{
    u'last_updated': u'2019-10-23T09:13:30.84299Z',
    u'name': u'1.0.0.2876',
    u'repository': 7863337,
    u'creator': 4824052,
    u'image_id': None,
    u'v2': True,
    u'last_updater_username': u'containersci',
    u'last_updater': 4824052,
    u'images': [{
        u'features': u'',
        u'os_features': u'',
        u'variant': None,
        u'os_version': None,
        u'architecture': u'amd64',
        u'os': u'linux',
        u'digest': u'sha256:776a9e00733cd130a2b06ee94254c72c0ae5e11dcfeff24e68c2e1980e320685',
        u'size': 79019268
    }],
    u'full_size': 79019268,
    u'id': 73482510
}, {
    u'last_updated': u'2019-10-16T06:47:29.631011Z',
    u'name': u'1.0.0.2689',
    u'repository': 7863337,
    u'creator': 4824052,
    u'image_id': None,
    u'v2': True,
    u'last_updater_username': u'containersci',
    u'last_updater': 4824052,
    u'images': [{
        u'features': u'',
        u'os_features': u'',
        u'variant': None,
        u'os_version': None,
        u'architecture': u'amd64',
        u'os': u'linux',
        u'digest': u'sha256:95aaaadeec53a11ec2ce58769e3d00acc593981f470c31e22ceba8f2bc673fcb',
        u'size': 77021619
    }],
    u'full_size': 77021619,
    u'id': 72714981
}]


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
    # current latest tag is 2.7.16.2728 or 3.7.2.2728 disable-secrets-detection
    assert int(results[0].split('.')[3]) >= 2728


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


def test_lexical_latest_tag():
    tag_list = ["2.0.2000", "2.1.2700", "2.1.373", "latest"]
    tag = lexical_find_latest_tag(tag_list)
    assert tag == "2.1.2700"


def test_date_latest_tag():
    tag = find_latest_tag_by_date(MOCK_TAG_LIST)
    assert tag == "1.0.0.2876"
