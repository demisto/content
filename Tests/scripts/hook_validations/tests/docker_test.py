from mock import patch
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
        u'digest': u'DIGEST',
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
        u'digest': u'DIGEST',
        u'size': 77021619
    }],
    u'full_size': 77021619,
    u'id': 72714981
}]

# demisto/python-deb doesn't contain a latest tag
@pytest.mark.parametrize('image', ['python', 'python-deb', 'python3', 'python3-deb'])
def test_get_docker_image_latest_tag(image):
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    tag = DockerImageValidator.get_docker_image_latest_tag('demisto/' + image)
    # current latest tag is 2.7.16.2728 or 3.7.2.2728 disable-secrets-detection
    assert int(tag.split('.')[3]) >= 2728


def test_lexical_find_latest_tag():
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    tag_list = ["2.0.2000", "2.1.2700", "2.1.373", "latest"]
    tag = DockerImageValidator.lexical_find_latest_tag(tag_list)
    assert tag == "2.1.2700"


def test_find_latest_tag_by_date():
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    tag = DockerImageValidator.find_latest_tag_by_date(MOCK_TAG_LIST)
    assert tag == "1.0.0.2876"


@pytest.mark.parametrize('www_auth, expected', [('AAArealm="2",service="3"AAA', ['2', '3']), ('bbb', [])])
def test_parse_www_auth(www_auth, expected):
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    assert expected.sort() == DockerImageValidator.parse_www_auth(www_auth).sort()


@pytest.mark.parametrize('input_tags, output_tags',
                         [(['1.2.3.0', '4.5.6.0', '7.8.9.0'], ['4.5.6.0', '1.2.3.0', '7.8.9.0']),
                          (['1.2.3.0', '4.a.6.0', '7.8.9.0'], ['7.8.9.0', '1.2.3.0'])])
def test_clear_non_numbered_tags(input_tags, output_tags):
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    assert output_tags.sort() == DockerImageValidator.clear_non_numbered_tags(input_tags).sort()


def test_parse_docker_image():
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    assert 'demisto/python', '1.3-alpine' == DockerImageValidator.parse_docker_image('demisto/python:1.3-alpine')
    assert 'demisto/slack', '1.2.3.4' == DockerImageValidator.parse_docker_image('demisto/slack:1.2.3.4')
    assert ('', '') == DockerImageValidator.parse_docker_image('demisto/python/1.2.3.4')


def test_is_docker_image_latest_tag():
    from Tests.scripts.hook_validations.docker import DockerImageValidator
    with patch.object(DockerImageValidator, '__init__', lambda x, y, z: None):
        docker_image_validator = DockerImageValidator(None, None)
        docker_image_validator.yml_file = {}
        docker_image_validator.docker_image_latest_tag = 'latest_tag'
        docker_image_validator.docker_image_name = 'demisto/python'
        docker_image_validator.from_version = '5.0.0'

        # ===== Added File Tests =====
        # default docker image
        docker_image_validator.is_latest_tag = True
        docker_image_validator.is_modified_file = False
        docker_image_validator.docker_image_tag = '1.3-alpine'
        assert docker_image_validator.is_docker_image_latest_tag() is False

        # regular docker image, not latest tag
        docker_image_validator.is_latest_tag = True
        docker_image_validator.docker_image_tag = 'not_latest_tag'
        assert docker_image_validator.is_docker_image_latest_tag() is False

        # regular docker image, latest tag
        docker_image_validator.is_latest_tag = True
        docker_image_validator.docker_image_tag = 'latest_tag'
        assert docker_image_validator.is_docker_image_latest_tag() is True

        # ===== Modified File Tests =====
        # from version 4.1.0
        docker_image_validator.is_latest_tag = True
        docker_image_validator.is_modified_file = True
        docker_image_validator.from_version = '4.1.0'
        assert docker_image_validator.is_docker_image_latest_tag() is True

        # from version 5.0.0 - regular docker image, latest tag
        docker_image_validator.is_latest_tag = True
        docker_image_validator.from_version = '5.0.0'
        assert docker_image_validator.is_docker_image_latest_tag() is True

        # from version 5.0.0 - regular docker image, not latest tag
        docker_image_validator.is_latest_tag = True
        docker_image_validator.from_version = '5.0.0'
        docker_image_validator.docker_image_tag = 'not_latest_tag'
        assert docker_image_validator.is_docker_image_latest_tag() is False

        # from version 5.0.0 - default docker image
        docker_image_validator.is_latest_tag = True
        docker_image_validator.docker_image_tag = '1.3-alpine'
        assert docker_image_validator.is_docker_image_latest_tag() is True
