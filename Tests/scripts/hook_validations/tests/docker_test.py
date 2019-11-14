from mock import patch


def test_parse_docker_image():
    from Tests.scripts.hook_validations.docker import parse_docker_image
    assert 'demisto/python', '1.3-alpine' == parse_docker_image('demisto/python:1.3-alpine')
    assert 'demisto/slack', '1.2.3.4' == parse_docker_image('demisto/slack:1.2.3.4')
    assert ('', '') == parse_docker_image('demisto/python/1.2.3.4')


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
