

def test_parse_docker_image():
    from Tests.scripts.hook_validations.docker import parse_docker_image
    assert 'demisto/python', '1.3-alpine' == parse_docker_image('demisto/python:1.3-alpine')
    assert 'demisto/slack', '1.2.3.4' == parse_docker_image('demisto/slack:1.2.3.4')
    assert '', '' == parse_docker_image('demisto/python/1.2.3.4')
