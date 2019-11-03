from Tests.scripts.hook_validations import image


def test_is_not_default_image():
    image_validator = image.ImageValidator("Integrations/ZeroFox/ZeroFox.yml")
    assert image_validator.is_not_default_image() is True
    image_validator = image.ImageValidator("Integrations/integration-Zoom.yml")
    assert image_validator.is_not_default_image() is True
    image.INTEGRATION_YML_REGEX = 'Tests/scripts/hook_validations/tests/tests_data/default_image.png'
    image_validator = image.ImageValidator("Tests/scripts/hook_validations/tests/tests_data/default_image.png")
    assert image_validator.is_not_default_image() is False
    image.INTEGRATION_REGEX = 'Tests/scripts/hook_validations/tests/tests_data/fake_integration.yml'
    image_validator = image.ImageValidator("Tests/scripts/hook_validations/tests/tests_data/fake_integration.yml")
    assert image_validator.is_not_default_image() is False
