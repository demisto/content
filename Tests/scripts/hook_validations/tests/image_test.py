from Tests.scripts.hook_validations.image import ImageValidator


def test_is_not_default_image():
    image_validator = ImageValidator("Integrations/ZeroFox/ZeroFox.yml")
    assert image_validator.is_not_default_image() is True
    image_validator = ImageValidator("Integrations/integration-Zoom.yml")
    assert image_validator.is_not_default_image() is True
    image_validator = ImageValidator("Tests/scripts/hook_validations/tests/tests_data/default_image.png")
    assert image_validator.is_not_default_image() is False
    image_validator = ImageValidator("Tests/scripts/hook_validations/tests/tests_data/fake_integration.yml")
    assert image_validator.is_not_default_image() is False

