import pytest

from Tests.Marketplace.validate_landing_page_sections import validate_file_keys, validate_valid_packs_in_sections


def test_validate_file_keys_negative():
    """
    Given
    - A landingPage_sections.json file with section that's not appearing under the 'sections' key
    When
    - Validating the file
    Then
    - Ensure an exception is raised
    """
    file_content = {'description': '',
                    'sections': ['Featured'],
                    'another_section': ['']}
    with pytest.raises(AssertionError):
        validate_file_keys(file_content)


def test_validate_file_keys_positive():
    """
    Given
    - A landingPage_sections.json file with valid section names
    When
    - Validating the file
    Then
    - Ensure no exception is raised
    """
    file_content = {'description': '',
                    'sections': ['Featured'],
                    'Featured': ['pack']}
    validate_file_keys(file_content)


def test_validate_valid_packs_in_sections_negative():
    """
    Given
    - A landingPage_sections.json file with a section that contains a non-valid pack
    When
    - Validating the file
    Then
    - Ensure an exception is raised
    """
    valid_packs = {'pack1', 'pack2'}
    file_content = {'description': '',
                    'sections': ['Featured'],
                    'Featured': ['pack3']}
    with pytest.raises(AssertionError):
        validate_valid_packs_in_sections(file_content, valid_packs)


def test_validate_valid_packs_in_sections_positive():
    """
    Given
    - A landingPage_sections.json file with valid sections
    When
    - Validating the file
    Then
    - Ensure no exception is raised
    """
    valid_packs = {'pack1', 'pack2'}
    file_content = {'description': '',
                    'sections': ['Featured'],
                    'Featured': ['pack1', 'pack2']}
    validate_valid_packs_in_sections(file_content, valid_packs)
