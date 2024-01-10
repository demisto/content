import itertools
from pathlib import Path

import pytest

from Utils.check_protected_directories import (
    CONTENT_ROOT,
    EXCEPTIONS,
    PROTECTED_DIRECTORY_PATHS,
    is_path_change_allowed,
)


@pytest.mark.parametrize(
    "path_str",
    (
        "Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml",
        "Packs/MyPack/Integrations/MyIntegration/MyIntegration.py",
        "Packs/MyPack/Integrations/MyIntegration/test_data/data.json",
    ),
)
def test_allowed_path(path_str: str):
    """
    Given:  a path to test
    When:   checking if path is allowed
    Then:   make sure the script allows changing this file.
    """
    assert is_path_change_allowed(Path(CONTENT_ROOT, path_str))  # absolute
    assert is_path_change_allowed(Path(path_str))  # relative


@pytest.mark.parametrize(
    "path",
    itertools.chain.from_iterable(
        (
            Path(root_dir, "some_file.py"),
            Path(root_dir, "subfolder", "some_file.py"),
        )
        for root_dir in sorted(PROTECTED_DIRECTORY_PATHS)
    ),
)
def test_prohibited_path(path: Path):
    """
    Given:  a path to test
    When:   checking if path is allowed
    Then:   make sure the script does NOT allow changing this file.
    """
    assert not is_path_change_allowed(path)  # absolute
    assert not is_path_change_allowed(path.relative_to(CONTENT_ROOT))  # relative


@pytest.mark.parametrize("path", sorted(EXCEPTIONS))
def test_exceptionally_allowed_file(path: Path):
    """
    Given:  a path to test, which is under EXCEPTIONS
    When:   checking if path is allowed
    Then:   make sure the script allows changing this file.
    """
    assert is_path_change_allowed(path)
