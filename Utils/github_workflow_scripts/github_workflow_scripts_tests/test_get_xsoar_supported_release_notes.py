from Utils.github_workflow_scripts.get_xsoar_supported_release_notes import \
    is_pack_xsoar_supported,\
    convert_files_to_paths,\
    format_output

import pytest


@pytest.mark.parametrize('pack_name, expected', [
    ("SentinelOne", True),
    ("HelloWorld", False),
    ("", False),
])
def test_is_pack_xsoar_supported(pack_name, expected):
    """
    Given:
        - A Pack name

    When:
        - The Pack support is 'xsoar'
        - The Pack support is 'community'
        - The Pack doesn't exist

    Then:
        - The test will succeed
        - The test will fail
        - The test will fail
    """

    assert expected == is_pack_xsoar_supported(pack_name)


@pytest.mark.parametrize('files_paths, expected', [
    ([], [])
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md"], ["Packs/CommonTypes/ReleaseNotes/3_3_39.md"]),
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md", "Packs/SentinelOne/ReleaseNotes/3_0_4.md"],
        ["Packs/CommonTypes/ReleaseNotes/3_3_39.md", "Packs/SentinelOne/ReleaseNotes/3_0_4.md"]),
])
def test_convert_files_to_paths(files_paths, expected):
    """
    Given:
        - A list of paths strings

    When:
        - The list is empty
        - The list includes 1 path
        - The list includes 2 paths

    Then:
        - The returned list is empty
        - The returned list is 1 in length
        - The returned list is 2 in length
    """

    fps = convert_files_to_paths(files_paths)
    expected_list_of_str = list(map(lambda fp: str(fp), fps))

    assert expected == expected_list_of_str


@pytest.mark.parametrize('rns, delimiter, expected', [
    ([], "," "")
    ([], ";", "")
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md"], ",", "Packs/CommonTypes/ReleaseNotes/3_3_39.md"),
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md"], ";", "Packs/CommonTypes/ReleaseNotes/3_3_39.md"),
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md", "Packs/SentinelOne/ReleaseNotes/3_0_4.md"], ",", "Packs/CommonTypes/ReleaseNotes/3_3_39.md,Packs/SentinelOne/ReleaseNotes/3_0_4.md"),
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md", "Packs/SentinelOne/ReleaseNotes/3_0_4.md"], ";", "Packs/CommonTypes/ReleaseNotes/3_3_39.md,Packs/SentinelOne/ReleaseNotes/3_0_4.md"),
    (["Packs/CommonTypes/ReleaseNotes/3_3_39.md", "Packs/SentinelOne/ReleaseNotes/3_0_4.md"], None, "Packs/CommonTypes/ReleaseNotes/3_3_39.md,Packs/SentinelOne/ReleaseNotes/3_0_4.md"),
])
def test_format_output(rns, delimiter, expected):
    """
    Given:
        - A list of paths strings

    When:
        - The list is empty and comma is the delimiter
        - The list is empty and semicolon is the delimiter
        - The list includes 1 path and comma is the delimiter
        - The list includes 1 path and semicolon is the delimiter
        - The list includes 2 paths and comma is the delimiter
        - The list includes 2 paths and semicolon is the delimiter
        - The list includes 2 paths and semicolon is the delimiter is not specified

    Then:
        - The returned string is empty
        - The returned string is empty
        - The returned string has 1 path
        - The returned string has 1 path
        - The returned string has 2 paths with comma in between
        - The returned string has 2 paths with semicolon in between
        - The returned string has 2 paths with comma in between
    """

    actual = format_output(rns, delimiter)
    assert expected == actual
