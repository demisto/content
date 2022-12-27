from Utils.github_workflow_scripts.get_xsoar_supported_release_notes import \
    is_pack_xsoar_supported,\
    convert_files_to_paths,\
    main

import pytest
# from argparse import Namespace


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

# @pytest.mark.parametrize('files_paths, expected', [
#     (["Packs/CommonTypes/ReleaseNotes/3_3_39.md" , "Packs/SentinelOne/ReleaseNotes/3_0_4.md"], )
# ])
# def test_convert_files_to_paths(files_paths, expected):



# class TestsRunDocsReview:
#     def test_file_name_includes_apostrophe(self, mocker, capsys):
#         """
#             Given:
#                 - A string contains a file name with an apostrophe.
#             When:
#                 - Running run_docs_review function of the run_docs_review github workflow script.
#             Then:
#                 - Verify the doc reviewer gets the file name with the apostrophe correctly.
#                 - Verify that the output is as expected.
#         """
#         file_name_with_apostrophe = "Packs/UnRealPack/Apostrophe's_Test.yml"
#         file_name = 'Packs/UnRealPack/UnRealFile.yml'
#         delimiter = ';'
#         files_names = f'{file_name_with_apostrophe}{delimiter}{file_name}'
#         sdk_docs_reviewer_starting_string = '================= Starting Doc Review ================='
#         expected_exit_code_of_run_docs_review = 0

#         args = Namespace(changed_files=files_names, delimiter=delimiter)
#         mocker.patch('Utils.github_workflow_scripts.run_docs_review.parse_changed_files_names', return_value=args)

#         result = run_docs_review()
#         captured = capsys.readouterr()
#         assert sdk_docs_reviewer_starting_string in captured.out
#         assert result == expected_exit_code_of_run_docs_review
