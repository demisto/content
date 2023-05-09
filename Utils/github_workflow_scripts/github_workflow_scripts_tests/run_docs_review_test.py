from argparse import Namespace
import logging
from Utils.github_workflow_scripts.run_docs_review import run_docs_review
from Utils.github_workflow_scripts.utils import flatten_call_args


class TestsRunDocsReview:
    def test_file_name_includes_apostrophe(self, mocker, capsys):
        """
            Given:
                - A string contains a file name with an apostrophe.
            When:
                - Running run_docs_review function of the run_docs_review github workflow script.
            Then:
                - Verify the doc reviewer gets the file name with the apostrophe correctly.
                - Verify that the output is as expected.
        """
        logger_info = mocker.patch.object(logging.getLogger("demisto-sdk"), "info")
        file_name_with_apostrophe = "Packs/UnRealPack/Apostrophe's_Test.yml"
        file_name = 'Packs/UnRealPack/UnRealFile.yml'
        delimiter = ';'
        files_names = f'{file_name_with_apostrophe}{delimiter}{file_name}'
        sdk_docs_reviewer_starting_string = "Starting Doc Review"
        expected_exit_code_of_run_docs_review = 0

        args = Namespace(changed_files=files_names, delimiter=delimiter)
        mocker.patch('Utils.github_workflow_scripts.run_docs_review.parse_changed_files_names', return_value=args)

        result = run_docs_review()
        # When demisto-sdk 1.14.1 is released, it's safe to remove the capsys check
        assert any(sdk_docs_reviewer_starting_string in log for log in flatten_call_args(logger_info.call_args_list)) or \
            sdk_docs_reviewer_starting_string in capsys.readouterr().out
        assert result == expected_exit_code_of_run_docs_review
