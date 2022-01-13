from argparse import Namespace

from Utils.github_workflow_scripts.run_docs_review import run_docs_review


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
        file_name = "Packs/UnRealPack/Apostrophe's_Test.yml"  # name includes an apostrophe
        delimiter = ';'
        sdk_docs_reviewer_starting_string = '================= Starting Doc Review ================='
        expected_exit_code_of_run_docs_review = 0

        args = Namespace(changed_files=file_name, delimiter=delimiter)
        mocker.patch('Utils.github_workflow_scripts.run_docs_review.parse_changed_files_names', return_value=args)

        result = run_docs_review()
        captured = capsys.readouterr()
        assert sdk_docs_reviewer_starting_string in captured.out
        assert file_name in captured.out
        assert result == expected_exit_code_of_run_docs_review
