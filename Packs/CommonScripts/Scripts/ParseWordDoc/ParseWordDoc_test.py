import demistomock as demisto


class TestParseWordDoc:
    @staticmethod
    def mock_results(mocker):
        mocker.patch.object(demisto, "results")

    @staticmethod
    def mock_context(mocker, args_value=None):
        if not args_value:
            args_value = {
                "entryID": "entry_id",
            }
        mocker.patch.object(demisto, "args", return_value=args_value)

    @staticmethod
    def mock_file_path(mocker, path, name):
        mocker.patch.object(demisto, "getFilePath", return_value={
            "path": path,
            "name": name
        })

    @staticmethod
    def mock_demisto(mocker, args_value=None, file_obj=None):
        TestParseWordDoc.mock_results(mocker)
        TestParseWordDoc.mock_context(mocker, args_value)
        if file_obj:
            TestParseWordDoc.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]

    @staticmethod
    def create_file_object(file_path):
        return {
            "path": file_path,
            "name": file_path.split("/")[-1]
        }

    def test_parse_word_doc(self, mocker):
        """
        Given:
            - A docx file

        When:
            - Run the ParseWordDoc script

        Then:
            - Verify that the docx file has now returned as .txt

        """
        from ParseWordDoc import main
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/file-sample.docx"))
        main()
        result = self.get_demisto_results()
        assert result.get('File') == 'file-sample.txt'
