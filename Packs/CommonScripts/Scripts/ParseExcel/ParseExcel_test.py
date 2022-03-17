import json
import demistomock as demisto


class TestParseExcel:
    @staticmethod
    def mock_results(mocker):
        mocker.patch.object(demisto, "results")

    @staticmethod
    def mock_context(mocker, args_value=None):
        if not args_value:
            args_value = {
                "entryId": "file_entry_id",
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
        TestParseExcel.mock_results(mocker)
        TestParseExcel.mock_context(mocker, args_value)
        if file_obj:
            TestParseExcel.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]['Contents']

    @staticmethod
    def create_file_object(file_path):
        return {
            "path": file_path,
            "name": file_path.split("/")[-1]
        }

    def test_main_csv(self, mocker):
        from ParseExcel import main
        with open("./TestData/file_example_result.json") as f:
            expected = json.load(f)

        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/file_example.xls"))
        main()
        result = self.get_demisto_results()
        assert expected == result
