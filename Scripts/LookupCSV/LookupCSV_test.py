import json
import demistomock as demisto
import pytest


class TestLookupCSV:
    @staticmethod
    def mock_results(mocker):
        mocker.patch.object(demisto, "results")

    @staticmethod
    def mock_context(mocker, args_value=None):
        if not args_value:
            args_value = {
                "entryID": "entry_id",
                "header_row": "true"
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
        TestLookupCSV.mock_results(mocker)
        TestLookupCSV.mock_context(mocker, args_value)
        if file_obj:
            TestLookupCSV.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]

    @staticmethod
    def create_file_object(file_path):
        return {
            "path": file_path,
            "name": file_path.split("/")[-1]
        }

    def test_main_csv(self, mocker):
        from LookupCSV import main
        with open("./TestData/simple_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_no_headers(self, mocker):
        from LookupCSV import main
        args_value = {
            "entryID": "entry_id",
        }

        with open("./TestData/simple_no_header_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple_no_header.csv"),
                          args_value=args_value)
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_search(self, mocker):
        from LookupCSV import main
        with open("./TestData/column_search_results.json") as f:
            expected = json.load(f)

        args_value = {
            "entryID": "entry_id",
            "header_row": "true",
            "column": "sourceIP",
            "value": "1.1.1.1"
        }
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/column_search.csv"),
                          args_value=args_value)
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_broken_search(self, mocker):
        from LookupCSV import main
        args_value = {
            "entryID": "entry_id",
            "header_row": "true",
            "column": "sourceIP",
            "value": "1.1.1.1"
        }
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/column_search.txt"),
                          args_value=args_value)
        with pytest.raises(SystemExit):
            # Raises using return_error due to invalid file spec (.txt, not .csv)
            main()
