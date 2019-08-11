import json

import demistomock as demisto


class TestParseCSV:
    @staticmethod
    def mock_results(mocker):
        mocker.patch.object(demisto, "results")

    @staticmethod
    def mock_context(mocker, args_value):
        mocker.patch.object(demisto, "args", return_value=args_value)

    @staticmethod
    def mock_file_path(mocker, path, name):
        mocker.patch.object(demisto, "getFilePath", return_value={
            "path": path,
            "name": name
        })

    @staticmethod
    def mock_demisto(mocker, args_value=None, file_obj=None):
        TestParseCSV.mock_results(mocker)
        if not args_value:
            args_value = {
                "entryID": "entry_id",
                "parseAll": "yes",
                "codec": "utf-8"
            }
        TestParseCSV.mock_context(mocker, args_value)
        if file_obj:
            TestParseCSV.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]

    @staticmethod
    def create_file_object(file_path):
        # (str) -> dict
        return {
            "path": file_path,
            "name": file_path.split("/")[-1]
        }

    def test_main_one_lined_csv(self, mocker):
        from ParseCSV import main

        self.mock_demisto(
            mocker,
            file_obj=TestParseCSV.create_file_object("./TestData/one_lined_csv.csv")
        )
        main()
        result = self.get_demisto_results()
        with open("./TestData/one_lined_csv_results.json") as f:
            expected = json.load(f)
        assert expected == result

    def test_main_csv_utf8(self, mocker):
        from ParseCSV import main
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple.csv"))
        main()
        result = self.get_demisto_results()
        with open("./TestData/simple_results.json") as f:
            expected = json.load(f)
        assert expected == result

    def test_main_csv_non_utf8(self, mocker):
        from ParseCSV import main
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple_non_utf.csv"))
        main()
        result = self.get_demisto_results()
        with open("./TestData/simple_non_utf_results.json") as f:
            expected = json.load(f)
        assert expected == result

