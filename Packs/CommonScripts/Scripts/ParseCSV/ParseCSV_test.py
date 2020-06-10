import json
import pytest
import demistomock as demisto


class TestParseCSV:
    @staticmethod
    def mock_results(mocker):
        mocker.patch.object(demisto, "results")

    @staticmethod
    def mock_context(mocker, args_value=None):
        if not args_value:
            args_value = {
                "entryID": "entry_id",
                "parseAll": "yes",
                "codec": "utf-8"
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
        TestParseCSV.mock_results(mocker)
        TestParseCSV.mock_context(mocker, args_value)
        if file_obj:
            TestParseCSV.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]

    @staticmethod
    def create_file_object(file_path):
        return {
            "path": file_path,
            "name": file_path.split("/")[-1]
        }

    def test_main_one_lined_csv(self, mocker):
        from ParseCSV import main
        with open("./TestData/one_lined_csv_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(
            mocker,
            file_obj=TestParseCSV.create_file_object("./TestData/one_lined_csv.csv")
        )
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_utf8(self, mocker):
        from ParseCSV import main
        with open("./TestData/simple_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_non_utf8(self, mocker):
        from ParseCSV import main
        with open("./TestData/simple_non_utf_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/simple_non_utf.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_empty_file(self, mocker):
        from ParseCSV import main
        with open("./TestData/empty_result.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./TestData/empty.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_with_hash(self, mocker):
        from ParseCSV import main
        with open("./TestData/one_is_hash_results.json") as f:
            expected = json.load(f)
        args = {
            "entryID": "entry_id",
            "parseAll": "no",
            "codec": "utf-8",
            "hashes": "1"
        }
        file_obj = self.create_file_object("./TestData/one_is_hash.csv")
        self.mock_demisto(mocker, args_value=args, file_obj=file_obj)
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_with_hash_empty_file(self, mocker):
        from ParseCSV import main
        args = {
            "entryID": "entry_id",
            "parseAll": "no",
            "codec": "utf-8",
            "hashes": "1"
        }
        file_obj = self.create_file_object("./TestData/empty.csv")
        self.mock_demisto(mocker, args_value=args, file_obj=file_obj)
        with pytest.raises(SystemExit, match="0"):
            main()

    def test_main_with_nullbytes(self, mocker):
        from ParseCSV import main
        with open("./TestData/nullbytes_results.json") as f:
            expeced = json.load(f)
        file_obj = self.create_file_object("./TestData/nullbytes.csv")
        self.mock_demisto(mocker, file_obj=file_obj)
        main()
        result = self.get_demisto_results()
        assert result == expeced
