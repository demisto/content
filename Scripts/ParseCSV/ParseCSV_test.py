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
    def mock_demisto(mocker, args_value, file_obj):
        TestParseCSV.mock_results(mocker)
        TestParseCSV.mock_context(mocker, args_value)
        TestParseCSV.mock_file_path(mocker, **file_obj)

    @staticmethod
    def get_demisto_results():
        return demisto.results.call_args[0][0]

    def test_main_bug_no_entries(self, mocker):
        from ParseCSV import main
        path = "./TestData/long_csv_file.csv"
        name = "long_csv_file.csv"
        context = {
            "entryID": "entry_id",
            "parseAll": "yes",
            "codec": "utf-8"
        }
        self.mock_demisto(
            mocker,
            args_value=context,
            file_obj={
                "path": path,
                "name": name
            }
        )
        main()
        res = self.get_demisto_results()
        pass
