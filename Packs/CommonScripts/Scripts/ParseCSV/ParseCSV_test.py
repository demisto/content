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
        with open("./test_data/one_lined_csv_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(
            mocker,
            file_obj=TestParseCSV.create_file_object("./test_data/one_lined_csv.csv")
        )
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_utf8(self, mocker):
        from ParseCSV import main
        with open("./test_data/simple_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./test_data/simple.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_csv_non_utf8(self, mocker):
        from ParseCSV import main
        with open("./test_data/simple_non_utf_results.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./test_data/simple_non_utf.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_empty_file(self, mocker):
        from ParseCSV import main
        with open("./test_data/empty_result.json") as f:
            expected = json.load(f)
        self.mock_demisto(mocker, file_obj=self.create_file_object("./test_data/empty.csv"))
        main()
        result = self.get_demisto_results()
        assert expected == result

    def test_main_with_hash(self, mocker):
        from ParseCSV import main
        with open("./test_data/one_is_hash_results.json") as f:
            expected = json.load(f)
        args = {
            "entryID": "entry_id",
            "parseAll": "no",
            "codec": "utf-8",
            "hashes": "1"
        }
        file_obj = self.create_file_object("./test_data/one_is_hash.csv")
        self.mock_demisto(mocker, args_value=args, file_obj=file_obj)
        main()
        result = self.get_demisto_results()
        files = result.get('EntryContext', {}).get('File', [])
        sorted_files = ['1', '2', '3']
        for f in files:
            if f.get('MD5'):
                sorted_files[0] = f
            if f.get('SHA256'):
                sorted_files[1] = f
            if f.get('SHA1'):
                sorted_files[2] = f
        result['EntryContext']['File'] = sorted_files
        assert expected == result

    def test_parsecsv_with_iocs_same_column(self, mocker):
        """
        Given: CSV table with different IOCs types in same column.

        When: Passing the same column number for both IOCs.

        Then: Ensure each IOC type in context is expected.
        """
        from ParseCSV import main
        with open("./test_data/IOCs_results.json") as f:
            expected = json.load(f)
        args = {
            "entryID": "entry_id",
            "parseAll": "no",
            "codec": "utf-8",
            "ips": "1",
            "domains": "1",
            "hashes": "1"
        }
        file_obj = self.create_file_object("./test_data/IOCs.csv")
        self.mock_demisto(mocker, args_value=args, file_obj=file_obj)
        main()
        result = self.get_demisto_results()

        ips_result = result.get('EntryContext', {}).get('IP', [])
        if ips_result and ips_result[0].get('Address') != '1.1.1.1':
            result['EntryContext']['IP'].reverse()

        domains_result = result.get('EntryContext', {}).get('Domain', [])
        if domains_result and not domains_result[0].get('Name').endswith('com'):
            result['EntryContext']['Domain'].reverse()

        assert expected == result

    def test_main_with_hash_empty_file(self, mocker):
        from ParseCSV import main
        args = {
            "entryID": "entry_id",
            "parseAll": "no",
            "codec": "utf-8",
            "hashes": "1"
        }
        file_obj = self.create_file_object("./test_data/empty.csv")
        self.mock_demisto(mocker, args_value=args, file_obj=file_obj)
        with pytest.raises(SystemExit, match="0"):
            main()

    def test_main_with_nullbytes(self, mocker):
        from ParseCSV import main
        with open("./test_data/nullbytes_results.json") as f:
            expeced = json.load(f)
        file_obj = self.create_file_object("./test_data/nullbytes.csv")
        self.mock_demisto(mocker, file_obj=file_obj)
        main()
        result = self.get_demisto_results()
        assert result == expeced
