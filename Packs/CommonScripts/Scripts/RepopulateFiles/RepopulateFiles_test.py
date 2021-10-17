from RepopulateFiles import main


class TestRepopulateFiles:
    def test_main_no_entries(self, mocker):
        mocker.patch('RepopulateFiles.demisto.executeCommand', return_value=None)
        main()
