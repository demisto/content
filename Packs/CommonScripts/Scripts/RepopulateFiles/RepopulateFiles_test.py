from RepopulateFiles import parse_attachment_entries, main


class TestRepopulateFiles:
    def test_main_no_entries(self, mocker):
        main()
