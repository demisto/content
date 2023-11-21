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
        self.mock_demisto(mocker, file_obj=self.create_file_object("./test_data/file-sample.docx"))
        main()
        result = self.get_demisto_results()
        assert result.get('File') == 'file-sample.txt'


def test_extract_urls_xml_with_hyperlink():
    """
    Given:
        - A docx file with hyperlink

    When:
        - Run the extract_urls_xml method

    Then:
        - Verify that the method extracting the url from the document

    """
    from ParseWordDoc import extract_urls_xml
    urls = extract_urls_xml('./test_data/file-sample2.docx')
    assert urls == ['https://typora.io']


def test_extract_urls_xml_without_hyperlink():
    """
    Given:
        - A docx file without hyperlink

    When:
        - Run the extract_urls_xml method

    Then:
        - Verify that the method extracting none urls from the document

    """
    from ParseWordDoc import extract_urls_xml
    urls = extract_urls_xml('./test_data/file-sample.docx')
    assert urls == []


def test_extract_urls_docx_without_hyperlink():
    """
    Given:
        - A docx file without hyperlink

    When:
        - Run the extract_urls_docx method

    Then:
        - Verify that the method extracting none urls from the document

    """
    from docx import Document
    from ParseWordDoc import extract_urls_docx
    document = Document('./test_data/file-sample2.docx')
    urls = extract_urls_docx(document)
    assert urls == []


def test_extract_urls_docx_with_hyperlinks():
    """
    Given:
        - A docx file with hyperlinks

    When:
        - Run the extract_urls_docx method

    Then:
        - Verify that the method extracting the urls from the document

    """
    from docx import Document
    from ParseWordDoc import extract_urls_docx
    document = Document('./test_data/MS-DOCX-190319.docx')
    urls = extract_urls_docx(document)
    assert 'https://go.microsoft.com/fwlink/?LinkId=90607' in urls
